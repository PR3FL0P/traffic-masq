use super::runtime::compensation_message;
use super::*;
use crate::core::client_compensation::restore_dhcp_client;
use crate::core::transaction::InterfaceChange;

pub(super) fn validate_wifi_client_interface(
    interface: &str,
    config: &InterfaceConfig,
) -> Result<(), String> {
    if !config.managed {
        return Err(format!(
            "interface '{interface}' is unmanaged; traffic-masq does not modify unmanaged interfaces. Enable 'managed' first."
        ));
    }
    if config.role != InterfaceRole::Input {
        return Err(format!(
            "a Wi-Fi client requires an input interface, but '{interface}' has role '{:?}'",
            config.role
        ));
    }
    if !config.dhcp_client.as_ref().is_some_and(|c| c.enabled) && config.ipv4.is_none() {
        return Err(format!(
            "a Wi-Fi client on '{interface}' requires an IP address: enable DHCP client (dhcp_client) or configure a static IPv4 address"
        ));
    }
    Ok(())
}

/// Shared target construction for operator activation and internal autoconnect.
fn profile_activation_target(
    interface: &str,
    previous: &InterfaceConfig,
    profile: &crate::wifi::WifiClientProfileSummary,
    dhcp_available: bool,
) -> Result<(InterfaceConfig, bool), WifiClientProfileErrorDetail> {
    let mut target = previous.clone();
    let auto_dhcp = target.ipv4.is_none()
        && !target
            .dhcp_client
            .as_ref()
            .is_some_and(|policy| policy.enabled);
    if auto_dhcp {
        if !dhcp_available {
            return Err(WifiClientProfileErrorDetail::ActivationFailed {
                message: "profile activation requires the DHCP client service because the interface has no static IPv4 address".into(),
            });
        }
        let policy = target.dhcp_client.get_or_insert_with(Default::default);
        policy.enabled = true;
        policy.wifi_owned = true;
    }
    validate_wifi_client_interface(interface, &target)
        .map_err(|message| WifiClientProfileErrorDetail::InvalidProfile { message })?;
    target.wifi_client = Some(WifiClientConfig {
        ssid: profile.ssid.clone(),
        country_code: profile.country_code.clone(),
        security: profile.security,
        passphrase_file: None,
    });
    target
        .validate(interface)
        .map_err(|error| WifiClientProfileErrorDetail::InvalidProfile {
            message: error.to_string(),
        })?;
    Ok((target, auto_dhcp))
}

impl ControlService {
    pub(super) async fn provision_wifi_client(
        &self,
        interface: String,
        settings: crate::api::model::ProvisionWifiClientRequest,
    ) -> Response {
        use crate::api::model::WifiClientIpPolicy;
        use crate::wifi::secret::WifiPassphraseUpdate;
        let Some(wifi_client) = &self.wifi_client else {
            return wifi_client_disabled();
        };
        let effective = match self.effective_config().await {
            Ok(config) => config,
            Err(message) => return wifi_client_error(WifiClientErrorDetail::Other { message }),
        };
        let previous = effective.network.interfaces.get(&interface);
        if !previous.is_some_and(|config| config.managed && config.role == InterfaceRole::Input) {
            return wifi_client_error(WifiClientErrorDetail::InvalidSpec {
                message: "Wi-Fi client provisioning requires a managed input interface; assign its role first".into(),
            });
        }
        if let Err(error) = wifi_client.preflight_binary().await {
            return classify_wifi_client_error(error);
        }
        let profile = match self
            .wifi_client_profiles
            .get_async(&settings.profile_id)
            .await
        {
            Ok(profile) => profile,
            Err(error) => return classify_wifi_client_profile_error(error),
        };
        let secret = match self
            .wifi_client_profiles
            .get_passphrase_async(&settings.profile_id)
            .await
        {
            Ok(secret) => secret,
            Err(error) => return classify_wifi_client_profile_error(error),
        };
        let mut target = previous.cloned().expect("validated input interface");
        target.managed = true;
        target.wifi = None;
        target.dhcp = None;
        match settings.ip_policy {
            WifiClientIpPolicy::Preserve => {}
            WifiClientIpPolicy::Dhcp => {
                target.ipv4 = None;
                let policy = target.dhcp_client.get_or_insert_with(Default::default);
                policy.enabled = true;
                policy.wifi_owned = false;
            }
            WifiClientIpPolicy::Static { cidr } => {
                target.ipv4 = Some(cidr);
                if let Some(policy) = target.dhcp_client.as_mut() {
                    policy.enabled = false;
                }
            }
        }
        if let Err(message) = validate_wifi_client_interface(&interface, &target) {
            return wifi_client_error(WifiClientErrorDetail::InvalidSpec { message });
        }
        target.wifi_client = Some(WifiClientConfig {
            ssid: profile.ssid,
            country_code: profile.country_code,
            security: profile.security,
            passphrase_file: None,
        });
        let update = secret
            .map(WifiPassphraseUpdate::Set)
            .unwrap_or(WifiPassphraseUpdate::Clear);
        match self
            .transactions
            .apply(
                &interface,
                InterfaceChange {
                    config: &target,
                    previous,
                    current_role: previous.map(|config| config.role),
                    allow_management_change: true,
                    passphrase: update,
                },
            )
            .await
        {
            Ok(change) => Response::NetworkChangePending { change },
            Err(error) => super::runtime::error_response(error),
        }
    }

    pub(super) async fn wifi_client_status(&self) -> Response {
        let Some(wifi_client) = &self.wifi_client else {
            return wifi_client_disabled();
        };
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(message) => return wifi_client_error(WifiClientErrorDetail::Other { message }),
        };
        let mut interfaces = Vec::new();
        for (name, config) in &effective.network.interfaces {
            if config.wifi_client.is_some() {
                if let Some(status) = wifi_client.status(name).await {
                    interfaces.push(status);
                }
            }
        }
        Response::WifiClientStatus {
            interfaces: interfaces.into_iter().map(Into::into).collect(),
        }
    }

    pub(super) async fn get_wifi_client_config(&self, interface: String) -> Response {
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(message) => return wifi_client_error(WifiClientErrorDetail::Other { message }),
        };
        let spec = match effective.network.interfaces.get(&interface) {
            Some(config) => match WifiClientSpec::from_interface_config(&interface, config) {
                Ok(spec) => spec,
                Err(error) => {
                    return wifi_client_error(WifiClientErrorDetail::InvalidSpec {
                        message: error.to_string(),
                    })
                }
            },
            None => None,
        };
        Response::WifiClientConfig {
            interface,
            spec: spec.map(Into::into),
        }
    }

    pub(super) async fn configure_wifi_client(
        &self,
        interface: String,
        settings: WifiClientEditRequest,
    ) -> Response {
        let Some(wifi_client) = &self.wifi_client else {
            return wifi_client_disabled();
        };
        // See `configure_wifi`: the supervisor is built unconditionally, so the
        // binary is verified at the point of use.
        if let Err(error) = wifi_client.preflight_binary().await {
            return wifi_client_error(WifiClientErrorDetail::Other {
                message: error.to_string(),
            });
        }
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(message) => return wifi_client_error(WifiClientErrorDetail::Other { message }),
        };
        let Some(mut interface_config) = effective.network.interfaces.get(&interface).cloned()
        else {
            return wifi_client_error(WifiClientErrorDetail::InterfaceNotFound);
        };

        if let Err(message) = validate_wifi_client_interface(&interface, &interface_config) {
            return wifi_client_error(WifiClientErrorDetail::InvalidSpec { message });
        }

        let previous_passphrase_file = interface_config
            .wifi_client
            .as_ref()
            .and_then(|c| c.passphrase_file.clone());
        let mut next = wifi_client_edit_request_to_config(settings);
        if next.security.requires_passphrase() {
            next.passphrase_file = previous_passphrase_file;
        }
        interface_config.wifi_client = Some(next);

        let spec = match WifiClientSpec::from_interface_config(&interface, &interface_config) {
            Ok(Some(spec)) => spec,
            Ok(None) => {
                return wifi_client_error(WifiClientErrorDetail::InvalidSpec {
                    message: format!(
                        "a Wi-Fi client requires a managed input interface on '{interface}'"
                    ),
                })
            }
            Err(error) => {
                return wifi_client_error(WifiClientErrorDetail::InvalidSpec {
                    message: error.to_string(),
                })
            }
        };

        if let Err(error) = wifi_client.validate_configuration(&spec).await {
            return classify_wifi_client_error(error);
        }
        let previous = effective.network.interfaces.get(&interface);
        let update = if spec.requires_passphrase() {
            WifiPassphraseUpdate::Keep
        } else {
            WifiPassphraseUpdate::Clear
        };
        match self
            .transactions
            .apply(
                &interface,
                InterfaceChange {
                    config: &interface_config,
                    previous,
                    current_role: previous.map(|config| config.role),
                    allow_management_change: false,
                    passphrase: update,
                },
            )
            .await
        {
            Ok(change) => Response::NetworkChangePending { change },
            Err(error) => super::runtime::error_response(error),
        }
    }

    pub(super) async fn disable_wifi_client(&self, interface: String) -> Response {
        match self.missing_wifi_edit(&interface, true, true, None).await {
            Ok(Some(response)) => return response,
            Ok(None) => {}
            Err(error) => return super::runtime::error_response(error),
        }

        if self.wifi_client.is_none() {
            return wifi_client_disabled();
        }
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(message) => return wifi_client_error(WifiClientErrorDetail::Other { message }),
        };
        let Some(previous) = effective.network.interfaces.get(&interface) else {
            return wifi_client_error(WifiClientErrorDetail::InterfaceNotFound);
        };
        if previous.wifi_client.is_none() {
            return wifi_client_error(WifiClientErrorDetail::InterfaceNotFound);
        }
        let mut target = previous.clone();
        target.wifi_client = None;
        // DHCP created implicitly for a Wi-Fi profile belongs to that
        // connection and is disabled with it. Independently configured DHCP
        // remains untouched.
        if let Some(policy) = target.dhcp_client.as_mut() {
            if policy.wifi_owned {
                policy.enabled = false;
                policy.wifi_owned = false;
            }
        }
        match self
            .transactions
            .apply(
                &interface,
                InterfaceChange {
                    config: &target,
                    previous: Some(previous),
                    current_role: Some(previous.role),
                    allow_management_change: true,
                    // Saved client credentials survive deactivation.
                    passphrase: WifiPassphraseUpdate::Keep,
                },
            )
            .await
        {
            Ok(change) => {
                let token = change.token.clone();
                self.pending_wifi_client_deactivations
                    .lock()
                    .await
                    .insert(token.clone(), interface);
                // Automatic timeout rollback happens inside the transaction
                // manager and therefore does not pass through dispatch. Retire
                // the post-commit marker after the confirmation window so a
                // timed-out deactivation cannot leak state indefinitely.
                let pending = self.pending_wifi_client_deactivations.clone();
                let transactions = self.transactions.clone();
                let mutations = self.network_mutations.clone();
                let cleanup_after = std::time::Duration::from_secs(
                    change.rollback_timeout_seconds.saturating_add(1),
                );
                tokio::spawn(async move {
                    tokio::time::sleep(cleanup_after).await;
                    loop {
                        // Serialize marker retirement with commit dispatch, which
                        // consumes the marker after the transaction is removed.
                        let admission = mutations.admit().await;
                        let still_committable = transactions
                            .pending()
                            .await
                            .into_iter()
                            .find(|change| change.token == token)
                            .is_some_and(|change| change.can_commit());
                        if !still_committable {
                            pending.lock().await.remove(&token);
                            break;
                        }
                        // The rollback timer can be delayed behind another
                        // serialized network operation. Do not retire the
                        // marker while a late commit is still legally possible.
                        drop(admission);
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                });
                Response::NetworkChangePending { change }
            }
            Err(error) => super::runtime::error_response(error),
        }
    }

    pub(super) async fn disable_wifi_client_locked(&self, interface: String) -> Response {
        let Some(wifi_client) = &self.wifi_client else {
            return wifi_client_disabled();
        };
        let _dhcp_mutation = if self.dhcp_client.is_some() {
            Some(self.dhcp_client_mutations.lock().await)
        } else {
            None
        };

        let committed = match self.overrides.effective_interface(&interface).await {
            Ok(config) => config,
            Err(error) => {
                return wifi_client_error(WifiClientErrorDetail::Other {
                    message: error.to_string(),
                });
            }
        };
        let Some(mut interface_config) = committed else {
            // Without persisted provenance this subsystem cannot claim DHCP ownership.
            return match wifi_client.disable(&interface).await {
                Ok(_) => Response::WifiClientDisabled { interface },
                Err(error) => classify_wifi_client_error(error),
            };
        };

        let owns_dhcp = interface_config
            .dhcp_client
            .as_ref()
            .is_some_and(|policy| policy.wifi_owned);
        let had_enabled_dhcp = interface_config
            .dhcp_client
            .as_ref()
            .is_some_and(|c| c.enabled);
        let previous_dhcp_spec = if had_enabled_dhcp {
            match DhcpClientSpec::from_interface_config(&interface, &interface_config) {
                Ok(spec) => spec,
                Err(error) => {
                    return wifi_client_error(WifiClientErrorDetail::Other {
                        message: format!("invalid committed DHCP client state: {error:#}"),
                    })
                }
            }
        } else {
            None
        };

        interface_config.wifi_client = None;

        let previous_status = wifi_client.status(&interface).await;
        let previous_link_ready = previous_status
            .as_ref()
            .is_none_or(|status| status.wpa_state.is_connected());
        let previous = previous_status.map(|status| status.spec);

        let mut previous_dhcp = None;
        if let Some(dhcp_client) = self.dhcp_client.as_ref().filter(|_| owns_dhcp) {
            match dhcp_client.disable(&interface).await {
                Ok(disabled_spec) => {
                    previous_dhcp = disabled_spec.or(previous_dhcp_spec.clone());
                }
                Err(error) => {
                    tracing::warn!(%interface, %error, "failed to disable DHCP client during Wi-Fi disable");
                    let restoration = restore_dhcp_client(
                        dhcp_client,
                        &interface,
                        previous_dhcp_spec.clone(),
                        previous_link_ready,
                    )
                    .await;
                    return wifi_client_error(WifiClientErrorDetail::Other {
                        message: compensation_message(
                            "failed to disable DHCP client",
                            &error,
                            restoration,
                        ),
                    });
                }
            }
        }
        if let Some(policy) = interface_config.dhcp_client.as_mut() {
            if policy.wifi_owned {
                policy.enabled = false;
                policy.wifi_owned = false;
            }
        }

        if let Err(error) = wifi_client.disable(&interface).await {
            let mut rollback_failures = Vec::new();
            if let Some(dhcp_client) = self.dhcp_client.as_ref().filter(|_| owns_dhcp) {
                if let Err(rollback) = restore_dhcp_client(
                    dhcp_client,
                    &interface,
                    previous_dhcp.clone(),
                    previous_link_ready,
                )
                .await
                {
                    rollback_failures.push(format!("DHCP client: {rollback:#}"));
                }
            }
            let restoration = match previous.clone() {
                Some(previous) => wifi_client.configure(previous).await.map(|_| ()),
                None => Ok(()),
            };
            if let Err(rollback) = restoration {
                rollback_failures.push(format!("Wi-Fi client: {rollback:#}"));
            }
            let message = if rollback_failures.is_empty() {
                format!("failed to disable Wi-Fi client: {error}")
            } else {
                format!(
                    "failed to disable Wi-Fi client: {error}; rollback was incomplete: {}; recovery required",
                    rollback_failures.join("; ")
                )
            };
            return wifi_client_error(WifiClientErrorDetail::Other { message });
        }

        if let Err(error) = self
            .overrides
            .set_interface(interface.clone(), interface_config, false)
            .await
        {
            if crate::atomic_file::is_indeterminate_write(&error) {
                return super::runtime::error_response(error);
            }
            let mut rollback_failures = Vec::new();
            let restoration = match previous {
                Some(previous) => wifi_client.configure(previous).await.map(|_| ()),
                None => Ok(()),
            };
            if let Err(rollback) = restoration {
                rollback_failures.push(format!("Wi-Fi client: {rollback:#}"));
            }
            if let Some(dhcp_client) = self.dhcp_client.as_ref().filter(|_| owns_dhcp) {
                if let Err(rollback) =
                    restore_dhcp_client(dhcp_client, &interface, previous_dhcp, previous_link_ready)
                        .await
                {
                    rollback_failures.push(format!("DHCP client: {rollback:#}"));
                }
            }
            let message = if rollback_failures.is_empty() {
                format!("failed to persist Wi-Fi client disable: {error}; prior runtime state was restored")
            } else {
                format!(
                    "failed to persist Wi-Fi client disable: {error}; runtime restoration failed: {}; recovery required",
                    rollback_failures.join("; ")
                )
            };
            return wifi_client_error(WifiClientErrorDetail::Other { message });
        }
        Response::WifiClientDisabled { interface }
    }

    pub(super) async fn wifi_client_set_passphrase(
        &self,
        interface: String,
        passphrase: String,
    ) -> Response {
        match self
            .missing_wifi_edit(&interface, true, false, Some(passphrase.clone()))
            .await
        {
            Ok(Some(response)) => return response,
            Ok(None) => {}
            Err(error) => return super::runtime::error_response(error),
        }

        let Some(wifi_client) = &self.wifi_client else {
            return wifi_client_disabled();
        };
        let passphrase = match WifiPassphrase::new(passphrase) {
            Ok(passphrase) => passphrase,
            Err(error) => {
                return wifi_client_error(WifiClientErrorDetail::InvalidSpec {
                    message: error.to_string(),
                })
            }
        };
        let Some(_) = wifi_client.status(&interface).await else {
            return wifi_client_error(WifiClientErrorDetail::InterfaceNotFound);
        };
        let previous = match self.overrides.effective_interface(&interface).await {
            Ok(Some(config)) => config,
            Ok(None) => return wifi_client_error(WifiClientErrorDetail::InterfaceNotFound),
            Err(error) => return super::runtime::error_response(error),
        };
        let mut next = previous.clone();
        let Some(settings) = &mut next.wifi_client else {
            return wifi_client_error(WifiClientErrorDetail::InterfaceNotFound);
        };
        if !settings.security.requires_passphrase() {
            return wifi_client_error(WifiClientErrorDetail::InvalidSpec {
                message: "an open network cannot use a passphrase".into(),
            });
        }
        settings.passphrase_file = None;
        self.transactions
            .apply(
                &interface,
                crate::core::transaction::InterfaceChange {
                    config: &next,
                    previous: Some(&previous),
                    current_role: Some(previous.role),
                    allow_management_change: true,
                    passphrase: crate::wifi::WifiPassphraseUpdate::Set(passphrase),
                },
            )
            .await
            .map(|change| Response::NetworkChangePending { change })
            .unwrap_or_else(super::runtime::error_response)
    }

    pub(super) async fn list_wifi_client_profiles(&self) -> Response {
        match self.wifi_client_profiles.list_async().await {
            Ok(profiles) => Response::WifiClientProfiles { profiles },
            Err(error) => classify_wifi_client_profile_error(error),
        }
    }

    pub(super) async fn get_wifi_client_profile(&self, id: String) -> Response {
        match self.wifi_client_profiles.get_async(&id).await {
            Ok(profile) => Response::WifiClientProfile { profile },
            Err(error) => classify_wifi_client_profile_error(error),
        }
    }

    pub(super) async fn create_wifi_client_profile(
        &self,
        mut request: WifiClientProfileWriteRequest,
    ) -> Response {
        let mutation = self.wifi_client_mutations.clone().lock_owned().await;
        let passphrase = match request.passphrase.take() {
            Some(raw) => match WifiPassphrase::new(&raw) {
                Ok(passphrase) => Some(passphrase),
                Err(error) => {
                    return wifi_client_profile_error(
                        WifiClientProfileErrorDetail::InvalidProfile {
                            message: error.to_string(),
                        },
                    )
                }
            },
            None => None,
        };
        let input = wifi_client_profile_input(request);
        let store = self.wifi_client_profiles.clone();
        match crate::wifi::store::blocking_store(move || {
            // Keep serialization until the blocking write finishes, even if this request is cancelled.
            let _mutation = mutation;
            store.create(input, passphrase)
        })
        .await
        {
            Ok(profile) => Response::WifiClientProfile { profile },
            Err(error) => classify_wifi_client_profile_error(error),
        }
    }

    pub(super) async fn update_wifi_client_profile(
        &self,
        id: String,
        mut request: WifiClientProfileWriteRequest,
    ) -> Response {
        if request.id != id {
            return wifi_client_profile_error(WifiClientProfileErrorDetail::InvalidProfile {
                message: "profile id in the path and body must match".to_string(),
            });
        }
        if request.clear_passphrase && request.passphrase.is_some() {
            return wifi_client_profile_error(WifiClientProfileErrorDetail::InvalidProfile {
                message: "passphrase and clear_passphrase are mutually exclusive".to_string(),
            });
        }
        let mutation = self.wifi_client_mutations.clone().lock_owned().await;
        let secret_update = if request.clear_passphrase {
            WifiClientProfileSecretUpdate::Clear
        } else if let Some(raw) = request.passphrase.take() {
            match WifiPassphrase::new(&raw) {
                Ok(passphrase) => WifiClientProfileSecretUpdate::Replace(passphrase),
                Err(error) => {
                    return wifi_client_profile_error(
                        WifiClientProfileErrorDetail::InvalidProfile {
                            message: error.to_string(),
                        },
                    )
                }
            }
        } else {
            WifiClientProfileSecretUpdate::Unchanged
        };
        let input = wifi_client_profile_input(request);
        let store = self.wifi_client_profiles.clone();
        match crate::wifi::store::blocking_store(move || {
            // Keep serialization until the blocking write finishes, even if this request is cancelled.
            let _mutation = mutation;
            store.update(input, secret_update)
        })
        .await
        {
            Ok(profile) => Response::WifiClientProfile { profile },
            Err(error) => classify_wifi_client_profile_error(error),
        }
    }

    pub(super) async fn delete_wifi_client_profile(&self, id: String) -> Response {
        let mutation = self.wifi_client_mutations.clone().lock_owned().await;
        let profile = match self.wifi_client_profiles.get_async(&id).await {
            Ok(profile) => profile,
            Err(error) => return classify_wifi_client_profile_error(error),
        };
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(message) => {
                return wifi_client_profile_error(WifiClientProfileErrorDetail::Other { message })
            }
        };
        let mut active = Vec::new();
        for interface in effective.network.interfaces.keys() {
            let status = match &self.wifi_client {
                Some(runtime) => runtime.status(interface).await,
                None => None,
            };
            if let Some(status) = status {
                if status.spec.ssid == profile.ssid
                    && status.spec.country_code == profile.country_code
                    && status.spec.security == profile.security
                {
                    active.push(interface.clone());
                }
            }
        }
        if !active.is_empty() {
            return wifi_client_profile_error(WifiClientProfileErrorDetail::ProfileActive {
                interfaces: active,
            });
        }
        let store = self.wifi_client_profiles.clone();
        let delete_id = id.clone();
        match crate::wifi::store::blocking_store(move || {
            let _mutation = mutation;
            store.delete(&delete_id)
        })
        .await
        {
            Ok(()) => Response::WifiClientProfileDeleted { id },
            Err(error) => classify_wifi_client_profile_error(error),
        }
    }

    pub(super) async fn activate_wifi_client_profile(
        &self,
        interface: String,
        profile_id: String,
    ) -> Response {
        let Some(wifi_client) = &self.wifi_client else {
            return wifi_client_profile_error(WifiClientProfileErrorDetail::WifiClientDisabled);
        };
        if let Err(error) = wifi_client.preflight_binary().await {
            return classify_wifi_client_error(error);
        }
        let profile = match self.wifi_client_profiles.get_async(&profile_id).await {
            Ok(profile) => profile,
            Err(error) => return classify_wifi_client_profile_error(error),
        };
        let secret = match self
            .wifi_client_profiles
            .get_passphrase_async(&profile_id)
            .await
        {
            Ok(secret) => secret,
            Err(error) => return classify_wifi_client_profile_error(error),
        };
        let effective = match self.effective_config().await {
            Ok(config) => config,
            Err(message) => {
                return wifi_client_profile_error(WifiClientProfileErrorDetail::Other { message })
            }
        };
        let Some(previous) = effective.network.interfaces.get(&interface) else {
            return wifi_client_profile_error(WifiClientProfileErrorDetail::InterfaceNotFound);
        };
        let (target, _) = match profile_activation_target(
            &interface,
            previous,
            &profile,
            self.dhcp_client.is_some(),
        ) {
            Ok(target) => target,
            Err(detail) => return wifi_client_profile_error(detail),
        };
        let update = secret
            .map(WifiPassphraseUpdate::Set)
            .unwrap_or(WifiPassphraseUpdate::Clear);
        match self
            .transactions
            .apply(
                &interface,
                InterfaceChange {
                    config: &target,
                    previous: Some(previous),
                    current_role: Some(previous.role),
                    allow_management_change: false,
                    passphrase: update,
                },
            )
            .await
        {
            Ok(change) => {
                self.wifi_autoconnect.lock().await.resume(&interface);
                Response::NetworkChangePending { change }
            }
            Err(error) => super::runtime::error_response(error),
        }
    }

    /// Internal autoconnect only; caller holds network admission/execution and
    /// the client mutation lock. Operator requests use commit-confirm above.
    pub(super) async fn activate_wifi_client_profile_internal(
        &self,
        interface: String,
        profile_id: String,
    ) -> Response {
        let Some(wifi_client) = &self.wifi_client else {
            return wifi_client_profile_error(WifiClientProfileErrorDetail::WifiClientDisabled);
        };
        let profile = match self.wifi_client_profiles.get_async(&profile_id).await {
            Ok(profile) => profile,
            Err(error) => return classify_wifi_client_profile_error(error),
        };
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(message) => {
                return wifi_client_profile_error(WifiClientProfileErrorDetail::Other { message })
            }
        };
        let Some(previous) = effective.network.interfaces.get(&interface) else {
            return wifi_client_profile_error(WifiClientProfileErrorDetail::InterfaceNotFound);
        };
        let (interface_config, auto_enabled_dhcp) = match profile_activation_target(
            &interface,
            previous,
            &profile,
            self.dhcp_client.is_some(),
        ) {
            Ok(target) => target,
            Err(detail) => return wifi_client_profile_error(detail),
        };
        if let Err(error) = crate::core::wifi_profile_activation::activate(
            wifi_client,
            self.dhcp_client.as_ref(),
            &self.overrides,
            self.network.as_ref(),
            &effective.network,
            &interface,
            interface_config,
            auto_enabled_dhcp,
            match self
                .wifi_client_profiles
                .get_passphrase_async(&profile_id)
                .await
            {
                Ok(secret) => secret,
                Err(error) => return classify_wifi_client_profile_error(error),
            },
        )
        .await
        {
            return match error {
                crate::core::wifi_profile_activation::ActivationError::Invalid(message) => {
                    wifi_client_profile_error(WifiClientProfileErrorDetail::InvalidProfile {
                        message,
                    })
                }
                crate::core::wifi_profile_activation::ActivationError::Activation(message) => {
                    wifi_client_profile_error(WifiClientProfileErrorDetail::ActivationFailed {
                        message,
                    })
                }
                crate::core::wifi_profile_activation::ActivationError::Persistence(error) => {
                    if crate::atomic_file::is_indeterminate_write(&error) {
                        super::runtime::error_response(error)
                    } else {
                        wifi_client_profile_error(WifiClientProfileErrorDetail::PersistenceFailed {
                            message: error.to_string(),
                        })
                    }
                }
            };
        }
        match wifi_client.status(&interface).await {
            Some(status) => Response::WifiClientProfileActivated {
                phase: self.wifi_client_activation_phase(&interface, &status).await,
                interface,
                profile,
                status: status.into(),
            },
            None => wifi_client_profile_error(WifiClientProfileErrorDetail::ActivationFailed {
                message: "supplicant disappeared after profile activation".to_string(),
            }),
        }
    }

    async fn wifi_client_activation_phase(
        &self,
        interface: &str,
        status: &crate::wifi::WifiClientStatus,
    ) -> crate::api::model::WifiClientActivationPhase {
        use crate::api::model::WifiClientActivationPhase as Phase;
        if !status.wpa_state.is_connected() {
            return Phase::ActivationStarted;
        }
        if let Ok(Some(config)) = self.overrides.effective_interface(interface).await {
            if config
                .dhcp_client
                .as_ref()
                .is_some_and(|policy| policy.enabled)
            {
                if let Some(dhcp) = &self.dhcp_client {
                    if let Some(lease) =
                        dhcp.status(interface).await.and_then(|status| status.lease)
                    {
                        if dhcp.verify_bound_lease(&lease).await.is_ok() {
                            return Phase::IpReady;
                        }
                    }
                }
            } else if let Some(ip) = config.ipv4 {
                if self
                    .network
                    .list_ipv4_addresses(interface)
                    .await
                    .is_ok_and(|addresses| {
                        addresses.iter().any(|address| {
                            address.address == ip.addr() && address.prefix_len == ip.prefix_len()
                        })
                    })
                {
                    return Phase::IpReady;
                }
            }
        }
        Phase::Associated
    }

    pub(super) async fn wifi_client_scan(&self, interface: String) -> Response {
        let effective = match self.effective_config().await {
            Ok(config) => config,
            Err(message) => return wifi_client_error(WifiClientErrorDetail::Other { message }),
        };
        if let Err(error) = crate::wifi::policy::WifiRadioPolicy::validate_scan(
            &effective.network,
            &interface,
            |name| self.network.wireless_phy(name),
        ) {
            return wifi_client_error(WifiClientErrorDetail::InvalidSpec {
                message: error.to_string(),
            });
        }
        if effective
            .network
            .interfaces
            .get(&interface)
            .is_some_and(|config| config.wifi.is_some())
        {
            return wifi_client_error(WifiClientErrorDetail::InvalidSpec {
                message: format!("scanning is unavailable while interface {interface} is configured as an access point"),
            });
        }
        let Some(wifi_client) = &self.wifi_client else {
            return wifi_client_disabled();
        };
        if let Err(error) = wifi_client.preflight_binary().await {
            return classify_wifi_client_error(error);
        }
        let interfaces = match self.network.list_interfaces().await {
            Ok(interfaces) => interfaces,
            Err(error) => {
                return Response::Error {
                    message: error.to_string(),
                };
            }
        };
        if !interfaces.is_empty() {
            let Some(target) = interfaces.iter().find(|i| i.name == interface) else {
                return wifi_client_error(WifiClientErrorDetail::InterfaceNotFound);
            };
            if !target.is_wireless {
                return wifi_client_error(WifiClientErrorDetail::NotWireless);
            }
        }
        if let Some(wifi) = &self.wifi {
            if wifi.status(&interface).await.is_some() {
                return wifi_client_error(WifiClientErrorDetail::InvalidSpec {
                    message: format!(
                        "interface {interface} is currently operating as an access point"
                    ),
                });
            }
        }
        match wifi_client.scan(&interface).await {
            Ok(results) => Response::WifiClientScanResults { interface, results },
            Err(error) => classify_wifi_client_error(error),
        }
    }

    pub(super) async fn wifi_client_reconnect(&self, interface: String) -> Response {
        let Some(wifi_client) = &self.wifi_client else {
            return wifi_client_disabled();
        };
        let _mutation = self.wifi_client_mutations.lock().await;
        if let Err(error) = wifi_client.reconnect(&interface).await {
            return classify_wifi_client_error(error);
        }
        self.wifi_autoconnect.lock().await.resume(&interface);

        match wifi_client.status(&interface).await {
            Some(status) => Response::WifiClientConfigured {
                spec: status.spec.into(),
            },
            None => wifi_client_error(WifiClientErrorDetail::InterfaceNotFound),
        }
    }
}

pub(super) fn wifi_client_disabled() -> Response {
    Response::WifiClientError {
        detail: WifiClientErrorDetail::WifiClientDisabled,
    }
}

pub(super) fn wifi_client_profile_input(
    request: WifiClientProfileWriteRequest,
) -> WifiClientProfileInput {
    WifiClientProfileInput {
        id: request.id,
        ssid: request.ssid,
        country_code: request.country_code,
        security: request.security,
        priority: request.priority,
        autoconnect: request.autoconnect,
    }
}

pub(super) fn wifi_client_profile_error(detail: WifiClientProfileErrorDetail) -> Response {
    Response::WifiClientProfileError { detail }
}

pub(super) fn classify_wifi_client_profile_error(error: WifiClientProfileError) -> Response {
    tracing::warn!(error = %error, "Wi-Fi client profile request failed");
    let detail = match error {
        WifiClientProfileError::InvalidId | WifiClientProfileError::InvalidProfile(_) => {
            WifiClientProfileErrorDetail::InvalidProfile {
                message: error.to_string(),
            }
        }
        WifiClientProfileError::AlreadyExists => WifiClientProfileErrorDetail::ProfileAlreadyExists,
        WifiClientProfileError::NotFound => WifiClientProfileErrorDetail::ProfileNotFound,
        WifiClientProfileError::Passphrase(_) => WifiClientProfileErrorDetail::InvalidProfile {
            message: error.to_string(),
        },
        WifiClientProfileError::Io(_)
        | WifiClientProfileError::Errno(_)
        | WifiClientProfileError::Json(_)
        | WifiClientProfileError::UnsupportedVersion(_)
        | WifiClientProfileError::SymlinkRejected(_)
        | WifiClientProfileError::UnsafeDirectory(_)
        | WifiClientProfileError::RollbackFailed { .. } => {
            WifiClientProfileErrorDetail::PersistenceFailed {
                message: error.to_string(),
            }
        }
    };
    wifi_client_profile_error(detail)
}

pub(super) fn wifi_client_error(detail: WifiClientErrorDetail) -> Response {
    Response::WifiClientError { detail }
}

pub(super) fn classify_wifi_client_error(error: ClientSupervisorError) -> Response {
    tracing::warn!(error = %error, "Wi-Fi client request failed");
    let detail = match error {
        ClientSupervisorError::NotConfigured { .. } => WifiClientErrorDetail::InterfaceNotFound,
        ClientSupervisorError::NotOwned { diagnostics, .. } => WifiClientErrorDetail::Other {
            message: diagnostics,
        },
        ClientSupervisorError::BinaryPreflight(
            crate::wifi::lifecycle::BinaryPreflightError::NotFound { .. },
        ) => WifiClientErrorDetail::WpaSupplicantMissing,
        ClientSupervisorError::BinaryPreflight(error) => {
            WifiClientErrorDetail::WpaSupplicantFailed {
                message: error.to_string(),
            }
        }
        ClientSupervisorError::StartupTimeout { .. } => WifiClientErrorDetail::CtrlTimeout,
        ClientSupervisorError::ScanBusy { .. } => WifiClientErrorDetail::ScanBusy,
        ClientSupervisorError::ScanTimeout { .. } => WifiClientErrorDetail::ScanTimeout,
        ClientSupervisorError::Ctrl(CtrlError::Timeout(_)) => WifiClientErrorDetail::CtrlTimeout,
        ClientSupervisorError::Ctrl(CtrlError::Io(_)) => WifiClientErrorDetail::CtrlUnavailable,
        ClientSupervisorError::Ctrl(error @ CtrlError::MalformedReply(_))
        | ClientSupervisorError::Ctrl(error @ CtrlError::UnknownCommand(_))
        | ClientSupervisorError::Ctrl(error @ CtrlError::InvalidMacAddr(_)) => {
            WifiClientErrorDetail::ProtocolFailure {
                message: error.to_string(),
            }
        }
        ClientSupervisorError::Ctrl(error) => WifiClientErrorDetail::WpaSupplicantFailed {
            message: error.to_string(),
        },
        ClientSupervisorError::Process(ProcessError::Spawn { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            WifiClientErrorDetail::WpaSupplicantMissing
        }
        ClientSupervisorError::Process(error) => WifiClientErrorDetail::WpaSupplicantFailed {
            message: error.to_string(),
        },
        ClientSupervisorError::Render(ClientRenderError::PassphraseRequired { .. }) => {
            WifiClientErrorDetail::PassphraseMissing
        }
        ClientSupervisorError::Render(error) => WifiClientErrorDetail::InvalidSpec {
            message: error.to_string(),
        },
        ClientSupervisorError::ResolvePassphrase(ResolvePassphraseError::Empty(_)) => {
            WifiClientErrorDetail::PassphraseMissing
        }
        ClientSupervisorError::ResolvePassphrase(error) => WifiClientErrorDetail::Other {
            message: error.to_string(),
        },
        ClientSupervisorError::Record(error) => WifiClientErrorDetail::Other {
            message: error.to_string(),
        },
        ClientSupervisorError::Configuration(error) => WifiClientErrorDetail::InvalidSpec {
            message: error.to_string(),
        },
    };
    Response::WifiClientError { detail }
}

pub(super) fn wifi_client_edit_request_to_config(
    settings: WifiClientEditRequest,
) -> WifiClientConfig {
    WifiClientConfig {
        ssid: settings.ssid,
        country_code: settings.country_code,
        security: settings.security,
        passphrase_file: None,
    }
}

#[cfg(test)]
mod ownership_diagnostics_tests {
    use super::*;

    #[test]
    fn ownership_diagnostics_are_returned_to_the_user() {
        let response = classify_wifi_client_error(ClientSupervisorError::NotOwned {
            interface: "wlan0".into(),
            diagnostics: "Socket /run/wpa_supplicant/wlan0 is held by wpa_supplicant PID 42; inspect its service".into(),
        });
        let Response::WifiClientError {
            detail: WifiClientErrorDetail::Other { message },
        } = response
        else {
            panic!("expected actionable ownership diagnostics");
        };
        assert!(message.contains("PID 42"));
        assert!(message.contains("inspect its service"));
    }
}
