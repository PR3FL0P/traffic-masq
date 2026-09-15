use super::*;

impl ControlService {
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
        Response::WifiClientStatus { interfaces }
    }

    pub(super) async fn get_wifi_client_config(&self, interface: String) -> Response {
        if self.wifi_client.is_none() {
            return wifi_client_disabled();
        }
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
        Response::WifiClientConfig { interface, spec }
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

        interface_config.wifi_client = Some(wifi_client_edit_request_to_config(settings));

        let spec = match WifiClientSpec::from_interface_config(&interface, &interface_config) {
            Ok(Some(spec)) => spec,
            Ok(None) => {
                return wifi_client_error(WifiClientErrorDetail::InvalidSpec {
                    message: "a Wi-Fi client requires an unmanaged input interface".to_string(),
                })
            }
            Err(error) => {
                return wifi_client_error(WifiClientErrorDetail::InvalidSpec {
                    message: error.to_string(),
                })
            }
        };

        let _mutation = self.wifi_client_mutations.lock().await;
        let previous = wifi_client
            .status(&interface)
            .await
            .map(|status| status.spec);
        if let Err(error) = wifi_client.configure(spec.clone()).await {
            return classify_wifi_client_error(error);
        }
        if let Err(error) = self
            .overrides
            .set_interface(interface.clone(), interface_config, false)
            .await
        {
            let restoration = match previous {
                Some(previous) => wifi_client.configure(previous).await.map(|_| ()),
                None => wifi_client.disable(&interface).await.map(|_| ()),
            };
            return wifi_client_error(WifiClientErrorDetail::Other {
                message: compensation_message(
                    "failed to persist Wi-Fi client override",
                    &error,
                    restoration,
                ),
            });
        }
        Response::WifiClientConfigured { spec }
    }

    pub(super) async fn disable_wifi_client(&self, interface: String) -> Response {
        let Some(wifi_client) = &self.wifi_client else {
            return wifi_client_disabled();
        };
        let _mutation = self.wifi_client_mutations.lock().await;
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
            let mut previous_dhcp = None;
            if let Some(dhcp_client) = &self.dhcp_client {
                match dhcp_client.disable(&interface).await {
                    Ok(spec) => previous_dhcp = spec,
                    Err(error) => {
                        return wifi_client_error(WifiClientErrorDetail::Other {
                            message: format!("failed to disable DHCP client: {error}"),
                        });
                    }
                }
            }
            if let Err(error) = wifi_client.disable(&interface).await {
                if let (Some(dhcp_client), Some(previous_dhcp)) = (&self.dhcp_client, previous_dhcp)
                {
                    let _ = dhcp_client
                        .configure_with_link_ready(previous_dhcp, false)
                        .await;
                }
                return classify_wifi_client_error(error);
            }
            return Response::WifiClientDisabled { interface };
        };

        let had_enabled_dhcp = interface_config
            .dhcp_client
            .as_ref()
            .is_some_and(|c| c.enabled);
        let previous_dhcp_spec = if had_enabled_dhcp {
            DhcpClientSpec::from_interface_config(&interface, &interface_config)
                .ok()
                .flatten()
        } else {
            None
        };

        interface_config.wifi_client = None;

        let mut previous_dhcp = None;
        if let Some(dhcp_client) = &self.dhcp_client {
            match dhcp_client.disable(&interface).await {
                Ok(disabled_spec) => {
                    previous_dhcp = disabled_spec.or(previous_dhcp_spec.clone());
                }
                Err(error) => {
                    tracing::warn!(%interface, %error, "failed to disable DHCP client during Wi-Fi disable");
                    if let Some(previous_dhcp) = previous_dhcp_spec {
                        let _ = dhcp_client
                            .configure_with_link_ready(previous_dhcp, false)
                            .await;
                    }
                    return wifi_client_error(WifiClientErrorDetail::Other {
                        message: format!("failed to disable DHCP client: {error}"),
                    });
                }
            }
        }
        if had_enabled_dhcp {
            interface_config.dhcp_client = Some(dhcp_client_request_to_config(
                &DhcpClientConfigRequest::default(),
                false,
            ));
            interface_config.managed = false;
        }

        let previous = wifi_client
            .status(&interface)
            .await
            .map(|status| status.spec);

        if let Err(error) = wifi_client.disable(&interface).await {
            if let (Some(dhcp_client), Some(previous_dhcp)) = (&self.dhcp_client, previous_dhcp) {
                let _ = dhcp_client
                    .configure_with_link_ready(previous_dhcp, false)
                    .await;
            }
            return classify_wifi_client_error(error);
        }

        if let Err(error) = self
            .overrides
            .set_interface(interface.clone(), interface_config, false)
            .await
        {
            let restoration = match previous {
                Some(previous) => wifi_client.configure(previous).await.map(|_| ()),
                None => Ok(()),
            };
            if let (Some(dhcp_client), Some(previous_dhcp)) = (&self.dhcp_client, previous_dhcp) {
                let _ = dhcp_client
                    .configure_with_link_ready(previous_dhcp, false)
                    .await;
            }
            return wifi_client_error(WifiClientErrorDetail::Other {
                message: compensation_message(
                    "failed to persist Wi-Fi client disable",
                    &error,
                    restoration,
                ),
            });
        }
        Response::WifiClientDisabled { interface }
    }

    pub(super) async fn wifi_client_set_passphrase(
        &self,
        interface: String,
        passphrase: String,
    ) -> Response {
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
        if let Err(error) = wifi_client.set_passphrase(&interface, &passphrase).await {
            return classify_wifi_client_error(error);
        }

        let Some(status) = wifi_client.status(&interface).await else {
            return wifi_client_error(WifiClientErrorDetail::InterfaceNotFound);
        };
        let spec = status.spec;
        match wifi_client.configure(spec.clone()).await {
            Ok(()) => Response::WifiClientConfigured { spec },
            Err(error) => classify_wifi_client_error(error),
        }
    }

    pub(super) async fn list_wifi_client_profiles(&self) -> Response {
        if self.wifi_client.is_none() {
            return wifi_client_profile_error(WifiClientProfileErrorDetail::WifiClientDisabled);
        }
        match self.wifi_client_profiles.list() {
            Ok(profiles) => Response::WifiClientProfiles { profiles },
            Err(error) => classify_wifi_client_profile_error(error),
        }
    }

    pub(super) async fn get_wifi_client_profile(&self, id: String) -> Response {
        if self.wifi_client.is_none() {
            return wifi_client_profile_error(WifiClientProfileErrorDetail::WifiClientDisabled);
        }
        match self.wifi_client_profiles.get(&id) {
            Ok(profile) => Response::WifiClientProfile { profile },
            Err(error) => classify_wifi_client_profile_error(error),
        }
    }

    pub(super) async fn create_wifi_client_profile(
        &self,
        mut request: WifiClientProfileWriteRequest,
    ) -> Response {
        if self.wifi_client.is_none() {
            return wifi_client_profile_error(WifiClientProfileErrorDetail::WifiClientDisabled);
        }
        let _mutation = self.wifi_client_mutations.lock().await;
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
        match self.wifi_client_profiles.create(input, passphrase) {
            Ok(profile) => Response::WifiClientProfile { profile },
            Err(error) => classify_wifi_client_profile_error(error),
        }
    }

    pub(super) async fn update_wifi_client_profile(
        &self,
        id: String,
        mut request: WifiClientProfileWriteRequest,
    ) -> Response {
        if self.wifi_client.is_none() {
            return wifi_client_profile_error(WifiClientProfileErrorDetail::WifiClientDisabled);
        }
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
        let _mutation = self.wifi_client_mutations.lock().await;
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
        match self.wifi_client_profiles.update(input, secret_update) {
            Ok(profile) => Response::WifiClientProfile { profile },
            Err(error) => classify_wifi_client_profile_error(error),
        }
    }

    pub(super) async fn delete_wifi_client_profile(&self, id: String) -> Response {
        let Some(wifi_client) = &self.wifi_client else {
            return wifi_client_profile_error(WifiClientProfileErrorDetail::WifiClientDisabled);
        };
        let _mutation = self.wifi_client_mutations.lock().await;
        let profile = match self.wifi_client_profiles.get(&id) {
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
            if let Some(status) = wifi_client.status(interface).await {
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
        match self.wifi_client_profiles.delete(&id) {
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
        let _mutation = self.wifi_client_mutations.lock().await;
        let profile = match self.wifi_client_profiles.get(&profile_id) {
            Ok(profile) => profile,
            Err(error) => return classify_wifi_client_profile_error(error),
        };
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(message) => {
                return wifi_client_profile_error(WifiClientProfileErrorDetail::Other { message })
            }
        };
        let Some(mut interface_config) = effective.network.interfaces.get(&interface).cloned()
        else {
            return wifi_client_profile_error(WifiClientProfileErrorDetail::InterfaceNotFound);
        };
        interface_config.wifi_client = Some(WifiClientConfig {
            ssid: profile.ssid.clone(),
            country_code: profile.country_code.clone(),
            security: profile.security,
            passphrase_file: None,
        });
        let spec = match WifiClientSpec::from_interface_config(&interface, &interface_config) {
            Ok(Some(spec)) => spec,
            Ok(None) | Err(_) => {
                return wifi_client_profile_error(WifiClientProfileErrorDetail::InvalidProfile {
                    message: "profile activation requires an unmanaged input interface".to_string(),
                })
            }
        };

        let previous_status = wifi_client.status(&interface).await;
        let previous_secret = match wifi_client.stored_passphrase(&interface).await {
            Ok(secret) => secret,
            Err(error) => {
                return wifi_client_profile_error(WifiClientProfileErrorDetail::ActivationFailed {
                    message: error.to_string(),
                })
            }
        };
        let profile_secret = match self.wifi_client_profiles.get_passphrase(&profile_id) {
            Ok(secret) => secret,
            Err(error) => return classify_wifi_client_profile_error(error),
        };
        let secret_result = match profile_secret.as_ref() {
            Some(secret) => wifi_client.set_passphrase(&interface, secret).await,
            None => wifi_client.clear_passphrase(&interface).await,
        };
        if let Err(error) = secret_result {
            return wifi_client_profile_error(WifiClientProfileErrorDetail::ActivationFailed {
                message: error.to_string(),
            });
        }
        if let Err(error) = wifi_client.configure(spec).await {
            restore_wifi_client_secret(wifi_client, &interface, previous_secret.as_ref()).await;
            return wifi_client_profile_error(WifiClientProfileErrorDetail::ActivationFailed {
                message: error.to_string(),
            });
        }
        if let Err(error) = self
            .overrides
            .set_interface(interface.clone(), interface_config, false)
            .await
        {
            restore_wifi_client_secret(wifi_client, &interface, previous_secret.as_ref()).await;
            match previous_status {
                Some(previous) => {
                    let _ = wifi_client.configure(previous.spec).await;
                }
                None => {
                    let _ = wifi_client.disable(&interface).await;
                }
            }
            return wifi_client_profile_error(WifiClientProfileErrorDetail::PersistenceFailed {
                message: error.to_string(),
            });
        }
        match wifi_client.status(&interface).await {
            Some(status) => Response::WifiClientProfileActivated {
                interface,
                profile,
                status,
            },
            None => wifi_client_profile_error(WifiClientProfileErrorDetail::ActivationFailed {
                message: "supplicant disappeared after profile activation".to_string(),
            }),
        }
    }

    pub(super) async fn wifi_client_scan(&self, interface: String) -> Response {
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
        if let Err(error) = wifi_client.reconnect(&interface).await {
            return classify_wifi_client_error(error);
        }

        match wifi_client.status(&interface).await {
            Some(status) => Response::WifiClientConfigured { spec: status.spec },
            None => wifi_client_error(WifiClientErrorDetail::InterfaceNotFound),
        }
    }
}
