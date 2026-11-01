use super::*;

impl ControlService {
    pub(super) async fn wifi_inventory(&self) -> Result<Response> {
        let Response::InterfaceInventory {
            revision,
            interfaces,
            observation_error,
            ..
        } = self.interface_inventory().await?
        else {
            unreachable!("interface inventory response");
        };
        let mut entries = Vec::new();
        for interface in interfaces {
            let assigned_wifi = interface
                .configured
                .as_ref()
                .is_some_and(|config| config.wifi.is_some() || config.wifi_client.is_some());
            let observed_wireless = interface
                .observed
                .as_ref()
                .is_some_and(|status| status.interface.is_wireless);
            if !assigned_wifi && !observed_wireless {
                continue;
            }
            let ap_runtime = match &self.wifi {
                Some(runtime) => runtime.status(&interface.name).await.map(Into::into),
                None => None,
            };
            let client_runtime = match &self.wifi_client {
                Some(runtime) => runtime.status(&interface.name).await.map(Into::into),
                None => None,
            };
            entries.push(traffic_masq_protocol::WifiInventoryEntry {
                interface,
                ap_runtime,
                client_runtime,
            });
        }
        Ok(Response::WifiInventory {
            revision,
            ap_execution_available: self.wifi.is_some(),
            client_execution_available: self.wifi_client.is_some(),
            interfaces: entries,
            observation_error,
        })
    }

    /// Resolve a library profile and its secret for a missing managed input. Apply
    /// IPv4 policy while preserving role/management, then save through the offline
    /// revision-fenced intent path. No connection attempt or confirmation timer.
    /// Admission must serialize writes; secret/validation/cleanup failures propagate.
    pub(super) async fn save_wifi_client_profile(
        &self,
        interface: String,
        settings: traffic_masq_protocol::ProvisionWifiClientRequest,
        expected_revision: u64,
    ) -> Result<Response> {
        use traffic_masq_protocol::WifiClientIpPolicy;
        self.check_missing_interface_write(&interface).await?;
        let mut target = self
            .overrides
            .effective_interface(&interface)
            .await?
            .context("interface is not configured")?;
        anyhow::ensure!(target.managed && target.role == InterfaceRole::Input,
            "offline Wi-Fi client provisioning requires a managed input interface; assign its role first");
        let profile = self
            .wifi_client_profiles
            .get_async(&settings.profile_id)
            .await?;
        let secret = self
            .wifi_client_profiles
            .get_passphrase_async(&settings.profile_id)
            .await?;
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
                    policy.wifi_owned = false;
                }
            }
        }
        super::wifi_client::validate_wifi_client_interface(&interface, &target)
            .map_err(anyhow::Error::msg)?;
        target.wifi = None;
        target.dhcp = None;
        target.wifi_client = Some(WifiClientConfig {
            ssid: profile.ssid,
            country_code: profile.country_code,
            security: profile.security,
            passphrase_file: None,
        });
        let response = self
            .save_wifi_interface_with_secret(interface.clone(), target, expected_revision, secret)
            .await?;
        self.wifi_autoconnect.lock().await.resume(&interface);
        Ok(response)
    }

    /// Legacy service actions save missing targets after verified runtime cleanup.
    pub(super) async fn missing_wifi_edit(
        &self,
        interface: &str,
        client: bool,
        disable: bool,
        passphrase: Option<String>,
    ) -> Result<Option<Response>> {
        let _execution = if disable {
            Some(self.network_mutations.execute().await)
        } else {
            None
        };
        if self
            .network
            .list_interfaces()
            .await?
            .iter()
            .any(|entry| entry.name == interface)
        {
            return Ok(None);
        }
        let snapshot = self.overrides.snapshot().await;
        let mut effective = snapshot.effective_config(&self.base_config)?;
        let Some(mut config) = effective.network.interfaces.remove(interface) else {
            return Ok(None);
        };
        if (client && config.wifi_client.is_none()) || (!client && config.wifi.is_none()) {
            return Ok(None);
        }
        if disable {
            if client {
                config.wifi_client = None;
                if let Some(policy) = config
                    .dhcp_client
                    .as_mut()
                    .filter(|policy| policy.wifi_owned)
                {
                    policy.enabled = false;
                    policy.wifi_owned = false;
                }
            } else {
                config.wifi = None;
            }
        }
        self.save_wifi_interface(interface.to_owned(), config, snapshot.revision, passphrase)
            .await
            .map(Some)
    }

    /// Save Wi-Fi intent only for a freshly observed missing configured interface,
    /// preserving role/management. Validate secret and candidate before publication.
    /// A new secret uses an immutable revision directory before the intent commit;
    /// failed/uncertain commits may retain unreferenced credentials for recovery.
    /// Cleanup and repeated absence observation precede revision-fenced persistence.
    /// Caller holds mutation admission; no live apply or confirmation timer.
    pub(super) async fn save_wifi_interface(
        &self,
        interface: String,
        config: InterfaceConfig,
        expected_revision: u64,
        passphrase: Option<String>,
    ) -> Result<Response> {
        self.save_wifi_interface_with_secret(
            interface,
            config,
            expected_revision,
            passphrase.map(WifiPassphrase::new).transpose()?,
        )
        .await
    }

    async fn save_wifi_interface_with_secret(
        &self,
        interface: String,
        mut config: InterfaceConfig,
        expected_revision: u64,
        secret: Option<WifiPassphrase>,
    ) -> Result<Response> {
        self.check_missing_interface_write(&interface).await?;
        let previous = self
            .overrides
            .effective_interface(&interface)
            .await?
            .context("interface is not configured")?;
        anyhow::ensure!(previous.role == config.role && previous.managed == config.managed,
            "offline Wi-Fi edits must preserve interface role and management policy; edit Interfaces first");
        let preliminary = self
            .overrides
            .build_candidate(&RouterIntentProposal::new().set_interface(
                interface.clone(),
                config.clone(),
                false,
            ))
            .await?;
        if preliminary.base_revision() != expected_revision {
            return Err(StaleCandidateError {
                candidate: expected_revision,
                current: preliminary.base_revision(),
            }
            .into());
        }
        let mut credential = None;
        if let Some(secret) = secret.as_ref() {
            let secured = match (&mut config.wifi, &mut config.wifi_client) {
                (Some(ap), None) if ap.security.requires_passphrase() => &mut ap.passphrase_file,
                (None, Some(client)) if client.security.requires_passphrase() => {
                    &mut client.passphrase_file
                }
                _ => anyhow::bail!("a passphrase requires exactly one secured Wi-Fi configuration"),
            };
            // A unique immutable credential precedes the atomic intent commit.
            // Never replace or delete a secret still referenced by older intent.
            let state_dir = self.config.runtime.state_dir.clone();
            let store = crate::wifi::store::blocking_store(move || {
                crate::wifi::store::PassphraseStore::new_revision(&state_dir)
            })
            .await?;
            *secured = Some(store.directory().join(&interface));
            credential = Some((store, secret));
        }
        let proposal = RouterIntentProposal::new().set_interface(interface.clone(), config, false);
        let candidate = self.overrides.build_candidate(&proposal).await?;
        if candidate.base_revision() != expected_revision {
            return Err(StaleCandidateError {
                candidate: expected_revision,
                current: candidate.base_revision(),
            }
            .into());
        }
        if let Some((store, secret)) = credential {
            store.set_async(&interface, secret).await?;
        }
        // Unreferenced versions are harmless after a failed or interrupted commit.
        // Retain them also for an indeterminate commit; either durable outcome can use its secret.
        self.save_missing_interface_intent(interface, proposal, expected_revision)
            .await
    }
}
