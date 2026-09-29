use super::dhcp::{default_dhcp_settings, dhcp_edit_request_to_config};
use super::*;

impl ControlService {
    pub(super) async fn wifi_status(&self) -> Response {
        let Some(wifi) = &self.wifi else {
            return wifi_disabled();
        };
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(message) => return wifi_error(WifiErrorDetail::Other { message }),
        };
        let mut interfaces = Vec::new();
        for (name, config) in &effective.network.interfaces {
            if config.wifi.is_some() {
                if let Some(status) = wifi.status(name).await {
                    interfaces.push(status);
                }
            }
        }
        Response::WifiStatus { interfaces }
    }

    pub(super) async fn get_wifi_config(&self, interface: String) -> Response {
        if self.wifi.is_none() {
            return wifi_disabled();
        }
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(message) => return wifi_error(WifiErrorDetail::Other { message }),
        };
        let spec = match effective.network.interfaces.get(&interface) {
            Some(config) => match WifiApSpec::from_interface_config(&interface, config) {
                Ok(spec) => spec,
                Err(error) => {
                    return wifi_error(WifiErrorDetail::InvalidSpec {
                        message: error.to_string(),
                    })
                }
            },
            None => None,
        };
        Response::WifiConfig { interface, spec }
    }

    pub(super) async fn configure_wifi(
        &self,
        interface: String,
        settings: WifiEditRequest,
    ) -> Response {
        let Some(wifi) = &self.wifi else {
            return wifi_disabled();
        };
        // The supervisor exists even when the daemon started with
        // `wifi.enabled = false`, so the binary has not necessarily been checked
        // yet. Check it here rather than letting the first spawn fail obscurely.
        if let Err(error) = wifi.preflight_binary().await {
            return wifi_error(WifiErrorDetail::Other {
                message: error.to_string(),
            });
        }
        let clear_stored_passphrase = settings.security == WifiSecurity::Open;
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(message) => return wifi_error(WifiErrorDetail::Other { message }),
        };
        let Some(mut interface_config) = effective.network.interfaces.get(&interface).cloned()
        else {
            return wifi_error(WifiErrorDetail::InterfaceNotFound);
        };

        let previous_passphrase_file = interface_config
            .wifi
            .as_ref()
            .and_then(|c| c.passphrase_file.clone());
        let mut next = wifi_edit_request_to_config(settings);
        if next.security.requires_passphrase() {
            next.passphrase_file = previous_passphrase_file;
        }
        interface_config.wifi = Some(next);

        let spec = match WifiApSpec::from_interface_config(&interface, &interface_config) {
            Ok(Some(spec)) => spec,
            Ok(None) => {
                return wifi_error(WifiErrorDetail::InvalidSpec {
                    message: "a Wi-Fi access point requires a managed output interface".to_string(),
                })
            }
            Err(error) => {
                return wifi_error(WifiErrorDetail::InvalidSpec {
                    message: error.to_string(),
                })
            }
        };

        if let Err(error) = wifi.validate_configuration(&spec).await {
            return classify_wifi_error(error);
        }
        let previous = effective.network.interfaces.get(&interface);
        let update = if clear_stored_passphrase {
            WifiPassphraseUpdate::Clear
        } else {
            WifiPassphraseUpdate::Keep
        };
        match self
            .transactions
            .apply_with_passphrase_update(
                &interface,
                &interface_config,
                previous,
                previous.map(|config| config.role),
                false,
                update,
            )
            .await
        {
            Ok(change) => Response::NetworkChangePending { change },
            Err(error) => super::runtime::error_response(error),
        }
    }

    #[allow(clippy::too_many_arguments)] // Mirrors the API request's independent provisioning options.
    pub(super) async fn provision_wifi_access_point(
        &self,
        interface: String,
        settings: WifiEditRequest,
        passphrase: Option<String>,
        clear_passphrase: bool,
        configure_dhcp: bool,
        subnet: Option<ipnet::Ipv4Net>,
        disable_dhcp: bool,
    ) -> Response {
        let Some(wifi) = &self.wifi else {
            return wifi_disabled();
        };
        let passphrase_update =
            match ap_passphrase_update(settings.security, passphrase, clear_passphrase) {
                Ok(update) => update,
                Err(detail) => return wifi_error(detail),
            };
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(message) => return wifi_error(WifiErrorDetail::Other { message }),
        };
        if configure_dhcp && disable_dhcp {
            return wifi_error(WifiErrorDetail::InvalidSpec {
                message: "DHCP enable and disable are mutually exclusive".into(),
            });
        }
        let previous_interface = effective.network.interfaces.get(&interface).cloned();
        if !previous_interface
            .as_ref()
            .is_some_and(|config| config.managed && config.role == InterfaceRole::Output)
        {
            return wifi_error(WifiErrorDetail::InvalidSpec {
                message:
                    "AP provisioning requires a managed output interface; assign its role first"
                        .into(),
            });
        }
        let mut target = previous_interface
            .clone()
            .expect("validated output interface");
        let Some(cidr) = subnet.or(target.ipv4) else {
            return wifi_error(WifiErrorDetail::InvalidSpec {
                message: "AP provisioning requires an IPv4 subnet".into(),
            });
        };
        if let Err(error) = wifi.preflight_binary().await {
            return classify_wifi_error(error);
        }
        target.managed = true;
        target.ipv4 = Some(cidr);
        target.wifi_client = None;
        if let Some(policy) = target.dhcp_client.as_mut() {
            policy.enabled = false;
            policy.wifi_owned = false;
        }
        if disable_dhcp {
            target.dhcp = None;
        }
        target.wifi = Some(wifi_edit_request_to_config(settings));
        if let (Some(next), Some(previous)) = (
            target.wifi.as_mut(),
            previous_interface
                .as_ref()
                .and_then(|config| config.wifi.as_ref()),
        ) {
            next.passphrase_file =
                ap_passphrase_file_update(previous.passphrase_file.as_ref(), &passphrase_update);
        }
        if configure_dhcp {
            let settings = match default_dhcp_settings(cidr) {
                Ok(settings) => settings,
                Err(message) => return wifi_error(WifiErrorDetail::InvalidSpec { message }),
            };
            target.dhcp = Some(dhcp_edit_request_to_config(settings));
        }
        let spec = match WifiApSpec::from_interface_config(&interface, &target) {
            Ok(Some(spec)) => spec,
            Ok(None) => {
                return wifi_error(WifiErrorDetail::InvalidSpec {
                    message: "AP is disabled".into(),
                })
            }
            Err(error) => {
                return wifi_error(WifiErrorDetail::InvalidSpec {
                    message: error.to_string(),
                })
            }
        };
        if let Err(error) = wifi.validate_radio(&spec).await {
            return classify_wifi_error(error);
        }
        if let Err(error) = DhcpServiceSpec::from_interface_config(
            &interface,
            &target,
            self.base_config.dhcp.default_lease_seconds,
        ) {
            return super::runtime::error_response(error);
        }
        // AP provisioning can sever the very connection used to administer the
        // daemon (SSID/security/channel changes are the common case). Keep the
        // converged candidate tentative and reuse the normal interface
        // commit-confirm timer instead of persisting it immediately. The same
        // transaction also journals the passphrase update, so timeout/manual
        // rollback restores both network state and the previous secret.
        let pending = match self
            .transactions
            .apply_with_passphrase_update(
                &interface,
                &target,
                previous_interface.as_ref(),
                previous_interface.as_ref().map(|config| config.role),
                true,
                passphrase_update,
            )
            .await
        {
            Ok(pending) => pending,
            Err(error) => return super::runtime::error_response(error),
        };
        Response::NetworkChangePending { change: pending }
    }

    pub(super) async fn disable_wifi(&self, interface: String) -> Response {
        if self.wifi.is_none() {
            return wifi_disabled();
        }
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(message) => return wifi_error(WifiErrorDetail::Other { message }),
        };
        let Some(previous) = effective.network.interfaces.get(&interface) else {
            return wifi_error(WifiErrorDetail::InterfaceNotFound);
        };
        if previous.wifi.is_none() {
            return wifi_error(WifiErrorDetail::InterfaceNotFound);
        }
        let mut target = previous.clone();
        target.wifi = None;
        match self
            .transactions
            .apply_with_passphrase_update(
                &interface,
                &target,
                Some(previous),
                Some(previous.role),
                true,
                // Removing an AP is the point at which its stored credential
                // becomes obsolete. The transaction journals it first, clears
                // it while tentative, and restores it automatically on rollback.
                WifiPassphraseUpdate::Clear,
            )
            .await
        {
            Ok(change) => Response::NetworkChangePending { change },
            Err(error) => super::runtime::error_response(error),
        }
    }

    pub(super) async fn wifi_set_passphrase(
        &self,
        interface: String,
        passphrase: String,
    ) -> Response {
        let Some(wifi) = &self.wifi else {
            return wifi_disabled();
        };
        let passphrase = match WifiPassphrase::new(passphrase) {
            Ok(passphrase) => passphrase,
            Err(error) => {
                return wifi_error(WifiErrorDetail::InvalidSpec {
                    message: error.to_string(),
                })
            }
        };
        let Some(status) = wifi.status(&interface).await else {
            return wifi_error(WifiErrorDetail::InterfaceNotFound);
        };
        let spec = status.spec;
        let previous_secret = match wifi.stored_passphrase(&interface).await {
            Ok(previous) => previous,
            Err(error) => return classify_wifi_error(error),
        };

        if let Err(error) = wifi.set_passphrase(&interface, &passphrase).await {
            return classify_wifi_error(error);
        }

        match wifi.configure(spec.clone()).await {
            Ok(()) => Response::WifiConfigured { spec },
            Err(error) => {
                let secret_restore = match previous_secret.as_ref() {
                    Some(previous) => wifi.set_passphrase(&interface, previous).await,
                    None => wifi.clear_passphrase(&interface).await,
                };
                if let Err(restore_error) = secret_restore {
                    return wifi_error(WifiErrorDetail::Other {
                        message: format!(
                            "failed to apply Wi-Fi passphrase: {error}; failed to restore previous secret: {restore_error}; recovery required"
                        ),
                    });
                }
                if let Err(restore_error) = wifi.configure(spec).await {
                    return wifi_error(WifiErrorDetail::Other {
                        message: format!(
                            "failed to apply Wi-Fi passphrase: {error}; previous secret was restored but hostapd restoration failed: {restore_error}; recovery required"
                        ),
                    });
                }
                classify_wifi_error(error)
            }
        }
    }

    pub(super) async fn list_wifi_stations(&self, interface: String) -> Response {
        let Some(wifi) = &self.wifi else {
            return wifi_disabled();
        };
        match wifi.stations(&interface).await {
            Ok(stations) => Response::WifiStations {
                interface,
                stations,
            },
            Err(error) => classify_wifi_error(error),
        }
    }

    pub(super) async fn wifi_deauth_station(&self, interface: String, mac: String) -> Response {
        let Some(wifi) = &self.wifi else {
            return wifi_disabled();
        };
        let mac: MacAddr = match mac.parse() {
            Ok(mac) => mac,
            Err(error) => {
                return wifi_error(WifiErrorDetail::InvalidSpec {
                    message: format!("{error}"),
                })
            }
        };
        if let Err(error) = wifi.deauthenticate(&interface, mac).await {
            return classify_wifi_error(error);
        }
        match wifi.stations(&interface).await {
            Ok(stations) => Response::WifiStations {
                interface,
                stations,
            },
            Err(error) => classify_wifi_error(error),
        }
    }

    pub(super) async fn wifi_reload(&self, interface: String) -> Response {
        let Some(wifi) = &self.wifi else {
            return wifi_disabled();
        };
        match wifi.reload(&interface).await {
            Ok(spec) => Response::WifiConfigured { spec },
            Err(error) => classify_wifi_error(error),
        }
    }
}

pub(super) fn ap_passphrase_file_update(
    previous: Option<&std::path::PathBuf>,
    update: &WifiPassphraseUpdate,
) -> Option<std::path::PathBuf> {
    match update {
        WifiPassphraseUpdate::Keep => previous.cloned(),
        WifiPassphraseUpdate::Set(_) | WifiPassphraseUpdate::Clear => None,
    }
}

pub(super) fn ap_passphrase_update(
    security: WifiSecurity,
    passphrase: Option<String>,
    clear_passphrase: bool,
) -> Result<WifiPassphraseUpdate, WifiErrorDetail> {
    if clear_passphrase && passphrase.is_some() {
        return Err(WifiErrorDetail::InvalidSpec {
            message: "passphrase and clear_passphrase are mutually exclusive".to_string(),
        });
    }
    if security == WifiSecurity::Open {
        if passphrase.is_some() {
            return Err(WifiErrorDetail::InvalidSpec {
                message: "an open access point cannot use a passphrase".to_string(),
            });
        }
        // Open mode must actively remove stale per-interface credentials.
        // This also keeps older REST clients safe because clear_passphrase
        // defaults to false when the field is absent.
        return Ok(WifiPassphraseUpdate::Clear);
    }
    if clear_passphrase {
        return Err(WifiErrorDetail::InvalidSpec {
            message: "a secured access point cannot clear its passphrase without a replacement"
                .to_string(),
        });
    }
    match passphrase {
        Some(value) => WifiPassphrase::new(value)
            .map(WifiPassphraseUpdate::Set)
            .map_err(|error| WifiErrorDetail::InvalidSpec {
                message: error.to_string(),
            }),
        None => Ok(WifiPassphraseUpdate::Keep),
    }
}

pub(super) fn wifi_disabled() -> Response {
    Response::WifiError {
        detail: WifiErrorDetail::WifiDisabled,
    }
}

pub(super) fn wifi_error(detail: WifiErrorDetail) -> Response {
    Response::WifiError { detail }
}

pub(super) fn classify_wifi_error(error: SupervisorError) -> Response {
    tracing::warn!(error = %error, "Wi-Fi request failed");
    let detail = match error {
        SupervisorError::NotConfigured { .. } => WifiErrorDetail::InterfaceNotFound,
        SupervisorError::NotOwned { .. } => WifiErrorDetail::NotOwned,
        SupervisorError::BinaryPreflight(
            crate::wifi::lifecycle::BinaryPreflightError::NotFound { .. },
        ) => WifiErrorDetail::HostapdMissing,
        SupervisorError::BinaryPreflight(error) => WifiErrorDetail::HostapdFailed {
            message: error.to_string(),
        },
        SupervisorError::StartupTimeout { .. } => WifiErrorDetail::CtrlTimeout,
        SupervisorError::Ctrl(CtrlError::Timeout(_)) => WifiErrorDetail::CtrlTimeout,
        SupervisorError::Ctrl(error) => WifiErrorDetail::HostapdFailed {
            message: error.to_string(),
        },
        SupervisorError::Process(ProcessError::Spawn { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            WifiErrorDetail::HostapdMissing
        }
        SupervisorError::Process(error) => WifiErrorDetail::HostapdFailed {
            message: error.to_string(),
        },
        SupervisorError::Radio(error) if error.is_unsupported() => WifiErrorDetail::InvalidSpec {
            message: error.to_string(),
        },
        SupervisorError::Radio(error) => WifiErrorDetail::Other {
            message: error.to_string(),
        },
        SupervisorError::Render(RenderError::PassphraseRequired { .. }) => {
            WifiErrorDetail::PassphraseMissing
        }
        SupervisorError::Render(error) => WifiErrorDetail::InvalidSpec {
            message: error.to_string(),
        },
        SupervisorError::ResolvePassphrase(ResolvePassphraseError::Empty(_)) => {
            WifiErrorDetail::PassphraseMissing
        }
        SupervisorError::ResolvePassphrase(error) => WifiErrorDetail::Other {
            message: error.to_string(),
        },
        SupervisorError::Record(error) => WifiErrorDetail::Other {
            message: error.to_string(),
        },
        SupervisorError::Configuration(error) => WifiErrorDetail::InvalidSpec {
            message: error.to_string(),
        },
    };
    Response::WifiError { detail }
}

pub(super) fn wifi_edit_request_to_config(settings: WifiEditRequest) -> WifiApConfig {
    WifiApConfig {
        ssid: settings.ssid,
        country_code: settings.country_code,
        band: settings.band,
        channel: settings.channel,
        channel_width: settings.channel_width,
        security: settings.security,
        hidden: settings.hidden,
        client_isolation: settings.client_isolation,
        max_stations: settings.max_stations,
        passphrase_file: None,
    }
}
