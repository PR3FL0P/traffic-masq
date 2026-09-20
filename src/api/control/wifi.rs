use super::dhcp::{default_dhcp_settings, dhcp_edit_request_to_config};
use super::runtime::compensation_message;
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
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(message) => return wifi_error(WifiErrorDetail::Other { message }),
        };
        let Some(mut interface_config) = effective.network.interfaces.get(&interface).cloned()
        else {
            return wifi_error(WifiErrorDetail::InterfaceNotFound);
        };

        interface_config.wifi = Some(wifi_edit_request_to_config(settings));

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

        let _mutation = self.wifi_mutations.lock().await;
        let previous = wifi.status(&interface).await.map(|status| status.spec);
        if let Err(error) = wifi.configure(spec.clone()).await {
            let restoration = match previous.clone() {
                Some(previous) => wifi.configure(previous).await.map(|_| ()),
                None => wifi.disable(&interface).await.map(|_| ()),
            };
            if let Err(rollback_error) = restoration {
                return wifi_error(WifiErrorDetail::Other {
                    message: format!(
                        "failed to configure Wi-Fi: {error}; runtime restoration failed: {rollback_error}; recovery required"
                    ),
                });
            }
            return classify_wifi_error(error);
        }
        if let Err(error) = self
            .overrides
            .set_interface(interface.clone(), interface_config, false)
            .await
        {
            let restoration = match previous {
                Some(previous) => wifi.configure(previous).await.map(|_| ()),
                None => wifi.disable(&interface).await.map(|_| ()),
            };
            return wifi_error(WifiErrorDetail::Other {
                message: compensation_message(
                    "failed to persist Wi-Fi override",
                    &error,
                    restoration,
                ),
            });
        }
        Response::WifiConfigured { spec }
    }

    pub(super) async fn provision_wifi_access_point(
        &self,
        interface: String,
        settings: WifiEditRequest,
        passphrase: Option<String>,
        configure_dhcp: bool,
    ) -> Response {
        let Some(wifi) = &self.wifi else {
            return wifi_disabled();
        };
        let staged_passphrase = match passphrase {
            Some(value) => match WifiPassphrase::new(value) {
                Ok(value) => Some(value),
                Err(error) => {
                    return wifi_error(WifiErrorDetail::InvalidSpec {
                        message: error.to_string(),
                    })
                }
            },
            None => None,
        };
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(message) => return wifi_error(WifiErrorDetail::Other { message }),
        };
        let Some(previous_interface) = effective.network.interfaces.get(&interface).cloned() else {
            return wifi_error(WifiErrorDetail::InterfaceNotFound);
        };
        let Some(cidr) = previous_interface.ipv4 else {
            return wifi_error(WifiErrorDetail::InvalidSpec {
                message: "AP provisioning requires a configured IPv4 CIDR".to_string(),
            });
        };
        if !previous_interface.managed || previous_interface.role != InterfaceRole::Output {
            return wifi_error(WifiErrorDetail::InvalidSpec {
                message: "AP provisioning requires a managed output interface".to_string(),
            });
        }
        if let Err(error) = wifi.preflight_binary().await {
            return classify_wifi_error(error);
        }
        let mut target = previous_interface.clone();
        target.wifi = Some(wifi_edit_request_to_config(settings));
        if let (Some(next), Some(previous)) =
            (target.wifi.as_mut(), previous_interface.wifi.as_ref())
        {
            next.passphrase_file = previous.passphrase_file.clone();
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
        let dhcp = match DhcpServiceSpec::from_interface_config(
            &interface,
            &target,
            self.base_config.dhcp.default_lease_seconds,
        ) {
            Ok(spec) => spec,
            Err(error) => return super::runtime::error_response(error),
        };
        // The legacy endpoint is an immediate commit, but its runtime and
        // secret changes use the same durable interface transaction protocol.
        let pending = match self
            .transactions
            .apply_with_passphrase(
                &interface,
                &target,
                Some(&previous_interface),
                Some(previous_interface.role),
                false,
                staged_passphrase,
            )
            .await
        {
            Ok(pending) => pending,
            Err(error) => return super::runtime::error_response(error),
        };
        let result = self
            .transactions
            .commit_with(&pending.token, |name, config, allow| {
                self.overrides
                    .commit_interface(name, config, allow, &pending.token)
            })
            .await;
        if let Err(error) = result {
            let restored = self.transactions.rollback(&pending.token).await.map(|_| ());
            return wifi_error(WifiErrorDetail::Other {
                message: compensation_message("failed to commit AP provisioning", &error, restored),
            });
        }
        Response::WifiAccessPointProvisioned {
            spec,
            dhcp: if configure_dhcp { dhcp } else { None },
        }
    }

    pub(super) async fn disable_wifi(&self, interface: String) -> Response {
        let Some(wifi) = &self.wifi else {
            return wifi_disabled();
        };
        let _mutation = self.wifi_mutations.lock().await;
        let previous = wifi.status(&interface).await.map(|status| status.spec);
        let committed = match self.overrides.effective_interface(&interface).await {
            Ok(config) => config,
            Err(error) => {
                return wifi_error(WifiErrorDetail::Other {
                    message: error.to_string(),
                })
            }
        };

        if let Err(error) = wifi.disable(&interface).await {
            let restoration = match previous.clone() {
                Some(previous) => wifi.configure(previous).await.map(|_| ()),
                None => Ok(()),
            };
            return wifi_error(WifiErrorDetail::Other {
                message: compensation_message(
                    "failed to disable Wi-Fi access point",
                    &error,
                    restoration,
                ),
            });
        }

        let Some(mut interface_config) = committed else {
            return Response::WifiDisabled { interface };
        };
        interface_config.wifi = None;
        if let Err(error) = self
            .overrides
            .set_interface(interface.clone(), interface_config, false)
            .await
        {
            let restoration = match previous {
                Some(previous) => wifi.configure(previous).await.map(|_| ()),
                None => Ok(()),
            };
            return wifi_error(WifiErrorDetail::Other {
                message: compensation_message(
                    "failed to persist Wi-Fi disable",
                    &error,
                    restoration,
                ),
            });
        }
        Response::WifiDisabled { interface }
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
