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

        let mut desired_interface = previous_interface.clone();
        desired_interface.wifi = Some(wifi_edit_request_to_config(settings));
        if let (Some(next), Some(previous)) = (
            desired_interface.wifi.as_mut(),
            previous_interface.wifi.as_ref(),
        ) {
            next.passphrase_file = previous.passphrase_file.clone();
        }
        let spec = match WifiApSpec::from_interface_config(&interface, &desired_interface) {
            Ok(Some(spec)) => spec,
            Ok(None) => unreachable!("managed output checked above"),
            Err(error) => {
                return wifi_error(WifiErrorDetail::InvalidSpec {
                    message: error.to_string(),
                })
            }
        };
        let dhcp_settings = if configure_dhcp {
            match default_dhcp_settings(cidr) {
                Ok(settings) => Some(settings),
                Err(message) => return wifi_error(WifiErrorDetail::InvalidSpec { message }),
            }
        } else {
            None
        };

        let _wifi_mutation = self.wifi_mutations.lock().await;
        let _dhcp_mutation = self.dhcp_mutations.lock().await;
        let previous_ap = wifi.status(&interface).await.map(|status| status.spec);
        let previous_secret = match wifi.stored_passphrase(&interface).await {
            Ok(secret) => secret,
            Err(error) => return classify_wifi_error(error),
        };
        let previous_dhcp = self.dhcp.spec(&interface).await;

        if let Some(secret) = staged_passphrase.as_ref() {
            if let Err(error) = wifi.set_passphrase(&interface, secret).await {
                return classify_wifi_error(error);
            }
        }
        if let Err(error) = wifi.configure(spec.clone()).await {
            compensate_ap(wifi, &interface, previous_ap, previous_secret).await;
            return classify_wifi_error(error);
        }
        if let Err(error) = self
            .overrides
            .set_interface(interface.clone(), desired_interface.clone(), false)
            .await
        {
            compensate_ap(wifi, &interface, previous_ap, previous_secret).await;
            return wifi_error(WifiErrorDetail::Other {
                message: format!("AP provisioning failed to persist Wi-Fi settings; prior AP and secret were restored where possible: {error}"),
            });
        }

        let configured_dhcp = if let Some(settings) = dhcp_settings {
            let mut dhcp_interface = desired_interface;
            dhcp_interface.dhcp = Some(dhcp_edit_request_to_config(settings));
            let result = match DhcpServiceSpec::from_interface_config(
                &interface,
                &dhcp_interface,
                self.base_config.dhcp.default_lease_seconds,
            ) {
                Ok(Some(spec)) => {
                    configure_dhcp_persisted(&self.dhcp, &self.overrides, spec.clone())
                        .await
                        .map(|()| spec)
                }
                Ok(None) => unreachable!("managed output was checked before provisioning"),
                Err(error) => Err(error),
            };
            match result {
                Ok(spec) => Some(spec),
                Err(error) => {
                    let _ = self
                        .overrides
                        .set_interface(interface.clone(), previous_interface, false)
                        .await;
                    match previous_dhcp {
                        Some(spec) => {
                            let _ = self.dhcp.configure(spec).await;
                        }
                        None => {
                            let _ = self.dhcp.disable(&interface).await;
                        }
                    }
                    compensate_ap(wifi, &interface, previous_ap, previous_secret).await;
                    return wifi_error(WifiErrorDetail::Other {
                        message: format!("AP provisioning failed while configuring DHCP; prior AP, secret, DHCP, and interface override were restored where possible: {error}"),
                    });
                }
            }
        } else {
            None
        };

        Response::WifiAccessPointProvisioned {
            spec,
            dhcp: configured_dhcp,
        }
    }

    pub(super) async fn disable_wifi(&self, interface: String) -> Response {
        let Some(wifi) = &self.wifi else {
            return wifi_disabled();
        };
        let _mutation = self.wifi_mutations.lock().await;
        let previous = wifi.status(&interface).await.map(|status| status.spec);

        if let Err(error) = wifi.disable(&interface).await {
            return classify_wifi_error(error);
        }

        let committed = match self.overrides.effective_interface(&interface).await {
            Ok(config) => config,
            Err(error) => {
                return wifi_error(WifiErrorDetail::Other {
                    message: error.to_string(),
                })
            }
        };
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
        if let Err(error) = wifi.set_passphrase(&interface, &passphrase).await {
            return classify_wifi_error(error);
        }

        let Some(status) = wifi.status(&interface).await else {
            return wifi_error(WifiErrorDetail::InterfaceNotFound);
        };
        let spec = status.spec;
        match wifi.configure(spec.clone()).await {
            Ok(()) => Response::WifiConfigured { spec },
            Err(error) => classify_wifi_error(error),
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
