use super::*;

impl ControlService {
    pub(super) async fn dhcp_client_status(&self) -> Response {
        let Some(supervisor) = &self.dhcp_client else {
            return dhcp_client_error(DhcpClientErrorDetail::DhcpClientDisabled);
        };
        Response::DhcpClientStatus {
            interfaces: supervisor
                .statuses()
                .await
                .into_iter()
                .map(dhcp_client_status_view)
                .collect(),
        }
    }

    pub(super) async fn get_dhcp_client(&self, interface: String) -> Response {
        let Some(supervisor) = &self.dhcp_client else {
            return dhcp_client_error(DhcpClientErrorDetail::DhcpClientDisabled);
        };
        match supervisor.status(&interface).await {
            Some(status) => Response::DhcpClientInterface {
                status: dhcp_client_status_view(status),
            },
            None => {
                let effective = match self.effective_config().await {
                    Ok(config) => config,
                    Err(message) => {
                        return dhcp_client_error(DhcpClientErrorDetail::RuntimeFailure { message })
                    }
                };
                match effective.network.interfaces.get(&interface) {
                    None => dhcp_client_error(DhcpClientErrorDetail::InterfaceNotFound),
                    Some(config) if config.dhcp_client.is_some() => {
                        dhcp_client_error(DhcpClientErrorDetail::Disabled)
                    }
                    Some(_) => dhcp_client_error(DhcpClientErrorDetail::Disabled),
                }
            }
        }
    }

    pub(super) async fn configure_dhcp_client(
        &self,
        interface: String,
        request: DhcpClientConfigRequest,
    ) -> Response {
        let Some(supervisor) = &self.dhcp_client else {
            return dhcp_client_error(DhcpClientErrorDetail::DhcpClientDisabled);
        };
        let _mutation = self.dhcp_client_mutations.lock().await;
        let effective = match self.effective_config().await {
            Ok(config) => config,
            Err(message) => {
                return dhcp_client_error(DhcpClientErrorDetail::RuntimeFailure { message })
            }
        };
        let Some(mut interface_config) = effective.network.interfaces.get(&interface).cloned()
        else {
            return dhcp_client_error(DhcpClientErrorDetail::InterfaceNotFound);
        };
        interface_config.role = InterfaceRole::Input;
        interface_config.managed = true;
        interface_config.ipv4 = None;
        interface_config.dhcp = None;
        interface_config.wifi = None;
        if let Some(wifi) = &self.wifi {
            let _ = wifi.disable(&interface).await;
        }
        interface_config.dhcp_client = Some(dhcp_client_request_to_config(&request, true));
        let spec = match DhcpClientSpec::from_interface_config(&interface, &interface_config) {
            Ok(Some(spec)) => spec,
            Ok(None) => return dhcp_client_error(DhcpClientErrorDetail::Disabled),
            Err(error) => {
                return dhcp_client_error(DhcpClientErrorDetail::InvalidConfig {
                    message: error.to_string(),
                })
            }
        };

        if let Err(error) = self
            .overrides
            .check_interface(&interface, &interface_config, false)
            .await
        {
            return dhcp_client_error(DhcpClientErrorDetail::InvalidConfig {
                message: error.to_string(),
            });
        }
        let previous = supervisor.spec(&interface).await;
        supervisor.configure(spec.clone()).await;
        if let Err(error) = self
            .overrides
            .set_interface(interface.clone(), interface_config, false)
            .await
        {
            if let Some(previous) = previous {
                supervisor.configure(previous).await;
            } else {
                let _ = supervisor.disable(&interface).await;
            }
            return dhcp_client_error(DhcpClientErrorDetail::PersistenceFailure {
                message: format!(
                    "failed to persist DHCP client intent; runtime state was restored: {error}"
                ),
            });
        }
        match supervisor.status(&interface).await {
            Some(status) => Response::DhcpClientInterface {
                status: dhcp_client_status_view(status),
            },
            None => dhcp_client_error(DhcpClientErrorDetail::RuntimeFailure {
                message: "DHCP client disappeared after configuration".to_string(),
            }),
        }
    }

    pub(super) async fn disable_dhcp_client(&self, interface: String) -> Response {
        let Some(supervisor) = &self.dhcp_client else {
            return dhcp_client_error(DhcpClientErrorDetail::DhcpClientDisabled);
        };
        let _mutation = self.dhcp_client_mutations.lock().await;
        let effective = match self.effective_config().await {
            Ok(config) => config,
            Err(message) => {
                return dhcp_client_error(DhcpClientErrorDetail::RuntimeFailure { message })
            }
        };
        let Some(mut config) = effective.network.interfaces.get(&interface).cloned() else {
            return dhcp_client_error(DhcpClientErrorDetail::InterfaceNotFound);
        };
        let previous = supervisor.spec(&interface).await;
        if previous.is_none() {
            return dhcp_client_error(DhcpClientErrorDetail::Disabled);
        }
        config.dhcp_client = Some(dhcp_client_request_to_config(
            &DhcpClientConfigRequest::default(),
            false,
        ));

        if let Err(error) = self
            .overrides
            .check_interface(&interface, &config, false)
            .await
        {
            return dhcp_client_error(DhcpClientErrorDetail::InvalidConfig {
                message: error.to_string(),
            });
        }
        if let Err(error) = supervisor.disable(&interface).await {
            return dhcp_client_error(DhcpClientErrorDetail::OwnershipConflict {
                message: error.to_string(),
            });
        }
        if let Err(error) = self
            .overrides
            .set_interface(interface.clone(), config, false)
            .await
        {
            if let Some(previous) = previous {
                supervisor.configure(previous).await;
            }
            return dhcp_client_error(DhcpClientErrorDetail::PersistenceFailure {
                message: format!(
                    "failed to persist DHCP client disable; runtime state was restored: {error}"
                ),
            });
        }
        Response::DhcpClientDisabled { interface }
    }

    pub(super) async fn renew_dhcp_client(&self, interface: String) -> Response {
        let Some(supervisor) = &self.dhcp_client else {
            return dhcp_client_error(DhcpClientErrorDetail::DhcpClientDisabled);
        };
        match supervisor.renew_now(&interface).await {
            Ok(status) => Response::DhcpClientInterface {
                status: dhcp_client_status_view(status),
            },
            Err(_) => dhcp_client_error(DhcpClientErrorDetail::Disabled),
        }
    }

    pub(super) async fn release_dhcp_client(&self, interface: String) -> Response {
        let Some(supervisor) = &self.dhcp_client else {
            return dhcp_client_error(DhcpClientErrorDetail::DhcpClientDisabled);
        };
        match supervisor.release_and_reacquire(&interface).await {
            Ok(status) => Response::DhcpClientInterface {
                status: dhcp_client_status_view(status),
            },
            Err(error) => dhcp_client_error(DhcpClientErrorDetail::RuntimeFailure {
                message: error.to_string(),
            }),
        }
    }
}
