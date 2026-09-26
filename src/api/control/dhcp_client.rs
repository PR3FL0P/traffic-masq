use super::runtime::compensation_message;
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
        let link_ready = match &self.wifi_client {
            Some(wifi) => match wifi.status(&interface).await {
                Some(status) => status.wpa_state.is_connected(),
                None => true,
            },
            None => true,
        };
        if let Err(error) =
            configure_dhcp_client_checked(supervisor, spec.clone(), link_ready).await
        {
            let restoration =
                restore_dhcp_client(supervisor, &interface, previous, link_ready).await;
            return dhcp_client_error(DhcpClientErrorDetail::RuntimeFailure {
                message: match restoration {
                    Ok(()) => format!(
                        "failed to configure DHCP client: {error:#}; prior runtime state was restored"
                    ),
                    Err(rollback) => format!(
                        "failed to configure DHCP client: {error:#}; rollback also failed: {rollback:#}; recovery required"
                    ),
                },
            });
        }
        if let Err(error) = self
            .overrides
            .set_interface(interface.clone(), interface_config, false)
            .await
        {
            let restoration =
                restore_dhcp_client(supervisor, &interface, previous, link_ready).await;
            return dhcp_client_error(DhcpClientErrorDetail::PersistenceFailure {
                message: match restoration {
                    Ok(()) => format!(
                        "failed to persist DHCP client intent; runtime state was restored: {error}"
                    ),
                    Err(rollback_error) => format!(
                        "failed to persist DHCP client intent: {error}; runtime restoration failed: {rollback_error}; recovery required"
                    ),
                },
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
        let link_ready = match &self.wifi_client {
            Some(wifi) => match wifi.status(&interface).await {
                Some(status) => status.wpa_state.is_connected(),
                None => true,
            },
            None => true,
        };
        if previous.is_none() {
            return dhcp_client_error(DhcpClientErrorDetail::Disabled);
        }
        config
            .dhcp_client
            .get_or_insert_with(Default::default)
            .enabled = false;

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
            let restoration =
                restore_dhcp_client(supervisor, &interface, previous.clone(), link_ready).await;
            return dhcp_client_error(DhcpClientErrorDetail::OwnershipConflict {
                message: compensation_message("failed to disable DHCP client", &error, restoration),
            });
        }
        if let Err(error) = self
            .overrides
            .set_interface(interface.clone(), config, false)
            .await
        {
            let restoration =
                restore_dhcp_client(supervisor, &interface, previous, link_ready).await;
            return dhcp_client_error(DhcpClientErrorDetail::PersistenceFailure {
                message: match restoration {
                    Ok(()) => format!(
                        "failed to persist DHCP client disable; runtime state was restored: {error}"
                    ),
                    Err(rollback) => format!(
                        "failed to persist DHCP client disable: {error}; runtime restoration failed: {rollback:#}; recovery required"
                    ),
                },
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
            Err(_error) if supervisor.spec(&interface).await.is_none() => {
                dhcp_client_error(DhcpClientErrorDetail::Disabled)
            }
            Err(error) => dhcp_client_error(DhcpClientErrorDetail::RuntimeFailure {
                message: error.to_string(),
            }),
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

pub(super) fn dhcp_client_request_to_config(
    request: &DhcpClientConfigRequest,
    enabled: bool,
) -> DhcpClientInterfaceConfig {
    DhcpClientInterfaceConfig {
        wifi_owned: false,
        enabled,
        route_metric: request.route_metric,
        install_default_route: request.install_default_route,
        request_dns: request.request_dns,
        send_release_on_shutdown: request.send_release_on_shutdown,
    }
}

async fn configure_dhcp_client_checked(
    supervisor: &DhcpClientSupervisor,
    spec: DhcpClientSpec,
    link_ready: bool,
) -> Result<()> {
    let interface = spec.interface.clone();
    supervisor.configure_with_link_ready(spec, link_ready).await;
    let status = supervisor
        .status(&interface)
        .await
        .ok_or_else(|| anyhow::anyhow!("DHCP client disappeared after configuration"))?;
    if let DhcpClientRunState::Degraded { reason } = status.state {
        anyhow::bail!("DHCP client failed to start on {interface}: {reason}");
    }
    Ok(())
}

async fn restore_dhcp_client(
    supervisor: &DhcpClientSupervisor,
    interface: &str,
    previous: Option<DhcpClientSpec>,
    link_ready: bool,
) -> Result<()> {
    match previous {
        Some(spec) => configure_dhcp_client_checked(supervisor, spec, link_ready).await,
        None => {
            supervisor.disable(interface).await?;
            Ok(())
        }
    }
}

pub(super) fn dhcp_client_status_view(status: DhcpClientStatus) -> DhcpClientStatusView {
    let (state, degraded_reason) = match status.state {
        DhcpClientRunState::WaitingForInterface => (DhcpClientOperationalState::Waiting, None),
        DhcpClientRunState::Running => (DhcpClientOperationalState::Running, None),
        DhcpClientRunState::Degraded { reason } => {
            (DhcpClientOperationalState::Degraded, Some(reason))
        }
    };
    let lease = status.lease.as_ref();
    DhcpClientStatusView {
        interface: status.interface,
        state,
        address: lease.map(|lease| lease.address),
        prefix_length: lease.map(|lease| lease.prefix_len),
        server: lease.map(|lease| lease.server_identifier),
        expires_at_unix: lease.map(|lease| lease.expires_at_unix),
        dns_servers: lease
            .map(|lease| lease.dns_servers.clone())
            .unwrap_or_default(),
        degraded_reason,
        config: DhcpClientConfigRequest {
            route_metric: status.spec.route_metric,
            install_default_route: status.spec.install_default_route,
            request_dns: status.spec.request_dns,
            send_release_on_shutdown: status.spec.send_release_on_shutdown,
        },
    }
}

pub(super) fn dhcp_client_error(detail: DhcpClientErrorDetail) -> Response {
    Response::DhcpClientError { detail }
}
