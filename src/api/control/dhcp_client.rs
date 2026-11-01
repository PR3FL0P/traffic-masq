use super::*;
use crate::core::transaction::InterfaceChange;

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
        if self.dhcp_client.is_none() {
            return dhcp_client_error(DhcpClientErrorDetail::DhcpClientDisabled);
        }
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
        // This operation only edits DHCP policy. Role, ownership and
        // static-address transitions belong to the confirmed interface path.
        if interface_config.role != InterfaceRole::Input
            || !interface_config.managed
            || interface_config.ipv4.is_some()
        {
            return dhcp_client_error(DhcpClientErrorDetail::InvalidConfig {
                message: format!(
                    "DHCP client on {interface} requires a managed input interface without a static IPv4 address; apply and commit those changes through Interfaces first"
                ),
            });
        }
        let previous_config = interface_config.clone();
        interface_config.dhcp_client = Some(dhcp_client_request_to_config(&request, true));
        if let Some(previous) = &previous_config.dhcp_client {
            interface_config.dhcp_client.as_mut().unwrap().wifi_owned = previous.wifi_owned;
        }
        match DhcpClientSpec::from_interface_config(&interface, &interface_config) {
            Ok(Some(_)) => (),
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
        self.transactions
            .apply(
                &interface,
                InterfaceChange {
                    config: &interface_config,
                    previous: Some(&previous_config),
                    current_role: Some(previous_config.role),
                    allow_management_change: true,
                    passphrase: crate::wifi::WifiPassphraseUpdate::Keep,
                },
            )
            .await
            .map(|change| Response::NetworkChangePending { change })
            .unwrap_or_else(super::runtime::error_response)
    }

    pub(super) async fn disable_dhcp_client(&self, interface: String) -> Response {
        if self.dhcp_client.is_none() {
            return dhcp_client_error(DhcpClientErrorDetail::DhcpClientDisabled);
        }
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
        let previous_config = config.clone();
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
        self.transactions
            .apply(
                &interface,
                InterfaceChange {
                    config: &config,
                    previous: Some(&previous_config),
                    current_role: Some(previous_config.role),
                    allow_management_change: true,
                    passphrase: crate::wifi::WifiPassphraseUpdate::Keep,
                },
            )
            .await
            .map(|change| Response::NetworkChangePending { change })
            .unwrap_or_else(super::runtime::error_response)
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
        hostname: request.hostname.clone(),
        wifi_owned: false,
        enabled,
        route_metric: request.route_metric,
        install_default_route: request.install_default_route,
        request_dns: request.request_dns,
        send_release_on_shutdown: request.send_release_on_shutdown,
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
            hostname: status.spec.hostname.clone(),
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
