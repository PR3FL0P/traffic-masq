use super::dhcp::{
    build_effective_dhcp_service, configure_dhcp_persisted, dhcp_edit_request_to_config,
    disable_dhcp_persisted,
};
use super::interfaces::{interface_edit_request_to_config, interface_statuses};
use super::runtime::error_response;
use super::*;

impl ControlService {
    /// Route a typed request to its handler while enforcing mutation and recovery gates.
    pub(super) async fn dispatch_inner(&self, request: Request) -> Response {
        // Admission stays held across convergence waits. Execution is held only
        // by direct writers: the worker must remain able to realize proposals.
        let _admission = if is_network_mutation(&request) {
            Some(self.network_mutations.admit().await)
        } else {
            None
        };
        let _execution = if is_network_mutation(&request)
            && !is_converged_network_transaction_request(&request)
        {
            Some(self.network_mutations.execute().await)
        } else {
            None
        };
        if is_network_mutation(&request) {
            // Confirmation requests carry a token, not an interface name.
            // Keep their recovery scope identical to the original apply.
            let transaction_interface = match &request {
                Request::CommitNetworkChange { token }
                | Request::RollbackNetworkChange { token } => self
                    .transactions
                    .pending()
                    .await
                    .into_iter()
                    .find(|change| &change.token == token)
                    .map(|change| change.interface),
                _ => None,
            };
            if let Err(error) = crate::core::recovery::check_scope(
                &self.config.runtime.state_dir,
                transaction_interface
                    .as_deref()
                    .or_else(|| recovery_interface(&request)),
            ) {
                return Response::Error {
                    message: format!("{error:#}"),
                };
            }
        }
        if is_network_mutation(&request) && !is_provisioning_secret_recovery_request(&request) {
            if let Some(router) = &self.router {
                // The provisioning-secret journal is an extra crash-recovery
                // barrier only after the router coordinator itself is idle.
                // Pending/RollbackFailed already serialize mutations and their
                // request handlers provide the appropriate typed errors.
                if router.status().await == CoordinatorStatus::Idle {
                    let secrets = crate::core::provisioning_secret_transaction::ProvisioningSecretTransactionStore::in_state_dir(
                        &self.config.runtime.state_dir,
                    );
                    let committed_token =
                        self.overrides.snapshot().await.committed_router_transaction;
                    match secrets
                        .unresolved_after_committed_cleanup(committed_token.as_deref())
                        .await
                    {
                        Ok(false) => {}
                        Ok(true) => {
                            return Response::Error {
                                message: "router provisioning secret recovery is pending; roll back or commit the router transaction before starting another network mutation".to_owned(),
                            };
                        }
                        Err(error) => {
                            return Response::Error {
                                message: format!(
                                    "cannot verify router provisioning secret recovery state: {error:#}"
                                ),
                            };
                        }
                    }
                }
            }
        }
        if is_direct_network_mutation(&request) {
            if !matches!(
                &request,
                Request::ApplyInterface { .. }
                    | Request::ApplyInterfaceEdit { .. }
                    | Request::CommitNetworkChange { .. }
                    | Request::RollbackNetworkChange { .. }
            ) && !self.transactions.pending().await.is_empty()
            {
                return Response::Error {
                    message: "an interface transaction is pending; direct network mutations are blocked until it commits or rolls back".to_owned(),
                };
            }
            if let Some(router) = &self.router {
                match router.status().await {
                    CoordinatorStatus::Idle => {}
                    CoordinatorStatus::Pending => {
                        return Response::Error {
                            message: "a router transaction is pending; direct network mutations are blocked until it commits or rolls back".to_owned(),
                        };
                    }
                    CoordinatorStatus::RecoveredButJournalCleanupPending => {
                        return Response::Error {
                            message: "kernel state recovered; journal housekeeping is pending and will retry automatically; overlapping mutations are temporarily blocked".to_owned(),
                        };
                    }
                    CoordinatorStatus::RollbackFailed => {
                        return Response::Error {
                            message: "router rollback recovery is required; direct network mutations are blocked until recovery completes".to_owned(),
                        };
                    }
                }
            }
        }

        match request {
            Request::Ping => Response::Pong,
            Request::GetApiHttpsConfig => match self.api_https_config_response().await {
                Ok(response) => response,
                Err(error) => error_response(error),
            },
            Request::ConfigureApiHttpsSettings { settings } => {
                match self.configure_api_https_settings(settings).await {
                    Ok(response) => response,
                    Err(error) => error_response(error),
                }
            }
            Request::ResetApiHttpsSettings => match self.reset_api_https_settings().await {
                Ok(response) => response,
                Err(error) => error_response(error),
            },
            Request::GetSecurityConfig => match self.security_config_response().await {
                Ok(response) => response,
                Err(error) => error_response(error),
            },
            Request::ConfigureSecuritySettings { settings } => {
                match self.configure_security_settings(settings).await {
                    Ok(response) => response,
                    Err(error) => error_response(error),
                }
            }
            Request::ResetSecuritySettings => match self.reset_security_settings().await {
                Ok(response) => response,
                Err(error) => error_response(error),
            },
            Request::ListInterfaces => {
                match interface_statuses(self.network.as_ref(), &self.transactions).await {
                    Ok(interfaces) => Response::Interfaces { interfaces },
                    Err(error) => error_response(error),
                }
            }
            Request::GetInterfaceConfig { interface } => {
                match self.interface_config_response(interface).await {
                    Ok(response) => response,
                    Err(error) => error_response(error),
                }
            }
            Request::DhcpStatus => Response::DhcpStatus {
                running_interfaces: self.dhcp.running_interfaces().await,
                unhealthy_interfaces: self.dhcp.unhealthy_interfaces().await,
            },
            Request::DhcpClientStatus => self.dhcp_client_status().await,
            Request::GetDhcpClient { interface } => self.get_dhcp_client(interface).await,
            Request::ConfigureDhcpClient { interface, config } => {
                self.configure_dhcp_client(interface, config).await
            }
            Request::DisableDhcpClient { interface } => self.disable_dhcp_client(interface).await,
            Request::RenewDhcpClient { interface } => self.renew_dhcp_client(interface).await,
            Request::ReleaseDhcpClient { interface } => self.release_dhcp_client(interface).await,
            Request::GetDhcpConfig { interface } => Response::DhcpConfig {
                spec: self.dhcp.spec(&interface).await,
                interface,
            },
            Request::ConfigureDhcp {
                interface,
                config: dhcp_config,
            } => match build_effective_dhcp_service(
                &interface,
                dhcp_config,
                &self.overrides,
                self.network.as_ref(),
                self.base_config.dhcp.default_lease_seconds,
            )
            .await
            {
                Ok(spec) => {
                    let _mutation = self.dhcp_mutations.lock().await;
                    match configure_dhcp_persisted(&self.dhcp, &self.overrides, spec.clone()).await
                    {
                        Ok(()) => Response::DhcpConfigured { spec },
                        Err(error) => error_response(error),
                    }
                }
                Err(error) => error_response(error),
            },
            Request::ConfigureDhcpSettings {
                interface,
                settings,
            } => match build_effective_dhcp_service(
                &interface,
                dhcp_edit_request_to_config(settings),
                &self.overrides,
                self.network.as_ref(),
                self.base_config.dhcp.default_lease_seconds,
            )
            .await
            {
                Ok(spec) => {
                    let _mutation = self.dhcp_mutations.lock().await;
                    match configure_dhcp_persisted(&self.dhcp, &self.overrides, spec.clone()).await
                    {
                        Ok(()) => Response::DhcpConfigured { spec },
                        Err(error) => error_response(error),
                    }
                }
                Err(error) => error_response(error),
            },
            Request::DisableDhcp { interface } => {
                let _mutation = self.dhcp_mutations.lock().await;
                match disable_dhcp_persisted(&self.dhcp, &self.overrides, &interface).await {
                    Ok(()) => Response::DhcpDisabled { interface },
                    Err(error) => error_response(error),
                }
            }
            Request::ListLeases { interface } => {
                if self.dhcp.spec(&interface).await.is_none() {
                    return Response::Error {
                        message: format!("DHCP is not configured for interface {interface}"),
                    };
                }

                let store =
                    LeaseStore::for_interface(&self.base_config.dhcp.leases_dir, &interface);
                match store.load().await {
                    Ok(leases) => Response::Leases { interface, leases },
                    Err(error) => error_response(error),
                }
            }
            Request::DryRunInterface {
                interface,
                config,
                allow_management_change,
            } => {
                let current = match self.overrides.effective_interface(&interface).await {
                    Ok(current) => current,
                    Err(error) => {
                        return Response::Error {
                            message: error.to_string(),
                        }
                    }
                };
                let current_role = current.as_ref().map(|config| config.role);
                if let Err(error) = self
                    .validate_default_route_management(
                        &interface,
                        current.as_ref(),
                        &config,
                        allow_management_change,
                    )
                    .await
                {
                    return Response::Error {
                        message: error.to_string(),
                    };
                }
                if let Err(error) = Self::validate_router_service_management(
                    &interface,
                    current.as_ref(),
                    &config,
                    allow_management_change,
                ) {
                    return Response::Error {
                        message: error.to_string(),
                    };
                }
                match self
                    .transactions
                    .dry_run_transition(
                        &interface,
                        &config,
                        current.as_ref(),
                        current_role,
                        allow_management_change,
                    )
                    .await
                {
                    Ok(plan) => Response::InterfacePlan { plan },
                    Err(error) => error_response(error),
                }
            }
            Request::DryRunInterfaceEdit { interface, edit } => {
                let current = match self.overrides.effective_interface(&interface).await {
                    Ok(current) => current,
                    Err(error) => {
                        return Response::Error {
                            message: error.to_string(),
                        }
                    }
                };
                let current_role = current.as_ref().map(|config| config.role);
                match interface_edit_request_to_config(edit, current.as_ref()) {
                    Ok((config, allow_management_change)) => {
                        if let Err(error) = self
                            .validate_default_route_management(
                                &interface,
                                current.as_ref(),
                                &config,
                                allow_management_change,
                            )
                            .await
                        {
                            return Response::Error {
                                message: error.to_string(),
                            };
                        }
                        if let Err(error) = Self::validate_router_service_management(
                            &interface,
                            current.as_ref(),
                            &config,
                            allow_management_change,
                        ) {
                            return Response::Error {
                                message: error.to_string(),
                            };
                        }
                        match self
                            .transactions
                            .dry_run_transition(
                                &interface,
                                &config,
                                current.as_ref(),
                                current_role,
                                allow_management_change,
                            )
                            .await
                        {
                            Ok(plan) => Response::InterfacePlan { plan },
                            Err(error) => error_response(error),
                        }
                    }
                    Err(error) => error_response(error),
                }
            }
            Request::ApplyInterface {
                interface,
                config,
                allow_management_change,
            } => {
                let current = match self.overrides.effective_interface(&interface).await {
                    Ok(current) => current,
                    Err(error) => {
                        return Response::Error {
                            message: error.to_string(),
                        }
                    }
                };
                let current_role = current.as_ref().map(|config| config.role);
                if let Err(error) = self
                    .validate_default_route_management(
                        &interface,
                        current.as_ref(),
                        &config,
                        allow_management_change,
                    )
                    .await
                {
                    return Response::Error {
                        message: error.to_string(),
                    };
                }
                if let Err(error) = Self::validate_router_service_management(
                    &interface,
                    current.as_ref(),
                    &config,
                    allow_management_change,
                ) {
                    return Response::Error {
                        message: error.to_string(),
                    };
                }
                match self
                    .transactions
                    .apply_transition(
                        &interface,
                        &config,
                        current.as_ref(),
                        current_role,
                        allow_management_change,
                    )
                    .await
                {
                    Ok(change) => Response::NetworkChangePending { change },
                    Err(error) => error_response(error),
                }
            }
            Request::ApplyInterfaceEdit { interface, edit } => {
                let current = match self.overrides.effective_interface(&interface).await {
                    Ok(current) => current,
                    Err(error) => {
                        return Response::Error {
                            message: error.to_string(),
                        }
                    }
                };
                let current_role = current.as_ref().map(|config| config.role);
                match interface_edit_request_to_config(edit, current.as_ref()) {
                    Ok((config, allow_management_change)) => {
                        if let Err(error) = self
                            .validate_default_route_management(
                                &interface,
                                current.as_ref(),
                                &config,
                                allow_management_change,
                            )
                            .await
                        {
                            return Response::Error {
                                message: error.to_string(),
                            };
                        }
                        if let Err(error) = Self::validate_router_service_management(
                            &interface,
                            current.as_ref(),
                            &config,
                            allow_management_change,
                        ) {
                            return Response::Error {
                                message: error.to_string(),
                            };
                        }
                        match self
                            .transactions
                            .apply_transition(
                                &interface,
                                &config,
                                current.as_ref(),
                                current_role,
                                allow_management_change,
                            )
                            .await
                        {
                            Ok(change) => Response::NetworkChangePending { change },
                            Err(error) => error_response(error),
                        }
                    }
                    Err(error) => error_response(error),
                }
            }
            Request::CommitNetworkChange { token } => match self
                .transactions
                .commit_with(&token, |interface, config, allow_management_change| {
                    self.overrides.commit_interface(
                        interface,
                        config,
                        allow_management_change,
                        &token,
                    )
                })
                .await
            {
                Ok(change) => Response::NetworkChangeCommitted { change },
                Err(error) => error_response(error),
            },
            Request::RollbackNetworkChange { token } => {
                match self.transactions.rollback(&token).await {
                    Ok(change) => Response::NetworkChangeRolledBack { change },
                    Err(error) => error_response(error),
                }
            }
            Request::PendingNetworkChanges => Response::PendingNetworkChanges {
                changes: self.transactions.pending().await,
            },
            Request::RouterStatus => self.router_status().await,
            Request::RouterPlan { proposal } => self.router_plan(proposal).await,
            Request::RouterApply { proposal } => self.router_apply(proposal).await,
            Request::RouterCommit { token } => self.router_commit(token).await,
            Request::RouterRollback { token } => self.router_rollback(token).await,
            Request::RouterPendingTransaction => self.router_pending_transaction().await,
            Request::ListRoutes {
                include_local_table,
            } => self.list_routes(include_local_table).await,
            Request::GetRouterConfig => self.get_router_config().await,
            Request::RouterProvisioningPreview { request } => {
                self.router_provisioning_preview(request).await
            }
            Request::RouterProvisioningApply { request } => {
                self.router_provisioning_apply(request).await
            }
            Request::RouterProvisioningStatus => self.router_provisioning_status().await,
            Request::RouterProvisioningRepair => self.router_provisioning_repair().await,
            Request::VpnListProfiles => self.vpn_list_profiles().await,
            Request::VpnImportProfile { name, contents } => {
                self.vpn_import_profile(name, contents).await
            }
            Request::VpnDeleteProfile { name } => self.vpn_delete_profile(name).await,
            Request::GetVpnConfig => self.vpn_config().await,
            Request::SetVpnEnabled { enabled } => self.set_vpn_enabled(enabled).await,
            Request::VpnStatus => self.vpn_status().await,
            Request::VpnActivate { name } => self.vpn_activate(name).await,
            Request::VpnDeactivate => self.vpn_deactivate().await,
            Request::VpnPolicyStatus => self.vpn_policy_status().await,
            Request::VpnPolicySetMode { mode } => self.vpn_policy_set_mode(mode).await,
            Request::VpnPolicyClearMode => self.vpn_policy_clear_mode().await,
            Request::WifiStatus => self.wifi_status().await,
            Request::GetWifiConfig { interface } => self.get_wifi_config(interface).await,
            Request::ConfigureWifi {
                interface,
                settings,
            } => self.configure_wifi(interface, settings).await,
            Request::ProvisionWifiAccessPoint {
                interface,
                settings,
                passphrase,
                clear_passphrase,
                configure_dhcp,
                subnet,
                disable_dhcp,
            } => {
                self.provision_wifi_access_point(
                    interface,
                    settings,
                    passphrase,
                    clear_passphrase,
                    configure_dhcp,
                    subnet,
                    disable_dhcp,
                )
                .await
            }
            Request::DisableWifi { interface } => self.disable_wifi(interface).await,
            Request::WifiSetPassphrase {
                interface,
                passphrase,
            } => self.wifi_set_passphrase(interface, passphrase).await,
            Request::ListWifiStations { interface } => self.list_wifi_stations(interface).await,
            Request::WifiDeauthStation { interface, mac } => {
                self.wifi_deauth_station(interface, mac).await
            }
            Request::WifiReload { interface } => self.wifi_reload(interface).await,
            Request::WifiClientStatus => self.wifi_client_status().await,
            Request::GetWifiClientConfig { interface } => {
                self.get_wifi_client_config(interface).await
            }
            Request::ConfigureWifiClient {
                interface,
                settings,
            } => self.configure_wifi_client(interface, settings).await,
            Request::DisableWifiClient { interface } => self.disable_wifi_client(interface).await,
            Request::WifiClientSetPassphrase {
                interface,
                passphrase,
            } => self.wifi_client_set_passphrase(interface, passphrase).await,
            Request::WifiClientReconnect { interface } => {
                self.wifi_client_reconnect(interface).await
            }
            Request::WifiClientScan { interface } => self.wifi_client_scan(interface).await,
            Request::ListWifiApProfiles => self.list_wifi_ap_profiles(),
            Request::SaveWifiApProfile { profile } => self.save_wifi_ap_profile(profile),
            Request::DeleteWifiApProfile { id } => self.delete_wifi_ap_profile(id),
            Request::ActivateWifiApProfile {
                interface,
                profile_id,
            } => self.activate_wifi_ap_profile(interface, profile_id).await,
            Request::ListWifiClientProfiles => self.list_wifi_client_profiles().await,
            Request::GetWifiClientProfile { id } => self.get_wifi_client_profile(id).await,
            Request::CreateWifiClientProfile { profile } => {
                self.create_wifi_client_profile(profile).await
            }
            Request::UpdateWifiClientProfile { id, profile } => {
                self.update_wifi_client_profile(id, profile).await
            }
            Request::DeleteWifiClientProfile { id } => self.delete_wifi_client_profile(id).await,
            Request::ProvisionWifiClient {
                interface,
                settings,
            } => self.provision_wifi_client(interface, settings).await,
            Request::ActivateWifiClientProfile {
                interface,
                profile_id,
            } => {
                self.activate_wifi_client_profile(interface, profile_id)
                    .await
            }
            Request::DeactivateWifiClientProfile { interface } => {
                self.disable_wifi_client(interface).await
            }
        }
    }
}

/// Classify requests that must be serialized with other network mutations.
fn is_network_mutation(request: &Request) -> bool {
    matches!(
        request,
        Request::ConfigureDhcpClient { .. }
            | Request::DisableDhcpClient { .. }
            | Request::RenewDhcpClient { .. }
            | Request::ReleaseDhcpClient { .. }
            | Request::ConfigureDhcpSettings { .. }
            | Request::ConfigureDhcp { .. }
            | Request::DisableDhcp { .. }
            | Request::ApplyInterface { .. }
            | Request::ApplyInterfaceEdit { .. }
            | Request::CommitNetworkChange { .. }
            | Request::RollbackNetworkChange { .. }
            | Request::RouterApply { .. }
            | Request::RouterCommit { .. }
            | Request::RouterRollback { .. }
            | Request::RouterProvisioningApply { .. }
            | Request::RouterProvisioningRepair
            | Request::VpnImportProfile { .. }
            | Request::VpnDeleteProfile { .. }
            | Request::SetVpnEnabled { .. }
            | Request::VpnActivate { .. }
            | Request::VpnDeactivate
            | Request::VpnPolicySetMode { .. }
            | Request::VpnPolicyClearMode
            | Request::ConfigureWifi { .. }
            | Request::ProvisionWifiAccessPoint { .. }
            | Request::SaveWifiApProfile { .. }
            | Request::DeleteWifiApProfile { .. }
            | Request::ActivateWifiApProfile { .. }
            | Request::DisableWifi { .. }
            | Request::WifiSetPassphrase { .. }
            | Request::WifiDeauthStation { .. }
            | Request::WifiReload { .. }
            | Request::ConfigureWifiClient { .. }
            | Request::DisableWifiClient { .. }
            | Request::WifiClientSetPassphrase { .. }
            | Request::WifiClientReconnect { .. }
            | Request::WifiClientScan { .. }
            | Request::CreateWifiClientProfile { .. }
            | Request::UpdateWifiClientProfile { .. }
            | Request::DeleteWifiClientProfile { .. }
            | Request::ProvisionWifiClient { .. }
            | Request::ActivateWifiClientProfile { .. }
            | Request::DeactivateWifiClientProfile { .. }
    )
}

/// Identify transactions that require convergence to progress while admission remains reserved.
fn is_converged_network_transaction_request(request: &Request) -> bool {
    matches!(
        request,
        Request::ProvisionWifiClient { .. }
            | Request::ProvisionWifiAccessPoint { .. }
            | Request::ActivateWifiApProfile { .. }
            | Request::ApplyInterface { .. }
            | Request::ApplyInterfaceEdit { .. }
            | Request::CommitNetworkChange { .. }
            | Request::RollbackNetworkChange { .. }
    )
}

/// Identify mutations that require exclusive runtime execution.
fn is_direct_network_mutation(request: &Request) -> bool {
    is_network_mutation(request)
        && !matches!(
            request,
            Request::RouterApply { .. }
                | Request::RouterCommit { .. }
                | Request::RouterRollback { .. }
                | Request::RouterProvisioningApply { .. }
                | Request::RouterProvisioningRepair
        )
}

/// Identify requests allowed to repair or inspect retained provisioning recovery state.
fn is_provisioning_secret_recovery_request(request: &Request) -> bool {
    matches!(
        request,
        Request::RouterCommit { .. }
            | Request::RouterRollback { .. }
            | Request::RollbackNetworkChange { .. }
    )
}

fn recovery_interface(request: &Request) -> Option<&str> {
    match request {
        Request::GetInterfaceConfig { interface, .. }
        | Request::GetDhcpClient { interface, .. }
        | Request::ConfigureDhcpClient { interface, .. }
        | Request::DisableDhcpClient { interface, .. }
        | Request::RenewDhcpClient { interface, .. }
        | Request::ReleaseDhcpClient { interface, .. }
        | Request::ConfigureDhcpSettings { interface, .. }
        | Request::GetDhcpConfig { interface, .. }
        | Request::ConfigureDhcp { interface, .. }
        | Request::DisableDhcp { interface, .. }
        | Request::ListLeases { interface, .. }
        | Request::DryRunInterface { interface, .. }
        | Request::DryRunInterfaceEdit { interface, .. }
        | Request::ApplyInterface { interface, .. }
        | Request::ApplyInterfaceEdit { interface, .. }
        | Request::GetWifiConfig { interface, .. }
        | Request::ConfigureWifi { interface, .. }
        | Request::ProvisionWifiAccessPoint { interface, .. }
        | Request::ActivateWifiApProfile { interface, .. }
        | Request::DisableWifi { interface, .. }
        | Request::WifiSetPassphrase { interface, .. }
        | Request::ListWifiStations { interface, .. }
        | Request::WifiDeauthStation { interface, .. }
        | Request::WifiReload { interface, .. }
        | Request::GetWifiClientConfig { interface, .. }
        | Request::ConfigureWifiClient { interface, .. }
        | Request::DisableWifiClient { interface, .. }
        | Request::WifiClientSetPassphrase { interface, .. }
        | Request::WifiClientReconnect { interface, .. }
        | Request::WifiClientScan { interface, .. }
        | Request::ProvisionWifiClient { interface, .. }
        | Request::ActivateWifiClientProfile { interface, .. }
        | Request::DeactivateWifiClientProfile { interface, .. } => Some(interface),
        _ => None,
    }
}
