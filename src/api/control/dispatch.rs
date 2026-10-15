use super::dhcp::{build_effective_dhcp_service, configure_dhcp_persisted, disable_dhcp_persisted};
use super::interfaces::{interface_edit_request_to_config, interface_statuses};
use super::runtime::error_response;
use super::*;
use crate::core::transaction::InterfaceChange;

impl ControlService {
    /// Route a typed request to its handler while enforcing mutation and recovery gates.
    pub(super) async fn dispatch_inner(&self, request: Request) -> Response {
        let policy = request.policy();
        let _admission = if policy.needs_admission() {
            Some(self.network_mutations.admit().await)
        } else {
            None
        };
        let _execution = if policy.needs_execution() {
            Some(self.network_mutations.execute().await)
        } else {
            None
        };
        if policy.network_mutation() {
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
            let scope = transaction_interface
                .as_deref()
                .or(policy.recovery_interface);
            let retry_journal = match &request {
                Request::RollbackNetworkChange { .. } => {
                    transaction_interface.as_ref().map(|interface| {
                        self.config
                            .runtime
                            .state_dir
                            .join("interface-transactions")
                            .join(format!("{interface}.json"))
                    })
                }
                Request::RouterRollback { .. } => Some(
                    self.config
                        .runtime
                        .state_dir
                        .join("router-transaction.json"),
                ),
                _ => None,
            };
            let admitted = match retry_journal {
                Some(path) => crate::core::recovery::check_rollback_scope(
                    &self.config.runtime.state_dir,
                    scope,
                    &path,
                ),
                None => crate::core::recovery::check_scope(&self.config.runtime.state_dir, scope),
            };
            if let Err(error) = admitted {
                return Response::Error {
                    message: format!("{error:#}"),
                };
            }
        }
        if policy.network_mutation() && !policy.provisioning_recovery {
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
        if policy.direct_network_mutation() {
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
                    CoordinatorStatus::RollbackFailed
                    | CoordinatorStatus::RecoveryRequired
                    | CoordinatorStatus::CommitIndeterminate => {
                        return Response::Error {
                            message: "router rollback recovery is required; direct network mutations are blocked until recovery completes".to_owned(),
                        };
                    }
                }
            }
        }

        match request {
            Request::Ping => Response::Pong,
            Request::DaemonLogs { limit } => {
                let directory = self.config.runtime.log_dir.clone();
                match tokio::task::spawn_blocking(move || {
                    crate::logging::recent::read_recent(&directory, limit)
                })
                .await
                {
                    Ok(Ok(snapshot)) => Response::DaemonLogs { snapshot },
                    Ok(Err(error)) => error_response(error),
                    Err(error) => error_response(error),
                }
            }
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
            Request::ListWifiInventory => match self.wifi_inventory().await {
                Ok(response) => response,
                Err(error) => error_response(error),
            },
            Request::SaveWifiClientProfile {
                interface,
                settings,
                expected_revision,
            } => match self
                .save_wifi_client_profile(interface, settings, expected_revision)
                .await
            {
                Ok(response) => response,
                Err(error) => error_response(error),
            },
            Request::SaveWifiInterface {
                interface,
                config,
                expected_revision,
                passphrase,
            } => match self
                .save_wifi_interface(interface, config.into(), expected_revision, passphrase)
                .await
            {
                Ok(response) => response,
                Err(error) => error_response(error),
            },
            Request::ListInterfaceInventory => match self.interface_inventory().await {
                Ok(response) => response,
                Err(error) => error_response(error),
            },
            Request::SaveInterfaceConfig {
                interface,
                config,
                allow_management_change,
                expected_revision,
            } => {
                let proposal = RouterIntentProposal::new().set_interface(
                    interface.clone(),
                    config.into(),
                    allow_management_change,
                );
                match self
                    .save_missing_interface_intent(interface, proposal, expected_revision)
                    .await
                {
                    Ok(response) => response,
                    Err(error) => error_response(error),
                }
            }
            Request::ForgetInterfaceConfig {
                interface,
                expected_revision,
            } => {
                let proposal = RouterIntentProposal::new().forget_interface(interface.clone());
                match self
                    .save_missing_interface_intent(interface, proposal, expected_revision)
                    .await
                {
                    Ok(response) => response,
                    Err(error) => error_response(error),
                }
            }
            Request::ResetInterfaceOverride {
                interface,
                expected_revision,
            } => {
                let proposal = RouterIntentProposal::new().remove_interface(interface.clone());
                match self
                    .save_missing_interface_intent(interface, proposal, expected_revision)
                    .await
                {
                    Ok(response) => response,
                    Err(error) => error_response(error),
                }
            }
            Request::ListInterfaces => {
                match interface_statuses(self.network.as_ref(), &self.transactions).await {
                    Ok(interfaces) => Response::Interfaces {
                        interfaces: interfaces.into_iter().map(Into::into).collect(),
                    },
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
            Request::GetDhcpConfig { interface } => {
                match self.overrides.effective_interface(&interface).await {
                    Ok(Some(config)) => match DhcpServiceSpec::from_interface_config(
                        &interface,
                        &config,
                        self.base_config.dhcp.default_lease_seconds,
                    ) {
                        Ok(spec) => Response::DhcpConfig {
                            interface,
                            spec: spec.map(Into::into),
                        },
                        Err(error) => error_response(error),
                    },
                    Ok(None) => Response::DhcpConfig {
                        interface,
                        spec: None,
                    },
                    Err(error) => error_response(error),
                }
            }
            Request::ConfigureDhcp {
                interface,
                config: dhcp_config,
            }
            | Request::ConfigureDhcpSettings {
                interface,
                settings: dhcp_config,
            } => match build_effective_dhcp_service(
                &interface,
                dhcp_config.into(),
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
                        Ok(()) => Response::DhcpConfigured { spec: spec.into() },
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
                    Ok(leases) => Response::Leases {
                        interface,
                        leases: leases
                            .into_iter()
                            .map(|lease| traffic_masq_protocol::DhcpLeaseView {
                                mac: lease.mac,
                                ip: lease.ip,
                                expires_at_unix: lease.expires_at_unix,
                            })
                            .collect(),
                    },
                    Err(error) => error_response(error),
                }
            }
            Request::DryRunInterface {
                interface,
                config,
                allow_management_change,
            } => {
                let config: InterfaceConfig = config.into();
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
                    Ok(plan) => Response::InterfacePlan { plan: plan.into() },
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
                            Ok(plan) => Response::InterfacePlan { plan: plan.into() },
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
                let config: InterfaceConfig = config.into();
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
                    .apply(
                        &interface,
                        InterfaceChange {
                            config: &config,
                            previous: current.as_ref(),
                            current_role,
                            allow_management_change,
                            passphrase: crate::wifi::WifiPassphraseUpdate::Keep,
                        },
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
                            .apply(
                                &interface,
                                InterfaceChange {
                                    config: &config,
                                    previous: current.as_ref(),
                                    current_role,
                                    allow_management_change,
                                    passphrase: crate::wifi::WifiPassphraseUpdate::Keep,
                                },
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
            Request::CommitNetworkChange { token } => {
                match self.transactions.commit(&token).await {
                    Ok(change) => {
                        let deactivated_interface = {
                            self.pending_wifi_client_deactivations
                                .lock()
                                .await
                                .remove(&token)
                        };
                        if let Some(interface) = deactivated_interface {
                            self.wifi_autoconnect.lock().await.suspend(&interface);
                        }
                        Response::NetworkChangeCommitted { change }
                    }
                    Err(error) => error_response(error),
                }
            }
            Request::RollbackNetworkChange { token } => {
                match self.transactions.rollback(&token).await {
                    Ok(change) => {
                        self.pending_wifi_client_deactivations
                            .lock()
                            .await
                            .remove(&token);
                        Response::NetworkChangeRolledBack { change }
                    }
                    Err(error) => error_response(error),
                }
            }
            Request::PendingNetworkChanges => Response::PendingNetworkChanges {
                changes: self.transactions.pending().await,
            },
            Request::RouterStatus => self.router_status().await,
            Request::SaveRouterIntent {
                config,
                expected_revision,
            } => {
                self.save_router_intent(config.into(), expected_revision)
                    .await
            }
            Request::RouterIntentPreview { proposal } => {
                self.router_intent_preview(proposal.into()).await
            }
            Request::RouterPlan { proposal } => self.router_plan(proposal.into()).await,
            Request::RouterApply { proposal } => self.router_apply(proposal.into()).await,
            Request::RouterCommit { token } => self.router_commit(token).await,
            Request::RouterRollback { token } => self.router_rollback(token).await,
            Request::RouterPendingTransaction => self.router_pending_transaction().await,
            Request::ListRouteInventory {
                include_local_table,
            } => self.list_route_inventory(include_local_table).await,
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
            Request::VpnListSources => self.vpn_list_sources().await,
            Request::VpnImportFromSource { name } => self.vpn_import_from_source(name).await,
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
