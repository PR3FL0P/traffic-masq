use super::*;

impl ControlService {
    pub(super) async fn dispatch_inner(&self, request: Request) -> Response {
        match request {
            Request::Ping => Response::Pong,
            Request::GetApiHttpsConfig => match self.api_https_config_response().await {
                Ok(response) => response,
                Err(error) => Response::Error {
                    message: error.to_string(),
                },
            },
            Request::ConfigureApiHttpsSettings { settings } => {
                match self.configure_api_https_settings(settings).await {
                    Ok(response) => response,
                    Err(error) => Response::Error {
                        message: error.to_string(),
                    },
                }
            }
            Request::ResetApiHttpsSettings => match self.reset_api_https_settings().await {
                Ok(response) => response,
                Err(error) => Response::Error {
                    message: error.to_string(),
                },
            },
            Request::GetSecurityConfig => match self.security_config_response().await {
                Ok(response) => response,
                Err(error) => Response::Error {
                    message: error.to_string(),
                },
            },
            Request::ConfigureSecuritySettings { settings } => {
                match self.configure_security_settings(settings).await {
                    Ok(response) => response,
                    Err(error) => Response::Error {
                        message: error.to_string(),
                    },
                }
            }
            Request::ResetSecuritySettings => match self.reset_security_settings().await {
                Ok(response) => response,
                Err(error) => Response::Error {
                    message: error.to_string(),
                },
            },
            Request::ListInterfaces => {
                match interface_statuses(self.network.as_ref(), &self.transactions).await {
                    Ok(interfaces) => Response::Interfaces { interfaces },
                    Err(error) => Response::Error {
                        message: error.to_string(),
                    },
                }
            }
            Request::GetInterfaceConfig { interface } => {
                match self.interface_config_response(interface).await {
                    Ok(response) => response,
                    Err(error) => Response::Error {
                        message: error.to_string(),
                    },
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
                        Err(error) => Response::Error {
                            message: error.to_string(),
                        },
                    }
                }
                Err(error) => Response::Error {
                    message: error.to_string(),
                },
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
                        Err(error) => Response::Error {
                            message: error.to_string(),
                        },
                    }
                }
                Err(error) => Response::Error {
                    message: error.to_string(),
                },
            },
            Request::DisableDhcp { interface } => {
                let _mutation = self.dhcp_mutations.lock().await;
                match disable_dhcp_persisted(&self.dhcp, &self.overrides, &interface).await {
                    Ok(()) => Response::DhcpDisabled { interface },
                    Err(error) => Response::Error {
                        message: error.to_string(),
                    },
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
                    Err(error) => Response::Error {
                        message: error.to_string(),
                    },
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
                    .validate_default_route_management(&interface, &config, allow_management_change)
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
                    Err(error) => Response::Error {
                        message: error.to_string(),
                    },
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
                            Err(error) => Response::Error {
                                message: error.to_string(),
                            },
                        }
                    }
                    Err(error) => Response::Error {
                        message: error.to_string(),
                    },
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
                    .validate_default_route_management(&interface, &config, allow_management_change)
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
                    Ok(change) => {
                        if config.role != InterfaceRole::Output || config.wifi.is_none() {
                            if let Some(wifi) = &self.wifi {
                                let _ = wifi.disable(&interface).await;
                            }
                        }
                        Response::NetworkChangePending { change }
                    }
                    Err(error) => Response::Error {
                        message: error.to_string(),
                    },
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
                            Ok(change) => {
                                if config.role != InterfaceRole::Output || config.wifi.is_none() {
                                    if let Some(wifi) = &self.wifi {
                                        let _ = wifi.disable(&interface).await;
                                    }
                                }
                                Response::NetworkChangePending { change }
                            }
                            Err(error) => Response::Error {
                                message: error.to_string(),
                            },
                        }
                    }
                    Err(error) => Response::Error {
                        message: error.to_string(),
                    },
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
                Ok(change) => {
                    let committed = self
                        .overrides
                        .effective_interface(&change.interface)
                        .await
                        .ok()
                        .flatten();
                    if let Some(config) = committed {
                        if config.role != InterfaceRole::Output || config.wifi.is_none() {
                            if let Some(wifi) = &self.wifi {
                                let _ = wifi.disable(&change.interface).await;
                            }
                        }
                    }
                    Response::NetworkChangeCommitted { change }
                }
                Err(error) => Response::Error {
                    message: error.to_string(),
                },
            },
            Request::RollbackNetworkChange { token } => {
                match self.transactions.rollback(&token).await {
                    Ok(change) => Response::NetworkChangeRolledBack { change },
                    Err(error) => Response::Error {
                        message: error.to_string(),
                    },
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
                configure_dhcp,
            } => {
                self.provision_wifi_access_point(interface, settings, passphrase, configure_dhcp)
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
            Request::ListWifiClientProfiles => self.list_wifi_client_profiles().await,
            Request::GetWifiClientProfile { id } => self.get_wifi_client_profile(id).await,
            Request::CreateWifiClientProfile { profile } => {
                self.create_wifi_client_profile(profile).await
            }
            Request::UpdateWifiClientProfile { id, profile } => {
                self.update_wifi_client_profile(id, profile).await
            }
            Request::DeleteWifiClientProfile { id } => self.delete_wifi_client_profile(id).await,
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
