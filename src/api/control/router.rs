use super::*;

impl ControlService {
    pub(super) async fn router_status(&self) -> Response {
        let Some(router) = &self.router else {
            return router_disabled();
        };
        let desired = match self.current_router_desired().await {
            Ok(desired) => desired,
            Err(response) => return response,
        };
        let health = router.manager().health(&desired).await;
        let coordinator_status = router.status().await;
        Response::RouterStatus {
            enabled: desired.enabled,
            ready: desired.enabled && health.ready(),
            coordinator_status,
            health,
        }
    }

    pub(super) async fn list_routes(&self, include_local_table: bool) -> Response {
        let routes = match self.network.list_ipv4_routes().await {
            Ok(routes) => routes,
            Err(error) => {
                return Response::Error {
                    message: error.to_string(),
                };
            }
        };
        let interfaces = self.network.list_interfaces().await.unwrap_or_default();
        let if_map: std::collections::HashMap<u32, String> = interfaces
            .into_iter()
            .map(|iface| (iface.index, iface.name))
            .collect();

        let mut status_routes: Vec<RouteStatus> = routes
            .into_iter()
            .filter(|route| include_local_table || route.table != 255)
            .map(|route| {
                let output_interface = route
                    .output_interface_index
                    .and_then(|idx| if_map.get(&idx).cloned());
                RouteStatus::from_info(&route, output_interface)
            })
            .collect();

        status_routes.sort_by(|a, b| {
            let table_rank = |table: u32| -> (u8, u32) {
                if table == 254 {
                    (0, 0)
                } else if table == 255 {
                    (2, 255)
                } else {
                    (1, table)
                }
            };
            table_rank(a.table)
                .cmp(&table_rank(b.table))
                .then_with(|| b.destination.prefix_len().cmp(&a.destination.prefix_len()))
                .then_with(|| a.destination.network().cmp(&b.destination.network()))
                .then_with(|| a.metric.unwrap_or(0).cmp(&b.metric.unwrap_or(0)))
        });

        Response::Routes {
            routes: status_routes,
        }
    }

    pub(super) async fn get_router_config(&self) -> Response {
        match self.effective_config().await {
            Ok(effective) => Response::RouterConfig {
                config: effective.router,
            },
            Err(message) => Response::Error { message },
        }
    }

    pub(super) async fn router_plan(&self, proposal: RouterProposalRequest) -> Response {
        let Some(router) = &self.router else {
            return router_disabled();
        };
        let candidate = match self
            .overrides
            .build_candidate(&build_router_proposal(proposal))
            .await
        {
            Ok(candidate) => candidate,
            Err(error) => return classify_router_error(error),
        };
        match router.plan(candidate).await {
            Ok(plan) => Response::RouterPlan {
                plan: plan.plan().clone(),
            },
            Err(error) => classify_router_error(error),
        }
    }

    pub(super) async fn router_apply(&self, proposal: RouterProposalRequest) -> Response {
        let Some(router) = &self.router else {
            return router_disabled();
        };
        let candidate = match self
            .overrides
            .build_candidate(&build_router_proposal(proposal))
            .await
        {
            Ok(candidate) => candidate,
            Err(error) => return classify_router_error(error),
        };
        let transaction_plan = match router.plan(candidate).await {
            Ok(plan) => plan,
            Err(error) => return classify_router_error(error),
        };
        let plan_preview = transaction_plan.plan().clone();
        match router.apply(transaction_plan).await {
            Ok(token) => Response::RouterTransactionPending {
                token,
                plan: plan_preview,
            },
            Err(error) => classify_router_error(error),
        }
    }

    pub(super) async fn router_commit(&self, token: String) -> Response {
        let Some(router) = &self.router else {
            return router_disabled();
        };
        match router.commit(&token).await {
            Ok(revision) => Response::RouterCommitted { revision },
            Err(error) => classify_router_error(error),
        }
    }

    pub(super) async fn router_rollback(&self, token: String) -> Response {
        let Some(router) = &self.router else {
            return router_disabled();
        };
        match router.rollback_with_token(&token).await {
            Ok(()) => Response::RouterRolledBack,
            Err(error) => {
                if let Some(failure) = router.rollback_failure().await {
                    Response::RouterError {
                        detail: RouterErrorDetail::RollbackFailed {
                            failures: failure.failures,
                        },
                    }
                } else {
                    classify_router_error(error)
                }
            }
        }
    }

    pub(super) async fn router_pending_transaction(&self) -> Response {
        let Some(router) = &self.router else {
            return router_disabled();
        };
        let status = router.status().await;
        let rollback_failure = router
            .rollback_failure()
            .await
            .map(|failure| failure.failures);
        Response::RouterPendingTransaction {
            token: router.pending_token().await,
            status,
            rollback_failure,
        }
    }

    pub(super) async fn router_provisioning_preview(
        &self,
        request: RouterProvisioningPreviewRequest,
    ) -> Response {
        if self.router.is_none() {
            return provisioning_error(RouterProvisioningErrorDetail::RouterDisabled);
        }

        let desired = provisioning_desired(&request.provisioning);
        let secrets = ProvisioningSecretAvailability {
            uplink_pending: request.uplink_secret_pending,
            output_pending: request.output_secret_pending,
        };
        let context = match self.provisioning_context(&desired, secrets).await {
            Ok(context) => context,
            Err(detail) => return provisioning_error(detail),
        };

        match derive_router_provisioning(&desired, &context) {
            Ok(effective) => Response::RouterProvisioningPreview {
                preview: provisioning_preview_view(
                    &request.provisioning,
                    &effective,
                    &context,
                    secrets,
                ),
            },
            Err(error) => provisioning_error(classify_provisioning_derivation_error(error)),
        }
    }

    pub(super) async fn router_provisioning_apply(
        &self,
        request: RouterProvisioningApplyRequest,
    ) -> Response {
        let Some(router) = &self.router else {
            return provisioning_error(RouterProvisioningErrorDetail::RouterDisabled);
        };

        let uplink_passphrase = match parse_optional_passphrase(request.uplink_passphrase.clone()) {
            Ok(passphrase) => passphrase,
            Err(detail) => return provisioning_error(detail),
        };
        let output_passphrase = match parse_optional_passphrase(request.output_passphrase.clone()) {
            Ok(passphrase) => passphrase,
            Err(detail) => return provisioning_error(detail),
        };

        let desired = provisioning_desired(&request.provisioning);
        let context = match self
            .provisioning_context(
                &desired,
                ProvisioningSecretAvailability {
                    uplink_pending: uplink_passphrase.is_some(),
                    output_pending: output_passphrase.is_some(),
                },
            )
            .await
        {
            Ok(context) => context,
            Err(detail) => return provisioning_error(detail),
        };
        let effective = match derive_router_provisioning(&desired, &context) {
            Ok(effective) => effective,
            Err(error) => return provisioning_error(classify_provisioning_derivation_error(error)),
        };

        let preview = provisioning_preview_view(
            &request.provisioning,
            &effective,
            &context,
            ProvisioningSecretAvailability::default(),
        );

        let _wifi_mutation = self.wifi_mutations.lock().await;
        let _wifi_client_mutation = self.wifi_client_mutations.lock().await;

        let uplink_interface = desired.uplink.interface.clone();
        let output_interface = desired.output.interface.clone();
        let mut staged_uplink = None;
        let mut staged_output = None;

        if let Some(passphrase) = &output_passphrase {
            let Some(supervisor) = &self.wifi else {
                return provisioning_error(RouterProvisioningErrorDetail::GlobalServiceDisabled {
                    service: "wifi".to_owned(),
                });
            };
            let previous = match supervisor.stored_passphrase(&output_interface).await {
                Ok(previous) => previous,
                Err(error) => {
                    return provisioning_error(RouterProvisioningErrorDetail::Other {
                        message: error.to_string(),
                    })
                }
            };
            if let Err(error) = supervisor
                .set_passphrase(&output_interface, passphrase)
                .await
            {
                return provisioning_error(RouterProvisioningErrorDetail::InvalidSecret {
                    message: error.to_string(),
                });
            }
            staged_output = Some(previous);
        }

        if let Some(passphrase) = &uplink_passphrase {
            let Some(supervisor) = &self.wifi_client else {
                self.restore_staged_provisioning_secrets(
                    &uplink_interface,
                    staged_uplink,
                    &output_interface,
                    staged_output,
                )
                .await;
                return provisioning_error(RouterProvisioningErrorDetail::GlobalServiceDisabled {
                    service: "wifi_client".to_owned(),
                });
            };
            let previous = match supervisor.stored_passphrase(&uplink_interface).await {
                Ok(previous) => previous,
                Err(error) => {
                    self.restore_staged_provisioning_secrets(
                        &uplink_interface,
                        staged_uplink,
                        &output_interface,
                        staged_output,
                    )
                    .await;
                    return provisioning_error(RouterProvisioningErrorDetail::Other {
                        message: error.to_string(),
                    });
                }
            };
            if let Err(error) = supervisor
                .set_passphrase(&uplink_interface, passphrase)
                .await
            {
                self.restore_staged_provisioning_secrets(
                    &uplink_interface,
                    staged_uplink,
                    &output_interface,
                    staged_output,
                )
                .await;
                return provisioning_error(RouterProvisioningErrorDetail::InvalidSecret {
                    message: error.to_string(),
                });
            }
            staged_uplink = Some(previous);
        }

        let proposal = effective.into_router_intent_proposal();
        let candidate = match self.overrides.build_candidate(&proposal).await {
            Ok(candidate) => candidate,
            Err(error) => {
                self.restore_staged_provisioning_secrets(
                    &uplink_interface,
                    staged_uplink,
                    &output_interface,
                    staged_output,
                )
                .await;
                return provisioning_error(classify_provisioning_transaction_error(&error));
            }
        };
        let transaction_plan = match router.plan(candidate).await {
            Ok(plan) => plan,
            Err(error) => {
                self.restore_staged_provisioning_secrets(
                    &uplink_interface,
                    staged_uplink,
                    &output_interface,
                    staged_output,
                )
                .await;
                return provisioning_error(classify_provisioning_transaction_error(&error));
            }
        };
        match router.apply(transaction_plan).await {
            Ok(token) => Response::RouterProvisioningApplied { token, preview },
            Err(error) => {
                self.restore_staged_provisioning_secrets(
                    &uplink_interface,
                    staged_uplink,
                    &output_interface,
                    staged_output,
                )
                .await;
                provisioning_error(classify_provisioning_transaction_error(&error))
            }
        }
    }

    pub(super) async fn router_provisioning_status(&self) -> Response {
        let Some(router) = &self.router else {
            return provisioning_error(RouterProvisioningErrorDetail::RouterDisabled);
        };
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(message) => {
                return provisioning_error(RouterProvisioningErrorDetail::Other { message })
            }
        };
        let unconfigured = effective.router.enabled
            && effective.router.uplink.is_none()
            && effective.router.owned_routes.is_empty();
        let desired = match RouterDesired::from_effective_config(&effective) {
            Ok(desired) => desired,
            Err(error) => {
                return provisioning_error(RouterProvisioningErrorDetail::InvalidConfiguration {
                    message: error.to_string(),
                })
            }
        };

        let readiness = router.manager().health(&desired).await;
        let coordinator = router.status().await;
        let failures = router
            .rollback_failure()
            .await
            .map(|failure| failure.failures)
            .unwrap_or_default();
        let ready = desired.enabled && readiness.ready() && !unconfigured;
        let stage = match coordinator {
            CoordinatorStatus::RollbackFailed => ProvisioningStage::RollbackFailed,
            CoordinatorStatus::Pending => ProvisioningStage::AwaitingConfirmation,
            CoordinatorStatus::Idle if unconfigured => ProvisioningStage::Unconfigured,
            CoordinatorStatus::Idle if !desired.enabled => ProvisioningStage::Inactive,
            CoordinatorStatus::Idle if ready => ProvisioningStage::Ready,
            CoordinatorStatus::Idle => ProvisioningStage::Degraded,
        };

        Response::RouterProvisioningStatus {
            status: RouterProvisioningStatusView {
                stage,
                enabled: desired.enabled,
                ready,
                coordinator,
                readiness,
                failures,
            },
        }
    }

    pub(super) async fn router_provisioning_repair(&self) -> Response {
        let Some(router) = &self.router else {
            return provisioning_error(RouterProvisioningErrorDetail::RouterDisabled);
        };
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(message) => {
                return provisioning_error(RouterProvisioningErrorDetail::Other { message })
            }
        };
        let desired = match RouterDesired::from_effective_config(&effective) {
            Ok(desired) if desired.enabled => desired,
            Ok(_) => return provisioning_error(RouterProvisioningErrorDetail::RouterDisabled),
            Err(error) => {
                return provisioning_error(RouterProvisioningErrorDetail::InvalidConfiguration {
                    message: error.to_string(),
                })
            }
        };

        if let Err(error) = router.repair(desired).await {
            return provisioning_error(classify_provisioning_transaction_error(&error));
        }
        match self.router_provisioning_status().await {
            Response::RouterProvisioningStatus { status } => {
                Response::RouterProvisioningRepaired { status }
            }
            response => response,
        }
    }

    pub(super) async fn provisioning_context(
        &self,
        desired: &RouterProvisioningDesired,
        secrets: ProvisioningSecretAvailability,
    ) -> Result<RouterProvisioningContext, RouterProvisioningErrorDetail> {
        let effective_config = self
            .effective_config()
            .await
            .map_err(|message| RouterProvisioningErrorDetail::Other { message })?;
        let observed = self.network.list_interfaces().await.map_err(|error| {
            RouterProvisioningErrorDetail::Other {
                message: error.to_string(),
            }
        })?;

        let provisioned = [
            desired.uplink.interface.as_str(),
            desired.output.interface.as_str(),
        ];
        let mut interfaces = BTreeMap::new();
        let mut known_networks = Vec::new();

        for interface in &observed {
            interfaces.insert(
                interface.name.clone(),
                ProvisioningInterfaceObservation {
                    role: effective_config
                        .network
                        .interfaces
                        .get(&interface.name)
                        .map(|config| config.role),
                    wireless_phy: if interface.is_wireless {
                        crate::netlink::wireless_phy(&interface.name)
                    } else {
                        None
                    },
                },
            );

            if provisioned.contains(&interface.name.as_str()) {
                continue;
            }
            let addresses = self
                .network
                .list_ipv4_addresses(&interface.name)
                .await
                .map_err(|error| RouterProvisioningErrorDetail::Other {
                    message: error.to_string(),
                })?;
            for address in addresses {
                if let Ok(network) = ipnet::Ipv4Net::new(address.address, address.prefix_len) {
                    known_networks.push(ProvisioningKnownNetwork {
                        network: network.trunc(),
                        source: format!("observed {}", interface.name),
                    });
                }
            }
        }

        for (name, config) in &effective_config.network.interfaces {
            if provisioned.contains(&name.as_str()) {
                continue;
            }
            if let Some(ipv4) = config.ipv4 {
                known_networks.push(ProvisioningKnownNetwork {
                    network: ipv4.trunc(),
                    source: format!("configured {name}"),
                });
            }
        }

        let mut runtime_sta_secrets = BTreeSet::new();
        if secrets.uplink_pending
            || self
                .stored_uplink_secret(&desired.uplink.interface)
                .await
                .map_err(|message| RouterProvisioningErrorDetail::Other { message })?
        {
            runtime_sta_secrets.insert(desired.uplink.interface.clone());
        }
        let mut runtime_ap_secrets = BTreeSet::new();
        if secrets.output_pending
            || self
                .stored_output_secret(&desired.output.interface)
                .await
                .map_err(|message| RouterProvisioningErrorDetail::Other { message })?
        {
            runtime_ap_secrets.insert(desired.output.interface.clone());
        }

        Ok(RouterProvisioningContext {
            effective_config,
            wifi_runtime_available: self.wifi.is_some(),
            wifi_client_runtime_available: self.wifi_client.is_some(),
            interfaces,
            known_networks,
            runtime_ap_secrets,
            runtime_sta_secrets,
        })
    }

    pub(super) async fn stored_uplink_secret(&self, interface: &str) -> Result<bool, String> {
        let Some(supervisor) = &self.wifi_client else {
            return Ok(false);
        };
        supervisor
            .stored_passphrase(interface)
            .await
            .map(|secret| secret.is_some())
            .map_err(|error| error.to_string())
    }

    pub(super) async fn stored_output_secret(&self, interface: &str) -> Result<bool, String> {
        let Some(supervisor) = &self.wifi else {
            return Ok(false);
        };
        supervisor
            .stored_passphrase(interface)
            .await
            .map(|secret| secret.is_some())
            .map_err(|error| error.to_string())
    }

    pub(super) async fn restore_staged_provisioning_secrets(
        &self,
        uplink_interface: &str,
        staged_uplink: Option<Option<WifiPassphrase>>,
        output_interface: &str,
        staged_output: Option<Option<WifiPassphrase>>,
    ) {
        if let (Some(previous), Some(supervisor)) = (staged_uplink, self.wifi_client.as_ref()) {
            restore_wifi_client_secret(supervisor, uplink_interface, previous.as_ref()).await;
        }
        if let (Some(previous), Some(supervisor)) = (staged_output, self.wifi.as_ref()) {
            restore_wifi_secret(supervisor, output_interface, previous.as_ref()).await;
        }
    }

    pub(super) async fn current_router_desired(&self) -> Result<RouterDesired, Response> {
        let snapshot = self.overrides.snapshot().await;
        let effective = snapshot
            .effective_config(&self.base_config)
            .map_err(classify_router_error)?;
        RouterDesired::from_effective_config(&effective).map_err(classify_router_error)
    }
}
