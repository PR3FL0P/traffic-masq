use super::provisioning::*;
use super::*;
use crate::core::recovery::{RecoveryAction, RecoveryCode};

fn router_recovery_notice(
    status: CoordinatorStatus,
    failures: Vec<String>,
) -> Option<RouterRecoveryNotice> {
    if status == CoordinatorStatus::CommitIndeterminate {
        return Some(RouterRecoveryNotice {
            recovery_progress: None,
            recovery_code: RecoveryCode::CommitIndeterminate.as_str().to_owned(),
            invariant: RecoveryCode::CommitIndeterminate.invariant().to_owned(),
            summary: "Commit persistence and compensation failed; the durable outcome is unknown."
                .to_owned(),
            blocked_operation: "mutations, confirmation and rollback".to_owned(),
            operator_action: RecoveryAction::RepairStorageAndRestart.as_str().to_owned(),
            operator_guidance: RecoveryAction::RepairStorageAndRestart
                .guidance()
                .to_owned(),
            runbook: RecoveryCode::CommitIndeterminate.runbook_ref().to_owned(),
            failures,
        });
    }
    let (code, action, summary) = match status {
        CoordinatorStatus::RecoveryRequired => (
            RecoveryCode::RouterRollbackFailed,
            RecoveryAction::RetryRollback,
            "Automatic recovery stopped. Repair the reported cause and explicitly retry rollback.",
        ),
        CoordinatorStatus::RollbackFailed => (
            RecoveryCode::RouterRollbackFailed,
            RecoveryAction::RetryRollback,
            "Previous router rollback did not fully restore runtime state.",
        ),
        CoordinatorStatus::RecoveredButJournalCleanupPending => (
            RecoveryCode::RouterJournalCleanupPending,
            RecoveryAction::AwaitCleanup,
            "Router recovery completed, but journal cleanup is still pending.",
        ),
        CoordinatorStatus::Idle
        | CoordinatorStatus::Pending
        | CoordinatorStatus::CommitIndeterminate => return None,
    };

    Some(RouterRecoveryNotice {
        recovery_progress: None,
        recovery_code: code.as_str().to_owned(),
        invariant: code.invariant().to_owned(),
        summary: summary.to_owned(),
        blocked_operation: "new router transactions".to_owned(),
        operator_action: action.as_str().to_owned(),
        operator_guidance: action.guidance().to_owned(),
        runbook: code.runbook_ref().to_owned(),
        failures,
    })
}

use crate::core::provisioning_secret_transaction::ProvisioningSecretTransactionStore;

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
        let coordinator = router.view().await;
        let status = coordinator.status();
        let recovery = router_recovery_notice(status, coordinator.failures()).map(|mut notice| {
            notice.recovery_progress = crate::core::recovery_control::progress(
                &self
                    .config
                    .runtime
                    .state_dir
                    .join("router-transaction.json"),
            );
            notice
        });
        Response::RouterStatus {
            enabled: desired.enabled,
            ready: desired.enabled && health.ready(),
            coordinator_status: status,
            health,
            recovery,
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
            routes: status_routes.into_iter().map(Into::into).collect(),
        }
    }

    pub(super) async fn get_router_config(&self) -> Response {
        match self.effective_config().await {
            Ok(effective) => Response::RouterConfig {
                config: effective.router.into(),
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
                plan: plan.plan().clone().into(),
            },
            Err(error) => classify_router_error(error),
        }
    }

    pub(super) async fn router_apply(&self, proposal: RouterProposalRequest) -> Response {
        let Some(router) = &self.router else {
            return router_disabled();
        };
        if !self.transactions.pending().await.is_empty() {
            return Response::RouterError {
                detail: RouterErrorDetail::Other {
                    message: "an interface transaction is pending; commit or roll it back before starting a router transaction".to_owned(),
                },
            };
        }
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
                plan: plan_preview.into(),
            },
            Err(error) => classify_router_error(error),
        }
    }

    pub(super) async fn router_commit(&self, token: String) -> Response {
        let Some(router) = &self.router else {
            return router_disabled();
        };
        match router.commit(&token).await {
            Ok(revision) => {
                // The router commit is authoritative. If journal cleanup fails,
                // startup recovery sees the committed token and discards the
                // old secrets rather than restoring them.
                let secrets = ProvisioningSecretTransactionStore::in_state_dir(
                    &self.config.runtime.state_dir,
                );
                if let Err(error) = secrets.finish(Some(&token)).await {
                    tracing::warn!(%error, %token, "failed to clean committed provisioning secret journal");
                }
                Response::RouterCommitted { revision }
            }
            Err(error) => classify_router_error(error),
        }
    }

    pub(super) async fn router_rollback(&self, token: String) -> Response {
        let Some(router) = &self.router else {
            return router_disabled();
        };
        match router.rollback_with_token(&token).await {
            Ok(()) => {
                let secrets = ProvisioningSecretTransactionStore::in_state_dir(
                    &self.config.runtime.state_dir,
                );
                match secrets
                    .restore(Some(&token))
                    .await
                {
                    Ok(true) => {
                        // The snapshot rollback ran while the staged secret was
                        // still installed. Keep the journal until the old secret
                        // is also active in hostapd/wpa_supplicant.
                        let desired = match self.current_router_desired().await {
                            Ok(desired) => desired,
                            Err(response) => return response,
                        };
                        if let Err(error) = router.repair(desired).await {
                            return classify_router_error(error.context(
                                "router state restored but Wi-Fi secret re-convergence failed; recovery journal retained",
                            ));
                        }
                        if let Err(error) = secrets.finish(Some(&token)).await {
                            return classify_router_error(error.context(
                                "router state and Wi-Fi secrets were restored but recovery journal cleanup failed",
                            ));
                        }
                    }
                    Ok(false) => {}
                    Err(error) => {
                        return Response::RouterError {
                            detail: RouterErrorDetail::Other {
                                message: format!(
                                    "router state restored but provisioning secrets could not be restored: {error:#}"
                                ),
                            },
                        }
                    }
                }
                Response::RouterRolledBack
            }
            Err(error) => {
                if error.downcast_ref::<NoPendingTransactionError>().is_some() {
                    let committed_token =
                        self.overrides.snapshot().await.committed_router_transaction;
                    if committed_token.as_deref() != Some(token.as_str()) {
                        let secrets = ProvisioningSecretTransactionStore::in_state_dir(
                            &self.config.runtime.state_dir,
                        );
                        match secrets.restore(Some(&token)).await {
                            Ok(true) => {
                                let desired = match self.current_router_desired().await {
                                    Ok(desired) => desired,
                                    Err(response) => return response,
                                };
                                if let Err(repair_error) = router.repair(desired).await {
                                    return classify_router_error(repair_error.context(
                                        "router rollback completed but Wi-Fi secret re-convergence failed; recovery journal retained",
                                    ));
                                }
                                if let Err(cleanup_error) = secrets.finish(Some(&token)).await {
                                    return classify_router_error(cleanup_error.context(
                                        "router rollback and Wi-Fi secret re-convergence completed but recovery journal cleanup failed",
                                    ));
                                }
                                return Response::RouterRolledBack;
                            }
                            Ok(false) => {}
                            Err(secret_error) => {
                                return Response::RouterError {
                                    detail: RouterErrorDetail::Other {
                                        message: format!(
                                            "router rollback completed but provisioning secrets could not be restored: {secret_error:#}"
                                        ),
                                    },
                                };
                            }
                        }
                    }
                }
                let coordinator = router.view().await;
                if matches!(
                    coordinator.status(),
                    CoordinatorStatus::RollbackFailed | CoordinatorStatus::RecoveryRequired
                ) {
                    Response::RouterError {
                        detail: RouterErrorDetail::RollbackFailed {
                            failures: coordinator.rollback_failures,
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
        let coordinator = router.view().await;
        let status = coordinator.status();
        let rollback_failure = (matches!(
            status,
            CoordinatorStatus::RollbackFailed | CoordinatorStatus::RecoveryRequired
        ))
        .then(|| coordinator.rollback_failures.clone());
        let recovery = router_recovery_notice(status, coordinator.failures()).map(|mut notice| {
            notice.recovery_progress = crate::core::recovery_control::progress(
                &self
                    .config
                    .runtime
                    .state_dir
                    .join("router-transaction.json"),
            );
            notice
        });
        let token = coordinator.token;
        Response::RouterPendingTransaction {
            token,
            status,
            rollback_failure,
            recovery,
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
        match router.status().await {
            CoordinatorStatus::Idle => {}
            CoordinatorStatus::Pending => {
                return provisioning_error(RouterProvisioningErrorDetail::TransactionPending);
            }
            CoordinatorStatus::RollbackFailed
            | CoordinatorStatus::RecoveryRequired
            | CoordinatorStatus::CommitIndeterminate
            | CoordinatorStatus::RecoveredButJournalCleanupPending => {
                return provisioning_error(RouterProvisioningErrorDetail::RollbackRecoveryRequired);
            }
        }
        if !self.transactions.pending().await.is_empty() {
            return provisioning_error(RouterProvisioningErrorDetail::Other {
                message: "an interface transaction is pending; commit or roll it back before provisioning the router".to_owned(),
            });
        }

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
        let output_supervisor = if output_passphrase.is_some() {
            match self.wifi.as_ref() {
                Some(supervisor) => Some(supervisor),
                None => {
                    return provisioning_error(
                        RouterProvisioningErrorDetail::GlobalServiceDisabled {
                            service: "wifi".to_owned(),
                        },
                    )
                }
            }
        } else {
            None
        };
        let uplink_supervisor = if uplink_passphrase.is_some() {
            match self.wifi_client.as_ref() {
                Some(supervisor) => Some(supervisor),
                None => {
                    return provisioning_error(
                        RouterProvisioningErrorDetail::GlobalServiceDisabled {
                            service: "wifi_client".to_owned(),
                        },
                    )
                }
            }
        } else {
            None
        };

        // Persist the old values *before* changing either secret. The journal
        // is the secret half of the router transaction and lets startup recover
        // a crash anywhere between staging and commit.
        let mut previous = BTreeMap::new();
        if let Some(supervisor) = output_supervisor {
            match supervisor.stored_passphrase(&output_interface).await {
                Ok(secret) => {
                    previous.insert(
                        output_interface.clone(),
                        (crate::wifi::store::WifiCredentialRole::Ap, secret),
                    );
                }
                Err(error) => {
                    return provisioning_error(RouterProvisioningErrorDetail::Other {
                        message: error.to_string(),
                    })
                }
            }
        }
        if let Some(supervisor) = uplink_supervisor {
            match supervisor.stored_passphrase(&uplink_interface).await {
                Ok(secret) => {
                    previous.insert(
                        uplink_interface.clone(),
                        (crate::wifi::store::WifiCredentialRole::Client, secret),
                    );
                }
                Err(error) => {
                    return provisioning_error(RouterProvisioningErrorDetail::Other {
                        message: error.to_string(),
                    })
                }
            }
        }

        let secret_tx =
            ProvisioningSecretTransactionStore::in_state_dir(&self.config.runtime.state_dir);
        if let Err(error) = secret_tx.stage(previous).await {
            return provisioning_error(RouterProvisioningErrorDetail::Other {
                message: format!("failed to open provisioning secret transaction: {error:#}"),
            });
        }

        if let (Some(supervisor), Some(passphrase)) =
            (output_supervisor, output_passphrase.as_ref())
        {
            if let Err(error) = supervisor
                .set_passphrase(&output_interface, passphrase)
                .await
            {
                let restore = restore_staged_and_finish(&secret_tx).await;
                return provisioning_error(RouterProvisioningErrorDetail::InvalidSecret {
                    message: match restore {
                        Ok(_) => error.to_string(),
                        Err(restore_error) => format!(
                            "{error}; restoring prior provisioning secrets also failed: {restore_error:#}"
                        ),
                    },
                });
            }
        }
        if let (Some(supervisor), Some(passphrase)) =
            (uplink_supervisor, uplink_passphrase.as_ref())
        {
            if let Err(error) = supervisor
                .set_passphrase(&uplink_interface, passphrase)
                .await
            {
                let restore = restore_staged_and_finish(&secret_tx).await;
                return provisioning_error(RouterProvisioningErrorDetail::InvalidSecret {
                    message: match restore {
                        Ok(_) => error.to_string(),
                        Err(restore_error) => format!(
                            "{error}; restoring prior provisioning secrets also failed: {restore_error:#}"
                        ),
                    },
                });
            }
        }

        let proposal = effective.into_router_intent_proposal();
        let candidate = match self.overrides.build_candidate(&proposal).await {
            Ok(candidate) => candidate,
            Err(error) => {
                let restore = restore_staged_and_finish(&secret_tx).await;
                if let Err(restore_error) = restore {
                    return provisioning_error(RouterProvisioningErrorDetail::Other {
                        message: format!(
                            "{error:#}; restoring prior provisioning secrets also failed: {restore_error:#}"
                        ),
                    });
                }
                return provisioning_error(classify_provisioning_transaction_error(&error));
            }
        };
        let transaction_plan = match router.plan(candidate).await {
            Ok(plan) => plan,
            Err(error) => {
                let restore = restore_staged_and_finish(&secret_tx).await;
                if let Err(restore_error) = restore {
                    return provisioning_error(RouterProvisioningErrorDetail::Other {
                        message: format!(
                            "{error:#}; restoring prior provisioning secrets also failed: {restore_error:#}"
                        ),
                    });
                }
                return provisioning_error(classify_provisioning_transaction_error(&error));
            }
        };

        let token = match router.apply(transaction_plan).await {
            Ok(token) => token,
            Err(error) => {
                // A clean coordinator rollback means the network is back at its
                // snapshot and it is safe to restore the staged secret. The
                // rollback itself ran while the new secret was still present,
                // so reconcile once more after restoring it to ensure running
                // Wi-Fi daemons also use the committed secret.
                if !matches!(
                    router.status().await,
                    CoordinatorStatus::RollbackFailed | CoordinatorStatus::RecoveryRequired
                ) {
                    match secret_tx.restore(None).await {
                        Ok(true) => {
                            let committed = match self.current_router_desired().await {
                                Ok(desired) => desired,
                                Err(response) => return response,
                            };
                            if let Err(repair_error) = router.repair(committed).await {
                                return provisioning_error(RouterProvisioningErrorDetail::Other {
                                    message: format!(
                                        "{error:#}; prior secrets were restored but Wi-Fi re-convergence failed: {repair_error:#}; recovery journal retained"
                                    ),
                                });
                            }
                            if let Err(cleanup_error) = secret_tx.finish(None).await {
                                return provisioning_error(RouterProvisioningErrorDetail::Other {
                                    message: format!(
                                        "{error:#}; prior secrets and runtime were restored but recovery journal cleanup failed: {cleanup_error:#}; recovery required"
                                    ),
                                });
                            }
                        }
                        Ok(false) => {}
                        Err(restore_error) => {
                            return provisioning_error(RouterProvisioningErrorDetail::Other {
                                message: format!(
                                    "{error:#}; restoring prior provisioning secrets also failed: {restore_error:#}"
                                ),
                            });
                        }
                    }
                }
                return provisioning_error(classify_provisioning_transaction_error(&error));
            }
        };

        if let Err(error) = secret_tx.bind_token(&token).await {
            match router.rollback_with_token(&token).await {
                Ok(()) => {
                    let message = match secret_tx
                        .restore(Some(&token))
                        .await
                    {
                        Ok(true) => {
                            let committed = match self.current_router_desired().await {
                                Ok(desired) => desired,
                                Err(response) => return response,
                            };
                            match router.repair(committed).await {
                                Ok(()) => match secret_tx.finish(Some(&token)).await {
                                    Ok(_) => format!(
                                        "failed to bind provisioning secrets to router transaction {token}: {error:#}; router state and prior secrets were restored"
                                    ),
                                    Err(cleanup_error) => format!(
                                        "failed to bind provisioning secrets to router transaction {token}: {error:#}; router state and prior secrets were restored but recovery journal cleanup failed: {cleanup_error:#}; recovery required"
                                    ),
                                },
                                Err(repair_error) => format!(
                                    "failed to bind provisioning secrets to router transaction {token}: {error:#}; prior secrets were restored but Wi-Fi re-convergence failed: {repair_error:#}; recovery journal retained"
                                ),
                            }
                        }
                        Ok(false) => format!(
                            "failed to bind provisioning secrets to router transaction {token}: {error:#}"
                        ),
                        Err(restore_error) => format!(
                            "failed to bind provisioning secrets to router transaction {token}: {error:#}; restoring prior secrets also failed: {restore_error:#}"
                        ),
                    };
                    return provisioning_error(RouterProvisioningErrorDetail::Other { message });
                }
                Err(rollback_error) => {
                    return provisioning_error(RouterProvisioningErrorDetail::Other {
                        message: format!(
                            "failed to bind provisioning secrets to router transaction {token}: {error:#}; router rollback also failed: {rollback_error:#}; recovery journal retained"
                        ),
                    });
                }
            }
        }

        self.spawn_provisioning_secret_timeout_recovery(token.clone());
        Response::RouterProvisioningApplied { token, preview }
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
            && effective.router.owned_routes.is_empty()
            && effective.router.forwarding.is_none();
        let desired = match RouterDesired::from_effective_config(&effective) {
            Ok(desired) => desired,
            Err(error) => {
                return provisioning_error(RouterProvisioningErrorDetail::InvalidConfiguration {
                    message: error.to_string(),
                })
            }
        };

        let readiness = router.manager().health(&desired).await;
        let coordinator = router.view().await;
        let status = coordinator.status();
        let failures = coordinator.failures();
        let ready = desired.enabled && readiness.ready() && !unconfigured;
        let stage = match status {
            CoordinatorStatus::RollbackFailed | CoordinatorStatus::RecoveryRequired => {
                ProvisioningStage::RollbackFailed
            }
            CoordinatorStatus::RecoveredButJournalCleanupPending
            | CoordinatorStatus::CommitIndeterminate => ProvisioningStage::Degraded,
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
                coordinator: status,
                readiness,
                failures,
            },
        }
    }

    pub(super) async fn router_provisioning_repair(&self) -> Response {
        let Some(router) = &self.router else {
            return provisioning_error(RouterProvisioningErrorDetail::RouterDisabled);
        };
        if !self.transactions.pending().await.is_empty() {
            return provisioning_error(RouterProvisioningErrorDetail::Other {
                message: "an interface transaction is pending; commit or roll it back before repairing router state".to_owned(),
            });
        }
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
                        self.network.wireless_phy(&interface.name)
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

    fn spawn_provisioning_secret_timeout_recovery(&self, token: String) {
        let Some(router) = self.router.clone() else {
            return;
        };
        let timeout = Duration::from_secs(self.config.security.rollback_timeout_seconds);
        let state_dir = self.config.runtime.state_dir.clone();
        let overrides = self.overrides.clone();
        let base_config = self.base_config.clone();
        let network_mutations = self.network_mutations.clone();
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            let _network_mutation = network_mutations.write().await;

            if crate::core::recovery::check_commit(&state_dir).is_err() {
                return;
            }
            // Race safely with the coordinator's own timer/commit path. Both
            // router operations serialize on the coordinator state lock.
            let committed = overrides
                .snapshot()
                .await
                .committed_router_transaction
                .as_deref()
                == Some(token.as_str());
            let secrets = ProvisioningSecretTransactionStore::in_state_dir(&state_dir);
            if committed {
                if let Err(error) = secrets.finish(Some(&token)).await {
                    tracing::warn!(%error, %token, "failed to clean committed provisioning secret journal");
                }
                return;
            }

            if router.status().await == CoordinatorStatus::Pending {
                if let Err(error) = router.rollback_for_shutdown().await {
                    tracing::error!(%error, %token, "router provisioning timeout rollback failed; secret journal retained");
                    return;
                }
            }
            if router.status().await != CoordinatorStatus::Idle {
                return;
            }

            let committed = overrides
                .snapshot()
                .await
                .committed_router_transaction
                .as_deref()
                == Some(token.as_str());
            if committed {
                if let Err(error) = secrets.finish(Some(&token)).await {
                    tracing::warn!(%error, %token, "failed to clean committed provisioning secret journal");
                }
                return;
            }

            match secrets.restore(Some(&token)).await {
                Ok(true) => {
                    let snapshot = overrides.snapshot().await;
                    match snapshot
                        .effective_config(&base_config)
                        .and_then(|effective| RouterDesired::from_effective_config(&effective))
                    {
                        Ok(desired) => match router.repair(desired).await {
                            Ok(()) => {
                                if let Err(error) = secrets.finish(Some(&token)).await {
                                    tracing::error!(%error, %token, "provisioning timeout recovery converged but journal cleanup failed; recovery remains blocked");
                                }
                            }
                            Err(error) => {
                                tracing::error!(%error, %token, "provisioning secrets restored after timeout but router re-convergence failed; recovery journal retained");
                            }
                        },
                        Err(error) => {
                            tracing::error!(%error, %token, "could not derive committed router state after provisioning timeout; recovery journal retained")
                        }
                    }
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::error!(%error, %token, "failed to restore provisioning secrets after timeout")
                }
            }
        });
    }

    pub(super) async fn current_router_desired(&self) -> Result<RouterDesired, Response> {
        let snapshot = self.overrides.snapshot().await;
        let effective = snapshot
            .effective_config(&self.base_config)
            .map_err(classify_router_error)?;
        RouterDesired::from_effective_config(&effective).map_err(classify_router_error)
    }
}

pub(super) fn router_disabled() -> Response {
    Response::RouterError {
        detail: RouterErrorDetail::RouterDisabled,
    }
}

pub(super) fn build_router_proposal(request: RouterProposalRequest) -> RouterIntentProposal {
    let mut proposal = RouterIntentProposal::new();
    if request.clear_router {
        proposal = proposal.clear_router();
    } else if let Some(router) = request.set_router {
        proposal = proposal.set_router(router);
    }
    for (interface, over) in request.set_interfaces {
        proposal = proposal.set_interface(interface, over.config, over.allow_management_change);
    }
    for interface in request.remove_interfaces {
        proposal = proposal.remove_interface(interface);
    }
    proposal
}

pub(super) fn classify_router_error(error: anyhow::Error) -> Response {
    let detail = if let Some(conflict) = error.downcast_ref::<CoordinatorConflict>() {
        match conflict {
            CoordinatorConflict::TransactionPending => RouterErrorDetail::TransactionPending,
            CoordinatorConflict::RollbackRecoveryRequired => {
                RouterErrorDetail::RollbackRecoveryRequired
            }
        }
    } else if let Some(stale) = error.downcast_ref::<StaleCandidateError>() {
        RouterErrorDetail::StaleCandidate {
            candidate_revision: stale.candidate,
            current_revision: stale.current,
        }
    } else if error
        .downcast_ref::<crate::core::router_transaction::StalePlanError>()
        .is_some()
    {
        RouterErrorDetail::StalePlan
    } else if error.downcast_ref::<NoPendingTransactionError>().is_some() {
        RouterErrorDetail::NoPendingTransaction
    } else {
        RouterErrorDetail::Other {
            message: error.to_string(),
        }
    };
    Response::RouterError { detail }
}

async fn restore_staged_and_finish(
    secrets: &ProvisioningSecretTransactionStore,
) -> anyhow::Result<bool> {
    let restored = secrets.restore(None).await?;
    if restored {
        secrets.finish(None).await?;
    }
    Ok(restored)
}

#[cfg(test)]
mod recovery_notice_tests {
    use super::*;

    #[test]
    fn uncertain_commit_notice_requires_storage_repair_and_restart() {
        let notice = router_recovery_notice(
            CoordinatorStatus::CommitIndeterminate,
            vec!["I/O failed".into()],
        )
        .unwrap();
        assert_eq!(
            notice.operator_action.parse::<RecoveryAction>().ok(),
            Some(RecoveryAction::RepairStorageAndRestart)
        );
        assert_eq!(
            RecoveryCode::from_code(&notice.recovery_code),
            Some(RecoveryCode::CommitIndeterminate)
        );
        assert!(notice.blocked_operation.contains("rollback"));
    }

    #[test]
    fn rollback_failed_notice_is_actionable() {
        let notice = router_recovery_notice(
            CoordinatorStatus::RollbackFailed,
            vec!["route restore failed".to_owned()],
        )
        .expect("rollback recovery notice");
        assert_eq!(notice.recovery_code, "TM-REC-207");
        assert_eq!(notice.invariant, "router_rollback_failed");
        assert_eq!(notice.blocked_operation, "new router transactions");
        assert!(!notice.summary.is_empty());
        assert_eq!(notice.operator_action, "retry_rollback");
        assert_eq!(
            notice.operator_action.parse::<RecoveryAction>().ok(),
            Some(RecoveryAction::RetryRollback)
        );
        assert_eq!(
            RecoveryCode::from_code(&notice.recovery_code),
            Some(RecoveryCode::RouterRollbackFailed)
        );
        assert_eq!(notice.runbook, "docs/recovery.md#tm-rec-207");
        assert_eq!(notice.failures, vec!["route restore failed"]);
    }

    #[test]
    fn cleanup_pending_notice_does_not_request_another_rollback() {
        let notice = router_recovery_notice(
            CoordinatorStatus::RecoveredButJournalCleanupPending,
            Vec::new(),
        )
        .expect("cleanup recovery notice");
        assert_eq!(notice.recovery_code, "TM-REC-208");
        assert_eq!(notice.invariant, "router_journal_cleanup_pending");
        assert_eq!(notice.blocked_operation, "new router transactions");
        assert!(!notice.summary.is_empty());
        assert_eq!(notice.operator_action, "await_cleanup");
        assert_eq!(
            notice.operator_action.parse::<RecoveryAction>().ok(),
            Some(RecoveryAction::AwaitCleanup)
        );
        assert_eq!(
            RecoveryCode::from_code(&notice.recovery_code),
            Some(RecoveryCode::RouterJournalCleanupPending)
        );
        assert_eq!(notice.runbook, "docs/recovery.md#tm-rec-208");
        assert!(notice.failures.is_empty());
    }

    #[test]
    fn healthy_and_pending_transactions_do_not_emit_recovery_notice() {
        assert!(router_recovery_notice(CoordinatorStatus::Idle, Vec::new()).is_none());
        assert!(router_recovery_notice(CoordinatorStatus::Pending, Vec::new()).is_none());
    }
}
