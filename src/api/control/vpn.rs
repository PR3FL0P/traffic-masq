use super::runtime::compensation_message;
use super::*;
use crate::api::model::{VpnActiveStatus, VpnProfileSummary};

fn vpn_profile_summary(summary: crate::vpn::WireGuardProfileSummary) -> VpnProfileSummary {
    VpnProfileSummary {
        name: summary.name,
        size_bytes: summary.size_bytes,
        modified_unix: summary.modified.and_then(|modified| {
            modified
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .ok()
                .map(|duration| duration.as_secs())
        }),
    }
}

fn vpn_active_status(status: crate::vpn::VpnActiveStatus) -> VpnActiveStatus {
    VpnActiveStatus {
        profile_name: status.profile_name,
        interface: status.interface,
        up: status.up,
    }
}

impl ControlService {
    pub(super) async fn vpn_config(&self) -> Response {
        match self.effective_config().await {
            Ok(config) => Response::VpnConfig {
                enabled: config.vpn.enabled,
            },
            Err(message) => Response::Error { message },
        }
    }

    pub(super) async fn set_vpn_enabled(&self, enabled: bool) -> Response {
        let Some(vpn) = &self.vpn else {
            return Response::Error {
                message: "VPN runtime unavailable".into(),
            };
        };
        if !enabled {
            let effective = match self.effective_config().await {
                Ok(config) => config,
                Err(message) => return Response::Error { message },
            };
            if !effective.router.vpn_chain.is_empty()
                || self.overrides.effective_vpn_mode().await == VpnPolicyMode::Vpn
            {
                return Response::Error { message: "Remove the router VPN chain and select Direct traffic policy before disabling VPN".into() };
            }
            match vpn.status().await {
                Ok(Some(_)) => {
                    return Response::Error {
                        message: "Disconnect the active VPN profile before disabling VPN".into(),
                    }
                }
                Err(error) => return classify_vpn_error(error),
                Ok(None) => {}
            }
        }
        match self.overrides.set_vpn_enabled(enabled).await {
            Ok(()) => self.vpn_config().await,
            Err(error) => Response::Error {
                message: error.to_string(),
            },
        }
    }

    async fn vpn_is_enabled(&self) -> bool {
        self.effective_config()
            .await
            .is_ok_and(|config| config.vpn.enabled)
    }

    pub(super) async fn vpn_list_profiles(&self) -> Response {
        let Some(vpn) = &self.vpn else {
            return vpn_disabled();
        };
        match vpn.list_profiles() {
            Ok(profiles) => Response::VpnProfiles {
                profiles: profiles.into_iter().map(vpn_profile_summary).collect(),
            },
            Err(error) => classify_vpn_error(error),
        }
    }

    pub(super) async fn vpn_import_profile(&self, name: String, contents: String) -> Response {
        let Some(vpn) = &self.vpn else {
            return vpn_disabled();
        };
        match self.vpn_profile_referenced_by_router(&name).await {
            Ok(true) => return vpn_error(VpnErrorDetail::ProfileInUse { name }),
            Ok(false) => {}
            Err(message) => return vpn_error(VpnErrorDetail::Other { message }),
        }
        match vpn.import_profile(&name, contents.as_bytes()) {
            Ok(name) => Response::VpnProfileImported { name },
            Err(error) => classify_vpn_error(error),
        }
    }

    pub(super) async fn vpn_delete_profile(&self, name: String) -> Response {
        let Some(vpn) = &self.vpn else {
            return vpn_disabled();
        };

        match self.vpn_profile_referenced_by_router(&name).await {
            Ok(true) => return vpn_error(VpnErrorDetail::ProfileInUse { name }),
            Ok(false) => {}
            Err(message) => return vpn_error(VpnErrorDetail::Other { message }),
        }

        match vpn.delete_profile(&name) {
            Ok(()) => Response::VpnProfileDeleted { name },
            Err(error) => classify_vpn_error(error),
        }
    }

    async fn vpn_profile_referenced_by_router(&self, name: &str) -> Result<bool, String> {
        if self.router.is_none() {
            return Ok(false);
        }
        let desired = self.current_router_desired().await.map_err(|error| {
            format!("cannot verify whether VPN profile '{name}' is used by the router: {error:?}")
        })?;
        Ok(desired.vpn_chain.iter().any(|hop| hop.profile_name == name))
    }

    pub(super) async fn vpn_status(&self) -> Response {
        if !self.vpn_is_enabled().await {
            return vpn_disabled();
        }
        let Some(vpn) = &self.vpn else {
            return vpn_disabled();
        };
        match vpn.status().await {
            Ok(active) => Response::VpnStatus {
                active: active.map(vpn_active_status),
            },
            Err(error) => classify_vpn_error(error),
        }
    }

    pub(super) async fn vpn_activate(&self, name: String) -> Response {
        if !self.vpn_is_enabled().await {
            return vpn_disabled();
        }
        let Some(vpn) = &self.vpn else {
            return vpn_disabled();
        };
        if let Err(error) = vpn.activate(&name).await {
            return classify_vpn_error(error);
        }
        match vpn.status().await {
            Ok(Some(active)) => Response::VpnActivated {
                active: vpn_active_status(active),
            },
            Ok(None) => {
                tracing::error!("VPN activation reported success but no interface is active");
                Response::Error {
                    message: "VPN activation succeeded but left no active interface".to_string(),
                }
            }
            Err(error) => classify_vpn_error(error),
        }
    }

    pub(super) async fn vpn_deactivate(&self) -> Response {
        let Some(vpn) = &self.vpn else {
            return vpn_disabled();
        };
        match vpn.deactivate().await {
            Ok(()) => Response::VpnDeactivated,
            Err(error) => classify_vpn_error(error),
        }
    }

    pub(super) async fn vpn_policy_status(&self) -> Response {
        if !self.vpn_is_enabled().await {
            return vpn_policy_disabled();
        }
        let (Some(policy), Some(vpn)) = (&self.vpn_policy, &self.vpn) else {
            return vpn_policy_disabled();
        };
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(error) => return vpn_policy_error(VpnPolicyErrorDetail::Other { message: error }),
        };
        self.vpn_policy_status_for(policy, vpn, &effective).await
    }

    pub(super) async fn vpn_policy_status_for(
        &self,
        policy: &VpnPolicyManager<WireGuardVpnDriver, Arc<dyn NftExecutor>>,
        vpn: &ProductionVpnManager,
        effective: &AppConfig,
    ) -> Response {
        let tunnel = match vpn.status().await {
            Ok(active) => active,
            Err(error) => return classify_vpn_error(error),
        };
        let tunnel_healthy = tunnel
            .as_ref()
            .is_some_and(|status| status.up && status.interface == OWNED_INTERFACE_NAME);

        let snapshot = match policy.snapshot(&vpn_policy_teardown_target()).await {
            Ok(snapshot) => snapshot,
            Err(error) => return vpn_policy_error(classify_vpn_policy_error(&error)),
        };
        let policy_active = snapshot.is_active();

        let desired = vpn_policy_desired(effective);
        let mode = self.overrides.effective_vpn_mode().await;
        let mode_override_active = self.overrides.snapshot().await.vpn_mode.is_some();

        Response::VpnPolicyStatus {
            status: VpnPolicyStatusView {
                mode,
                mode_override_active,
                tunnel: tunnel.map(vpn_active_status),
                tunnel_healthy,
                policy_active,
                kill_switch_active: policy_active,
                protected_subnets: desired
                    .as_ref()
                    .map(|desired| desired.protected_subnets.clone())
                    .unwrap_or_default(),
                physical_uplink: desired.map(|desired| desired.physical_uplink),
            },
        }
    }

    pub(super) async fn vpn_policy_apply_mode(
        &self,
        policy: &VpnPolicyManager<WireGuardVpnDriver, Arc<dyn NftExecutor>>,
        effective: &AppConfig,
        target: VpnPolicyMode,
    ) -> Result<(), Response> {
        match target {
            VpnPolicyMode::Vpn => {
                let Some(desired) = vpn_policy_desired(effective) else {
                    return Err(vpn_policy_error(VpnPolicyErrorDetail::NoProtectedSubnets));
                };
                policy
                    .activate(&desired)
                    .await
                    .map(|_| ())
                    .map_err(|error| vpn_policy_error(classify_vpn_policy_error(&error)))
            }
            VpnPolicyMode::Direct => {
                let desired =
                    vpn_policy_desired(effective).unwrap_or_else(vpn_policy_teardown_target);
                policy.deactivate(&desired).await.map_err(|error| {
                    vpn_policy_error(VpnPolicyErrorDetail::Other {
                        message: error.to_string(),
                    })
                })
            }
        }
    }

    pub(super) async fn vpn_policy_set_mode(&self, mode: VpnPolicyMode) -> Response {
        if !self.vpn_is_enabled().await {
            return vpn_policy_disabled();
        }
        let (Some(policy), Some(_vpn)) = (&self.vpn_policy, &self.vpn) else {
            return vpn_policy_disabled();
        };
        // Coexistence-window guard (Landing 1): `vpn_policy_set_mode` bypasses
        // `RouterTransactionCoordinator` entirely, so it must not race a
        // pending chain transaction over the same hop-0 reserved-ID band.
        // Refuse outright while a transaction is
        // pending or stuck in a failed rollback rather than letting the two
        // non-coordinated mutation paths touch the same resources at once.
        if let Some(router) = &self.router {
            match router.status().await {
                crate::core::router_transaction::CoordinatorStatus::Idle => {}
                crate::core::router_transaction::CoordinatorStatus::Pending
                | crate::core::router_transaction::CoordinatorStatus::CommitIndeterminate
                | crate::core::router_transaction::CoordinatorStatus::RecoveryRequired
                | crate::core::router_transaction::CoordinatorStatus::RollbackFailed | crate::core::router_transaction::CoordinatorStatus::RecoveredButJournalCleanupPending => {
                    return vpn_policy_error(VpnPolicyErrorDetail::Other {
                        message: "a router transaction is pending; refusing to change VPN mode \
                                  until it commits or rolls back"
                            .to_string(),
                    });
                }
            }
        }
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(error) => return vpn_policy_error(VpnPolicyErrorDetail::Other { message: error }),
        };
        if !effective.router.vpn_chain.is_empty() {
            return vpn_policy_error(VpnPolicyErrorDetail::Other {
                message: "a router VPN chain is configured; legacy VPN policy mode cannot \
                          mutate its reserved routing namespace"
                    .to_string(),
            });
        }
        let rollback_desired = match vpn_policy_desired_for_mode(&effective, mode) {
            Ok(desired) => desired,
            Err(detail) => return vpn_policy_error(detail),
        };
        let snapshot = match policy.snapshot(&rollback_desired).await {
            Ok(snapshot) => snapshot,
            Err(error) => return vpn_policy_error(classify_vpn_policy_error(&error)),
        };
        if let Err(response) = self.vpn_policy_apply_mode(policy, &effective, mode).await {
            return response;
        }
        if let Err(error) = self.overrides.set_vpn_mode(mode).await {
            if crate::atomic_file::is_indeterminate_write(&error) {
                return vpn_policy_error(VpnPolicyErrorDetail::Other {
                    message: format!("{error:#}"),
                });
            }
            let rollback = policy.rollback(&rollback_desired, &snapshot).await;
            return vpn_policy_error(VpnPolicyErrorDetail::Other {
                message: compensation_message(
                    "failed to persist VPN policy mode",
                    &error,
                    rollback,
                ),
            });
        }
        self.vpn_policy_status().await
    }

    pub(super) async fn vpn_policy_clear_mode(&self) -> Response {
        if !self.vpn_is_enabled().await {
            return vpn_policy_disabled();
        }
        let (Some(policy), Some(_vpn)) = (&self.vpn_policy, &self.vpn) else {
            return vpn_policy_disabled();
        };
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(error) => return vpn_policy_error(VpnPolicyErrorDetail::Other { message: error }),
        };
        if !effective.router.vpn_chain.is_empty() {
            return vpn_policy_error(VpnPolicyErrorDetail::Other {
                message: "a router VPN chain is configured; legacy VPN policy mode cannot \
                          mutate its reserved routing namespace"
                    .to_string(),
            });
        }
        let target = effective.vpn.policy.default_mode;
        let rollback_desired = match vpn_policy_desired_for_mode(&effective, target) {
            Ok(desired) => desired,
            Err(detail) => return vpn_policy_error(detail),
        };
        let snapshot = match policy.snapshot(&rollback_desired).await {
            Ok(snapshot) => snapshot,
            Err(error) => return vpn_policy_error(classify_vpn_policy_error(&error)),
        };
        if let Err(response) = self.vpn_policy_apply_mode(policy, &effective, target).await {
            return response;
        }
        if let Err(error) = self.overrides.clear_vpn_mode().await {
            if crate::atomic_file::is_indeterminate_write(&error) {
                return vpn_policy_error(VpnPolicyErrorDetail::Other {
                    message: format!("{error:#}"),
                });
            }
            let rollback = policy.rollback(&rollback_desired, &snapshot).await;
            return vpn_policy_error(VpnPolicyErrorDetail::Other {
                message: compensation_message(
                    "failed to clear VPN policy mode override",
                    &error,
                    rollback,
                ),
            });
        }
        self.vpn_policy_status().await
    }
}

fn vpn_policy_desired_for_mode(
    effective: &AppConfig,
    target: VpnPolicyMode,
) -> Result<crate::core::vpn_policy_manager::VpnPolicyDesired, VpnPolicyErrorDetail> {
    match target {
        VpnPolicyMode::Vpn => {
            vpn_policy_desired(effective).ok_or(VpnPolicyErrorDetail::NoProtectedSubnets)
        }
        VpnPolicyMode::Direct => {
            Ok(vpn_policy_desired(effective).unwrap_or_else(vpn_policy_teardown_target))
        }
    }
}

pub(super) fn vpn_disabled() -> Response {
    vpn_error(VpnErrorDetail::VpnDisabled)
}

pub(super) fn vpn_error(detail: VpnErrorDetail) -> Response {
    Response::VpnError { detail }
}

pub(super) fn vpn_policy_disabled() -> Response {
    vpn_policy_error(VpnPolicyErrorDetail::VpnDisabled)
}

pub(super) fn vpn_policy_error(detail: VpnPolicyErrorDetail) -> Response {
    Response::VpnPolicyError { detail }
}

pub(super) fn classify_vpn_policy_error(error: &anyhow::Error) -> VpnPolicyErrorDetail {
    let message = error.to_string();
    tracing::warn!(error = %message, "VPN policy request failed");
    if message.contains("no active VPN tunnel")
        || message.contains("does not match the expected VPN policy interface")
    {
        VpnPolicyErrorDetail::TunnelUnhealthy { message }
    } else if message.contains("foreign objects occupy the reserved namespace") {
        VpnPolicyErrorDetail::ReservedNamespaceConflict { message }
    } else {
        VpnPolicyErrorDetail::Other { message }
    }
}

pub(super) fn classify_vpn_error(error: ManagerError) -> Response {
    tracing::warn!(error = %error, "VPN request failed");
    let detail = match error {
        ManagerError::Driver(VpnDriverError::Store(StoreError::NotFound(name))) => {
            VpnErrorDetail::NotFound { name }
        }
        ManagerError::Driver(VpnDriverError::Store(StoreError::Profile(profile_error)))
        | ManagerError::Driver(VpnDriverError::Profile(profile_error)) => {
            VpnErrorDetail::InvalidProfile {
                message: profile_error.to_string(),
            }
        }
        ManagerError::AlreadyActive => VpnErrorDetail::AlreadyActive,
        ManagerError::NotActive => VpnErrorDetail::NotActive,
        ManagerError::ProfileInUse(name) => VpnErrorDetail::ProfileInUse { name },
        ManagerError::ForeignInterfaceConflict(_) | ManagerError::OwnershipProofFailed(_) => {
            VpnErrorDetail::ForeignInterfaceConflict
        }
        other => VpnErrorDetail::Other {
            message: other.to_string(),
        },
    };
    Response::VpnError { detail }
}
