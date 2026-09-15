use super::*;

impl ControlService {
    pub(super) async fn vpn_list_profiles(&self) -> Response {
        let Some(vpn) = &self.vpn else {
            return vpn_disabled();
        };
        match vpn.list_profiles() {
            Ok(profiles) => Response::VpnProfiles {
                profiles: profiles.into_iter().map(Into::into).collect(),
            },
            Err(error) => classify_vpn_error(error),
        }
    }

    pub(super) async fn vpn_import_profile(&self, name: String, contents: String) -> Response {
        let Some(vpn) = &self.vpn else {
            return vpn_disabled();
        };
        match vpn.import_profile(&name, contents.as_bytes()) {
            Ok(name) => Response::VpnProfileImported { name },
            Err(error) => classify_vpn_error(error),
        }
    }

    pub(super) async fn vpn_delete_profile(&self, name: String) -> Response {
        let Some(vpn) = &self.vpn else {
            return vpn_disabled();
        };
        match vpn.delete_profile(&name) {
            Ok(()) => Response::VpnProfileDeleted { name },
            Err(error) => classify_vpn_error(error),
        }
    }

    pub(super) async fn vpn_status(&self) -> Response {
        let Some(vpn) = &self.vpn else {
            return vpn_disabled();
        };
        match vpn.status().await {
            Ok(active) => Response::VpnStatus {
                active: active.map(Into::into),
            },
            Err(error) => classify_vpn_error(error),
        }
    }

    pub(super) async fn vpn_activate(&self, name: String) -> Response {
        let Some(vpn) = &self.vpn else {
            return vpn_disabled();
        };
        if let Err(error) = vpn.activate(&name).await {
            return classify_vpn_error(error);
        }
        match vpn.status().await {
            Ok(Some(active)) => Response::VpnActivated {
                active: active.into(),
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
                tunnel: tunnel.map(Into::into),
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
        let (Some(policy), Some(_vpn)) = (&self.vpn_policy, &self.vpn) else {
            return vpn_policy_disabled();
        };
        // Coexistence-window guard (Landing 1): `vpn_policy_set_mode` bypasses
        // `RouterTransactionCoordinator` entirely, so it must not race a
        // pending chain-length-1 transaction over the same hop-0
        // interface/reserved-ID band. Refuse outright while a transaction is
        // pending or stuck in a failed rollback rather than letting the two
        // non-coordinated mutation paths touch the same resources at once.
        if let Some(router) = &self.router {
            match router.status().await {
                crate::core::router_transaction::CoordinatorStatus::Idle => {}
                crate::core::router_transaction::CoordinatorStatus::Pending
                | crate::core::router_transaction::CoordinatorStatus::RollbackFailed => {
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
        if let Err(response) = self.vpn_policy_apply_mode(policy, &effective, mode).await {
            return response;
        }
        if let Err(error) = self.overrides.set_vpn_mode(mode).await {
            if mode == VpnPolicyMode::Vpn {
                let _ = self
                    .vpn_policy_apply_mode(policy, &effective, VpnPolicyMode::Direct)
                    .await;
            }
            return vpn_policy_error(VpnPolicyErrorDetail::Other {
                message: error.to_string(),
            });
        }
        self.vpn_policy_status().await
    }

    pub(super) async fn vpn_policy_clear_mode(&self) -> Response {
        let (Some(policy), Some(_vpn)) = (&self.vpn_policy, &self.vpn) else {
            return vpn_policy_disabled();
        };
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(error) => return vpn_policy_error(VpnPolicyErrorDetail::Other { message: error }),
        };
        let target = effective.vpn.policy.default_mode;
        if let Err(response) = self.vpn_policy_apply_mode(policy, &effective, target).await {
            return response;
        }
        if let Err(error) = self.overrides.clear_vpn_mode().await {
            if target == VpnPolicyMode::Vpn {
                let _ = self
                    .vpn_policy_apply_mode(policy, &effective, VpnPolicyMode::Direct)
                    .await;
            }
            return vpn_policy_error(VpnPolicyErrorDetail::Other {
                message: error.to_string(),
            });
        }
        self.vpn_policy_status().await
    }
}
