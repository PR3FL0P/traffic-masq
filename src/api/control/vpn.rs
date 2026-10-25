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
        let profile = match self.current_standalone_profile().await {
            Ok(profile) => profile,
            Err(response) => return response,
        };
        self.apply_standalone_vpn(enabled, profile, self.overrides.snapshot().await.vpn_mode)
            .await
    }

    async fn apply_standalone_vpn(
        &self,
        enabled: bool,
        profile: Option<String>,
        mode: Option<VpnPolicyMode>,
    ) -> Response {
        if self.vpn.is_none() {
            return vpn_disabled();
        }
        let effective = match self.effective_config().await {
            Ok(config) => config,
            Err(message) => return Response::Error { message },
        };
        if !effective.router.vpn_chain.is_empty() {
            return Response::Error { message: "a router VPN chain is configured; use Router settings and its confirmed transaction".into() };
        }
        let proposal = crate::core::router_candidate::RouterIntentProposal::new()
            .set_standalone_vpn(enabled, profile, mode);
        let candidate = match self.overrides.build_candidate(&proposal).await {
            Ok(candidate) => candidate,
            Err(error) => return super::runtime::error_response(error),
        };
        self.apply_router_candidate(candidate).await
    }

    async fn current_standalone_profile(&self) -> Result<Option<String>, Response> {
        let Some(vpn) = &self.vpn else {
            return Err(vpn_disabled());
        };
        vpn.status()
            .await
            .map(|status| status.map(|status| status.profile_name))
            .map_err(classify_vpn_error)
    }

    async fn vpn_is_enabled(&self) -> bool {
        self.effective_config()
            .await
            .is_ok_and(|config| config.vpn.enabled)
    }

    pub(super) async fn vpn_list_sources(&self) -> Response {
        let config = match self.effective_config().await {
            Ok(c) => c,
            Err(message) => return Response::Error { message },
        };
        let directory = config.vpn.wireguard_import_dir;
        match crate::vpn::store::list_source_profiles(&directory) {
            Ok(profiles) => Response::VpnSources {
                directory: directory.display().to_string(),
                profiles: profiles.into_iter().map(vpn_profile_summary).collect(),
            },
            Err(error) => Response::Error {
                message: error.to_string(),
            },
        }
    }

    pub(super) async fn vpn_import_from_source(&self, name: String) -> Response {
        let Some(vpn) = &self.vpn else {
            return vpn_disabled();
        };
        match vpn.list_profiles() {
            Ok(profiles) if profiles.iter().any(|profile| profile.name == name) => return Response::Error { message: format!("Profile '{name}' already exists; remove the inactive profile before importing it again") },
            Ok(_) => {},
            Err(error) => return classify_vpn_error(error),
        }
        let config = match self.effective_config().await {
            Ok(c) => c,
            Err(message) => return Response::Error { message },
        };
        match crate::vpn::store::read_source_profile(&config.vpn.wireguard_import_dir, &name) {
            Ok(contents) => match std::str::from_utf8(&contents) {
                Ok(contents) => self.vpn_import_profile(name, contents.to_owned()).await,
                Err(error) => Response::Error {
                    message: error.to_string(),
                },
            },
            Err(error) => Response::Error {
                message: error.to_string(),
            },
        }
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
        let contents = zeroize::Zeroizing::new(contents);
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
        Ok(desired.vpn_chain.iter().any(|hop| hop.profile_name == name)
            || desired
                .standalone_vpn
                .as_ref()
                .is_some_and(|vpn| vpn.profile.as_deref() == Some(name)))
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
        if let Some(vpn) = &self.vpn {
            match vpn.snapshot_profile().await {
                Err(error) => return classify_vpn_error(error),
                Ok(Some(active)) if active == name => {
                    return vpn_error(VpnErrorDetail::AlreadyActive)
                }
                Ok(_) => {}
            }
        }
        self.apply_standalone_vpn(true, Some(name), self.overrides.snapshot().await.vpn_mode)
            .await
    }

    pub(super) async fn vpn_deactivate(&self) -> Response {
        if self.overrides.effective_vpn_mode().await == VpnPolicyMode::Vpn {
            return Response::Error {
                message: "Select and confirm Direct traffic policy before disconnecting VPN".into(),
            };
        }
        let enabled = self.vpn_is_enabled().await;
        self.apply_standalone_vpn(enabled, None, self.overrides.snapshot().await.vpn_mode)
            .await
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

    pub(super) async fn vpn_policy_set_mode(&self, mode: VpnPolicyMode) -> Response {
        if !self.vpn_is_enabled().await {
            return vpn_policy_disabled();
        }
        let profile = match self.current_standalone_profile().await {
            Ok(profile) => profile,
            Err(response) => return response,
        };
        self.apply_standalone_vpn(true, profile, Some(mode)).await
    }

    pub(super) async fn vpn_policy_clear_mode(&self) -> Response {
        if !self.vpn_is_enabled().await {
            return vpn_policy_disabled();
        }
        let profile = match self.current_standalone_profile().await {
            Ok(profile) => profile,
            Err(response) => return response,
        };
        self.apply_standalone_vpn(true, profile, None).await
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
