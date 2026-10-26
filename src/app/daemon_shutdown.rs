//! Final daemon cleanup after background workers and pending transactions stop.

use anyhow::{bail, Result};

use crate::config::{AppConfig, ShutdownPolicy};
use crate::core::transaction::NetworkTransactionManager;
use crate::dhcp::client::DhcpClientSupervisor;
use crate::dhcp::supervisor::DhcpSupervisor;
use crate::firewall::RouterDataplaneProvider;
use crate::vpn::ProductionVpnManager;
use crate::wifi::{HostapdSupervisor, WifiClientSupervisor};

use super::router_startup::{restore_router_dataplane, RouterRuntimeState};
use super::shutdown_control::{self, PendingShutdownRequest};

/// The decision and evidence for the final cleanup. A failed commit check
/// prevents baseline restoration even when shutdown otherwise requests it.
struct ShutdownPlan {
    policy: ShutdownPolicy,
    request: Option<PendingShutdownRequest>,
    errors: Vec<String>,
}

impl ShutdownPlan {
    fn for_current_process(config: &AppConfig, graceful_signal: bool) -> Self {
        let request = match shutdown_control::request_for_current_process(&config.runtime.pid_path)
        {
            Ok(request) => request,
            Err(error) => {
                tracing::warn!(%error, "ignoring invalid transient shutdown request");
                None
            }
        };
        let restore_requested = request
            .as_ref()
            .is_some_and(PendingShutdownRequest::restores_interfaces);
        let commit_uncertain = crate::core::recovery::check_commit(&config.runtime.state_dir).err();
        let stopped_recovery =
            !crate::core::recovery_control::stopped_journals(&config.runtime.state_dir).is_empty();
        let mut errors = Vec::new();
        if let Some(error) = &commit_uncertain {
            errors.push(error.to_string());
        }
        // Preserve runtime ownership and recovery evidence until startup can
        // resolve the persisted commit token. Baseline cleanup would be unsafe.
        let policy = Self::select_policy(
            !stopped_recovery && commit_uncertain.is_none(),
            restore_requested,
            graceful_signal,
            config.runtime.shutdown_policy,
        );
        if restore_requested {
            tracing::info!(
                "administrative shutdown requested restoration of traffic-masq-owned network state"
            );
        }
        Self {
            policy,
            request,
            errors,
        }
    }

    fn restores_interfaces(&self) -> bool {
        self.policy == ShutdownPolicy::RestoreInterfaces
    }

    fn select_policy(
        commit_certain: bool,
        restore_requested: bool,
        graceful_signal: bool,
        configured_policy: ShutdownPolicy,
    ) -> ShutdownPolicy {
        if commit_certain
            && (restore_requested
                || !graceful_signal
                || configured_policy == ShutdownPolicy::RestoreInterfaces)
        {
            ShutdownPolicy::RestoreInterfaces
        } else {
            ShutdownPolicy::PreserveInterfaces
        }
    }
}

/// Resources whose final cleanup must follow the persisted shutdown policy.
/// The order in `finish` is part of the recovery contract.
pub(super) struct ShutdownResources<'a, P: RouterDataplaneProvider> {
    pub(super) config: &'a AppConfig,
    pub(super) transactions: &'a NetworkTransactionManager,
    pub(super) router_state: Option<&'a RouterRuntimeState<P>>,
    pub(super) vpn: Option<&'a ProductionVpnManager>,
    pub(super) dhcp_client: &'a DhcpClientSupervisor,
    pub(super) dhcp: &'a DhcpSupervisor,
    pub(super) wifi: Option<&'a HostapdSupervisor>,
    pub(super) wifi_client: Option<&'a WifiClientSupervisor>,
}

impl<P: RouterDataplaneProvider + Send + Sync> ShutdownResources<'_, P> {
    /// Finish shutdown after admitted API work and background writers have stopped.
    /// Validate commit proof before deciding baseline restoration versus pending
    /// rollback; stop owned services and collect cleanup/API/reconciler errors.
    /// Failed cleanup keeps durable recovery evidence for startup rather than
    /// claiming that all state was restored.
    pub(super) async fn finish(
        self,
        graceful_signal: bool,
        api_result: Result<()>,
        reconcile_error: Option<String>,
    ) -> Result<()> {
        let mut plan = ShutdownPlan::for_current_process(self.config, graceful_signal);
        let restore_interfaces = plan.restores_interfaces();
        let mut cleanup_errors = plan.errors;

        self.dhcp_client.shutdown(plan.policy).await;

        let network_cleanup = if restore_interfaces {
            self.transactions.restore_baselines().await
        } else {
            self.transactions.rollback_all_pending().await
        };
        if let Err(error) = network_cleanup {
            tracing::error!(%error, "network cleanup failed during daemon shutdown");
            cleanup_errors.push(error.to_string());
        }

        // Cleanup itself may have exhausted recovery. Do not let a policy
        // chosen before that failure authorize later baseline destruction.
        if crate::core::recovery_control::preservation_required(&self.config.runtime.state_dir) {
            plan.policy = ShutdownPolicy::PreserveInterfaces;
        }
        if plan.policy == ShutdownPolicy::RestoreInterfaces {
            if let Some(state) = self.router_state {
                if let Err(error) = restore_router_dataplane(state).await {
                    tracing::error!(%error, "router cleanup failed during daemon shutdown");
                    cleanup_errors.push(error.to_string());
                }
            }
        }

        if let Some(vpn) = self.vpn {
            if let Err(error) = vpn.shutdown(plan.policy).await {
                tracing::error!(%error, "VPN shutdown cleanup failed");
                cleanup_errors.push(error.to_string());
            }
        }

        self.dhcp.shutdown().await;

        if let Some(wifi) = self.wifi {
            wifi.shutdown(plan.policy).await;
        }

        if let Some(wifi_client) = self.wifi_client {
            wifi_client.shutdown(plan.policy).await;
        }

        if plan.policy == ShutdownPolicy::RestoreInterfaces {
            let cleanup = async {
                for parent in
                    crate::wifi::concurrent::recorded_parents(&self.config.runtime.state_dir)
                        .await?
                {
                    crate::wifi::concurrent::remove_ap(&self.config.runtime.state_dir, &parent)
                        .await?;
                }
                Ok::<_, anyhow::Error>(())
            }
            .await;
            if let Err(error) = cleanup {
                cleanup_errors.push(format!("virtual AP cleanup: {error:#}"));
            }
        }

        if let Err(error) = api_result {
            cleanup_errors.push(format!("HTTP API failed: {error:#}"));
        }
        if let Some(error) = reconcile_error {
            cleanup_errors.push(error);
        }
        if cleanup_errors.is_empty() {
            if let Some(request) = &plan.request {
                if let Err(error) =
                    shutdown_control::acknowledge(&self.config.runtime.pid_path, request)
                {
                    cleanup_errors.push(format!(
                        "failed to acknowledge requested shutdown cleanup: {error:#}"
                    ));
                }
            }
        }
        if cleanup_errors.is_empty() {
            Ok(())
        } else {
            bail!(cleanup_errors.join("; "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncertain_commit_preserves_recovery_state_even_for_requested_restore() {
        assert_eq!(
            ShutdownPlan::select_policy(false, true, false, ShutdownPolicy::RestoreInterfaces),
            ShutdownPolicy::PreserveInterfaces
        );
        assert_eq!(
            ShutdownPlan::select_policy(true, true, true, ShutdownPolicy::PreserveInterfaces),
            ShutdownPolicy::RestoreInterfaces
        );
    }
}
