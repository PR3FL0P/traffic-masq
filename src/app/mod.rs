//! Installation, startup, and process lifecycle management.

use crate::core::mutation::NetworkMutationGate;

pub mod init;
pub mod installer;
mod process;
mod reconcile;
pub mod reset;
mod router_startup;
pub(crate) mod runtime;
pub mod service;
mod shutdown_control;
mod startup_recovery;
mod vpn_startup;

use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::signal;
#[cfg(test)]
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{self, MissedTickBehavior};

use crate::api::control::ControlService;
use crate::api::server::HttpApiBindings;
use crate::auth::{AuthService, Principal};
use crate::config::{AppConfig, ShutdownPolicy};
use crate::core::desired::DesiredNetworkState;
use crate::core::interface::{InterfaceManager, InterfaceSnapshot};
#[cfg(test)]
use crate::core::override_manager::RuntimeOverrideManager;
#[cfg(test)]
use crate::core::ownership::AddressOwnershipJournal;
use crate::core::router::RouterDesired;
#[cfg(test)]
use crate::dhcp::client::DhcpClientSpec;
use crate::dhcp::client::DhcpClientSupervisor;
#[cfg(test)]
use crate::dhcp::supervisor::DhcpServiceSpec;
use crate::dhcp::supervisor::DhcpSupervisor;
use crate::firewall::{NftCommandExecutor, NftExecutor};
#[cfg(test)]
use crate::firewall::{RouterDataplaneProvider, RouterDataplaneSnapshot};
use crate::logging::init_logging;
use crate::netlink::{NetworkProvider, RtnetlinkNetworkProvider};
#[cfg(test)]
use crate::vpn::ProductionVpnManager;
use crate::wifi::{HostapdSupervisor, WifiClientSupervisor};

use process::ProcessGuard;
#[cfg(test)]
use reconcile::{
    check_process_liveness, interface_needs_reapply, plan_dhcp_reconcile,
    reconcile_network_runtime_once, DhcpClientRuntimeReconciler, DhcpReconcileAction,
    DhcpRuntimeReconciler, WifiRuntimeReconciler,
};
use reconcile::{
    spawn_process_liveness_checks, spawn_router_dataplane_integrity_checks,
    spawn_runtime_network_reconcile,
};
use router_startup::{
    apply_router_dataplane, missing_router_repair_interfaces, production_dataplane_provider,
    production_router_coordinator, restore_router_dataplane, rollback_router_dataplane,
};
use startup_recovery::StartupRecovery;
use vpn_startup::{
    apply_vpn_policy_startup, build_vpn_manager, build_vpn_policy_manager,
    migrate_vpn_policy_mode_to_chain,
};

type ProductionVpnPolicyManager = crate::core::vpn_policy_manager::VpnPolicyManager<
    crate::vpn::WireGuardVpnDriver,
    Arc<dyn NftExecutor>,
>;
const SESSION_REAP_INTERVAL: Duration = Duration::from_secs(900);

/// Run periodic expired-session cleanup until shutdown is requested.
fn spawn_session_reaper(auth: AuthService, mut shutdown: watch::Receiver<bool>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = time::interval(SESSION_REAP_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        interval.tick().await;

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if shutdown_requested(&shutdown) {
                        break;
                    }
                    match auth.purge_expired_sessions().await {
                        Ok(0) => {}
                        Ok(removed) => tracing::debug!(removed, "purged expired sessions"),
                        Err(error) => tracing::warn!(%error, "failed to purge expired sessions"),
                    }
                }
                changed = shutdown.changed() => match changed {
                    Ok(()) if shutdown_requested(&shutdown) => break,
                    Ok(()) => {}
                    Err(_) => break,
                }
            }
        }
    })
}

/// Restart supervised processes that have died.
///
/// Separate from convergence, and still periodic, because process death is the
/// one drift the kernel does not announce to us: `SupervisedProcess` is built
/// around PIDs so that a restarted daemon can adopt processes it did not spawn,
/// and a PID gives nothing to await on. Making this event-driven needs
/// `pidfd_open`, which is its own piece of work — see the architecture plan.
///
/// Kept at its previous cadence so restart latency does not change; it no
/// longer delays network convergence, which is what the interval used to gate.
fn spawn_wifi_autoconnect(
    control: ControlService,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(15));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                _ = interval.tick() => {
                    if *shutdown.borrow() { break; }
                    if let Err(error) = control.autoconnect_wifi_once().await {
                        tracing::warn!(%error, "Wi-Fi autoconnect pass failed");
                    }
                }
            }
        }
    })
}

async fn preflight_hostapd_binary(binary: &Path) -> Result<()> {
    crate::command::probe(binary).await.with_context(|| {
        format!(
            "hostapd binary {} is not runnable — install hostapd or fix wifi.hostapd_binary",
            binary.display()
        )
    })?;
    Ok(())
}

async fn preflight_iw_binary(binary: &Path) -> Result<()> {
    crate::command::probe(binary).await.with_context(|| {
        format!(
            "iw binary {} is not runnable — install iw or fix wifi.iw_binary",
            binary.display()
        )
    })?;
    Ok(())
}

async fn build_wifi_supervisor(effective_config: &AppConfig) -> Result<Option<HostapdSupervisor>> {
    // Built regardless of `wifi.enabled`: constructing the supervisor has no
    // side effects, and gating it made enabling Wi-Fi a boot-time decision —
    // with no supervisor every Wi-Fi request answers "disabled", which is the
    // state you are in when you want to turn it on.
    //
    // `enabled` survives as a startup hint: if this box declares that it uses
    // Wi-Fi, a missing binary is still reported immediately rather than at the
    // first attempt to configure an access point.
    if effective_config.wifi.enabled {
        preflight_hostapd_binary(&effective_config.wifi.hostapd_binary).await?;
        preflight_iw_binary(&effective_config.wifi.iw_binary).await?;
    }
    let supervisor = HostapdSupervisor::start(effective_config).await?;
    Ok(Some(supervisor))
}

async fn preflight_wpa_supplicant_binary(binary: &Path) -> Result<()> {
    crate::command::probe(binary).await
        .with_context(|| {
            format!(
                "wpa_supplicant binary {} is not runnable — install wpa_supplicant or fix wifi_client.wpa_supplicant_binary",
                binary.display()
            )
        })?;
    Ok(())
}

async fn build_wifi_client_supervisor(
    effective_config: &AppConfig,
) -> Result<Option<WifiClientSupervisor>> {
    // Same reasoning as `build_wifi_supervisor`.
    if effective_config.wifi_client.enabled {
        preflight_wpa_supplicant_binary(&effective_config.wifi_client.wpa_supplicant_binary)
            .await?;
    }
    let supervisor = WifiClientSupervisor::start(effective_config).await?;
    Ok(Some(supervisor))
}

/// Open the configured authentication store and reset the device administrator password.
pub async fn reset_device_password(config: &AppConfig, password: &str) -> Result<Principal> {
    config.validate()?;
    let _process_guard = ProcessGuard::acquire(&config.runtime.pid_path)?;
    let auth = AuthService::open(&config.auth).await?;
    Ok(auth.reset_device_password(password).await?)
}

/// LIFO teardown stack for `run_daemon`'s startup phase only. Each startup
/// step pushes its own rollback right after it succeeds; any later failure
/// or shutdown-requested check runs `unwind()` to tear everything down in
/// reverse order, then returns.
///
/// Dropping a non-empty stack without calling `unwind()` is intentional and
/// correct: it is exactly what happens on the happy path once startup
/// completes (responsibility passes to the already-correct end-of-run
/// shutdown path). The pushed futures are inert until polled, so a drop runs
/// none of their side effects.
struct StartupRollback<'a> {
    steps: Vec<Pin<Box<dyn Future<Output = ()> + Send + 'a>>>,
}

impl<'a> StartupRollback<'a> {
    fn new() -> Self {
        Self { steps: Vec::new() }
    }

    /// Record a rollback action, to run in LIFO order if `unwind` is called.
    fn push<F>(&mut self, rollback: F)
    where
        F: Future<Output = ()> + Send + 'a,
    {
        self.steps.push(Box::pin(rollback));
    }

    /// Run every pushed rollback, most-recently-pushed first. Consumes
    /// `self`, so a second `unwind()` call is a compile error, not a silent
    /// double-teardown.
    async fn unwind(mut self) {
        while let Some(step) = self.steps.pop() {
            step.await;
        }
    }
}

fn router_recovery_allows_degraded_startup(
    status: crate::core::router_transaction::CoordinatorStatus,
    foreign_route_conflict: bool,
) -> bool {
    matches!(
        status,
        crate::core::router_transaction::CoordinatorStatus::RollbackFailed
            | crate::core::router_transaction::CoordinatorStatus::RecoveredButJournalCleanupPending
    ) || foreign_route_conflict
}

/// Initialize services, recover interrupted changes, and drive network convergence until shutdown.
/// Drain accepted operations before applying configured shutdown and restoration policies.
pub async fn run_daemon(mut config: AppConfig) -> Result<()> {
    migrate_vpn_policy_mode_to_chain(&mut config).await;
    let shutdown = install_shutdown_signal()?;
    let _process_guard = ProcessGuard::acquire(&config.runtime.pid_path)?;
    let _logging_guard = init_logging(&config)?;

    let StartupRecovery {
        network_provider,
        ownership_journal,
        interface_manager,
        overrides,
        effective_config,
        strict_admitted,
        router_recovery_pending,
        management_allowlist,
    } = startup_recovery::prepare(&config).await?;

    // Teardown for everything brought up during startup, unwound in reverse
    // order on any later failure or shutdown-requested check. Each step below
    // pushes its own rollback right after it succeeds, so a failure N steps in
    // never has to re-derive what the previous N-1 steps were.
    let mut stack = StartupRollback::new();

    let mut startup_config = effective_config.clone();
    startup_config.network.interfaces.retain(|name, _| {
        crate::core::recovery::check_scope(&config.runtime.state_dir, Some(name)).is_ok()
    });
    // Defer legacy interface/dataplane bootstrap when a router snapshot exists;
    // the coordinator owns restoration and subsequent committed-state repair.
    let startup_baselines = if router_recovery_pending {
        Vec::new()
    } else {
        interface_manager
            .apply_network_degraded(&startup_config.network, &management_allowlist)
            .await?
    };
    // Cloned, not borrowed: `startup_baselines` is moved into
    // ControlService::new_with_baselines later in this function, and a live
    // borrow held inside `stack` would make that move a compile error.
    stack.push({
        let interface_manager = interface_manager.clone();
        let startup_baselines = startup_baselines.clone();
        async move { rollback_interfaces(&interface_manager, &startup_baselines).await }
    });

    if shutdown_requested(&shutdown) && !router_recovery_pending {
        stack.unwind().await;
        tracing::info!("shutdown requested during network initialization");
        return Ok(());
    }

    let wifi_supervisor = if router_recovery_pending {
        Some(HostapdSupervisor::open_for_recovery(&startup_config))
    } else {
        match build_wifi_supervisor(&startup_config).await {
            Ok(supervisor) => supervisor,
            Err(error) => {
                tracing::error!(subsystem = "wifi_ap", operation = "initialize_supervisor",
                    error = %format!("{error:#}"), "Wi-Fi subsystem unavailable; other subsystems will still start");
                None
            }
        }
    };
    if let Some(wifi) = &wifi_supervisor {
        let wifi = wifi.clone();
        stack.push(async move { wifi.shutdown(ShutdownPolicy::RestoreInterfaces).await });
    }

    if shutdown_requested(&shutdown) && !router_recovery_pending {
        stack.unwind().await;
        tracing::info!("shutdown requested during Wi-Fi initialization");
        return Ok(());
    }

    let wifi_client_supervisor = if router_recovery_pending {
        Some(WifiClientSupervisor::open_for_recovery(&startup_config))
    } else {
        match build_wifi_client_supervisor(&startup_config).await {
            Ok(supervisor) => supervisor,
            Err(error) => {
                tracing::error!(subsystem = "wifi_client", operation = "initialize_supervisor",
                    error = %format!("{error:#}"), "Wi-Fi subsystem unavailable; other subsystems will still start");
                None
            }
        }
    };
    if let Some(wifi_client) = &wifi_client_supervisor {
        let wifi_client = wifi_client.clone();
        stack.push(async move {
            wifi_client
                .shutdown(ShutdownPolicy::RestoreInterfaces)
                .await
        });
    }

    if shutdown_requested(&shutdown) && !router_recovery_pending {
        stack.unwind().await;
        tracing::info!("shutdown requested during Wi-Fi client initialization");
        return Ok(());
    }

    let dhcp = if router_recovery_pending {
        DhcpSupervisor::open_for_recovery(&startup_config)
    } else {
        match DhcpSupervisor::start(&startup_config).await {
            Ok(supervisor) => supervisor,
            Err(error) => {
                stack.unwind().await;
                return Err(error);
            }
        }
    };
    stack.push({
        let dhcp = dhcp.clone();
        async move { dhcp.shutdown().await }
    });

    if shutdown_requested(&shutdown) && !router_recovery_pending {
        stack.unwind().await;
        tracing::info!("shutdown requested during DHCP initialization");
        return Ok(());
    }

    let dhcp_client = if router_recovery_pending {
        match DhcpClientSupervisor::open_for_recovery(&startup_config, network_provider.clone()) {
            Ok(supervisor) => supervisor,
            Err(error) => {
                stack.unwind().await;
                return Err(error);
            }
        }
    } else {
        match DhcpClientSupervisor::start(&startup_config, network_provider.clone()).await {
            Ok(supervisor) => supervisor,
            Err(error) => {
                stack.unwind().await;
                return Err(error);
            }
        }
    };
    stack.push({
        let dhcp_client = dhcp_client.clone();
        async move {
            dhcp_client
                .shutdown(ShutdownPolicy::RestoreInterfaces)
                .await
        }
    });

    // Serializes request/background control-plane mutations. Autonomous DHCP
    // lease ownership writes deliberately do not acquire this gate (router
    // apply may wait for DHCP readiness); they serialize with interface
    // address writers through InterfaceMutationLocks instead.
    let network_mutations = Arc::new(NetworkMutationGate::default());

    if shutdown_requested(&shutdown) && !router_recovery_pending {
        stack.unwind().await;
        tracing::info!("shutdown requested during DHCP client initialization");
        return Ok(());
    }

    let desired = match if strict_admitted {
        RouterDesired::from_effective_config(&effective_config)
    } else {
        RouterDesired::from_router_recovery_config(&effective_config)
    } {
        Ok(desired) => desired,
        Err(error) => {
            stack.unwind().await;
            return Err(error);
        }
    };
    // `Arc`-wrapped so its rollback closure can own a cheap clone instead of
    // borrowing: a borrow captured inside `stack` would have to outlive
    // `router_state` itself, which the final shutdown path below also reads
    // — two ends pulling on the same value from opposite directions is
    // exactly what `Arc` sidesteps.
    let router_state = if desired.enabled
        && !router_recovery_pending
        && crate::core::recovery::check_scope(&config.runtime.state_dir, None).is_ok()
    {
        let dataplane_provider = production_dataplane_provider(network_provider.clone());
        match apply_router_dataplane(&desired, network_provider.clone(), dataplane_provider).await {
            Ok(state) => Some(Arc::new(state)),
            Err(error)
                if error
                    .downcast_ref::<crate::core::route::ForeignRouteConflict>()
                    .is_some() =>
            {
                tracing::error!(error = %format!("{error:#}"), state = "blocked_degraded_dataplane",
                    "foreign route preserved; control plane will remain available");
                None
            }
            Err(error) => {
                stack.unwind().await;
                return Err(error);
            }
        }
    } else {
        None
    };
    if let Some(state) = &router_state {
        let state = state.clone();
        stack.push(async move { rollback_router_dataplane(&state).await });
    }

    if shutdown_requested(&shutdown) && !router_recovery_pending {
        stack.unwind().await;
        tracing::info!("shutdown requested during router dataplane initialization");
        return Ok(());
    }

    // The coordinator is part of the control plane, so it is built regardless
    // of whether the router carries an intent right now. Gating it on
    // `router.enabled` made enabling the router a boot-time decision: with no
    // coordinator every router request answers RouterDisabled, which is exactly
    // the state you are in when you want to provision one. Building it is pure
    // wiring — it reuses the already-open network provider and touches no data plane.
    let router_coordinator = match production_router_coordinator(
        &desired,
        &effective_config.vpn.wireguard_config_dir,
        &effective_config.runtime.state_dir,
        network_provider.clone(),
        ownership_journal.clone(),
        dhcp.clone(),
        dhcp_client.clone(),
        wifi_client_supervisor.clone(),
        wifi_supervisor.clone(),
        overrides.clone(),
        Duration::from_secs(config.security.rollback_timeout_seconds.max(1)),
    ) {
        Ok(coordinator) => {
            coordinator.set_timeout_mutation_gate(network_mutations.clone());
            let recovered = async {
                let _network_mutation = network_mutations.write().await;
                coordinator.recover().await
            }
            .await;
            if let Err(error) = recovered {
                // Interface recovery is deliberately isolated. A blocked interface
                // must never downgrade an unrelated, unproven router journal error
                // from fatal to degraded startup.
                if router_recovery_allows_degraded_startup(
                    coordinator.status().await,
                    error
                        .downcast_ref::<crate::core::route::ForeignRouteConflict>()
                        .is_some(),
                ) {
                    tracing::error!(journal = %config.runtime.state_dir.join("router-transaction.json").display(),
                        operation = "startup_recovery", invariant = "preserve_unresolved_snapshot",
                        metadata_safe_to_remove = false, error = %format!("{error:#}"),
                        "router dataplane blocked; control plane remains available");
                } else {
                    stack.unwind().await;
                    return Err(crate::core::recovery::context_if_missing(
                        error,
                        crate::core::recovery::RecoveryDiagnostic::fatal(
                            crate::core::recovery::StartupRecoveryCode::ProvableRouterRecovery,
                            "startup_recovery",
                            crate::core::recovery::RecoveryAction::InspectRecoveryState,
                        )
                        .journal(config.runtime.state_dir.join("router-transaction.json"))
                        .object("router")
                        .detail(
                            "next_step",
                            "inspect_nested_recovery_diagnostic_before_restoring_state",
                        ),
                    ));
                }
            }
            Some(coordinator)
        }
        Err(error) => {
            stack.unwind().await;
            return Err(error);
        }
    };

    if shutdown_requested(&shutdown) {
        stack.unwind().await;
        tracing::info!("shutdown requested after startup recovery completed");
        return Ok(());
    }

    // Router recovery is now complete. A pending recovery path has intentionally postponed full
    // admission until this point; a normal-start path was admitted before any network mutation.
    let effective_config = if strict_admitted {
        effective_config
    } else {
        if let Err(error) = config.validate() {
            stack.unwind().await;
            return Err(error);
        }
        match overrides.hydrate_strict().await {
            Ok(effective_config) => effective_config,
            Err(error) => {
                stack.unwind().await;
                return Err(error);
            }
        }
    };
    let strict_desired = match RouterDesired::from_effective_config(&effective_config) {
        Ok(desired) => desired,
        Err(error) => {
            stack.unwind().await;
            return Err(error);
        }
    };
    if !strict_admitted && strict_desired != desired {
        stack.unwind().await;
        anyhow::bail!(
            "router-relevant runtime overrides changed during startup recovery; refusing to continue with mixed recovery state"
        );
    }
    let desired = strict_desired;

    if router_recovery_pending {
        // The rollback coordinator was given inert runtime adapters. Only after the journal is
        // resolved and strict admission succeeds may normal startup cleanup/configuration run.
        if let Some(wifi) = &wifi_supervisor {
            if let Err(error) = wifi.reconcile_startup(&effective_config).await {
                tracing::error!(subsystem = "wifi_ap", operation = "reconcile_startup_after_recovery",
                    error = %format!("{error:#}"), "Wi-Fi subsystem unavailable; other subsystems will still start");
            }
        }
        if let Some(wifi_client) = &wifi_client_supervisor {
            if let Err(error) = wifi_client.reconcile_startup(&effective_config).await {
                tracing::error!(subsystem = "wifi_client", operation = "reconcile_startup_after_recovery",
                    error = %format!("{error:#}"), "Wi-Fi client subsystem unavailable; other subsystems will still start");
            }
        }
        if let Err(error) = dhcp.reconcile_startup(&effective_config).await {
            stack.unwind().await;
            return Err(error);
        }
        if let Err(error) = dhcp_client.reconcile_startup(&effective_config).await {
            stack.unwind().await;
            return Err(error);
        }
    }

    // Normal committed-state repair is deliberately after strict hydration:
    // recovery may run with a damaged unrelated API/security override, but
    // convergence must not mutate the network for a configuration normal
    // startup would reject.
    if let Some(coordinator) = &router_coordinator {
        let _network_mutation = network_mutations.write().await;
        match missing_router_repair_interfaces(&desired, network_provider.as_ref()).await {
            Ok(missing) if missing.is_empty() => {
                if let Err(error) = coordinator.repair(desired.clone()).await {
                    tracing::error!(operation = "repair_committed_router", error = %format!("{error:#}"),
                        "router convergence degraded; control plane remains available");
                }
            }
            Ok(missing) => {
                tracing::warn!(
                    interfaces = %missing.join(", "),
                    hint = "Check ip link; reconnect the adapters or correct the interface names in router configuration. Runtime convergence will retry when they appear.",
                    "router startup repair convergence is deferred: configured interfaces are absent; daemon startup will continue"
                );
            }
            Err(error) => {
                tracing::error!(operation = "inspect_router_repair_interfaces", error = %format!("{error:#}"),
                    "router startup repair inspection failed; control plane remains available");
            }
        }
    }

    // Recovery is complete before opening API listeners or the auth database.
    // A local control-plane failure must never prevent rollback of durable
    // network journals from a previous run.
    let bindings = match HttpApiBindings::bind(&effective_config) {
        Ok(bindings) => bindings,
        Err(error) => {
            stack.unwind().await;
            return Err(error);
        }
    };
    let auth = match AuthService::open(&config.auth).await {
        Ok(auth) => auth,
        Err(error) => {
            stack.unwind().await;
            return Err(error.into());
        }
    };

    let vpn_manager = match build_vpn_manager(&effective_config).await {
        Ok(vpn_manager) => vpn_manager,
        Err(error) => {
            stack.unwind().await;
            return Err(error);
        }
    };
    if let Some(vpn) = &vpn_manager {
        let vpn = vpn.clone();
        stack.push(async move {
            if let Err(error) = vpn.shutdown(ShutdownPolicy::RestoreInterfaces).await {
                tracing::error!(%error, "failed to shut down VPN manager during startup rollback");
            }
        });
    }

    apply_vpn_policy_startup(
        &effective_config,
        &overrides,
        network_provider.clone(),
        NftCommandExecutor,
        &vpn_manager,
    )
    .await;

    // The service is constructed with the effective configuration, because the
    // runtime values it derives (rollback timeout, state directory) have to be
    // the ones actually in force. The merge base is the file config, so that
    // removing an override takes effect and so that the service and the runtime
    // reconcile loop agree on what the effective configuration is.
    let mut control = ControlService::new_with_baselines(
        effective_config.clone(),
        network_provider.clone(),
        dhcp.clone(),
        overrides.clone(),
        startup_baselines,
        ownership_journal.clone(),
    )
    .with_base_config(config.clone())
    .with_network_mutation_gate(network_mutations.clone());
    if let Some(coordinator) = router_coordinator.clone() {
        control = control.with_router_coordinator(coordinator);
    }

    if let Some(wifi) = &wifi_supervisor {
        control = control.with_wifi_supervisor(wifi.clone());
    }
    if let Some(wifi_client) = &wifi_client_supervisor {
        control = control.with_wifi_client_supervisor(wifi_client.clone());
    }
    control = control.with_dhcp_client_supervisor(dhcp_client.clone());
    let vpn_policy_manager = vpn_manager.as_ref().map(|vpn| {
        let firewall_executor: Arc<dyn NftExecutor> = Arc::new(NftCommandExecutor);
        Arc::new(build_vpn_policy_manager(
            network_provider.clone(),
            firewall_executor,
            vpn.clone(),
        ))
    });
    if let Some(vpn) = &vpn_manager {
        control = control.with_vpn_manager(vpn.clone());
    }
    if let Some(policy) = &vpn_policy_manager {
        control = control.with_vpn_policy_manager(policy.clone());
    }
    // One desired state for both halves. The transaction manager proposes into
    // it and the converger drives it; two instances would mean proposals nobody
    // converges and a converger that never sees them.
    let desired_state = DesiredNetworkState::new(config.clone(), overrides.clone());
    control = control.with_desired_state(desired_state.clone());

    let transactions = control.transactions();
    let socket_path = bindings.socket_path().to_path_buf();
    let session_reaper = spawn_session_reaper(auth.clone(), shutdown.clone());
    let autoconnect_control = control.clone();
    let server = bindings.into_server(control, auth);

    let dhcp_interfaces = dhcp.running_interfaces().await;
    tracing::info!(
        dhcp_interfaces = ?dhcp_interfaces,
        socket = %socket_path.display(),
        https = effective_config.api.tcp.as_ref().is_some_and(|tcp| tcp.enabled),
        router_enabled = desired.enabled,
        vpn_enabled = effective_config.vpn.enabled,
        wifi_enabled = wifi_supervisor.is_some(),
        wifi_client_enabled = wifi_client_supervisor.is_some(),
        "traffic-masqd ready"
    );

    // Subscribed before the converger starts, and fatal if it fails: without
    // kernel notifications nothing would ever be converged, and a daemon that
    // silently stops reconciling is worse than one that refuses to start.
    let kernel_events = match crate::netlink::events::subscribe_to_kernel_changes() {
        Ok(events) => events,
        Err(error) => {
            stack.unwind().await;
            return Err(error)
                .context("failed to subscribe to kernel network change notifications");
        }
    };

    let reconcile_network_provider: Arc<dyn NetworkProvider> =
        match RtnetlinkNetworkProvider::connect() {
            Ok(provider) => Arc::new(provider),
            Err(error) => {
                stack.unwind().await;
                return Err(error).context(
                    "failed to open rtnetlink connection for runtime interface/DHCP reconcile",
                );
            }
        };
    let (reconcile_stop, reconcile_shutdown) = watch::channel(false);
    let reconcile_task = spawn_runtime_network_reconcile(
        desired_state.clone(),
        ownership_journal.clone(),
        reconcile_network_provider,
        dhcp.clone(),
        wifi_supervisor.clone(),
        wifi_client_supervisor.clone(),
        dhcp_client.clone(),
        network_mutations.clone(),
        router_coordinator.clone(),
        kernel_events,
        reconcile_shutdown,
    );
    // Nothing fallible or shutdown-checked remains between here and the main
    // serve loop: startup has fully succeeded, so teardown responsibility
    // passes to the daemon's normal shutdown path below. Dropped explicitly
    // rather than left to fall out of scope at the end of the function, to
    // mark the handoff at the point it actually happens.
    drop(stack);

    let (liveness_stop, liveness_shutdown) = watch::channel(false);
    let liveness_task = spawn_process_liveness_checks(
        desired_state.clone(),
        effective_config.runtime.state_dir.clone(),
        dhcp.clone(),
        wifi_supervisor.clone(),
        wifi_client_supervisor.clone(),
        dhcp_client.clone(),
        network_mutations.clone(),
        router_coordinator.clone(),
        liveness_shutdown,
    );

    let (integrity_stop, integrity_shutdown) = watch::channel(false);
    let integrity_task = spawn_router_dataplane_integrity_checks(
        desired_state.clone(),
        overrides.clone(),
        network_mutations.clone(),
        router_coordinator.clone(),
        vpn_policy_manager,
        integrity_shutdown,
    );

    let (autoconnect_stop, autoconnect_shutdown) = tokio::sync::watch::channel(false);
    let autoconnect_task = spawn_wifi_autoconnect(autoconnect_control, autoconnect_shutdown);
    // The API normally follows the process shutdown signal. A failed network
    // reconciler also stops it: keeping the control plane writable after the
    // only convergence worker has died would turn network transactions into
    // misleading timeouts or partial recovery attempts.
    let (server_stop, server_shutdown) = watch::channel(shutdown_requested(&shutdown));
    let mut process_shutdown = shutdown.clone();
    let signal_server_stop = server_stop.clone();
    let server_shutdown_relay = tokio::spawn(async move {
        loop {
            if shutdown_requested(&process_shutdown) {
                let _ = signal_server_stop.send(true);
                break;
            }
            if process_shutdown.changed().await.is_err() {
                let _ = signal_server_stop.send(true);
                break;
            }
        }
    });

    let mut reconcile_task = reconcile_task;
    let mut reconcile_finished = false;
    let mut reconcile_error = None;
    let mut server_run = Box::pin(server.run(server_shutdown));
    let api_result = tokio::select! {
        result = &mut server_run => result,
        result = &mut reconcile_task => {
            reconcile_finished = true;
            let message = match result {
                Ok(Ok(())) => "network reconciler stopped unexpectedly".to_string(),
                Ok(Err(error)) => format!("network reconciler failed: {error:#}"),
                Err(error) => format!("network reconciler task failed: {error}"),
            };
            desired_state.fail_converger(message.clone());
            reconcile_error = Some(message);
            let _ = server_stop.send(true);
            (&mut server_run).await
        }
    };
    let _ = server_stop.send(true);
    server_shutdown_relay.abort();
    let _ = server_shutdown_relay.await;
    let _ = autoconnect_stop.send(true);
    // Finish any in-flight scan/activation before rolling back and stopping runtimes.
    let _ = autoconnect_task.await;

    // Stop background dataplane repair before explicit transaction rollback.
    let _ = integrity_stop.send(true);
    let _ = integrity_task.await;

    // No new process restarts should be introduced while shutdown is trying
    // to prove rollback. The desired-state converger stays alive a little
    // longer because interface transaction rollback is expressed through it.
    // Let a restart already in progress finish its bookkeeping before rollback.
    // Aborting here can cancel a supervisor between a runtime write and its record.
    let _ = liveness_stop.send(true);
    let _ = liveness_task.await;

    // Before the converger is stopped, not after: an unconfirmed change is
    // abandoned by dropping it from the desired state, and only the converger
    // can take the machine back to what was committed. Stopping it first would
    // leave a change nobody ever confirmed on the box for good.
    if let Err(error) = transactions.rollback_all_pending().await {
        tracing::error!(%error, "failed to abandon unconfirmed network changes during shutdown");
    }

    if let Some(coordinator) = &router_coordinator {
        let _network_mutation = network_mutations.write().await;
        if coordinator.status().await != crate::core::router_transaction::CoordinatorStatus::Idle {
            if let Err(error) = coordinator.rollback().await {
                tracing::error!(%error, "failed to roll back router transaction during shutdown");
            }
        }
    }

    let _ = reconcile_stop.send(true);
    if !reconcile_finished {
        match reconcile_task.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                reconcile_error.get_or_insert_with(|| {
                    format!("network reconciler failed during shutdown: {error:#}")
                });
            }
            Err(error) => {
                reconcile_error.get_or_insert_with(|| {
                    format!("network reconciler task failed during shutdown: {error}")
                });
            }
        }
    }
    session_reaper.abort();
    let _ = session_reaper.await;
    let graceful_signal = shutdown_requested(&shutdown);
    tracing::info!(graceful_signal, "traffic-masqd stopping");

    let mut cleanup_errors = Vec::new();
    let shutdown_request =
        match shutdown_control::request_for_current_process(&effective_config.runtime.pid_path) {
            Ok(request) => request,
            Err(error) => {
                tracing::warn!(%error, "ignoring invalid transient shutdown request");
                None
            }
        };
    let restore_requested = shutdown_request
        .as_ref()
        .is_some_and(|request| request.restores_interfaces());
    let commit_uncertain =
        crate::core::recovery::check_commit(&effective_config.runtime.state_dir).err();
    if let Some(error) = &commit_uncertain {
        cleanup_errors.push(error.to_string());
    }
    // Preserve runtime ownership and all recovery evidence until startup can
    // resolve the persisted commit token. Baseline cleanup would be an unsafe rollback.
    let restore_interfaces = commit_uncertain.is_none()
        && (restore_requested
            || !graceful_signal
            || effective_config.runtime.shutdown_policy == ShutdownPolicy::RestoreInterfaces);
    let shutdown_policy = if restore_interfaces {
        ShutdownPolicy::RestoreInterfaces
    } else {
        ShutdownPolicy::PreserveInterfaces
    };
    if restore_requested {
        tracing::info!(
            "administrative shutdown requested restoration of traffic-masq-owned network state"
        );
    }

    dhcp_client.shutdown(shutdown_policy).await;

    let network_cleanup = if restore_interfaces {
        transactions.restore_baselines().await
    } else {
        transactions.rollback_all_pending().await
    };
    if let Err(error) = network_cleanup {
        tracing::error!(%error, "network cleanup failed during daemon shutdown");
        cleanup_errors.push(error.to_string());
    }

    if restore_interfaces {
        if let Some(state) = &router_state {
            if let Err(error) = restore_router_dataplane(state).await {
                tracing::error!(%error, "router cleanup failed during daemon shutdown");
                cleanup_errors.push(error.to_string());
            }
        }
    }

    if let Some(vpn) = &vpn_manager {
        if let Err(error) = vpn.shutdown(shutdown_policy).await {
            tracing::error!(%error, "VPN shutdown cleanup failed");
            cleanup_errors.push(error.to_string());
        }
    }

    dhcp.shutdown().await;

    if let Some(wifi) = &wifi_supervisor {
        wifi.shutdown(shutdown_policy).await;
    }

    if let Some(wifi_client) = &wifi_client_supervisor {
        wifi_client.shutdown(shutdown_policy).await;
    }

    if let Err(error) = api_result {
        cleanup_errors.push(format!("HTTP API failed: {error:#}"));
    }
    if let Some(error) = reconcile_error {
        cleanup_errors.push(error);
    }
    if cleanup_errors.is_empty() {
        if let Some(request) = &shutdown_request {
            if let Err(error) =
                shutdown_control::acknowledge(&effective_config.runtime.pid_path, request)
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

fn shutdown_requested(shutdown: &watch::Receiver<bool>) -> bool {
    *shutdown.borrow()
}

#[cfg(unix)]
fn install_shutdown_signal() -> Result<watch::Receiver<bool>> {
    use signal::unix::{signal, SignalKind};

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let (sender, receiver) = watch::channel(false);
    tokio::spawn(async move {
        tokio::select! {
            _ = interrupt.recv() => tracing::info!(signal = "SIGINT", "shutdown requested"),
            _ = terminate.recv() => tracing::info!(signal = "SIGTERM", "shutdown requested"),
        }
        let _ = sender.send(true);
    });
    Ok(receiver)
}

#[cfg(not(unix))]
fn install_shutdown_signal() -> Result<watch::Receiver<bool>> {
    let (sender, receiver) = watch::channel(false);
    tokio::spawn(async move {
        if signal::ctrl_c().await.is_ok() {
            let _ = sender.send(true);
        }
    });
    Ok(receiver)
}

async fn rollback_interfaces(manager: &InterfaceManager, snapshots: &[InterfaceSnapshot]) {
    for snapshot in snapshots.iter().rev() {
        if let Err(error) = manager.rollback(snapshot).await {
            tracing::error!(
                interface = %snapshot.name,
                %error,
                "failed to rollback interface during daemon startup cleanup"
            );
        }
    }
}

#[cfg(test)]
mod tests;
