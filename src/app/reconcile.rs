//! Runtime interface convergence and network process integrity workers.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{self, MissedTickBehavior};

use crate::config::{InterfaceConfig, VpnPolicyMode};
use crate::core::desired::DesiredNetworkState;
use crate::core::interface::InterfaceManager;
use crate::core::mutation::NetworkMutationGate;
use crate::core::override_manager::RuntimeOverrideManager;
use crate::core::ownership::AddressOwnershipJournal;
use crate::core::router::RouterDesired;
use crate::core::router_transaction::RouterTransactionCoordinator;
use crate::core::vpn_policy_manager::{vpn_policy_desired, vpn_policy_teardown_target};
use crate::dhcp::client::{DhcpClientSpec, DhcpClientSupervisor};
use crate::dhcp::supervisor::{DhcpServiceSpec, DhcpSupervisor};
use crate::firewall::missing_router_dataplane_interface;
use crate::netlink::events::KernelEvent;
use crate::netlink::{AddressOwner, Ipv4AddressInfo, NetworkInterface, NetworkProvider};
use crate::wifi::{HostapdSupervisor, WifiClientSupervisor};

use super::{shutdown_requested, ProductionVpnPolicyManager};

const PROCESS_LIVENESS_INTERVAL: Duration = Duration::from_secs(1);
const ROUTER_DATAPLANE_INTEGRITY_INTERVAL: Duration = Duration::from_secs(15);

#[async_trait]
pub(super) trait DhcpRuntimeReconciler: Send + Sync {
    async fn spec(&self, interface: &str) -> Option<DhcpServiceSpec>;
    async fn disable(&self, interface: &str) -> Result<Option<DhcpServiceSpec>>;
    async fn binding_stale(&self, interface: &str) -> Result<bool>;
    async fn reconcile(&self, spec: DhcpServiceSpec) -> Result<()>;

    async fn ensure_runtime_alive(&self) -> Result<bool>;
}

#[async_trait]
impl DhcpRuntimeReconciler for DhcpSupervisor {
    async fn spec(&self, interface: &str) -> Option<DhcpServiceSpec> {
        self.spec(interface).await
    }

    async fn disable(&self, interface: &str) -> Result<Option<DhcpServiceSpec>> {
        self.disable(interface).await
    }

    async fn binding_stale(&self, interface: &str) -> Result<bool> {
        self.binding_stale(interface).await
    }

    async fn reconcile(&self, spec: DhcpServiceSpec) -> Result<()> {
        self.reconcile(spec).await
    }

    async fn ensure_runtime_alive(&self) -> Result<bool> {
        self.ensure_runtime_alive().await
    }
}

#[async_trait]
pub(super) trait DhcpClientRuntimeReconciler: Send + Sync {
    async fn specs(&self) -> Vec<DhcpClientSpec>;
    async fn disable(&self, interface: &str) -> Result<Option<DhcpClientSpec>>;
    async fn reconcile(&self, spec: DhcpClientSpec, link_ready: bool) -> Result<()>;
    async fn verify_ready(&self, _interface: &str) -> Result<()> {
        Ok(())
    }
    async fn ensure_alive(&self) -> Result<bool>;
}

#[async_trait]
impl DhcpClientRuntimeReconciler for DhcpClientSupervisor {
    async fn specs(&self) -> Vec<DhcpClientSpec> {
        self.statuses()
            .await
            .into_iter()
            .map(|status| status.spec)
            .collect()
    }

    async fn disable(&self, interface: &str) -> Result<Option<DhcpClientSpec>> {
        self.disable(interface).await
    }

    async fn reconcile(&self, spec: DhcpClientSpec, link_ready: bool) -> Result<()> {
        let name = spec.interface.clone();
        self.reconcile_with_link_ready(spec, link_ready).await;
        let status = self
            .status(&name)
            .await
            .context("DHCP client disappeared")?;
        if let crate::dhcp::client::DhcpClientRunState::Degraded { reason } = status.state {
            bail!("DHCP client on {name} is degraded: {reason}");
        }
        Ok(())
    }

    async fn verify_ready(&self, interface: &str) -> Result<()> {
        self.wait_until_ready(interface).await
    }

    async fn ensure_alive(&self) -> Result<bool> {
        self.ensure_alive().await
    }
}

#[async_trait]
pub(super) trait WifiRuntimeReconciler: Send + Sync {
    async fn ensure_alive(&self) -> Result<bool>;

    async fn reconcile_interface(&self, _interface: &str, _config: &InterfaceConfig) -> Result<()> {
        Ok(())
    }

    async fn association_ready(&self, _interface: &str) -> Option<bool> {
        None
    }
}

#[async_trait]
impl WifiRuntimeReconciler for HostapdSupervisor {
    async fn ensure_alive(&self) -> Result<bool> {
        Ok(HostapdSupervisor::ensure_alive(self).await?)
    }

    async fn reconcile_interface(&self, interface: &str, config: &InterfaceConfig) -> Result<()> {
        self.reconcile_interface_config(interface, config).await
    }
}

#[async_trait]
impl WifiRuntimeReconciler for WifiClientSupervisor {
    async fn ensure_alive(&self) -> Result<bool> {
        Ok(WifiClientSupervisor::ensure_alive(self).await?)
    }

    async fn reconcile_interface(&self, interface: &str, config: &InterfaceConfig) -> Result<()> {
        self.reconcile_interface_config(interface, config).await
    }

    async fn association_ready(&self, interface: &str) -> Option<bool> {
        self.status(interface)
            .await
            .map(|status| status.wpa_state.is_connected())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DhcpReconcileAction {
    Keep,
    Configure(DhcpServiceSpec),
    Disable,
}

fn log_router_dataplane_convergence_error(error: &anyhow::Error) {
    if let Some(missing) = missing_router_dataplane_interface(error) {
        tracing::warn!(
            interface = %missing.interface,
            role = %missing.role,
            error = %format!("{error:#}"),
            hint = "Check ip link; reconnect the adapter or update the interface name in router configuration. Retrying automatically when it appears.",
            "router dataplane convergence is deferred until the interface appears; daemon remains operational"
        );
    } else {
        tracing::warn!(error = %format!("{error:#}"), "router dataplane convergence failed");
    }
}

pub(super) fn interface_needs_reapply(
    interface: &NetworkInterface,
    current_addresses: &[Ipv4AddressInfo],
    config: &InterfaceConfig,
    ownership_tagging_available: bool,
) -> bool {
    if !interface.is_up {
        return true;
    }

    if crate::core::interface::owns_dynamic_ipv4(config) {
        return false;
    }

    let desired = config
        .ipv4
        .map(|network| (network.addr(), network.prefix_len()));

    if current_addresses
        .iter()
        .any(|address| Some((address.address, address.prefix_len)) != desired)
    {
        return true;
    }

    match desired {
        Some((address, prefix_len)) => {
            let existing = current_addresses
                .iter()
                .find(|current| current.address == address && current.prefix_len == prefix_len);
            match existing {
                // The address is there but is not tagged as ours. Claiming it
                // is the whole of the work, and it is not optional: without the
                // tag we cannot later prove we put it there, and the interface
                // becomes one we refuse to stop managing.
                Some(existing) => {
                    ownership_tagging_available
                        && existing.owner() != AddressOwner::TrafficMasqStatic
                }
                None => true,
            }
        }
        None => false,
    }
}

pub(super) fn plan_dhcp_reconcile(
    desired: Option<DhcpServiceSpec>,
    current: Option<DhcpServiceSpec>,
    interface_present: bool,
    ipv4_ready: bool,
    binding_stale: bool,
) -> DhcpReconcileAction {
    match desired {
        None => {
            if current.is_some() {
                DhcpReconcileAction::Disable
            } else {
                DhcpReconcileAction::Keep
            }
        }
        Some(_) if !interface_present || !ipv4_ready => {
            if current.is_some() {
                DhcpReconcileAction::Disable
            } else {
                DhcpReconcileAction::Keep
            }
        }
        Some(spec) => {
            if current.as_ref() != Some(&spec) || binding_stale {
                DhcpReconcileAction::Configure(spec)
            } else {
                DhcpReconcileAction::Keep
            }
        }
    }
}

async fn apply_dhcp_reconcile_action<D: DhcpRuntimeReconciler>(
    dhcp: &D,
    interface: &str,
    action: DhcpReconcileAction,
) -> Result<()> {
    match action {
        DhcpReconcileAction::Keep => {}
        DhcpReconcileAction::Configure(spec) => dhcp.reconcile(spec).await?,
        DhcpReconcileAction::Disable => {
            dhcp.disable(interface).await?;
        }
    }
    Ok(())
}

async fn reconcile_dhcp_client<L: DhcpClientRuntimeReconciler>(
    client: &L,
    interface: &str,
    config: &InterfaceConfig,
    link_ready: bool,
) -> Result<()> {
    match DhcpClientSpec::from_interface_config(interface, config)? {
        Some(spec) => client.reconcile(spec, link_ready).await?,
        None => {
            client.disable(interface).await?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
/// Perform one desired-state reconciliation pass across interface, DHCP, and Wi-Fi services.
pub(super) async fn reconcile_network_runtime_once<
    D: DhcpRuntimeReconciler,
    W: WifiRuntimeReconciler,
    C: WifiRuntimeReconciler,
    L: DhcpClientRuntimeReconciler,
>(
    desired: &DesiredNetworkState,
    journal: &AddressOwnershipJournal,
    network: Arc<dyn NetworkProvider>,
    dhcp: &D,
    wifi: Option<&W>,
    wifi_client: Option<&C>,
    dhcp_client: Option<&L>,
) -> Result<BTreeMap<String, String>> {
    crate::core::recovery::check_commit(desired.state_dir())?;
    let effective = desired.effective().await?;
    crate::wifi::policy::WifiRadioPolicy::validate(&effective.network, |name| {
        network.wireless_phy(name)
    })?;
    let management_allowlist = desired.management_allowlist().await;
    let mut failures: BTreeMap<String, String> = BTreeMap::new();
    let interface_manager = InterfaceManager::new(network.clone(), journal.clone());
    let wifi_runtime_dirs = crate::wifi::WifiRuntimeDirs::new(
        &effective.wifi.runtime_dir,
        &effective.wifi_client.runtime_dir,
    );
    crate::core::transaction::retry_interface_recovery(
        desired.state_dir(),
        &interface_manager,
        &desired.committed_overrides().await,
        &wifi_runtime_dirs,
    )
    .await?;
    // An old journal may just have restored a legacy secret. Use committed
    // intent, never a tentative role switch, before allowing its consumer.
    // Retry migration failures on later passes even after journal recovery
    // itself has succeeded and removed the interface's recovery fence.
    crate::wifi::store::migrate_legacy_passphrases(&desired.committed_config().await?).await?;
    let observed_interfaces: HashMap<_, _> = network
        .list_interfaces()
        .await?
        .into_iter()
        .map(|interface| (interface.name.clone(), interface))
        .collect();

    let restorations = desired.restorations().await;
    for (name, config) in &effective.network.interfaces {
        let result: Result<()> = async {
            crate::core::recovery::check_scope(&effective.runtime.state_dir, Some(name))?;
            let strict = desired.is_tentative(name).await || restorations.contains_key(name);
            let desired_dhcp = DhcpServiceSpec::from_interface_config(
                name,
                config,
                effective.dhcp.default_lease_seconds,
            )?;
            let current_dhcp = dhcp.spec(name).await;
            let Some(observed_interface) = observed_interfaces.get(name) else {
                apply_dhcp_reconcile_action(
                    dhcp,
                    name,
                    plan_dhcp_reconcile(desired_dhcp, current_dhcp, false, false, false),
                )
                .await?;
                let desired_ipv4 = config
                    .ipv4
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "none".to_string());
                bail!(
                    "interface {name} is absent; convergence is deferred until it appears \
                     (desired: managed={}, role={:?}, ipv4={desired_ipv4}, dhcp_server={}, \
                     dhcp_client={}, wifi_ap={}, wifi_client={}). Check that the interface name \
                     exists and the device/link is present; if it was renamed or removed, update \
                     or remove its traffic-masq configuration",
                    config.managed,
                    config.role,
                    config.dhcp.is_some(),
                    config.dhcp_client.is_some(),
                    config.wifi.is_some(),
                    config.wifi_client.is_some(),
                );
            };

            // Release AP ownership before starting a station on the same radio.
            // Starting an AP still waits until after station teardown and IPv4.
            if config.wifi.is_none() {
                if let Some(access_point) = wifi {
                    access_point.reconcile_interface(name, config).await?;
                }
            }
            if let Some(client) = wifi_client {
                client.reconcile_interface(name, config).await?;
            } else {
                anyhow::ensure!(
                    config.wifi_client.is_none(),
                    "Wi-Fi client runtime is unavailable"
                );
            }
            let mut link_ready = true;
            if config.wifi_client.is_some() {
                let deadline = time::Instant::now() + Duration::from_secs(5);
                loop {
                    link_ready = match wifi_client {
                        Some(client) => client.association_ready(name).await.unwrap_or(false),
                        None => false,
                    };
                    if link_ready || !strict {
                        break;
                    }
                    anyhow::ensure!(
                        time::Instant::now() < deadline,
                        "Wi-Fi association is not ready on {name}"
                    );
                    time::sleep(Duration::from_millis(20)).await;
                }
            }
            if let Some(client) = dhcp_client {
                reconcile_dhcp_client(client, name, config, link_ready).await?;
            } else {
                anyhow::ensure!(
                    DhcpClientSpec::from_interface_config(name, config)?.is_none(),
                    "DHCP client runtime is unavailable"
                );
            }

            if let Some(snapshot) = restorations.get(name) {
                interface_manager.rollback(snapshot).await?;
            } else {
                let current_addresses = network.list_ipv4_addresses(name).await?;
                let needs_apply = if config.managed {
                    // Foreign addresses are intentionally preserved; their presence
                    // must not cause an endless cycle of our own netlink events.
                    let mut relevant = Vec::new();
                    for address in &current_addresses {
                        if config.ipv4.is_some_and(|ip| {
                            ip.addr() == address.address && ip.prefix_len() == address.prefix_len
                        }) || interface_manager.owns_address(name, address).await
                        {
                            relevant.push(address.clone());
                        }
                    }
                    interface_needs_reapply(observed_interface, &relevant, config, false)
                } else {
                    interface_manager
                        .owns_any_address(name, &current_addresses)
                        .await
                };
                if needs_apply {
                    interface_manager
                        .apply_interface(
                            name,
                            config,
                            Some(config.role),
                            management_allowlist.contains(name),
                        )
                        .await?;
                }
            }
            let (ipv4_ready, binding_stale) = if desired_dhcp.is_some() {
                interface_manager
                    .verify_configured_ipv4(name, config)
                    .await?;
                (true, dhcp.binding_stale(name).await?)
            } else {
                (false, false)
            };
            if config.wifi.is_some() {
                let access_point = wifi.context("Wi-Fi access point runtime is unavailable")?;
                access_point.reconcile_interface(name, config).await?;
            }
            apply_dhcp_reconcile_action(
                dhcp,
                name,
                plan_dhcp_reconcile(desired_dhcp, current_dhcp, true, ipv4_ready, binding_stale),
            )
            .await?;
            if strict && DhcpClientSpec::from_interface_config(name, config)?.is_some() {
                if let Some(client) = dhcp_client {
                    client.verify_ready(name).await?;
                }
            }
            Ok(())
        }
        .await;
        if let Err(error) = result {
            tracing::warn!(interface = %name, error = %format!("{error:#}"), "interface convergence incomplete");
            failures.insert(name.clone(), format!("{error:#}"));
        }
    }

    Ok(failures)
}

/// Converge the machine towards the desired state, driven by events.
///
/// There is no periodic interface pass. The things that can make interface
/// state disagree all announce themselves:
///
/// - the desired state moved (an override was written),
/// - rtnetlink state moved (link, address, route or policy rule),
/// - notifications were dropped, so an unknown amount of the above happened.
///
/// nftables has no rtnetlink notification, so router dataplane integrity is
/// audited separately at a low cadence without polling all interface state.
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_runtime_network_reconcile(
    desired: DesiredNetworkState,
    journal: AddressOwnershipJournal,
    network: Arc<dyn NetworkProvider>,
    dhcp: DhcpSupervisor,
    wifi: Option<HostapdSupervisor>,
    wifi_client: Option<WifiClientSupervisor>,
    dhcp_client: DhcpClientSupervisor,
    network_mutations: Arc<NetworkMutationGate>,
    router: Option<RouterTransactionCoordinator>,
    mut kernel_events: mpsc::UnboundedReceiver<KernelEvent>,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<Result<()>> {
    // Attach synchronously, before the task is scheduled. Once the API is
    // serving, a transaction must never observe daemon state as `Detached`
    // merely because Tokio has not polled the reconciler yet.
    desired.attach_converger();
    let mut recovery_events = crate::core::recovery::subscribe();
    tokio::spawn(async move {
        loop {
            if shutdown_requested(&shutdown) {
                break;
            }

            // Converge first, wait second: the daemon has to reach the desired
            // state at startup without something having to happen first.
            //
            // Read the version before the pass, publish it after: the report
            // then says which proposals this pass had actually seen, so a
            // caller cannot mistake an older pass for an answer about its own
            // change.
            let version = desired.version();
            let (result, router_busy) = {
                // Interface transactions are themselves driven by this
                // converger, so both use a shared/read gate. Direct API and
                // router mutations take the exclusive/write side. This keeps
                // convergence alive for tentative interface state while
                // preventing it from racing a direct mutation.
                let _network_mutation = network_mutations.read().await;
                let router_busy = match &router {
                    Some(router) => {
                        router.status().await
                            != crate::core::router_transaction::CoordinatorStatus::Idle
                    }
                    None => false,
                };
                if router_busy {
                    (None, true)
                } else {
                    let result = reconcile_network_runtime_once(
                        &desired,
                        &journal,
                        network.clone(),
                        &dhcp,
                        wifi.as_ref(),
                        wifi_client.as_ref(),
                        Some(&dhcp_client),
                    )
                    .await;
                    // Tentative interface state is owned by its transaction.
                    // Router drift repair runs only against settled intent.
                    if !desired.has_pending().await {
                        if let Some(router) = &router {
                            let repair = async {
                                let effective = desired.effective().await?;
                                router
                                    .reconcile_dataplane(RouterDesired::from_effective_config(
                                        &effective,
                                    )?)
                                    .await
                            }
                            .await;
                            if let Err(error) = repair {
                                log_router_dataplane_convergence_error(&error);
                            }
                        }
                    }
                    (Some(result), false)
                }
            };
            if let Some(result) = result {
                if let Err(error) = &result {
                    tracing::warn!(%error, "runtime interface reconcile pass failed");
                }
                desired.report_result(version, result);
            } else {
                tracing::debug!("runtime reconcile suspended while a router transaction is pending recovery/confirmation");
            }

            tokio::select! {
                event = kernel_events.recv() => match event {
                    Some(_) => {
                        // A single `ip addr add` is several netlink messages, and
                        // the daemon's own writes are echoed back to it. Collapse
                        // whatever queued up into the one pass that follows —
                        // convergence re-reads everything anyway.
                        while kernel_events.try_recv().is_ok() {}
                    }
                    None => {
                        let message =
                            "kernel change notifications stopped; nothing can be converged any more";
                        desired.fail_converger(message);
                        tracing::error!("{message}");
                        bail!(message);
                    }
                },
                () = desired.changed() => {}
                _ = recovery_events.changed() => {}
                // I/O failures may clear without a kernel notification. Retry
                // unresolved startup snapshots even while the network is quiet.
                () = time::sleep(Duration::from_secs(30)),
                    if !router_busy && !crate::core::recovery::blocked_interfaces(desired.state_dir()).is_empty() => {}
                () = async {
                    if let Some(router) = &router {
                        router.wait_until_idle().await;
                    }
                }, if router_busy => {}
                changed = shutdown.changed() => match changed {
                    Ok(()) if shutdown_requested(&shutdown) => break,
                    Ok(()) => {}
                    Err(_) => break,
                }
            }
        }
        desired.stop_converger();
        Ok(())
    })
}

/// One pass of "is everything we spawned still running".
///
/// Split from the task that drives it so it can be exercised against fakes.
pub(super) async fn check_process_liveness<D, W, C, L>(
    dhcp: &D,
    wifi: Option<&W>,
    wifi_client: Option<&C>,
    dhcp_client: Option<&L>,
) where
    D: DhcpRuntimeReconciler,
    W: WifiRuntimeReconciler,
    C: WifiRuntimeReconciler,
    L: DhcpClientRuntimeReconciler,
{
    if let Err(error) = dhcp.ensure_runtime_alive().await {
        tracing::warn!(%error, "failed to restart the shared DHCP runtime");
    }
    if let Some(wifi) = wifi {
        if let Err(error) = wifi.ensure_alive().await {
            tracing::warn!(%error, "failed to check Wi-Fi access point liveness");
        }
    }
    if let Some(wifi_client) = wifi_client {
        if let Err(error) = wifi_client.ensure_alive().await {
            tracing::warn!(%error, "failed to check Wi-Fi client liveness");
        }
    }
    if let (Some(wifi_client), Some(dhcp_client)) = (wifi_client, dhcp_client) {
        for spec in dhcp_client.specs().await {
            if let Some(link_ready) = wifi_client.association_ready(&spec.interface).await {
                if let Err(error) = dhcp_client.reconcile(spec, link_ready).await {
                    tracing::warn!(%error, "DHCP client liveness reconcile failed");
                }
            }
        }
    }
    if let Some(dhcp_client) = dhcp_client {
        if let Err(error) = dhcp_client.ensure_alive().await {
            tracing::warn!(%error, "failed to check DHCP client liveness");
        }
    }
}

/// Monitor supervised network processes and retry recoverable failures until shutdown.
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_process_liveness_checks(
    desired: DesiredNetworkState,
    state_dir: std::path::PathBuf,
    dhcp: DhcpSupervisor,
    wifi: Option<HostapdSupervisor>,
    wifi_client: Option<WifiClientSupervisor>,
    dhcp_client: DhcpClientSupervisor,
    network_mutations: Arc<NetworkMutationGate>,
    router: Option<RouterTransactionCoordinator>,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut association_events = wifi_client
            .as_ref()
            .map(|wifi| wifi.subscribe_association_changes());
        let mut interval = time::interval(PROCESS_LIVENESS_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                event = async {
                    match association_events.as_mut() {
                        Some(receiver) => receiver.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if matches!(event, Err(tokio::sync::broadcast::error::RecvError::Closed)) {
                        association_events = None;
                    }
                    if let Ok((interface, pid)) = event {
                        let _network_mutation = network_mutations.execute().await;
                    if crate::core::recovery::check_commit(&state_dir).is_err() { continue; }
                        if let Some(router) = &router {
                            if router.status().await != crate::core::router_transaction::CoordinatorStatus::Idle { continue; }
                        }
                        if let Some(wifi) = &wifi_client {
                            // Re-read status under the gate: queued events may belong to a
                            // replaced supplicant or precede a network transaction.
                            if let Some(status) = wifi.status(&interface).await.filter(|status| status.pid == pid) {
                                if let Some(spec) = dhcp_client.spec(&interface).await {
                                    dhcp_client.reconcile_with_link_ready(spec, status.wpa_state.is_connected()).await;
                                }
                            }
                        }
                    }
                }

                _ = interval.tick() => {
                    if shutdown_requested(&shutdown) {
                        break;
                    }
                    // Liveness checks can restart or reconfigure supervised
                    // runtimes. Keep them exclusive with desired-state convergence:
                    // otherwise a DHCP/Wi-Fi readiness pass can replay state it
                    // observed just before a transaction converged.
                    let _network_mutation = network_mutations.execute().await;
                    if crate::core::recovery::check_commit(&state_dir).is_err() { continue; }
                    let router_busy = match &router {
                        Some(router) => router.status().await
                            != crate::core::router_transaction::CoordinatorStatus::Idle,
                        None => false,
                    };
                    if router_busy {
                        tracing::debug!("process liveness mutations suspended while a router transaction is pending recovery/confirmation");
                        continue;
                    }
                    let wifi_admitted = match desired.effective().await {
                        Ok(config) => match crate::wifi::policy::WifiRadioPolicy::validate_system(&config.network) {
                            Ok(()) => true,
                            Err(error) => {
                                tracing::warn!(%error, "Wi-Fi process restart blocked by radio policy");
                                false
                            }
                        },
                        Err(error) => { tracing::warn!(%error, "process restart blocked by invalid desired state"); continue; }
                    };
                    check_process_liveness(
                        &dhcp,
                        wifi.as_ref().filter(|_| wifi_admitted),
                        wifi_client.as_ref().filter(|_| wifi_admitted),
                        Some(&dhcp_client),
                    )
                    .await;
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

/// Monitor committed route and firewall state and repair drift under the mutation gate.
pub(super) fn spawn_router_dataplane_integrity_checks(
    desired: DesiredNetworkState,
    overrides: RuntimeOverrideManager,
    network_mutations: Arc<NetworkMutationGate>,
    router: Option<RouterTransactionCoordinator>,
    vpn_policy: Option<Arc<ProductionVpnPolicyManager>>,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if router.is_none() && vpn_policy.is_none() {
            return;
        }
        let mut interval = time::interval(ROUTER_DATAPLANE_INTEGRITY_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        // Startup already performs an explicit repair; wait a full interval
        // before the first integrity audit rather than duplicating it.
        interval.tick().await;

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if shutdown_requested(&shutdown) { break; }
                    // This audit is an autonomous writer when it repairs drift.
                    // Take exclusive runtime execution so it cannot race interface
                    // convergence or another background repair pass.
                    let _network_mutation = network_mutations.execute().await;
                    if crate::core::recovery::check_commit(desired.state_dir()).is_err() { continue; }
                    let router_busy = match &router {
                        Some(router) => router.status().await
                            != crate::core::router_transaction::CoordinatorStatus::Idle,
                        None => false,
                    };
                    if desired.has_pending().await || router_busy {
                        continue;
                    }
                    let result = async {
                        let effective = desired.effective().await?;
                        let router_desired = RouterDesired::from_effective_config(&effective)?;
                        if let Some(router) = &router {
                            router.reconcile_dataplane(router_desired.clone()).await?;
                        }

                        // The legacy single-hop VPN policy owns the same hop-0
                        // reserved namespace as the router VPN chain. Audit it
                        // only when no chain is configured, so the two
                        // coexistence paths never repair over one another.
                        if effective.vpn.enabled && router_desired.vpn_chain.is_empty() {
                            if let Some(policy) = &vpn_policy {
                                match overrides.effective_vpn_mode().await {
                                    VpnPolicyMode::Vpn => {
                                        let wanted = vpn_policy_desired(&effective).ok_or_else(|| {
                                            anyhow::anyhow!(
                                                "VPN policy mode is vpn but effective config has no protected subnets"
                                            )
                                        })?;
                                        if policy.health(&wanted).await.is_err() {
                                            policy.activate(&wanted).await?;
                                        }
                                    }
                                    VpnPolicyMode::Direct => {
                                        if policy.health_inactive().await.is_err() {
                                            let target = vpn_policy_desired(&effective)
                                                .unwrap_or_else(vpn_policy_teardown_target);
                                            policy.deactivate(&target).await?;
                                        }
                                    }
                                }
                            }
                        }
                        Ok::<_, anyhow::Error>(())
                    }.await;
                    if let Err(error) = result {
                        if missing_router_dataplane_interface(&error).is_some() {
                            log_router_dataplane_convergence_error(&error);
                        } else {
                            tracing::warn!(%error, "network integrity audit failed");
                        }
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
