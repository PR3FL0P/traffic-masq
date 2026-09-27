//! Installation, startup, and process lifecycle management.

use crate::core::mutation::NetworkMutationGate;

pub mod init;
pub mod installer;
mod process;
pub mod reset;
pub(crate) mod runtime;
pub mod service;
mod shutdown_control;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use tokio::signal;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{self, MissedTickBehavior};

use crate::api::control::ControlService;
use crate::api::server::HttpApiBindings;
use crate::auth::{AuthService, Principal};
use crate::config::{AppConfig, InterfaceConfig, ShutdownPolicy, VpnPolicyMode};
use crate::core::desired::DesiredNetworkState;
use crate::core::interface::{InterfaceManager, InterfaceSnapshot};
use crate::core::override_manager::RuntimeOverrideManager;
use crate::core::ownership::AddressOwnershipJournal;
use crate::core::route::{RouteManager, RouteSnapshot};
use crate::core::router::{RouterDesired, RouterManager};
use crate::core::router_subsystems::{ProductionRouterSubsystems, VpnChainDeps};
use crate::core::router_transaction::RouterTransactionCoordinator;
use crate::core::vpn_policy_manager::{
    vpn_policy_desired, vpn_policy_teardown_target, VpnPolicyManager,
};
use crate::dhcp::client::{DhcpClientSpec, DhcpClientSupervisor};
use crate::dhcp::supervisor::{DhcpServiceSpec, DhcpSupervisor};
use crate::firewall::{
    missing_router_dataplane_interface, vpn::VpnPolicyFirewallBackend, Ipv4ForwardingBackend,
    LinuxRouterDataplaneProvider, NftCommandExecutor, NftExecutor, NftablesBackend,
    ProcSysIpv4ForwardingIo, RouterDataplaneManager, RouterDataplaneProvider,
    RouterDataplaneSnapshot,
};
use crate::logging::init_logging;
use crate::netlink::events::KernelEvent;
use crate::netlink::{
    AddressOwner, Ipv4AddressInfo, NetworkInterface, NetworkProvider, RtnetlinkNetworkProvider,
};
use crate::state::overrides::RuntimeOverrides;
use crate::vpn::{
    ActiveProfileStore, LazyNetlinkVpnProvider, ProductionVpnManager, VpnManager, VpnProvider,
    WireGuardProfileStore, WireGuardVpnDriver,
};
use crate::wifi::{HostapdSupervisor, WifiApSpec, WifiClientSpec, WifiClientSupervisor};

use process::ProcessGuard;

type ProductionDataplaneProvider = LinuxRouterDataplaneProvider<
    ProcSysIpv4ForwardingIo,
    NftCommandExecutor,
    Arc<dyn NetworkProvider>,
>;
type ProductionVpnPolicyManager = VpnPolicyManager<WireGuardVpnDriver, Arc<dyn NftExecutor>>;

const PROCESS_LIVENESS_INTERVAL: Duration = Duration::from_secs(1);
const ROUTER_DATAPLANE_INTEGRITY_INTERVAL: Duration = Duration::from_secs(15);

const SESSION_REAP_INTERVAL: Duration = Duration::from_secs(900);

#[async_trait]
trait DhcpRuntimeReconciler: Send + Sync {
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
trait DhcpClientRuntimeReconciler: Send + Sync {
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
        let deadline = time::Instant::now() + Duration::from_secs(5);
        loop {
            let status = self
                .status(interface)
                .await
                .context("DHCP client disappeared")?;
            if let Some(lease) = status.lease {
                return self.verify_bound_lease(&lease).await;
            }
            if let crate::dhcp::client::DhcpClientRunState::Degraded { reason } = status.state {
                bail!("DHCP client on {interface} is degraded: {reason}");
            }
            anyhow::ensure!(
                time::Instant::now() < deadline,
                "DHCP lease is not ready on {interface}"
            );
            time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn ensure_alive(&self) -> Result<bool> {
        self.ensure_alive().await
    }
}

#[async_trait]
trait WifiRuntimeReconciler: Send + Sync {
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
        let desired = WifiApSpec::from_interface_config(interface, config)?;
        match desired {
            Some(spec) => {
                self.configure(spec).await?;
                Ok(())
            }
            None if self.status(interface).await.is_some() => {
                self.disable(interface).await?;
                Ok(())
            }
            None => Ok(()),
        }
    }
}

#[async_trait]
impl WifiRuntimeReconciler for WifiClientSupervisor {
    async fn ensure_alive(&self) -> Result<bool> {
        Ok(WifiClientSupervisor::ensure_alive(self).await?)
    }

    async fn reconcile_interface(&self, interface: &str, config: &InterfaceConfig) -> Result<()> {
        let desired = WifiClientSpec::from_interface_config(interface, config)?;
        match desired {
            Some(spec) => {
                self.configure(spec).await?;
                Ok(())
            }
            None if self.status(interface).await.is_some() => {
                self.disable(interface).await?;
                Ok(())
            }
            None => Ok(()),
        }
    }

    async fn association_ready(&self, interface: &str) -> Option<bool> {
        self.status(interface)
            .await
            .map(|status| status.wpa_state.is_connected())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DhcpReconcileAction {
    Keep,
    Configure(DhcpServiceSpec),
    Disable,
}

struct RouterRuntimeState<P: RouterDataplaneProvider> {
    routes: RouteManager,
    route_snapshot: RouteSnapshot,
    dataplane: RouterDataplaneManager<P>,
    dataplane_snapshot: RouterDataplaneSnapshot,
}

async fn apply_router_dataplane<P>(
    desired: &RouterDesired,
    network_provider: Arc<dyn NetworkProvider>,
    dataplane_provider: P,
) -> Result<RouterRuntimeState<P>>
where
    P: RouterDataplaneProvider + Send + Sync,
{
    let routes = RouteManager::new(network_provider);
    let route_snapshot = routes
        .apply(&desired.routes, desired.allow_default_route_change)
        .await
        .context("failed to apply router-owned routes")?;

    let dataplane = RouterDataplaneManager::new(dataplane_provider);
    let plan = match dataplane.plan_target(desired.dataplane.clone()).await {
        Ok(plan) => plan,
        Err(error) => {
            if let Err(rollback_error) = routes.rollback(&route_snapshot).await {
                tracing::error!(
                    %rollback_error,
                    "failed to rollback router routes after dataplane planning failure"
                );
            }
            return Err(error).context("failed to plan router dataplane");
        }
    };
    let dataplane_snapshot = match dataplane.apply(&plan).await {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let route_rollback = routes.rollback(&route_snapshot).await;
            if let Err(rollback_error) = &route_rollback {
                tracing::error!(
                    %rollback_error,
                    "failed to rollback router routes after dataplane apply failure"
                );
            }
            if route_rollback.is_ok() {
                if let Some(missing) = missing_router_dataplane_interface(&error) {
                    tracing::warn!(
                        interface = %missing.interface,
                        role = %missing.role,
                        error = %format!("{error:#}"),
                        hint = "Check ip link; reconnect the adapter or update the interface name in router configuration. Retrying automatically when it appears.",
                        "router dataplane startup convergence is deferred until the interface appears; daemon startup will continue"
                    );
                    return Ok(RouterRuntimeState {
                        routes,
                        route_snapshot,
                        dataplane,
                        dataplane_snapshot: plan.snapshot,
                    });
                }
            }
            return Err(error).context("failed to apply router dataplane");
        }
    };

    Ok(RouterRuntimeState {
        routes,
        route_snapshot,
        dataplane,
        dataplane_snapshot,
    })
}

/// Full startup repair must not snapshot/plan absent physical interfaces.
/// The runtime interface converger and dataplane reconciler finish this work
/// when the kernel announces their return. Crash recovery is never skipped.
async fn missing_router_repair_interfaces(
    desired: &RouterDesired,
    network: &dyn NetworkProvider,
) -> Result<Vec<String>> {
    let observed = network
        .list_interfaces()
        .await
        .context("failed to observe interfaces before router startup repair")?;
    let mut missing: Vec<String> = desired
        .interfaces
        .iter()
        .filter(|entry| {
            !desired
                .vpn_chain
                .iter()
                .any(|hop| hop.interface == entry.name)
        })
        .filter(|entry| {
            !observed
                .iter()
                .any(|interface| interface.name == entry.name)
        })
        .map(|entry| entry.name.clone())
        .collect();
    missing.sort();
    missing.dedup();
    Ok(missing)
}

async fn restore_router_dataplane<P>(state: &RouterRuntimeState<P>) -> Result<()>
where
    P: RouterDataplaneProvider + Send + Sync,
{
    let mut errors = Vec::new();
    if let Err(error) = state.dataplane.rollback(&state.dataplane_snapshot).await {
        errors.push(format!("router dataplane rollback failed: {error:#}"));
    }
    if let Err(error) = state.routes.rollback(&state.route_snapshot).await {
        errors.push(format!("router route rollback failed: {error:#}"));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        bail!(errors.join("; "))
    }
}

async fn rollback_router_dataplane<P>(state: &RouterRuntimeState<P>)
where
    P: RouterDataplaneProvider + Send + Sync,
{
    if let Err(error) = restore_router_dataplane(state).await {
        tracing::error!(%error, "failed to rollback router dataplane during daemon shutdown");
    }
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

/// Compare the address ownership journal with the machine, once, at startup.
///
/// The journal is written before the kernel is touched, so after a crash it can
/// claim an address that never made it onto a link, or one that has since been
/// replaced by somebody else's. Both are dropped here. Everything that survives
/// is an address this daemon may take off again, which is exactly the authority
/// that must not be granted on the strength of an unchecked file.
async fn reconcile_address_ownership(
    journal: &AddressOwnershipJournal,
    network: &dyn NetworkProvider,
) {
    for interface in journal.interfaces().await {
        let observed = match network.list_ipv4_addresses(&interface).await {
            Ok(observed) => observed,
            Err(error) => {
                // The interface is not there right now — unplugged, or renamed.
                // The claims stay: convergence will look again, and dropping
                // them here would disown addresses that come back with it.
                tracing::info!(
                    %interface,
                    %error,
                    "keeping recorded IPv4 address ownership: the interface cannot be read right now"
                );
                continue;
            }
        };
        match journal.reconcile(&interface, &observed).await {
            Ok(outcome) => {
                for (claim, reason) in &outcome.dropped {
                    tracing::info!(
                        %interface,
                        address = %format!("{}/{}", claim.address, claim.prefix_len),
                        reason = %reason,
                        "dropping a recorded IPv4 address claim: the machine disagrees"
                    );
                }
                if !outcome.kept.is_empty() {
                    tracing::info!(
                        %interface,
                        addresses = %outcome
                            .kept
                            .iter()
                            .map(|claim| format!("{}/{}", claim.address, claim.prefix_len))
                            .collect::<Vec<_>>()
                            .join(", "),
                        "adopted IPv4 addresses recorded by a previous run"
                    );
                }
            }
            Err(error) => tracing::warn!(
                %interface,
                %error,
                "failed to reconcile recorded IPv4 address ownership"
            ),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn production_router_coordinator(
    desired: &RouterDesired,
    vpn_store_dir: &Path,
    state_dir: &Path,
    network: Arc<dyn NetworkProvider>,
    journal: AddressOwnershipJournal,
    dhcp: DhcpSupervisor,
    dhcp_client: DhcpClientSupervisor,
    wifi_client: Option<WifiClientSupervisor>,
    wifi: Option<HostapdSupervisor>,
    overrides: RuntimeOverrideManager,
    rollback_timeout: Duration,
) -> Result<RouterTransactionCoordinator> {
    let interfaces = InterfaceManager::new(network.clone(), journal);
    let routes = RouteManager::new(network.clone());
    let dataplane_provider = production_dataplane_provider(network.clone());
    let dataplane = RouterDataplaneManager::new(dataplane_provider);
    let router_interfaces = desired
        .interfaces
        .iter()
        .map(|interface| interface.name.clone())
        .collect();
    let mut subsystems = ProductionRouterSubsystems::new_with_dhcp_client(
        interfaces,
        routes,
        dhcp,
        dataplane,
        router_interfaces,
        Arc::new(dhcp_client),
    );
    // Wi-Fi runtimes are attached when they exist. A missing runtime is not
    // fatal here: the intent this coordinator will be asked to apply is not
    // known yet, and refusing now would judge it by the intent that happened to
    // exist at boot. `plan_uplink_wifi` / `plan_output_wifi` already reject a
    // Wi-Fi intent without a runtime, at the point where the intent is real.
    if let Some(wifi_client) = wifi_client {
        subsystems = subsystems.with_station_runtime(Arc::new(wifi_client));
    }
    if let Some(wifi) = wifi {
        subsystems = subsystems.with_access_point_runtime(Arc::new(wifi));
    }

    // Keep VPN control-plane dependencies available for runtime enablement.
    // RouterDesired still rejects a VPN chain while VPN is disabled.
    {
        let vpn_provider: Arc<dyn VpnProvider> = Arc::new(LazyNetlinkVpnProvider::new());
        subsystems = subsystems.with_vpn_chain(VpnChainDeps {
            vpn_provider,
            wireguard_store: WireGuardProfileStore::new(vpn_store_dir.to_path_buf()),
            state_dir: state_dir.to_path_buf(),
            network,
            nft_executor: Arc::new(NftCommandExecutor),
        });
    }

    let manager = RouterManager::new(Arc::new(subsystems));
    Ok(RouterTransactionCoordinator::new(
        manager,
        overrides,
        rollback_timeout,
    ))
}

async fn build_vpn_manager(config: &AppConfig) -> Result<Option<Arc<ProductionVpnManager>>> {
    let store = WireGuardProfileStore::new(config.vpn.wireguard_config_dir.clone());
    let active_profile_store =
        ActiveProfileStore::new(config.runtime.state_dir.join("vpn-active-profile.json"));
    let provider: Arc<dyn VpnProvider> = Arc::new(LazyNetlinkVpnProvider::new());
    let driver = WireGuardVpnDriver::new(provider, store);
    let manager = Arc::new(VpnManager::new(driver, active_profile_store));

    // Build the control plane even when disabled; only enabled VPNs reconcile.
    if config.vpn.enabled {
        match manager.reconcile().await {
            Ok(outcome) => {
                tracing::info!(?outcome, "VPN startup reconcile complete");
            }
            Err(error) => {
                return Err(error).context("VPN startup reconcile failed");
            }
        }
    }
    Ok(Some(manager))
}

pub(crate) fn build_vpn_policy_manager<E: NftExecutor>(
    network: Arc<dyn NetworkProvider>,
    firewall_executor: E,
    tunnel: Arc<ProductionVpnManager>,
) -> VpnPolicyManager<WireGuardVpnDriver, E> {
    let firewall = VpnPolicyFirewallBackend::new(firewall_executor);
    VpnPolicyManager::new(network, firewall, tunnel)
}

async fn apply_vpn_policy_startup<E: NftExecutor>(
    effective_config: &AppConfig,
    overrides: &RuntimeOverrideManager,
    network_provider: Arc<dyn NetworkProvider>,
    firewall_executor: E,
    vpn_manager: &Option<Arc<ProductionVpnManager>>,
) {
    // The router VPN chain owns the same hop-0 reserved routing namespace
    // as the legacy single-hop policy (the kernel interfaces themselves are
    // deliberately distinct). Router recovery/repair runs
    // before this startup hook, so touching legacy policy here would mutate a
    // just-recovered chain outside the router transaction coordinator. The
    // periodic integrity path has the same coexistence guard.
    if !effective_config.vpn.enabled || !effective_config.router.vpn_chain.is_empty() {
        return;
    }

    let Some(tunnel) = vpn_manager else {
        return;
    };

    let mode = overrides.effective_vpn_mode().await;
    let policy = build_vpn_policy_manager(network_provider, firewall_executor, tunnel.clone());

    match mode {
        VpnPolicyMode::Vpn => {
            let Some(desired) = vpn_policy_desired(effective_config) else {
                tracing::error!(
                    "persisted VPN traffic policy mode is \"vpn\" but the effective config has \
                     no router uplink or managed output subnets to protect — fail closed, VPN \
                     policy not activated"
                );
                return;
            };
            match policy.activate(&desired).await {
                Ok(_) => tracing::info!(
                    interface = %desired.vpn_interface,
                    "VPN traffic policy activated at startup"
                ),
                Err(error) => tracing::error!(
                    %error,
                    "failed to activate VPN traffic policy at startup — fail closed, protected \
                     traffic is not routed through VPN; router mode continues unaffected"
                ),
            }
        }
        VpnPolicyMode::Direct => {
            let desired =
                vpn_policy_desired(effective_config).unwrap_or_else(vpn_policy_teardown_target);
            if let Err(error) = policy.deactivate(&desired).await {
                tracing::warn!(
                    %error,
                    "failed to fully clean up VPN traffic policy state while starting in direct \
                     mode"
                );
            }
        }
    }
}

fn production_dataplane_provider(network: Arc<dyn NetworkProvider>) -> ProductionDataplaneProvider {
    LinuxRouterDataplaneProvider::new(
        Ipv4ForwardingBackend::new(ProcSysIpv4ForwardingIo),
        NftablesBackend::new(NftCommandExecutor),
        network,
    )
}

fn management_allowlist(snapshot: &RuntimeOverrides) -> BTreeSet<String> {
    snapshot
        .interfaces
        .iter()
        .filter(|(_, value)| value.allow_management_change)
        .map(|(interface, _)| interface.clone())
        .collect()
}

fn interface_needs_reapply(
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

fn plan_dhcp_reconcile(
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
async fn reconcile_network_runtime_once<
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
    let management_allowlist = desired.management_allowlist().await;
    let mut failures: BTreeMap<String, String> = BTreeMap::new();
    let interface_manager = InterfaceManager::new(network.clone(), journal.clone());
    crate::core::transaction::retry_interface_recovery(
        desired.state_dir(),
        &interface_manager,
        &desired.committed_overrides().await,
    )
    .await?;
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
fn spawn_runtime_network_reconcile(
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
async fn check_process_liveness<D, W, C, L>(
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

/// Monitor supervised network processes and retry recoverable failures until shutdown.
fn spawn_process_liveness_checks(
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
                    check_process_liveness(
                        &dhcp,
                        wifi.as_ref(),
                        wifi_client.as_ref(),
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
fn spawn_router_dataplane_integrity_checks(
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

/// One-time load-path migration (Landing 1, plan step 10): a persisted
/// config with `vpn.policy.default_mode == Vpn` and an empty
/// `router.vpn_chain` predates the chain model entirely — synthesize a
/// length-1 chain from whatever profile the legacy single-tunnel path had
/// most recently activated, so the chain becomes the one source of truth
/// going forward instead of `default_mode` silently continuing to mean
/// something the rest of the system no longer consults.
///
/// LIMITATION: this only ever sees the *legacy* active-profile record
/// (`<state_dir>/vpn-active-profile.json`, the file `build_vpn_manager`
/// reads/writes for `OWNED_INTERFACE_NAME`/`tm-wg0`) because that is the
/// only place "which profile was active" is knowable without a driver
/// handle — `AppConfig::load` itself is synchronous and has no I/O access to
/// runtime state, so the migration cannot run there and instead runs here,
/// at daemon startup, before `RuntimeOverrideManager::load` builds the
/// effective config every other startup step consumes. If no legacy active
/// profile was ever persisted (e.g. `default_mode: Vpn` was set but the
/// tunnel was never actually activated, or the state directory was wiped),
/// there is nothing to synthesize from and `default_mode` is left in place
/// unmigrated — falling back to the pre-chain behavior for that one startup
/// rather than silently fabricating a chain with no real profile. The
/// synthesized chain is not written back to the on-disk config file in this
/// landing; it only affects the in-memory `AppConfig` for this run (and
/// anything derived from it, including `RuntimeOverrideManager`'s base), so
/// a config file inspected by hand won't yet show the migrated chain.
async fn migrate_vpn_policy_mode_to_chain(config: &mut AppConfig) {
    if config.router.forwarding.is_some()
        || config.vpn.policy.default_mode != VpnPolicyMode::Vpn
        || !config.router.vpn_chain.is_empty()
    {
        return;
    }
    let active_profile_store =
        ActiveProfileStore::new(config.runtime.state_dir.join("vpn-active-profile.json"));
    let persisted = match active_profile_store.load().await {
        Ok(Some(persisted)) => persisted,
        Ok(None) => {
            tracing::warn!(
                "vpn.policy.default_mode is \"vpn\" but no legacy active VPN profile is \
                 persisted; leaving vpn_chain empty for this run rather than fabricating a hop \
                 with no real profile"
            );
            return;
        }
        Err(error) => {
            tracing::warn!(
                error = %error,
                "failed to read the legacy active VPN profile while migrating \
                 vpn.policy.default_mode = \"vpn\" to a hop chain; leaving vpn_chain empty for \
                 this run"
            );
            return;
        }
    };
    tracing::info!(
        profile = %persisted.profile_name,
        "migrating legacy vpn.policy.default_mode = \"vpn\" to a length-1 VPN hop chain"
    );
    config.router.vpn_chain = vec![crate::config::VpnHopConfig {
        profile_name: persisted.profile_name,
    }];
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

    // Decode the durable proof envelope without admitting unrelated runtime settings. Individual
    // proof fields are handled independently below so one recovery scope cannot suppress another.
    let recovery_store =
        crate::state::overrides::RuntimeOverrideStore::in_state_dir(&config.runtime.state_dir);
    let recovery_proof = recovery_store.load_recovery_commit_proof().await?;
    let committed_router_transaction = recovery_proof.committed_router_transaction();
    let committed_interface_transactions = recovery_proof.committed_interface_transactions();

    let network_provider: Arc<dyn NetworkProvider> = Arc::new(RtnetlinkNetworkProvider::connect()?);
    // The directory itself is still a global invariant: if it cannot be enumerated, ownership is
    // unknowable. Damage to one named document is isolated to that interface and fenced below.
    let ownership_open = AddressOwnershipJournal::open_isolated(&config.runtime.state_dir)
        .context("failed to open the IPv4 address ownership journal")?;
    let ownership_blocked_interfaces = ownership_open
        .blocked_interfaces
        .iter()
        .map(|(interface, _)| interface.clone())
        .collect::<std::collections::BTreeSet<_>>();
    for (interface, reason) in &ownership_open.blocked_interfaces {
        let ownership_path = config
            .runtime
            .state_dir
            .join("address-ownership")
            .join(format!("{interface}.json"));
        crate::core::recovery::block_interface_nonretryable(
            &config.runtime.state_dir,
            interface,
            &ownership_path,
            format!("address_ownership={}; {reason}", ownership_path.display()),
        );
    }
    let ownership_journal = ownership_open.journal;
    reconcile_address_ownership(&ownership_journal, network_provider.as_ref()).await;

    let interface_manager =
        InterfaceManager::new(network_provider.clone(), ownership_journal.clone());
    match committed_interface_transactions {
        Ok(committed) => {
            crate::core::transaction::recover_interface_transactions_with_commit_tokens_excluding(
                &config.runtime.state_dir,
                &interface_manager,
                &committed,
                &ownership_blocked_interfaces,
            )
            .await?;
        }
        Err(error) => {
            // Never guess that a journal is uncommitted when the independent proof field is
            // malformed. Fence only the interfaces that actually have pending journals and keep
            // unrelated router recovery available.
            crate::core::transaction::block_interface_transactions_without_commit_proof(
                &config.runtime.state_dir,
                &format!("runtime override interface commit proof is invalid: {error:#}"),
            )
            .await?;
            tracing::error!(
                operation = "recover_interface_transactions",
                invariant = "independent_commit_proof",
                error = %format!("{error:#}"),
                "interface commit proof is untrusted; pending interface scopes were fenced"
            );
        }
    }

    let router_journal = config.runtime.state_dir.join("router-transaction.json");
    let router_recovery_pending = crate::atomic_file::regular_file_exists(&router_journal)
        .context(
            crate::core::recovery::RecoveryDiagnostic::fatal(
                crate::core::recovery::StartupRecoveryCode::AccessibleRouterRecoveryJournal,
                "inspect",
                crate::core::recovery::RecoveryAction::RepairStorageAccess,
            )
            .journal(router_journal.clone())
            .object("router")
            .detail("expected_type", "regular_file_when_present")
            .detail(
                "expected_mode",
                format!("{:04o}", crate::atomic_file::PRIVATE_FILE_MODE),
            )
            .detail("symlink_allowed", false),
        )?;
    let provisioning_journal = config
        .runtime
        .state_dir
        .join("wifi")
        .join("router-provisioning-secrets.json");
    let provisioning_recovery_pending =
        crate::atomic_file::regular_file_exists(&provisioning_journal).context(
            crate::core::recovery::RecoveryDiagnostic::fatal(
                crate::core::recovery::StartupRecoveryCode::RestoreProvisioningSecrets,
                "inspect",
                crate::core::recovery::RecoveryAction::RepairStorageAccess,
            )
            .journal(provisioning_journal.clone())
            .object("router-provisioning-secrets")
            .detail("expected_type", "regular_file_when_present")
            .detail(
                "expected_mode",
                format!("{:04o}", crate::atomic_file::PRIVATE_FILE_MODE),
            )
            .detail("symlink_allowed", false),
        )?;

    let committed_router_transaction = match committed_router_transaction {
        Ok(token) => token,
        Err(error) if router_recovery_pending || provisioning_recovery_pending => {
            return Err(crate::core::recovery::context_if_missing(
                error,
                crate::core::recovery::RecoveryDiagnostic::fatal(
                    crate::core::recovery::StartupRecoveryCode::ProvableRouterRecovery,
                    "startup_recovery",
                    crate::core::recovery::RecoveryAction::InspectRecoveryState,
                )
                .journal(router_journal.clone())
                .object("router")
                .detail("required_proof", "independent_committed_transaction_token"),
            ));
        }
        Err(error) => {
            // There is no router recovery metadata to act on. Preserve the field error for strict
            // admission later, but do not let it suppress already-completed interface recovery.
            tracing::warn!(
                error = %format!("{error:#}"),
                "router commit proof is invalid but no router recovery journal is pending"
            );
            None
        }
    };

    // Provisioning secrets belong to the router recovery scope. Run this only after independent
    // interface recovery, so a router-secret problem cannot suppress interface rollback.
    let provisioning_recovery =
        crate::core::provisioning_secret_transaction::ProvisioningSecretTransactionStore::in_state_dir(
            &config.runtime.state_dir,
        )
        .recover(committed_router_transaction.as_deref())
        .await;
    if let Err(error) = provisioning_recovery {
        return Err(crate::core::recovery::context_if_missing(
            error,
            crate::core::recovery::RecoveryDiagnostic::fatal(
                crate::core::recovery::StartupRecoveryCode::RestoreProvisioningSecrets,
                "startup_recovery",
                crate::core::recovery::RecoveryAction::InspectRecoveryState,
            )
            .journal(provisioning_journal)
            .object("router-provisioning-secrets")
            .detail(
                "next_step",
                "inspect_nested_recovery_diagnostic_before_restoring_state",
            ),
        ));
    }

    // Build only router-relevant state first. When no router journal is pending, recovery is already
    // complete and normal startup must pass strict admission before it mutates the network. With a
    // pending router journal, strict admission remains deferred until rollback has finished.
    let overrides = RuntimeOverrideManager::from_router_recovery_proof(
        recovery_store,
        &config,
        &recovery_proof,
        committed_router_transaction,
    )?;
    let (effective_config, strict_admitted) = if router_recovery_pending {
        let snapshot = overrides.snapshot().await;
        (snapshot.effective_router_recovery_config(&config)?, false)
    } else {
        config.validate()?;
        (overrides.hydrate_strict().await?, true)
    };
    let override_snapshot = overrides.snapshot().await;
    let management_allowlist = management_allowlist(&override_snapshot);

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
