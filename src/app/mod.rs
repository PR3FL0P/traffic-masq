mod process;
pub mod service;

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use ipnet::Ipv4Net;
use tokio::signal;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{self, MissedTickBehavior};

use crate::api::control::ControlService;
use crate::api::server::HttpApiBindings;
use crate::auth::{AuthService, Principal};
use crate::config::{AppConfig, InterfaceConfig, InterfaceRole, ShutdownPolicy, VpnPolicyMode};
use crate::core::interface::{InterfaceManager, InterfaceSnapshot};
use crate::core::route::{RouteManager, RouteSnapshot};
use crate::core::router::{RouterDesired, RouterManager};
use crate::core::router_subsystems::ProductionRouterSubsystems;
use crate::core::router_transaction::RouterTransactionCoordinator;
use crate::core::transaction::NetworkTransactionManager;
use crate::core::vpn_policy_manager::{VpnPolicyDesired, VpnPolicyManager};
use crate::dhcp::client::{DhcpClientSpec, DhcpClientSupervisor};
use crate::dhcp::supervisor::{DhcpServiceSpec, DhcpSupervisor};
use crate::firewall::{
    vpn::VpnPolicyFirewallBackend, Ipv4ForwardingBackend, LinuxRouterDataplaneProvider,
    NftCommandExecutor, NftExecutor, NftablesBackend, ProcSysIpv4ForwardingIo,
    RouterDataplaneManager, RouterDataplaneProvider, RouterDataplaneSnapshot,
};
use crate::logging::init_logging;
use crate::netlink::{
    Ipv4AddressInfo, NetworkInterface, NetworkProvider, RtnetlinkNetworkProvider,
};
use crate::state::overrides::{RuntimeOverrideManager, RuntimeOverrides};
use crate::vpn::manager::OWNED_INTERFACE_NAME;
use crate::vpn::{
    ActiveProfileStore, NetlinkVpnProvider, ProductionVpnManager, VpnManager, VpnProvider,
    WireGuardProfileStore, WireGuardVpnDriver,
};
use crate::wifi::{HostapdSupervisor, WifiClientSupervisor};

use process::ProcessGuard;

type ProductionDataplaneProvider = LinuxRouterDataplaneProvider<
    ProcSysIpv4ForwardingIo,
    NftCommandExecutor,
    RtnetlinkNetworkProvider,
>;

const RUNTIME_RECONCILE_INTERVAL: Duration = Duration::from_secs(1);

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
    async fn spec(&self, interface: &str) -> Option<DhcpClientSpec>;
    async fn disable(&self, interface: &str) -> Result<Option<DhcpClientSpec>>;
    async fn reconcile(&self, spec: DhcpClientSpec, link_ready: bool);
    async fn ensure_alive(&self) -> Result<bool>;
}

#[async_trait]
impl DhcpClientRuntimeReconciler for DhcpClientSupervisor {
    async fn spec(&self, interface: &str) -> Option<DhcpClientSpec> {
        self.spec(interface).await
    }

    async fn disable(&self, interface: &str) -> Result<Option<DhcpClientSpec>> {
        self.disable(interface).await
    }

    async fn reconcile(&self, spec: DhcpClientSpec, link_ready: bool) {
        self.reconcile_with_link_ready(spec, link_ready).await
    }

    async fn ensure_alive(&self) -> Result<bool> {
        self.ensure_alive().await
    }
}

#[async_trait]
trait WifiRuntimeReconciler: Send + Sync {
    async fn ensure_alive(&self) -> Result<bool>;

    async fn association_ready(&self, _interface: &str) -> Option<bool> {
        None
    }
}

#[async_trait]
impl WifiRuntimeReconciler for HostapdSupervisor {
    async fn ensure_alive(&self) -> Result<bool> {
        Ok(HostapdSupervisor::ensure_alive(self).await?)
    }
}

#[async_trait]
impl WifiRuntimeReconciler for WifiClientSupervisor {
    async fn ensure_alive(&self) -> Result<bool> {
        Ok(WifiClientSupervisor::ensure_alive(self).await?)
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
            if let Err(rollback_error) = routes.rollback(&route_snapshot).await {
                tracing::error!(
                    %rollback_error,
                    "failed to rollback router routes after dataplane apply failure"
                );
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

async fn rollback_router_dataplane<P>(state: &RouterRuntimeState<P>)
where
    P: RouterDataplaneProvider + Send + Sync,
{
    if let Err(error) = state.dataplane.rollback(&state.dataplane_snapshot).await {
        tracing::error!(%error, "failed to rollback router dataplane during daemon shutdown");
    }
    if let Err(error) = state.routes.rollback(&state.route_snapshot).await {
        tracing::error!(%error, "failed to rollback router routes during daemon shutdown");
    }
}

fn production_router_coordinator(
    desired: &RouterDesired,
    dhcp: DhcpSupervisor,
    dhcp_client: DhcpClientSupervisor,
    wifi_client: Option<WifiClientSupervisor>,
    wifi: Option<HostapdSupervisor>,
    overrides: RuntimeOverrideManager,
    rollback_timeout: Duration,
) -> Result<RouterTransactionCoordinator> {
    let network: Arc<dyn NetworkProvider> = Arc::new(
        RtnetlinkNetworkProvider::connect()
            .context("failed to open rtnetlink connection for router transaction coordinator")?,
    );
    let interfaces = InterfaceManager::new(network.clone());
    let routes = RouteManager::new(network);
    let dataplane_provider = production_dataplane_provider()
        .context("failed to build router dataplane provider for transaction coordinator")?;
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
    if let (Some(wifi_client), Some(wifi)) = (wifi_client, wifi) {
        subsystems = subsystems.with_wifi_runtimes(Arc::new(wifi_client), Arc::new(wifi));
    } else if desired.uplink_wifi.is_some() || !desired.output_wifi.is_empty() {
        anyhow::bail!("router Wi-Fi intent requires both STA and AP runtimes");
    }
    let manager = RouterManager::new(Arc::new(subsystems));
    Ok(RouterTransactionCoordinator::new(
        manager,
        overrides,
        rollback_timeout,
    ))
}

async fn build_vpn_manager(config: &AppConfig) -> Result<Option<Arc<ProductionVpnManager>>> {
    if !config.vpn.enabled {
        return Ok(None);
    }

    let store = WireGuardProfileStore::new(config.vpn.wireguard_config_dir.clone());
    let active_profile_store =
        ActiveProfileStore::new(config.runtime.state_dir.join("vpn-active-profile.json"));
    let provider: Arc<dyn VpnProvider> = Arc::new(NetlinkVpnProvider::connect()?);
    let driver = WireGuardVpnDriver::new(provider, store);
    let manager = Arc::new(VpnManager::new(driver, active_profile_store));

    match manager.reconcile().await {
        Ok(outcome) => {
            tracing::info!(?outcome, "VPN startup reconcile complete");
        }
        Err(error) => {
            return Err(error).context("VPN startup reconcile failed");
        }
    }

    Ok(Some(manager))
}

pub(crate) fn vpn_policy_desired(config: &AppConfig) -> Option<VpnPolicyDesired> {
    let uplink = config.router.uplink.as_ref()?;
    let protected_subnets: Vec<Ipv4Net> = config
        .network
        .interfaces
        .values()
        .filter(|interface| interface.role == InterfaceRole::Output && interface.managed)
        .filter_map(|interface| interface.ipv4)
        .collect();
    if protected_subnets.is_empty() {
        return None;
    }
    Some(VpnPolicyDesired {
        protected_subnets,
        vpn_interface: OWNED_INTERFACE_NAME.to_string(),
        physical_uplink: uplink.interface.clone(),
    })
}

pub(crate) fn vpn_policy_teardown_target() -> VpnPolicyDesired {
    VpnPolicyDesired {
        protected_subnets: Vec::new(),
        vpn_interface: OWNED_INTERFACE_NAME.to_string(),
        physical_uplink: String::new(),
    }
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

fn production_dataplane_provider() -> Result<ProductionDataplaneProvider> {
    let network = RtnetlinkNetworkProvider::connect()
        .context("failed to open rtnetlink connection for router dataplane preflight")?;
    Ok(LinuxRouterDataplaneProvider::new(
        Ipv4ForwardingBackend::new(ProcSysIpv4ForwardingIo),
        NftablesBackend::new(NftCommandExecutor),
        network,
    ))
}

fn management_allowlist(snapshot: &crate::state::overrides::RuntimeOverrides) -> BTreeSet<String> {
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
        Some((address, prefix_len)) => !current_addresses
            .iter()
            .any(|current| current.address == address && current.prefix_len == prefix_len),
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
) {
    match action {
        DhcpReconcileAction::Keep => {}
        DhcpReconcileAction::Configure(spec) => {
            if let Err(error) = dhcp.reconcile(spec).await {
                tracing::warn!(interface, %error, "failed to reconcile DHCP service");
            }
        }
        DhcpReconcileAction::Disable => {
            if let Err(error) = dhcp.disable(interface).await {
                tracing::warn!(interface, %error, "failed to disable stale DHCP service");
            }
        }
    }
}

async fn reconcile_dhcp_client<L: DhcpClientRuntimeReconciler>(
    client: &L,
    interface: &str,
    config: &InterfaceConfig,
    link_ready: bool,
) {
    let desired = match DhcpClientSpec::from_interface_config(interface, config) {
        Ok(spec) => spec,
        Err(error) => {
            tracing::warn!(interface, %error, "failed to derive effective DHCP client during reconcile");
            return;
        }
    };
    let current = client.spec(interface).await;
    match (desired, current) {
        (Some(spec), current) if current.as_ref() != Some(&spec) => {
            client.reconcile(spec, link_ready).await;
        }
        (None, Some(_)) => {
            if let Err(error) = client.disable(interface).await {
                tracing::warn!(interface, %error, "failed to disable stale DHCP client");
            }
        }
        (Some(spec), Some(_)) => client.reconcile(spec, link_ready).await,
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
async fn reconcile_network_runtime_once<
    D: DhcpRuntimeReconciler,
    W: WifiRuntimeReconciler,
    C: WifiRuntimeReconciler,
    L: DhcpClientRuntimeReconciler,
>(
    base_config: &AppConfig,
    overrides: &RuntimeOverrideManager,
    network: Arc<dyn NetworkProvider>,
    dhcp: &D,
    wifi: Option<&W>,
    wifi_client: Option<&C>,
    dhcp_client: Option<&L>,
    pending_interfaces: &BTreeSet<String>,
) -> Result<()> {
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

    let snapshot = overrides.snapshot().await;
    let effective = snapshot.effective_config(base_config)?;
    let management_allowlist = management_allowlist(&snapshot);
    let interface_manager = InterfaceManager::new(network.clone());
    let observed_interfaces: HashMap<_, _> = network
        .list_interfaces()
        .await?
        .into_iter()
        .map(|interface| (interface.name.clone(), interface))
        .collect();

    for (name, config) in &effective.network.interfaces {
        // A change that has been applied to the kernel but not yet confirmed
        // owns this interface until it is committed or rolled back. During that
        // window the kernel deliberately holds the new state while the override
        // still describes the old one, so reconciling would simply undo the
        // user's change — within a second, and without leaving a trace.
        if pending_interfaces.contains(name) {
            tracing::debug!(
                interface = %name,
                "skipping runtime reconcile: an applied network change is awaiting confirmation"
            );
            continue;
        }

        if let Some(dhcp_client) = dhcp_client {
            let link_ready = if config.wifi_client.is_some() {
                match wifi_client {
                    Some(client) => client.association_ready(name).await.unwrap_or(false),
                    None => false,
                }
            } else {
                true
            };
            reconcile_dhcp_client(dhcp_client, name, config, link_ready).await;
        }
        let desired_dhcp = match DhcpServiceSpec::from_interface_config(
            name,
            config,
            base_config.dhcp.default_lease_seconds,
        ) {
            Ok(spec) => spec,
            Err(error) => {
                tracing::warn!(interface = %name, %error, "failed to derive effective DHCP service during reconcile");
                continue;
            }
        };
        let current_dhcp = dhcp.spec(name).await;
        let Some(observed_interface) = observed_interfaces.get(name) else {
            apply_dhcp_reconcile_action(
                dhcp,
                name,
                plan_dhcp_reconcile(desired_dhcp, current_dhcp, false, false, false),
            )
            .await;
            continue;
        };

        if config.managed {
            let current_addresses = match network.list_ipv4_addresses(name).await {
                Ok(addresses) => addresses,
                Err(error) => {
                    tracing::warn!(interface = %name, %error, "failed to list IPv4 addresses during runtime reconcile");
                    continue;
                }
            };
            if interface_needs_reapply(observed_interface, &current_addresses, config) {
                let allow_management_change = management_allowlist.contains(name);

                if let Err(error) = interface_manager
                    .apply_interface(name, config, Some(config.role), allow_management_change)
                    .await
                {
                    tracing::warn!(interface = %name, %error, "failed to reapply managed interface during runtime reconcile");
                    continue;
                }
            }
        }

        let (ipv4_ready, binding_stale) = if desired_dhcp.is_some() {
            match interface_manager.verify_configured_ipv4(name, config).await {
                Ok(()) => match dhcp.binding_stale(name).await {
                    Ok(binding_stale) => (true, binding_stale),
                    Err(error) => {
                        tracing::warn!(interface = %name, %error, "failed to check DHCP binding freshness during runtime reconcile");
                        (false, false)
                    }
                },
                Err(error) => {
                    tracing::warn!(interface = %name, %error, "managed interface is not yet ready for DHCP during runtime reconcile");
                    (false, false)
                }
            }
        } else {
            (false, false)
        };

        apply_dhcp_reconcile_action(
            dhcp,
            name,
            plan_dhcp_reconcile(desired_dhcp, current_dhcp, true, ipv4_ready, binding_stale),
        )
        .await;
    }

    if let Some(dhcp_client) = dhcp_client {
        if let Err(error) = dhcp_client.ensure_alive().await {
            tracing::warn!(%error, "failed to check DHCP client liveness");
        }
    }

    Ok(())
}

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

#[allow(clippy::too_many_arguments)]
fn spawn_runtime_network_reconcile(
    config: AppConfig,
    overrides: RuntimeOverrideManager,
    network: Arc<dyn NetworkProvider>,
    dhcp: DhcpSupervisor,
    wifi: Option<HostapdSupervisor>,
    wifi_client: Option<WifiClientSupervisor>,
    dhcp_client: DhcpClientSupervisor,
    transactions: NetworkTransactionManager,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = time::interval(RUNTIME_RECONCILE_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if shutdown_requested(&shutdown) {
                        break;
                    }
                    let pending_interfaces: BTreeSet<String> = transactions
                        .pending()
                        .await
                        .into_iter()
                        .map(|change| change.interface)
                        .collect();
                    if let Err(error) = reconcile_network_runtime_once(&config, &overrides, network.clone(), &dhcp, wifi.as_ref(), wifi_client.as_ref(), Some(&dhcp_client), &pending_interfaces).await {
                        tracing::warn!(%error, "runtime interface/DHCP reconcile pass failed");
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
    tokio::process::Command::new(binary)
        .arg("-v")
        .output()
        .await
        .with_context(|| {
            format!(
                "hostapd binary {} is not runnable — install hostapd or fix wifi.hostapd_binary",
                binary.display()
            )
        })?;
    Ok(())
}

async fn build_wifi_supervisor(
    effective_config: &AppConfig,
    override_snapshot: &RuntimeOverrides,
) -> Result<Option<HostapdSupervisor>> {
    if !effective_config.wifi.enabled {
        return Ok(None);
    }
    preflight_hostapd_binary(&effective_config.wifi.hostapd_binary).await?;
    let supervisor = HostapdSupervisor::start(effective_config, override_snapshot).await?;
    Ok(Some(supervisor))
}

async fn preflight_wpa_supplicant_binary(binary: &Path) -> Result<()> {
    tokio::process::Command::new(binary)
        .arg("-v")
        .output()
        .await
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
    override_snapshot: &RuntimeOverrides,
) -> Result<Option<WifiClientSupervisor>> {
    if !effective_config.wifi_client.enabled {
        return Ok(None);
    }
    preflight_wpa_supplicant_binary(&effective_config.wifi_client.wpa_supplicant_binary).await?;
    let supervisor = WifiClientSupervisor::start(effective_config, override_snapshot).await?;
    Ok(Some(supervisor))
}

pub async fn reset_device_password(config: &AppConfig, password: &str) -> Result<Principal> {
    config.validate()?;
    let _process_guard = ProcessGuard::acquire(&config.runtime.pid_path)?;
    let auth = AuthService::open(&config.auth).await?;
    Ok(auth.reset_device_password(password).await?)
}

pub async fn run_daemon(config: AppConfig) -> Result<()> {
    config.validate()?;
    let shutdown = install_shutdown_signal()?;
    let _process_guard = ProcessGuard::acquire(&config.runtime.pid_path)?;
    init_logging(&config)?;

    let overrides = RuntimeOverrideManager::load(&config.runtime.state_dir, &config).await?;
    let override_snapshot = overrides.snapshot().await;
    let effective_config = override_snapshot.effective_config(&config)?;
    let bindings = HttpApiBindings::bind(&effective_config)?;
    let auth = AuthService::open(&config.auth).await?;
    if shutdown_requested(&shutdown) {
        tracing::info!("shutdown requested before network initialization");
        return Ok(());
    }
    let management_allowlist = management_allowlist(&override_snapshot);

    let network_provider: Arc<dyn NetworkProvider> = Arc::new(RtnetlinkNetworkProvider::connect()?);
    let interface_manager = InterfaceManager::new(network_provider.clone());
    let startup_baselines = interface_manager
        .apply_network_with_management_allowlist(&effective_config.network, &management_allowlist)
        .await?;

    if shutdown_requested(&shutdown) {
        rollback_interfaces(&interface_manager, &startup_baselines).await;
        tracing::info!("shutdown requested during network initialization");
        return Ok(());
    }

    let wifi_supervisor = match build_wifi_supervisor(&effective_config, &override_snapshot).await {
        Ok(supervisor) => supervisor,
        Err(error) => {
            rollback_interfaces(&interface_manager, &startup_baselines).await;
            return Err(error);
        }
    };

    if shutdown_requested(&shutdown) {
        if let Some(wifi) = &wifi_supervisor {
            wifi.shutdown(ShutdownPolicy::RestoreInterfaces).await;
        }
        rollback_interfaces(&interface_manager, &startup_baselines).await;
        tracing::info!("shutdown requested during Wi-Fi initialization");
        return Ok(());
    }

    let wifi_client_supervisor =
        match build_wifi_client_supervisor(&effective_config, &override_snapshot).await {
            Ok(supervisor) => supervisor,
            Err(error) => {
                rollback_interfaces(&interface_manager, &startup_baselines).await;
                return Err(error);
            }
        };

    if shutdown_requested(&shutdown) {
        if let Some(wifi) = &wifi_supervisor {
            wifi.shutdown(ShutdownPolicy::RestoreInterfaces).await;
        }
        if let Some(wifi_client) = &wifi_client_supervisor {
            wifi_client
                .shutdown(ShutdownPolicy::RestoreInterfaces)
                .await;
        }
        rollback_interfaces(&interface_manager, &startup_baselines).await;
        tracing::info!("shutdown requested during Wi-Fi client initialization");
        return Ok(());
    }

    let dhcp = match DhcpSupervisor::start(&effective_config, &override_snapshot).await {
        Ok(supervisor) => supervisor,
        Err(error) => {
            rollback_interfaces(&interface_manager, &startup_baselines).await;
            return Err(error);
        }
    };

    if shutdown_requested(&shutdown) {
        if let Some(wifi) = &wifi_supervisor {
            wifi.shutdown(ShutdownPolicy::RestoreInterfaces).await;
        }
        if let Some(wifi_client) = &wifi_client_supervisor {
            wifi_client
                .shutdown(ShutdownPolicy::RestoreInterfaces)
                .await;
        }
        dhcp.shutdown().await;
        rollback_interfaces(&interface_manager, &startup_baselines).await;
        tracing::info!("shutdown requested during DHCP initialization");
        return Ok(());
    }

    let dhcp_client =
        match DhcpClientSupervisor::start(&effective_config, network_provider.clone()).await {
            Ok(supervisor) => supervisor,
            Err(error) => {
                dhcp.shutdown().await;
                rollback_interfaces(&interface_manager, &startup_baselines).await;
                return Err(error);
            }
        };

    if shutdown_requested(&shutdown) {
        dhcp_client
            .shutdown(ShutdownPolicy::RestoreInterfaces)
            .await;
        if let Some(wifi) = &wifi_supervisor {
            wifi.shutdown(ShutdownPolicy::RestoreInterfaces).await;
        }
        if let Some(wifi_client) = &wifi_client_supervisor {
            wifi_client
                .shutdown(ShutdownPolicy::RestoreInterfaces)
                .await;
        }
        dhcp.shutdown().await;
        rollback_interfaces(&interface_manager, &startup_baselines).await;
        tracing::info!("shutdown requested during DHCP client initialization");
        return Ok(());
    }

    let desired = RouterDesired::from_effective_config(&effective_config)?;
    let router_state = if desired.enabled {
        let dataplane_provider = match production_dataplane_provider() {
            Ok(provider) => provider,
            Err(error) => {
                dhcp_client
                    .shutdown(ShutdownPolicy::RestoreInterfaces)
                    .await;
                dhcp.shutdown().await;
                rollback_interfaces(&interface_manager, &startup_baselines).await;
                return Err(error);
            }
        };
        match apply_router_dataplane(&desired, network_provider.clone(), dataplane_provider).await {
            Ok(state) => Some(state),
            Err(error) => {
                dhcp_client
                    .shutdown(ShutdownPolicy::RestoreInterfaces)
                    .await;
                dhcp.shutdown().await;
                rollback_interfaces(&interface_manager, &startup_baselines).await;
                return Err(error);
            }
        }
    } else {
        None
    };

    if shutdown_requested(&shutdown) {
        if let Some(state) = &router_state {
            rollback_router_dataplane(state).await;
        }
        if let Some(wifi) = &wifi_supervisor {
            wifi.shutdown(ShutdownPolicy::RestoreInterfaces).await;
        }
        if let Some(wifi_client) = &wifi_client_supervisor {
            wifi_client
                .shutdown(ShutdownPolicy::RestoreInterfaces)
                .await;
        }
        dhcp_client
            .shutdown(ShutdownPolicy::RestoreInterfaces)
            .await;
        dhcp.shutdown().await;
        rollback_interfaces(&interface_manager, &startup_baselines).await;
        tracing::info!("shutdown requested during router dataplane initialization");
        return Ok(());
    }

    // The coordinator is part of the control plane.  Keep it available while
    // the router awaits initial provisioning, even though there is no active
    // data-plane intent yet.
    let router_coordinator = if effective_config.router.enabled {
        match production_router_coordinator(
            &desired,
            dhcp.clone(),
            dhcp_client.clone(),
            wifi_client_supervisor.clone(),
            wifi_supervisor.clone(),
            overrides.clone(),
            Duration::from_secs(config.security.rollback_timeout_seconds),
        ) {
            Ok(coordinator) => Some(coordinator),
            Err(error) => {
                if let Some(state) = &router_state {
                    rollback_router_dataplane(state).await;
                }
                dhcp_client
                    .shutdown(ShutdownPolicy::RestoreInterfaces)
                    .await;
                dhcp.shutdown().await;
                rollback_interfaces(&interface_manager, &startup_baselines).await;
                return Err(error);
            }
        }
    } else {
        None
    };

    let vpn_manager = match build_vpn_manager(&effective_config).await {
        Ok(vpn_manager) => vpn_manager,
        Err(error) => {
            if let Some(state) = &router_state {
                rollback_router_dataplane(state).await;
            }
            dhcp_client
                .shutdown(ShutdownPolicy::RestoreInterfaces)
                .await;
            dhcp.shutdown().await;
            rollback_interfaces(&interface_manager, &startup_baselines).await;
            return Err(error);
        }
    };

    apply_vpn_policy_startup(
        &effective_config,
        &overrides,
        network_provider.clone(),
        NftCommandExecutor,
        &vpn_manager,
    )
    .await;

    let mut control = ControlService::new_with_baselines(
        effective_config.clone(),
        network_provider.clone(),
        dhcp.clone(),
        overrides.clone(),
        startup_baselines,
    );
    if let Some(coordinator) = router_coordinator {
        control = control.with_router_coordinator(coordinator);
    }

    if let Some(wifi) = &wifi_supervisor {
        control = control.with_wifi_supervisor(wifi.clone());
    }
    if let Some(wifi_client) = &wifi_client_supervisor {
        control = control.with_wifi_client_supervisor(wifi_client.clone());
    }
    control = control.with_dhcp_client_supervisor(dhcp_client.clone());
    if let Some(vpn) = &vpn_manager {
        control = control.with_vpn_manager(vpn.clone());
        let firewall_executor: Arc<dyn NftExecutor> = Arc::new(NftCommandExecutor);
        control = control.with_vpn_policy_manager(Arc::new(build_vpn_policy_manager(
            network_provider,
            firewall_executor,
            vpn.clone(),
        )));
    }
    let transactions = control.transactions();
    let socket_path = bindings.socket_path().to_path_buf();
    let session_reaper = spawn_session_reaper(auth.clone(), shutdown.clone());
    let server = bindings.into_server(control, auth);

    tracing::info!(
        dhcp_interfaces = ?dhcp.running_interfaces().await,
        socket = %socket_path.display(),
        https = effective_config.api.tcp.as_ref().is_some_and(|tcp| tcp.enabled),
        router_enabled = desired.enabled,
        vpn_enabled = vpn_manager.is_some(),
        wifi_enabled = wifi_supervisor.is_some(),
        wifi_client_enabled = wifi_client_supervisor.is_some(),
        "traffic-masqd ready"
    );

    let reconcile_task =
        spawn_runtime_network_reconcile(
            config.clone(),
            overrides.clone(),
            Arc::new(RtnetlinkNetworkProvider::connect().context(
                "failed to open rtnetlink connection for runtime interface/DHCP reconcile",
            )?),
            dhcp.clone(),
            wifi_supervisor.clone(),
            wifi_client_supervisor.clone(),
            dhcp_client.clone(),
            transactions.clone(),
            shutdown.clone(),
        );

    let api_result = server.run(shutdown.clone()).await;
    reconcile_task.abort();
    let _ = reconcile_task.await;
    session_reaper.abort();
    let _ = session_reaper.await;
    let graceful_signal = shutdown_requested(&shutdown);
    tracing::info!(graceful_signal, "traffic-masqd stopping");

    let mut cleanup_errors = Vec::new();
    let restore_interfaces = !graceful_signal
        || effective_config.runtime.shutdown_policy == ShutdownPolicy::RestoreInterfaces;

    dhcp_client
        .shutdown(if restore_interfaces {
            ShutdownPolicy::RestoreInterfaces
        } else {
            ShutdownPolicy::PreserveInterfaces
        })
        .await;

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
            rollback_router_dataplane(state).await;
        }
    }

    if let Some(vpn) = &vpn_manager {
        if let Err(error) = vpn.shutdown(effective_config.runtime.shutdown_policy).await {
            tracing::error!(%error, "VPN shutdown cleanup failed");
            cleanup_errors.push(error.to_string());
        }
    }

    dhcp.shutdown().await;

    if let Some(wifi) = &wifi_supervisor {
        wifi.shutdown(effective_config.runtime.shutdown_policy)
            .await;
    }

    if let Some(wifi_client) = &wifi_client_supervisor {
        wifi_client
            .shutdown(effective_config.runtime.shutdown_policy)
            .await;
    }

    if let Err(error) = api_result {
        cleanup_errors.push(format!("HTTP API failed: {error:#}"));
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
mod tests {
    use crate::netlink::AddressOwnership;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    use async_trait::async_trait;
    use tempfile::tempdir;
    use tokio::sync::Mutex;

    use crate::config::{
        DhcpInterfaceConfig, InterfaceConfig, InterfaceRole, RouterConfig, UplinkConfig,
        UplinkMode, VpnConfig,
    };
    use crate::firewall::vpn::test_support::{nft_ruleset, FakeNftExecutor};
    use crate::firewall::{OwnedFirewallIntegrity, RouterDataplaneDesired};
    use crate::netlink::{
        Ipv4AddressInfo, Ipv4RouteInfo, Ipv4RouteSpec, Ipv4RuleInfo, Ipv4RuleSpec,
    };
    use crate::vpn::active_profile::ActiveProfileStore;
    use crate::vpn::store::WireGuardProfileStore;
    use crate::vpn::wireguard::{WireGuardKey, WireGuardPeerConfig, WireGuardVpnDriver};
    use crate::vpn::{ProviderError, VpnProvider};

    use super::*;

    #[derive(Debug, Default)]
    struct FakeNetworkProvider {
        interfaces: Mutex<HashMap<String, crate::netlink::NetworkInterface>>,
        addresses: Mutex<HashMap<String, Vec<Ipv4AddressInfo>>>,
        routes: Mutex<Vec<Ipv4RouteInfo>>,
        rules: Mutex<Vec<Ipv4RuleInfo>>,
        fail_next_add_route: Mutex<bool>,
    }

    impl FakeNetworkProvider {
        async fn add_interface(&self, name: &str, index: u32) {
            self.add_interface_with_state(name, index, true, Vec::new())
                .await;
        }

        async fn add_interface_with_state(
            &self,
            name: &str,
            index: u32,
            is_up: bool,
            addresses: Vec<Ipv4AddressInfo>,
        ) {
            self.interfaces.lock().await.insert(
                name.to_string(),
                crate::netlink::NetworkInterface {
                    is_wireless: false,
                    index,
                    name: name.to_string(),
                    is_up,
                    rx_bytes: 0,
                    tx_bytes: 0,
                },
            );
            self.addresses
                .lock()
                .await
                .insert(name.to_string(), addresses);
        }
    }

    #[async_trait]
    impl NetworkProvider for FakeNetworkProvider {
        async fn list_interfaces(&self) -> Result<Vec<crate::netlink::NetworkInterface>> {
            Ok(self.interfaces.lock().await.values().cloned().collect())
        }

        async fn list_ipv4_addresses(&self, interface: &str) -> Result<Vec<Ipv4AddressInfo>> {
            Ok(self
                .addresses
                .lock()
                .await
                .get(interface)
                .cloned()
                .unwrap_or_default())
        }

        async fn set_link_up(&self, name: &str) -> Result<()> {
            let mut interfaces = self.interfaces.lock().await;
            let interface = interfaces
                .get_mut(name)
                .ok_or_else(|| anyhow::anyhow!("interface not found: {name}"))?;
            interface.is_up = true;
            Ok(())
        }

        async fn set_link_down(&self, name: &str) -> Result<()> {
            let mut interfaces = self.interfaces.lock().await;
            let interface = interfaces
                .get_mut(name)
                .ok_or_else(|| anyhow::anyhow!("interface not found: {name}"))?;
            interface.is_up = false;
            Ok(())
        }

        async fn add_ipv4_address(
            &self,
            interface: &str,
            address: Ipv4Addr,
            prefix_len: u8,
            ownership: AddressOwnership,
        ) -> Result<()> {
            let interface_index = self
                .interfaces
                .lock()
                .await
                .get(interface)
                .ok_or_else(|| anyhow::anyhow!("interface not found: {interface}"))?
                .index;
            let mut addresses = self.addresses.lock().await;
            let entry = addresses.entry(interface.to_string()).or_default();
            if !entry
                .iter()
                .any(|current| current.address == address && current.prefix_len == prefix_len)
            {
                entry.push(Ipv4AddressInfo {
                    interface_index,
                    address,
                    prefix_len,
                    protocol: ownership.protocol(),
                });
            }
            Ok(())
        }

        async fn delete_ipv4_address(
            &self,
            interface: &str,
            address: Ipv4Addr,
            prefix_len: u8,
        ) -> Result<()> {
            if let Some(addresses) = self.addresses.lock().await.get_mut(interface) {
                addresses.retain(|current| {
                    !(current.address == address && current.prefix_len == prefix_len)
                });
            }
            Ok(())
        }

        async fn list_ipv4_routes(&self) -> Result<Vec<Ipv4RouteInfo>> {
            Ok(self.routes.lock().await.clone())
        }

        async fn add_ipv4_route(&self, route: &Ipv4RouteSpec) -> Result<()> {
            let mut fail = self.fail_next_add_route.lock().await;
            if *fail {
                *fail = false;
                anyhow::bail!("injected route add failure");
            }
            drop(fail);
            self.routes.lock().await.push(Ipv4RouteInfo {
                destination: route.destination,
                gateway: route.gateway,
                output_interface_index: route.output_interface_index,
                table: route.table,
                metric: route.metric,
                protocol: route.protocol,
                scope: if route.gateway.is_some() { 0 } else { 253 },
            });
            Ok(())
        }

        async fn delete_ipv4_route(&self, route: &Ipv4RouteInfo) -> Result<()> {
            self.routes.lock().await.retain(|current| current != route);
            Ok(())
        }

        async fn list_ipv4_rules(&self) -> Result<Vec<Ipv4RuleInfo>> {
            Ok(self.rules.lock().await.clone())
        }

        async fn add_ipv4_rule(&self, rule: &Ipv4RuleSpec) -> Result<()> {
            self.rules.lock().await.push(Ipv4RuleInfo {
                source: rule.source,
                destination: rule.destination,
                table: rule.table,
                priority: rule.priority,
                fw_mark: rule.fw_mark,
                fw_mask: rule.fw_mask,
                input_interface: rule.input_interface.clone(),
                output_interface: rule.output_interface.clone(),
            });
            Ok(())
        }

        async fn delete_ipv4_rule(&self, rule: &Ipv4RuleInfo) -> Result<()> {
            self.rules.lock().await.retain(|current| current != rule);
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct FakeDhcpReconciler {
        specs: Mutex<HashMap<String, DhcpServiceSpec>>,
        stale_bindings: Mutex<HashMap<String, bool>>,
        configure_calls: Mutex<Vec<DhcpServiceSpec>>,
        disable_calls: Mutex<Vec<String>>,
        runtime_liveness_checks: Mutex<usize>,
    }

    #[async_trait]
    impl DhcpRuntimeReconciler for FakeDhcpReconciler {
        async fn spec(&self, interface: &str) -> Option<DhcpServiceSpec> {
            self.specs.lock().await.get(interface).cloned()
        }

        async fn disable(&self, interface: &str) -> Result<Option<DhcpServiceSpec>> {
            self.disable_calls.lock().await.push(interface.to_string());
            Ok(self.specs.lock().await.remove(interface))
        }

        async fn binding_stale(&self, interface: &str) -> Result<bool> {
            Ok(*self
                .stale_bindings
                .lock()
                .await
                .get(interface)
                .unwrap_or(&false))
        }

        async fn reconcile(&self, spec: DhcpServiceSpec) -> Result<()> {
            self.configure_calls.lock().await.push(spec.clone());
            self.stale_bindings
                .lock()
                .await
                .insert(spec.interface.clone(), false);
            self.specs.lock().await.insert(spec.interface.clone(), spec);
            Ok(())
        }

        async fn ensure_runtime_alive(&self) -> Result<bool> {
            *self.runtime_liveness_checks.lock().await += 1;
            Ok(false)
        }
    }

    #[derive(Debug, Default)]
    struct FakeDhcpClientReconciler {
        specs: Mutex<HashMap<String, DhcpClientSpec>>,
        reconcile_calls: Mutex<Vec<DhcpClientSpec>>,
        readiness: Mutex<Vec<(String, bool)>>,
        disable_calls: Mutex<Vec<String>>,
        liveness_checks: Mutex<usize>,
    }

    #[async_trait]
    impl DhcpClientRuntimeReconciler for FakeDhcpClientReconciler {
        async fn spec(&self, interface: &str) -> Option<DhcpClientSpec> {
            self.specs.lock().await.get(interface).cloned()
        }

        async fn disable(&self, interface: &str) -> Result<Option<DhcpClientSpec>> {
            self.disable_calls.lock().await.push(interface.to_string());
            Ok(self.specs.lock().await.remove(interface))
        }

        async fn reconcile(&self, spec: DhcpClientSpec, link_ready: bool) {
            self.readiness
                .lock()
                .await
                .push((spec.interface.clone(), link_ready));
            let changed = self.specs.lock().await.get(&spec.interface) != Some(&spec);
            if changed {
                self.reconcile_calls.lock().await.push(spec.clone());
                self.specs.lock().await.insert(spec.interface.clone(), spec);
            }
        }

        async fn ensure_alive(&self) -> Result<bool> {
            *self.liveness_checks.lock().await += 1;
            Ok(false)
        }
    }

    #[derive(Debug, Default)]
    struct FakeWifiReconciler {
        liveness_checks: Mutex<usize>,
        associations: Mutex<HashMap<String, bool>>,
    }

    #[async_trait]
    impl WifiRuntimeReconciler for FakeWifiReconciler {
        async fn ensure_alive(&self) -> Result<bool> {
            *self.liveness_checks.lock().await += 1;
            Ok(false)
        }

        async fn association_ready(&self, interface: &str) -> Option<bool> {
            self.associations.lock().await.get(interface).copied()
        }
    }

    struct FakeDataplaneProvider {
        state: Mutex<RouterDataplaneSnapshot>,
        fail_next_apply: Mutex<bool>,
    }

    impl Default for FakeDataplaneProvider {
        fn default() -> Self {
            Self {
                state: Mutex::new(RouterDataplaneSnapshot {
                    ipv4_forwarding: false,
                    owned: None,
                    owned_firewall_integrity: OwnedFirewallIntegrity::Intact,
                }),
                fail_next_apply: Mutex::new(false),
            }
        }
    }

    #[async_trait]
    impl RouterDataplaneProvider for FakeDataplaneProvider {
        async fn observe(&self) -> Result<RouterDataplaneSnapshot> {
            Ok(self.state.lock().await.clone())
        }

        async fn apply_owned(&self, desired: &RouterDataplaneDesired) -> Result<()> {
            let mut fail = self.fail_next_apply.lock().await;
            if *fail {
                *fail = false;
                anyhow::bail!("injected dataplane apply failure");
            }
            drop(fail);
            let mut state = self.state.lock().await;
            state.ipv4_forwarding = true;
            state.owned = Some(desired.clone());
            Ok(())
        }

        async fn disable_owned(&self) -> Result<()> {
            self.state.lock().await.owned = None;
            Ok(())
        }

        async fn restore_owned(&self, snapshot: &RouterDataplaneSnapshot) -> Result<()> {
            *self.state.lock().await = snapshot.clone();
            Ok(())
        }
    }

    const VALID_VPN_PRIVATE_KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const VALID_VPN_PUBLIC_KEY: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

    fn valid_vpn_profile() -> String {
        format!(
            "[Interface]\n\
             PrivateKey = {VALID_VPN_PRIVATE_KEY}\n\
             Address = 10.0.0.2/24\n\
             \n\
             [Peer]\n\
             PublicKey = {VALID_VPN_PUBLIC_KEY}\n\
             AllowedIPs = 0.0.0.0/0\n\
             Endpoint = 203.0.113.1:51820\n"
        )
    }

    #[derive(Debug, Clone)]
    struct FakeVpnLink {
        up: bool,
    }

    #[derive(Default)]
    struct FakeVpnProvider {
        links: Mutex<HashMap<String, FakeVpnLink>>,
    }

    #[async_trait]
    impl VpnProvider for FakeVpnProvider {
        async fn link_exists(&self, name: &str) -> Result<bool, ProviderError> {
            Ok(self.links.lock().await.contains_key(name))
        }

        async fn create_link(
            &self,
            name: &str,
            _private_key: &WireGuardKey,
            _listen_port: Option<u16>,
        ) -> Result<(), ProviderError> {
            self.links
                .lock()
                .await
                .insert(name.to_string(), FakeVpnLink { up: false });
            Ok(())
        }

        async fn set_addresses(
            &self,
            name: &str,
            _addresses: &[ipnet::IpNet],
        ) -> Result<(), ProviderError> {
            self.require_link(name).await
        }

        async fn set_peers(
            &self,
            name: &str,
            _peers: &[WireGuardPeerConfig],
        ) -> Result<(), ProviderError> {
            self.require_link(name).await
        }

        async fn set_link_up(&self, name: &str) -> Result<(), ProviderError> {
            let mut links = self.links.lock().await;
            let link = links
                .get_mut(name)
                .ok_or_else(|| ProviderError::NotFound(name.to_string()))?;
            link.up = true;
            Ok(())
        }

        async fn set_link_down(&self, name: &str) -> Result<(), ProviderError> {
            let mut links = self.links.lock().await;
            let link = links
                .get_mut(name)
                .ok_or_else(|| ProviderError::NotFound(name.to_string()))?;
            link.up = false;
            Ok(())
        }

        async fn delete_link(&self, name: &str) -> Result<(), ProviderError> {
            self.links
                .lock()
                .await
                .remove(name)
                .map(|_| ())
                .ok_or_else(|| ProviderError::NotFound(name.to_string()))
        }

        async fn public_key(&self, name: &str) -> Result<Option<WireGuardKey>, ProviderError> {
            Ok(self
                .links
                .lock()
                .await
                .get(name)
                .map(|_| WireGuardKey::parse(VALID_VPN_PUBLIC_KEY, "test").unwrap()))
        }

        async fn is_up(&self, name: &str) -> Result<bool, ProviderError> {
            Ok(self
                .links
                .lock()
                .await
                .get(name)
                .map(|link| link.up)
                .unwrap_or(false))
        }
    }

    impl FakeVpnProvider {
        async fn require_link(&self, name: &str) -> Result<(), ProviderError> {
            if self.links.lock().await.contains_key(name) {
                Ok(())
            } else {
                Err(ProviderError::NotFound(name.to_string()))
            }
        }
    }

    fn fake_vpn_manager() -> (Arc<ProductionVpnManager>, tempfile::TempDir) {
        let dir = tempdir().expect("tempdir");
        let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
        let active_profile_store = ActiveProfileStore::new(dir.path().join("active-profile.json"));
        let provider: Arc<dyn VpnProvider> = Arc::new(FakeVpnProvider::default());
        let driver = WireGuardVpnDriver::new(provider, store);
        (Arc::new(VpnManager::new(driver, active_profile_store)), dir)
    }

    fn vpn_policy_startup_config() -> AppConfig {
        let mut config = AppConfig::default();
        config.network.interfaces.insert(
            "wan0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Input,
                managed: false,
                ipv4: None,
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
            },
        );
        config.network.interfaces.insert(
            "lan0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Output,
                managed: true,
                ipv4: Some("192.168.10.1/24".parse().expect("network")),
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
            },
        );
        config.router = RouterConfig {
            enabled: true,
            uplink: Some(UplinkConfig {
                interface: "wan0".to_string(),
                mode: UplinkMode::External,
            }),
            ..RouterConfig::default()
        };
        config.vpn = VpnConfig {
            enabled: true,
            wireguard_config_dir: std::path::PathBuf::from("/var/lib/traffic-masq/vpn/wireguard"),
            policy: Default::default(),
        };
        config
    }

    fn hotplug_reconcile_config() -> AppConfig {
        let mut config = AppConfig::default();
        config.network.interfaces.insert(
            "lan0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Output,
                managed: true,
                ipv4: Some("192.168.77.1/24".parse().expect("network")),
                dhcp: Some(DhcpInterfaceConfig {
                    pool_start: Ipv4Addr::new(192, 168, 77, 100),
                    pool_end: Ipv4Addr::new(192, 168, 77, 120),
                    router: Ipv4Addr::new(192, 168, 77, 1),
                    dns_servers: vec![Ipv4Addr::new(1, 1, 1, 1)],
                    lease_seconds: Some(300),
                }),
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
            },
        );
        config
    }

    #[test]
    fn interface_reapply_detects_link_or_address_drift() {
        let config = hotplug_reconcile_config();
        let desired = config.network.interfaces.get("lan0").expect("lan0 config");
        let interface = crate::netlink::NetworkInterface {
            is_wireless: false,
            index: 7,
            name: "lan0".to_string(),
            is_up: true,
            rx_bytes: 0,
            tx_bytes: 0,
        };

        assert!(!interface_needs_reapply(
            &interface,
            &[Ipv4AddressInfo {
                interface_index: 7,
                address: Ipv4Addr::new(192, 168, 77, 1),
                prefix_len: 24,
                protocol: None,
            }],
            desired,
        ));

        assert!(interface_needs_reapply(
            &crate::netlink::NetworkInterface {
                is_up: false,
                ..interface.clone()
            },
            &[Ipv4AddressInfo {
                interface_index: 7,
                address: Ipv4Addr::new(192, 168, 77, 1),
                prefix_len: 24,
                protocol: None,
            }],
            desired,
        ));

        assert!(interface_needs_reapply(
            &interface,
            &[Ipv4AddressInfo {
                interface_index: 7,
                address: Ipv4Addr::new(192, 168, 88, 1),
                prefix_len: 24,
                protocol: None,
            }],
            desired,
        ));
    }

    #[test]
    fn dhcp_reconcile_disables_missing_interface_and_reconfigures_stale_binding() {
        let config = hotplug_reconcile_config();
        let spec = DhcpServiceSpec::from_interface_config(
            "lan0",
            config.network.interfaces.get("lan0").expect("lan0 config"),
            config.dhcp.default_lease_seconds,
        )
        .expect("spec")
        .expect("dhcp enabled");

        assert_eq!(
            plan_dhcp_reconcile(Some(spec.clone()), Some(spec.clone()), false, false, false),
            DhcpReconcileAction::Disable
        );
        assert_eq!(
            plan_dhcp_reconcile(Some(spec.clone()), Some(spec.clone()), true, true, true),
            DhcpReconcileAction::Configure(spec.clone())
        );
        assert_eq!(
            plan_dhcp_reconcile(Some(spec.clone()), Some(spec.clone()), true, true, false),
            DhcpReconcileAction::Keep
        );
    }

    #[tokio::test]
    async fn runtime_reconcile_reapplies_output_interface_and_restores_dhcp_after_replug() {
        let config = hotplug_reconcile_config();
        let state_dir = tempdir().expect("state dir");
        let overrides = RuntimeOverrideManager::load(state_dir.path(), &config)
            .await
            .expect("overrides");
        let network = Arc::new(FakeNetworkProvider::default());
        network
            .add_interface_with_state("lan0", 7, false, Vec::new())
            .await;
        let dhcp = FakeDhcpReconciler::default();
        let wifi = FakeWifiReconciler::default();

        reconcile_network_runtime_once(
            &config,
            &overrides,
            network.clone(),
            &dhcp,
            Some(&wifi),
            None::<&FakeWifiReconciler>,
            None::<&FakeDhcpClientReconciler>,
            &BTreeSet::new(),
        )
        .await
        .expect("reconcile");

        let interfaces = network.list_interfaces().await.expect("interfaces");
        let lan0 = interfaces
            .into_iter()
            .find(|interface| interface.name == "lan0")
            .expect("lan0 present");
        assert!(lan0.is_up);
        assert_eq!(
            network
                .list_ipv4_addresses("lan0")
                .await
                .expect("addresses"),
            vec![Ipv4AddressInfo {
                interface_index: 7,
                address: Ipv4Addr::new(192, 168, 77, 1),
                prefix_len: 24,
                protocol: None,
            }]
        );
        assert_eq!(dhcp.configure_calls.lock().await.len(), 1);
        assert!(dhcp.disable_calls.lock().await.is_empty());

        assert_eq!(*dhcp.runtime_liveness_checks.lock().await, 1);

        assert_eq!(*wifi.liveness_checks.lock().await, 1);
    }

    #[tokio::test]
    async fn runtime_reconcile_leaves_an_interface_with_an_unconfirmed_change_alone() {
        let config = hotplug_reconcile_config();
        let state_dir = tempdir().expect("state dir");
        let overrides = RuntimeOverrideManager::load(state_dir.path(), &config)
            .await
            .expect("overrides");
        let network = Arc::new(FakeNetworkProvider::default());
        // The state a just-applied, not-yet-committed change leaves behind: the
        // address is gone from the kernel while the override still says the
        // interface is managed and configured.
        network
            .add_interface_with_state("lan0", 7, true, Vec::new())
            .await;
        let dhcp = FakeDhcpReconciler::default();
        let wifi = FakeWifiReconciler::default();

        let pending = BTreeSet::from(["lan0".to_string()]);
        reconcile_network_runtime_once(
            &config,
            &overrides,
            network.clone(),
            &dhcp,
            Some(&wifi),
            None::<&FakeWifiReconciler>,
            None::<&FakeDhcpClientReconciler>,
            &pending,
        )
        .await
        .expect("reconcile");

        assert!(
            network
                .list_ipv4_addresses("lan0")
                .await
                .expect("addresses")
                .is_empty(),
            "reconcile must not undo a change that is still awaiting confirmation"
        );
        assert!(dhcp.configure_calls.lock().await.is_empty());
        assert!(dhcp.disable_calls.lock().await.is_empty());
    }

    #[tokio::test]
    async fn reconcile_skips_wifi_liveness_when_wifi_is_disabled() {
        let config = hotplug_reconcile_config();
        let state_dir = tempdir().expect("state dir");
        let overrides = RuntimeOverrideManager::load(state_dir.path(), &config)
            .await
            .expect("overrides");
        let network = Arc::new(FakeNetworkProvider::default());
        let dhcp = FakeDhcpReconciler::default();

        reconcile_network_runtime_once(
            &config,
            &overrides,
            network,
            &dhcp,
            None::<&FakeWifiReconciler>,
            None::<&FakeWifiReconciler>,
            None::<&FakeDhcpClientReconciler>,
            &BTreeSet::new(),
        )
        .await
        .expect("reconcile");
    }

    #[tokio::test]
    async fn reconcile_checks_the_wifi_client_independently_of_the_access_point() {
        let config = hotplug_reconcile_config();
        let state_dir = tempdir().expect("state dir");
        let overrides = RuntimeOverrideManager::load(state_dir.path(), &config)
            .await
            .expect("overrides");
        let network = Arc::new(FakeNetworkProvider::default());
        let dhcp = FakeDhcpReconciler::default();
        let wifi_client = FakeWifiReconciler::default();

        reconcile_network_runtime_once(
            &config,
            &overrides,
            network,
            &dhcp,
            None::<&FakeWifiReconciler>,
            Some(&wifi_client),
            None::<&FakeDhcpClientReconciler>,
            &BTreeSet::new(),
        )
        .await
        .expect("reconcile");

        assert_eq!(*wifi_client.liveness_checks.lock().await, 1);
    }

    fn dhcp_client_reconcile_config() -> AppConfig {
        let mut config = hotplug_reconcile_config();
        config.network.interfaces.insert(
            "wan0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Input,
                managed: true,
                ipv4: None,
                dhcp: None,
                dhcp_client: Some(crate::config::DhcpClientInterfaceConfig::default()),
                wifi: None,
                wifi_client: None,
            },
        );
        config
    }

    #[tokio::test]
    async fn runtime_reconcile_declares_a_dhcp_client_once_and_stays_stable() {
        let config = dhcp_client_reconcile_config();
        let state_dir = tempdir().expect("state dir");
        let overrides = RuntimeOverrideManager::load(state_dir.path(), &config)
            .await
            .expect("overrides");
        let network = Arc::new(FakeNetworkProvider::default());
        let dynamic = Ipv4AddressInfo {
            interface_index: 9,
            address: Ipv4Addr::new(192, 0, 2, 42),
            prefix_len: 24,
            protocol: None,
        };
        network
            .add_interface_with_state("wan0", 9, true, vec![dynamic.clone()])
            .await;
        let dhcp = FakeDhcpReconciler::default();
        let dhcp_client = FakeDhcpClientReconciler::default();

        for _ in 0..3 {
            reconcile_network_runtime_once(
                &config,
                &overrides,
                network.clone(),
                &dhcp,
                None::<&FakeWifiReconciler>,
                None::<&FakeWifiReconciler>,
                Some(&dhcp_client),
                &BTreeSet::new(),
            )
            .await
            .expect("reconcile");
        }

        assert_eq!(dhcp_client.reconcile_calls.lock().await.len(), 1);
        assert!(dhcp_client.disable_calls.lock().await.is_empty());
        assert_eq!(*dhcp_client.liveness_checks.lock().await, 3);

        assert_eq!(
            network
                .list_ipv4_addresses("wan0")
                .await
                .expect("addresses"),
            vec![dynamic]
        );

        assert!(dhcp
            .configure_calls
            .lock()
            .await
            .iter()
            .all(|spec| spec.interface != "wan0"));
    }

    #[tokio::test]
    async fn managed_wifi_dhcp_tracks_completed_while_wired_stays_ready() {
        let mut config = dhcp_client_reconcile_config();
        let wifi = config.network.interfaces.get_mut("wan0").expect("wan0");
        wifi.wifi_client = Some(crate::config::WifiClientConfig {
            ssid: "upstream".to_string(),
            country_code: None,
            security: crate::config::WifiClientSecurity::Open,
            passphrase_file: None,
        });
        config.network.interfaces.insert(
            "eth0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Input,
                managed: true,
                ipv4: None,
                dhcp: None,
                dhcp_client: Some(crate::config::DhcpClientInterfaceConfig::default()),
                wifi: None,
                wifi_client: None,
            },
        );
        let state_dir = tempdir().expect("state dir");
        let overrides = RuntimeOverrideManager::load(state_dir.path(), &config)
            .await
            .expect("overrides");
        let network = Arc::new(FakeNetworkProvider::default());
        network.add_interface("wan0", 9).await;
        network.add_interface("eth0", 10).await;
        let dhcp = FakeDhcpReconciler::default();
        let wifi_client = FakeWifiReconciler::default();
        wifi_client
            .associations
            .lock()
            .await
            .insert("wan0".to_string(), false);
        let dhcp_client = FakeDhcpClientReconciler::default();

        reconcile_network_runtime_once(
            &config,
            &overrides,
            network.clone(),
            &dhcp,
            None::<&FakeWifiReconciler>,
            Some(&wifi_client),
            Some(&dhcp_client),
            &BTreeSet::new(),
        )
        .await
        .expect("disconnected reconcile");
        assert!(dhcp_client
            .readiness
            .lock()
            .await
            .contains(&("wan0".to_string(), false)));
        assert!(dhcp_client
            .readiness
            .lock()
            .await
            .contains(&("eth0".to_string(), true)));

        wifi_client
            .associations
            .lock()
            .await
            .insert("wan0".to_string(), true);
        reconcile_network_runtime_once(
            &config,
            &overrides,
            network,
            &dhcp,
            None::<&FakeWifiReconciler>,
            Some(&wifi_client),
            Some(&dhcp_client),
            &BTreeSet::new(),
        )
        .await
        .expect("completed reconcile");
        assert_eq!(
            dhcp_client
                .readiness
                .lock()
                .await
                .iter()
                .filter(|(interface, ready)| interface == "wan0" && *ready)
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn runtime_reconcile_disables_a_dhcp_client_whose_intent_was_removed() {
        let config = hotplug_reconcile_config();
        let state_dir = tempdir().expect("state dir");
        let overrides = RuntimeOverrideManager::load(state_dir.path(), &config)
            .await
            .expect("overrides");
        let network = Arc::new(FakeNetworkProvider::default());
        network.add_interface("wan0", 9).await;
        let dhcp = FakeDhcpReconciler::default();
        let dhcp_client = FakeDhcpClientReconciler::default();

        let spec = DhcpClientSpec::from_interface_config(
            "wan0",
            dhcp_client_reconcile_config()
                .network
                .interfaces
                .get("wan0")
                .expect("wan0 config"),
        )
        .expect("spec")
        .expect("dhcp client enabled");
        dhcp_client
            .specs
            .lock()
            .await
            .insert("wan0".to_string(), spec);

        let mut config = config;
        config.network.interfaces.insert(
            "wan0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Input,
                managed: false,
                ipv4: None,
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
            },
        );

        reconcile_network_runtime_once(
            &config,
            &overrides,
            network,
            &dhcp,
            None::<&FakeWifiReconciler>,
            None::<&FakeWifiReconciler>,
            Some(&dhcp_client),
            &BTreeSet::new(),
        )
        .await
        .expect("reconcile");

        assert_eq!(
            dhcp_client.disable_calls.lock().await.as_slice(),
            &["wan0".to_string()]
        );
        assert!(dhcp_client.specs.lock().await.is_empty());
    }

    #[tokio::test]
    async fn runtime_reconcile_disables_stale_dhcp_when_interface_disappears() {
        let config = hotplug_reconcile_config();
        let state_dir = tempdir().expect("state dir");
        let overrides = RuntimeOverrideManager::load(state_dir.path(), &config)
            .await
            .expect("overrides");
        let dhcp = FakeDhcpReconciler::default();
        let spec = DhcpServiceSpec::from_interface_config(
            "lan0",
            config.network.interfaces.get("lan0").expect("lan0 config"),
            config.dhcp.default_lease_seconds,
        )
        .expect("spec")
        .expect("dhcp enabled");
        dhcp.specs.lock().await.insert("lan0".to_string(), spec);
        let network = Arc::new(FakeNetworkProvider::default());

        reconcile_network_runtime_once(
            &config,
            &overrides,
            network,
            &dhcp,
            None::<&HostapdSupervisor>,
            None::<&WifiClientSupervisor>,
            None::<&FakeDhcpClientReconciler>,
            &BTreeSet::new(),
        )
        .await
        .expect("reconcile");

        assert_eq!(
            dhcp.disable_calls.lock().await.as_slice(),
            &["lan0".to_string()]
        );
        assert!(dhcp.specs.lock().await.is_empty());
    }

    fn desired_with_route_and_dataplane() -> RouterDesired {
        let mut config = AppConfig::default();
        config.network.interfaces.insert(
            "wan0".to_string(),
            crate::config::InterfaceConfig {
                role: crate::config::InterfaceRole::Input,
                managed: false,
                ipv4: None,
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
            },
        );
        config.network.interfaces.insert(
            "lan0".to_string(),
            crate::config::InterfaceConfig {
                role: crate::config::InterfaceRole::Output,
                managed: true,
                ipv4: Some("192.168.10.1/24".parse().expect("network")),
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
            },
        );
        config.router = RouterConfig {
            enabled: true,
            uplink: Some(UplinkConfig {
                interface: "wan0".to_string(),
                mode: UplinkMode::External,
            }),
            owned_routes: vec![crate::config::OwnedIpv4RouteConfig {
                destination: "203.0.113.0/24".parse().expect("route"),
                gateway: None,
                output_interface: Some("wan0".to_string()),
                table: 254,
                metric: Some(100),
            }],
            allow_default_route_change: false,
        };
        RouterDesired::from_effective_config(&config).expect("desired")
    }

    #[tokio::test]
    async fn apply_router_dataplane_applies_routes_then_dataplane() {
        let network = Arc::new(FakeNetworkProvider::default());
        network.add_interface("wan0", 1).await;
        network.add_interface("lan0", 2).await;
        let desired = desired_with_route_and_dataplane();

        let state =
            apply_router_dataplane(&desired, network.clone(), FakeDataplaneProvider::default())
                .await
                .expect("apply");

        assert_eq!(network.routes.lock().await.len(), 1);
        assert!(state
            .dataplane
            .snapshot()
            .await
            .expect("snapshot")
            .owned
            .is_some());

        assert!(state.dataplane_snapshot.owned.is_none());
    }

    #[tokio::test]
    async fn dataplane_apply_failure_rolls_back_routes_without_leaving_partial_state() {
        let network = Arc::new(FakeNetworkProvider::default());
        network.add_interface("wan0", 1).await;
        network.add_interface("lan0", 2).await;
        let desired = desired_with_route_and_dataplane();
        let dataplane_provider = FakeDataplaneProvider::default();
        *dataplane_provider.fail_next_apply.lock().await = true;

        let error = apply_router_dataplane(&desired, network.clone(), dataplane_provider)
            .await
            .map(|_| ())
            .expect_err("dataplane apply must fail");
        assert!(format!("{error:#}").contains("injected dataplane apply failure"));
        assert!(network.routes.lock().await.is_empty());
    }

    #[tokio::test]
    async fn rollback_router_dataplane_restores_pre_apply_baseline() {
        let network = Arc::new(FakeNetworkProvider::default());
        network.add_interface("wan0", 1).await;
        network.add_interface("lan0", 2).await;
        let desired = desired_with_route_and_dataplane();

        let state =
            apply_router_dataplane(&desired, network.clone(), FakeDataplaneProvider::default())
                .await
                .expect("apply");
        assert_eq!(network.routes.lock().await.len(), 1);

        rollback_router_dataplane(&state).await;

        assert!(network.routes.lock().await.is_empty());
        assert!(state
            .dataplane
            .snapshot()
            .await
            .expect("snapshot")
            .owned
            .is_none());
    }

    #[test]
    fn vpn_policy_desired_builds_from_managed_output_subnets_and_router_uplink() {
        let config = vpn_policy_startup_config();

        let desired = vpn_policy_desired(&config).expect("desired");

        assert_eq!(desired.vpn_interface, OWNED_INTERFACE_NAME);
        assert_eq!(desired.physical_uplink, "wan0");
        assert_eq!(
            desired.protected_subnets,
            vec!["192.168.10.1/24".parse::<Ipv4Net>().unwrap()]
        );
    }

    #[test]
    fn vpn_policy_desired_is_none_without_router_uplink() {
        let config = AppConfig::default();

        assert!(vpn_policy_desired(&config).is_none());
    }

    #[tokio::test]
    async fn apply_vpn_policy_startup_is_noop_when_vpn_is_disabled() {
        let config = vpn_policy_startup_config();
        let state_dir = tempdir().expect("state dir");
        let overrides = RuntimeOverrideManager::load(state_dir.path(), &config)
            .await
            .expect("overrides");
        let network = Arc::new(FakeNetworkProvider::default());

        let firewall_executor = FakeNftExecutor::with_responses(vec![]);

        apply_vpn_policy_startup(
            &config,
            &overrides,
            network.clone(),
            firewall_executor,
            &None,
        )
        .await;

        assert!(network.rules.lock().await.is_empty());
        assert!(network.routes.lock().await.is_empty());
    }

    #[tokio::test]
    async fn apply_vpn_policy_startup_activates_policy_in_vpn_mode_when_tunnel_is_healthy() {
        let config = vpn_policy_startup_config();
        let state_dir = tempdir().expect("state dir");
        let overrides = RuntimeOverrideManager::load(state_dir.path(), &config)
            .await
            .expect("overrides");
        overrides
            .set_vpn_mode(crate::config::VpnPolicyMode::Vpn)
            .await
            .expect("persist vpn mode");

        let network = Arc::new(FakeNetworkProvider::default());
        network.add_interface(OWNED_INTERFACE_NAME, 42).await;

        let firewall_executor = FakeNftExecutor::with_responses(vec![
            Ok(nft_ruleset(None)),
            Ok(nft_ruleset(None)),
            Ok(Vec::new()),
        ]);
        let (tunnel, _dir) = fake_vpn_manager();
        tunnel
            .import_profile("home.conf", valid_vpn_profile().as_bytes())
            .expect("import");
        tunnel.activate("home.conf").await.expect("tunnel activate");
        let vpn_manager = Some(tunnel);

        apply_vpn_policy_startup(
            &config,
            &overrides,
            network.clone(),
            firewall_executor,
            &vpn_manager,
        )
        .await;

        let rules = network.rules.lock().await;
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].fw_mark, Some(0x5400_0000));
        let routes = network.routes.lock().await;
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].output_interface_index, Some(42));
    }

    #[tokio::test]
    async fn apply_vpn_policy_startup_fails_closed_when_tunnel_is_not_active() {
        let config = vpn_policy_startup_config();
        let state_dir = tempdir().expect("state dir");
        let overrides = RuntimeOverrideManager::load(state_dir.path(), &config)
            .await
            .expect("overrides");
        overrides
            .set_vpn_mode(crate::config::VpnPolicyMode::Vpn)
            .await
            .expect("persist vpn mode");

        let network = Arc::new(FakeNetworkProvider::default());
        network.add_interface(OWNED_INTERFACE_NAME, 42).await;

        let firewall_executor = FakeNftExecutor::with_responses(vec![]);
        let (tunnel, _dir) = fake_vpn_manager();

        let vpn_manager = Some(tunnel);

        apply_vpn_policy_startup(
            &config,
            &overrides,
            network.clone(),
            firewall_executor,
            &vpn_manager,
        )
        .await;

        assert!(network.rules.lock().await.is_empty());
        assert!(network.routes.lock().await.is_empty());
    }

    #[tokio::test]
    async fn apply_vpn_policy_startup_deactivates_leftover_policy_in_direct_mode() {
        let config = vpn_policy_startup_config();
        let state_dir = tempdir().expect("state dir");
        let overrides = RuntimeOverrideManager::load(state_dir.path(), &config)
            .await
            .expect("overrides");

        let network = Arc::new(FakeNetworkProvider::default());
        network.rules.lock().await.push(Ipv4RuleInfo {
            source: None,
            destination: None,
            table: 30_100,
            priority: Some(10_100),
            fw_mark: Some(0x5400_0000),
            fw_mask: Some(0xff00_0000),
            input_interface: None,
            output_interface: None,
        });
        network.routes.lock().await.push(Ipv4RouteInfo {
            destination: "0.0.0.0/0".parse().unwrap(),
            gateway: None,
            output_interface_index: Some(999),
            table: 30_100,
            metric: Some(50),
            protocol: crate::netlink::TRAFFIC_MASQ_ROUTE_PROTOCOL,
            scope: 253,
        });
        let leftover_firewall = crate::firewall::vpn::VpnPolicyFirewallDesired {
            protected_subnets: vec!["192.168.10.0/24".parse().unwrap()],
            vpn_interface: OWNED_INTERFACE_NAME.to_string(),
            physical_uplink: "wan0".to_string(),
        };

        let firewall_executor = FakeNftExecutor::with_responses(vec![
            Ok(nft_ruleset(Some(&leftover_firewall))),
            Ok(Vec::new()),
        ]);
        let (tunnel, _dir) = fake_vpn_manager();
        let vpn_manager = Some(tunnel);

        apply_vpn_policy_startup(
            &config,
            &overrides,
            network.clone(),
            firewall_executor,
            &vpn_manager,
        )
        .await;

        assert!(network.rules.lock().await.is_empty());
        assert!(network.routes.lock().await.is_empty());
    }

    #[tokio::test]
    async fn preflight_accepts_a_runnable_binary() {
        let binary = if std::path::Path::new("/bin/true").exists() {
            "/bin/true"
        } else {
            "/bin/sh"
        };
        preflight_hostapd_binary(Path::new(binary))
            .await
            .expect("a real, executable binary must pass preflight");
    }

    #[tokio::test]
    async fn preflight_reports_a_missing_binary_clearly() {
        let error = preflight_hostapd_binary(Path::new("/definitely/not/a/real/hostapd"))
            .await
            .expect_err("a nonexistent binary must fail preflight");
        let message = format!("{error:#}");
        assert!(message.contains("hostapd"), "{message}");
        assert!(
            message.contains("/definitely/not/a/real/hostapd"),
            "{message}"
        );
    }

    #[tokio::test]
    async fn build_wifi_supervisor_is_none_when_wifi_is_disabled() {
        let mut config = AppConfig::default();
        config.wifi.enabled = false;

        config.wifi.hostapd_binary = std::path::PathBuf::from("/definitely/not/a/real/hostapd");
        let overrides = RuntimeOverrides::default();

        let supervisor = build_wifi_supervisor(&config, &overrides)
            .await
            .expect("disabled wifi must not fail");
        assert!(supervisor.is_none());
    }
}
