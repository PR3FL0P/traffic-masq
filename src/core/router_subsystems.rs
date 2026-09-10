use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use ipnet::Ipv4Net;

use crate::core::interface::{InterfaceChangePlan, InterfaceManager, InterfaceSnapshot};
use crate::core::route::{RouteManager, RoutePlan, RouteSnapshot};
use crate::core::router::{
    DhcpPlan, RouterDesired, RouterDhcpHealthReason, RouterSubsystems, VpnChainPlan,
    VpnChainSnapshot, WifiPlan, WifiSnapshot,
};
use crate::core::vpn_chain::{VpnHopDesired, VpnHopKind, VpnHopRoutingDesired};
use crate::core::vpn_policy::VpnPolicyReservedIds;
use crate::core::vpn_policy_manager::VpnPolicyManager;
use crate::dhcp::client::{
    DhcpClientLeaseState, DhcpClientRunState, DhcpClientSpec, DhcpClientStatus,
    DhcpClientSupervisor,
};
use crate::dhcp::supervisor::{DhcpServiceSpec, DhcpSupervisor};
use crate::firewall::vpn::VpnPolicyFirewallBackend;
use crate::firewall::{
    NftExecutor, NoopRouterDataplaneEventSink, RouterDataplaneEventSink, RouterDataplaneManager,
    RouterDataplanePlan, RouterDataplaneProvider, RouterDataplaneSnapshot,
};
use crate::netlink::{Ipv4RouteSpec, Ipv4RuleSpec, NetworkProvider, TRAFFIC_MASQ_ROUTE_PROTOCOL};
use crate::vpn::active_profile::ActiveProfileStore;
use crate::vpn::store::WireGuardProfileStore;
use crate::vpn::wireguard::WireGuardVpnDriver;
use crate::vpn::{ProductionVpnManager, VpnManager, VpnProvider};
use crate::wifi::{
    HostapdState, HostapdSupervisor, WifiApSpec, WifiClientSpec, WifiClientSupervisor, WpaState,
};

/// Shared dependencies for constructing the per-hop `VpnManager`/
/// `VpnPolicyManager` instances the VPN hop chain needs. Kept as a single
/// optional bundle (rather than several optional fields) because they are
/// only ever present or absent together: a build/deployment that doesn't
/// wire up VPN chaining at all should fall back to the trait's
/// bail-if-nonempty default behaviour, exactly like `stations`/
/// `access_points` do for the Wi-Fi stages above.
pub struct VpnChainDeps {
    pub vpn_provider: Arc<dyn VpnProvider>,
    pub wireguard_store: WireGuardProfileStore,
    /// Base directory for per-hop `active-profile-<hop_index>.json` files.
    pub state_dir: PathBuf,
    pub network: Arc<dyn NetworkProvider>,
    pub nft_executor: Arc<dyn NftExecutor>,
}

#[async_trait]
pub trait RouterDhcpClientRuntime: Send + Sync {
    async fn status(&self, interface: &str) -> Option<DhcpClientStatus>;
    async fn configure(&self, spec: DhcpClientSpec);
    async fn disable(&self, interface: &str) -> Result<()>;
    async fn verify_bound_lease(&self, status: &DhcpClientStatus) -> Result<()>;
}

#[async_trait]
impl RouterDhcpClientRuntime for DhcpClientSupervisor {
    async fn status(&self, interface: &str) -> Option<DhcpClientStatus> {
        self.status(interface).await
    }

    async fn configure(&self, spec: DhcpClientSpec) {
        self.configure(spec).await;
    }

    async fn disable(&self, interface: &str) -> Result<()> {
        self.disable(interface).await.map(|_| ())
    }

    async fn verify_bound_lease(&self, status: &DhcpClientStatus) -> Result<()> {
        let lease = status
            .lease
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("DHCP client has no lease"))?;
        self.verify_bound_lease(lease).await
    }
}

#[async_trait]
pub trait RouterApRuntime: Send + Sync {
    async fn status(&self, interface: &str) -> Option<(WifiApSpec, bool)>;
    async fn configure(&self, spec: WifiApSpec) -> Result<()>;
    async fn disable(&self, interface: &str) -> Result<()>;
}

#[async_trait]
impl RouterApRuntime for HostapdSupervisor {
    async fn status(&self, interface: &str) -> Option<(WifiApSpec, bool)> {
        HostapdSupervisor::status(self, interface)
            .await
            .map(|status| (status.spec, status.hostapd_state == HostapdState::Enabled))
    }

    async fn configure(&self, spec: WifiApSpec) -> Result<()> {
        HostapdSupervisor::configure(self, spec).await?;
        Ok(())
    }

    async fn disable(&self, interface: &str) -> Result<()> {
        HostapdSupervisor::disable(self, interface).await?;
        Ok(())
    }
}

#[async_trait]
pub trait RouterStaRuntime: Send + Sync {
    async fn status(&self, interface: &str) -> Option<(WifiClientSpec, bool)>;
    async fn configure(&self, spec: WifiClientSpec) -> Result<()>;
    async fn disable(&self, interface: &str) -> Result<()>;
}

#[async_trait]
impl RouterStaRuntime for WifiClientSupervisor {
    async fn status(&self, interface: &str) -> Option<(WifiClientSpec, bool)> {
        WifiClientSupervisor::status(self, interface)
            .await
            .map(|status| (status.spec, status.wpa_state == WpaState::Completed))
    }

    async fn configure(&self, spec: WifiClientSpec) -> Result<()> {
        WifiClientSupervisor::configure(self, spec).await?;
        Ok(())
    }

    async fn disable(&self, interface: &str) -> Result<()> {
        WifiClientSupervisor::disable(self, interface).await?;
        Ok(())
    }
}

pub struct ProductionRouterSubsystems<P, E = NoopRouterDataplaneEventSink>
where
    P: RouterDataplaneProvider,
    E: RouterDataplaneEventSink,
{
    interfaces: InterfaceManager,
    routes: RouteManager,
    dhcp: DhcpSupervisor,
    dataplane: RouterDataplaneManager<P, E>,
    /// Which interfaces a router transaction is allowed to touch.
    ///
    /// In memory on purpose, and not part of the address ownership journal.
    /// This is not a record of a resource that was installed on the machine —
    /// it is the scope of an intent, derived from the committed router intent
    /// every time the daemon starts and narrowed again as the intent changes
    /// (`adopt` / `retain`). Writing it down would create a second, staler copy
    /// of something the overrides already hold durably.
    ///
    /// The addresses these interfaces carry *are* journalled: the router
    /// applies them through the same `InterfaceManager` as everything else.
    router_interfaces: RwLock<Vec<String>>,
    dhcp_client: Option<Arc<dyn RouterDhcpClientRuntime>>,
    access_points: Option<Arc<dyn RouterApRuntime>>,
    stations: Option<Arc<dyn RouterStaRuntime>>,
    vpn_chain_deps: Option<VpnChainDeps>,
    /// Per-hop `VpnManager` instances, built lazily and cached by hop index
    /// so repeated `apply`/`rollback`/`health` calls for the same hop reuse
    /// the same in-memory `owned` map rather than losing track of what is
    /// active every time a new instance would otherwise be constructed.
    vpn_hop_managers: RwLock<BTreeMap<u32, Arc<ProductionVpnManager>>>,
    /// The chain that is believed active right now, in application order.
    /// In-memory on purpose, mirroring `router_interfaces` above: it is the
    /// runtime record of "what this process last successfully applied", not
    /// a second copy of committed config — `RouterConfig.vpn_chain` (the
    /// persisted intent) already lives elsewhere.
    vpn_active_chain: RwLock<Vec<VpnHopDesired>>,
}

impl<P> ProductionRouterSubsystems<P, NoopRouterDataplaneEventSink>
where
    P: RouterDataplaneProvider,
{
    pub fn new(
        interfaces: InterfaceManager,
        routes: RouteManager,
        dhcp: DhcpSupervisor,
        dataplane: RouterDataplaneManager<P, NoopRouterDataplaneEventSink>,
        router_interfaces: Vec<String>,
    ) -> Self {
        Self {
            interfaces,
            routes,
            dhcp,
            dataplane,
            router_interfaces: RwLock::new(router_interfaces),
            dhcp_client: None,
            access_points: None,
            stations: None,
            vpn_chain_deps: None,
            vpn_hop_managers: RwLock::new(BTreeMap::new()),
            vpn_active_chain: RwLock::new(Vec::new()),
        }
    }

    pub fn new_with_dhcp_client(
        interfaces: InterfaceManager,
        routes: RouteManager,
        dhcp: DhcpSupervisor,
        dataplane: RouterDataplaneManager<P, NoopRouterDataplaneEventSink>,
        router_interfaces: Vec<String>,
        dhcp_client: Arc<dyn RouterDhcpClientRuntime>,
    ) -> Self {
        Self {
            interfaces,
            routes,
            dhcp,
            dataplane,
            router_interfaces: RwLock::new(router_interfaces),
            dhcp_client: Some(dhcp_client),
            access_points: None,
            stations: None,
            vpn_chain_deps: None,
            vpn_hop_managers: RwLock::new(BTreeMap::new()),
            vpn_active_chain: RwLock::new(Vec::new()),
        }
    }
}

impl<P, E> ProductionRouterSubsystems<P, E>
where
    P: RouterDataplaneProvider,
    E: RouterDataplaneEventSink,
{
    /// The interfaces this router installation currently owns.
    ///
    /// This follows the committed intent instead of being frozen at
    /// construction: a daemon that started without a router intent owns
    /// nothing, and would otherwise snapshot nothing when one is provisioned —
    /// leaving the change with nothing to roll back to.
    async fn owned_interfaces(&self) -> Vec<String> {
        self.router_interfaces.read().await.clone()
    }

    /// Narrow ownership to exactly `interfaces`.
    ///
    /// The counterpart to [`Self::adopt`]: ownership widens when an intent is
    /// applied and narrows again once it settles, so an interface that has
    /// dropped out of the intent stops being tracked instead of lingering.
    async fn retain(&self, interfaces: &[String]) {
        let mut owned = self.router_interfaces.write().await;
        *owned = interfaces.to_vec();
        owned.sort();
        owned.dedup();
    }

    /// Take ownership of everything an intent is about to touch.
    ///
    /// Called before snapshots are taken, so an interface the new intent
    /// introduces is captured too, not just the ones already owned.
    async fn adopt(&self, desired: &RouterDesired) {
        let mut owned = self.router_interfaces.write().await;
        owned.extend(desired.interfaces.iter().map(|entry| entry.name.clone()));
        owned.sort();
        owned.dedup();
    }

    async fn scoped_names(&self, desired: &RouterDesired) -> Vec<String> {
        let mut names = self.owned_interfaces().await;
        names.extend(desired.interfaces.iter().map(|entry| entry.name.clone()));
        names.sort();
        names.dedup();
        names
    }

    pub fn with_event_sink(
        interfaces: InterfaceManager,
        routes: RouteManager,
        dhcp: DhcpSupervisor,
        dataplane: RouterDataplaneManager<P, E>,
        router_interfaces: Vec<String>,
    ) -> Self {
        Self {
            interfaces,
            routes,
            dhcp,
            dataplane,
            router_interfaces: RwLock::new(router_interfaces),
            dhcp_client: None,
            access_points: None,
            stations: None,
            vpn_chain_deps: None,
            vpn_hop_managers: RwLock::new(BTreeMap::new()),
            vpn_active_chain: RwLock::new(Vec::new()),
        }
    }

    pub fn with_wifi_runtimes(
        mut self,
        stations: Arc<dyn RouterStaRuntime>,
        access_points: Arc<dyn RouterApRuntime>,
    ) -> Self {
        self.stations = Some(stations);
        self.access_points = Some(access_points);
        self
    }

    /// Wire up the VPN hop chain's runtime dependencies. Without this, any
    /// non-empty `RouterDesired.vpn_chain` makes `plan_vpn_chain`/
    /// `apply_vpn_chain` fail with "VPN chain runtime is unavailable",
    /// exactly like `stations`/`access_points` do for the Wi-Fi stages.
    pub fn with_vpn_chain(mut self, deps: VpnChainDeps) -> Self {
        self.vpn_chain_deps = Some(deps);
        self
    }

    fn require_vpn_chain_deps(&self) -> Result<&VpnChainDeps> {
        self.vpn_chain_deps
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("VPN chain runtime is unavailable"))
    }

    /// The per-hop `VpnManager`, built lazily and cached by hop index. Each
    /// hop gets its own `ActiveProfileStore` (`active-profile-<hop_index>.json`)
    /// so multiple hops' persisted ownership records don't clobber each
    /// other the way a single shared store would.
    async fn vpn_manager_for_hop(&self, hop_index: u32) -> Result<Arc<ProductionVpnManager>> {
        let deps = self.require_vpn_chain_deps()?;
        if let Some(existing) = self.vpn_hop_managers.read().await.get(&hop_index) {
            return Ok(existing.clone());
        }
        let driver =
            WireGuardVpnDriver::new(deps.vpn_provider.clone(), deps.wireguard_store.clone());
        let active_profile_store = ActiveProfileStore::for_hop(&deps.state_dir, hop_index);
        let manager = Arc::new(VpnManager::new(driver, active_profile_store));
        self.vpn_hop_managers
            .write()
            .await
            .insert(hop_index, manager.clone());
        Ok(manager)
    }

    /// A `VpnPolicyManager` scoped to `reserved` (the exit hop's per-hop
    /// reserved IDs) rather than the legacy single-hop default. Cheap to
    /// build fresh per call — everything it wraps is an `Arc`/`Clone` handle.
    fn vpn_policy_manager_for_hop(
        &self,
        reserved: VpnPolicyReservedIds,
        tunnel: Arc<ProductionVpnManager>,
    ) -> Result<VpnPolicyManager<WireGuardVpnDriver, Arc<dyn NftExecutor>>> {
        let deps = self.require_vpn_chain_deps()?;
        let firewall = VpnPolicyFirewallBackend::new(deps.nft_executor.clone());
        Ok(VpnPolicyManager::new_with_reserved(
            deps.network.clone(),
            firewall,
            tunnel,
            reserved,
        ))
    }

    /// Route-only setup for a relay hop: send its own outbound tunnel
    /// traffic (selected by `hop.reserved`'s fwmark) through the previous
    /// hop's interface via a dedicated route table.
    ///
    /// LIMITATION: this installs the routing-table half only (fwmark ->
    /// table -> upstream interface). `VpnDriver` has no `wg set <if> fwmark
    /// <mark>` primitive today, so nothing yet tags a relay hop's own
    /// outbound WireGuard UDP with `hop.reserved.fw_mark` — the rule/route
    /// pair installed here is real but currently inert until the driver
    /// trait grows that capability (or an equivalent netlink call is added
    /// directly here). Left in place rather than skipped so the reserved
    /// route table/rule bookkeeping (and its rollback) is exercised end to
    /// end; flagged explicitly rather than silently claimed as complete.
    async fn install_relay_route(
        &self,
        hop: &VpnHopDesired,
        own_route: &VpnHopRoutingDesired,
    ) -> Result<()> {
        let deps = self.require_vpn_chain_deps()?;
        let upstream_index = deps
            .network
            .list_interfaces()
            .await
            .context("failed to list interfaces while installing relay hop route")?
            .into_iter()
            .find(|interface| interface.name == own_route.upstream_interface)
            .map(|interface| interface.index)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "relay hop {} upstream interface {} not found",
                    hop.hop_index,
                    own_route.upstream_interface
                )
            })?;

        let rule = Ipv4RuleSpec {
            source: None,
            destination: None,
            table: hop.reserved.route_table.get(),
            priority: Some(hop.reserved.rule_priority_start.get()),
            fw_mark: Some(hop.reserved.fw_mark.get()),
            fw_mask: Some(hop.reserved.fw_mask.get()),
            input_interface: None,
            output_interface: None,
        };
        let route = Ipv4RouteSpec {
            destination: Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0)
                .expect("0.0.0.0/0 is always a valid network"),
            gateway: None,
            output_interface_index: Some(upstream_index),
            table: hop.reserved.route_table.get(),
            metric: Some(50),
            protocol: TRAFFIC_MASQ_ROUTE_PROTOCOL,
        };

        deps.network
            .add_ipv4_rule(&rule)
            .await
            .context("failed to install relay hop IPv4 rule")?;
        if let Err(error) = deps.network.add_ipv4_route(&route).await {
            let _ = deps
                .network
                .delete_ipv4_rule(&crate::netlink::Ipv4RuleInfo {
                    source: rule.source,
                    destination: rule.destination,
                    table: rule.table,
                    priority: rule.priority,
                    fw_mark: rule.fw_mark,
                    fw_mask: rule.fw_mask,
                    input_interface: rule.input_interface.clone(),
                    output_interface: rule.output_interface.clone(),
                })
                .await;
            return Err(error).context("failed to install relay hop IPv4 route");
        }
        Ok(())
    }

    async fn remove_relay_route(&self, hop: &VpnHopDesired, own_route: &VpnHopRoutingDesired) {
        let Ok(deps) = self.require_vpn_chain_deps() else {
            return;
        };
        let _ = own_route;
        let rule = Ipv4RuleSpec {
            source: None,
            destination: None,
            table: hop.reserved.route_table.get(),
            priority: Some(hop.reserved.rule_priority_start.get()),
            fw_mark: Some(hop.reserved.fw_mark.get()),
            fw_mask: Some(hop.reserved.fw_mask.get()),
            input_interface: None,
            output_interface: None,
        };
        for rule_info in deps.network.list_ipv4_rules().await.unwrap_or_default() {
            if rule_info.table == rule.table
                && rule_info.priority == rule.priority
                && rule_info.fw_mark == rule.fw_mark
            {
                let _ = deps.network.delete_ipv4_rule(&rule_info).await;
            }
        }
        for route_info in deps.network.list_ipv4_routes().await.unwrap_or_default() {
            if route_info.table == hop.reserved.route_table.get() {
                let _ = deps.network.delete_ipv4_route(&route_info).await;
            }
        }
    }

    /// Activate a single hop: bring up its WireGuard interface, then apply
    /// the kind-specific routing/policy on top. Rolls back the interface
    /// activation itself if the routing/policy step fails, so a failed hop
    /// never leaves a half-activated tunnel behind.
    async fn activate_hop(&self, hop: &VpnHopDesired) -> Result<()> {
        let tunnel = self.vpn_manager_for_hop(hop.hop_index).await?;
        tunnel
            .activate_on(&hop.interface, &hop.profile_name)
            .await
            .map_err(|error| {
                anyhow::anyhow!("failed to activate VPN hop {}: {error}", hop.hop_index)
            })?;

        let routing_result = match &hop.kind {
            VpnHopKind::Relay { own_route } => self.install_relay_route(hop, own_route).await,
            VpnHopKind::Exit { policy } => {
                match self.vpn_policy_manager_for_hop(hop.reserved, tunnel.clone()) {
                    Ok(policy_manager) => policy_manager.activate(policy).await.map(|_| ()),
                    Err(error) => Err(error),
                }
            }
        };

        if let Err(error) = routing_result {
            let _ = tunnel.deactivate_on(&hop.interface).await;
            return Err(error);
        }
        Ok(())
    }

    /// Tear down a single hop: routing/policy first, then the interface
    /// itself. Best-effort — used both for normal chain-shrink teardown and
    /// for rolling back a partially-applied chain, where every failure is
    /// already being reported by the caller.
    async fn deactivate_hop(&self, hop: &VpnHopDesired) {
        match &hop.kind {
            VpnHopKind::Relay { own_route } => {
                self.remove_relay_route(hop, own_route).await;
            }
            VpnHopKind::Exit { policy } => {
                if let Ok(tunnel) = self.vpn_manager_for_hop(hop.hop_index).await {
                    if let Ok(policy_manager) =
                        self.vpn_policy_manager_for_hop(hop.reserved, tunnel)
                    {
                        let _ = policy_manager.deactivate(policy).await;
                    }
                }
            }
        }
        if let Ok(tunnel) = self.vpn_manager_for_hop(hop.hop_index).await {
            let _ = tunnel.deactivate_on(&hop.interface).await;
        }
    }
}

#[async_trait]
impl<P, E> RouterSubsystems for ProductionRouterSubsystems<P, E>
where
    P: RouterDataplaneProvider + Send + Sync,
    E: RouterDataplaneEventSink + Send + Sync,
{
    async fn retain_router_interfaces(&self, interfaces: &[String]) {
        self.retain(interfaces).await;
    }

    async fn plan_interfaces(&self, desired: &RouterDesired) -> Result<Vec<InterfaceChangePlan>> {
        let mut plans = Vec::with_capacity(desired.interfaces.len());
        for entry in &desired.interfaces {
            let plan = self
                .interfaces
                .plan_interface(&entry.name, &entry.config, Some(entry.config.role), false)
                .await?;
            plans.push(plan);
        }
        Ok(plans)
    }

    async fn plan_uplink_wifi(
        &self,
        desired: &RouterDesired,
    ) -> Result<Vec<WifiPlan<WifiClientSpec>>> {
        let Some(runtime) = &self.stations else {
            if desired.uplink_wifi.is_some() {
                bail!("uplink Wi-Fi runtime is unavailable");
            }
            return Ok(Vec::new());
        };
        let mut names = self.owned_interfaces().await;
        if let Some(spec) = &desired.uplink_wifi {
            if !names.contains(&spec.interface) {
                names.push(spec.interface.clone());
            }
        }
        names.sort();
        names.dedup();
        let mut plans = Vec::new();
        for name in names {
            let current = runtime.status(&name).await.map(|(spec, _)| spec);
            let target = desired
                .uplink_wifi
                .as_ref()
                .filter(|spec| spec.interface == name)
                .cloned();
            match (current, target) {
                (None, None) => {}
                (None, Some(desired)) => plans.push(WifiPlan::Start { desired }),
                (Some(current), None) => plans.push(WifiPlan::Stop { current }),
                (Some(current), Some(desired)) if current == desired => {
                    plans.push(WifiPlan::Unchanged { current })
                }
                (Some(current), Some(desired)) => {
                    plans.push(WifiPlan::Reconfigure { current, desired })
                }
            }
        }
        Ok(plans)
    }

    async fn plan_output_wifi(&self, desired: &RouterDesired) -> Result<Vec<WifiPlan<WifiApSpec>>> {
        let Some(runtime) = &self.access_points else {
            if !desired.output_wifi.is_empty() {
                bail!("output Wi-Fi runtime is unavailable");
            }
            return Ok(Vec::new());
        };
        let targets: BTreeMap<&str, &WifiApSpec> = desired
            .output_wifi
            .iter()
            .map(|spec| (spec.interface.as_str(), spec))
            .collect();
        let mut names = self.owned_interfaces().await;
        names.extend(targets.keys().map(|name| (*name).to_owned()));
        names.sort();
        names.dedup();
        let mut plans = Vec::new();
        for name in names {
            let current = runtime.status(&name).await.map(|(spec, _)| spec);
            let target = targets.get(name.as_str()).map(|spec| (*spec).clone());
            match (current, target) {
                (None, None) => {}
                (None, Some(desired)) => plans.push(WifiPlan::Start { desired }),
                (Some(current), None) => plans.push(WifiPlan::Stop { current }),
                (Some(current), Some(desired)) if current == desired => {
                    plans.push(WifiPlan::Unchanged { current })
                }
                (Some(current), Some(desired)) => {
                    plans.push(WifiPlan::Reconfigure { current, desired })
                }
            }
        }
        Ok(plans)
    }

    async fn plan_routes(&self, desired: &RouterDesired) -> Result<RoutePlan> {
        self.routes
            .plan(&desired.routes, desired.allow_default_route_change)
            .await
    }

    async fn plan_dhcp(&self, desired: &RouterDesired) -> Result<Vec<DhcpPlan>> {
        let desired_by_interface: BTreeMap<&str, &DhcpServiceSpec> = desired
            .dhcp
            .iter()
            .map(|spec| (spec.interface.as_str(), spec))
            .collect();
        let mut interfaces: Vec<&str> = desired_by_interface.keys().copied().collect();
        let owned = self.owned_interfaces().await;
        for name in &owned {
            if !interfaces.contains(&name.as_str()) {
                interfaces.push(name.as_str());
            }
        }
        interfaces.sort_unstable();

        let mut plans = Vec::new();
        for name in interfaces {
            let current = self.dhcp.spec(name).await;
            let target = desired_by_interface.get(name).map(|spec| (*spec).clone());
            let plan = match (current, target) {
                (None, None) => continue,
                (None, Some(desired)) => DhcpPlan::Start { desired },
                (Some(current), None) => DhcpPlan::Stop { current },
                (Some(current), Some(desired)) if current == desired => {
                    DhcpPlan::Unchanged { current }
                }
                (Some(current), Some(desired)) => DhcpPlan::Reconfigure { current, desired },
            };
            plans.push(plan);
        }
        Ok(plans)
    }

    async fn plan_dataplane(&self, desired: &RouterDesired) -> Result<RouterDataplanePlan> {
        self.dataplane.plan_target(desired.dataplane.clone()).await
    }

    async fn snapshot_interfaces(&self) -> Result<Vec<InterfaceSnapshot>> {
        let owned = self.owned_interfaces().await;
        let mut snapshots = Vec::with_capacity(owned.len());
        for name in &owned {
            match self.interfaces.snapshot_if_present(name).await? {
                Some(snapshot) => snapshots.push(snapshot),
                None => tracing::warn!(
                    interface = %name,
                    "router-owned interface is not present; snapshotting the rest"
                ),
            }
        }
        Ok(snapshots)
    }

    async fn snapshot_uplink_wifi(&self) -> Result<Vec<WifiSnapshot<WifiClientSpec>>> {
        let Some(runtime) = &self.stations else {
            return Ok(Vec::new());
        };
        let owned = self.owned_interfaces().await;
        let mut snapshots = Vec::with_capacity(owned.len());
        for name in &owned {
            snapshots.push(WifiSnapshot {
                interface: name.clone(),
                spec: runtime.status(name).await.map(|(spec, _)| spec),
            });
        }
        Ok(snapshots)
    }

    async fn snapshot_output_wifi(&self) -> Result<Vec<WifiSnapshot<WifiApSpec>>> {
        let Some(runtime) = &self.access_points else {
            return Ok(Vec::new());
        };
        let owned = self.owned_interfaces().await;
        let mut snapshots = Vec::with_capacity(owned.len());
        for name in &owned {
            snapshots.push(WifiSnapshot {
                interface: name.clone(),
                spec: runtime.status(name).await.map(|(spec, _)| spec),
            });
        }
        Ok(snapshots)
    }

    async fn snapshot_routes(&self) -> Result<RouteSnapshot> {
        self.routes.snapshot().await
    }

    async fn snapshot_dhcp(&self) -> Result<Vec<DhcpServiceSpec>> {
        let mut specs = Vec::new();
        for name in &self.owned_interfaces().await {
            if let Some(spec) = self.dhcp.spec(name).await {
                specs.push(spec);
            }
        }
        Ok(specs)
    }

    async fn snapshot_dataplane(&self) -> Result<RouterDataplaneSnapshot> {
        self.dataplane.snapshot().await
    }

    async fn snapshot_uplink_dhcp(&self) -> Result<Option<DhcpClientSpec>> {
        let Some(runtime) = &self.dhcp_client else {
            return Ok(None);
        };
        for name in &self.owned_interfaces().await {
            if let Some(status) = runtime.status(name).await {
                return Ok(Some(status.spec));
            }
        }
        Ok(None)
    }

    async fn snapshot_for(
        &self,
        desired: &RouterDesired,
    ) -> Result<crate::core::router::RouterSnapshot> {
        self.adopt(desired).await;
        let names = self.scoped_names(desired).await;
        let mut interfaces = Vec::with_capacity(names.len());
        for name in &names {
            // An interface that is gone has nothing to restore, so skipping it
            // is the whole of the correct behaviour. Failing instead would let
            // one unplugged adapter block every router transaction — including
            // the one that would remove it from the intent.
            match self.interfaces.snapshot_if_present(name).await? {
                Some(snapshot) => interfaces.push(snapshot),
                None => tracing::warn!(
                    interface = %name,
                    "router-scoped interface is not present; it will not be part of the rollback snapshot"
                ),
            }
        }

        let mut uplink_wifi = Vec::with_capacity(names.len());
        let mut output_wifi = Vec::with_capacity(names.len());
        for name in &names {
            uplink_wifi.push(WifiSnapshot {
                interface: name.clone(),
                spec: match &self.stations {
                    Some(runtime) => runtime.status(name).await.map(|(spec, _)| spec),
                    None => None,
                },
            });
            output_wifi.push(WifiSnapshot {
                interface: name.clone(),
                spec: match &self.access_points {
                    Some(runtime) => runtime.status(name).await.map(|(spec, _)| spec),
                    None => None,
                },
            });
        }

        let uplink_dhcp = match (&self.dhcp_client, desired.uplink_dhcp.as_ref()) {
            (Some(runtime), Some(target)) => {
                runtime.status(&target.interface).await.map(|s| s.spec)
            }
            (Some(runtime), None) => {
                let mut current = None;
                for name in &names {
                    if let Some(status) = runtime.status(name).await {
                        current = Some(status.spec);
                        break;
                    }
                }
                current
            }
            (None, _) => None,
        };

        let mut dhcp = Vec::new();
        let mut dhcp_absent_interfaces = Vec::new();
        for name in &names {
            if let Some(spec) = self.dhcp.spec(name).await {
                dhcp.push(spec);
            } else {
                dhcp_absent_interfaces.push(name.clone());
            }
        }

        Ok(crate::core::router::RouterSnapshot {
            interfaces,
            uplink_wifi,
            uplink_dhcp,
            output_wifi,
            routes: self.routes.snapshot().await?,
            dhcp,
            dhcp_absent_interfaces,
            vpn_chain: self.snapshot_vpn_chain().await?,
            dataplane: self.dataplane.snapshot().await?,
        })
    }

    async fn apply_interfaces(&self, plan: &[InterfaceChangePlan]) -> Result<()> {
        for item in plan {
            self.interfaces.apply_plan(item).await?;
        }
        Ok(())
    }

    async fn apply_uplink_wifi(&self, plan: &[WifiPlan<WifiClientSpec>]) -> Result<()> {
        let Some(runtime) = &self.stations else {
            if !plan.is_empty() {
                bail!("uplink Wi-Fi runtime is unavailable");
            }
            return Ok(());
        };
        for item in plan {
            match item {
                WifiPlan::Start { desired } | WifiPlan::Reconfigure { desired, .. } => {
                    runtime.configure(desired.clone()).await?;
                }
                WifiPlan::Stop { current } => runtime.disable(&current.interface).await?,
                WifiPlan::Unchanged { .. } => {}
            }
        }
        Ok(())
    }

    async fn apply_output_wifi(&self, plan: &[WifiPlan<WifiApSpec>]) -> Result<()> {
        let Some(runtime) = &self.access_points else {
            if !plan.is_empty() {
                bail!("output Wi-Fi runtime is unavailable");
            }
            return Ok(());
        };
        for item in plan {
            match item {
                WifiPlan::Start { desired } | WifiPlan::Reconfigure { desired, .. } => {
                    runtime.configure(desired.clone()).await?;
                }
                WifiPlan::Stop { current } => runtime.disable(&current.interface).await?,
                WifiPlan::Unchanged { .. } => {}
            }
        }
        Ok(())
    }

    async fn apply_routes(&self, plan: &RoutePlan) -> Result<()> {
        self.routes.apply_plan(plan).await
    }

    async fn apply_dhcp(&self, plan: &[DhcpPlan]) -> Result<()> {
        for item in plan {
            match item {
                DhcpPlan::Start { desired } | DhcpPlan::Reconfigure { desired, .. } => {
                    self.dhcp.configure(desired.clone()).await?;
                }
                DhcpPlan::Stop { current } => {
                    self.dhcp.disable(&current.interface).await?;
                }
                DhcpPlan::Unchanged { .. } => {}
            }
        }
        Ok(())
    }

    async fn apply_dataplane(&self, plan: &RouterDataplanePlan) -> Result<()> {
        self.dataplane.apply(plan).await.map(|_| ())
    }

    async fn apply_uplink_dhcp(&self, desired: Option<&DhcpClientSpec>) -> Result<()> {
        let Some(runtime) = &self.dhcp_client else {
            if desired.is_some() {
                bail!("embedded DHCP client runtime is unavailable");
            }
            return Ok(());
        };
        match desired {
            Some(spec) => runtime.configure(spec.clone()).await,
            None => {
                for name in &self.owned_interfaces().await {
                    if runtime.status(name).await.is_some() {
                        runtime.disable(name).await?;
                    }
                }
            }
        }
        Ok(())
    }

    async fn rollback_interfaces(&self, snapshot: &[InterfaceSnapshot]) -> Result<()> {
        let mut errors = Vec::new();
        for entry in snapshot {
            if let Err(error) = self.interfaces.rollback(entry).await {
                errors.push(format!("{}: {error}", entry.name));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            bail!("interface rollback was incomplete: {}", errors.join("; "))
        }
    }

    async fn rollback_uplink_wifi(&self, snapshot: &[WifiSnapshot<WifiClientSpec>]) -> Result<()> {
        let Some(runtime) = &self.stations else {
            if !snapshot.is_empty() {
                bail!("uplink Wi-Fi runtime is unavailable");
            }
            return Ok(());
        };
        let mut errors = Vec::new();
        for entry in snapshot {
            let result = match &entry.spec {
                Some(spec) => runtime.configure(spec.clone()).await,
                None => runtime.disable(&entry.interface).await,
            };
            if let Err(error) = result {
                errors.push(format!("{}: {error}", entry.interface));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            bail!(
                "uplink Wi-Fi rollback was incomplete: {}",
                errors.join("; ")
            )
        }
    }

    async fn rollback_output_wifi(&self, snapshot: &[WifiSnapshot<WifiApSpec>]) -> Result<()> {
        let Some(runtime) = &self.access_points else {
            if !snapshot.is_empty() {
                bail!("output Wi-Fi runtime is unavailable");
            }
            return Ok(());
        };
        let mut errors = Vec::new();
        for entry in snapshot {
            let result = match &entry.spec {
                Some(spec) => runtime.configure(spec.clone()).await,
                None => runtime.disable(&entry.interface).await,
            };
            if let Err(error) = result {
                errors.push(format!("{}: {error}", entry.interface));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            bail!(
                "output Wi-Fi rollback was incomplete: {}",
                errors.join("; ")
            )
        }
    }

    async fn rollback_routes(&self, snapshot: &RouteSnapshot) -> Result<()> {
        self.routes.rollback(snapshot).await
    }

    async fn rollback_dhcp(&self, snapshot: &[DhcpServiceSpec]) -> Result<()> {
        let previous: BTreeMap<&str, &DhcpServiceSpec> = snapshot
            .iter()
            .map(|spec| (spec.interface.as_str(), spec))
            .collect();
        let mut errors = Vec::new();
        for name in &self.owned_interfaces().await {
            let result = match previous.get(name.as_str()) {
                Some(spec) => self.dhcp.configure((*spec).clone()).await,
                None => self.dhcp.disable(name).await.map(|_| ()),
            };
            if let Err(error) = result {
                errors.push(format!("{name}: {error}"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            bail!("DHCP rollback was incomplete: {}", errors.join("; "))
        }
    }

    async fn rollback_dhcp_scoped(
        &self,
        snapshot: &[DhcpServiceSpec],
        previously_absent: &[String],
    ) -> Result<()> {
        let previous: BTreeMap<&str, &DhcpServiceSpec> = snapshot
            .iter()
            .map(|spec| (spec.interface.as_str(), spec))
            .collect();
        let mut names = self.owned_interfaces().await;
        names.extend(snapshot.iter().map(|spec| spec.interface.clone()));
        names.extend(previously_absent.iter().cloned());
        names.sort();
        names.dedup();
        let mut errors = Vec::new();
        for name in names {
            let result = match previous.get(name.as_str()) {
                Some(spec) => self.dhcp.configure((*spec).clone()).await,
                None => self.dhcp.disable(&name).await.map(|_| ()),
            };
            if let Err(error) = result {
                errors.push(format!("{name}: {error}"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            bail!("DHCP rollback was incomplete: {}", errors.join("; "))
        }
    }

    async fn rollback_dataplane(&self, snapshot: &RouterDataplaneSnapshot) -> Result<()> {
        self.dataplane.rollback(snapshot).await
    }

    async fn rollback_uplink_dhcp(&self, snapshot: Option<&DhcpClientSpec>) -> Result<()> {
        self.apply_uplink_dhcp(snapshot).await
    }

    async fn health_interfaces(&self, desired: &RouterDesired) -> Result<()> {
        for entry in &desired.interfaces {
            if !entry.config.managed {
                continue;
            }
            self.interfaces
                .verify_configured_ipv4(&entry.name, &entry.config)
                .await?;
        }
        Ok(())
    }

    async fn health_uplink_wifi(&self, desired: &RouterDesired) -> Result<()> {
        let Some(expected) = &desired.uplink_wifi else {
            return Ok(());
        };
        let runtime = self
            .stations
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("uplink Wi-Fi runtime is unavailable"))?;
        let Some((current, ready)) = runtime.status(&expected.interface).await else {
            bail!("uplink Wi-Fi intent is missing on {}", expected.interface);
        };
        if current != *expected {
            bail!(
                "uplink Wi-Fi intent does not match on {}",
                expected.interface
            );
        }
        if !ready {
            bail!("uplink Wi-Fi is not associated on {}", expected.interface);
        }
        Ok(())
    }

    async fn health_output_wifi(&self, desired: &RouterDesired) -> Result<()> {
        if desired.output_wifi.is_empty() {
            return Ok(());
        }
        let runtime = self
            .access_points
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("output Wi-Fi runtime is unavailable"))?;
        for expected in &desired.output_wifi {
            let Some((current, ready)) = runtime.status(&expected.interface).await else {
                bail!("output Wi-Fi intent is missing on {}", expected.interface);
            };
            if current != *expected {
                bail!(
                    "output Wi-Fi intent does not match on {}",
                    expected.interface
                );
            }
            if !ready {
                bail!("output Wi-Fi is not ready on {}", expected.interface);
            }
        }
        Ok(())
    }

    async fn health_routes(&self, desired: &RouterDesired) -> Result<()> {
        let health = self.routes.health(&desired.routes).await?;
        if health.is_healthy() {
            Ok(())
        } else {
            bail!(
                "router routes drifted from desired state: {:?}",
                health.drift
            )
        }
    }

    async fn health_dhcp(&self, desired: &RouterDesired) -> Result<()> {
        let unhealthy = self.dhcp.unhealthy_interfaces().await;
        for spec in &desired.dhcp {
            if unhealthy.iter().any(|name| name == &spec.interface) {
                bail!("DHCP service on {} is unhealthy", spec.interface);
            }
            let current = self.dhcp.spec(&spec.interface).await;
            if current.as_ref() != Some(spec) {
                bail!(
                    "DHCP service on {} does not match the desired configuration",
                    spec.interface
                );
            }
        }
        Ok(())
    }

    async fn health_uplink_dhcp(&self, desired: &RouterDesired) -> Option<RouterDhcpHealthReason> {
        let expected = desired.uplink_dhcp.as_ref()?;
        let Some(runtime) = &self.dhcp_client else {
            return Some(RouterDhcpHealthReason::IntentMissing {
                interface: expected.interface.clone(),
            });
        };
        let Some(status) = runtime.status(&expected.interface).await else {
            return Some(RouterDhcpHealthReason::IntentMissing {
                interface: expected.interface.clone(),
            });
        };
        if status.spec != *expected {
            return Some(RouterDhcpHealthReason::IntentMismatch {
                interface: expected.interface.clone(),
            });
        }
        match &status.state {
            DhcpClientRunState::WaitingForInterface => {
                return Some(RouterDhcpHealthReason::Waiting {
                    interface: expected.interface.clone(),
                });
            }
            DhcpClientRunState::Degraded { reason } => {
                return Some(RouterDhcpHealthReason::Degraded {
                    interface: expected.interface.clone(),
                    detail: reason.clone(),
                });
            }
            DhcpClientRunState::Running => {}
        }
        let Some(lease) = &status.lease else {
            return Some(RouterDhcpHealthReason::LeaseMissing {
                interface: expected.interface.clone(),
            });
        };
        if lease.state != DhcpClientLeaseState::Bound {
            return Some(RouterDhcpHealthReason::LeaseNotBound {
                interface: expected.interface.clone(),
            });
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if lease.expires_at_unix <= now {
            return Some(RouterDhcpHealthReason::LeaseExpired {
                interface: expected.interface.clone(),
            });
        }
        if let Err(error) = runtime.verify_bound_lease(&status).await {
            return Some(RouterDhcpHealthReason::ObservationMismatch {
                interface: expected.interface.clone(),
                detail: error.to_string(),
            });
        }
        None
    }

    async fn health_dataplane(&self, desired: &RouterDesired) -> Result<()> {
        let health = self.dataplane.health_target(&desired.dataplane).await?;
        if health.is_healthy() {
            Ok(())
        } else {
            bail!(
                "router dataplane drifted from desired state: {:?}",
                health.drift
            )
        }
    }

    async fn plan_vpn_chain(&self, desired: &RouterDesired) -> Result<VpnChainPlan> {
        if !desired.vpn_chain.is_empty() && self.vpn_chain_deps.is_none() {
            bail!("VPN chain runtime is unavailable");
        }
        Ok(VpnChainPlan {
            hops: desired.vpn_chain.clone(),
        })
    }

    async fn snapshot_vpn_chain(&self) -> Result<VpnChainSnapshot> {
        let previous = self.vpn_active_chain.read().await.clone();
        Ok(VpnChainSnapshot {
            hops: previous.iter().map(|hop| hop.interface.clone()).collect(),
            previous_hops: previous,
        })
    }

    /// Activates hops 0..N in order. On any hop's failure, rolls back the
    /// hops this call just activated (N..0) — and best-effort restores
    /// whatever of the previous chain was torn down to make room for the
    /// new one — entirely inside this method, so `RouterManager::apply`
    /// never observes mid-chain partial state; it only ever needs to call
    /// `rollback_vpn_chain` once, against the pre-apply snapshot.
    async fn apply_vpn_chain(&self, plan: &VpnChainPlan) -> Result<()> {
        if plan.hops.is_empty() {
            // Nothing desired: tear down whatever chain is currently active
            // (if any) and stop, regardless of whether chain deps are wired
            // up — an empty desired chain must never require a runtime.
            let previous = self.vpn_active_chain.read().await.clone();
            for hop in previous.iter().rev() {
                self.deactivate_hop(hop).await;
            }
            *self.vpn_active_chain.write().await = Vec::new();
            return Ok(());
        }
        if self.vpn_chain_deps.is_none() {
            bail!("VPN chain runtime is unavailable");
        }

        let previous = self.vpn_active_chain.read().await.clone();
        let desired_interfaces: std::collections::BTreeSet<&str> =
            plan.hops.iter().map(|hop| hop.interface.as_str()).collect();

        // Tear down whatever previously-active hop the new plan no longer
        // wants before activating the new chain, so stale hops never linger
        // alongside the replacement chain.
        let mut torn_down: Vec<&VpnHopDesired> = Vec::new();
        for hop in previous.iter().rev() {
            if !desired_interfaces.contains(hop.interface.as_str()) {
                self.deactivate_hop(hop).await;
                torn_down.push(hop);
            }
        }

        let mut applied: Vec<&VpnHopDesired> = Vec::new();
        for hop in &plan.hops {
            if let Err(error) = self.activate_hop(hop).await {
                for done in applied.into_iter().rev() {
                    self.deactivate_hop(done).await;
                }
                // Best-effort: restore whatever of the previous chain was
                // torn down above, so a failed re-apply doesn't also strand
                // the router with no VPN chain when one was previously
                // healthy. Failures here are not fatal to this method's
                // own error, which already reports the real cause.
                for hop in torn_down.iter().rev() {
                    let _ = self.activate_hop(hop).await;
                }
                return Err(error);
            }
            applied.push(hop);
        }

        *self.vpn_active_chain.write().await = plan.hops.clone();
        Ok(())
    }

    async fn rollback_vpn_chain(&self, snapshot: &VpnChainSnapshot) -> Result<()> {
        let current = self.vpn_active_chain.read().await.clone();
        for hop in current.iter().rev() {
            self.deactivate_hop(hop).await;
        }

        let mut errors = Vec::new();
        for hop in &snapshot.previous_hops {
            if let Err(error) = self.activate_hop(hop).await {
                errors.push(format!("hop {}: {error:#}", hop.hop_index));
            }
        }

        *self.vpn_active_chain.write().await = if errors.is_empty() {
            snapshot.previous_hops.clone()
        } else {
            Vec::new()
        };

        if errors.is_empty() {
            Ok(())
        } else {
            bail!("VPN chain rollback was incomplete: {}", errors.join("; "))
        }
    }

    async fn health_vpn_chain(&self, desired: &RouterDesired) -> Result<()> {
        if desired.vpn_chain.is_empty() {
            return Ok(());
        }
        let active = self.vpn_active_chain.read().await.clone();
        if active.len() != desired.vpn_chain.len() {
            bail!(
                "VPN chain intent does not match: expected {} hops, {} active",
                desired.vpn_chain.len(),
                active.len()
            );
        }
        for (expected, current) in desired.vpn_chain.iter().zip(active.iter()) {
            if expected != current {
                bail!(
                    "VPN chain intent does not match on hop {}",
                    expected.hop_index
                );
            }
            let tunnel = self.vpn_manager_for_hop(expected.hop_index).await?;
            match tunnel.status_on(&expected.interface).await {
                Ok(Some(status)) if status.up => {}
                Ok(Some(_)) => bail!("VPN hop {} is not up", expected.hop_index),
                Ok(None) => bail!("VPN hop {} is missing", expected.hop_index),
                Err(error) => bail!(
                    "VPN hop {} status check failed: {error}",
                    expected.hop_index
                ),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::netlink::AddressOwnership;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use async_trait::async_trait;
    use tokio::sync::Mutex;

    use crate::config::{
        AppConfig, DhcpInterfaceConfig, InterfaceConfig, InterfaceRole, RouterConfig, UplinkConfig,
        UplinkMode,
    };
    use crate::core::ownership::AddressOwnershipJournal;
    use crate::core::router::RouterDesired;
    use crate::firewall::{OwnedFirewallIntegrity, RouterDataplaneDesired};
    use crate::netlink::{
        Ipv4AddressInfo, Ipv4RouteInfo, Ipv4RouteSpec, NetworkInterface, NetworkProvider,
    };

    use super::*;

    #[derive(Debug, Default)]
    struct FakeNetworkProvider {
        interfaces: Mutex<HashMap<String, NetworkInterface>>,
        addresses: Mutex<HashMap<String, Vec<Ipv4AddressInfo>>>,
        routes: Mutex<Vec<Ipv4RouteInfo>>,
        fail_next_add_route: Mutex<bool>,
    }

    impl FakeNetworkProvider {
        async fn add_interface(&self, name: &str, index: u32, is_up: bool) {
            self.interfaces.lock().await.insert(
                name.to_string(),
                NetworkInterface {
                    is_wireless: false,
                    index,
                    name: name.to_string(),
                    is_up,
                    rx_bytes: 0,
                    tx_bytes: 0,
                },
            );
        }
    }

    #[async_trait]
    impl NetworkProvider for FakeNetworkProvider {
        async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
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
            self.interfaces
                .lock()
                .await
                .get_mut(name)
                .ok_or_else(|| anyhow::anyhow!("interface not found: {name}"))?
                .is_up = true;
            Ok(())
        }

        async fn set_link_down(&self, name: &str) -> Result<()> {
            self.interfaces
                .lock()
                .await
                .get_mut(name)
                .ok_or_else(|| anyhow::anyhow!("interface not found: {name}"))?
                .is_up = false;
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
                .map_or(0, |value| value.index);
            self.addresses
                .lock()
                .await
                .entry(interface.to_string())
                .or_default()
                .push(Ipv4AddressInfo {
                    interface_index,
                    address,
                    prefix_len,
                    protocol: ownership.protocol(),
                });
            Ok(())
        }

        async fn delete_ipv4_address(
            &self,
            interface: &str,
            address: Ipv4Addr,
            prefix_len: u8,
        ) -> Result<()> {
            self.addresses
                .lock()
                .await
                .entry(interface.to_string())
                .or_default()
                .retain(|current| current.address != address || current.prefix_len != prefix_len);
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
    }

    struct FakeDataplaneProvider {
        state: Mutex<RouterDataplaneSnapshot>,
    }

    impl Default for FakeDataplaneProvider {
        fn default() -> Self {
            Self {
                state: Mutex::new(RouterDataplaneSnapshot {
                    ipv4_forwarding: false,
                    owned: None,
                    owned_firewall_integrity: OwnedFirewallIntegrity::Intact,
                }),
            }
        }
    }

    #[async_trait]
    impl RouterDataplaneProvider for FakeDataplaneProvider {
        async fn observe(&self) -> Result<RouterDataplaneSnapshot> {
            Ok(self.state.lock().await.clone())
        }

        async fn apply_owned(&self, desired: &RouterDataplaneDesired) -> Result<()> {
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

    fn output_interface(address: &str, pool_start: u8, pool_end: u8) -> InterfaceConfig {
        let ipv4: ipnet::Ipv4Net = address.parse().expect("IPv4 network");
        let octet = ipv4.addr().octets()[2];
        InterfaceConfig {
            nat: true,
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some(ipv4),
            dhcp: Some(DhcpInterfaceConfig {
                pool_start: Ipv4Addr::new(192, 168, octet, pool_start),
                pool_end: Ipv4Addr::new(192, 168, octet, pool_end),
                router: ipv4.addr(),
                dns_servers: Vec::new(),
                lease_seconds: None,
            }),
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        }
    }

    fn enabled_config() -> AppConfig {
        let mut config = AppConfig::default();
        config.network.interfaces.insert(
            "wan0".to_string(),
            InterfaceConfig {
                nat: true,
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
            output_interface("192.168.10.1/24", 100, 150),
        );
        config.router = RouterConfig {
            vpn_chain: Vec::new(),
            enabled: true,
            uplink: Some(UplinkConfig {
                interface: "wan0".to_string(),
                mode: UplinkMode::External,
            }),
            owned_routes: Vec::new(),
            allow_default_route_change: false,
        };
        config
    }

    fn dhcp_less_output_interface(address: &str) -> InterfaceConfig {
        InterfaceConfig {
            nat: true,
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some(address.parse().expect("IPv4 network")),
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        }
    }

    async fn subsystems_for(
        network_config: &AppConfig,
    ) -> (
        ProductionRouterSubsystems<FakeDataplaneProvider>,
        Arc<FakeNetworkProvider>,
    ) {
        let provider = Arc::new(FakeNetworkProvider::default());
        provider.add_interface("wan0", 1, true).await;
        provider.add_interface("lan0", 2, false).await;

        let interfaces =
            InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory());
        let routes = RouteManager::new(provider.clone());
        let dhcp = DhcpSupervisor::start(&AppConfig::default())
            .await
            .expect("dhcp supervisor without any configured interfaces never binds a socket");
        let dataplane = RouterDataplaneManager::new(FakeDataplaneProvider::default());
        let subsystems = ProductionRouterSubsystems::new(
            interfaces,
            routes,
            dhcp,
            dataplane,
            vec!["wan0".to_string(), "lan0".to_string()],
        );
        let _ = network_config;
        (subsystems, provider)
    }

    /// A daemon that started without a router intent owns no interfaces. Taking
    /// ownership has to happen when the intent arrives, otherwise the router
    /// could never be provisioned at runtime with anything to roll back to.
    #[tokio::test]
    async fn a_router_provisioned_at_runtime_takes_ownership_of_its_interfaces() {
        let mut config = enabled_config();
        config.network.interfaces.insert(
            "lan0".to_string(),
            dhcp_less_output_interface("192.168.10.1/24"),
        );
        let (mut subsystems, provider) = subsystems_for(&config).await;
        // Start from "router disabled at boot": nothing is owned yet.
        subsystems.router_interfaces = RwLock::new(Vec::new());
        let _ = &provider;
        assert!(subsystems.owned_interfaces().await.is_empty());

        let desired = RouterDesired::from_effective_config(&config).expect("desired");
        let snapshot = subsystems.snapshot_for(&desired).await.expect("snapshot");

        assert!(
            !snapshot.interfaces.is_empty(),
            "a runtime-provisioned router must capture the interfaces it is about to touch"
        );
        let owned = subsystems.owned_interfaces().await;
        for entry in &desired.interfaces {
            assert!(
                owned.contains(&entry.name),
                "interface {} should be owned after the intent was snapshotted",
                entry.name
            );
        }
    }

    /// Ownership widens when an intent is applied and narrows when it settles,
    /// so it tracks the intent in force rather than every intent that ever was.
    #[tokio::test]
    async fn ownership_narrows_to_the_intent_that_settled() {
        let mut config = enabled_config();
        config.network.interfaces.insert(
            "lan0".to_string(),
            dhcp_less_output_interface("192.168.10.1/24"),
        );
        let (mut subsystems, _provider) = subsystems_for(&config).await;
        subsystems.router_interfaces = RwLock::new(vec!["old0".to_string(), "wan0".to_string()]);

        let desired = RouterDesired::from_effective_config(&config).expect("desired");
        subsystems.snapshot_for(&desired).await.expect("snapshot");

        // While the transaction is in flight the old interface is still owned,
        // because a rollback may still need to restore it.
        assert!(subsystems
            .owned_interfaces()
            .await
            .contains(&"old0".to_string()));

        let settled: Vec<String> = desired
            .interfaces
            .iter()
            .map(|entry| entry.name.clone())
            .collect();
        subsystems.retain_router_interfaces(&settled).await;

        // Ownership is kept sorted, so compare as sets rather than sequences.
        let owned = subsystems.owned_interfaces().await;
        let mut expected = settled.clone();
        expected.sort();
        assert_eq!(owned, expected);
        assert!(
            !owned.contains(&"old0".to_string()),
            "an interface the settled intent does not cover must be released"
        );
    }

    /// A removable adapter can vanish at any moment. When it does, it must not
    /// take every router transaction down with it — including the one that
    /// would drop it from the intent.
    #[tokio::test]
    async fn a_vanished_interface_does_not_block_router_transactions() {
        let mut config = enabled_config();
        config.network.interfaces.insert(
            "lan0".to_string(),
            dhcp_less_output_interface("192.168.10.1/24"),
        );
        let (mut subsystems, _provider) = subsystems_for(&config).await;
        // usb0 was part of a previous intent and has since been unplugged: it
        // is still owned, but the kernel knows nothing about it.
        subsystems.router_interfaces = RwLock::new(vec![
            "lan0".to_string(),
            "usb0".to_string(),
            "wan0".to_string(),
        ]);

        let desired = RouterDesired::from_effective_config(&config).expect("desired");

        let snapshot = subsystems
            .snapshot_for(&desired)
            .await
            .expect("a missing interface must not fail the snapshot");
        assert!(
            snapshot.interfaces.iter().any(|entry| entry.name == "wan0"),
            "interfaces that are present must still be captured"
        );
        assert!(
            snapshot.interfaces.iter().all(|entry| entry.name != "usb0"),
            "an absent interface has nothing to restore and must be skipped"
        );

        let owned = subsystems
            .snapshot_interfaces()
            .await
            .expect("snapshot_interfaces must tolerate a missing interface too");
        assert!(owned.iter().all(|entry| entry.name != "usb0"));
    }

    #[tokio::test]
    async fn full_round_trip_applies_interfaces_routes_and_dataplane() {
        let mut config = enabled_config();
        config.network.interfaces.insert(
            "lan0".to_string(),
            dhcp_less_output_interface("192.168.10.1/24"),
        );
        let (subsystems, provider) = subsystems_for(&config).await;
        let desired = RouterDesired::from_effective_config(&config).expect("desired");

        let interface_plan = subsystems
            .plan_interfaces(&desired)
            .await
            .expect("interface plan");
        assert_eq!(interface_plan.len(), 2);
        let route_plan = subsystems.plan_routes(&desired).await.expect("route plan");
        let dhcp_plan = subsystems.plan_dhcp(&desired).await.expect("dhcp plan");
        assert!(dhcp_plan.is_empty());
        let dataplane_plan = subsystems
            .plan_dataplane(&desired)
            .await
            .expect("dataplane plan");

        subsystems
            .apply_interfaces(&interface_plan)
            .await
            .expect("apply interfaces");
        subsystems
            .apply_routes(&route_plan)
            .await
            .expect("apply routes");
        subsystems
            .apply_dhcp(&dhcp_plan)
            .await
            .expect("apply dhcp (no-op)");
        subsystems
            .apply_dataplane(&dataplane_plan)
            .await
            .expect("apply dataplane");

        let addresses = provider
            .list_ipv4_addresses("lan0")
            .await
            .expect("addresses");
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0].address, Ipv4Addr::new(192, 168, 10, 1));

        subsystems
            .health_interfaces(&desired)
            .await
            .expect("interfaces healthy");
        subsystems
            .health_routes(&desired)
            .await
            .expect("routes healthy");
        subsystems
            .health_dhcp(&desired)
            .await
            .expect("dhcp healthy");
        subsystems
            .health_dataplane(&desired)
            .await
            .expect("dataplane healthy");
    }

    #[tokio::test]
    async fn plan_dhcp_reports_start_for_a_newly_desired_interface_without_binding_a_socket() {
        let config = enabled_config();
        let (subsystems, _provider) = subsystems_for(&config).await;
        let desired = RouterDesired::from_effective_config(&config).expect("desired");

        let dhcp_plan = subsystems.plan_dhcp(&desired).await.expect("dhcp plan");
        assert_eq!(dhcp_plan.len(), 1);
        assert!(matches!(
            &dhcp_plan[0],
            DhcpPlan::Start { desired } if desired.interface == "lan0"
        ));
    }

    #[tokio::test]
    async fn apply_interfaces_only_touches_router_scoped_interfaces() {
        let config = enabled_config();
        let (subsystems, provider) = subsystems_for(&config).await;
        provider.add_interface("mgmt0", 3, true).await;
        provider.addresses.lock().await.insert(
            "mgmt0".to_string(),
            vec![Ipv4AddressInfo {
                interface_index: 3,
                address: Ipv4Addr::new(10, 0, 0, 1),
                prefix_len: 24,
                protocol: None,
            }],
        );
        let desired = RouterDesired::from_effective_config(&config).expect("desired");

        let plan = subsystems
            .plan_interfaces(&desired)
            .await
            .expect("interface plan");
        assert!(plan.iter().all(|item| item.interface != "mgmt0"));
        subsystems
            .apply_interfaces(&plan)
            .await
            .expect("apply interfaces");

        let mgmt_addresses = provider
            .list_ipv4_addresses("mgmt0")
            .await
            .expect("addresses");
        assert_eq!(mgmt_addresses.len(), 1);
        assert_eq!(mgmt_addresses[0].address, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[tokio::test]
    async fn a_subsystem_failure_is_not_absorbed_by_a_nested_rollback() {
        let config = enabled_config();
        let (subsystems, provider) = subsystems_for(&config).await;
        *provider.fail_next_add_route.lock().await = true;
        let plan = RoutePlan {
            add: vec![Ipv4RouteSpec {
                destination: "198.51.100.0/24".parse().expect("destination"),
                gateway: None,
                output_interface_index: Some(1),
                table: 254,
                metric: Some(100),
                protocol: crate::netlink::TRAFFIC_MASQ_ROUTE_PROTOCOL,
            }],
            delete: Vec::new(),
        };

        let error = subsystems
            .apply_routes(&plan)
            .await
            .expect_err("provider failure must propagate, not be retried by the adapter");
        assert!(format!("{error:#}").contains("injected route add failure"));
        assert!(provider.routes.lock().await.is_empty());
    }

    #[tokio::test]
    async fn rollback_interfaces_is_best_effort_and_reports_every_failure() {
        let config = enabled_config();
        let (subsystems, _provider) = subsystems_for(&config).await;
        let snapshot = vec![
            InterfaceSnapshot {
                name: "wan0".to_string(),
                was_up: true,
                ipv4_addresses: Vec::new(),
            },
            InterfaceSnapshot {
                name: "missing0".to_string(),
                was_up: true,
                ipv4_addresses: Vec::new(),
            },
        ];

        let error = subsystems
            .rollback_interfaces(&snapshot)
            .await
            .expect_err("unknown interface must fail rollback");
        assert!(error.to_string().contains("missing0"));
        assert!(error.to_string().contains("incomplete"));
    }

    // --- VPN hop chain: `apply_vpn_chain`/`rollback_vpn_chain` -------------
    //
    // These use only `Relay` hops (route-only, no nftables mark/killswitch)
    // rather than mixing in a real `Exit` hop, to avoid needing to also mock
    // the nft nftables nftables round-trip (`FakeNftExecutor`'s exact
    // request/response sequencing) for what is fundamentally a test about
    // hop-activation *ordering*, not about the exit hop's firewall
    // mechanics (which `vpn_policy_manager.rs`'s own tests already cover in
    // detail).

    use crate::core::vpn_chain::{VpnHopDesired, VpnHopKind, VpnHopRoutingDesired};
    use crate::core::vpn_policy::VpnPolicyReservedIds;
    use crate::firewall::vpn::test_support::FakeNftExecutor;
    use crate::netlink::{Ipv4RuleInfo, Ipv4RuleSpec as NetIpv4RuleSpec};
    use crate::vpn::store::WireGuardProfileStore;
    use crate::vpn::wireguard::{WireGuardKey, WireGuardPeerConfig};
    use crate::vpn::{ProviderError, VpnProvider};
    use std::sync::Mutex as StdMutex;

    const VALID_PRIVATE_KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const VALID_PUBLIC_KEY: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

    fn valid_wg_config() -> String {
        format!(
            "[Interface]\n\
             PrivateKey = {VALID_PRIVATE_KEY}\n\
             Address = 10.0.0.2/24\n\
             \n\
             [Peer]\n\
             PublicKey = {VALID_PUBLIC_KEY}\n\
             AllowedIPs = 0.0.0.0/0\n\
             Endpoint = 203.0.113.1:51820\n"
        )
    }

    #[derive(Default)]
    struct FakeChainVpnProvider {
        links: StdMutex<HashMap<String, bool>>,
        fail_create: StdMutex<Option<String>>,
    }

    impl FakeChainVpnProvider {
        fn fail_create_link_for(&self, name: &str) {
            *self.fail_create.lock().unwrap() = Some(name.to_string());
        }
    }

    #[async_trait]
    impl VpnProvider for FakeChainVpnProvider {
        async fn link_exists(&self, name: &str) -> Result<bool, ProviderError> {
            Ok(self.links.lock().unwrap().contains_key(name))
        }

        async fn create_link(
            &self,
            name: &str,
            _private_key: &WireGuardKey,
            _listen_port: Option<u16>,
        ) -> Result<(), ProviderError> {
            if self.fail_create.lock().unwrap().as_deref() == Some(name) {
                return Err(ProviderError::CommandFailed {
                    command: "create_link",
                    status: "1".to_string(),
                    stderr: format!("injected create_link failure for {name}"),
                });
            }
            self.links.lock().unwrap().insert(name.to_string(), false);
            Ok(())
        }

        async fn set_addresses(
            &self,
            name: &str,
            _addresses: &[ipnet::IpNet],
        ) -> Result<(), ProviderError> {
            self.require(name)
        }

        async fn set_peers(
            &self,
            name: &str,
            _peers: &[WireGuardPeerConfig],
        ) -> Result<(), ProviderError> {
            self.require(name)
        }

        async fn set_link_up(&self, name: &str) -> Result<(), ProviderError> {
            let mut links = self.links.lock().unwrap();
            let up = links
                .get_mut(name)
                .ok_or_else(|| ProviderError::NotFound(name.to_string()))?;
            *up = true;
            Ok(())
        }

        async fn set_link_down(&self, name: &str) -> Result<(), ProviderError> {
            let mut links = self.links.lock().unwrap();
            let up = links
                .get_mut(name)
                .ok_or_else(|| ProviderError::NotFound(name.to_string()))?;
            *up = false;
            Ok(())
        }

        async fn delete_link(&self, name: &str) -> Result<(), ProviderError> {
            self.links
                .lock()
                .unwrap()
                .remove(name)
                .map(|_| ())
                .ok_or_else(|| ProviderError::NotFound(name.to_string()))
        }

        async fn public_key(&self, name: &str) -> Result<Option<WireGuardKey>, ProviderError> {
            Ok(self
                .links
                .lock()
                .unwrap()
                .get(name)
                .map(|_| WireGuardKey::parse(VALID_PUBLIC_KEY, "test").unwrap()))
        }

        async fn is_up(&self, name: &str) -> Result<bool, ProviderError> {
            Ok(*self.links.lock().unwrap().get(name).unwrap_or(&false))
        }
    }

    impl FakeChainVpnProvider {
        fn require(&self, name: &str) -> Result<(), ProviderError> {
            if self.links.lock().unwrap().contains_key(name) {
                Ok(())
            } else {
                Err(ProviderError::NotFound(name.to_string()))
            }
        }
    }

    #[derive(Default)]
    struct FakeChainNetworkProvider {
        interfaces: Mutex<HashMap<String, NetworkInterface>>,
        rules: Mutex<Vec<Ipv4RuleInfo>>,
        routes: Mutex<Vec<Ipv4RouteInfo>>,
    }

    impl FakeChainNetworkProvider {
        async fn add_interface(&self, name: &str, index: u32) {
            self.interfaces.lock().await.insert(
                name.to_string(),
                NetworkInterface {
                    is_wireless: false,
                    index,
                    name: name.to_string(),
                    is_up: true,
                    rx_bytes: 0,
                    tx_bytes: 0,
                },
            );
        }
    }

    #[async_trait]
    impl NetworkProvider for FakeChainNetworkProvider {
        async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
            Ok(self.interfaces.lock().await.values().cloned().collect())
        }

        async fn list_ipv4_addresses(&self, _interface: &str) -> Result<Vec<Ipv4AddressInfo>> {
            Ok(Vec::new())
        }

        async fn set_link_up(&self, _name: &str) -> Result<()> {
            Ok(())
        }

        async fn set_link_down(&self, _name: &str) -> Result<()> {
            Ok(())
        }

        async fn add_ipv4_address(
            &self,
            _interface: &str,
            _address: Ipv4Addr,
            _prefix_len: u8,
            _ownership: AddressOwnership,
        ) -> Result<()> {
            Ok(())
        }

        async fn delete_ipv4_address(
            &self,
            _interface: &str,
            _address: Ipv4Addr,
            _prefix_len: u8,
        ) -> Result<()> {
            Ok(())
        }

        async fn list_ipv4_routes(&self) -> Result<Vec<Ipv4RouteInfo>> {
            Ok(self.routes.lock().await.clone())
        }

        async fn add_ipv4_route(&self, route: &Ipv4RouteSpec) -> Result<()> {
            self.routes.lock().await.push(Ipv4RouteInfo {
                destination: route.destination,
                gateway: route.gateway,
                output_interface_index: route.output_interface_index,
                table: route.table,
                metric: route.metric,
                protocol: route.protocol,
                scope: 253,
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

        async fn add_ipv4_rule(&self, rule: &NetIpv4RuleSpec) -> Result<()> {
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

    fn relay_hop(hop_index: u32, interface: &str, upstream: &str) -> VpnHopDesired {
        VpnHopDesired {
            hop_index,
            profile_name: "chain.conf".to_string(),
            interface: interface.to_string(),
            upstream: upstream.to_string(),
            reserved: VpnPolicyReservedIds::for_hop(hop_index).expect("reserved ids"),
            kind: VpnHopKind::Relay {
                own_route: VpnHopRoutingDesired {
                    hop_interface: interface.to_string(),
                    upstream_interface: upstream.to_string(),
                },
            },
        }
    }

    async fn chain_subsystems() -> (
        ProductionRouterSubsystems<FakeDataplaneProvider>,
        Arc<FakeChainVpnProvider>,
        Arc<FakeChainNetworkProvider>,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let net_provider = Arc::new(FakeChainNetworkProvider::default());
        net_provider.add_interface("wan0", 1).await;

        let interfaces = InterfaceManager::new(
            Arc::new(FakeNetworkProvider::default()),
            AddressOwnershipJournal::in_memory(),
        );
        let routes = RouteManager::new(Arc::new(FakeNetworkProvider::default()));
        let dhcp = DhcpSupervisor::start(&AppConfig::default())
            .await
            .expect("dhcp supervisor without any configured interfaces never binds a socket");
        let dataplane = RouterDataplaneManager::new(FakeDataplaneProvider::default());

        let vpn_provider = Arc::new(FakeChainVpnProvider::default());
        let wireguard_store = WireGuardProfileStore::new(dir.path().join("wireguard"));
        wireguard_store
            .import(
                &crate::vpn::wireguard::WireGuardDriver,
                "chain.conf",
                valid_wg_config().as_bytes(),
            )
            .expect("import chain profile");

        let vpn_provider_erased: Arc<dyn VpnProvider> = vpn_provider.clone();
        let subsystems =
            ProductionRouterSubsystems::new(interfaces, routes, dhcp, dataplane, Vec::new())
                .with_vpn_chain(VpnChainDeps {
                    vpn_provider: vpn_provider_erased,
                    wireguard_store,
                    state_dir: dir.path().to_path_buf(),
                    network: net_provider.clone(),
                    nft_executor: Arc::new(FakeNftExecutor::default()),
                });
        std::mem::forget(dir);
        (subsystems, vpn_provider, net_provider)
    }

    #[tokio::test]
    async fn apply_vpn_chain_activates_hops_in_order() {
        let (subsystems, vpn_provider, net) = chain_subsystems().await;
        net.add_interface("tm-wg-0", 2).await;
        net.add_interface("tm-wg-1", 3).await;
        let plan = VpnChainPlan {
            hops: vec![
                relay_hop(0, "tm-wg-0", "wan0"),
                relay_hop(1, "tm-wg-1", "tm-wg-0"),
                relay_hop(2, "tm-wg-2", "tm-wg-1"),
            ],
        };

        subsystems
            .apply_vpn_chain(&plan)
            .await
            .expect("3-hop chain activates");

        for name in ["tm-wg-0", "tm-wg-1", "tm-wg-2"] {
            assert!(
                vpn_provider.link_exists(name).await.expect("link_exists"),
                "{name} should be active after apply_vpn_chain"
            );
        }
    }

    /// If a mid-chain hop fails to activate, every hop this call already
    /// activated must be rolled back — in reverse order — entirely inside
    /// `apply_vpn_chain`, before it returns `Err`.
    #[tokio::test]
    async fn apply_vpn_chain_rolls_back_already_applied_hops_on_mid_chain_failure() {
        let (subsystems, vpn_provider, net) = chain_subsystems().await;
        net.add_interface("tm-wg-0", 2).await;
        net.add_interface("tm-wg-1", 3).await;
        vpn_provider.fail_create_link_for("tm-wg-2");

        let plan = VpnChainPlan {
            hops: vec![
                relay_hop(0, "tm-wg-0", "wan0"),
                relay_hop(1, "tm-wg-1", "tm-wg-0"),
                relay_hop(2, "tm-wg-2", "tm-wg-1"),
            ],
        };

        let error = subsystems
            .apply_vpn_chain(&plan)
            .await
            .expect_err("hop 2's activation failure must propagate");
        assert!(error.to_string().contains("tm-wg-2") || error.to_string().contains("hop"));

        for name in ["tm-wg-0", "tm-wg-1", "tm-wg-2"] {
            assert!(
                !vpn_provider.link_exists(name).await.expect("link_exists"),
                "{name} must have been rolled back after the mid-chain failure"
            );
        }
    }
}
