use crate::core::router::DhcpClientSnapshot;
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
use crate::vpn::{ProductionVpnManager, ReconcileOutcome, VpnManager, VpnProvider};
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
    async fn configure(&self, spec: DhcpClientSpec) -> Result<()>;
    async fn disable(&self, interface: &str) -> Result<()>;
    async fn verify_bound_lease(&self, status: &DhcpClientStatus) -> Result<()>;
    async fn restore(&self, snapshot: &DhcpClientSnapshot) -> Result<()> {
        match &snapshot.spec {
            Some(spec) => self.configure(spec.clone()).await,
            None => self.disable(&snapshot.interface).await,
        }
    }
}

#[async_trait]
impl RouterDhcpClientRuntime for DhcpClientSupervisor {
    async fn status(&self, interface: &str) -> Option<DhcpClientStatus> {
        self.status(interface).await
    }

    async fn configure(&self, spec: DhcpClientSpec) -> Result<()> {
        let interface = spec.interface.clone();
        DhcpClientSupervisor::configure(self, spec).await;
        let status = self
            .status(&interface)
            .await
            .ok_or_else(|| anyhow::anyhow!("DHCP client disappeared after configuration"))?;
        if let DhcpClientRunState::Degraded { reason } = status.state {
            bail!("DHCP client failed to start on {interface}: {reason}");
        }
        Ok(())
    }

    async fn disable(&self, interface: &str) -> Result<()> {
        self.disable(interface).await.map(|_| ())
    }

    async fn restore(&self, snapshot: &DhcpClientSnapshot) -> Result<()> {
        let Some(spec) = &snapshot.spec else {
            return self.disable(&snapshot.interface).await.map(|_| ());
        };

        // Router rollback restores DHCP intent, never a snapshotted lease.
        // Wait for a fresh lease before declaring rollback complete so the
        // coordinator does not report success while connectivity is still
        // unresolved.
        DhcpClientSupervisor::configure(self, spec.clone()).await;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let status = self
                .status(&snapshot.interface)
                .await
                .ok_or_else(|| anyhow::anyhow!("DHCP client disappeared during rollback"))?;
            if let Some(lease) = status.lease.as_ref() {
                return DhcpClientSupervisor::verify_bound_lease(self, lease).await;
            }
            if let DhcpClientRunState::Degraded { reason } = status.state {
                bail!(
                    "DHCP client failed to reacquire a lease on {}: {reason}",
                    snapshot.interface
                );
            }
            anyhow::ensure!(
                tokio::time::Instant::now() < deadline,
                "DHCP client did not reacquire a lease on {} during rollback",
                snapshot.interface
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
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

    pub fn with_station_runtime(mut self, stations: Arc<dyn RouterStaRuntime>) -> Self {
        self.stations = Some(stations);
        self
    }

    pub fn with_access_point_runtime(mut self, access_points: Arc<dyn RouterApRuntime>) -> Self {
        self.access_points = Some(access_points);
        self
    }

    pub fn with_wifi_runtimes(
        self,
        stations: Arc<dyn RouterStaRuntime>,
        access_points: Arc<dyn RouterApRuntime>,
    ) -> Self {
        self.with_station_runtime(stations)
            .with_access_point_runtime(access_points)
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

        let mut managers = self.vpn_hop_managers.write().await;
        if let Some(existing) = managers.get(&hop_index) {
            return Ok(existing.clone());
        }
        let driver =
            WireGuardVpnDriver::new(deps.vpn_provider.clone(), deps.wireguard_store.clone());
        let active_profile_store = ActiveProfileStore::for_hop(&deps.state_dir, hop_index);
        let manager = Arc::new(VpnManager::new(driver, active_profile_store));
        managers.insert(hop_index, manager.clone());
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
    async fn restore_relay_route_specs(&self, specs: &[Ipv4RouteSpec]) -> Vec<String> {
        let Ok(deps) = self.require_vpn_chain_deps() else {
            return vec!["VPN chain runtime is unavailable while restoring relay routes".to_owned()];
        };
        let mut failures = Vec::new();
        for spec in specs {
            if let Err(error) = deps.network.add_ipv4_route(spec).await {
                failures.push(error.to_string());
            }
        }
        failures
    }

    async fn relay_route_specs(
        &self,
        hop: &VpnHopDesired,
        own_route: &VpnHopRoutingDesired,
    ) -> Result<(Ipv4RuleSpec, Ipv4RouteSpec)> {
        let deps = self.require_vpn_chain_deps()?;
        let upstream_index = deps
            .network
            .list_interfaces()
            .await
            .context("failed to list interfaces while resolving relay hop route")?
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

        Ok((
            Ipv4RuleSpec {
                source: None,
                destination: None,
                table: hop.reserved.route_table.get(),
                priority: Some(hop.reserved.rule_priority_start.get()),
                fw_mark: Some(hop.reserved.fw_mark.get()),
                fw_mask: Some(hop.reserved.fw_mask.get()),
                input_interface: None,
                output_interface: None,
            },
            Ipv4RouteSpec {
                destination: Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0)
                    .expect("0.0.0.0/0 is always a valid network"),
                gateway: None,
                output_interface_index: Some(upstream_index),
                table: hop.reserved.route_table.get(),
                metric: Some(50),
                protocol: TRAFFIC_MASQ_ROUTE_PROTOCOL,
            },
        ))
    }

    async fn health_relay_route(
        &self,
        hop: &VpnHopDesired,
        own_route: &VpnHopRoutingDesired,
    ) -> Result<()> {
        let deps = self.require_vpn_chain_deps()?;
        let (rule, route) = self.relay_route_specs(hop, own_route).await?;
        let rule_info = crate::netlink::Ipv4RuleInfo {
            source: rule.source,
            destination: rule.destination,
            table: rule.table,
            priority: rule.priority,
            fw_mark: rule.fw_mark,
            fw_mask: rule.fw_mask,
            input_interface: rule.input_interface.clone(),
            output_interface: rule.output_interface.clone(),
        };
        let rules = deps
            .network
            .list_ipv4_rules()
            .await
            .context("failed to inspect relay hop IPv4 rules")?;
        if !rules.iter().any(|current| current == &rule_info) {
            bail!("relay hop {} IPv4 rule is missing", hop.hop_index);
        }
        if rules
            .iter()
            .any(|current| current.priority == rule.priority && current != &rule_info)
        {
            bail!(
                "relay hop {} reserved IPv4 rule priority {:?} is occupied by different state",
                hop.hop_index,
                rule.priority
            );
        }

        let routes = deps
            .network
            .list_ipv4_routes()
            .await
            .context("failed to inspect relay hop IPv4 routes")?;
        let table_routes: Vec<_> = routes
            .iter()
            .filter(|current| current.table == route.table)
            .collect();
        if table_routes.len() != 1 {
            bail!(
                "relay hop {} route table {} drifted: expected one route, found {}",
                hop.hop_index,
                route.table,
                table_routes.len()
            );
        }
        let current = table_routes[0];
        if current.destination != route.destination
            || current.gateway != route.gateway
            || current.output_interface_index != route.output_interface_index
            || current.table != route.table
            || current.metric != route.metric
            || current.protocol != route.protocol
        {
            bail!("relay hop {} route state drifted", hop.hop_index);
        }
        Ok(())
    }

    async fn install_relay_route(
        &self,
        hop: &VpnHopDesired,
        own_route: &VpnHopRoutingDesired,
    ) -> Result<()> {
        let deps = self.require_vpn_chain_deps()?;
        let (rule, route) = self.relay_route_specs(hop, own_route).await?;

        let rule_info = crate::netlink::Ipv4RuleInfo {
            source: rule.source,
            destination: rule.destination,
            table: rule.table,
            priority: rule.priority,
            fw_mark: rule.fw_mark,
            fw_mask: rule.fw_mask,
            input_interface: rule.input_interface.clone(),
            output_interface: rule.output_interface.clone(),
        };
        let existing_rules = deps
            .network
            .list_ipv4_rules()
            .await
            .context("failed to inspect relay hop IPv4 rules")?;
        let rule_exists = existing_rules.iter().any(|current| current == &rule_info);
        if existing_rules
            .iter()
            .any(|current| current.priority == rule.priority && current != &rule_info)
        {
            bail!(
                "relay hop {} reserved IPv4 rule priority {:?} is occupied by different state",
                hop.hop_index,
                rule.priority
            );
        }

        // Inspect all route state before mutating rules. This prevents a
        // transient netlink read failure from leaving a newly-added rule behind.
        let existing_routes = deps
            .network
            .list_ipv4_routes()
            .await
            .context("failed to inspect relay hop IPv4 routes")?;
        let table_routes: Vec<_> = existing_routes
            .iter()
            .filter(|current| current.table == route.table)
            .collect();
        if table_routes
            .iter()
            .any(|current| current.protocol != TRAFFIC_MASQ_ROUTE_PROTOCOL)
        {
            bail!(
                "relay hop {} reserved route table {} contains foreign route state",
                hop.hop_index,
                route.table
            );
        }
        let route_matches = |current: &crate::netlink::Ipv4RouteInfo| {
            current.destination == route.destination
                && current.gateway == route.gateway
                && current.output_interface_index == route.output_interface_index
                && current.table == route.table
                && current.metric == route.metric
                && current.protocol == route.protocol
        };
        let exact_route_exists = table_routes.iter().any(|current| route_matches(current));
        if exact_route_exists && table_routes.len() == 1 {
            if !rule_exists {
                deps.network
                    .add_ipv4_rule(&rule)
                    .await
                    .context("failed to install relay hop IPv4 rule")?;
            }
            return Ok(());
        }

        let mut deleted_specs = Vec::new();
        for current in table_routes {
            if let Err(error) = deps.network.delete_ipv4_route(current).await {
                let restore_failures = self.restore_relay_route_specs(&deleted_specs).await;
                if restore_failures.is_empty() {
                    return Err(error).context("failed to remove stale owned relay hop IPv4 route");
                }
                bail!(
                    "failed to remove stale owned relay hop IPv4 route: {error}; restoring previously removed routes also failed: {}",
                    restore_failures.join("; ")
                );
            }
            deleted_specs.push(Ipv4RouteSpec {
                destination: current.destination,
                gateway: current.gateway,
                output_interface_index: current.output_interface_index,
                table: current.table,
                metric: current.metric,
                protocol: current.protocol,
            });
        }
        if !rule_exists {
            if let Err(error) = deps.network.add_ipv4_rule(&rule).await {
                let restore_failures = self.restore_relay_route_specs(&deleted_specs).await;
                if restore_failures.is_empty() {
                    return Err(error).context("failed to install relay hop IPv4 rule");
                }
                bail!(
                    "failed to install relay hop IPv4 rule: {error}; restoring prior relay routes also failed: {}",
                    restore_failures.join("; ")
                );
            }
        }

        if let Err(error) = deps.network.add_ipv4_route(&route).await {
            let mut cleanup_failures = Vec::new();
            if !rule_exists {
                if let Err(cleanup) = deps.network.delete_ipv4_rule(&rule_info).await {
                    cleanup_failures.push(format!("IPv4 rule: {cleanup}"));
                }
            }
            cleanup_failures.extend(
                self.restore_relay_route_specs(&deleted_specs)
                    .await
                    .into_iter()
                    .map(|failure| format!("prior route: {failure}")),
            );
            if cleanup_failures.is_empty() {
                return Err(error).context("failed to install relay hop IPv4 route");
            }
            bail!(
                "failed to install relay hop IPv4 route: {error}; rollback was incomplete: {}",
                cleanup_failures.join("; ")
            );
        }
        Ok(())
    }

    async fn remove_relay_route(
        &self,
        hop: &VpnHopDesired,
        own_route: &VpnHopRoutingDesired,
    ) -> Result<()> {
        let deps = self.require_vpn_chain_deps()?;
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
        let expected_rule = crate::netlink::Ipv4RuleInfo {
            source: rule.source,
            destination: rule.destination,
            table: rule.table,
            priority: rule.priority,
            fw_mark: rule.fw_mark,
            fw_mask: rule.fw_mask,
            input_interface: rule.input_interface.clone(),
            output_interface: rule.output_interface.clone(),
        };
        let mut errors = Vec::new();
        match deps.network.list_ipv4_rules().await {
            Ok(rules) => {
                for rule_info in rules {
                    if rule_info == expected_rule {
                        if let Err(error) = deps.network.delete_ipv4_rule(&rule_info).await {
                            errors.push(format!("IPv4 rule: {error}"));
                        }
                    }
                }
            }
            Err(error) => errors.push(format!("list IPv4 rules: {error}")),
        }
        match deps.network.list_ipv4_routes().await {
            Ok(routes) => {
                for route_info in routes {
                    if route_info.table == hop.reserved.route_table.get()
                        && route_info.protocol == TRAFFIC_MASQ_ROUTE_PROTOCOL
                    {
                        if let Err(error) = deps.network.delete_ipv4_route(&route_info).await {
                            errors.push(format!("IPv4 route: {error}"));
                        }
                    }
                }
            }
            Err(error) => errors.push(format!("list IPv4 routes: {error}")),
        }
        if errors.is_empty() {
            Ok(())
        } else {
            bail!(
                "failed to remove relay hop {} routing state: {}",
                hop.hop_index,
                errors.join("; ")
            )
        }
    }

    /// Activate a single hop: bring up its WireGuard interface, then apply
    /// the kind-specific routing/policy on top. Rolls back the interface
    /// activation itself if the routing/policy step fails, so a failed hop
    /// never leaves a half-activated tunnel behind.
    async fn activate_hop(&self, hop: &VpnHopDesired) -> Result<()> {
        let tunnel = self.vpn_manager_for_hop(hop.hop_index).await?;
        let newly_activated = match tunnel.reconcile_on(&hop.interface).await? {
            ReconcileOutcome::Absent => {
                tunnel
                    .activate_on(&hop.interface, &hop.profile_name)
                    .await
                    .map_err(|error| {
                        anyhow::anyhow!("failed to activate VPN hop {}: {error}", hop.hop_index)
                    })?;
                true
            }
            ReconcileOutcome::Adopted(record) => {
                if record.profile_name != hop.profile_name {
                    bail!(
                        "VPN hop {} is owned by this daemon but uses profile '{}' instead of '{}'",
                        hop.hop_index,
                        record.profile_name,
                        hop.profile_name
                    );
                }
                false
            }
            ReconcileOutcome::ForeignInterfacePresent => bail!(
                "VPN hop {} interface '{}' exists without a matching ownership proof",
                hop.hop_index,
                hop.interface
            ),
        };

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
            if !newly_activated {
                return Err(error);
            }
            return match tunnel.deactivate_on(&hop.interface).await {
                Ok(()) => Err(error),
                Err(cleanup) => bail!(
                    "failed to configure VPN hop {}: {error:#}; \
                     failed to roll back its tunnel: {cleanup}",
                    hop.hop_index
                ),
            };
        }
        Ok(())
    }

    /// Tear down a single hop: routing/policy first, then the interface.
    /// Every failure is propagated so the outer transaction can retain its
    /// recovery journal instead of reporting a false-success rollback.
    async fn deactivate_hop(&self, hop: &VpnHopDesired) -> Result<()> {
        let mut errors = Vec::new();
        let tunnel = match self.vpn_manager_for_hop(hop.hop_index).await {
            Ok(tunnel) => Some(tunnel),
            Err(error) => {
                errors.push(format!("manager: {error:#}"));
                None
            }
        };

        match &hop.kind {
            VpnHopKind::Relay { own_route } => {
                if let Err(error) = self.remove_relay_route(hop, own_route).await {
                    errors.push(format!("relay routing: {error:#}"));
                }
            }
            VpnHopKind::Exit { policy } => {
                if let Some(tunnel) = tunnel.clone() {
                    match self.vpn_policy_manager_for_hop(hop.reserved, tunnel) {
                        Ok(policy_manager) => {
                            if let Err(error) = policy_manager.deactivate(policy).await {
                                errors.push(format!("policy: {error:#}"));
                            }
                        }
                        Err(error) => errors.push(format!("policy manager: {error:#}")),
                    }
                }
            }
        }

        if let Some(tunnel) = tunnel {
            match tunnel.reconcile_on(&hop.interface).await {
                Ok(ReconcileOutcome::Absent) => {}
                Ok(ReconcileOutcome::Adopted(_)) => {
                    if let Err(error) = tunnel.deactivate_on(&hop.interface).await {
                        errors.push(format!("tunnel: {error}"));
                    }
                }
                Ok(ReconcileOutcome::ForeignInterfacePresent) => errors.push(format!(
                    "tunnel: interface '{}' is still present without matching durable ownership proof",
                    hop.interface
                )),
                Err(error) => errors.push(format!("tunnel ownership check: {error}")),
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            bail!(
                "failed to deactivate VPN hop {}: {}",
                hop.hop_index,
                errors.join("; ")
            )
        }
    }
}

#[async_trait]
impl<P, E> RouterSubsystems for ProductionRouterSubsystems<P, E>
where
    P: RouterDataplaneProvider + Send + Sync,
    E: RouterDataplaneEventSink + Send + Sync,
{
    async fn prepare_recovery(&self, current: &RouterDesired) -> Result<()> {
        if current.vpn_chain.is_empty() {
            return Ok(());
        }
        self.require_vpn_chain_deps()?;

        let mut recovered = Vec::new();
        for hop in &current.vpn_chain {
            let manager = self.vpn_manager_for_hop(hop.hop_index).await?;
            match manager.reconcile_on(&hop.interface).await? {
                ReconcileOutcome::Absent => {}
                ReconcileOutcome::Adopted(record) if record.profile_name == hop.profile_name => {
                    recovered.push(hop.clone());
                }
                ReconcileOutcome::Adopted(record) => {
                    // The link is ours, but it belongs to the pre-transaction
                    // profile. Keep the ownership record in the manager so a
                    // subsequent snapshot rollback can re-use it, but do not
                    // misclassify it as partially-applied candidate state.
                    tracing::warn!(
                        interface = %hop.interface,
                        expected_profile = %hop.profile_name,
                        observed_profile = %record.profile_name,
                        "owned VPN hop belongs to different intent during recovery"
                    );
                }
                ReconcileOutcome::ForeignInterfacePresent => bail!(
                    "cannot recover VPN hop {}: interface '{}' exists without matching durable ownership proof",
                    hop.hop_index,
                    hop.interface
                ),
            }
        }
        // Recovery also runs before live repairs. Preserve known resources
        // until apply/rollback has actually removed them, including hops no
        // longer present in the desired chain or whose links disappeared.
        let mut active = self.vpn_active_chain.write().await;
        for hop in recovered {
            if !active.contains(&hop) {
                active.push(hop);
            }
        }
        Ok(())
    }

    async fn adopt_router_interfaces(&self, desired: &RouterDesired) {
        self.adopt(desired).await;
    }

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
        let names = self.scoped_names(desired).await;
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
        let names = self.scoped_names(desired).await;
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
        let interfaces = self.scoped_names(desired).await;

        let mut plans = Vec::new();
        for name in interfaces {
            let current = self.dhcp.spec(&name).await;
            let target = desired_by_interface.get(name.as_str()).map(|spec| (*spec).clone());
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

        let mut dhcp_clients = Vec::new();
        if let Some(runtime) = &self.dhcp_client {
            for name in &names {
                let status = runtime.status(name).await;
                dhcp_clients.push(DhcpClientSnapshot {
                    interface: name.clone(),
                    spec: status.map(|status| status.spec),
                    lease: None,
                });
            }
        }
        // Retained for deserializing version-1/2 journals; new snapshots use
        // the complete scoped collection, including absent clients.
        let uplink_dhcp = None;

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
            dhcp_clients,
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

    async fn quiesce_uplink_dhcp(&self, desired: Option<&DhcpClientSpec>) -> Result<()> {
        let Some(runtime) = &self.dhcp_client else {
            if desired.is_some() {
                bail!("embedded DHCP client runtime is unavailable");
            }
            return Ok(());
        };
        for name in &self.owned_interfaces().await {
            let current = runtime.status(name).await;
            let keep_running = match (current.as_ref(), desired) {
                (Some(status), Some(spec)) if &spec.interface == name => {
                    &status.spec == spec && matches!(&status.state, DhcpClientRunState::Running)
                }
                _ => false,
            };
            if current.is_some() && !keep_running {
                runtime.disable(name).await?;
            }
        }
        Ok(())
    }

    async fn apply_uplink_dhcp(&self, desired: Option<&DhcpClientSpec>) -> Result<()> {
        self.apply_uplink_dhcp_candidate(desired).await.map(|_| ())
    }

    async fn apply_uplink_dhcp_candidate(
        &self,
        desired: Option<&DhcpClientSpec>,
    ) -> Result<bool> {
        let Some(runtime) = &self.dhcp_client else {
            if desired.is_some() {
                bail!("embedded DHCP client runtime is unavailable");
            }
            return Ok(false);
        };
        let mut changed = false;
        for name in &self.owned_interfaces().await {
            if desired.is_none_or(|spec| &spec.interface != name)
                && runtime.status(name).await.is_some()
            {
                runtime.disable(name).await?;
                changed = true;
            }
        }
        if let Some(spec) = desired {
            let current = runtime.status(&spec.interface).await;
            let needs_configure = current.as_ref().is_none_or(|status| {
                &status.spec != spec || !matches!(&status.state, DhcpClientRunState::Running)
            });
            runtime.configure(spec.clone()).await?;
            changed |= needs_configure;
        }
        Ok(changed)
    }

    async fn rollback_candidate_uplink_dhcp(&self) -> Result<()> {
        let Some(runtime) = &self.dhcp_client else {
            return Ok(());
        };
        let mut errors = Vec::new();
        for name in &self.owned_interfaces().await {
            if runtime.status(name).await.is_some() {
                if let Err(error) = runtime.disable(name).await {
                    errors.push(format!("{name}: {error:#}"));
                }
            }
        }
        anyhow::ensure!(
            errors.is_empty(),
            "candidate DHCP client cleanup failed: {}",
            errors.join("; ")
        );
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
            if snapshot.iter().any(|entry| entry.spec.is_some()) {
                bail!("uplink Wi-Fi runtime is unavailable");
            }
            return Ok(());
        };
        let mut errors = Vec::new();
        for entry in snapshot {
            let result = match &entry.spec {
                Some(spec) => {
                    async {
                        if let Some(ap) = &self.access_points {
                            if ap.status(&entry.interface).await.is_some() {
                                ap.disable(&entry.interface).await?;
                            }
                        }
                        runtime.configure(spec.clone()).await
                    }
                    .await
                }
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
            if snapshot.iter().any(|entry| entry.spec.is_some()) {
                bail!("output Wi-Fi runtime is unavailable");
            }
            return Ok(());
        };
        let mut errors = Vec::new();
        for entry in snapshot {
            let result = match &entry.spec {
                Some(spec) => {
                    async {
                        if let Some(station) = &self.stations {
                            if station.status(&entry.interface).await.is_some() {
                                station.disable(&entry.interface).await?;
                            }
                        }
                        runtime.configure(spec.clone()).await
                    }
                    .await
                }
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

    async fn rollback_dhcp_clients(
        &self, snapshots: &[DhcpClientSnapshot], legacy: Option<&DhcpClientSpec>,
    ) -> Result<()> {
        if snapshots.is_empty() { return self.rollback_uplink_dhcp(legacy).await; }
        let runtime = self.dhcp_client.as_ref().context("DHCP client runtime is unavailable")?;
        let mut errors = Vec::new();
        for snapshot in snapshots {
            if let Err(error) = runtime.restore(snapshot).await {
                errors.push(format!("{}: {error:#}", snapshot.interface));
            }
        }
        anyhow::ensure!(errors.is_empty(), "DHCP client restoration failed: {}", errors.join("; "));
        Ok(())
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
        let running = self.dhcp.running_interfaces().await;
        let unhealthy = self.dhcp.unhealthy_interfaces().await;
        for spec in &desired.dhcp {
            if unhealthy.iter().any(|name| name == &spec.interface) {
                bail!("DHCP service on {} is unhealthy", spec.interface);
            }
            if !running.iter().any(|name| name == &spec.interface) {
                bail!("DHCP service on {} is not running", spec.interface);
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
    /// hops this call just activated and restores removed previous hops. Any
    /// compensation failure is returned to the outer transaction instead of
    /// being hidden.
    async fn apply_vpn_chain(&self, plan: &VpnChainPlan) -> Result<()> {
        let previous = self.vpn_active_chain.read().await.clone();

        if plan.hops.is_empty() {
            let mut errors = Vec::new();
            for hop in previous.iter().rev() {
                if let Err(error) = self.deactivate_hop(hop).await {
                    errors.push(format!("hop {}: {error:#}", hop.hop_index));
                }
            }
            if errors.is_empty() {
                *self.vpn_active_chain.write().await = Vec::new();
                return Ok(());
            }
            bail!("VPN chain teardown was incomplete: {}", errors.join("; "));
        }
        if self.vpn_chain_deps.is_none() {
            bail!("VPN chain runtime is unavailable");
        }

        // While apply is in flight, record every hop that may need cleanup.
        // If apply fails, RouterManager's outer rollback can therefore retry
        // cleanup even when this method's own compensation was incomplete.
        let mut rollback_candidates = previous.clone();
        for hop in &plan.hops {
            if !rollback_candidates.iter().any(|candidate| candidate == hop) {
                rollback_candidates.push(hop.clone());
            }
        }
        *self.vpn_active_chain.write().await = rollback_candidates;

        let mut torn_down: Vec<&VpnHopDesired> = Vec::new();
        for hop in previous.iter().rev() {
            let unchanged = plan
                .hops
                .iter()
                .find(|desired| desired.interface == hop.interface)
                .is_some_and(|desired| desired == hop);
            if !unchanged {
                self.deactivate_hop(hop).await.with_context(|| {
                    format!("failed to tear down replaced VPN hop {}", hop.hop_index)
                })?;
                torn_down.push(hop);
            }
        }

        let mut applied: Vec<&VpnHopDesired> = Vec::new();
        for hop in &plan.hops {
            if let Err(error) = self.activate_hop(hop).await {
                let mut compensation_errors = Vec::new();
                for done in applied.into_iter().rev() {
                    if let Err(cleanup) = self.deactivate_hop(done).await {
                        compensation_errors.push(format!(
                            "cleanup hop {}: {cleanup:#}",
                            done.hop_index
                        ));
                    }
                }
                for old in torn_down.iter().rev() {
                    if let Err(restore) = self.activate_hop(old).await {
                        compensation_errors.push(format!(
                            "restore hop {}: {restore:#}",
                            old.hop_index
                        ));
                    }
                }
                if compensation_errors.is_empty() {
                    // Keep the conservative rollback-candidate set until the
                    // outer RouterManager rollback verifies every resource is
                    // gone/restored. The failed hop itself may have returned an
                    // error because its *inner* cleanup was incomplete.
                    return Err(error);
                }
                bail!(
                    "failed to activate VPN hop {}: {error:#}; compensation failures: {}",
                    hop.hop_index,
                    compensation_errors.join("; ")
                );
            }
            applied.push(hop);
        }

        *self.vpn_active_chain.write().await = plan.hops.clone();
        Ok(())
    }

    async fn rollback_vpn_chain(&self, snapshot: &VpnChainSnapshot) -> Result<()> {
        let current = self.vpn_active_chain.read().await.clone();
        let mut errors = Vec::new();

        for hop in current.iter().rev() {
            if let Err(error) = self.deactivate_hop(hop).await {
                errors.push(format!("deactivate hop {}: {error:#}", hop.hop_index));
            }
        }

        for hop in &snapshot.previous_hops {
            if let Err(error) = self.activate_hop(hop).await {
                errors.push(format!("restore hop {}: {error:#}", hop.hop_index));
            }
        }

        if errors.is_empty() {
            *self.vpn_active_chain.write().await = snapshot.previous_hops.clone();
            Ok(())
        } else {
            // Preserve a superset of potentially-live hops so a later repair
            // attempt does not forget resources whose teardown failed.
            let mut candidates = current;
            for hop in &snapshot.previous_hops {
                if !candidates.iter().any(|candidate| candidate == hop) {
                    candidates.push(hop.clone());
                }
            }
            *self.vpn_active_chain.write().await = candidates;
            bail!("VPN chain rollback was incomplete: {}", errors.join("; "))
        }
    }

    async fn health_vpn_chain(&self, desired: &RouterDesired) -> Result<()> {
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
            match &expected.kind {
                VpnHopKind::Relay { own_route } => {
                    self.health_relay_route(expected, own_route).await?;
                }
                VpnHopKind::Exit { policy } => {
                    self.vpn_policy_manager_for_hop(expected.reserved, tunnel)?
                        .health(policy)
                        .await?;
                }
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
    use crate::test_support::FakeNetworkProvider;

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
            forwarding: None,
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
        let provider = Arc::new(FakeNetworkProvider::permissive_addresses());
        provider.add_interface_with_state("wan0", 1, true, Vec::new()).await;
        provider.add_interface_with_state("lan0", 2, false, Vec::new()).await;

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

    #[tokio::test]
    async fn wired_router_snapshot_rolls_back_without_wifi_runtimes() {
        let mut config = enabled_config();
        config.network.interfaces.insert(
            "lan0".to_string(),
            dhcp_less_output_interface("192.168.10.1/24"),
        );
        let (subsystems, _) = subsystems_for(&config).await;
        let desired = RouterDesired::from_effective_config(&config).unwrap();
        let manager = crate::core::router::RouterManager::new(Arc::new(subsystems));
        let snapshot = manager.snapshot_for(&desired).await.unwrap();
        assert!(!snapshot.uplink_wifi.is_empty());
        assert!(!snapshot.output_wifi.is_empty());
        let failures = manager.rollback_to(&snapshot).await;
        assert!(failures.is_empty(), "{failures:?}");
    }

    #[tokio::test]
    async fn wifi_rollback_releases_the_conflicting_radio_role() {
        #[derive(Default)]
        struct Radio {
            ap: Mutex<Option<WifiApSpec>>,
            station: Mutex<Option<WifiClientSpec>>,
        }
        #[async_trait]
        impl RouterApRuntime for Radio {
            async fn status(&self, _: &str) -> Option<(WifiApSpec, bool)> {
                self.ap.lock().await.clone().map(|spec| (spec, true))
            }
            async fn configure(&self, spec: WifiApSpec) -> Result<()> {
                anyhow::ensure!(self.station.lock().await.is_none(), "station owns radio");
                *self.ap.lock().await = Some(spec);
                Ok(())
            }
            async fn disable(&self, _: &str) -> Result<()> {
                *self.ap.lock().await = None;
                Ok(())
            }
        }
        #[async_trait]
        impl RouterStaRuntime for Radio {
            async fn status(&self, _: &str) -> Option<(WifiClientSpec, bool)> {
                self.station.lock().await.clone().map(|spec| (spec, true))
            }
            async fn configure(&self, spec: WifiClientSpec) -> Result<()> {
                anyhow::ensure!(self.ap.lock().await.is_none(), "AP owns radio");
                *self.station.lock().await = Some(spec);
                Ok(())
            }
            async fn disable(&self, _: &str) -> Result<()> {
                *self.station.lock().await = None;
                Ok(())
            }
        }
        let radio = Arc::new(Radio::default());
        let (subsystems, _) = subsystems_for(&enabled_config()).await;
        let subsystems = subsystems.with_wifi_runtimes(radio.clone(), radio.clone());
        let ap = WifiApSpec {
            interface: "wan0".into(),
            ssid: "old-ap".into(),
            country_code: None,
            band: crate::config::WifiBand::Ghz2,
            channel: 1,
            channel_width: crate::config::WifiChannelWidth::Ht20,
            security: crate::config::WifiSecurity::Open,
            hidden: false,
            client_isolation: false,
            max_stations: 32,
            passphrase_file: None,
        };
        let station = WifiClientSpec {
            interface: "wan0".into(),
            ssid: "upstream".into(),
            country_code: None,
            security: crate::config::WifiClientSecurity::Open,
            passphrase_file: None,
        };
        *radio.station.lock().await = Some(station.clone());
        subsystems
            .rollback_output_wifi(&[WifiSnapshot {
                interface: "wan0".into(),
                spec: Some(ap.clone()),
            }])
            .await
            .unwrap();
        assert_eq!(*radio.ap.lock().await, Some(ap));
        assert!(radio.station.lock().await.is_none());

        subsystems
            .rollback_uplink_wifi(&[WifiSnapshot {
                interface: "wan0".into(),
                spec: Some(station.clone()),
            }])
            .await
            .unwrap();
        assert_eq!(*radio.station.lock().await, Some(station));
        assert!(radio.ap.lock().await.is_none());
    }

    #[tokio::test]
    async fn planning_a_runtime_router_is_observational_and_apply_adopts_interfaces() {
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
        assert!(
            subsystems.owned_interfaces().await.is_empty(),
            "snapshotting for a plan preview must not mutate router ownership"
        );

        subsystems.adopt_router_interfaces(&desired).await;
        let owned = subsystems.owned_interfaces().await;
        for entry in &desired.interfaces {
            assert!(
                owned.contains(&entry.name),
                "interface {} should be owned once execution begins",
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
        provider.add_interface_with_state("mgmt0", 3, true, Vec::new()).await;
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
    use std::path::Path;
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
        launch_markers: StdMutex<HashMap<String, String>>,
        fail_create: StdMutex<Option<String>>,
        fail_set_peers: StdMutex<Option<String>>,
        fail_delete: StdMutex<Option<String>>,
    }

    impl FakeChainVpnProvider {
        fn fail_create_link_for(&self, name: &str) {
            *self.fail_create.lock().unwrap() = Some(name.to_string());
        }

        fn fail_set_peers_for(&self, name: &str) {
            *self.fail_set_peers.lock().unwrap() = Some(name.to_string());
        }

        fn fail_delete_link_for(&self, name: &str) {
            *self.fail_delete.lock().unwrap() = Some(name.to_string());
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
            launch_marker: &str,
        ) -> Result<(), ProviderError> {
            if self.fail_create.lock().unwrap().as_deref() == Some(name) {
                return Err(ProviderError::CommandFailed {
                    command: "create_link",
                    status: "1".to_string(),
                    stderr: format!("injected create_link failure for {name}"),
                });
            }
            self.links.lock().unwrap().insert(name.to_string(), false);
            self.launch_markers
                .lock()
                .unwrap()
                .insert(name.to_string(), launch_marker.to_string());
            Ok(())
        }

        async fn delete_link_if_launch_marker(
            &self,
            name: &str,
            launch_marker: &str,
        ) -> Result<bool, ProviderError> {
            let matches = self
                .launch_markers
                .lock()
                .unwrap()
                .get(name)
                .is_some_and(|marker| marker == launch_marker);
            if !matches {
                return Ok(false);
            }
            self.delete_link(name).await?;
            Ok(true)
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
            if self.fail_set_peers.lock().unwrap().as_deref() == Some(name) {
                return Err(ProviderError::CommandFailed {
                    command: "set_peers",
                    status: "1".to_string(),
                    stderr: format!("injected set_peers failure for {name}"),
                });
            }
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
            if self.fail_delete.lock().unwrap().as_deref() == Some(name) {
                return Err(ProviderError::CommandFailed {
                    command: "delete_link",
                    status: "1".to_string(),
                    stderr: format!("injected delete_link failure for {name}"),
                });
            }
            let removed = self.links.lock().unwrap().remove(name);
            self.launch_markers.lock().unwrap().remove(name);
            removed
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

    async fn build_chain_subsystems(
        dir: &Path,
        vpn_provider: Arc<FakeChainVpnProvider>,
        net_provider: Arc<FakeChainNetworkProvider>,
    ) -> ProductionRouterSubsystems<FakeDataplaneProvider> {
        let interfaces = InterfaceManager::new(
            Arc::new(FakeNetworkProvider::permissive_addresses()),
            AddressOwnershipJournal::in_memory(),
        );
        let routes = RouteManager::new(Arc::new(FakeNetworkProvider::permissive_addresses()));
        let dhcp = DhcpSupervisor::start(&AppConfig::default())
            .await
            .expect("dhcp supervisor without any configured interfaces never binds a socket");
        let dataplane = RouterDataplaneManager::new(FakeDataplaneProvider::default());

        let wireguard_store = WireGuardProfileStore::new(dir.join("wireguard"));
        let vpn_provider_erased: Arc<dyn VpnProvider> = vpn_provider;
        ProductionRouterSubsystems::new(interfaces, routes, dhcp, dataplane, Vec::new())
            .with_vpn_chain(VpnChainDeps {
                vpn_provider: vpn_provider_erased,
                wireguard_store,
                state_dir: dir.to_path_buf(),
                network: net_provider,
                nft_executor: Arc::new(FakeNftExecutor::default()),
            })
    }

    async fn chain_subsystems() -> (
        ProductionRouterSubsystems<FakeDataplaneProvider>,
        Arc<FakeChainVpnProvider>,
        Arc<FakeChainNetworkProvider>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let net_provider = Arc::new(FakeChainNetworkProvider::default());
        net_provider.add_interface("wan0", 1).await;

        let vpn_provider = Arc::new(FakeChainVpnProvider::default());
        let wireguard_store = WireGuardProfileStore::new(dir.path().join("wireguard"));
        wireguard_store
            .import(
                &crate::vpn::wireguard::WireGuardDriver,
                "chain.conf",
                valid_wg_config().as_bytes(),
            )
            .expect("import chain profile");
        let subsystems = build_chain_subsystems(dir.path(), vpn_provider.clone(), net_provider.clone()).await;
        (subsystems, vpn_provider, net_provider, dir)
    }

    #[tokio::test]
    async fn apply_vpn_chain_activates_hops_in_order() {
        let (subsystems, vpn_provider, net, _dir) = chain_subsystems().await;
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
        let (subsystems, vpn_provider, net, _dir) = chain_subsystems().await;
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

    #[tokio::test]
    async fn partial_wireguard_activation_removes_the_created_link() {
        let (subsystems, vpn_provider, _net, _dir) = chain_subsystems().await;
        vpn_provider.fail_set_peers_for("tm-wg-0");
        let plan = VpnChainPlan {
            hops: vec![relay_hop(0, "tm-wg-0", "wan0")],
        };

        subsystems
            .apply_vpn_chain(&plan)
            .await
            .expect_err("set_peers failure must propagate");

        assert!(
            !vpn_provider.link_exists("tm-wg-0").await.expect("link"),
            "driver-level compensation must delete a partially-created link"
        );
    }

    #[tokio::test]
    async fn failed_wireguard_cleanup_remains_visible_to_outer_rollback() {
        let (subsystems, vpn_provider, _net, _dir) = chain_subsystems().await;
        vpn_provider.fail_set_peers_for("tm-wg-0");
        vpn_provider.fail_delete_link_for("tm-wg-0");
        let hop = relay_hop(0, "tm-wg-0", "wan0");
        let plan = VpnChainPlan {
            hops: vec![hop.clone()],
        };

        subsystems
            .apply_vpn_chain(&plan)
            .await
            .expect_err("activation cleanup failure must propagate");
        assert!(vpn_provider.link_exists("tm-wg-0").await.expect("link"));

        let recovery = subsystems.snapshot_vpn_chain().await.expect("recovery set");
        assert!(recovery.previous_hops.contains(&hop));
        assert!(
            subsystems
                .rollback_vpn_chain(&VpnChainSnapshot::default())
                .await
                .is_err(),
            "foreign/unproven surviving link must keep rollback in failed state"
        );
    }

    #[tokio::test]
    async fn vpn_chain_health_detects_and_repair_reinstalls_relay_rule() {
        let (subsystems, _vpn_provider, net, _dir) = chain_subsystems().await;
        net.add_interface("tm-wg-0", 2).await;
        let hop = relay_hop(0, "tm-wg-0", "wan0");
        let plan = VpnChainPlan {
            hops: vec![hop.clone()],
        };
        subsystems.apply_vpn_chain(&plan).await.expect("initial apply");
        let mut desired = RouterDesired::from_effective_config(&AppConfig::default()).unwrap();
        desired.vpn_chain = vec![hop];
        net.rules.lock().await.clear();

        assert!(subsystems.health_vpn_chain(&desired).await.is_err());
        subsystems.apply_vpn_chain(&plan).await.expect("repair apply");
        subsystems.health_vpn_chain(&desired).await.expect("healthy after repair");
    }

    #[tokio::test]
    async fn vpn_repair_keeps_obsolete_hops_until_teardown() {
        let (subsystems, vpn_provider, net, _dir) = chain_subsystems().await;
        net.add_interface("tm-wg-0", 2).await;
        let hop = relay_hop(0, "tm-wg-0", "wan0");
        subsystems
            .apply_vpn_chain(&VpnChainPlan { hops: vec![hop.clone()] })
            .await
            .unwrap();
        let desired = RouterDesired::from_effective_config(&AppConfig::default()).unwrap();
        assert!(subsystems.health_vpn_chain(&desired).await.is_err());
        subsystems.prepare_recovery(&desired).await.unwrap();
        assert_eq!(
            subsystems.snapshot_vpn_chain().await.unwrap().previous_hops,
            vec![hop]
        );
        subsystems.apply_vpn_chain(&VpnChainPlan { hops: vec![] }).await.unwrap();
        assert!(!vpn_provider.link_exists("tm-wg-0").await.unwrap());
        assert!(net.rules.lock().await.is_empty());
        assert!(net.routes.lock().await.is_empty());
        subsystems.health_vpn_chain(&desired).await.unwrap();
    }

    #[tokio::test]
    async fn vpn_repair_keeps_hops_outside_the_recovered_desired_chain() {
        let (subsystems, _vpn_provider, net, _dir) = chain_subsystems().await;
        net.add_interface("tm-wg-0", 2).await;
        let first = relay_hop(0, "tm-wg-0", "wan0");
        let second = relay_hop(1, "tm-wg-1", "tm-wg-0");
        let hops = vec![first.clone(), second];
        subsystems.apply_vpn_chain(&VpnChainPlan { hops: hops.clone() }).await.unwrap();
        let mut desired = RouterDesired::from_effective_config(&AppConfig::default()).unwrap();
        desired.vpn_chain = vec![first];
        subsystems.prepare_recovery(&desired).await.unwrap();
        assert_eq!(subsystems.snapshot_vpn_chain().await.unwrap().previous_hops, hops);
    }

    #[tokio::test]
    async fn vpn_chain_restart_readopts_owned_hops_and_apply_is_idempotent() {
        let (subsystems, vpn_provider, net, dir) = chain_subsystems().await;
        net.add_interface("tm-wg-0", 2).await;
        let plan = VpnChainPlan {
            hops: vec![relay_hop(0, "tm-wg-0", "wan0")],
        };
        subsystems.apply_vpn_chain(&plan).await.expect("initial apply");
        drop(subsystems);

        let restarted = build_chain_subsystems(dir.path(), vpn_provider.clone(), net.clone()).await;
        let mut desired = RouterDesired::from_effective_config(&AppConfig::default())
            .expect("disabled desired");
        desired.vpn_chain = plan.hops.clone();

        restarted
            .prepare_recovery(&desired)
            .await
            .expect("re-adopt persisted ownership");
        assert_eq!(
            restarted.snapshot_vpn_chain().await.expect("snapshot").previous_hops,
            plan.hops
        );
        restarted
            .apply_vpn_chain(&plan)
            .await
            .expect("idempotent repair apply");

        assert!(vpn_provider.link_exists("tm-wg-0").await.expect("link"));
        assert_eq!(net.rules.lock().await.len(), 1, "relay rule must not duplicate");
        assert_eq!(net.routes.lock().await.len(), 1, "relay route must not duplicate");
    }

    #[tokio::test]
    async fn vpn_chain_crash_recovery_rolls_candidate_back_to_snapshot() {
        let (subsystems, vpn_provider, net, dir) = chain_subsystems().await;
        net.add_interface("tm-wg-0", 2).await;
        let old_plan = VpnChainPlan {
            hops: vec![relay_hop(0, "tm-wg-0", "wan0")],
        };
        subsystems.apply_vpn_chain(&old_plan).await.expect("old apply");
        let old_snapshot = subsystems.snapshot_vpn_chain().await.expect("old snapshot");

        let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
        store
            .import(
                &crate::vpn::wireguard::WireGuardDriver,
                "new.conf",
                valid_wg_config().as_bytes(),
            )
            .expect("import replacement profile");
        let mut replacement = relay_hop(0, "tm-wg-0", "wan0");
        replacement.profile_name = "new.conf".to_string();
        let candidate = VpnChainPlan {
            hops: vec![replacement.clone()],
        };
        subsystems
            .apply_vpn_chain(&candidate)
            .await
            .expect("candidate apply");
        drop(subsystems);

        let restarted = build_chain_subsystems(dir.path(), vpn_provider.clone(), net).await;
        let mut candidate_desired = RouterDesired::from_effective_config(&AppConfig::default())
            .expect("disabled desired");
        candidate_desired.vpn_chain = candidate.hops;
        restarted
            .prepare_recovery(&candidate_desired)
            .await
            .expect("recover candidate ownership");
        restarted
            .rollback_vpn_chain(&old_snapshot)
            .await
            .expect("rollback old snapshot");

        let persisted = ActiveProfileStore::for_hop(dir.path(), 0)
            .load()
            .await
            .expect("load active profile")
            .expect("active profile restored");
        assert_eq!(persisted.profile_name, "chain.conf");
        assert!(vpn_provider.link_exists("tm-wg-0").await.expect("link"));
    }
}
