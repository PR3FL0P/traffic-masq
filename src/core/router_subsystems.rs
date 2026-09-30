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
            return vec![
                "VPN chain runtime is unavailable while restoring relay routes".to_owned(),
            ];
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
        let network = crate::config::NetworkConfig {
            interfaces: desired
                .interfaces
                .iter()
                .map(|entry| (entry.name.clone(), entry.config.clone()))
                .collect(),
        };
        self.interfaces.validate_wifi_radio_policy(&network)?;
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
            let target = desired_by_interface
                .get(name.as_str())
                .map(|spec| (*spec).clone());
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
            vpn_chain: {
                let previous = self.vpn_active_chain.read().await.clone();
                VpnChainSnapshot {
                    hops: previous.iter().map(|hop| hop.interface.clone()).collect(),
                    previous_hops: previous,
                }
            },
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

    async fn apply_uplink_dhcp_candidate(&self, desired: Option<&DhcpClientSpec>) -> Result<bool> {
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

    async fn rollback_dhcp_clients(
        &self,
        snapshots: &[DhcpClientSnapshot],
        legacy: Option<&DhcpClientSpec>,
    ) -> Result<()> {
        if snapshots.is_empty() {
            self.apply_uplink_dhcp_candidate(legacy).await?;
            return Ok(());
        }
        let runtime = self
            .dhcp_client
            .as_ref()
            .context("DHCP client runtime is unavailable")?;
        let mut errors = Vec::new();
        for snapshot in snapshots {
            if let Err(error) = runtime.restore(snapshot).await {
                errors.push(format!("{}: {error:#}", snapshot.interface));
            }
        }
        anyhow::ensure!(
            errors.is_empty(),
            "DHCP client restoration failed: {}",
            errors.join("; ")
        );
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
                        compensation_errors
                            .push(format!("cleanup hop {}: {cleanup:#}", done.hop_index));
                    }
                }
                for old in torn_down.iter().rev() {
                    if let Err(restore) = self.activate_hop(old).await {
                        compensation_errors
                            .push(format!("restore hop {}: {restore:#}", old.hop_index));
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
mod tests;
