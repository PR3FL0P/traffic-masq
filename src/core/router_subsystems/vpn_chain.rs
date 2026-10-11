use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use ipnet::Ipv4Net;
use tokio::sync::RwLock;

use crate::core::router::{RouterDesired, VpnChainPlan, VpnChainSnapshot};
use crate::core::vpn_chain::{VpnHopDesired, VpnHopKind, VpnHopRoutingDesired};
use crate::core::vpn_policy::VpnPolicyReservedIds;
use crate::core::vpn_policy_manager::{VpnPolicyDesired, VpnPolicyManager};
use crate::firewall::vpn::VpnPolicyFirewallBackend;
use crate::firewall::NftExecutor;
use crate::netlink::{Ipv4RouteSpec, Ipv4RuleSpec, NetworkProvider, TRAFFIC_MASQ_ROUTE_PROTOCOL};
use crate::vpn::active_profile::ActiveProfileStore;
use crate::vpn::store::WireGuardProfileStore;
use crate::vpn::wireguard::WireGuardVpnDriver;
use crate::vpn::{ProductionVpnManager, ReconcileOutcome, VpnManager, VpnProvider};

/// Shared dependencies for constructing the per-hop `VpnManager`/
/// `VpnPolicyManager` instances the VPN hop chain needs. Kept as a single
/// optional bundle (rather than several optional fields) because they are
/// only ever present or absent together: a build/deployment that doesn't
/// wire up VPN chaining at all should reject a non-empty chain during
/// planning or apply, like the optional Wi-Fi runtimes.
pub struct VpnChainDeps {
    pub vpn_provider: Arc<dyn VpnProvider>,
    pub wireguard_store: WireGuardProfileStore,
    /// Base directory for per-hop `active-profile-<hop_index>.json` files.
    pub state_dir: PathBuf,
    pub network: Arc<dyn NetworkProvider>,
    pub nft_executor: Arc<dyn NftExecutor>,
}

/// VPN chain state and operations shared by full apply, rollback, and drift repair.
pub(super) struct VpnChainRuntime {
    deps: Option<VpnChainDeps>,
    /// Cached managers retain per-hop in-memory ownership across operations.
    vpn_hop_managers: RwLock<BTreeMap<u32, Arc<ProductionVpnManager>>>,
    /// In-memory record of the believed active chain. During a failed apply or
    /// rollback it conservatively includes every hop that may need cleanup;
    /// committed router intent remains the durable source of truth.
    vpn_active_chain: RwLock<Vec<VpnHopDesired>>,
}

impl VpnChainRuntime {
    pub(super) fn new() -> Self {
        Self {
            deps: None,
            vpn_hop_managers: RwLock::new(BTreeMap::new()),
            vpn_active_chain: RwLock::new(Vec::new()),
        }
    }

    pub(super) fn set_deps(&mut self, deps: VpnChainDeps) {
        self.deps = Some(deps);
    }

    fn require_vpn_chain_deps(&self) -> Result<&VpnChainDeps> {
        self.deps
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

    /// Use the kernel's current destinations, never a second DNS answer that
    /// could differ from the address installed at activation (or after roaming).
    pub(super) async fn with_host_endpoints(
        &self,
        policy: &VpnPolicyDesired,
    ) -> Result<VpnPolicyDesired> {
        let mut observed = policy.clone();
        if !policy.route_host_traffic {
            return Ok(observed);
        }
        let deps = self.require_vpn_chain_deps()?;
        let mut endpoints: Vec<Ipv4Addr> = Vec::new();
        for (index, profile) in policy.chain_profiles.iter().enumerate() {
            let interface = crate::vpn::manager::hop_interface_name(index as u32);
            let addresses = deps
                .vpn_provider
                .peer_endpoints(&interface)
                .await
                .with_context(|| {
                    format!("failed to observe endpoints of VPN profile '{profile}' on {interface}")
                })?;
            anyhow::ensure!(
                !addresses.is_empty(),
                "no VPN endpoint is configured on {interface}"
            );
            for address in addresses {
                match address.ip() {
                    std::net::IpAddr::V4(ip) => {
                        if !endpoints.contains(&ip) { endpoints.push(ip); }
                    }
                    std::net::IpAddr::V6(ip) => bail!(
                        "VPN profile '{profile}' endpoint {ip} is IPv6; routing router traffic through the VPN supports IPv4 endpoints only"
                    ),
                }
            }
        }
        anyhow::ensure!(
            !endpoints.is_empty(),
            "no VPN endpoint could be determined for routing router traffic"
        );
        endpoints.sort();
        observed.host_endpoints = endpoints;
        Ok(observed)
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
                    Ok(policy_manager) => match self.with_host_endpoints(policy).await {
                        Ok(policy) => policy_manager.activate(&policy).await.map(|_| ()),
                        Err(error) => Err(error),
                    },
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

    pub(super) async fn prepare_recovery(&self, current: &RouterDesired) -> Result<()> {
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

    pub(super) async fn snapshot(&self) -> VpnChainSnapshot {
        let previous = self.vpn_active_chain.read().await.clone();
        VpnChainSnapshot {
            hops: previous.iter().map(|hop| hop.interface.clone()).collect(),
            previous_hops: previous,
        }
    }

    pub(super) async fn plan_vpn_chain(&self, desired: &RouterDesired) -> Result<VpnChainPlan> {
        if !desired.vpn_chain.is_empty() && self.deps.is_none() {
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
    pub(super) async fn apply_vpn_chain(&self, plan: &VpnChainPlan) -> Result<()> {
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
        if self.deps.is_none() {
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

    pub(super) async fn rollback_vpn_chain(&self, snapshot: &VpnChainSnapshot) -> Result<()> {
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

    pub(super) async fn health_vpn_chain(&self, desired: &RouterDesired) -> Result<()> {
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
                    let policy = self.with_host_endpoints(policy).await?;
                    self.vpn_policy_manager_for_hop(expected.reserved, tunnel)?
                        .health(&policy)
                        .await?;
                }
            }
        }
        Ok(())
    }
}
