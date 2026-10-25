use std::sync::Arc;

use anyhow::{bail, Context, Result};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use crate::config::{AppConfig, InterfaceRole};
use crate::core::vpn_policy::{
    VpnPolicyDesiredState, VpnPolicyReservedIds, VpnPolicyResourceConflictDetector,
};
use crate::firewall::vpn::{
    VpnFirewallIntegrity, VpnHostTrafficDesired, VpnPolicyFirewallBackend, VpnPolicyFirewallDesired,
};
use crate::firewall::NftExecutor;
use crate::netlink::{
    Ipv4RouteInfo, Ipv4RouteSpec, Ipv4RuleInfo, Ipv4RuleSpec, NetworkProvider,
    TRAFFIC_MASQ_ROUTE_PROTOCOL,
};
use crate::vpn::manager::OWNED_INTERFACE_NAME;
use crate::vpn::{VpnDriver, VpnManager};

const VPN_POLICY_ROUTE_METRIC: u32 = 50;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnPolicyDesired {
    /// Standalone policy supplies NAT; router chains use explicit forwarding NAT instead.
    #[serde(
        default = "default_masquerade_forwarded",
        skip_serializing_if = "masquerades_forwarded"
    )]
    pub masquerade_forwarded: bool,
    pub protected_subnets: Vec<Ipv4Net>,
    pub vpn_interface: String,
    pub physical_uplink: String,
    /// Also route the router's own traffic through the tunnel.
    #[serde(default)]
    pub route_host_traffic: bool,
    /// Profiles of every hop in the chain, whose endpoints must bypass the tunnel.
    #[serde(default)]
    pub chain_profiles: Vec<String>,
    /// Endpoint addresses observed in the kernel at apply/health time;
    /// never part of persisted intent.
    #[serde(default, skip_serializing)]
    pub host_endpoints: Vec<std::net::Ipv4Addr>,
}

/// The VPN policy this configuration calls for, or `None` if there is nothing
/// to protect.
///
/// Lives beside [`VpnPolicyDesired`] rather than in `app`, where it used to sit:
/// deciding what the policy should be given a configuration is a domain rule,
/// not part of wiring the daemon together. Having it in `app` meant `api` had
/// to reach into `app` to ask the question, which closed a cycle between the
/// two.
pub fn vpn_policy_desired(config: &AppConfig) -> Option<VpnPolicyDesired> {
    if config.router.forwarding.is_some() {
        return None;
    }
    let uplink = config.router.uplink.as_ref()?;
    let protected_subnets: Vec<Ipv4Net> = config
        .network
        .interfaces
        .values()
        .filter(|interface| interface.role == InterfaceRole::Output && interface.managed)
        .filter_map(|interface| interface.ipv4)
        .map(|network| network.trunc())
        .collect();
    if protected_subnets.is_empty() {
        return None;
    }
    Some(VpnPolicyDesired {
        masquerade_forwarded: true,
        protected_subnets,
        vpn_interface: OWNED_INTERFACE_NAME.to_string(),
        physical_uplink: uplink.interface.clone(),
        route_host_traffic: false,
        chain_profiles: Vec::new(),
        host_endpoints: Vec::new(),
    })
}

/// The desired state that means "own nothing": used to find and remove whatever
/// a previous run installed.
pub fn vpn_policy_teardown_target() -> VpnPolicyDesired {
    VpnPolicyDesired {
        masquerade_forwarded: true,
        protected_subnets: Vec::new(),
        vpn_interface: OWNED_INTERFACE_NAME.to_string(),
        physical_uplink: String::new(),
        route_host_traffic: false,
        chain_profiles: Vec::new(),
        host_endpoints: Vec::new(),
    }
}

impl VpnPolicyDesired {
    fn firewall(&self) -> VpnPolicyFirewallDesired {
        VpnPolicyFirewallDesired {
            masquerade_forwarded: self.masquerade_forwarded,
            protected_subnets: self.protected_subnets.clone(),
            vpn_interface: self.vpn_interface.clone(),
            physical_uplink: self.physical_uplink.clone(),
            host_traffic: self.route_host_traffic.then(|| VpnHostTrafficDesired {
                vpn_endpoints: self.host_endpoints.clone(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct VpnPolicySnapshot {
    rules: Vec<Ipv4RuleInfo>,
    routes: Vec<Ipv4RouteInfo>,
    firewall: Option<VpnPolicyFirewallDesired>,
}

impl VpnPolicySnapshot {
    pub(crate) fn rebind_interface(&mut self, previous: u32, current: u32) {
        for route in &mut self.routes {
            if route.output_interface_index == Some(previous) {
                route.output_interface_index = Some(current);
            }
        }
    }

    pub fn is_active(&self) -> bool {
        !self.rules.is_empty()
    }
}

pub struct VpnPolicyManager<D: VpnDriver, E: NftExecutor> {
    network: Arc<dyn NetworkProvider>,
    conflicts: VpnPolicyResourceConflictDetector,
    firewall: Arc<VpnPolicyFirewallBackend<E>>,
    tunnel: Arc<VpnManager<D>>,
    reserved: VpnPolicyReservedIds,
}

impl<D: VpnDriver, E: NftExecutor> VpnPolicyManager<D, E> {
    pub fn new(
        network: Arc<dyn NetworkProvider>,
        firewall: VpnPolicyFirewallBackend<E>,
        tunnel: Arc<VpnManager<D>>,
    ) -> Self {
        Self::new_with_reserved(network, firewall, tunnel, VpnPolicyReservedIds::default())
    }

    /// Like [`Self::new`], but with an explicit reserved-ID allocation
    /// instead of the legacy single-hop default. Used by the VPN hop chain
    /// (`ProductionRouterSubsystems::apply_vpn_chain`) to run one
    /// `VpnPolicyManager` per exit hop, each scoped to
    /// `VpnPolicyReservedIds::for_hop(hop_index)` instead of colliding on
    /// the same reserved band.
    pub fn new_with_reserved(
        network: Arc<dyn NetworkProvider>,
        firewall: VpnPolicyFirewallBackend<E>,
        tunnel: Arc<VpnManager<D>>,
        reserved: VpnPolicyReservedIds,
    ) -> Self {
        Self {
            conflicts: VpnPolicyResourceConflictDetector::new(network.clone())
                .with_reserved_ids(reserved),
            network,
            firewall: Arc::new(firewall),
            tunnel,
            reserved,
        }
    }

    /// Capture the rules, routes, and firewall state affected by the desired VPN policy.
    pub async fn snapshot(&self, desired: &VpnPolicyDesired) -> Result<VpnPolicySnapshot> {
        let expected = self.desired_state_best_effort(desired).await;
        let observation = self.conflicts.observe(&expected).await?;
        if !observation.is_conflict_free() {
            bail!(
                "refusing to observe VPN policy state: foreign objects occupy the reserved \
                 namespace: {}",
                observation.conflict_diagnostics()
            );
        }
        let firewall = self
            .firewall
            .observe_async()
            .await
            .context("failed to observe VPN policy firewall state")?;

        let mut routes = observation.owned_routes;
        routes.extend(observation.unexpected_owned_routes);
        Ok(VpnPolicySnapshot {
            rules: observation.owned_rules,
            routes,
            firewall: firewall.desired,
        })
    }

    /// Verify that the desired VPN policy rules, routes, and firewall state are present.
    pub async fn health(&self, desired: &VpnPolicyDesired) -> Result<()> {
        let firewall_desired = desired.firewall();
        firewall_desired.validate()?;
        self.ensure_tunnel_healthy(&desired.vpn_interface).await?;

        let expected = self.desired_state_strict(desired).await?;
        let observation = self.conflicts.observe(&expected).await?;
        if !observation.is_conflict_free() {
            bail!(
                "VPN policy reserved namespace contains foreign state: {}",
                observation.conflict_diagnostics()
            );
        }
        if !observation.is_fully_present() {
            bail!(
                "VPN policy routing state drifted: missing rules {:?}, missing routes {:?}, unexpected owned routes {:?}",
                observation.missing_rules,
                observation.missing_routes,
                observation.unexpected_owned_routes
            );
        }

        let firewall = self
            .firewall
            .observe_async()
            .await
            .context("failed to observe VPN policy firewall health")?;
        if firewall.integrity != VpnFirewallIntegrity::Intact
            || firewall.desired.as_ref() != Some(&firewall_desired)
        {
            bail!("VPN policy firewall state drifted");
        }
        Ok(())
    }

    /// Verify that no daemon-owned VPN policy state remains active.
    pub async fn health_inactive(&self) -> Result<()> {
        let expected = VpnPolicyDesiredState {
            rules: Vec::new(),
            routes: Vec::new(),
        };
        let observation = self.conflicts.observe(&expected).await?;
        if !observation.is_conflict_free() || !observation.unexpected_owned_routes.is_empty() {
            bail!("VPN policy routing state is still present");
        }

        let firewall = self
            .firewall
            .observe_async()
            .await
            .context("failed to observe inactive VPN policy firewall health")?;
        if firewall.integrity != VpnFirewallIntegrity::Intact || firewall.desired.is_some() {
            bail!("VPN policy firewall state is still present or drifted");
        }
        Ok(())
    }

    /// Validate and apply VPN traffic policy, returning the preceding state for rollback.
    pub async fn activate(&self, desired: &VpnPolicyDesired) -> Result<VpnPolicySnapshot> {
        desired.firewall().validate()?;
        self.ensure_tunnel_healthy(&desired.vpn_interface).await?;

        let expected = self.desired_state_strict(desired).await?;
        let observation = self.conflicts.observe(&expected).await?;
        if !observation.is_conflict_free() {
            bail!(
                "refusing to activate VPN policy: foreign objects occupy the reserved \
                 namespace: {}",
                observation.conflict_diagnostics()
            );
        }

        let firewall_before = self
            .firewall
            .observe_async()
            .await
            .context("failed to observe VPN policy firewall state before activation")?;
        let mut snapshot_routes = observation.owned_routes.clone();
        snapshot_routes.extend(observation.unexpected_owned_routes.clone());
        let snapshot = VpnPolicySnapshot {
            rules: observation.owned_rules.clone(),
            routes: snapshot_routes,
            firewall: firewall_before.desired,
        };

        if let Err(error) = self.install_missing_rules_and_routes(&observation).await {
            return match self.rollback(desired, &snapshot).await {
                Ok(()) => Err(error),
                Err(rollback) => Err(error.context(format!(
                    "VPN policy activation failed and rollback was incomplete: {rollback:#}"
                ))),
            };
        }

        if let Err(error) = self
            .firewall
            .apply_async(&desired.firewall())
            .await
            .context("failed to apply VPN policy firewall marking/NAT/kill switch")
        {
            return match self.rollback(desired, &snapshot).await {
                Ok(()) => Err(error),
                Err(rollback) => Err(error.context(format!(
                    "VPN policy firewall activation failed and rollback was incomplete: {rollback:#}"
                ))),
            };
        }

        Ok(snapshot)
    }

    /// Remove daemon-owned VPN policy resources associated with the desired policy.
    pub async fn deactivate(&self, desired: &VpnPolicyDesired) -> Result<()> {
        let snapshot = self.snapshot(desired).await?;
        if let Err(error) = self.deactivate_inner(desired).await {
            return match self.rollback(desired, &snapshot).await {
                Ok(()) => Err(error),
                Err(rollback) => Err(error.context(format!(
                    "VPN policy deactivation failed and rollback was incomplete: {rollback:#}"
                ))),
            };
        }
        Ok(())
    }

    async fn deactivate_inner(&self, desired: &VpnPolicyDesired) -> Result<()> {
        let mut errors = Vec::new();

        // Remove policy routing first. If that cannot be completed, keep the
        // firewall/kill-switch installed so a failed teardown remains
        // fail-closed rather than silently exposing direct traffic.
        let expected = self.desired_state_best_effort(desired).await;
        match self.conflicts.observe(&expected).await {
            Ok(observation) => {
                for route in observation
                    .owned_routes
                    .into_iter()
                    .chain(observation.unexpected_owned_routes)
                {
                    if let Err(error) = self.network.delete_ipv4_route(&route).await {
                        errors.push(format!("failed to remove VPN policy route: {error:#}"));
                    }
                }
                for rule in observation.owned_rules {
                    if let Err(error) = self.network.delete_ipv4_rule(&rule).await {
                        errors.push(format!("failed to remove VPN policy rule: {error:#}"));
                    }
                }
            }
            Err(error) => {
                errors.push(format!(
                    "failed to observe VPN policy IPv4 state: {error:#}"
                ));
            }
        }

        if !errors.is_empty() {
            bail!(
                "VPN policy deactivation was incomplete; firewall retained fail-closed: {}",
                errors.join("; ")
            );
        }

        self.firewall
            .restore_async(None)
            .await
            .context("failed to remove VPN policy firewall state")
    }

    /// Reinstate previous protection before restoring a tunnel or its routes.
    /// An unprotected snapshot must wait until network restoration succeeds.
    pub(crate) async fn protect_rollback(&self, snapshot: &VpnPolicySnapshot) -> Result<()> {
        if let Some(firewall) = &snapshot.firewall {
            self.firewall
                .restore_async(Some(firewall))
                .await
                .context("failed to reinstate VPN protection before rollback")?;
        }
        Ok(())
    }

    /// Restore policy routing and firewall resources from the captured snapshot.
    pub async fn rollback(
        &self,
        desired: &VpnPolicyDesired,
        snapshot: &VpnPolicySnapshot,
    ) -> Result<()> {
        let mut errors = Vec::new();

        // Restore routes/rules before relaxing the firewall. If network state
        // cannot be restored exactly, leave the current firewall in place and
        // surface an incomplete rollback.
        let expected = self.desired_state_best_effort(desired).await;
        match self.conflicts.observe(&expected).await {
            Ok(observation) => {
                let mut current_routes = observation.owned_routes;
                current_routes.extend(observation.unexpected_owned_routes);

                for route in current_routes
                    .iter()
                    .filter(|route| !snapshot.routes.contains(route))
                {
                    if let Err(error) = self.network.delete_ipv4_route(route).await {
                        errors.push(format!("failed to remove route during rollback: {error:#}"));
                    }
                }
                for route in snapshot
                    .routes
                    .iter()
                    .filter(|route| !current_routes.contains(route))
                {
                    if let Err(error) = self
                        .network
                        .add_ipv4_route(&route_spec_from_info(route))
                        .await
                    {
                        errors.push(format!(
                            "failed to restore route during rollback: {error:#}"
                        ));
                    }
                }

                for rule in observation
                    .owned_rules
                    .iter()
                    .filter(|rule| !snapshot.rules.contains(rule))
                {
                    if let Err(error) = self.network.delete_ipv4_rule(rule).await {
                        errors.push(format!("failed to remove rule during rollback: {error:#}"));
                    }
                }
                for rule in snapshot
                    .rules
                    .iter()
                    .filter(|rule| !observation.owned_rules.contains(rule))
                {
                    if let Err(error) = self.network.add_ipv4_rule(&rule_spec_from_info(rule)).await
                    {
                        errors.push(format!("failed to restore rule during rollback: {error:#}"));
                    }
                }
            }
            Err(error) => {
                errors.push(format!(
                    "failed to observe VPN policy IPv4 state during rollback: {error:#}"
                ));
            }
        }

        if !errors.is_empty() {
            bail!(
                "VPN policy rollback was incomplete; firewall retained fail-closed: {}",
                errors.join("; ")
            );
        }

        self.firewall
            .restore_async(snapshot.firewall.as_ref())
            .await
            .context("failed to restore VPN policy firewall state during rollback")
    }

    async fn install_missing_rules_and_routes(
        &self,
        observation: &crate::core::vpn_policy::VpnPolicyResourceObservation,
    ) -> Result<()> {
        for route in &observation.unexpected_owned_routes {
            self.network
                .delete_ipv4_route(route)
                .await
                .context("failed to remove drifted owned VPN policy route")?;
        }
        for rule in &observation.missing_rules {
            self.network
                .add_ipv4_rule(rule)
                .await
                .context("failed to install VPN policy IPv4 rule")?;
        }
        for route in &observation.missing_routes {
            self.network
                .add_ipv4_route(route)
                .await
                .context("failed to install VPN policy IPv4 route")?;
        }
        Ok(())
    }

    async fn ensure_tunnel_healthy(&self, vpn_interface: &str) -> Result<()> {
        let status = self
            .tunnel
            .status_on(vpn_interface)
            .await
            .context("failed to read VPN tunnel status")?;
        match status {
            Some(status) if status.up => Ok(()),
            Some(status) => bail!(
                "refusing to activate VPN policy: tunnel interface '{}' is not up — fail closed, \
                 not falling back to direct uplink",
                status.interface
            ),
            None => {
                let active = self.tunnel.active_interfaces();
                if let Some(record) = active.first() {
                    bail!(
                        "refusing to activate VPN policy: active tunnel interface '{}' does not match the expected VPN policy interface '{}' — fail closed, not falling back to direct uplink",
                        record.interface,
                        vpn_interface
                    );
                }
                bail!(
                    "refusing to activate VPN policy: no active VPN tunnel — fail closed, not \
                     falling back to direct uplink"
                )
            }
        }
    }

    fn desired_rule(&self) -> Ipv4RuleSpec {
        Ipv4RuleSpec {
            source: None,
            destination: None,
            table: self.reserved.route_table.get(),
            priority: Some(self.reserved.rule_priority_start.get()),
            fw_mark: Some(self.reserved.fw_mark.get()),
            fw_mask: Some(self.reserved.fw_mask.get()),
            input_interface: None,
            output_interface: None,
        }
    }

    async fn desired_route(&self, vpn_interface: &str) -> Result<Ipv4RouteSpec> {
        let index = self.resolve_interface_index(vpn_interface).await?;
        Ok(Ipv4RouteSpec {
            destination: default_ipv4_route(),
            gateway: None,
            output_interface_index: Some(index),
            table: self.reserved.route_table.get(),
            metric: Some(VPN_POLICY_ROUTE_METRIC),
            protocol: TRAFFIC_MASQ_ROUTE_PROTOCOL,
        })
    }

    async fn desired_state_strict(
        &self,
        desired: &VpnPolicyDesired,
    ) -> Result<VpnPolicyDesiredState> {
        Ok(VpnPolicyDesiredState {
            rules: vec![self.desired_rule()],
            routes: vec![self.desired_route(&desired.vpn_interface).await?],
        })
    }

    async fn desired_state_best_effort(&self, desired: &VpnPolicyDesired) -> VpnPolicyDesiredState {
        let routes = match self.desired_route(&desired.vpn_interface).await {
            Ok(route) => vec![route],
            Err(_) => Vec::new(),
        };
        VpnPolicyDesiredState {
            rules: vec![self.desired_rule()],
            routes,
        }
    }

    async fn resolve_interface_index(&self, name: &str) -> Result<u32> {
        self.network
            .list_interfaces()
            .await
            .context("failed to list interfaces while resolving VPN policy interface")?
            .into_iter()
            .find(|interface| interface.name == name)
            .map(|interface| interface.index)
            .ok_or_else(|| anyhow::anyhow!("VPN policy interface not found: {name}"))
    }
}

fn default_ipv4_route() -> Ipv4Net {
    Ipv4Net::new(std::net::Ipv4Addr::UNSPECIFIED, 0).expect("0.0.0.0/0 is always a valid network")
}

fn route_spec_from_info(info: &Ipv4RouteInfo) -> Ipv4RouteSpec {
    Ipv4RouteSpec {
        destination: info.destination,
        gateway: info.gateway,
        output_interface_index: info.output_interface_index,
        table: info.table,
        metric: info.metric,
        protocol: info.protocol,
    }
}

fn rule_spec_from_info(info: &Ipv4RuleInfo) -> Ipv4RuleSpec {
    Ipv4RuleSpec {
        source: info.source,
        destination: info.destination,
        table: info.table,
        priority: info.priority,
        fw_mark: info.fw_mark,
        fw_mask: info.fw_mask,
        input_interface: info.input_interface.clone(),
        output_interface: info.output_interface.clone(),
    }
}

fn default_masquerade_forwarded() -> bool {
    true
}

// Omit the historical default to preserve existing recovery fingerprints/metadata.
fn masquerades_forwarded(value: &bool) -> bool {
    *value
}

#[cfg(test)]
mod tests;
