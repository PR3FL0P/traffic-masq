use std::sync::Arc;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::firewall::vpn::{FirewallMark, FirewallMarkMask, VPN_POLICY_FWMARK, VPN_POLICY_FWMASK};
use crate::netlink::{
    Ipv4RouteInfo, Ipv4RouteSpec, Ipv4RuleInfo, Ipv4RuleSpec, NetworkProvider,
    TRAFFIC_MASQ_ROUTE_PROTOCOL,
};

pub const VPN_POLICY_ROUTE_TABLE_ID: PolicyRouteTableId = PolicyRouteTableId(30_100);

pub const VPN_POLICY_RULE_PRIORITY_START: PolicyRulePriority = PolicyRulePriority(10_100);

/// Hop 0's slice of the per-hop rule-priority band (`BASE + 0*10 ..= BASE +
/// 0*10 + 9`) — kept in lockstep with [`VpnPolicyReservedIds::for_hop`] so
/// `for_hop(0)` reproduces [`VpnPolicyReservedIds::default`] exactly. Each
/// hop only needs a 10-wide slice (one rule per hop), not the historical
/// 100-wide single-tunnel band; widening `for_hop(0)` back out to
/// `10_100..=10_199` would make it overlap every other hop's band instead of
/// staying disjoint from them.
pub const VPN_POLICY_RULE_PRIORITY_END: PolicyRulePriority = PolicyRulePriority(10_109);

/// Base route table id for per-hop allocation: hop N uses `BASE + N`.
/// Chosen so `for_hop(0)` reproduces [`VPN_POLICY_ROUTE_TABLE_ID`] exactly,
/// keeping the legacy single-hop `Default` impl unchanged.
pub const VPN_POLICY_ROUTE_TABLE_BASE: u32 = 30_100;

/// Base rule-priority for per-hop allocation: hop N uses
/// `BASE + N*10 ..= BASE + N*10 + 9`. Chosen so `for_hop(0)` reproduces
/// [`VPN_POLICY_RULE_PRIORITY_START`]/`_END` exactly.
pub const VPN_POLICY_RULE_PRIORITY_BASE: u32 = 10_100;

/// Hop indices beyond this are rejected by [`VpnPolicyReservedIds::for_hop`]:
/// keeps the widened per-hop priority band (`BASE + N*10 ..= BASE + N*10 + 9`)
/// inside the historical single reserved band `10_100..=10_199` and bounds
/// how large a persisted `vpn_chain` may be.
pub const MAX_VPN_HOP_INDEX: u32 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PolicyRouteTableId(u32);

impl PolicyRouteTableId {
    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PolicyRulePriority(u32);

impl PolicyRulePriority {
    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnPolicyReservedIds {
    pub route_table: PolicyRouteTableId,
    pub rule_priority_start: PolicyRulePriority,
    pub rule_priority_end: PolicyRulePriority,
    pub fw_mark: FirewallMark,
    pub fw_mask: FirewallMarkMask,
}

impl Default for VpnPolicyReservedIds {
    fn default() -> Self {
        Self {
            route_table: VPN_POLICY_ROUTE_TABLE_ID,
            rule_priority_start: VPN_POLICY_RULE_PRIORITY_START,
            rule_priority_end: VPN_POLICY_RULE_PRIORITY_END,
            fw_mark: VPN_POLICY_FWMARK,
            fw_mask: VPN_POLICY_FWMASK,
        }
    }
}

impl VpnPolicyReservedIds {
    /// Per-hop allocation: hop N gets route table `BASE + N`, rule
    /// priorities `BASE + N*10 ..= BASE + N*10 + 9`, and the same fwmark
    /// namespace as every other hop (fwmark selectors are disambiguated by
    /// which chain a rule belongs to via the route table/priority, not by a
    /// distinct mark per hop). `for_hop(0)` is exactly
    /// [`VpnPolicyReservedIds::default`].
    pub fn for_hop(hop_index: u32) -> Result<Self> {
        if hop_index > MAX_VPN_HOP_INDEX {
            bail!(
                "VPN hop index {hop_index} exceeds the maximum supported chain length \
                 ({MAX_VPN_HOP_INDEX})"
            );
        }
        let route_table = VPN_POLICY_ROUTE_TABLE_BASE + hop_index;
        let priority_start = VPN_POLICY_RULE_PRIORITY_BASE + hop_index * 10;
        let priority_end = priority_start + 9;
        Ok(Self {
            route_table: PolicyRouteTableId(route_table),
            rule_priority_start: PolicyRulePriority(priority_start),
            rule_priority_end: PolicyRulePriority(priority_end),
            fw_mark: VPN_POLICY_FWMARK,
            fw_mask: VPN_POLICY_FWMASK,
        })
    }

    pub fn validate(self) -> Result<()> {
        if self.route_table.get() == 0 {
            bail!("VPN policy route table must not be RT_TABLE_UNSPEC (0)");
        }
        if self.rule_priority_start.get() > self.rule_priority_end.get() {
            bail!("VPN policy rule priority range is inverted");
        }
        if self.fw_mask.get() == 0 {
            bail!("VPN policy fwmark mask must not be zero");
        }
        Ok(())
    }

    pub fn contains_priority(self, priority: u32) -> bool {
        self.rule_priority_start.get() <= priority && priority <= self.rule_priority_end.get()
    }

    pub fn mark_selector_overlaps(self, fw_mark: Option<u32>, fw_mask: Option<u32>) -> bool {
        let Some(mark) = fw_mark else {
            return false;
        };
        let mask = fw_mask.unwrap_or(u32::MAX);
        marks_overlap(mark, mask, self.fw_mark.get(), self.fw_mask.get())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnPolicyDesiredState {
    pub rules: Vec<Ipv4RuleSpec>,
    pub routes: Vec<Ipv4RouteSpec>,
}

impl VpnPolicyDesiredState {
    pub fn validate(&self, reserved: VpnPolicyReservedIds) -> Result<()> {
        reserved.validate()?;

        for (index, rule) in self.rules.iter().enumerate() {
            rule.validate()
                .map_err(|error| anyhow::anyhow!("VPN policy rule {index}: {error}"))?;
            validate_reserved_rule(rule, reserved)
                .map_err(|error| anyhow::anyhow!("VPN policy rule {index}: {error}"))?;
            if self.rules[..index].contains(rule) {
                bail!("duplicate VPN policy rule at index {index}");
            }
        }

        for (index, route) in self.routes.iter().enumerate() {
            route
                .validate()
                .map_err(|error| anyhow::anyhow!("VPN policy route {index}: {error}"))?;
            validate_reserved_route(route, reserved)
                .map_err(|error| anyhow::anyhow!("VPN policy route {index}: {error}"))?;
            if self.routes[..index].contains(route) {
                bail!("duplicate VPN policy route at index {index}");
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnPolicyResourceObservation {
    pub owned_rules: Vec<Ipv4RuleInfo>,
    pub missing_rules: Vec<Ipv4RuleSpec>,
    pub owned_routes: Vec<Ipv4RouteInfo>,
    pub missing_routes: Vec<Ipv4RouteSpec>,
    pub unexpected_owned_routes: Vec<Ipv4RouteInfo>,
    pub conflicts: Vec<VpnPolicyConflict>,
}

impl VpnPolicyResourceObservation {
    pub fn is_conflict_free(&self) -> bool {
        self.conflicts.is_empty()
    }

    pub fn is_fully_present(&self) -> bool {
        self.missing_rules.is_empty()
            && self.missing_routes.is_empty()
            && self.unexpected_owned_routes.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpnPolicyConflict {
    Rule {
        rule: Ipv4RuleInfo,
        reasons: Vec<RuleConflictReason>,
    },
    Route {
        route: Ipv4RouteInfo,
        reason: RouteConflictReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleConflictReason {
    ReservedPriority,
    ReservedTable,
    ReservedMark,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteConflictReason {
    ForeignRouteInReservedTable,
}

#[derive(Clone)]
pub struct VpnPolicyResourceConflictDetector {
    provider: Arc<dyn NetworkProvider>,
    reserved: VpnPolicyReservedIds,
}

impl VpnPolicyResourceConflictDetector {
    pub fn new(provider: Arc<dyn NetworkProvider>) -> Self {
        Self {
            provider,
            reserved: VpnPolicyReservedIds::default(),
        }
    }

    pub fn with_reserved_ids(mut self, reserved: VpnPolicyReservedIds) -> Self {
        self.reserved = reserved;
        self
    }

    pub async fn observe(
        &self,
        desired: &VpnPolicyDesiredState,
    ) -> Result<VpnPolicyResourceObservation> {
        desired.validate(self.reserved)?;

        let mut remaining_rules = desired.rules.clone();
        let mut remaining_routes = desired.routes.clone();
        let current_rules = self.provider.list_ipv4_rules().await?;
        let current_routes = self
            .provider
            .list_ipv4_routes_in_table(self.reserved.route_table.get())
            .await?;

        let mut owned_rules = Vec::new();
        let mut owned_routes = Vec::new();
        let mut unexpected_owned_routes = Vec::new();
        let mut conflicts = Vec::new();

        for rule in current_rules {
            if let Some(position) = remaining_rules
                .iter()
                .position(|expected| rule_matches_spec(&rule, expected))
            {
                owned_rules.push(rule);
                remaining_rules.remove(position);
                continue;
            }

            let reasons = overlapping_reserved_rule_reasons(&rule, self.reserved);
            if !reasons.is_empty() {
                conflicts.push(VpnPolicyConflict::Rule { rule, reasons });
            }
        }

        for route in current_routes {
            if route.protocol == TRAFFIC_MASQ_ROUTE_PROTOCOL {
                if let Some(position) = remaining_routes
                    .iter()
                    .position(|expected| route_matches_spec(&route, expected))
                {
                    owned_routes.push(route);
                    remaining_routes.remove(position);
                } else {
                    unexpected_owned_routes.push(route);
                }
            } else {
                conflicts.push(VpnPolicyConflict::Route {
                    route,
                    reason: RouteConflictReason::ForeignRouteInReservedTable,
                });
            }
        }

        sort_rules(&mut owned_rules);
        sort_rule_specs(&mut remaining_rules);
        sort_routes(&mut owned_routes);
        sort_route_specs(&mut remaining_routes);
        sort_routes(&mut unexpected_owned_routes);
        sort_conflicts(&mut conflicts);

        Ok(VpnPolicyResourceObservation {
            owned_rules,
            missing_rules: remaining_rules,
            owned_routes,
            missing_routes: remaining_routes,
            unexpected_owned_routes,
            conflicts,
        })
    }
}

fn validate_reserved_rule(rule: &Ipv4RuleSpec, reserved: VpnPolicyReservedIds) -> Result<()> {
    let touches_reserved_priority = rule
        .priority
        .is_some_and(|priority| reserved.contains_priority(priority));
    let touches_reserved_table = rule.table == reserved.route_table.get();
    let touches_reserved_mark = reserved.mark_selector_overlaps(rule.fw_mark, rule.fw_mask);

    if let Some(priority) = rule.priority {
        if !reserved.contains_priority(priority) {
            bail!(
                "priority {priority} lies outside the reserved VPN policy priority range {}..={}",
                reserved.rule_priority_start.get(),
                reserved.rule_priority_end.get()
            );
        }
    }
    if rule.table != reserved.route_table.get() {
        bail!(
            "rule table {} does not match reserved VPN policy table {}",
            rule.table,
            reserved.route_table.get()
        );
    }
    if rule.fw_mark.is_some() && !touches_reserved_mark {
        bail!(
            "rule fwmark selector does not overlap the reserved VPN mark namespace {:#010x}/{:#010x}",
            reserved.fw_mark.get(),
            reserved.fw_mask.get()
        );
    }
    if !(touches_reserved_priority || touches_reserved_table || touches_reserved_mark) {
        bail!("rule does not touch any reserved VPN policy identifier");
    }
    Ok(())
}

fn validate_reserved_route(route: &Ipv4RouteSpec, reserved: VpnPolicyReservedIds) -> Result<()> {
    if route.table != reserved.route_table.get() {
        bail!(
            "route table {} does not match reserved VPN policy table {}",
            route.table,
            reserved.route_table.get()
        );
    }
    if route.protocol != TRAFFIC_MASQ_ROUTE_PROTOCOL {
        bail!(
            "route protocol {} does not match traffic-masq reserved protocol {}",
            route.protocol,
            TRAFFIC_MASQ_ROUTE_PROTOCOL
        );
    }
    Ok(())
}

fn overlapping_reserved_rule_reasons(
    rule: &Ipv4RuleInfo,
    reserved: VpnPolicyReservedIds,
) -> Vec<RuleConflictReason> {
    let mut reasons = Vec::new();
    if rule
        .priority
        .is_some_and(|priority| reserved.contains_priority(priority))
    {
        reasons.push(RuleConflictReason::ReservedPriority);
    }
    if rule.table == reserved.route_table.get() {
        reasons.push(RuleConflictReason::ReservedTable);
    }
    if reserved.mark_selector_overlaps(rule.fw_mark, rule.fw_mask) {
        reasons.push(RuleConflictReason::ReservedMark);
    }
    reasons
}

fn marks_overlap(mark_a: u32, mask_a: u32, mark_b: u32, mask_b: u32) -> bool {
    ((mark_a ^ mark_b) & mask_a & mask_b) == 0
}

fn rule_matches_spec(info: &Ipv4RuleInfo, spec: &Ipv4RuleSpec) -> bool {
    info.source == spec.source
        && info.destination == spec.destination
        && info.table == spec.table
        && info.priority == spec.priority
        && info.fw_mark == spec.fw_mark
        && effective_mask(info.fw_mark, info.fw_mask) == effective_mask(spec.fw_mark, spec.fw_mask)
        && info.input_interface == spec.input_interface
        && info.output_interface == spec.output_interface
}

fn effective_mask(mark: Option<u32>, mask: Option<u32>) -> Option<u32> {
    mark.map(|_| mask.unwrap_or(u32::MAX))
}

fn route_matches_spec(info: &Ipv4RouteInfo, spec: &Ipv4RouteSpec) -> bool {
    info.destination == spec.destination
        && info.gateway == spec.gateway
        && info.output_interface_index == spec.output_interface_index
        && info.table == spec.table
        && info.metric == spec.metric
        && info.protocol == spec.protocol
}

fn ipv4_net_sort_key(network: Option<ipnet::Ipv4Net>) -> Option<(u32, u8)> {
    network.map(|network| (u32::from(network.network()), network.prefix_len()))
}

fn sort_rule_specs(rules: &mut [Ipv4RuleSpec]) {
    rules.sort_by_key(|rule| {
        (
            rule.priority,
            rule.table,
            rule.fw_mark,
            effective_mask(rule.fw_mark, rule.fw_mask),
            ipv4_net_sort_key(rule.source),
            ipv4_net_sort_key(rule.destination),
            rule.input_interface.clone(),
            rule.output_interface.clone(),
        )
    });
}

fn sort_rules(rules: &mut [Ipv4RuleInfo]) {
    rules.sort_by_key(|rule| {
        (
            rule.priority,
            rule.table,
            rule.fw_mark,
            effective_mask(rule.fw_mark, rule.fw_mask),
            ipv4_net_sort_key(rule.source),
            ipv4_net_sort_key(rule.destination),
            rule.input_interface.clone(),
            rule.output_interface.clone(),
        )
    });
}

fn sort_route_specs(routes: &mut [Ipv4RouteSpec]) {
    routes.sort_by_key(|route| {
        (
            route.table,
            u32::from(route.destination.network()),
            route.destination.prefix_len(),
            route.gateway,
            route.output_interface_index,
            route.metric,
            route.protocol,
        )
    });
}

fn sort_routes(routes: &mut [Ipv4RouteInfo]) {
    routes.sort_by_key(|route| {
        (
            route.table,
            u32::from(route.destination.network()),
            route.destination.prefix_len(),
            route.gateway,
            route.output_interface_index,
            route.metric,
            route.protocol,
            route.scope,
        )
    });
}

fn sort_conflicts(conflicts: &mut [VpnPolicyConflict]) {
    conflicts.sort_by_key(|conflict| match conflict {
        VpnPolicyConflict::Rule { rule, reasons } => (
            0u8,
            rule.priority.unwrap_or(u32::MAX),
            rule.table,
            rule.fw_mark.unwrap_or(0),
            reasons.len() as u32,
        ),
        VpnPolicyConflict::Route { route, .. } => (
            1u8,
            route.metric.unwrap_or(u32::MAX),
            route.table,
            u32::from(route.destination.network()),
            route.destination.prefix_len() as u32,
        ),
    });
}

#[cfg(test)]
mod tests;
