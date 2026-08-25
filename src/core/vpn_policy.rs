use std::sync::Arc;

use anyhow::{bail, Result};

use crate::firewall::vpn::{FirewallMark, FirewallMarkMask, VPN_POLICY_FWMARK, VPN_POLICY_FWMASK};
use crate::netlink::{
    Ipv4RouteInfo, Ipv4RouteSpec, Ipv4RuleInfo, Ipv4RuleSpec, NetworkProvider,
    TRAFFIC_MASQ_ROUTE_PROTOCOL,
};

pub const VPN_POLICY_ROUTE_TABLE_ID: PolicyRouteTableId = PolicyRouteTableId(30_100);

pub const VPN_POLICY_RULE_PRIORITY_START: PolicyRulePriority = PolicyRulePriority(10_100);

pub const VPN_POLICY_RULE_PRIORITY_END: PolicyRulePriority = PolicyRulePriority(10_199);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyRouteTableId(u32);

impl PolicyRouteTableId {
    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyRulePriority(u32);

impl PolicyRulePriority {
    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
mod tests {
    use crate::netlink::AddressOwnership;
    use std::net::Ipv4Addr;

    use async_trait::async_trait;

    use crate::netlink::{Ipv4AddressInfo, NetworkInterface};

    use super::*;

    #[derive(Default)]
    struct FakeNetwork {
        rules: Vec<Ipv4RuleInfo>,
        routes: Vec<Ipv4RouteInfo>,
    }

    #[async_trait]
    impl NetworkProvider for FakeNetwork {
        async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
            Ok(Vec::new())
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

        async fn list_ipv4_rules(&self) -> Result<Vec<Ipv4RuleInfo>> {
            Ok(self.rules.clone())
        }

        async fn list_ipv4_routes(&self) -> Result<Vec<Ipv4RouteInfo>> {
            Ok(self.routes.clone())
        }
    }

    fn reserved() -> VpnPolicyReservedIds {
        VpnPolicyReservedIds::default()
    }

    fn desired_state() -> VpnPolicyDesiredState {
        VpnPolicyDesiredState {
            rules: vec![Ipv4RuleSpec {
                source: Some("192.168.10.0/24".parse().expect("source subnet")),
                destination: None,
                table: reserved().route_table.get(),
                priority: Some(reserved().rule_priority_start.get()),
                fw_mark: Some(reserved().fw_mark.get()),
                fw_mask: Some(reserved().fw_mask.get()),
                input_interface: None,
                output_interface: None,
            }],
            routes: vec![Ipv4RouteSpec {
                destination: "0.0.0.0/0".parse().expect("default route"),
                gateway: None,
                output_interface_index: Some(7),
                table: reserved().route_table.get(),
                metric: Some(50),
                protocol: TRAFFIC_MASQ_ROUTE_PROTOCOL,
            }],
        }
    }

    fn owned_rule() -> Ipv4RuleInfo {
        Ipv4RuleInfo {
            source: Some("192.168.10.0/24".parse().expect("source subnet")),
            destination: None,
            table: reserved().route_table.get(),
            priority: Some(reserved().rule_priority_start.get()),
            fw_mark: Some(reserved().fw_mark.get()),
            fw_mask: Some(reserved().fw_mask.get()),
            input_interface: None,
            output_interface: None,
        }
    }

    fn owned_route() -> Ipv4RouteInfo {
        Ipv4RouteInfo {
            destination: "0.0.0.0/0".parse().expect("default route"),
            gateway: None,
            output_interface_index: Some(7),
            table: reserved().route_table.get(),
            metric: Some(50),
            protocol: TRAFFIC_MASQ_ROUTE_PROTOCOL,
            scope: 253,
        }
    }

    #[test]
    fn reserved_ids_are_self_consistent() {
        reserved().validate().expect("defaults are valid");
        assert!(reserved().contains_priority(reserved().rule_priority_start.get()));
        assert!(reserved().contains_priority(reserved().rule_priority_end.get()));
        assert!(!reserved().contains_priority(reserved().rule_priority_end.get() + 1));
    }

    #[test]
    fn reserved_mark_overlap_detection_matches_namespace_intersection() {
        assert!(reserved().mark_selector_overlaps(
            Some(reserved().fw_mark.get()),
            Some(reserved().fw_mask.get())
        ));
        assert!(reserved().mark_selector_overlaps(Some(reserved().fw_mark.get()), None));
        assert!(reserved().mark_selector_overlaps(Some(0x54ab_0001), Some(0xff00_0000)));
        assert!(!reserved().mark_selector_overlaps(Some(0x5300_0000), Some(0xff00_0000)));
        assert!(!reserved().mark_selector_overlaps(None, None));
    }

    #[test]
    fn desired_state_rejects_rule_outside_reserved_priority_band() {
        let mut desired = desired_state();
        desired.rules[0].priority = Some(reserved().rule_priority_end.get() + 1);

        let error = desired.validate(reserved()).expect_err("priority conflict");
        assert!(error
            .to_string()
            .contains("outside the reserved VPN policy priority range"));
    }

    #[test]
    fn desired_state_rejects_route_outside_reserved_table() {
        let mut desired = desired_state();
        desired.routes[0].table = 254;

        let error = desired
            .validate(reserved())
            .expect_err("reserved table mismatch");
        assert!(error
            .to_string()
            .contains("does not match reserved VPN policy table"));
    }

    #[tokio::test]
    async fn observe_classifies_exact_matches_as_owned_without_conflicts() {
        let provider = Arc::new(FakeNetwork {
            rules: vec![owned_rule()],
            routes: vec![owned_route()],
        });
        let observation = VpnPolicyResourceConflictDetector::new(provider)
            .observe(&desired_state())
            .await
            .expect("observe");

        assert_eq!(observation.owned_rules, vec![owned_rule()]);
        assert_eq!(observation.owned_routes, vec![owned_route()]);
        assert!(observation.missing_rules.is_empty());
        assert!(observation.missing_routes.is_empty());
        assert!(observation.unexpected_owned_routes.is_empty());
        assert!(observation.conflicts.is_empty());
        assert!(observation.is_conflict_free());
        assert!(observation.is_fully_present());
    }

    #[tokio::test]
    async fn observe_reports_foreign_rule_conflicts_for_reserved_priority_and_mark() {
        let foreign_rule = Ipv4RuleInfo {
            source: None,
            destination: Some("203.0.113.0/24".parse().expect("destination")),
            table: 254,
            priority: Some(reserved().rule_priority_start.get()),
            fw_mark: Some(0x54ff_0000),
            fw_mask: Some(0xff00_0000),
            input_interface: Some("eth9".into()),
            output_interface: None,
        };
        let provider = Arc::new(FakeNetwork {
            rules: vec![foreign_rule.clone()],
            routes: vec![],
        });
        let observation = VpnPolicyResourceConflictDetector::new(provider)
            .observe(&desired_state())
            .await
            .expect("observe");

        assert!(observation.owned_rules.is_empty());
        assert_eq!(observation.missing_rules, desired_state().rules);
        assert_eq!(observation.conflicts.len(), 1);
        match &observation.conflicts[0] {
            VpnPolicyConflict::Rule { rule, reasons } => {
                assert_eq!(rule, &foreign_rule);
                assert!(reasons.contains(&RuleConflictReason::ReservedPriority));
                assert!(reasons.contains(&RuleConflictReason::ReservedMark));
            }
            other => panic!("expected rule conflict, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn observe_reports_foreign_routes_in_reserved_table_as_conflicts() {
        let foreign_route = Ipv4RouteInfo {
            protocol: 4,
            ..owned_route()
        };
        let provider = Arc::new(FakeNetwork {
            rules: vec![],
            routes: vec![foreign_route.clone()],
        });
        let observation = VpnPolicyResourceConflictDetector::new(provider)
            .observe(&desired_state())
            .await
            .expect("observe");

        assert_eq!(observation.missing_routes, desired_state().routes);
        assert_eq!(observation.conflicts.len(), 1);
        match &observation.conflicts[0] {
            VpnPolicyConflict::Route { route, reason } => {
                assert_eq!(route, &foreign_route);
                assert_eq!(*reason, RouteConflictReason::ForeignRouteInReservedTable);
            }
            other => panic!("expected route conflict, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn observe_distinguishes_unexpected_owned_routes_from_foreign_conflicts() {
        let mut stale_owned_route = owned_route();
        stale_owned_route.destination = "198.51.100.0/24".parse().expect("stale route");
        let provider = Arc::new(FakeNetwork {
            rules: vec![],
            routes: vec![stale_owned_route.clone()],
        });
        let observation = VpnPolicyResourceConflictDetector::new(provider)
            .observe(&desired_state())
            .await
            .expect("observe");

        assert!(observation.conflicts.is_empty());
        assert_eq!(observation.unexpected_owned_routes, vec![stale_owned_route]);
        assert_eq!(observation.missing_routes, desired_state().routes);
        assert!(!observation.is_fully_present());
    }

    #[tokio::test]
    async fn observe_treats_duplicate_exact_rule_as_conflicting_extra_occupant() {
        let owned = owned_rule();
        let provider = Arc::new(FakeNetwork {
            rules: vec![owned.clone(), owned.clone()],
            routes: vec![owned_route()],
        });
        let observation = VpnPolicyResourceConflictDetector::new(provider)
            .observe(&desired_state())
            .await
            .expect("observe");

        assert_eq!(observation.owned_rules, vec![owned.clone()]);
        assert_eq!(observation.conflicts.len(), 1);
        match &observation.conflicts[0] {
            VpnPolicyConflict::Rule { rule, reasons } => {
                assert_eq!(rule, &owned);
                assert!(reasons.contains(&RuleConflictReason::ReservedPriority));
                assert!(reasons.contains(&RuleConflictReason::ReservedTable));
                assert!(reasons.contains(&RuleConflictReason::ReservedMark));
            }
            other => panic!("expected duplicate rule conflict, got {other:?}"),
        }
    }
}
