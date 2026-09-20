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
fn for_hop_zero_matches_default() {
    let hop0 = VpnPolicyReservedIds::for_hop(0).expect("hop 0");
    assert_eq!(hop0, VpnPolicyReservedIds::default());
}

#[test]
fn for_hop_allocates_disjoint_non_overlapping_bands_per_hop() {
    let mut seen_tables = std::collections::HashSet::new();
    let mut seen_priorities = std::collections::HashSet::new();
    for hop in 0..=MAX_VPN_HOP_INDEX {
        let reserved = VpnPolicyReservedIds::for_hop(hop).expect("valid hop");
        reserved.validate().expect("valid reserved ids");
        assert!(
            seen_tables.insert(reserved.route_table.get()),
            "route table collided at hop {hop}"
        );
        for priority in reserved.rule_priority_start.get()..=reserved.rule_priority_end.get() {
            assert!(
                seen_priorities.insert(priority),
                "priority {priority} collided at hop {hop}"
            );
        }
    }
}

#[test]
fn for_hop_rejects_indices_beyond_the_cap() {
    let error = VpnPolicyReservedIds::for_hop(MAX_VPN_HOP_INDEX + 1)
        .expect_err("hop index beyond cap must be rejected");
    assert!(error.to_string().contains("exceeds the maximum"));
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
