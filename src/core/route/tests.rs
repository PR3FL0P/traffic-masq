use crate::netlink::AddressOwnership;
use std::net::Ipv4Addr;

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::netlink::{Ipv4AddressInfo, NetworkInterface, TRAFFIC_MASQ_DHCP_ROUTE_PROTOCOL};

use super::*;

fn router_with_one_owned_route() -> RouterConfig {
    RouterConfig {
        port_forwards: Vec::new(),
        forwarding: None,
        vpn_chain: Vec::new(),
        uplink: None,
        owned_routes: vec![OwnedIpv4RouteConfig {
            destination: "203.0.113.0/24".parse().expect("route destination"),
            gateway: None,
            output_interface: Some("wan0".to_string()),
            table: 254,
            metric: Some(100),
        }],
        allow_default_route_change: false,
        route_host_traffic: false,
    }
}

#[test]
fn router_config_builds_effective_route_desired_state() {
    let mut router = router_with_one_owned_route();

    let desired = desired_owned_routes(&router);
    assert_eq!(desired.len(), 1);
    assert_eq!(desired[0].destination, router.owned_routes[0].destination);
    assert_eq!(desired[0].output_interface.as_deref(), Some("wan0"));

    // Removing the last owned route leaves no route intent to apply.
    router.owned_routes.clear();
    assert!(!router.is_active());
    assert!(desired_owned_routes(&router).is_empty());
}

#[derive(Default)]
struct FakeNetwork {
    routes: Mutex<Vec<Ipv4RouteInfo>>,
    fail_next_add: Mutex<bool>,
}

impl FakeNetwork {
    async fn route_snapshot(&self) -> Vec<Ipv4RouteInfo> {
        self.routes.lock().await.clone()
    }
}

#[async_trait]
impl NetworkProvider for FakeNetwork {
    async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        Ok(vec![NetworkInterface {
            is_wireless: false,
            index: 7,
            name: "uplink0".to_string(),
            is_up: true,
            rx_bytes: 0,
            tx_bytes: 0,
        }])
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
        let mut fail = self.fail_next_add.lock().await;
        if *fail {
            *fail = false;
            bail!("injected add failure");
        }
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

fn desired(destination: &str) -> ManagedIpv4Route {
    ManagedIpv4Route {
        destination: destination.parse().expect("destination"),
        gateway: None,
        output_interface: Some("uplink0".to_string()),
        table: 254,
        metric: Some(100),
    }
}

fn route(destination: &str, protocol: u8) -> Ipv4RouteInfo {
    Ipv4RouteInfo {
        destination: destination.parse().expect("destination"),
        gateway: None,
        output_interface_index: Some(7),
        table: 254,
        metric: Some(100),
        protocol,
        scope: 253,
    }
}

#[tokio::test]
async fn plans_only_owned_route_changes_and_resolves_interface_names() {
    let provider = Arc::new(FakeNetwork::default());
    provider.routes.lock().await.extend([
        route("192.0.2.0/24", TRAFFIC_MASQ_ROUTE_PROTOCOL),
        route("203.0.113.0/24", 4),
    ]);
    let manager = RouteManager::new(provider);

    let plan = manager
        .plan(&[desired("198.51.100.0/24")], false)
        .await
        .expect("plan");
    assert_eq!(
        plan.delete,
        vec![route("192.0.2.0/24", TRAFFIC_MASQ_ROUTE_PROTOCOL)]
    );
    assert_eq!(plan.add.len(), 1);
    assert_eq!(plan.add[0].output_interface_index, Some(7));
    assert_eq!(plan.add[0].protocol, TRAFFIC_MASQ_ROUTE_PROTOCOL);
}

#[tokio::test]
async fn refuses_default_route_changes_without_confirmation() {
    let provider = Arc::new(FakeNetwork::default());
    let manager = RouteManager::new(provider);
    assert!(manager.plan(&[desired("0.0.0.0/0")], false).await.is_err());
    manager
        .plan(&[desired("0.0.0.0/0")], true)
        .await
        .expect("explicitly allowed default route");
}

#[tokio::test]
async fn disabled_router_removes_default_route_only_with_explicit_permission() {
    let provider = Arc::new(FakeNetwork::default());
    let owned = route("0.0.0.0/0", TRAFFIC_MASQ_ROUTE_PROTOCOL);
    let foreign = route("0.0.0.0/0", 4);
    provider
        .routes
        .lock()
        .await
        .extend([owned.clone(), foreign.clone()]);
    let manager = RouteManager::new(provider.clone());
    let mut config = crate::config::AppConfig::default();
    let desired = crate::core::router::RouterDesired::from_effective_config(&config)
        .expect("disabled router intent");

    let error = manager
        .apply(&desired.routes, desired.allow_default_route_change)
        .await
        .expect_err("removing an owned default still requires permission");
    assert!(error.to_string().contains("without explicit confirmation"));
    assert_eq!(
        provider.route_snapshot().await,
        vec![owned.clone(), foreign.clone()]
    );

    config.router.allow_default_route_change = true;
    let desired = crate::core::router::RouterDesired::from_effective_config(&config)
        .expect("confirmed disabled router intent");
    let snapshot = manager
        .apply(&desired.routes, desired.allow_default_route_change)
        .await
        .expect("explicitly allowed default route removal");
    assert_eq!(provider.route_snapshot().await, vec![foreign.clone()]);

    manager
        .rollback(&snapshot)
        .await
        .expect("restore owned default route");
    let restored = provider.route_snapshot().await;
    assert_eq!(restored.len(), 2);
    assert!(restored.contains(&owned));
    assert!(restored.contains(&foreign));
}

#[tokio::test]
async fn route_plan_exposes_default_route_risk() {
    let manager = RouteManager::new(Arc::new(FakeNetwork::default()));
    let ordinary = manager
        .plan(&[desired("198.51.100.0/24")], false)
        .await
        .expect("ordinary plan");
    assert!(!ordinary.changes_default_route());
    let default = manager
        .plan(&[desired("0.0.0.0/0")], true)
        .await
        .expect("default plan");
    assert!(default.changes_default_route());
}

#[tokio::test]
async fn health_reports_missing_and_unexpected_owned_routes_but_ignores_foreign_routes() {
    let provider = Arc::new(FakeNetwork::default());
    provider.routes.lock().await.extend([
        route("192.0.2.0/24", TRAFFIC_MASQ_ROUTE_PROTOCOL),
        route("203.0.113.0/24", 4),
        route("0.0.0.0/0", TRAFFIC_MASQ_DHCP_ROUTE_PROTOCOL),
    ]);
    let manager = RouteManager::new(provider);
    let health = manager
        .health(&[desired("198.51.100.0/24")])
        .await
        .expect("health");
    assert!(!health.is_healthy());
    assert_eq!(health.drift.len(), 2);
    assert!(matches!(health.drift[0], RouteDrift::Missing { .. }));
    assert!(matches!(health.drift[1], RouteDrift::Unexpected { .. }));
}

#[tokio::test]
async fn applies_prebuilt_route_plan_without_replanning() {
    let provider = Arc::new(FakeNetwork::default());
    let manager = RouteManager::new(provider.clone());
    let plan = manager
        .plan(&[desired("198.51.100.0/24")], false)
        .await
        .expect("plan");
    manager.apply_plan(&plan).await.expect("apply plan");
    assert!(provider
        .route_snapshot()
        .await
        .contains(&route("198.51.100.0/24", TRAFFIC_MASQ_ROUTE_PROTOCOL)));
}

#[tokio::test]
async fn failed_apply_restores_previous_owned_routes_and_preserves_foreign_routes() {
    let provider = Arc::new(FakeNetwork::default());
    let original_owned = route("192.0.2.0/24", TRAFFIC_MASQ_ROUTE_PROTOCOL);
    let foreign = route("203.0.113.0/24", 4);
    let dynamic = route("0.0.0.0/0", TRAFFIC_MASQ_DHCP_ROUTE_PROTOCOL);
    provider
        .routes
        .lock()
        .await
        .extend([original_owned.clone(), foreign.clone(), dynamic.clone()]);
    *provider.fail_next_add.lock().await = true;
    let manager = RouteManager::new(provider.clone());

    assert!(manager
        .apply(&[desired("198.51.100.0/24")], false)
        .await
        .is_err());
    let routes = provider.route_snapshot().await;
    assert!(routes.contains(&original_owned));
    assert!(routes.contains(&foreign));
    assert!(routes.contains(&dynamic));
    assert!(!routes.contains(&route("198.51.100.0/24", TRAFFIC_MASQ_ROUTE_PROTOCOL)));
}

#[tokio::test]
async fn preflight_foreign_collision_detection_rejects_matching_table_dest_and_metric() {
    let provider = Arc::new(FakeNetwork::default());
    provider
        .routes
        .lock()
        .await
        .push(route("198.51.100.0/24", 4));
    let manager = RouteManager::new(provider.clone());

    let err = manager
        .plan(&[desired("198.51.100.0/24")], false)
        .await
        .expect_err("should collide with foreign static route");
    let msg = err.to_string();
    assert!(
        msg.contains("destination prefix 198.51.100.0/24 in table 254 collides with existing route owned by [ext:static] with identical metric 100"),
        "unexpected error message: {msg}"
    );

    let mut non_colliding = desired("198.51.100.0/24");
    non_colliding.metric = Some(200);
    let plan = manager
        .plan(&[non_colliding], false)
        .await
        .expect("different metric must not collide");
    assert_eq!(plan.add.len(), 1);
    assert_eq!(plan.add[0].metric, Some(200));

    let mut different_table = desired("198.51.100.0/24");
    different_table.table = 100;
    let plan = manager
        .plan(&[different_table], false)
        .await
        .expect("different table must not collide");
    assert_eq!(plan.add.len(), 1);
    assert_eq!(plan.add[0].table, 100);
}

#[tokio::test]
async fn preflight_foreign_collision_detects_dhcp_and_kernel_routes() {
    let provider = Arc::new(FakeNetwork::default());
    provider.routes.lock().await.extend([
        route("0.0.0.0/0", TRAFFIC_MASQ_DHCP_ROUTE_PROTOCOL),
        route("10.0.0.0/24", 2),
    ]);
    let manager = RouteManager::new(provider.clone());

    let err = manager
        .plan(&[desired("0.0.0.0/0")], true)
        .await
        .expect_err("should collide with dhcp default route");
    let msg = err.to_string();
    assert!(
        msg.contains(
            "collides with existing route owned by traffic-masq (dhcp) with identical metric 100"
        ),
        "unexpected error message: {msg}"
    );

    let err = manager
        .plan(&[desired("10.0.0.0/24")], false)
        .await
        .expect_err("should collide with kernel route");
    let msg = err.to_string();
    assert!(
        msg.contains(
            "collides with existing route owned by [ext:kernel] with identical metric 100"
        ),
        "unexpected error message: {msg}"
    );
}

#[tokio::test]
async fn owned_routes_scopes_exclusively_to_proto_201() {
    let provider = Arc::new(FakeNetwork::default());
    provider.routes.lock().await.extend([
        route("192.0.2.0/24", TRAFFIC_MASQ_ROUTE_PROTOCOL),
        route("0.0.0.0/0", TRAFFIC_MASQ_DHCP_ROUTE_PROTOCOL),
        route("10.0.0.0/24", 2),
        route("172.16.0.0/24", 4),
    ]);
    let manager = RouteManager::new(provider);
    let snapshot = manager.snapshot().await.expect("snapshot");
    assert_eq!(snapshot.owned_routes.len(), 1);
    assert_eq!(
        snapshot.owned_routes[0].destination,
        "192.0.2.0/24".parse().unwrap()
    );
    assert_eq!(
        snapshot.owned_routes[0].protocol,
        TRAFFIC_MASQ_ROUTE_PROTOCOL
    );
}

#[tokio::test]
async fn route_matches_and_plan_treats_none_and_zero_metric_as_equivalent() {
    let provider = Arc::new(FakeNetwork::default());
    let mut existing = route("192.0.2.0/24", TRAFFIC_MASQ_ROUTE_PROTOCOL);
    existing.metric = None; // dumped from kernel with metric 0 omitted
    provider.routes.lock().await.push(existing);

    let manager = RouteManager::new(provider);
    let mut desired_zero = desired("192.0.2.0/24");
    desired_zero.metric = Some(0);

    // Should match existing route without generating any additions or deletions
    let plan = manager
        .plan(&[desired_zero], false)
        .await
        .expect("plan with metric 0 matching None");
    assert!(plan.is_empty(), "expected empty plan, got: {plan:?}");
}

#[tokio::test]
async fn rollback_treats_none_and_zero_metric_as_equivalent() {
    let provider = Arc::new(FakeNetwork::default());
    let mut snapshot_route = route("192.0.2.0/24", TRAFFIC_MASQ_ROUTE_PROTOCOL);
    snapshot_route.metric = None;
    let snapshot = RouteSnapshot {
        owned_routes: vec![snapshot_route],
    };

    let mut current_route = route("192.0.2.0/24", TRAFFIC_MASQ_ROUTE_PROTOCOL);
    current_route.metric = Some(0);
    provider.routes.lock().await.push(current_route);

    let manager = RouteManager::new(provider.clone());
    manager
        .rollback(&snapshot)
        .await
        .expect("rollback should succeed without changes");

    let routes = provider.routes.lock().await;
    assert_eq!(routes.len(), 1);
}

#[tokio::test]
async fn foreign_conflict_is_typed_and_preserves_the_route() {
    let provider = Arc::new(FakeNetwork::default());
    let foreign = route("198.51.100.0/24", 4);
    provider.routes.lock().await.push(foreign.clone());
    let manager = RouteManager::new(provider.clone());
    let error = manager
        .plan(&[desired("198.51.100.0/24")], true)
        .await
        .unwrap_err();
    assert!(error.downcast_ref::<ForeignRouteConflict>().is_some());
    assert_eq!(provider.route_snapshot().await, vec![foreign]);
}

#[tokio::test]
async fn repeated_route_rollback_does_not_duplicate_restored_objects() {
    let provider = Arc::new(FakeNetwork::default());
    let owned = route("198.51.100.0/24", TRAFFIC_MASQ_ROUTE_PROTOCOL);
    provider.routes.lock().await.push(owned.clone());
    let manager = RouteManager::new(provider.clone());
    let snapshot = manager.snapshot().await.unwrap();
    provider.routes.lock().await.clear();
    manager.rollback(&snapshot).await.unwrap();
    manager.rollback(&snapshot).await.unwrap();
    assert_eq!(provider.route_snapshot().await.len(), 1);
    assert!(route_info_matches(
        &provider.route_snapshot().await[0],
        &owned
    ));
}

#[tokio::test]
async fn cleanup_removed_routes_preserves_foreign_and_still_saved_missing_routes() {
    let provider = Arc::new(FakeNetwork::default());
    let kept = route("203.0.113.0/24", TRAFFIC_MASQ_ROUTE_PROTOCOL);
    let removed = route("198.51.100.0/24", TRAFFIC_MASQ_ROUTE_PROTOCOL);
    let foreign = route("192.0.2.0/24", 4);
    *provider.routes.lock().await = vec![kept.clone(), removed, foreign.clone()];
    let manager = RouteManager::new(provider.clone());
    let mut saved = desired("203.0.113.0/24");
    saved.output_interface = Some("missing0".into());
    manager.cleanup_removed(&[saved], false).await.unwrap();
    assert_eq!(provider.route_snapshot().await, vec![kept, foreign.clone()]);
    // A later committed removal is independent of other absent endpoints.
    manager.cleanup_removed(&[], false).await.unwrap();
    manager.cleanup_removed(&[], false).await.unwrap();
    assert_eq!(provider.route_snapshot().await, vec![foreign]);
}

#[tokio::test]
async fn cleanup_removed_routes_requires_permission_for_default_and_never_adds_routes() {
    let provider = Arc::new(FakeNetwork::default());
    let default = route("0.0.0.0/0", TRAFFIC_MASQ_ROUTE_PROTOCOL);
    *provider.routes.lock().await = vec![default.clone()];
    let manager = RouteManager::new(provider.clone());
    let mut missing = desired("203.0.113.0/24");
    missing.output_interface = Some("missing0".into());
    assert!(manager
        .cleanup_removed(&[missing.clone()], false)
        .await
        .is_err());
    assert_eq!(provider.route_snapshot().await, vec![default]);
    manager.cleanup_removed(&[missing], true).await.unwrap();
    assert!(provider.route_snapshot().await.is_empty());
}
