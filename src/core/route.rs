use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::{OwnedIpv4RouteConfig, RouterConfig};
use crate::netlink::{Ipv4RouteInfo, Ipv4RouteSpec, NetworkProvider, TRAFFIC_MASQ_ROUTE_PROTOCOL};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedIpv4Route {
    pub destination: ipnet::Ipv4Net,
    pub gateway: Option<Ipv4Addr>,
    pub output_interface: Option<String>,
    pub table: u32,
    pub metric: Option<u32>,
}

impl From<&OwnedIpv4RouteConfig> for ManagedIpv4Route {
    fn from(route: &OwnedIpv4RouteConfig) -> Self {
        Self {
            destination: route.destination,
            gateway: route.gateway,
            output_interface: route.output_interface.clone(),
            table: route.table,
            metric: route.metric,
        }
    }
}

/// The routes the router should own, given its configuration.
///
/// A free function here rather than a method on `RouterConfig`, because the
/// result is a domain type of the route manager. Hanging it off the config type
/// made `config` — the module almost everything else depends on — depend on
/// `core` in return, which is a cycle at the very bottom of the stack.
pub fn desired_owned_routes(router: &RouterConfig) -> Vec<ManagedIpv4Route> {
    if !router.enabled {
        return Vec::new();
    }
    router.owned_routes.iter().map(Into::into).collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutePlan {
    pub add: Vec<Ipv4RouteSpec>,
    pub delete: Vec<Ipv4RouteInfo>,
}

impl RoutePlan {
    pub fn is_empty(&self) -> bool {
        self.add.is_empty() && self.delete.is_empty()
    }

    pub fn changes_default_route(&self) -> bool {
        self.add
            .iter()
            .any(|route| route.destination.prefix_len() == 0)
            || self
                .delete
                .iter()
                .any(|route| route.destination.prefix_len() == 0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RouteDrift {
    Missing { route: Ipv4RouteSpec },
    Unexpected { route: Ipv4RouteInfo },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteHealth {
    pub drift: Vec<RouteDrift>,
}

impl RouteHealth {
    pub fn is_healthy(&self) -> bool {
        self.drift.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RouteSnapshot {
    owned_routes: Vec<Ipv4RouteInfo>,
}

impl RouteSnapshot {
    pub fn empty() -> Self {
        Self {
            owned_routes: Vec::new(),
        }
    }
}

#[derive(Clone)]
pub struct RouteManager {
    provider: Arc<dyn NetworkProvider>,
}

impl RouteManager {
    pub fn new(provider: Arc<dyn NetworkProvider>) -> Self {
        Self { provider }
    }

    pub async fn snapshot(&self) -> Result<RouteSnapshot> {
        let owned_routes = self.owned_routes().await?;
        Ok(RouteSnapshot { owned_routes })
    }

    pub async fn plan(
        &self,
        desired: &[ManagedIpv4Route],
        allow_default_route_change: bool,
    ) -> Result<RoutePlan> {
        let all_routes = self.provider.list_ipv4_routes().await?;
        let mut current: Vec<_> = all_routes
            .iter()
            .filter(|route| route.protocol == TRAFFIC_MASQ_ROUTE_PROTOCOL)
            .cloned()
            .collect();
        sort_routes(&mut current);

        let desired = self.resolve_desired(desired).await?;

        let mut add: Vec<_> = desired
            .iter()
            .filter(|route| !current.iter().any(|current| route_matches(current, route)))
            .cloned()
            .collect();
        let mut delete: Vec<_> = current
            .into_iter()
            .filter(|route| !desired.iter().any(|desired| route_matches(route, desired)))
            .collect();
        sort_specs(&mut add);
        sort_routes(&mut delete);

        let foreign_routes: HashMap<(u32, ipnet::Ipv4Net, u32), crate::netlink::RouteOwner> =
            all_routes
                .iter()
                .filter(|r| r.protocol != TRAFFIC_MASQ_ROUTE_PROTOCOL)
                .map(|r| {
                    (
                        (r.table, r.destination.trunc(), r.metric.unwrap_or(0)),
                        r.owner(),
                    )
                })
                .collect();

        for desired_route in &add {
            let key = (
                desired_route.table,
                desired_route.destination.trunc(),
                desired_route.metric.unwrap_or(0),
            );
            if let Some(owner) = foreign_routes.get(&key) {
                bail!(
                    "destination prefix {} in table {} collides with existing route owned by {} with identical metric {}",
                    desired_route.destination,
                    desired_route.table,
                    owner,
                    desired_route.metric.unwrap_or(0)
                );
            }
        }

        let plan = RoutePlan { add, delete };
        if plan.changes_default_route() && !allow_default_route_change {
            bail!("refusing to change an IPv4 default route without explicit confirmation");
        }
        Ok(plan)
    }

    pub async fn health(&self, desired: &[ManagedIpv4Route]) -> Result<RouteHealth> {
        let plan = self.plan(desired, true).await?;
        let drift = plan
            .add
            .into_iter()
            .map(|route| RouteDrift::Missing { route })
            .chain(
                plan.delete
                    .into_iter()
                    .map(|route| RouteDrift::Unexpected { route }),
            )
            .collect();
        Ok(RouteHealth { drift })
    }

    pub async fn apply(
        &self,
        desired: &[ManagedIpv4Route],
        allow_default_route_change: bool,
    ) -> Result<RouteSnapshot> {
        let snapshot = self.snapshot().await?;
        let plan = self.plan(desired, allow_default_route_change).await?;
        if let Err(error) = self.apply_plan(&plan).await {
            return match self.rollback(&snapshot).await {
                Ok(()) => Err(anyhow::anyhow!(
                    "route apply failed; previous owned routes were restored: {error}"
                )),
                Err(rollback_error) => Err(anyhow::anyhow!(
                    "route apply failed: {error}; route rollback also failed: {rollback_error}"
                )),
            };
        }
        Ok(snapshot)
    }

    pub async fn rollback(&self, snapshot: &RouteSnapshot) -> Result<()> {
        let current = self.owned_routes().await?;
        let mut errors = Vec::new();

        for route in current.iter().filter(|route| {
            !snapshot
                .owned_routes
                .iter()
                .any(|s| route_info_matches(s, route))
        }) {
            if let Err(error) = self.provider.delete_ipv4_route(route).await {
                errors.push(format!("failed to delete {}: {error}", route.destination));
            }
        }

        let current = self.owned_routes().await?;
        for route in snapshot
            .owned_routes
            .iter()
            .filter(|route| !current.iter().any(|c| route_info_matches(c, route)))
        {
            if let Err(error) = self.provider.add_ipv4_route(&spec_from_info(route)).await {
                errors.push(format!("failed to restore {}: {error}", route.destination));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            bail!("route rollback was incomplete: {}", errors.join("; "))
        }
    }

    pub async fn apply_plan(&self, plan: &RoutePlan) -> Result<()> {
        for route in &plan.delete {
            self.provider
                .delete_ipv4_route(route)
                .await
                .with_context(|| format!("failed to delete route {}", route.destination))?;
        }
        for route in &plan.add {
            self.provider
                .add_ipv4_route(route)
                .await
                .with_context(|| format!("failed to add route {}", route.destination))?;
        }
        Ok(())
    }

    async fn owned_routes(&self) -> Result<Vec<Ipv4RouteInfo>> {
        let mut routes: Vec<_> = self
            .provider
            .list_ipv4_routes()
            .await?
            .into_iter()
            .filter(|route| route.protocol == TRAFFIC_MASQ_ROUTE_PROTOCOL)
            .collect();
        sort_routes(&mut routes);
        Ok(routes)
    }

    async fn resolve_desired(&self, desired: &[ManagedIpv4Route]) -> Result<Vec<Ipv4RouteSpec>> {
        let interfaces: HashMap<_, _> = self
            .provider
            .list_interfaces()
            .await?
            .into_iter()
            .map(|interface| (interface.name, interface.index))
            .collect();
        let mut resolved = Vec::with_capacity(desired.len());

        for route in desired {
            let output_interface_index =
                match route.output_interface.as_deref() {
                    Some(name) => Some(*interfaces.get(name).ok_or_else(|| {
                        anyhow::anyhow!("route output interface not found: {name}")
                    })?),
                    None => None,
                };
            let spec = Ipv4RouteSpec {
                destination: route.destination.trunc(),
                gateway: route.gateway,
                output_interface_index,
                table: route.table,
                metric: route.metric,
                protocol: TRAFFIC_MASQ_ROUTE_PROTOCOL,
            };
            spec.validate()?;
            if resolved.iter().any(|r: &Ipv4RouteSpec| {
                r.table == spec.table
                    && r.destination == spec.destination
                    && r.metric.unwrap_or(0) == spec.metric.unwrap_or(0)
            }) {
                bail!("duplicate managed IPv4 route: {}", route.destination);
            }
            resolved.push(spec);
        }

        sort_specs(&mut resolved);
        Ok(resolved)
    }
}

fn route_matches(info: &Ipv4RouteInfo, spec: &Ipv4RouteSpec) -> bool {
    info.destination == spec.destination
        && info.gateway == spec.gateway
        && info.output_interface_index == spec.output_interface_index
        && info.table == spec.table
        && info.metric.unwrap_or(0) == spec.metric.unwrap_or(0)
        && info.protocol == spec.protocol
}

fn route_info_matches(a: &Ipv4RouteInfo, b: &Ipv4RouteInfo) -> bool {
    a.destination == b.destination
        && a.gateway == b.gateway
        && a.output_interface_index == b.output_interface_index
        && a.table == b.table
        && a.metric.unwrap_or(0) == b.metric.unwrap_or(0)
        && a.protocol == b.protocol
}

fn spec_from_info(info: &Ipv4RouteInfo) -> Ipv4RouteSpec {
    Ipv4RouteSpec {
        destination: info.destination,
        gateway: info.gateway,
        output_interface_index: info.output_interface_index,
        table: info.table,
        metric: info.metric,
        protocol: info.protocol,
    }
}

fn sort_specs(routes: &mut [Ipv4RouteSpec]) {
    routes.sort_by_key(|route| {
        (
            route.table,
            u32::from(route.destination.network()),
            route.destination.prefix_len(),
            route.gateway,
            route.output_interface_index,
            route.metric.unwrap_or(0),
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
            route.metric.unwrap_or(0),
            route.protocol,
            route.scope,
        )
    });
}

#[cfg(test)]
mod tests {
    use crate::netlink::AddressOwnership;
    use std::net::Ipv4Addr;

    use async_trait::async_trait;
    use tokio::sync::Mutex;

    use crate::netlink::{Ipv4AddressInfo, NetworkInterface, TRAFFIC_MASQ_DHCP_ROUTE_PROTOCOL};

    use super::*;

    fn router_with_one_owned_route() -> RouterConfig {
        RouterConfig {
            forwarding: None,
            vpn_chain: Vec::new(),
            enabled: true,
            uplink: None,
            owned_routes: vec![OwnedIpv4RouteConfig {
                destination: "203.0.113.0/24".parse().expect("route destination"),
                gateway: None,
                output_interface: Some("wan0".to_string()),
                table: 254,
                metric: Some(100),
            }],
            allow_default_route_change: false,
        }
    }

    #[test]
    fn router_config_builds_effective_route_desired_state() {
        let mut router = router_with_one_owned_route();

        let desired = desired_owned_routes(&router);
        assert_eq!(desired.len(), 1);
        assert_eq!(desired[0].destination, router.owned_routes[0].destination);
        assert_eq!(desired[0].output_interface.as_deref(), Some("wan0"));

        // A disabled router owns nothing, but the configuration it would use if
        // re-enabled is left untouched.
        router.enabled = false;
        assert!(desired_owned_routes(&router).is_empty());
        assert_eq!(router.owned_routes.len(), 1);
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
        provider.routes.lock().await.extend([
            original_owned.clone(),
            foreign.clone(),
            dynamic.clone(),
        ]);
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
            msg.contains("collides with existing route owned by traffic-masq (dhcp) with identical metric 100"),
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
}
