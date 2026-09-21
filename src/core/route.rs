use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::{OwnedIpv4RouteConfig, RouterConfig};
use crate::netlink::{Ipv4RouteInfo, Ipv4RouteSpec, NetworkProvider, TRAFFIC_MASQ_ROUTE_PROTOCOL};

#[derive(Debug, thiserror::Error)]
#[error("blocked/degraded dataplane: destination prefix {destination} in table {table} collides with existing route owned by {owner} with identical metric {metric}; invariant=preserve_foreign_route; operation=plan_route; metadata_safe_to_remove=false")]
pub struct ForeignRouteConflict {
    pub destination: ipnet::Ipv4Net,
    pub table: u32,
    pub metric: u32,
    pub owner: String,
}

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    /// Compare desired routes with observed routes and reject protected-route conflicts.
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
                return Err(ForeignRouteConflict {
                    destination: desired_route.destination,
                    table: desired_route.table,
                    metric: desired_route.metric.unwrap_or(0),
                    owner: owner.to_string(),
                }
                .into());
            }
        }

        let plan = RoutePlan { add, delete };
        if plan.changes_default_route() && !allow_default_route_change {
            bail!("refusing to change an IPv4 default route without explicit confirmation");
        }
        Ok(plan)
    }

    /// Report missing or stale daemon-owned routes against the desired route set.
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

    /// Plan and apply route changes, returning the prior owned-route snapshot.
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

    /// Restore daemon-owned routes from the snapshot while preserving foreign routes.
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
                // Another writer may have already completed this deletion.
                let remaining = self.owned_routes().await?;
                if remaining
                    .iter()
                    .any(|entry| route_info_matches(entry, route))
                {
                    errors.push(format!("operation=delete_route; object={}; invariant=restore_owned_routes: {error}", route.destination));
                }
            }
        }

        let current = self.owned_routes().await?;
        for route in snapshot
            .owned_routes
            .iter()
            .filter(|route| !current.iter().any(|c| route_info_matches(c, route)))
        {
            if let Err(error) = self.provider.add_ipv4_route(&spec_from_info(route)).await {
                let observed = self.owned_routes().await?;
                if !observed
                    .iter()
                    .any(|entry| route_info_matches(entry, route))
                {
                    errors.push(format!("operation=restore_route; object={}; invariant=restore_owned_routes: {error}", route.destination));
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            bail!("route rollback was incomplete: {}", errors.join("; "))
        }
    }

    /// Apply the planned route additions and deletions through the network provider.
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
mod tests;
