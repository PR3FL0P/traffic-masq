use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};
use async_trait::async_trait;

use crate::core::interface::{InterfaceChangePlan, InterfaceManager, InterfaceSnapshot};
use crate::core::route::{RouteManager, RoutePlan, RouteSnapshot};
use crate::core::router::{
    DhcpPlan, RouterDesired, RouterDhcpHealthReason, RouterSubsystems, WifiPlan, WifiSnapshot,
};
use crate::dhcp::client::{
    DhcpClientLeaseState, DhcpClientRunState, DhcpClientSpec, DhcpClientStatus,
    DhcpClientSupervisor,
};
use crate::dhcp::supervisor::{DhcpServiceSpec, DhcpSupervisor};
use crate::firewall::{
    NoopRouterDataplaneEventSink, RouterDataplaneEventSink, RouterDataplaneManager,
    RouterDataplanePlan, RouterDataplaneProvider, RouterDataplaneSnapshot,
};
use crate::wifi::{
    HostapdState, HostapdSupervisor, WifiApSpec, WifiClientSpec, WifiClientSupervisor, WpaState,
};

#[async_trait]
pub trait RouterDhcpClientRuntime: Send + Sync {
    async fn status(&self, interface: &str) -> Option<DhcpClientStatus>;
    async fn configure(&self, spec: DhcpClientSpec);
    async fn disable(&self, interface: &str) -> Result<()>;
    async fn verify_bound_lease(&self, status: &DhcpClientStatus) -> Result<()>;
}

#[async_trait]
impl RouterDhcpClientRuntime for DhcpClientSupervisor {
    async fn status(&self, interface: &str) -> Option<DhcpClientStatus> {
        self.status(interface).await
    }

    async fn configure(&self, spec: DhcpClientSpec) {
        self.configure(spec).await;
    }

    async fn disable(&self, interface: &str) -> Result<()> {
        self.disable(interface).await.map(|_| ())
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
    router_interfaces: Vec<String>,
    dhcp_client: Option<Arc<dyn RouterDhcpClientRuntime>>,
    access_points: Option<Arc<dyn RouterApRuntime>>,
    stations: Option<Arc<dyn RouterStaRuntime>>,
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
            router_interfaces,
            dhcp_client: None,
            access_points: None,
            stations: None,
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
            router_interfaces,
            dhcp_client: Some(dhcp_client),
            access_points: None,
            stations: None,
        }
    }
}

impl<P, E> ProductionRouterSubsystems<P, E>
where
    P: RouterDataplaneProvider,
    E: RouterDataplaneEventSink,
{
    fn scoped_names(&self, desired: &RouterDesired) -> Vec<String> {
        let mut names = self.router_interfaces.clone();
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
            router_interfaces,
            dhcp_client: None,
            access_points: None,
            stations: None,
        }
    }

    pub fn with_wifi_runtimes(
        mut self,
        stations: Arc<dyn RouterStaRuntime>,
        access_points: Arc<dyn RouterApRuntime>,
    ) -> Self {
        self.stations = Some(stations);
        self.access_points = Some(access_points);
        self
    }
}

#[async_trait]
impl<P, E> RouterSubsystems for ProductionRouterSubsystems<P, E>
where
    P: RouterDataplaneProvider + Send + Sync,
    E: RouterDataplaneEventSink + Send + Sync,
{
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
        let mut names = self.router_interfaces.clone();
        if let Some(spec) = &desired.uplink_wifi {
            if !names.contains(&spec.interface) {
                names.push(spec.interface.clone());
            }
        }
        names.sort();
        names.dedup();
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
        let mut names = self.router_interfaces.clone();
        names.extend(targets.keys().map(|name| (*name).to_owned()));
        names.sort();
        names.dedup();
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
        let mut interfaces: Vec<&str> = desired_by_interface.keys().copied().collect();
        for name in &self.router_interfaces {
            if !interfaces.contains(&name.as_str()) {
                interfaces.push(name.as_str());
            }
        }
        interfaces.sort_unstable();

        let mut plans = Vec::new();
        for name in interfaces {
            let current = self.dhcp.spec(name).await;
            let target = desired_by_interface.get(name).map(|spec| (*spec).clone());
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
        let mut snapshots = Vec::with_capacity(self.router_interfaces.len());
        for name in &self.router_interfaces {
            snapshots.push(self.interfaces.snapshot(name).await?);
        }
        Ok(snapshots)
    }

    async fn snapshot_uplink_wifi(&self) -> Result<Vec<WifiSnapshot<WifiClientSpec>>> {
        let Some(runtime) = &self.stations else {
            return Ok(Vec::new());
        };
        let mut snapshots = Vec::with_capacity(self.router_interfaces.len());
        for name in &self.router_interfaces {
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
        let mut snapshots = Vec::with_capacity(self.router_interfaces.len());
        for name in &self.router_interfaces {
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
        for name in &self.router_interfaces {
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
        for name in &self.router_interfaces {
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
        let names = self.scoped_names(desired);
        let mut interfaces = Vec::with_capacity(names.len());
        for name in &names {
            interfaces.push(self.interfaces.snapshot(name).await?);
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

        let uplink_dhcp = match (&self.dhcp_client, desired.uplink_dhcp.as_ref()) {
            (Some(runtime), Some(target)) => {
                runtime.status(&target.interface).await.map(|s| s.spec)
            }
            (Some(runtime), None) => {
                let mut current = None;
                for name in &names {
                    if let Some(status) = runtime.status(name).await {
                        current = Some(status.spec);
                        break;
                    }
                }
                current
            }
            (None, _) => None,
        };

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
            output_wifi,
            routes: self.routes.snapshot().await?,
            dhcp,
            dhcp_absent_interfaces,
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

    async fn apply_uplink_dhcp(&self, desired: Option<&DhcpClientSpec>) -> Result<()> {
        let Some(runtime) = &self.dhcp_client else {
            if desired.is_some() {
                bail!("embedded DHCP client runtime is unavailable");
            }
            return Ok(());
        };
        match desired {
            Some(spec) => runtime.configure(spec.clone()).await,
            None => {
                for name in &self.router_interfaces {
                    if runtime.status(name).await.is_some() {
                        runtime.disable(name).await?;
                    }
                }
            }
        }
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
            if !snapshot.is_empty() {
                bail!("uplink Wi-Fi runtime is unavailable");
            }
            return Ok(());
        };
        let mut errors = Vec::new();
        for entry in snapshot {
            let result = match &entry.spec {
                Some(spec) => runtime.configure(spec.clone()).await,
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
            if !snapshot.is_empty() {
                bail!("output Wi-Fi runtime is unavailable");
            }
            return Ok(());
        };
        let mut errors = Vec::new();
        for entry in snapshot {
            let result = match &entry.spec {
                Some(spec) => runtime.configure(spec.clone()).await,
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
        for name in &self.router_interfaces {
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
        let mut names = self.router_interfaces.clone();
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
        let unhealthy = self.dhcp.unhealthy_interfaces().await;
        for spec in &desired.dhcp {
            if unhealthy.iter().any(|name| name == &spec.interface) {
                bail!("DHCP service on {} is unhealthy", spec.interface);
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
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use async_trait::async_trait;
    use tokio::sync::Mutex;

    use crate::config::{
        AppConfig, DhcpInterfaceConfig, InterfaceConfig, InterfaceRole, RouterConfig, UplinkConfig,
        UplinkMode,
    };
    use crate::core::router::RouterDesired;
    use crate::firewall::{OwnedFirewallIntegrity, RouterDataplaneDesired};
    use crate::netlink::{
        Ipv4AddressInfo, Ipv4RouteInfo, Ipv4RouteSpec, NetworkInterface, NetworkProvider,
    };

    use super::*;

    #[derive(Debug, Default)]
    struct FakeNetworkProvider {
        interfaces: Mutex<HashMap<String, NetworkInterface>>,
        addresses: Mutex<HashMap<String, Vec<Ipv4AddressInfo>>>,
        routes: Mutex<Vec<Ipv4RouteInfo>>,
        fail_next_add_route: Mutex<bool>,
    }

    impl FakeNetworkProvider {
        async fn add_interface(&self, name: &str, index: u32, is_up: bool) {
            self.interfaces.lock().await.insert(
                name.to_string(),
                NetworkInterface {
                    is_wireless: false,
                    index,
                    name: name.to_string(),
                    is_up,
                    rx_bytes: 0,
                    tx_bytes: 0,
                },
            );
        }
    }

    #[async_trait]
    impl NetworkProvider for FakeNetworkProvider {
        async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
            Ok(self.interfaces.lock().await.values().cloned().collect())
        }

        async fn list_ipv4_addresses(&self, interface: &str) -> Result<Vec<Ipv4AddressInfo>> {
            Ok(self
                .addresses
                .lock()
                .await
                .get(interface)
                .cloned()
                .unwrap_or_default())
        }

        async fn set_link_up(&self, name: &str) -> Result<()> {
            self.interfaces
                .lock()
                .await
                .get_mut(name)
                .ok_or_else(|| anyhow::anyhow!("interface not found: {name}"))?
                .is_up = true;
            Ok(())
        }

        async fn set_link_down(&self, name: &str) -> Result<()> {
            self.interfaces
                .lock()
                .await
                .get_mut(name)
                .ok_or_else(|| anyhow::anyhow!("interface not found: {name}"))?
                .is_up = false;
            Ok(())
        }

        async fn add_ipv4_address(
            &self,
            interface: &str,
            address: Ipv4Addr,
            prefix_len: u8,
        ) -> Result<()> {
            let interface_index = self
                .interfaces
                .lock()
                .await
                .get(interface)
                .map_or(0, |value| value.index);
            self.addresses
                .lock()
                .await
                .entry(interface.to_string())
                .or_default()
                .push(Ipv4AddressInfo {
                    interface_index,
                    address,
                    prefix_len,
                });
            Ok(())
        }

        async fn delete_ipv4_address(
            &self,
            interface: &str,
            address: Ipv4Addr,
            prefix_len: u8,
        ) -> Result<()> {
            self.addresses
                .lock()
                .await
                .entry(interface.to_string())
                .or_default()
                .retain(|current| current.address != address || current.prefix_len != prefix_len);
            Ok(())
        }

        async fn list_ipv4_routes(&self) -> Result<Vec<Ipv4RouteInfo>> {
            Ok(self.routes.lock().await.clone())
        }

        async fn add_ipv4_route(&self, route: &Ipv4RouteSpec) -> Result<()> {
            let mut fail = self.fail_next_add_route.lock().await;
            if *fail {
                *fail = false;
                anyhow::bail!("injected route add failure");
            }
            drop(fail);
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
        let provider = Arc::new(FakeNetworkProvider::default());
        provider.add_interface("wan0", 1, true).await;
        provider.add_interface("lan0", 2, false).await;

        let interfaces = InterfaceManager::new(provider.clone());
        let routes = RouteManager::new(provider.clone());
        let dhcp = DhcpSupervisor::start(
            &AppConfig::default(),
            &crate::state::overrides::RuntimeOverrides::default(),
        )
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
        provider.add_interface("mgmt0", 3, true).await;
        provider.addresses.lock().await.insert(
            "mgmt0".to_string(),
            vec![Ipv4AddressInfo {
                interface_index: 3,
                address: Ipv4Addr::new(10, 0, 0, 1),
                prefix_len: 24,
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
}
