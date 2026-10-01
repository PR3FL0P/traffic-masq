use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;

mod vpn_chain;

pub use vpn_chain::VpnChainDeps;
use vpn_chain::VpnChainRuntime;

use crate::core::interface::{InterfaceChangePlan, InterfaceManager, InterfaceSnapshot};
use crate::core::route::{RouteManager, RoutePlan, RouteSnapshot};
use crate::core::router::{
    DhcpClientSnapshot, DhcpPlan, RouterDesired, RouterDhcpHealthReason, RouterSubsystemPlan,
    RouterSubsystems, VpnChainPlan, VpnChainSnapshot, WifiPlan, WifiSnapshot,
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
    vpn_chain: VpnChainRuntime,
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
        Self::with_event_sink(interfaces, routes, dhcp, dataplane, router_interfaces)
    }

    pub fn new_with_dhcp_client(
        interfaces: InterfaceManager,
        routes: RouteManager,
        dhcp: DhcpSupervisor,
        dataplane: RouterDataplaneManager<P, NoopRouterDataplaneEventSink>,
        router_interfaces: Vec<String>,
        dhcp_client: Arc<dyn RouterDhcpClientRuntime>,
    ) -> Self {
        let mut subsystems = Self::new(interfaces, routes, dhcp, dataplane, router_interfaces);
        subsystems.dhcp_client = Some(dhcp_client);
        subsystems
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
            vpn_chain: VpnChainRuntime::new(),
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
        self.vpn_chain.set_deps(deps);
        self
    }
}

impl<P, E> ProductionRouterSubsystems<P, E>
where
    P: RouterDataplaneProvider,
    E: RouterDataplaneEventSink,
{
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
}

#[async_trait]
impl<P, E> RouterSubsystems for ProductionRouterSubsystems<P, E>
where
    P: RouterDataplaneProvider + Send + Sync,
    E: RouterDataplaneEventSink + Send + Sync,
{
    async fn prepare_recovery(&self, current: &RouterDesired) -> Result<()> {
        self.vpn_chain.prepare_recovery(current).await
    }

    async fn adopt_router_interfaces(&self, desired: &RouterDesired) {
        self.adopt(desired).await;
    }

    async fn retain_router_interfaces(&self, interfaces: &[String]) {
        self.retain(interfaces).await;
    }

    async fn plan_for(&self, desired: &RouterDesired) -> Result<RouterSubsystemPlan> {
        let interfaces = self.plan_interfaces(desired).await?;
        let uplink_wifi = self.plan_uplink_wifi(desired).await?;
        let output_wifi = self.plan_output_wifi(desired).await?;
        let routes = self.plan_routes(desired).await?;
        let dhcp = self.plan_dhcp(desired).await?;
        let vpn_chain = self.plan_vpn_chain(desired).await?;
        let dataplane = self.plan_dataplane(desired).await?;
        Ok(RouterSubsystemPlan {
            interfaces,
            uplink_wifi,
            output_wifi,
            routes,
            dhcp,
            vpn_chain,
            dataplane,
        })
    }

    async fn plan_routes(&self, desired: &RouterDesired) -> Result<RoutePlan> {
        self.routes
            .plan(&desired.routes, desired.allow_default_route_change)
            .await
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
            vpn_chain: self.vpn_chain.snapshot().await,
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
                errors.push(error.context(entry.name.clone()));
            }
        }
        crate::core::recovery_control::aggregate(errors, "interface rollback was incomplete")
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
        self.vpn_chain.plan_vpn_chain(desired).await
    }

    async fn apply_vpn_chain(&self, plan: &VpnChainPlan) -> Result<()> {
        self.vpn_chain.apply_vpn_chain(plan).await
    }

    async fn rollback_vpn_chain(&self, snapshot: &VpnChainSnapshot) -> Result<()> {
        self.vpn_chain.rollback_vpn_chain(snapshot).await
    }

    async fn health_vpn_chain(&self, desired: &RouterDesired) -> Result<()> {
        self.vpn_chain.health_vpn_chain(desired).await
    }
}

#[cfg(test)]
mod tests;
