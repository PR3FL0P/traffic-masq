//! Router startup wiring and temporary route/dataplane baseline restoration.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::core::interface::InterfaceManager;
use crate::core::override_manager::RuntimeOverrideManager;
use crate::core::ownership::AddressOwnershipJournal;
use crate::core::route::{RouteManager, RouteSnapshot};
use crate::core::router::{RouterDesired, RouterManager};
use crate::core::router_subsystems::{ProductionRouterSubsystems, VpnChainDeps};
use crate::core::router_transaction::RouterTransactionCoordinator;
use crate::dhcp::client::DhcpClientSupervisor;
use crate::dhcp::supervisor::DhcpSupervisor;
use crate::firewall::{
    missing_router_dataplane_interface, Ipv4ForwardingBackend, LinuxRouterDataplaneProvider,
    NftCommandExecutor, NftablesBackend, ProcSysIpv4ForwardingIo, RouterDataplaneManager,
    RouterDataplaneProvider, RouterDataplaneSnapshot,
};
use crate::netlink::NetworkProvider;
use crate::vpn::{LazyNetlinkVpnProvider, VpnProvider, WireGuardProfileStore};
use crate::wifi::{HostapdSupervisor, WifiClientSupervisor};

type ProductionDataplaneProvider = LinuxRouterDataplaneProvider<
    ProcSysIpv4ForwardingIo,
    NftCommandExecutor,
    Arc<dyn NetworkProvider>,
>;

pub(super) struct RouterRuntimeState<P: RouterDataplaneProvider> {
    routes: RouteManager,
    route_snapshot: RouteSnapshot,
    pub(super) dataplane: RouterDataplaneManager<P>,
    pub(super) dataplane_snapshot: RouterDataplaneSnapshot,
}

pub(super) async fn apply_router_dataplane<P>(
    desired: &RouterDesired,
    network_provider: Arc<dyn NetworkProvider>,
    dataplane_provider: P,
) -> Result<RouterRuntimeState<P>>
where
    P: RouterDataplaneProvider + Send + Sync,
{
    let routes = RouteManager::new(network_provider);
    let route_snapshot = routes
        .apply(&desired.routes, desired.allow_default_route_change)
        .await
        .context("failed to apply router-owned routes")?;

    let dataplane = RouterDataplaneManager::new(dataplane_provider);
    let plan = match dataplane.plan_target(desired.dataplane.clone()).await {
        Ok(plan) => plan,
        Err(error) => {
            if let Err(rollback_error) = routes.rollback(&route_snapshot).await {
                tracing::error!(
                    %rollback_error,
                    "failed to rollback router routes after dataplane planning failure"
                );
            }
            return Err(error).context("failed to plan router dataplane");
        }
    };
    let dataplane_snapshot = match dataplane.apply(&plan).await {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let route_rollback = routes.rollback(&route_snapshot).await;
            if let Err(rollback_error) = &route_rollback {
                tracing::error!(
                    %rollback_error,
                    "failed to rollback router routes after dataplane apply failure"
                );
            }
            if route_rollback.is_ok() {
                if let Some(missing) = missing_router_dataplane_interface(&error) {
                    tracing::warn!(
                        interface = %missing.interface,
                        role = %missing.role,
                        error = %format!("{error:#}"),
                        hint = "Check ip link; reconnect the adapter or update the interface name in router configuration. Retrying automatically when it appears.",
                        "router dataplane startup convergence is deferred until the interface appears; daemon startup will continue"
                    );
                    return Ok(RouterRuntimeState {
                        routes,
                        route_snapshot,
                        dataplane,
                        dataplane_snapshot: plan.snapshot,
                    });
                }
            }
            return Err(error).context("failed to apply router dataplane");
        }
    };

    Ok(RouterRuntimeState {
        routes,
        route_snapshot,
        dataplane,
        dataplane_snapshot,
    })
}

/// Repair must not snapshot/plan absent interface dependencies, including
/// endpoints used only by explicit forwarding rules or router-owned routes.
/// The runtime interface converger and dataplane reconciler finish this work
/// when the kernel announces their return. Crash recovery is never skipped.
pub(super) async fn missing_router_repair_interfaces(
    desired: &RouterDesired,
    network: &dyn NetworkProvider,
) -> Result<Vec<String>> {
    let observed = network
        .list_interfaces()
        .await
        .context("failed to observe interfaces before router startup repair")?;
    Ok(desired
        .required_existing_interfaces()
        .into_iter()
        .filter(|name| !observed.iter().any(|interface| interface.name == *name))
        .map(str::to_owned)
        .collect())
}

pub(super) async fn restore_router_dataplane<P>(state: &RouterRuntimeState<P>) -> Result<()>
where
    P: RouterDataplaneProvider + Send + Sync,
{
    let mut errors = Vec::new();
    if let Err(error) = state.dataplane.rollback(&state.dataplane_snapshot).await {
        errors.push(format!("router dataplane rollback failed: {error:#}"));
    }
    if let Err(error) = state.routes.rollback(&state.route_snapshot).await {
        errors.push(format!("router route rollback failed: {error:#}"));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        bail!(errors.join("; "))
    }
}

pub(super) async fn rollback_router_dataplane<P>(state: &RouterRuntimeState<P>)
where
    P: RouterDataplaneProvider + Send + Sync,
{
    if let Err(error) = restore_router_dataplane(state).await {
        tracing::error!(%error, "failed to rollback router dataplane during daemon shutdown");
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn production_router_coordinator(
    desired: &RouterDesired,
    vpn_store_dir: &Path,
    state_dir: &Path,
    network: Arc<dyn NetworkProvider>,
    journal: AddressOwnershipJournal,
    dhcp: DhcpSupervisor,
    dhcp_client: DhcpClientSupervisor,
    wifi_client: Option<WifiClientSupervisor>,
    wifi: Option<HostapdSupervisor>,
    overrides: RuntimeOverrideManager,
    rollback_timeout: Duration,
) -> Result<RouterTransactionCoordinator> {
    let interfaces = InterfaceManager::new(network.clone(), journal);
    let routes = RouteManager::new(network.clone());
    let dataplane_provider = production_dataplane_provider(network.clone());
    let dataplane = RouterDataplaneManager::new(dataplane_provider);
    let router_interfaces = desired
        .interfaces
        .iter()
        .map(|interface| interface.name.clone())
        .collect();
    let mut subsystems = ProductionRouterSubsystems::new_with_dhcp_client(
        interfaces,
        routes,
        dhcp,
        dataplane,
        router_interfaces,
        Arc::new(dhcp_client),
    );
    // Wi-Fi runtimes are attached when they exist. A missing runtime is not
    // fatal here: the intent this coordinator will be asked to apply is not
    // known yet, and refusing now would judge it by the intent that happened to
    // exist at boot. `plan_uplink_wifi` / `plan_output_wifi` already reject a
    // Wi-Fi intent without a runtime, at the point where the intent is real.
    if let Some(wifi_client) = wifi_client {
        subsystems = subsystems.with_station_runtime(Arc::new(wifi_client));
    }
    if let Some(wifi) = wifi {
        subsystems = subsystems.with_access_point_runtime(Arc::new(wifi));
    }

    // Keep VPN control-plane dependencies available for runtime enablement.
    // RouterDesired still rejects a VPN chain while VPN is disabled.
    {
        let vpn_provider: Arc<dyn VpnProvider> = Arc::new(LazyNetlinkVpnProvider::new());
        subsystems = subsystems.with_vpn_chain(VpnChainDeps {
            vpn_provider,
            wireguard_store: WireGuardProfileStore::new(vpn_store_dir.to_path_buf()),
            state_dir: state_dir.to_path_buf(),
            network,
            nft_executor: Arc::new(NftCommandExecutor),
        });
    }

    let manager = RouterManager::new(Arc::new(subsystems));
    Ok(RouterTransactionCoordinator::new(
        manager,
        overrides,
        rollback_timeout,
    ))
}

pub(super) fn production_dataplane_provider(
    network: Arc<dyn NetworkProvider>,
) -> ProductionDataplaneProvider {
    LinuxRouterDataplaneProvider::new(
        Ipv4ForwardingBackend::new(ProcSysIpv4ForwardingIo),
        NftablesBackend::new(NftCommandExecutor),
        network,
    )
}
