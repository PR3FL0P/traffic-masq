//! Runtime interface convergence and network process integrity workers.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use futures_util::{stream::FuturesUnordered, FutureExt, StreamExt};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{self, MissedTickBehavior};

use crate::config::{AppConfig, InterfaceConfig, VpnPolicyMode};
use crate::core::desired::DesiredNetworkState;
use crate::core::interface::InterfaceManager;
use crate::core::mutation::NetworkMutationGate;
use crate::core::override_manager::RuntimeOverrideManager;
use crate::core::ownership::AddressOwnershipJournal;
use crate::core::router::RouterDesired;
use crate::core::router_transaction::RouterTransactionCoordinator;
use crate::core::vpn_policy_manager::{vpn_policy_desired, vpn_policy_teardown_target};
use crate::dhcp::client::{DhcpClientSpec, DhcpClientSupervisor};
use crate::dhcp::supervisor::{DhcpServiceSpec, DhcpSupervisor};
use crate::firewall::missing_router_dataplane_interface;
use crate::netlink::events::KernelEvent;
use crate::netlink::{AddressOwner, Ipv4AddressInfo, NetworkInterface, NetworkProvider};
use crate::wifi::{HostapdSupervisor, WifiClientSupervisor};

use super::{shutdown_requested, ProductionVpnPolicyManager};

const PROCESS_LIVENESS_INTERVAL: Duration = Duration::from_secs(1);
const ROUTER_DATAPLANE_INTEGRITY_INTERVAL: Duration = Duration::from_secs(15);
const NETWORK_RECONCILE_RETRY_BASE: Duration = Duration::from_secs(1);
const NETWORK_RECONCILE_RETRY_MAX: Duration = Duration::from_secs(30);

#[async_trait]
pub(super) trait DhcpRuntimeReconciler: Send + Sync {
    async fn spec(&self, interface: &str) -> Option<DhcpServiceSpec>;
    async fn disable(&self, interface: &str) -> Result<Option<DhcpServiceSpec>>;
    async fn binding_stale(&self, interface: &str) -> Result<bool>;
    async fn reconcile(&self, spec: DhcpServiceSpec) -> Result<()>;

    async fn ensure_runtime_alive(&self) -> Result<bool>;
}

#[async_trait]
impl DhcpRuntimeReconciler for DhcpSupervisor {
    async fn spec(&self, interface: &str) -> Option<DhcpServiceSpec> {
        self.spec(interface).await
    }

    async fn disable(&self, interface: &str) -> Result<Option<DhcpServiceSpec>> {
        self.disable(interface).await
    }

    async fn binding_stale(&self, interface: &str) -> Result<bool> {
        self.binding_stale(interface).await
    }

    async fn reconcile(&self, spec: DhcpServiceSpec) -> Result<()> {
        self.reconcile(spec).await
    }

    async fn ensure_runtime_alive(&self) -> Result<bool> {
        self.ensure_runtime_alive().await
    }
}

#[async_trait]
pub(super) trait DhcpClientRuntimeReconciler: Send + Sync {
    async fn specs(&self) -> Vec<DhcpClientSpec>;
    async fn disable(&self, interface: &str) -> Result<Option<DhcpClientSpec>>;
    async fn reconcile(&self, spec: DhcpClientSpec, link_ready: bool) -> Result<()>;
    async fn verify_ready(&self, _interface: &str) -> Result<()> {
        Ok(())
    }
    async fn ensure_alive(&self) -> Result<bool>;
    async fn ensure_alive_for_config(&self, _config: &AppConfig) -> Result<bool> {
        self.ensure_alive().await
    }
}

#[async_trait]
impl DhcpClientRuntimeReconciler for DhcpClientSupervisor {
    async fn specs(&self) -> Vec<DhcpClientSpec> {
        self.statuses()
            .await
            .into_iter()
            .map(|status| status.spec)
            .collect()
    }

    async fn disable(&self, interface: &str) -> Result<Option<DhcpClientSpec>> {
        self.disable(interface).await
    }

    async fn reconcile(&self, spec: DhcpClientSpec, link_ready: bool) -> Result<()> {
        let name = spec.interface.clone();
        self.reconcile_with_link_ready(spec, link_ready).await;
        let status = self
            .status(&name)
            .await
            .context("DHCP client disappeared")?;
        if let crate::dhcp::client::DhcpClientRunState::Degraded { reason } = status.state {
            bail!("DHCP client on {name} is degraded: {reason}");
        }
        Ok(())
    }

    async fn verify_ready(&self, interface: &str) -> Result<()> {
        self.wait_until_ready(interface).await
    }

    async fn ensure_alive(&self) -> Result<bool> {
        self.ensure_alive().await
    }
    async fn ensure_alive_for_config(&self, config: &AppConfig) -> Result<bool> {
        DhcpClientSupervisor::ensure_alive_for_config(self, config).await
    }
}

#[async_trait]
pub(super) trait WifiRuntimeReconciler: Send + Sync {
    async fn ensure_alive(&self) -> Result<bool>;
    async fn ensure_alive_for_config(&self, _config: &AppConfig) -> Result<bool> {
        self.ensure_alive().await
    }

    async fn reconcile_interface(&self, _interface: &str, _config: &InterfaceConfig) -> Result<()> {
        Ok(())
    }

    async fn association_ready(&self, _interface: &str) -> Option<bool> {
        None
    }
    async fn association_ready_for_config(
        &self,
        interface: &str,
        _config: &AppConfig,
    ) -> Option<bool> {
        self.association_ready(interface).await
    }
}

#[async_trait]
impl WifiRuntimeReconciler for HostapdSupervisor {
    async fn ensure_alive(&self) -> Result<bool> {
        Ok(HostapdSupervisor::ensure_alive(self).await?)
    }

    async fn reconcile_interface(&self, interface: &str, config: &InterfaceConfig) -> Result<()> {
        self.reconcile_interface_config(interface, config).await
    }
    async fn ensure_alive_for_config(&self, config: &AppConfig) -> Result<bool> {
        Ok(HostapdSupervisor::ensure_alive_for_config(self, config).await?)
    }
}

#[async_trait]
impl WifiRuntimeReconciler for WifiClientSupervisor {
    async fn ensure_alive(&self) -> Result<bool> {
        Ok(WifiClientSupervisor::ensure_alive(self).await?)
    }

    async fn reconcile_interface(&self, interface: &str, config: &InterfaceConfig) -> Result<()> {
        self.reconcile_interface_config(interface, config).await
    }

    async fn association_ready(&self, interface: &str) -> Option<bool> {
        self.status(interface)
            .await
            .map(|status| status.wpa_state.is_connected())
    }
    async fn ensure_alive_for_config(&self, config: &AppConfig) -> Result<bool> {
        Ok(WifiClientSupervisor::ensure_alive_for_config(self, config).await?)
    }

    async fn association_ready_for_config(
        &self,
        interface: &str,
        config: &AppConfig,
    ) -> Option<bool> {
        let expected = config
            .network
            .interfaces
            .get(interface)
            .and_then(|config| {
                crate::wifi::WifiClientSpec::from_interface_config(interface, config)
                    .ok()
                    .flatten()
            })?;
        self.status(interface)
            .await
            .filter(|status| status.spec == expected)
            .map(|status| status.wpa_state.is_connected())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DhcpReconcileAction {
    Keep,
    Configure(DhcpServiceSpec),
    Disable,
}

fn log_router_dataplane_convergence_error(error: &anyhow::Error) {
    if let Some(missing) = missing_router_dataplane_interface(error) {
        tracing::warn!(
            interface = %missing.interface,
            role = %missing.role,
            error = %format!("{error:#}"),
            hint = "Check ip link; reconnect the adapter or update the interface name in router configuration. Retrying automatically when it appears.",
            "router dataplane convergence is deferred until the interface appears; daemon remains operational"
        );
    } else {
        tracing::warn!(error = %format!("{error:#}"), "router dataplane convergence failed");
    }
}

pub(super) async fn reconcile_router_dataplane(
    router: &RouterTransactionCoordinator,
    desired: RouterDesired,
    network: &dyn NetworkProvider,
) -> Result<()> {
    // A missing adapter cannot be repaired by writes. Check before opening a
    // repair journal: compensation would otherwise reconfigure healthy LAN
    // services and generate new kernel events on every unsuccessful pass.
    let missing =
        super::router_startup::missing_router_repair_interfaces(&desired, network).await?;
    if let Some(interface) = missing.first() {
        router.cleanup_removed_dataplane(&desired).await?;
        return Err(crate::firewall::RouterDataplaneInterfaceMissing {
            role: "router".into(),
            interface: interface.clone(),
        }
        .into());
    }
    router.reconcile_dataplane(desired).await
}

pub(super) fn interface_needs_reapply(
    interface: &NetworkInterface,
    current_addresses: &[Ipv4AddressInfo],
    config: &InterfaceConfig,
    ownership_tagging_available: bool,
) -> bool {
    if !interface.is_up {
        return true;
    }

    if crate::core::interface::owns_dynamic_ipv4(config) {
        return false;
    }

    let desired = config
        .ipv4
        .map(|network| (network.addr(), network.prefix_len()));

    if current_addresses
        .iter()
        .any(|address| Some((address.address, address.prefix_len)) != desired)
    {
        return true;
    }

    match desired {
        Some((address, prefix_len)) => {
            let existing = current_addresses
                .iter()
                .find(|current| current.address == address && current.prefix_len == prefix_len);
            match existing {
                // The address is there but is not tagged as ours. Claiming it
                // is the whole of the work, and it is not optional: without the
                // tag we cannot later prove we put it there, and the interface
                // becomes one we refuse to stop managing.
                Some(existing) => {
                    ownership_tagging_available
                        && existing.owner() != AddressOwner::TrafficMasqStatic
                }
                None => true,
            }
        }
        None => false,
    }
}

pub(super) fn plan_dhcp_reconcile(
    desired: Option<DhcpServiceSpec>,
    current: Option<DhcpServiceSpec>,
    interface_present: bool,
    ipv4_ready: bool,
    binding_stale: bool,
) -> DhcpReconcileAction {
    match desired {
        None => {
            if current.is_some() {
                DhcpReconcileAction::Disable
            } else {
                DhcpReconcileAction::Keep
            }
        }
        Some(_) if !interface_present || !ipv4_ready => {
            if current.is_some() {
                DhcpReconcileAction::Disable
            } else {
                DhcpReconcileAction::Keep
            }
        }
        Some(spec) => {
            if current.as_ref() != Some(&spec) || binding_stale {
                DhcpReconcileAction::Configure(spec)
            } else {
                DhcpReconcileAction::Keep
            }
        }
    }
}

async fn apply_dhcp_reconcile_action<D: DhcpRuntimeReconciler + ?Sized>(
    dhcp: &D,
    interface: &str,
    action: DhcpReconcileAction,
) -> Result<()> {
    match action {
        DhcpReconcileAction::Keep => {}
        DhcpReconcileAction::Configure(spec) => dhcp.reconcile(spec).await?,
        DhcpReconcileAction::Disable => {
            dhcp.disable(interface).await?;
        }
    }
    Ok(())
}

async fn reconcile_dhcp_client<L: DhcpClientRuntimeReconciler + ?Sized>(
    client: &L,
    interface: &str,
    config: &InterfaceConfig,
    link_ready: bool,
) -> Result<()> {
    match DhcpClientSpec::from_interface_config(interface, config)? {
        Some(spec) => client.reconcile(spec, link_ready).await?,
        None => {
            client.disable(interface).await?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
/// Perform one desired-state pass across interface, DHCP and Wi-Fi services.
/// Caller must hold the runtime mutation gate; this function does not acquire it.
/// Check commit/recovery fences before subsystem writes and retry interface
/// recovery first. Return per-interface failures for the supervisor to retry;
/// global observation/recovery errors abort the pass. Presence notifications
/// and later supervisor passes, rather than this function, schedule further work.
pub(super) async fn reconcile_network_runtime_once<
    D: DhcpRuntimeReconciler,
    W: WifiRuntimeReconciler,
    C: WifiRuntimeReconciler,
    L: DhcpClientRuntimeReconciler,
>(
    desired: &DesiredNetworkState,
    journal: &AddressOwnershipJournal,
    network: Arc<dyn NetworkProvider>,
    dhcp: &D,
    wifi: Option<&W>,
    wifi_client: Option<&C>,
    dhcp_client: Option<&L>,
) -> Result<BTreeMap<String, String>> {
    crate::core::recovery::check_commit(desired.state_dir())?;
    let pass_version = desired.version();
    let effective = desired.effective().await?;
    crate::wifi::policy::WifiRadioPolicy::validate(&effective.network, |name| {
        network.wireless_phy(name)
    })?;
    let mut failures: BTreeMap<String, String> = BTreeMap::new();
    let interface_manager = InterfaceManager::new(network.clone(), journal.clone());
    let wifi_runtime_dirs = crate::wifi::WifiRuntimeDirs::new(
        &effective.wifi.runtime_dir,
        &effective.wifi_client.runtime_dir,
    );
    // Recovery restores current-format secrets under the same reservation as credential edits.
    let credential_updates = desired.credential_updates.write().await;
    crate::core::transaction::retry_interface_recovery(
        desired.state_dir(),
        &interface_manager,
        &desired.committed_overrides().await,
        &wifi_runtime_dirs,
        desired,
    )
    .await?;
    drop(credential_updates);
    let observed_interfaces: HashMap<_, _> = network
        .list_interfaces()
        .await?
        .into_iter()
        .map(|interface| (interface.name.clone(), interface))
        .collect();

    desired.record_interface_presence(
        effective.network.interfaces.keys().cloned(),
        &observed_interfaces.keys().cloned().collect(),
    );
    let mut observed_interfaces = Arc::new(observed_interfaces);
    let mut observation_version = pass_version;
    let mut changes = desired.intent_changes();
    let mut running = std::collections::HashSet::new();
    let mut completed = HashMap::new();
    let mut jobs = FuturesUnordered::new();
    let mut global_error = None;
    let run = |name: String, version: u64, observed: Arc<HashMap<String, NetworkInterface>>| {
        let network = network.clone();
        async move {
            let (version, result) = reconcile_interface_runtime_once(
                desired,
                journal,
                network,
                dhcp,
                wifi.map(|runtime| runtime as &dyn WifiRuntimeReconciler),
                wifi_client.map(|runtime| runtime as &dyn WifiRuntimeReconciler),
                dhcp_client.map(|runtime| runtime as &dyn DhcpClientRuntimeReconciler),
                &name,
                version,
                observed,
            )
            .await;
            (name, version, result)
        }
        .boxed()
    };
    loop {
        let version = desired.version();
        // A rollback published while another radio starts must get its own
        // worker immediately. Never cancel an in-flight process/kernel write.
        if global_error.is_none() && observation_version != version {
            match network.list_interfaces().await {
                Ok(interfaces) => {
                    observed_interfaces = Arc::new(
                        interfaces
                            .into_iter()
                            .map(|interface| (interface.name.clone(), interface))
                            .collect(),
                    );
                    observation_version = version;
                }
                Err(error) => global_error = Some(error),
            }
        }
        if global_error.is_none() {
            match desired.effective().await {
                Ok(effective) => {
                    for name in effective.network.interfaces.keys() {
                        if !running.contains(name) && completed.get(name) != Some(&version) {
                            running.insert(name.clone());
                            jobs.push(run(name.clone(), version, observed_interfaces.clone()));
                        }
                    }
                }
                // Keep polling all owned runtime writes before returning an
                // error; dropping their futures can strand a process launch.
                Err(error) => global_error = Some(error),
            }
        }
        if jobs.is_empty() {
            break;
        }
        tokio::select! {
            Some((name, version, result)) = jobs.next() => {
                running.remove(&name);
                if let Some(result) = result {
                    completed.insert(name.clone(), version);
                    match result {
                        Ok(()) => { failures.remove(&name); }
                        Err(error) => {
                            desired.record_failure_kind(pass_version, &name, &error);
                            failures.insert(name, format!("{error:#}"));
                        }
                    }
                }
                // Superseded work has no result: schedule its current intent.
            }
            _ = changes.changed() => {}
        }
    }
    match global_error {
        Some(error) => Err(error),
        None => Ok(failures),
    }
}

/// One lane owns all consumers of an interface. Radios are also serialized so
/// AP/STA transitions cannot overlap on a shared PHY. Read intent only after
/// acquiring those reservations; a queued job must never replay an old snapshot.
#[allow(clippy::too_many_arguments)]
async fn reconcile_interface_runtime_once(
    desired: &DesiredNetworkState,
    journal: &AddressOwnershipJournal,
    network: Arc<dyn NetworkProvider>,
    dhcp: &dyn DhcpRuntimeReconciler,
    wifi: Option<&dyn WifiRuntimeReconciler>,
    wifi_client: Option<&dyn WifiRuntimeReconciler>,
    dhcp_client: Option<&dyn DhcpClientRuntimeReconciler>,
    name: &str,
    version: u64,
    observed_interfaces: Arc<HashMap<String, NetworkInterface>>,
) -> (u64, Option<Result<()>>) {
    let phy = network.wireless_phy(name);
    let _radio = match phy {
        Some(phy) => Some(desired.radio_locks.lock(&phy).await),
        None => None,
    };
    let _lane = desired.runtime_locks.lock(name).await;
    if desired.version() != version {
        // A queued radio/lane changed while we waited. Reschedule it with the
        // current intent and a fresh shared device observation.
        return (version, None);
    }
    let revision = desired.interface_revision(name);
    let ensure_current = || -> Result<()> {
        crate::core::recovery::check_scope(desired.state_dir(), Some(name))?;
        anyhow::ensure!(
            desired.interface_revision(name) == revision,
            "interface intent superseded"
        );
        Ok(())
    };
    let outcome = async {
        crate::core::recovery::check_commit(desired.state_dir())?;
        let effective = desired.effective().await?;
        crate::wifi::policy::WifiRadioPolicy::validate(&effective.network, |name| {
            network.wireless_phy(name)
        })?;
        let Some(config) = effective.network.interfaces.get(name) else {
            return Ok(());
        };
        let management_allowlist = desired.management_allowlist().await;
        let restorations = desired.restorations().await;
        let interface_manager = InterfaceManager::new(network.clone(), journal.clone());
        let result: Result<()> = async {
            crate::core::recovery::check_scope(&effective.runtime.state_dir, Some(name))?;
            // Applying a candidate requires connectivity before confirmation.
            // Canceling it restores configuration, not the availability of an
            // external Wi-Fi network or DHCP server.
            let restoring = restorations.contains_key(name);
            let strict = desired.is_tentative(name).await && !restoring;
            let desired_dhcp = DhcpServiceSpec::from_interface_config(
                name,
                config,
                effective.dhcp.default_lease_seconds,
            )?;
            let mut current_dhcp = dhcp.spec(name).await;
            let Some(observed_interface) = observed_interfaces.get(name) else {
                apply_dhcp_reconcile_action(
                    dhcp,
                    name,
                    plan_dhcp_reconcile(desired_dhcp, current_dhcp, false, false, false),
                )
                .await?;
                if restoring {
                    // The vanished link has no kernel address state to replay.
                    // Stop surviving owned service tasks and leases before
                    // completing cancellation; committed intent can be edited
                    // or applied normally if the device returns later.
                    let disabled = InterfaceConfig {
                        mac_address: None,
                        managed: false,
                        ipv4: None,
                        dhcp: None,
                        dhcp_client: None,
                        wifi: None,
                        wifi_client: None,

                        role: config.role,
                    };
                    if let Some(client) = dhcp_client {
                        client.disable(name).await?;
                    }
                    if let Some(client) = wifi_client {
                        client.reconcile_interface(name, &disabled).await?;
                    }
                    if let Some(access_point) = wifi {
                        access_point.reconcile_interface(name, &disabled).await?;
                    }
                    return Ok(());
                }
                let desired_ipv4 = config
                    .ipv4
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "none".to_string());
                return Err(crate::core::recovery_control::failure(
                    crate::core::recovery_control::FailureKind::DeviceMissing,
                    format!(
                        "interface {name} is absent; convergence is deferred until it appears \
                     (desired: managed={}, role={:?}, ipv4={desired_ipv4}, dhcp_server={}, \
                     dhcp_client={}, wifi_ap={}, wifi_client={}). Check that the interface name \
                     exists and the device/link is present; if it was renamed or removed, update \
                     or remove its traffic-masq configuration",
                        config.managed,
                        config.role,
                        config.dhcp.is_some(),
                        config.dhcp_client.is_some(),
                        config.wifi.is_some(),
                        config.wifi_client.is_some(),
                    ),
                ));
            };

            ensure_current()?;
            // Hardware identity changes precede consumers: DHCP captures the MAC
            // when opening its runtime, and Wi-Fi daemons require a stable identity.
            let target_mac = restorations
                .get(name)
                .map_or(config.mac_address, |snapshot| snapshot.mac_address);
            if let Some(mac) = target_mac {
                if network.mac_address(name).await? != Some(mac.octets()) {
                    if !restoring {
                        interface_manager
                            .plan_interface(
                                name,
                                config,
                                Some(config.role),
                                management_allowlist.contains(name),
                            )
                            .await?;
                    }
                    let mut stopped = config.clone();
                    stopped.mac_address = None;
                    stopped.ipv4 = None;
                    stopped.dhcp = None;
                    stopped.dhcp_client = None;
                    stopped.wifi = None;
                    stopped.wifi_client = None;
                    if let Some(client) = dhcp_client {
                        client.disable(name).await?;
                    }
                    apply_dhcp_reconcile_action(dhcp, name, DhcpReconcileAction::Disable).await?;
                    current_dhcp = None;
                    if let Some(client) = wifi_client {
                        client.reconcile_interface(name, &stopped).await?;
                    }
                    if let Some(access_point) = wifi {
                        access_point.reconcile_interface(name, &stopped).await?;
                    }
                    ensure_current()?;
                    interface_manager.apply_mac_address(name, mac).await?;
                }
            }
            ensure_current()?;
            // Release AP ownership before starting a station on the same radio.
            // Starting an AP still waits until after station teardown and IPv4.
            if config.wifi.is_none() {
                if let Some(access_point) = wifi {
                    access_point.reconcile_interface(name, config).await?;
                }
            }
            ensure_current()?;
            if let Some(client) = wifi_client {
                client.reconcile_interface(name, config).await?;
            } else {
                anyhow::ensure!(
                    config.wifi_client.is_none(),
                    "Wi-Fi client runtime is unavailable"
                );
            }
            ensure_current()?;
            let mut link_ready = true;
            if config.wifi_client.is_some() {
                let deadline = time::Instant::now() + Duration::from_secs(5);
                loop {
                    link_ready = match wifi_client {
                        Some(client) => client.association_ready(name).await.unwrap_or(false),
                        None => false,
                    };
                    if link_ready || !strict {
                        break;
                    }
                    anyhow::ensure!(
                        time::Instant::now() < deadline,
                        "Wi-Fi association is not ready on {name}"
                    );
                    time::sleep(Duration::from_millis(20)).await;
                }
            }
            ensure_current()?;
            if let Some(client) = dhcp_client {
                reconcile_dhcp_client(client, name, config, link_ready).await?;
            } else {
                anyhow::ensure!(
                    DhcpClientSpec::from_interface_config(name, config)?.is_none(),
                    "DHCP client runtime is unavailable"
                );
            }

            ensure_current()?;
            if let Some(snapshot) = restorations.get(name) {
                interface_manager
                    .rollback_transaction_snapshot(snapshot)
                    .await?;
            } else {
                let current_addresses = network.list_ipv4_addresses(name).await?;
                let needs_apply = if config.managed {
                    // Foreign addresses are intentionally preserved; their presence
                    // must not cause an endless cycle of our own netlink events.
                    let mut relevant = Vec::new();
                    for address in &current_addresses {
                        if config.ipv4.is_some_and(|ip| {
                            ip.addr() == address.address && ip.prefix_len() == address.prefix_len
                        }) || interface_manager.owns_address(name, address).await
                        {
                            relevant.push(address.clone());
                        }
                    }
                    interface_needs_reapply(observed_interface, &relevant, config, false)
                } else {
                    interface_manager
                        .owns_any_address(name, &current_addresses)
                        .await
                };
                if needs_apply {
                    interface_manager
                        .apply_interface(
                            name,
                            config,
                            Some(config.role),
                            management_allowlist.contains(name),
                        )
                        .await?;
                }
            }
            ensure_current()?;
            let (ipv4_ready, binding_stale) = if desired_dhcp.is_some() {
                interface_manager
                    .verify_configured_ipv4(name, config)
                    .await?;
                (true, dhcp.binding_stale(name).await?)
            } else {
                (false, false)
            };
            if config.wifi.is_some() {
                let access_point = wifi.context("Wi-Fi access point runtime is unavailable")?;
                access_point.reconcile_interface(name, config).await?;
            }
            ensure_current()?;
            apply_dhcp_reconcile_action(
                dhcp,
                name,
                plan_dhcp_reconcile(desired_dhcp, current_dhcp, true, ipv4_ready, binding_stale),
            )
            .await?;
            if strict && DhcpClientSpec::from_interface_config(name, config)?.is_some() {
                if let Some(client) = dhcp_client {
                    client.verify_ready(name).await?;
                }
            }
            Ok(())
        }
        .await;

        result
    }
    .await;
    if desired.interface_revision(name) != revision {
        return (version, None);
    }
    if let Err(error) = &outcome {
        tracing::debug!(interface = %name, error = %format!("{error:#}"), "interface convergence incomplete");
    }
    desired.report_interface_result(name, version, &outcome);
    (version, Some(outcome))
}

/// Converge the machine towards the desired state, driven by events.
///
/// Successful passes wait for events. Failed passes also retry with bounded
/// backoff, since transient I/O failures can clear without a notification.
/// Changes that can make interface state disagree announce themselves:
///
/// - the desired state moved (an override was written),
/// - rtnetlink state moved (link, address, route or policy rule),
/// - notifications were dropped, so an unknown amount of the above happened.
///
/// nftables has no rtnetlink notification, so router dataplane integrity is
/// audited separately at a low cadence without polling all interface state.
#[allow(clippy::too_many_arguments)]
/// Attach the desired-state converger synchronously and spawn startup/event
/// passes. The task owns a shared mutation gate during each pass and retries
/// transient failures with backoff, reacting to device and recovery events.
/// The caller must signal shutdown and join it before final cleanup.
pub(super) fn spawn_runtime_network_reconcile(
    desired: DesiredNetworkState,
    journal: AddressOwnershipJournal,
    network: Arc<dyn NetworkProvider>,
    dhcp: DhcpSupervisor,
    wifi: Option<HostapdSupervisor>,
    wifi_client: Option<WifiClientSupervisor>,
    dhcp_client: DhcpClientSupervisor,
    network_mutations: Arc<NetworkMutationGate>,
    router: Option<RouterTransactionCoordinator>,
    kernel_events: mpsc::UnboundedReceiver<KernelEvent>,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<Result<()>> {
    spawn_runtime_network_reconcile_with_recovery_events(
        desired,
        journal,
        network,
        dhcp,
        wifi,
        wifi_client,
        dhcp_client,
        network_mutations,
        router,
        kernel_events,
        crate::core::recovery::subscribe(),
        shutdown,
    )
}

#[allow(clippy::too_many_arguments)]
/// Spawn convergence using explicit device/recovery event receivers. Attach
/// before returning so API admission sees an active converger. Shared runtime
/// gate excludes direct exclusive mutations; router-busy state skips competing
/// router writes. Retry failed passes until shutdown; caller joins the handle.
pub(super) fn spawn_runtime_network_reconcile_with_recovery_events(
    desired: DesiredNetworkState,
    journal: AddressOwnershipJournal,
    network: Arc<dyn NetworkProvider>,
    dhcp: DhcpSupervisor,
    wifi: Option<HostapdSupervisor>,
    wifi_client: Option<WifiClientSupervisor>,
    dhcp_client: DhcpClientSupervisor,
    network_mutations: Arc<NetworkMutationGate>,
    router: Option<RouterTransactionCoordinator>,
    mut kernel_events: mpsc::UnboundedReceiver<KernelEvent>,
    mut recovery_events: watch::Receiver<u64>,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<Result<()>> {
    // Attach synchronously, before the task is scheduled. Once the API is
    // serving, a transaction must never observe daemon state as `Detached`
    // merely because Tokio has not polled the reconciler yet.
    desired.attach_converger();
    tokio::spawn(async move {
        let mut retry_delay = NETWORK_RECONCILE_RETRY_BASE;
        'converge: loop {
            if shutdown_requested(&shutdown) {
                break;
            }

            // Converge first, wait second: the daemon has to reach the desired
            // state at startup without something having to happen first.
            //
            // Read the version before the pass, publish it after: the report
            // then says which proposals this pass had actually seen, so a
            // caller cannot mistake an older pass for an answer about its own
            // change.
            let version = desired.version();
            let (result, router_busy, router_retry_needed) = {
                // Interface transactions are themselves driven by this
                // converger, so both use a shared/read gate. Direct API and
                // router mutations take the exclusive/write side. This keeps
                // convergence alive for tentative interface state while
                // preventing it from racing a direct mutation.
                let _network_mutation = network_mutations.converge().await;
                let router_busy = match &router {
                    Some(router) => {
                        router.status().await
                            != crate::core::router_transaction::CoordinatorStatus::Idle
                    }
                    None => false,
                };
                if router_busy {
                    (None, true, false)
                } else {
                    let result = reconcile_network_runtime_once(
                        &desired,
                        &journal,
                        network.clone(),
                        &dhcp,
                        wifi.as_ref(),
                        wifi_client.as_ref(),
                        Some(&dhcp_client),
                    )
                    .await;
                    // Tentative interface state is owned by its transaction.
                    // Router drift repair runs only against settled intent.
                    let mut router_retry_needed = false;
                    if !desired.has_pending().await {
                        if let Some(router) = &router {
                            let repair = async {
                                let effective = desired.effective().await?;
                                reconcile_router_dataplane(
                                    router,
                                    RouterDesired::from_effective_config(&effective)?,
                                    network.as_ref(),
                                )
                                .await
                            }
                            .await;
                            if let Err(error) = repair {
                                router_retry_needed = true;
                                log_router_dataplane_convergence_error(&error);
                            }
                        }
                    }
                    (Some(result), false, router_retry_needed)
                }
            };
            // Journal retirement performed by this pass publishes recovery
            // receipts too. Acknowledge those before waiting so a failed
            // repair cannot use its own cleanup notification to bypass backoff.
            recovery_events.borrow_and_update();
            let retry_needed = router_retry_needed
                || match &result {
                    Some(Ok(failures)) => !failures.is_empty(),
                    Some(Err(_)) => true,
                    None => false,
                };
            let retry_at = time::Instant::now() + retry_delay;
            retry_delay = if retry_needed {
                (retry_delay * 2).min(NETWORK_RECONCILE_RETRY_MAX)
            } else {
                NETWORK_RECONCILE_RETRY_BASE
            };
            if let Some(result) = result {
                if let Err(error) = &result {
                    tracing::warn!(error = %format!("{error:#}"), "runtime interface reconcile pass failed");
                }
                desired.report_result(version, result);
            } else {
                tracing::debug!("runtime reconcile suspended while a router transaction is pending recovery/confirmation");
            }

            loop {
                tokio::select! {
                event = kernel_events.recv() => match event {
                    Some(_) => {
                        // A single `ip addr add` is several netlink messages, and
                        // the daemon's own writes are echoed back to it. Collapse
                        // whatever queued up into the one pass that follows —
                        // convergence re-reads everything anyway.
                        while kernel_events.try_recv().is_ok() {}
                        // Failed repairs can echo their own writes back to us.
                        // Keep draining notifications, but respect the retry
                        // deadline. New operator intent still wakes us below.
                        if !retry_needed { break; }
                    }
                    None => {
                        let message =
                            "kernel change notifications stopped; nothing can be converged any more";
                        desired.fail_converger(message);
                        tracing::error!("{message}");
                        bail!(message);
                    }
                },
                () = desired.changed() => {
                    retry_delay = NETWORK_RECONCILE_RETRY_BASE;
                    break;
                }
                _ = recovery_events.changed() => { break; }
                () = time::sleep_until(retry_at), if retry_needed => { break; }
                // I/O failures may clear without a kernel notification. Retry
                // unresolved startup snapshots even while the network is quiet.
                () = time::sleep(Duration::from_secs(30)),
                    if !router_busy && !crate::core::recovery::blocked_interfaces(desired.state_dir()).is_empty() => { break; }
                () = async {
                    if let Some(router) = &router {
                        router.wait_until_idle().await;
                    }
                }, if router_busy => { break; }
                changed = shutdown.changed() => match changed {
                    Ok(()) if shutdown_requested(&shutdown) => break 'converge,
                    Ok(()) => { break; }
                    Err(_) => break 'converge,
                }
                }
            }
        }
        desired.stop_converger();
        Ok(())
    })
}

/// One pass of "is everything we spawned still running".
///
/// Split from the task that drives it so it can be exercised against fakes.
pub(super) async fn check_process_liveness<D, W, C, L>(
    desired_config: Option<&AppConfig>,
    dhcp: &D,
    wifi: Option<&W>,
    wifi_client: Option<&C>,
    dhcp_client: Option<&L>,
) where
    D: DhcpRuntimeReconciler,
    W: WifiRuntimeReconciler,
    C: WifiRuntimeReconciler,
    L: DhcpClientRuntimeReconciler,
{
    if let Err(error) = dhcp.ensure_runtime_alive().await {
        tracing::warn!(error = %format!("{error:#}"), "failed to restart the shared DHCP runtime");
    }
    if let Some(wifi) = wifi {
        let result = match desired_config {
            Some(config) => wifi.ensure_alive_for_config(config).await,
            None => wifi.ensure_alive().await,
        };
        if let Err(error) = result {
            tracing::warn!(error = %format!("{error:#}"), "failed to check Wi-Fi access point liveness");
        }
    }
    if let Some(wifi_client) = wifi_client {
        let result = match desired_config {
            Some(config) => wifi_client.ensure_alive_for_config(config).await,
            None => wifi_client.ensure_alive().await,
        };
        if let Err(error) = result {
            tracing::warn!(error = %format!("{error:#}"), "failed to check Wi-Fi client liveness");
        }
    }
    if let (Some(wifi_client), Some(dhcp_client)) = (wifi_client, dhcp_client) {
        for spec in dhcp_client.specs().await {
            if let Some(config) = desired_config {
                let expected = config
                    .network
                    .interfaces
                    .get(&spec.interface)
                    .and_then(|config| {
                        DhcpClientSpec::from_interface_config(&spec.interface, config)
                            .ok()
                            .flatten()
                    });
                if expected.as_ref() != Some(&spec) {
                    continue;
                }
            }
            let link_ready = match desired_config {
                Some(config) => {
                    wifi_client
                        .association_ready_for_config(&spec.interface, config)
                        .await
                }
                None => wifi_client.association_ready(&spec.interface).await,
            };
            if let Some(link_ready) = link_ready {
                if let Err(error) = dhcp_client.reconcile(spec, link_ready).await {
                    tracing::warn!(error = %format!("{error:#}"), "DHCP client liveness reconcile failed");
                }
            }
        }
    }
    if let Some(dhcp_client) = dhcp_client {
        let result = match desired_config {
            Some(config) => dhcp_client.ensure_alive_for_config(config).await,
            None => dhcp_client.ensure_alive().await,
        };
        if let Err(error) = result {
            tracing::warn!(error = %format!("{error:#}"), "failed to check DHCP client liveness");
        }
    }
}

/// Monitor supervised network processes and retry recoverable failures until shutdown.
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_process_liveness_checks(
    desired: DesiredNetworkState,
    state_dir: std::path::PathBuf,
    dhcp: DhcpSupervisor,
    wifi: Option<HostapdSupervisor>,
    wifi_client: Option<WifiClientSupervisor>,
    dhcp_client: DhcpClientSupervisor,
    network_mutations: Arc<NetworkMutationGate>,
    router: Option<RouterTransactionCoordinator>,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut association_events = wifi_client
            .as_ref()
            .map(|wifi| wifi.subscribe_association_changes());
        let mut interval = time::interval(PROCESS_LIVENESS_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                event = async {
                    match association_events.as_mut() {
                        Some(receiver) => receiver.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if matches!(event, Err(tokio::sync::broadcast::error::RecvError::Closed)) {
                        association_events = None;
                    }
                    if let Ok((interface, pid)) = event {
                        let _network_mutation = network_mutations.execute().await;
                    if crate::core::recovery::check_commit(&state_dir).is_err()
                        || crate::core::recovery_control::check_runtime(&state_dir, None).is_err() { continue; }
                        if let Some(router) = &router {
                            if router.status().await != crate::core::router_transaction::CoordinatorStatus::Idle { continue; }
                        }
                        if let Some(wifi) = &wifi_client {
                            // Re-read status under the gate: queued events may belong to a
                            // replaced supplicant or precede a network transaction.
                            if let Some(status) = wifi.status(&interface).await.filter(|status| status.pid == pid) {
                                if let Ok(config) = desired.effective().await {
                                    if let Some(config) = config.network.interfaces.get(&interface) {
                                        let client = crate::wifi::WifiClientSpec::from_interface_config(&interface, config).ok().flatten();
                                        if client.as_ref() == Some(&status.spec) {
                                            if let Ok(Some(spec)) = DhcpClientSpec::from_interface_config(&interface, config) {
                                                dhcp_client.reconcile_with_link_ready(spec, status.wpa_state.is_connected()).await;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                _ = interval.tick() => {
                    if shutdown_requested(&shutdown) {
                        break;
                    }
                    // Liveness checks can restart or reconfigure supervised
                    // runtimes. Keep them exclusive with desired-state convergence:
                    // otherwise a DHCP/Wi-Fi readiness pass can replay state it
                    // observed just before a transaction converged.
                    let _network_mutation = network_mutations.execute().await;
                    if crate::core::recovery::check_commit(&state_dir).is_err()
                        || crate::core::recovery_control::check_runtime(&state_dir, None).is_err() { continue; }
                    let router_busy = match &router {
                        Some(router) => router.status().await
                            != crate::core::router_transaction::CoordinatorStatus::Idle,
                        None => false,
                    };
                    if router_busy {
                        tracing::debug!("process liveness mutations suspended while a router transaction is pending recovery/confirmation");
                        continue;
                    }
                    let config = match desired.effective().await {
                        Ok(config) => config,
                        Err(error) => { tracing::warn!(error = %format!("{error:#}"), "process restart blocked by invalid desired state"); continue; }
                    };
                    let wifi_admitted = match crate::wifi::policy::WifiRadioPolicy::validate_system(&config.network) {
                            Ok(()) => true,
                            Err(error) => {
                                tracing::warn!(error = %format!("{error:#}"), "Wi-Fi process restart blocked by radio policy");
                                false
                            }
                        };
                    check_process_liveness(
                        Some(&config),
                        &dhcp,
                        wifi.as_ref().filter(|_| wifi_admitted),
                        wifi_client.as_ref().filter(|_| wifi_admitted),
                        Some(&dhcp_client),
                    )
                    .await;
                }
                changed = shutdown.changed() => match changed {
                    Ok(()) if shutdown_requested(&shutdown) => break,
                    Ok(()) => {}
                    Err(_) => break,
                }
            }
        }
    })
}

/// Monitor committed route and firewall state and repair drift under the mutation gate.
pub(super) fn spawn_router_dataplane_integrity_checks(
    desired: DesiredNetworkState,
    overrides: RuntimeOverrideManager,
    network_provider: Arc<dyn NetworkProvider>,
    network_mutations: Arc<NetworkMutationGate>,
    router: Option<RouterTransactionCoordinator>,
    vpn_policy: Option<Arc<ProductionVpnPolicyManager>>,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if router.is_none() && vpn_policy.is_none() {
            return;
        }
        let mut interval = time::interval(ROUTER_DATAPLANE_INTEGRITY_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        // Startup already performs an explicit repair; wait a full interval
        // before the first integrity audit rather than duplicating it.
        interval.tick().await;

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if shutdown_requested(&shutdown) { break; }
                    // This audit is an autonomous writer when it repairs drift.
                    // Take exclusive runtime execution so it cannot race interface
                    // convergence or another background repair pass.
                    let _network_mutation = network_mutations.execute().await;
                    if crate::core::recovery::check_commit(desired.state_dir()).is_err() { continue; }
                    let router_busy = match &router {
                        Some(router) => router.status().await
                            != crate::core::router_transaction::CoordinatorStatus::Idle,
                        None => false,
                    };
                    if desired.has_pending().await || router_busy {
                        continue;
                    }
                    let result = async {
                        let effective = desired.effective().await?;
                        let router_desired = RouterDesired::from_effective_config(&effective)?;
                        if let Some(router) = &router {
                            reconcile_router_dataplane(
                                router, router_desired.clone(), network_provider.as_ref(),
                            ).await?;
                        }

                        // The legacy single-hop VPN policy owns the same hop-0
                        // reserved namespace as the router VPN chain. Audit it
                        // only when no chain is configured, so the two
                        // coexistence paths never repair over one another.
                        if effective.vpn.enabled && effective.vpn.standalone.is_none()
                            && router_desired.vpn_chain.is_empty() {
                            if let Some(policy) = &vpn_policy {
                                match overrides.effective_vpn_mode().await {
                                    VpnPolicyMode::Vpn => {
                                        let wanted = vpn_policy_desired(&effective).ok_or_else(|| {
                                            anyhow::anyhow!(
                                                "VPN policy mode is vpn but effective config has no protected subnets"
                                            )
                                        })?;
                                        if policy.health(&wanted).await.is_err() {
                                            policy.activate(&wanted).await?;
                                        }
                                    }
                                    VpnPolicyMode::Direct => {
                                        if policy.health_inactive().await.is_err() {
                                            let target = vpn_policy_desired(&effective)
                                                .unwrap_or_else(vpn_policy_teardown_target);
                                            policy.deactivate(&target).await?;
                                        }
                                    }
                                }
                            }
                        }
                        Ok::<_, anyhow::Error>(())
                    }.await;
                    if let Err(error) = result {
                        if missing_router_dataplane_interface(&error).is_some() {
                            log_router_dataplane_convergence_error(&error);
                        } else {
                            tracing::warn!(error = %format!("{error:#}"), "network integrity audit failed");
                        }
                    }
                }
                changed = shutdown.changed() => match changed {
                    Ok(()) if shutdown_requested(&shutdown) => break,
                    Ok(()) => {}
                    Err(_) => break,
                }
            }
        }
    })
}
