use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use tokio::sync::{watch, Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::config::{
    AppConfig, DhcpClientInterfaceConfig, InterfaceConfig, InterfaceRole, ShutdownPolicy,
};
use crate::dhcp::client::lease::{
    DhcpClientLease, DhcpClientLeasePolicy, DhcpClientLeaseState, DhcpClientOwnedRoute,
    DHCP_CLIENT_LEASE_SCHEMA_VERSION,
};
use crate::dhcp::client::ownership::DhcpClientOwnershipApplier;
use crate::dhcp::client::packet::ClientPacketBuilder;
use crate::dhcp::client::runtime::{DhcpClientActionSink, DhcpClientTransport};
use crate::dhcp::client::state_machine::{Lease, SendKind};
use crate::dhcp::client::store::DhcpClientLeaseStore;
use crate::netlink::{NetworkProvider, TRAFFIC_MASQ_DHCP_ROUTE_PROTOCOL};

const MAIN_ROUTE_TABLE: u32 = 254;

const GATEWAY_ROUTE_SCOPE: u8 = 0;
const LINK_ROUTE_SCOPE: u8 = 253;

const RESTART_BACKOFF_BASE: Duration = Duration::from_secs(2);
const BACKOFF_CEILING: Duration = Duration::from_secs(120);

const TASK_STOP_TIMEOUT: Duration = Duration::from_secs(5);

// Retain the acquisition budget, allow the complete mandatory ARP schedule,
// and leave time for kernel application, durable storage and scheduling.
pub(crate) const LEASE_READY_TIMEOUT: Duration = Duration::from_secs(5)
    .saturating_add(crate::dhcp::client::runtime::ARP_PROBE_DURATION_MAX)
    .saturating_add(Duration::from_secs(5));

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpClientSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    pub interface: String,
    pub route_metric: u32,
    pub install_default_route: bool,
    pub request_dns: bool,
    pub send_release_on_shutdown: bool,
}

impl DhcpClientSpec {
    pub fn from_interface_config(
        interface: &str,
        config: &InterfaceConfig,
    ) -> Result<Option<Self>> {
        config.validate(interface)?;

        let Some(dhcp_client) = config.dhcp_client.as_ref() else {
            return Ok(None);
        };

        if !dhcp_client.enabled {
            return Ok(None);
        }

        let spec = Self::from_parts(interface, dhcp_client);
        spec.validate()?;
        Ok(Some(spec))
    }

    fn from_parts(interface: &str, dhcp_client: &DhcpClientInterfaceConfig) -> Self {
        Self {
            interface: interface.to_string(),
            hostname: dhcp_client.hostname.clone(),
            route_metric: dhcp_client.route_metric,
            install_default_route: dhcp_client.install_default_route,
            request_dns: dhcp_client.request_dns,
            send_release_on_shutdown: dhcp_client.send_release_on_shutdown,
        }
    }

    pub fn validate(&self) -> Result<()> {
        crate::config::validate_interface_name(&self.interface)?;
        let config = InterfaceConfig {
            wifi_concurrent: false,
            mac_address: None,
            role: InterfaceRole::Input,
            managed: true,
            ipv4: None,
            dhcp: None,
            dhcp_client: Some(self.interface_config()),
            wifi: None,
            wifi_client: None,
        };
        config.validate(&self.interface)
    }

    pub fn interface_config(&self) -> DhcpClientInterfaceConfig {
        DhcpClientInterfaceConfig {
            hostname: self.hostname.clone(),
            wifi_owned: false,
            enabled: true,
            route_metric: self.route_metric,
            install_default_route: self.install_default_route,
            request_dns: self.request_dns,
            send_release_on_shutdown: self.send_release_on_shutdown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DhcpClientRunState {
    WaitingForInterface,

    Running,

    Degraded { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpClientStatus {
    pub interface: String,
    pub spec: DhcpClientSpec,
    pub state: DhcpClientRunState,

    pub lease: Option<DhcpClientLease>,
}

#[derive(Debug, Default)]
struct SharedState {
    lease: Option<DhcpClientLease>,
    failure: Option<String>,
}

pub struct DhcpClientLaunch {
    pub hostname: Option<String>,
    pub interface: String,
    pub interface_index: u32,
    pub hardware_address: [u8; 6],

    pub remembered: Option<Lease>,
    pub sink: Box<dyn DhcpClientActionSink>,
}

pub struct RunningDhcpClient {
    pub cancel: watch::Sender<bool>,
    pub task: JoinHandle<Result<()>>,

    pub transport: Arc<dyn DhcpClientTransport>,
}

#[async_trait]
pub trait DhcpClientLauncher: Send + Sync {
    async fn launch(&self, launch: DhcpClientLaunch) -> Result<RunningDhcpClient>;
}

#[cfg(target_os = "linux")]
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxDhcpClientLauncher;

#[cfg(target_os = "linux")]
#[async_trait]
impl DhcpClientLauncher for LinuxDhcpClientLauncher {
    async fn launch(&self, launch: DhcpClientLaunch) -> Result<RunningDhcpClient> {
        use crate::dhcp::client::runtime::{
            DhcpClientActor, DhcpClientRuntimeConfig, LinuxArpDad, LinuxDhcpClientSocket,
        };

        let mut config = DhcpClientRuntimeConfig::new(
            launch.interface.clone(),
            launch.interface_index,
            launch.hardware_address,
        );
        config.hostname = launch.hostname.clone();
        let socket = Arc::new(
            LinuxDhcpClientSocket::bind(config.clone()).with_context(|| {
                format!("failed to bind DHCP client socket on {}", config.interface)
            })?,
        );
        let dad = Arc::new(LinuxArpDad::new(launch.hardware_address)?);
        let mut actor = DhcpClientActor::new(config, socket.clone(), dad, launch.sink)?;
        if let Some(lease) = launch.remembered {
            actor = actor.with_remembered_lease(lease);
        }
        let (cancel, cancel_rx) = watch::channel(false);
        Ok(RunningDhcpClient {
            cancel,
            task: tokio::spawn(actor.run(cancel_rx)),
            transport: socket,
        })
    }
}

struct ClientTask {
    spec: DhcpClientSpec,

    identity: Option<InterfaceIdentity>,
    running: Option<RunningDhcpClient>,
    shared: Arc<Mutex<SharedState>>,
    consecutive_failures: u32,
    next_attempt_earliest: Option<Instant>,
    last_error: Option<String>,

    link_ready: bool,
}

impl ClientTask {
    fn new(spec: DhcpClientSpec, link_ready: bool) -> Self {
        Self {
            spec,
            identity: None,
            running: None,
            shared: Arc::new(Mutex::new(SharedState::default())),
            consecutive_failures: 0,
            next_attempt_earliest: None,
            last_error: None,
            link_ready,
        }
    }

    fn state(&self) -> DhcpClientRunState {
        match (&self.running, &self.last_error) {
            (Some(_), _) => DhcpClientRunState::Running,
            (None, Some(reason)) => DhcpClientRunState::Degraded {
                reason: reason.clone(),
            },
            (None, None) => DhcpClientRunState::WaitingForInterface,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InterfaceIdentity {
    index: u32,
    hardware_address: [u8; 6],
}

#[derive(Clone)]
pub struct DhcpClientSupervisor {
    inner: Arc<Inner>,
}

struct Inner {
    recovery: crate::core::recovery::RecoveryState,
    network: Arc<dyn NetworkProvider>,
    applier: Arc<DhcpClientOwnershipApplier>,
    launcher: Arc<dyn DhcpClientLauncher>,
    tasks: Mutex<HashMap<String, ClientTask>>,
    operation_lock: RwLock<()>,
    interface_operations: crate::core::mutation::InterfaceMutationLocks,
}

impl Inner {
    async fn record_success(&self, interface: &str) {
        let mut tasks = self.tasks.lock().await;
        if let Some(task) = tasks.get_mut(interface) {
            task.consecutive_failures = 0;
            task.next_attempt_earliest = None;
            task.last_error = None;
        }
    }
}

impl DhcpClientSupervisor {
    #[cfg(target_os = "linux")]
    /// Construct DHCP client supervision without enumerating persisted leases or starting clients.
    pub fn open_for_recovery(
        recovery: crate::core::recovery::RecoveryState,
        config: &AppConfig,
        network: Arc<dyn NetworkProvider>,
    ) -> Result<Self> {
        Self::open_with_launcher_for_recovery(
            recovery,
            config,
            network,
            Arc::new(LinuxDhcpClientLauncher),
        )
    }

    /// Construct a recovery runtime using an injected launcher, without normal startup reconcile.
    pub fn open_with_launcher_for_recovery(
        recovery: crate::core::recovery::RecoveryState,
        config: &AppConfig,
        network: Arc<dyn NetworkProvider>,
        launcher: Arc<dyn DhcpClientLauncher>,
    ) -> Result<Self> {
        let store = DhcpClientLeaseStore::new(&config.runtime.state_dir)
            .context("failed to open the DHCP client lease store")?;
        Ok(Self {
            inner: Arc::new(Inner {
                recovery: recovery.clone(),
                applier: Arc::new(DhcpClientOwnershipApplier::new_with_mutation_locks(
                    network.clone(),
                    store,
                    recovery.address_locks(),
                )),
                network,
                launcher,
                tasks: Mutex::new(HashMap::new()),
                operation_lock: RwLock::new(()),
                interface_operations: Default::default(),
            }),
        })
    }

    /// Recover persisted DHCP ownership and apply committed clients after router recovery.
    pub async fn reconcile_startup(&self, config: &AppConfig) -> Result<()> {
        let specs = Self::effective_specs(config)?;
        self.recover_persisted_leases(&specs).await?;
        for spec in specs {
            let link_ready = config
                .network
                .interfaces
                .get(&spec.interface)
                .is_some_and(|interface| interface.wifi_client.is_none());
            self.configure_with_link_ready(spec, link_ready).await;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    /// Initialize DHCP client supervision with the production launcher and recover persisted leases.
    pub async fn start(config: &AppConfig, network: Arc<dyn NetworkProvider>) -> Result<Self> {
        let supervisor = Self::open_for_recovery(Default::default(), config, network)?;
        supervisor.reconcile_startup(config).await?;
        Ok(supervisor)
    }

    /// Recover lease ownership and configure effective clients using an injected runtime launcher.
    pub async fn start_with_launcher(
        config: &AppConfig,
        network: Arc<dyn NetworkProvider>,
        launcher: Arc<dyn DhcpClientLauncher>,
    ) -> Result<Self> {
        let supervisor =
            Self::open_with_launcher_for_recovery(Default::default(), config, network, launcher)?;
        supervisor.reconcile_startup(config).await?;
        Ok(supervisor)
    }

    pub fn effective_specs(config: &AppConfig) -> Result<Vec<DhcpClientSpec>> {
        let mut specs = BTreeMap::new();
        for (name, interface) in &config.network.interfaces {
            if let Some(spec) = DhcpClientSpec::from_interface_config(name, interface)? {
                specs.insert(name.clone(), spec);
            }
        }
        Ok(specs.into_values().collect())
    }

    async fn recover_persisted_leases(&self, specs: &[DhcpClientSpec]) -> Result<()> {
        for interface in self.inner.applier.persisted_interfaces()? {
            if self
                .inner
                .recovery
                .check_scope(self.inner.applier.state_dir(), Some(&interface))
                .is_err()
            {
                continue;
            }
            let result: Result<()> = async {
            let committed = specs.iter().find(|spec| spec.interface == interface);
            let reason = match committed {
                None => Some("no committed DHCP client configuration"),
                Some(spec) => match self.inner.applier.persisted_lease(&interface)? {
                    Some(lease) if persisted_lease_matches_spec(&lease, spec) => None,
                    Some(_) => Some("persisted lease does not match committed DHCP client policy"),
                    None => return Ok(()),
                },
            };
            let Some(reason) = reason else {
                return Ok(());
            };
            tracing::warn!(%interface, %reason, "cleaning up persisted DHCP ownership during startup recovery");
            self.inner
                .applier
                .cleanup(&interface)
                .await
                .with_context(|| {
                    format!("failed to clean up persisted DHCP ownership for {interface}: {reason}")
                })?;
                Ok(())
            }.await;
            if let Err(error) = result {
                tracing::error!(%interface, operation = "recover_dhcp_ownership",
                    invariant = "exact_lease_ownership", metadata_safe_to_remove = false,
                    error = %format!("{error:#}"), "DHCP recovery blocked on this interface; continuing startup");
            }
        }
        Ok(())
    }

    /// Configure a DHCP client assuming the link is ready for acquisition.
    pub async fn configure(&self, spec: DhcpClientSpec) {
        self.configure_with_link_ready(spec, true).await;
    }

    /// Replace client settings and start acquisition only when the supplied link state permits it.
    pub async fn configure_with_link_ready(&self, spec: DhcpClientSpec, link_ready: bool) {
        if let Err(error) = self
            .inner
            .recovery
            .check_scope(self.inner.applier.state_dir(), Some(&spec.interface))
        {
            tracing::error!(interface = %spec.interface, error = %format!("{error:#}"), "DHCP client blocked by interface recovery");
            return;
        }
        let _operation = self.inner.operation_lock.read().await;
        let interface = spec.interface.clone();
        let _interface_operation = self.inner.interface_operations.lock(&interface).await;
        let (unchanged, readiness_changed) = {
            let mut tasks = self.inner.tasks.lock().await;
            match tasks.get_mut(&interface) {
                Some(task) => {
                    let readiness_changed = task.link_ready != link_ready;
                    let unchanged =
                        task.spec == spec && task.running.is_some() && !readiness_changed;
                    task.spec = spec.clone();
                    task.link_ready = link_ready;
                    (unchanged, readiness_changed)
                }
                None => {
                    tasks.insert(interface.clone(), ClientTask::new(spec.clone(), link_ready));
                    (false, false)
                }
            }
        };

        if unchanged {
            return;
        }
        self.stop_task(&interface).await;
        if link_ready {
            self.start_task(&interface).await;
        } else {
            self.suspend_owned_state(&interface).await;
            self.record_waiting(&interface).await;
            if readiness_changed {
                tracing::info!(%interface, "DHCP client paused while Wi-Fi is not associated");
            }
        }
    }

    /// Stop a client and release its owned state, returning its previous specification.
    pub async fn disable(&self, interface: &str) -> Result<Option<DhcpClientSpec>> {
        let _operation = self.inner.operation_lock.read().await;
        let _interface_operation = self.inner.interface_operations.lock(interface).await;
        if !self.inner.tasks.lock().await.contains_key(interface) {
            if let Err(error) = self.inner.applier.cleanup(interface).await {
                tracing::warn!(%interface, error = %format!("{error:#}"), "failed to release owned DHCP client state while disabling it; cleanup will be retried");
                return Err(error.into());
            }
            return Ok(None);
        }
        let previous_lease = self.status(interface).await.and_then(|status| status.lease);
        self.stop_task(interface).await;
        if let Err(error) = self.inner.applier.cleanup(interface).await {
            tracing::warn!(%interface, error = %format!("{error:#}"), "failed to release owned DHCP client state while disabling it; restoring the client runtime");
            let restoration = self
                .restore_runtime_after_interrupted_stop(interface, previous_lease)
                .await;
            return Err(match restoration {
                Ok(()) => anyhow::anyhow!(error).context(
                    "failed to release owned DHCP client state while disabling it; client runtime was restored",
                ),
                Err(rollback) => anyhow::anyhow!(error).context(format!(
                    "failed to release owned DHCP client state while disabling it and client runtime restoration also failed: {rollback:#}; recovery required"
                )),
            });
        }
        let task = self.inner.tasks.lock().await.remove(interface);
        tracing::info!(%interface, "DHCP client disabled");
        Ok(task.map(|task| task.spec))
    }

    /// Reconcile the configured client with a ready link.
    pub async fn reconcile(&self, spec: DhcpClientSpec) {
        self.reconcile_with_link_ready(spec, true).await;
    }

    /// Update client settings and link readiness, restarting acquisition when necessary.
    pub async fn reconcile_with_link_ready(&self, spec: DhcpClientSpec, link_ready: bool) {
        let current = {
            let tasks = self.inner.tasks.lock().await;
            tasks
                .get(&spec.interface)
                .map(|task| (task.spec.clone(), task.link_ready))
        };
        if current.as_ref() == Some(&(spec.clone(), link_ready)) {
            return;
        }
        self.configure_with_link_ready(spec, link_ready).await;
    }

    pub async fn spec(&self, interface: &str) -> Option<DhcpClientSpec> {
        self.inner
            .tasks
            .lock()
            .await
            .get(interface)
            .map(|task| task.spec.clone())
    }

    pub async fn status(&self, interface: &str) -> Option<DhcpClientStatus> {
        let tasks = self.inner.tasks.lock().await;
        let task = tasks.get(interface)?;
        let state = task.state();
        let shared = task.shared.clone();
        let spec = task.spec.clone();
        drop(tasks);
        let shared = shared.lock().await;
        Some(DhcpClientStatus {
            interface: interface.to_string(),
            spec,
            state: match &shared.failure {
                Some(reason) => DhcpClientRunState::Degraded {
                    reason: reason.clone(),
                },
                None => state,
            },
            lease: shared.lease.clone(),
        })
    }

    /// Verify that the lease still corresponds to the expected owned kernel resources.
    pub async fn verify_bound_lease(&self, lease: &DhcpClientLease) -> Result<()> {
        self.inner
            .applier
            .observe_exact(lease)
            .await
            .map_err(Into::into)
    }

    /// Wait for a lease and verify its owned kernel resources before strict convergence succeeds.
    pub(crate) async fn wait_until_ready(&self, interface: &str) -> Result<()> {
        let deadline = Instant::now() + LEASE_READY_TIMEOUT;
        loop {
            let status = self
                .status(interface)
                .await
                .context("DHCP client disappeared")?;
            if let Some(lease) = status.lease {
                return self.verify_bound_lease(&lease).await;
            }
            if let DhcpClientRunState::Degraded { reason } = status.state {
                bail!("DHCP client on {interface} is degraded: {reason}");
            }
            if Instant::now() >= deadline {
                tracing::warn!(%interface, state = ?status.state, timeout_seconds = LEASE_READY_TIMEOUT.as_secs(), "DHCP readiness timed out without a lease; inspect DHCP packet and address-probe events");
                bail!(
                    "DHCP lease is not ready on {interface} after {} seconds (state: {:?})",
                    LEASE_READY_TIMEOUT.as_secs(),
                    status.state
                );
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    pub async fn statuses(&self) -> Vec<DhcpClientStatus> {
        let interfaces: Vec<String> = self.inner.tasks.lock().await.keys().cloned().collect();
        let mut statuses = Vec::with_capacity(interfaces.len());
        for interface in interfaces {
            if let Some(status) = self.status(&interface).await {
                statuses.push(status);
            }
        }
        statuses.sort_by(|left, right| left.interface.cmp(&right.interface));
        statuses
    }

    /// Restart acquisition for the configured interface to request a fresh lease.
    pub async fn renew_now(&self, interface: &str) -> Result<DhcpClientStatus> {
        let _operation = self.inner.operation_lock.read().await;
        let _interface_operation = self.inner.interface_operations.lock(interface).await;
        let link_ready = self
            .inner
            .tasks
            .lock()
            .await
            .get(interface)
            .map(|task| task.link_ready)
            .context("DHCP client interface is not configured")?;
        self.stop_task(interface).await;
        if link_ready {
            self.start_task(interface).await;
        } else {
            self.record_waiting(interface).await;
        }
        self.status_after_manual_restart(interface, "renew").await
    }

    /// Release the current lease and start a new DHCP acquisition.
    pub async fn release_and_reacquire(&self, interface: &str) -> Result<DhcpClientStatus> {
        let _operation = self.inner.operation_lock.read().await;
        let _interface_operation = self.inner.interface_operations.lock(interface).await;
        let (link_ready, transport, shared, hostname) = {
            let tasks = self.inner.tasks.lock().await;
            let task = tasks
                .get(interface)
                .context("DHCP client interface is not configured")?;
            (
                task.link_ready,
                task.running
                    .as_ref()
                    .map(|running| running.transport.clone()),
                task.shared.clone(),
                task.spec.hostname.clone(),
            )
        };
        let lease = shared.lock().await.lease.clone();
        self.stop_task(interface).await;
        let release_error = if let (Some(transport), Some(lease)) = (transport, lease.as_ref()) {
            send_release(transport.as_ref(), lease, hostname.as_deref())
                .await
                .err()
        } else {
            None
        };
        if let Err(error) = self.inner.applier.cleanup(interface).await {
            let restoration = self
                .restore_runtime_after_interrupted_stop(interface, lease.clone())
                .await;
            return Err(match restoration {
                Ok(()) => anyhow::anyhow!(error).context(
                    "failed to clean up DHCP client lease during release/reacquire; client runtime was restored",
                ),
                Err(rollback) => anyhow::anyhow!(error).context(format!(
                    "failed to clean up DHCP client lease during release/reacquire and client runtime restoration also failed: {rollback:#}; recovery required"
                )),
            });
        }
        {
            let mut state = shared.lock().await;
            state.lease = None;
            state.failure = None;
        }
        if link_ready {
            self.start_task(interface).await;
        } else {
            self.record_waiting(interface).await;
        }
        if let Some(error) = release_error {
            tracing::warn!(%interface, error = %format!("{error:#}"), "DHCP RELEASE could not be delivered; owned state was still cleaned up");
        }
        self.status_after_manual_restart(interface, "release/reacquire")
            .await
    }

    async fn restore_runtime_after_interrupted_stop(
        &self,
        interface: &str,
        previous_lease: Option<DhcpClientLease>,
    ) -> Result<()> {
        let (link_ready, shared) = {
            let tasks = self.inner.tasks.lock().await;
            let task = tasks
                .get(interface)
                .context("DHCP client interface disappeared while restoring runtime")?;
            (task.link_ready, task.shared.clone())
        };

        // `cleanup()` writes CleanupNeeded before touching kernel state and may
        // fail after removing only part of the lease. Re-applying the snapshot
        // restores the exact address/routes and returns the durable ownership
        // record to Bound before the DHCP actor is restarted. Otherwise startup
        // would adopt CleanupNeeded, retry cleanup, and accidentally complete
        // the operation we are supposed to roll back.
        if let Some(lease) = previous_lease {
            let restored = self
                .inner
                .applier
                .apply(lease)
                .await
                .context("failed to restore DHCP client owned lease state")?;
            let mut state = shared.lock().await;
            state.lease = Some(restored);
            state.failure = None;
        }

        if link_ready {
            self.start_task(interface).await;
        } else {
            self.record_waiting(interface).await;
        }
        self.status_after_manual_restart(interface, "runtime restoration")
            .await
            .map(|_| ())
    }

    async fn status_after_manual_restart(
        &self,
        interface: &str,
        operation: &str,
    ) -> Result<DhcpClientStatus> {
        let status = self
            .status(interface)
            .await
            .with_context(|| format!("DHCP client interface disappeared during {operation}"))?;
        if let DhcpClientRunState::Degraded { reason } = &status.state {
            bail!("DHCP client {operation} failed on {interface}: {reason}");
        }
        Ok(status)
    }

    /// Recover stopped client tasks when their retry deadlines permit it.
    pub async fn ensure_alive(&self) -> Result<bool> {
        self.ensure_alive_matching(None).await
    }

    /// Called under the network mutation gate with the current desired snapshot.
    /// Stale tasks cannot restart or replay settings withdrawn by a newer edit.
    pub async fn ensure_alive_for_config(&self, config: &AppConfig) -> Result<bool> {
        let desired = Self::effective_specs(config)?;
        self.ensure_alive_matching(Some(&desired)).await
    }

    async fn ensure_alive_matching(&self, desired: Option<&[DhcpClientSpec]>) -> Result<bool> {
        let _operation = self.inner.operation_lock.read().await;
        let interfaces: Vec<String> = self
            .inner
            .tasks
            .lock()
            .await
            .iter()
            .filter(|(_, task)| desired.is_none_or(|specs| specs.contains(&task.spec)))
            .map(|(name, _)| name.clone())
            .collect();
        let mut changed = false;
        for interface in interfaces {
            let _interface_operation = self.inner.interface_operations.lock(&interface).await;
            if let Some(specs) = desired {
                if self
                    .inner
                    .tasks
                    .lock()
                    .await
                    .get(&interface)
                    .is_none_or(|task| !specs.contains(&task.spec))
                {
                    continue;
                }
            }
            if self.ensure_interface_alive(&interface).await {
                changed = true;
            }
        }
        Ok(changed)
    }

    async fn ensure_interface_alive(&self, interface: &str) -> bool {
        let (identity, has_running, finished, backed_off, link_ready) = {
            let tasks = self.inner.tasks.lock().await;
            let Some(task) = tasks.get(interface) else {
                return false;
            };
            (
                task.identity,
                task.running.is_some(),
                task.running
                    .as_ref()
                    .is_some_and(|running| running.task.is_finished()),
                task.next_attempt_earliest
                    .is_some_and(|earliest| Instant::now() < earliest),
                task.link_ready,
            )
        };

        let observed = self.resolve_identity(interface).await;
        if !link_ready {
            if has_running {
                self.stop_task(interface).await;
            }
            self.suspend_owned_state(interface).await;
            return has_running;
        }
        match (observed, has_running) {
            (None, true) => {
                tracing::warn!(%interface, "DHCP client interface disappeared; stopping its client");
                self.stop_task(interface).await;
                self.record_waiting(interface).await;
                true
            }
            (None, false) => false,

            (Some(observed), true) if identity == Some(observed) && !finished => false,
            (Some(observed), _) => {
                if has_running && identity == Some(observed) {
                    let reason = self.reap_finished(interface).await;
                    tracing::warn!(
                        %interface,
                        reason = %reason.as_deref().unwrap_or("task exited"),
                        "DHCP client task stopped; will retry with backoff"
                    );
                    return false;
                } else if has_running {
                    tracing::info!(%interface, "DHCP client interface identity changed; restarting its client");
                    self.stop_task(interface).await;
                }

                if backed_off {
                    return false;
                }

                self.start_task(interface).await;
                true
            }
        }
    }

    /// Stop client runtimes and apply the requested ownership cleanup policy.
    pub async fn shutdown(&self, policy: ShutdownPolicy) {
        let _operation = self.inner.operation_lock.write().await;
        let interfaces: Vec<String> = self.inner.tasks.lock().await.keys().cloned().collect();

        for interface in interfaces {
            let (running, spec, lease) = {
                let mut tasks = self.inner.tasks.lock().await;
                let Some(task) = tasks.get_mut(&interface) else {
                    continue;
                };
                let shared = task.shared.clone();
                let lease = shared.lock().await.lease.clone();
                (task.running.take(), task.spec.clone(), lease)
            };

            let transport = running.as_ref().map(|running| running.transport.clone());
            if let Some(running) = running {
                stop_running(running).await;
            }

            if policy != ShutdownPolicy::RestoreInterfaces {
                continue;
            }
            if spec.send_release_on_shutdown {
                if let (Some(transport), Some(lease)) = (transport, lease.as_ref()) {
                    if let Err(error) =
                        send_release(transport.as_ref(), lease, spec.hostname.as_deref()).await
                    {
                        tracing::warn!(%interface, error = %format!("{error:#}"), "failed to send DHCP RELEASE during shutdown");
                    }
                }
            }
            if let Err(error) = self.inner.applier.cleanup(&interface).await {
                tracing::warn!(%interface, error = %format!("{error:#}"), "failed to clean up owned DHCP client state during shutdown");
            }
        }
        self.inner.tasks.lock().await.clear();
    }

    async fn resolve_identity(&self, interface: &str) -> Option<InterfaceIdentity> {
        let interfaces = self.inner.network.list_interfaces().await.ok()?;
        let index = interfaces
            .iter()
            .find(|candidate| candidate.name == interface)
            .map(|candidate| candidate.index)?;
        let hardware = self.inner.network.hardware_address(interface).await.ok()?;
        let hardware_address: [u8; 6] = hardware.try_into().ok()?;
        Some(InterfaceIdentity {
            index,
            hardware_address,
        })
    }

    async fn start_task(&self, interface: &str) {
        let Some(identity) = self.resolve_identity(interface).await else {
            tracing::warn!(
                %interface,
                "configured DHCP client interface is not usable yet; waiting for it"
            );
            self.record_waiting(interface).await;
            return;
        };

        let link_ready = self
            .inner
            .tasks
            .lock()
            .await
            .get(interface)
            .is_some_and(|task| task.link_ready);
        if !link_ready {
            return;
        }
        let (spec, shared) = {
            let tasks = self.inner.tasks.lock().await;
            let Some(task) = tasks.get(interface) else {
                return;
            };
            (task.spec.clone(), task.shared.clone())
        };
        let remembered = match self.adopt_persisted_lease(interface, &spec).await {
            Ok(remembered) => remembered,
            Err(error) => {
                tracing::error!(%interface, error = %format!("{error:#}"), "unresolved persisted DHCP ownership blocks client start");
                self.record_failure(interface, format!("{error:#}")).await;
                return;
            }
        };
        {
            let mut state = shared.lock().await;
            state.lease = remembered.clone();
            state.failure = None;
        }

        let sink = OwnershipSink {
            spec: spec.clone(),
            identity,
            applier: self.inner.applier.clone(),
            shared: shared.clone(),
            inner: Arc::downgrade(&self.inner),
        };
        let launch = DhcpClientLaunch {
            hostname: spec.hostname.clone(),
            interface: interface.to_string(),
            interface_index: identity.index,
            hardware_address: identity.hardware_address,
            remembered: remembered.as_ref().map(monotonic_lease),
            sink: Box::new(sink),
        };

        match self.inner.launcher.launch(launch).await {
            Ok(running) => {
                let mut tasks = self.inner.tasks.lock().await;
                if let Some(task) = tasks.get_mut(interface) {
                    task.running = Some(running);
                    task.identity = Some(identity);
                    task.next_attempt_earliest = None;
                    task.last_error = None;
                }
                tracing::info!(
                    %interface,
                    ifindex = identity.index,
                    adopted = remembered.is_some(),
                    "DHCP client started"
                );
            }
            Err(error) => {
                tracing::error!(%interface, error = %format!("{error:#}"), "failed to start the DHCP client");
                self.record_failure(interface, format!("{error:#}")).await;
            }
        }
    }

    async fn adopt_persisted_lease(
        &self,
        interface: &str,
        spec: &DhcpClientSpec,
    ) -> Result<Option<DhcpClientLease>> {
        if let Some(lease) = self.inner.applier.persisted_lease(interface)? {
            if !persisted_lease_matches_spec(&lease, spec) {
                tracing::warn!(
                    %interface,
                    "persisted DHCP lease does not match committed client policy; cleaning it up before reacquiring"
                );
                return match self.inner.applier.cleanup(interface).await {
                    Ok(()) => Ok(None),
                    Err(cleanup) => Err(anyhow::anyhow!(
                        "persisted DHCP ownership does not match committed policy and cleanup failed ({cleanup}); recovery required"
                    )),
                };
            }
        }
        match self
            .inner
            .applier
            .adopt(interface, current_unix_time())
            .await
        {
            Ok(lease) => Ok(lease),
            Err(error) => {
                tracing::warn!(
                    %interface,
                    error = %format!("{error:#}"),
                    "persisted DHCP lease could not be adopted; releasing any state it still proves"
                );
                match self.inner.applier.cleanup(interface).await {
                    Ok(()) => Ok(None),
                    Err(cleanup) => Err(anyhow::anyhow!(
                        "persisted DHCP ownership could not be adopted ({error}) and cleanup also failed ({cleanup}); recovery required"
                    )),
                }
            }
        }
    }

    async fn stop_task(&self, interface: &str) {
        let running = {
            let mut tasks = self.inner.tasks.lock().await;
            tasks
                .get_mut(interface)
                .and_then(|task| task.running.take())
        };
        if let Some(running) = running {
            stop_running(running).await;
        }
    }

    async fn suspend_owned_state(&self, interface: &str) {
        let shared = self
            .inner
            .tasks
            .lock()
            .await
            .get(interface)
            .map(|task| task.shared.clone());
        match self
            .inner
            .applier
            .suspend(interface, current_unix_time())
            .await
        {
            Ok(lease) => {
                if let Some(shared) = shared {
                    let mut state = shared.lock().await;
                    state.lease = lease;
                    state.failure = None;
                }
            }
            Err(error) => {
                tracing::warn!(%interface, error = %format!("{error:#}"), "failed to suspend traffic-masq-owned DHCP state while link is not ready");
                if let Some(shared) = shared {
                    shared.lock().await.failure = Some(format!("{error:#}"));
                }
            }
        }
    }

    async fn reap_finished(&self, interface: &str) -> Option<String> {
        let running = {
            let mut tasks = self.inner.tasks.lock().await;
            tasks
                .get_mut(interface)
                .and_then(|task| task.running.take())
        }?;
        let reason = match running.task.await {
            Ok(Ok(())) => "client task exited".to_string(),
            Ok(Err(error)) => format!("{error:#}"),
            Err(error) => format!("client task panicked: {error}"),
        };
        self.record_failure(interface, reason.clone()).await;
        Some(reason)
    }

    async fn record_failure(&self, interface: &str, reason: String) {
        let mut tasks = self.inner.tasks.lock().await;
        let Some(task) = tasks.get_mut(interface) else {
            return;
        };
        task.running = None;
        task.consecutive_failures = task.consecutive_failures.saturating_add(1);
        task.next_attempt_earliest = Some(Instant::now() + backoff(task.consecutive_failures));
        task.last_error = Some(reason);
    }

    async fn record_waiting(&self, interface: &str) {
        let mut tasks = self.inner.tasks.lock().await;
        let Some(task) = tasks.get_mut(interface) else {
            return;
        };
        task.running = None;
        task.identity = None;
        task.last_error = None;
        task.consecutive_failures = 0;
        task.next_attempt_earliest = None;
    }
}

struct OwnershipSink {
    spec: DhcpClientSpec,
    identity: InterfaceIdentity,
    applier: Arc<DhcpClientOwnershipApplier>,
    shared: Arc<Mutex<SharedState>>,
    inner: std::sync::Weak<Inner>,
}

#[async_trait]
impl DhcpClientActionSink for OwnershipSink {
    async fn lease_acquired(&mut self, lease: Lease) -> Result<()> {
        // Lease callbacks are participants in the configured DHCP runtime,
        // not independent control requests. DHCP ownership and interface
        // address writers serialize through the shared per-interface mutation
        // lock. Taking control admission here would deadlock lease readiness.
        let persisted = self.persisted_lease(&lease);
        match self.applier.apply(persisted).await {
            Ok(applied) => {
                let mut shared = self.shared.lock().await;
                shared.lease = Some(applied);
                shared.failure = None;
                if let Some(inner) = self.inner.upgrade() {
                    inner.record_success(&self.spec.interface).await;
                }
                Ok(())
            }
            Err(error) => {
                let reason = format!("{error:#}");
                self.shared.lock().await.failure = Some(reason.clone());
                Err(anyhow::anyhow!(
                    "failed to apply DHCP lease ownership on {}: {reason}",
                    self.spec.interface
                ))
            }
        }
    }

    async fn lease_lost(&mut self) -> Result<()> {
        let mut shared = self.shared.lock().await;
        shared.lease = None;
        Ok(())
    }

    async fn cleanup_needed(&mut self, _lease: Lease) -> Result<()> {
        // Lease callbacks are participants in the configured DHCP runtime,
        // not independent control requests. DHCP ownership and interface
        // address writers serialize through the shared per-interface mutation
        // lock. Taking control admission here would deadlock lease readiness.
        let result = self
            .applier
            .cleanup_for_identity(
                &self.spec.interface,
                self.identity.index,
                &self.identity.hardware_address,
            )
            .await;
        if matches!(result, Ok(false)) {
            return Ok(());
        }
        let mut shared = self.shared.lock().await;
        shared.lease = None;
        match result {
            Ok(_) => Ok(()),
            Err(error) => {
                let reason = format!("{error:#}");
                shared.failure = Some(reason.clone());
                Err(anyhow::anyhow!(
                    "failed to release DHCP lease ownership on {}: {reason}",
                    self.spec.interface
                ))
            }
        }
    }
}

impl OwnershipSink {
    fn persisted_lease(&self, lease: &Lease) -> DhcpClientLease {
        let lease_seconds = seconds_between(lease.acquired_at, lease.expires_at);
        let renewal_seconds = seconds_between(lease.acquired_at, lease.renewal_at);
        let rebinding_seconds = seconds_between(lease.acquired_at, lease.rebinding_at);
        let owned_routes = self.owned_routes(lease);
        DhcpClientLease {
            schema_version: DHCP_CLIENT_LEASE_SCHEMA_VERSION,
            state: DhcpClientLeaseState::PendingApply,
            interface: self.spec.interface.clone(),
            interface_index: self.identity.index,
            hardware_address: self.identity.hardware_address.to_vec(),
            client_identifier: client_identifier(self.identity.hardware_address),
            policy: Some(DhcpClientLeasePolicy {
                route_metric: self.spec.route_metric,
                install_default_route: self.spec.install_default_route,
                request_dns: self.spec.request_dns,
            }),
            server_identifier: lease.server_identifier,
            address: lease.address,
            prefix_len: lease.prefix_len,
            routers: lease.routers.clone(),
            dns_servers: if self.spec.request_dns {
                lease.dns_servers.clone()
            } else {
                Vec::new()
            },
            lease_seconds,
            renewal_seconds,
            rebinding_seconds,
            expires_at_unix: current_unix_time().saturating_add(u64::from(lease_seconds)),
            owned_routes,
        }
    }

    fn owned_routes(&self, lease: &Lease) -> Vec<DhcpClientOwnedRoute> {
        let mut routes = vec![DhcpClientOwnedRoute {
            destination: Ipv4Net::new(lease.address, lease.prefix_len)
                .expect("validated DHCP prefix")
                .trunc(),
            gateway: None,
            output_interface_index: Some(self.identity.index),
            table: MAIN_ROUTE_TABLE,
            metric: None,
            protocol: TRAFFIC_MASQ_DHCP_ROUTE_PROTOCOL,
            scope: LINK_ROUTE_SCOPE,
        }];
        if self.spec.install_default_route {
            if let Some(gateway) = lease.routers.first().copied() {
                routes.push(DhcpClientOwnedRoute {
                    destination: Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0)
                        .expect("0.0.0.0/0 is valid"),
                    gateway: Some(gateway),
                    output_interface_index: Some(self.identity.index),
                    table: MAIN_ROUTE_TABLE,
                    metric: Some(self.spec.route_metric),
                    protocol: TRAFFIC_MASQ_DHCP_ROUTE_PROTOCOL,
                    scope: GATEWAY_ROUTE_SCOPE,
                });
            }
        }
        routes
    }
}

fn persisted_lease_matches_spec(lease: &DhcpClientLease, spec: &DhcpClientSpec) -> bool {
    lease.policy.as_ref()
        == Some(&DhcpClientLeasePolicy {
            route_metric: spec.route_metric,
            install_default_route: spec.install_default_route,
            request_dns: spec.request_dns,
        })
        && {
            let mut expected = expected_owned_routes(lease, spec);
            for route in &mut expected {
                if route.destination.prefix_len() == 0 {
                    if let Some(effective) = lease.owned_routes.iter().find(|owned| {
                        owned.destination == route.destination
                            && owned.metric.unwrap_or(0) >= spec.route_metric
                    }) {
                        route.metric = effective.metric;
                    }
                }
            }
            lease.owned_routes == expected
        }
}

fn expected_owned_routes(
    lease: &DhcpClientLease,
    spec: &DhcpClientSpec,
) -> Vec<DhcpClientOwnedRoute> {
    let mut routes = vec![DhcpClientOwnedRoute {
        destination: Ipv4Net::new(lease.address, lease.prefix_len)
            .expect("validated DHCP prefix")
            .trunc(),
        gateway: None,
        output_interface_index: Some(lease.interface_index),
        table: MAIN_ROUTE_TABLE,
        metric: None,
        protocol: TRAFFIC_MASQ_DHCP_ROUTE_PROTOCOL,
        scope: LINK_ROUTE_SCOPE,
    }];
    if spec.install_default_route {
        if let Some(gateway) = lease.routers.first().copied() {
            routes.push(DhcpClientOwnedRoute {
                destination: Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).expect("0.0.0.0/0 is valid"),
                gateway: Some(gateway),
                output_interface_index: Some(lease.interface_index),
                table: MAIN_ROUTE_TABLE,
                metric: Some(spec.route_metric),
                protocol: TRAFFIC_MASQ_DHCP_ROUTE_PROTOCOL,
                scope: GATEWAY_ROUTE_SCOPE,
            });
        }
    }
    routes
}

fn client_identifier(hardware_address: [u8; 6]) -> Vec<u8> {
    let mut identifier = Vec::with_capacity(7);
    identifier.push(1);
    identifier.extend_from_slice(&hardware_address);
    identifier
}

fn seconds_between(from: Duration, to: Duration) -> u32 {
    to.saturating_sub(from).as_secs().min(u64::from(u32::MAX)) as u32
}

fn monotonic_lease(lease: &DhcpClientLease) -> Lease {
    let remaining = lease.expires_at_unix.saturating_sub(current_unix_time());
    let expires_at = Duration::from_secs(remaining);
    Lease {
        address: lease.address,
        subnet_mask: prefix_to_mask(lease.prefix_len),
        prefix_len: lease.prefix_len,
        routers: lease.routers.clone(),
        dns_servers: lease.dns_servers.clone(),
        server_identifier: lease.server_identifier,
        acquired_at: Duration::ZERO,
        renewal_at: expires_at / 2,
        rebinding_at: expires_at * 7 / 8,
        expires_at,
    }
}

fn prefix_to_mask(prefix_len: u8) -> Ipv4Addr {
    if prefix_len == 0 {
        return Ipv4Addr::UNSPECIFIED;
    }
    Ipv4Addr::from(u32::MAX << (32 - prefix_len.min(32)))
}

async fn send_release(
    transport: &dyn DhcpClientTransport,
    lease: &DhcpClientLease,
    hostname: Option<&str>,
) -> Result<()> {
    let hardware_address: [u8; 6] = lease
        .hardware_address
        .as_slice()
        .try_into()
        .context("persisted DHCP lease has a non-Ethernet hardware address")?;
    let builder = ClientPacketBuilder::new(rand::random(), hardware_address);
    let builder = match hostname {
        Some(hostname) => builder.hostname(hostname),
        None => builder,
    };
    let packet = builder.release(lease.address, lease.server_identifier)?;
    transport
        .send(&packet, SendKind::Unicast(lease.server_identifier))
        .await
}

async fn stop_running(running: RunningDhcpClient) {
    let _ = running.cancel.send(true);
    let mut task = running.task;
    match tokio::time::timeout(TASK_STOP_TIMEOUT, &mut task).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => {
            // The actor returned an error, but it is conclusively stopped.
            tracing::debug!(error = %format!("{error:#}"), "DHCP client task returned an error while stopping")
        }
        Ok(Err(error)) => {
            // A completed JoinHandle (including panic/cancellation) cannot keep
            // mutating network state, so it is safe to continue cleanup.
            tracing::debug!(error = %format!("{error:#}"), "DHCP client task did not join cleanly")
        }
        Err(_) => {
            // Dropping a JoinHandle detaches the task.  A renew/rollback must
            // never start a replacement while the old actor might still own
            // the interface, so force cancellation and wait for completion.
            tracing::warn!("DHCP client task did not stop in time; aborting it");
            task.abort();
            match task.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::debug!(error = %format!("{error:#}"), "aborted DHCP client task returned an error")
                }
                Err(error) if error.is_cancelled() => {}
                Err(error) => {
                    tracing::debug!(error = %format!("{error:#}"), "aborted DHCP client task did not join cleanly")
                }
            }
        }
    }
}

fn backoff(consecutive_failures: u32) -> Duration {
    let multiplier = 1u32.checked_shl(consecutive_failures.saturating_sub(1));
    multiplier
        .and_then(|multiplier| RESTART_BACKOFF_BASE.checked_mul(multiplier))
        .unwrap_or(BACKOFF_CEILING)
        .min(BACKOFF_CEILING)
}

fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests;
