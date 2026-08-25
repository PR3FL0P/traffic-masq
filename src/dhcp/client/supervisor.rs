use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use async_trait::async_trait;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::config::{
    AppConfig, DhcpClientInterfaceConfig, InterfaceConfig, InterfaceRole, ShutdownPolicy,
};
use crate::dhcp::client::lease::{
    DhcpClientLease, DhcpClientLeaseState, DhcpClientOwnedRoute, DHCP_CLIENT_LEASE_SCHEMA_VERSION,
};
use crate::dhcp::client::ownership::DhcpClientOwnershipApplier;
use crate::dhcp::client::packet::ClientPacketBuilder;
use crate::dhcp::client::runtime::{DhcpClientActionSink, DhcpClientTransport};
use crate::dhcp::client::state_machine::{Lease, SendKind};
use crate::dhcp::client::store::DhcpClientLeaseStore;
use crate::netlink::{NetworkProvider, TRAFFIC_MASQ_DHCP_ROUTE_PROTOCOL};

const MAIN_ROUTE_TABLE: u32 = 254;

const GATEWAY_ROUTE_SCOPE: u8 = 0;

const RESTART_BACKOFF_BASE: Duration = Duration::from_secs(2);
const BACKOFF_CEILING: Duration = Duration::from_secs(120);

const TASK_STOP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpClientSpec {
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
            route_metric: dhcp_client.route_metric,
            install_default_route: dhcp_client.install_default_route,
            request_dns: dhcp_client.request_dns,
            send_release_on_shutdown: dhcp_client.send_release_on_shutdown,
        }
    }

    pub fn validate(&self) -> Result<()> {
        crate::config::validate_interface_name(&self.interface)?;
        let config = InterfaceConfig {
            role: InterfaceRole::Input,
            managed: true,
            ipv4: None,
            dhcp: None,
            dhcp_client: Some(self.interface_config()),
            wifi: None,
            wifi_client: None,
        nat: true,
        };
        config.validate(&self.interface)
    }

    pub fn interface_config(&self) -> DhcpClientInterfaceConfig {
        DhcpClientInterfaceConfig {
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

        let config = DhcpClientRuntimeConfig::new(
            launch.interface.clone(),
            launch.interface_index,
            launch.hardware_address,
        );
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
    network: Arc<dyn NetworkProvider>,
    applier: Arc<DhcpClientOwnershipApplier>,
    launcher: Arc<dyn DhcpClientLauncher>,
    tasks: Mutex<HashMap<String, ClientTask>>,
    operation_lock: Mutex<()>,
}

impl DhcpClientSupervisor {
    #[cfg(target_os = "linux")]
    pub async fn start(config: &AppConfig, network: Arc<dyn NetworkProvider>) -> Result<Self> {
        Self::start_with_launcher(config, network, Arc::new(LinuxDhcpClientLauncher)).await
    }

    pub async fn start_with_launcher(
        config: &AppConfig,
        network: Arc<dyn NetworkProvider>,
        launcher: Arc<dyn DhcpClientLauncher>,
    ) -> Result<Self> {
        let store = DhcpClientLeaseStore::new(&config.runtime.state_dir)
            .context("failed to open the DHCP client lease store")?;
        let supervisor = Self {
            inner: Arc::new(Inner {
                applier: Arc::new(DhcpClientOwnershipApplier::new(network.clone(), store)),
                network,
                launcher,
                tasks: Mutex::new(HashMap::new()),
                operation_lock: Mutex::new(()),
            }),
        };

        for spec in Self::effective_specs(config)? {
            let link_ready = config
                .network
                .interfaces
                .get(&spec.interface)
                .is_some_and(|interface| interface.wifi_client.is_none());

            supervisor.configure_with_link_ready(spec, link_ready).await;
        }
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

    pub async fn configure(&self, spec: DhcpClientSpec) {
        self.configure_with_link_ready(spec, true).await;
    }

    pub async fn configure_with_link_ready(&self, spec: DhcpClientSpec, link_ready: bool) {
        let _operation = self.inner.operation_lock.lock().await;
        let interface = spec.interface.clone();
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
            self.record_waiting(&interface).await;
            if readiness_changed {
                tracing::info!(%interface, "DHCP client paused while Wi-Fi is not associated");
            }
        }
    }

    pub async fn disable(&self, interface: &str) -> Result<Option<DhcpClientSpec>> {
        let _operation = self.inner.operation_lock.lock().await;
        if !self.inner.tasks.lock().await.contains_key(interface) {
            return Ok(None);
        }
        self.stop_task(interface).await;
        if let Err(error) = self.inner.applier.cleanup(interface).await {
            tracing::warn!(%interface, %error, "failed to release owned DHCP client state while disabling it; cleanup will be retried");
            return Err(error.into());
        }
        let task = self.inner.tasks.lock().await.remove(interface);
        tracing::info!(%interface, "DHCP client disabled");
        Ok(task.map(|task| task.spec))
    }

    pub async fn reconcile(&self, spec: DhcpClientSpec) {
        self.reconcile_with_link_ready(spec, true).await;
    }

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
            state: match (&state, &shared.failure) {
                (DhcpClientRunState::Running, Some(reason)) => DhcpClientRunState::Degraded {
                    reason: reason.clone(),
                },
                _ => state,
            },
            lease: shared.lease.clone(),
        })
    }

    pub async fn verify_bound_lease(&self, lease: &DhcpClientLease) -> Result<()> {
        self.inner
            .applier
            .observe_exact(lease)
            .await
            .map_err(Into::into)
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

    pub async fn renew_now(&self, interface: &str) -> Result<DhcpClientStatus> {
        let _operation = self.inner.operation_lock.lock().await;
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
        self.status(interface)
            .await
            .context("DHCP client interface disappeared during renew")
    }

    pub async fn release_and_reacquire(&self, interface: &str) -> Result<DhcpClientStatus> {
        let _operation = self.inner.operation_lock.lock().await;
        let (link_ready, transport, shared) = {
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
            )
        };
        let lease = shared.lock().await.lease.clone();
        self.stop_task(interface).await;
        let release_error = if let (Some(transport), Some(lease)) = (transport, lease.as_ref()) {
            send_release(transport.as_ref(), lease).await.err()
        } else {
            None
        };
        self.inner.applier.cleanup(interface).await?;
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
            tracing::warn!(%interface, %error, "DHCP RELEASE could not be delivered; owned state was still cleaned up");
        }
        self.status(interface)
            .await
            .context("DHCP client interface disappeared during release")
    }

    pub async fn ensure_alive(&self) -> Result<bool> {
        let _operation = self.inner.operation_lock.lock().await;
        let interfaces: Vec<String> = self.inner.tasks.lock().await.keys().cloned().collect();
        let mut changed = false;
        for interface in interfaces {
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

            let _ = self.adopt_persisted_lease(interface).await;
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
                if backed_off {
                    return false;
                }
                if has_running && identity == Some(observed) {
                    let reason = self.reap_finished(interface).await;
                    tracing::warn!(
                        %interface,
                        reason = %reason.as_deref().unwrap_or("task exited"),
                        "DHCP client task stopped; restarting it"
                    );
                } else if has_running {
                    tracing::info!(%interface, "DHCP client interface identity changed; restarting its client");
                    self.stop_task(interface).await;
                }
                self.start_task(interface).await;
                true
            }
        }
    }

    pub async fn shutdown(&self, policy: ShutdownPolicy) {
        let _operation = self.inner.operation_lock.lock().await;
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
                    if let Err(error) = send_release(transport.as_ref(), lease).await {
                        tracing::warn!(%interface, %error, "failed to send DHCP RELEASE during shutdown");
                    }
                }
            }
            if let Err(error) = self.inner.applier.cleanup(&interface).await {
                tracing::warn!(%interface, %error, "failed to clean up owned DHCP client state during shutdown");
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
        let remembered = self.adopt_persisted_lease(interface).await;
        let (spec, shared) = {
            let tasks = self.inner.tasks.lock().await;
            let Some(task) = tasks.get(interface) else {
                return;
            };
            (task.spec.clone(), task.shared.clone())
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
        };
        let launch = DhcpClientLaunch {
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
                    task.consecutive_failures = 0;
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
                tracing::error!(%interface, %error, "failed to start the DHCP client");
                self.record_failure(interface, error.to_string()).await;
            }
        }
    }

    async fn adopt_persisted_lease(&self, interface: &str) -> Option<DhcpClientLease> {
        match self
            .inner
            .applier
            .adopt(interface, current_unix_time())
            .await
        {
            Ok(lease) => lease,
            Err(error) => {
                tracing::warn!(
                    %interface,
                    %error,
                    "persisted DHCP lease could not be adopted; releasing any state it still proves"
                );
                if let Err(error) = self.inner.applier.cleanup(interface).await {
                    tracing::warn!(%interface, %error, "failed to clean up an unadoptable DHCP lease");
                }
                None
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

    async fn reap_finished(&self, interface: &str) -> Option<String> {
        let running = {
            let mut tasks = self.inner.tasks.lock().await;
            tasks
                .get_mut(interface)
                .and_then(|task| task.running.take())
        }?;
        let reason = match running.task.await {
            Ok(Ok(())) => "client task exited".to_string(),
            Ok(Err(error)) => error.to_string(),
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
}

#[async_trait]
impl DhcpClientActionSink for OwnershipSink {
    async fn lease_acquired(&mut self, lease: Lease) -> Result<()> {
        let persisted = self.persisted_lease(&lease);
        match self.applier.apply(persisted).await {
            Ok(applied) => {
                let mut shared = self.shared.lock().await;
                shared.lease = Some(applied);
                shared.failure = None;
                Ok(())
            }
            Err(error) => {
                let reason = error.to_string();
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
        let result = self.applier.cleanup(&self.spec.interface).await;
        let mut shared = self.shared.lock().await;
        shared.lease = None;
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                let reason = error.to_string();
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
        if !self.spec.install_default_route {
            return Vec::new();
        }
        let Some(gateway) = lease.routers.first().copied() else {
            return Vec::new();
        };
        vec![DhcpClientOwnedRoute {
            destination: Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).expect("0.0.0.0/0 is valid"),
            gateway: Some(gateway),
            output_interface_index: Some(self.identity.index),
            table: MAIN_ROUTE_TABLE,
            metric: Some(self.spec.route_metric),
            protocol: TRAFFIC_MASQ_DHCP_ROUTE_PROTOCOL,
            scope: GATEWAY_ROUTE_SCOPE,
        }]
    }
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

async fn send_release(transport: &dyn DhcpClientTransport, lease: &DhcpClientLease) -> Result<()> {
    let hardware_address: [u8; 6] = lease
        .hardware_address
        .as_slice()
        .try_into()
        .context("persisted DHCP lease has a non-Ethernet hardware address")?;
    let packet = ClientPacketBuilder::new(rand::random(), hardware_address)
        .release(lease.address, lease.server_identifier)?;
    transport
        .send(&packet, SendKind::Unicast(lease.server_identifier))
        .await
}

async fn stop_running(running: RunningDhcpClient) {
    let _ = running.cancel.send(true);
    match tokio::time::timeout(TASK_STOP_TIMEOUT, running.task).await {
        Ok(Ok(Ok(()))) | Err(_) => {}
        Ok(Ok(Err(error))) => {
            tracing::debug!(%error, "DHCP client task returned an error while stopping")
        }
        Ok(Err(error)) => tracing::debug!(%error, "DHCP client task did not join cleanly"),
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
mod tests {
    use crate::netlink::{AddressOwnership, TRAFFIC_MASQ_DHCP_ADDRESS_PROTOCOL};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tempfile::TempDir;

    use super::*;
    use crate::config::{DhcpClientInterfaceConfig, NetworkConfig};
    use crate::netlink::{Ipv4AddressInfo, Ipv4RouteInfo, Ipv4RouteSpec, NetworkInterface};

    const MAC: [u8; 6] = [2, 0, 0, 0, 0, 7];

    #[derive(Default)]
    struct FakeNetwork {
        interfaces: Mutex<Vec<NetworkInterface>>,
        addresses: Mutex<Vec<Ipv4AddressInfo>>,
        routes: Mutex<Vec<Ipv4RouteInfo>>,
        mac: Mutex<Vec<u8>>,
        fail_address_deletes: AtomicUsize,
    }

    impl FakeNetwork {
        fn detached() -> Arc<Self> {
            Arc::new(Self {
                mac: Mutex::new(MAC.to_vec()),
                ..Self::default()
            })
        }

        async fn present(index: u32) -> Arc<Self> {
            let network = Self::detached();
            network.attach("wan0", index).await;
            network
        }

        async fn attach(&self, name: &str, index: u32) {
            self.interfaces.lock().await.push(NetworkInterface {
                is_wireless: false,
                index,
                name: name.to_string(),
                is_up: true,
                rx_bytes: 0,
                tx_bytes: 0,
            });
        }

        async fn detach(&self, name: &str) {
            self.interfaces
                .lock()
                .await
                .retain(|interface| interface.name != name);
        }
    }

    #[async_trait]
    impl NetworkProvider for FakeNetwork {
        async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
            Ok(self.interfaces.lock().await.clone())
        }

        async fn hardware_address(&self, _interface: &str) -> Result<Vec<u8>> {
            Ok(self.mac.lock().await.clone())
        }

        async fn list_ipv4_addresses(&self, _interface: &str) -> Result<Vec<Ipv4AddressInfo>> {
            Ok(self.addresses.lock().await.clone())
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
            address: Ipv4Addr,
            prefix_len: u8,
            ownership: AddressOwnership,
        ) -> Result<()> {
            self.addresses.lock().await.push(Ipv4AddressInfo {
                interface_index: 7,
                address,
                prefix_len,
                protocol: ownership.protocol(),
            });
            Ok(())
        }

        async fn delete_ipv4_address(
            &self,
            _interface: &str,
            address: Ipv4Addr,
            prefix_len: u8,
        ) -> Result<()> {
            if self.fail_address_deletes.load(Ordering::SeqCst) > 0 {
                self.fail_address_deletes.fetch_sub(1, Ordering::SeqCst);
                anyhow::bail!("injected address delete failure");
            }
            self.addresses
                .lock()
                .await
                .retain(|item| item.address != address || item.prefix_len != prefix_len);
            Ok(())
        }

        async fn list_ipv4_routes(&self) -> Result<Vec<Ipv4RouteInfo>> {
            Ok(self.routes.lock().await.clone())
        }

        async fn add_ipv4_route(&self, route: &Ipv4RouteSpec) -> Result<()> {
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
            self.routes.lock().await.retain(|item| item != route);
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeLauncher {
        launches: std::sync::Mutex<Vec<String>>,
        remembered: std::sync::Mutex<Vec<Option<Ipv4Addr>>>,
        sinks: std::sync::Mutex<Vec<Box<dyn DhcpClientActionSink>>>,
        sends: Arc<std::sync::Mutex<Vec<(Vec<u8>, SendKind)>>>,
        fail_next: AtomicUsize,

        exit_immediately: AtomicUsize,
    }

    struct FakeTransport(Arc<std::sync::Mutex<Vec<(Vec<u8>, SendKind)>>>);

    #[async_trait]
    impl DhcpClientTransport for FakeTransport {
        async fn receive(&self) -> Result<crate::dhcp::client::runtime::IngressDatagram> {
            std::future::pending().await
        }

        async fn send(&self, packet: &[u8], kind: SendKind) -> Result<()> {
            self.0.lock().unwrap().push((packet.to_vec(), kind));
            Ok(())
        }
    }

    #[async_trait]
    impl DhcpClientLauncher for FakeLauncher {
        async fn launch(&self, launch: DhcpClientLaunch) -> Result<RunningDhcpClient> {
            if self.fail_next.load(Ordering::SeqCst) > 0 {
                self.fail_next.fetch_sub(1, Ordering::SeqCst);
                anyhow::bail!("injected launch failure");
            }
            self.launches.lock().unwrap().push(launch.interface.clone());
            self.remembered
                .lock()
                .unwrap()
                .push(launch.remembered.as_ref().map(|lease| lease.address));
            self.sinks.lock().unwrap().push(launch.sink);
            let (cancel, mut cancel_rx) = watch::channel(false);
            let exit = self.exit_immediately.load(Ordering::SeqCst) > 0;
            if exit {
                self.exit_immediately.fetch_sub(1, Ordering::SeqCst);
            }
            let task = tokio::spawn(async move {
                if exit {
                    anyhow::bail!("injected actor failure");
                }
                while cancel_rx.changed().await.is_ok() {
                    if *cancel_rx.borrow() {
                        break;
                    }
                }
                Ok(())
            });
            Ok(RunningDhcpClient {
                cancel,
                task,
                transport: Arc::new(FakeTransport(self.sends.clone())),
            })
        }
    }

    impl FakeLauncher {
        fn launch_count(&self) -> usize {
            self.launches.lock().unwrap().len()
        }

        fn take_sink(&self) -> Box<dyn DhcpClientActionSink> {
            self.sinks.lock().unwrap().pop().expect("a launched sink")
        }
    }

    fn config(state_dir: &TempDir, interface: Option<DhcpClientInterfaceConfig>) -> AppConfig {
        let mut config = AppConfig::default();
        config.runtime.state_dir = state_dir.path().to_path_buf();
        let mut network = NetworkConfig::default();
        network.interfaces.insert(
            "wan0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Input,
                managed: interface.is_some(),
                ipv4: None,
                dhcp: None,
                dhcp_client: interface,
                wifi: None,
                wifi_client: None,
            nat: true,
            },
        );
        config.network = network;
        config
    }

    fn spec() -> DhcpClientSpec {
        DhcpClientSpec {
            interface: "wan0".to_string(),
            route_metric: 100,
            install_default_route: true,
            request_dns: true,
            send_release_on_shutdown: false,
        }
    }

    fn lease(address: Ipv4Addr) -> Lease {
        Lease {
            address,
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            prefix_len: 24,
            routers: vec![Ipv4Addr::new(192, 0, 2, 1)],
            dns_servers: vec![Ipv4Addr::new(192, 0, 2, 53)],
            server_identifier: Ipv4Addr::new(192, 0, 2, 1),
            acquired_at: Duration::ZERO,
            renewal_at: Duration::from_secs(1800),
            rebinding_at: Duration::from_secs(3150),
            expires_at: Duration::from_secs(3600),
        }
    }

    async fn supervisor_with(
        state_dir: &TempDir,
        network: Arc<FakeNetwork>,
        launcher: Arc<FakeLauncher>,
    ) -> DhcpClientSupervisor {
        DhcpClientSupervisor::start_with_launcher(
            &config(state_dir, Some(DhcpClientInterfaceConfig::default())),
            network,
            launcher,
        )
        .await
        .expect("supervisor")
    }

    #[test]
    fn spec_is_derived_only_from_an_enabled_block() {
        let mut interface = InterfaceConfig {
            role: InterfaceRole::Input,
            managed: true,
            ipv4: None,
            dhcp: None,
            dhcp_client: Some(DhcpClientInterfaceConfig::default()),
            wifi: None,
            wifi_client: None,
        nat: true,
        };
        let derived = DhcpClientSpec::from_interface_config("wan0", &interface)
            .expect("valid")
            .expect("spec");
        assert_eq!(derived, spec());
        derived.validate().expect("round-tripped spec stays valid");
        assert_eq!(
            derived.interface_config(),
            DhcpClientInterfaceConfig::default()
        );

        interface.dhcp_client.as_mut().unwrap().enabled = false;
        interface.managed = false;
        assert!(DhcpClientSpec::from_interface_config("wan0", &interface)
            .expect("valid")
            .is_none());

        interface.dhcp_client = None;
        assert!(DhcpClientSpec::from_interface_config("wan0", &interface)
            .expect("valid")
            .is_none());
    }

    #[tokio::test]
    async fn absent_interface_waits_without_failing_startup_and_starts_on_hotplug() {
        let state_dir = TempDir::new().expect("state dir");
        let network = FakeNetwork::detached();
        let launcher = Arc::new(FakeLauncher::default());
        let supervisor = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;

        assert_eq!(launcher.launch_count(), 0);
        let status = supervisor.status("wan0").await.expect("status");
        assert_eq!(status.state, DhcpClientRunState::WaitingForInterface);
        assert!(status.lease.is_none());

        network.attach("wan0", 7).await;
        assert!(supervisor.ensure_alive().await.expect("ensure alive"));
        assert_eq!(launcher.launch_count(), 1);
        assert_eq!(
            supervisor.status("wan0").await.expect("status").state,
            DhcpClientRunState::Running
        );
    }

    #[tokio::test]
    async fn repeated_reconcile_never_restarts_a_healthy_client() {
        let state_dir = TempDir::new().expect("state dir");
        let network = FakeNetwork::present(7).await;
        let launcher = Arc::new(FakeLauncher::default());
        let supervisor = supervisor_with(&state_dir, network, launcher.clone()).await;
        assert_eq!(launcher.launch_count(), 1);

        for _ in 0..5 {
            supervisor.reconcile(spec()).await;
            supervisor.ensure_alive().await.expect("ensure alive");
        }
        assert_eq!(launcher.launch_count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn launch_failure_degrades_and_retries_under_bounded_backoff() {
        let state_dir = TempDir::new().expect("state dir");
        let network = FakeNetwork::present(7).await;
        let launcher = Arc::new(FakeLauncher::default());
        launcher.fail_next.store(1, Ordering::SeqCst);
        let supervisor = supervisor_with(&state_dir, network, launcher.clone()).await;

        assert_eq!(launcher.launch_count(), 0);
        let status = supervisor.status("wan0").await.expect("status");
        assert!(matches!(status.state, DhcpClientRunState::Degraded { .. }));

        assert!(!supervisor.ensure_alive().await.expect("ensure alive"));
        assert_eq!(launcher.launch_count(), 0);

        tokio::time::advance(RESTART_BACKOFF_BASE + Duration::from_millis(1)).await;
        assert!(supervisor.ensure_alive().await.expect("ensure alive"));
        assert_eq!(launcher.launch_count(), 1);
        assert_eq!(
            supervisor.status("wan0").await.expect("status").state,
            DhcpClientRunState::Running
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_task_that_exits_is_restarted_rather_than_left_dead() {
        let state_dir = TempDir::new().expect("state dir");
        let network = FakeNetwork::present(7).await;
        let launcher = Arc::new(FakeLauncher::default());
        launcher.exit_immediately.store(1, Ordering::SeqCst);
        let supervisor = supervisor_with(&state_dir, network, launcher.clone()).await;
        assert_eq!(launcher.launch_count(), 1);

        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(supervisor.ensure_alive().await.expect("ensure alive"));
        assert_eq!(launcher.launch_count(), 2);
    }

    #[tokio::test]
    async fn replug_with_a_new_ifindex_restarts_the_client() {
        let state_dir = TempDir::new().expect("state dir");
        let network = FakeNetwork::present(7).await;
        let launcher = Arc::new(FakeLauncher::default());
        let supervisor = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;
        assert_eq!(launcher.launch_count(), 1);

        network.detach("wan0").await;
        assert!(supervisor.ensure_alive().await.expect("ensure alive"));
        assert_eq!(
            supervisor.status("wan0").await.expect("status").state,
            DhcpClientRunState::WaitingForInterface
        );

        network.attach("wan0", 11).await;
        assert!(supervisor.ensure_alive().await.expect("ensure alive"));
        assert_eq!(launcher.launch_count(), 2);
        assert!(supervisor.ensure_alive().await.expect("ensure alive") == false);
    }

    #[tokio::test]
    async fn an_acquired_lease_is_applied_persisted_and_reported() {
        let state_dir = TempDir::new().expect("state dir");
        let network = FakeNetwork::present(7).await;
        let launcher = Arc::new(FakeLauncher::default());
        let supervisor = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;

        let mut sink = launcher.take_sink();
        sink.lease_acquired(lease(Ipv4Addr::new(192, 0, 2, 42)))
            .await
            .expect("lease applied");

        let status = supervisor.status("wan0").await.expect("status");
        assert_eq!(status.state, DhcpClientRunState::Running);
        let applied = status.lease.expect("lease");
        assert_eq!(applied.address, Ipv4Addr::new(192, 0, 2, 42));
        assert_eq!(applied.state, DhcpClientLeaseState::Bound);
        assert_eq!(applied.owned_routes.len(), 1);
        assert_eq!(applied.owned_routes[0].metric, Some(100));
        assert_eq!(
            applied.owned_routes[0].protocol,
            TRAFFIC_MASQ_DHCP_ROUTE_PROTOCOL
        );
        assert_eq!(
            network
                .list_ipv4_addresses("wan0")
                .await
                .expect("addresses"),
            vec![Ipv4AddressInfo {
                interface_index: 7,
                // A DHCP-held address is tagged as such, so it is
                // distinguishable from a hand-configured one.
                address: Ipv4Addr::new(192, 0, 2, 42),
                prefix_len: 24,
                protocol: Some(TRAFFIC_MASQ_DHCP_ADDRESS_PROTOCOL),
            }]
        );

        sink.cleanup_needed(lease(Ipv4Addr::new(192, 0, 2, 42)))
            .await
            .expect("cleanup");
        assert!(network
            .list_ipv4_addresses("wan0")
            .await
            .expect("addresses")
            .is_empty());
        assert!(network.list_ipv4_routes().await.expect("routes").is_empty());
        assert!(supervisor
            .status("wan0")
            .await
            .expect("status")
            .lease
            .is_none());
    }

    #[tokio::test]
    async fn a_still_valid_lease_is_adopted_on_restart_instead_of_reacquired() {
        let state_dir = TempDir::new().expect("state dir");
        let network = FakeNetwork::present(7).await;
        let launcher = Arc::new(FakeLauncher::default());
        let supervisor = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;
        let mut sink = launcher.take_sink();
        sink.lease_acquired(lease(Ipv4Addr::new(192, 0, 2, 42)))
            .await
            .expect("lease applied");

        let restarted = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;
        assert_eq!(
            launcher
                .remembered
                .lock()
                .unwrap()
                .last()
                .copied()
                .flatten(),
            Some(Ipv4Addr::new(192, 0, 2, 42)),
            "a valid persisted lease must be adopted into INIT-REBOOT"
        );
        assert_eq!(
            restarted
                .status("wan0")
                .await
                .expect("status")
                .lease
                .expect("lease")
                .address,
            Ipv4Addr::new(192, 0, 2, 42)
        );
        drop(supervisor);
    }

    #[tokio::test]
    async fn wifi_gate_blocks_until_completed_and_disconnect_holds_valid_lease() {
        let state_dir = TempDir::new().expect("state dir");
        let network = FakeNetwork::present(7).await;
        let launcher = Arc::new(FakeLauncher::default());
        let supervisor = DhcpClientSupervisor::start_with_launcher(
            &config(&state_dir, None),
            network.clone(),
            launcher.clone(),
        )
        .await
        .expect("supervisor");

        supervisor.configure_with_link_ready(spec(), false).await;
        assert_eq!(launcher.launch_count(), 0, "no DHCP before association");
        supervisor.reconcile_with_link_ready(spec(), false).await;
        assert_eq!(
            launcher.launch_count(),
            0,
            "polling must not create a restart loop"
        );

        supervisor.reconcile_with_link_ready(spec(), true).await;
        assert_eq!(launcher.launch_count(), 1, "COMPLETED starts DHCP");
        let mut sink = launcher.take_sink();
        sink.lease_acquired(lease(Ipv4Addr::new(192, 0, 2, 42)))
            .await
            .expect("lease applied");

        supervisor.reconcile_with_link_ready(spec(), false).await;
        assert_eq!(
            launcher.launch_count(),
            1,
            "disconnect stops rather than restarts"
        );
        assert!(
            launcher.sends.lock().unwrap().is_empty(),
            "disconnect sends no RELEASE"
        );
        assert_eq!(
            network.addresses.lock().await.len(),
            1,
            "valid lease is held"
        );

        supervisor.reconcile_with_link_ready(spec(), true).await;
        assert_eq!(launcher.launch_count(), 2);
        assert_eq!(
            launcher
                .remembered
                .lock()
                .unwrap()
                .last()
                .copied()
                .flatten(),
            Some(Ipv4Addr::new(192, 0, 2, 42)),
            "reconnect revalidates the remembered lease with INIT-REBOOT"
        );
    }

    #[tokio::test]
    async fn lease_expiry_while_wifi_is_disconnected_cleans_owned_state() {
        let state_dir = TempDir::new().expect("state dir");
        let network = FakeNetwork::present(7).await;
        let launcher = Arc::new(FakeLauncher::default());
        let supervisor = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;
        let mut sink = launcher.take_sink();
        sink.lease_acquired(lease(Ipv4Addr::new(192, 0, 2, 42)))
            .await
            .expect("lease applied");
        supervisor.reconcile_with_link_ready(spec(), false).await;

        let store = DhcpClientLeaseStore::new(state_dir.path()).expect("store");
        let mut persisted = store.load("wan0").expect("load").expect("lease");
        persisted.expires_at_unix = current_unix_time();
        store.save(&persisted).expect("expire lease");

        supervisor.ensure_alive().await.expect("expiry check");
        assert!(network.addresses.lock().await.is_empty());
        assert!(network.routes.lock().await.is_empty());
        assert!(store.load("wan0").expect("load").is_none());
        supervisor.reconcile_with_link_ready(spec(), true).await;
        assert_eq!(launcher.remembered.lock().unwrap().last(), Some(&None));
    }

    #[tokio::test]
    async fn preserve_shutdown_keeps_owned_state_and_sends_no_release() {
        let state_dir = TempDir::new().expect("state dir");
        let network = FakeNetwork::present(7).await;
        let launcher = Arc::new(FakeLauncher::default());
        let supervisor = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;
        let mut sink = launcher.take_sink();
        sink.lease_acquired(lease(Ipv4Addr::new(192, 0, 2, 42)))
            .await
            .expect("lease applied");

        supervisor
            .shutdown(ShutdownPolicy::PreserveInterfaces)
            .await;

        assert!(launcher.sends.lock().unwrap().is_empty());
        assert_eq!(
            network
                .list_ipv4_addresses("wan0")
                .await
                .expect("addresses")
                .len(),
            1,
            "a preserved uplink must keep its address across a daemon restart"
        );
        assert_eq!(network.list_ipv4_routes().await.expect("routes").len(), 1);
    }

    #[tokio::test]
    async fn destructive_shutdown_releases_when_asked_and_cleans_up_owned_state() {
        let state_dir = TempDir::new().expect("state dir");
        let network = FakeNetwork::present(7).await;
        let launcher = Arc::new(FakeLauncher::default());
        let mut config = config(&state_dir, Some(DhcpClientInterfaceConfig::default()));
        config
            .network
            .interfaces
            .get_mut("wan0")
            .unwrap()
            .dhcp_client
            .as_mut()
            .unwrap()
            .send_release_on_shutdown = true;
        let supervisor =
            DhcpClientSupervisor::start_with_launcher(&config, network.clone(), launcher.clone())
                .await
                .expect("supervisor");
        let mut sink = launcher.take_sink();
        sink.lease_acquired(lease(Ipv4Addr::new(192, 0, 2, 42)))
            .await
            .expect("lease applied");

        supervisor.shutdown(ShutdownPolicy::RestoreInterfaces).await;

        let sends = launcher.sends.lock().unwrap().clone();
        assert_eq!(sends.len(), 1, "exactly one RELEASE");
        assert_eq!(
            sends[0].1,
            SendKind::Unicast(Ipv4Addr::new(192, 0, 2, 1)),
            "RELEASE is unicast to the server that granted the lease"
        );
        assert!(network
            .list_ipv4_addresses("wan0")
            .await
            .expect("addresses")
            .is_empty());
        assert!(network.list_ipv4_routes().await.expect("routes").is_empty());
    }

    #[tokio::test]
    async fn disabling_an_interface_stops_it_and_gives_back_owned_state() {
        let state_dir = TempDir::new().expect("state dir");
        let network = FakeNetwork::present(7).await;
        let launcher = Arc::new(FakeLauncher::default());
        let supervisor = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;
        let mut sink = launcher.take_sink();
        sink.lease_acquired(lease(Ipv4Addr::new(192, 0, 2, 42)))
            .await
            .expect("lease applied");

        let removed = supervisor.disable("wan0").await.expect("disable");
        assert_eq!(removed, Some(spec()));
        assert!(supervisor.status("wan0").await.is_none());
        assert!(network
            .list_ipv4_addresses("wan0")
            .await
            .expect("addresses")
            .is_empty());

        assert!(supervisor.disable("wan0").await.expect("disable").is_none());
    }

    #[tokio::test]
    async fn failed_disable_cleanup_keeps_intent_and_retries_exactly() {
        let state_dir = TempDir::new().expect("state dir");
        let network = FakeNetwork::present(7).await;
        let launcher = Arc::new(FakeLauncher::default());
        let supervisor = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;
        let mut sink = launcher.take_sink();
        let address = Ipv4Addr::new(192, 0, 2, 42);
        sink.lease_acquired(lease(address))
            .await
            .expect("lease applied");

        network.fail_address_deletes.store(1, Ordering::SeqCst);
        supervisor
            .disable("wan0")
            .await
            .expect_err("transient cleanup failure must be reported");
        assert_eq!(supervisor.spec("wan0").await, Some(spec()));
        assert!(network
            .list_ipv4_addresses("wan0")
            .await
            .expect("addresses")
            .iter()
            .any(|item| item.address == address));

        let removed = supervisor
            .disable("wan0")
            .await
            .expect("cleanup retry succeeds");
        assert_eq!(removed, Some(spec()));
        assert!(supervisor.spec("wan0").await.is_none());
        assert!(network
            .list_ipv4_addresses("wan0")
            .await
            .expect("addresses")
            .is_empty());
    }

    #[tokio::test]
    async fn a_refused_lease_application_degrades_the_client_without_touching_foreign_state() {
        let state_dir = TempDir::new().expect("state dir");
        let network = FakeNetwork::present(7).await;

        network.addresses.lock().await.push(Ipv4AddressInfo {
            interface_index: 7,
            address: Ipv4Addr::new(192, 0, 2, 42),
            prefix_len: 24,
            protocol: None,
        });
        let launcher = Arc::new(FakeLauncher::default());
        let supervisor = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;
        let mut sink = launcher.take_sink();

        let error = sink
            .lease_acquired(lease(Ipv4Addr::new(192, 0, 2, 42)))
            .await
            .expect_err("a foreign address must never be taken over");
        assert!(error.to_string().contains("wan0"));

        let status = supervisor.status("wan0").await.expect("status");
        assert!(matches!(status.state, DhcpClientRunState::Degraded { .. }));
        assert!(status.lease.is_none());
        assert_eq!(
            network
                .list_ipv4_addresses("wan0")
                .await
                .expect("addresses")
                .len(),
            1,
            "the foreign address must survive untouched"
        );
    }

    #[tokio::test]
    async fn renew_now_restarts_with_remembered_lease_without_cleanup() {
        let state_dir = TempDir::new().expect("state dir");
        let network = FakeNetwork::present(7).await;
        let launcher = Arc::new(FakeLauncher::default());
        let supervisor = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;
        let mut sink = launcher.take_sink();
        let address = Ipv4Addr::new(192, 0, 2, 42);
        sink.lease_acquired(lease(address))
            .await
            .expect("apply lease");

        let status = supervisor.renew_now("wan0").await.expect("renew");
        assert_eq!(
            status.lease.as_ref().map(|lease| lease.address),
            Some(address)
        );
        assert_eq!(launcher.launch_count(), 2);
        assert_eq!(
            launcher
                .remembered
                .lock()
                .unwrap()
                .last()
                .copied()
                .flatten(),
            Some(address)
        );
        assert!(network
            .list_ipv4_addresses("wan0")
            .await
            .unwrap()
            .iter()
            .any(|item| item.address == address));
    }

    #[tokio::test]
    async fn release_and_reacquire_sends_release_cleans_exact_state_and_keeps_intent() {
        let state_dir = TempDir::new().expect("state dir");
        let network = FakeNetwork::present(7).await;
        let launcher = Arc::new(FakeLauncher::default());
        let supervisor = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;
        let mut sink = launcher.take_sink();
        let address = Ipv4Addr::new(192, 0, 2, 42);
        sink.lease_acquired(lease(address))
            .await
            .expect("apply lease");

        let status = supervisor
            .release_and_reacquire("wan0")
            .await
            .expect("release");
        assert!(status.lease.is_none());
        assert_eq!(launcher.launch_count(), 2);
        assert!(
            !launcher.sends.lock().unwrap().is_empty(),
            "explicit release must send a packet"
        );
        assert!(network
            .list_ipv4_addresses("wan0")
            .await
            .unwrap()
            .is_empty());
        assert_eq!(supervisor.spec("wan0").await, Some(spec()));
    }

    #[test]
    fn backoff_doubles_and_is_capped() {
        assert_eq!(backoff(1), RESTART_BACKOFF_BASE);
        assert_eq!(backoff(2), RESTART_BACKOFF_BASE * 2);
        assert_eq!(backoff(3), RESTART_BACKOFF_BASE * 4);
        assert_eq!(backoff(64), BACKOFF_CEILING);
    }

    #[test]
    fn a_remembered_lease_carries_only_its_remaining_lifetime() {
        let persisted = DhcpClientLease {
            schema_version: DHCP_CLIENT_LEASE_SCHEMA_VERSION,
            state: DhcpClientLeaseState::Bound,
            interface: "wan0".into(),
            interface_index: 7,
            hardware_address: MAC.to_vec(),
            client_identifier: client_identifier(MAC),
            server_identifier: Ipv4Addr::new(192, 0, 2, 1),
            address: Ipv4Addr::new(192, 0, 2, 42),
            prefix_len: 24,
            routers: vec![Ipv4Addr::new(192, 0, 2, 1)],
            dns_servers: vec![],
            lease_seconds: 3600,
            renewal_seconds: 1800,
            rebinding_seconds: 3150,
            expires_at_unix: current_unix_time() + 600,
            owned_routes: vec![],
        };
        let remembered = monotonic_lease(&persisted);
        assert_eq!(remembered.acquired_at, Duration::ZERO);
        assert!(remembered.expires_at <= Duration::from_secs(600));
        assert!(remembered.renewal_at < remembered.rebinding_at);
        assert!(remembered.rebinding_at < remembered.expires_at);
        assert_eq!(remembered.subnet_mask, Ipv4Addr::new(255, 255, 255, 0));
    }
}
