use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;
use tokio::sync::{Mutex, RwLock};

use crate::config::{AppConfig, InterfaceConfig, ShutdownPolicy};
use crate::dhcp::supervisor::resolve_interface_index;
use crate::wifi::client::ctrl::{
    CtrlError, WpaState, WpaSupplicantCtrlClient, WpaSupplicantEvent, WpaSupplicantEventClient,
};
use crate::wifi::client::render::{
    config_path, render_wpa_supplicant_config, ClientRenderError, ClientRenderInput,
    RenderedClientConfig,
};
use crate::wifi::lifecycle::{
    classify_ownership, cleanup_unconfigured_records, graceful_stop, persist_owned_ctrl_node,
    preflight_binary as preflight_daemon_binary, save_launch_intent, save_spawned_record, unix_now,
    write_private_config, OwnershipOutcome, WifiHealth, STARTUP_POLL_INTERVAL,
    STARTUP_READY_TIMEOUT,
};
use crate::wifi::process::{ProcessError, SupervisedProcess, TokioSupervisedProcess};
use crate::wifi::record::{PersistedWifiRecord, WifiProcessKind, WifiRecordError, WifiRecordStore};
use crate::wifi::render::WifiDigest;
use crate::wifi::retry::{retry_health, RetryState};
use crate::wifi::secret::WifiPassphrase;
use crate::wifi::store::{resolve_passphrase_parts, PassphraseStore, ResolvePassphraseError};
use crate::wifi::supervisor::interface_is_wireless;
use crate::wifi::WifiClientSpec;

const DEFAULT_CTRL_TIMEOUT: Duration = Duration::from_secs(2);

const ASSOCIATION_GRACE: Duration = Duration::from_secs(90);

mod scan;

#[derive(Debug, Error)]
pub enum ClientSupervisorError {
    #[error("Wi-Fi client on {interface} is not configured")]
    NotConfigured { interface: String },

    #[error(
        "refusing to manage wpa_supplicant on {interface}: a process not started by this daemon already occupies its control socket"
    )]
    NotOwned { interface: String },

    #[error("wpa_supplicant for {interface} did not become ready within {timeout:?}")]
    StartupTimeout {
        interface: String,
        timeout: Duration,
    },

    #[error("a Wi-Fi scan is already in progress on {interface}")]
    ScanBusy { interface: String },

    #[error("Wi-Fi scan on {interface} did not complete within {timeout:?}")]
    ScanTimeout {
        interface: String,
        timeout: Duration,
    },

    #[error(transparent)]
    Render(#[from] ClientRenderError),

    #[error(transparent)]
    ResolvePassphrase(#[from] ResolvePassphraseError),

    #[error(transparent)]
    Record(#[from] WifiRecordError),

    #[error(transparent)]
    Process(#[from] ProcessError),

    #[error(transparent)]
    BinaryPreflight(#[from] crate::wifi::lifecycle::BinaryPreflightError),

    #[error(transparent)]
    Ctrl(#[from] CtrlError),

    #[error("{0:#}")]
    Configuration(#[from] anyhow::Error),
}

impl ClientSupervisorError {
    /// The interface this error is about, when there is one.
    pub fn interface(&self) -> &str {
        match self {
            ClientSupervisorError::NotConfigured { interface }
            | ClientSupervisorError::NotOwned { interface }
            | ClientSupervisorError::StartupTimeout { interface, .. } => interface,
            _ => "",
        }
    }
}

#[derive(Debug, Clone)]
struct ClientTask {
    spec: WifiClientSpec,
    record: PersistedWifiRecord,
    retry: RetryState,
    associated_or_started_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WifiClientStatus {
    pub interface: String,
    pub spec: WifiClientSpec,
    pub pid: u32,
    pub wpa_state: WpaState,

    pub bssid: Option<crate::wifi::MacAddr>,
    pub freq: Option<u32>,
    pub health: WifiHealth,
}

#[derive(Clone)]
pub struct WifiClientSupervisor {
    inner: Arc<Inner>,
}

struct AssociationMonitor {
    pid: u32,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for AssociationMonitor {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Inner {
    association_events: tokio::sync::broadcast::Sender<(String, u32)>,
    association_monitors: Mutex<HashMap<String, AssociationMonitor>>,
    wpa_supplicant_binary: PathBuf,
    runtime_dir: PathBuf,
    records_dir: PathBuf,
    restart_backoff_seconds: u64,
    ctrl_timeout: Duration,
    process: Arc<dyn SupervisedProcess>,
    passphrase_store: PassphraseStore,
    tasks: Mutex<HashMap<String, ClientTask>>,
    operation_lock: RwLock<()>,
    interface_operations: crate::core::mutation::InterfaceMutationLocks,
}

#[derive(Clone)]
struct OwnedWpaCtrlIdentity {
    interface: String,
    kind: WifiProcessKind,
    record: PersistedWifiRecord,
    require_current_record: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CtrlSocketNode {
    dev: u64,
    ino: u64,
}

impl CtrlSocketNode {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    }
}

impl OwnedWpaCtrlIdentity {
    fn store(&self, inner: &Inner) -> WifiRecordStore {
        WifiRecordStore::new(
            self.kind,
            &inner.records_dir,
            &inner.runtime_dir,
            &self.interface,
        )
    }

    async fn prove(&self, inner: &Inner) -> Result<bool, ClientSupervisorError> {
        if self.record.pid == 0 || self.record.ctrl_path != inner.runtime_dir.join(&self.interface)
        {
            return Ok(false);
        }

        let store = self.store(inner);
        if store.transition_pending().await? {
            return Ok(false);
        }
        let Some(mut persisted) = store.load().await? else {
            return Ok(false);
        };
        // Recovery may resolve a PID from a durable launch intent, but the
        // intent itself must still match at both sides of connect.
        if !self.require_current_record && persisted.pid == 0 {
            persisted.pid = self.record.pid;
        }
        if persisted != self.record {
            return Ok(false);
        }
        if !inner.process.is_alive(self.record.pid).await? {
            return Ok(false);
        }

        let binary_path = self
            .record
            .binary_path
            .as_deref()
            .unwrap_or(inner.wpa_supplicant_binary.as_path());
        if !inner
            .process
            .identity_matches_record(&self.record, self.kind, binary_path)
            .await?
        {
            return Ok(false);
        }

        Ok(inner
            .process
            .owns_unix_socket(self.record.pid, &self.record.ctrl_path)
            .await?)
    }
}

/// A command socket whose process and pathname ownership were proven both
/// before and after connect. All STA control traffic should originate here.
struct OwnedWpaCtrlSession {
    inner: Arc<Inner>,
    identity: OwnedWpaCtrlIdentity,
    client: WpaSupplicantCtrlClient,
}

impl OwnedWpaCtrlSession {
    async fn capture_ctrl_node(&self) -> Result<CtrlSocketNode, ClientSupervisorError> {
        if !self.identity.prove(&self.inner).await? {
            return Err(ClientSupervisorError::NotOwned {
                interface: self.identity.interface.clone(),
            });
        }

        let metadata = match tokio::fs::symlink_metadata(&self.identity.record.ctrl_path).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(ClientSupervisorError::NotOwned {
                    interface: self.identity.interface.clone(),
                })
            }
            Err(error) => return Err(anyhow::Error::from(error).into()),
        };
        let node = CtrlSocketNode::from_metadata(&metadata);

        // Bind the captured dev/inode to the same ownership proof. If the
        // pathname changed while it was being inspected, do not trust it.
        if !self.identity.prove(&self.inner).await? {
            return Err(ClientSupervisorError::NotOwned {
                interface: self.identity.interface.clone(),
            });
        }
        Ok(node)
    }

    async fn attach_events(
        &self,
    ) -> Result<
        (
            WpaSupplicantEventClient,
            tokio::sync::broadcast::Receiver<WpaSupplicantEvent>,
        ),
        ClientSupervisorError,
    > {
        if !self.identity.prove(&self.inner).await? {
            return Err(ClientSupervisorError::NotOwned {
                interface: self.identity.interface.clone(),
            });
        }
        let connection = WpaSupplicantEventClient::connect(
            &self.identity.record.ctrl_path,
            self.inner.ctrl_timeout,
        )
        .await?;
        // ATTACH is itself a control command. Re-prove after connect and only
        // then allow it to be sent to the connected endpoint.
        if !self.identity.prove(&self.inner).await? {
            return Err(ClientSupervisorError::NotOwned {
                interface: self.identity.interface.clone(),
            });
        }
        Ok(connection.attach().await?)
    }
}

impl WifiClientSupervisor {
    /// Construct supplicant supervision without cleanup or committed-state application.
    pub fn open_for_recovery(config: &AppConfig) -> Self {
        Self::open_with_process_for_recovery(config, Arc::new(TokioSupervisedProcess::new()))
    }

    /// Construct a recovery runtime with an injected process adapter.
    pub fn open_with_process_for_recovery(
        config: &AppConfig,
        process: Arc<dyn SupervisedProcess>,
    ) -> Self {
        let records_dir = config.runtime.state_dir.join("wifi");
        Self {
            inner: Arc::new(Inner {
                association_events: tokio::sync::broadcast::channel(64).0,
                association_monitors: Mutex::new(HashMap::new()),
                wpa_supplicant_binary: config.wifi_client.wpa_supplicant_binary.clone(),
                runtime_dir: config.wifi_client.runtime_dir.clone(),
                passphrase_store: PassphraseStore::for_role(
                    &config.runtime.state_dir,
                    crate::wifi::store::WifiCredentialRole::Client,
                ),
                records_dir,
                restart_backoff_seconds: config.wifi_client.restart_backoff_seconds.max(1),
                ctrl_timeout: DEFAULT_CTRL_TIMEOUT,
                process,
                tasks: Mutex::new(HashMap::new()),
                operation_lock: RwLock::new(()),
                interface_operations: Default::default(),
            }),
        }
    }

    /// Perform normal startup cleanup and apply committed station state.
    pub async fn reconcile_startup(&self, config: &AppConfig) -> Result<(), ClientSupervisorError> {
        crate::wifi::policy::WifiRadioPolicy::validate_system(&config.network)
            .map_err(anyhow::Error::from)?;
        let specs = Self::effective_specs(config)?;
        let configured_interfaces: HashSet<String> =
            specs.iter().map(|spec| spec.interface.clone()).collect();
        let no_interfaces = HashSet::new();
        cleanup_unconfigured_records(
            &self.inner.records_dir,
            &self.inner.runtime_dir,
            WifiProcessKind::Scan,
            &no_interfaces,
            self.inner.process.as_ref(),
            &self.inner.wpa_supplicant_binary,
        )
        .await
        .map_err(ClientSupervisorError::Configuration)?;
        cleanup_unconfigured_records(
            &self.inner.records_dir,
            &self.inner.runtime_dir,
            WifiProcessKind::Client,
            &configured_interfaces,
            self.inner.process.as_ref(),
            &self.inner.wpa_supplicant_binary,
        )
        .await
        .map_err(ClientSupervisorError::Configuration)?;

        for spec in specs {
            if resolve_interface_index(&spec.interface).is_err() {
                tracing::warn!(
                    interface = %spec.interface,
                    "configured Wi-Fi client interface is absent at startup; skipping it — \
                     the runtime reconcile loop will configure it if it reappears"
                );
                continue;
            }
            if !interface_is_wireless(&spec.interface) {
                tracing::warn!(
                    interface = %spec.interface,
                    "configured Wi-Fi client interface has no phy80211 attachment (not a wireless NIC); skipping it"
                );
                continue;
            }
            if let Err(error) = self.configure(spec.clone()).await {
                tracing::warn!(
                    interface = %error.interface(),
                    %error,
                    "failed to start Wi-Fi client at startup; will keep retrying in the background"
                );
                self.record_failed_startup(&spec, &error.to_string()).await;
            }
        }
        Ok(())
    }

    /// Apply one interface's effective station intent during runtime convergence.
    pub(crate) async fn reconcile_interface_config(
        &self,
        interface: &str,
        config: &InterfaceConfig,
    ) -> anyhow::Result<()> {
        let desired = WifiClientSpec::from_interface_config(interface, config)?;
        match desired {
            Some(spec) => {
                self.configure(spec).await?;
                Ok(())
            }
            None if self.status(interface).await.is_some() => {
                self.disable(interface).await?;
                Ok(())
            }
            None => Ok(()),
        }
    }

    /// Start the wpa_supplicant supervisor from effective configuration using the production process adapter.
    pub async fn start(config: &AppConfig) -> Result<Self, ClientSupervisorError> {
        let supervisor = Self::open_for_recovery(config);
        supervisor.reconcile_startup(config).await?;
        Ok(supervisor)
    }

    /// Initialize wpa_supplicant supervision with the supplied process adapter and recover configured interfaces.
    pub async fn start_with_process(
        config: &AppConfig,
        process: Arc<dyn SupervisedProcess>,
    ) -> Result<Self, ClientSupervisorError> {
        let supervisor = Self::open_with_process_for_recovery(config, process);
        supervisor.reconcile_startup(config).await?;
        Ok(supervisor)
    }

    /// One supplicant per interface the configuration asks for.
    ///
    /// See [`crate::dhcp::supervisor::DhcpSupervisor::effective_specs`] for why
    /// this no longer consults the persisted overrides.
    pub fn effective_specs(config: &AppConfig) -> Result<Vec<WifiClientSpec>, anyhow::Error> {
        let mut specs = std::collections::BTreeMap::new();
        for (name, interface) in &config.network.interfaces {
            if let Some(spec) = WifiClientSpec::from_interface_config(name, interface)? {
                specs.insert(name.clone(), spec);
            }
        }

        Ok(specs.into_values().collect())
    }

    fn ctrl_path(&self, interface: &str) -> PathBuf {
        self.inner.runtime_dir.join(interface)
    }

    /// Records a placeholder task for an interface whose supplicant could not
    /// be started (e.g. a foreign manager holds the interface). The liveness
    /// loop keeps retrying it with backoff until the interface is freed.
    pub async fn record_failed_startup(&self, spec: &WifiClientSpec, error: &str) {
        let mut tasks = self.inner.tasks.lock().await;
        tasks
            .entry(spec.interface.clone())
            .or_insert_with(|| ClientTask {
                spec: spec.clone(),
                record: PersistedWifiRecord {
                    pid: 0,
                    started_at_unix: unix_now(),
                    process_start_ticks: None,
                    boot_id: None,
                    binary_path: Some(self.inner.wpa_supplicant_binary.clone()),
                    ctrl_path: self.ctrl_path(&spec.interface),
                    ctrl_dev: None,
                    ctrl_ino: None,
                    config_path: config_path(&self.inner.runtime_dir, &spec.interface),
                    config_digest: WifiDigest::of(&[]),
                    key_digest: WifiDigest::of(&[]),
                    ssid: spec.ssid.clone(),
                },
                retry: RetryState::failed_startup(self.inner.restart_backoff_seconds, error),
                associated_or_started_at: Instant::now(),
            });
    }

    fn record_store(&self, interface: &str) -> WifiRecordStore {
        WifiRecordStore::for_client(&self.inner.records_dir, &self.inner.runtime_dir, interface)
    }

    async fn render_for(
        &self,
        spec: &WifiClientSpec,
    ) -> Result<RenderedClientConfig, ClientSupervisorError> {
        let passphrase = if spec.requires_passphrase() {
            resolve_passphrase_parts(
                &spec.interface,
                spec.passphrase_file.as_deref(),
                &self.inner.passphrase_store,
            )?
        } else {
            None
        };
        Ok(render_wpa_supplicant_config(ClientRenderInput {
            spec,
            ctrl_interface: &self.inner.runtime_dir,
            ctrl_interface_group: None,
            passphrase: passphrase.as_ref(),
        })?)
    }

    pub async fn validate_configuration(
        &self,
        spec: &WifiClientSpec,
    ) -> Result<(), ClientSupervisorError> {
        self.render_for(spec).await?;
        Ok(())
    }

    /// Serialize configuration changes and reconcile the requested interface with wpa_supplicant.
    /// Reuse matching state or restart the owned process as needed; propagate setup failures.
    pub async fn configure(&self, spec: WifiClientSpec) -> Result<(), ClientSupervisorError> {
        crate::core::recovery::check_scope(
            self.inner.records_dir.parent().expect("state directory"),
            Some(&spec.interface),
        )?;
        let _operation = self.inner.operation_lock.read().await;
        let interface = spec.interface.clone();
        let _interface_operation = self.inner.interface_operations.lock(&interface).await;
        let ctrl_path = self.ctrl_path(&interface);
        let rendered = self.render_for(&spec).await?;

        let existing = self.inner.tasks.lock().await.get(&interface).cloned();
        let task = match existing {
            Some(mut task)
                if task.record.config_digest == rendered.config_digest
                    && task.record.key_digest == rendered.key_digest =>
            {
                if self.task_process_session(&task).await?.is_some() {
                    task
                } else {
                    self.restart_task(&mut task, &spec, &rendered, &ctrl_path)
                        .await?;
                    task
                }
            }
            Some(mut task) => {
                self.restart_task(&mut task, &spec, &rendered, &ctrl_path)
                    .await?;
                task
            }
            None => {
                self.reconcile_new_interface(&spec, &rendered, &ctrl_path)
                    .await?
            }
        };

        let pid = task.record.pid;
        self.inner
            .tasks
            .lock()
            .await
            .insert(interface.clone(), task);
        self.monitor_association(&interface, pid).await;
        Ok(())
    }

    pub fn subscribe_association_changes(&self) -> tokio::sync::broadcast::Receiver<(String, u32)> {
        self.inner.association_events.subscribe()
    }

    async fn monitor_association(&self, interface: &str, pid: u32) {
        if pid == 0 {
            return;
        }
        if self
            .inner
            .association_monitors
            .lock()
            .await
            .get(interface)
            .is_some_and(|monitor| monitor.pid == pid && !monitor.task.is_finished())
        {
            return;
        }

        let Some(task) = self
            .inner
            .tasks
            .lock()
            .await
            .get(interface)
            .filter(|task| task.record.pid == pid)
            .cloned()
        else {
            return;
        };
        let Ok(session) = self.owned_ctrl_session(&task).await else {
            // Periodic reconciliation retries attachment and recovers missed events.
            return;
        };
        let Ok((events, mut receiver)) = session.attach_events().await else {
            return;
        };

        let sender = self.inner.association_events.clone();
        let name = interface.to_owned();
        let task = tokio::spawn(async move {
            loop {
                match receiver.recv().await {
                    Ok(
                        WpaSupplicantEvent::Connected { .. }
                        | WpaSupplicantEvent::Disconnected { .. },
                    ) => {
                        let _ = sender.send((name.clone(), pid));
                    }
                    Ok(WpaSupplicantEvent::Terminating) => break,
                    Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            events.close().await;
        });
        self.inner
            .association_monitors
            .lock()
            .await
            .insert(interface.to_owned(), AssociationMonitor { pid, task });
    }

    async fn task_identity_matches(
        &self,
        task: &ClientTask,
    ) -> Result<bool, ClientSupervisorError> {
        if task.record.pid == 0 || !self.inner.process.is_alive(task.record.pid).await? {
            return Ok(false);
        }
        let binary_path = task
            .record
            .binary_path
            .as_deref()
            .unwrap_or(self.inner.wpa_supplicant_binary.as_path());
        if !self
            .inner
            .process
            .identity_matches_record(&task.record, WifiProcessKind::Client, binary_path)
            .await?
        {
            return Ok(false);
        }

        Ok(true)
    }

    fn task_ctrl_identity(&self, task: &ClientTask) -> OwnedWpaCtrlIdentity {
        OwnedWpaCtrlIdentity {
            interface: task.spec.interface.clone(),
            kind: WifiProcessKind::Client,
            record: task.record.clone(),
            require_current_record: true,
        }
    }

    async fn open_owned_ctrl_session(
        &self,
        identity: OwnedWpaCtrlIdentity,
    ) -> Result<OwnedWpaCtrlSession, ClientSupervisorError> {
        if !identity.prove(&self.inner).await? {
            return Err(ClientSupervisorError::NotOwned {
                interface: identity.interface.clone(),
            });
        }

        let client =
            WpaSupplicantCtrlClient::connect(&identity.record.ctrl_path, self.inner.ctrl_timeout)
                .await?;

        // A connected AF_UNIX datagram stays bound to the socket object it
        // connected to even if the pathname is replaced. Re-proving pathname
        // ownership here closes the ordinary unlink/rebind race around connect.
        if !identity.prove(&self.inner).await? {
            return Err(ClientSupervisorError::NotOwned {
                interface: identity.interface.clone(),
            });
        }

        Ok(OwnedWpaCtrlSession {
            inner: self.inner.clone(),
            identity,
            client,
        })
    }

    async fn owned_ctrl_session(
        &self,
        task: &ClientTask,
    ) -> Result<OwnedWpaCtrlSession, ClientSupervisorError> {
        self.open_owned_ctrl_session(self.task_ctrl_identity(task))
            .await
    }

    /// Return the ownership-bound session itself rather than a bool so callers
    /// cannot prove one connection and then accidentally reopen the pathname.
    async fn task_process_session(
        &self,
        task: &ClientTask,
    ) -> Result<Option<OwnedWpaCtrlSession>, ClientSupervisorError> {
        let session = match self.owned_ctrl_session(task).await {
            Ok(session) => session,
            Err(
                error @ (ClientSupervisorError::NotOwned { .. } | ClientSupervisorError::Ctrl(_)),
            ) => {
                tracing::warn!(interface = %task.spec.interface, pid = task.record.pid, error = %format!("{error:#}"), "wpa_supplicant control session unavailable");
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        match session.client.ping().await {
            Ok(()) => Ok(Some(session)),
            Err(error) => {
                tracing::warn!(interface = %task.spec.interface, pid = task.record.pid, error = %format!("{error:#}"), "wpa_supplicant PING failed");
                Ok(None)
            }
        }
    }

    async fn restart_task(
        &self,
        task: &mut ClientTask,
        spec: &WifiClientSpec,
        rendered: &RenderedClientConfig,
        ctrl_path: &Path,
    ) -> Result<(), ClientSupervisorError> {
        self.stop_task(task, "configuration changed").await?;
        let record = self.spawn_and_record(spec, rendered, ctrl_path).await?;
        task.spec = spec.clone();
        task.record = record;
        task.retry.reset_restart_budget();
        task.associated_or_started_at = Instant::now();
        Ok(())
    }

    async fn reconcile_new_interface(
        &self,
        spec: &WifiClientSpec,
        rendered: &RenderedClientConfig,
        ctrl_path: &Path,
    ) -> Result<ClientTask, ClientSupervisorError> {
        let outcome = self.observe_ownership(spec, rendered, ctrl_path).await?;
        match &outcome {
            OwnershipOutcome::DigestMismatch(record) => {
                tracing::info!(interface = %spec.interface, pid = record.pid, reason = "configuration digest changed", "replacing recorded wpa_supplicant")
            }
            OwnershipOutcome::UnreachableOwned(record) => {
                tracing::warn!(interface = %spec.interface, pid = record.pid, reason = "owned control endpoint unreachable", "replacing recorded wpa_supplicant")
            }
            _ => {}
        }
        let record = match outcome {
            OwnershipOutcome::Absent => self.spawn_and_record(spec, rendered, ctrl_path).await?,
            OwnershipOutcome::Adopted(record) => record,
            OwnershipOutcome::DigestMismatch(record)
            | OwnershipOutcome::UnreachableOwned(record) => {
                self.inner
                    .process
                    .stop_recorded(&record, WifiProcessKind::Client, "wpa_supplicant")
                    .await?;
                self.spawn_and_record(spec, rendered, ctrl_path).await?
            }
            OwnershipOutcome::ForeignPresent => {
                return Err(ClientSupervisorError::NotOwned {
                    interface: spec.interface.clone(),
                })
            }
        };
        Ok(ClientTask {
            spec: spec.clone(),
            record,
            retry: RetryState::default(),
            associated_or_started_at: Instant::now(),
        })
    }

    async fn recorded_ctrl_identity_for_probe(
        &self,
        kind: WifiProcessKind,
        interface: &str,
        ctrl_path: &Path,
    ) -> Result<Option<OwnedWpaCtrlIdentity>, ClientSupervisorError> {
        let store = WifiRecordStore::new(
            kind,
            &self.inner.records_dir,
            &self.inner.runtime_dir,
            interface,
        );
        let Some(mut record) = store.load().await? else {
            return Ok(None);
        };
        if record.ctrl_path != ctrl_path {
            return Ok(None);
        }

        if record.pid == 0 {
            let binary_path = record
                .binary_path
                .as_deref()
                .unwrap_or(self.inner.wpa_supplicant_binary.as_path());
            let pids = match self
                .inner
                .process
                .pids_matching_identity(
                    kind,
                    binary_path,
                    &record.config_path,
                    record.started_at_unix,
                )
                .await
            {
                Ok(pids) if pids.len() == 1 => pids,
                Ok(_) | Err(_) => return Ok(None),
            };
            record.pid = pids[0];
        }

        Ok(Some(OwnedWpaCtrlIdentity {
            interface: interface.to_string(),
            kind,
            record,
            // A recovered launch-intent candidate may still have pid == 0 in
            // the store. classify_ownership() performs the durable adoption;
            // this identity is only used to prove that a protocol probe is safe.
            require_current_record: false,
        }))
    }

    async fn observe_ownership(
        &self,
        spec: &WifiClientSpec,
        rendered: &RenderedClientConfig,
        ctrl_path: &Path,
    ) -> Result<OwnershipOutcome, ClientSupervisorError> {
        let store = self.record_store(&spec.interface);
        let candidate = self
            .recorded_ctrl_identity_for_probe(WifiProcessKind::Client, &spec.interface, ctrl_path)
            .await?;

        let safe_identity = match candidate {
            Some(identity) if identity.prove(&self.inner).await? => Some(identity),
            _ => None,
        };
        let mut ownership_changed_during_connect = false;
        let status = if let Some(identity) = safe_identity.clone() {
            match self.open_owned_ctrl_session(identity).await {
                Ok(session) => session.client.status().await.ok(),
                Err(ClientSupervisorError::NotOwned { .. }) => {
                    ownership_changed_during_connect = true;
                    None
                }
                Err(ClientSupervisorError::Ctrl(_)) => None,
                Err(error) => return Err(error),
            }
        } else {
            None
        };

        let ctrl_reachable = if ownership_changed_during_connect {
            true
        } else if safe_identity.is_some() {
            status.is_some()
        } else {
            match tokio::fs::symlink_metadata(ctrl_path).await {
                Ok(_) => true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => {
                    return Err(ClientSupervisorError::Configuration(
                        anyhow::Error::from(error).context(format!(
                            "failed to inspect wpa_supplicant control socket {}",
                            ctrl_path.display()
                        )),
                    ))
                }
            }
        };

        classify_ownership(
            &store,
            WifiProcessKind::Client,
            self.inner.process.as_ref(),
            &self.inner.wpa_supplicant_binary,
            ctrl_reachable,
            |record| {
                // Endpoint ownership is established by process identity plus
                // pre/post-connect socket ownership above. STATUS is only an
                // additional semantic mismatch check: a disconnected owned
                // supplicant may legitimately omit SSID.
                status.as_ref().is_some_and(|status| {
                    status
                        .ssid
                        .as_deref()
                        .is_none_or(|ssid| ssid == record.ssid)
                })
            },
            rendered.config_digest,
            rendered.key_digest,
        )
        .await
        .map_err(Into::into)
    }

    /// Launch the service and persist its process identity for ownership-checked recovery.
    async fn spawn_and_record(
        &self,
        spec: &WifiClientSpec,
        rendered: &RenderedClientConfig,
        ctrl_path: &Path,
    ) -> Result<PersistedWifiRecord, ClientSupervisorError> {
        // Stopping our process does not reserve its pathname. A foreign
        // endpoint appearing before restart must block every spawn path.
        match tokio::fs::symlink_metadata(ctrl_path).await {
            Ok(_) => {
                return Err(ClientSupervisorError::NotOwned {
                    interface: spec.interface.clone(),
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(anyhow::Error::from(error).into()),
        }
        write_config_file(rendered).await?;
        let store = self.record_store(&spec.interface);
        let launch_boot_id = self
            .inner
            .process
            .boot_id()
            .await?
            .ok_or(ProcessError::BootIdUnavailable)?;
        save_launch_intent(
            &store,
            launch_boot_id,
            &self.inner.wpa_supplicant_binary,
            ctrl_path,
            &rendered.path,
            rendered.config_digest,
            rendered.key_digest,
            &spec.ssid,
        )
        .await?;

        let pid = match self
            .inner
            .process
            .spawn_wifi_client(
                &self.inner.wpa_supplicant_binary,
                &spec.interface,
                &rendered.path,
            )
            .await
        {
            Ok(pid) => pid,
            Err(error) => {
                if let Err(cleanup) = store.clear().await {
                    return Err(ClientSupervisorError::Configuration(anyhow::anyhow!(
                        "wpa_supplicant spawn failed: {error}; launch-intent cleanup also failed: {cleanup}; recovery required"
                    )));
                }
                let _ = tokio::fs::remove_file(&rendered.path).await;
                return Err(error.into());
            }
        };

        tracing::info!(interface = %spec.interface, pid, purpose = "association", "wpa_supplicant started");
        let result = async {
            let process_start_ticks = self
                .inner
                .process
                .process_start_ticks(pid)
                .await?
                .ok_or(ProcessError::IdentityChanged { pid })?;
            let boot_id = self
                .inner
                .process
                .boot_id()
                .await?
                .ok_or(ProcessError::BootIdUnavailable)?;
            let record = save_spawned_record(
                &store,
                pid,
                process_start_ticks,
                boot_id,
                &self.inner.wpa_supplicant_binary,
                ctrl_path,
                &rendered.path,
                rendered.config_digest,
                rendered.key_digest,
                &spec.ssid,
            )
            .await?;
            self.wait_for_ready(
                OwnedWpaCtrlIdentity {
                    interface: spec.interface.clone(),
                    kind: WifiProcessKind::Client,
                    record: record.clone(),
                    require_current_record: true,
                },
                self.inner.ctrl_timeout,
            )
            .await?;
            let record =
                persist_owned_ctrl_node(&store, self.inner.process.as_ref(), record).await?;
            store.clear_transition().await?;
            Ok(record)
        }
        .await;

        match result {
            Ok(record) => Ok(record),
            Err(error) => {
                tracing::warn!(interface = %spec.interface, pid, error = %format!("{error:#}"), "wpa_supplicant startup failed; stopping process");
                match self.graceful_stop(pid).await {
                Ok(()) => match store.clear().await {
                    Ok(()) => {
                        let _ = tokio::fs::remove_file(&rendered.path).await;
                        Err(error)
                    },
                    Err(cleanup) => Err(ClientSupervisorError::Configuration(anyhow::anyhow!(
                        "wpa_supplicant startup failed: {error}; process stopped but ownership-record cleanup failed: {cleanup}; recovery required"
                    ))),
                },
                Err(cleanup) => Err(ClientSupervisorError::Configuration(anyhow::anyhow!(
                    "wpa_supplicant startup failed: {error}; cleanup also failed: {cleanup}; recovery required"
                ))),
                }
            }
        }
    }

    /// Open and ping an ownership-verified control session for at least 15 seconds.
    /// Poll every 20 ms after completed failures; individual observation/ping
    /// awaits are not bounded by this readiness deadline and can exceed it.
    /// Refuse an existing socket with foreign identity rather than adopting it.
    async fn wait_for_ready(
        &self,
        identity: OwnedWpaCtrlIdentity,
        timeout: Duration,
    ) -> Result<OwnedWpaCtrlSession, ClientSupervisorError> {
        let deadline = Instant::now() + STARTUP_READY_TIMEOUT.max(timeout);
        loop {
            match self.open_owned_ctrl_session(identity.clone()).await {
                Ok(session) if session.client.ping().await.is_ok() => return Ok(session),
                Ok(_) | Err(ClientSupervisorError::Ctrl(_)) => {}
                Err(ClientSupervisorError::NotOwned { .. }) => {
                    // During normal startup the path may simply not exist yet.
                    // If it does exist while ownership proof fails, fail closed
                    // instead of accepting whichever daemon answers there.
                    match tokio::fs::symlink_metadata(&identity.record.ctrl_path).await {
                        Ok(_) => {
                            return Err(ClientSupervisorError::NotOwned {
                                interface: identity.interface.clone(),
                            })
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => return Err(anyhow::Error::from(error).into()),
                    }
                }
                Err(error) => return Err(error),
            }

            if Instant::now() >= deadline {
                return Err(ClientSupervisorError::StartupTimeout {
                    interface: identity.interface.clone(),
                    timeout: STARTUP_READY_TIMEOUT.max(timeout),
                });
            }
            tokio::time::sleep(STARTUP_POLL_INTERVAL).await;
        }
    }

    async fn stop_task(
        &self,
        task: &ClientTask,
        reason: &'static str,
    ) -> Result<(), ClientSupervisorError> {
        if task.record.pid == 0 || !self.inner.process.is_alive(task.record.pid).await? {
            return Ok(());
        }
        if !self.task_identity_matches(task).await? {
            return Err(ClientSupervisorError::NotOwned {
                interface: task.spec.interface.clone(),
            });
        }
        tracing::info!(interface = %task.spec.interface, pid = task.record.pid, reason, "stopping configured wpa_supplicant");
        self.inner
            .process
            .stop_recorded(&task.record, WifiProcessKind::Client, "wpa_supplicant")
            .await?;
        Ok(())
    }

    async fn graceful_stop(&self, pid: u32) -> Result<(), ClientSupervisorError> {
        graceful_stop(self.inner.process.as_ref(), pid, "wpa_supplicant").await?;
        Ok(())
    }

    /// Validate durable ownership before an offline cleanup stops any service.
    pub async fn check_cleanup_ownership(
        &self,
        interface: &str,
    ) -> Result<(), ClientSupervisorError> {
        let _operation = self.inner.operation_lock.read().await;
        let _interface_operation = self.inner.interface_operations.lock(interface).await;
        let store = self.record_store(interface);
        if store.transition_pending().await? {
            return Err(ClientSupervisorError::Configuration(anyhow::anyhow!(
                "Wi-Fi launch transition on {interface} is incomplete; recovery required"
            )));
        }
        if let Some(record) = store.load().await? {
            let tasks = self.inner.tasks.lock().await;
            if !tasks
                .get(interface)
                .is_some_and(|task| task.record == record)
            {
                return Err(ClientSupervisorError::NotOwned {
                    interface: interface.to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Stop the configured process and remove its runtime configuration and ownership record.
    /// Return the previous specification, or `None` when the interface was not configured.
    pub async fn disable(
        &self,
        interface: &str,
    ) -> Result<Option<WifiClientSpec>, ClientSupervisorError> {
        let _operation = self.inner.operation_lock.read().await;
        let _interface_operation = self.inner.interface_operations.lock(interface).await;
        let Some(task) = self.inner.tasks.lock().await.get(interface).cloned() else {
            return Ok(None);
        };

        self.stop_task(&task, "Wi-Fi client configuration removed")
            .await?;
        self.record_store(interface).clear().await?;
        let runtime_config = config_path(&self.inner.runtime_dir, interface);
        match tokio::fs::remove_file(&runtime_config).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(ClientSupervisorError::Configuration(anyhow::anyhow!(
                    "failed to remove wpa_supplicant config {}: {error}",
                    runtime_config.display()
                )))
            }
        }
        self.inner
            .association_monitors
            .lock()
            .await
            .remove(interface);
        self.inner.tasks.lock().await.remove(interface);
        Ok(Some(task.spec))
    }

    /// Check that the configured wpa_supplicant binary is runnable.
    ///
    /// See [`crate::wifi::HostapdSupervisor::preflight_binary`]: the supervisor
    /// is built unconditionally, so a client configured at runtime needs the
    /// same diagnosis of a missing binary that startup gives.
    pub async fn preflight_binary(&self) -> Result<(), ClientSupervisorError> {
        preflight_daemon_binary(
            &self.inner.wpa_supplicant_binary,
            "wpa_supplicant",
            "wifi_client.wpa_supplicant_binary",
        )
        .await
        .map_err(ClientSupervisorError::BinaryPreflight)
    }

    /// Return configured service state and observed health; `None` means no supervised task exists.
    pub async fn status(&self, interface: &str) -> Option<WifiClientStatus> {
        let _operation = self.inner.operation_lock.read().await;
        let _interface_operation = self.inner.interface_operations.lock(interface).await;
        let task = self.inner.tasks.lock().await.get(interface).cloned()?;

        let (wpa_state, bssid, freq) = match self.owned_ctrl_session(&task).await {
            Ok(session) => match session.client.status().await {
                Ok(status) => (status.wpa_state, status.bssid, status.freq),
                Err(_) => (WpaState::Other("unreachable".to_string()), None, None),
            },
            Err(_) => (WpaState::Other("unreachable".to_string()), None, None),
        };

        let health = if let Some(error) = task.retry.failure() {
            retry_health(
                error,
                task.retry.attempts(),
                task.retry.next_restart(),
                interface,
            )
            .await
        } else if wpa_state.is_connected() {
            WifiHealth::Healthy
        } else {
            WifiHealth::Starting
        };

        Some(WifiClientStatus {
            interface: interface.to_string(),
            pid: task.record.pid,
            spec: task.spec,
            wpa_state,
            bssid,
            freq,
            health,
        })
    }

    /// Ask a configured supplicant to reconnect to its selected network.
    pub async fn reconnect(&self, interface: &str) -> Result<(), ClientSupervisorError> {
        let _operation = self.inner.operation_lock.read().await;
        let _interface_operation = self.inner.interface_operations.lock(interface).await;
        let task = self
            .inner
            .tasks
            .lock()
            .await
            .get(interface)
            .cloned()
            .ok_or_else(|| ClientSupervisorError::NotConfigured {
                interface: interface.into(),
            })?;
        self.owned_ctrl_session(&task)
            .await?
            .client
            .reconnect()
            .await?;
        Ok(())
    }

    /// Read the stored interface passphrase, returning `None` when no secret exists.
    pub async fn stored_passphrase(
        &self,
        interface: &str,
    ) -> Result<Option<WifiPassphrase>, ClientSupervisorError> {
        self.inner
            .passphrase_store
            .get(interface)
            .map_err(ResolvePassphraseError::from)
            .map_err(Into::into)
    }

    /// Remove the stored interface passphrase on the blocking pool.
    pub async fn clear_passphrase(&self, interface: &str) -> Result<(), ClientSupervisorError> {
        self.inner
            .passphrase_store
            .clear(interface)
            .map_err(ResolvePassphraseError::from)
            .map_err(Into::into)
    }

    /// Persist an interface passphrase on the blocking pool; service reconfiguration is separate.
    pub async fn set_passphrase(
        &self,
        interface: &str,
        passphrase: &WifiPassphrase,
    ) -> Result<(), ClientSupervisorError> {
        self.inner
            .passphrase_store
            .set(interface, passphrase)
            .map_err(ResolvePassphraseError::from)?;
        Ok(())
    }

    /// Check supervised processes and retry eligible failures using restart backoff.
    pub async fn ensure_alive(&self) -> Result<bool, ClientSupervisorError> {
        self.ensure_alive_matching(None).await
    }

    /// Called under the network mutation gate with the current desired snapshot.
    /// Stale tasks cannot restart or replay settings withdrawn by a newer edit.
    pub async fn ensure_alive_for_config(
        &self,
        config: &AppConfig,
    ) -> Result<bool, ClientSupervisorError> {
        let desired = Self::effective_specs(config)?;
        self.ensure_alive_matching(Some(&desired)).await
    }

    async fn ensure_alive_matching(
        &self,
        desired: Option<&[WifiClientSpec]>,
    ) -> Result<bool, ClientSupervisorError> {
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

        let mut restarted_any = false;
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
            if self.ensure_interface_alive(&interface).await? {
                restarted_any = true;
            }
            let pid = self
                .inner
                .tasks
                .lock()
                .await
                .get(&interface)
                .map(|task| task.record.pid);
            if let Some(pid) = pid {
                self.monitor_association(&interface, pid).await;
            }
        }
        Ok(restarted_any)
    }

    async fn ensure_interface_alive(&self, interface: &str) -> Result<bool, ClientSupervisorError> {
        let Some(mut task) = self.inner.tasks.lock().await.get(interface).cloned() else {
            return Ok(false);
        };

        if task.retry.is_waiting() {
            return Ok(false);
        }

        let ctrl_path = self.ctrl_path(interface);
        let session = self.task_process_session(&task).await?;
        let status = match session {
            Some(session) => match session.client.status().await {
                Ok(status) => Some(status),
                Err(error) => {
                    tracing::warn!(%interface, pid = task.record.pid, error = %format!("{error:#}"), "wpa_supplicant STATUS failed");
                    None
                }
            },
            None => None,
        };

        let stuck = match &status {
            Some(status) if status.wpa_state.is_connected() => {
                task.associated_or_started_at = Instant::now();
                false
            }
            Some(status)
                if matches!(
                    status.wpa_state,
                    WpaState::Authenticating
                        | WpaState::Associating
                        | WpaState::Associated
                        | WpaState::FourWayHandshake
                        | WpaState::GroupHandshake
                ) =>
            {
                task.associated_or_started_at.elapsed() > ASSOCIATION_GRACE
            }
            Some(_) => {
                task.associated_or_started_at = Instant::now();
                false
            }

            None => false,
        };

        if status.is_some() && !stuck {
            task.retry = RetryState::default();
            self.inner
                .tasks
                .lock()
                .await
                .insert(interface.to_string(), task);
            return Ok(false);
        }

        let competitors = crate::wifi::process::find_competing_network_managers().await;
        if stuck {
            let advice = if competitors.is_empty() {
                String::new()
            } else {
                format!(
                    "\n{}",
                    crate::wifi::process::format_competing_manager_advice(&competitors, interface)
                )
            };
            tracing::warn!(
                %interface,
                pid = task.record.pid,
                grace = ?ASSOCIATION_GRACE,
                competing = ?competitors,
                "wpa_supplicant is alive but has not associated; restarting it; competing managers: {competitors:?}{advice}"
            );
        } else if competitors.is_empty() {
            tracing::warn!(
                %interface,
                pid = task.record.pid,
                "wpa_supplicant is not responding; restarting it"
            );
        } else {
            let advice =
                crate::wifi::process::format_competing_manager_advice(&competitors, interface);
            tracing::warn!(
                %interface,
                pid = task.record.pid,
                competing = ?competitors,
                %advice,
                "wpa_supplicant is not responding; restarting it; other network managers are running and may be controlling this interface. Resolution advice:\n{advice}"
            );
        }

        let rendered = self.render_for(&task.spec).await?;
        // Placeholder tasks (failed startup) have pid 0; signalling pid 0
        // would signal the whole process group, including this daemon.
        if task.record.pid != 0 {
            self.stop_task(
                &task,
                if stuck {
                    "association grace period expired"
                } else {
                    "control endpoint unavailable"
                },
            )
            .await?;
        }

        // Do not probe an endpoint after the owned process has stopped. At
        // this point any remaining pathname is unproven and therefore blocks
        // replacement rather than being treated as an endpoint we may query.
        match tokio::fs::symlink_metadata(&ctrl_path).await {
            Ok(metadata)
                if task.record.ctrl_dev == Some(metadata.dev())
                    && task.record.ctrl_ino == Some(metadata.ino())
                    && crate::wifi::lifecycle::ctrl_socket_is_stale(&ctrl_path) =>
            {
                tokio::fs::remove_file(&ctrl_path)
                    .await
                    .map_err(anyhow::Error::from)?;
            }
            Ok(_) => {
                return Err(ClientSupervisorError::NotOwned {
                    interface: interface.to_string(),
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(anyhow::Error::from(error).into()),
        }

        task.retry.record_attempt();
        match self
            .spawn_and_record(&task.spec, &rendered, &ctrl_path)
            .await
        {
            Ok(record) => {
                task.record = record;
                task.retry.respawn_ready();
                task.associated_or_started_at = Instant::now();
            }
            Err(error) => {
                tracing::error!(%interface, %error, "failed to respawn wpa_supplicant");
                task.retry
                    .respawn_failed(self.inner.restart_backoff_seconds, &error.to_string());
            }
        }
        self.inner
            .tasks
            .lock()
            .await
            .insert(interface.to_string(), task);
        Ok(true)
    }

    /// Apply the shutdown policy to supervised processes and their ownership records.
    pub async fn shutdown(&self, policy: ShutdownPolicy) {
        let _operation = self.inner.operation_lock.write().await;
        self.inner.association_monitors.lock().await.clear();
        let tasks = std::mem::take(&mut *self.inner.tasks.lock().await);

        for (interface, task) in tasks {
            if policy == ShutdownPolicy::RestoreInterfaces {
                if let Err(error) = self
                    .stop_task(&task, "daemon shutdown restoring interfaces")
                    .await
                {
                    tracing::error!(%interface, %error, "failed to stop wpa_supplicant during shutdown; ownership record retained");
                    continue;
                }
                if let Err(error) = self.record_store(&interface).clear().await {
                    tracing::error!(%interface, %error, "wpa_supplicant stopped but ownership record cleanup failed");
                }
                let path = config_path(&self.inner.runtime_dir, &interface);
                if let Err(error) = tokio::fs::remove_file(&path).await {
                    if error.kind() != std::io::ErrorKind::NotFound {
                        tracing::warn!(%interface, path = %path.display(), %error, "failed to remove wpa_supplicant runtime config during shutdown");
                    }
                }
            }
        }
    }
}

async fn write_config_file(rendered: &RenderedClientConfig) -> Result<(), ClientSupervisorError> {
    write_private_config(&rendered.path, &rendered.text)
        .await
        .map_err(|source| io_error(&rendered.path, source))
}

fn io_error(path: &Path, source: std::io::Error) -> ClientSupervisorError {
    ClientSupervisorError::Configuration(anyhow::Error::from(source).context(format!(
        "failed to write wpa_supplicant configuration to {}",
        path.display()
    )))
}

#[cfg(test)]
mod tests;
