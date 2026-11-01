use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;
use tokio::sync::{Mutex, RwLock};

use crate::config::{AppConfig, InterfaceConfig, ShutdownPolicy};
use crate::dhcp::supervisor::resolve_interface_index;
use crate::wifi::ctrl::{CtrlError, HostapdCtrlClient, HostapdState, MacAddr, Station};
pub use crate::wifi::lifecycle::WifiHealth;
use crate::wifi::lifecycle::{
    classify_ownership, cleanup_unconfigured_records, graceful_stop, persist_owned_ctrl_node,
    preflight_binary as preflight_daemon_binary, save_launch_intent, save_spawned_record,
    wait_until_ready, write_private_config, OwnershipOutcome, STARTUP_READY_TIMEOUT,
};
use crate::wifi::process::{ProcessError, SupervisedProcess, TokioSupervisedProcess};
use crate::wifi::radio::{
    CapabilitiesRadioValidator, Nl80211CapabilitiesProvider, RadioError, RadioValidator,
};
use crate::wifi::record::{PersistedWifiRecord, WifiProcessKind, WifiRecordError, WifiRecordStore};
use crate::wifi::render::{
    self, render_hostapd_config, ApRenderInput, RenderError, RenderedApConfig, WifiDigest,
};
use crate::wifi::retry::{retry_health, RetryState};
use crate::wifi::secret::WifiPassphrase;
use crate::wifi::store::{resolve_passphrase, PassphraseStore, ResolvePassphraseError};
use crate::wifi::WifiApSpec;

mod health;
use health::{
    clear_suspended_failure_message, diagnostic_summary, hostapd_failure_should_suspend_retry,
    hostapd_failure_text_should_suspend_retry, suspended_failure_message, suspended_retry_health,
};

const DEFAULT_CTRL_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Error)]
pub enum SupervisorError {
    #[error("Wi-Fi access point on {interface} is not configured")]
    NotConfigured { interface: String },

    #[error("refusing to manage hostapd on {interface}: {diagnostics}")]
    NotOwned {
        interface: String,
        diagnostics: String,
    },

    #[error("hostapd for {interface} did not become ready within {timeout:?}{diagnostics}")]
    StartupTimeout {
        interface: String,
        timeout: Duration,
        diagnostics: String,
    },

    #[error(transparent)]
    Render(#[from] RenderError),

    #[error(transparent)]
    ResolvePassphrase(#[from] ResolvePassphraseError),

    #[error(transparent)]
    Record(#[from] WifiRecordError),

    #[error(transparent)]
    Process(#[from] ProcessError),

    #[error(transparent)]
    BinaryPreflight(#[from] crate::wifi::lifecycle::BinaryPreflightError),

    #[error(transparent)]
    Radio(#[from] RadioError),

    #[error(transparent)]
    Ctrl(#[from] CtrlError),

    #[error("{0:#}")]
    Configuration(#[from] anyhow::Error),
}

impl SupervisorError {
    /// The interface this error is about, when there is one.
    pub fn interface(&self) -> &str {
        match self {
            SupervisorError::NotConfigured { interface }
            | SupervisorError::NotOwned { interface, .. }
            | SupervisorError::StartupTimeout { interface, .. } => interface,
            _ => "",
        }
    }
}

#[derive(Debug, Clone)]
struct ApTask {
    spec: WifiApSpec,
    record: PersistedWifiRecord,
    retry: RetryState,
    last_hostapd_state: Option<HostapdState>,
    last_state_change_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WifiApStatus {
    pub interface: String,
    pub spec: WifiApSpec,
    pub pid: u32,
    pub hostapd_state: HostapdState,
    pub num_stations: Option<u32>,
    pub health: WifiHealth,
}

#[derive(Clone)]
pub struct HostapdSupervisor {
    inner: Arc<Inner>,
}

struct Inner {
    recovery: crate::core::recovery::RecoveryState,
    client_runtime_dir: PathBuf,
    hostapd_binary: PathBuf,
    runtime_dir: PathBuf,
    records_dir: PathBuf,
    restart_backoff_seconds: u64,
    ctrl_timeout: Duration,
    process: Arc<dyn SupervisedProcess>,
    radio: Arc<dyn RadioValidator>,
    passphrase_store: PassphraseStore,
    tasks: Mutex<HashMap<String, ApTask>>,
    operation_lock: RwLock<()>,
    interface_operations: crate::core::mutation::InterfaceMutationLocks,
}

impl HostapdSupervisor {
    /// Construct hostapd supervision without process cleanup or committed-state application.
    pub fn open_for_recovery(
        recovery: crate::core::recovery::RecoveryState,
        config: &AppConfig,
    ) -> Self {
        Self::open_with_process_for_recovery(
            recovery,
            config,
            Arc::new(TokioSupervisedProcess::new()),
        )
    }

    /// Construct a recovery runtime with an injected process adapter.
    pub fn open_with_process_for_recovery(
        recovery: crate::core::recovery::RecoveryState,
        config: &AppConfig,
        process: Arc<dyn SupervisedProcess>,
    ) -> Self {
        let records_dir = config.runtime.state_dir.join("wifi");
        Self {
            inner: Arc::new(Inner {
                recovery: recovery.clone(),
                client_runtime_dir: config.wifi_client.runtime_dir.clone(),
                hostapd_binary: config.wifi.hostapd_binary.clone(),
                runtime_dir: config.wifi.runtime_dir.clone(),
                passphrase_store: PassphraseStore::for_role(
                    &config.runtime.state_dir,
                    crate::wifi::store::WifiCredentialRole::Ap,
                ),
                records_dir,
                restart_backoff_seconds: config.wifi.restart_backoff_seconds.max(1),
                ctrl_timeout: DEFAULT_CTRL_TIMEOUT,
                process,
                radio: Arc::new(CapabilitiesRadioValidator::new(Arc::new(
                    Nl80211CapabilitiesProvider,
                ))),
                tasks: Mutex::new(HashMap::new()),
                operation_lock: RwLock::new(()),
                interface_operations: Default::default(),
            }),
        }
    }

    /// Perform normal startup cleanup and apply committed access-point state.
    pub async fn reconcile_startup(&self, config: &AppConfig) -> Result<(), SupervisorError> {
        crate::wifi::policy::WifiRadioPolicy::validate_system(&config.network)
            .map_err(anyhow::Error::from)?;
        let specs = Self::effective_specs(config)?;
        let configured_interfaces: HashSet<String> = specs
            .iter()
            // Stop preserved paired AP processes before station recovery: an
            // old channel must not prevent the uplink from associating.
            .filter(|spec| {
                crate::wifi::concurrent::parent_for(&config.network, &spec.interface).is_none()
            })
            .map(|spec| spec.interface.clone())
            .collect();
        let configured_clients: HashSet<String> = config
            .network
            .interfaces
            .iter()
            .filter_map(|(name, interface)| interface.wifi_client.as_ref().map(|_| name.clone()))
            .collect();
        let no_interfaces = HashSet::new();
        cleanup_unconfigured_records(
            &self.inner.recovery,
            &self.inner.records_dir,
            &config.wifi_client.runtime_dir,
            WifiProcessKind::Scan,
            &no_interfaces,
            self.inner.process.as_ref(),
        )
        .await
        .map_err(SupervisorError::Configuration)?;
        cleanup_unconfigured_records(
            &self.inner.recovery,
            &self.inner.records_dir,
            &config.wifi_client.runtime_dir,
            WifiProcessKind::Client,
            &configured_clients,
            self.inner.process.as_ref(),
        )
        .await
        .map_err(SupervisorError::Configuration)?;
        cleanup_unconfigured_records(
            &self.inner.recovery,
            &self.inner.records_dir,
            &self.inner.runtime_dir,
            WifiProcessKind::AccessPoint,
            &configured_interfaces,
            self.inner.process.as_ref(),
        )
        .await
        .map_err(SupervisorError::Configuration)?;

        for spec in specs {
            // The network converger starts paired APs after station association
            // and resolves their channel from the live upstream connection.
            if crate::wifi::concurrent::parent_for(&config.network, &spec.interface).is_some() {
                continue;
            }
            if resolve_interface_index(&spec.interface).is_err() {
                tracing::warn!(
                    interface = %spec.interface,
                    "configured Wi-Fi interface is absent at startup; skipping it — \
                     the runtime reconcile loop will configure it if it reappears"
                );
                continue;
            }
            if !interface_is_wireless(&spec.interface) {
                tracing::warn!(
                    interface = %spec.interface,
                    "configured Wi-Fi interface has no phy80211 attachment (not a wireless NIC); skipping it"
                );
                continue;
            }
            if let Err(error) = self.configure(spec.clone()).await {
                let error_text = error.to_string();
                if hostapd_failure_text_should_suspend_retry(&error_text) {
                    tracing::error!(
                        interface = %error.interface(),
                        %error,
                        "failed to start Wi-Fi access point at startup; deterministic hostapd failure, automatic retry suspended until config or interface identity changes"
                    );
                } else {
                    tracing::warn!(
                        interface = %error.interface(),
                        %error,
                        "failed to start Wi-Fi access point at startup; will keep retrying in the background"
                    );
                }
                self.record_failed_startup(&spec, &error_text).await;
            }
        }
        Ok(())
    }

    /// Apply one interface's effective access-point intent during runtime convergence.
    pub(crate) async fn reconcile_interface_config(
        &self,
        interface: &str,
        config: &InterfaceConfig,
    ) -> anyhow::Result<()> {
        let desired = WifiApSpec::from_interface_config(interface, config)?;
        match desired {
            Some(spec) => {
                self.configure(spec).await?;
                Ok(())
            }
            None if self.status(interface).await.is_some()
                || self.record_store(interface).load().await?.is_some() =>
            {
                self.disable(interface).await?;
                Ok(())
            }
            None => Ok(()),
        }
    }

    /// Start the hostapd supervisor from effective configuration using the production process adapter.
    pub async fn start(config: &AppConfig) -> Result<Self, SupervisorError> {
        let supervisor = Self::open_for_recovery(Default::default(), config);
        supervisor.reconcile_startup(config).await?;
        Ok(supervisor)
    }

    /// Initialize hostapd supervision with the supplied process adapter and recover configured interfaces.
    pub async fn start_with_process(
        config: &AppConfig,
        process: Arc<dyn SupervisedProcess>,
    ) -> Result<Self, SupervisorError> {
        let supervisor = Self::open_with_process_for_recovery(Default::default(), config, process);
        supervisor.reconcile_startup(config).await?;
        Ok(supervisor)
    }

    #[cfg(test)]
    pub(crate) async fn start_with_process_and_radio(
        config: &AppConfig,
        process: Arc<dyn SupervisedProcess>,
        radio: Arc<dyn RadioValidator>,
    ) -> Result<Self, SupervisorError> {
        let supervisor = Self::open_with_process_for_recovery(Default::default(), config, process);
        // Tests that exercise process/control semantics inject deterministic
        // radio capabilities rather than depending on the host machine PHY.
        let supervisor = Self {
            inner: Arc::new(Inner {
                recovery: Default::default(),
                client_runtime_dir: config.wifi_client.runtime_dir.clone(),
                hostapd_binary: supervisor.inner.hostapd_binary.clone(),
                runtime_dir: supervisor.inner.runtime_dir.clone(),
                records_dir: supervisor.inner.records_dir.clone(),
                restart_backoff_seconds: supervisor.inner.restart_backoff_seconds,
                ctrl_timeout: supervisor.inner.ctrl_timeout,
                process: supervisor.inner.process.clone(),
                radio,
                passphrase_store: supervisor.inner.passphrase_store.clone(),
                tasks: Mutex::new(HashMap::new()),
                operation_lock: RwLock::new(()),
                interface_operations: Default::default(),
            }),
        };
        supervisor.reconcile_startup(config).await?;
        Ok(supervisor)
    }

    /// One access point per interface the configuration asks for.
    ///
    /// See [`crate::dhcp::supervisor::DhcpSupervisor::effective_specs`] for why
    /// this no longer consults the persisted overrides.
    pub fn effective_specs(config: &AppConfig) -> Result<Vec<WifiApSpec>, anyhow::Error> {
        let mut specs = std::collections::BTreeMap::new();
        for (name, interface) in &config.network.interfaces {
            if let Some(spec) = WifiApSpec::from_interface_config(name, interface)? {
                specs.insert(name.clone(), spec);
            }
        }

        Ok(specs.into_values().collect())
    }

    fn ctrl_path(&self, interface: &str) -> PathBuf {
        self.inner.runtime_dir.join(interface)
    }

    /// Records a placeholder task for an interface whose access point could not
    /// be started. Transient failures keep retrying with backoff; deterministic
    /// hostapd configuration/radio failures remain suspended until config or
    /// interface identity changes.
    pub async fn record_failed_startup(&self, spec: &WifiApSpec, error: &str) {
        let mut retry = RetryState::failed_startup(self.inner.restart_backoff_seconds, error);
        if hostapd_failure_text_should_suspend_retry(error) {
            let failure = suspended_failure_message(error);
            retry.suspend(&failure, resolve_interface_index(&spec.interface).ok());
        }
        // A passphrase can change while the desired WifiApSpec stays equal.
        // Remember the failed rendering so that credential changes resume retries.
        let failed_rendering = if retry.is_suspended() {
            self.render_for(spec).await.ok()
        } else {
            None
        };
        let mut tasks = self.inner.tasks.lock().await;
        tasks
            .entry(spec.interface.clone())
            .or_insert_with(|| ApTask {
                spec: spec.clone(),
                record: PersistedWifiRecord {
                    pid: 0,
                    started_at_unix: 0,
                    process_start_ticks: None,
                    boot_id: None,
                    binary_path: Some(self.inner.hostapd_binary.clone()),
                    ctrl_path: self.ctrl_path(&spec.interface),
                    ctrl_dev: None,
                    ctrl_ino: None,
                    config_path: render::config_path(&self.inner.runtime_dir, &spec.interface),
                    config_digest: failed_rendering
                        .as_ref()
                        .map(|rendered| rendered.config_digest)
                        .unwrap_or_else(|| WifiDigest::of(&[])),
                    key_digest: failed_rendering
                        .as_ref()
                        .map(|rendered| rendered.key_digest)
                        .unwrap_or_else(|| WifiDigest::of(&[])),
                    ssid: spec.ssid.clone(),
                },
                retry,
                last_hostapd_state: None,
                last_state_change_at: Instant::now(),
            });
    }

    fn record_store(&self, interface: &str) -> WifiRecordStore {
        WifiRecordStore::for_access_point(
            &self.inner.records_dir,
            &self.inner.runtime_dir,
            interface,
        )
    }

    async fn render_for(&self, spec: &WifiApSpec) -> Result<RenderedApConfig, SupervisorError> {
        let store = self.inner.passphrase_store.clone();
        let owned_spec = spec.clone();
        let passphrase =
            crate::wifi::store::blocking_store(move || resolve_passphrase(&owned_spec, &store))
                .await?;
        Ok(render_hostapd_config(ApRenderInput {
            spec,
            ctrl_interface: &self.inner.runtime_dir,
            ctrl_interface_group: None,
            passphrase: passphrase.as_ref(),
        })?)
    }

    /// Validate the requested AP radio settings against the selected PHY and
    /// the kernel's currently effective regulatory constraints. This is safe to
    /// call as an API preflight; `configure` repeats it under the mutation lock.
    pub async fn validate_configuration(&self, spec: &WifiApSpec) -> Result<(), SupervisorError> {
        self.validate_radio(spec).await?;
        self.render_for(spec).await?;
        Ok(())
    }

    pub(crate) async fn resolve_radio_spec(&self, spec: &WifiApSpec) -> anyhow::Result<WifiApSpec> {
        let mut resolved = spec.clone();
        let root = self.inner.records_dir.parent().expect("state directory");
        let Some(parent) = crate::wifi::concurrent::owned_parent(root, &spec.interface).await?
        else {
            return Ok(resolved);
        };
        crate::wifi::concurrent::validate(&parent).await?;
        let record = WifiRecordStore::for_client(
            &self.inner.records_dir,
            &self.inner.client_runtime_dir,
            &parent,
        )
        .load()
        .await?
        .ok_or_else(|| anyhow::anyhow!("virtual AP is waiting for Wi-Fi connection on {parent}"))?;
        let binary = record
            .binary_path
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("station executable identity is missing"))?;
        anyhow::ensure!(
            record.pid != 0
                && self
                    .inner
                    .process
                    .identity_matches_record(&record, WifiProcessKind::Client, binary)
                    .await?
                && self
                    .inner
                    .process
                    .owns_unix_socket(record.pid, &record.ctrl_path)
                    .await?,
            "station control socket is not owned by traffic-masq"
        );
        let client = crate::wifi::WpaSupplicantCtrlClient::connect(
            &record.ctrl_path,
            self.inner.ctrl_timeout,
        )
        .await?;
        let status = client.status().await?;
        anyhow::ensure!(
            status.wpa_state.is_connected(),
            "virtual AP is waiting for Wi-Fi connection on {parent}"
        );
        let frequency = status
            .freq
            .ok_or_else(|| anyhow::anyhow!("upstream frequency is unavailable"))?;
        let (band, channel) = crate::wifi::concurrent::channel_for(frequency)?;
        resolved.band = band;
        resolved.channel = channel;
        resolved.channel_width = crate::config::WifiChannelWidth::Ht20;
        Ok(resolved)
    }

    pub async fn validate_radio(&self, spec: &WifiApSpec) -> Result<(), SupervisorError> {
        let resolved = self.resolve_radio_spec(spec).await?;
        self.inner.radio.validate(&resolved).await?;
        Ok(())
    }

    /// Serialize configuration changes and reconcile the requested interface with hostapd.
    /// Reuse matching state or restart the owned process as needed; propagate setup failures.
    pub async fn configure(&self, spec: WifiApSpec) -> Result<(), SupervisorError> {
        let spec = self.resolve_radio_spec(&spec).await?;
        self.inner.recovery.check_scope(
            self.inner.records_dir.parent().expect("state directory"),
            Some(&spec.interface),
        )?;
        let _operation = self.inner.operation_lock.read().await;
        let interface = spec.interface.clone();
        let _interface_operation = self.inner.interface_operations.lock(&interface).await;
        crate::wifi::process::check_radio_unblocked(&interface).await?;
        self.inner.radio.validate(&spec).await?;
        let ctrl_path = self.ctrl_path(&interface);
        let rendered = self.render_for(&spec).await?;

        let existing = self.inner.tasks.lock().await.get(&interface).cloned();
        let task = match existing {
            Some(task)
                if task.record.pid == 0
                    && task.retry.is_suspended()
                    && task.spec == spec
                    && task.record.config_digest == rendered.config_digest
                    && task.record.key_digest == rendered.key_digest =>
            {
                // Reapplying the same intent and credentials must not bypass
                // a deterministic startup failure's retry suspension.
                self.ensure_interface_alive(&interface).await?;
                return Ok(());
            }
            Some(task)
                if task.record.config_digest == rendered.config_digest
                    && task.record.key_digest == rendered.key_digest =>
            {
                if task.retry.is_waiting() || self.task_process_matches(&task).await? {
                    task
                } else {
                    // The convergence loop also reapplies unchanged intent.
                    // Route repair through the same retry policy as liveness
                    // checks, otherwise it bypasses the restart backoff.
                    self.ensure_interface_alive(&interface).await?;
                    return Ok(());
                }
            }
            Some(mut task) => {
                // A pid-0 task is the placeholder `record_failed_startup`
                // leaves behind: there is no running hostapd to reload, so
                // treat it exactly like a restart regardless of what changed.
                let process_alive =
                    task.record.pid != 0 && self.inner.process.is_alive(task.record.pid).await?;
                if !process_alive || requires_restart(&task.spec, &spec) {
                    self.restart_task(&mut task, &spec, &rendered, &ctrl_path)
                        .await?;
                } else {
                    self.reload_task(&mut task, &spec, &rendered, &ctrl_path)
                        .await?;
                }
                task
            }
            None => {
                self.reconcile_new_interface(&spec, &rendered, &ctrl_path)
                    .await?
            }
        };

        self.inner.tasks.lock().await.insert(interface, task);
        Ok(())
    }

    async fn task_process_identity_matches(&self, task: &ApTask) -> Result<bool, SupervisorError> {
        if task.record.pid == 0 || !self.inner.process.is_alive(task.record.pid).await? {
            return Ok(false);
        }
        let binary_path = task
            .record
            .binary_path
            .as_deref()
            .expect("record store requires executable identity");
        Ok(self
            .inner
            .process
            .identity_matches_record(&task.record, WifiProcessKind::AccessPoint, binary_path)
            .await?)
    }

    async fn task_ctrl_socket_is_owned(&self, task: &ApTask) -> Result<bool, SupervisorError> {
        if task.record.ctrl_path != self.ctrl_path(&task.spec.interface)
            || !self.task_process_identity_matches(task).await?
        {
            return Ok(false);
        }
        Ok(self
            .inner
            .process
            .owns_unix_socket(task.record.pid, &task.record.ctrl_path)
            .await?)
    }

    async fn task_ctrl_is_owned(&self, task: &ApTask) -> Result<bool, SupervisorError> {
        if self
            .record_store(&task.spec.interface)
            .transition_pending()
            .await?
        {
            return Ok(false);
        }
        self.task_ctrl_socket_is_owned(task).await
    }

    async fn owned_ctrl_client(&self, task: &ApTask) -> Result<HostapdCtrlClient, SupervisorError> {
        if !self.task_ctrl_is_owned(task).await? {
            return Err(SupervisorError::NotOwned {
                interface: task.spec.interface.clone(),
                diagnostics: crate::wifi::process::wifi_conflict_diagnostics(
                    &task.spec.interface,
                    &self.ctrl_path(&task.spec.interface),
                )
                .await,
            });
        }
        let client =
            HostapdCtrlClient::connect(&task.record.ctrl_path, self.inner.ctrl_timeout).await?;
        // Re-check after connect. A connected AF_UNIX datagram remains bound to
        // the socket object it connected to even if the pathname is replaced;
        // this closes the ordinary unlink/rebind race around connect itself.
        if !self.task_ctrl_is_owned(task).await? {
            return Err(SupervisorError::NotOwned {
                interface: task.spec.interface.clone(),
                diagnostics: crate::wifi::process::wifi_conflict_diagnostics(
                    &task.spec.interface,
                    &self.ctrl_path(&task.spec.interface),
                )
                .await,
            });
        }
        Ok(client)
    }

    async fn task_process_matches(&self, task: &ApTask) -> Result<bool, SupervisorError> {
        let client = match self.owned_ctrl_client(task).await {
            Ok(client) => client,
            Err(SupervisorError::NotOwned { .. }) | Err(SupervisorError::Ctrl(_)) => {
                return Ok(false)
            }
            Err(error) => return Err(error),
        };
        Ok(client.ping().await.is_ok())
    }

    async fn reload_task(
        &self,
        task: &mut ApTask,
        spec: &WifiApSpec,
        rendered: &RenderedApConfig,
        ctrl_path: &Path,
    ) -> Result<(), SupervisorError> {
        let store = self.record_store(&spec.interface);
        // Prove both process identity and ctrl-socket ownership before touching
        // the runtime config. `configure` already holds operation_lock, so this
        // client cannot race another supervisor restart/configure operation.
        if task.record.ctrl_path != ctrl_path {
            return Err(SupervisorError::NotOwned {
                interface: spec.interface.clone(),
                diagnostics: crate::wifi::process::wifi_conflict_diagnostics(
                    &spec.interface,
                    &self.ctrl_path(&spec.interface),
                )
                .await,
            });
        }
        let client = self.owned_ctrl_client(task).await?;

        // Persist the fact that runtime may diverge from the durable record
        // before changing either the config file or the live daemon. Startup
        // recovery treats this marker as rollback-required and restarts from
        // committed desired state.
        store.mark_transition().await?;

        write_config_file(rendered).await?;
        client.reload().await?;

        let record = PersistedWifiRecord {
            config_digest: rendered.config_digest,
            key_digest: rendered.key_digest,
            ssid: spec.ssid.clone(),
            ..task.record.clone()
        };
        store.save(&record).await?;
        store.clear_transition().await?;

        task.spec = spec.clone();
        task.record = record;
        task.retry.clear();
        Ok(())
    }

    async fn restart_task(
        &self,
        task: &mut ApTask,
        spec: &WifiApSpec,
        rendered: &RenderedApConfig,
        ctrl_path: &Path,
    ) -> Result<(), SupervisorError> {
        self.stop_task(task).await?;
        let record = self.spawn_and_record(spec, rendered, ctrl_path).await?;
        task.spec = spec.clone();
        task.record = record;
        task.retry.clear();
        Ok(())
    }

    async fn reconcile_new_interface(
        &self,
        spec: &WifiApSpec,
        rendered: &RenderedApConfig,
        ctrl_path: &Path,
    ) -> Result<ApTask, SupervisorError> {
        let outcome = self.observe_ownership(spec, rendered, ctrl_path).await?;
        let record = match outcome {
            OwnershipOutcome::Absent => self.spawn_and_record(spec, rendered, ctrl_path).await?,
            OwnershipOutcome::Adopted(record) => record,
            OwnershipOutcome::DigestMismatch(record)
            | OwnershipOutcome::UnreachableOwned(record) => {
                self.inner
                    .process
                    .stop_recorded(&record, WifiProcessKind::AccessPoint, "hostapd")
                    .await?;
                self.spawn_and_record(spec, rendered, ctrl_path).await?
            }
            OwnershipOutcome::ForeignPresent => {
                return Err(SupervisorError::NotOwned {
                    interface: spec.interface.clone(),
                    diagnostics: crate::wifi::process::wifi_conflict_diagnostics(
                        &spec.interface,
                        &self.ctrl_path(&spec.interface),
                    )
                    .await,
                })
            }
        };
        Ok(ApTask {
            spec: spec.clone(),
            record,
            retry: RetryState::default(),
            last_hostapd_state: None,
            last_state_change_at: Instant::now(),
        })
    }

    async fn recorded_ctrl_is_safe_to_probe(
        &self,
        store: &WifiRecordStore,
        ctrl_path: &Path,
    ) -> Result<bool, SupervisorError> {
        let Some(record) = store.load().await? else {
            return Ok(false);
        };
        if record.ctrl_path != ctrl_path {
            return Ok(false);
        }
        let binary_path = record
            .binary_path
            .as_deref()
            .expect("record store requires executable identity");
        let pid = if record.pid == 0 {
            let pids = match self
                .inner
                .process
                .pids_matching_identity(
                    WifiProcessKind::AccessPoint,
                    binary_path,
                    &record.config_path,
                    record.started_at_unix,
                )
                .await
            {
                Ok(pids) if pids.len() == 1 => pids,
                Ok(_) | Err(_) => return Ok(false),
            };
            pids[0]
        } else {
            if !self
                .inner
                .process
                .identity_matches_record(&record, WifiProcessKind::AccessPoint, binary_path)
                .await?
            {
                return Ok(false);
            }
            record.pid
        };
        Ok(self.inner.process.owns_unix_socket(pid, ctrl_path).await?)
    }

    async fn observe_ownership(
        &self,
        spec: &WifiApSpec,
        rendered: &RenderedApConfig,
        ctrl_path: &Path,
    ) -> Result<OwnershipOutcome, SupervisorError> {
        let store = self.record_store(&spec.interface);
        let safe_to_probe = self
            .recorded_ctrl_is_safe_to_probe(&store, ctrl_path)
            .await?;
        let status = if safe_to_probe {
            match HostapdCtrlClient::connect(ctrl_path, self.inner.ctrl_timeout).await {
                Ok(client)
                    if self
                        .recorded_ctrl_is_safe_to_probe(&store, ctrl_path)
                        .await? =>
                {
                    client.status().await.ok()
                }
                _ => None,
            }
        } else {
            None
        };
        let ctrl_reachable = if safe_to_probe {
            status.is_some()
        } else {
            match tokio::fs::symlink_metadata(ctrl_path).await {
                Ok(_) => true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => {
                    return Err(SupervisorError::Configuration(
                        anyhow::Error::from(error).context(format!(
                            "failed to inspect hostapd control socket {}",
                            ctrl_path.display()
                        )),
                    ))
                }
            }
        };

        classify_ownership(
            &store,
            WifiProcessKind::AccessPoint,
            self.inner.process.as_ref(),
            &self.inner.hostapd_binary,
            ctrl_reachable,
            |record| {
                status.as_ref().is_some_and(|status| {
                    status.state == HostapdState::Enabled
                        && status.ssid.as_deref() == Some(record.ssid.as_str())
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
        spec: &WifiApSpec,
        rendered: &RenderedApConfig,
        ctrl_path: &Path,
    ) -> Result<PersistedWifiRecord, SupervisorError> {
        crate::wifi::process::check_radio_unblocked(&spec.interface).await?;
        // Stopping our process does not reserve its pathname. A foreign
        // endpoint appearing before restart must block every spawn path.
        match tokio::fs::symlink_metadata(ctrl_path).await {
            Ok(_) => {
                return Err(SupervisorError::NotOwned {
                    interface: spec.interface.clone(),
                    diagnostics: crate::wifi::process::wifi_conflict_diagnostics(
                        &spec.interface,
                        ctrl_path,
                    )
                    .await,
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
            &self.inner.hostapd_binary,
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
            .spawn(&self.inner.hostapd_binary, &rendered.path)
            .await
        {
            Ok(pid) => pid,
            Err(error) => {
                if let Err(cleanup) = store.clear().await {
                    return Err(SupervisorError::Configuration(anyhow::anyhow!(
                        "hostapd spawn failed: {error}; launch-intent cleanup also failed: {cleanup}; recovery required"
                    )));
                }
                let _ = tokio::fs::remove_file(&rendered.path).await;
                return Err(error.into());
            }
        };

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
                &self.inner.hostapd_binary,
                ctrl_path,
                &rendered.path,
                rendered.config_digest,
                rendered.key_digest,
                &spec.ssid,
            )
            .await?;
            wait_for_ready(
                self.inner.process.as_ref(),
                &record,
                self.inner.ctrl_timeout,
                &spec.interface,
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
            Err(error) => match self.graceful_stop(pid).await {
                Ok(()) => match store.clear().await {
                    Ok(()) => {
                        let _ = tokio::fs::remove_file(&rendered.path).await;
                        Err(error)
                    },
                    Err(cleanup) => Err(SupervisorError::Configuration(anyhow::anyhow!(
                        "hostapd startup failed: {error}; process stopped but ownership-record cleanup failed: {cleanup}; recovery required"
                    ))),
                },
                Err(cleanup) => Err(SupervisorError::Configuration(anyhow::anyhow!(
                    "hostapd startup failed: {error}; cleanup also failed: {cleanup}; recovery required"
                ))),
            },
        }
    }

    async fn stop_task(&self, task: &ApTask) -> Result<(), SupervisorError> {
        if task.record.pid == 0 || !self.inner.process.is_alive(task.record.pid).await? {
            return Ok(());
        }
        if !self.task_process_identity_matches(task).await? {
            return Err(SupervisorError::NotOwned {
                interface: task.spec.interface.clone(),
                diagnostics: crate::wifi::process::wifi_conflict_diagnostics(
                    &task.spec.interface,
                    &self.ctrl_path(&task.spec.interface),
                )
                .await,
            });
        }
        self.inner
            .process
            .stop_recorded(&task.record, WifiProcessKind::AccessPoint, "hostapd")
            .await?;
        Ok(())
    }

    async fn graceful_stop(&self, pid: u32) -> Result<(), SupervisorError> {
        graceful_stop(self.inner.process.as_ref(), pid, "hostapd").await?;
        Ok(())
    }

    /// Validate durable ownership before an offline cleanup stops any service.
    pub async fn check_cleanup_ownership(&self, interface: &str) -> Result<(), SupervisorError> {
        let _operation = self.inner.operation_lock.read().await;
        let _interface_operation = self.inner.interface_operations.lock(interface).await;
        self.check_cleanup_ownership_locked(interface).await
    }

    // Caller holds the interface operation lock. An unadopted record is safe
    // to retire only after proving its PID has exited. Missing sockets alone
    // never establish process absence, and launch intents still need recovery.
    async fn check_cleanup_ownership_locked(&self, interface: &str) -> Result<(), SupervisorError> {
        let store = self.record_store(interface);
        if store.transition_pending().await? {
            return Err(SupervisorError::Configuration(anyhow::anyhow!(
                "Wi-Fi launch transition on {interface} is incomplete; recovery required"
            )));
        }
        if let Some(record) = store.load().await? {
            let task_record = self
                .inner
                .tasks
                .lock()
                .await
                .get(interface)
                .map(|task| task.record.clone());
            let matches_task = task_record.as_ref().is_some_and(|task| *task == record);
            let can_retire = !matches_task
                && task_record.as_ref().is_none_or(|task| task.pid == 0)
                && record.pid != 0
                && !self.inner.process.is_alive(record.pid).await?;
            if !matches_task && !can_retire {
                return Err(SupervisorError::NotOwned {
                    interface: interface.to_owned(),
                    diagnostics: crate::wifi::process::wifi_conflict_diagnostics(
                        interface,
                        &self.ctrl_path(interface),
                    )
                    .await,
                });
            }
        }
        Ok(())
    }

    /// Stop the configured process and remove its runtime configuration and ownership record.
    /// Return the previous specification, or `None` when the interface was not configured.
    pub async fn disable(&self, interface: &str) -> Result<Option<WifiApSpec>, SupervisorError> {
        let _operation = self.inner.operation_lock.read().await;
        let _interface_operation = self.inner.interface_operations.lock(interface).await;
        self.check_cleanup_ownership_locked(interface).await?;
        let task = self.inner.tasks.lock().await.get(interface).cloned();
        let record = self.record_store(interface).load().await?;
        if task.is_none() && record.is_none() {
            return Ok(None);
        }
        // A failed-start placeholder has no process or socket ownership of its
        // own. Clean the durable exited record instead of the placeholder.
        if let Some(task) = task
            .as_ref()
            .filter(|task| task.record.pid != 0 || record.is_none())
        {
            self.stop_task(task).await?;
        }
        if task.as_ref().is_some_and(|task| task.record.pid != 0) {
            self.record_store(interface).clear().await?;
        } else {
            crate::wifi::lifecycle::clear_owned_record(&self.record_store(interface)).await?;
        }
        let config_path = render::config_path(&self.inner.runtime_dir, interface);
        match tokio::fs::remove_file(&config_path).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(SupervisorError::Configuration(anyhow::anyhow!(
                    "failed to remove hostapd config {}: {error}",
                    config_path.display()
                )))
            }
        }
        self.inner.tasks.lock().await.remove(interface);
        Ok(task.map(|task| task.spec))
    }

    /// Check that the configured hostapd binary is runnable.
    ///
    /// Lives on the supervisor rather than at startup because the supervisor is
    /// now built unconditionally: an access point can be configured at runtime
    /// on a daemon that started with `wifi.enabled = false`, and that path needs
    /// the same clear diagnosis of a missing binary that startup gives.
    pub async fn preflight_binary(&self) -> Result<(), SupervisorError> {
        preflight_daemon_binary(&self.inner.hostapd_binary, "hostapd", "wifi.hostapd_binary")
            .await
            .map_err(SupervisorError::BinaryPreflight)
    }

    /// Return configured service state and observed health; `None` means no supervised task exists.
    pub async fn status(&self, interface: &str) -> Option<WifiApStatus> {
        let _operation = self.inner.operation_lock.read().await;
        let _interface_operation = self.inner.interface_operations.lock(interface).await;
        let task = self.inner.tasks.lock().await.get(interface).cloned()?;

        // Never query a pathname merely because a task exists. A stale task or
        // an unlink/rebind can otherwise make STATUS read a foreign hostapd.
        let (hostapd_state, num_stations, observation_error) =
            match self.owned_ctrl_client(&task).await {
                Ok(client) => match client.status().await {
                    Ok(status) => (status.state, status.num_stations, None),
                    Err(error) => (
                        HostapdState::Other("unreachable".to_string()),
                        None,
                        Some(format!("hostapd STATUS failed: {error}")),
                    ),
                },
                Err(error) => (
                    HostapdState::Other("unreachable".to_string()),
                    None,
                    Some(error.to_string()),
                ),
            };

        let health = if hostapd_state == HostapdState::Enabled {
            WifiHealth::Healthy
        } else if let Some(error) = task.retry.failure() {
            if task.retry.is_suspended() {
                suspended_retry_health(error, task.retry.attempts(), interface).await
            } else {
                retry_health(
                    error,
                    task.retry.attempts(),
                    task.retry.next_restart(),
                    interface,
                )
                .await
            }
        } else {
            match &hostapd_state {
                HostapdState::Enabled => unreachable!("handled above"),
                HostapdState::Uninitialized
                | HostapdState::CountryUpdate
                | HostapdState::Acs
                | HostapdState::HtScan
                | HostapdState::Dfs => WifiHealth::Starting,
                HostapdState::Disabled => {
                    let base = if task.spec.channel == 0 {
                        "hostapd reports DISABLED with automatic channel selection; if ACS cannot collect survey data, select a fixed channel supported by the radio and country".to_string()
                    } else {
                        "hostapd reports DISABLED; check the channel, country and driver diagnostics".to_string()
                    };
                    let error = self.with_hostapd_diagnostics(&task, base).await;
                    retry_health(
                        &error,
                        task.retry.attempts().max(1),
                        task.retry.next_restart(),
                        interface,
                    )
                    .await
                }
                HostapdState::Other(state) => {
                    let base = observation_error.clone().unwrap_or_else(|| {
                        if state.is_empty() {
                            "hostapd STATUS reply did not contain a state field".to_string()
                        } else {
                            format!("hostapd reports unexpected state {state:?}")
                        }
                    });
                    let error = self.with_hostapd_diagnostics(&task, base).await;
                    retry_health(
                        &error,
                        task.retry.attempts().max(1),
                        task.retry.next_restart(),
                        interface,
                    )
                    .await
                }
            }
        };

        Some(WifiApStatus {
            interface: interface.to_string(),
            pid: task.record.pid,
            spec: task.spec,
            hostapd_state,
            num_stations,
            health,
        })
    }

    /// Query connected stations for a configured and ownership-verified access point.
    pub async fn stations(&self, interface: &str) -> Result<Vec<Station>, SupervisorError> {
        let _operation = self.inner.operation_lock.read().await;
        let _interface_operation = self.inner.interface_operations.lock(interface).await;
        let task = self
            .inner
            .tasks
            .lock()
            .await
            .get(interface)
            .cloned()
            .ok_or_else(|| SupervisorError::NotConfigured {
                interface: interface.to_string(),
            })?;
        let client = self.owned_ctrl_client(&task).await?;
        Ok(client.stations().await?)
    }

    /// Ask the configured and ownership-verified access point to disconnect a station.
    pub async fn deauthenticate(
        &self,
        interface: &str,
        mac: MacAddr,
    ) -> Result<(), SupervisorError> {
        let _operation = self.inner.operation_lock.read().await;
        let _interface_operation = self.inner.interface_operations.lock(interface).await;
        let task = self
            .inner
            .tasks
            .lock()
            .await
            .get(interface)
            .cloned()
            .ok_or_else(|| SupervisorError::NotConfigured {
                interface: interface.to_string(),
            })?;
        let client = self.owned_ctrl_client(&task).await?;
        client.deauthenticate(mac).await?;
        Ok(())
    }

    /// Reconfigure an ownership-verified access point from its current specification.
    pub async fn reload(&self, interface: &str) -> Result<WifiApSpec, SupervisorError> {
        let _operation = self.inner.operation_lock.read().await;
        let _interface_operation = self.inner.interface_operations.lock(interface).await;
        let task = self
            .inner
            .tasks
            .lock()
            .await
            .get(interface)
            .cloned()
            .ok_or_else(|| SupervisorError::NotConfigured {
                interface: interface.to_string(),
            })?;
        let client = self.owned_ctrl_client(&task).await?;
        client.reload().await?;
        Ok(task.spec)
    }

    /// Persist an interface passphrase on the blocking pool; service reconfiguration is separate.
    pub async fn set_passphrase(
        &self,
        interface: &str,
        passphrase: &WifiPassphrase,
    ) -> Result<(), SupervisorError> {
        self.inner
            .passphrase_store
            .set_async(interface, passphrase)
            .await
            .map_err(ResolvePassphraseError::from)?;
        Ok(())
    }

    /// Read the stored interface passphrase, returning `None` when no secret exists.
    pub async fn stored_passphrase(
        &self,
        interface: &str,
    ) -> Result<Option<WifiPassphrase>, SupervisorError> {
        self.inner
            .passphrase_store
            .get_async(interface)
            .await
            .map_err(ResolvePassphraseError::from)
            .map_err(Into::into)
    }

    /// Remove the stored interface passphrase on the blocking pool.
    pub async fn clear_passphrase(&self, interface: &str) -> Result<(), SupervisorError> {
        self.inner
            .passphrase_store
            .clear_async(interface)
            .await
            .map_err(ResolvePassphraseError::from)?;
        Ok(())
    }

    /// Check supervised processes and retry eligible failures using restart backoff.
    pub async fn ensure_alive(&self) -> Result<bool, SupervisorError> {
        self.ensure_alive_matching(None).await
    }

    /// Called under the network mutation gate with the current desired snapshot.
    /// Stale tasks cannot restart or replay settings withdrawn by a newer edit.
    pub async fn ensure_alive_for_config(
        &self,
        config: &AppConfig,
    ) -> Result<bool, SupervisorError> {
        let desired: Vec<_> = Self::effective_specs(config)?
            .into_iter()
            .filter(|spec| {
                crate::wifi::concurrent::parent_for(&config.network, &spec.interface).is_none()
            })
            .collect();
        self.ensure_alive_matching(Some(&desired)).await
    }

    async fn ensure_alive_matching(
        &self,
        desired: Option<&[WifiApSpec]>,
    ) -> Result<bool, SupervisorError> {
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
        }
        Ok(restarted_any)
    }

    async fn ensure_interface_alive(&self, interface: &str) -> Result<bool, SupervisorError> {
        let Some(mut task) = self.inner.tasks.lock().await.get(interface).cloned() else {
            return Ok(false);
        };
        let mut resumed_from_suspension = false;

        if task.retry.is_suspended() {
            let previous_ifindex = task.retry.suspended_interface();
            let current_ifindex = resolve_interface_index(interface).ok();
            if !task.retry.resume_for_interface(current_ifindex) {
                if previous_ifindex != current_ifindex {
                    self.inner
                        .tasks
                        .lock()
                        .await
                        .insert(interface.to_string(), task);
                }
                return Ok(false);
            }
            tracing::info!(
                %interface,
                ?previous_ifindex,
                ?current_ifindex,
                "Wi-Fi interface identity changed; resuming suspended hostapd retries"
            );
            if let Some(error) = task.retry.failure() {
                let resumed_error = clear_suspended_failure_message(error);
                task.retry.record_failure(resumed_error);
            }
            resumed_from_suspension = true;
        }

        if task.retry.is_waiting() {
            return Ok(false);
        }

        let ctrl_path = self.ctrl_path(interface);
        // Check liveness before probing ownership. Once hostapd has exited, its
        // control socket can no longer pass ownership verification; reporting
        // that secondary fact as the root cause hides the daemon failure.
        let process_alive =
            task.record.pid != 0 && self.inner.process.is_alive(task.record.pid).await?;
        let trusted_ctrl_node = if !process_alive {
            task.record.ctrl_dev.zip(task.record.ctrl_ino)
        } else if self.task_ctrl_socket_is_owned(&task).await? {
            match tokio::fs::symlink_metadata(&ctrl_path).await {
                Ok(metadata) => Some((metadata.dev(), metadata.ino())),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => {
                    return Err(SupervisorError::Configuration(
                        anyhow::Error::from(error).context(format!(
                            "failed to inspect hostapd control socket {}",
                            ctrl_path.display()
                        )),
                    ))
                }
            }
        } else if !self.task_process_identity_matches(&task).await? {
            task.record.ctrl_dev.zip(task.record.ctrl_ino)
        } else {
            None
        };
        let (status, observation_error) = if !process_alive {
            (
                None,
                Some(if task.record.pid == 0 {
                    task.retry
                        .failure()
                        .map(str::to_owned)
                        .unwrap_or_else(|| "hostapd has not started".to_string())
                } else {
                    format!("hostapd process {} exited", task.record.pid)
                }),
            )
        } else {
            match self.owned_ctrl_client(&task).await {
                Ok(client) => match client.status().await {
                    Ok(status) => (Some(status), None),
                    Err(error) => (None, Some(format!("hostapd STATUS failed: {error}"))),
                },
                Err(error @ SupervisorError::NotOwned { .. })
                | Err(error @ SupervisorError::Ctrl(_)) => (None, Some(error.to_string())),
                Err(error) => return Err(error),
            }
        };
        let state = status.as_ref().map(|status| status.state.clone());
        if state != task.last_hostapd_state {
            task.last_hostapd_state = state.clone();
            task.last_state_change_at = Instant::now();
        }
        if state == Some(HostapdState::Enabled) {
            if task.retry.attempts() != 0 {
                task.retry = RetryState::default();
            }
            self.inner
                .tasks
                .lock()
                .await
                .insert(interface.to_string(), task);
            return Ok(false);
        }
        let transition_timeout = match state {
            Some(HostapdState::Dfs) => Some(Duration::from_secs(900)),
            Some(HostapdState::Acs | HostapdState::HtScan) => Some(Duration::from_secs(120)),
            Some(HostapdState::Uninitialized | HostapdState::CountryUpdate) => {
                Some(Duration::from_secs(30))
            }
            _ => None,
        };
        if transition_timeout.is_some_and(|limit| task.last_state_change_at.elapsed() < limit) {
            self.inner
                .tasks
                .lock()
                .await
                .insert(interface.to_string(), task);
            return Ok(false);
        }

        let base_failure = match (&state, observation_error) {
            (_, Some(error)) => error,
            (Some(HostapdState::Disabled), None) if task.spec.channel == 0 => {
                "hostapd reports DISABLED with automatic channel selection; if ACS cannot collect survey data, select a fixed channel supported by the radio and country".to_string()
            }
            (Some(HostapdState::Disabled), None) => {
                "hostapd reports DISABLED; check channel, country, nl80211/driver and interface diagnostics".to_string()
            }
            (Some(HostapdState::Other(value)), None) if value.is_empty() => {
                "hostapd STATUS reply did not contain a state field".to_string()
            }
            (Some(HostapdState::Other(value)), None) => {
                format!("hostapd reports unexpected state {value:?}")
            }
            (Some(state), None) => format!(
                "hostapd remained in transitional state {state:?} for too long"
            ),
            (None, None) => "hostapd control interface is unreachable".to_string(),
        };
        let diagnostics = self
            .inner
            .process
            .recent_diagnostics(task.record.pid)
            .await
            .unwrap_or_default();
        let failure = match diagnostic_summary(&diagnostics) {
            Some(tail) => format!("{base_failure}; recent hostapd diagnostics: {tail}"),
            None => base_failure,
        };
        let suspend_retry = !resumed_from_suspension
            && (hostapd_failure_should_suspend_retry(&diagnostics)
                || hostapd_failure_text_should_suspend_retry(&failure));
        task.retry.record_failure(failure.clone());

        let competitors = crate::wifi::process::find_competing_network_managers().await;
        if suspend_retry && competitors.is_empty() {
            tracing::error!(
                %interface,
                pid = task.record.pid,
                error = %failure,
                "hostapd hit a deterministic configuration/radio failure; automatic retries will be suspended"
            );
        } else if suspend_retry {
            let advice =
                crate::wifi::process::format_competing_manager_advice(&competitors, interface);
            tracing::error!(
                %interface,
                pid = task.record.pid,
                competing = ?competitors,
                error = %failure,
                %advice,
                "hostapd hit a deterministic configuration/radio failure; automatic retries will be suspended"
            );
        } else if competitors.is_empty() {
            tracing::warn!(
                %interface,
                pid = task.record.pid,
                error = %failure,
                "hostapd is unhealthy; restarting it"
            );
        } else {
            let advice =
                crate::wifi::process::format_competing_manager_advice(&competitors, interface);
            tracing::warn!(
                %interface,
                pid = task.record.pid,
                competing = ?competitors,
                error = %failure,
                %advice,
                "hostapd is unhealthy; restarting it; other network managers are running and may be controlling this interface. Resolution advice:\n{advice}"
            );
        }
        // A placeholder task from a failed startup has pid 0; there is no
        // process to stop, and signalling pid 0 would signal the whole process
        // group — including this daemon.
        if task.record.pid != 0 && self.inner.process.is_alive(task.record.pid).await? {
            if !self.task_process_identity_matches(&task).await? {
                return Err(SupervisorError::NotOwned {
                    interface: interface.to_string(),
                    diagnostics: crate::wifi::process::wifi_conflict_diagnostics(
                        interface,
                        &self.ctrl_path(interface),
                    )
                    .await,
                });
            }
            self.stop_task(&task).await?;
        }

        // Do not probe an unverified pathname after stopping our process. If
        // the exact filesystem socket node proven above survived daemon exit,
        // it is a stale node we can remove. A different/rebound node is foreign.
        match tokio::fs::symlink_metadata(&ctrl_path).await {
            Ok(metadata)
                if trusted_ctrl_node == Some((metadata.dev(), metadata.ino()))
                    && crate::wifi::lifecycle::ctrl_socket_is_stale(&ctrl_path) =>
            {
                tokio::fs::remove_file(&ctrl_path).await.map_err(|error| {
                    SupervisorError::Configuration(anyhow::Error::from(error).context(format!(
                        "failed to remove stale owned hostapd control socket {}",
                        ctrl_path.display()
                    )))
                })?;
            }
            Ok(_) => {
                return Err(SupervisorError::NotOwned {
                    interface: interface.to_string(),
                    diagnostics: crate::wifi::process::wifi_conflict_diagnostics(
                        interface,
                        &self.ctrl_path(interface),
                    )
                    .await,
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(SupervisorError::Configuration(
                    anyhow::Error::from(error).context(format!(
                        "failed to inspect hostapd control socket {}",
                        ctrl_path.display()
                    )),
                ))
            }
        }

        task.retry.record_attempt();
        if suspend_retry {
            let failure = suspended_failure_message(&failure);
            task.retry
                .suspend(&failure, resolve_interface_index(interface).ok());
            self.inner
                .tasks
                .lock()
                .await
                .insert(interface.to_string(), task);
            return Ok(false);
        }

        let respawn = async {
            let rendered = self.render_for(&task.spec).await?;
            self.spawn_and_record(&task.spec, &rendered, &ctrl_path)
                .await
        }
        .await;
        match respawn {
            Ok(record) => {
                task.record = record;
                // A responsive control socket proves startup, not a working AP.
                // ACS can fail after PING succeeds. Keep exponential backoff
                // until a later health check actually observes ENABLED.
                task.retry.await_health(self.inner.restart_backoff_seconds);
                task.last_hostapd_state = None;
                task.last_state_change_at = Instant::now();
            }
            Err(error) => {
                tracing::error!(%interface, %error, "failed to respawn hostapd");
                // The failed launch has its own diagnostics in `error`. The old
                // PID must not classify subsequent retries using stale output.
                task.record.pid = 0;
                let error_text = error.to_string();
                if hostapd_failure_text_should_suspend_retry(&error_text) {
                    task.retry.suspend(
                        &suspended_failure_message(&error_text),
                        resolve_interface_index(interface).ok(),
                    );
                } else {
                    task.retry
                        .respawn_failed(self.inner.restart_backoff_seconds, &error_text);
                }
            }
        }
        self.inner
            .tasks
            .lock()
            .await
            .insert(interface.to_string(), task);
        Ok(true)
    }

    async fn with_hostapd_diagnostics(&self, task: &ApTask, base: String) -> String {
        let Ok(lines) = self.inner.process.recent_diagnostics(task.record.pid).await else {
            return base;
        };
        match diagnostic_summary(&lines) {
            Some(tail) => format!("{base}; recent hostapd diagnostics: {tail}"),
            None => base,
        }
    }

    /// Apply the shutdown policy to supervised processes and their ownership records.
    pub async fn shutdown(&self, policy: ShutdownPolicy) {
        let _operation = self.inner.operation_lock.write().await;
        let tasks = std::mem::take(&mut *self.inner.tasks.lock().await);

        for (interface, task) in tasks {
            if policy == ShutdownPolicy::RestoreInterfaces {
                if let Err(error) = self.stop_task(&task).await {
                    tracing::error!(%interface, %error, "failed to stop hostapd during shutdown; ownership record retained");
                    continue;
                }
                if let Err(error) = self.record_store(&interface).clear().await {
                    tracing::error!(%interface, %error, "hostapd stopped but ownership record cleanup failed");
                }
                let path = render::config_path(&self.inner.runtime_dir, &interface);
                if let Err(error) = tokio::fs::remove_file(&path).await {
                    if error.kind() != std::io::ErrorKind::NotFound {
                        tracing::warn!(%interface, path = %path.display(), %error, "failed to remove hostapd runtime config during shutdown");
                    }
                }
            }
        }
    }
}

fn requires_restart(old: &WifiApSpec, new: &WifiApSpec) -> bool {
    old.band != new.band
        || old.channel != new.channel
        || old.channel_width != new.channel_width
        || old.country_code != new.country_code
        || old.security != new.security
        || old.max_stations != new.max_stations
}

async fn write_config_file(rendered: &RenderedApConfig) -> Result<(), SupervisorError> {
    write_private_config(&rendered.path, &rendered.text)
        .await
        .map_err(|source| io_error(&rendered.path, source))
}

fn io_error(path: &Path, source: std::io::Error) -> SupervisorError {
    SupervisorError::Configuration(anyhow::Error::from(source).context(format!(
        "failed to write hostapd configuration to {}",
        path.display()
    )))
}

async fn wait_for_ready(
    process: &dyn SupervisedProcess,
    record: &PersistedWifiRecord,
    timeout: Duration,
    interface: &str,
) -> Result<(), SupervisorError> {
    let Some(binary_path) = record.binary_path.as_deref() else {
        return Err(SupervisorError::NotOwned {
            interface: interface.to_string(),
            diagnostics: crate::wifi::process::wifi_conflict_diagnostics(
                interface,
                &record.ctrl_path,
            )
            .await,
        });
    };
    let ready = wait_until_ready(timeout, || async {
        let owned = process
            .identity_matches_record(record, WifiProcessKind::AccessPoint, binary_path)
            .await
            .unwrap_or(false)
            && process
                .owns_unix_socket(record.pid, &record.ctrl_path)
                .await
                .unwrap_or(false);
        if !owned {
            return false;
        }
        match HostapdCtrlClient::connect(&record.ctrl_path, timeout).await {
            Ok(client) => {
                let still_owned = process
                    .identity_matches_record(record, WifiProcessKind::AccessPoint, binary_path)
                    .await
                    .unwrap_or(false)
                    && process
                        .owns_unix_socket(record.pid, &record.ctrl_path)
                        .await
                        .unwrap_or(false);
                still_owned && client.ping().await.is_ok()
            }
            Err(_) => false,
        }
    })
    .await;
    if ready {
        Ok(())
    } else {
        let diagnostics = process
            .recent_diagnostics(record.pid)
            .await
            .ok()
            .and_then(|lines| diagnostic_summary(&lines))
            .map(|tail| format!("; recent hostapd diagnostics: {tail}"))
            .unwrap_or_default();
        Err(SupervisorError::StartupTimeout {
            interface: interface.to_string(),
            timeout: STARTUP_READY_TIMEOUT.max(timeout),
            diagnostics,
        })
    }
}

pub(crate) use crate::netlink::interface_is_wireless;

#[cfg(test)]
mod tests;
