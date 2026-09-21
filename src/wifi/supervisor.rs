use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tokio::sync::Mutex;

use crate::config::{AppConfig, ShutdownPolicy};
use crate::dhcp::supervisor::resolve_interface_index;
use crate::wifi::ctrl::{CtrlError, HostapdCtrlClient, HostapdState, MacAddr, Station};
pub use crate::wifi::lifecycle::WifiHealth;
use crate::wifi::lifecycle::{
    classify_ownership, cleanup_unconfigured_records, graceful_stop,
    preflight_binary as preflight_daemon_binary, retry_health, save_launch_intent,
    save_spawned_record, wait_until_ready, write_private_config, OwnershipOutcome, RetryState,
    STARTUP_READY_TIMEOUT,
};
use crate::wifi::process::{ProcessError, SupervisedProcess, TokioSupervisedProcess};
use crate::wifi::record::{PersistedWifiRecord, WifiProcessKind, WifiRecordError, WifiRecordStore};
use crate::wifi::render::{
    self, render_hostapd_config, ApRenderInput, RenderError, RenderedApConfig, WifiDigest,
};
use crate::wifi::secret::WifiPassphrase;
use crate::wifi::store::{resolve_passphrase, PassphraseStore, ResolvePassphraseError};
use crate::wifi::WifiApSpec;

const DEFAULT_CTRL_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Error)]
pub enum SupervisorError {
    #[error("Wi-Fi access point on {interface} is not configured")]
    NotConfigured { interface: String },

    #[error(
        "refusing to manage hostapd on {interface}: a process not started by this daemon already occupies its control socket"
    )]
    NotOwned { interface: String },

    #[error("hostapd for {interface} did not become ready within {timeout:?}")]
    StartupTimeout {
        interface: String,
        timeout: Duration,
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
    Ctrl(#[from] CtrlError),

    #[error(transparent)]
    Configuration(#[from] anyhow::Error),
}

impl SupervisorError {
    /// The interface this error is about, when there is one.
    pub fn interface(&self) -> &str {
        match self {
            SupervisorError::NotConfigured { interface }
            | SupervisorError::NotOwned { interface }
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
    hostapd_binary: PathBuf,
    runtime_dir: PathBuf,
    records_dir: PathBuf,
    restart_backoff_seconds: u64,
    ctrl_timeout: Duration,
    process: Arc<dyn SupervisedProcess>,
    passphrase_store: PassphraseStore,
    tasks: Mutex<HashMap<String, ApTask>>,
    operation_lock: Mutex<()>,
}

impl HostapdSupervisor {
    /// Start the hostapd supervisor from effective configuration using the production process adapter.
    pub async fn start(config: &AppConfig) -> Result<Self, SupervisorError> {
        Self::start_with_process(config, Arc::new(TokioSupervisedProcess::new())).await
    }

    /// Initialize hostapd supervision with the supplied process adapter and recover configured interfaces.
    pub async fn start_with_process(
        config: &AppConfig,
        process: Arc<dyn SupervisedProcess>,
    ) -> Result<Self, SupervisorError> {
        let records_dir = config.runtime.state_dir.join("wifi");
        let supervisor = Self {
            inner: Arc::new(Inner {
                hostapd_binary: config.wifi.hostapd_binary.clone(),
                runtime_dir: config.wifi.runtime_dir.clone(),
                passphrase_store: PassphraseStore::new(records_dir.join("psk")),
                records_dir,
                restart_backoff_seconds: config.wifi.restart_backoff_seconds.max(1),
                ctrl_timeout: DEFAULT_CTRL_TIMEOUT,
                process,
                tasks: Mutex::new(HashMap::new()),
                operation_lock: Mutex::new(()),
            }),
        };

        let specs = Self::effective_specs(config)?;
        let configured_interfaces: HashSet<String> =
            specs.iter().map(|spec| spec.interface.clone()).collect();
        let configured_clients: HashSet<String> = config
            .network
            .interfaces
            .iter()
            .filter_map(|(name, interface)| interface.wifi_client.as_ref().map(|_| name.clone()))
            .collect();
        let no_interfaces = HashSet::new();
        // AP startup precedes the client supervisor. Recover every Wi-Fi
        // process type that could otherwise occupy an AP control socket first,
        // including an uncommitted client/scan left by a crashed immediate
        // mutation. Committed clients are explicitly preserved.
        cleanup_unconfigured_records(
            &supervisor.inner.records_dir,
            WifiProcessKind::Scan,
            &no_interfaces,
            supervisor.inner.process.as_ref(),
        )
        .await
        .map_err(SupervisorError::Configuration)?;
        cleanup_unconfigured_records(
            &supervisor.inner.records_dir,
            WifiProcessKind::Client,
            &configured_clients,
            supervisor.inner.process.as_ref(),
        )
        .await
        .map_err(SupervisorError::Configuration)?;
        cleanup_unconfigured_records(
            &supervisor.inner.records_dir,
            WifiProcessKind::AccessPoint,
            &configured_interfaces,
            supervisor.inner.process.as_ref(),
        )
        .await
        .map_err(SupervisorError::Configuration)?;

        for spec in specs {
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

            // A failure to bring up one access point (interface busy with a
            // foreign manager, driver refusing the AP mode, ...) must not take
            // the whole daemon down. The task is recorded anyway so the
            // periodic liveness loop keeps retrying it with backoff until the
            // interface becomes available.
            if let Err(error) = supervisor.configure(spec.clone()).await {
                tracing::warn!(
                    interface = %error.interface(),
                    %error,
                    "failed to start Wi-Fi access point at startup; \
                     will keep retrying in the background"
                );
                supervisor
                    .record_failed_startup(&spec, &error.to_string())
                    .await;
            }
        }

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
    /// be started (e.g. a foreign manager holds the interface). The liveness
    /// loop treats it like any other dead task and keeps retrying with backoff,
    /// so the AP comes up as soon as the interface is freed.
    pub async fn record_failed_startup(&self, spec: &WifiApSpec, error: &str) {
        let mut tasks = self.inner.tasks.lock().await;
        tasks
            .entry(spec.interface.clone())
            .or_insert_with(|| ApTask {
                spec: spec.clone(),
                record: PersistedWifiRecord {
                    pid: 0,
                    started_at_unix: 0,
                    ctrl_path: self.ctrl_path(&spec.interface),
                    config_path: render::config_path(&self.inner.runtime_dir, &spec.interface),
                    config_digest: WifiDigest::of(&[]),
                    key_digest: WifiDigest::of(&[]),
                    ssid: spec.ssid.clone(),
                },
                retry: RetryState::failed_startup(self.inner.restart_backoff_seconds, error),
            });
    }

    fn record_store(&self, interface: &str) -> WifiRecordStore {
        WifiRecordStore::for_access_point(&self.inner.records_dir, interface)
    }

    async fn render_for(&self, spec: &WifiApSpec) -> Result<RenderedApConfig, SupervisorError> {
        let passphrase = resolve_passphrase(spec, &self.inner.passphrase_store)?;
        Ok(render_hostapd_config(ApRenderInput {
            spec,
            ctrl_interface: &self.inner.runtime_dir,
            ctrl_interface_group: None,
            passphrase: passphrase.as_ref(),
        })?)
    }

    /// Serialize configuration changes and reconcile the requested interface with hostapd.
    /// Reuse matching state or restart the owned process as needed; propagate setup failures.
    pub async fn configure(&self, spec: WifiApSpec) -> Result<(), SupervisorError> {
        crate::core::recovery::check_scope(
            self.inner.records_dir.parent().expect("state directory"),
            Some(&spec.interface),
        )?;
        let _operation = self.inner.operation_lock.lock().await;
        let interface = spec.interface.clone();
        let ctrl_path = self.ctrl_path(&interface);
        let rendered = self.render_for(&spec).await?;

        let existing = self.inner.tasks.lock().await.get(&interface).cloned();
        let task = match existing {
            Some(mut task)
                if task.record.config_digest == rendered.config_digest
                    && task.record.key_digest == rendered.key_digest =>
            {
                if self.task_process_matches(&task).await? {
                    task
                } else {
                    self.restart_task(&mut task, &spec, &rendered, &ctrl_path)
                        .await?;
                    task
                }
            }
            Some(mut task) => {
                // A pid-0 task is the placeholder `record_failed_startup`
                // leaves behind: there is no running hostapd to reload, so
                // treat it exactly like a restart regardless of what changed.
                if task.record.pid == 0 || requires_restart(&task.spec, &spec) {
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

    async fn task_process_matches(&self, task: &ApTask) -> Result<bool, SupervisorError> {
        if self
            .record_store(&task.spec.interface)
            .transition_pending()
            .await?
        {
            return Ok(false);
        }
        if task.record.pid == 0 || !self.inner.process.is_alive(task.record.pid).await? {
            return Ok(false);
        }
        if !self
            .inner
            .process
            .cmdline_matches_kind(
                task.record.pid,
                WifiProcessKind::AccessPoint,
                &task.record.config_path,
            )
            .await?
        {
            return Ok(false);
        }

        let client =
            match HostapdCtrlClient::connect(&task.record.ctrl_path, self.inner.ctrl_timeout).await
            {
                Ok(client) => client,
                Err(_) => return Ok(false),
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
        // Persist the fact that runtime may diverge from the durable record
        // before changing either the config file or the live daemon. Startup
        // recovery treats this marker as rollback-required and restarts from
        // committed desired state.
        store.mark_transition().await?;

        write_config_file(rendered).await?;
        let client = HostapdCtrlClient::connect(ctrl_path, self.inner.ctrl_timeout).await?;
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
        task.retry.consecutive_failures = 0;
        task.retry.next_restart_earliest = None;
        Ok(())
    }

    async fn restart_task(
        &self,
        task: &mut ApTask,
        spec: &WifiApSpec,
        rendered: &RenderedApConfig,
        ctrl_path: &Path,
    ) -> Result<(), SupervisorError> {
        self.graceful_stop(task.record.pid).await?;
        let record = self.spawn_and_record(spec, rendered, ctrl_path).await?;
        task.spec = spec.clone();
        task.record = record;
        task.retry.consecutive_failures = 0;
        task.retry.next_restart_earliest = None;
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
                self.graceful_stop(record.pid).await?;
                self.spawn_and_record(spec, rendered, ctrl_path).await?
            }
            OwnershipOutcome::ForeignPresent => {
                return Err(SupervisorError::NotOwned {
                    interface: spec.interface.clone(),
                })
            }
        };
        Ok(ApTask {
            spec: spec.clone(),
            record,
            retry: RetryState::default(),
        })
    }

    async fn observe_ownership(
        &self,
        spec: &WifiApSpec,
        rendered: &RenderedApConfig,
        ctrl_path: &Path,
    ) -> Result<OwnershipOutcome, SupervisorError> {
        let store = self.record_store(&spec.interface);

        let status = match HostapdCtrlClient::connect(ctrl_path, self.inner.ctrl_timeout).await {
            Ok(client) => client.status().await.ok(),
            Err(_) => None,
        };
        classify_ownership(
            &store,
            WifiProcessKind::AccessPoint,
            self.inner.process.as_ref(),
            status.is_some(),
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
        write_config_file(rendered).await?;
        let store = self.record_store(&spec.interface);
        save_launch_intent(
            &store,
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
                return Err(error.into());
            }
        };

        let result = async {
            let record = save_spawned_record(
                &store,
                pid,
                ctrl_path,
                &rendered.path,
                rendered.config_digest,
                rendered.key_digest,
                &spec.ssid,
            )
            .await?;
            wait_for_ready(ctrl_path, self.inner.ctrl_timeout, &spec.interface).await?;
            store.clear_transition().await?;
            Ok(record)
        }
        .await;

        match result {
            Ok(record) => Ok(record),
            Err(error) => match self.graceful_stop(pid).await {
                Ok(()) => match store.clear().await {
                    Ok(()) => Err(error),
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

    async fn graceful_stop(&self, pid: u32) -> Result<(), SupervisorError> {
        graceful_stop(self.inner.process.as_ref(), pid, "hostapd").await?;
        Ok(())
    }

    /// Stop the configured process and remove its runtime configuration and ownership record.
    /// Return the previous specification, or `None` when the interface was not configured.
    pub async fn disable(&self, interface: &str) -> Result<Option<WifiApSpec>, SupervisorError> {
        let _operation = self.inner.operation_lock.lock().await;
        let Some(task) = self.inner.tasks.lock().await.get(interface).cloned() else {
            return Ok(None);
        };

        self.graceful_stop(task.record.pid).await?;
        self.record_store(interface).clear().await?;
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
        Ok(Some(task.spec))
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
            .map_err(SupervisorError::Configuration)
    }

    /// Return configured service state and observed health; `None` means no supervised task exists.
    pub async fn status(&self, interface: &str) -> Option<WifiApStatus> {
        let task = self.inner.tasks.lock().await.get(interface).cloned()?;
        let ctrl_path = self.ctrl_path(interface);

        let (hostapd_state, num_stations) =
            match HostapdCtrlClient::connect(&ctrl_path, self.inner.ctrl_timeout).await {
                Ok(client) => match client.status().await {
                    Ok(status) => (status.state, status.num_stations),
                    Err(_) => (HostapdState::Other("unreachable".to_string()), None),
                },
                Err(_) => (HostapdState::Other("unreachable".to_string()), None),
            };

        let health = if let Some(error) = task.retry.last_failure.as_deref() {
            retry_health(
                error,
                task.retry.consecutive_failures,
                task.retry.next_restart_earliest,
                interface,
            )
            .await
        } else if hostapd_state == HostapdState::Enabled {
            WifiHealth::Healthy
        } else {
            WifiHealth::Starting
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

    /// Query connected stations for a configured access point; reject unknown interfaces.
    pub async fn stations(&self, interface: &str) -> Result<Vec<Station>, SupervisorError> {
        if !self.inner.tasks.lock().await.contains_key(interface) {
            return Err(SupervisorError::NotConfigured {
                interface: interface.to_string(),
            });
        }
        let ctrl_path = self.ctrl_path(interface);
        let client = HostapdCtrlClient::connect(&ctrl_path, self.inner.ctrl_timeout).await?;
        Ok(client.stations().await?)
    }

    /// Ask the configured access point to disconnect the specified station.
    pub async fn deauthenticate(
        &self,
        interface: &str,
        mac: MacAddr,
    ) -> Result<(), SupervisorError> {
        if !self.inner.tasks.lock().await.contains_key(interface) {
            return Err(SupervisorError::NotConfigured {
                interface: interface.to_string(),
            });
        }
        let ctrl_path = self.ctrl_path(interface);
        let client = HostapdCtrlClient::connect(&ctrl_path, self.inner.ctrl_timeout).await?;
        client.deauthenticate(mac).await?;
        Ok(())
    }

    /// Reconfigure an access point from its current specification, including its stored secret.
    pub async fn reload(&self, interface: &str) -> Result<WifiApSpec, SupervisorError> {
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
        let ctrl_path = self.ctrl_path(interface);
        let client = HostapdCtrlClient::connect(&ctrl_path, self.inner.ctrl_timeout).await?;
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
            .set(interface, passphrase)
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
            .get(interface)
            .map_err(ResolvePassphraseError::from)
            .map_err(Into::into)
    }

    /// Remove the stored interface passphrase on the blocking pool.
    pub async fn clear_passphrase(&self, interface: &str) -> Result<(), SupervisorError> {
        self.inner
            .passphrase_store
            .clear(interface)
            .map_err(ResolvePassphraseError::from)?;
        Ok(())
    }

    /// Check supervised processes and retry eligible failures using restart backoff.
    pub async fn ensure_alive(&self) -> Result<bool, SupervisorError> {
        let _operation = self.inner.operation_lock.lock().await;
        let interfaces: Vec<String> = self.inner.tasks.lock().await.keys().cloned().collect();

        let mut restarted_any = false;
        for interface in interfaces {
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

        if task.retry.is_waiting() {
            return Ok(false);
        }

        let ctrl_path = self.ctrl_path(interface);
        let transition_pending = self.record_store(interface).transition_pending().await?;
        let process_alive = self
            .inner
            .process
            .is_alive(task.record.pid)
            .await
            .unwrap_or(false);
        let ctrl_alive = !transition_pending
            && process_alive
            && match HostapdCtrlClient::connect(&ctrl_path, self.inner.ctrl_timeout).await {
                Ok(client) => client.ping().await.is_ok(),
                Err(_) => false,
            };

        if ctrl_alive {
            if task.retry.consecutive_failures != 0 {
                task.retry = RetryState::default();
                self.inner
                    .tasks
                    .lock()
                    .await
                    .insert(interface.to_string(), task);
            }
            return Ok(false);
        }

        let competitors = crate::wifi::process::find_competing_network_managers().await;
        if competitors.is_empty() {
            tracing::warn!(
                %interface,
                pid = task.record.pid,
                "hostapd is not responding; restarting it"
            );
        } else {
            let advice =
                crate::wifi::process::format_competing_manager_advice(&competitors, interface);
            tracing::warn!(
                %interface,
                pid = task.record.pid,
                competing = ?competitors,
                %advice,
                "hostapd is not responding; restarting it; other network managers are running and may be controlling this interface. Resolution advice:\n{advice}"
            );
        }
        let rendered = self.render_for(&task.spec).await?;

        // A placeholder task from a failed startup has pid 0; there is no
        // process to stop, and signalling pid 0 would signal the whole process
        // group — including this daemon.
        if task.record.pid != 0 {
            self.graceful_stop(task.record.pid).await?;
        }

        if let Ok(client) = HostapdCtrlClient::connect(&ctrl_path, self.inner.ctrl_timeout).await {
            if client.ping().await.is_ok() {
                return Err(SupervisorError::NotOwned {
                    interface: interface.to_string(),
                });
            }
        }

        task.retry.consecutive_failures += 1;
        match self
            .spawn_and_record(&task.spec, &rendered, &ctrl_path)
            .await
        {
            Ok(record) => {
                task.record = record;
                task.retry.next_restart_earliest = None;
                task.retry.last_failure = None;
            }
            Err(error) => {
                tracing::error!(%interface, %error, "failed to respawn hostapd");
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
        let _operation = self.inner.operation_lock.lock().await;
        let tasks = std::mem::take(&mut *self.inner.tasks.lock().await);

        for (interface, task) in tasks {
            if policy == ShutdownPolicy::RestoreInterfaces {
                if let Err(error) = self.graceful_stop(task.record.pid).await {
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
    ctrl_path: &Path,
    timeout: Duration,
    interface: &str,
) -> Result<(), SupervisorError> {
    let ready = wait_until_ready(timeout, || async {
        match HostapdCtrlClient::connect(ctrl_path, timeout).await {
            Ok(client) => client.ping().await.is_ok(),
            Err(_) => false,
        }
    })
    .await;
    if ready {
        Ok(())
    } else {
        Err(SupervisorError::StartupTimeout {
            interface: interface.to_string(),
            timeout: STARTUP_READY_TIMEOUT.max(timeout),
        })
    }
}

pub(crate) use crate::netlink::interface_is_wireless;

#[cfg(test)]
mod tests;
