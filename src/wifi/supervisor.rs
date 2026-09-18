use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tokio::sync::Mutex;

use crate::config::{AppConfig, ShutdownPolicy};
use crate::dhcp::supervisor::resolve_interface_index;
use crate::wifi::ctrl::{CtrlError, HostapdCtrlClient, HostapdState, MacAddr, Station};
use crate::wifi::lifecycle::{
    classify_ownership, graceful_stop, preflight_binary as preflight_daemon_binary, retry_health,
    save_spawned_record,
    wait_until_ready, write_private_config, OwnershipOutcome, RetryState, STARTUP_READY_TIMEOUT,
};
pub use crate::wifi::lifecycle::WifiHealth;
use crate::wifi::process::{ProcessError, SupervisedProcess, TokioSupervisedProcess};
use crate::wifi::record::{PersistedWifiRecord, WifiRecordError, WifiRecordStore};
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
    pub async fn start(config: &AppConfig) -> Result<Self, SupervisorError> {
        Self::start_with_process(config, Arc::new(TokioSupervisedProcess::new())).await
    }

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

        for spec in Self::effective_specs(config)? {
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
                retry: RetryState::failed_startup(
                    self.inner.restart_backoff_seconds,
                    error,
                ),
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

    pub async fn configure(&self, spec: WifiApSpec) -> Result<(), SupervisorError> {
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
        if task.record.pid == 0 || !self.inner.process.is_alive(task.record.pid).await? {
            return Ok(false);
        }
        if !self
            .inner
            .process
            .cmdline_contains(task.record.pid, &task.record.config_path)
            .await?
        {
            return Ok(false);
        }

        let client = match HostapdCtrlClient::connect(
            &task.record.ctrl_path,
            self.inner.ctrl_timeout,
        )
        .await
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
        write_config_file(rendered).await?;
        let client = HostapdCtrlClient::connect(ctrl_path, self.inner.ctrl_timeout).await?;
        client.reload().await?;

        let record = PersistedWifiRecord {
            config_digest: rendered.config_digest,
            key_digest: rendered.key_digest,
            ssid: spec.ssid.clone(),
            ..task.record.clone()
        };
        self.record_store(&spec.interface).save(&record).await?;

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

    async fn spawn_and_record(
        &self,
        spec: &WifiApSpec,
        rendered: &RenderedApConfig,
        ctrl_path: &Path,
    ) -> Result<PersistedWifiRecord, SupervisorError> {
        write_config_file(rendered).await?;
        let pid = self
            .inner
            .process
            .spawn(&self.inner.hostapd_binary, &rendered.path)
            .await?;

        let result = async {
            wait_for_ready(ctrl_path, self.inner.ctrl_timeout, &spec.interface).await?;

            Ok(save_spawned_record(
                &self.record_store(&spec.interface),
                pid,
                ctrl_path,
                &rendered.path,
                rendered.config_digest,
                rendered.key_digest,
                &spec.ssid,
            )
            .await?)
        }
        .await;

        match result {
            Ok(record) => Ok(record),
            Err(error) => match self.graceful_stop(pid).await {
                Ok(()) => match self.record_store(&spec.interface).clear().await {
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
        preflight_daemon_binary(
            &self.inner.hostapd_binary,
            "hostapd",
            "wifi.hostapd_binary",
        )
        .await
        .map_err(SupervisorError::Configuration)
    }

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

    pub async fn clear_passphrase(&self, interface: &str) -> Result<(), SupervisorError> {
        self.inner
            .passphrase_store
            .clear(interface)
            .map_err(ResolvePassphraseError::from)?;
        Ok(())
    }

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
        let process_alive = self
            .inner
            .process
            .is_alive(task.record.pid)
            .await
            .unwrap_or(false);
        let ctrl_alive = process_alive
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
mod tests {
    use std::os::unix::net::UnixDatagram as StdUnixDatagram;
    use std::sync::atomic::{AtomicBool, Ordering};

    use tempfile::tempdir;

    use super::*;
    use crate::config::{
        DhcpConfig, InterfaceConfig, InterfaceRole, NetworkConfig, RouterConfig, RuntimeConfig,
        SecurityConfig, ShutdownPolicy as ConfigShutdownPolicy, VpnConfig, WifiApConfig, WifiBand,
        WifiChannelWidth, WifiConfig, WifiSecurity,
    };
    use crate::test_support::{FakeProcessCall as FakeCall, FakeSupervisedProcess};
    use crate::wifi::render::WifiDigest;

    enum SsidSource {
        Fixed(String),
        ConfigFile(PathBuf),
    }

    impl SsidSource {
        fn current(&self) -> String {
            match self {
                SsidSource::Fixed(ssid) => ssid.clone(),
                SsidSource::ConfigFile(path) => read_ssid_from_config(path),
            }
        }
    }

    fn read_ssid_from_config(path: &Path) -> String {
        let content = std::fs::read_to_string(path).expect("read fake hostapd config");
        let hex = content
            .lines()
            .find_map(|line| line.strip_prefix("ssid2="))
            .expect("ssid2 line present");
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("valid hex"))
            .collect();
        String::from_utf8(bytes).expect("ssid2 decodes as UTF-8 in these tests")
    }

    struct FakeHostapdCtrl {
        shutdown: Arc<AtomicBool>,
        join: Option<std::thread::JoinHandle<()>>,
        ctrl_path: PathBuf,
    }

    impl FakeHostapdCtrl {
        fn spawn(ctrl_path: PathBuf, source: SsidSource) -> Self {
            let socket = StdUnixDatagram::bind(&ctrl_path).expect("bind fake ctrl socket");
            socket
                .set_read_timeout(Some(Duration::from_millis(20)))
                .expect("set read timeout");
            let shutdown = Arc::new(AtomicBool::new(false));
            let shutdown_for_thread = shutdown.clone();

            let join = std::thread::spawn(move || {
                let mut ssid = source.current();
                let mut buffer = [0u8; 4096];
                while !shutdown_for_thread.load(Ordering::Relaxed) {
                    let (read, from) = match socket.recv_from(&mut buffer) {
                        Ok(result) => result,
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) =>
                        {
                            continue;
                        }
                        Err(_) => break,
                    };
                    let command = String::from_utf8_lossy(&buffer[..read]).into_owned();
                    let reply = if command == "PING" {
                        "PONG\n".to_string()
                    } else if command == "STATUS" {
                        format!(
                            "state=ENABLED\nssid[0]={ssid}\nbssid[0]=02:00:00:00:00:00\nnum_sta[0]=0\n"
                        )
                    } else if command == "RELOAD" {
                        ssid = source.current();
                        "OK\n".to_string()
                    } else if command == "STA-FIRST" {
                        "FAIL\n".to_string()
                    } else if command.starts_with("DEAUTHENTICATE ") {
                        "OK\n".to_string()
                    } else {
                        "UNKNOWN COMMAND\n".to_string()
                    };
                    let _ = socket.send_to_addr(reply.as_bytes(), &from);
                }
            });

            Self {
                shutdown,
                join: Some(join),
                ctrl_path,
            }
        }

        fn spawn_fixed(ctrl_path: PathBuf, ssid: &str) -> Self {
            Self::spawn(ctrl_path, SsidSource::Fixed(ssid.to_string()))
        }

        fn spawn_for_config(ctrl_path: PathBuf, config_path: PathBuf) -> Self {
            Self::spawn(ctrl_path, SsidSource::ConfigFile(config_path))
        }

        fn spawn_silent(ctrl_path: PathBuf) -> Self {
            let socket = StdUnixDatagram::bind(&ctrl_path).expect("bind silent fake ctrl socket");
            socket
                .set_read_timeout(Some(Duration::from_millis(20)))
                .expect("set read timeout");
            let shutdown = Arc::new(AtomicBool::new(false));
            let shutdown_for_thread = shutdown.clone();
            let join = std::thread::spawn(move || {
                let mut buffer = [0u8; 4096];
                while !shutdown_for_thread.load(Ordering::Relaxed) {
                    match socket.recv_from(&mut buffer) {
                        Ok(_) => {}
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) => {}
                        Err(_) => break,
                    }
                }
            });
            Self {
                shutdown,
                join: Some(join),
                ctrl_path,
            }
        }
    }

    impl Drop for FakeHostapdCtrl {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::Relaxed);
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
            let _ = std::fs::remove_file(&self.ctrl_path);
        }
    }

    type FakeProcess = FakeSupervisedProcess<FakeHostapdCtrl>;

    fn fake_process() -> Arc<FakeProcess> {
        FakeProcess::new("hostapd", 1000, "", |_interface, config_path, _profile| {
            let ctrl_path = config_path.with_extension("");
            FakeHostapdCtrl::spawn_for_config(ctrl_path, config_path.to_path_buf())
        })
    }

    fn seed_process(process: &FakeProcess, pid: u32, config_path: PathBuf, ssid: &str) {
        let ctrl_path = config_path.with_extension("");
        let responder = FakeHostapdCtrl::spawn_fixed(ctrl_path, ssid);
        process.seed(pid, config_path, responder);
    }

    fn ap_config(ssid: &str) -> WifiApConfig {
        WifiApConfig {
            ssid: ssid.to_string(),
            country_code: Some("PL".to_string()),
            band: WifiBand::Ghz2,
            channel: 6,
            channel_width: WifiChannelWidth::Ht20,

            security: WifiSecurity::Open,
            hidden: false,
            client_isolation: false,
            max_stations: 32,
            passphrase_file: None,
        }
    }

    fn spec(interface: &str, ssid: &str) -> WifiApSpec {
        let config = InterfaceConfig {
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some("192.168.101.1/24".parse().expect("network")),
            dhcp: None,
            dhcp_client: None,
            wifi: Some(ap_config(ssid)),
            wifi_client: None,
            nat: true,
        };
        WifiApSpec::from_interface_config(interface, &config)
            .expect("valid")
            .expect("spec")
    }

    fn app_config(state_dir: &Path, runtime_dir: &Path) -> AppConfig {
        AppConfig {
            runtime: RuntimeConfig {
                state_dir: state_dir.to_path_buf(),
                log_dir: state_dir.join("log"),
                socket_path: state_dir.join("daemon.sock"),
                pid_path: state_dir.join("daemon.pid"),
                socket_group: None,
                shutdown_policy: ConfigShutdownPolicy::PreserveInterfaces,
            },
            network: NetworkConfig::default(),
            router: RouterConfig::default(),
            dhcp: DhcpConfig {
                leases_dir: state_dir.join("dhcp/leases"),
                default_lease_seconds: 86_400,
            },
            wifi: WifiConfig {
                enabled: true,
                hostapd_binary: PathBuf::from("/usr/sbin/hostapd"),
                runtime_dir: runtime_dir.to_path_buf(),
                restart_backoff_seconds: 1,
            },
            wifi_client: Default::default(),
            vpn: VpnConfig {
                enabled: false,
                wireguard_config_dir: state_dir.join("vpn/wireguard"),
                policy: Default::default(),
            },
            security: SecurityConfig {
                rollback_timeout_seconds: 60,
            },
            api: Default::default(),
            auth: Default::default(),
        }
    }

    async fn test_supervisor(
        state_dir: &Path,
        runtime_dir: &Path,
        process: Arc<FakeProcess>,
    ) -> HostapdSupervisor {
        tokio::fs::create_dir_all(runtime_dir)
            .await
            .expect("create runtime dir");
        let inner = Inner {
            hostapd_binary: PathBuf::from("/usr/sbin/hostapd"),
            runtime_dir: runtime_dir.to_path_buf(),
            passphrase_store: PassphraseStore::new(state_dir.join("wifi/psk")),
            records_dir: state_dir.join("wifi"),
            restart_backoff_seconds: 1,
            ctrl_timeout: Duration::from_millis(500),
            process,
            tasks: Mutex::new(HashMap::new()),
            operation_lock: Mutex::new(()),
        };
        HostapdSupervisor {
            inner: Arc::new(inner),
        }
    }

    #[tokio::test]
    async fn effective_specs_derives_one_spec_per_access_point_interface() {
        let temp = tempdir().expect("tempdir");
        let mut config = app_config(temp.path(), &temp.path().join("hostapd"));
        config.network.interfaces.insert(
            "wlan0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Output,
                managed: true,
                ipv4: Some("192.168.101.1/24".parse().unwrap()),
                dhcp: None,
                dhcp_client: None,
                wifi: Some(ap_config("net-a")),
                wifi_client: None,
                nat: true,
            },
        );
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
                nat: true,
            },
        );

        let specs = HostapdSupervisor::effective_specs(&config).expect("effective specs");
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].interface, "wlan0");
        assert_eq!(specs[0].ssid, "net-a");
    }

    #[tokio::test]
    async fn configure_spawns_hostapd_and_persists_a_record() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = fake_process();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;

        supervisor
            .configure(spec("wlan0", "net-a"))
            .await
            .expect("configure");

        assert_eq!(
            process.calls(),
            vec![FakeCall::Spawn(render::config_path(&runtime_dir, "wlan0"))]
        );
        let status = supervisor.status("wlan0").await.expect("status");
        assert_eq!(status.hostapd_state, HostapdState::Enabled);

        let record = WifiRecordStore::for_access_point(temp.path().join("wifi"), "wlan0")
            .load()
            .await
            .expect("load")
            .expect("present");
        assert_eq!(record.ssid, "net-a");
        assert_eq!(record.pid, 1000);
    }

    #[tokio::test]
    async fn readiness_failure_stops_the_spawned_hostapd_without_recording_it() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = fake_process();
        process
            .suppress_spawn_responder
            .store(true, Ordering::Relaxed);
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;

        let error = supervisor
            .configure(spec("wlan0", "net-a"))
            .await
            .expect_err("readiness must time out");

        assert!(matches!(error, SupervisorError::StartupTimeout { .. }));
        assert_eq!(
            process.calls(),
            vec![
                FakeCall::Spawn(render::config_path(&runtime_dir, "wlan0")),
                FakeCall::Terminate(1000),
            ]
        );
        assert!(supervisor
            .record_store("wlan0")
            .load()
            .await
            .expect("load")
            .is_none());
        assert!(supervisor.status("wlan0").await.is_none());
    }

    #[tokio::test]
    async fn configuring_the_same_spec_twice_is_a_no_op() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = fake_process();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;

        supervisor
            .configure(spec("wlan0", "net-a"))
            .await
            .expect("configure once");
        supervisor
            .configure(spec("wlan0", "net-a"))
            .await
            .expect("configure again");

        assert_eq!(
            process.calls().len(),
            1,
            "second configure must not respawn"
        );
    }

    #[tokio::test]
    async fn configure_after_a_failed_startup_spawns_instead_of_reloading() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = fake_process();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;
        let spec = spec("wlan0", "net-a");

        supervisor
            .record_failed_startup(&spec, "interface busy with a foreign manager")
            .await;

        supervisor
            .configure(spec.clone())
            .await
            .expect("recovering from a failed startup must spawn hostapd, not reload it");

        assert_eq!(
            process.calls().len(),
            1,
            "the placeholder task has no real process to reload; configure must spawn fresh"
        );
    }

    #[tokio::test]
    async fn an_ssid_only_change_reloads_instead_of_restarting() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = fake_process();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;

        supervisor
            .configure(spec("wlan0", "net-a"))
            .await
            .expect("configure once");
        supervisor
            .configure(spec("wlan0", "net-b"))
            .await
            .expect("configure with new ssid");

        assert_eq!(
            process.calls().len(),
            1,
            "an SSID change must reload, not restart"
        );
        let status = supervisor.status("wlan0").await.expect("status");
        assert_eq!(status.spec.ssid, "net-b");

        assert_eq!(status.hostapd_state, HostapdState::Enabled);
    }

    #[tokio::test]
    async fn a_channel_change_restarts_hostapd() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = fake_process();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;

        supervisor
            .configure(spec("wlan0", "net-a"))
            .await
            .expect("configure once");

        let mut changed = spec("wlan0", "net-a");
        changed.channel = 11;
        supervisor
            .configure(changed)
            .await
            .expect("configure with new channel");

        assert_eq!(
            process.calls(),
            vec![
                FakeCall::Spawn(render::config_path(&runtime_dir, "wlan0")),
                FakeCall::Terminate(1000),
                FakeCall::Spawn(render::config_path(&runtime_dir, "wlan0")),
            ],
            "a channel change must terminate the old process, then spawn a new one"
        );
    }


    #[tokio::test]
    async fn unchanged_ap_with_unresponsive_ctrl_socket_is_restarted() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = fake_process();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;
        let original = spec("wlan0", "net-a");

        supervisor
            .configure(original.clone())
            .await
            .expect("configure original");
        let config_path = render::config_path(&runtime_dir, "wlan0");
        process.kill_externally(1000);
        process.seed(
            1000,
            config_path.clone(),
            FakeHostapdCtrl::spawn_silent(supervisor.ctrl_path("wlan0")),
        );

        supervisor
            .configure(original)
            .await
            .expect("unresponsive control socket must trigger restart");

        assert_eq!(process.spawn_count(), 2);
        assert!(process
            .calls()
            .iter()
            .any(|call| matches!(call, FakeCall::Terminate(1000))));
    }

    #[tokio::test]
    async fn failed_restart_can_be_rolled_back_to_the_previous_ap() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = fake_process();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;
        let original = spec("wlan0", "net-a");

        supervisor
            .configure(original.clone())
            .await
            .expect("configure original");

        process.fail_spawn.store(true, Ordering::Relaxed);
        let mut changed = original.clone();
        changed.channel = 11;
        supervisor
            .configure(changed)
            .await
            .expect_err("replacement spawn must fail");

        process.fail_spawn.store(false, Ordering::Relaxed);
        supervisor
            .configure(original.clone())
            .await
            .expect("rollback must respawn original");

        assert_eq!(supervisor.status("wlan0").await.expect("status").spec, original);
        assert_eq!(process.spawn_count(), 3);
    }

    #[tokio::test]
    async fn adopts_a_process_that_passes_the_two_factor_check() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = fake_process();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;

        let target = spec("wlan0", "net-a");
        let rendered = supervisor.render_for(&target).await.expect("render");

        seed_process(&process, 4242, rendered.path.clone(), "net-a");
        supervisor
            .record_store("wlan0")
            .save(&PersistedWifiRecord {
                pid: 4242,
                started_at_unix: 0,
                ctrl_path: supervisor.ctrl_path("wlan0"),
                config_path: rendered.path.clone(),
                config_digest: rendered.config_digest,
                key_digest: rendered.key_digest,
                ssid: "net-a".to_string(),
            })
            .await
            .expect("seed record");

        supervisor.configure(target).await.expect("configure");

        assert!(
            process.calls().is_empty(),
            "adopting a matching record must not spawn or restart anything"
        );
        let status = supervisor.status("wlan0").await.expect("status");
        assert_eq!(status.pid, 4242);
    }

    #[tokio::test]
    async fn refuses_a_live_ctrl_socket_with_no_matching_record() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = fake_process();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;

        let _foreign =
            FakeHostapdCtrl::spawn_fixed(supervisor.ctrl_path("wlan0"), "unrelated-network");

        let error = supervisor
            .configure(spec("wlan0", "net-a"))
            .await
            .expect_err("must refuse a foreign occupant");
        assert!(matches!(error, SupervisorError::NotOwned { .. }));
        assert!(
            process.calls().is_empty(),
            "a refusal must never spawn or signal anything"
        );
    }

    #[tokio::test]
    async fn a_digest_mismatch_restarts_with_the_new_config() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = fake_process();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;

        let target = spec("wlan0", "net-a");
        let rendered = supervisor.render_for(&target).await.expect("render");

        seed_process(&process, 4242, rendered.path.clone(), "net-a");
        supervisor
            .record_store("wlan0")
            .save(&PersistedWifiRecord {
                pid: 4242,
                started_at_unix: 0,
                ctrl_path: supervisor.ctrl_path("wlan0"),
                config_path: rendered.path.clone(),
                config_digest: WifiDigest::from_bytes([9; 32]),
                key_digest: rendered.key_digest,
                ssid: "net-a".to_string(),
            })
            .await
            .expect("seed stale record");

        supervisor.configure(target).await.expect("configure");

        assert_eq!(
            process.calls(),
            vec![
                FakeCall::Terminate(4242),
                FakeCall::Spawn(render::config_path(&runtime_dir, "wlan0")),
            ]
        );
    }

    #[tokio::test]
    async fn absent_ctrl_socket_clears_any_stale_record_and_spawns_fresh() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = fake_process();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;

        supervisor
            .record_store("wlan0")
            .save(&PersistedWifiRecord {
                pid: 9999,
                started_at_unix: 0,
                ctrl_path: supervisor.ctrl_path("wlan0"),
                config_path: render::config_path(&runtime_dir, "wlan0"),
                config_digest: WifiDigest::from_bytes([1; 32]),
                key_digest: WifiDigest::from_bytes([2; 32]),
                ssid: "net-a".to_string(),
            })
            .await
            .expect("seed stale record");

        supervisor
            .configure(spec("wlan0", "net-a"))
            .await
            .expect("configure");

        assert_eq!(
            process.calls(),
            vec![FakeCall::Spawn(render::config_path(&runtime_dir, "wlan0"))]
        );
        assert_eq!(
            WifiRecordStore::for_access_point(temp.path().join("wifi"), "wlan0")
                .load()
                .await
                .expect("load")
                .expect("present")
                .pid,
            1000
        );
    }

    #[tokio::test]
    async fn disable_stops_hostapd_and_forgets_the_interface() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = fake_process();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;
        supervisor
            .configure(spec("wlan0", "net-a"))
            .await
            .expect("configure");

        let disabled = supervisor.disable("wlan0").await.expect("disable");
        assert_eq!(disabled.map(|spec| spec.ssid), Some("net-a".to_string()));
        assert!(supervisor.status("wlan0").await.is_none());
        assert_eq!(process.calls().last(), Some(&FakeCall::Terminate(1000)));
        assert_eq!(
            WifiRecordStore::for_access_point(temp.path().join("wifi"), "wlan0")
                .load()
                .await
                .expect("load"),
            None
        );
    }

    #[tokio::test]
    async fn disable_on_an_unconfigured_interface_is_none_not_an_error() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = fake_process();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process).await;
        assert_eq!(supervisor.disable("wlan0").await.expect("disable"), None);
    }

    #[tokio::test]
    async fn ensure_alive_respawns_a_dead_hostapd_and_backs_off_on_repeated_failure() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = fake_process();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;
        supervisor
            .configure(spec("wlan0", "net-a"))
            .await
            .expect("configure");

        process.kill_externally(1000);
        process.fail_spawn.store(true, Ordering::Relaxed);

        let restarted = supervisor.ensure_alive().await.expect("ensure_alive");
        assert!(restarted, "a dead hostapd must trigger a respawn attempt");
        assert_eq!(
            process.calls().last(),
            Some(&FakeCall::Spawn(render::config_path(&runtime_dir, "wlan0")))
        );

        let calls_before = process.calls().len();
        let restarted_again = supervisor.ensure_alive().await.expect("ensure_alive again");
        assert!(!restarted_again, "backoff must suppress an immediate retry");
        assert_eq!(
            process.calls().len(),
            calls_before,
            "a suppressed retry must not call spawn again"
        );
    }

    #[tokio::test]
    async fn ensure_alive_refuses_respawn_when_the_old_ctrl_socket_still_answers() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = fake_process();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;
        supervisor
            .configure(spec("wlan0", "net-a"))
            .await
            .expect("configure");
        let original_record = supervisor
            .record_store("wlan0")
            .load()
            .await
            .expect("load")
            .expect("record");
        process.persistent_responder.store(true, Ordering::Relaxed);

        let error = supervisor
            .ensure_alive()
            .await
            .expect_err("persistent ctrl responder must be refused");

        assert!(matches!(error, SupervisorError::NotOwned { .. }));
        assert_eq!(
            process.calls(),
            vec![FakeCall::Spawn(render::config_path(&runtime_dir, "wlan0"))],
            "ownership refusal must not signal an already-dead PID or spawn a replacement"
        );
        assert_eq!(
            supervisor
                .record_store("wlan0")
                .load()
                .await
                .expect("load")
                .expect("record"),
            original_record,
            "ownership refusal must not overwrite the existing record"
        );
    }

    #[tokio::test]
    async fn ensure_alive_leaves_a_healthy_access_point_untouched() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = fake_process();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;
        supervisor
            .configure(spec("wlan0", "net-a"))
            .await
            .expect("configure");

        let restarted = supervisor.ensure_alive().await.expect("ensure_alive");
        assert!(!restarted, "a healthy hostapd must not be touched");
        assert_eq!(process.calls().len(), 1, "only the original spawn call");
    }

    #[tokio::test]
    async fn set_passphrase_then_reconfigure_takes_the_reload_path() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = fake_process();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;
        let mut secured = spec("wlan0", "net-a");
        secured.security = WifiSecurity::Wpa2;

        let first_passphrase =
            crate::wifi::secret::WifiPassphrase::new("first passphrase").expect("valid");
        supervisor
            .set_passphrase("wlan0", &first_passphrase)
            .await
            .expect("set_passphrase");
        supervisor
            .configure(secured.clone())
            .await
            .expect("configure");
        assert_eq!(process.calls().len(), 1);

        let second_passphrase =
            crate::wifi::secret::WifiPassphrase::new("second passphrase").expect("valid");
        supervisor
            .set_passphrase("wlan0", &second_passphrase)
            .await
            .expect("set_passphrase");
        assert_eq!(
            process.calls().len(),
            1,
            "storing a passphrase must not restart hostapd"
        );

        supervisor
            .configure(secured)
            .await
            .expect("configure again");
        assert_eq!(
            process.calls().len(),
            1,
            "a passphrase-only change must reload rather than restart"
        );
    }

    #[tokio::test]
    async fn reload_sends_reload_even_when_nothing_changed() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = fake_process();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;
        supervisor
            .configure(spec("wlan0", "net-a"))
            .await
            .expect("configure");

        let spec = supervisor.reload("wlan0").await.expect("reload");
        assert_eq!(spec.ssid, "net-a");
    }

    #[tokio::test]
    async fn reload_on_an_unconfigured_interface_is_not_configured() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = fake_process();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process).await;

        let error = supervisor.reload("wlan0").await.unwrap_err();
        assert!(matches!(error, SupervisorError::NotConfigured { .. }));
    }

    #[tokio::test]
    async fn deauthenticate_reaches_the_running_hostapd() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = fake_process();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process).await;
        supervisor
            .configure(spec("wlan0", "net-a"))
            .await
            .expect("configure");

        let mac = MacAddr::new([0x02, 0, 0, 0, 0, 1]);
        supervisor
            .deauthenticate("wlan0", mac)
            .await
            .expect("deauthenticate");
    }

    #[tokio::test]
    async fn deauthenticate_on_an_unconfigured_interface_is_not_configured() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = fake_process();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process).await;

        let mac = MacAddr::new([0x02, 0, 0, 0, 0, 1]);
        let error = supervisor.deauthenticate("wlan0", mac).await.unwrap_err();
        assert!(matches!(error, SupervisorError::NotConfigured { .. }));
    }

    #[tokio::test]
    async fn shutdown_with_preserve_interfaces_leaves_hostapd_and_its_record_alone() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = fake_process();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;
        supervisor
            .configure(spec("wlan0", "net-a"))
            .await
            .expect("configure");

        supervisor
            .shutdown(ShutdownPolicy::PreserveInterfaces)
            .await;

        assert!(
            process
                .calls()
                .iter()
                .all(|call| !matches!(call, FakeCall::Terminate(_) | FakeCall::Kill(_))),
            "PreserveInterfaces must never signal hostapd"
        );
        assert!(
            WifiRecordStore::for_access_point(temp.path().join("wifi"), "wlan0")
                .load()
                .await
                .expect("load")
                .is_some(),
            "the record must survive so the next start can adopt it"
        );
    }

    #[tokio::test]
    async fn shutdown_with_restore_interfaces_stops_hostapd_and_clears_its_record() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = fake_process();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;
        supervisor
            .configure(spec("wlan0", "net-a"))
            .await
            .expect("configure");

        supervisor.shutdown(ShutdownPolicy::RestoreInterfaces).await;

        assert_eq!(process.calls().last(), Some(&FakeCall::Terminate(1000)));
        assert_eq!(
            WifiRecordStore::for_access_point(temp.path().join("wifi"), "wlan0")
                .load()
                .await
                .expect("load"),
            None
        );
    }

    #[test]
    fn backoff_doubles_up_to_the_five_minute_ceiling() {
        assert_eq!(crate::wifi::lifecycle::backoff_duration(5, 1), Duration::from_secs(5));
        assert_eq!(crate::wifi::lifecycle::backoff_duration(5, 2), Duration::from_secs(10));
        assert_eq!(crate::wifi::lifecycle::backoff_duration(5, 3), Duration::from_secs(20));
        assert_eq!(
            crate::wifi::lifecycle::backoff_duration(5, 20),
            crate::wifi::lifecycle::BACKOFF_CEILING
        );
    }

    #[test]
    fn restart_classification_matches_the_documented_reload_safe_set() {
        let base = spec("wlan0", "net-a");

        let mut ssid_only = base.clone();
        ssid_only.ssid = "net-b".to_string();
        assert!(!requires_restart(&base, &ssid_only));

        let mut hidden_only = base.clone();
        hidden_only.hidden = true;
        assert!(!requires_restart(&base, &hidden_only));

        let mut isolation_only = base.clone();
        isolation_only.client_isolation = true;
        assert!(!requires_restart(&base, &isolation_only));

        let mut channel_only = base.clone();
        channel_only.channel = 11;
        assert!(requires_restart(&base, &channel_only));

        let mut band_only = base.clone();
        band_only.band = WifiBand::Ghz5;
        assert!(requires_restart(&base, &band_only));

        let mut width_only = base.clone();
        width_only.channel_width = WifiChannelWidth::Ht40;
        assert!(requires_restart(&base, &width_only));

        let mut country_only = base.clone();
        country_only.country_code = Some("DE".to_string());
        assert!(requires_restart(&base, &country_only));

        let mut security_only = base.clone();
        security_only.security = WifiSecurity::Wpa2;
        assert!(requires_restart(&base, &security_only));
    }
}
