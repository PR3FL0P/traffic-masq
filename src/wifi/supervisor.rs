use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use thiserror::Error;
use tokio::sync::Mutex;

use crate::atomic_file::{self, PRIVATE_FILE_MODE};
use crate::config::{AppConfig, ShutdownPolicy};
use crate::dhcp::supervisor::resolve_interface_index;
use crate::wifi::ctrl::{CtrlError, HostapdCtrlClient, HostapdState, MacAddr, Station};
use crate::wifi::process::{ProcessError, SupervisedProcess, TokioSupervisedProcess};
use crate::wifi::record::{PersistedWifiRecord, WifiRecordError, WifiRecordStore};
use crate::wifi::render::{
    self, render_hostapd_config, ApRenderInput, RenderError, RenderedApConfig,
};
use crate::wifi::secret::WifiPassphrase;
use crate::wifi::store::{resolve_passphrase, PassphraseStore, ResolvePassphraseError};
use crate::wifi::WifiApSpec;

const DEFAULT_CTRL_TIMEOUT: Duration = Duration::from_secs(2);

const STARTUP_READY_TIMEOUT: Duration = Duration::from_secs(3);
const STARTUP_POLL_INTERVAL: Duration = Duration::from_millis(20);

const GRACEFUL_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const GRACEFUL_STOP_POLL_INTERVAL: Duration = Duration::from_millis(50);

const BACKOFF_CEILING: Duration = Duration::from_secs(300);

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

#[derive(Debug, Clone)]
struct ApTask {
    spec: WifiApSpec,
    record: PersistedWifiRecord,
    consecutive_failures: u32,
    next_restart_earliest: Option<Instant>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WifiApStatus {
    pub interface: String,
    pub spec: WifiApSpec,
    pub pid: u32,
    pub hostapd_state: HostapdState,
    pub num_stations: Option<u32>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum OwnershipOutcome {
    Absent,

    ForeignPresent,

    Adopted(PersistedWifiRecord),

    DigestMismatch(PersistedWifiRecord),
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

            supervisor.configure(spec).await?;
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
            Some(task)
                if task.record.config_digest == rendered.config_digest
                    && task.record.key_digest == rendered.key_digest =>
            {
                task
            }
            Some(mut task) => {
                if requires_restart(&task.spec, &spec) {
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
        task.consecutive_failures = 0;
        task.next_restart_earliest = None;
        Ok(())
    }

    async fn restart_task(
        &self,
        task: &mut ApTask,
        spec: &WifiApSpec,
        rendered: &RenderedApConfig,
        ctrl_path: &Path,
    ) -> Result<(), SupervisorError> {
        self.graceful_stop(task.record.pid).await;
        let record = self.spawn_and_record(spec, rendered, ctrl_path).await?;
        task.spec = spec.clone();
        task.record = record;
        task.consecutive_failures = 0;
        task.next_restart_earliest = None;
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
            OwnershipOutcome::DigestMismatch(record) => {
                self.graceful_stop(record.pid).await;
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
            consecutive_failures: 0,
            next_restart_earliest: None,
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
        let Some(status) = status else {
            let _ = store.clear().await;
            return Ok(OwnershipOutcome::Absent);
        };

        let Some(record) = store.load().await? else {
            return Ok(OwnershipOutcome::ForeignPresent);
        };

        let process_factor = self
            .inner
            .process
            .cmdline_contains(record.pid, &record.config_path)
            .await
            .unwrap_or(false);
        let ctrl_factor = status.state == HostapdState::Enabled
            && status.ssid.as_deref() == Some(record.ssid.as_str());

        if !process_factor || !ctrl_factor {
            return Ok(OwnershipOutcome::ForeignPresent);
        }

        if record.config_digest == rendered.config_digest
            && record.key_digest == rendered.key_digest
        {
            Ok(OwnershipOutcome::Adopted(record))
        } else {
            Ok(OwnershipOutcome::DigestMismatch(record))
        }
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

            let record = PersistedWifiRecord {
                pid,
                started_at_unix: unix_now(),
                ctrl_path: ctrl_path.to_path_buf(),
                config_path: rendered.path.clone(),
                config_digest: rendered.config_digest,
                key_digest: rendered.key_digest,
                ssid: spec.ssid.clone(),
            };
            self.record_store(&spec.interface).save(&record).await?;
            Ok(record)
        }
        .await;

        if result.is_err() {
            self.graceful_stop(pid).await;
        }

        result
    }

    async fn graceful_stop(&self, pid: u32) {
        if let Err(error) = self.inner.process.terminate(pid).await {
            tracing::warn!(pid, %error, "failed to send SIGTERM to hostapd");
        }

        let deadline = Instant::now() + GRACEFUL_STOP_TIMEOUT;
        loop {
            match self.inner.process.is_alive(pid).await {
                Ok(false) | Err(_) => return,
                Ok(true) if Instant::now() >= deadline => break,
                Ok(true) => tokio::time::sleep(GRACEFUL_STOP_POLL_INTERVAL).await,
            }
        }

        tracing::warn!(pid, "hostapd did not exit after SIGTERM; sending SIGKILL");
        let _ = self.inner.process.kill(pid).await;
    }

    pub async fn disable(&self, interface: &str) -> Result<Option<WifiApSpec>, SupervisorError> {
        let _operation = self.inner.operation_lock.lock().await;
        let Some(task) = self.inner.tasks.lock().await.remove(interface) else {
            return Ok(None);
        };

        self.graceful_stop(task.record.pid).await;
        let _ = self.record_store(interface).clear().await;
        let _ =
            tokio::fs::remove_file(render::config_path(&self.inner.runtime_dir, interface)).await;
        Ok(Some(task.spec))
    }

    /// Check that the configured hostapd binary is runnable.
    ///
    /// Lives on the supervisor rather than at startup because the supervisor is
    /// now built unconditionally: an access point can be configured at runtime
    /// on a daemon that started with `wifi.enabled = false`, and that path needs
    /// the same clear diagnosis of a missing binary that startup gives.
    pub async fn preflight_binary(&self) -> Result<(), SupervisorError> {
        tokio::process::Command::new(&self.inner.hostapd_binary)
            .arg("-v")
            .output()
            .await
            .map_err(|error| {
                SupervisorError::Configuration(anyhow::anyhow!(
                    "hostapd binary {} is not runnable ({error}) — install hostapd or fix wifi.hostapd_binary",
                    self.inner.hostapd_binary.display()
                ))
            })?;
        Ok(())
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

        Some(WifiApStatus {
            interface: interface.to_string(),
            pid: task.record.pid,
            spec: task.spec,
            hostapd_state,
            num_stations,
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

        if let Some(earliest) = task.next_restart_earliest {
            if Instant::now() < earliest {
                return Ok(false);
            }
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
            if task.consecutive_failures != 0 {
                task.consecutive_failures = 0;
                task.next_restart_earliest = None;
                self.inner
                    .tasks
                    .lock()
                    .await
                    .insert(interface.to_string(), task);
            }
            return Ok(false);
        }

        tracing::warn!(
            %interface,
            pid = task.record.pid,
            "hostapd is not responding; restarting it"
        );
        let rendered = self.render_for(&task.spec).await?;

        self.graceful_stop(task.record.pid).await;

        if let Ok(client) = HostapdCtrlClient::connect(&ctrl_path, self.inner.ctrl_timeout).await {
            if client.ping().await.is_ok() {
                return Err(SupervisorError::NotOwned {
                    interface: interface.to_string(),
                });
            }
        }

        task.consecutive_failures += 1;
        match self
            .spawn_and_record(&task.spec, &rendered, &ctrl_path)
            .await
        {
            Ok(record) => {
                task.record = record;
                task.next_restart_earliest = None;
            }
            Err(error) => {
                tracing::error!(%interface, %error, "failed to respawn hostapd");
                task.next_restart_earliest = Some(
                    Instant::now()
                        + backoff_duration(
                            self.inner.restart_backoff_seconds,
                            task.consecutive_failures,
                        ),
                );
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
                self.graceful_stop(task.record.pid).await;
                let _ = self.record_store(&interface).clear().await;
                let _ = tokio::fs::remove_file(render::config_path(
                    &self.inner.runtime_dir,
                    &interface,
                ))
                .await;
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

fn backoff_duration(base_seconds: u64, consecutive_failures: u32) -> Duration {
    let multiplier = 1u64.checked_shl(consecutive_failures.saturating_sub(1));
    let seconds = multiplier
        .and_then(|multiplier| base_seconds.checked_mul(multiplier))
        .unwrap_or(u64::MAX);
    Duration::from_secs(seconds).min(BACKOFF_CEILING)
}

async fn write_config_file(rendered: &RenderedApConfig) -> Result<(), SupervisorError> {
    if let Some(parent) = rendered.path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|source| io_error(&rendered.path, source))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                .await
                .map_err(|source| io_error(&rendered.path, source))?;
        }
    }
    let mut content = rendered.text.clone().into_bytes();
    content.push(b'\n');
    atomic_file::replace_async(&rendered.path, &content, PRIVATE_FILE_MODE)
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
    let deadline = Instant::now() + STARTUP_READY_TIMEOUT.max(timeout);
    loop {
        if let Ok(client) = HostapdCtrlClient::connect(ctrl_path, timeout).await {
            if client.ping().await.is_ok() {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err(SupervisorError::StartupTimeout {
                interface: interface.to_string(),
                timeout: STARTUP_READY_TIMEOUT.max(timeout),
            });
        }
        tokio::time::sleep(STARTUP_POLL_INTERVAL).await;
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) use crate::netlink::interface_is_wireless;

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixDatagram as StdUnixDatagram;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Mutex as StdMutex;

    use tempfile::tempdir;

    use super::*;
    use crate::config::{
        DhcpConfig, InterfaceConfig, InterfaceRole, NetworkConfig, RouterConfig, RuntimeConfig,
        SecurityConfig, ShutdownPolicy as ConfigShutdownPolicy, VpnConfig, WifiApConfig, WifiBand,
        WifiChannelWidth, WifiConfig, WifiSecurity,
    };
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

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum FakeCall {
        Spawn(PathBuf),
        Terminate(u32),
        Kill(u32),
    }

    #[derive(Default)]
    struct FakeProcess {
        configs: StdMutex<HashMap<u32, PathBuf>>,
        responders: StdMutex<HashMap<u32, FakeHostapdCtrl>>,
        calls: StdMutex<Vec<FakeCall>>,
        next_pid: AtomicU32,
        fail_spawn: AtomicBool,
        suppress_spawn_responder: AtomicBool,
        persistent_responder: AtomicBool,
    }

    impl FakeProcess {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                next_pid: AtomicU32::new(1000),
                ..Default::default()
            })
        }

        fn calls(&self) -> Vec<FakeCall> {
            self.calls.lock().unwrap().clone()
        }

        fn seed(&self, pid: u32, config_path: PathBuf, ssid: &str) {
            let ctrl_path = config_path.with_extension("");
            let responder = FakeHostapdCtrl::spawn_fixed(ctrl_path, ssid);
            self.configs.lock().unwrap().insert(pid, config_path);
            self.responders.lock().unwrap().insert(pid, responder);
        }

        fn kill_externally(&self, pid: u32) {
            self.responders.lock().unwrap().remove(&pid);
            self.configs.lock().unwrap().remove(&pid);
        }
    }

    #[async_trait::async_trait]
    impl SupervisedProcess for FakeProcess {
        async fn spawn(&self, _binary: &Path, config_path: &Path) -> Result<u32, ProcessError> {
            self.calls
                .lock()
                .unwrap()
                .push(FakeCall::Spawn(config_path.to_path_buf()));
            if self.fail_spawn.load(Ordering::Relaxed) {
                return Err(ProcessError::Spawn {
                    binary: PathBuf::from("hostapd"),
                    source: std::io::Error::other("fake spawn failure"),
                });
            }
            let pid = self.next_pid.fetch_add(1, Ordering::Relaxed);
            if !self.suppress_spawn_responder.load(Ordering::Relaxed) {
                let ctrl_path = config_path.with_extension("");
                let responder =
                    FakeHostapdCtrl::spawn_for_config(ctrl_path, config_path.to_path_buf());
                self.responders.lock().unwrap().insert(pid, responder);
            }
            self.configs
                .lock()
                .unwrap()
                .insert(pid, config_path.to_path_buf());
            Ok(pid)
        }

        async fn is_alive(&self, pid: u32) -> Result<bool, ProcessError> {
            Ok(!self.persistent_responder.load(Ordering::Relaxed)
                && self.responders.lock().unwrap().contains_key(&pid))
        }

        async fn cmdline_contains(
            &self,
            pid: u32,
            config_path: &Path,
        ) -> Result<bool, ProcessError> {
            Ok(self
                .configs
                .lock()
                .unwrap()
                .get(&pid)
                .is_some_and(|recorded| recorded == config_path))
        }

        async fn terminate(&self, pid: u32) -> Result<(), ProcessError> {
            self.calls.lock().unwrap().push(FakeCall::Terminate(pid));
            if !self.persistent_responder.load(Ordering::Relaxed) {
                self.responders.lock().unwrap().remove(&pid);
                self.configs.lock().unwrap().remove(&pid);
            }
            Ok(())
        }

        async fn kill(&self, pid: u32) -> Result<(), ProcessError> {
            self.calls.lock().unwrap().push(FakeCall::Kill(pid));
            self.responders.lock().unwrap().remove(&pid);
            self.configs.lock().unwrap().remove(&pid);
            Ok(())
        }
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
        let process = FakeProcess::new();
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
        let process = FakeProcess::new();
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
        let process = FakeProcess::new();
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
    async fn an_ssid_only_change_reloads_instead_of_restarting() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = FakeProcess::new();
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
        let process = FakeProcess::new();
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
    async fn adopts_a_process_that_passes_the_two_factor_check() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = FakeProcess::new();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;

        let target = spec("wlan0", "net-a");
        let rendered = supervisor.render_for(&target).await.expect("render");

        process.seed(4242, rendered.path.clone(), "net-a");
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
        let process = FakeProcess::new();
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
        let process = FakeProcess::new();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;

        let target = spec("wlan0", "net-a");
        let rendered = supervisor.render_for(&target).await.expect("render");

        process.seed(4242, rendered.path.clone(), "net-a");
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
        let process = FakeProcess::new();
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
        let process = FakeProcess::new();
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
        let process = FakeProcess::new();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process).await;
        assert_eq!(supervisor.disable("wlan0").await.expect("disable"), None);
    }

    #[tokio::test]
    async fn ensure_alive_respawns_a_dead_hostapd_and_backs_off_on_repeated_failure() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = FakeProcess::new();
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
        let process = FakeProcess::new();
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
            vec![
                FakeCall::Spawn(render::config_path(&runtime_dir, "wlan0")),
                FakeCall::Terminate(1000),
            ],
            "ownership refusal must not spawn a replacement"
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
        let process = FakeProcess::new();
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
        let process = FakeProcess::new();
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
        let process = FakeProcess::new();
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
        let process = FakeProcess::new();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process).await;

        let error = supervisor.reload("wlan0").await.unwrap_err();
        assert!(matches!(error, SupervisorError::NotConfigured { .. }));
    }

    #[tokio::test]
    async fn deauthenticate_reaches_the_running_hostapd() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = FakeProcess::new();
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
        let process = FakeProcess::new();
        let supervisor = test_supervisor(temp.path(), &runtime_dir, process).await;

        let mac = MacAddr::new([0x02, 0, 0, 0, 0, 1]);
        let error = supervisor.deauthenticate("wlan0", mac).await.unwrap_err();
        assert!(matches!(error, SupervisorError::NotConfigured { .. }));
    }

    #[tokio::test]
    async fn shutdown_with_preserve_interfaces_leaves_hostapd_and_its_record_alone() {
        let temp = tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("hostapd");
        let process = FakeProcess::new();
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
        let process = FakeProcess::new();
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
        assert_eq!(backoff_duration(5, 1), Duration::from_secs(5));
        assert_eq!(backoff_duration(5, 2), Duration::from_secs(10));
        assert_eq!(backoff_duration(5, 3), Duration::from_secs(20));
        assert_eq!(backoff_duration(5, 20), BACKOFF_CEILING);
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
