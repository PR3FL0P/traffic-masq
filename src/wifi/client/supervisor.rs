use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use thiserror::Error;
use tokio::sync::Mutex;

use crate::atomic_file::{self, PRIVATE_FILE_MODE};
use crate::config::{AppConfig, ShutdownPolicy};
use crate::dhcp::supervisor::resolve_interface_index;
use crate::wifi::client::ctrl::{
    CtrlError, WpaState, WpaSupplicantCtrlClient, WpaSupplicantEvent, WpaSupplicantEventClient,
    WpaSupplicantScanResult,
};
use crate::wifi::client::render::{
    config_path, render_wpa_supplicant_config, ClientRenderError, ClientRenderInput,
    RenderedClientConfig,
};
use crate::wifi::process::{ProcessError, SupervisedProcess, TokioSupervisedProcess};
use crate::wifi::record::{PersistedWifiRecord, WifiRecordError, WifiRecordStore};
use crate::wifi::secret::WifiPassphrase;
use crate::wifi::store::{resolve_passphrase_parts, PassphraseStore, ResolvePassphraseError};
use crate::wifi::supervisor::interface_is_wireless;
use crate::wifi::WifiClientSpec;

const DEFAULT_CTRL_TIMEOUT: Duration = Duration::from_secs(2);

const STARTUP_READY_TIMEOUT: Duration = Duration::from_secs(3);
const STARTUP_POLL_INTERVAL: Duration = Duration::from_millis(20);

const GRACEFUL_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const GRACEFUL_STOP_POLL_INTERVAL: Duration = Duration::from_millis(50);

const BACKOFF_CEILING: Duration = Duration::from_secs(300);

const ASSOCIATION_GRACE: Duration = Duration::from_secs(90);

const SCAN_TIMEOUT: Duration = Duration::from_secs(15);

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
    Ctrl(#[from] CtrlError),

    #[error(transparent)]
    Configuration(#[from] anyhow::Error),
}

#[derive(Debug, Clone)]
struct ClientTask {
    spec: WifiClientSpec,
    record: PersistedWifiRecord,
    consecutive_failures: u32,
    next_restart_earliest: Option<Instant>,

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
}

#[derive(Clone)]
pub struct WifiClientSupervisor {
    inner: Arc<Inner>,
}

struct Inner {
    wpa_supplicant_binary: PathBuf,
    runtime_dir: PathBuf,
    records_dir: PathBuf,
    restart_backoff_seconds: u64,
    ctrl_timeout: Duration,
    process: Arc<dyn SupervisedProcess>,
    passphrase_store: PassphraseStore,
    tasks: Mutex<HashMap<String, ClientTask>>,
    operation_lock: Mutex<()>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OwnershipOutcome {
    Absent,
    ForeignPresent,
    Adopted(PersistedWifiRecord),
    DigestMismatch(PersistedWifiRecord),
}

impl WifiClientSupervisor {
    pub async fn start(config: &AppConfig) -> Result<Self, ClientSupervisorError> {
        Self::start_with_process(config, Arc::new(TokioSupervisedProcess::new())).await
    }

    pub async fn start_with_process(
        config: &AppConfig,
        process: Arc<dyn SupervisedProcess>,
    ) -> Result<Self, ClientSupervisorError> {
        let records_dir = config.runtime.state_dir.join("wifi");
        let supervisor = Self {
            inner: Arc::new(Inner {
                wpa_supplicant_binary: config.wifi_client.wpa_supplicant_binary.clone(),
                runtime_dir: config.wifi_client.runtime_dir.clone(),

                passphrase_store: PassphraseStore::new(records_dir.join("psk")),
                records_dir,
                restart_backoff_seconds: config.wifi_client.restart_backoff_seconds.max(1),
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

            supervisor.configure(spec).await?;
        }

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

    fn record_store(&self, interface: &str) -> WifiRecordStore {
        WifiRecordStore::for_client(&self.inner.records_dir, interface)
    }

    async fn render_for(
        &self,
        spec: &WifiClientSpec,
    ) -> Result<RenderedClientConfig, ClientSupervisorError> {
        let passphrase = resolve_passphrase_parts(
            &spec.interface,
            spec.passphrase_file.as_deref(),
            &self.inner.passphrase_store,
        )?;
        Ok(render_wpa_supplicant_config(ClientRenderInput {
            spec,
            ctrl_interface: &self.inner.runtime_dir,
            ctrl_interface_group: None,
            passphrase: passphrase.as_ref(),
        })?)
    }

    pub async fn configure(&self, spec: WifiClientSpec) -> Result<(), ClientSupervisorError> {
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
                self.restart_task(&mut task, &spec, &rendered, &ctrl_path)
                    .await?;
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

    async fn restart_task(
        &self,
        task: &mut ClientTask,
        spec: &WifiClientSpec,
        rendered: &RenderedClientConfig,
        ctrl_path: &Path,
    ) -> Result<(), ClientSupervisorError> {
        self.graceful_stop(task.record.pid).await;
        let record = self.spawn_and_record(spec, rendered, ctrl_path).await?;
        task.spec = spec.clone();
        task.record = record;
        task.consecutive_failures = 0;
        task.next_restart_earliest = None;
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
        let record = match outcome {
            OwnershipOutcome::Absent => self.spawn_and_record(spec, rendered, ctrl_path).await?,
            OwnershipOutcome::Adopted(record) => record,
            OwnershipOutcome::DigestMismatch(record) => {
                self.graceful_stop(record.pid).await;
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
            consecutive_failures: 0,
            next_restart_earliest: None,
            associated_or_started_at: Instant::now(),
        })
    }

    async fn observe_ownership(
        &self,
        spec: &WifiClientSpec,
        rendered: &RenderedClientConfig,
        ctrl_path: &Path,
    ) -> Result<OwnershipOutcome, ClientSupervisorError> {
        let store = self.record_store(&spec.interface);

        let status =
            match WpaSupplicantCtrlClient::connect(ctrl_path, self.inner.ctrl_timeout).await {
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

        let ctrl_factor = match status.ssid.as_deref() {
            Some(ssid) => ssid == record.ssid,
            None => true,
        };

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
        spec: &WifiClientSpec,
        rendered: &RenderedClientConfig,
        ctrl_path: &Path,
    ) -> Result<PersistedWifiRecord, ClientSupervisorError> {
        write_config_file(rendered).await?;
        let pid = self
            .inner
            .process
            .spawn_wifi_client(
                &self.inner.wpa_supplicant_binary,
                &spec.interface,
                &rendered.path,
            )
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
            tracing::warn!(pid, %error, "failed to send SIGTERM to wpa_supplicant");
        }

        let deadline = Instant::now() + GRACEFUL_STOP_TIMEOUT;
        loop {
            match self.inner.process.is_alive(pid).await {
                Ok(false) | Err(_) => return,
                Ok(true) if Instant::now() >= deadline => break,
                Ok(true) => tokio::time::sleep(GRACEFUL_STOP_POLL_INTERVAL).await,
            }
        }

        tracing::warn!(
            pid,
            "wpa_supplicant did not exit after SIGTERM; sending SIGKILL"
        );
        let _ = self.inner.process.kill(pid).await;
    }

    pub async fn disable(
        &self,
        interface: &str,
    ) -> Result<Option<WifiClientSpec>, ClientSupervisorError> {
        let _operation = self.inner.operation_lock.lock().await;
        let Some(task) = self.inner.tasks.lock().await.remove(interface) else {
            return Ok(None);
        };

        self.graceful_stop(task.record.pid).await;
        let _ = self.record_store(interface).clear().await;
        let _ = tokio::fs::remove_file(config_path(&self.inner.runtime_dir, interface)).await;
        Ok(Some(task.spec))
    }

    /// Check that the configured wpa_supplicant binary is runnable.
    ///
    /// See [`crate::wifi::HostapdSupervisor::preflight_binary`]: the supervisor
    /// is built unconditionally, so a client configured at runtime needs the
    /// same diagnosis of a missing binary that startup gives.
    pub async fn preflight_binary(&self) -> Result<(), ClientSupervisorError> {
        tokio::process::Command::new(&self.inner.wpa_supplicant_binary)
            .arg("-v")
            .output()
            .await
            .map_err(|error| {
                ClientSupervisorError::Configuration(anyhow::anyhow!(
                    "wpa_supplicant binary {} is not runnable ({error}) — install wpa_supplicant or fix wifi_client.wpa_supplicant_binary",
                    self.inner.wpa_supplicant_binary.display()
                ))
            })?;
        Ok(())
    }

    pub async fn status(&self, interface: &str) -> Option<WifiClientStatus> {
        let task = self.inner.tasks.lock().await.get(interface).cloned()?;
        let ctrl_path = self.ctrl_path(interface);

        let (wpa_state, bssid, freq) =
            match WpaSupplicantCtrlClient::connect(&ctrl_path, self.inner.ctrl_timeout).await {
                Ok(client) => match client.status().await {
                    Ok(status) => (status.wpa_state, status.bssid, status.freq),
                    Err(_) => (WpaState::Other("unreachable".to_string()), None, None),
                },
                Err(_) => (WpaState::Other("unreachable".to_string()), None, None),
            };

        Some(WifiClientStatus {
            interface: interface.to_string(),
            pid: task.record.pid,
            spec: task.spec,
            wpa_state,
            bssid,
            freq,
        })
    }

    pub async fn reconnect(&self, interface: &str) -> Result<(), ClientSupervisorError> {
        if !self.inner.tasks.lock().await.contains_key(interface) {
            return Err(ClientSupervisorError::NotConfigured {
                interface: interface.to_string(),
            });
        }
        let ctrl_path = self.ctrl_path(interface);
        let client = WpaSupplicantCtrlClient::connect(&ctrl_path, self.inner.ctrl_timeout).await?;
        client.reconnect().await?;
        Ok(())
    }

    pub async fn scan(
        &self,
        interface: &str,
    ) -> Result<Vec<WpaSupplicantScanResult>, ClientSupervisorError> {
        let _operation = self.inner.operation_lock.lock().await;
        if !self.inner.tasks.lock().await.contains_key(interface) {
            return Err(ClientSupervisorError::NotConfigured {
                interface: interface.to_string(),
            });
        }

        let ctrl_path = self.ctrl_path(interface);
        let (events, mut receiver) =
            WpaSupplicantEventClient::attach(&ctrl_path, self.inner.ctrl_timeout).await?;
        let client = WpaSupplicantCtrlClient::connect(&ctrl_path, self.inner.ctrl_timeout).await?;
        if let Err(error) = client.scan().await {
            events.close().await;
            return match error {
                CtrlError::Failed => Err(ClientSupervisorError::ScanBusy {
                    interface: interface.to_string(),
                }),
                error => Err(error.into()),
            };
        }

        let completed = tokio::time::timeout(SCAN_TIMEOUT, async {
            loop {
                match receiver.recv().await {
                    Ok(WpaSupplicantEvent::ScanResults) => return true,
                    Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return false,
                }
            }
        })
        .await
        .unwrap_or(false);
        events.close().await;

        if !completed {
            return Err(ClientSupervisorError::ScanTimeout {
                interface: interface.to_string(),
                timeout: SCAN_TIMEOUT,
            });
        }
        Ok(client.scan_results().await?)
    }

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

    pub async fn clear_passphrase(&self, interface: &str) -> Result<(), ClientSupervisorError> {
        self.inner
            .passphrase_store
            .clear(interface)
            .map_err(ResolvePassphraseError::from)
            .map_err(Into::into)
    }

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

    pub async fn ensure_alive(&self) -> Result<bool, ClientSupervisorError> {
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

    async fn ensure_interface_alive(&self, interface: &str) -> Result<bool, ClientSupervisorError> {
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
        let status = if process_alive {
            match WpaSupplicantCtrlClient::connect(&ctrl_path, self.inner.ctrl_timeout).await {
                Ok(client) => client.status().await.ok(),
                Err(_) => None,
            }
        } else {
            None
        };

        let stuck = match &status {
            Some(status) if status.wpa_state.is_connected() => {
                task.associated_or_started_at = Instant::now();
                false
            }
            Some(_) => task.associated_or_started_at.elapsed() > ASSOCIATION_GRACE,

            None => false,
        };

        if status.is_some() && !stuck {
            task.consecutive_failures = 0;
            task.next_restart_earliest = None;
            self.inner
                .tasks
                .lock()
                .await
                .insert(interface.to_string(), task);
            return Ok(false);
        }

        if stuck {
            tracing::warn!(
                %interface,
                pid = task.record.pid,
                grace = ?ASSOCIATION_GRACE,
                "wpa_supplicant is alive but has not associated; restarting it"
            );
        } else {
            tracing::warn!(
                %interface,
                pid = task.record.pid,
                "wpa_supplicant is not responding; restarting it"
            );
        }

        let rendered = self.render_for(&task.spec).await?;
        self.graceful_stop(task.record.pid).await;

        if let Ok(client) =
            WpaSupplicantCtrlClient::connect(&ctrl_path, self.inner.ctrl_timeout).await
        {
            if client.ping().await.is_ok() {
                return Err(ClientSupervisorError::NotOwned {
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
                task.associated_or_started_at = Instant::now();
            }
            Err(error) => {
                tracing::error!(%interface, %error, "failed to respawn wpa_supplicant");
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
                let _ =
                    tokio::fs::remove_file(config_path(&self.inner.runtime_dir, &interface)).await;
            }
        }
    }
}

fn backoff_duration(base_seconds: u64, consecutive_failures: u32) -> Duration {
    let multiplier = 1u64.checked_shl(consecutive_failures.saturating_sub(1));
    let seconds = multiplier
        .and_then(|multiplier| base_seconds.checked_mul(multiplier))
        .unwrap_or(u64::MAX);
    Duration::from_secs(seconds).min(BACKOFF_CEILING)
}

async fn write_config_file(rendered: &RenderedClientConfig) -> Result<(), ClientSupervisorError> {
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

fn io_error(path: &Path, source: std::io::Error) -> ClientSupervisorError {
    ClientSupervisorError::Configuration(anyhow::Error::from(source).context(format!(
        "failed to write wpa_supplicant configuration to {}",
        path.display()
    )))
}

async fn wait_for_ready(
    ctrl_path: &Path,
    timeout: Duration,
    interface: &str,
) -> Result<(), ClientSupervisorError> {
    let deadline = Instant::now() + STARTUP_READY_TIMEOUT.max(timeout);
    loop {
        if let Ok(client) = WpaSupplicantCtrlClient::connect(ctrl_path, timeout).await {
            if client.ping().await.is_ok() {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err(ClientSupervisorError::StartupTimeout {
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

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixDatagram as StdUnixDatagram;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Mutex as StdMutex;

    use tempfile::tempdir;

    use super::*;
    use crate::config::{
        DhcpConfig, InterfaceConfig, InterfaceRole, NetworkConfig, RouterConfig, RuntimeConfig,
        SecurityConfig, ShutdownPolicy as ConfigShutdownPolicy, VpnConfig, WifiClientConfig,
        WifiClientGlobalConfig, WifiClientSecurity, WifiConfig,
    };
    use crate::wifi::render::WifiDigest;

    fn read_ssid_from_config(path: &Path) -> String {
        let content = std::fs::read_to_string(path).expect("read fake wpa_supplicant config");
        let hex = content
            .lines()
            .map(str::trim)
            .find_map(|line| line.strip_prefix("ssid="))
            .expect("ssid line present");
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("valid hex"))
            .collect();
        String::from_utf8(bytes).expect("ssid decodes as UTF-8 in these tests")
    }

    struct FakeSupplicantCtrl {
        shutdown: Arc<AtomicBool>,
        join: Option<std::thread::JoinHandle<()>>,
        ctrl_path: PathBuf,
    }

    impl FakeSupplicantCtrl {
        fn spawn(ctrl_path: PathBuf, state: &str, config: &Path) -> Self {
            let socket = StdUnixDatagram::bind(&ctrl_path).expect("bind fake ctrl socket");
            socket
                .set_read_timeout(Some(Duration::from_millis(20)))
                .expect("set read timeout");
            let shutdown = Arc::new(AtomicBool::new(false));
            let shutdown_for_thread = shutdown.clone();
            let state = state.to_string();
            let config = config.to_path_buf();

            let join = std::thread::spawn(move || {
                let ssid = Some(read_ssid_from_config(&config));
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
                    let reply = match command.as_str() {
                        "PING" => "PONG\n".to_string(),
                        "STATUS" => {
                            let mut reply = format!("wpa_state={state}\n");

                            if state == "COMPLETED" {
                                if let Some(ssid) = &ssid {
                                    reply.push_str(&format!("ssid={ssid}\n"));
                                }
                                reply.push_str("bssid=02:00:00:00:00:01\nfreq=2437\n");
                            }
                            reply
                        }
                        "RECONNECT" | "DISCONNECT" | "REASSOCIATE" => "OK\n".to_string(),
                        _ => "UNKNOWN COMMAND\n".to_string(),
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
    }

    impl Drop for FakeSupplicantCtrl {
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
        responders: StdMutex<HashMap<u32, FakeSupplicantCtrl>>,
        calls: StdMutex<Vec<FakeCall>>,
        next_pid: AtomicU32,
        fail_spawn: AtomicBool,
        suppress_spawn_responder: AtomicBool,
        persistent_responder: AtomicBool,

        spawn_state: StdMutex<String>,
    }

    impl FakeProcess {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                next_pid: AtomicU32::new(2000),
                spawn_state: StdMutex::new("COMPLETED".to_string()),
                ..Default::default()
            })
        }

        fn spawning_in_state(self: &Arc<Self>, state: &str) {
            *self.spawn_state.lock().unwrap() = state.to_string();
        }

        fn calls(&self) -> Vec<FakeCall> {
            self.calls.lock().unwrap().clone()
        }

        fn spawn_count(&self) -> usize {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|call| matches!(call, FakeCall::Spawn(_)))
                .count()
        }

        fn seed(&self, pid: u32, config_path: PathBuf, state: &str) {
            let ctrl_path = config_path.with_extension("");
            let responder = FakeSupplicantCtrl::spawn(ctrl_path, state, &config_path);
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
                    binary: PathBuf::from("wpa_supplicant"),
                    source: std::io::Error::other("fake spawn failure"),
                });
            }
            let pid = self.next_pid.fetch_add(1, Ordering::Relaxed);
            if !self.suppress_spawn_responder.load(Ordering::Relaxed) {
                let ctrl_path = config_path.with_extension("");
                let state = self.spawn_state.lock().unwrap().clone();
                let responder = FakeSupplicantCtrl::spawn(ctrl_path, &state, config_path);
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

    fn client_config(ssid: &str) -> WifiClientConfig {
        WifiClientConfig {
            ssid: ssid.to_string(),
            country_code: Some("PL".to_string()),

            security: WifiClientSecurity::Open,
            passphrase_file: None,
        }
    }

    fn spec(interface: &str, ssid: &str) -> WifiClientSpec {
        let config = InterfaceConfig {
            role: InterfaceRole::Input,
            managed: false,
            ipv4: None,
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: Some(client_config(ssid)),
        };
        WifiClientSpec::from_interface_config(interface, &config)
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
            wifi: WifiConfig::default(),
            wifi_client: WifiClientGlobalConfig {
                enabled: true,
                wpa_supplicant_binary: PathBuf::from("/usr/sbin/wpa_supplicant"),
                runtime_dir: runtime_dir.to_path_buf(),
                restart_backoff_seconds: 1,
            },
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

    async fn supervisor(
        state_dir: &Path,
        runtime_dir: &Path,
        process: Arc<FakeProcess>,
    ) -> WifiClientSupervisor {
        WifiClientSupervisor::start_with_process(&app_config(state_dir, runtime_dir), process)
            .await
            .expect("start")
    }

    #[tokio::test]
    async fn configure_spawns_and_records_ownership() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let process = FakeProcess::new();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        supervisor
            .configure(spec("wlan0", "upstream"))
            .await
            .expect("configure");

        assert_eq!(process.spawn_count(), 1);
        let record = WifiRecordStore::for_client(temp.path().join("wifi"), "wlan0")
            .load()
            .await
            .expect("load")
            .expect("record present");
        assert_eq!(record.ssid, "upstream");
        assert_eq!(record.pid, 2000);
    }

    #[tokio::test]
    async fn readiness_failure_stops_the_spawned_supplicant_without_recording_it() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let process = FakeProcess::new();
        process
            .suppress_spawn_responder
            .store(true, Ordering::Relaxed);
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        let error = supervisor
            .configure(spec("wlan0", "upstream"))
            .await
            .expect_err("readiness must time out");

        assert!(matches!(
            error,
            ClientSupervisorError::StartupTimeout { .. }
        ));
        assert_eq!(
            process.calls(),
            vec![
                FakeCall::Spawn(config_path(&runtime, "wlan0")),
                FakeCall::Terminate(2000),
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
    async fn the_client_record_does_not_collide_with_an_access_point_one() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let process = FakeProcess::new();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        supervisor
            .configure(spec("wlan0", "upstream"))
            .await
            .expect("configure");

        let records = temp.path().join("wifi");
        assert!(WifiRecordStore::for_client(&records, "wlan0")
            .load()
            .await
            .expect("load client")
            .is_some());
        assert!(
            WifiRecordStore::for_access_point(&records, "wlan0")
                .load()
                .await
                .expect("load ap")
                .is_none(),
            "a client record must not be readable as an access point record"
        );
    }

    #[tokio::test]
    async fn reconfiguring_with_an_identical_spec_is_a_no_op() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let process = FakeProcess::new();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        supervisor
            .configure(spec("wlan0", "upstream"))
            .await
            .expect("first");
        supervisor
            .configure(spec("wlan0", "upstream"))
            .await
            .expect("second");

        assert_eq!(process.spawn_count(), 1);
        assert!(
            !process
                .calls()
                .iter()
                .any(|call| matches!(call, FakeCall::Terminate(_))),
            "an unchanged configure must not stop the running supplicant"
        );
    }

    #[tokio::test]
    async fn changing_the_network_restarts_rather_than_reloading() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let process = FakeProcess::new();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        supervisor
            .configure(spec("wlan0", "upstream"))
            .await
            .expect("first");
        supervisor
            .configure(spec("wlan0", "somewhere-else"))
            .await
            .expect("second");

        assert_eq!(process.spawn_count(), 2);
        assert!(process
            .calls()
            .iter()
            .any(|call| matches!(call, FakeCall::Terminate(2000))));

        let record = WifiRecordStore::for_client(temp.path().join("wifi"), "wlan0")
            .load()
            .await
            .expect("load")
            .expect("record");
        assert_eq!(record.ssid, "somewhere-else");
        assert_eq!(record.pid, 2001);
    }

    #[tokio::test]
    async fn a_passphrase_only_change_still_restarts() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let process = FakeProcess::new();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        let mut secured = spec("wlan0", "upstream");
        secured.security = WifiClientSecurity::Wpa2;
        supervisor
            .set_passphrase(
                "wlan0",
                &WifiPassphrase::new("first-secret").expect("valid"),
            )
            .await
            .expect("set first");
        supervisor
            .configure(secured.clone())
            .await
            .expect("configure");
        assert_eq!(process.spawn_count(), 1);

        supervisor
            .set_passphrase(
                "wlan0",
                &WifiPassphrase::new("second-secret").expect("valid"),
            )
            .await
            .expect("set second");
        supervisor.configure(secured).await.expect("reconfigure");

        assert_eq!(
            process.spawn_count(),
            2,
            "a key-material-only change must be detected via key_digest"
        );
    }

    #[tokio::test]
    async fn an_unchanged_supplicant_from_a_previous_daemon_is_adopted() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let records = temp.path().join("wifi");
        let process = FakeProcess::new();

        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;
        let target = spec("wlan0", "upstream");
        let rendered = supervisor.render_for(&target).await.expect("render");
        write_config_file(&rendered).await.expect("write config");
        process.seed(4242, rendered.path.clone(), "COMPLETED");
        WifiRecordStore::for_client(&records, "wlan0")
            .save(&PersistedWifiRecord {
                pid: 4242,
                started_at_unix: 1,
                ctrl_path: runtime.join("wlan0"),
                config_path: rendered.path.clone(),
                config_digest: rendered.config_digest,
                key_digest: rendered.key_digest,
                ssid: "upstream".to_string(),
            })
            .await
            .expect("seed record");

        supervisor.configure(target).await.expect("configure");

        assert_eq!(
            process.spawn_count(),
            0,
            "an adopted supplicant must not be respawned"
        );
        assert_eq!(
            supervisor.status("wlan0").await.expect("status").pid,
            4242,
            "the adopted pid must be the one now tracked"
        );
    }

    #[tokio::test]
    async fn a_still_associating_supplicant_is_adopted_not_refused() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let records = temp.path().join("wifi");
        let process = FakeProcess::new();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        let target = spec("wlan0", "upstream");
        let rendered = supervisor.render_for(&target).await.expect("render");
        write_config_file(&rendered).await.expect("write config");

        process.seed(4243, rendered.path.clone(), "SCANNING");
        WifiRecordStore::for_client(&records, "wlan0")
            .save(&PersistedWifiRecord {
                pid: 4243,
                started_at_unix: 1,
                ctrl_path: runtime.join("wlan0"),
                config_path: rendered.path.clone(),
                config_digest: rendered.config_digest,
                key_digest: rendered.key_digest,
                ssid: "upstream".to_string(),
            })
            .await
            .expect("seed record");

        supervisor.configure(target).await.expect("configure");

        assert_eq!(process.spawn_count(), 0);
        assert_eq!(supervisor.status("wlan0").await.expect("status").pid, 4243);
    }

    #[tokio::test]
    async fn a_supplicant_answering_for_a_different_network_is_refused() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let records = temp.path().join("wifi");
        let process = FakeProcess::new();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        let target = spec("wlan0", "upstream");
        let rendered = supervisor.render_for(&target).await.expect("render");
        write_config_file(&rendered).await.expect("write config");
        process.seed(4244, rendered.path.clone(), "COMPLETED");

        WifiRecordStore::for_client(&records, "wlan0")
            .save(&PersistedWifiRecord {
                pid: 4244,
                started_at_unix: 1,
                ctrl_path: runtime.join("wlan0"),
                config_path: rendered.path.clone(),
                config_digest: rendered.config_digest,
                key_digest: rendered.key_digest,
                ssid: "someone-elses-network".to_string(),
            })
            .await
            .expect("seed record");

        let error = supervisor.configure(target).await.expect_err("must refuse");
        assert!(
            matches!(error, ClientSupervisorError::NotOwned { .. }),
            "{error:?}"
        );
        assert_eq!(process.spawn_count(), 0);
    }

    #[tokio::test]
    async fn a_live_supplicant_with_no_record_is_refused_never_taken_over() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let process = FakeProcess::new();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        let target = spec("wlan0", "upstream");
        let rendered = supervisor.render_for(&target).await.expect("render");
        write_config_file(&rendered).await.expect("write config");
        process.seed(4245, rendered.path.clone(), "COMPLETED");

        let error = supervisor.configure(target).await.expect_err("must refuse");
        assert!(
            matches!(error, ClientSupervisorError::NotOwned { .. }),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn a_stale_record_with_nothing_behind_it_is_a_fresh_start() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let records = temp.path().join("wifi");
        let process = FakeProcess::new();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        WifiRecordStore::for_client(&records, "wlan0")
            .save(&PersistedWifiRecord {
                pid: 9999,
                started_at_unix: 1,
                ctrl_path: runtime.join("wlan0"),
                config_path: runtime.join("wlan0.conf"),
                config_digest: WifiDigest::from_bytes([7; 32]),
                key_digest: WifiDigest::from_bytes([8; 32]),
                ssid: "upstream".to_string(),
            })
            .await
            .expect("seed record");

        supervisor
            .configure(spec("wlan0", "upstream"))
            .await
            .expect("configure");
        assert_eq!(process.spawn_count(), 1);
    }

    #[tokio::test]
    async fn a_config_changed_while_the_daemon_was_stopped_restarts_the_supplicant() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let records = temp.path().join("wifi");
        let process = FakeProcess::new();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        let target = spec("wlan0", "upstream");
        let rendered = supervisor.render_for(&target).await.expect("render");
        write_config_file(&rendered).await.expect("write config");
        process.seed(4246, rendered.path.clone(), "COMPLETED");

        WifiRecordStore::for_client(&records, "wlan0")
            .save(&PersistedWifiRecord {
                pid: 4246,
                started_at_unix: 1,
                ctrl_path: runtime.join("wlan0"),
                config_path: rendered.path.clone(),
                config_digest: WifiDigest::from_bytes([1; 32]),
                key_digest: WifiDigest::from_bytes([2; 32]),
                ssid: "upstream".to_string(),
            })
            .await
            .expect("seed record");

        supervisor.configure(target).await.expect("configure");

        assert_eq!(process.spawn_count(), 1);
        assert!(process
            .calls()
            .iter()
            .any(|call| matches!(call, FakeCall::Terminate(4246))));
    }

    #[tokio::test]
    async fn ensure_alive_respawns_a_supplicant_that_died() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let process = FakeProcess::new();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        supervisor
            .configure(spec("wlan0", "upstream"))
            .await
            .expect("configure");
        process.kill_externally(2000);

        assert!(supervisor.ensure_alive().await.expect("ensure_alive"));
        assert_eq!(process.spawn_count(), 2);
    }

    #[tokio::test]
    async fn ensure_alive_refuses_respawn_when_the_old_ctrl_socket_still_answers() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let process = FakeProcess::new();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;
        supervisor
            .configure(spec("wlan0", "upstream"))
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

        assert!(matches!(error, ClientSupervisorError::NotOwned { .. }));
        assert_eq!(
            process.calls(),
            vec![
                FakeCall::Spawn(config_path(&runtime, "wlan0")),
                FakeCall::Terminate(2000),
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
    async fn ensure_alive_leaves_a_healthy_supplicant_alone() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let process = FakeProcess::new();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        supervisor
            .configure(spec("wlan0", "upstream"))
            .await
            .expect("configure");

        assert!(!supervisor.ensure_alive().await.expect("ensure_alive"));
        assert_eq!(process.spawn_count(), 1);
    }

    #[tokio::test]
    async fn ensure_alive_tolerates_a_supplicant_that_is_still_associating() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let process = FakeProcess::new();
        process.spawning_in_state("4WAY_HANDSHAKE");
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        supervisor
            .configure(spec("wlan0", "upstream"))
            .await
            .expect("configure");

        assert!(
            !supervisor.ensure_alive().await.expect("ensure_alive"),
            "a supplicant inside the association grace period must be left alone"
        );
        assert_eq!(process.spawn_count(), 1);
    }

    #[tokio::test]
    async fn ensure_alive_restarts_a_supplicant_wedged_past_the_grace_period() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let process = FakeProcess::new();
        process.spawning_in_state("4WAY_HANDSHAKE");
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        supervisor
            .configure(spec("wlan0", "upstream"))
            .await
            .expect("configure");

        {
            let mut tasks = supervisor.inner.tasks.lock().await;
            let task = tasks.get_mut("wlan0").expect("task");
            task.associated_or_started_at =
                Instant::now() - ASSOCIATION_GRACE - Duration::from_secs(1);
        }

        assert!(
            supervisor.ensure_alive().await.expect("ensure_alive"),
            "a supplicant stuck out of COMPLETED past the grace period must be restarted"
        );
        assert_eq!(process.spawn_count(), 2);
    }

    #[tokio::test]
    async fn reaching_completed_resets_the_association_clock() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let process = FakeProcess::new();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        supervisor
            .configure(spec("wlan0", "upstream"))
            .await
            .expect("configure");
        {
            let mut tasks = supervisor.inner.tasks.lock().await;
            let task = tasks.get_mut("wlan0").expect("task");
            task.associated_or_started_at =
                Instant::now() - ASSOCIATION_GRACE - Duration::from_secs(1);
        }

        assert!(!supervisor.ensure_alive().await.expect("ensure_alive"));
        let refreshed = {
            let tasks = supervisor.inner.tasks.lock().await;
            tasks.get("wlan0").expect("task").associated_or_started_at
        };
        assert!(refreshed.elapsed() < ASSOCIATION_GRACE);
    }

    #[tokio::test]
    async fn a_failed_respawn_backs_off_before_trying_again() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let process = FakeProcess::new();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        supervisor
            .configure(spec("wlan0", "upstream"))
            .await
            .expect("configure");
        process.kill_externally(2000);
        process.fail_spawn.store(true, Ordering::Relaxed);

        assert!(supervisor.ensure_alive().await.expect("first"));
        let after_first = process.spawn_count();

        assert!(!supervisor.ensure_alive().await.expect("second"));
        assert_eq!(process.spawn_count(), after_first);
    }

    #[tokio::test]
    async fn disable_stops_the_supplicant_and_clears_its_record() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let process = FakeProcess::new();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        supervisor
            .configure(spec("wlan0", "upstream"))
            .await
            .expect("configure");
        let removed = supervisor.disable("wlan0").await.expect("disable");

        assert_eq!(removed.map(|spec| spec.ssid), Some("upstream".to_string()));
        assert!(process
            .calls()
            .iter()
            .any(|call| matches!(call, FakeCall::Terminate(2000))));
        assert!(
            WifiRecordStore::for_client(temp.path().join("wifi"), "wlan0")
                .load()
                .await
                .expect("load")
                .is_none()
        );
        assert!(supervisor.status("wlan0").await.is_none());
        assert!(!config_path(&runtime, "wlan0").exists());
    }

    #[tokio::test]
    async fn disabling_an_unconfigured_interface_is_not_an_error() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let supervisor = supervisor(temp.path(), &runtime, FakeProcess::new()).await;
        assert!(supervisor
            .disable("wlan9")
            .await
            .expect("disable")
            .is_none());
    }

    #[tokio::test]
    async fn status_reports_the_live_association() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let supervisor = supervisor(temp.path(), &runtime, FakeProcess::new()).await;

        supervisor
            .configure(spec("wlan0", "upstream"))
            .await
            .expect("configure");
        let status = supervisor.status("wlan0").await.expect("status");

        assert_eq!(status.interface, "wlan0");
        assert_eq!(status.wpa_state, WpaState::Completed);
        assert_eq!(status.freq, Some(2437));
        assert_eq!(status.spec.ssid, "upstream");
    }

    #[tokio::test]
    async fn status_of_a_managed_but_unreachable_supplicant_says_so() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let process = FakeProcess::new();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        supervisor
            .configure(spec("wlan0", "upstream"))
            .await
            .expect("configure");
        process.kill_externally(2000);

        let status = supervisor.status("wlan0").await.expect("still managed");
        assert_eq!(status.wpa_state, WpaState::Other("unreachable".to_string()));
    }

    #[tokio::test]
    async fn reconnect_requires_a_configured_interface() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let supervisor = supervisor(temp.path(), &runtime, FakeProcess::new()).await;

        let error = supervisor
            .reconnect("wlan9")
            .await
            .expect_err("not managed");
        assert!(
            matches!(error, ClientSupervisorError::NotConfigured { .. }),
            "{error:?}"
        );

        supervisor
            .configure(spec("wlan0", "upstream"))
            .await
            .expect("configure");
        supervisor.reconnect("wlan0").await.expect("reconnect");
    }

    #[tokio::test]
    async fn shutdown_with_preserve_interfaces_leaves_the_supplicant_running() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let process = FakeProcess::new();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        supervisor
            .configure(spec("wlan0", "upstream"))
            .await
            .expect("configure");
        supervisor
            .shutdown(ShutdownPolicy::PreserveInterfaces)
            .await;

        assert!(!process
            .calls()
            .iter()
            .any(|call| matches!(call, FakeCall::Terminate(_) | FakeCall::Kill(_))));
        assert!(
            WifiRecordStore::for_client(temp.path().join("wifi"), "wlan0")
                .load()
                .await
                .expect("load")
                .is_some()
        );
    }

    #[tokio::test]
    async fn shutdown_with_restore_interfaces_stops_it_and_clears_the_record() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let process = FakeProcess::new();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        supervisor
            .configure(spec("wlan0", "upstream"))
            .await
            .expect("configure");
        supervisor.shutdown(ShutdownPolicy::RestoreInterfaces).await;

        assert!(process
            .calls()
            .iter()
            .any(|call| matches!(call, FakeCall::Terminate(2000))));
        assert!(
            WifiRecordStore::for_client(temp.path().join("wifi"), "wlan0")
                .load()
                .await
                .expect("load")
                .is_none()
        );
    }
}
