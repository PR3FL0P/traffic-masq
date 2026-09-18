use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;
use tokio::sync::Mutex;

use crate::config::{AppConfig, ShutdownPolicy};
use crate::dhcp::supervisor::resolve_interface_index;
use crate::wifi::client::ctrl::{
    CtrlError, WpaState, WpaSupplicantCtrlClient, WpaSupplicantEvent, WpaSupplicantEventClient,
    WpaSupplicantScanResult,
};
use crate::wifi::client::render::{
    config_path, render_scan_config, render_wpa_supplicant_config, scan_config_path,
    ClientRenderError, ClientRenderInput, RenderedClientConfig,
};
use crate::wifi::lifecycle::{
    classify_ownership, graceful_stop, preflight_binary as preflight_daemon_binary, retry_health,
    save_spawned_record,
    unix_now, wait_until_ready, write_private_config, OwnershipOutcome, RetryState, WifiHealth,
    STARTUP_READY_TIMEOUT,
};
use crate::wifi::process::{ProcessError, SupervisedProcess, TokioSupervisedProcess};
use crate::wifi::record::{PersistedWifiRecord, WifiRecordError, WifiRecordStore};
use crate::wifi::render::WifiDigest;
use crate::wifi::secret::WifiPassphrase;
use crate::wifi::store::{resolve_passphrase_parts, PassphraseStore, ResolvePassphraseError};
use crate::wifi::supervisor::interface_is_wireless;
use crate::wifi::WifiClientSpec;

const DEFAULT_CTRL_TIMEOUT: Duration = Duration::from_secs(2);


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

            // Same policy as the AP supervisor: one busy or refusing interface
            // must not take the daemon down. Record a placeholder task so the
            // liveness loop keeps retrying until the interface is free.
            if let Err(error) = supervisor.configure(spec.clone()).await {
                tracing::warn!(
                    interface = %error.interface(),
                    %error,
                    "failed to start Wi-Fi client at startup; \
                     will keep retrying in the background"
                );
                supervisor
                    .record_failed_startup(&spec, &error.to_string())
                    .await;
            }
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
                    ctrl_path: self.ctrl_path(&spec.interface),
                    config_path: config_path(&self.inner.runtime_dir, &spec.interface),
                    config_digest: WifiDigest::of(&[]),
                    key_digest: WifiDigest::of(&[]),
                    ssid: spec.ssid.clone(),
                },
                retry: RetryState::failed_startup(
                    self.inner.restart_backoff_seconds,
                    error,
                ),
                associated_or_started_at: Instant::now(),
            });
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

    async fn task_process_matches(
        &self,
        task: &ClientTask,
    ) -> Result<bool, ClientSupervisorError> {
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

        let client = match WpaSupplicantCtrlClient::connect(
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

    async fn restart_task(
        &self,
        task: &mut ClientTask,
        spec: &WifiClientSpec,
        rendered: &RenderedClientConfig,
        ctrl_path: &Path,
    ) -> Result<(), ClientSupervisorError> {
        self.graceful_stop(task.record.pid).await?;
        let record = self.spawn_and_record(spec, rendered, ctrl_path).await?;
        task.spec = spec.clone();
        task.record = record;
        task.retry.consecutive_failures = 0;
        task.retry.next_restart_earliest = None;
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
            OwnershipOutcome::DigestMismatch(record)
            | OwnershipOutcome::UnreachableOwned(record) => {
                self.graceful_stop(record.pid).await?;
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
        classify_ownership(
            &store,
            self.inner.process.as_ref(),
            status.is_some(),
            |record| {
                status.as_ref().is_some_and(|status| match status.ssid.as_deref() {
                    Some(ssid) => ssid == record.ssid,
                    None => true,
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
                    Err(cleanup) => Err(ClientSupervisorError::Configuration(anyhow::anyhow!(
                        "wpa_supplicant startup failed: {error}; process stopped but ownership-record cleanup failed: {cleanup}; recovery required"
                    ))),
                },
                Err(cleanup) => Err(ClientSupervisorError::Configuration(anyhow::anyhow!(
                    "wpa_supplicant startup failed: {error}; cleanup also failed: {cleanup}; recovery required"
                ))),
            },
        }
    }

    async fn graceful_stop(&self, pid: u32) -> Result<(), ClientSupervisorError> {
        graceful_stop(self.inner.process.as_ref(), pid, "wpa_supplicant").await?;
        Ok(())
    }

    pub async fn disable(
        &self,
        interface: &str,
    ) -> Result<Option<WifiClientSpec>, ClientSupervisorError> {
        let _operation = self.inner.operation_lock.lock().await;
        let Some(task) = self.inner.tasks.lock().await.get(interface).cloned() else {
            return Ok(None);
        };

        self.graceful_stop(task.record.pid).await?;
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
        .map_err(ClientSupervisorError::Configuration)
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

        let health = if let Some(error) = task.retry.last_failure.as_deref() {
            retry_health(
                error,
                task.retry.consecutive_failures,
                task.retry.next_restart_earliest,
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
        crate::config::validate_interface_name(interface)?;
        let _operation = self.inner.operation_lock.lock().await;
        let ctrl_path = self.ctrl_path(interface);

        if self.inner.tasks.lock().await.contains_key(interface) {
            return self.perform_scan(&ctrl_path, interface).await;
        }

        // If a supplicant is already active and responding on the control socket, reuse it
        if let Ok(client) =
            WpaSupplicantCtrlClient::connect(&ctrl_path, Duration::from_millis(50)).await
        {
            if client.ping().await.is_ok() {
                return self.perform_scan(&ctrl_path, interface).await;
            }
        }

        // Ephemeral scan for unconfigured or inactive interface
        tokio::fs::create_dir_all(&self.inner.runtime_dir)
            .await
            .map_err(|source| anyhow::anyhow!("failed to create runtime dir: {source}"))?;

        let scan_config_path = scan_config_path(&self.inner.runtime_dir, interface);
        let scan_config = render_scan_config(&self.inner.runtime_dir);

        tokio::fs::write(&scan_config_path, scan_config.as_bytes())
            .await
            .map_err(|source| anyhow::anyhow!("failed to write scan config: {source}"))?;

        // Clean up stale socket if present
        let _ = tokio::fs::remove_file(&ctrl_path).await;

        let pid = match self
            .inner
            .process
            .spawn_wifi_client(
                &self.inner.wpa_supplicant_binary,
                interface,
                &scan_config_path,
            )
            .await
        {
            Ok(pid) => pid,
            Err(err) => {
                let _ = tokio::fs::remove_file(&scan_config_path).await;
                return Err(ClientSupervisorError::from(err));
            }
        };

        let ready = wait_for_ready(&ctrl_path, self.inner.ctrl_timeout, interface).await;
        let scan_result = match ready {
            Ok(()) => self.perform_scan(&ctrl_path, interface).await,
            Err(err) => Err(err),
        };

        let stop_result = self.graceful_stop(pid).await;
        let _ = tokio::fs::remove_file(&scan_config_path).await;
        let _ = tokio::fs::remove_file(&ctrl_path).await;

        match (scan_result, stop_result) {
            (Ok(results), Ok(())) => Ok(results),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(stop)) => Err(stop),
            (Err(error), Err(stop)) => Err(ClientSupervisorError::Configuration(anyhow::anyhow!(
                "Wi-Fi scan failed: {error}; stopping ephemeral supplicant also failed: {stop}; recovery required"
            ))),
        }
    }

    async fn perform_scan(
        &self,
        ctrl_path: &Path,
        interface: &str,
    ) -> Result<Vec<WpaSupplicantScanResult>, ClientSupervisorError> {
        let (events, mut receiver) =
            WpaSupplicantEventClient::attach(ctrl_path, self.inner.ctrl_timeout).await?;
        let client = WpaSupplicantCtrlClient::connect(ctrl_path, self.inner.ctrl_timeout).await?;
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
            self.graceful_stop(task.record.pid).await?;
        }

        if let Ok(client) =
            WpaSupplicantCtrlClient::connect(&ctrl_path, self.inner.ctrl_timeout).await
        {
            if client.ping().await.is_ok() {
                return Err(ClientSupervisorError::NotOwned {
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

    pub async fn shutdown(&self, policy: ShutdownPolicy) {
        let _operation = self.inner.operation_lock.lock().await;
        let tasks = std::mem::take(&mut *self.inner.tasks.lock().await);

        for (interface, task) in tasks {
            if policy == ShutdownPolicy::RestoreInterfaces {
                if let Err(error) = self.graceful_stop(task.record.pid).await {
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

async fn wait_for_ready(
    ctrl_path: &Path,
    timeout: Duration,
    interface: &str,
) -> Result<(), ClientSupervisorError> {
    let ready = wait_until_ready(timeout, || async {
        match WpaSupplicantCtrlClient::connect(ctrl_path, timeout).await {
            Ok(client) => client.ping().await.is_ok(),
            Err(_) => false,
        }
    })
    .await;
    if ready {
        Ok(())
    } else {
        Err(ClientSupervisorError::StartupTimeout {
            interface: interface.to_string(),
            timeout: STARTUP_READY_TIMEOUT.max(timeout),
        })
    }
}


#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixDatagram as StdUnixDatagram;
    use std::sync::atomic::{AtomicBool, Ordering};

    use tempfile::tempdir;

    use super::*;
    use crate::config::{
        DhcpConfig, InterfaceConfig, InterfaceRole, NetworkConfig, RouterConfig, RuntimeConfig,
        SecurityConfig, ShutdownPolicy as ConfigShutdownPolicy, VpnConfig, WifiClientConfig,
        WifiClientGlobalConfig, WifiClientSecurity, WifiConfig,
    };
    use crate::test_support::{FakeProcessCall as FakeCall, FakeSupervisedProcess};
    use crate::wifi::render::WifiDigest;

    fn read_ssid_from_config(path: &Path) -> Option<String> {
        let content = std::fs::read_to_string(path).ok()?;
        let hex = content
            .lines()
            .map(str::trim)
            .find_map(|line| line.strip_prefix("ssid="))?;
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .filter_map(|index| {
                if index + 2 <= hex.len() {
                    u8::from_str_radix(&hex[index..index + 2], 16).ok()
                } else {
                    None
                }
            })
            .collect();
        String::from_utf8(bytes).ok()
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
                let ssid = read_ssid_from_config(&config);
                let mut buffer = [0u8; 4096];
                let mut attached: Vec<std::os::unix::net::SocketAddr> = Vec::new();
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
                        "ATTACH" => {
                            attached.push(from.clone());
                            "OK\n".to_string()
                        }
                        "DETACH" => {
                            #[cfg(target_os = "linux")]
                            {
                                use std::os::linux::net::SocketAddrExt;
                                if let Some(name) = from.as_abstract_name() {
                                    attached
                                        .retain(|address| address.as_abstract_name() != Some(name));
                                }
                            }
                            "OK\n".to_string()
                        }
                        "SCAN" => {
                            for addr in &attached {
                                let _ = socket.send_to_addr(b"<3>CTRL-EVENT-SCAN-RESULTS\n", addr);
                            }
                            "OK\n".to_string()
                        }
                        "SCAN_RESULTS" => "bssid / frequency / signal level / flags / ssid\n\
                             02:00:00:00:00:01\t2412\t-42\t[WPA2-PSK-CCMP][SAE][ESS]\tupstream\n"
                            .to_string(),
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

    impl Drop for FakeSupplicantCtrl {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::Relaxed);
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
            let _ = std::fs::remove_file(&self.ctrl_path);
        }
    }

    type FakeProcess = FakeSupervisedProcess<FakeSupplicantCtrl>;

    fn fake_process() -> Arc<FakeProcess> {
        FakeProcess::new(
            "wpa_supplicant",
            2000,
            "COMPLETED",
            |interface, config_path, state| {
                let ctrl_path = config_path
                    .parent()
                    .unwrap_or_else(|| Path::new(""))
                    .join(interface);
                FakeSupplicantCtrl::spawn(ctrl_path, state, config_path)
            },
        )
    }

    fn seed_process(process: &FakeProcess, pid: u32, config_path: PathBuf, state: &str) {
        let ctrl_path = config_path.with_extension("");
        let responder = FakeSupplicantCtrl::spawn(ctrl_path, state, &config_path);
        process.seed(pid, config_path, responder);
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
            managed: true,
            ipv4: None,
            dhcp: None,
            dhcp_client: Some(crate::config::DhcpClientInterfaceConfig {
                enabled: true,
                ..Default::default()
            }),
            wifi: None,
            wifi_client: Some(client_config(ssid)),
            nat: true,
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
        let process = fake_process();
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
        let process = fake_process();
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
        let process = fake_process();
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
        let process = fake_process();
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
        let process = fake_process();
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
    async fn unchanged_client_with_unresponsive_ctrl_socket_is_restarted() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let process = fake_process();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;
        let original = spec("wlan0", "upstream");

        supervisor
            .configure(original.clone())
            .await
            .expect("configure original");
        let config = config_path(&runtime, "wlan0");
        process.kill_externally(2000);
        process.seed(
            2000,
            config,
            FakeSupplicantCtrl::spawn_silent(runtime.join("wlan0")),
        );

        supervisor
            .configure(original)
            .await
            .expect("unresponsive control socket must trigger restart");

        assert_eq!(process.spawn_count(), 2);
        assert!(process
            .calls()
            .iter()
            .any(|call| matches!(call, FakeCall::Terminate(2000))));
    }

    #[tokio::test]
    async fn failed_restart_can_be_rolled_back_to_the_previous_network() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let process = fake_process();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;
        let original = spec("wlan0", "upstream");

        supervisor
            .configure(original.clone())
            .await
            .expect("configure original");

        process.fail_spawn.store(true, Ordering::Relaxed);
        supervisor
            .configure(spec("wlan0", "somewhere-else"))
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
    async fn a_passphrase_only_change_still_restarts() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let process = fake_process();
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
        let process = fake_process();

        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;
        let target = spec("wlan0", "upstream");
        let rendered = supervisor.render_for(&target).await.expect("render");
        write_config_file(&rendered).await.expect("write config");
        seed_process(&process, 4242, rendered.path.clone(), "COMPLETED");
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
        let process = fake_process();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        let target = spec("wlan0", "upstream");
        let rendered = supervisor.render_for(&target).await.expect("render");
        write_config_file(&rendered).await.expect("write config");

        seed_process(&process, 4243, rendered.path.clone(), "SCANNING");
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
        let process = fake_process();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        let target = spec("wlan0", "upstream");
        let rendered = supervisor.render_for(&target).await.expect("render");
        write_config_file(&rendered).await.expect("write config");
        seed_process(&process, 4244, rendered.path.clone(), "COMPLETED");

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
        let process = fake_process();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        let target = spec("wlan0", "upstream");
        let rendered = supervisor.render_for(&target).await.expect("render");
        write_config_file(&rendered).await.expect("write config");
        seed_process(&process, 4245, rendered.path.clone(), "COMPLETED");

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
        let process = fake_process();
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
        let process = fake_process();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        let target = spec("wlan0", "upstream");
        let rendered = supervisor.render_for(&target).await.expect("render");
        write_config_file(&rendered).await.expect("write config");
        seed_process(&process, 4246, rendered.path.clone(), "COMPLETED");

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
        let process = fake_process();
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
        let process = fake_process();
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
            vec![FakeCall::Spawn(config_path(&runtime, "wlan0"))],
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
    async fn ensure_alive_leaves_a_healthy_supplicant_alone() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let process = fake_process();
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
        let process = fake_process();
        process.set_spawn_profile("4WAY_HANDSHAKE");
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
        let process = fake_process();
        process.set_spawn_profile("4WAY_HANDSHAKE");
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
    async fn ensure_alive_does_not_restart_a_normally_disconnected_supplicant() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let process = fake_process();
        process.set_spawn_profile("DISCONNECTED");
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        supervisor
            .configure(spec("wlan0", "upstream"))
            .await
            .expect("configure");
        {
            let mut tasks = supervisor.inner.tasks.lock().await;
            tasks.get_mut("wlan0").expect("task").associated_or_started_at =
                Instant::now() - ASSOCIATION_GRACE - Duration::from_secs(1);
        }

        assert!(!supervisor.ensure_alive().await.expect("ensure_alive"));
        assert_eq!(process.spawn_count(), 1);
    }

    #[tokio::test]
    async fn reaching_completed_resets_the_association_clock() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let process = fake_process();
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
        let process = fake_process();
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
        let process = fake_process();
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
        let supervisor = supervisor(temp.path(), &runtime, fake_process()).await;
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
        let supervisor = supervisor(temp.path(), &runtime, fake_process()).await;

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
        let process = fake_process();
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
        let supervisor = supervisor(temp.path(), &runtime, fake_process()).await;

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
        let process = fake_process();
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
        let process = fake_process();
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

    #[tokio::test]
    async fn scan_on_unconfigured_interface_performs_ephemeral_scan_and_cleans_up() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let process = fake_process();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        let results = supervisor.scan("wlan0").await.expect("scan succeeds");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].ssid, "upstream");
        assert_eq!(results[0].frequency_mhz, 2412);

        // Ephemeral process was spawned and terminated:
        assert_eq!(process.spawn_count(), 1);
        let calls = process.calls();
        assert!(calls.iter().any(|c| matches!(c, FakeCall::Terminate(_))));

        // Ephemeral config and socket were removed:
        assert!(!runtime.join("wlan0-scan.conf").exists());
        assert!(!runtime.join("wlan0").exists());
    }

    #[tokio::test]
    async fn scan_on_configured_interface_reuses_running_supplicant() {
        let temp = tempdir().expect("tempdir");
        let runtime = temp.path().join("run");
        let process = fake_process();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

        supervisor
            .configure(spec("wlan0", "upstream"))
            .await
            .expect("configure");
        assert_eq!(process.spawn_count(), 1);

        let results = supervisor.scan("wlan0").await.expect("scan succeeds");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].ssid, "upstream");

        // No new process was spawned, and the running process was NOT terminated:
        assert_eq!(process.spawn_count(), 1);
        let terminate_count = process
            .calls()
            .iter()
            .filter(|c| matches!(c, FakeCall::Terminate(_)))
            .count();
        assert_eq!(terminate_count, 0);
    }
}
