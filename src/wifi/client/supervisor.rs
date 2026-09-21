use std::collections::{HashMap, HashSet};
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
    classify_ownership, cleanup_unconfigured_records, graceful_stop,
    preflight_binary as preflight_daemon_binary, retry_health, save_launch_intent,
    save_spawned_record, unix_now, wait_until_ready, write_private_config, OwnershipOutcome,
    RetryState, WifiHealth, STARTUP_READY_TIMEOUT,
};
use crate::wifi::process::{ProcessError, SupervisedProcess, TokioSupervisedProcess};
use crate::wifi::record::{PersistedWifiRecord, WifiProcessKind, WifiRecordError, WifiRecordStore};
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
    /// Start the wpa_supplicant supervisor from effective configuration using the production process adapter.
    pub async fn start(config: &AppConfig) -> Result<Self, ClientSupervisorError> {
        Self::start_with_process(config, Arc::new(TokioSupervisedProcess::new())).await
    }

    /// Initialize wpa_supplicant supervision with the supplied process adapter and recover configured interfaces.
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

        let specs = Self::effective_specs(config)?;
        let configured_interfaces: HashSet<String> =
            specs.iter().map(|spec| spec.interface.clone()).collect();
        let no_interfaces = HashSet::new();
        cleanup_unconfigured_records(
            &supervisor.inner.records_dir,
            WifiProcessKind::Scan,
            &no_interfaces,
            supervisor.inner.process.as_ref(),
        )
        .await
        .map_err(ClientSupervisorError::Configuration)?;
        cleanup_unconfigured_records(
            &supervisor.inner.records_dir,
            WifiProcessKind::Client,
            &configured_interfaces,
            supervisor.inner.process.as_ref(),
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
                retry: RetryState::failed_startup(self.inner.restart_backoff_seconds, error),
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

    /// Serialize configuration changes and reconcile the requested interface with wpa_supplicant.
    /// Reuse matching state or restart the owned process as needed; propagate setup failures.
    pub async fn configure(&self, spec: WifiClientSpec) -> Result<(), ClientSupervisorError> {
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

    async fn task_process_matches(&self, task: &ClientTask) -> Result<bool, ClientSupervisorError> {
        if task.record.pid == 0 || !self.inner.process.is_alive(task.record.pid).await? {
            return Ok(false);
        }
        if !self
            .inner
            .process
            .cmdline_matches_kind(
                task.record.pid,
                WifiProcessKind::Client,
                &task.record.config_path,
            )
            .await?
        {
            return Ok(false);
        }

        let client =
            match WpaSupplicantCtrlClient::connect(&task.record.ctrl_path, self.inner.ctrl_timeout)
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
            WifiProcessKind::Client,
            self.inner.process.as_ref(),
            status.is_some(),
            |record| {
                status
                    .as_ref()
                    .is_some_and(|status| match status.ssid.as_deref() {
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

    /// Launch the service and persist its process identity for ownership-checked recovery.
    async fn spawn_and_record(
        &self,
        spec: &WifiClientSpec,
        rendered: &RenderedClientConfig,
        ctrl_path: &Path,
    ) -> Result<PersistedWifiRecord, ClientSupervisorError> {
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

    /// Stop the configured process and remove its runtime configuration and ownership record.
    /// Return the previous specification, or `None` when the interface was not configured.
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

    /// Return configured service state and observed health; `None` means no supervised task exists.
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

    /// Ask a configured supplicant to reconnect to its selected network.
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

    /// Scan through an available supplicant, starting a temporary process when necessary.
    /// Validate the interface name and serialize scanning with configuration changes.
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

        let store = WifiRecordStore::for_scan(&self.inner.records_dir, interface);
        let config_digest = WifiDigest::of(&[scan_config.as_bytes()]);
        let key_digest = WifiDigest::of(&[]);
        save_launch_intent(
            &store,
            &ctrl_path,
            &scan_config_path,
            config_digest,
            key_digest,
            "",
        )
        .await?;

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
                let cleanup = store.clear().await;
                let _ = tokio::fs::remove_file(&scan_config_path).await;
                if let Err(cleanup) = cleanup {
                    return Err(ClientSupervisorError::Configuration(anyhow::anyhow!(
                        "Wi-Fi scan spawn failed: {err}; launch-intent cleanup also failed: {cleanup}; recovery required"
                    )));
                }
                return Err(ClientSupervisorError::from(err));
            }
        };

        if let Err(error) = save_spawned_record(
            &store,
            pid,
            &ctrl_path,
            &scan_config_path,
            config_digest,
            key_digest,
            "",
        )
        .await
        {
            return match self.graceful_stop(pid).await {
                Ok(()) => {
                    let cleanup = store.clear().await;
                    let _ = tokio::fs::remove_file(&scan_config_path).await;
                    let _ = tokio::fs::remove_file(&ctrl_path).await;
                    match cleanup {
                        Ok(()) => Err(error.into()),
                        Err(cleanup) => Err(ClientSupervisorError::Configuration(anyhow::anyhow!(
                            "failed to persist Wi-Fi scan ownership: {error}; process stopped but ownership cleanup failed: {cleanup}; recovery required"
                        ))),
                    }
                }
                Err(stop) => Err(ClientSupervisorError::Configuration(anyhow::anyhow!(
                    "failed to persist Wi-Fi scan ownership: {error}; stopping ephemeral supplicant also failed: {stop}; recovery required"
                ))),
            };
        }

        let ready = wait_for_ready(&ctrl_path, self.inner.ctrl_timeout, interface).await;
        let scan_result = match ready {
            Ok(()) => self.perform_scan(&ctrl_path, interface).await,
            Err(err) => Err(err),
        };

        match self.graceful_stop(pid).await {
            Ok(()) => {
                let clear_result = store.clear().await;
                let _ = tokio::fs::remove_file(&scan_config_path).await;
                let _ = tokio::fs::remove_file(&ctrl_path).await;
                match (scan_result, clear_result) {
                    (Ok(results), Ok(())) => Ok(results),
                    (Err(error), Ok(())) => Err(error),
                    (Ok(_), Err(cleanup)) => Err(ClientSupervisorError::Configuration(
                        anyhow::anyhow!(
                            "Wi-Fi scan completed but ownership cleanup failed: {cleanup}; recovery required"
                        ),
                    )),
                    (Err(error), Err(cleanup)) => Err(ClientSupervisorError::Configuration(
                        anyhow::anyhow!(
                            "Wi-Fi scan failed: {error}; ownership cleanup also failed: {cleanup}; recovery required"
                        ),
                    )),
                }
            }
            Err(stop) => match scan_result {
                Ok(_) => Err(stop),
                Err(error) => Err(ClientSupervisorError::Configuration(anyhow::anyhow!(
                    "Wi-Fi scan failed: {error}; stopping ephemeral supplicant also failed: {stop}; recovery required"
                ))),
            },
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

    /// Apply the shutdown policy to supervised processes and their ownership records.
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
mod tests;
