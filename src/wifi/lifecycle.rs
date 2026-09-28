use std::collections::HashSet;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::atomic_file::{self, PRIVATE_FILE_MODE};
use crate::wifi::process::SupervisedProcess;
use crate::wifi::record::{PersistedWifiRecord, WifiProcessKind, WifiRecordError, WifiRecordStore};
use crate::wifi::render::WifiDigest;

pub(crate) const STARTUP_READY_TIMEOUT: Duration = Duration::from_secs(15);
pub(crate) const STARTUP_POLL_INTERVAL: Duration = Duration::from_millis(20);
pub(crate) const BACKOFF_CEILING: Duration = Duration::from_secs(300);

const GRACEFUL_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const GRACEFUL_STOP_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Why a supervised Wi-Fi daemon is or is not working, in user-facing terms.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum WifiHealth {
    Healthy,
    Starting,
    Retrying {
        error: String,
        attempts: u32,
        retry_in_secs: Option<u64>,
        competing_managers: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        advice: Option<String>,
    },
}

#[derive(Debug, Clone, Default)]
pub(crate) struct RetryState {
    pub(crate) consecutive_failures: u32,
    pub(crate) next_restart_earliest: Option<Instant>,
    pub(crate) last_failure: Option<String>,
}

impl RetryState {
    pub(crate) fn failed_startup(base_seconds: u64, error: &str) -> Self {
        Self {
            consecutive_failures: 1,
            next_restart_earliest: Some(Instant::now() + backoff_duration(base_seconds, 1)),
            last_failure: Some(error.to_string()),
        }
    }

    pub(crate) fn is_waiting(&self) -> bool {
        self.next_restart_earliest
            .is_some_and(|earliest| Instant::now() < earliest)
    }

    pub(crate) fn respawn_failed(&mut self, base_seconds: u64, error: &str) {
        self.last_failure = Some(error.to_string());
        self.next_restart_earliest =
            Some(Instant::now() + backoff_duration(base_seconds, self.consecutive_failures));
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OwnershipOutcome {
    Absent,
    ForeignPresent,
    /// The durable record still matches the process PID, executable, start
    /// time and exact daemon argv, but the control socket is not responding.
    /// The caller may safely restart this process, but must not spawn alongside it.
    UnreachableOwned(PersistedWifiRecord),
    Adopted(PersistedWifiRecord),
    DigestMismatch(PersistedWifiRecord),
}

/// Retry a readiness probe until it succeeds or the timeout expires.
pub(crate) async fn wait_until_ready<F, Fut>(timeout: Duration, mut probe: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + STARTUP_READY_TIMEOUT.max(timeout);
    loop {
        if probe().await {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(STARTUP_POLL_INTERVAL).await;
    }
}

#[allow(clippy::too_many_arguments)] // Identity and digest evidence must be checked together.
pub(crate) async fn classify_ownership<F>(
    store: &WifiRecordStore,
    kind: WifiProcessKind,
    process: &dyn SupervisedProcess,
    expected_binary: &Path,
    ctrl_reachable: bool,
    ctrl_matches_record: F,
    config_digest: WifiDigest,
    key_digest: WifiDigest,
) -> Result<OwnershipOutcome, WifiRecordError>
where
    F: FnOnce(&PersistedWifiRecord) -> bool,
{
    let mut record = store.load().await?;

    // pid == 0 is a durable write-ahead launch intent. It is saved before
    // spawn, when no PID exists yet. If the daemon crashed after spawn but
    // before replacing the intent with the real PID, recover the child by its
    // exact configured executable plus private config-path argument. Never
    // guess when more than one process matches.
    if let Some(pending) = record.clone().filter(|record| record.pid == 0) {
        let Some(expected_boot) = pending.boot_id.as_deref() else {
            return Ok(OwnershipOutcome::ForeignPresent);
        };
        match process.boot_id().await {
            Ok(Some(current_boot)) if current_boot.as_str() == expected_boot => {}
            Ok(Some(_)) => {
                store.clear().await?;
                return Ok(if ctrl_reachable {
                    OwnershipOutcome::ForeignPresent
                } else {
                    OwnershipOutcome::Absent
                });
            }
            Ok(None) | Err(_) => return Ok(OwnershipOutcome::ForeignPresent),
        }
        let binary_path = pending.binary_path.as_deref().unwrap_or(expected_binary);
        match process
            .pids_matching_identity(
                kind,
                binary_path,
                &pending.config_path,
                pending.started_at_unix,
            )
            .await
        {
            Ok(pids) if pids.is_empty() => {
                store.clear().await?;
                record = None;
            }
            Ok(pids) if pids.len() == 1 => {
                let mut recovered = pending;
                recovered.pid = pids[0];
                recovered.process_start_ticks = match process.process_start_ticks(pids[0]).await {
                    Ok(Some(ticks)) => Some(ticks),
                    Ok(None) => {
                        tracing::warn!(pid = pids[0], "could not capture exact Wi-Fi process starttime; retaining launch intent and refusing ownership recovery");
                        return Ok(OwnershipOutcome::ForeignPresent);
                    }
                    Err(error) => {
                        tracing::warn!(pid = pids[0], %error, "could not capture exact Wi-Fi process starttime; retaining launch intent and refusing ownership recovery");
                        return Ok(OwnershipOutcome::ForeignPresent);
                    }
                };
                recovered.boot_id = match process.boot_id().await {
                    Ok(Some(boot_id)) => Some(boot_id),
                    Ok(None) => {
                        tracing::warn!(pid = pids[0], "could not capture Linux boot identity; retaining launch intent and refusing ownership recovery");
                        return Ok(OwnershipOutcome::ForeignPresent);
                    }
                    Err(error) => {
                        tracing::warn!(pid = pids[0], %error, "could not capture Linux boot identity; retaining launch intent and refusing ownership recovery");
                        return Ok(OwnershipOutcome::ForeignPresent);
                    }
                };
                if recovered.binary_path.is_none() {
                    recovered.binary_path = Some(expected_binary.to_path_buf());
                }
                store.save(&recovered).await?;
                record = Some(recovered);
            }
            Ok(pids) => {
                tracing::warn!(
                    config_path = %pending.config_path.display(),
                    ?pids,
                    "multiple processes match a pending Wi-Fi launch intent; refusing ownership recovery"
                );
                return Ok(OwnershipOutcome::ForeignPresent);
            }
            Err(error) => {
                tracing::warn!(
                    config_path = %pending.config_path.display(),
                    %error,
                    "could not recover pending Wi-Fi launch ownership; retaining intent and refusing replacement"
                );
                return Ok(OwnershipOutcome::ForeignPresent);
            }
        }
    }

    if let Some(stale) = record.as_ref().filter(|record| record.pid != 0) {
        let binary = stale.binary_path.as_deref().unwrap_or(expected_binary);
        if !process
            .identity_matches_record(stale, kind, binary)
            .await
            .unwrap_or(true)
        {
            match tokio::fs::symlink_metadata(&stale.ctrl_path).await {
                Ok(node)
                    if node.file_type().is_socket()
                        && Some(node.dev()) == stale.ctrl_dev
                        && Some(node.ino()) == stale.ctrl_ino
                        && ctrl_socket_is_stale(&stale.ctrl_path) =>
                {
                    tokio::fs::remove_file(&stale.ctrl_path)
                        .await
                        .map_err(|error| WifiRecordError::Write(stale.ctrl_path.clone(), error))?;
                    store.clear().await?;
                    return Ok(OwnershipOutcome::Absent);
                }
                Ok(_) => return Ok(OwnershipOutcome::ForeignPresent),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    store.clear().await?;
                    return Ok(OwnershipOutcome::Absent);
                }
                Err(error) => return Err(WifiRecordError::Read(stale.ctrl_path.clone(), error)),
            }
        }
    }

    if !ctrl_reachable {
        let Some(record) = record else {
            return Ok(OwnershipOutcome::Absent);
        };
        let binary_path = record.binary_path.as_deref().unwrap_or(expected_binary);
        return match process
            .identity_matches_record(&record, kind, binary_path)
            .await
        {
            Ok(true) => {
                let mut record = record;
                if record.binary_path.is_none() {
                    record.binary_path = Some(expected_binary.to_path_buf());
                    store.save(&record).await?;
                }
                Ok(OwnershipOutcome::UnreachableOwned(record))
            }
            Ok(false) => {
                // The durable PID/executable/config proof is stale. Only now is it safe to
                // discard it and allow a fresh daemon to be spawned.
                store.clear().await?;
                Ok(OwnershipOutcome::Absent)
            }
            Err(error) => {
                tracing::warn!(pid = record.pid, %error, "could not verify Wi-Fi process ownership; retaining record and refusing replacement");
                Ok(OwnershipOutcome::ForeignPresent)
            }
        };
    }

    let Some(record) = record else {
        return Ok(OwnershipOutcome::ForeignPresent);
    };
    let binary_path = record.binary_path.as_deref().unwrap_or(expected_binary);

    let process_matches = process
        .identity_matches_record(&record, kind, binary_path)
        .await
        .unwrap_or(false);
    if !process_matches {
        return Ok(OwnershipOutcome::ForeignPresent);
    }

    let mut record = record;
    if record.binary_path.is_none() {
        record.binary_path = Some(expected_binary.to_path_buf());
        store.save(&record).await?;
    }

    if record.binary_path.as_deref() != Some(expected_binary) {
        return Ok(OwnershipOutcome::DigestMismatch(record));
    }

    if store.transition_pending().await? {
        // A persisted transition marker plus exact PID/executable/config proof is enough
        // to know this is our interrupted mutation even when the reload changed
        // control-plane fields such as the SSID. Restart from committed intent.
        return Ok(OwnershipOutcome::DigestMismatch(record));
    }

    if !ctrl_matches_record(&record) {
        return Ok(OwnershipOutcome::ForeignPresent);
    }

    if record.config_digest == config_digest && record.key_digest == key_digest {
        Ok(OwnershipOutcome::Adopted(record))
    } else {
        Ok(OwnershipOutcome::DigestMismatch(record))
    }
}

#[allow(clippy::too_many_arguments)] // Persist the complete launch identity before spawning.
pub(crate) async fn save_launch_intent(
    store: &WifiRecordStore,
    boot_id: String,
    binary_path: &Path,
    ctrl_path: &Path,
    config_path: &Path,
    config_digest: WifiDigest,
    key_digest: WifiDigest,
    ssid: &str,
) -> Result<PersistedWifiRecord, WifiRecordError> {
    let record = PersistedWifiRecord {
        pid: 0,
        started_at_unix: unix_now(),
        process_start_ticks: None,
        boot_id: Some(boot_id),
        binary_path: Some(binary_path.to_path_buf()),
        ctrl_path: ctrl_path.to_path_buf(),
        ctrl_dev: None,
        ctrl_ino: None,
        config_path: config_path.to_path_buf(),
        config_digest,
        key_digest,
        ssid: ssid.to_string(),
    };
    store.save(&record).await?;
    Ok(record)
}

#[allow(clippy::too_many_arguments)] // Keep all persisted process identity fields explicit at call sites.
pub(crate) async fn save_spawned_record(
    store: &WifiRecordStore,
    pid: u32,
    process_start_ticks: u64,
    boot_id: String,
    binary_path: &Path,
    ctrl_path: &Path,
    config_path: &Path,
    config_digest: WifiDigest,
    key_digest: WifiDigest,
    ssid: &str,
) -> Result<PersistedWifiRecord, WifiRecordError> {
    let record = PersistedWifiRecord {
        pid,
        started_at_unix: unix_now(),
        process_start_ticks: Some(process_start_ticks),
        boot_id: Some(boot_id),
        binary_path: Some(binary_path.to_path_buf()),
        ctrl_path: ctrl_path.to_path_buf(),
        ctrl_dev: None,
        ctrl_ino: None,
        config_path: config_path.to_path_buf(),
        config_digest,
        key_digest,
        ssid: ssid.to_string(),
    };
    store.save(&record).await?;
    Ok(record)
}

/// A retained pathname is stale only when the kernel confirms that no socket
/// is bound to it. Connecting sends no control command to a foreign daemon.
pub(crate) fn ctrl_socket_is_stale(path: &Path) -> bool {
    std::os::unix::net::UnixDatagram::unbound()
        .and_then(|socket| socket.connect(path))
        .is_err_and(|error| error.kind() == std::io::ErrorKind::ConnectionRefused)
}

pub(crate) async fn persist_owned_ctrl_node(
    store: &WifiRecordStore,
    process: &dyn SupervisedProcess,
    mut record: PersistedWifiRecord,
) -> Result<PersistedWifiRecord, WifiRecordError> {
    let binary = record
        .binary_path
        .clone()
        .ok_or_else(|| WifiRecordError::MismatchedContext(store.path().to_path_buf()))?;
    if !process
        .identity_matches_record(&record, store.kind(), &binary)
        .await
        .unwrap_or(false)
    {
        return Err(WifiRecordError::MismatchedContext(
            store.path().to_path_buf(),
        ));
    }
    if !process
        .owns_unix_socket(record.pid, &record.ctrl_path)
        .await
        .unwrap_or(false)
    {
        return Err(WifiRecordError::MismatchedContext(
            store.path().to_path_buf(),
        ));
    }
    if record.process_start_ticks.is_none() || record.boot_id.is_none() {
        return Err(WifiRecordError::MismatchedContext(
            store.path().to_path_buf(),
        ));
    }
    let node = tokio::fs::symlink_metadata(&record.ctrl_path)
        .await
        .map_err(|error| WifiRecordError::Read(record.ctrl_path.clone(), error))?;
    if !node.file_type().is_socket()
        || !process
            .identity_matches_record(&record, store.kind(), &binary)
            .await
            .unwrap_or(false)
        || !process
            .owns_unix_socket(record.pid, &record.ctrl_path)
            .await
            .unwrap_or(false)
    {
        return Err(WifiRecordError::MismatchedContext(
            store.path().to_path_buf(),
        ));
    }
    record.ctrl_dev = Some(node.dev());
    record.ctrl_ino = Some(node.ino());
    store.save(&record).await?;
    Ok(record)
}

pub(crate) async fn retry_health(
    error: &str,
    attempts: u32,
    next_restart_earliest: Option<Instant>,
    interface: &str,
) -> WifiHealth {
    let retry_in_secs = next_restart_earliest
        .map(|earliest| earliest.saturating_duration_since(Instant::now()).as_secs());
    let competing_managers = crate::wifi::process::find_competing_network_managers().await;
    let advice = if competing_managers.is_empty() {
        None
    } else {
        Some(crate::wifi::process::format_competing_manager_advice(
            &competing_managers,
            interface,
        ))
    };
    WifiHealth::Retrying {
        error: error.to_string(),
        attempts,
        retry_in_secs,
        competing_managers,
        advice,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BinaryPreflightError {
    #[error("binary {binary} does not exist")]
    NotFound { binary: std::path::PathBuf },
    #[error("binary {binary} is not runnable: {source}")]
    ProbeFailed {
        binary: std::path::PathBuf,
        source: anyhow::Error,
    },
}

pub(crate) async fn preflight_binary(
    binary: &Path,
    daemon: &str,
    setting: &str,
) -> Result<(), BinaryPreflightError> {
    let _ = (daemon, setting);
    if !binary.exists() {
        return Err(BinaryPreflightError::NotFound {
            binary: binary.to_path_buf(),
        });
    }
    crate::command::probe(binary)
        .await
        .map_err(|source| BinaryPreflightError::ProbeFailed {
            binary: binary.to_path_buf(),
            source,
        })
}

/// Send SIGTERM and wait for exit, escalating to SIGKILL after the grace period.
/// Treat an absent process as stopped; report failure if it survives the kill deadline.
pub(crate) async fn graceful_stop<P: SupervisedProcess + ?Sized>(
    process: &P,
    pid: u32,
    daemon: &'static str,
) -> Result<(), crate::wifi::process::ProcessError> {
    if pid == 0 {
        return Ok(());
    }
    if !process.is_alive(pid).await? {
        return Ok(());
    }
    if let Err(error) = process.terminate(pid).await {
        // The process may have exited between the liveness probe and SIGTERM.
        if !process.is_alive(pid).await? {
            return Ok(());
        }
        return Err(error);
    }

    let deadline = Instant::now() + GRACEFUL_STOP_TIMEOUT;
    loop {
        match process.is_alive(pid).await? {
            false => return Ok(()),
            true if Instant::now() >= deadline => break,
            true => tokio::time::sleep(GRACEFUL_STOP_POLL_INTERVAL).await,
        }
    }

    tracing::warn!(pid, "{daemon} did not exit after SIGTERM; sending SIGKILL");
    if let Err(error) = process.kill(pid).await {
        if !process.is_alive(pid).await? {
            return Ok(());
        }
        return Err(error);
    }
    let kill_deadline = Instant::now() + GRACEFUL_STOP_TIMEOUT;
    loop {
        match process.is_alive(pid).await? {
            false => return Ok(()),
            true if Instant::now() >= kill_deadline => {
                return Err(crate::wifi::process::ProcessError::StopTimeout { pid, daemon });
            }
            true => tokio::time::sleep(GRACEFUL_STOP_POLL_INTERVAL).await,
        }
    }
}

/// Compute a bounded exponential restart delay from the consecutive failure count.
pub(crate) fn backoff_duration(base_seconds: u64, consecutive_failures: u32) -> Duration {
    let multiplier = 1u64.checked_shl(consecutive_failures.saturating_sub(1));
    let seconds = multiplier
        .and_then(|multiplier| base_seconds.checked_mul(multiplier))
        .unwrap_or(u64::MAX);
    Duration::from_secs(seconds).min(BACKOFF_CEILING)
}

/// Atomically write a runtime configuration with private file permissions off the async executor.
pub(crate) async fn write_private_config(path: &Path, text: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).await?;
        }
    }
    let mut content = text.as_bytes().to_vec();
    content.push(b'\n');
    atomic_file::replace_preserving_on_error_async(path, &content, PRIVATE_FILE_MODE).await
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Remove a Wi-Fi daemon that was started by an immediate mutation which
/// crashed before the corresponding desired configuration became durable.
/// Only ownership records absent from the committed startup configuration are
/// considered, and every signal is guarded by the same executable plus
/// process-kind/config proof used by normal adoption.
pub(crate) async fn cleanup_unconfigured_records(
    records_dir: &Path,
    runtime_dir: &Path,
    kind: WifiProcessKind,
    configured_interfaces: &HashSet<String>,
    process: &dyn SupervisedProcess,
    expected_binary: &Path,
) -> anyhow::Result<()> {
    for (interface, store, record) in
        WifiRecordStore::discover(kind, records_dir, runtime_dir).await?
    {
        if configured_interfaces.contains(&interface)
            || records_dir.parent().is_some_and(|root| {
                crate::core::recovery::check_scope(root, Some(&interface)).is_err()
            })
        {
            continue;
        }

        let result: anyhow::Result<()> = async {
            let binary_path = record
                .binary_path
                .as_deref()
                .unwrap_or(expected_binary);
            let recovered_from_intent = record.pid == 0;
            let pid = if recovered_from_intent {
                let current_boot = process
                    .boot_id()
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("Linux boot identity is unavailable"))?;
                let Some(expected_boot) = record.boot_id.as_deref() else {
                    anyhow::bail!("cannot recover legacy Wi-Fi launch intent for {interface}: boot identity is missing");
                };
                if expected_boot != current_boot.as_str() {
                    None
                } else {
                    let pids = process
                    .pids_matching_identity(
                        kind,
                        binary_path,
                        &record.config_path,
                        record.started_at_unix,
                    )
                    .await?;
                    match pids.as_slice() {
                        [] => None,
                        [pid] => Some(*pid),
                        _ => anyhow::bail!(
                            "cannot recover stale Wi-Fi launch on {interface}: multiple processes {:?} use {}",
                            pids,
                            record.config_path.display()
                        ),
                    }
                }
            } else if process
                .identity_matches_record(&record, kind, binary_path)
                .await?
            {
                Some(record.pid)
            } else {
                None
            };

            if let Some(pid) = pid {
                tracing::warn!(
                    %interface,
                    pid,
                    config_path = %record.config_path.display(),
                    "stopping Wi-Fi process absent from committed configuration"
                );
                let mut owned = record.clone();
                owned.pid = pid;
                if recovered_from_intent {
                    owned.process_start_ticks = Some(
                        process
                            .process_start_ticks(pid)
                            .await?
                            .ok_or_else(|| anyhow::anyhow!("process {pid} disappeared before exact starttime could be captured"))?,
                    );
                    owned.boot_id = Some(
                        process
                            .boot_id()
                            .await?
                            .ok_or_else(|| anyhow::anyhow!("Linux boot identity is unavailable"))?,
                    );
                } else if owned.process_start_ticks.is_none() || owned.boot_id.is_none() {
                    anyhow::bail!("cannot signal legacy Wi-Fi process record for {interface}: exact process lifetime identity is missing");
                }
                owned.binary_path = Some(binary_path.to_path_buf());
                process.stop_recorded(&owned, kind, "Wi-Fi startup recovery").await?;
            }
            store.clear().await?;
            Ok(())
        }
        .await;
        if let Err(error) = result {
            tracing::error!(%interface, journal = %store.path().display(), operation = "recover_wifi_process",
                invariant = "proven_process_identity", metadata_safe_to_remove = false,
                error = %format!("{error:#}"), "Wi-Fi recovery isolated to this interface");
        }
    }
    Ok(())
}

/// Recover interrupted interface transactions before starting any supervisor.
/// A durable PID, or a write-ahead launch intent that resolves to exactly one
/// process, plus its exact configured executable, kind/config argument,
/// Linux boot identity, and kernel process starttime is the ownership proof
/// used for signalling. Stale
/// records are cleared without signalling a process that no longer matches.
pub(crate) async fn stop_recorded_interface(
    state_dir: &Path,
    runtime_dirs: &crate::wifi::WifiRuntimeDirs,
    interface: &str,
) -> anyhow::Result<()> {
    let process = crate::wifi::process::TokioSupervisedProcess::new();
    for kind in [
        WifiProcessKind::AccessPoint,
        WifiProcessKind::Client,
        WifiProcessKind::Scan,
    ] {
        let store = WifiRecordStore::new(
            kind,
            state_dir.join("wifi"),
            runtime_dirs.for_kind(kind),
            interface,
        );
        if let Some(record) = store.load().await? {
            let Some(binary_path) = record.binary_path.as_deref() else {
                anyhow::bail!(
                    "cannot recover Wi-Fi ownership on {interface}: legacy process record has no executable identity"
                );
            };
            let recovered_from_intent = record.pid == 0;
            let pid = if recovered_from_intent {
                let current_boot = process
                    .boot_id()
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("Linux boot identity is unavailable"))?;
                let Some(expected_boot) = record.boot_id.as_deref() else {
                    anyhow::bail!("cannot recover legacy Wi-Fi launch intent for {interface}: boot identity is missing");
                };
                if expected_boot != current_boot.as_str() {
                    None
                } else {
                    let pids = process
                        .pids_matching_identity(
                            kind,
                            binary_path,
                            &record.config_path,
                            record.started_at_unix,
                        )
                        .await?;
                    match pids.as_slice() {
                        [] => None,
                        [pid] => Some(*pid),
                        _ => anyhow::bail!(
                            "cannot recover Wi-Fi ownership on {interface}: multiple processes {:?} use {}",
                            pids,
                            record.config_path.display()
                        ),
                    }
                }
            } else if process
                .identity_matches_record(&record, kind, binary_path)
                .await?
            {
                Some(record.pid)
            } else {
                None
            };
            if let Some(pid) = pid {
                let mut owned = record.clone();
                owned.pid = pid;
                if recovered_from_intent {
                    owned.process_start_ticks = Some(
                        process
                            .process_start_ticks(pid)
                            .await?
                            .ok_or_else(|| anyhow::anyhow!("process {pid} disappeared before exact starttime could be captured"))?,
                    );
                    owned.boot_id =
                        Some(process.boot_id().await?.ok_or_else(|| {
                            anyhow::anyhow!("Linux boot identity is unavailable")
                        })?);
                } else if owned.process_start_ticks.is_none() || owned.boot_id.is_none() {
                    anyhow::bail!("cannot signal legacy Wi-Fi process record for {interface}: exact process lifetime identity is missing");
                }
                process
                    .stop_recorded(&owned, kind, "Wi-Fi recovery")
                    .await?;
            }
            store.clear().await?;
        }
    }
    Ok(())
}
