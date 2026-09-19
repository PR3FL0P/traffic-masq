use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::atomic_file::{self, PRIVATE_FILE_MODE};
use crate::wifi::process::SupervisedProcess;
use crate::wifi::record::{PersistedWifiRecord, WifiRecordError, WifiRecordStore};
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
        self.next_restart_earliest = Some(
            Instant::now() + backoff_duration(base_seconds, self.consecutive_failures),
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OwnershipOutcome {
    Absent,
    ForeignPresent,
    /// The durable record and process command line still prove ownership, but
    /// the control socket is not responding. The caller may safely restart
    /// this process, but must not spawn alongside it.
    UnreachableOwned(PersistedWifiRecord),
    Adopted(PersistedWifiRecord),
    DigestMismatch(PersistedWifiRecord),
}

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

pub(crate) async fn classify_ownership<F>(
    store: &WifiRecordStore,
    process: &dyn SupervisedProcess,
    ctrl_reachable: bool,
    ctrl_matches_record: F,
    config_digest: WifiDigest,
    key_digest: WifiDigest,
) -> Result<OwnershipOutcome, WifiRecordError>
where
    F: FnOnce(&PersistedWifiRecord) -> bool,
{
    let record = store.load().await?;
    if !ctrl_reachable {
        let Some(record) = record else {
            return Ok(OwnershipOutcome::Absent);
        };
        return match process.cmdline_contains(record.pid, &record.config_path).await {
            Ok(true) => Ok(OwnershipOutcome::UnreachableOwned(record)),
            Ok(false) => {
                // The durable PID/config proof is stale. Only now is it safe to
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

    let process_matches = process
        .cmdline_contains(record.pid, &record.config_path)
        .await
        .unwrap_or(false);
    if !process_matches || !ctrl_matches_record(&record) {
        return Ok(OwnershipOutcome::ForeignPresent);
    }

    if record.config_digest == config_digest && record.key_digest == key_digest {
        Ok(OwnershipOutcome::Adopted(record))
    } else {
        Ok(OwnershipOutcome::DigestMismatch(record))
    }
}

pub(crate) async fn save_spawned_record(
    store: &WifiRecordStore,
    pid: u32,
    ctrl_path: &Path,
    config_path: &Path,
    config_digest: WifiDigest,
    key_digest: WifiDigest,
    ssid: &str,
) -> Result<PersistedWifiRecord, WifiRecordError> {
    let record = PersistedWifiRecord {
        pid,
        started_at_unix: unix_now(),
        ctrl_path: ctrl_path.to_path_buf(),
        config_path: config_path.to_path_buf(),
        config_digest,
        key_digest,
        ssid: ssid.to_string(),
    };
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

pub(crate) async fn preflight_binary(
    binary: &Path,
    daemon: &str,
    setting: &str,
) -> Result<(), anyhow::Error> {
    crate::command::probe(binary).await.map_err(|error| {
        anyhow::anyhow!(
            "{daemon} binary {} is not runnable ({error}) — install {daemon} or fix {setting}",
            binary.display()
        )
    })
}

pub(crate) async fn graceful_stop(
    process: &dyn SupervisedProcess,
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

pub(crate) fn backoff_duration(base_seconds: u64, consecutive_failures: u32) -> Duration {
    let multiplier = 1u64.checked_shl(consecutive_failures.saturating_sub(1));
    let seconds = multiplier
        .and_then(|multiplier| base_seconds.checked_mul(multiplier))
        .unwrap_or(u64::MAX);
    Duration::from_secs(seconds).min(BACKOFF_CEILING)
}

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

/// Recover interrupted interface transactions before starting any supervisor.
/// A durable PID plus its exact config argument is the ownership proof; stale
/// records are cleared without signalling a process that no longer matches.
pub(crate) async fn stop_recorded_interface(state_dir: &Path, interface: &str) -> anyhow::Result<()> {
    let process = crate::wifi::process::TokioSupervisedProcess::new();
    for kind in [crate::wifi::record::WifiProcessKind::AccessPoint, crate::wifi::record::WifiProcessKind::Client] {
        let store = WifiRecordStore::new(kind, state_dir.join("wifi"), interface);
        if let Some(record) = store.load().await? {
            if process.cmdline_contains(record.pid, &record.config_path).await? {
                graceful_stop(&process, record.pid, "Wi-Fi recovery").await?;
            }
            store.clear().await?;
        }
    }
    Ok(())
}
