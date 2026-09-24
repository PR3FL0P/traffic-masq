use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use fs2::FileExt;
use nix::sys::signal::{kill, Signal};
use nix::unistd::{setsid, Pid};

use crate::api::client::ApiClient;
use crate::api::model::Request;
use crate::config::AppConfig;
use crate::core::recovery::{
    RecoveryCode, RecoveryDiagnosticRecord, RECOVERY_DIAGNOSTIC_RECORD_VERSION,
};

use super::process::process_lock_is_held;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStatus {
    Stopped,
    StartingOrUnhealthy { pid: Option<u32> },
    Ready { pid: Option<u32> },
}

const STARTUP_RECOVERY_REPORT: &str = "traffic-masqd-startup-recovery.json";

#[derive(Debug)]
pub struct StartupAttemptGuard {
    lock: File,
}

impl Drop for StartupAttemptGuard {
    fn drop(&mut self) {
        if let Err(error) = FileExt::unlock(&self.lock) {
            tracing::warn!(%error, "failed to release startup-attempt lock");
        }
    }
}

pub fn acquire_startup_attempt(config: &AppConfig) -> Result<StartupAttemptGuard> {
    let parent = config
        .runtime
        .pid_path
        .parent()
        .context("daemon PID path has no parent")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create runtime directory {}", parent.display()))?;
    let file_name = config
        .runtime
        .pid_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("traffic-masqd.pid");
    let lock_path = config
        .runtime
        .pid_path
        .with_file_name(format!("{file_name}.start.lock"));
    crate::atomic_file::reject_symlink(&lock_path)
        .with_context(|| format!("refusing unsafe startup-attempt lock {}", lock_path.display()))?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(crate::atomic_file::PRIVATE_FILE_MODE)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(&lock_path)
        .with_context(|| format!("failed to open startup-attempt lock {}", lock_path.display()))?;
    lock.try_lock_exclusive().map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            anyhow::anyhow!("another traffic-masqd start attempt is already in progress")
        } else {
            anyhow::Error::new(error)
                .context(format!("failed to lock startup-attempt file {}", lock_path.display()))
        }
    })?;
    Ok(StartupAttemptGuard { lock })
}

fn startup_recovery_report_path(config: &AppConfig) -> PathBuf {
    config.runtime.log_dir.join(STARTUP_RECOVERY_REPORT)
}

pub fn clear_startup_recovery_report(config: &AppConfig) -> Result<()> {
    let path = startup_recovery_report_path(config);
    crate::atomic_file::remove_durable(&path)
        .map(|_| ())
        .with_context(|| format!("failed to clear startup recovery report {}", path.display()))
}

pub async fn persist_startup_recovery_report(
    config: &AppConfig,
    error: &anyhow::Error,
) -> Result<bool> {
    let Some(diagnostic) = crate::core::recovery::diagnostic_from_error(error) else {
        return Ok(false);
    };
    fs::create_dir_all(&config.runtime.log_dir).with_context(|| {
        format!(
            "failed to create log directory {} for startup recovery report",
            config.runtime.log_dir.display()
        )
    })?;
    let path = startup_recovery_report_path(config);
    let mut bytes = serde_json::to_vec_pretty(&diagnostic.record())?;
    bytes.push(b'\n');
    crate::atomic_file::replace_preserving_on_error_async(
        &path,
        &bytes,
        crate::atomic_file::PRIVATE_FILE_MODE,
    )
    .await
    .with_context(|| format!("failed to write startup recovery report {}", path.display()))?;
    Ok(true)
}

fn read_startup_recovery_report(config: &AppConfig) -> Result<Option<RecoveryDiagnosticRecord>> {
    let path = startup_recovery_report_path(config);
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to open startup recovery report {}", path.display()))
        }
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let report: RecoveryDiagnosticRecord = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid startup recovery report {}", path.display()))?;
    anyhow::ensure!(
        report.version == RECOVERY_DIAGNOSTIC_RECORD_VERSION,
        "unsupported startup recovery report version {}",
        report.version
    );
    let recovery_code = RecoveryCode::from_code(&report.recovery_code).with_context(|| {
        format!(
            "unknown recovery code {} in startup recovery report",
            report.recovery_code
        )
    })?;
    anyhow::ensure!(
        recovery_code.is_startup_blocking(),
        "non-blocking recovery code {} is invalid in a startup recovery report",
        report.recovery_code
    );
    anyhow::ensure!(
        report.invariant == recovery_code.invariant(),
        "startup recovery report code/invariant mismatch: {} maps to {}, not {}",
        report.recovery_code,
        recovery_code.invariant(),
        report.invariant
    );
    anyhow::ensure!(
        report.runbook == recovery_code.runbook_ref(),
        "startup recovery report code/runbook mismatch: {} maps to {}, not {}",
        report.recovery_code,
        recovery_code.runbook_ref(),
        report.runbook
    );
    Ok(Some(report))
}

fn render_startup_recovery_report(report: &RecoveryDiagnosticRecord) -> String {
    let mut message = String::from(
        "traffic-masqd startup is blocked by persisted recovery state.\n\nRecovery:\n",
    );
    message.push_str(&format!("  recovery_code: {}\n", report.recovery_code));
    message.push_str(&format!("  invariant: {}\n", report.invariant));
    message.push_str(&format!("  operation: {}\n", report.operation));
    if let Some(object) = &report.object {
        message.push_str(&format!("  object: {object}\n"));
    }
    if let Some(journal) = &report.journal {
        message.push_str(&format!("  journal: {}\n", journal.display()));
    }
    if let Some(path) = &report.path {
        message.push_str(&format!("  path: {}\n", path.display()));
    }
    if !report.details.is_empty() {
        message.push_str("\nDetected:\n");
        for (key, value) in &report.details {
            message.push_str(&format!("  {key}: {value}\n"));
        }
    }
    message.push_str(&format!(
        "\nRequired action:\n  {}\n  {}\n",
        report.operator_action, report.operator_guidance
    ));
    if !report.metadata_safe_to_remove {
        message.push_str(
            "\nRecovery metadata must be preserved. Do not delete or edit the reported journal or recovery path manually.\n",
        );
    }
    message.push_str(&format!("\nRunbook: {}", report.runbook));
    message.push_str("\nFor additional daemon logs, run `traffic-masqd logs --lines 100`.");
    message
}

pub fn augment_start_error(
    config: &AppConfig,
    error: anyhow::Error,
    report_preparation_error: Option<&str>,
) -> anyhow::Error {
    if let Some(report_error) = report_preparation_error {
        return error.context(format!(
            "startup recovery diagnostic is unavailable because the previous report could not be cleared safely: {report_error}; inspect daemon logs with `traffic-masqd logs --lines 100`"
        ));
    }
    match read_startup_recovery_report(config) {
        Ok(Some(report)) => error.context(render_startup_recovery_report(&report)),
        Ok(None) => error.context(
            "traffic-masqd did not publish a recovery diagnostic; inspect daemon logs with `traffic-masqd logs --lines 100`",
        ),
        Err(report_error) => error.context(format!(
            "failed to read startup recovery diagnostic: {report_error:#}; inspect daemon logs with `traffic-masqd logs --lines 100`"
        )),
    }
}

/// Inspect the daemon PID and process lock to report service state.
pub async fn status(config: &AppConfig) -> Result<ServiceStatus> {
    let lock_held = process_lock_is_held(&config.runtime.pid_path)?;
    if !lock_held {
        return Ok(ServiceStatus::Stopped);
    }

    let pid = read_pid(&config.runtime.pid_path)?;
    let client = ApiClient::new(config.runtime.socket_path.clone());
    match client.request(&Request::Ping).await {
        Ok(_) => Ok(ServiceStatus::Ready { pid }),
        Err(_) => Ok(ServiceStatus::StartingOrUnhealthy { pid }),
    }
}

/// Start the daemon using the current executable and wait for readiness within the deadline.
pub async fn start(
    config: &AppConfig,
    config_path: Option<&Path>,
    startup_timeout: Duration,
) -> Result<u32> {
    let executable = std::env::current_exe().context("failed to resolve traffic-masqd path")?;
    start_executable(&executable, config, config_path, startup_timeout).await
}

/// Launch the selected daemon executable and wait for its API socket to become available.
pub async fn start_executable(
    executable: &Path,
    config: &AppConfig,
    config_path: Option<&Path>,
    startup_timeout: Duration,
) -> Result<u32> {
    if status(config).await? != ServiceStatus::Stopped {
        bail!("traffic-masqd is already running or starting");
    }
    let mut command = Command::new(executable);
    if let Some(config_path) = config_path {
        command.arg("--config").arg(config_path);
    }
    command
        .arg("run")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    unsafe {
        command.pre_exec(|| {
            setsid()
                .map(|_| ())
                .map_err(|error| std::io::Error::from_raw_os_error(error as i32))
        });
    }

    let mut child = command
        .spawn()
        .context("failed to spawn traffic-masqd background process")?;
    let spawned_pid = child.id();
    let deadline = tokio::time::Instant::now() + startup_timeout;

    loop {
        if matches!(status(config).await?, ServiceStatus::Ready { .. }) {
            return Ok(spawned_pid);
        }
        if let Some(exit) = child.try_wait()? {
            bail!("traffic-masqd exited during startup with status {exit}");
        }
        if tokio::time::Instant::now() >= deadline {
            if let Ok(pid) = i32::try_from(spawned_pid) {
                let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
            }
            bail!(
                "traffic-masqd did not become ready within {} seconds and was asked to stop; inspect logs with `traffic-masqd logs`",
                startup_timeout.as_secs()
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Request daemon termination and wait for shutdown; report whether a running process was stopped.
pub async fn stop(config: &AppConfig, shutdown_timeout: Duration) -> Result<bool> {
    if !process_lock_is_held(&config.runtime.pid_path)? {
        return Ok(false);
    }
    let pid = read_pid(&config.runtime.pid_path)?
        .ok_or_else(|| anyhow::anyhow!("daemon lock is held but PID file is missing"))?;
    let pid = i32::try_from(pid).context("daemon PID exceeds Linux pid_t range")?;
    kill(Pid::from_raw(pid), Signal::SIGTERM)
        .with_context(|| format!("failed to send SIGTERM to traffic-masqd PID {pid}"))?;

    let deadline = tokio::time::Instant::now() + shutdown_timeout;
    loop {
        if !process_lock_is_held(&config.runtime.pid_path)? {
            return Ok(true);
        }
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "traffic-masqd did not stop within {} seconds",
                shutdown_timeout.as_secs()
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Print the requested tail of the latest log and optionally follow new entries.
pub async fn print_logs(config: &AppConfig, lines: usize, follow: bool) -> Result<()> {
    let mut path = latest_log_path(&config.runtime.log_dir)?;
    print_tail(&path, lines)?;
    if !follow {
        return Ok(());
    }

    let mut offset = fs::metadata(&path)?.len();
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let latest = latest_log_path(&config.runtime.log_dir)?;
        if latest != path {
            path = latest;
            offset = 0;
        }

        let length = fs::metadata(&path)?.len();
        if length < offset {
            offset = 0;
        }
        if length == offset {
            continue;
        }

        let mut file = File::open(&path)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut appended = String::new();
        file.read_to_string(&mut appended)?;
        print!("{appended}");
        std::io::stdout().flush()?;
        offset = file.stream_position()?;
    }
}

fn read_pid(path: &Path) -> Result<Option<u32>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read PID file {}", path.display()))
        }
    };
    let pid = contents
        .trim()
        .parse::<u32>()
        .with_context(|| format!("invalid PID file {}", path.display()))?;
    Ok(Some(pid))
}

fn latest_log_path(directory: &Path) -> Result<PathBuf> {
    let entries = fs::read_dir(directory)
        .with_context(|| format!("failed to read log directory {}", directory.display()))?;
    let mut candidates = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with("traffic-masqd.log") {
            continue;
        }
        let metadata = entry.metadata()?;
        if metadata.is_file() {
            candidates.push((metadata.modified()?, entry.path()));
        }
    }
    candidates
        .into_iter()
        .max_by_key(|(modified, _)| *modified)
        .map(|(_, path)| path)
        .ok_or_else(|| anyhow::anyhow!("no traffic-masqd logs found in {}", directory.display()))
}

fn print_tail(path: &Path, lines: usize) -> Result<()> {
    if lines == 0 {
        return Ok(());
    }
    let reader = BufReader::new(
        File::open(path).with_context(|| format!("failed to open log {}", path.display()))?,
    );
    let mut tail = VecDeque::with_capacity(lines);
    for line in reader.lines() {
        if tail.len() == lines {
            tail.pop_front();
        }
        tail.push_back(line?);
    }
    for line in tail {
        println!("{line}");
    }
    Ok(())
}

#[cfg(test)]
mod tests;
