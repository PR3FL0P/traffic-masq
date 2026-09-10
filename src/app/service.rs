use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use nix::sys::signal::{kill, Signal};
use nix::unistd::{setsid, Pid};

use crate::api::client::ApiClient;
use crate::api::model::Request;
use crate::config::AppConfig;

use super::process::process_lock_is_held;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStatus {
    Stopped,
    StartingOrUnhealthy { pid: Option<u32> },
    Ready { pid: Option<u32> },
}

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

pub async fn start(
    config: &AppConfig,
    config_path: Option<&Path>,
    startup_timeout: Duration,
) -> Result<u32> {
    let executable = std::env::current_exe().context("failed to resolve traffic-masqd path")?;
    start_executable(&executable, config, config_path, startup_timeout).await
}

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
mod tests {
    use tempfile::tempdir;

    use crate::app::process::ProcessGuard;

    use super::*;

    #[tokio::test]
    async fn status_distinguishes_stopped_from_locked_but_unready() {
        let directory = tempdir().expect("tempdir");
        let mut config = AppConfig::default();
        config.runtime.pid_path = directory.path().join("traffic-masqd.pid");
        config.runtime.socket_path = directory.path().join("traffic-masqd.sock");

        assert_eq!(
            status(&config).await.expect("stopped status"),
            ServiceStatus::Stopped
        );
        let guard = ProcessGuard::acquire(&config.runtime.pid_path).expect("process guard");
        assert_eq!(
            status(&config).await.expect("unready status"),
            ServiceStatus::StartingOrUnhealthy {
                pid: Some(std::process::id())
            }
        );
        drop(guard);
        assert_eq!(
            status(&config).await.expect("stopped status"),
            ServiceStatus::Stopped
        );
    }

    #[test]
    fn prints_and_selects_latest_rolling_log() {
        let directory = tempdir().expect("tempdir");
        let older = directory.path().join("traffic-masqd.log.2026-01-01");
        let latest = directory.path().join("traffic-masqd.log.2026-01-02");
        fs::write(&older, "old\n").expect("older log");
        std::thread::sleep(Duration::from_millis(10));
        fs::write(&latest, "one\ntwo\nthree\n").expect("latest log");
        assert_eq!(latest_log_path(directory.path()).expect("latest"), latest);
    }
}
