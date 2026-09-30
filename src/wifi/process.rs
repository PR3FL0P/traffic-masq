use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::process::Stdio;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

use crate::wifi::record::WifiProcessKind;

#[derive(Debug, Error)]
pub enum ProcessError {
    #[error("failed to spawn {binary}: {source}")]
    Spawn {
        binary: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to inspect process {pid}: {source}")]
    Inspect {
        pid: u32,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to scan processes for Wi-Fi ownership: {source}")]
    Scan {
        #[source]
        source: std::io::Error,
    },

    #[error("failed to read Linux boot identity: {source}")]
    BootId {
        #[source]
        source: std::io::Error,
    },

    #[error("Linux boot identity is unavailable")]
    BootIdUnavailable,

    #[error("failed to signal process {pid}: {source}")]
    Signal { pid: u32, source: nix::errno::Errno },

    #[error("{daemon} process {pid} remained alive after SIGKILL")]
    StopTimeout { pid: u32, daemon: &'static str },

    #[error("pidfd operation for process {pid} failed: {source}")]
    Pidfd { pid: u32, source: std::io::Error },

    #[error("process {pid} no longer matches its recorded Wi-Fi identity")]
    IdentityChanged { pid: u32 },
}

#[async_trait]
pub trait SupervisedProcess: Send + Sync {
    async fn spawn(&self, binary: &Path, config_path: &Path) -> Result<u32, ProcessError>;

    async fn spawn_wifi_client(
        &self,
        binary: &Path,
        interface: &str,
        config_path: &Path,
    ) -> Result<u32, ProcessError> {
        let _ = interface;
        self.spawn(binary, config_path).await
    }

    async fn is_alive(&self, pid: u32) -> Result<bool, ProcessError>;

    async fn identity_matches(
        &self,
        pid: u32,
        kind: WifiProcessKind,
        binary_path: &Path,
        config_path: &Path,
        started_at_unix: u64,
    ) -> Result<bool, ProcessError>;

    /// Return the Linux kernel process starttime from `/proc/<pid>/stat` field 22.
    /// Implementations that cannot provide a stable lifetime identifier may return `None`.
    async fn process_start_ticks(&self, pid: u32) -> Result<Option<u64>, ProcessError> {
        let _ = pid;
        Ok(None)
    }

    /// Return the current Linux boot identifier when available. Persisted
    /// process start ticks are only unique inside one boot epoch.
    async fn boot_id(&self) -> Result<Option<String>, ProcessError> {
        Ok(None)
    }

    /// Match a persisted process record. New records carry an exact kernel
    /// starttime; legacy records fall back to the historical wall-clock check.
    async fn identity_matches_record(
        &self,
        record: &crate::wifi::record::PersistedWifiRecord,
        kind: WifiProcessKind,
        binary_path: &Path,
    ) -> Result<bool, ProcessError> {
        if !self
            .identity_matches(
                record.pid,
                kind,
                binary_path,
                &record.config_path,
                record.started_at_unix,
            )
            .await?
        {
            return Ok(false);
        }
        if let Some(expected_boot) = record.boot_id.as_deref() {
            if self.boot_id().await?.as_deref() != Some(expected_boot) {
                return Ok(false);
            }
        }
        let Some(expected) = record.process_start_ticks else {
            return Ok(true);
        };
        Ok(self.process_start_ticks(record.pid).await? == Some(expected))
    }

    /// Return all running processes whose executable and argv match the exact
    /// Wi-Fi daemon identity expected by this supervisor. This recovers a
    /// write-ahead launch intent persisted before the child PID existed.
    async fn pids_matching_identity(
        &self,
        kind: WifiProcessKind,
        binary_path: &Path,
        config_path: &Path,
        started_at_unix: u64,
    ) -> Result<Vec<u32>, ProcessError>;

    /// Prove that `socket_path` is the Unix-domain socket currently held open
    /// by `pid`. This ties a control pathname to the supervised process rather
    /// than trusting whichever process happens to answer at that pathname.
    async fn owns_unix_socket(&self, pid: u32, socket_path: &Path) -> Result<bool, ProcessError>;

    async fn terminate(&self, pid: u32) -> Result<(), ProcessError>;

    async fn kill(&self, pid: u32) -> Result<(), ProcessError>;

    async fn stop_recorded(
        &self,
        record: &crate::wifi::record::PersistedWifiRecord,
        kind: WifiProcessKind,
        daemon: &'static str,
    ) -> Result<(), ProcessError> {
        let Some(binary) = record.binary_path.as_deref() else {
            return Err(ProcessError::IdentityChanged { pid: record.pid });
        };
        if !self.identity_matches_record(record, kind, binary).await? {
            return Err(ProcessError::IdentityChanged { pid: record.pid });
        }
        crate::wifi::lifecycle::graceful_stop(self, record.pid, daemon).await
    }
}

#[async_trait]
impl SupervisedProcess for std::sync::Arc<dyn SupervisedProcess> {
    async fn spawn(&self, binary: &Path, config_path: &Path) -> Result<u32, ProcessError> {
        (**self).spawn(binary, config_path).await
    }

    async fn spawn_wifi_client(
        &self,
        binary: &Path,
        interface: &str,
        config_path: &Path,
    ) -> Result<u32, ProcessError> {
        (**self)
            .spawn_wifi_client(binary, interface, config_path)
            .await
    }

    async fn is_alive(&self, pid: u32) -> Result<bool, ProcessError> {
        (**self).is_alive(pid).await
    }

    async fn identity_matches(
        &self,
        pid: u32,
        kind: WifiProcessKind,
        binary_path: &Path,
        config_path: &Path,
        started_at_unix: u64,
    ) -> Result<bool, ProcessError> {
        (**self)
            .identity_matches(pid, kind, binary_path, config_path, started_at_unix)
            .await
    }

    async fn process_start_ticks(&self, pid: u32) -> Result<Option<u64>, ProcessError> {
        (**self).process_start_ticks(pid).await
    }

    async fn boot_id(&self) -> Result<Option<String>, ProcessError> {
        (**self).boot_id().await
    }

    async fn identity_matches_record(
        &self,
        record: &crate::wifi::record::PersistedWifiRecord,
        kind: WifiProcessKind,
        binary_path: &Path,
    ) -> Result<bool, ProcessError> {
        (**self)
            .identity_matches_record(record, kind, binary_path)
            .await
    }

    async fn pids_matching_identity(
        &self,
        kind: WifiProcessKind,
        binary_path: &Path,
        config_path: &Path,
        started_at_unix: u64,
    ) -> Result<Vec<u32>, ProcessError> {
        (**self)
            .pids_matching_identity(kind, binary_path, config_path, started_at_unix)
            .await
    }

    async fn owns_unix_socket(&self, pid: u32, socket_path: &Path) -> Result<bool, ProcessError> {
        (**self).owns_unix_socket(pid, socket_path).await
    }

    async fn terminate(&self, pid: u32) -> Result<(), ProcessError> {
        (**self).terminate(pid).await
    }

    async fn kill(&self, pid: u32) -> Result<(), ProcessError> {
        (**self).kill(pid).await
    }

    async fn stop_recorded(
        &self,
        record: &crate::wifi::record::PersistedWifiRecord,
        kind: WifiProcessKind,
        daemon: &'static str,
    ) -> Result<(), ProcessError> {
        (**self).stop_recorded(record, kind, daemon).await
    }
}

#[derive(Debug, Default)]
pub struct TokioSupervisedProcess {
    children: Mutex<HashMap<u32, Child>>,
}

impl TokioSupervisedProcess {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SupervisedProcess for TokioSupervisedProcess {
    async fn spawn(&self, binary: &Path, config_path: &Path) -> Result<u32, ProcessError> {
        let mut child = Command::new(binary)
            .arg(config_path)
            .stderr(Stdio::piped())
            .kill_on_drop(false)
            .spawn()
            .map_err(|source| ProcessError::Spawn {
                binary: binary.to_path_buf(),
                source,
            })?;
        let pid = child
            .id()
            .expect("a freshly spawned child always has a pid");
        if let Some(stderr) = child.stderr.take() {
            capture_wifi_stderr(
                stderr,
                "hostapd",
                config_path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or("unknown"),
                pid,
            );
        }
        self.children.lock().await.insert(pid, child);
        Ok(pid)
    }

    async fn spawn_wifi_client(
        &self,
        binary: &Path,
        interface: &str,
        config_path: &Path,
    ) -> Result<u32, ProcessError> {
        let mut child = Command::new(binary)
            .arg("-i")
            .arg(interface)
            .arg("-c")
            .arg(config_path)
            .stderr(Stdio::piped())
            .kill_on_drop(false)
            .spawn()
            .map_err(|source| ProcessError::Spawn {
                binary: binary.to_path_buf(),
                source,
            })?;
        let pid = child
            .id()
            .expect("a freshly spawned child always has a pid");
        if let Some(stderr) = child.stderr.take() {
            capture_wifi_stderr(stderr, "wpa_supplicant", interface, pid);
        }
        self.children.lock().await.insert(pid, child);
        Ok(pid)
    }

    async fn is_alive(&self, pid: u32) -> Result<bool, ProcessError> {
        let mut children = self.children.lock().await;
        if let Some(child) = children.get_mut(&pid) {
            return match child.try_wait() {
                Ok(None) => Ok(true),
                Ok(Some(_status)) => {
                    children.remove(&pid);
                    Ok(false)
                }
                Err(source) => Err(ProcessError::Inspect { pid, source }),
            };
        }
        drop(children);
        Ok(probe_pid_exists(pid))
    }

    async fn identity_matches(
        &self,
        pid: u32,
        kind: WifiProcessKind,
        binary_path: &Path,
        config_path: &Path,
        started_at_unix: u64,
    ) -> Result<bool, ProcessError> {
        let path = format!("/proc/{pid}/cmdline");
        let raw = match tokio::fs::read(&path).await {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(source) => return Err(ProcessError::Inspect { pid, source }),
        };
        if !argv_matches_kind(&raw, kind, config_path) {
            return Ok(false);
        }
        Ok(executable_matches(pid, binary_path).await?
            && process_started_near(pid, started_at_unix).await?)
    }

    async fn process_start_ticks(&self, pid: u32) -> Result<Option<u64>, ProcessError> {
        process_start_ticks(pid).await
    }

    async fn boot_id(&self) -> Result<Option<String>, ProcessError> {
        current_boot_id().await
    }

    async fn identity_matches_record(
        &self,
        record: &crate::wifi::record::PersistedWifiRecord,
        kind: WifiProcessKind,
        binary_path: &Path,
    ) -> Result<bool, ProcessError> {
        let path = format!("/proc/{}/cmdline", record.pid);
        let raw = match tokio::fs::read(&path).await {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(source) => {
                return Err(ProcessError::Inspect {
                    pid: record.pid,
                    source,
                })
            }
        };
        if !argv_matches_kind(&raw, kind, &record.config_path)
            || !executable_matches(record.pid, binary_path).await?
        {
            return Ok(false);
        }
        if let Some(expected_boot) = record.boot_id.as_deref() {
            if current_boot_id().await?.as_deref() != Some(expected_boot) {
                return Ok(false);
            }
        }
        match record.process_start_ticks {
            Some(expected) => Ok(process_start_ticks(record.pid).await? == Some(expected)),
            None => process_started_near(record.pid, record.started_at_unix).await,
        }
    }

    async fn pids_matching_identity(
        &self,
        kind: WifiProcessKind,
        binary_path: &Path,
        config_path: &Path,
        started_at_unix: u64,
    ) -> Result<Vec<u32>, ProcessError> {
        let mut matches = Vec::new();
        let mut entries = tokio::fs::read_dir("/proc")
            .await
            .map_err(|source| ProcessError::Scan { source })?;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|source| ProcessError::Scan { source })?
        {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            let cmdline = entry.path().join("cmdline");
            let raw = match tokio::fs::read(cmdline).await {
                Ok(raw) => raw,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(source) => return Err(ProcessError::Scan { source }),
            };
            if argv_matches_kind(&raw, kind, config_path)
                && executable_matches(pid, binary_path).await?
                && process_started_after_intent(pid, started_at_unix).await?
            {
                matches.push(pid);
            }
        }
        matches.sort_unstable();
        Ok(matches)
    }

    async fn owns_unix_socket(&self, pid: u32, socket_path: &Path) -> Result<bool, ProcessError> {
        unix_socket_owned_by(pid, socket_path).await
    }

    async fn terminate(&self, pid: u32) -> Result<(), ProcessError> {
        send_signal(pid, Signal::SIGTERM)
    }

    async fn kill(&self, pid: u32) -> Result<(), ProcessError> {
        send_signal(pid, Signal::SIGKILL)
    }

    async fn stop_recorded(
        &self,
        record: &crate::wifi::record::PersistedWifiRecord,
        kind: WifiProcessKind,
        daemon: &'static str,
    ) -> Result<(), ProcessError> {
        #[cfg(target_os = "linux")]
        {
            return self.stop_recorded_pidfd(record, kind, daemon).await;
        }
        #[cfg(not(target_os = "linux"))]
        {
            let Some(binary) = record.binary_path.as_deref() else {
                return Err(ProcessError::IdentityChanged { pid: record.pid });
            };
            if !self.identity_matches_record(record, kind, binary).await? {
                return Err(ProcessError::IdentityChanged { pid: record.pid });
            }
            crate::wifi::lifecycle::graceful_stop(self, record.pid, daemon).await
        }
    }
}

fn capture_wifi_stderr(
    stderr: tokio::process::ChildStderr,
    daemon: &'static str,
    interface: &str,
    pid: u32,
) {
    let interface = interface.to_string();
    tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let lower = line.to_ascii_lowercase();
            if ["passphrase", "password", "psk", "secret", "ssid2", "key="]
                .iter()
                .any(|marker| lower.contains(marker))
            {
                tracing::warn!(daemon, %interface, pid, "Wi-Fi daemon emitted a sensitive diagnostic; content redacted");
            } else {
                tracing::warn!(daemon, %interface, pid, stderr = %line, "Wi-Fi daemon diagnostic");
            }
        }
    });
}

#[cfg(target_os = "linux")]
impl TokioSupervisedProcess {
    async fn stop_recorded_pidfd(
        &self,
        record: &crate::wifi::record::PersistedWifiRecord,
        kind: WifiProcessKind,
        daemon: &'static str,
    ) -> Result<(), ProcessError> {
        use nix::libc;
        let pid = record.pid;
        if pid == 0 {
            return Ok(());
        }
        // Open the lifetime handle first. All subsequent inspection and signals
        // are constrained by this handle; a recycled numeric PID cannot receive them.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        if raw < 0 {
            let source = std::io::Error::last_os_error();
            if source.raw_os_error() == Some(libc::ESRCH) {
                return Ok(());
            }
            return Err(ProcessError::Pidfd { pid, source });
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        let Some(binary) = record.binary_path.as_deref() else {
            return Err(ProcessError::IdentityChanged { pid });
        };
        // Numeric PID plus argv/executable is not a lifetime identity. For Linux
        // signalling we require the exact kernel starttime persisted after spawn.
        if record.process_start_ticks.is_none()
            || record.boot_id.is_none()
            || !self.identity_matches_record(record, kind, binary).await?
            || pidfd_exited(&fd, pid)?
        {
            return Err(ProcessError::IdentityChanged { pid });
        }
        pidfd_signal(&fd, pid, libc::SIGTERM)?;
        if wait_pidfd(&fd, pid, std::time::Duration::from_secs(5)).await? {
            return Ok(());
        }
        tracing::warn!(
            pid,
            daemon,
            "Wi-Fi daemon did not exit after SIGTERM; sending SIGKILL"
        );
        pidfd_signal(&fd, pid, libc::SIGKILL)?;
        if wait_pidfd(&fd, pid, std::time::Duration::from_secs(5)).await? {
            Ok(())
        } else {
            Err(ProcessError::StopTimeout { pid, daemon })
        }
    }
}

#[cfg(target_os = "linux")]
fn pidfd_exited(fd: &OwnedFd, pid: u32) -> Result<bool, ProcessError> {
    let mut pollfd = nix::libc::pollfd {
        fd: fd.as_raw_fd(),
        events: nix::libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { nix::libc::poll(&mut pollfd, 1, 0) };
    if result < 0 {
        return Err(ProcessError::Pidfd {
            pid,
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(result > 0)
}

#[cfg(target_os = "linux")]
fn pidfd_signal(fd: &OwnedFd, pid: u32, signal: i32) -> Result<(), ProcessError> {
    let result = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            signal,
            std::ptr::null::<nix::libc::siginfo_t>(),
            0,
        )
    };
    if result < 0 {
        let source = std::io::Error::last_os_error();
        if source.raw_os_error() != Some(nix::libc::ESRCH) {
            return Err(ProcessError::Pidfd { pid, source });
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn wait_pidfd(
    fd: &OwnedFd,
    pid: u32,
    timeout: std::time::Duration,
) -> Result<bool, ProcessError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if pidfd_exited(fd, pid)? {
            return Ok(true);
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(false);
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

fn argv_matches_kind(raw: &[u8], kind: WifiProcessKind, config_path: &Path) -> bool {
    let args: Vec<&[u8]> = raw
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .collect();
    let config = config_path.as_os_str().as_encoded_bytes();
    match kind {
        WifiProcessKind::AccessPoint => args.len() == 2 && args[1] == config,
        WifiProcessKind::Client | WifiProcessKind::Scan => {
            let Some(stem) = config_path.file_stem().and_then(|stem| stem.to_str()) else {
                return false;
            };
            let interface = match kind {
                WifiProcessKind::Client => stem,
                WifiProcessKind::Scan => match stem.strip_suffix("-scan") {
                    Some(interface) => interface,
                    None => return false,
                },
                WifiProcessKind::AccessPoint => unreachable!(),
            };
            args.len() == 5
                && args[1] == &b"-i"[..]
                && args[2] == interface.as_bytes()
                && args[3] == &b"-c"[..]
                && args[4] == config
        }
    }
}

async fn executable_matches(pid: u32, binary_path: &Path) -> Result<bool, ProcessError> {
    let proc_exe = format!("/proc/{pid}/exe");
    let actual = match tokio::fs::metadata(&proc_exe).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => return Err(ProcessError::Inspect { pid, source }),
    };
    let expected = tokio::fs::metadata(binary_path)
        .await
        .map_err(|source| ProcessError::Inspect { pid, source })?;
    Ok(actual.dev() == expected.dev() && actual.ino() == expected.ino())
}

fn parse_proc_stat_start_ticks(raw: &[u8]) -> Option<u64> {
    // `/proc/<pid>/stat` field 2 (`comm`) is parenthesized and may contain
    // whitespace or `)` characters. The final `)` terminates it; field 3
    // starts immediately afterwards. `starttime` is field 22, i.e. item 19
    // when counting from field 3 at index zero.
    let comm_end = raw.iter().rposition(|byte| *byte == b')')?;
    let starttime = raw[comm_end + 1..]
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty())
        .nth(19)?;
    std::str::from_utf8(starttime).ok()?.parse().ok()
}

async fn current_boot_id() -> Result<Option<String>, ProcessError> {
    let raw = match tokio::fs::read_to_string("/proc/sys/kernel/random/boot_id").await {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(ProcessError::BootId { source }),
    };
    let boot_id = raw.trim();
    Ok((!boot_id.is_empty()).then(|| boot_id.to_string()))
}

async fn process_start_ticks(pid: u32) -> Result<Option<u64>, ProcessError> {
    let path = format!("/proc/{pid}/stat");
    let raw = match tokio::fs::read(path).await {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(ProcessError::Inspect { pid, source }),
    };
    parse_proc_stat_start_ticks(&raw)
        .map(Some)
        .ok_or_else(|| ProcessError::Inspect {
            pid,
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "could not parse process starttime from /proc/<pid>/stat",
            ),
        })
}

async fn process_started_at(pid: u32) -> Result<Option<u64>, ProcessError> {
    let proc_dir = format!("/proc/{pid}");
    let metadata = match tokio::fs::metadata(&proc_dir).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(ProcessError::Inspect { pid, source }),
    };
    Ok(u64::try_from(metadata.ctime()).ok())
}

async fn process_started_near(pid: u32, started_at_unix: u64) -> Result<bool, ProcessError> {
    const MAX_RECORD_DELAY_SECONDS: u64 = 30;
    Ok(process_started_at(pid).await?.is_some_and(|actual| {
        actual <= started_at_unix.saturating_add(1)
            && actual.saturating_add(MAX_RECORD_DELAY_SECONDS) >= started_at_unix
    }))
}

async fn process_started_after_intent(pid: u32, intent_at_unix: u64) -> Result<bool, ProcessError> {
    const MAX_LAUNCH_DELAY_SECONDS: u64 = 30;
    Ok(process_started_at(pid).await?.is_some_and(|actual| {
        actual.saturating_add(1) >= intent_at_unix
            && actual <= intent_at_unix.saturating_add(MAX_LAUNCH_DELAY_SECONDS)
    }))
}

async fn unix_socket_owned_by(pid: u32, socket_path: &Path) -> Result<bool, ProcessError> {
    let table = tokio::fs::read("/proc/net/unix")
        .await
        .map_err(|source| ProcessError::Inspect { pid, source })?;
    let expected_path = socket_path.as_os_str().as_encoded_bytes();
    let mut matching_inodes = table
        .split(|byte| *byte == b'\n')
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&[u8]> = line
                .split(|byte| byte.is_ascii_whitespace())
                .filter(|field| !field.is_empty())
                .collect();
            (fields.len() >= 8 && fields[7] == expected_path).then(|| fields[6])
        });
    let Some(inode) = matching_inodes.next() else {
        return Ok(false);
    };
    // Multiple live sockets claiming the same pathname means an unlink/rebind
    // race is in progress. Refuse to guess which one a new ctrl client reaches.
    if matching_inodes.next().is_some() {
        return Ok(false);
    }
    let Ok(inode) = std::str::from_utf8(inode) else {
        return Ok(false);
    };

    let expected_fd = format!("socket:[{inode}]");
    let fd_dir = format!("/proc/{pid}/fd");
    let mut entries = match tokio::fs::read_dir(&fd_dir).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => return Err(ProcessError::Inspect { pid, source }),
    };
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|source| ProcessError::Inspect { pid, source })?
    {
        match tokio::fs::read_link(entry.path()).await {
            Ok(target) if target.as_os_str() == std::ffi::OsStr::new(&expected_fd) => {
                return Ok(true)
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(ProcessError::Inspect { pid, source }),
        }
    }
    Ok(false)
}

fn send_signal(pid: u32, signal: Signal) -> Result<(), ProcessError> {
    match kill(Pid::from_raw(pid as i32), signal) {
        Ok(()) => Ok(()),

        Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(errno) => Err(ProcessError::Signal { pid, source: errno }),
    }
}

/// Well-known daemons that may fight us for control of a wireless interface.
///
/// Deliberately excludes `hostapd`/`wpa_supplicant`: this daemon supervises
/// its own instances of both, so their presence on the machine is normal, not
/// evidence of a foreign manager, and including them here would make the scan
/// report itself as the competitor on almost every restart.
const COMPETING_DAEMONS: &[&str] = &[
    "iwd",
    "NetworkManager",
    "systemd-network",
    "systemd-networkd",
    "connman",
    "connmand",
    "dhcpcd",
    "dhclient",
    "dhcpd",
    "udhcpc",
];

/// Scans /proc for running processes whose comm matches a known network-management
/// daemon. Used to enrich restart diagnostics: when our supervised daemon keeps
/// dying, the usual cause is another manager reconfiguring the interface behind
/// our back.
pub async fn find_competing_network_managers() -> Vec<String> {
    let mut found = Vec::new();
    let mut entries = match tokio::fs::read_dir("/proc").await {
        Ok(entries) => entries,
        Err(_) => return found,
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let comm_path = entry.path().join("comm");
        if let Ok(comm) = tokio::fs::read_to_string(&comm_path).await {
            let comm = comm.trim();
            if COMPETING_DAEMONS.contains(&comm) {
                let canonical = match comm {
                    "systemd-network" | "systemd-networkd" => "systemd-networkd",
                    "connmand" | "connman" => "connman",
                    other => other,
                };
                if !found.iter().any(|existing| existing == canonical) {
                    found.push(canonical.to_string());
                }
            }
        }
    }
    found.sort();
    found
}

pub use traffic_masq_protocol::{
    detect_init_system, format_competing_manager_advice, format_competing_manager_advice_for_init,
    InitSystem,
};

fn probe_pid_exists(pid: u32) -> bool {
    matches!(
        kill(Pid::from_raw(pid as i32), None),
        Ok(()) | Err(nix::errno::Errno::EPERM)
    )
}

#[cfg(test)]
mod tests;
