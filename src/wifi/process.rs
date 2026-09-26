use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use thiserror::Error;
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

    #[error("failed to signal process {pid}: {source}")]
    Signal { pid: u32, source: nix::errno::Errno },

    #[error("{daemon} process {pid} remained alive after SIGKILL")]
    StopTimeout { pid: u32, daemon: &'static str },
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
        let child = Command::new(binary)
            .arg(config_path)
            .kill_on_drop(false)
            .spawn()
            .map_err(|source| ProcessError::Spawn {
                binary: binary.to_path_buf(),
                source,
            })?;
        let pid = child
            .id()
            .expect("a freshly spawned child always has a pid");
        self.children.lock().await.insert(pid, child);
        Ok(pid)
    }

    async fn spawn_wifi_client(
        &self,
        binary: &Path,
        interface: &str,
        config_path: &Path,
    ) -> Result<u32, ProcessError> {
        let child = Command::new(binary)
            .arg("-i")
            .arg(interface)
            .arg("-c")
            .arg(config_path)
            .kill_on_drop(false)
            .spawn()
            .map_err(|source| ProcessError::Spawn {
                binary: binary.to_path_buf(),
                source,
            })?;
        let pid = child
            .id()
            .expect("a freshly spawned child always has a pid");
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

/// Detected init system used to tailor service management commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitSystem {
    Runit,
    Systemd,
    OpenRc,
    Unknown,
}

/// Detects the active init system on Linux.
pub fn detect_init_system() -> InitSystem {
    if let Ok(comm) = std::fs::read_to_string("/proc/1/comm") {
        let comm = comm.trim();
        if comm == "runit" {
            return InitSystem::Runit;
        }
        if comm == "systemd" {
            return InitSystem::Systemd;
        }
    }
    if std::path::Path::new("/run/systemd/system").exists() {
        return InitSystem::Systemd;
    }
    if std::path::Path::new("/run/runit").exists() {
        return InitSystem::Runit;
    }
    if std::path::Path::new("/run/openrc").exists() {
        return InitSystem::OpenRc;
    }
    InitSystem::Unknown
}

/// Generates clear, actionable advice on how to stop/disable competing network managers
/// (or isolate the specific interface from them) adapted to the current operating environment.
pub fn format_competing_manager_advice(managers: &[String], interface: &str) -> String {
    format_competing_manager_advice_for_init(managers, interface, detect_init_system())
}

pub fn format_competing_manager_advice_for_init(
    managers: &[String],
    interface: &str,
    init: InitSystem,
) -> String {
    let mut lines = Vec::new();

    for manager in managers {
        match manager.as_str() {
            "iwd" => {
                lines.push(format!("• Manager '{manager}' is running:"));
                match init {
                    InitSystem::Runit => {
                        lines.push("  - Stop service:      sudo sv down iwd".to_string());
                        lines
                            .push("  - Disable service:   sudo touch /etc/sv/iwd/down".to_string());
                    }
                    InitSystem::Systemd => {
                        lines.push("  - Stop service:      sudo systemctl stop iwd".to_string());
                        lines.push(
                            "  - Disable service:   sudo systemctl disable --now iwd".to_string(),
                        );
                    }
                    InitSystem::OpenRc => {
                        lines.push("  - Stop service:      sudo rc-service iwd stop".to_string());
                        lines.push(
                            "  - Disable service:   sudo rc-update del iwd default".to_string(),
                        );
                    }
                    _ => {
                        lines.push("  - Stop service:      sudo sv down iwd   (or: sudo systemctl stop iwd)".to_string());
                        lines.push("  - Disable service:   sudo touch /etc/sv/iwd/down   (or: sudo systemctl disable --now iwd)".to_string());
                    }
                }
                lines.push(format!(
                    "  - Release '{interface}' only: add to /etc/iwd/main.conf:"
                ));
                lines.push("      [Blacklist]".to_string());
                lines.push(format!("      Interfaces={interface}"));
            }
            "NetworkManager" => {
                lines.push(format!("• Manager '{manager}' is running:"));
                match init {
                    InitSystem::Runit => {
                        lines
                            .push("  - Stop service:      sudo sv down NetworkManager".to_string());
                        lines.push(
                            "  - Disable service:   sudo touch /etc/sv/NetworkManager/down"
                                .to_string(),
                        );
                    }
                    InitSystem::Systemd => {
                        lines.push(
                            "  - Stop service:      sudo systemctl stop NetworkManager".to_string(),
                        );
                        lines.push(
                            "  - Disable service:   sudo systemctl disable --now NetworkManager"
                                .to_string(),
                        );
                    }
                    InitSystem::OpenRc => {
                        lines.push(
                            "  - Stop service:      sudo rc-service NetworkManager stop"
                                .to_string(),
                        );
                        lines.push(
                            "  - Disable service:   sudo rc-update del NetworkManager default"
                                .to_string(),
                        );
                    }
                    _ => {
                        lines.push("  - Stop service:      sudo sv down NetworkManager   (or: sudo systemctl stop NetworkManager)".to_string());
                        lines.push("  - Disable service:   sudo touch /etc/sv/NetworkManager/down   (or: sudo systemctl disable --now NetworkManager)".to_string());
                    }
                }
                lines.push(format!(
                    "  - Release '{interface}' only: sudo nmcli device set {interface} managed no"
                ));
                lines.push(format!("    (or in /etc/NetworkManager/conf.d/99-traffic-masq.conf: [keyfile] unmanaged-devices=interface-name:{interface})"));
            }
            "systemd-network" | "systemd-networkd" | "networkd" => {
                lines.push("• Manager 'systemd-networkd' is running:".to_string());
                lines.push(
                    "  - Stop service:      sudo systemctl stop systemd-networkd".to_string(),
                );
                lines.push(
                    "  - Disable service:   sudo systemctl disable --now systemd-networkd"
                        .to_string(),
                );
                lines.push(format!("  - Release '{interface}' only: create /etc/systemd/network/99-{interface}-unmanaged.network:"));
                lines.push("      [Match]".to_string());
                lines.push(format!("      Name={interface}"));
                lines.push("      [Link]".to_string());
                lines.push("      Unmanaged=yes".to_string());
            }
            "connman" | "connmand" => {
                lines.push("• Manager 'connman' is running:".to_string());
                match init {
                    InitSystem::Runit => {
                        lines.push("  - Stop service:      sudo sv down connman".to_string());
                        lines.push(
                            "  - Disable service:   sudo touch /etc/sv/connman/down".to_string(),
                        );
                    }
                    InitSystem::Systemd => {
                        lines
                            .push("  - Stop service:      sudo systemctl stop connman".to_string());
                        lines.push(
                            "  - Disable service:   sudo systemctl disable --now connman"
                                .to_string(),
                        );
                    }
                    InitSystem::OpenRc => {
                        lines.push(
                            "  - Stop service:      sudo rc-service connman stop".to_string(),
                        );
                        lines.push(
                            "  - Disable service:   sudo rc-update del connman default".to_string(),
                        );
                    }
                    _ => {
                        lines.push("  - Stop service:      sudo sv down connman   (or: sudo systemctl stop connman)".to_string());
                        lines.push("  - Disable service:   sudo touch /etc/sv/connman/down   (or: sudo systemctl disable --now connman)".to_string());
                    }
                }
                lines.push(format!(
                    "  - Release '{interface}' only: add to /etc/connman/main.conf:"
                ));
                lines.push(format!("      NetworkInterfaceBlacklist = {interface}"));
            }
            "dhcpcd" => {
                lines.push("• Manager 'dhcpcd' is running:".to_string());
                match init {
                    InitSystem::Runit => {
                        lines.push("  - Stop service:      sudo sv down dhcpcd".to_string());
                        lines.push(
                            "  - Disable service:   sudo touch /etc/sv/dhcpcd/down".to_string(),
                        );
                    }
                    InitSystem::Systemd => {
                        lines.push("  - Stop service:      sudo systemctl stop dhcpcd".to_string());
                        lines.push(
                            "  - Disable service:   sudo systemctl disable --now dhcpcd"
                                .to_string(),
                        );
                    }
                    InitSystem::OpenRc => {
                        lines
                            .push("  - Stop service:      sudo rc-service dhcpcd stop".to_string());
                        lines.push(
                            "  - Disable service:   sudo rc-update del dhcpcd default".to_string(),
                        );
                    }
                    _ => {
                        lines.push("  - Stop service:      sudo sv down dhcpcd   (or: sudo systemctl stop dhcpcd)".to_string());
                        lines.push("  - Disable service:   sudo touch /etc/sv/dhcpcd/down   (or: sudo systemctl disable --now dhcpcd)".to_string());
                    }
                }
                lines.push(format!(
                    "  - Release '{interface}' only: add to /etc/dhcpcd.conf:"
                ));
                lines.push(format!("      denyinterfaces {interface}"));
            }
            other => {
                lines.push(format!("• Manager '{other}' is running:"));
                match init {
                    InitSystem::Runit => {
                        lines.push(format!("  - Stop service:      sudo sv down {other}"));
                        lines.push(format!(
                            "  - Disable service:   sudo touch /etc/sv/{other}/down"
                        ));
                    }
                    InitSystem::Systemd => {
                        lines.push(format!(
                            "  - Stop service:      sudo systemctl stop {other}"
                        ));
                        lines.push(format!(
                            "  - Disable service:   sudo systemctl disable --now {other}"
                        ));
                    }
                    InitSystem::OpenRc => {
                        lines.push(format!(
                            "  - Stop service:      sudo rc-service {other} stop"
                        ));
                        lines.push(format!(
                            "  - Disable service:   sudo rc-update del {other} default"
                        ));
                    }
                    _ => {
                        lines.push(format!("  - Stop service:      sudo sv down {other}   (or: sudo systemctl stop {other})"));
                        lines.push(format!("  - Disable service:   sudo touch /etc/sv/{other}/down   (or: sudo systemctl disable --now {other})"));
                    }
                }
            }
        }
    }

    lines.join("\n")
}

fn probe_pid_exists(pid: u32) -> bool {
    matches!(
        kill(Pid::from_raw(pid as i32), None),
        Ok(()) | Err(nix::errno::Errno::EPERM)
    )
}

#[cfg(test)]
mod tests;
