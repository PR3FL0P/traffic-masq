use std::collections::HashMap;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use thiserror::Error;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

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

    #[error("failed to signal process {pid}: {source}")]
    Signal { pid: u32, source: nix::errno::Errno },
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

    async fn cmdline_contains(&self, pid: u32, config_path: &Path) -> Result<bool, ProcessError>;

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

    async fn cmdline_contains(&self, pid: u32, config_path: &Path) -> Result<bool, ProcessError> {
        (**self).cmdline_contains(pid, config_path).await
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

    async fn cmdline_contains(&self, pid: u32, config_path: &Path) -> Result<bool, ProcessError> {
        let path = format!("/proc/{pid}/cmdline");
        let raw = match tokio::fs::read(&path).await {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(source) => return Err(ProcessError::Inspect { pid, source }),
        };

        let config_path = config_path.as_os_str();
        Ok(raw
            .split(|byte| *byte == 0)
            .any(|argument| argument == config_path.as_encoded_bytes()))
    }

    async fn terminate(&self, pid: u32) -> Result<(), ProcessError> {
        send_signal(pid, Signal::SIGTERM)
    }

    async fn kill(&self, pid: u32) -> Result<(), ProcessError> {
        send_signal(pid, Signal::SIGKILL)
    }
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
const COMPETING_DAEMONS: &[&str] = &["iwd", "NetworkManager", "connman"];

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
            let comm = comm.trim_end_matches('\n');
            if COMPETING_DAEMONS.contains(&comm) && !found.iter().any(|existing| existing == comm) {
                found.push(comm.to_string());
            }
        }
    }
    found.sort();
    found
}

fn probe_pid_exists(pid: u32) -> bool {
    matches!(
        kill(Pid::from_raw(pid as i32), None),
        Ok(()) | Err(nix::errno::Errno::EPERM)
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tempfile::NamedTempFile;

    use super::*;

    #[tokio::test]
    async fn a_freshly_spawned_process_is_alive_and_visible_in_proc() {
        let process = TokioSupervisedProcess::new();

        let pid = process
            .spawn(Path::new("/bin/sleep"), Path::new("300"))
            .await
            .expect("spawn");

        assert!(process.is_alive(pid).await.expect("is_alive"));
        assert!(process
            .cmdline_contains(pid, Path::new("300"))
            .await
            .expect("cmdline_contains"));

        process.kill(pid).await.expect("kill");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!process.is_alive(pid).await.expect("is_alive after kill"));
    }

    #[tokio::test]
    async fn cmdline_contains_is_false_for_a_config_path_not_in_argv() {
        let process = TokioSupervisedProcess::new();
        let pid = process
            .spawn(Path::new("/bin/sleep"), Path::new("300"))
            .await
            .expect("spawn");

        assert!(!process
            .cmdline_contains(pid, Path::new("600"))
            .await
            .expect("cmdline_contains"));

        process.kill(pid).await.expect("cleanup");
    }

    #[tokio::test]
    async fn terminate_and_kill_on_a_pid_that_already_exited_are_not_errors() {
        let config = NamedTempFile::new().expect("tempfile");
        let process = TokioSupervisedProcess::new();
        let pid = process
            .spawn(Path::new("/bin/true"), config.path())
            .await
            .expect("spawn");

        tokio::time::sleep(Duration::from_millis(100)).await;
        process.terminate(pid).await.expect("terminate a dead pid");
        process.kill(pid).await.expect("kill a dead pid");
    }

    #[tokio::test]
    async fn is_alive_and_cmdline_contains_are_false_for_a_pid_never_spawned_here() {
        let config = NamedTempFile::new().expect("tempfile");
        let process = TokioSupervisedProcess::new();

        assert!(process.is_alive(1).await.expect("pid 1 exists"));
        assert!(!process
            .cmdline_contains(1, config.path())
            .await
            .expect("pid 1 is not hostapd"));

        assert!(!process.is_alive(u32::MAX / 2).await.expect("is_alive"));
    }

    #[tokio::test]
    async fn competing_manager_scan_returns_a_list_without_errors() {
        // On any Linux system /proc is readable; the result may legitimately be
        // empty, but the scan itself must never fail or panic.
        let _ = super::find_competing_network_managers().await;
    }

    #[test]
    fn competing_daemons_excludes_our_own_supervised_processes() {
        // hostapd and wpa_supplicant are what THIS daemon supervises; treating
        // them as competitors would make the scan report itself as the
        // interloper on almost every restart.
        assert!(!super::COMPETING_DAEMONS.contains(&"hostapd"));
        assert!(!super::COMPETING_DAEMONS.contains(&"wpa_supplicant"));
    }
}
