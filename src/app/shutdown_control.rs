//! Transient, process-bound shutdown intent shared by administrative commands and the daemon.
//!
//! The request lives beside the PID file rather than in persistent state: it is lifecycle
//! control, not configuration or recovery data. A random token and target PID bind the
//! acknowledgement to one administrative attempt, while an expiry prevents an abandoned request from
//! changing some much later ordinary shutdown.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::atomic_file::{self, PRIVATE_FILE_MODE};

const SCHEMA_VERSION: u32 = 1;
const EXPIRY_GRACE: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ShutdownMode {
    RestoreInterfaces,
    CancelPending,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShutdownRequestDocument {
    schema_version: u32,
    pid: u32,
    token: String,
    expires_at_unix_seconds: u64,
    mode: ShutdownMode,
}

#[derive(Debug, Clone)]
pub(crate) struct PendingShutdownRequest {
    token: String,
    mode: ShutdownMode,
}

impl PendingShutdownRequest {
    pub(crate) fn cancels_pending(&self) -> bool {
        self.mode == ShutdownMode::CancelPending
    }

    pub(crate) fn restores_interfaces(&self) -> bool {
        self.mode == ShutdownMode::RestoreInterfaces
    }
}

#[derive(Debug)]
pub(crate) struct ShutdownRequestHandle {
    request_path: PathBuf,
    acknowledgement_path: PathBuf,
    token: String,
}

impl ShutdownRequestHandle {
    /// Require proof that the daemon completed the requested cleanup before callers destroy
    /// recovery journals. On failure the control files are intentionally left for diagnosis and
    /// expire naturally; a later retry can replace them atomically.
    pub(crate) fn verify_and_cleanup(self) -> Result<()> {
        atomic_file::reject_symlink(&self.acknowledgement_path)?;
        let acknowledgement =
            fs::read_to_string(&self.acknowledgement_path).with_context(|| {
                format!(
                    "daemon stopped without acknowledging requested network cleanup ({})",
                    self.acknowledgement_path.display()
                )
            })?;
        if acknowledgement.trim() != self.token {
            bail!("daemon shutdown acknowledgement does not match this administrative attempt");
        }
        atomic_file::remove_durable(&self.acknowledgement_path)?;
        atomic_file::remove_durable(&self.request_path)?;
        Ok(())
    }
}

pub(crate) fn request_restore_interfaces(
    pid_path: &Path,
    pid: u32,
    timeout: Duration,
) -> Result<ShutdownRequestHandle> {
    request_shutdown(pid_path, pid, timeout, ShutdownMode::RestoreInterfaces)
}

pub(crate) fn request_cancel_pending(
    pid_path: &Path,
    pid: u32,
    timeout: Duration,
) -> Result<ShutdownRequestHandle> {
    request_shutdown(pid_path, pid, timeout, ShutdownMode::CancelPending)
}

fn request_shutdown(
    pid_path: &Path,
    pid: u32,
    timeout: Duration,
    mode: ShutdownMode,
) -> Result<ShutdownRequestHandle> {
    let request_path = request_path(pid_path);
    let acknowledgement_path = acknowledgement_path(pid_path);
    let parent = request_path
        .parent()
        .context("shutdown request path has no parent directory")?;
    let metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("failed to inspect runtime directory {}", parent.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "runtime directory {} must be a real directory",
            parent.display()
        );
    }

    // A stale acknowledgement must never satisfy a new request.
    let _ = atomic_file::remove_durable(&acknowledgement_path)?;

    let token = random_token();
    let now = unix_now()?;
    let validity = timeout.saturating_add(timeout).saturating_add(EXPIRY_GRACE);
    let expires_at_unix_seconds = now
        .checked_add(validity.as_secs())
        .context("shutdown request expiry overflow")?;
    let document = ShutdownRequestDocument {
        schema_version: SCHEMA_VERSION,
        pid,
        token: token.clone(),
        expires_at_unix_seconds,
        mode,
    };
    atomic_file::replace(
        &request_path,
        &serde_json::to_vec(&document)?,
        PRIVATE_FILE_MODE,
    )
    .with_context(|| {
        format!(
            "failed to write shutdown request {}",
            request_path.display()
        )
    })?;

    Ok(ShutdownRequestHandle {
        request_path,
        acknowledgement_path,
        token,
    })
}

pub(crate) fn request_for_current_process(
    pid_path: &Path,
) -> Result<Option<PendingShutdownRequest>> {
    let path = request_path(pid_path);
    atomic_file::reject_symlink(&path)?;
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read shutdown request {}", path.display()))
        }
    };
    let document: ShutdownRequestDocument = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid shutdown request {}", path.display()))?;
    if document.schema_version != SCHEMA_VERSION {
        bail!(
            "unsupported shutdown request schema {} in {}",
            document.schema_version,
            path.display()
        );
    }
    if document.pid != std::process::id() || document.expires_at_unix_seconds < unix_now()? {
        return Ok(None);
    }
    Ok(Some(PendingShutdownRequest {
        token: document.token,
        mode: document.mode,
    }))
}

pub(crate) fn acknowledge(pid_path: &Path, request: &PendingShutdownRequest) -> Result<()> {
    let path = acknowledgement_path(pid_path);
    atomic_file::replace(&path, request.token.as_bytes(), PRIVATE_FILE_MODE)
        .with_context(|| format!("failed to acknowledge shutdown request {}", path.display()))
}

fn request_path(pid_path: &Path) -> PathBuf {
    sibling_path(pid_path, "shutdown-request.json")
}

fn acknowledgement_path(pid_path: &Path) -> PathBuf {
    sibling_path(pid_path, "shutdown-complete")
}

fn sibling_path(pid_path: &Path, suffix: &str) -> PathBuf {
    let name = pid_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("traffic-masqd.pid");
    pid_path.with_file_name(format!("{name}.{suffix}"))
}

fn unix_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs())
}

fn random_token() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    let mut token = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut token, "{byte:02x}").expect("writing to a String cannot fail");
    }
    token
}

#[cfg(test)]
mod tests;
