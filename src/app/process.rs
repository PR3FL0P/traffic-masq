use std::fs::{self, File, Metadata, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use fs2::FileExt;

pub struct ProcessGuard {
    _lock: File,
    pid_path: PathBuf,
    pid_identity: FileIdentity,
}

impl ProcessGuard {
    /// Acquire the exclusive daemon lock and publish the current process ID.
    /// Keep the lock held for the guard lifetime and remove only the PID file this guard owns.
    pub fn acquire(pid_path: &Path) -> Result<Self> {
        let parent = pid_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("PID path has no parent: {}", pid_path.display()))?;
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create runtime directory {}", parent.display()))?;

        let lock_path = lock_path_for(pid_path);
        reject_symlink(&lock_path, "process lock")?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&lock_path)
            .with_context(|| format!("failed to open process lock {}", lock_path.display()))?;
        lock.try_lock_exclusive().with_context(|| {
            format!(
                "failed to acquire exclusive daemon lock: {}",
                traffic_masq_host_observation::file_lock_diagnostics(&lock, &lock_path)
            )
        })?;

        reject_symlink(pid_path, "PID")?;
        let mut pid_file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(pid_path)
            .with_context(|| format!("failed to create PID file {}", pid_path.display()))?;
        writeln!(pid_file, "{}", std::process::id())?;
        pid_file.sync_all()?;
        fs::set_permissions(pid_path, fs::Permissions::from_mode(0o600))?;
        let pid_identity = FileIdentity::from_metadata(&pid_file.metadata()?);

        Ok(Self {
            _lock: lock,
            pid_path: pid_path.to_path_buf(),
            pid_identity,
        })
    }
}

impl ProcessGuard {
    fn remove_owned_pid(&self) {
        let Ok(metadata) = fs::symlink_metadata(&self.pid_path) else {
            return;
        };
        if metadata.file_type().is_symlink()
            || FileIdentity::from_metadata(&metadata) != self.pid_identity
        {
            return;
        }
        if let Err(error) = fs::remove_file(&self.pid_path) {
            tracing::warn!(
                path = %self.pid_path.display(),
                %error,
                "failed to remove owned PID file"
            );
        }
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        // Keep ownership until PID cleanup finishes. Closing only this fd is
        // insufficient: a concurrently forked child may hold the same open
        // file description until exec, extending the flock lifetime.
        self.remove_owned_pid();
        if let Err(error) = FileExt::unlock(&self._lock) {
            tracing::warn!(%error, "failed to release process lock");
        }
    }
}

/// Probe the daemon lock without keeping it locked, returning whether another process holds it.
pub fn process_lock_is_held(pid_path: &Path) -> Result<bool> {
    let lock_path = lock_path_for(pid_path);
    let lock = match OpenOptions::new().read(true).write(true).open(&lock_path) {
        Ok(lock) => lock,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to open process lock {}", lock_path.display()))
        }
    };

    match lock.try_lock_exclusive() {
        Ok(()) => {
            FileExt::unlock(&lock)?;
            Ok(false)
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(true),
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect process lock {}", lock_path.display())),
    }
}

pub fn lock_path_for(pid_path: &Path) -> PathBuf {
    let file_name = pid_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("traffic-masqd.pid");
    pid_path.with_file_name(format!("{file_name}.lock"))
}

fn reject_symlink(path: &Path, description: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!(
                "refusing to use symbolic link as {description}: {}",
                path.display()
            )
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect {description} path {}", path.display())),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[cfg(test)]
mod tests;
