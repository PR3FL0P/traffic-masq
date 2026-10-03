use std::fs::{self, File};
use std::io::{ErrorKind, Read};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use nix::errno::Errno;
use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::atomic_file::{self, PrivateDirError, PRIVATE_DIR_MODE, PRIVATE_FILE_MODE};
use crate::vpn::wireguard::{
    validate_wireguard_profile_name, ProfileError, WireGuardDriver, WireGuardProfile,
};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error(transparent)]
    Profile(#[from] ProfileError),

    #[error("I/O error accessing WireGuard profile store: {0}")]
    Io(#[from] std::io::Error),

    #[error("WireGuard profile store path {0} is not usable as a directory")]
    UnsafeDirectory(PathBuf),

    #[error("refusing to follow symlink at {0}")]
    SymlinkRejected(PathBuf),

    #[error("profile path would escape the configured store directory")]
    PathEscape,

    #[error("profile '{0}' not found")]
    NotFound(String),

    #[error("low-level file operation failed: {0}")]
    Errno(#[from] Errno),

    #[error("profile store operation failed: {operation}; rollback also failed: {rollback}")]
    RollbackFailed { operation: String, rollback: String },
}

impl From<PrivateDirError> for StoreError {
    fn from(error: PrivateDirError) -> Self {
        match error {
            PrivateDirError::Symlink(path) => Self::SymlinkRejected(path),
            PrivateDirError::NotADirectory(path) => Self::UnsafeDirectory(path),
            PrivateDirError::Io(error) => Self::Io(error),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireGuardProfileSummary {
    pub name: String,
    pub size_bytes: u64,
    pub modified: Option<SystemTime>,
}

#[derive(Debug, Clone)]
pub struct WireGuardProfileStore {
    directory: PathBuf,
}

impl WireGuardProfileStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    fn ensure_directory(&self) -> Result<PathBuf, StoreError> {
        atomic_file::ensure_private_dir(&self.directory, PRIVATE_DIR_MODE)?;
        Ok(fs::canonicalize(&self.directory)?)
    }

    fn safe_target(&self, canonical_dir: &Path, name: &str) -> Result<PathBuf, StoreError> {
        validate_wireguard_profile_name(name)?;
        let target = canonical_dir.join(name);
        if target.parent() != Some(canonical_dir) {
            return Err(StoreError::PathEscape);
        }
        Ok(target)
    }

    pub fn import(
        &self,
        driver: &WireGuardDriver,
        name: &str,
        raw: &[u8],
    ) -> Result<WireGuardProfile, StoreError> {
        let profile = driver.parse_named_profile(name, raw)?;

        let canonical_dir = self.ensure_directory()?;
        let target = self.safe_target(&canonical_dir, name)?;

        // Checked here, before delegating, so a planted symlink is reported as
        // `SymlinkRejected` with its path rather than as the generic I/O
        // refusal `atomic_file` raises.
        if let Ok(metadata) = fs::symlink_metadata(&target) {
            if metadata.file_type().is_symlink() {
                return Err(StoreError::SymlinkRejected(target));
            }
        }

        // Snapshot the previous bytes because `replace` can fail after the
        // rename (for example while fsyncing the parent directory). A failed
        // API import must therefore restore the exact previous profile rather
        // than assuming an error implies no mutation.
        let previous = read_optional_regular(&target)?;
        if let Err(error) = atomic_file::replace(&target, raw, PRIVATE_FILE_MODE) {
            restore_profile_after_failure(
                &target,
                previous.as_ref().map(|value| value.as_slice()),
                &error,
            )?;
            return Err(StoreError::Io(error));
        }

        Ok(profile)
    }

    pub fn read(
        &self,
        driver: &WireGuardDriver,
        name: &str,
    ) -> Result<WireGuardProfile, StoreError> {
        let canonical_dir = self.ensure_directory()?;
        let target = self.safe_target(&canonical_dir, name)?;

        let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let raw_fd = match open(&target, flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::ENOENT) => return Err(StoreError::NotFound(name.to_string())),
            Err(Errno::ELOOP) => return Err(StoreError::SymlinkRejected(target)),
            Err(error) => return Err(error.into()),
        };

        let mut file = unsafe { File::from_raw_fd(raw_fd) };

        let mut raw = Zeroizing::new(Vec::new());
        file.read_to_end(&mut raw)?;

        Ok(driver.parse_named_profile(name, &raw)?)
    }

    pub fn list(&self) -> Result<Vec<WireGuardProfileSummary>, StoreError> {
        let canonical_dir = self.ensure_directory()?;
        let mut summaries = Vec::new();

        for entry in fs::read_dir(&canonical_dir)? {
            let entry = entry?;
            let file_type = entry.file_type()?;

            if !file_type.is_file() || file_type.is_symlink() || file_type.is_socket() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if validate_wireguard_profile_name(&name).is_err() {
                continue;
            }
            let metadata = entry.metadata()?;
            summaries.push(WireGuardProfileSummary {
                name,
                size_bytes: metadata.len(),
                modified: metadata.modified().ok(),
            });
        }

        summaries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(summaries)
    }

    pub fn delete(&self, name: &str) -> Result<(), StoreError> {
        let canonical_dir = self.ensure_directory()?;
        let target = self.safe_target(&canonical_dir, name)?;

        match fs::symlink_metadata(&target) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(StoreError::SymlinkRejected(target));
                }
                if !metadata.is_file() {
                    return Err(StoreError::UnsafeDirectory(target));
                }
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Err(StoreError::NotFound(name.to_string()))
            }
            Err(error) => return Err(error.into()),
        }

        let previous = read_optional_regular(&target)?
            .ok_or_else(|| StoreError::NotFound(name.to_string()))?;
        if let Err(error) = atomic_file::remove_durable(&target) {
            restore_profile_after_failure(&target, Some(previous.as_slice()), &error)?;
            return Err(StoreError::Io(error));
        }
        Ok(())
    }
}

fn read_optional_regular(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
    let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let raw_fd = match open(path, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::ENOENT) => return Ok(None),
        Err(Errno::ELOOP) => return Err(StoreError::SymlinkRejected(path.to_path_buf())),
        Err(error) => return Err(error.into()),
    };
    let mut file = unsafe { File::from_raw_fd(raw_fd) };
    let mut raw = Zeroizing::new(Vec::new());
    file.read_to_end(&mut raw)?;
    Ok(Some(raw))
}

fn restore_profile_after_failure(
    path: &Path,
    previous: Option<&[u8]>,
    operation: &std::io::Error,
) -> Result<(), StoreError> {
    let rollback = match previous {
        Some(previous) => atomic_file::replace(path, previous, PRIVATE_FILE_MODE).map(|_| ()),
        None => atomic_file::remove_durable(path).map(|_| ()),
    };
    rollback.map_err(|rollback| StoreError::RollbackFailed {
        operation: operation.to_string(),
        rollback: rollback.to_string(),
    })
}

#[cfg(test)]
mod tests;

/// Read-only import sources: never create or chmod the system WireGuard directory.
pub(crate) fn list_source_profiles(
    directory: &Path,
) -> Result<Vec<WireGuardProfileSummary>, StoreError> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut profiles = Vec::new();
    for entry in entries {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if validate_wireguard_profile_name(&name).is_err()
            || !name.ends_with(".conf")
            || !entry.file_type()?.is_file()
        {
            continue;
        }
        let metadata = entry.metadata()?;
        profiles.push(WireGuardProfileSummary {
            name,
            size_bytes: metadata.len(),
            modified: metadata.modified().ok(),
        });
    }
    profiles.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(profiles)
}

pub(crate) fn read_source_profile(
    directory: &Path,
    name: &str,
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    validate_wireguard_profile_name(name)?;
    if !name.ends_with(".conf") {
        return Err(StoreError::PathEscape);
    }
    let path = directory.join(name);
    let fd = open(
        &path,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| std::io::Error::from_raw_os_error(error as i32))?;
    let file = unsafe { File::from_raw_fd(fd) };
    if !file.metadata()?.is_file() {
        return Err(StoreError::PathEscape);
    }
    let mut contents = Zeroizing::new(Vec::new());
    file.take(1024 * 1024 + 1).read_to_end(&mut contents)?;
    if contents.len() > 1024 * 1024 {
        return Err(
            std::io::Error::new(ErrorKind::InvalidData, "WireGuard source exceeds 1 MiB").into(),
        );
    }
    Ok(contents)
}
