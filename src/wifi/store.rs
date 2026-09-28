use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::FromRawFd;
use std::path::{Component, Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::atomic_file::{self, PrivateDirError, PRIVATE_DIR_MODE, PRIVATE_FILE_MODE};
use crate::config::{validate_interface_name, InterfaceConfig, WifiSecurity};
use crate::wifi::secret::{PassphraseError, WifiPassphrase};
use crate::wifi::WifiApSpec;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WifiCredentialRole {
    Ap,
    Client,
}

impl WifiCredentialRole {
    pub fn from_config(config: &InterfaceConfig) -> Option<Self> {
        match (&config.wifi, &config.wifi_client) {
            (Some(_), None) => Some(Self::Ap),
            (None, Some(_)) => Some(Self::Client),
            _ => None,
        }
    }
}

#[derive(Debug, Error)]
pub enum PassphraseStoreError {
    #[error("invalid interface name: {0}")]
    InvalidInterfaceName(String),

    #[error("I/O error accessing Wi-Fi passphrase store: {0}")]
    Io(#[from] std::io::Error),

    #[error("Wi-Fi passphrase store path {0} is not usable as a directory")]
    UnsafeDirectory(PathBuf),

    #[error("refusing to follow symlink at {0}")]
    SymlinkRejected(PathBuf),

    #[error("passphrase path would escape the configured store directory")]
    PathEscape,

    #[error("low-level file operation failed: {0}")]
    Errno(#[from] Errno),

    #[error("passphrase store operation failed: {operation}; rollback also failed: {rollback}")]
    RollbackFailed { operation: String, rollback: String },

    #[error(transparent)]
    Passphrase(#[from] PassphraseError),
}

impl From<PrivateDirError> for PassphraseStoreError {
    fn from(error: PrivateDirError) -> Self {
        match error {
            PrivateDirError::Symlink(path) => Self::SymlinkRejected(path),
            PrivateDirError::NotADirectory(path) => Self::UnsafeDirectory(path),
            PrivateDirError::Io(error) => Self::Io(error),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PassphraseStore {
    directory: PathBuf,
}

impl PassphraseStore {
    /// Role stores deliberately sit beside the legacy directory: Linux
    /// interfaces named `ap` or `client` may already occupy `psk/<name>`.
    pub fn for_role(state_dir: impl AsRef<Path>, role: WifiCredentialRole) -> Self {
        Self::new(state_dir.as_ref().join(match role {
            WifiCredentialRole::Ap => "wifi/psk-ap",
            WifiCredentialRole::Client => "wifi/psk-client",
        }))
    }
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    fn ensure_directory(&self) -> Result<PathBuf, PassphraseStoreError> {
        atomic_file::ensure_private_dir(&self.directory, PRIVATE_DIR_MODE)?;
        Ok(fs::canonicalize(&self.directory)?)
    }

    fn safe_target(
        &self,
        canonical_dir: &Path,
        interface: &str,
    ) -> Result<PathBuf, PassphraseStoreError> {
        validate_interface_name(interface)
            .map_err(|error| PassphraseStoreError::InvalidInterfaceName(error.to_string()))?;

        let mut components = Path::new(interface).components();
        match (components.next(), components.next()) {
            (Some(Component::Normal(_)), None) => {}
            _ => return Err(PassphraseStoreError::PathEscape),
        }

        Ok(canonical_dir.join(interface))
    }

    pub fn set(
        &self,
        interface: &str,
        passphrase: &WifiPassphrase,
    ) -> Result<(), PassphraseStoreError> {
        let canonical_dir = self.ensure_directory()?;
        let target = self.safe_target(&canonical_dir, interface)?;
        let previous = read_secret_bytes(&target)?;

        if let Err(error) =
            atomic_file::replace(&target, passphrase.expose().as_bytes(), PRIVATE_FILE_MODE)
        {
            return restore_after_store_failure(
                &target,
                previous.as_ref().map(|value| value.as_slice()),
                error,
            );
        }
        Ok(())
    }

    pub fn get(&self, interface: &str) -> Result<Option<WifiPassphrase>, PassphraseStoreError> {
        let canonical_dir = self.ensure_directory()?;
        let target = self.safe_target(&canonical_dir, interface)?;

        let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let raw_fd = match open(&target, flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::ENOENT) => return Ok(None),
            Err(Errno::ELOOP) => return Err(PassphraseStoreError::SymlinkRejected(target)),
            Err(error) => return Err(error.into()),
        };

        let mut file = unsafe { File::from_raw_fd(raw_fd) };

        let mut contents = Zeroizing::new(String::new());
        file.read_to_string(&mut contents)?;
        Ok(Some(WifiPassphrase::new(contents.as_str())?))
    }

    pub fn clear(&self, interface: &str) -> Result<(), PassphraseStoreError> {
        let canonical_dir = self.ensure_directory()?;
        let target = self.safe_target(&canonical_dir, interface)?;
        let Some(previous) = read_secret_bytes(&target)? else {
            return Ok(());
        };

        if let Err(error) = atomic_file::remove_durable(&target) {
            return restore_after_store_failure(&target, Some(previous.as_slice()), error);
        }
        Ok(())
    }
}

/// Run after legacy transaction recovery and before starting any Wi-Fi consumer.
/// There is intentionally no legacy fallback in role-specific stores.
pub async fn migrate_legacy_passphrases(config: &crate::config::AppConfig) -> anyhow::Result<()> {
    let config = config.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let state_dir = &config.runtime.state_dir;
        let legacy = PassphraseStore::new(state_dir.join("wifi/psk"));
        match fs::symlink_metadata(legacy.directory()) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        let directory = legacy.ensure_directory()?;
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let interface = entry.file_name().into_string()
                .map_err(|_| anyhow::anyhow!("invalid legacy Wi-Fi credential filename"))?;
            validate_interface_name(&interface)?;
            // Unresolved old journals must restore their legacy secret first.
            if crate::core::recovery::check_scope(state_dir, Some(&interface)).is_err() {
                continue;
            }
            let Some(secret) = legacy.get(&interface)? else { continue };
            let role = config.network.interfaces.get(&interface)
                .and_then(WifiCredentialRole::from_config);
            let destination = match role {
                Some(role) => PassphraseStore::for_role(state_dir, role),
                None => PassphraseStore::new(state_dir.join("wifi/psk-unassigned")),
            };
            if let Some(existing) = destination.get(&interface)? {
                anyhow::ensure!(existing.expose() == secret.expose(),
                    "conflicting legacy and role-specific Wi-Fi credentials for {interface}; migration requires resolution");
            } else {
                destination.set(&interface, &secret)?;
            }
            // Copy is durable before retiring the source. A crash between the
            // two operations is replayed by the equality check above.
            legacy.clear(&interface)?;
        }
        Ok(())
    }).await??;
    Ok(())
}

fn read_secret_bytes(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, PassphraseStoreError> {
    let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let raw_fd = match open(path, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::ENOENT) => return Ok(None),
        Err(Errno::ELOOP) => return Err(PassphraseStoreError::SymlinkRejected(path.to_path_buf())),
        Err(error) => return Err(error.into()),
    };

    let mut file = unsafe { File::from_raw_fd(raw_fd) };
    let mut bytes = Zeroizing::new(Vec::new());
    file.read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

fn restore_after_store_failure(
    path: &Path,
    previous: Option<&[u8]>,
    operation: std::io::Error,
) -> Result<(), PassphraseStoreError> {
    let rollback = match previous {
        Some(previous) => atomic_file::replace(path, previous, PRIVATE_FILE_MODE).map(|_| ()),
        None => atomic_file::remove_durable(path).map(|_| ()),
    };
    match rollback {
        Ok(()) => Err(PassphraseStoreError::Io(operation)),
        Err(rollback) => Err(PassphraseStoreError::RollbackFailed {
            operation: operation.to_string(),
            rollback: rollback.to_string(),
        }),
    }
}

#[derive(Debug, Error)]
pub enum ResolvePassphraseError {
    #[error(transparent)]
    Store(#[from] PassphraseStoreError),

    #[error("failed to read Wi-Fi passphrase_file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("refusing to follow symlink at {0}")]
    SymlinkRejected(PathBuf),

    #[error("Wi-Fi passphrase_file {0} must not be readable by group or other (chmod 600)")]
    InsecurePermissions(PathBuf),

    #[error("Wi-Fi passphrase_file {0} is empty")]
    Empty(PathBuf),

    #[error(transparent)]
    Passphrase(#[from] PassphraseError),
}
pub fn resolve_passphrase(
    spec: &WifiApSpec,
    store: &PassphraseStore,
) -> Result<Option<WifiPassphrase>, ResolvePassphraseError> {
    if spec.security == WifiSecurity::Open {
        return Ok(None);
    }
    resolve_passphrase_parts(&spec.interface, spec.passphrase_file.as_deref(), store)
}

pub fn resolve_passphrase_parts(
    interface: &str,
    passphrase_file: Option<&Path>,
    store: &PassphraseStore,
) -> Result<Option<WifiPassphrase>, ResolvePassphraseError> {
    if let Some(passphrase) = store.get(interface)? {
        return Ok(Some(passphrase));
    }
    let Some(path) = passphrase_file else {
        return Ok(None);
    };
    Ok(Some(read_passphrase_file(path)?))
}

fn read_passphrase_file(path: &Path) -> Result<WifiPassphrase, ResolvePassphraseError> {
    let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let raw_fd = match open(path, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::ELOOP) => {
            return Err(ResolvePassphraseError::SymlinkRejected(path.to_path_buf()))
        }
        Err(error) => {
            return Err(ResolvePassphraseError::Io {
                path: path.to_path_buf(),
                source: std::io::Error::from(error),
            })
        }
    };

    let mut file = unsafe { File::from_raw_fd(raw_fd) };

    let metadata = file
        .metadata()
        .map_err(|source| ResolvePassphraseError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(ResolvePassphraseError::InsecurePermissions(
            path.to_path_buf(),
        ));
    }

    let mut contents = Zeroizing::new(String::new());
    file.read_to_string(&mut contents)
        .map_err(|source| ResolvePassphraseError::Io {
            path: path.to_path_buf(),
            source,
        })?;

    let first_line = contents
        .split('\n')
        .next()
        .unwrap_or("")
        .trim_end_matches('\r');
    if first_line.is_empty() {
        return Err(ResolvePassphraseError::Empty(path.to_path_buf()));
    }
    Ok(WifiPassphrase::new(first_line)?)
}

#[cfg(test)]
mod tests;
