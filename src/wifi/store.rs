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

    /// Allocate an immutable credential version; callers atomically commit its path in intent.
    pub fn new_revision(state_dir: &Path) -> Result<Self, PassphraseStoreError> {
        use std::os::unix::fs::DirBuilderExt;
        let parent = state_dir.join("wifi/credential-revisions");
        atomic_file::ensure_private_dir(&parent, PRIVATE_DIR_MODE)?;
        for _ in 0..16 {
            let directory = parent.join(format!("{:032x}", rand::random::<u128>()));
            match fs::DirBuilder::new()
                .mode(PRIVATE_DIR_MODE)
                .create(&directory)
            {
                Ok(()) => {
                    File::open(&parent)?.sync_all()?;
                    return Ok(Self::new(fs::canonicalize(directory)?));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate unique credential version",
        )
        .into())
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

    /// Write this role-specific interface secret at mode 0600 in a private 0700
    /// directory, replacing any previous secret. Reject unsafe names and symlinks.
    /// A write failure attempts to restore prior bytes; RollbackFailed means the
    /// durable outcome is uncertain. Callers must serialize writes.
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

    /// Read a secret, returning None for an absent file. May create the private
    /// directory and repair its mode to 0700 even on a read. Reject symlinks,
    /// invalid names, invalid passphrases and I/O failures; never log the result.
    pub fn get(&self, interface: &str) -> Result<Option<WifiPassphrase>, PassphraseStoreError> {
        let canonical_dir = self.ensure_directory()?;
        let target = self.safe_target(&canonical_dir, interface)?;

        let Some(mut file) = open_secret_file(&target)? else {
            return Ok(None);
        };

        let mut contents = Zeroizing::new(String::new());
        file.read_to_string(&mut contents)?;
        Ok(Some(WifiPassphrase::new(contents.as_str())?))
    }

    /// Durably remove a secret; an absent file succeeds. May create/chmod the
    /// private directory. Reject symlinks and invalid names. Removal errors attempt
    /// restoration; RollbackFailed reports failed compensation.
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

fn open_secret_file(path: &Path) -> Result<Option<File>, PassphraseStoreError> {
    let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let raw_fd = match open(path, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::ENOENT) => return Ok(None),
        Err(Errno::ELOOP) => return Err(PassphraseStoreError::SymlinkRejected(path.to_path_buf())),
        Err(error) => return Err(error.into()),
    };
    Ok(Some(unsafe { File::from_raw_fd(raw_fd) }))
}

fn read_secret_bytes(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, PassphraseStoreError> {
    let Some(mut file) = open_secret_file(path)? else {
        return Ok(None);
    };
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
/// Return None for open APs; otherwise resolve the role-specific store first,
/// then the configured file. Reading the store may create/chmod its directory.
/// Returned credentials are secret; invalid values and unsafe files are errors.
pub fn resolve_passphrase(
    spec: &WifiApSpec,
    store: &PassphraseStore,
) -> Result<Option<WifiPassphrase>, ResolvePassphraseError> {
    if spec.security == WifiSecurity::Open {
        return Ok(None);
    }
    resolve_passphrase_parts(&spec.interface, spec.passphrase_file.as_deref(), store)
}

/// Prefer the interface secret in the supplied role-specific store to the file.
/// Only fall back to passphrase_file if the store has no secret; None means
/// neither source is configured. Store reads may create/chmod its directory.
/// Reject symlinks, insecure file permissions, invalid passphrases and I/O errors.
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
