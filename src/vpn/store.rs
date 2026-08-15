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

        // Atomic, where this used to open the target with O_TRUNC: a crash
        // mid-import left a truncated profile that would fail to parse on the
        // next read.
        atomic_file::replace(&target, raw, PRIVATE_FILE_MODE)?;

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

        let mut raw = Vec::new();
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

        fs::remove_file(&target)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{symlink, PermissionsExt};

    use tempfile::tempdir;

    use super::*;

    const VALID_PRIVATE_KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const VALID_PUBLIC_KEY: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

    fn valid_config() -> String {
        format!(
            "[Interface]\n\
             PrivateKey = {VALID_PRIVATE_KEY}\n\
             Address = 10.0.0.2/24\n\
             \n\
             [Peer]\n\
             PublicKey = {VALID_PUBLIC_KEY}\n\
             AllowedIPs = 0.0.0.0/0\n\
             Endpoint = 203.0.113.1:51820\n"
        )
    }

    #[test]
    fn import_creates_file_with_expected_mode_and_contents() {
        let dir = tempdir().expect("tempdir");
        let store_dir = dir.path().join("wireguard");
        let store = WireGuardProfileStore::new(&store_dir);
        let driver = WireGuardDriver;

        let raw = valid_config();
        let profile = store
            .import(&driver, "home.conf", raw.as_bytes())
            .expect("import should succeed");
        assert_eq!(profile.name, "home.conf");

        let file_path = store_dir.join("home.conf");
        assert!(file_path.exists());

        let contents = fs::read(&file_path).expect("read imported file");
        assert_eq!(contents, raw.as_bytes());

        let file_mode = fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);

        let dir_mode = fs::metadata(&store_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
    }

    #[test]
    fn import_rejects_path_traversal_in_name() {
        let dir = tempdir().expect("tempdir");
        let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
        let driver = WireGuardDriver;

        let err = store
            .import(&driver, "../escape.conf", valid_config().as_bytes())
            .unwrap_err();
        assert!(matches!(err, StoreError::Profile(_)));

        assert!(!dir.path().join("escape.conf").exists());
    }

    #[test]
    fn import_refuses_to_follow_preexisting_symlink_at_target() {
        let dir = tempdir().expect("tempdir");
        let store_dir = dir.path().join("wireguard");
        fs::create_dir_all(&store_dir).unwrap();
        fs::set_permissions(&store_dir, fs::Permissions::from_mode(0o700)).unwrap();

        let outside_target = dir.path().join("outside-secret.conf");

        let link_path = store_dir.join("evil.conf");
        symlink(&outside_target, &link_path).expect("create symlink");

        let store = WireGuardProfileStore::new(&store_dir);
        let driver = WireGuardDriver;

        let err = store
            .import(&driver, "evil.conf", valid_config().as_bytes())
            .unwrap_err();
        assert!(matches!(err, StoreError::SymlinkRejected(_)));

        assert!(!outside_target.exists());

        assert!(fs::symlink_metadata(&link_path)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn import_rejects_symlinked_store_directory() {
        let dir = tempdir().expect("tempdir");
        let real_dir = dir.path().join("real");
        fs::create_dir_all(&real_dir).unwrap();
        let link_dir = dir.path().join("link");
        symlink(&real_dir, &link_dir).expect("create dir symlink");

        let store = WireGuardProfileStore::new(&link_dir);
        let driver = WireGuardDriver;
        let err = store
            .import(&driver, "home.conf", valid_config().as_bytes())
            .unwrap_err();
        assert!(matches!(err, StoreError::SymlinkRejected(_)));
    }

    #[test]
    fn list_returns_safe_metadata_without_secrets() {
        let dir = tempdir().expect("tempdir");
        let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
        let driver = WireGuardDriver;

        store
            .import(&driver, "a.conf", valid_config().as_bytes())
            .unwrap();
        store
            .import(&driver, "b.conf", valid_config().as_bytes())
            .unwrap();

        let summaries = store.list().expect("list");
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].name, "a.conf");
        assert_eq!(summaries[1].name, "b.conf");
        assert!(summaries[0].size_bytes > 0);

        for summary in &summaries {
            let debug = format!("{summary:?}");
            assert!(!debug.contains(VALID_PRIVATE_KEY));
        }
    }

    #[test]
    fn list_ignores_symlinks_inside_store_directory() {
        let dir = tempdir().expect("tempdir");
        let store_dir = dir.path().join("wireguard");
        let store = WireGuardProfileStore::new(&store_dir);
        let driver = WireGuardDriver;

        store
            .import(&driver, "real.conf", valid_config().as_bytes())
            .unwrap();

        let outside = dir.path().join("outside.conf");
        fs::write(&outside, valid_config()).unwrap();
        symlink(&outside, store_dir.join("linked.conf")).unwrap();

        let summaries = store.list().expect("list");
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].name, "real.conf");
    }

    #[test]
    fn delete_removes_only_files_inside_store() {
        let dir = tempdir().expect("tempdir");
        let store_dir = dir.path().join("wireguard");
        let store = WireGuardProfileStore::new(&store_dir);
        let driver = WireGuardDriver;

        store
            .import(&driver, "home.conf", valid_config().as_bytes())
            .unwrap();
        assert!(store_dir.join("home.conf").exists());

        store.delete("home.conf").expect("delete");
        assert!(!store_dir.join("home.conf").exists());

        let err = store.delete("home.conf").unwrap_err();
        assert!(matches!(err, StoreError::NotFound(_)));
    }

    #[test]
    fn delete_rejects_path_traversal_and_leaves_outside_file_untouched() {
        let dir = tempdir().expect("tempdir");
        let store_dir = dir.path().join("wireguard");
        fs::create_dir_all(&store_dir).unwrap();

        let outside = dir.path().join("victim.conf");
        fs::write(&outside, "do-not-delete-me").unwrap();

        let store = WireGuardProfileStore::new(&store_dir);
        let err = store.delete("../victim.conf").unwrap_err();
        assert!(matches!(err, StoreError::Profile(_)));
        assert!(outside.exists());
    }

    #[test]
    fn delete_refuses_to_remove_symlink_even_if_target_name_matches() {
        let dir = tempdir().expect("tempdir");
        let store_dir = dir.path().join("wireguard");
        fs::create_dir_all(&store_dir).unwrap();

        let outside = dir.path().join("outside.conf");
        fs::write(&outside, "sensitive").unwrap();
        symlink(&outside, store_dir.join("linked.conf")).unwrap();

        let store = WireGuardProfileStore::new(&store_dir);
        let err = store.delete("linked.conf").unwrap_err();
        assert!(matches!(err, StoreError::SymlinkRejected(_)));
        assert!(outside.exists());
        assert!(fs::symlink_metadata(store_dir.join("linked.conf"))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn read_round_trips_imported_profile() {
        let dir = tempdir().expect("tempdir");
        let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
        let driver = WireGuardDriver;

        store
            .import(&driver, "home.conf", valid_config().as_bytes())
            .unwrap();

        let profile = store.read(&driver, "home.conf").expect("read");
        assert_eq!(profile.name, "home.conf");
        assert_eq!(profile.peers.len(), 1);
    }

    #[test]
    fn read_missing_profile_is_not_found() {
        let dir = tempdir().expect("tempdir");
        let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
        let driver = WireGuardDriver;
        let err = store.read(&driver, "missing.conf").unwrap_err();
        assert!(matches!(err, StoreError::NotFound(_)));
    }

    #[test]
    fn ensure_directory_rejects_symlinked_directory_on_list() {
        let dir = tempdir().expect("tempdir");
        let real_dir = dir.path().join("real");
        fs::create_dir_all(&real_dir).unwrap();
        let link_dir = dir.path().join("link");
        symlink(&real_dir, &link_dir).unwrap();

        let store = WireGuardProfileStore::new(&link_dir);
        let err = store.list().unwrap_err();
        assert!(matches!(err, StoreError::SymlinkRejected(_)));
    }
}
