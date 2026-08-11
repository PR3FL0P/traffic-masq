use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::dhcp::client::lease::{valid_interface_name, DhcpClientLease};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, thiserror::Error)]
pub enum LeaseStoreError {
    #[error("invalid interface name")]
    InvalidInterface,
    #[error("unsafe symlink at {0}")]
    Symlink(PathBuf),
    #[error("unsupported DHCP lease schema version {0}")]
    UnsupportedSchema(u32),
    #[error("invalid DHCP lease: {0}")]
    InvalidLease(String),
    #[error("lease store I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid lease document: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone)]
pub struct DhcpClientLeaseStore {
    directory: PathBuf,
}

impl DhcpClientLeaseStore {
    pub fn new(state_root: impl AsRef<Path>) -> Result<Self, LeaseStoreError> {
        let root = state_root.as_ref();
        reject_symlink(root)?;
        fs::create_dir_all(root)?;
        reject_symlink(root)?;
        let directory = root.join("dhcp-client");
        if directory.exists() {
            reject_symlink(&directory)?;
            if !directory.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    format!("{} is not a directory", directory.display()),
                )
                .into());
            }
        } else {
            fs::create_dir(&directory)?;
        }
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        Ok(Self { directory })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn load(&self, interface: &str) -> Result<Option<DhcpClientLease>, LeaseStoreError> {
        let path = self.path(interface)?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(LeaseStoreError::Symlink(path))
            }
            Ok(metadata) if !metadata.is_file() => {
                return Err(
                    io::Error::new(io::ErrorKind::InvalidData, "lease path is not a file").into(),
                )
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        let bytes = fs::read(path)?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        let schema = value
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        if schema != 1 {
            return Err(LeaseStoreError::UnsupportedSchema(schema as u32));
        }
        let lease: DhcpClientLease = serde_json::from_value(value)?;
        lease
            .validate()
            .map_err(|error| LeaseStoreError::InvalidLease(error.to_string()))?;
        if lease.interface != interface {
            return Err(LeaseStoreError::InvalidLease(
                "document/interface filename mismatch".into(),
            ));
        }
        Ok(Some(lease))
    }

    pub fn save(&self, lease: &DhcpClientLease) -> Result<(), LeaseStoreError> {
        lease.validate().map_err(|error| match error {
            crate::dhcp::client::lease::LeaseValidationError::UnsupportedSchema(version) => {
                LeaseStoreError::UnsupportedSchema(version)
            }
            other => LeaseStoreError::InvalidLease(other.to_string()),
        })?;
        let destination = self.path(&lease.interface)?;
        reject_existing_symlink(&destination)?;
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = self.directory.join(format!(
            ".{}.{}.{}.tmp",
            lease.interface,
            std::process::id(),
            sequence
        ));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .open(&temporary)?;
            serde_json::to_writer_pretty(&mut file, lease)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            reject_existing_symlink(&destination)?;
            fs::rename(&temporary, &destination)?;
            fs::set_permissions(&destination, fs::Permissions::from_mode(0o600))?;
            File::open(&self.directory)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    pub fn remove(&self, interface: &str) -> Result<(), LeaseStoreError> {
        let path = self.path(interface)?;
        reject_existing_symlink(&path)?;
        match fs::remove_file(path) {
            Ok(()) => File::open(&self.directory)?.sync_all()?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn path(&self, interface: &str) -> Result<PathBuf, LeaseStoreError> {
        if !valid_interface_name(interface) {
            return Err(LeaseStoreError::InvalidInterface);
        }
        Ok(self.directory.join(format!("{interface}.json")))
    }
}

fn reject_symlink(path: &Path) -> Result<(), LeaseStoreError> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(LeaseStoreError::Symlink(path.to_path_buf()));
        }
    }
    Ok(())
}

fn reject_existing_symlink(path: &Path) -> Result<(), LeaseStoreError> {
    reject_symlink(path)
}

#[cfg(test)]
mod tests {
    use std::{
        net::Ipv4Addr,
        os::unix::fs::{symlink, MetadataExt},
    };

    use tempfile::tempdir;

    use super::*;
    use crate::dhcp::client::lease::{DhcpClientLeaseState, DHCP_CLIENT_LEASE_SCHEMA_VERSION};

    fn lease() -> DhcpClientLease {
        DhcpClientLease {
            schema_version: DHCP_CLIENT_LEASE_SCHEMA_VERSION,
            state: DhcpClientLeaseState::PendingApply,
            interface: "eth0".into(),
            interface_index: 2,
            hardware_address: vec![2, 0, 0, 0, 0, 1],
            client_identifier: vec![1, 2, 0, 0, 0, 0, 1],
            server_identifier: Ipv4Addr::new(192, 0, 2, 1),
            address: Ipv4Addr::new(192, 0, 2, 20),
            prefix_len: 24,
            routers: vec![Ipv4Addr::new(192, 0, 2, 1)],
            dns_servers: vec![Ipv4Addr::new(192, 0, 2, 53)],
            lease_seconds: 3600,
            renewal_seconds: 1800,
            rebinding_seconds: 3150,
            expires_at_unix: 10_000,
            owned_routes: vec![],
        }
    }

    #[test]
    fn creates_private_directory_and_atomic_private_file_and_overwrites() {
        let root = tempdir().unwrap();
        let store = DhcpClientLeaseStore::new(root.path()).unwrap();
        assert_eq!(
            fs::metadata(store.directory()).unwrap().mode() & 0o777,
            0o700
        );
        let mut expected = lease();
        store.save(&expected).unwrap();
        let path = store.directory().join("eth0.json");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        expected.state = DhcpClientLeaseState::Bound;
        store.save(&expected).unwrap();
        assert_eq!(store.load("eth0").unwrap(), Some(expected));
        assert!(fs::read_dir(store.directory()).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")));
    }

    #[test]
    fn rejects_traversal_symlinks_and_unsupported_schema() {
        let root = tempdir().unwrap();
        let store = DhcpClientLeaseStore::new(root.path()).unwrap();
        assert!(matches!(
            store.load("../eth0"),
            Err(LeaseStoreError::InvalidInterface)
        ));
        let target = root.path().join("target");
        fs::write(&target, b"do not replace").unwrap();
        symlink(&target, store.directory().join("eth0.json")).unwrap();
        assert!(matches!(
            store.save(&lease()),
            Err(LeaseStoreError::Symlink(_))
        ));
        assert_eq!(fs::read(&target).unwrap(), b"do not replace");
        fs::remove_file(store.directory().join("eth0.json")).unwrap();
        fs::write(
            store.directory().join("eth0.json"),
            br#"{"schema_version":99}"#,
        )
        .unwrap();
        assert!(matches!(
            store.load("eth0"),
            Err(LeaseStoreError::UnsupportedSchema(99))
        ));
    }

    #[test]
    fn rejects_symlinked_store_directory() {
        let root = tempdir().unwrap();
        let elsewhere = tempdir().unwrap();
        symlink(elsewhere.path(), root.path().join("dhcp-client")).unwrap();
        assert!(matches!(
            DhcpClientLeaseStore::new(root.path()),
            Err(LeaseStoreError::Symlink(_))
        ));
    }
}
