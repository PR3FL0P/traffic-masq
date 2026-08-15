use std::{io, path::Path};

use crate::dhcp::client::lease::DhcpClientLease;
use crate::state::private_store::{PrivateJsonDirectory, PrivateStoreError};

#[derive(Debug, thiserror::Error)]
pub enum LeaseStoreError {
    #[error("invalid interface name")]
    InvalidInterface,
    #[error("unsafe symlink at {0}")]
    Symlink(std::path::PathBuf),
    #[error("unsupported DHCP lease schema version {0}")]
    UnsupportedSchema(u32),
    #[error("invalid DHCP lease: {0}")]
    InvalidLease(String),
    #[error("lease store I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid lease document: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<PrivateStoreError> for LeaseStoreError {
    fn from(error: PrivateStoreError) -> Self {
        match error {
            PrivateStoreError::InvalidKey => Self::InvalidInterface,
            PrivateStoreError::Symlink(path) => Self::Symlink(path),
            PrivateStoreError::Io(error) => Self::Io(error),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DhcpClientLeaseStore {
    documents: PrivateJsonDirectory,
}

impl DhcpClientLeaseStore {
    pub fn new(state_root: impl AsRef<Path>) -> Result<Self, LeaseStoreError> {
        Ok(Self {
            documents: PrivateJsonDirectory::open(state_root, "dhcp-client")?,
        })
    }

    pub fn directory(&self) -> &Path {
        self.documents.directory()
    }

    pub fn load(&self, interface: &str) -> Result<Option<DhcpClientLease>, LeaseStoreError> {
        let Some(bytes) = self.documents.read(interface)? else {
            return Ok(None);
        };
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
        let mut document = serde_json::to_vec_pretty(lease)?;
        document.push(b'\n');
        self.documents.write(&lease.interface, &document)?;
        Ok(())
    }

    pub fn remove(&self, interface: &str) -> Result<(), LeaseStoreError> {
        self.documents.remove(interface)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
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
