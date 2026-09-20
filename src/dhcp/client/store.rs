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

    pub fn interfaces(&self) -> Result<Vec<String>, LeaseStoreError> {
        self.documents.keys().map_err(Into::into)
    }
}

#[cfg(test)]
mod tests;
