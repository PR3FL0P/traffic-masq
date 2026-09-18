use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::fs;

use crate::atomic_file::{self, PRIVATE_FILE_MODE};
use crate::dhcp::lease::DhcpLease;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseStore {
    path: PathBuf,
}

impl LeaseStore {
    pub fn for_interface(directory: impl AsRef<Path>, interface: &str) -> Self {
        Self {
            path: directory.as_ref().join(format!("{interface}.json")),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn load(&self) -> Result<Vec<DhcpLease>> {
        let content = match fs::read(&self.path).await {
            Ok(content) => content,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read lease file {}", self.path.display()))
            }
        };

        serde_json::from_slice(&content)
            .with_context(|| format!("failed to parse lease file {}", self.path.display()))
    }

    pub async fn save(&self, leases: &[DhcpLease]) -> Result<()> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("lease path has no parent: {}", self.path.display()))?;
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create lease directory {}", parent.display()))?;

        let mut content = serde_json::to_vec_pretty(leases)?;
        content.push(b'\n');

        atomic_file::replace_preserving_on_error_async(&self.path, &content, PRIVATE_FILE_MODE)
            .await
            .with_context(|| format!("failed to replace lease file {}", self.path.display()))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tempfile::tempdir;

    use super::*;

    #[tokio::test]
    async fn saves_and_loads_leases_atomically() {
        let directory = tempdir().expect("tempdir");
        let store = LeaseStore::for_interface(directory.path(), "wlan0");
        let leases = vec![DhcpLease {
            mac: [1, 2, 3, 4, 5, 6],
            ip: Ipv4Addr::new(192, 168, 10, 100),
            expires_at_unix: 123_456,
        }];

        store.save(&leases).await.expect("save");
        assert!(store.path().exists());
        assert_eq!(store.load().await.expect("load"), leases);
    }

    #[tokio::test]
    async fn missing_lease_file_loads_as_empty() {
        let directory = tempdir().expect("tempdir");
        let store = LeaseStore::for_interface(directory.path(), "wlan0");
        assert!(store.load().await.expect("load").is_empty());
    }
}
