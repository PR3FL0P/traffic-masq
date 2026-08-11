use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::fs::{self, File};
use tokio::io::AsyncWriteExt;

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

        let content = serde_json::to_vec_pretty(leases)?;
        let temporary = temporary_path(&self.path);
        let mut file = File::create(&temporary).await.with_context(|| {
            format!(
                "failed to create temporary lease file {}",
                temporary.display()
            )
        })?;
        file.write_all(&content).await?;
        file.write_all(b"\n").await?;
        file.flush().await?;
        file.sync_all().await?;
        drop(file);

        fs::rename(&temporary, &self.path).await.with_context(|| {
            format!(
                "failed to atomically replace lease file {} with {}",
                self.path.display(),
                temporary.display()
            )
        })?;

        sync_directory(parent).await?;

        Ok(())
    }
}

async fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .await
        .with_context(|| format!("failed to open lease directory {}", path.display()))?
        .sync_all()
        .await
        .with_context(|| format!("failed to sync lease directory {}", path.display()))
}

fn temporary_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("leases.json");
    path.with_file_name(format!(".{file_name}.tmp-{}", std::process::id()))
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
