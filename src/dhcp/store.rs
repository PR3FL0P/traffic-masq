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
        atomic_file::create_dir_all_durable_async(parent)
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
mod tests;
