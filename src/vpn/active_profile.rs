use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::fs;

use crate::atomic_file::{self, PRIVATE_FILE_MODE};

pub const CURRENT_ACTIVE_PROFILE_SCHEMA: u32 = 1;

#[derive(Debug, Error)]
pub enum ActiveProfileError {
    #[error("failed to read persisted active profile {0}: {1}")]
    Read(PathBuf, std::io::Error),

    #[error("failed to parse persisted active profile {0}: {1}")]
    Parse(PathBuf, serde_json::Error),

    #[error(
        "persisted active profile {0} uses unsupported schema version {1} (current is {CURRENT_ACTIVE_PROFILE_SCHEMA})"
    )]
    UnsupportedSchema(PathBuf, u32),

    #[error("failed to write persisted active profile {0}: {1}")]
    Write(PathBuf, std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedActiveProfileDocument {
    schema_version: u32,
    profile_name: String,
    interface: String,
    ownership_proof_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedActiveProfile {
    pub profile_name: String,
    pub interface: String,
    pub ownership_proof_base64: String,
}

#[derive(Debug, Clone)]
pub struct ActiveProfileStore {
    path: PathBuf,
}

impl ActiveProfileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// A per-hop store, keyed by filename `active-profile-<hop_index>.json`
    /// inside `dir`. No schema change is needed to generalize from a single
    /// tunnel to a chain — only the path used to construct the store, one
    /// per hop.
    pub fn for_hop(dir: impl AsRef<Path>, hop_index: u32) -> Self {
        Self::new(
            dir.as_ref()
                .join(format!("active-profile-{hop_index}.json")),
        )
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn load(&self) -> Result<Option<PersistedActiveProfile>, ActiveProfileError> {
        let content = match fs::read(&self.path).await {
            Ok(content) => content,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(ActiveProfileError::Read(self.path.clone(), error)),
        };

        let document: PersistedActiveProfileDocument = serde_json::from_slice(&content)
            .map_err(|error| ActiveProfileError::Parse(self.path.clone(), error))?;

        if document.schema_version != CURRENT_ACTIVE_PROFILE_SCHEMA {
            return Err(ActiveProfileError::UnsupportedSchema(
                self.path.clone(),
                document.schema_version,
            ));
        }

        Ok(Some(PersistedActiveProfile {
            profile_name: document.profile_name,
            interface: document.interface,
            ownership_proof_base64: document.ownership_proof_base64,
        }))
    }

    pub async fn save(&self, record: &PersistedActiveProfile) -> Result<(), ActiveProfileError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|error| ActiveProfileError::Write(self.path.clone(), error))?;
        }

        let document = PersistedActiveProfileDocument {
            schema_version: CURRENT_ACTIVE_PROFILE_SCHEMA,
            profile_name: record.profile_name.clone(),
            interface: record.interface.clone(),
            ownership_proof_base64: record.ownership_proof_base64.clone(),
        };
        let mut content = serde_json::to_vec_pretty(&document)
            .expect("PersistedActiveProfileDocument serialization is infallible");
        content.push(b'\n');

        atomic_file::replace_preserving_on_error_async(&self.path, &content, PRIVATE_FILE_MODE)
            .await
            .map_err(|error| ActiveProfileError::Write(self.path.clone(), error))
    }

    pub async fn clear(&self) -> Result<(), ActiveProfileError> {
        atomic_file::remove_preserving_on_error_async(&self.path, PRIVATE_FILE_MODE)
            .await
            .map(|_| ())
            .map_err(|error| ActiveProfileError::Write(self.path.clone(), error))
    }
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use tempfile::tempdir;

    use super::*;

    fn proof(seed: u8) -> String {
        BASE64.encode([seed; 32])
    }

    #[tokio::test]
    async fn missing_file_loads_as_none() {
        let directory = tempdir().expect("tempdir");
        let store = ActiveProfileStore::new(directory.path().join("active-profile.json"));

        assert_eq!(store.load().await.expect("load"), None);
    }

    #[tokio::test]
    async fn save_then_load_round_trips() {
        let directory = tempdir().expect("tempdir");
        let store = ActiveProfileStore::new(directory.path().join("active-profile.json"));
        let record = PersistedActiveProfile {
            profile_name: "home.conf".to_string(),
            interface: "tm-wg0".to_string(),
            ownership_proof_base64: proof(7),
        };

        store.save(&record).await.expect("save");
        let loaded = store.load().await.expect("load").expect("record present");

        assert_eq!(loaded, record);
    }

    #[tokio::test]
    async fn save_overwrites_previous_record() {
        let directory = tempdir().expect("tempdir");
        let store = ActiveProfileStore::new(directory.path().join("active-profile.json"));
        store
            .save(&PersistedActiveProfile {
                profile_name: "home.conf".to_string(),
                interface: "tm-wg0".to_string(),
                ownership_proof_base64: proof(1),
            })
            .await
            .expect("save first");
        store
            .save(&PersistedActiveProfile {
                profile_name: "office.conf".to_string(),
                interface: "tm-wg0".to_string(),
                ownership_proof_base64: proof(2),
            })
            .await
            .expect("save second");

        let loaded = store.load().await.expect("load").expect("record present");
        assert_eq!(loaded.profile_name, "office.conf");
        assert_eq!(loaded.ownership_proof_base64, proof(2));
    }

    #[tokio::test]
    async fn clear_removes_record_and_is_idempotent() {
        let directory = tempdir().expect("tempdir");
        let store = ActiveProfileStore::new(directory.path().join("active-profile.json"));
        store
            .save(&PersistedActiveProfile {
                profile_name: "home.conf".to_string(),
                interface: "tm-wg0".to_string(),
                ownership_proof_base64: proof(3),
            })
            .await
            .expect("save");

        store.clear().await.expect("clear");
        assert_eq!(store.load().await.expect("load"), None);

        store.clear().await.expect("clear again");
    }

    #[tokio::test]
    async fn rejects_unsupported_schema_version() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("active-profile.json");
        tokio::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 99,
                "profile_name": "home.conf",
                "interface": "tm-wg0",
                "ownership_proof_base64": proof(4),
            }))
            .unwrap(),
        )
        .await
        .unwrap();
        let store = ActiveProfileStore::new(path);

        let error = store.load().await.expect_err("unsupported schema");
        assert!(matches!(
            error,
            ActiveProfileError::UnsupportedSchema(_, 99)
        ));
    }
}
