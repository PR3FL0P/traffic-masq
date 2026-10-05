use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::fs;

use crate::atomic_file::{self, PRIVATE_FILE_MODE};

pub const CURRENT_ACTIVE_PROFILE_SCHEMA: u32 = 1;
pub const CURRENT_ACTIVATION_INTENT_SCHEMA: u32 = 1;

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

    #[error(
        "persisted VPN activation intent {0} uses unsupported schema version {1} (current is {CURRENT_ACTIVATION_INTENT_SCHEMA})"
    )]
    UnsupportedActivationIntentSchema(PathBuf, u32),

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedActivationIntentDocument {
    schema_version: u32,
    profile_name: String,
    interface: String,
    launch_marker: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedActivationIntent {
    pub profile_name: String,
    pub interface: String,
    pub launch_marker: String,
}

#[derive(Debug, Clone)]
pub struct ActivationIntentStore {
    path: PathBuf,
}

impl ActivationIntentStore {
    pub fn for_active_profile(active: &ActiveProfileStore) -> Self {
        Self {
            path: active.path.with_extension("intent.json"),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn load(&self) -> Result<Option<PersistedActivationIntent>, ActiveProfileError> {
        let content = match fs::read(&self.path).await {
            Ok(content) => content,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(ActiveProfileError::Read(self.path.clone(), error)),
        };

        let document: PersistedActivationIntentDocument = serde_json::from_slice(&content)
            .map_err(|error| ActiveProfileError::Parse(self.path.clone(), error))?;
        if document.schema_version != CURRENT_ACTIVATION_INTENT_SCHEMA {
            return Err(ActiveProfileError::UnsupportedActivationIntentSchema(
                self.path.clone(),
                document.schema_version,
            ));
        }

        Ok(Some(PersistedActivationIntent {
            profile_name: document.profile_name,
            interface: document.interface,
            launch_marker: document.launch_marker,
        }))
    }

    pub async fn save(&self, intent: &PersistedActivationIntent) -> Result<(), ActiveProfileError> {
        if let Some(parent) = self.path.parent() {
            atomic_file::create_dir_all_durable_async(parent)
                .await
                .map_err(|error| ActiveProfileError::Write(self.path.clone(), error))?;
        }

        let document = PersistedActivationIntentDocument {
            schema_version: CURRENT_ACTIVATION_INTENT_SCHEMA,
            profile_name: intent.profile_name.clone(),
            interface: intent.interface.clone(),
            launch_marker: intent.launch_marker.clone(),
        };
        let mut content = serde_json::to_vec_pretty(&document)
            .expect("PersistedActivationIntentDocument serialization is infallible");
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
            atomic_file::create_dir_all_durable_async(parent)
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
mod tests;
