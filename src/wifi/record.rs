use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::fs;

use crate::atomic_file::{self, PRIVATE_FILE_MODE};
use crate::wifi::render::WifiDigest;

pub const CURRENT_WIFI_RECORD_SCHEMA: u32 = 1;

#[derive(Debug, Error)]
pub enum WifiRecordError {
    #[error("failed to read persisted Wi-Fi process record {0}: {1}")]
    Read(PathBuf, std::io::Error),

    #[error("failed to parse persisted Wi-Fi process record {0}: {1}")]
    Parse(PathBuf, serde_json::Error),

    #[error(
        "persisted Wi-Fi process record {0} uses unsupported schema version {1} (current is {CURRENT_WIFI_RECORD_SCHEMA})"
    )]
    UnsupportedSchema(PathBuf, u32),

    #[error("failed to write persisted Wi-Fi process record {0}: {1}")]
    Write(PathBuf, std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedWifiRecordDocument {
    schema_version: u32,
    pid: u32,
    started_at_unix: u64,
    ctrl_path: PathBuf,
    config_path: PathBuf,
    config_digest: WifiDigest,
    key_digest: WifiDigest,
    ssid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedWifiRecord {
    pub pid: u32,
    pub started_at_unix: u64,
    pub ctrl_path: PathBuf,
    pub config_path: PathBuf,
    pub config_digest: WifiDigest,
    pub key_digest: WifiDigest,
    pub ssid: String,
}

#[derive(Debug, Clone)]
pub struct WifiRecordStore {
    path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiProcessKind {
    AccessPoint,
    Client,
}

impl WifiProcessKind {
    fn file_prefix(self) -> &'static str {
        match self {
            Self::AccessPoint => "active",
            Self::Client => "active-client",
        }
    }
}

impl WifiRecordStore {
    pub fn new(kind: WifiProcessKind, directory: impl AsRef<Path>, interface: &str) -> Self {
        Self {
            path: directory
                .as_ref()
                .join(format!("{}-{interface}.json", kind.file_prefix())),
        }
    }

    pub fn for_access_point(directory: impl AsRef<Path>, interface: &str) -> Self {
        Self::new(WifiProcessKind::AccessPoint, directory, interface)
    }

    pub fn for_client(directory: impl AsRef<Path>, interface: &str) -> Self {
        Self::new(WifiProcessKind::Client, directory, interface)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn load(&self) -> Result<Option<PersistedWifiRecord>, WifiRecordError> {
        let content = match fs::read(&self.path).await {
            Ok(content) => content,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(WifiRecordError::Read(self.path.clone(), error)),
        };

        let document: PersistedWifiRecordDocument = serde_json::from_slice(&content)
            .map_err(|error| WifiRecordError::Parse(self.path.clone(), error))?;

        if document.schema_version != CURRENT_WIFI_RECORD_SCHEMA {
            return Err(WifiRecordError::UnsupportedSchema(
                self.path.clone(),
                document.schema_version,
            ));
        }

        Ok(Some(PersistedWifiRecord {
            pid: document.pid,
            started_at_unix: document.started_at_unix,
            ctrl_path: document.ctrl_path,
            config_path: document.config_path,
            config_digest: document.config_digest,
            key_digest: document.key_digest,
            ssid: document.ssid,
        }))
    }

    pub async fn save(&self, record: &PersistedWifiRecord) -> Result<(), WifiRecordError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|error| WifiRecordError::Write(self.path.clone(), error))?;
        }

        let document = PersistedWifiRecordDocument {
            schema_version: CURRENT_WIFI_RECORD_SCHEMA,
            pid: record.pid,
            started_at_unix: record.started_at_unix,
            ctrl_path: record.ctrl_path.clone(),
            config_path: record.config_path.clone(),
            config_digest: record.config_digest,
            key_digest: record.key_digest,
            ssid: record.ssid.clone(),
        };
        let mut content = serde_json::to_vec_pretty(&document)
            .expect("PersistedWifiRecordDocument serialization is infallible");
        content.push(b'\n');

        atomic_file::replace_async(&self.path, &content, PRIVATE_FILE_MODE)
            .await
            .map_err(|error| WifiRecordError::Write(self.path.clone(), error))
    }

    pub async fn clear(&self) -> Result<(), WifiRecordError> {
        match fs::remove_file(&self.path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(WifiRecordError::Write(self.path.clone(), error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    fn digest(seed: u8) -> WifiDigest {
        WifiDigest::from_bytes([seed; 32])
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn record(pid: u32) -> PersistedWifiRecord {
        PersistedWifiRecord {
            pid,
            started_at_unix: 1_700_000_000,
            ctrl_path: PathBuf::from("/run/traffic-masq/hostapd/wlan0"),
            config_path: PathBuf::from("/run/traffic-masq/hostapd/wlan0.conf"),
            config_digest: digest(1),
            key_digest: digest(2),
            ssid: "traffic-masq".to_string(),
        }
    }

    #[tokio::test]
    async fn missing_file_loads_as_none() {
        let directory = tempdir().expect("tempdir");
        let store = WifiRecordStore::for_access_point(directory.path(), "wlan0");
        assert_eq!(store.load().await.expect("load"), None);
    }

    #[tokio::test]
    async fn save_then_load_round_trips() {
        let directory = tempdir().expect("tempdir");
        let store = WifiRecordStore::for_access_point(directory.path(), "wlan0");
        let saved = record(1234);

        store.save(&saved).await.expect("save");
        let loaded = store.load().await.expect("load").expect("present");
        assert_eq!(loaded, saved);
    }

    #[tokio::test]
    async fn two_interfaces_get_independent_files() {
        let directory = tempdir().expect("tempdir");
        let wlan0 = WifiRecordStore::for_access_point(directory.path(), "wlan0");
        let wlan1 = WifiRecordStore::for_access_point(directory.path(), "wlan1");

        wlan0.save(&record(1)).await.expect("save wlan0");
        wlan1.save(&record(2)).await.expect("save wlan1");

        assert_ne!(wlan0.path(), wlan1.path());
        assert_eq!(wlan0.load().await.expect("load").unwrap().pid, 1);
        assert_eq!(wlan1.load().await.expect("load").unwrap().pid, 2);
    }

    #[tokio::test]
    async fn save_overwrites_previous_record() {
        let directory = tempdir().expect("tempdir");
        let store = WifiRecordStore::for_access_point(directory.path(), "wlan0");
        store.save(&record(1)).await.expect("save first");
        store.save(&record(2)).await.expect("save second");

        let loaded = store.load().await.expect("load").expect("present");
        assert_eq!(loaded.pid, 2);
    }

    #[tokio::test]
    async fn clear_removes_record_and_is_idempotent() {
        let directory = tempdir().expect("tempdir");
        let store = WifiRecordStore::for_access_point(directory.path(), "wlan0");
        store.save(&record(1)).await.expect("save");

        store.clear().await.expect("clear");
        assert_eq!(store.load().await.expect("load"), None);
        store.clear().await.expect("clear again");
    }

    #[tokio::test]
    async fn rejects_unsupported_schema_version() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("active-wlan0.json");
        tokio::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 99,
                "pid": 1,
                "started_at_unix": 0,
                "ctrl_path": "/run/x",
                "config_path": "/run/x.conf",
                "config_digest": hex_of(&[1; 32]),
                "key_digest": hex_of(&[2; 32]),
                "ssid": "traffic-masq",
            }))
            .unwrap(),
        )
        .await
        .unwrap();

        let store = WifiRecordStore::for_access_point(directory.path(), "wlan0");
        let error = store.load().await.expect_err("unsupported schema");
        assert!(matches!(error, WifiRecordError::UnsupportedSchema(_, 99)));
    }
}
