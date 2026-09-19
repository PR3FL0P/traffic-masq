use std::collections::BTreeSet;
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
    #[error("failed to list persisted Wi-Fi process records in {0}: {1}")]
    List(PathBuf, std::io::Error),

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
    legacy_path: Option<PathBuf>,
    expected_config_stem: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiProcessKind {
    AccessPoint,
    Client,
    Scan,
}

impl WifiProcessKind {
    fn storage_directory(self, directory: &Path) -> PathBuf {
        match self {
            Self::AccessPoint => directory.join("ap"),
            Self::Client => directory.join("client"),
            Self::Scan => directory.join("scan"),
        }
    }

    fn legacy_path(self, directory: &Path, interface: &str) -> Option<PathBuf> {
        match self {
            Self::AccessPoint => Some(directory.join(format!("active-{interface}.json"))),
            Self::Client => Some(directory.join(format!("active-client-{interface}.json"))),
            // Scan records already lived in their own namespace before AP/client
            // records were split, so no migration is required for them.
            Self::Scan => None,
        }
    }

    fn expected_config_stem(self, interface: &str) -> String {
        match self {
            Self::AccessPoint | Self::Client => interface.to_string(),
            Self::Scan => format!("{interface}-scan"),
        }
    }
}

impl WifiRecordStore {
    pub fn new(kind: WifiProcessKind, directory: impl AsRef<Path>, interface: &str) -> Self {
        let base = directory.as_ref();
        Self {
            path: kind
                .storage_directory(base)
                .join(format!("active-{interface}.json")),
            legacy_path: kind.legacy_path(base, interface),
            expected_config_stem: kind.expected_config_stem(interface),
        }
    }

    pub fn for_access_point(directory: impl AsRef<Path>, interface: &str) -> Self {
        Self::new(WifiProcessKind::AccessPoint, directory, interface)
    }

    pub fn for_client(directory: impl AsRef<Path>, interface: &str) -> Self {
        Self::new(WifiProcessKind::Client, directory, interface)
    }

    pub fn for_scan(directory: impl AsRef<Path>, interface: &str) -> Self {
        Self::new(WifiProcessKind::Scan, directory, interface)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn transition_path_for(path: &Path) -> PathBuf {
        path.with_extension("transition")
    }

    fn transition_path(&self) -> PathBuf {
        Self::transition_path_for(&self.path)
    }

    fn record_matches_store(&self, record: &PersistedWifiRecord) -> bool {
        record.config_path.file_stem().and_then(|stem| stem.to_str())
            == Some(self.expected_config_stem.as_str())
    }

    async fn load_path(path: &Path) -> Result<Option<PersistedWifiRecord>, WifiRecordError> {
        let content = match fs::read(path).await {
            Ok(content) => content,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(WifiRecordError::Read(path.to_path_buf(), error)),
        };

        let document: PersistedWifiRecordDocument = serde_json::from_slice(&content)
            .map_err(|error| WifiRecordError::Parse(path.to_path_buf(), error))?;

        if document.schema_version != CURRENT_WIFI_RECORD_SCHEMA {
            return Err(WifiRecordError::UnsupportedSchema(
                path.to_path_buf(),
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

    async fn path_exists(path: &Path) -> Result<bool, WifiRecordError> {
        match fs::metadata(path).await {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
            Err(error) => Err(WifiRecordError::Read(path.to_path_buf(), error)),
        }
    }

    async fn clear_path(path: &Path) -> Result<(), WifiRecordError> {
        atomic_file::remove_preserving_on_error_async(path, PRIVATE_FILE_MODE)
            .await
            .map(|_| ())
            .map_err(|error| WifiRecordError::Write(path.to_path_buf(), error))
    }

    async fn legacy_record(&self) -> Result<Option<PersistedWifiRecord>, WifiRecordError> {
        let Some(path) = self.legacy_path.as_deref() else {
            return Ok(None);
        };
        let Some(record) = Self::load_path(path).await? else {
            return Ok(None);
        };
        Ok(self.record_matches_store(&record).then_some(record))
    }

    async fn clear_matching_legacy(&self) -> Result<(), WifiRecordError> {
        let Some(path) = self.legacy_path.as_deref() else {
            return Ok(());
        };
        let Some(record) = Self::load_path(path).await? else {
            return Ok(());
        };
        if !self.record_matches_store(&record) {
            return Ok(());
        }
        Self::clear_path(path).await?;
        Self::clear_path(&Self::transition_path_for(path)).await
    }

    async fn migrate_legacy(
        &self,
        record: &PersistedWifiRecord,
    ) -> Result<(), WifiRecordError> {
        let legacy = self
            .legacy_path
            .as_deref()
            .expect("legacy migration requires a legacy path");
        if Self::path_exists(&Self::transition_path_for(legacy)).await? {
            self.mark_transition().await?;
        }
        self.save_primary(record).await?;
        self.clear_matching_legacy().await
    }

    pub async fn transition_pending(&self) -> Result<bool, WifiRecordError> {
        let path = self.transition_path();
        if Self::path_exists(&path).await? {
            return Ok(true);
        }

        // A transition can still live under the legacy name until the first
        // ownership read after an upgrade. Only trust it when the associated
        // legacy record proves that it belongs to this exact kind/interface.
        let Some(legacy) = self.legacy_path.as_deref() else {
            return Ok(false);
        };
        if self.legacy_record().await?.is_none() {
            return Ok(false);
        }
        Self::path_exists(&Self::transition_path_for(legacy)).await
    }

    pub async fn mark_transition(&self) -> Result<(), WifiRecordError> {
        let path = self.transition_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|error| WifiRecordError::Write(path.clone(), error))?;
        }
        atomic_file::replace_preserving_on_error_async(&path, b"pending\n", PRIVATE_FILE_MODE)
            .await
            .map_err(|error| WifiRecordError::Write(path, error))
    }

    pub async fn clear_transition(&self) -> Result<(), WifiRecordError> {
        Self::clear_path(&self.transition_path()).await?;
        let Some(legacy) = self.legacy_path.as_deref() else {
            return Ok(());
        };
        if self.legacy_record().await?.is_some() {
            Self::clear_path(&Self::transition_path_for(legacy)).await?;
        }
        Ok(())
    }

    pub async fn load(&self) -> Result<Option<PersistedWifiRecord>, WifiRecordError> {
        if let Some(record) = Self::load_path(&self.path).await? {
            // A crash after writing the new namespaced record but before
            // removing its legacy copy is harmless; finish that migration now.
            self.clear_matching_legacy().await?;
            return Ok(Some(record));
        }

        let Some(record) = self.legacy_record().await? else {
            return Ok(None);
        };
        self.migrate_legacy(&record).await?;
        Ok(Some(record))
    }

    async fn save_primary(&self, record: &PersistedWifiRecord) -> Result<(), WifiRecordError> {
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

        atomic_file::replace_preserving_on_error_async(&self.path, &content, PRIVATE_FILE_MODE)
            .await
            .map_err(|error| WifiRecordError::Write(self.path.clone(), error))
    }

    pub async fn save(&self, record: &PersistedWifiRecord) -> Result<(), WifiRecordError> {
        self.save_primary(record).await?;
        self.clear_matching_legacy().await
    }

    pub async fn clear(&self) -> Result<(), WifiRecordError> {
        Self::clear_path(&self.path).await?;
        self.clear_transition().await?;
        self.clear_matching_legacy().await
    }

    /// Discover ownership records of one Wi-Fi process kind. AP and client
    /// records use separate namespaces. Legacy root-level names are considered
    /// only long enough to validate their embedded config path and migrate them
    /// into the unambiguous namespace.
    pub async fn discover(
        kind: WifiProcessKind,
        directory: impl AsRef<Path>,
    ) -> Result<Vec<(String, Self, PersistedWifiRecord)>, WifiRecordError> {
        let base = directory.as_ref();
        let namespaced_directory = kind.storage_directory(base);
        let mut candidates = BTreeSet::new();
        collect_candidates(&namespaced_directory, false, kind, &mut candidates).await?;
        if kind != WifiProcessKind::Scan {
            collect_candidates(base, true, kind, &mut candidates).await?;
        }

        let mut records = Vec::new();
        for interface in candidates {
            let store = Self::new(kind, base, &interface);
            if let Some(record) = store.load().await? {
                records.push((interface, store, record));
            }
        }
        Ok(records)
    }
}

async fn collect_candidates(
    directory: &Path,
    legacy: bool,
    kind: WifiProcessKind,
    candidates: &mut BTreeSet<String>,
) -> Result<(), WifiRecordError> {
    let mut entries = match fs::read_dir(directory).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(WifiRecordError::List(directory.to_path_buf(), error)),
    };
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|error| WifiRecordError::List(directory.to_path_buf(), error))?
    {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let interface = if legacy {
            interface_from_legacy_filename(kind, &name)
        } else {
            interface_from_namespaced_filename(&name)
        };
        if let Some(interface) = interface {
            candidates.insert(interface);
        }
    }
    Ok(())
}

fn interface_from_namespaced_filename(name: &str) -> Option<String> {
    let stem = name.strip_suffix(".json")?;
    let interface = stem.strip_prefix("active-")?;
    (!interface.is_empty()).then(|| interface.to_string())
}

fn interface_from_legacy_filename(kind: WifiProcessKind, name: &str) -> Option<String> {
    let stem = name.strip_suffix(".json")?;
    let interface = match kind {
        WifiProcessKind::AccessPoint => stem.strip_prefix("active-")?,
        WifiProcessKind::Client => stem.strip_prefix("active-client-")?,
        WifiProcessKind::Scan => return None,
    };
    (!interface.is_empty()).then(|| interface.to_string())
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

    async fn write_document(path: &Path, record: &PersistedWifiRecord) {
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
        tokio::fs::write(path, serde_json::to_vec_pretty(&document).unwrap())
            .await
            .expect("write legacy record");
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
    async fn transition_marker_round_trips_and_clear_removes_it() {
        let directory = tempdir().expect("tempdir");
        let store = WifiRecordStore::for_access_point(directory.path(), "wlan0");

        assert!(!store.transition_pending().await.expect("initial state"));
        store.mark_transition().await.expect("mark");
        assert!(store.transition_pending().await.expect("marked"));
        store.save(&record(1)).await.expect("save");
        store.clear().await.expect("clear");
        assert!(!store.transition_pending().await.expect("cleared"));
    }

    #[tokio::test]
    async fn ap_and_client_namespaces_cannot_collide() {
        let directory = tempdir().expect("tempdir");
        let ap = WifiRecordStore::for_access_point(directory.path(), "client-wlan0");
        let client = WifiRecordStore::for_client(directory.path(), "wlan0");
        let mut ap_record = record(7);
        ap_record.config_path = PathBuf::from("/run/traffic-masq/hostapd/client-wlan0.conf");
        let mut client_record = record(8);
        client_record.config_path = PathBuf::from("/run/traffic-masq/wpa/wlan0.conf");

        ap.save(&ap_record).await.expect("save AP");
        client.save(&client_record).await.expect("save client");

        assert_ne!(ap.path(), client.path());
        assert_eq!(ap.load().await.expect("load AP").unwrap().pid, 7);
        assert_eq!(client.load().await.expect("load client").unwrap().pid, 8);
    }

    #[tokio::test]
    async fn legacy_ap_record_is_migrated_into_ap_namespace() {
        let directory = tempdir().expect("tempdir");
        let legacy = directory.path().join("active-client-wlan0.json");
        let legacy_transition = legacy.with_extension("transition");
        let mut saved = record(7);
        saved.config_path = PathBuf::from("/run/traffic-masq/hostapd/client-wlan0.conf");
        write_document(&legacy, &saved).await;
        tokio::fs::write(&legacy_transition, b"pending\n")
            .await
            .expect("legacy transition");

        let store = WifiRecordStore::for_access_point(directory.path(), "client-wlan0");
        assert_eq!(store.load().await.expect("load").unwrap().pid, 7);
        assert!(store.path().exists());
        assert!(!legacy.exists());
        assert!(store.transition_pending().await.expect("transition migrated"));
        assert!(!legacy_transition.exists());
    }

    #[tokio::test]
    async fn discovery_migrates_legacy_record_into_namespaced_store() {
        let directory = tempdir().expect("tempdir");
        let legacy = directory.path().join("active-client-wlan0.json");
        let mut saved = record(10);
        saved.config_path = PathBuf::from("/run/traffic-masq/wpa/wlan0.conf");
        write_document(&legacy, &saved).await;

        let records = WifiRecordStore::discover(WifiProcessKind::Client, directory.path())
            .await
            .expect("discover client");

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, "wlan0");
        assert_eq!(records[0].2.pid, 10);
        assert!(records[0].1.path().starts_with(directory.path().join("client")));
        assert!(!legacy.exists());
    }

    #[tokio::test]
    async fn legacy_collision_is_migrated_only_by_matching_kind() {
        let directory = tempdir().expect("tempdir");
        let legacy = directory.path().join("active-client-wlan0.json");
        let mut saved = record(9);
        saved.config_path = PathBuf::from("/run/traffic-masq/wpa/wlan0.conf");
        write_document(&legacy, &saved).await;

        let ap = WifiRecordStore::for_access_point(directory.path(), "client-wlan0");
        assert!(ap.load().await.expect("AP load").is_none());
        assert!(legacy.exists(), "AP lookup must not consume a client record");

        let client = WifiRecordStore::for_client(directory.path(), "wlan0");
        assert_eq!(client.load().await.expect("client load").unwrap().pid, 9);
        assert!(client.path().exists());
        assert!(!legacy.exists());
    }

    #[tokio::test]
    async fn rejects_unsupported_schema_version() {
        let directory = tempdir().expect("tempdir");
        let store = WifiRecordStore::for_access_point(directory.path(), "wlan0");
        tokio::fs::create_dir_all(store.path().parent().unwrap())
            .await
            .unwrap();
        let path = store.path().to_path_buf();
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

        let error = store.load().await.expect_err("unsupported schema");
        assert!(matches!(error, WifiRecordError::UnsupportedSchema(_, 99)));
    }
}
