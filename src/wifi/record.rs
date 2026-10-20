use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::fs;

use crate::atomic_file::{self, PRIVATE_FILE_MODE};
use crate::wifi::render::WifiDigest;

pub const CURRENT_WIFI_RECORD_SCHEMA: u32 = 2;

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

    #[error("persisted Wi-Fi process record {0} does not match its namespace or expected paths")]
    MismatchedContext(PathBuf),

    #[error("cannot clean Wi-Fi control socket {0}: saved file identity is missing or changed, or the socket is still active; ownership record retained")]
    UnprovenCtrlSocket(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedWifiRecordDocument {
    schema_version: u32,
    #[serde(default)]
    kind: Option<WifiProcessKind>,
    #[serde(default)]
    interface: Option<String>,
    pid: u32,
    started_at_unix: u64,
    #[serde(default)]
    process_start_ticks: Option<u64>,
    #[serde(default)]
    boot_id: Option<String>,
    #[serde(default)]
    binary_path: Option<PathBuf>,
    ctrl_path: PathBuf,
    #[serde(default)]
    ctrl_dev: Option<u64>,
    #[serde(default)]
    ctrl_ino: Option<u64>,
    config_path: PathBuf,
    config_digest: WifiDigest,
    key_digest: WifiDigest,
    ssid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedWifiRecord {
    pub pid: u32,
    pub started_at_unix: u64,
    pub process_start_ticks: Option<u64>,
    pub boot_id: Option<String>,
    pub binary_path: Option<PathBuf>,
    pub ctrl_path: PathBuf,
    pub ctrl_dev: Option<u64>,
    pub ctrl_ino: Option<u64>,
    pub config_path: PathBuf,
    pub config_digest: WifiDigest,
    pub key_digest: WifiDigest,
    pub ssid: String,
}

#[derive(Debug, Clone)]
pub struct WifiRecordStore {
    path: PathBuf,
    expected_config_stem: String,
    runtime_dir: PathBuf,
    interface: String,
    kind: WifiProcessKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WifiProcessKind {
    AccessPoint,
    Client,
    Scan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiRuntimeDirs {
    access_point: PathBuf,
    client: PathBuf,
}

impl WifiRuntimeDirs {
    pub fn new(access_point: impl AsRef<Path>, client: impl AsRef<Path>) -> Self {
        Self {
            access_point: access_point.as_ref().to_path_buf(),
            client: client.as_ref().to_path_buf(),
        }
    }

    pub fn for_kind(&self, kind: WifiProcessKind) -> &Path {
        match kind {
            WifiProcessKind::AccessPoint => &self.access_point,
            WifiProcessKind::Client | WifiProcessKind::Scan => &self.client,
        }
    }
}

impl WifiProcessKind {
    fn storage_directory(self, directory: &Path) -> PathBuf {
        match self {
            Self::AccessPoint => directory.join("ap"),
            Self::Client => directory.join("client"),
            Self::Scan => directory.join("scan"),
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
    pub fn new(
        kind: WifiProcessKind,
        directory: impl AsRef<Path>,
        runtime_dir: impl AsRef<Path>,
        interface: &str,
    ) -> Self {
        let base = directory.as_ref();
        Self {
            path: kind
                .storage_directory(base)
                .join(format!("active-{interface}.json")),
            expected_config_stem: kind.expected_config_stem(interface),
            runtime_dir: runtime_dir.as_ref().to_path_buf(),
            interface: interface.to_string(),
            kind,
        }
    }

    pub fn for_access_point(
        directory: impl AsRef<Path>,
        runtime_dir: impl AsRef<Path>,
        interface: &str,
    ) -> Self {
        Self::new(
            WifiProcessKind::AccessPoint,
            directory,
            runtime_dir,
            interface,
        )
    }

    pub fn for_client(
        directory: impl AsRef<Path>,
        runtime_dir: impl AsRef<Path>,
        interface: &str,
    ) -> Self {
        Self::new(WifiProcessKind::Client, directory, runtime_dir, interface)
    }

    pub fn for_scan(
        directory: impl AsRef<Path>,
        runtime_dir: impl AsRef<Path>,
        interface: &str,
    ) -> Self {
        Self::new(WifiProcessKind::Scan, directory, runtime_dir, interface)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn kind(&self) -> WifiProcessKind {
        self.kind
    }

    fn transition_path_for(path: &Path) -> PathBuf {
        path.with_extension("transition")
    }

    fn transition_path(&self) -> PathBuf {
        Self::transition_path_for(&self.path)
    }

    fn expected_ctrl_path(&self) -> PathBuf {
        self.runtime_dir.join(&self.interface)
    }

    fn expected_config_path(&self) -> PathBuf {
        self.runtime_dir
            .join(format!("{}.conf", self.expected_config_stem))
    }

    fn record_matches_store(&self, record: &PersistedWifiRecord) -> bool {
        record.ctrl_path == self.expected_ctrl_path()
            && record.config_path == self.expected_config_path()
            && record.ctrl_dev.is_some() == record.ctrl_ino.is_some()
            && record
                .binary_path
                .as_ref()
                .is_some_and(|path| path.is_absolute())
            && record.boot_id.as_ref().is_some_and(|id| !id.is_empty())
            && (record.pid == 0 || record.process_start_ticks.is_some())
            && record.started_at_unix != 0
    }

    async fn load_path(
        &self,
        path: &Path,
    ) -> Result<Option<(PersistedWifiRecord, u32)>, WifiRecordError> {
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

        let context_matches = document.kind == Some(self.kind)
            && document.interface.as_deref() == Some(self.interface.as_str());
        if !context_matches {
            return Err(WifiRecordError::MismatchedContext(path.to_path_buf()));
        }

        Ok(Some((
            PersistedWifiRecord {
                pid: document.pid,
                started_at_unix: document.started_at_unix,
                process_start_ticks: document.process_start_ticks,
                boot_id: document.boot_id,
                binary_path: document.binary_path,
                ctrl_path: document.ctrl_path,
                ctrl_dev: document.ctrl_dev,
                ctrl_ino: document.ctrl_ino,
                config_path: document.config_path,
                config_digest: document.config_digest,
                key_digest: document.key_digest,
                ssid: document.ssid,
            },
            document.schema_version,
        )))
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
    pub async fn transition_pending(&self) -> Result<bool, WifiRecordError> {
        Self::path_exists(&self.transition_path()).await
    }

    pub async fn mark_transition(&self) -> Result<(), WifiRecordError> {
        let path = self.transition_path();
        if let Some(parent) = path.parent() {
            atomic_file::create_dir_all_durable_async(parent)
                .await
                .map_err(|error| WifiRecordError::Write(path.clone(), error))?;
        }
        atomic_file::replace_preserving_on_error_async(&path, b"pending\n", PRIVATE_FILE_MODE)
            .await
            .map_err(|error| WifiRecordError::Write(path, error))
    }

    pub async fn clear_transition(&self) -> Result<(), WifiRecordError> {
        Self::clear_path(&self.transition_path()).await
    }

    pub async fn load(&self) -> Result<Option<PersistedWifiRecord>, WifiRecordError> {
        let Some((record, _)) = self.load_path(&self.path).await? else {
            return Ok(None);
        };
        if !self.record_matches_store(&record) {
            return Err(WifiRecordError::MismatchedContext(self.path.clone()));
        }
        Ok(Some(record))
    }

    async fn save_primary(&self, record: &PersistedWifiRecord) -> Result<(), WifiRecordError> {
        if let Some(parent) = self.path.parent() {
            atomic_file::create_dir_all_durable_async(parent)
                .await
                .map_err(|error| WifiRecordError::Write(self.path.clone(), error))?;
        }

        let document = PersistedWifiRecordDocument {
            schema_version: CURRENT_WIFI_RECORD_SCHEMA,
            kind: Some(self.kind),
            interface: Some(self.interface.clone()),
            pid: record.pid,
            started_at_unix: record.started_at_unix,
            process_start_ticks: record.process_start_ticks,
            boot_id: record.boot_id.clone(),
            binary_path: record.binary_path.clone(),
            ctrl_path: record.ctrl_path.clone(),
            ctrl_dev: record.ctrl_dev,
            ctrl_ino: record.ctrl_ino,
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
        if !self.record_matches_store(record) {
            return Err(WifiRecordError::MismatchedContext(self.path.clone()));
        }
        self.save_primary(record).await
    }

    pub async fn clear(&self) -> Result<(), WifiRecordError> {
        Self::clear_path(&self.path).await?;
        self.clear_transition().await
    }

    /// Discover ownership records of one Wi-Fi process kind. AP and client
    /// records use separate namespaces.
    pub async fn discover(
        kind: WifiProcessKind,
        directory: impl AsRef<Path>,
        runtime_dir: impl AsRef<Path>,
    ) -> Result<Vec<(String, Self, PersistedWifiRecord)>, WifiRecordError> {
        let base = directory.as_ref();
        let runtime_dir = runtime_dir.as_ref();
        let namespaced_directory = kind.storage_directory(base);
        let mut candidates = BTreeSet::new();
        collect_candidates(&namespaced_directory, &mut candidates).await?;

        let mut records = Vec::new();
        for interface in candidates {
            let store = Self::new(kind, base, runtime_dir, &interface);
            match store.load().await {
                Ok(Some(record)) => records.push((interface, store, record)),
                Ok(None) => {}
                Err(error) => tracing::error!(%interface, journal = %store.path().display(),
                    operation = "discover_wifi_record", invariant = "proven_process_identity",
                    metadata_safe_to_remove = false, %error, "Wi-Fi ownership record blocked; continuing discovery"),
            }
        }
        Ok(records)
    }
}

async fn collect_candidates(
    directory: &Path,
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
        let interface = interface_from_namespaced_filename(&name);
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
#[cfg(test)]
mod tests;
