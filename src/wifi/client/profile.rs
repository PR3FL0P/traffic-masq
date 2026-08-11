use std::fs::{self, File};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use nix::errno::Errno;
use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::config::{InterfaceConfig, InterfaceRole, WifiClientConfig, WifiClientSecurity};
use crate::wifi::{PassphraseError, WifiPassphrase};

const PROFILE_VERSION: u32 = 1;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Error)]
pub enum WifiClientProfileError {
    #[error("invalid Wi-Fi client profile id: expected 1-64 ASCII characters from [A-Za-z0-9_-]")]
    InvalidId,
    #[error("invalid Wi-Fi client profile: {0}")]
    InvalidProfile(String),
    #[error("Wi-Fi client profile already exists")]
    AlreadyExists,
    #[error("Wi-Fi client profile not found")]
    NotFound,
    #[error("unsupported Wi-Fi client profile metadata version {0}")]
    UnsupportedVersion(u32),
    #[error("refusing to follow symlink at {0}")]
    SymlinkRejected(PathBuf),
    #[error("Wi-Fi client profile store path {0} is not a safe directory")]
    UnsafeDirectory(PathBuf),
    #[error("I/O error accessing Wi-Fi client profiles: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid Wi-Fi client profile metadata: {0}")]
    Json(#[from] serde_json::Error),
    #[error("low-level file operation failed: {0}")]
    Errno(#[from] Errno),
    #[error(transparent)]
    Passphrase(#[from] PassphraseError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiClientProfileInput {
    pub id: String,
    pub ssid: String,
    pub country_code: Option<String>,
    pub security: WifiClientSecurity,
    pub priority: i32,
}

impl WifiClientProfileInput {
    pub fn validate(&self) -> Result<(), WifiClientProfileError> {
        validate_id(&self.id)?;
        validate_fields(&self.ssid, &self.country_code, self.security)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifiClientProfileMetadata {
    pub version: u32,
    pub id: String,
    pub ssid: String,
    pub country_code: Option<String>,
    pub security: WifiClientSecurity,
    pub priority: i32,
    pub created_at: i64,
    pub modified_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifiClientProfileSummary {
    pub id: String,
    pub ssid: String,
    pub country_code: Option<String>,
    pub security: WifiClientSecurity,
    pub priority: i32,
    pub created_at: i64,
    pub modified_at: i64,
    pub has_passphrase: bool,
}

pub enum WifiClientProfileSecretUpdate {
    Unchanged,
    Replace(WifiPassphrase),
    Clear,
}

impl std::fmt::Debug for WifiClientProfileSecretUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unchanged => f.write_str("Unchanged"),
            Self::Replace(_) => f.write_str("Replace([REDACTED])"),
            Self::Clear => f.write_str("Clear"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WifiClientProfileStore {
    root: PathBuf,
}

impl WifiClientProfileStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn list(&self) -> Result<Vec<WifiClientProfileSummary>, WifiClientProfileError> {
        let dirs = self.ensure_directories()?;
        let mut profiles = Vec::new();
        for entry in fs::read_dir(&dirs.metadata)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                return Err(WifiClientProfileError::SymlinkRejected(path));
            }
            if !file_type.is_file() || path.extension().and_then(|v| v.to_str()) != Some("json") {
                continue;
            }
            let metadata = read_metadata(&path)?;
            validate_metadata(&metadata)?;
            profiles.push(self.summary(&dirs, metadata)?);
        }
        profiles.sort_by(|a, b| b.priority.cmp(&a.priority).then_with(|| a.id.cmp(&b.id)));
        Ok(profiles)
    }

    pub fn get(&self, id: &str) -> Result<WifiClientProfileSummary, WifiClientProfileError> {
        validate_id(id)?;
        let dirs = self.ensure_directories()?;
        let metadata = read_metadata(&metadata_path(&dirs, id)).map_err(map_not_found)?;
        validate_metadata(&metadata)?;
        if metadata.id != id {
            return Err(WifiClientProfileError::InvalidProfile(
                "stored id does not match its filename".to_string(),
            ));
        }
        self.summary(&dirs, metadata)
    }

    pub fn get_passphrase(
        &self,
        id: &str,
    ) -> Result<Option<WifiPassphrase>, WifiClientProfileError> {
        validate_id(id)?;
        let dirs = self.ensure_directories()?;

        if !metadata_path(&dirs, id).exists() {
            return Err(WifiClientProfileError::NotFound);
        }
        read_passphrase(&secret_path(&dirs, id))
    }

    pub fn create(
        &self,
        input: WifiClientProfileInput,
        passphrase: Option<WifiPassphrase>,
    ) -> Result<WifiClientProfileSummary, WifiClientProfileError> {
        input.validate()?;
        validate_secret_for_security(input.security, passphrase.is_some())?;
        let dirs = self.ensure_directories()?;
        let metadata_target = metadata_path(&dirs, &input.id);
        reject_existing_target(&metadata_target, true)?;
        let secret_target = secret_path(&dirs, &input.id);
        reject_existing_target(&secret_target, true)?;

        let now = unix_timestamp()?;
        let metadata = WifiClientProfileMetadata {
            version: PROFILE_VERSION,
            id: input.id,
            ssid: input.ssid,
            country_code: input.country_code,
            security: input.security,
            priority: input.priority,
            created_at: now,
            modified_at: now,
        };

        if let Some(passphrase) = passphrase.as_ref() {
            write_atomic(&secret_target, passphrase.expose().as_bytes())?;
        }
        let encoded = serde_json::to_vec_pretty(&metadata)?;
        if let Err(error) = write_atomic(&metadata_target, &encoded) {
            let _ = fs::remove_file(&secret_target);
            return Err(error);
        }
        self.summary(&dirs, metadata)
    }

    pub fn update(
        &self,
        input: WifiClientProfileInput,
        secret_update: WifiClientProfileSecretUpdate,
    ) -> Result<WifiClientProfileSummary, WifiClientProfileError> {
        input.validate()?;
        let dirs = self.ensure_directories()?;
        let metadata_target = metadata_path(&dirs, &input.id);
        let old = read_metadata(&metadata_target).map_err(map_not_found)?;
        validate_metadata(&old)?;
        let secret_target = secret_path(&dirs, &input.id);
        let existing_secret = target_exists_regular(&secret_target)?;
        let resulting_secret = match &secret_update {
            WifiClientProfileSecretUpdate::Unchanged => existing_secret,
            WifiClientProfileSecretUpdate::Replace(_) => true,
            WifiClientProfileSecretUpdate::Clear => false,
        };
        validate_secret_for_security(input.security, resulting_secret)?;

        match &secret_update {
            WifiClientProfileSecretUpdate::Unchanged => {}
            WifiClientProfileSecretUpdate::Replace(passphrase) => {
                write_atomic(&secret_target, passphrase.expose().as_bytes())?;
            }
            WifiClientProfileSecretUpdate::Clear => remove_regular(&secret_target, false)?,
        }

        let metadata = WifiClientProfileMetadata {
            version: PROFILE_VERSION,
            id: input.id,
            ssid: input.ssid,
            country_code: input.country_code,
            security: input.security,
            priority: input.priority,
            created_at: old.created_at,
            modified_at: unix_timestamp()?,
        };
        let encoded = serde_json::to_vec_pretty(&metadata)?;
        write_atomic(&metadata_target, &encoded)?;
        self.summary(&dirs, metadata)
    }

    pub fn delete(&self, id: &str) -> Result<(), WifiClientProfileError> {
        validate_id(id)?;
        let dirs = self.ensure_directories()?;
        remove_regular(&metadata_path(&dirs, id), true)?;
        sync_directory(&dirs.metadata)?;
        remove_regular(&secret_path(&dirs, id), false)?;
        sync_directory(&dirs.secrets)?;
        Ok(())
    }

    fn summary(
        &self,
        dirs: &StoreDirectories,
        metadata: WifiClientProfileMetadata,
    ) -> Result<WifiClientProfileSummary, WifiClientProfileError> {
        let has_passphrase = target_exists_regular(&secret_path(dirs, &metadata.id))?;
        Ok(WifiClientProfileSummary {
            id: metadata.id,
            ssid: metadata.ssid,
            country_code: metadata.country_code,
            security: metadata.security,
            priority: metadata.priority,
            created_at: metadata.created_at,
            modified_at: metadata.modified_at,
            has_passphrase,
        })
    }

    fn ensure_directories(&self) -> Result<StoreDirectories, WifiClientProfileError> {
        ensure_directory(&self.root)?;
        let root = fs::canonicalize(&self.root)?;
        let metadata = root.join("metadata");
        let secrets = root.join("secrets");
        ensure_directory(&metadata)?;
        ensure_directory(&secrets)?;
        Ok(StoreDirectories { metadata, secrets })
    }
}

struct StoreDirectories {
    metadata: PathBuf,
    secrets: PathBuf,
}

fn validate_id(id: &str) -> Result<(), WifiClientProfileError> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(WifiClientProfileError::InvalidId);
    }
    Ok(())
}

fn validate_fields(
    ssid: &str,
    country_code: &Option<String>,
    security: WifiClientSecurity,
) -> Result<(), WifiClientProfileError> {
    let config = InterfaceConfig {
        role: InterfaceRole::Input,
        managed: false,
        ipv4: None,
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: Some(WifiClientConfig {
            ssid: ssid.to_string(),
            country_code: country_code.clone(),
            security,
            passphrase_file: None,
        }),
    };
    config
        .validate("wlan0")
        .map_err(|error| WifiClientProfileError::InvalidProfile(error.to_string()))
}

fn validate_metadata(metadata: &WifiClientProfileMetadata) -> Result<(), WifiClientProfileError> {
    if metadata.version != PROFILE_VERSION {
        return Err(WifiClientProfileError::UnsupportedVersion(metadata.version));
    }
    validate_id(&metadata.id)?;
    validate_fields(&metadata.ssid, &metadata.country_code, metadata.security)
}

fn validate_secret_for_security(
    security: WifiClientSecurity,
    has_passphrase: bool,
) -> Result<(), WifiClientProfileError> {
    if security == WifiClientSecurity::Open && has_passphrase {
        return Err(WifiClientProfileError::InvalidProfile(
            "open Wi-Fi client profiles cannot store a passphrase".to_string(),
        ));
    }
    Ok(())
}

fn ensure_directory(path: &Path) -> Result<(), WifiClientProfileError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(WifiClientProfileError::SymlinkRejected(path.to_path_buf()))
        }
        Ok(metadata) if !metadata.is_dir() => {
            return Err(WifiClientProfileError::UnsafeDirectory(path.to_path_buf()))
        }
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => fs::create_dir_all(path)?,
        Err(error) => return Err(error.into()),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn metadata_path(dirs: &StoreDirectories, id: &str) -> PathBuf {
    dirs.metadata.join(format!("{id}.json"))
}

fn secret_path(dirs: &StoreDirectories, id: &str) -> PathBuf {
    dirs.secrets.join(format!("{id}.psk"))
}

fn reject_existing_target(path: &Path, conflict: bool) -> Result<(), WifiClientProfileError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(WifiClientProfileError::SymlinkRejected(path.to_path_buf()))
        }
        Ok(_) if conflict => Err(WifiClientProfileError::AlreadyExists),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn target_exists_regular(path: &Path) -> Result<bool, WifiClientProfileError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(WifiClientProfileError::SymlinkRejected(path.to_path_buf()))
        }
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Err(WifiClientProfileError::UnsafeDirectory(path.to_path_buf())),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn read_metadata(path: &Path) -> Result<WifiClientProfileMetadata, WifiClientProfileError> {
    let mut file = open_read(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(serde_json::from_str(&contents)?)
}

fn read_passphrase(path: &Path) -> Result<Option<WifiPassphrase>, WifiClientProfileError> {
    let mut file = match open_read(path) {
        Ok(file) => file,
        Err(WifiClientProfileError::Io(error)) if error.kind() == ErrorKind::NotFound => {
            return Ok(None)
        }
        Err(error) => return Err(error),
    };
    let mut contents = Zeroizing::new(String::new());
    file.read_to_string(&mut contents)?;
    Ok(Some(WifiPassphrase::new(contents.as_str())?))
}

fn open_read(path: &Path) -> Result<File, WifiClientProfileError> {
    let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    match open(path, flags, Mode::empty()) {
        Ok(fd) => Ok(unsafe { File::from_raw_fd(fd) }),
        Err(Errno::ELOOP) => Err(WifiClientProfileError::SymlinkRejected(path.to_path_buf())),
        Err(error) => Err(WifiClientProfileError::Io(std::io::Error::from(error))),
    }
}

fn write_atomic(path: &Path, contents: &[u8]) -> Result<(), WifiClientProfileError> {
    reject_existing_target(path, false)?;
    let (temporary, mut file) = create_temp(path)?;
    let result = (|| -> std::io::Result<()> {
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;

        reject_target_io(path)?;
        fs::rename(&temporary, path)?;
        sync_directory(path.parent().expect("profile target has parent"))
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    Ok(())
}

fn reject_target_io(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(std::io::Error::other(
            "refusing to replace symlinked profile target",
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn create_temp(path: &Path) -> Result<(PathBuf, File), WifiClientProfileError> {
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("profile");
    for _ in 0..100 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary =
            path.with_file_name(format!(".{name}.tmp-{}-{sequence}", std::process::id()));
        let flags =
            OFlag::O_CREAT | OFlag::O_WRONLY | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        match open(&temporary, flags, Mode::S_IRUSR | Mode::S_IWUSR) {
            Ok(fd) => {
                return Ok((temporary, unsafe { File::from_raw_fd(fd) }));
            }
            Err(Errno::EEXIST) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(WifiClientProfileError::Io(std::io::Error::new(
        ErrorKind::AlreadyExists,
        "failed to allocate a unique profile temporary file",
    )))
}

fn remove_regular(path: &Path, required: bool) -> Result<(), WifiClientProfileError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(WifiClientProfileError::SymlinkRejected(path.to_path_buf()))
        }
        Ok(metadata) if metadata.is_file() => Ok(fs::remove_file(path)?),
        Ok(_) => Err(WifiClientProfileError::UnsafeDirectory(path.to_path_buf())),
        Err(error) if error.kind() == ErrorKind::NotFound && required => {
            Err(WifiClientProfileError::NotFound)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

fn unix_timestamp() -> Result<i64, WifiClientProfileError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| std::io::Error::other("system clock is before Unix epoch"))?
        .as_secs();
    i64::try_from(seconds).map_err(|_| {
        WifiClientProfileError::Io(std::io::Error::other("Unix timestamp does not fit in i64"))
    })
}

fn map_not_found(error: WifiClientProfileError) -> WifiClientProfileError {
    match error {
        WifiClientProfileError::Io(error) if error.kind() == ErrorKind::NotFound => {
            WifiClientProfileError::NotFound
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{symlink, MetadataExt};

    use tempfile::tempdir;

    use super::*;

    fn input(id: &str) -> WifiClientProfileInput {
        WifiClientProfileInput {
            id: id.to_string(),
            ssid: "home network".to_string(),
            country_code: Some("PL".to_string()),
            security: WifiClientSecurity::Wpa2,
            priority: 10,
        }
    }

    fn secret() -> WifiPassphrase {
        WifiPassphrase::new("correct horse battery").expect("passphrase")
    }

    #[test]
    fn rejects_traversal_and_non_ascii_ids() {
        let dir = tempdir().unwrap();
        let store = WifiClientProfileStore::new(dir.path().join("profiles"));
        for id in ["", "..", "a/b", "a.b", "é", &"a".repeat(65)] {
            assert!(matches!(
                store.create(input(id), None),
                Err(WifiClientProfileError::InvalidId)
            ));
        }
    }

    #[test]
    fn crud_and_secret_update_semantics_work() {
        let dir = tempdir().unwrap();
        let store = WifiClientProfileStore::new(dir.path().join("profiles"));
        let created = store.create(input("home"), Some(secret())).unwrap();
        assert!(created.has_passphrase);
        assert_eq!(
            store.get_passphrase("home").unwrap().unwrap().expose(),
            "correct horse battery"
        );

        let mut changed = input("home");
        changed.ssid = "new ssid".into();
        let updated = store
            .update(changed.clone(), WifiClientProfileSecretUpdate::Unchanged)
            .unwrap();
        assert_eq!(updated.created_at, created.created_at);
        assert!(updated.has_passphrase);
        let cleared = store
            .update(changed.clone(), WifiClientProfileSecretUpdate::Clear)
            .unwrap();
        assert!(!cleared.has_passphrase);
        let replaced = store
            .update(changed, WifiClientProfileSecretUpdate::Replace(secret()))
            .unwrap();
        assert!(replaced.has_passphrase);
        assert_eq!(store.list().unwrap(), vec![replaced]);

        store.delete("home").unwrap();
        assert!(matches!(
            store.get("home"),
            Err(WifiClientProfileError::NotFound)
        ));
        assert!(matches!(
            store.delete("home"),
            Err(WifiClientProfileError::NotFound)
        ));
    }

    #[test]
    fn creates_restricted_directories_and_files() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("profiles");
        let store = WifiClientProfileStore::new(&root);
        store.create(input("home"), Some(secret())).unwrap();
        assert_eq!(fs::metadata(&root).unwrap().mode() & 0o777, 0o700);
        assert_eq!(
            fs::metadata(root.join("metadata")).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(root.join("secrets")).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(root.join("metadata/home.json"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(root.join("secrets/home.psk")).unwrap().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn rejects_symlinked_root_directories_and_targets() {
        let dir = tempdir().unwrap();
        let actual = dir.path().join("actual");
        fs::create_dir(&actual).unwrap();
        let linked = dir.path().join("linked");
        symlink(&actual, &linked).unwrap();
        let store = WifiClientProfileStore::new(&linked);
        assert!(matches!(
            store.list(),
            Err(WifiClientProfileError::SymlinkRejected(_))
        ));

        let root = dir.path().join("profiles");
        let store = WifiClientProfileStore::new(&root);
        store.list().unwrap();
        symlink(dir.path().join("outside"), root.join("metadata/evil.json")).unwrap();
        assert!(matches!(
            store.get("evil"),
            Err(WifiClientProfileError::SymlinkRejected(_))
        ));
        symlink(
            dir.path().join("outside-secret"),
            root.join("secrets/secret.psk"),
        )
        .unwrap();
        assert!(matches!(
            store.create(input("secret"), None),
            Err(WifiClientProfileError::SymlinkRejected(_))
        ));
    }

    #[test]
    fn metadata_summary_debug_and_errors_never_leak_the_secret() {
        let dir = tempdir().unwrap();
        let store = WifiClientProfileStore::new(dir.path().join("profiles"));
        let value = "unique-secret-value";
        let update = WifiClientProfileSecretUpdate::Replace(WifiPassphrase::new(value).unwrap());
        assert!(!format!("{update:?}").contains(value));
        store
            .create(input("home"), Some(WifiPassphrase::new(value).unwrap()))
            .unwrap();
        let summary = store.get("home").unwrap();
        assert!(!format!("{summary:?}").contains(value));
        assert!(!serde_json::to_string(&summary).unwrap().contains(value));
        assert!(!fs::read_to_string(store.root().join("metadata/home.json"))
            .unwrap()
            .contains(value));
    }

    #[test]
    fn profile_validation_matches_wifi_client_config() {
        let dir = tempdir().unwrap();
        let store = WifiClientProfileStore::new(dir.path().join("profiles"));
        let mut invalid = input("bad");
        invalid.ssid.clear();
        assert!(matches!(
            store.create(invalid, None),
            Err(WifiClientProfileError::InvalidProfile(_))
        ));
        let mut invalid = input("bad-country");
        invalid.country_code = Some("pl".into());
        assert!(matches!(
            store.create(invalid, None),
            Err(WifiClientProfileError::InvalidProfile(_))
        ));
        let mut open = input("open");
        open.security = WifiClientSecurity::Open;
        assert!(matches!(
            store.create(open, Some(secret())),
            Err(WifiClientProfileError::InvalidProfile(_))
        ));
    }

    #[test]
    fn list_rejects_symlink_entries_instead_of_following_them() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("profiles");
        let store = WifiClientProfileStore::new(&root);
        store.list().unwrap();
        symlink("elsewhere", root.join("metadata/planted.json")).unwrap();
        assert!(matches!(
            store.list(),
            Err(WifiClientProfileError::SymlinkRejected(_))
        ));
    }
}
