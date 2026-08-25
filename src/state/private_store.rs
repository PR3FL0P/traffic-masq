//! A directory of small private JSON documents, keyed by interface name.
//!
//! What this adds over [`crate::atomic_file`] is the *keying*: a document is
//! named by an interface, the key is validated as one, and the directory can be
//! listed. The `0700`/`0600`/atomic-rename/no-symlink rules themselves live in
//! `atomic_file`, shared with the stores that are not keyed this way.

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use crate::atomic_file::{self, PrivateDirError, PRIVATE_DIR_MODE, PRIVATE_FILE_MODE};

#[derive(Debug, thiserror::Error)]
pub enum PrivateStoreError {
    #[error("invalid document key")]
    InvalidKey,
    #[error("unsafe symlink at {0}")]
    Symlink(PathBuf),
    #[error("private store I/O error: {0}")]
    Io(#[from] io::Error),
}

impl From<PrivateDirError> for PrivateStoreError {
    fn from(error: PrivateDirError) -> Self {
        match error {
            PrivateDirError::Symlink(path) => Self::Symlink(path),
            PrivateDirError::NotADirectory(path) => Self::Io(io::Error::new(
                io::ErrorKind::NotADirectory,
                format!("{} is not a directory", path.display()),
            )),
            PrivateDirError::Io(error) => Self::Io(error),
        }
    }
}

/// One directory of private per-interface documents.
#[derive(Debug, Clone)]
pub struct PrivateJsonDirectory {
    directory: PathBuf,
}

impl PrivateJsonDirectory {
    /// Open `<state_root>/<name>`, creating it if needed.
    pub fn open(state_root: impl AsRef<Path>, name: &str) -> Result<Self, PrivateStoreError> {
        let root = state_root.as_ref();
        reject_symlink(root)?;
        fs::create_dir_all(root)?;
        reject_symlink(root)?;
        let directory = root.join(name);
        atomic_file::ensure_private_dir(&directory, PRIVATE_DIR_MODE)?;
        Ok(Self { directory })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Read a document, or `None` if it was never written.
    pub fn read(&self, key: &str) -> Result<Option<Vec<u8>>, PrivateStoreError> {
        let path = self.path(key)?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(PrivateStoreError::Symlink(path))
            }
            Ok(metadata) if !metadata.is_file() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "document path is not a file",
                )
                .into())
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        Ok(Some(fs::read(path)?))
    }

    /// Replace a document atomically.
    ///
    /// The symlink check is repeated here, before delegating, so that a planted
    /// symlink is reported as [`PrivateStoreError::Symlink`] with its path
    /// rather than as the generic I/O refusal `atomic_file` raises.
    pub fn write(&self, key: &str, bytes: &[u8]) -> Result<(), PrivateStoreError> {
        let destination = self.path(key)?;
        reject_symlink(&destination)?;
        atomic_file::replace(&destination, bytes, PRIVATE_FILE_MODE)?;
        Ok(())
    }

    pub fn remove(&self, key: &str) -> Result<(), PrivateStoreError> {
        let path = self.path(key)?;
        reject_symlink(&path)?;
        match fs::remove_file(path) {
            Ok(()) => File::open(&self.directory)?.sync_all()?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    /// The keys of every document in the directory.
    ///
    /// Temporary files and anything that is not a plain `<key>.json` are
    /// skipped: a leftover from an interrupted write is not a record.
    pub fn keys(&self) -> Result<Vec<String>, PrivateStoreError> {
        let mut keys = Vec::new();
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(key) = name.strip_suffix(".json") else {
                continue;
            };
            if valid_document_key(key) {
                keys.push(key.to_string());
            }
        }
        keys.sort();
        Ok(keys)
    }

    fn path(&self, key: &str) -> Result<PathBuf, PrivateStoreError> {
        if !valid_document_key(key) {
            return Err(PrivateStoreError::InvalidKey);
        }
        Ok(self.directory.join(format!("{key}.json")))
    }
}

/// Whether a key can be used as a file name without surprises.
///
/// Deliberately the same rule as a Linux interface name: every document these
/// stores hold is about one interface, and a key that cannot be an interface
/// name is a key that came from somewhere it should not have.
pub fn valid_document_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 15
        && key != "."
        && key != ".."
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn reject_symlink(path: &Path) -> Result<(), PrivateStoreError> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(PrivateStoreError::Symlink(path.to_path_buf()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{symlink, MetadataExt};

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn writes_are_private_atomic_and_leave_no_temporaries() {
        let root = tempdir().expect("tempdir");
        let store = PrivateJsonDirectory::open(root.path(), "records").expect("store");

        assert_eq!(
            fs::metadata(store.directory()).expect("metadata").mode() & 0o777,
            0o700
        );

        store.write("eth0", b"{\"a\":1}").expect("write");
        store.write("eth0", b"{\"a\":2}").expect("overwrite");

        let path = store.directory().join("eth0.json");
        assert_eq!(fs::metadata(&path).expect("metadata").mode() & 0o777, 0o600);
        assert_eq!(
            store.read("eth0").expect("read").as_deref(),
            Some(&b"{\"a\":2}"[..])
        );
        assert!(fs::read_dir(store.directory())
            .expect("read_dir")
            .all(|entry| !entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")));

        assert_eq!(store.keys().expect("keys"), vec!["eth0".to_string()]);
        store.remove("eth0").expect("remove");
        assert_eq!(store.read("eth0").expect("read"), None);
        assert!(store.keys().expect("keys").is_empty());
    }

    #[test]
    fn refuses_traversal_and_symlinked_documents() {
        let root = tempdir().expect("tempdir");
        let store = PrivateJsonDirectory::open(root.path(), "records").expect("store");

        assert!(matches!(
            store.read("../eth0"),
            Err(PrivateStoreError::InvalidKey)
        ));

        let target = root.path().join("target");
        fs::write(&target, b"do not replace").expect("write target");
        symlink(&target, store.directory().join("eth0.json")).expect("symlink");

        assert!(matches!(
            store.write("eth0", b"{}"),
            Err(PrivateStoreError::Symlink(_))
        ));
        assert_eq!(fs::read(&target).expect("read target"), b"do not replace");
    }

    #[test]
    fn refuses_a_symlinked_store_directory() {
        let root = tempdir().expect("tempdir");
        let elsewhere = tempdir().expect("tempdir");
        symlink(elsewhere.path(), root.path().join("records")).expect("symlink");

        assert!(matches!(
            PrivateJsonDirectory::open(root.path(), "records"),
            Err(PrivateStoreError::Symlink(_))
        ));
    }
}
