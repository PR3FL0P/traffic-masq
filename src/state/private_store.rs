//! A directory of small private JSON documents, keyed by interface name.
//!
//! What this adds over [`crate::atomic_file`] is the *keying*: a document is
//! named by an interface, the key is validated as one, and the directory can be
//! listed. The `0700`/`0600`/atomic-rename/no-symlink rules themselves live in
//! `atomic_file`, shared with the stores that are not keyed this way.

use std::fs;
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
    /// Open `<state_root>/<name>`, creating it if needed with directory mode 0700.
    /// Reject names containing traversal or multiple components and symlinked store paths.
    pub fn open(state_root: impl AsRef<Path>, name: &str) -> Result<Self, PrivateStoreError> {
        let mut components = Path::new(name).components();
        if !matches!(components.next(), Some(std::path::Component::Normal(_)))
            || components.next().is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "store name must be a single normal path component",
            )
            .into());
        }
        let root = state_root.as_ref();
        reject_symlink(root)?;
        fs::create_dir_all(root)?;
        reject_symlink(root)?;
        let directory = root.join(name);
        atomic_file::ensure_private_dir(&directory, PRIVATE_DIR_MODE)?;
        Ok(Self { directory })
    }

    /// Return the directory containing this store without accessing the filesystem.
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
        atomic_file::replace_preserving_on_error(&destination, bytes, PRIVATE_FILE_MODE)?;
        Ok(())
    }

    /// Durably remove a validated document; a missing document is already removed.
    /// Attempt restoration if deletion fails after modifying the directory.
    pub fn remove(&self, key: &str) -> Result<(), PrivateStoreError> {
        let path = self.path(key)?;
        reject_symlink(&path)?;
        atomic_file::remove_preserving_on_error(&path, PRIVATE_FILE_MODE)?;
        Ok(())
    }

    /// The keys of every document in the directory.
    ///
    /// Temporary files and unrelated names are skipped. A path that *looks* like a real
    /// `<key>.json` document but is a symlink or another file type is an error instead of being
    /// silently hidden from recovery enumeration.
    pub fn keys(&self) -> Result<Vec<String>, PrivateStoreError> {
        let mut keys = Vec::new();
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(key) = name.strip_suffix(".json") else {
                continue;
            };
            if !valid_document_key(key) {
                continue;
            }
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                return Err(PrivateStoreError::Symlink(path));
            }
            if !file_type.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("document path is not a regular file: {}", path.display()),
                )
                .into());
            }
            keys.push(key.to_string());
        }
        keys.sort();
        Ok(keys)
    }

    /// Validate the interface key before constructing its JSON document path.
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

/// Reject a symlink while preserving metadata errors other than a missing path.
fn reject_symlink(path: &Path) -> Result<(), PrivateStoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(PrivateStoreError::Symlink(path.to_path_buf()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests;
