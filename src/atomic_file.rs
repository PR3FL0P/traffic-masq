//! Atomic replacement of small private files, and the private directories they
//! live in.
//!
//! traffic-masq keeps several kinds of record that must survive a crash and
//! must not be readable or replaceable by anyone but root: DHCP leases and
//! client lease state, Wi-Fi passphrases and AP/STA process records, WireGuard
//! profiles and the active-profile marker, and the journal of addresses the
//! daemon installed. The rules are the same for all of them — the directory is
//! `0700`, the file is `0600`, a write is atomic, and a symlink anywhere on the
//! path is refused rather than followed.
//!
//! Those rules used to exist in seven copies, one per store, and had already
//! drifted: some fsynced the parent directory and some did not, some set the
//! mode when opening and some with a `set_permissions` after the rename, and
//! the temporary-file naming differed in every one of them. This module is the
//! single copy. It deliberately does not know what a store *is* — path safety
//! (which names a caller will accept, where a directory may live) stays with
//! the store, because those rules genuinely differ.
//!
//! Deliberately a leaf: nothing here imports from the rest of the crate, so it
//! can be used from any layer without creating a dependency edge.

//! Atomic file replacement with symlink checks and Unix permission handling.
//!
//! These functions are used for secrets and journals: data is first written
//! to a temporary file with the requested mode, which then replaces the target.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Mode for a file only root may read.
/// Default mode for files containing private daemon state or secrets.
pub const PRIVATE_FILE_MODE: u32 = 0o600;

/// Mode for a directory only root may traverse.
/// Default mode for directories containing private daemon state.
pub const PRIVATE_DIR_MODE: u32 = 0o700;

/// How many names to try before giving up on finding an unused temporary.
const TEMP_NAME_ATTEMPTS: u32 = 100;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Why a directory could not be used as a private store.
///
/// Kept separate from [`io::Error`] because every caller distinguishes these
/// two cases in its own error type, and an `io::Error` cannot carry which one
/// it was without losing the path.
#[derive(Debug)]
pub enum PrivateDirError {
    /// The path is a symlink. Following it would let whoever planted it choose
    /// where the daemon writes.
    Symlink(PathBuf),
    /// The path exists but is not a directory.
    NotADirectory(PathBuf),
    Io(io::Error),
}

impl From<io::Error> for PrivateDirError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl std::fmt::Display for PrivateDirError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Symlink(path) => write!(formatter, "unsafe symlink at {}", path.display()),
            Self::NotADirectory(path) => {
                write!(formatter, "{} is not a directory", path.display())
            }
            Self::Io(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for PrivateDirError {}

/// Refuse a path that is a symlink.
///
/// A missing path is fine — it is the *existing* symlink that is the problem.
/// Reject a symlink at `path` without following it.
pub fn reject_symlink(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsafe symlink at {}", path.display()),
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Create `path` if it is missing and force `mode` on it.
///
/// An existing symlink or non-directory is refused rather than replaced: this
/// runs as root, and silently writing through whatever is already there is the
/// whole class of bug the check exists to prevent.
/// Create a directory if needed and ensure it has the requested private mode.
pub fn ensure_private_dir(path: &Path, mode: u32) -> Result<(), PrivateDirError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(PrivateDirError::Symlink(path.to_path_buf()))
        }
        Ok(metadata) if !metadata.is_dir() => {
            return Err(PrivateDirError::NotADirectory(path.to_path_buf()))
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
        }
        Err(error) => return Err(error.into()),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// Replace `path` with `contents`, atomically, at `mode`.
///
/// Written to a temporary in the same directory and renamed, so a reader —
/// including this daemon after a crash — never sees half a document. The
/// temporary is opened `O_NOFOLLOW | O_EXCL` at the target mode, so the bytes
/// are never briefly world-readable and never land somewhere a symlink chose.
/// The parent directory is fsynced last, because the rename is the part that
/// has to survive power loss.
///
/// The parent directory must already exist; use [`ensure_private_dir`] first if
/// that is not guaranteed.
/// Atomically replace a regular file while preserving the requested mode.
pub fn replace(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    reject_symlink(path)?;

    let (temporary, mut file) = create_temporary(path, parent, mode)?;
    let result = (|| -> io::Result<()> {
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        // Re-checked after the temporary was written: the window between the
        // first check and the rename is exactly when a symlink would be
        // planted.
        reject_symlink(path)?;
        fs::rename(&temporary, path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        File::open(parent)?.sync_all()
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// [`replace`], off the async runtime.
///
/// The work is genuinely blocking — three fsyncs — so it goes to the blocking
/// pool rather than being reimplemented against `tokio::fs`. One implementation
/// of the delicate part is the point of this module.
/// Asynchronously perform [`replace`] without blocking the Tokio executor.
pub async fn replace_async(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let path = path.to_path_buf();
    let contents = contents.to_vec();
    tokio::task::spawn_blocking(move || replace(&path, &contents, mode))
        .await
        .map_err(io::Error::other)?
}

/// Open a uniquely named temporary next to `path`.
///
/// Retries on a name collision instead of failing: two writers to the same
/// store are rare but not impossible, and a collision is not an error the
/// caller can do anything about.
fn create_temporary(path: &Path, parent: &Path, mode: u32) -> io::Result<(PathBuf, File)> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("document");

    for _ in 0..TEMP_NAME_ATTEMPTS {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{file_name}.tmp-{}-{sequence}",
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&candidate)
        {
            Ok(file) => return Ok((candidate, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }

    Err(io::Error::other(format!(
        "failed to allocate a unique temporary file next to {}",
        path.display()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn replace_writes_private_contents() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("document.json");

        replace(&path, b"first", PRIVATE_FILE_MODE).expect("write");

        assert_eq!(fs::read(&path).expect("read"), b"first");
        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, PRIVATE_FILE_MODE);
    }

    #[test]
    fn replace_overwrites_without_widening_permissions() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("document.json");

        replace(&path, b"first", PRIVATE_FILE_MODE).expect("first write");
        replace(&path, b"second", PRIVATE_FILE_MODE).expect("second write");

        assert_eq!(fs::read(&path).expect("read"), b"second");
        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, PRIVATE_FILE_MODE);
    }

    #[test]
    fn replace_leaves_no_temporary_behind() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("document.json");

        replace(&path, b"contents", PRIVATE_FILE_MODE).expect("write");

        let leftovers: Vec<_> = fs::read_dir(directory.path())
            .expect("read_dir")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp") || name.contains(".tmp-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "left temporaries behind: {leftovers:?}"
        );
    }

    #[test]
    fn replace_refuses_to_follow_a_symlinked_target() {
        let directory = tempdir().expect("tempdir");
        let outside = directory.path().join("outside");
        fs::write(&outside, b"original").expect("seed");
        let link = directory.path().join("document.json");
        std::os::unix::fs::symlink(&outside, &link).expect("symlink");

        let error = replace(&link, b"attacker", PRIVATE_FILE_MODE).expect_err("must refuse");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            fs::read(&outside).expect("read"),
            b"original",
            "the symlink target must not have been written through"
        );
    }

    #[tokio::test]
    async fn replace_async_matches_the_blocking_version() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("document.json");

        replace_async(&path, b"async", PRIVATE_FILE_MODE)
            .await
            .expect("write");

        assert_eq!(fs::read(&path).expect("read"), b"async");
        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, PRIVATE_FILE_MODE);
    }

    #[test]
    fn ensure_private_dir_creates_and_tightens() {
        let directory = tempdir().expect("tempdir");
        let target = directory.path().join("store");

        ensure_private_dir(&target, PRIVATE_DIR_MODE).expect("create");

        let mode = fs::metadata(&target)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, PRIVATE_DIR_MODE);
    }

    #[test]
    fn ensure_private_dir_tightens_a_loose_existing_directory() {
        let directory = tempdir().expect("tempdir");
        let target = directory.path().join("store");
        fs::create_dir(&target).expect("mkdir");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).expect("loosen");

        ensure_private_dir(&target, PRIVATE_DIR_MODE).expect("tighten");

        let mode = fs::metadata(&target)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, PRIVATE_DIR_MODE);
    }

    #[test]
    fn ensure_private_dir_refuses_a_symlink() {
        let directory = tempdir().expect("tempdir");
        let elsewhere = directory.path().join("elsewhere");
        fs::create_dir(&elsewhere).expect("mkdir");
        let link = directory.path().join("store");
        std::os::unix::fs::symlink(&elsewhere, &link).expect("symlink");

        let error = ensure_private_dir(&link, PRIVATE_DIR_MODE).expect_err("must refuse");

        assert!(matches!(error, PrivateDirError::Symlink(_)), "{error:?}");
    }

    #[test]
    fn ensure_private_dir_refuses_a_file() {
        let directory = tempdir().expect("tempdir");
        let target = directory.path().join("store");
        fs::write(&target, b"not a directory").expect("seed");

        let error = ensure_private_dir(&target, PRIVATE_DIR_MODE).expect_err("must refuse");

        assert!(
            matches!(error, PrivateDirError::NotADirectory(_)),
            "{error:?}"
        );
    }
}
