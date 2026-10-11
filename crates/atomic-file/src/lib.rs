//! Atomic replacement of small private files, and the private directories they
//! live in.
//!
//! traffic-masq keeps several kinds of record that must survive a crash and
//! must not be readable or replaceable by anyone but root: DHCP leases and
//! client lease state, Wi-Fi passphrases and AP/STA process records, WireGuard
//! profiles and the active-profile marker, and the journal of addresses the
//! daemon installed. The rules are the same for all of them — the directory is
//! `0700`, the file is `0600`, a write is atomic, and a symlink at the target
//! path is refused rather than followed. Callers must trust parent directories.
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

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Default mode for files containing private daemon state or secrets.
pub const PRIVATE_FILE_MODE: u32 = 0o600;

/// Default mode for directories containing private daemon state.
pub const PRIVATE_DIR_MODE: u32 = 0o700;

/// How many names to try before giving up on finding an unused temporary.
const TEMP_NAME_ATTEMPTS: u32 = 100;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Replacement and compensation both failed: the published bytes are uncertain.
#[derive(Debug, thiserror::Error)]
#[error("{operation}; rollback also failed: {rollback}; persisted state is indeterminate")]
pub struct IndeterminateWrite {
    operation: io::Error,
    rollback: io::Error,
}

pub fn is_indeterminate_write(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<io::Error>().is_some_and(|error| {
            error
                .get_ref()
                .is_some_and(|inner| inner.is::<IndeterminateWrite>())
        })
    })
}

#[cfg(any(test, feature = "fault-injection"))]
fn write_faults() -> &'static std::sync::Mutex<std::collections::HashMap<PathBuf, u8>> {
    static FAULTS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<PathBuf, u8>>> =
        std::sync::OnceLock::new();
    FAULTS.get_or_init(Default::default)
}

#[cfg(test)]
fn directory_sync_faults() -> &'static std::sync::Mutex<std::collections::HashSet<PathBuf>> {
    static FAULTS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<PathBuf>>> =
        std::sync::OnceLock::new();
    FAULTS.get_or_init(Default::default)
}

/// Fail after publishing the next replacement, then before publishing its compensation.
#[cfg(any(test, feature = "fault-injection"))]
#[doc(hidden)]
pub fn fail_replacement_and_compensation(path: &Path) {
    write_faults().lock().unwrap().insert(path.to_owned(), 2);
}

#[cfg(any(test, feature = "fault-injection"))]
type WritePause = (std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>);

#[cfg(any(test, feature = "fault-injection"))]
fn write_pauses() -> &'static std::sync::Mutex<std::collections::HashMap<PathBuf, WritePause>> {
    static PAUSES: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<PathBuf, WritePause>>,
    > = std::sync::OnceLock::new();
    PAUSES.get_or_init(Default::default)
}

/// Pause one replacement at its storage boundary. Dropping the release sender
/// releases the worker; a watchdog also prevents a broken test hanging forever.
#[cfg(any(test, feature = "fault-injection"))]
#[doc(hidden)]
pub fn pause_next_replacement(
    path: &Path,
) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    write_pauses()
        .lock()
        .unwrap()
        .insert(path.to_owned(), (entered_tx, release_rx));
    (entered_rx, release_tx)
}

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

/// Return whether `path` is an existing regular file without following symlinks.
///
/// Recovery callers use this instead of `Path::exists`/`try_exists`: those APIs
/// follow symlinks, so a dangling link can look exactly like a missing journal.
/// Existing non-regular objects are rejected as unsafe recovery metadata.
pub fn regular_file_exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsafe symlink at {}", path.display()),
        )),
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Create `path` if it is missing and force `mode` on it durably.
///
/// An existing symlink or non-directory is refused rather than replaced: this
/// runs as root, and silently writing through whatever is already there is the
/// whole class of bug the check exists to prevent.
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
    sync_directory_ancestors(path)?;
    Ok(())
}

/// Create a directory tree and persist every link to its parents.
/// Existing parent permissions are preserved. Callers must trust parents.
/// Sync existing ancestors too: a prior failed call may have created a tree
/// without persisting it, so existence alone is not a durability proof.
pub fn create_dir_all_durable(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    sync_directory_ancestors(path)
}

/// Create and sync a directory tree on the blocking pool.
pub async fn create_dir_all_durable_async(path: &Path) -> io::Result<()> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || create_dir_all_durable(&path))
        .await
        .map_err(io::Error::other)?
}

fn sync_directory_ancestors(path: &Path) -> io::Result<()> {
    let mut previous = None;
    for directory in path.ancestors() {
        // Relative paths end at the empty path, whose containing directory is `.`.
        let directory = if directory.as_os_str().is_empty() {
            Path::new(".")
        } else {
            directory
        };
        if previous != Some(directory) {
            #[cfg(test)]
            if directory_sync_faults().lock().unwrap().remove(directory) {
                return Err(io::Error::other("injected directory sync failure"));
            }
            File::open(directory)?.sync_all()?;
        }
        previous = Some(directory);
    }
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
///
/// # Errors
/// A parent fsync error can occur after rename publishes the new bytes. `Err`
/// does not imply the old file survived. Use [`replace_preserving_on_error`]
/// for compensation; failed compensation leaves an indeterminate outcome.
pub fn replace(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    replace_tracking_publication(path, contents, mode, &mut false)
}

// Only rename publishes bytes. Failures before it leave the destination intact
// and must not trigger another write on an already failing filesystem.
fn replace_tracking_publication(
    path: &Path,
    contents: &[u8],
    mode: u32,
    published: &mut bool,
) -> io::Result<()> {
    #[cfg(any(test, feature = "fault-injection"))]
    {
        let pause = write_pauses().lock().unwrap().remove(path);
        if let Some((entered, release)) = pause {
            let _ = entered.send(());
            let _ = release.recv_timeout(std::time::Duration::from_secs(5));
        }
    }
    #[cfg(any(test, feature = "fault-injection"))]
    let fault = {
        let mut faults = write_faults().lock().unwrap();
        let fault = faults.get(path).copied().unwrap_or(0);
        if fault > 1 {
            faults.insert(path.to_owned(), fault - 1);
        } else {
            faults.remove(path);
        }
        fault
    };
    #[cfg(any(test, feature = "fault-injection"))]
    if fault == 1 {
        return Err(io::Error::other("injected compensation failure"));
    }
    let parent = parent_directory(path);
    reject_symlink(path)?;

    let (temporary, mut file) = create_temporary(path, parent, mode)?;
    let result = (|| -> io::Result<()> {
        // Set the exact mode on the open temporary before publishing it.
        // Creation permissions alone are filtered by the process umask.
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        // Re-checked after the temporary was written: the window between the
        // first check and the rename is exactly when a symlink would be
        // planted.
        reject_symlink(path)?;
        #[cfg(any(test, feature = "fault-injection"))]
        if fault == 3 {
            return Err(io::Error::other("injected failure before rename"));
        }
        fs::rename(&temporary, path)?;
        *published = true;
        #[cfg(any(test, feature = "fault-injection"))]
        if fault == 2 {
            return Err(io::Error::other("injected directory sync failure"));
        }
        File::open(parent)?.sync_all()
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// Run [`replace`] on the blocking pool so file and directory fsyncs do not
/// block the Tokio executor. Propagate both filesystem and worker errors.
/// # Cancellation
/// Dropping or timing out this future does not stop an already running blocking
/// filesystem operation. The write/removal or compensation may finish later.
/// Callers must serialize mutations and retain recovery evidence until the
/// durable outcome is established; cancellation is not successful rollback.
pub async fn replace_async(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let path = path.to_path_buf();
    let contents = contents.to_vec();
    tokio::task::spawn_blocking(move || replace(&path, &contents, mode))
        .await
        .map_err(io::Error::other)?
}

/// Replace a file, attempting to restore its previous bytes if replacement fails.
/// If the file did not exist, remove the newly created target on failure.
/// Return the original error after successful compensation; include both errors
/// when restoration also fails and the final on-disk state may be uncertain.
/// # Examples
///
/// ```
/// use traffic_masq_atomic_file::{replace_preserving_on_error, PRIVATE_FILE_MODE};
/// let directory = tempfile::tempdir()?;
/// let path = directory.path().join("intent.json");
/// replace_preserving_on_error(&path, b"old", PRIVATE_FILE_MODE)?;
/// // An existing symlink is refused before publication.
/// let alias = directory.path().join("alias.json");
/// std::os::unix::fs::symlink(&path, &alias)?;
/// assert!(replace_preserving_on_error(&alias, b"new", PRIVATE_FILE_MODE).is_err());
/// assert_eq!(std::fs::read(&path)?, b"old");
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn replace_preserving_on_error(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let previous = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
    {
        Ok(mut file) => {
            use std::io::Read;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            Some(bytes)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };

    let mut published = false;
    let Err(operation) = replace_tracking_publication(path, contents, mode, &mut published) else {
        return Ok(());
    };
    if !published {
        return Err(operation);
    }
    let rollback = match previous.as_deref() {
        Some(previous) => replace(path, previous, mode),
        None => remove_durable(path).map(|_| ()),
    };
    match rollback {
        Ok(()) => Err(operation),
        Err(rollback) => Err(io::Error::other(IndeterminateWrite {
            operation,
            rollback,
        })),
    }
}

/// Async wrapper for [`replace_preserving_on_error`].
/// # Cancellation
/// Dropping or timing out this future does not stop an already running blocking
/// filesystem operation. The write/removal or compensation may finish later.
/// Callers must serialize mutations and retain recovery evidence until the
/// durable outcome is established; cancellation is not successful rollback.
pub async fn replace_preserving_on_error_async(
    path: &Path,
    contents: &[u8],
    mode: u32,
) -> io::Result<()> {
    let path = path.to_path_buf();
    let contents = contents.to_vec();
    tokio::task::spawn_blocking(move || replace_preserving_on_error(&path, &contents, mode))
        .await
        .map_err(io::Error::other)?
}

/// Remove `path` durably. A successful return means both the directory entry
/// was removed and the parent directory was fsynced, so crash recovery cannot
/// resurrect a record that callers already treated as cleared. Returns false
/// for an absent entry. A parent fsync error may occur after deletion; `Err`
/// does not imply the file still exists. See [`remove_preserving_on_error`].
pub fn remove_durable(path: &Path) -> io::Result<bool> {
    reject_symlink(path)?;
    match fs::remove_file(path) {
        Ok(()) => {
            let parent = parent_directory(path);
            File::open(parent)?.sync_all()?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Remove a regular file with strong failure semantics. If this returns
/// `Err`, the exact previous bytes are restored unless that restoration also
/// fails (in which case the combined error makes the ambiguity explicit).
pub fn remove_preserving_on_error(path: &Path, mode: u32) -> io::Result<bool> {
    let previous = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
    {
        Ok(mut file) => {
            use std::io::Read;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            bytes
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };

    let Err(operation) = remove_durable(path) else {
        return Ok(true);
    };
    match replace(path, &previous, mode) {
        Ok(()) => Err(operation),
        Err(rollback) => Err(io::Error::other(format!(
            "{operation}; rollback also failed: {rollback}"
        ))),
    }
}

/// Async wrapper for [`remove_preserving_on_error`].
/// # Cancellation
/// Dropping or timing out this future does not stop an already running blocking
/// filesystem operation. The write/removal or compensation may finish later.
/// Callers must serialize mutations and retain recovery evidence until the
/// durable outcome is established; cancellation is not successful rollback.
pub async fn remove_preserving_on_error_async(path: &Path, mode: u32) -> io::Result<bool> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || remove_preserving_on_error(&path, mode))
        .await
        .map_err(io::Error::other)?
}

/// Async wrapper for [`remove_durable`].
/// # Cancellation
/// Dropping or timing out this future does not stop an already running blocking
/// filesystem operation. The write/removal or compensation may finish later.
/// Callers must serialize mutations and retain recovery evidence until the
/// durable outcome is established; cancellation is not successful rollback.
pub async fn remove_durable_async(path: &Path) -> io::Result<bool> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || remove_durable(&path))
        .await
        .map_err(io::Error::other)?
}

/// Return the containing directory, treating a bare filename as relative to `.`.
fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
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
mod tests;
