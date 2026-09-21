//! Terminal recovery receipts and metadata-only housekeeping.
//!
//! A receipt authenticates the exact journal bytes, not a filename or token.
//! Never overwrite a journal while its retirement is still pending.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

fn pending() -> &'static Mutex<BTreeMap<PathBuf, Vec<u8>>> {
    static PENDING: OnceLock<Mutex<BTreeMap<PathBuf, Vec<u8>>>> = OnceLock::new();
    PENDING.get_or_init(Mutex::default)
}

fn events() -> &'static tokio::sync::watch::Sender<u64> {
    static EVENTS: OnceLock<tokio::sync::watch::Sender<u64>> = OnceLock::new();
    EVENTS.get_or_init(|| tokio::sync::watch::channel(0).0)
}

pub fn subscribe() -> tokio::sync::watch::Receiver<u64> {
    events().subscribe()
}

fn receipt(path: &Path) -> PathBuf {
    path.with_extension("json.recovered")
}

pub fn cleanup_pending(path: &Path) -> bool {
    pending()
        .lock()
        .expect("recovery housekeeping lock")
        .contains_key(path)
}

pub async fn completed(path: &Path, bytes: &[u8]) -> Result<bool> {
    let digest = Sha256::digest(bytes).to_vec();
    if pending()
        .lock()
        .expect("recovery housekeeping lock")
        .get(path)
        == Some(&digest)
    {
        return Ok(true);
    }
    let marker = receipt(path);
    crate::atomic_file::reject_symlink(&marker)?;
    match tokio::fs::read(marker).await {
        Ok(saved) => Ok(saved == digest),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Call only after restoration (including runtime consumers) or durable commit.
/// Unlink/fsync/receipt-write failures cannot undo that completed operation.
pub async fn retire(path: &Path) -> Result<()> {
    crate::atomic_file::reject_symlink(path)?;
    let bytes = match tokio::fs::read(path).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("operation=read_completed_journal; invariant=retain_recovery_proof; metadata_safe_to_remove=true"),
    };
    let digest = Sha256::digest(&bytes).to_vec();
    let first = pending()
        .lock()
        .expect("recovery housekeeping lock")
        .insert(path.to_owned(), digest)
        .is_none();
    if let Err(error) = housekeeping(path).await {
        tracing::warn!(journal = %path.display(), operation = "retire_journal",
            invariant = "kernel_restored_metadata_pending", metadata_safe_to_remove = true,
            state = "recovered_but_journal_cleanup_pending", error = %format!("{error:#}"),
            "recovery completed; housekeeping will retry separately");
        if first {
            let path = path.to_owned();
            tokio::spawn(async move {
                while cleanup_pending(&path) {
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    if let Err(error) = housekeeping(&path).await {
                        tracing::warn!(journal = %path.display(), operation = "journal_housekeeping",
                            metadata_safe_to_remove = true, %error, "journal cleanup still pending");
                    }
                }
            });
        }
    }
    Ok(())
}

async fn housekeeping(path: &Path) -> Result<()> {
    // Serializes the background retry with pre-write housekeeping. New writes
    // are admitted only after the old journal AND receipt have been removed.
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    let _lock = LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let Some(digest) = pending()
        .lock()
        .expect("recovery housekeeping lock")
        .get(path)
        .cloned()
    else {
        return Ok(());
    };
    crate::atomic_file::reject_symlink(path)?;
    match tokio::fs::read(path).await {
        Ok(bytes) => {
            anyhow::ensure!(Sha256::digest(&bytes).to_vec() == digest,
                "invariant=journal_identity; operation=cleanup; journal={}; metadata_safe_to_remove=false: journal changed", path.display());
            // Try unlink even if persisting a receipt failed. If both fail,
            // the in-memory receipt still prevents replay during this run.
            let marker = receipt(path);
            if let Err(error) =
                crate::atomic_file::replace_preserving_on_error_async(&marker, &digest, 0o600).await
            {
                tracing::warn!(journal = %path.display(), %error, "could not persist recovery receipt");
            }
            crate::atomic_file::remove_preserving_on_error_async(path, 0o600).await?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    crate::atomic_file::remove_preserving_on_error_async(&receipt(path), 0o600).await?;
    pending()
        .lock()
        .expect("recovery housekeeping lock")
        .remove(path);
    events().send_modify(|epoch| *epoch = epoch.wrapping_add(1));
    Ok(())
}

pub async fn before_write(path: &Path) -> Result<()> {
    housekeeping(path).await.with_context(|| format!(
        "journal={}; state=recovered_but_journal_cleanup_pending; operation=admit_new_transaction; metadata_safe_to_remove=true", path.display()))?;
    anyhow::ensure!(
        !cleanup_pending(path),
        "journal cleanup pending: {}",
        path.display()
    );
    // A crash can occur between unlinking the journal and its receipt. Never
    // let an orphan receipt authenticate a future identical secret journal.
    crate::atomic_file::remove_preserving_on_error_async(&receipt(path), 0o600).await?;
    Ok(())
}

/// Caller must supply independent proof that replay is unnecessary. Unknown
/// ownership is never inferred merely from a parse failure or an old revision.
pub async fn quarantine(path: &Path, suffix: &str) -> Result<()> {
    anyhow::ensure!(
        matches!(suffix, "corrupt" | "stale"),
        "invalid quarantine suffix"
    );
    crate::atomic_file::reject_symlink(path)?;
    let bytes = tokio::fs::read(path).await?;
    let identity = format!("{:x}", Sha256::digest(&bytes));
    let destination = path.with_extension(format!("json.{identity}.{suffix}"));
    crate::atomic_file::reject_symlink(&destination)?;
    // A hard link gives no-clobber semantics; retain the source on any error.
    match tokio::fs::hard_link(path, &destination).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            anyhow::ensure!(
                tokio::fs::read(&destination).await? == bytes,
                "quarantine identity conflict"
            );
        }
        Err(error) => return Err(error.into()),
    }
    let parent = path.parent().context("journal has no parent")?.to_owned();
    tokio::task::spawn_blocking(move || std::fs::File::open(parent)?.sync_all()).await??;
    retire(path).await
}

fn blocked() -> &'static Mutex<BTreeMap<PathBuf, BTreeMap<String, String>>> {
    static BLOCKED: OnceLock<Mutex<BTreeMap<PathBuf, BTreeMap<String, String>>>> = OnceLock::new();
    BLOCKED.get_or_init(Mutex::default)
}

pub fn block_interface(root: &Path, interface: &str, reason: String) {
    tracing::error!(object = %interface, journal = %root.join("interface-transactions").join(format!("{interface}.json")).display(),
        invariant = "restore_before_mutation", operation = "recover_interface",
        metadata_safe_to_remove = false, error = %reason, "interface blocked; other interfaces remain available");
    blocked()
        .lock()
        .expect("recovery scope lock")
        .entry(root.to_owned())
        .or_default()
        .insert(interface.to_owned(), reason);
}

/// Interfaces with unresolved startup recovery, excluding cleanup-only work.
pub(crate) fn blocked_interfaces(root: &Path) -> Vec<String> {
    blocked()
        .lock()
        .expect("recovery scope lock")
        .get(root)
        .map(|scopes| scopes.keys().cloned().collect())
        .unwrap_or_default()
}

pub fn unblock_interface(root: &Path, interface: &str) {
    if let Some(scopes) = blocked().lock().expect("recovery scope lock").get_mut(root) {
        scopes.remove(interface);
    }
}

pub fn check_scope(root: &Path, interface: Option<&str>) -> Result<()> {
    let cleanup = pending().lock().expect("recovery housekeeping lock");
    for path in cleanup.keys().filter(|path| path.starts_with(root)) {
        let scoped = path.parent() == Some(root.join("interface-transactions").as_path());
        let name = path.file_stem().and_then(|name| name.to_str());
        if !scoped || interface.is_none() || name == interface {
            anyhow::bail!("journal={}; state=recovered_but_journal_cleanup_pending; operation=admit_mutation; metadata_safe_to_remove=true", path.display());
        }
    }
    drop(cleanup);
    let guard = blocked().lock().expect("recovery scope lock");
    if let Some(scopes) = guard.get(root) {
        for (name, reason) in scopes {
            if interface.is_none_or(|interface| interface == name) {
                anyhow::bail!("interface={name}; invariant=restore_before_mutation; operation=admit_mutation; metadata_safe_to_remove=false; recovery blocked: {reason}");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn receipt_proves_only_the_exact_journal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transaction.json");
        tokio::fs::write(receipt(&path), Sha256::digest(b"old").as_slice())
            .await
            .unwrap();
        assert!(completed(&path, b"old").await.unwrap());
        assert!(!completed(&path, b"new").await.unwrap());
    }

    #[tokio::test]
    async fn housekeeping_failure_does_not_fail_restoration_or_allow_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transaction.json");
        tokio::fs::write(&path, b"restored").await.unwrap();
        // A directory at the receipt path forces housekeeping failure even as root.
        tokio::fs::create_dir(receipt(&path)).await.unwrap();
        retire(&path).await.unwrap();
        assert!(cleanup_pending(&path));
        assert!(before_write(&path).await.is_err());
        tokio::fs::remove_dir(receipt(&path)).await.unwrap();
        before_write(&path).await.unwrap();
        assert!(!cleanup_pending(&path));
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn housekeeping_never_removes_a_different_journal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transaction.json");
        tokio::fs::write(&path, b"new").await.unwrap();
        pending()
            .lock()
            .unwrap()
            .insert(path.clone(), Sha256::digest(b"old").to_vec());
        assert!(before_write(&path).await.is_err());
        assert_eq!(tokio::fs::read(&path).await.unwrap(), b"new");
        pending().lock().unwrap().remove(&path);
    }

    #[tokio::test]
    async fn quarantine_preserves_evidence_and_is_repeatable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transaction.json");
        for _ in 0..2 {
            tokio::fs::write(&path, b"committed").await.unwrap();
            quarantine(&path, "stale").await.unwrap();
            assert!(!path.exists());
        }
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 1);
        assert!(entries[0]
            .as_ref()
            .unwrap()
            .path()
            .to_string_lossy()
            .ends_with(".stale"));
    }

    #[test]
    fn blocked_scope_does_not_block_another_interface_or_state_directory() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        block_interface(dir.path(), "wlan0", "invalid snapshot".into());
        assert!(check_scope(dir.path(), Some("wlan0")).is_err());
        assert!(check_scope(dir.path(), Some("eth0")).is_ok());
        assert!(check_scope(other.path(), Some("wlan0")).is_ok());
        assert!(check_scope(dir.path(), None).is_err());
    }
}

#[cfg(test)]
mod crash_tests {
    use super::*;

    #[tokio::test]
    async fn new_transaction_cannot_inherit_an_orphan_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        tokio::fs::write(receipt(&path), Sha256::digest(b"same bytes").as_slice())
            .await
            .unwrap();
        before_write(&path).await.unwrap();
        tokio::fs::write(&path, b"same bytes").await.unwrap();
        assert!(!completed(&path, b"same bytes").await.unwrap());
    }
}
