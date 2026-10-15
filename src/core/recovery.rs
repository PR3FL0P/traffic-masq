//! Terminal recovery receipts and metadata-only housekeeping.
//!
//! A receipt authenticates the exact journal bytes, not a filename or token.
//! Never overwrite a journal while its retirement is still pending.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryCode {
    AccessibleInterfaceRecoveryStore,
    ProvableRouterRecovery,
    AccessibleRouterRecoveryJournal,
    DecodableRecoverySnapshot,
    ValidRecoverySnapshot,
    SupportedSchema,
    RevisionOrder,
    RouterRollbackFailed,
    RouterJournalCleanupPending,
    CommitIndeterminate,
    RestoreProvisioningSecrets,
    ValidProvisioningSecretSnapshot,
    SupportedProvisioningSecretSchema,
}

impl RecoveryCode {
    pub const ALL: &'static [Self] = &[
        Self::AccessibleInterfaceRecoveryStore,
        Self::ProvableRouterRecovery,
        Self::AccessibleRouterRecoveryJournal,
        Self::DecodableRecoverySnapshot,
        Self::ValidRecoverySnapshot,
        Self::SupportedSchema,
        Self::RevisionOrder,
        Self::RouterRollbackFailed,
        Self::RouterJournalCleanupPending,
        Self::CommitIndeterminate,
        Self::RestoreProvisioningSecrets,
        Self::ValidProvisioningSecretSnapshot,
        Self::SupportedProvisioningSecretSchema,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccessibleInterfaceRecoveryStore => "TM-REC-101",
            Self::ProvableRouterRecovery => "TM-REC-201",
            Self::AccessibleRouterRecoveryJournal => "TM-REC-202",
            Self::DecodableRecoverySnapshot => "TM-REC-203",
            Self::ValidRecoverySnapshot => "TM-REC-204",
            Self::SupportedSchema => "TM-REC-205",
            Self::RevisionOrder => "TM-REC-206",
            Self::RouterRollbackFailed => "TM-REC-207",
            Self::RouterJournalCleanupPending => "TM-REC-208",
            Self::CommitIndeterminate => "TM-REC-209",
            Self::RestoreProvisioningSecrets => "TM-REC-301",
            Self::ValidProvisioningSecretSnapshot => "TM-REC-302",
            Self::SupportedProvisioningSecretSchema => "TM-REC-303",
        }
    }

    pub fn from_code(value: &str) -> Option<Self> {
        Some(match value {
            "TM-REC-101" => Self::AccessibleInterfaceRecoveryStore,
            "TM-REC-201" => Self::ProvableRouterRecovery,
            "TM-REC-202" => Self::AccessibleRouterRecoveryJournal,
            "TM-REC-203" => Self::DecodableRecoverySnapshot,
            "TM-REC-204" => Self::ValidRecoverySnapshot,
            "TM-REC-205" => Self::SupportedSchema,
            "TM-REC-206" => Self::RevisionOrder,
            "TM-REC-207" => Self::RouterRollbackFailed,
            "TM-REC-208" => Self::RouterJournalCleanupPending,
            "TM-REC-209" => Self::CommitIndeterminate,
            "TM-REC-301" => Self::RestoreProvisioningSecrets,
            "TM-REC-302" => Self::ValidProvisioningSecretSnapshot,
            "TM-REC-303" => Self::SupportedProvisioningSecretSchema,
            _ => return None,
        })
    }

    pub const fn invariant(self) -> &'static str {
        match self {
            Self::AccessibleInterfaceRecoveryStore => "accessible_interface_recovery_store",
            Self::ProvableRouterRecovery => "provable_router_recovery",
            Self::AccessibleRouterRecoveryJournal => "accessible_router_recovery_journal",
            Self::DecodableRecoverySnapshot => "decodable_recovery_snapshot",
            Self::ValidRecoverySnapshot => "valid_recovery_snapshot",
            Self::SupportedSchema => "supported_schema",
            Self::RevisionOrder => "revision_order",
            Self::RouterRollbackFailed => "router_rollback_failed",
            Self::RouterJournalCleanupPending => "router_journal_cleanup_pending",
            Self::CommitIndeterminate => "commit_indeterminate",
            Self::RestoreProvisioningSecrets => "restore_provisioning_secrets",
            Self::ValidProvisioningSecretSnapshot => "valid_provisioning_secret_snapshot",
            Self::SupportedProvisioningSecretSchema => "supported_provisioning_secret_schema",
        }
    }

    pub const fn is_startup_blocking(self) -> bool {
        !matches!(
            self,
            Self::RouterRollbackFailed
                | Self::RouterJournalCleanupPending
                | Self::CommitIndeterminate
        )
    }

    pub const fn runbook_ref(self) -> &'static str {
        match self {
            Self::AccessibleInterfaceRecoveryStore => "docs/recovery.md#tm-rec-101",
            Self::ProvableRouterRecovery => "docs/recovery.md#tm-rec-201",
            Self::AccessibleRouterRecoveryJournal => "docs/recovery.md#tm-rec-202",
            Self::DecodableRecoverySnapshot => "docs/recovery.md#tm-rec-203",
            Self::ValidRecoverySnapshot => "docs/recovery.md#tm-rec-204",
            Self::SupportedSchema => "docs/recovery.md#tm-rec-205",
            Self::RevisionOrder => "docs/recovery.md#tm-rec-206",
            Self::RouterRollbackFailed => "docs/recovery.md#tm-rec-207",
            Self::RouterJournalCleanupPending => "docs/recovery.md#tm-rec-208",
            Self::CommitIndeterminate => "docs/recovery.md#tm-rec-209",
            Self::RestoreProvisioningSecrets => "docs/recovery.md#tm-rec-301",
            Self::ValidProvisioningSecretSnapshot => "docs/recovery.md#tm-rec-302",
            Self::SupportedProvisioningSecretSchema => "docs/recovery.md#tm-rec-303",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupRecoveryCode {
    AccessibleInterfaceRecoveryStore,
    ProvableRouterRecovery,
    AccessibleRouterRecoveryJournal,
    DecodableRecoverySnapshot,
    ValidRecoverySnapshot,
    SupportedSchema,
    RevisionOrder,
    RestoreProvisioningSecrets,
    ValidProvisioningSecretSnapshot,
    SupportedProvisioningSecretSchema,
}

impl StartupRecoveryCode {
    pub const ALL: &'static [Self] = &[
        Self::AccessibleInterfaceRecoveryStore,
        Self::ProvableRouterRecovery,
        Self::AccessibleRouterRecoveryJournal,
        Self::DecodableRecoverySnapshot,
        Self::ValidRecoverySnapshot,
        Self::SupportedSchema,
        Self::RevisionOrder,
        Self::RestoreProvisioningSecrets,
        Self::ValidProvisioningSecretSnapshot,
        Self::SupportedProvisioningSecretSchema,
    ];
}

impl From<StartupRecoveryCode> for RecoveryCode {
    fn from(code: StartupRecoveryCode) -> Self {
        match code {
            StartupRecoveryCode::AccessibleInterfaceRecoveryStore => {
                Self::AccessibleInterfaceRecoveryStore
            }
            StartupRecoveryCode::ProvableRouterRecovery => Self::ProvableRouterRecovery,
            StartupRecoveryCode::AccessibleRouterRecoveryJournal => {
                Self::AccessibleRouterRecoveryJournal
            }
            StartupRecoveryCode::DecodableRecoverySnapshot => Self::DecodableRecoverySnapshot,
            StartupRecoveryCode::ValidRecoverySnapshot => Self::ValidRecoverySnapshot,
            StartupRecoveryCode::SupportedSchema => Self::SupportedSchema,
            StartupRecoveryCode::RevisionOrder => Self::RevisionOrder,
            StartupRecoveryCode::RestoreProvisioningSecrets => Self::RestoreProvisioningSecrets,
            StartupRecoveryCode::ValidProvisioningSecretSnapshot => {
                Self::ValidProvisioningSecretSnapshot
            }
            StartupRecoveryCode::SupportedProvisioningSecretSchema => {
                Self::SupportedProvisioningSecretSchema
            }
        }
    }
}

impl std::fmt::Display for RecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

pub use traffic_masq_protocol::RecoveryAction;

pub const RECOVERY_DIAGNOSTIC_RECORD_VERSION: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryDiagnosticRecord {
    pub version: u8,
    #[serde(default)]
    pub recovery_code: String,
    #[serde(default)]
    pub runbook: String,
    pub invariant: String,
    pub object: Option<String>,
    pub journal: Option<PathBuf>,
    pub path: Option<PathBuf>,
    pub operation: String,
    pub metadata_safe_to_remove: bool,
    pub details: BTreeMap<String, String>,
    pub operator_action: String,
    pub operator_guidance: String,
}

#[derive(Debug, Clone)]
pub struct RecoveryDiagnostic {
    recovery_code: RecoveryCode,
    object: Option<&'static str>,
    journal: Option<PathBuf>,
    path: Option<PathBuf>,
    operation: &'static str,
    metadata_safe_to_remove: bool,
    details: Vec<(&'static str, String)>,
    operator_action: RecoveryAction,
}

impl RecoveryDiagnostic {
    pub fn fatal(
        recovery_code: StartupRecoveryCode,
        operation: &'static str,
        operator_action: RecoveryAction,
    ) -> Self {
        Self {
            recovery_code: recovery_code.into(),
            object: None,
            journal: None,
            path: None,
            operation,
            metadata_safe_to_remove: false,
            details: Vec::new(),
            operator_action,
        }
    }

    pub fn object(mut self, object: &'static str) -> Self {
        self.object = Some(object);
        self
    }

    pub fn journal(mut self, journal: impl Into<PathBuf>) -> Self {
        self.journal = Some(journal.into());
        self
    }

    pub fn path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn detail(mut self, key: &'static str, value: impl ToString) -> Self {
        self.details.push((key, value.to_string()));
        self
    }

    pub fn record(&self) -> RecoveryDiagnosticRecord {
        RecoveryDiagnosticRecord {
            version: RECOVERY_DIAGNOSTIC_RECORD_VERSION,
            recovery_code: self.recovery_code.as_str().to_owned(),
            runbook: self.recovery_code.runbook_ref().to_owned(),
            invariant: self.recovery_code.invariant().to_owned(),
            object: self.object.map(str::to_owned),
            journal: self.journal.clone(),
            path: self.path.clone(),
            operation: self.operation.to_owned(),
            metadata_safe_to_remove: self.metadata_safe_to_remove,
            details: self
                .details
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone()))
                .collect(),
            operator_action: self.operator_action.as_str().to_owned(),
            operator_guidance: self.operator_action.guidance().to_owned(),
        }
    }
}

impl std::error::Error for RecoveryDiagnostic {}

pub fn diagnostic_from_error(error: &anyhow::Error) -> Option<&RecoveryDiagnostic> {
    error.downcast_ref::<RecoveryDiagnostic>()
}

pub fn context_if_missing(error: anyhow::Error, fallback: RecoveryDiagnostic) -> anyhow::Error {
    if diagnostic_from_error(&error).is_some() {
        error
    } else {
        error.context(fallback)
    }
}

impl std::fmt::Display for RecoveryDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "recovery_code={}; invariant={}; runbook={}; operation={}; metadata_safe_to_remove={}",
            self.recovery_code,
            self.recovery_code.invariant(),
            self.recovery_code.runbook_ref(),
            self.operation,
            self.metadata_safe_to_remove
        )?;
        if let Some(object) = self.object {
            write!(f, "; object={object}")?;
        }
        if let Some(path) = &self.path {
            write!(f, "; path={}", path.display())?;
        }
        if let Some(journal) = &self.journal {
            write!(f, "; journal={}", journal.display())?;
        }
        for (key, value) in &self.details {
            write!(f, "; {key}={value}")?;
        }
        write!(
            f,
            "; operator_action={}; operator_guidance={}",
            self.operator_action,
            self.operator_action.guidance()
        )
    }
}

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
    crate::core::recovery_control::forget(path);
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
    let path = path.to_owned();
    // A cancelled caller cannot release the lock while a blocking receipt
    // writer/unlink still runs. The owner finishes cleanup before a later
    // before_write can admit another journal at this path.
    tokio::spawn(async move { housekeeping_owned(&path).await }).await?
}

async fn housekeeping_owned(path: &Path) -> Result<()> {
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
    crate::core::recovery_control::remove_control(path).await?;
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
    crate::atomic_file::remove_preserving_on_error_async(
        &crate::core::recovery_control::control_path(path),
        0o600,
    )
    .await?;
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

#[derive(Debug, Clone)]
struct InterfaceBlock {
    reason: String,
    retry_transaction: bool,
}

fn blocked() -> &'static Mutex<BTreeMap<PathBuf, BTreeMap<String, InterfaceBlock>>> {
    static BLOCKED: OnceLock<Mutex<BTreeMap<PathBuf, BTreeMap<String, InterfaceBlock>>>> =
        OnceLock::new();
    BLOCKED.get_or_init(Mutex::default)
}

fn block_interface_inner(
    root: &Path,
    interface: &str,
    recovery_path: &Path,
    reason: String,
    retry_transaction: bool,
) {
    tracing::error!(object = %interface, journal = %recovery_path.display(),
        invariant = "restore_before_mutation", operation = "recover_interface",
        metadata_safe_to_remove = false, error = %reason, "interface blocked; other interfaces remain available");
    blocked()
        .lock()
        .expect("recovery scope lock")
        .entry(root.to_owned())
        .or_default()
        .insert(
            interface.to_owned(),
            InterfaceBlock {
                reason,
                retry_transaction,
            },
        );
}

pub fn block_interface(root: &Path, interface: &str, reason: String) {
    let recovery_path = root
        .join("interface-transactions")
        .join(format!("{interface}.json"));
    block_interface_inner(root, interface, &recovery_path, reason, true);
}

/// Fence an interface for recovery metadata outside the interface-transaction store.
///
/// The transaction retry loop must not clear this block: the foreign metadata must be repaired and
/// reloaded first.
pub fn block_interface_nonretryable(
    root: &Path,
    interface: &str,
    recovery_path: &Path,
    reason: String,
) {
    block_interface_inner(root, interface, recovery_path, reason, false);
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

/// Interface-transaction failures that the background retry loop is allowed to retry.
pub(crate) fn retryable_blocked_interfaces(root: &Path) -> Vec<String> {
    blocked()
        .lock()
        .expect("recovery scope lock")
        .get(root)
        .map(|scopes| {
            scopes
                .iter()
                .filter(|(_, block)| block.retry_transaction)
                .map(|(name, _)| name.clone())
                .collect()
        })
        .unwrap_or_default()
}

pub fn unblock_interface(root: &Path, interface: &str) {
    if let Some(scopes) = blocked().lock().expect("recovery scope lock").get_mut(root) {
        scopes.remove(interface);
    }
}

// A failed commit must never be compensated using an obsolete in-memory revision.
// This fence lasts for the process lifetime. Startup independently reloads the
// authoritative document and commit tokens after storage access is repaired.
fn uncertain_commits() -> &'static Mutex<BTreeMap<PathBuf, String>> {
    static COMMITS: OnceLock<Mutex<BTreeMap<PathBuf, String>>> = OnceLock::new();
    COMMITS.get_or_init(Default::default)
}

pub(crate) fn fence_commit(root: &Path, reason: String) {
    uncertain_commits()
        .lock()
        .expect("commit fence lock")
        .insert(root.to_owned(), reason);
}

// Settings-only writes can leave the document revision uncertain while both
// possible documents carry identical network intent and commit proof. Keep all
// further persistence fenced, without disabling compensation of that network.
fn uncertain_settings() -> &'static Mutex<BTreeMap<PathBuf, String>> {
    static SETTINGS: OnceLock<Mutex<BTreeMap<PathBuf, String>>> = OnceLock::new();
    SETTINGS.get_or_init(Default::default)
}

pub(crate) fn fence_settings(root: &Path, reason: String) {
    uncertain_settings()
        .lock()
        .expect("settings fence lock")
        .insert(root.to_owned(), reason);
}

pub(crate) fn check_persistence(root: &Path) -> Result<()> {
    check_commit(root)?;
    if let Some(reason) = uncertain_settings()
        .lock()
        .expect("settings fence lock")
        .get(root)
    {
        anyhow::bail!("state=settings_commit_indeterminate; configuration writes blocked; network recovery remains available; restart to reload settings: {reason}");
    }
    Ok(())
}

pub(crate) fn commit_uncertainty(root: &Path) -> Option<String> {
    uncertain_commits()
        .lock()
        .expect("commit fence lock")
        .get(root)
        .cloned()
}

pub(crate) fn check_commit(root: &Path) -> Result<()> {
    if let Some(reason) = commit_uncertainty(root) {
        anyhow::bail!("state=commit_indeterminate; mutations and rollback blocked; repair storage access and restart the daemon to resolve persisted commit proof: {reason}");
    }
    Ok(())
}

pub fn check_scope(root: &Path, interface: Option<&str>) -> Result<()> {
    check_scope_inner(root, interface, None)
}

/// An explicit retry may bypass only its own transaction stop, never an
/// ownership block, another recovery scope, cleanup, or uncertain commit.
pub fn check_rollback_scope(root: &Path, interface: Option<&str>, journal: &Path) -> Result<()> {
    check_scope_inner(root, interface, Some(journal))
}

fn check_scope_inner(root: &Path, interface: Option<&str>, retry: Option<&Path>) -> Result<()> {
    check_commit(root)?;
    crate::core::recovery_control::check_runtime_except(root, interface, retry)?;
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
        for (name, block) in scopes {
            let journal = root
                .join("interface-transactions")
                .join(format!("{name}.json"));
            if block.retry_transaction
                && retry == Some(journal.as_path())
                && crate::core::recovery_control::stopped(&journal)
            {
                continue;
            }
            if interface.is_none_or(|interface| interface == name) {
                anyhow::bail!("interface={name}; invariant=restore_before_mutation; operation=admit_mutation; metadata_safe_to_remove=false; recovery blocked: {}", block.reason);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonretryable_interface_block_is_visible_but_not_transaction_retryable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("address-ownership/lan0.json");
        block_interface_nonretryable(dir.path(), "lan0", &path, "invalid ownership".into());

        assert_eq!(blocked_interfaces(dir.path()), vec!["lan0".to_string()]);
        assert!(retryable_blocked_interfaces(dir.path()).is_empty());
        assert!(check_scope(dir.path(), Some("lan0")).is_err());
        unblock_interface(dir.path(), "lan0");
    }

    #[test]
    fn fatal_diagnostic_has_stable_journal_format() {
        let diagnostic = RecoveryDiagnostic::fatal(
            StartupRecoveryCode::RevisionOrder,
            "validate",
            crate::core::recovery::RecoveryAction::RestoreCoherentBackup,
        )
        .journal("/state/router-transaction.json")
        .object("router")
        .detail("journal_base_revision", 15)
        .detail("committed_revision", 14)
        .to_string();
        assert_eq!(
            diagnostic,
            "recovery_code=TM-REC-206; invariant=revision_order; runbook=docs/recovery.md#tm-rec-206; operation=validate; metadata_safe_to_remove=false; object=router; journal=/state/router-transaction.json; journal_base_revision=15; committed_revision=14; operator_action=restore_coherent_backup; operator_guidance=restore the complete state directory from one coherent backup and do not replace a journal alone"
        );
    }

    #[test]
    fn fatal_diagnostic_distinguishes_resource_path_from_journal() {
        let diagnostic = RecoveryDiagnostic::fatal(
            StartupRecoveryCode::AccessibleInterfaceRecoveryStore,
            "open",
            crate::core::recovery::RecoveryAction::RepairStorageAccess,
        )
        .path("/state/interface-transactions")
        .object("interface-transactions")
        .detail("expected_type", "directory")
        .detail("expected_mode", "0700")
        .detail("symlink_allowed", false)
        .to_string();
        assert_eq!(
            diagnostic,
            "recovery_code=TM-REC-101; invariant=accessible_interface_recovery_store; runbook=docs/recovery.md#tm-rec-101; operation=open; metadata_safe_to_remove=false; object=interface-transactions; path=/state/interface-transactions; expected_type=directory; expected_mode=0700; symlink_allowed=false; operator_action=repair_storage_access; operator_guidance=preserve recovery metadata and repair the reported path type permissions or storage access"
        );
        assert!(!diagnostic.contains("journal="));
    }

    #[test]
    fn typed_diagnostic_survives_anyhow_context() {
        let diagnostic = RecoveryDiagnostic::fatal(
            StartupRecoveryCode::RevisionOrder,
            "validate",
            RecoveryAction::RestoreCoherentBackup,
        )
        .journal("/state/router-transaction.json")
        .detail("journal_base_revision", 15);
        let error = anyhow::Error::msg("revision mismatch").context(diagnostic);
        let recovered = diagnostic_from_error(&error).expect("typed recovery diagnostic");
        let record = recovered.record();
        assert_eq!(record.version, RECOVERY_DIAGNOSTIC_RECORD_VERSION);
        assert_eq!(record.recovery_code, "TM-REC-206");
        assert_eq!(record.runbook, "docs/recovery.md#tm-rec-206");
        assert_eq!(record.invariant, "revision_order");
        assert_eq!(record.operator_action, "restore_coherent_backup");
        assert_eq!(
            record
                .details
                .get("journal_base_revision")
                .map(String::as_str),
            Some("15")
        );
    }

    #[test]
    fn recovery_fallback_does_not_hide_specific_diagnostic() {
        let specific = RecoveryDiagnostic::fatal(
            StartupRecoveryCode::RevisionOrder,
            "validate",
            RecoveryAction::RestoreCoherentBackup,
        );
        let error = anyhow::Error::msg("revision mismatch").context(specific);
        let wrapped = context_if_missing(
            error,
            RecoveryDiagnostic::fatal(
                crate::core::recovery::StartupRecoveryCode::ProvableRouterRecovery,
                "startup_recovery",
                RecoveryAction::InspectRecoveryState,
            ),
        );
        assert_eq!(
            diagnostic_from_error(&wrapped)
                .expect("specific diagnostic")
                .record()
                .invariant,
            "revision_order"
        );
    }

    #[test]
    fn recovery_code_assignments_are_stable() {
        let assignments: Vec<_> = RecoveryCode::ALL
            .iter()
            .map(|code| (code.as_str(), code.invariant()))
            .collect();
        assert_eq!(
            assignments,
            vec![
                ("TM-REC-101", "accessible_interface_recovery_store"),
                ("TM-REC-201", "provable_router_recovery"),
                ("TM-REC-202", "accessible_router_recovery_journal"),
                ("TM-REC-203", "decodable_recovery_snapshot"),
                ("TM-REC-204", "valid_recovery_snapshot"),
                ("TM-REC-205", "supported_schema"),
                ("TM-REC-206", "revision_order"),
                ("TM-REC-207", "router_rollback_failed"),
                ("TM-REC-208", "router_journal_cleanup_pending"),
                ("TM-REC-209", "commit_indeterminate"),
                ("TM-REC-301", "restore_provisioning_secrets"),
                ("TM-REC-302", "valid_provisioning_secret_snapshot"),
                ("TM-REC-303", "supported_provisioning_secret_schema"),
            ]
        );
    }

    #[test]
    fn recovery_codes_are_unique_round_trip_and_have_runbook_sections() {
        let runbook = include_str!("../../docs/recovery.md");
        let mut codes = std::collections::BTreeSet::new();
        let mut invariants = std::collections::BTreeSet::new();

        for code in RecoveryCode::ALL {
            assert!(
                codes.insert(code.as_str()),
                "duplicate recovery code {}",
                code
            );
            assert!(
                invariants.insert(code.invariant()),
                "duplicate recovery invariant {}",
                code.invariant()
            );
            assert_eq!(RecoveryCode::from_code(code.as_str()), Some(*code));
            let anchor = code
                .runbook_ref()
                .split_once('#')
                .expect("runbook reference has anchor")
                .1;
            assert!(
                runbook.contains(&format!("<a id=\"{anchor}\"></a>")),
                "missing runbook anchor for {}",
                code
            );
        }

        assert_eq!(codes.len(), 13);
        assert_eq!(invariants.len(), 13);
        assert_eq!(RecoveryCode::from_code("TM-REC-999"), None);
    }

    #[test]
    fn only_degraded_router_codes_are_non_blocking() {
        for code in RecoveryCode::ALL {
            let expected = !matches!(
                code,
                RecoveryCode::RouterRollbackFailed
                    | RecoveryCode::RouterJournalCleanupPending
                    | RecoveryCode::CommitIndeterminate
            );
            assert_eq!(code.is_startup_blocking(), expected, "{code}");
        }
    }

    #[test]
    fn startup_recovery_codes_cover_exactly_the_blocking_codes() {
        let startup = StartupRecoveryCode::ALL
            .iter()
            .copied()
            .map(|code| RecoveryCode::from(code).as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let expected = RecoveryCode::ALL
            .iter()
            .copied()
            .filter(|code| code.is_startup_blocking())
            .map(RecoveryCode::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(startup, expected);
    }

    #[test]
    fn recovery_actions_have_stable_operator_values() {
        assert_eq!(
            RecoveryAction::InspectRecoveryState.as_str(),
            "inspect_recovery_state"
        );
        assert_eq!(
            RecoveryAction::RepairStorageAccess.as_str(),
            "repair_storage_access"
        );
        assert_eq!(
            RecoveryAction::RestoreCoherentBackup.as_str(),
            "restore_coherent_backup"
        );
        assert_eq!(RecoveryAction::RetryRollback.as_str(), "retry_rollback");
        assert_eq!(RecoveryAction::AwaitCleanup.as_str(), "await_cleanup");
        assert_eq!(
            RecoveryAction::UseCompatibleDaemon.as_str(),
            "use_compatible_daemon"
        );
        assert_eq!("retry_rollback".parse(), Ok(RecoveryAction::RetryRollback));
        assert_eq!("await_cleanup".parse(), Ok(RecoveryAction::AwaitCleanup));
        assert_eq!("retry_cleanup".parse(), Ok(RecoveryAction::AwaitCleanup));
        assert!("future_action".parse::<RecoveryAction>().is_err());
        assert_eq!(
            RecoveryAction::RestoreCoherentBackup.guidance(),
            "restore the complete state directory from one coherent backup and do not replace a journal alone"
        );
    }

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
    async fn cancelled_housekeeping_cannot_publish_receipt_after_new_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        tokio::fs::write(&path, b"same bytes").await.unwrap();
        let marker = receipt(&path);
        let (entered, release) = crate::atomic_file::pause_next_replacement(&marker);
        let retiring_path = path.clone();
        let retiring = tokio::spawn(async move { retire(&retiring_path).await });
        tokio::task::spawn_blocking(move || {
            entered
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap()
        })
        .await
        .unwrap();
        retiring.abort();
        assert!(retiring.await.unwrap_err().is_cancelled());

        // Admission must drain the old receipt writer and its cleanup even
        // after the caller drops. Otherwise a late receipt authenticates a
        // new, byte-identical provisioning journal as already restored.
        let admission_path = path.clone();
        let mut admission = tokio::spawn(async move { before_write(&admission_path).await });
        let early =
            tokio::time::timeout(std::time::Duration::from_millis(150), &mut admission).await;
        let waiting = early.is_err();
        release.send(()).unwrap();
        match early {
            Ok(result) => result.unwrap().unwrap(),
            Err(_) => tokio::time::timeout(std::time::Duration::from_secs(5), admission)
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
        }
        tokio::fs::write(&path, b"same bytes").await.unwrap();
        if !waiting {
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while !marker.exists() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
        assert!(
            !completed(&path, b"same bytes").await.unwrap(),
            "late receipt authenticated the new journal as already restored"
        );
        assert!(
            waiting,
            "new admission did not wait for cancelled receipt persistence"
        );
    }

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
