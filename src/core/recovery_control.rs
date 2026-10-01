//! Bounded recovery cycles, with write-ahead interruption evidence.
//!
//! Control records are bound to the exact immutable snapshot journal. An attempt
//! is persisted before mutation; interruption requires an explicit retry. Commit
//! proof and completion receipts must be checked before consulting this policy.
use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(60);
pub const RECOVERY_TIMEOUT: Duration = Duration::from_secs(180);
pub const MAX_ATTEMPTS: u32 = 3;

pub use traffic_masq_protocol::RecoveryFailureKind as FailureKind;

fn automatic(kind: FailureKind) -> bool {
    matches!(
        kind,
        FailureKind::Transient | FailureKind::DeviceMissing | FailureKind::Unknown
    )
}

#[derive(Debug, thiserror::Error)]
#[error("recovery_failure={kind:?}: {message}")]
pub struct Failure {
    pub kind: FailureKind,
    pub message: String,
}

pub fn failure(kind: FailureKind, message: impl Into<String>) -> anyhow::Error {
    Failure {
        kind,
        message: message.into(),
    }
    .into()
}

/// Inspect types and OS error codes, never diagnostic wording.
pub fn classify(error: &anyhow::Error) -> FailureKind {
    if crate::atomic_file::is_indeterminate_write(error) {
        return FailureKind::Storage;
    }
    if let Some(code) = crate::netlink::netlink_os_error(error) {
        return match code {
            4 | 11 | 16 | 110 => FailureKind::Transient,
            6 | 19 => FailureKind::DeviceMissing,
            17 => FailureKind::Conflict,
            1 | 13 | 22 | 95 => FailureKind::Incompatible,
            _ => FailureKind::Unknown,
        };
    }
    for cause in error.chain() {
        if let Some(failure) = cause.downcast_ref::<Failure>() {
            return failure.kind;
        }
        if cause.is::<crate::netlink::MissingInterface>()
            || cause.is::<crate::firewall::RouterDataplaneInterfaceMissing>()
        {
            return FailureKind::DeviceMissing;
        }
        if cause.is::<crate::core::route::ForeignRouteConflict>() {
            return FailureKind::Conflict;
        }
        if let Some(store) = cause.downcast_ref::<crate::state::private_store::PrivateStoreError>()
        {
            return match store {
                crate::state::private_store::PrivateStoreError::Io(io)
                    if matches!(
                        io.kind(),
                        std::io::ErrorKind::Interrupted
                            | std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    FailureKind::Transient
                }
                _ => FailureKind::Storage,
            };
        }
        if let Some(store) = cause.downcast_ref::<crate::wifi::store::PassphraseStoreError>() {
            return match store {
                crate::wifi::store::PassphraseStoreError::Io(io)
                    if matches!(
                        io.kind(),
                        std::io::ErrorKind::Interrupted
                            | std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    FailureKind::Transient
                }
                crate::wifi::store::PassphraseStoreError::Errno(
                    nix::errno::Errno::EINTR | nix::errno::Errno::EAGAIN | nix::errno::Errno::EBUSY,
                ) => FailureKind::Transient,
                _ => FailureKind::Storage,
            };
        }
        if let Some(ownership) =
            cause.downcast_ref::<crate::core::ownership::OwnershipJournalError>()
        {
            if matches!(
                ownership,
                crate::core::ownership::OwnershipJournalError::UnsupportedSchema(_)
                    | crate::core::ownership::OwnershipJournalError::InvalidRecord(_)
            ) {
                return FailureKind::Incompatible;
            }
        }
        if cause.is::<serde_json::Error>() {
            return FailureKind::Incompatible;
        }
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            return match io.kind() {
                std::io::ErrorKind::Interrupted
                | std::io::ErrorKind::WouldBlock
                | std::io::ErrorKind::TimedOut => FailureKind::Transient,
                _ if io.raw_os_error() == Some(19) => FailureKind::DeviceMissing,
                _ => FailureKind::Storage,
            };
        }
    }
    FailureKind::Unknown
}

pub fn aggregate(errors: Vec<anyhow::Error>, context: &str) -> Result<()> {
    if errors.is_empty() {
        return Ok(());
    }
    let kind = errors
        .iter()
        .map(classify)
        .max_by_key(|kind| match kind {
            FailureKind::CommitIndeterminate => 7,
            FailureKind::Storage => 6,
            FailureKind::Incompatible => 5,
            FailureKind::Conflict => 4,
            FailureKind::DeviceMissing => 3,
            FailureKind::Transient => 2,
            FailureKind::Unknown => 1,
        })
        .expect("nonempty error list");
    Err(failure(
        kind,
        format!(
            "{context}: {}",
            errors
                .iter()
                .map(|error| format!("{error:#}"))
                .collect::<Vec<_>>()
                .join("; ")
        ),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Ready,
    Attempting,
    Stopped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Control {
    version: u32,
    journal_digest: Vec<u8>,
    phase: Phase,
    attempts: u32,
    deadline_unix: u64,
    failure_kind: FailureKind,
    last_error: String,
}

fn controls() -> &'static Mutex<BTreeMap<PathBuf, Control>> {
    static CONTROLS: OnceLock<Mutex<BTreeMap<PathBuf, Control>>> = OnceLock::new();
    CONTROLS.get_or_init(Mutex::default)
}

fn deadlines() -> &'static Mutex<BTreeMap<PathBuf, tokio::time::Instant>> {
    static DEADLINES: OnceLock<Mutex<BTreeMap<PathBuf, tokio::time::Instant>>> = OnceLock::new();
    DEADLINES.get_or_init(Mutex::default)
}

fn io_lock(journal: &Path) -> std::sync::Arc<tokio::sync::Mutex<()>> {
    static LOCKS: OnceLock<Mutex<BTreeMap<PathBuf, std::sync::Arc<tokio::sync::Mutex<()>>>>> =
        OnceLock::new();
    LOCKS
        .get_or_init(Mutex::default)
        .lock()
        .expect("recovery I/O lock registry")
        .entry(journal.to_owned())
        .or_default()
        .clone()
}

/// The owned reservation stays inside the blocking worker if its caller is
/// cancelled. An old unlink can never race a newer persisted stop decision.
pub async fn remove_control(journal: &Path) -> Result<()> {
    let reservation = io_lock(journal).lock_owned().await;
    let path = control_path(journal);
    tokio::task::spawn_blocking(move || {
        let _reservation = reservation;
        crate::atomic_file::remove_preserving_on_error(&path, crate::atomic_file::PRIVATE_FILE_MODE)
    })
    .await??;
    Ok(())
}

struct AttemptGuard {
    path: PathBuf,
    armed: bool,
}
impl Drop for AttemptGuard {
    fn drop(&mut self) {
        if self.armed {
            if let Some(control) = controls()
                .lock()
                .expect("recovery control lock")
                .get_mut(&self.path)
            {
                control.phase = Phase::Stopped;
                control.last_error = "recovery attempt interrupted; explicit retry required".into();
            }
        }
    }
}

/// Application can be cancelled by a request timeout before a confirmation
/// timer exists. Persist that uncertainty before its first runtime mutation.
pub struct ApplyGuard {
    guard: AttemptGuard,
}

pub async fn begin_apply(journal: &Path) -> Result<ApplyGuard> {
    let mut control = Control {
        version: 1,
        journal_digest: digest(journal).await?,
        phase: Phase::Attempting,
        attempts: 0,
        deadline_unix: now().saturating_add(RECOVERY_TIMEOUT.as_secs()),
        failure_kind: FailureKind::Unknown,
        last_error: "application interrupted before confirmation bookkeeping".into(),
    };
    let mut guard = AttemptGuard {
        path: journal.to_owned(),
        armed: true,
    };
    if let Err(error) = save(journal, &control).await {
        guard.armed = false;
        control.phase = Phase::Stopped;
        control.failure_kind = FailureKind::Storage;
        control.last_error = format!("{error:#}");
        controls()
            .lock()
            .expect("recovery control lock")
            .insert(journal.to_owned(), control);
        return Err(error);
    }
    Ok(ApplyGuard { guard })
}

impl ApplyGuard {
    /// A known apply outcome lets normal confirmation/compensation take over.
    pub async fn finish(mut self) -> Result<()> {
        remove_control(&self.guard.path).await?;
        forget(&self.guard.path);
        self.guard.armed = false;
        Ok(())
    }
}

pub fn progress(journal: &Path) -> Option<traffic_masq_protocol::RecoveryProgress> {
    let mut progress = controls()
        .lock()
        .expect("recovery control lock")
        .get(journal)
        .map(|control| traffic_masq_protocol::RecoveryProgress {
            failure_kind: control.failure_kind,
            attempts: control.attempts,
            max_attempts: MAX_ATTEMPTS,
            deadline_unix: control.deadline_unix,
            automatic_recovery: control.phase != Phase::Stopped,
            last_error: control.last_error.clone(),
        })?;
    let parent = journal.parent()?;
    let root = if journal.file_name().and_then(|name| name.to_str())
        == Some("router-transaction.json")
    {
        parent
    } else if parent.file_name().and_then(|name| name.to_str()) == Some("interface-transactions") {
        parent.parent()?
    } else {
        parent
    };
    if crate::core::recovery::check_commit(root).is_err() {
        progress.failure_kind = FailureKind::CommitIndeterminate;
        progress.automatic_recovery = false;
    }
    Some(progress)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn control_path(journal: &Path) -> PathBuf {
    journal.with_extension("json.recovery-control")
}

async fn digest(journal: &Path) -> Result<Vec<u8>> {
    crate::atomic_file::reject_symlink(journal)?;
    let bytes = zeroize::Zeroizing::new(tokio::fs::read(journal).await?);
    Ok(Sha256::digest(&*bytes).to_vec())
}

async fn load(journal: &Path) -> Result<Option<Control>> {
    let expected = digest(journal).await?;
    let cached = controls()
        .lock()
        .expect("recovery control lock")
        .get(journal)
        .cloned()
        .filter(|control| control.journal_digest == expected);
    let path = control_path(journal);
    crate::atomic_file::reject_symlink(&path)?;
    let bytes = match tokio::fs::read(&path).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(cached),
        Err(error) => return Err(error.into()),
    };
    // Even a manual retry cannot hide corrupt durable control behind a cache.
    let mut control: Control = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(control.version == 1, "unsupported recovery control version");
    if control.journal_digest != expected {
        return Ok(None);
    }
    if let Some(cached) = cached {
        return Ok(Some(cached));
    }
    // No in-memory attempt owns this record: the previous process was interrupted.
    if control.phase == Phase::Attempting {
        control.phase = Phase::Stopped;
        control.last_error =
            "previous recovery attempt was interrupted; explicit retry required".into();
    }
    deadlines()
        .lock()
        .expect("recovery deadline lock")
        .entry(journal.to_owned())
        .or_insert_with(|| {
            tokio::time::Instant::now()
                + Duration::from_secs(control.deadline_unix.saturating_sub(now()))
                    .min(RECOVERY_TIMEOUT)
        });
    controls()
        .lock()
        .expect("recovery control lock")
        .insert(journal.to_owned(), control.clone());
    Ok(Some(control))
}

async fn save(journal: &Path, control: &Control) -> Result<()> {
    // In-memory stop always survives a failed write for the running daemon.
    controls()
        .lock()
        .expect("recovery control lock")
        .insert(journal.to_owned(), control.clone());
    let reservation = io_lock(journal).lock_owned().await;
    let path = control_path(journal);
    let bytes = serde_json::to_vec(control)?;
    tokio::task::spawn_blocking(move || {
        let _reservation = reservation;
        crate::atomic_file::replace_preserving_on_error(
            &path,
            &bytes,
            crate::atomic_file::PRIVATE_FILE_MODE,
        )
    })
    .await?
    .context("recovery decision persistence failed; restart persistence is unconfirmed")
}

/// Validation failures outside an attempt must also fence in-process runtime.
pub async fn stop(journal: &Path, kind: FailureKind, message: impl Into<String>) -> Result<()> {
    let control = Control {
        version: 1,
        journal_digest: digest(journal).await.unwrap_or_default(),
        phase: Phase::Stopped,
        attempts: 0,
        deadline_unix: now(),
        failure_kind: kind,
        last_error: message.into(),
    };
    save(journal, &control).await
}

pub fn stopped(journal: &Path) -> bool {
    controls()
        .lock()
        .expect("recovery control lock")
        .get(journal)
        .is_some_and(|control| control.phase == Phase::Stopped)
}

pub fn preservation_required(root: &Path) -> bool {
    controls()
        .lock()
        .expect("recovery control lock")
        .keys()
        .any(|path| path.starts_with(root))
        || crate::core::recovery::check_commit(root).is_err()
}

pub fn stopped_journals(root: &Path) -> Vec<PathBuf> {
    controls()
        .lock()
        .expect("recovery control lock")
        .iter()
        .filter(|(path, control)| path.starts_with(root) && control.phase == Phase::Stopped)
        .map(|(path, _)| path.clone())
        .collect()
}

pub fn check_runtime(root: &Path, interface: Option<&str>) -> Result<()> {
    check_runtime_except(root, interface, None)
}

pub fn check_runtime_except(
    root: &Path,
    interface: Option<&str>,
    except: Option<&Path>,
) -> Result<()> {
    for path in stopped_journals(root) {
        if except == Some(path.as_path()) {
            continue;
        }
        let scoped = path.parent() == Some(root.join("interface-transactions").as_path());
        if !scoped
            || interface.is_none()
            || path.file_stem().and_then(|name| name.to_str()) == interface
        {
            anyhow::bail!("state=recovery_required; journal={}; automatic recovery stopped; explicit retry required", path.display());
        }
    }
    Ok(())
}

/// Load a persisted stop before startup mutates runtime consumers.
pub async fn restore_stop(journal: &Path) -> Result<bool> {
    Ok(load(journal)
        .await?
        .is_some_and(|control| control.phase == Phase::Stopped))
}

pub fn forget(journal: &Path) {
    controls()
        .lock()
        .expect("recovery control lock")
        .remove(journal);
    deadlines()
        .lock()
        .expect("recovery deadline lock")
        .remove(journal);
}

/// The caller serializes this with all writers to the snapshot's scope. A
/// manual invocation starts a fresh cycle only after the previous one stopped.
pub async fn run<T, F: Future<Output = Result<T>>>(
    journal: &Path,
    manual: bool,
    work: F,
) -> Result<T> {
    let mut previous = match load(journal).await {
        Ok(previous) => previous,
        Err(error) => {
            // Fail closed even for unreadable/malformed control metadata.
            let control = Control {
                version: 1,
                journal_digest: digest(journal).await.unwrap_or_default(),
                phase: Phase::Stopped,
                attempts: MAX_ATTEMPTS,
                deadline_unix: now(),
                failure_kind: FailureKind::Storage,
                last_error: format!("{error:#}"),
            };
            controls()
                .lock()
                .expect("recovery control lock")
                .insert(journal.to_owned(), control);
            return Err(error.context("recovery control untrusted; automatic recovery stopped"));
        }
    };
    // The scope lock is held by this caller. An attempting record cannot have
    // another live owner; cancellation may have occurred while its first
    // metadata write was still awaiting completion, before a guard existed.
    if let Some(control) = &mut previous {
        if control.phase == Phase::Attempting {
            control.phase = Phase::Stopped;
            control.last_error = "previous attempt was interrupted; explicit retry required".into();
        }
    }
    let fresh = previous
        .as_ref()
        .is_none_or(|control| manual && control.phase == Phase::Stopped);
    if fresh {
        deadlines().lock().expect("recovery deadline lock").insert(
            journal.to_owned(),
            tokio::time::Instant::now() + RECOVERY_TIMEOUT,
        );
    }
    let cycle_deadline = *deadlines()
        .lock()
        .expect("recovery deadline lock")
        .entry(journal.to_owned())
        .or_insert_with(|| tokio::time::Instant::now() + RECOVERY_TIMEOUT);
    let mut control = match previous {
        Some(control) if !(manual && control.phase == Phase::Stopped) => control,
        _ => Control {
            version: 1,
            journal_digest: digest(journal).await?,
            phase: Phase::Ready,
            attempts: 0,
            deadline_unix: now().saturating_add(RECOVERY_TIMEOUT.as_secs()),
            failure_kind: FailureKind::Unknown,
            last_error: String::new(),
        },
    };
    if control.phase != Phase::Ready
        || control.attempts >= MAX_ATTEMPTS
        || now() >= control.deadline_unix
        || tokio::time::Instant::now() >= cycle_deadline
    {
        control.phase = Phase::Stopped;
        save(journal, &control).await?;
        anyhow::bail!(
            "state=recovery_required; attempts={}; cause={:?}; {}; explicit retry required",
            control.attempts,
            control.failure_kind,
            control.last_error
        );
    }
    control.attempts += 1;
    control.phase = Phase::Attempting;
    let mut guard = AttemptGuard {
        path: journal.to_owned(),
        armed: true,
    };
    if let Err(error) = save(journal, &control).await {
        guard.armed = false;
        control.phase = Phase::Stopped;
        control.failure_kind = FailureKind::Storage;
        control.last_error = format!("{error:#}");
        controls()
            .lock()
            .expect("recovery control lock")
            .insert(journal.to_owned(), control);
        return Err(error);
    }
    let remaining = cycle_deadline
        .saturating_duration_since(tokio::time::Instant::now())
        .min(Duration::from_secs(
            control.deadline_unix.saturating_sub(now()),
        ));
    let result = if remaining.is_zero() {
        Err(failure(
            FailureKind::Transient,
            "recovery budget expired before runtime execution",
        ))
    } else {
        match tokio::time::timeout(ATTEMPT_TIMEOUT.min(remaining), work).await {
            Ok(result) => result,
            Err(_) => Err(failure(
                FailureKind::Unknown,
                "recovery attempt timed out; runtime outcome must be re-observed",
            )),
        }
    };
    guard.armed = false;
    match result {
        Ok(value) => {
            forget(journal);
            Ok(value)
        }
        Err(error) => {
            control.failure_kind = classify(&error);
            control.last_error = format!("{error:#}");
            control.phase = if automatic(control.failure_kind)
                && control.attempts < MAX_ATTEMPTS
                && now() < control.deadline_unix
                && tokio::time::Instant::now() < cycle_deadline
            {
                Phase::Ready
            } else {
                Phase::Stopped
            };
            if let Err(storage) = save(journal, &control).await {
                control.phase = Phase::Stopped;
                control.failure_kind = FailureKind::Storage;
                control.last_error =
                    format!("recovery failed: {error:#}; persistence unconfirmed: {storage:#}");
                controls()
                    .lock()
                    .expect("recovery control lock")
                    .insert(journal.to_owned(), control);
                return Err(storage.context(format!("recovery failed: {error:#}")));
            }
            Err(error)
        }
    }
}

/// Increasing delays; every attempt remains inside the original cycle budget.
pub fn retry_delay(journal: &Path) -> Duration {
    let (attempts, kind) = controls()
        .lock()
        .expect("recovery control lock")
        .get(journal)
        .map_or((0, FailureKind::Unknown), |control| {
            (control.attempts, control.failure_kind)
        });
    Duration::from_secs(if kind == FailureKind::DeviceMissing {
        if attempts <= 1 {
            30
        } else {
            60
        }
    } else if attempts <= 1 {
        1
    } else {
        5
    })
}

#[cfg(test)]
mod tests;
