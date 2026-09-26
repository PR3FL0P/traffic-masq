use crate::core::mutation::NetworkMutationGate;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::{watch, Mutex, MutexGuard};

use crate::core::override_manager::RuntimeOverrideManager;
use crate::core::router::{RouterDesired, RouterManager, RouterPlan, RouterSnapshot};
use crate::core::router_candidate::RouterCandidate;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ObservationFingerprint([u8; 32]);

impl ObservationFingerprint {
    fn of(snapshot: &RouterSnapshot) -> Result<Self> {
        let canonical = serde_json::to_vec(snapshot)
            .context("failed to serialize router snapshot for plan fingerprinting")?;
        Ok(Self(Sha256::digest(canonical).into()))
    }
}

pub struct TransactionPlan {
    candidate: RouterCandidate,
    plan: RouterPlan,
    fingerprint: ObservationFingerprint,
}

impl TransactionPlan {
    pub fn candidate(&self) -> &RouterCandidate {
        &self.candidate
    }

    /// Capture the observed router fingerprint and build a plan for a validated candidate.
    pub fn plan(&self) -> &RouterPlan {
        &self.plan
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CoordinatorConflict {
    #[error(
        "a router transaction is already pending; commit or roll it back before starting a new one"
    )]
    TransactionPending,
    #[error(
        "a previous router rollback failed and left the coordinator in recovery state; \
         resolve it before starting a new transaction"
    )]
    RollbackRecoveryRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("router plan is stale: the observed system state changed since the plan was built")]
pub struct StalePlanError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("no router transaction is pending")]
pub struct NoPendingTransactionError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinatorStatus {
    Idle,
    Pending,
    RollbackFailed,
    RecoveredButJournalCleanupPending,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatorView {
    pub status: CoordinatorStatus,
    pub token: Option<String>,
    pub rollback_failures: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RollbackFailure {
    pub token: String,
    pub candidate: RouterCandidate,
    pub snapshot: RouterSnapshot,
    pub failures: Vec<String>,
    /// Startup ownership reconstruction that must succeed before any rollback.
    pub recovery_desired: Option<RouterDesired>,
}

#[derive(Debug, Clone)]
struct PendingTransaction {
    token: String,
    candidate: RouterCandidate,
    snapshot: RouterSnapshot,
}

#[allow(clippy::large_enum_variant)] // Avoid changing transaction state ownership solely to shrink the enum.
enum CoordinatorState {
    Idle,
    Pending(PendingTransaction),
    RollbackFailed(RollbackFailure),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RollbackTrigger {
    Manual,
    Timeout,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct TransactionJournal {
    version: u32,
    base_revision: u64,
    token: String,
    snapshot: RouterSnapshot,
    /// The state that may have been partially applied when the process died.
    /// Version-1 journals do not have this field; recovery for those keeps the
    /// historical snapshot-only behaviour.
    #[serde(default)]
    current_desired: Option<RouterDesired>,
}

struct Inner {
    manager: RouterManager,
    overrides: RuntimeOverrideManager,
    rollback_timeout: Duration,
    state: Mutex<CoordinatorState>,
    journal: std::path::PathBuf,
    token_counter: AtomicU64,
    timeout_mutation_gate: StdRwLock<Option<Arc<NetworkMutationGate>>>,
    idle_epoch: watch::Sender<u64>,
}

#[derive(Clone)]
pub struct RouterTransactionCoordinator {
    inner: Arc<Inner>,
}

impl RouterTransactionCoordinator {
    pub fn new(
        manager: RouterManager,
        overrides: RuntimeOverrideManager,
        rollback_timeout: Duration,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                journal: overrides.path().with_file_name("router-transaction.json"),
                manager,
                overrides,
                rollback_timeout,
                state: Mutex::new(CoordinatorState::Idle),
                token_counter: AtomicU64::new(0),
                timeout_mutation_gate: StdRwLock::new(None),
                idle_epoch: watch::channel(0).0,
            }),
        }
    }

    /// Gate used by the automatic timeout rollback. API-driven router
    /// operations are already serialized by ControlService; the timer is the
    /// one mutation path that otherwise has no request-level guard.
    pub fn set_timeout_mutation_gate(&self, gate: Arc<NetworkMutationGate>) {
        *self
            .inner
            .timeout_mutation_gate
            .write()
            .expect("router timeout mutation-gate lock poisoned") = Some(gate);
    }

    /// Capture the observed router fingerprint and build a plan for a validated candidate.
    pub async fn plan(&self, candidate: RouterCandidate) -> Result<TransactionPlan> {
        let snapshot = self.inner.manager.snapshot_for(candidate.desired()).await?;
        let fingerprint = ObservationFingerprint::of(&snapshot)?;
        let plan = self.inner.manager.plan(candidate.desired().clone()).await?;
        Ok(TransactionPlan {
            candidate,
            plan,
            fingerprint,
        })
    }

    pub fn manager(&self) -> RouterManager {
        self.inner.manager.clone()
    }

    /// Reject stale or conflicting plans, journal recovery state, and apply the candidate.
    /// Return a confirmation token; an unconfirmed change is rolled back after its deadline.
    pub async fn apply(&self, plan: TransactionPlan) -> Result<String> {
        crate::core::recovery::check_scope(
            self.inner
                .overrides
                .path()
                .parent()
                .expect("state directory"),
            None,
        )?;
        let mut state = self.inner.state.lock().await;
        match &*state {
            CoordinatorState::Idle => {}
            CoordinatorState::Pending(_) => {
                return Err(CoordinatorConflict::TransactionPending.into())
            }
            CoordinatorState::RollbackFailed(_) => {
                return Err(CoordinatorConflict::RollbackRecoveryRequired.into())
            }
        }

        let committed_revision = self.inner.overrides.committed_revision().await;
        plan.candidate.ensure_base_revision(committed_revision)?;

        let current_snapshot = self
            .inner
            .manager
            .snapshot_for(plan.candidate.desired())
            .await?;
        if ObservationFingerprint::of(&current_snapshot)? != plan.fingerprint {
            return Err(StalePlanError.into());
        }

        let token = self.next_token();
        self.write_journal(
            plan.candidate.base_revision(),
            &token,
            &current_snapshot,
            plan.candidate.desired(),
        )
        .await?;
        if let Err(error) = self.inner.manager.apply(&plan.plan).await {
            // Retry the complete snapshot: a failed apply may also have failed
            // its compensation. Keep the journal until restoration succeeds.
            let mut failures = self.rollback_snapshot(&token, &current_snapshot).await;
            if failures.is_empty() {
                if let Err(ownership_error) = self.retain_committed_router_interfaces().await {
                    failures.push(format!(
                        "failed to restore committed router ownership: {ownership_error:#}"
                    ));
                }
            }
            if failures.is_empty() {
                if let Err(cleanup_error) = self.clear_journal().await {
                    *state = CoordinatorState::RollbackFailed(RollbackFailure {
                        recovery_desired: None,
                        token: token.clone(),
                        candidate: plan.candidate,
                        snapshot: current_snapshot,
                        failures: vec![format!(
                            "failed to clear rollback journal: {cleanup_error:#}"
                        )],
                    });
                    return Err(error.context(format!(
                        "rollback journal cleanup failed: {cleanup_error:#}"
                    )));
                }
            } else {
                let recovery = failures.join("; ");
                *state = CoordinatorState::RollbackFailed(RollbackFailure {
                    recovery_desired: None,
                    token: token.clone(),
                    candidate: plan.candidate,
                    snapshot: current_snapshot,
                    failures,
                });
                return Err(error.context(format!(
                    "router rollback recovery remains required: {recovery}"
                )));
            }
            return Err(error);
        }

        *state = CoordinatorState::Pending(PendingTransaction {
            token: token.clone(),
            candidate: plan.candidate,
            snapshot: current_snapshot,
        });
        drop(state);
        self.spawn_rollback_timer(token.clone());
        Ok(token)
    }

    /// Reapply committed router intent without creating a new confirmation transaction.
    pub async fn repair(&self, desired: RouterDesired) -> Result<()> {
        self.repair_inner(desired, false).await
    }

    /// Repair committed routing and firewall state without a full subsystem reconfiguration.
    pub async fn reconcile_dataplane(&self, desired: RouterDesired) -> Result<()> {
        self.repair_inner(desired, true).await
    }

    async fn repair_inner(&self, desired: RouterDesired, dataplane_only: bool) -> Result<()> {
        crate::core::recovery::check_scope(
            self.inner
                .overrides
                .path()
                .parent()
                .expect("state directory"),
            None,
        )?;
        let mut state = self.inner.state.lock().await;
        match &*state {
            CoordinatorState::Idle => {}
            CoordinatorState::Pending(_) => {
                return Err(CoordinatorConflict::TransactionPending.into())
            }
            CoordinatorState::RollbackFailed(_) => {
                return Err(CoordinatorConflict::RollbackRecoveryRequired.into())
            }
        }
        if dataplane_only && !self.inner.manager.dataplane_needs_reconcile(&desired).await {
            return Ok(());
        }
        self.inner.manager.prepare_recovery(&desired).await?;
        let candidate = self
            .inner
            .overrides
            .build_candidate(&crate::core::router_candidate::RouterIntentProposal::new())
            .await?;
        let snapshot = self.inner.manager.snapshot_for(&desired).await?;
        let token = self.next_token();
        self.write_journal(candidate.base_revision(), &token, &snapshot, &desired)
            .await?;
        let result = if dataplane_only {
            self.inner.manager.reconcile_dataplane(&desired).await
        } else {
            match self.inner.manager.plan(desired).await {
                Ok(plan) => self.inner.manager.apply(&plan).await,
                Err(error) => Err(error),
            }
        };
        if let Err(error) = result {
            let mut failures = self.inner.manager.rollback_to(&snapshot).await;
            if failures.is_empty() {
                if let Err(ownership_error) = self.retain_committed_router_interfaces().await {
                    failures.push(format!(
                        "failed to restore committed router ownership: {ownership_error:#}"
                    ));
                }
            }
            if failures.is_empty() {
                if let Err(cleanup) = self.clear_journal().await {
                    failures.push(cleanup.to_string());
                }
            }
            if !failures.is_empty() {
                *state = CoordinatorState::RollbackFailed(RollbackFailure {
                    recovery_desired: None,
                    token,
                    candidate,
                    snapshot,
                    failures,
                });
            }
            return Err(error);
        }
        if let Err(error) = self.retain_committed_router_interfaces().await {
            *state = CoordinatorState::RollbackFailed(RollbackFailure {
                recovery_desired: None,
                token,
                candidate,
                snapshot,
                failures: vec![format!(
                    "failed to settle committed router ownership: {error:#}"
                )],
            });
            return Err(error.context("router repair applied but ownership settlement failed"));
        }
        if let Err(error) = self.clear_journal().await {
            // Keep recovery ownership until the durable journal is resolved.
            *state = CoordinatorState::RollbackFailed(RollbackFailure {
                recovery_desired: None,
                token,
                candidate,
                snapshot,
                failures: vec![error.to_string()],
            });
            return Err(error);
        }
        Ok(())
    }

    /// Persist the matching pending candidate and return its new committed revision.
    /// Persistence failure keeps the transaction pending; successful commit retires recovery state.
    pub async fn commit(&self, token: &str) -> Result<u64> {
        let mut state = self.inner.state.lock().await;
        let pending = match &*state {
            CoordinatorState::Pending(pending) => pending.clone(),
            CoordinatorState::Idle => return Err(NoPendingTransactionError.into()),
            CoordinatorState::RollbackFailed(_) => {
                return Err(CoordinatorConflict::RollbackRecoveryRequired.into())
            }
        };

        anyhow::ensure!(
            pending.token == token,
            "router transaction token does not match pending transaction"
        );
        let revision = self
            .inner
            .overrides
            .commit_candidate_with_token(&pending.candidate, Some(&pending.token))
            .await?;

        // Ownership now matches the intent that is in force. Interfaces this
        // intent dropped were torn down as part of the apply, so holding onto
        // them would only make the set grow with every provisioning that ever
        // happened. Narrowing after the commit succeeds, never before.
        let owned: Vec<String> = pending
            .candidate
            .desired()
            .interfaces
            .iter()
            .map(|entry| entry.name.clone())
            .collect();
        self.inner.manager.retain_router_interfaces(&owned).await;

        *state = CoordinatorState::Idle;
        self.notify_idle();
        // The persisted revision is authoritative if removal fails or the
        // process dies here. Recovery must never undo a committed revision.
        if let Err(error) = self.clear_journal().await {
            tracing::warn!(%error, "failed to remove committed transaction journal");
        }
        Ok(revision)
    }

    /// Restore the pending router snapshot, retaining failure state when restoration is incomplete.
    pub async fn rollback(&self) -> Result<()> {
        let mut state = self.inner.state.lock().await;
        self.rollback_locked(&mut state, RollbackTrigger::Manual)
            .await
    }

    /// Return an internally consistent view of coordinator state under one lock.
    pub async fn view(&self) -> CoordinatorView {
        let state = self.inner.state.lock().await;
        match &*state {
            CoordinatorState::Idle => CoordinatorView {
                status: if crate::core::recovery::cleanup_pending(&self.inner.journal) {
                    CoordinatorStatus::RecoveredButJournalCleanupPending
                } else {
                    CoordinatorStatus::Idle
                },
                token: None,
                rollback_failures: Vec::new(),
            },
            CoordinatorState::Pending(pending) => CoordinatorView {
                status: CoordinatorStatus::Pending,
                token: Some(pending.token.clone()),
                rollback_failures: Vec::new(),
            },
            CoordinatorState::RollbackFailed(failure) => CoordinatorView {
                status: CoordinatorStatus::RollbackFailed,
                token: Some(failure.token.clone()),
                rollback_failures: failure.failures.clone(),
            },
        }
    }

    /// Return the token for a pending transaction or failed rollback, or `None` when idle.
    pub async fn pending_token(&self) -> Option<String> {
        match &*self.inner.state.lock().await {
            CoordinatorState::Pending(pending) => Some(pending.token.clone()),
            CoordinatorState::RollbackFailed(failure) => Some(failure.token.clone()),
            CoordinatorState::Idle => None,
        }
    }

    /// Restore the pending snapshot only when its token matches the supplied token.
    pub async fn rollback_with_token(&self, token: &str) -> Result<()> {
        let mut state = self.inner.state.lock().await;
        let expected = match &*state {
            CoordinatorState::Pending(pending) => &pending.token,
            CoordinatorState::RollbackFailed(failure) => &failure.token,
            CoordinatorState::Idle => return Err(NoPendingTransactionError.into()),
        };
        anyhow::ensure!(
            expected == token,
            "router transaction token does not match pending transaction"
        );
        self.rollback_locked(&mut state, RollbackTrigger::Manual)
            .await
    }

    /// Report whether the coordinator is idle, awaiting confirmation, or awaiting rollback recovery.
    pub async fn status(&self) -> CoordinatorStatus {
        match &*self.inner.state.lock().await {
            CoordinatorState::Idle
                if crate::core::recovery::cleanup_pending(&self.inner.journal) =>
            {
                CoordinatorStatus::RecoveredButJournalCleanupPending
            }
            CoordinatorState::Idle => CoordinatorStatus::Idle,
            CoordinatorState::Pending(_) => CoordinatorStatus::Pending,
            CoordinatorState::RollbackFailed(_) => CoordinatorStatus::RollbackFailed,
        }
    }

    /// Wait until a pending/recovery transaction has returned to idle.
    ///
    /// The epoch watch closes the race between checking `status()` and
    /// registering the wakeup: an idle transition that happens in between is
    /// retained as a changed watch value.
    pub async fn wait_until_idle(&self) {
        let mut idle = self.inner.idle_epoch.subscribe();
        let mut housekeeping = crate::core::recovery::subscribe();
        loop {
            if self.status().await == CoordinatorStatus::Idle {
                return;
            }
            tokio::select! {
                changed = idle.changed() => if changed.is_err() { return; },
                // Housekeeping can retire metadata without changing transaction state.
                _ = housekeeping.changed() => {},
            }
        }
    }

    fn notify_idle(&self) {
        self.inner
            .idle_epoch
            .send_modify(|epoch| *epoch = epoch.wrapping_add(1));
    }

    /// Return details retained after an incomplete rollback, if any.
    pub async fn rollback_failure(&self) -> Option<RollbackFailure> {
        match &*self.inner.state.lock().await {
            CoordinatorState::RollbackFailed(failure) => Some(failure.clone()),
            _ => None,
        }
    }

    async fn rollback_locked(
        &self,
        state: &mut MutexGuard<'_, CoordinatorState>,
        trigger: RollbackTrigger,
    ) -> Result<()> {
        // A failed startup prepare may have discovered only part of a VPN
        // chain. Never let a manual retry retire that journal using incomplete
        // volatile ownership; reconstruct it first and retain the intent on error.
        if let CoordinatorState::RollbackFailed(failure) = &mut **state {
            if let Some(desired) = &failure.recovery_desired {
                if let Err(error) = self.inner.manager.prepare_recovery(desired).await {
                    failure.failures = vec![format!("failed to prepare recovery: {error:#}")];
                    return Err(
                        error.context("failed to reconstruct partially-applied router state")
                    );
                }
                failure.recovery_desired = None;
            }
        }
        let (token, candidate, snapshot) = match &**state {
            CoordinatorState::Pending(pending) => (
                pending.token.clone(),
                pending.candidate.clone(),
                pending.snapshot.clone(),
            ),
            CoordinatorState::RollbackFailed(failure) => (
                failure.token.clone(),
                failure.candidate.clone(),
                failure.snapshot.clone(),
            ),
            CoordinatorState::Idle => return Err(NoPendingTransactionError.into()),
        };

        let mut failures = self.rollback_snapshot(&token, &snapshot).await;
        if failures.is_empty() {
            // Applying a candidate widens the volatile ownership scope before
            // its apply-time snapshot. The snapshot therefore contains both
            // committed and candidate-only interfaces and cannot be used to
            // decide what remains owned after an abort. Restore ownership from
            // the durable committed intent instead.
            if let Err(error) = self.retain_committed_router_interfaces().await {
                failures.push(format!(
                    "failed to restore committed router ownership: {error:#}"
                ));
            }
        }
        if failures.is_empty() {
            if let Err(error) = self.clear_journal().await {
                **state = CoordinatorState::RollbackFailed(RollbackFailure {
                    recovery_desired: None,
                    token,
                    candidate,
                    snapshot,
                    failures: vec![format!("failed to clear rollback journal: {error:#}")],
                });
                return Err(error.context("network restored but rollback journal cleanup failed"));
            }
            **state = CoordinatorState::Idle;
            self.notify_idle();
            if trigger == RollbackTrigger::Timeout {
                tracing::warn!("router transaction automatically rolled back after timeout");
            }
            Ok(())
        } else {
            let message = failures.join("; ");
            **state = CoordinatorState::RollbackFailed(RollbackFailure {
                recovery_desired: None,
                token,
                candidate,
                snapshot,
                failures,
            });
            Err(anyhow::anyhow!("router rollback failed: {message}"))
        }
    }

    async fn rollback_snapshot(&self, token: &str, snapshot: &RouterSnapshot) -> Vec<String> {
        let secrets = crate::core::provisioning_secret_transaction::ProvisioningSecretTransactionStore::in_state_dir(
            self.inner.overrides.path().parent().expect("override store has a parent"),
        );
        // Runtime restoration can need the old credentials to start a station
        // or AP. Restore them before the snapshot, including apply compensation
        // where the provisioning journal has not been bound to a token yet.
        let restored = secrets
            .restore_for_token_or_unbound_for_reconvergence(token)
            .await;
        let mut failures = self.inner.manager.rollback_to(snapshot).await;
        match restored {
            Err(error) => {
                failures.push(format!("failed to restore provisioning secrets: {error:#}"))
            }
            Ok(true) if failures.is_empty() => {
                if let Err(error) = secrets.complete_reconvergence().await {
                    failures.push(format!(
                        "failed to clear provisioning secret journal: {error:#}"
                    ));
                }
            }
            _ => {}
        }
        failures
    }

    async fn retain_committed_router_interfaces(&self) -> Result<()> {
        let committed = self
            .inner
            .overrides
            .build_candidate(&crate::core::router_candidate::RouterIntentProposal::new())
            .await?;
        let owned = committed
            .desired()
            .interfaces
            .iter()
            .map(|entry| entry.name.clone())
            .collect::<Vec<_>>();
        self.inner.manager.retain_router_interfaces(&owned).await;
        Ok(())
    }

    async fn retain_committed_router_interfaces_for_recovery(&self) -> Result<()> {
        let committed = self
            .inner
            .overrides
            .build_recovery_candidate(&crate::core::router_candidate::RouterIntentProposal::new())
            .await?;
        let owned = committed
            .desired()
            .interfaces
            .iter()
            .map(|entry| entry.name.clone())
            .collect::<Vec<_>>();
        self.inner.manager.retain_router_interfaces(&owned).await;
        Ok(())
    }

    async fn rollback_timeout_fired(&self, token: &str) {
        let gate = self
            .inner
            .timeout_mutation_gate
            .read()
            .expect("router timeout mutation-gate lock poisoned")
            .clone();
        let _network_mutation = match &gate {
            Some(gate) => Some(gate.write().await),
            None => None,
        };
        let mut state = self.inner.state.lock().await;
        match &*state {
            CoordinatorState::Pending(pending) if pending.token == token => {}

            _ => return,
        }
        if let Err(error) = self
            .rollback_locked(&mut state, RollbackTrigger::Timeout)
            .await
        {
            tracing::error!(%error, "automatic router rollback failed");
        }
    }

    fn spawn_rollback_timer(&self, token: String) {
        let coordinator = self.clone();
        let timeout = self.inner.rollback_timeout;
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            coordinator.rollback_timeout_fired(&token).await;
        });
    }

    async fn write_journal(
        &self,
        base_revision: u64,
        token: &str,
        snapshot: &RouterSnapshot,
        current_desired: &RouterDesired,
    ) -> Result<()> {
        crate::core::recovery::before_write(&self.inner.journal).await?;
        anyhow::ensure!(
            !crate::atomic_file::regular_file_exists(&self.inner.journal)?,
            "invariant=retain_recovery_proof; journal={}; operation=write_journal; metadata_safe_to_remove=false: unresolved journal",
            self.inner.journal.display()
        );
        let journal = TransactionJournal {
            version: 2,
            base_revision,
            token: token.to_owned(),
            snapshot: snapshot.clone(),
            current_desired: Some(current_desired.clone()),
        };
        let bytes = serde_json::to_vec(&journal)?;
        if let Some(parent) = self.inner.journal.parent() {
            let parent = parent.to_path_buf();
            tokio::task::spawn_blocking(move || {
                crate::atomic_file::ensure_private_dir(
                    &parent,
                    crate::atomic_file::PRIVATE_DIR_MODE,
                )
            })
            .await??;
        }
        crate::atomic_file::replace_preserving_on_error_async(&self.inner.journal, &bytes, 0o600)
            .await?;
        Ok(())
    }

    async fn clear_journal(&self) -> Result<()> {
        crate::core::recovery::retire(&self.inner.journal).await?;
        Ok(())
    }

    /// Restore an interrupted transaction before accepting control requests.
    pub async fn recover(&self) -> Result<bool> {
        let mut state = self.inner.state.lock().await;
        let journal_access_diagnostic = || {
            crate::core::recovery::RecoveryDiagnostic::fatal(
                crate::core::recovery::StartupRecoveryCode::AccessibleRouterRecoveryJournal,
                "inspect",
                crate::core::recovery::RecoveryAction::RepairStorageAccess,
            )
            .journal(self.inner.journal.clone())
            .object("router")
            .detail("expected_type", "regular_file_when_present")
            .detail(
                "expected_mode",
                format!("{:04o}", crate::atomic_file::PRIVATE_FILE_MODE),
            )
            .detail("symlink_allowed", false)
        };
        if !crate::atomic_file::regular_file_exists(&self.inner.journal)
            .with_context(journal_access_diagnostic)?
        {
            return Ok(false);
        }
        let bytes = match tokio::fs::read(&self.inner.journal).await {
            Ok(bytes) => bytes,
            // The parent state directory is trusted, but tolerate a concurrent
            // housekeeping unlink between metadata inspection and read.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error).context(journal_access_diagnostic()),
        };
        if crate::core::recovery::completed(&self.inner.journal, &bytes).await? {
            self.retain_committed_router_interfaces_for_recovery()
                .await?;
            self.clear_journal().await?;
            *state = CoordinatorState::Idle;
            self.notify_idle();
            return Ok(false);
        }
        // Even an unsupported schema can be retired when its token is proven
        // committed. A parse error alone is never proof of kernel ownership.
        let committed_token = self
            .inner
            .overrides
            .snapshot()
            .await
            .committed_router_transaction;
        let header: serde_json::Value = serde_json::from_slice(&bytes).with_context(|| {
            crate::core::recovery::RecoveryDiagnostic::fatal(
                crate::core::recovery::StartupRecoveryCode::DecodableRecoverySnapshot,
                "decode",
                crate::core::recovery::RecoveryAction::RestoreCoherentBackup,
            )
            .journal(self.inner.journal.clone())
            .object("router")
            .detail("required_proof", "independent_committed_transaction_token")
            .detail("backup_scope", "complete_state_directory")
        })?;
        if header
            .get("token")
            .and_then(|value| value.as_str())
            .is_some_and(|token| Some(token) == committed_token.as_deref())
        {
            let suffix = match serde_json::from_slice::<TransactionJournal>(&bytes) {
                Ok(record) if matches!(record.version, 1 | 2) => "stale",
                _ => "corrupt",
            };
            if let Err(error) = crate::core::recovery::quarantine(&self.inner.journal, suffix).await
            {
                tracing::warn!(journal = %self.inner.journal.display(), operation = "quarantine_committed_journal",
                    invariant = "committed_token_proof", metadata_safe_to_remove = true, %error,
                    "quarantine unavailable; retiring committed metadata separately");
                self.clear_journal().await?;
            }
            self.retain_committed_router_interfaces_for_recovery()
                .await?;
            *state = CoordinatorState::Idle;
            self.notify_idle();
            return Ok(false);
        }
        let journal: TransactionJournal = serde_json::from_value(header).with_context(|| {
            crate::core::recovery::RecoveryDiagnostic::fatal(
                crate::core::recovery::StartupRecoveryCode::ValidRecoverySnapshot,
                "decode",
                crate::core::recovery::RecoveryAction::RestoreCoherentBackup,
            )
            .journal(self.inner.journal.clone())
            .object("router")
            .detail("required_proof", "independent_committed_transaction_token")
            .detail("backup_scope", "complete_state_directory")
        })?;
        if !matches!(journal.version, 1 | 2) {
            let diagnostic = crate::core::recovery::RecoveryDiagnostic::fatal(
                crate::core::recovery::StartupRecoveryCode::SupportedSchema,
                "decode",
                crate::core::recovery::RecoveryAction::UseCompatibleDaemon,
            )
            .journal(self.inner.journal.clone())
            .object("router")
            .detail("journal_schema", journal.version)
            .detail("supported_schemas", "1,2")
            .detail("fallback_action", "restore_coherent_backup");
            return Err(
                anyhow::anyhow!("unsupported router transaction journal version")
                    .context(diagnostic),
            );
        }
        let revision = self.inner.overrides.committed_revision().await;
        if revision < journal.base_revision {
            let diagnostic = crate::core::recovery::RecoveryDiagnostic::fatal(
                crate::core::recovery::StartupRecoveryCode::RevisionOrder,
                "validate",
                crate::core::recovery::RecoveryAction::RestoreCoherentBackup,
            )
            .journal(self.inner.journal.clone())
            .object("router")
            .detail("journal_base_revision", journal.base_revision)
            .detail("committed_revision", revision)
            .detail("backup_scope", "complete_state_directory");
            return Err(anyhow::anyhow!(
                "transaction journal is newer than committed configuration"
            )
            .context(diagnostic));
        }
        let committed = self
            .inner
            .overrides
            .snapshot()
            .await
            .committed_router_transaction
            .as_deref()
            == Some(journal.token.as_str());
        if !committed {
            let candidate = self
                .inner
                .overrides
                .build_recovery_candidate(
                    &crate::core::router_candidate::RouterIntentProposal::new(),
                )
                .await?;
            *state = CoordinatorState::RollbackFailed(RollbackFailure {
                recovery_desired: journal.current_desired.clone(),
                token: journal.token.clone(), candidate, snapshot: journal.snapshot.clone(),
                failures: vec![format!("journal={}; operation=startup_rollback; invariant=restore_snapshot; metadata_safe_to_remove=false", self.inner.journal.display())],
            });
            if let Some(current_desired) = journal.current_desired.as_ref() {
                if let Err(error) = self.inner.manager.prepare_recovery(current_desired).await {
                    if let CoordinatorState::RollbackFailed(failure) = &mut *state {
                        failure.failures.push(format!("operation=prepare_recovery; invariant=prove_partial_ownership: {error:#}"));
                    }
                    return Err(error).context("failed to reconstruct partially-applied router state; metadata_safe_to_remove=false");
                }
            }
            if let CoordinatorState::RollbackFailed(failure) = &mut *state {
                failure.recovery_desired = None;
            }
            let failures = self.inner.manager.rollback_to(&journal.snapshot).await;
            if !failures.is_empty() {
                let message = failures.join("; ");
                if let CoordinatorState::RollbackFailed(failure) = &mut *state {
                    failure.failures = failures;
                }
                anyhow::bail!("invariant=restore_snapshot; journal={}; object=router; operation=rollback; metadata_safe_to_remove=false: {message}", self.inner.journal.display());
            }
            tracing::warn!("restored interrupted router transaction");
        }
        // Rebuild volatile ownership from the durable committed intent for both
        // aborted and already-committed journals. This keeps recovery correct
        // even if the manager was constructed with a wider transient scope.
        self.retain_committed_router_interfaces_for_recovery()
            .await
            .context("failed to restore committed router ownership during recovery")?;
        self.clear_journal().await?;
        *state = CoordinatorState::Idle;
        self.notify_idle();
        Ok(!committed)
    }

    fn next_token(&self) -> String {
        let counter = self.inner.token_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("{}-{counter}-{nanos}", std::process::id())
    }
}

#[cfg(test)]
mod tests;
