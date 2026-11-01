pub use traffic_masq_protocol::CoordinatorStatus;

use crate::core::mutation::NetworkMutationGate;
use crate::core::recovery_control;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::{watch, Mutex, OwnedMutexGuard};

use crate::core::override_manager::RuntimeOverrideManager;
use crate::core::provisioning_secret_transaction::ProvisioningSecretTransactionStore;
use crate::core::router::{
    RouterApplyError, RouterDesired, RouterManager, RouterPlan, RouterSnapshot,
};
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

    /// Return the plan already built by the coordinator.
    pub(crate) fn observation_fingerprint(&self) -> String {
        self.fingerprint
            .0
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatorView {
    pub confirmation_deadline: Option<tokio::time::Instant>,
    pub phase: RouterPhase,
    /// A failed commit write whose durable outcome cannot yet be proved.
    pub commit_uncertainty: Option<String>,
    /// Recovery completed, but its durable journal receipt still needs removal.
    pub cleanup_pending: bool,
    pub token: Option<String>,
    pub rollback_failures: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouterPhase {
    Idle,
    Pending,
    RollbackRequired,
    RecoveryRequired,
}

impl CoordinatorView {
    /// Preserve the wire status while keeping transaction and recovery state separate.
    pub fn status(&self) -> CoordinatorStatus {
        if self.commit_uncertainty.is_some() {
            return CoordinatorStatus::CommitIndeterminate;
        }
        match self.phase {
            RouterPhase::Idle if self.cleanup_pending => {
                CoordinatorStatus::RecoveredButJournalCleanupPending
            }
            RouterPhase::Idle => CoordinatorStatus::Idle,
            RouterPhase::Pending => CoordinatorStatus::Pending,
            RouterPhase::RollbackRequired => CoordinatorStatus::RollbackFailed,
            RouterPhase::RecoveryRequired => CoordinatorStatus::RecoveryRequired,
        }
    }

    /// Include the commit diagnostic in the legacy API failure list.
    pub fn failures(&self) -> Vec<String> {
        self.commit_uncertainty
            .as_ref()
            .map(|error| vec![error.clone()])
            .unwrap_or_else(|| self.rollback_failures.clone())
    }
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
    confirmation_deadline: Option<tokio::time::Instant>,
    candidate: RouterCandidate,
    snapshot: RouterSnapshot,
}

#[allow(clippy::large_enum_variant)] // Avoid changing transaction state ownership solely to shrink the enum.
enum CoordinatorState {
    Idle,
    Pending(PendingTransaction),
    RollbackFailed(RollbackFailure),
}

struct ApplyRegistration {
    // On cancellation, record interruption before releasing state ownership.
    preparation: Result<recovery_control::ApplyGuard>,
    state: OwnedMutexGuard<CoordinatorState>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RollbackTrigger {
    Manual,
    Timeout,
    Startup,
    Shutdown,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct TransactionJournal {
    version: u32,
    base_revision: u64,
    token: String,
    snapshot: RouterSnapshot,
    /// The state that may have been partially applied when the process died.
    current_desired: RouterDesired,
}

struct Inner {
    manager: RouterManager,
    overrides: RuntimeOverrideManager,
    rollback_timeout: Duration,
    state: Arc<Mutex<CoordinatorState>>,
    // Published synchronously with every state transition. Readers never wait
    // for the operation owner while it performs runtime or storage I/O.
    observation: StdRwLock<CoordinatorView>,
    journal: std::path::PathBuf,
    token_counter: AtomicU64,
    timer_epoch: AtomicU64,
    timeout_mutation_gate: StdRwLock<Option<Arc<NetworkMutationGate>>>,
    idle_epoch: watch::Sender<u64>,
    last_applied_revision: StdRwLock<Option<u64>>,
}

/// Router mutations are internal to the control service and daemon lifecycle.
/// Callers must hold the shared gate's exclusive runtime reservation before
/// invoking mutation methods; API calls also hold admission. The coordinator's
/// mutex only serializes its own state. Timeout rollback acquires execution itself.
///
/// Cancellation of apply preserves a recovery token and requires explicit
/// rollback; unlike interface apply, it does not spawn background compensation.
///
/// ```compile_fail
/// use traffic_masq::core::router_transaction::{RouterTransactionCoordinator, TransactionPlan};
/// async fn bypass_control(coordinator: &RouterTransactionCoordinator, plan: TransactionPlan) {
///     coordinator.apply(plan).await.unwrap();
/// }
/// ```
#[derive(Clone)]
pub struct RouterTransactionCoordinator {
    inner: Arc<Inner>,
}

impl RouterTransactionCoordinator {
    pub fn recovery(&self) -> &crate::core::recovery::RecoveryState {
        self.inner.overrides.recovery()
    }

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
                state: Arc::new(Mutex::new(CoordinatorState::Idle)),
                observation: StdRwLock::new(Self::observe(&CoordinatorState::Idle)),
                token_counter: AtomicU64::new(0),
                timer_epoch: AtomicU64::new(0),
                timeout_mutation_gate: StdRwLock::new(None),
                idle_epoch: watch::channel(0).0,
                last_applied_revision: StdRwLock::new(None),
            }),
        }
    }

    /// Historical verification within this process, not proof of current
    /// health. Offline cleanup does not claim a newly applied revision.
    pub fn last_applied_revision(&self) -> Option<u64> {
        *self
            .inner
            .last_applied_revision
            .read()
            .expect("applied revision lock")
    }

    fn record_applied_revision(&self, revision: u64) {
        *self
            .inner
            .last_applied_revision
            .write()
            .expect("applied revision lock") = Some(revision);
    }

    /// Gate used by the automatic timeout rollback. API-driven router
    /// operations are already serialized by ControlService; the timer is the
    /// one mutation path that otherwise has no request-level guard.
    pub(crate) fn set_timeout_mutation_gate(&self, gate: Arc<NetworkMutationGate>) {
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

    pub(crate) fn manager(&self) -> RouterManager {
        self.inner.manager.clone()
    }

    /// Reject stale or conflicting plans, journal recovery state, and apply the candidate.
    /// Return a confirmation token; an unconfirmed change is rolled back after its deadline.
    pub(crate) async fn apply(&self, plan: TransactionPlan) -> Result<String> {
        match self.apply_inner(plan).await {
            Ok(token) => Ok(token),
            Err(error) => {
                if matches!(*self.inner.state.lock().await, CoordinatorState::Idle) {
                    // Rejection before registration has not changed runtime consumers.
                    // Once registered, rollback owns both journals and restores secrets
                    // before services, so there is no second repair at the API boundary.
                    self.restore_staged_provisioning_secrets().await.with_context(|| {
                        format!("router apply rejected: {error:#}; staged secret restoration failed")
                    })?;
                }
                Err(error)
            }
        }
    }

    async fn apply_inner(&self, plan: TransactionPlan) -> Result<String> {
        self.recovery().check_scope(
            self.inner
                .overrides
                .path()
                .parent()
                .expect("state directory"),
            None,
        )?;
        let state = self.inner.state.clone().lock_owned().await;
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
        self.inner
            .manager
            .preflight(plan.candidate.desired())
            .await?;

        let current_snapshot = self
            .inner
            .manager
            .snapshot_for(plan.candidate.desired())
            .await?;
        if ObservationFingerprint::of(&current_snapshot)? != plan.fingerprint {
            return Err(StalePlanError.into());
        }

        let token = self.next_token();
        let ApplyRegistration {
            preparation,
            mut state,
        } = self
            .register_apply(
                state,
                CoordinatorState::Pending(PendingTransaction {
                    token: token.clone(),
                    confirmation_deadline: None,
                    candidate: plan.candidate.clone(),
                    snapshot: current_snapshot.clone(),
                }),
            )
            .await?;
        let applied = match preparation {
            Ok(guard) => {
                let result = match tokio::time::timeout(
                    recovery_control::ATTEMPT_TIMEOUT,
                    self.inner.manager.apply_transaction(&plan.plan),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => Err(recovery_control::failure(
                        recovery_control::FailureKind::Transient,
                        "router apply timed out; runtime outcome must be re-observed",
                    )),
                };
                match guard.finish().await {
                    Ok(()) => result,
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        };
        if let Err(error) = applied {
            self.transition(
                &mut state,
                CoordinatorState::RollbackFailed(RollbackFailure {
                    token: token.clone(),
                    candidate: plan.candidate.clone(),
                    snapshot: current_snapshot.clone(),
                    failures: vec![format!("apply failed: {error:#}")],
                    recovery_desired: Some(plan.candidate.desired().clone()),
                }),
            );
            // The coordinator owns compensation: restore credentials before
            // any runtime consumer, and retain the journal until it succeeds.
            let failures = self
                .rollback_snapshot(
                    &token,
                    &current_snapshot,
                    false,
                    Some(plan.candidate.desired()),
                )
                .await;
            if !failures.is_empty() {
                let recovery = failures.join("; ");
                let apply_error = RouterApplyError {
                    original: error
                        .downcast_ref::<RouterApplyError>()
                        .map(|apply| apply.original.clone())
                        .unwrap_or_else(|| format!("{error:#}")),
                    rollback_failures: failures.clone(),
                };
                self.transition(
                    &mut state,
                    CoordinatorState::RollbackFailed(RollbackFailure {
                        recovery_desired: Some(plan.candidate.desired().clone()),
                        token: token.clone(),
                        candidate: plan.candidate,
                        snapshot: current_snapshot,
                        failures,
                    }),
                );
                self.spawn_timer(token.clone(), false);
                return Err(anyhow::Error::new(apply_error).context(format!(
                    "router rollback recovery remains required: {recovery}"
                )));
            }
            self.transition(&mut state, CoordinatorState::Idle);
            self.notify_idle();
            return Err(error);
        }

        self.transition(
            &mut state,
            CoordinatorState::Pending(PendingTransaction {
                token: token.clone(),
                confirmation_deadline: Some(
                    tokio::time::Instant::now() + self.inner.rollback_timeout,
                ),
                candidate: plan.candidate,
                snapshot: current_snapshot,
            }),
        );
        drop(state);
        self.spawn_rollback_timer(token.clone());
        Ok(token)
    }

    /// Keep journal publication, volatile ownership and secret binding under one
    /// owner even if the caller is cancelled during blocking persistence.
    async fn register_apply(
        &self,
        mut state: OwnedMutexGuard<CoordinatorState>,
        next: CoordinatorState,
    ) -> Result<ApplyRegistration> {
        let coordinator = self.clone();
        tokio::spawn(async move {
            let (token, candidate, snapshot, desired, bind_secrets) = match &next {
                CoordinatorState::Pending(pending) => (
                    &pending.token,
                    &pending.candidate,
                    &pending.snapshot,
                    pending.candidate.desired(),
                    true,
                ),
                CoordinatorState::RollbackFailed(failure) => (
                    &failure.token,
                    &failure.candidate,
                    &failure.snapshot,
                    failure
                        .recovery_desired
                        .as_ref()
                        .unwrap_or(failure.candidate.desired()),
                    false,
                ),
                CoordinatorState::Idle => unreachable!("apply registration requires a snapshot"),
            };
            coordinator
                .write_journal(candidate.base_revision(), token, snapshot, desired)
                .await?;
            let token = token.clone();
            coordinator.transition(&mut state, next);
            let preparation = async {
                let guard = coordinator
                    .recovery()
                    .begin_apply(&coordinator.inner.journal)
                    .await?;
                if bind_secrets {
                    if let Err(error) = coordinator.provisioning_secrets().bind_token(&token).await
                    {
                        guard
                            .finish()
                            .await
                            .context("failed to settle secret binding outcome")?;
                        return Err(error
                            .context("failed to bind provisioning secrets to router transaction"));
                    }
                }
                Ok(guard)
            }
            .await;
            Ok(ApplyRegistration { preparation, state })
        })
        .await?
    }

    fn provisioning_secrets(&self) -> ProvisioningSecretTransactionStore {
        ProvisioningSecretTransactionStore::in_state_dir(
            self.inner
                .overrides
                .path()
                .parent()
                .expect("override state directory"),
            self.recovery().clone(),
        )
    }

    /// Discard staged credentials only before a router transaction owns them.
    pub(crate) async fn restore_staged_provisioning_secrets(&self) -> Result<()> {
        let state = self.inner.state.lock().await;
        anyhow::ensure!(
            matches!(*state, CoordinatorState::Idle),
            "router transaction owns provisioning secrets"
        );
        self.recovery().check_commit(
            self.inner
                .overrides
                .path()
                .parent()
                .expect("override state directory"),
        )?;
        let secrets = self.provisioning_secrets();
        if secrets.restore(None).await? {
            secrets.finish(None).await?;
        }
        Ok(())
    }

    /// Reapply committed router intent without creating a new confirmation transaction.
    pub(crate) async fn repair(&self, desired: RouterDesired) -> Result<()> {
        self.repair_inner(desired, false).await
    }

    /// Repair committed routing and firewall state without a full subsystem reconfiguration.
    pub(crate) async fn reconcile_dataplane(&self, desired: RouterDesired) -> Result<()> {
        self.repair_inner(desired, true).await
    }

    /// Cleanup follows durable commit and is idempotent. Interruption needs no
    /// rollback journal: restart repeats deletions from the latest committed
    /// intent and ownership proofs, never restoring deleted permissions.
    pub(crate) async fn cleanup_removed_dataplane(&self, desired: &RouterDesired) -> Result<()> {
        // Detached caller cancellation must not release coordination while an
        // nft spawn_blocking write is still running. This task retains state
        // ownership until all removal operations settle.
        let coordinator = self.clone();
        let desired = desired.clone();
        tokio::spawn(async move { coordinator.cleanup_removed_dataplane_inner(&desired).await })
            .await
            .context("router cleanup worker failed")?
    }

    async fn cleanup_removed_dataplane_inner(&self, desired: &RouterDesired) -> Result<()> {
        self.recovery().check_scope(
            self.inner
                .overrides
                .path()
                .parent()
                .expect("state directory"),
            None,
        )?;
        let state = self.inner.state.lock().await;
        match &*state {
            CoordinatorState::Idle => {}
            CoordinatorState::Pending(_) => {
                return Err(CoordinatorConflict::TransactionPending.into())
            }
            CoordinatorState::RollbackFailed(_) => {
                return Err(CoordinatorConflict::RollbackRecoveryRequired.into())
            }
        }
        let committed = self
            .inner
            .overrides
            .build_candidate(&crate::core::router_candidate::RouterIntentProposal::new())
            .await?;
        anyhow::ensure!(
            committed.desired() == desired,
            "router cleanup no longer matches committed intent"
        );
        self.inner.manager.cleanup_removed_dataplane(desired).await
    }

    async fn repair_inner(&self, desired: RouterDesired, dataplane_only: bool) -> Result<()> {
        self.recovery().check_scope(
            self.inner
                .overrides
                .path()
                .parent()
                .expect("state directory"),
            None,
        )?;
        let state = self.inner.state.clone().lock_owned().await;
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
            self.inner.manager.preflight(&desired).await?;
            let committed = self
                .inner
                .overrides
                .build_candidate(&crate::core::router_candidate::RouterIntentProposal::new())
                .await?;
            anyhow::ensure!(
                committed.desired() == &desired,
                "router verification no longer matches committed intent"
            );
            self.record_applied_revision(committed.base_revision());
            return Ok(());
        }
        self.inner.manager.preflight(&desired).await?;
        self.inner.manager.prepare_recovery(&desired).await?;
        let candidate = self
            .inner
            .overrides
            .build_candidate(&crate::core::router_candidate::RouterIntentProposal::new())
            .await?;
        let verified_revision =
            (candidate.desired() == &desired).then_some(candidate.base_revision());
        let snapshot = self.inner.manager.snapshot_for(&desired).await?;
        let token = self.next_token();
        let ApplyRegistration {
            preparation,
            mut state,
        } = self
            .register_apply(
                state,
                CoordinatorState::RollbackFailed(RollbackFailure {
                    token: token.clone(),
                    candidate: candidate.clone(),
                    snapshot: snapshot.clone(),
                    failures: vec!["router repair was interrupted".into()],
                    recovery_desired: Some(desired.clone()),
                }),
            )
            .await?;
        let result = match preparation {
            Ok(guard) => {
                let work = async {
                    if dataplane_only {
                        self.inner.manager.reconcile_dataplane(&desired).await
                    } else {
                        match self.inner.manager.plan(desired).await {
                            Ok(plan) => self.inner.manager.apply_transaction(&plan).await,
                            Err(error) => Err(error),
                        }
                    }
                };
                let result =
                    match tokio::time::timeout(recovery_control::ATTEMPT_TIMEOUT, work).await {
                        Ok(result) => result,
                        Err(_) => Err(recovery_control::failure(
                            recovery_control::FailureKind::Transient,
                            "router repair timed out; runtime outcome must be re-observed",
                        )),
                    };
                match guard.finish().await {
                    Ok(()) => result,
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            let failures = self.rollback_snapshot(&token, &snapshot, false, None).await;
            if !failures.is_empty() {
                self.transition(
                    &mut state,
                    CoordinatorState::RollbackFailed(RollbackFailure {
                        recovery_desired: None,
                        token: token.clone(),
                        candidate,
                        snapshot,
                        failures,
                    }),
                );
                if !self.recovery().stopped(&self.inner.journal) {
                    self.spawn_timer(token, false);
                }
            } else {
                self.transition(&mut state, CoordinatorState::Idle);
                self.notify_idle();
            }
            return Err(error);
        }
        if let Err(error) = self.retain_committed_router_interfaces().await {
            self.transition(
                &mut state,
                CoordinatorState::RollbackFailed(RollbackFailure {
                    recovery_desired: None,
                    token,
                    candidate,
                    snapshot,
                    failures: vec![format!(
                        "failed to settle committed router ownership: {error:#}"
                    )],
                }),
            );
            return Err(error.context("router repair applied but ownership settlement failed"));
        }
        if let Err(error) = self.clear_journal().await {
            // Keep recovery ownership until the durable journal is resolved.
            self.transition(
                &mut state,
                CoordinatorState::RollbackFailed(RollbackFailure {
                    recovery_desired: None,
                    token,
                    candidate,
                    snapshot,
                    failures: vec![error.to_string()],
                }),
            );
            return Err(error);
        }
        if let Some(revision) = verified_revision {
            self.record_applied_revision(revision);
        }
        self.transition(&mut state, CoordinatorState::Idle);
        self.notify_idle();
        Ok(())
    }

    /// Persist the matching pending candidate and return its new committed revision.
    /// Persistence failure keeps the transaction pending; successful commit retires recovery state.
    pub(crate) async fn commit(&self, token: &str) -> Result<u64> {
        let mut state = self.inner.state.lock().await;
        self.recovery().check_commit(
            self.inner
                .overrides
                .path()
                .parent()
                .expect("state directory"),
        )?;
        if self.recovery().progress(&self.inner.journal).is_some() {
            return Err(CoordinatorConflict::RollbackRecoveryRequired.into());
        }
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
        anyhow::ensure!(
            pending
                .confirmation_deadline
                .is_some_and(|deadline| tokio::time::Instant::now() < deadline),
            "router transaction confirmation deadline expired"
        );
        let revision = self
            .inner
            .overrides
            .commit_candidate_with_token(&pending.candidate, Some(&pending.token))
            .await?;

        self.record_applied_revision(revision);

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

        // Commit proof owns the new credentials. Cleanup is housekeeping and
        // cannot turn a durably committed transaction into a failed commit.
        if let Err(error) = self.provisioning_secrets().finish(Some(token)).await {
            tracing::warn!(%error, %token, "failed to clean committed provisioning secret journal");
        }
        self.transition(&mut state, CoordinatorState::Idle);
        self.notify_idle();
        // The persisted revision is authoritative if removal fails or the
        // process dies here. Recovery must never undo a committed revision.
        if let Err(error) = self.clear_journal().await {
            tracing::warn!(%error, "failed to remove committed transaction journal");
        }
        Ok(revision)
    }

    /// Restore the pending router snapshot, retaining failure state when restoration is incomplete.
    #[cfg(test)]
    async fn rollback(&self) -> Result<()> {
        let mut state = self.inner.state.lock().await;
        let result = self
            .rollback_locked(&mut state, RollbackTrigger::Manual)
            .await;
        if result.is_err() && !self.recovery().stopped(&self.inner.journal) {
            if let CoordinatorState::RollbackFailed(failure) = &*state {
                self.spawn_timer(failure.token.clone(), false);
            }
        }
        result
    }

    fn observe(state: &CoordinatorState) -> CoordinatorView {
        let (phase, token, rollback_failures) = match state {
            CoordinatorState::Idle => (RouterPhase::Idle, None, Vec::new()),
            CoordinatorState::Pending(pending) => (
                if pending.confirmation_deadline.is_some() {
                    RouterPhase::Pending
                } else {
                    // An apply without a confirmed outcome remains rollback-only.
                    RouterPhase::RollbackRequired
                },
                Some(pending.token.clone()),
                Vec::new(),
            ),
            CoordinatorState::RollbackFailed(failure) => (
                RouterPhase::RollbackRequired,
                Some(failure.token.clone()),
                failure.failures.clone(),
            ),
        };
        CoordinatorView {
            confirmation_deadline: match state {
                CoordinatorState::Pending(pending) => pending.confirmation_deadline,
                _ => None,
            },
            phase,
            commit_uncertainty: None,
            cleanup_pending: false,
            token,
            rollback_failures,
        }
    }

    fn transition(&self, state: &mut CoordinatorState, next: CoordinatorState) {
        let observation = Self::observe(&next);
        *state = next;
        *self
            .inner
            .observation
            .write()
            .expect("router observation lock") = observation;
    }

    /// Read the latest published transition without waiting for runtime work.
    /// Recovery guards and housekeeping can change independently of that state.
    pub async fn view(&self) -> CoordinatorView {
        let mut view = self
            .inner
            .observation
            .read()
            .expect("router observation lock")
            .clone();
        view.commit_uncertainty = self.recovery().commit_uncertainty(
            self.inner
                .overrides
                .path()
                .parent()
                .expect("state directory"),
        );
        view.cleanup_pending = self.recovery().cleanup_pending(&self.inner.journal);
        if view.token.is_some() {
            if self.recovery().stopped(&self.inner.journal) {
                view.phase = RouterPhase::RecoveryRequired;
            } else if self.recovery().progress(&self.inner.journal).is_some() {
                view.phase = RouterPhase::RollbackRequired;
            }
        }
        view
    }

    /// Return the published pending/recovery token without waiting for runtime work.
    pub async fn pending_token(&self) -> Option<String> {
        self.view().await.token
    }

    /// Restore the pending snapshot only when its token matches the supplied token.
    pub(crate) async fn rollback_with_token(&self, token: &str) -> Result<()> {
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
        let result = self
            .rollback_locked(&mut state, RollbackTrigger::Manual)
            .await;
        if result.is_err() && !self.recovery().stopped(&self.inner.journal) {
            if let CoordinatorState::RollbackFailed(failure) = &*state {
                self.spawn_timer(failure.token.clone(), false);
            }
        }
        result
    }

    /// Report whether the coordinator is idle, awaiting confirmation, or awaiting rollback recovery.
    pub async fn status(&self) -> CoordinatorStatus {
        self.view().await.status()
    }

    /// Wait until a pending/recovery transaction has returned to idle.
    ///
    /// The epoch watch closes the race between checking `status()` and
    /// registering the wakeup: an idle transition that happens in between is
    /// retained as a changed watch value.
    pub async fn wait_until_idle(&self) {
        let mut idle = self.inner.idle_epoch.subscribe();
        let mut housekeeping = self.recovery().subscribe();
        loop {
            // This is an explicit completion wait, unlike status observation.
            // Join registration/cleanup work even if its last published state
            // is idle, and only then decide whether the coordinator settled.
            let state = self.inner.state.lock().await;
            let settled = matches!(*state, CoordinatorState::Idle)
                && self.status().await == CoordinatorStatus::Idle;
            drop(state);
            if settled {
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
        state: &mut CoordinatorState,
        trigger: RollbackTrigger,
    ) -> Result<()> {
        self.recovery().check_commit(
            self.inner
                .overrides
                .path()
                .parent()
                .expect("state directory"),
        )?;
        if trigger == RollbackTrigger::Manual {
            self.recovery().check_rollback_scope(
                self.inner
                    .overrides
                    .path()
                    .parent()
                    .expect("state directory"),
                None,
                &self.inner.journal,
            )?;
        }
        let recovery_desired = match &*state {
            CoordinatorState::RollbackFailed(failure) => failure.recovery_desired.clone(),
            CoordinatorState::Pending(pending)
                if pending.confirmation_deadline.is_none()
                    || self.recovery().progress(&self.inner.journal).is_some() =>
            {
                Some(pending.candidate.desired().clone())
            }
            _ => None,
        };
        let (token, candidate, snapshot) = match &*state {
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

        // A request may have been cancelled after durable commit but before
        // clearing volatile pending state. Commit proof always wins over rollback.
        if self
            .inner
            .overrides
            .snapshot()
            .await
            .committed_router_transaction
            .as_deref()
            == Some(token.as_str())
        {
            self.retain_committed_router_interfaces_for_recovery()
                .await?;
            self.clear_journal().await?;
            if let Err(error) = self.provisioning_secrets().finish(Some(&token)).await {
                tracing::warn!(%error, %token, "failed to clean committed provisioning secret journal");
            }
            self.transition(state, CoordinatorState::Idle);
            self.notify_idle();
            return if trigger == RollbackTrigger::Manual {
                Err(NoPendingTransactionError.into())
            } else {
                Ok(())
            };
        }
        let journal_exists = match crate::atomic_file::regular_file_exists(&self.inner.journal) {
            Ok(exists) => exists,
            Err(error) => {
                if let Err(persistence) = self
                    .recovery()
                    .stop(
                        &self.inner.journal,
                        recovery_control::FailureKind::Storage,
                        format!("{error:#}"),
                    )
                    .await
                {
                    return Err(
                        persistence.context(format!("journal inspection failed: {error:#}"))
                    );
                }
                return Err(error.into());
            }
        };
        if trigger == RollbackTrigger::Manual && !journal_exists {
            self.write_journal(
                candidate.base_revision(),
                &token,
                &snapshot,
                candidate.desired(),
            )
            .await?;
        }
        let failures = self
            .rollback_snapshot(
                &token,
                &snapshot,
                trigger == RollbackTrigger::Manual,
                recovery_desired.as_ref(),
            )
            .await;
        if failures.is_empty() {
            self.transition(state, CoordinatorState::Idle);
            self.notify_idle();
            if trigger == RollbackTrigger::Timeout {
                tracing::warn!("router transaction automatically rolled back after timeout");
            }
            Ok(())
        } else {
            let message = failures.join("; ");
            self.transition(
                state,
                CoordinatorState::RollbackFailed(RollbackFailure {
                    recovery_desired: recovery_desired.clone(),
                    token,
                    candidate,
                    snapshot,
                    failures,
                }),
            );
            Err(anyhow::anyhow!("router rollback failed: {message}"))
        }
    }

    async fn rollback_snapshot(
        &self,
        token: &str,
        snapshot: &RouterSnapshot,
        manual: bool,
        recovery_desired: Option<&RouterDesired>,
    ) -> Vec<String> {
        let result = self
            .recovery()
            .run(&self.inner.journal, manual, async {
                if let Some(desired) = recovery_desired {
                    self.inner
                        .manager
                        .prepare_recovery(desired)
                        .await
                        .context("failed to reconstruct partially-applied router state")?;
                }
                let secrets = self.provisioning_secrets();
                // Do not start runtime consumers until their credentials are restored.
                let restored = secrets
                    .restore(Some(token))
                    .await
                    .context("failed to restore provisioning secrets")?;
                self.inner.manager.rollback_to_classified(snapshot).await?;
                if restored {
                    secrets.finish(Some(token)).await?;
                }
                self.retain_committed_router_interfaces_for_recovery()
                    .await?;
                self.clear_journal().await?;
                Ok(())
            })
            .await;
        result
            .err()
            .map(|error| vec![format!("{error:#}")])
            .unwrap_or_default()
    }

    /// Shutdown is automatic work and must never restart a stopped cycle.
    pub(crate) async fn rollback_for_shutdown(&self) -> Result<()> {
        let mut state = self.inner.state.lock().await;
        self.rollback_locked(&mut state, RollbackTrigger::Shutdown)
            .await
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

    #[cfg(test)]
    async fn rollback_timeout_fired(&self, token: &str) -> bool {
        self.rollback_timeout_fired_for_epoch(token, None).await
    }

    async fn rollback_timeout_fired_for_epoch(&self, token: &str, epoch: Option<u64>) -> bool {
        let gate = self
            .inner
            .timeout_mutation_gate
            .read()
            .expect("router timeout mutation-gate lock poisoned")
            .clone();
        let _network_mutation = match &gate {
            Some(gate) => Some(gate.execute().await),
            None => None,
        };
        let mut state = self.inner.state.lock().await;
        if epoch.is_some_and(|epoch| self.inner.timer_epoch.load(Ordering::SeqCst) != epoch) {
            return false;
        }
        if self
            .recovery()
            .check_commit(
                self.inner
                    .overrides
                    .path()
                    .parent()
                    .expect("state directory"),
            )
            .is_err()
        {
            return false;
        }
        match &*state {
            CoordinatorState::Pending(pending) if pending.token == token => {}
            CoordinatorState::RollbackFailed(failure) if failure.token == token => {}
            _ => return false,
        }
        if let Err(error) = self
            .rollback_locked(&mut state, RollbackTrigger::Timeout)
            .await
        {
            tracing::error!(%error, "automatic router rollback failed; will retry");
            return !self.recovery().stopped(&self.inner.journal);
        }
        false
    }

    fn spawn_rollback_timer(&self, token: String) {
        self.spawn_timer(token, true);
    }

    fn spawn_timer(&self, token: String, confirmation: bool) {
        let coordinator = self.clone();
        let epoch = self.inner.timer_epoch.fetch_add(1, Ordering::SeqCst) + 1;
        let timeout = if confirmation {
            self.inner.rollback_timeout
        } else {
            self.recovery().retry_delay(&self.inner.journal)
        };
        let deadline = tokio::time::Instant::now() + timeout;
        tokio::spawn(async move {
            tokio::time::sleep_until(deadline).await;
            while coordinator.inner.timer_epoch.load(Ordering::SeqCst) == epoch
                && coordinator
                    .rollback_timeout_fired_for_epoch(&token, Some(epoch))
                    .await
            {
                // No mutation/state locks are retained between attempts.
                tokio::time::sleep(
                    coordinator
                        .recovery()
                        .retry_delay(&coordinator.inner.journal),
                )
                .await;
            }
        });
    }

    async fn write_journal(
        &self,
        base_revision: u64,
        token: &str,
        snapshot: &RouterSnapshot,
        current_desired: &RouterDesired,
    ) -> Result<()> {
        self.recovery().before_write(&self.inner.journal).await?;
        anyhow::ensure!(
            !crate::atomic_file::regular_file_exists(&self.inner.journal)?,
            "invariant=retain_recovery_proof; journal={}; operation=write_journal; metadata_safe_to_remove=false: unresolved journal",
            self.inner.journal.display()
        );
        let journal = TransactionJournal {
            version: 3,
            base_revision,
            token: token.to_owned(),
            snapshot: snapshot.clone(),
            current_desired: current_desired.clone(),
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
        self.recovery().retire(&self.inner.journal).await?;
        Ok(())
    }

    /// Restore an interrupted transaction before accepting control requests.
    pub(crate) async fn recover(&self) -> Result<bool> {
        self.recovery().check_commit(
            self.inner
                .overrides
                .path()
                .parent()
                .expect("state directory"),
        )?;
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
        if self
            .recovery()
            .completed(&self.inner.journal, &bytes)
            .await?
        {
            self.retain_committed_router_interfaces_for_recovery()
                .await?;
            self.clear_journal().await?;
            self.transition(&mut state, CoordinatorState::Idle);
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
                Ok(record) if matches!(record.version, 2 | 3) => "stale",
                _ => "corrupt",
            };
            if let Err(error) = self
                .recovery()
                .quarantine(&self.inner.journal, suffix)
                .await
            {
                tracing::warn!(journal = %self.inner.journal.display(), operation = "quarantine_committed_journal",
                    invariant = "committed_token_proof", metadata_safe_to_remove = true, %error,
                    "quarantine unavailable; retiring committed metadata separately");
                self.clear_journal().await?;
            }
            self.retain_committed_router_interfaces_for_recovery()
                .await?;
            self.transition(&mut state, CoordinatorState::Idle);
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
        if !matches!(journal.version, 2 | 3) {
            let diagnostic = crate::core::recovery::RecoveryDiagnostic::fatal(
                crate::core::recovery::StartupRecoveryCode::SupportedSchema,
                "decode",
                crate::core::recovery::RecoveryAction::UseCompatibleDaemon,
            )
            .journal(self.inner.journal.clone())
            .object("router")
            .detail("journal_schema", journal.version)
            .detail("supported_schemas", "2,3")
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
            self.transition(&mut state, CoordinatorState::RollbackFailed(RollbackFailure {
                recovery_desired: Some(journal.current_desired.clone()),
                token: journal.token.clone(), candidate, snapshot: journal.snapshot.clone(),
                failures: vec![format!("journal={}; operation=startup_rollback; invariant=restore_snapshot; metadata_safe_to_remove=false", self.inner.journal.display())],
            }));
            if let Err(error) = self
                .rollback_locked(&mut state, RollbackTrigger::Startup)
                .await
            {
                if !self.recovery().stopped(&self.inner.journal) {
                    self.spawn_timer(journal.token.clone(), false);
                }
                return Err(error);
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
        self.transition(&mut state, CoordinatorState::Idle);
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
