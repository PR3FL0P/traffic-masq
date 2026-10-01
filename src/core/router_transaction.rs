pub use traffic_masq_protocol::CoordinatorStatus;

use crate::core::mutation::NetworkMutationGate;
use crate::core::recovery_control;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatorView {
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
    timer_epoch: AtomicU64,
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
                timer_epoch: AtomicU64::new(0),
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
        self.write_journal(
            plan.candidate.base_revision(),
            &token,
            &current_snapshot,
            plan.candidate.desired(),
        )
        .await?;
        // Cancellation must leave an inspectable token and original snapshot.
        *state = CoordinatorState::Pending(PendingTransaction {
            token: token.clone(),
            candidate: plan.candidate.clone(),
            snapshot: current_snapshot.clone(),
        });
        let applied = match recovery_control::begin_apply(&self.inner.journal).await {
            Ok(guard) => {
                let result = match tokio::time::timeout(
                    recovery_control::ATTEMPT_TIMEOUT,
                    self.inner.manager.apply(&plan.plan),
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
            *state = CoordinatorState::RollbackFailed(RollbackFailure {
                token: token.clone(),
                candidate: plan.candidate.clone(),
                snapshot: current_snapshot.clone(),
                failures: vec![format!("apply failed: {error:#}")],
                recovery_desired: Some(plan.candidate.desired().clone()),
            });
            // Retry the complete snapshot: a failed apply may also have failed
            // its compensation. Keep the journal until restoration succeeds.
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
                *state = CoordinatorState::RollbackFailed(RollbackFailure {
                    recovery_desired: Some(plan.candidate.desired().clone()),
                    token: token.clone(),
                    candidate: plan.candidate,
                    snapshot: current_snapshot,
                    failures,
                });
                self.spawn_timer(token.clone(), false);
                return Err(error.context(format!(
                    "router rollback recovery remains required: {recovery}"
                )));
            }
            *state = CoordinatorState::Idle;
            self.notify_idle();
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
        self.inner.manager.preflight(&desired).await?;
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
        *state = CoordinatorState::RollbackFailed(RollbackFailure {
            token: token.clone(),
            candidate: candidate.clone(),
            snapshot: snapshot.clone(),
            failures: vec!["router repair was interrupted".into()],
            recovery_desired: Some(desired.clone()),
        });
        let result = match recovery_control::begin_apply(&self.inner.journal).await {
            Ok(guard) => {
                let work = async {
                    if dataplane_only {
                        self.inner.manager.reconcile_dataplane(&desired).await
                    } else {
                        match self.inner.manager.plan(desired).await {
                            Ok(plan) => self.inner.manager.apply(&plan).await,
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
                *state = CoordinatorState::RollbackFailed(RollbackFailure {
                    recovery_desired: None,
                    token: token.clone(),
                    candidate,
                    snapshot,
                    failures,
                });
                if !recovery_control::stopped(&self.inner.journal) {
                    self.spawn_timer(token, false);
                }
            } else {
                *state = CoordinatorState::Idle;
                self.notify_idle();
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
        *state = CoordinatorState::Idle;
        self.notify_idle();
        Ok(())
    }

    /// Persist the matching pending candidate and return its new committed revision.
    /// Persistence failure keeps the transaction pending; successful commit retires recovery state.
    pub async fn commit(&self, token: &str) -> Result<u64> {
        let mut state = self.inner.state.lock().await;
        crate::core::recovery::check_commit(
            self.inner
                .overrides
                .path()
                .parent()
                .expect("state directory"),
        )?;
        if recovery_control::progress(&self.inner.journal).is_some() {
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
        let result = self
            .rollback_locked(&mut state, RollbackTrigger::Manual)
            .await;
        if result.is_err() && !recovery_control::stopped(&self.inner.journal) {
            if let CoordinatorState::RollbackFailed(failure) = &*state {
                self.spawn_timer(failure.token.clone(), false);
            }
        }
        result
    }

    /// Return an internally consistent view of coordinator state under one lock.
    pub async fn view(&self) -> CoordinatorView {
        let state = self.inner.state.lock().await;
        let commit_uncertainty = crate::core::recovery::commit_uncertainty(
            self.inner
                .overrides
                .path()
                .parent()
                .expect("state directory"),
        );
        let cleanup_pending = crate::core::recovery::cleanup_pending(&self.inner.journal);
        match &*state {
            CoordinatorState::Idle => CoordinatorView {
                phase: RouterPhase::Idle,
                commit_uncertainty,
                cleanup_pending,
                token: None,
                rollback_failures: Vec::new(),
            },
            CoordinatorState::Pending(pending) => CoordinatorView {
                phase: if recovery_control::stopped(&self.inner.journal) {
                    RouterPhase::RecoveryRequired
                } else if recovery_control::progress(&self.inner.journal).is_some() {
                    RouterPhase::RollbackRequired
                } else {
                    RouterPhase::Pending
                },
                commit_uncertainty,
                cleanup_pending,
                token: Some(pending.token.clone()),
                rollback_failures: Vec::new(),
            },
            CoordinatorState::RollbackFailed(failure) => CoordinatorView {
                phase: if recovery_control::stopped(&self.inner.journal) {
                    RouterPhase::RecoveryRequired
                } else {
                    RouterPhase::RollbackRequired
                },
                commit_uncertainty,
                cleanup_pending,
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
        let result = self
            .rollback_locked(&mut state, RollbackTrigger::Manual)
            .await;
        if result.is_err() && !recovery_control::stopped(&self.inner.journal) {
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
        crate::core::recovery::check_commit(
            self.inner
                .overrides
                .path()
                .parent()
                .expect("state directory"),
        )?;
        if trigger == RollbackTrigger::Manual {
            crate::core::recovery::check_rollback_scope(
                self.inner
                    .overrides
                    .path()
                    .parent()
                    .expect("state directory"),
                None,
                &self.inner.journal,
            )?;
        }
        let recovery_desired = match &**state {
            CoordinatorState::RollbackFailed(failure) => failure.recovery_desired.clone(),
            CoordinatorState::Pending(pending)
                if recovery_control::progress(&self.inner.journal).is_some() =>
            {
                Some(pending.candidate.desired().clone())
            }
            _ => None,
        };
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
            **state = CoordinatorState::Idle;
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
                if let Err(persistence) = recovery_control::stop(
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
            **state = CoordinatorState::Idle;
            self.notify_idle();
            if trigger == RollbackTrigger::Timeout {
                tracing::warn!("router transaction automatically rolled back after timeout");
            }
            Ok(())
        } else {
            let message = failures.join("; ");
            **state = CoordinatorState::RollbackFailed(RollbackFailure {
                recovery_desired: recovery_desired.clone(),
                token,
                candidate,
                snapshot,
                failures,
            });
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
        let result = recovery_control::run(&self.inner.journal, manual, async {
            if let Some(desired) = recovery_desired {
                self.inner.manager.prepare_recovery(desired).await
                    .context("failed to reconstruct partially-applied router state")?;
            }
            let secrets = crate::core::provisioning_secret_transaction::ProvisioningSecretTransactionStore::in_state_dir(
                self.inner.overrides.path().parent().expect("override store has a parent"),
            );
            // Do not start runtime consumers until their credentials are restored.
            let restored = secrets.restore(Some(token)).await.context("failed to restore provisioning secrets")?;
            self.inner.manager.rollback_to_classified(snapshot).await?;
            if restored {
                secrets.finish(Some(token)).await?;
            }
            self.retain_committed_router_interfaces_for_recovery().await?;
            self.clear_journal().await?;
            Ok(())
        }).await;
        result
            .err()
            .map(|error| vec![format!("{error:#}")])
            .unwrap_or_default()
    }

    /// Shutdown is automatic work and must never restart a stopped cycle.
    pub async fn rollback_for_shutdown(&self) -> Result<()> {
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
            Some(gate) => Some(gate.write().await),
            None => None,
        };
        let mut state = self.inner.state.lock().await;
        if epoch.is_some_and(|epoch| self.inner.timer_epoch.load(Ordering::SeqCst) != epoch) {
            return false;
        }
        if crate::core::recovery::check_commit(
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
            return !recovery_control::stopped(&self.inner.journal);
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
            recovery_control::retry_delay(&self.inner.journal)
        };
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            while coordinator.inner.timer_epoch.load(Ordering::SeqCst) == epoch
                && coordinator
                    .rollback_timeout_fired_for_epoch(&token, Some(epoch))
                    .await
            {
                // No mutation/state locks are retained between attempts.
                tokio::time::sleep(recovery_control::retry_delay(&coordinator.inner.journal)).await;
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
        crate::core::recovery::check_commit(
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
            if let Err(error) = self
                .rollback_locked(&mut state, RollbackTrigger::Startup)
                .await
            {
                if !recovery_control::stopped(&self.inner.journal) {
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
