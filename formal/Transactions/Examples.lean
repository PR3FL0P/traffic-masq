import Transactions.Proofs

namespace Transactions

/-- A successful confirmation remains committed even before journal cleanup. -/
theorem committed_with_cleanup_pending_reachable :
    Reachable { phase := .settled, journal := true, commitProof := true } := by
  have registered := Reachable.next Reachable.start (Step.register initial rfl)
  have applying := Reachable.next registered (Step.apply _ rfl)
  have applied := Reachable.next applying (Step.applied _ rfl)
  have admitted := Reachable.next applied (Step.admitCommit _ true rfl rfl)
  exact Reachable.next admitted (Step.commitSucceeded _ rfl)

/-- Cancellation, stopped recovery, manual retry, and successful compensation
form an actual path through the model, including retirement of the journal. -/
theorem cancelled_then_retried_rollback_reachable :
    Reachable { phase := .settled, secretsRestored := true, runtimeRestored := true } := by
  have registered := Reachable.next Reachable.start (Step.register initial rfl)
  have cancelled := Reachable.next registered (Step.compensate _ (Or.inl rfl))
  have stopped := Reachable.next cancelled (Step.stopRecovery _ rfl)
  have retried := Reachable.next stopped (Step.manualRetry _ rfl)
  have secrets := Reachable.next retried (Step.restoreSecrets _ rfl)
  have runtime := Reachable.next secrets (Step.restoreRuntime _ rfl rfl)
  have settled := Reachable.next runtime (Step.rollbackSucceeded _ rfl rfl)
  exact Reachable.next settled (Step.retireJournal _ rfl)

/-- An uncertain persistence outcome retains recovery evidence. -/
theorem uncertain_commit_reachable :
    Reachable { phase := .commitIndeterminate, journal := true } := by
  have registered := Reachable.next Reachable.start (Step.register initial rfl)
  have applying := Reachable.next registered (Step.apply _ rfl)
  have applied := Reachable.next applying (Step.applied _ rfl)
  have admitted := Reachable.next applied (Step.admitCommit _ true rfl rfl)
  exact Reachable.next admitted (Step.commitUnknown _ rfl)

end Transactions
