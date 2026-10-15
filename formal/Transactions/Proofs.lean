import Transactions.Model

namespace Transactions

theorem initial_safe : Safe initial := by
  simp [Safe, initial, unresolved]

theorem step_preserves_safe {s t : State} (safe : Safe s) (step : Step s t) :
    Safe t := by
  cases step <;> simp_all [Safe, unresolved]
  rename_i eligible
  rcases eligible with h | h | h <;> simp_all

theorem reachable_safe {s : State} (reachable : Reachable s) : Safe s := by
  induction reachable with
  | start => exact initial_safe
  | next _ step ih => exact step_preserves_safe ih step

theorem unresolved_keeps_journal {s : State} (reachable : Reachable s)
    (pending : unresolved s.phase) : s.journal = true :=
  (reachable_safe reachable).1 pending

theorem runtime_restoration_requires_secrets {s : State} (reachable : Reachable s)
    (restored : s.runtimeRestored = true) : s.secretsRestored = true :=
  (reachable_safe reachable).2.1 restored

theorem journal_retirement_requires_outcome {s t : State}
    (reachable : Reachable s) (step : Step s t)
    (before : s.journal = true) (after : t.journal = false) :
    s.commitProof = true ∨ s.runtimeRestored = true := by
  cases step <;> simp_all
  exact (reachable_safe reachable).2.2.1 ‹s.phase = .settled›

/-- A fence has no in-process outgoing transition. Restart needs durable proof
resolution and is deliberately outside this single-process model. -/
theorem indeterminate_is_fenced {s t : State}
    (fenced : s.phase = .commitIndeterminate) : ¬ Step s t := by
  intro step
  cases step <;> simp_all

theorem committed_never_restores {s t : State} (reachable : Reachable s)
    (committed : s.commitProof = true) (step : Step s t) :
    t.phase = .settled ∧ t.commitProof = true ∧
      t.runtimeRestored = s.runtimeRestored := by
  have settled := (reachable_safe reachable).2.2.2 committed
  cases step <;> simp_all

/-- The only exit from stopped recovery is explicit retry. -/
theorem stopped_requires_manual_retry {s t : State}
    (stopped : s.phase = .recoveryRequired) (step : Step s t) :
    t = { s with phase := .rollbackRequired } := by
  cases step <;> simp_all

theorem commit_admission_requires_successful_apply {s t : State}
    (step : Step s t) (admitted : t.phase = .committing) :
    s.phase = .awaitingCommit := by
  cases step <;> simp_all

end Transactions
