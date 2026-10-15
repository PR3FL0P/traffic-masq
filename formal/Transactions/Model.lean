namespace Transactions

/-- One transaction scope. Locking and durable I/O are abstract boundaries. -/
inductive Phase where
  | idle | registered | applying | awaitingCommit | committing
  | rollbackRequired | recoveryRequired | commitIndeterminate | settled
  deriving DecidableEq, Repr

structure State where
  phase : Phase := .idle
  journal : Bool := false
  commitProof : Bool := false
  secretsRestored : Bool := false
  runtimeRestored : Bool := false
  deriving DecidableEq, Repr

def initial : State := {}

/-- Admission happens before the asynchronous persistence outcome is known.
The deadline premise describes admission, not completion time. -/
inductive Step : State → State → Prop where
  | register (s : State) (h : s.phase = .idle) :
      Step s { s with phase := .registered, journal := true }
  | apply (s : State) (h : s.phase = .registered) :
      Step s { s with phase := .applying }
  | applied (s : State) (h : s.phase = .applying) :
      Step s { s with phase := .awaitingCommit }
  | compensate (s : State)
      (h : s.phase = .registered ∨ s.phase = .applying ∨ s.phase = .awaitingCommit) :
      Step s { s with phase := .rollbackRequired }
  | admitCommit (s : State) (deadlineOpen : Bool)
      (h : s.phase = .awaitingCommit) (deadline : deadlineOpen = true) :
      Step s { s with phase := .committing }
  | commitSucceeded (s : State) (h : s.phase = .committing) :
      Step s { s with phase := .settled, commitProof := true }
  | commitFailed (s : State) (h : s.phase = .committing) :
      Step s { s with phase := .awaitingCommit }
  | commitUnknown (s : State) (h : s.phase = .committing) :
      Step s { s with phase := .commitIndeterminate }
  | restoreSecrets (s : State) (h : s.phase = .rollbackRequired) :
      Step s { s with secretsRestored := true }
  | restoreRuntime (s : State) (h : s.phase = .rollbackRequired)
      (credentials : s.secretsRestored = true) :
      Step s { s with runtimeRestored := true }
  | stopRecovery (s : State) (h : s.phase = .rollbackRequired) :
      Step s { s with phase := .recoveryRequired }
  | manualRetry (s : State) (h : s.phase = .recoveryRequired) :
      Step s { s with phase := .rollbackRequired }
  | rollbackSucceeded (s : State) (h : s.phase = .rollbackRequired)
      (restored : s.runtimeRestored = true) :
      Step s { s with phase := .settled }
  | retireJournal (s : State) (h : s.phase = .settled) :
      Step s { s with journal := false }

/-- Finite execution prefixes, including interrupted operations. -/
inductive Reachable : State → Prop where
  | start : Reachable initial
  | next {s t : State} : Reachable s → Step s t → Reachable t

def unresolved (phase : Phase) : Prop :=
  phase ≠ .idle ∧ phase ≠ .settled

/-- Evidence remains until a durable commit or successful restoration. -/
def Safe (s : State) : Prop :=
  (unresolved s.phase → s.journal = true) ∧
  (s.runtimeRestored = true → s.secretsRestored = true) ∧
  (s.phase = .settled → s.commitProof = true ∨ s.runtimeRestored = true) ∧
  (s.commitProof = true → s.phase = .settled)

end Transactions
