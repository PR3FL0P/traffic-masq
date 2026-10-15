namespace Transactions.ImplementationAudit

/-- A fence can arrive after admission while compensation waits for a lane. -/
structure Compensation where
  fenced : Bool := false
  credentialsRestored : Bool := false
  intentRestored : Bool := false
  deriving DecidableEq, Repr

def fence (s : Compensation) : Compensation := { s with fenced := true }

/-- The old inline failed-apply path did not recheck the fence. -/
def uncheckedRestore (s : Compensation) : Compensation :=
  { s with credentialsRestored := true, intentRestored := true }

/-- The corrected path checks the current fence after acquiring its lane. -/
def checkedRestore (s : Compensation) : Compensation :=
  if s.fenced then s else uncheckedRestore s

theorem failed_apply_counterexample :
    let admitted : Compensation := {}
    let resumed := uncheckedRestore (fence admitted)
    resumed.fenced = true ∧ resumed.credentialsRestored = true ∧
      resumed.intentRestored = true := by decide

theorem checked_restore_preserves_fenced_state (s : Compensation)
    (blocked : s.fenced = true) : checkedRestore s = s := by
  simp [checkedRestore, blocked]

/-- Old and new journals may have identical bytes, so digest identity alone
cannot distinguish generations after a delayed receipt write. -/
structure Cleanup where
  worker : Bool := false
  reservation : Bool := false
  freshJournal : Bool := false
  receipt : Bool := false
  deriving DecidableEq, Repr

inductive Event where
  | beginReceipt | cancelCaller | finishReceipt | admitNewJournal
  deriving DecidableEq, Repr

def cleanupStep (s : Cleanup) : Event → Cleanup
  | .beginReceipt =>
      if s.freshJournal || s.receipt || s.worker then s
      else { s with worker := true, reservation := true }
  | .cancelCaller => s -- The owned cleanup task retains the reservation.
  | .finishReceipt =>
      if s.worker then { s with worker := false, reservation := false, receipt := true }
      else s
  | .admitNewJournal =>
      if s.reservation then s else { s with freshJournal := true, receipt := false }

def legacyCleanupStep (s : Cleanup) (event : Event) : Cleanup :=
  match event with
  | .cancelCaller => { s with reservation := false }
  | _ => cleanupStep s event

def cleanupTrace (step : Cleanup → Event → Cleanup) (events : List Event) : Cleanup :=
  events.foldl step {}

def lateReceiptTrace : List Event :=
  [.beginReceipt, .cancelCaller, .admitNewJournal, .finishReceipt]

theorem cancelled_cleanup_counterexample :
    let result := cleanupTrace legacyCleanupStep lateReceiptTrace
    result.freshJournal = true ∧ result.receipt = true := by decide

def CleanupSafe (s : Cleanup) : Prop :=
  (s.worker = true → s.reservation = true ∧ s.freshJournal = false) ∧
  (s.freshJournal = true → s.receipt = false)

theorem cleanup_step_preserves_safe (s : Cleanup) (event : Event)
    (safe : CleanupSafe s) : CleanupSafe (cleanupStep s event) := by
  cases s with
  | mk worker reservation fresh receipt =>
    cases worker <;> cases reservation <;> cases fresh <;> cases receipt <;>
      cases event <;> simp_all [CleanupSafe, cleanupStep]

theorem cleanup_trace_safe (events : List Event) :
    CleanupSafe (cleanupTrace cleanupStep events) := by
  have initial : CleanupSafe ({} : Cleanup) := by simp [CleanupSafe]
  have fold_safe : ∀ (events : List Event) (s : Cleanup),
      CleanupSafe s → CleanupSafe (events.foldl cleanupStep s) := by
    intro events
    induction events with
    | nil => intro s safe; exact safe
    | cons event events ih =>
      intro s safe
      exact ih _ (cleanup_step_preserves_safe s event safe)
  exact fold_safe events {} initial

theorem fresh_journal_never_inherits_receipt (events : List Event)
    (fresh : (cleanupTrace cleanupStep events).freshJournal = true) :
    (cleanupTrace cleanupStep events).receipt = false :=
  (cleanup_trace_safe events).2 fresh

end Transactions.ImplementationAudit
