# Implementation audit: cancellation, confirmation, and recovery

The audit compares the abstract protocol with the Rust transaction and recovery
implementation shipped alongside this formalization. It is a manual
correspondence audit backed by executable Rust regression tests and Lean
counterexample traces; it is not an extracted proof of Rust correctness.

## Confirmed defect: failed apply bypassed the commit fence

The ordinary interface `rollback_locked` path checks the commit fence before
restoration and again after acquiring the runtime reservation/lane. The inline
compensation path in `NetworkTransactionManager::apply` did neither. Thus a
global commit fence raised while apply waited for convergence did not stop it
from restoring credentials and publishing old rollback intent.

The regression `failed_apply_must_not_restore_credentials_after_commit_becomes_indeterminate`
uses the public manager, a controlled converger, real role-specific credential
files, and an injected global fence. Before the fix it failed with:

```text
failed apply compensated credentials despite the global commit fence
left: "original-password"
right: "replacement-password"
```

Fix: check scope before interface registration, check rollback scope before
inline compensation, and recheck commit uncertainty after acquiring its runtime
lane. The follow-up regression
`failed_apply_rechecks_commit_fence_after_waiting_for_runtime_lane` holds that
lane and observes compensation joining the shared convergence reservation before
raising the fence. This explicitly tests the gap after the first check.
`interface_apply_rejects_existing_commit_fence_before_registration` checks that a
pre-existing fence admits no new journal or proposal.

The reproducer establishes a manager-level safety violation. It does not claim
that two simultaneous HTTP requests bypass the service's serialized admission.
Nor can a fence cancel filesystem/kernel work already admitted to a worker;
the checked boundary prevents starting compensation when the fence is visible.

Lean's `ImplementationAudit.failed_apply_counterexample` represents the
unconditional restore after a fence arrives. The corrected boundary satisfies
`checked_restore_preserves_fenced_state`.

## Confirmed defect: cancelled housekeeping released its reservation too early

`recovery::housekeeping` held an async mutex while awaiting blocking filesystem
operations. Dropping the future released the mutex, but did not stop its receipt
writer. A subsequent `before_write` could finish cleanup and admit another
journal before that old writer completed.

The regression
`cancelled_housekeeping_cannot_publish_receipt_after_new_transaction` pauses the
old receipt writer at the actual atomic-file boundary, cancels its caller, and
tries to admit a byte-identical new journal. This matters for staged provisioning
secret journals: before token binding, successive snapshots can have identical
bytes. A digest authenticates content, not a transaction generation.

Before the fix the test failed with:

```text
late receipt authenticated the new journal as already restored
```

A later recovery could therefore skip restoration of that new journal. The
test exercises real receipt files and `completed`, not a mocked outcome.

Fix: housekeeping executes in an owned task. Caller cancellation detaches the
operation, while its owner retains the mutex through receipt publication,
journal unlink, receipt removal, and recovery-control removal. New admission
waits until that operation settles. The contract covers caller cancellation
within a running runtime, not termination of the entire process/runtime.

Lean's `ImplementationAudit.cancelled_cleanup_counterexample` shows the old
four-event interleaving: begin receipt, cancel caller, admit new journal, finish
old receipt. `cleanup_step_preserves_safe` and `fresh_journal_never_inherits_receipt`
prove the corrected reservation rule for arbitrary finite event traces. The
model abstracts successful I/O boundaries; I/O failures still require retained
pending cleanup evidence in Rust.

## Boundaries reviewed without a new confirmed defect

| Boundary | Rust evidence and regression coverage |
| --- | --- |
| Cancellation during journal publication | Interface registration retains operation/lane reservations in an owned task; router registration retains coordinator state ownership. Existing tests pause journal publication and cancel its caller. |
| Cancellation during credential writes | Blocking interface credential workers own their runtime/lane/credential reservations. Existing regression verifies the lane remains held until the late write settles. |
| Confirmation versus timeout | Interface transaction locks and router coordinator state locks serialize the outcome. Admission checks the monotonic deadline after taking these locks; an admitted persistence operation may complete after expiry. |
| Cancellation during commit persistence | `CommitPersistenceGuard` raises uncertainty when a storage await is dropped. Known durable token proof wins over stale volatile pending state. |
| Startup recovery of committed journals | Interface token headers and router token proof prevent restoration of an already committed candidate, independently of snapshot schema validity. |
| Credential/runtime ordering | Router rollback restores secrets before runtime consumers. Interface rollback may publish restoration intent after a credential failure, but retains the journal and cannot report completed restoration. |
| Stopped automatic recovery | Recovery control records retain stopped/interrupted decisions; explicit retry starts a new cycle. Existing tests cover restart, shutdown, corruption, and attempt budgets. |

The original `Model.lean` deliberately groups durable commit and volatile
settlement into one abstract success transition. It does not describe every
await between these operations. This audit adds finer models specifically for
the two confirmed scheduling defects; other boundaries above rely on code
review and Rust tests, rather than a full Lean refinement relation.

Validation commands:

```sh
cargo test --locked -p traffic-masq --lib core::
cargo test --locked -p traffic-masq --lib --quiet
cargo clippy --locked -p traffic-masq --lib --tests -- -D warnings
cargo fmt --all -- --check
cd formal && lake build
```

After the fixes, all 332 core tests passed. The full daemon library suite passed
with 1,214 tests successful, zero failed, and three ignored. Formatting, Clippy
with warnings denied, and the Lean build passed. Both original counterexamples were first reproduced as
failing Rust tests before changing the implementation. The Lean audit proofs
use only the standard `propext` axiom; the concrete counterexample witnesses
require no axioms.
