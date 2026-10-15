# Transaction architecture in Lean 4

This package formalizes the commit-confirm protocol used by interface and router
transactions. It is an abstract specification, not a verification of the Rust
implementation. It uses Lean's standard library only, with a pinned toolchain.

Run from this directory:

```sh
lake build
```

Install Lean's `elan` toolchain manager following the
[official installation guide](https://lean-lang.org/install/manual/).
`lean-toolchain` selects the version; Lake checks all proof modules.

## State and transitions

`Transactions/Model.lean` models one transaction scope and one process lifetime.
Its state separates transaction phase, durable journal evidence, durable commit
proof, credential restoration, and runtime restoration. `Step` describes
observable successful boundaries. Failed I/O that leaves the state unchanged
can be represented by repeating the same state between these boundaries.

```text
idle → registered → applying → awaitingCommit → committing → settled
          │             │            │              ├→ awaitingCommit (failed write)
          └─────────────┴────────────┘              └→ commitIndeterminate
                        ↓
                 rollbackRequired ↔ recoveryRequired
                        ↓            explicit retry only
           secrets restored → runtime restored → settled
                                                     ↓
                                              journal retirement
```

`registered` means journal publication and assignment to an operation owner have
completed. Cancellation before or during registration is abstracted by that
owned operation; cancellation after registration requests compensation.
`committing` means confirmation was admitted while its monotonic deadline was
open. The model permits completion after that deadline. A successful durable
commit leaves the journal available until housekeeping retires it. Cleanup
failure does not change the committed outcome.

## Checked properties

| Theorem | Guarantee |
| --- | --- |
| `reachable_safe` | Every finite execution prefix preserves the safety invariant. |
| `unresolved_keeps_journal` | An unresolved transaction retains durable recovery evidence. |
| `runtime_restoration_requires_secrets` | Successful runtime restoration has credential restoration evidence. |
| `journal_retirement_requires_outcome` | Journal removal follows a durable commit or completed restoration. |
| `indeterminate_is_fenced` | An uncertain commit permits no further in-process protocol steps. |
| `committed_never_restores` | A durable commit cannot transition into compensation. |
| `stopped_requires_manual_retry` | Stopped recovery resumes only through explicit retry. |
| `commit_admission_requires_successful_apply` | Confirmation starts only from successful apply. |

The proofs use induction over reachable states and case analysis over protocol
steps. There are no placeholder proofs or custom axioms.
`Transactions/Examples.lean` proves reachability of successful commit with
cleanup pending, cancellation followed by stopped recovery and manual rollback,
and uncertain commit. These witnesses check that the main paths are inhabited.

`Transactions/ImplementationAudit.lean` adds executable counterexamples for two
defects confirmed in Rust: failed-apply compensation bypassing a commit fence,
and cancelled housekeeping publishing a receipt after new journal admission.
It proves the corrected fence and reservation rules. See [the implementation
audit](AUDIT.md) for reproducing tests, fixes, and the reviewed boundaries.

## Correspondence with Rust

| Abstract boundary | Implementation to review when changing the protocol |
| --- | --- |
| Registration before mutation | `src/core/transaction.rs`: journal registration and rollback-only pending entry; `src/core/router_transaction.rs`: owned registration task and provisioning secret binding |
| Successful apply permits confirmation | Interface `AwaitingCommit` / router `Pending`, with confirmation deadline present |
| Commit admission and persistence | Interface `commit` and its private `commit_with` helper; router `commit`; `src/core/desired.rs` and override persistence |
| Commit uncertainty fence | `src/core/recovery.rs`: `check_commit`, `fence_commit`; interface pending phase and router status overlay |
| Compensation and credential evidence | Interface `rollback_locked`; router `rollback_snapshot`; `src/core/provisioning_secret_transaction.rs` |
| Stopped recovery and explicit retry | `src/core/recovery_control.rs` |
| Retirement after outcome | Interface `clear_journal`; router `clear_journal` and committed-token recovery paths |

Router rollback restores credentials before invoking runtime restoration. The
interface path can publish rollback intent even when secret restoration fails;
the model's runtime evidence means **successful completion**, not absence of
intermediate runtime activity. Transactions without secret edits treat secret
restoration as a successful no-op.

## Abstraction assumptions and remaining obligations

* Each modeled scope is serialized by the Rust transaction/runtime locks.
  Lock acquisition, cancellation handoff, worker draining, and cross-scope
  interference are not proved here.
* Journal publication is durable; persistence success establishes a token-bound
  commit proof; a compensated persistence error establishes the old intent;
  uncertain persistence activates the global fence. These storage contracts are
  assumed at the abstract transition boundary.
* A restoration success reports the actual restored credentials/runtime.
  Kernel, process, credential store, and atomic-file implementations are outside
  the model.
* The fence is global in Rust. This single-scope model describes its consequence
  for a transaction once fenced; it does not model propagation between scopes.
* Process restart, token matching, journal schema validation, commit-proof
  resolution after a crash, recovery attempt budgets, and timer epochs remain
  separate proof obligations. `settled` is terminal for this token, rather than
  the coordinator's reusable idle state.
* No termination or bounded-time rollback theorem is claimed. A stopped or
  fenced state may persist indefinitely; timers request work, not restoration
  by a fixed deadline.

The correspondence table is maintained by review. There is no automatic Rust
extraction or refinement proof. Protocol changes should update the model and
proofs together with the relevant Rust regression tests. CI builds this package
when the formalization or transaction/recovery implementation changes.
