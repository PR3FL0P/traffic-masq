# Connectivity changes and recovery contract

Use this contract when adding or changing a command or background writer that
can interrupt access, or changing its persistence, cancellation or recovery path.
This includes reconciliation, DHCP callbacks, Wi-Fi autoconnect, supervised
process repair and startup recovery.
REST, control RPC and clients share the exhaustive `Request::policy()` in
`crates/protocol/src/request_policy.rs`. Select authorization, mutation kind,
recovery scope, pending-interface admission and request deadline there. Do not
add a transport-specific exception to the dispatcher.

## Admission and confirmation

| Change | Execution and persistence rule | Pending interface change |
| --- | --- | --- |
| Live interface address, role, ownership, AP/client configuration or profile activation/deactivation | Interface snapshot, tentative apply, daemon confirmation deadline, explicit commit or rollback | Generic interface edits retain per-interface ownership; convenience commands require idle interfaces |
| Live router intent, forwarding, routes or VPN chain changes | Router snapshot and any provisioning-secret journal, tentative apply, explicit commit or rollback | Router coordinator checks transaction ownership and recovery state |
| Router provisioning repair and router dataplane reconciliation | Reapply committed intent under coordinator ownership with recovery evidence; successful repair settles ownership and retires its journal without user confirmation or a new committed revision | Router coordinator checks transaction ownership and recovery state |
| Save/Forget/Reset for a missing interface | Validate revision and intent, clean up owned services, freshly prove absence, then commit durable intent | Requires idle interfaces |
| Offline router intent | Validate revision and absent dependencies, commit durable intent, then perform removal-only cleanup; report cleanup blockers without undoing saved intent | Requires idle interfaces |
| DHCP client enable/configure/disable, DHCP server configure/disable, live AP/client passphrase updates | Interface snapshot and role-specific secret journal where applicable; tentative apply, explicit commit or rollback | Requires idle interfaces |
| Standalone VPN enable/disable, connect/disconnect and Direct/VPN policy changes | Shared router coordinator, standalone tunnel/policy snapshot, atomic committed VPN intent and token | Router coordinator checks transaction ownership and recovery state |
| DHCP renew/release-and-reacquire, Wi-Fi scan/reconnect/reload and station deauthentication | Immediate operational action with subsystem ownership/recovery records | Requires idle interfaces |
| Profile library writes | Durable library edit; activation follows the live interface protocol | Requires idle interfaces |
| API/security settings | Serialized settings write; restart requirements are reported separately | Settings rules apply; no live network confirmation |
| Reads, preview and diagnostics | No runtime mutation or admission reservation | Remain available |

DHCP configuration cannot bypass confirmed interface role, ownership or
static-address transitions. The live DHCP and passphrase convenience commands use
`InterfaceTransaction` admission so convergence can run while apply awaits it.
DHCP `ReleaseDhcpClient` means release **and reacquire**, an operational lease
refresh; permanent address removal uses confirmed client disable. Rollback restores
DHCP configuration and ownership, not a promise to regain the same server lease.

Standalone VPN uses the existing router journal and confirmation endpoints.
Snapshot observation is read-only; tunnel ownership is reconstructed only under
an owned apply/recovery operation. Restoring a tunnel can change its ifindex, so
owned policy routes are rebound to the restored interface before replay. Restore
previous VPN protection before reconstructing a tunnel; a failed tunnel restore
must retain the kill switch and recovery evidence. Confirm
Direct policy before disconnecting a protected standalone tunnel. Router VPN
chains and standalone policy cannot occupy the same reserved routing namespace.

Internet-sharing previews carry the committed revision and observed snapshot
fingerprint. TUI apply sends both expectations back; the daemon rejects a stale
preview before effects and still repeats the coordinator's snapshot check under
transaction ownership. API clients that preview should supply these expectations.

The immediate commands above are existing API behavior: they can interrupt
connectivity and do **not** promise automatic commit-confirm rollback. Treat a
new immediate command as an explicit design decision and document its recovery
proof; do not infer safety from the presence of an ownership record. Composite
network configuration belongs in an existing interface/router transaction.

Management/default-route consent authorizes a connectivity risk; it does not
commit a tentative change. A successful apply response also does not commit it.
Only the matching token persisted in committed state establishes confirmation.
A failed or disconnected response is not evidence that the operation had no
effect. The daemon owns the confirmation timer and accepted operation lifetime.

Validate configuration, ownership and required risk consent before mutation.
Revalidate applicable expected revisions, plan fingerprints and device/resource
assumptions under the mutation reservation; a preview is not an execution lease.
For offline edits, follow the cleanup and fresh absence checks in
[editing an unplugged interface](recovery.md#editing-an-unplugged-interface).
Offline router saves follow a different order described in
[saved router intent and removal-only cleanup](recovery.md#saved-router-intent-and-removal-only-cleanup).
For interface edits, failed cleanup prevents the new intent from committing;
the previous committed intent remains the compensation target. For router saves,
failed or indeterminate persistence prevents cleanup from starting. After a
successful router save, cleanup failure leaves the new intent authoritative and
is reported in `cleanup_blockers`; convergence resumes removal from that intent.

Bind confirmation and rollback to the current transaction token and scope;
stale tokens must not affect a later transaction. Only a successfully applied
transaction in its confirmable phase can admit commit. Serialize commit admission
with timeout and rollback, and check the monotonic confirmation deadline there.
An admitted commit may finish after the displayed expiry. `expires_at_unix` is
advisory: expiry schedules recovery, not a guarantee of completed restoration.
After disconnect, timeout or expiry, clients inspect current state before
retrying; they must not automatically replay a mutation.

Direct and convenience writes cannot overlap a pending interface change.
Generic interface edits and token operations use their existing scoped
transaction ownership; router operations use the router coordinator. Recovery
fences still apply before either path. Reads must remain available while a
transaction or recovery is pending.

## Runtime ownership and cancellation

All runtime writers must participate in the shared mutation gate and applicable
interface/radio locks, including background writers without a `Request`.
Separate control admission from runtime execution: interface transactions must
leave convergence workers able to run while awaiting their result. Queued work
must re-read current intent after acquiring its lane and discard stale work.
Background repair must respect transaction ownership and recovery fences.
See [the architecture](architecture.md) for the shared convergence reservation
and exclusive background execution rules.

Create the rollback-only owner and cancellation guard before runtime mutation.
Journal registration must retain its reservations until durable evidence has an
owner, including when the caller is cancelled. Interface apply transfers
compensation to an owned task that reacquires the required locks without
resetting recovery budgets. Router apply and repair instead retain their journal
and inspectable rollback-only token in `recovery_required`; cancellation requires
explicit rollback and does not launch background compensation. Shutdown and
restart preserve that stopped router recovery until an explicit retry.
Cancellation of an async caller does not stop a queued or running blocking
worker: storage, credential and kernel workers retain their reservations until
completion. Conflicting rollback, observation and cleanup must wait for those
effects; a late write must not outlive its recovery owner or overwrite restoration.

On shutdown, stop admission, drain accepted operations within the shutdown
budget, then cancel remaining tasks while preserving unresolved journals and
worker reservations. Client disconnection must not cancel an accepted operation.

## Durable evidence and compatibility

Use the shared [atomic-file primitives](../crates/atomic-file/src/lib.rs) for
file-based recovery evidence and committed overrides. Publication requires an
atomic replacement with file and parent-directory synchronization; newly created
private directories and their ancestors must also be durable. Journal retirement
must synchronize deletion. Preserve private permissions and reject unexpected
symlinks or object types; snapshots and secret journals can contain credentials.

Persist committed intent, its revision and matching commit token atomically.
Distinguish failure before publication, failure with proven compensation, and
an indeterminate outcome after publication. A returned I/O error alone does not
prove that old bytes survived. Never compensate using an obsolete in-memory
revision when durable commit evidence is uncertain.

Validate journal schema, scope, ownership and revision consistency before replay.
Preserve corrupt or unsupported unresolved evidence and fence the affected
scope; inability to enumerate the recovery store can block startup globally.
Independent commit proof or an exact recovery receipt may permit retirement
without replaying an unreadable journal. Do not infer that proof from corrupt
contents. Schema changes must specify supported readers and upgrade/downgrade
behavior for overrides, transaction journals, secret journals and ownership
records; see [the recovery runbook](recovery.md) and [security notes](../SECURITY.md).

## One recovery decision

Every transactional path uses the same rules, whether triggered by failed
apply, timeout, explicit rollback, cancelled work, shutdown or startup:

1. Persist the snapshot and recovery control evidence before the first mutation.
   A failed operation may already have changed runtime state.
2. Resolve independent commit proof before rollback. A network
   `commit_indeterminate` fences further writes and rollback until restart
   resolves durable evidence. A proven settings-only
   `settings_commit_indeterminate` blocks configuration persistence but keeps
   network recovery available; it must not be widened into a network rollback
   fence. New persisted fields default to full fencing unless proved settings-only.
3. Restore provisioning credentials before restarting their consumers. If this
   fails, retain the journals and do not restart consumers with staged secrets.
4. Attempt every independent restoration hook and collect all failures. Full
   router rollback uses `Stage::ALL`, traversed in reverse: dataplane, routes,
   DHCP server, output Wi-Fi, VPN chain, candidate DHCP cleanup, uplink Wi-Fi,
   interfaces, then previous DHCP clients. Candidate cleanup must precede
   interface restoration; previous DHCP clients restart afterwards.
5. Preserve snapshot, secret and control records whenever restoration is
   incomplete. Confirmation and overlapping mutation remain blocked. Apply the
   shared bounded recovery policy; do not reset its budget on a device event.
6. Retire journals only after restoration and dependent cleanup complete, or
   independent commit proof makes rollback obsolete. Cleanup failure must not
   trigger a second destructive rollback of an already restored state.
   Repair of already committed router intent has a separate successful outcome:
   settle runtime ownership and retire the repair journal without entering
   `awaiting_commit`. Its failure/cancellation path still retains recovery
   ownership until compensation and cleanup are resolved.
7. Verify that a new edit can apply and commit, and that reloading committed
   storage yields its revision and intent. A cleared error alone is insufficient.

Ownership checks apply throughout: recovery must preserve foreign resources.
Successful interface rollback means restoring configuration and completing
dependent credential, service and ownership cleanup. It does not require Wi-Fi
association or a DHCP lease. With an absent adapter, stop surviving owned tasks
and settle leases; there is no vanished link state to replay. Once cleanup
succeeds, the journal can retire and a returning adapter follows committed intent.

Restart behavior differs by coordinator: interface startup revalidates journals
and ownership in a fresh bounded recovery session, including previously stopped
attempts; stopped router recovery retains its explicit retry requirement.
A device event alone cannot restart a stopped cycle. During an active cycle,
repeated manual requests cannot renew its budget.
See the [operator runbook](recovery.md) for retry limits, stopped cycles,
indeterminate commits and journal cleanup failures.

## Verification required for changes to this contract

Test the production admission/coordinator paths with faults at OS or storage
boundaries. Assert runtime state where the adapter models it, durable intent,
tokens, recovery admission, journal retention/retirement, and the next successful
change. Reopening storage must be part of restart checks; reusing only an
in-memory writer cannot verify persistence.

For each changed path, cover the applicable boundaries below with production-path
regressions. Identify reused tests and explain any inapplicable rows in the change
description; the inventory of existing tests below is not the acceptance matrix.

| Boundary | Required evidence |
| --- | --- |
| Journal registration and first side effect | Failure/crash before and after publication; no mutation without owned durable recovery evidence |
| Commit publication | Failure before replacement, after publication/sync and during compensation; definite and indeterminate outcomes; reopened storage resolves token and intent together |
| Journal retirement | Failure/crash before and after deletion or receipt publication; safe retry without a second destructive rollback or deletion of a newer journal |
| Cancellation and shutdown | Cancellation during queued/running storage, credential and kernel work; reservations survive until completion, compensation has an owner and shutdown retains unresolved evidence |
| Concurrency and confirmation | Competing direct/interface/router/background writers; commit versus timeout/rollback; stale revision, fingerprint and token rejection before effects; reads remain available |
| Recovery and compatibility | Fault at each affected restoration hook, secret restoration failure, stopped budgets, repeated recovery/restart, corrupt or unsupported records, correct settings-only versus network fencing |
| Device and ownership changes | Device disappearance/reappearance or identity reuse, changed external resources, fresh offline absence checks, preservation of foreign resources and ownership evidence |

For transaction state or ordering changes, review and update the
[formal model, proofs and Rust correspondence](../formal/README.md), then run
`lake build` in `formal`. These proofs assume storage and runtime contracts;
they do not replace Rust fault and concurrency tests. Run the affected Rust
regressions and the required [CI checks](../.github/workflows/ci.yml). Changes to
kernel/network adapters also require the applicable isolated checks in
`sh packaging/test-namespaces.sh --sudo`; document unavailable checks and remaining
evidence gaps. Hardware testing remains explicitly requested work.

Current regression coverage:

| Test | Evidence |
| --- | --- |
| `standalone_vpn_is_tentative_rollback_then_commit_survives_reload` | Real VPN adapter under the router coordinator; tentative runtime, unchanged durable intent, rollback, next commit and storage reload |
| `standalone_vpn_restart_recovers_protected_policy_before_new_commit` | Reconstructed tunnel ownership and router coordinator restore a protected snapshot from the journal before accepting a new confirmed policy |
| `standalone_failed_tunnel_restore_reinstates_protection_and_retains_recovery` | Missing profile during restoration; previous protection remains, journal and commit fence survive, explicit retry and next commit succeed |
| `standalone_vpn_rollback_rebinds_owned_routes_after_tunnel_recreation` | Restored policy routes use the replacement owned tunnel index |
| `reviewed_sharing_plan_rejects_changed_revision_or_observation_before_apply` | Preview metadata rejects stale revision/fingerprint without starting a transaction; a fresh plan then commits |
| `overlapping_writes_require_idle_but_reads_and_transaction_owners_remain_available` | Shared request classification for overlapping writes, reads and scoped transaction owners |
| `lan_rollback_restores_runtime_and_storage_then_allows_a_confirmed_edit` | Control API → real reconciliation → manual/timeout rollback → address restoration and journal cleanup → next apply/commit → storage reload |
| `every_recovery_stage_preserves_proof_across_restart_then_accepts_a_new_change` | Fault in each of nine router restoration hooks → all remaining hooks attempted → immutable journal and secret evidence retained → commit/apply blocked → storage reopened and stopped recovery preserved → explicit complete retry → next apply/commit persisted |
| [`transaction` tests](../src/core/transaction/tests.rs) and [regressions](../src/core/transaction/tests/regressions.rs) | Interface apply, confirmation, cancellation and recovery regressions |
| [`router_transaction` tests](../src/core/router_transaction/tests.rs) | Repair without a new revision, credential restoration ordering, commit uncertainty, cancellation and cleanup receipts |
| [`provisioning_secret_transaction` tests](../src/core/provisioning_secret_transaction/tests.rs) | Token-bound secret restoration, retained journals, schema validation and independent commit proof |
| [`recovery_control` tests](../src/core/recovery_control/tests.rs) | Bounded attempts, stopped recovery, cancellation handoff, corrupt control records and clock changes |

The router matrix checks orchestration with simulated subsystem hooks; the LAN
workflow simulates kernel I/O. They do not establish physical reachability or
real Wi-Fi association. Namespace/kernel checks and explicitly requested hardware
testing provide separate evidence. No test may equate merely returning to
`Idle` with restoration of every affected resource.

## Code examples

These excerpts use existing production types and test fixtures. Test excerpts
belong inside their linked suites; they are not standalone programs. Keep the
complete coordinator paths as the implementation reference: the excerpts show
individual obligations, not a replacement transaction implementation.

### Select admission without blocking interface convergence

In [`Request::policy()`](../crates/protocol/src/request_policy.rs), live interface
edits select `InterfaceTransaction`. The following assertions, adapted from its
policy test, express why: admission is reserved, but the dispatcher must leave
runtime execution available for the convergence worker that apply awaits.

```rust
use traffic_masq_protocol::{ControlRequest as Request, InterfaceEditRequest, InterfaceRole};

let request = Request::ApplyInterfaceEdit {
    interface: "lan0".into(),
    edit: InterfaceEditRequest {
        mac_address: None,
        cidr: "192.0.2.1/24".into(),
        role: InterfaceRole::Output,
        managed: true,
        allow_management_change: true,
    },
};
let policy = request.policy();
assert!(policy.needs_admission());
assert!(!policy.needs_execution());
assert_eq!(policy.recovery_interface, Some("lan0"));
assert!(!policy.requires_idle_interfaces); // Generic edit uses scoped ownership.
```

The last assertion does not authorize overlapping writes. The transaction manager
still checks per-interface ownership and recovery fences. Convenience interface
commands use `requires_idle_interfaces: true`. Reuse the checks in
[`dispatch_inner`](../src/api/control/dispatch.rs); a policy classification alone
does not validate consent, journal an operation or establish its recovery owner.

### Repair committed intent without asking for confirmation

The test `repair_reapplies_committed_intent_without_creating_a_revision` in the
[`router coordinator suite`](../src/core/router_transaction/tests.rs) first seeds
committed intent at revision 1. It then derives the repair target from that
persisted configuration:

```rust
let desired = RouterDesired::from_effective_config(
    &overrides
        .snapshot()
        .await
        .effective_config(&base_config())
        .expect("effective config"),
)
.expect("desired");

coordinator.repair(desired).await.expect("repair");
assert_eq!(coordinator.last_applied_revision(), Some(1));
assert_eq!(overrides.committed_revision().await, 1);
assert_eq!(coordinator.status().await, CoordinatorStatus::Idle);
let events = fake.events();
assert!(events.contains(&"apply_dataplane".to_string()));
assert!(!events.iter().any(|event| event.starts_with("rollback_")));
```

This checks that repair executes runtime work while preserving the committed
revision. Use the coordinator's repair path for this operation; a new proposed
configuration must instead use apply and explicit confirmation. The full
[`repair_inner`](../src/core/router_transaction.rs) owns journal registration,
compensation, ownership settlement and retirement.

### Prove a failed rollback retains evidence and permits a later change

The [router recovery matrix](../src/core/router_transaction/tests/recovery_chain.rs)
injects a failure in each restoration hook. After apply has produced `token` and
the test has captured `original_journal`, its failure checks include:

```rust
fake.fail_rollback(failed_stage);
*fake.rollback_failure_kind.lock().unwrap() = Some(recovery_control::FailureKind::Conflict);

assert!(coordinator.rollback_with_token(&token).await.is_err());
assert_eq!(rollback_events(&fake), RESTORATION);
assert_eq!(std::fs::read(&journal).unwrap(), original_journal);
assert!(secrets.unresolved_after_committed_cleanup(None).await.unwrap());
assert!(coordinator.commit(&token).await.is_err());
```

Checking the full event sequence proves that an independent hook failure did not
skip later restoration attempts. The complete test also rejects another apply,
reopens override storage, reconstructs the coordinator, verifies that startup
preserves the stopped cycle, and explicitly retries after removing the fault.
After successful retry it applies and commits a new candidate, then checks
durable confirmation using a freshly loaded store:

```rust
let candidate = build_candidate(&reloaded).await;
let expected_intent = candidate.desired().clone();
let plan = restarted.plan(candidate).await.unwrap();
let next_token = restarted.apply(plan).await.unwrap();
restarted.commit(&next_token).await.unwrap();
let disk = RuntimeOverrideManager::load(directory.path(), &base_config())
    .await
    .unwrap();
assert_eq!(disk.committed_revision().await, 1);
let saved = disk.snapshot().await;
let actual_intent = RouterDesired::from_effective_config(
    &saved.effective_config(&base_config()).unwrap(),
)
.unwrap();
assert_eq!(actual_intent, expected_intent);
assert_eq!(
    saved.committed_router_transaction.as_deref(),
    Some(next_token.as_str()),
);
```

For runtime-state and saved-intent assertions, also follow
`lan_rollback_restores_runtime_and_storage_then_allows_a_confirmed_edit` in the
[LAN workflow suite](../src/app/tests/transaction_liveness/failure_scenarios.rs).
It verifies restoration of the old address, removal of the candidate address,
journal retirement, and the next committed address after storage reload.

Run these focused existing regressions from the repository root:

```sh
cargo test --locked -p traffic-masq-protocol --lib interface_convergence_can_run_while_other_writers_keep_execution_reserved
cargo test --locked -p traffic-masq --lib repair_reapplies_committed_intent_without_creating_a_revision
cargo test --locked -p traffic-masq --lib every_recovery_stage_preserves_proof_across_restart_then_accepts_a_new_change
cargo test --locked -p traffic-masq --lib lan_rollback_restores_runtime_and_storage_then_allows_a_confirmed_edit
```

These commands exercise the examples' source tests. Select additional checks
from the acceptance matrix for the actual changed path.
