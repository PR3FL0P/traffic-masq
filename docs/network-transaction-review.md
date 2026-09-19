# Network event and transaction review

The transaction system is **not consistently correct across all paths**. This review traced control dispatch, interface desired-state convergence, router orchestration, DHCP lease callbacks, Wi-Fi supervision/autoconnect, VPN operations, persistence/recovery, timeout, and shutdown. Findings below are source-traced; the validation section distinguishes executed regressions from static findings. No production networking commands were run.

## Findings

### 1. High: router apply blocks the DHCP lease it waits for

[src/api/control/dispatch.rs:15](/home/user/Documents/programming/traffic-masq/src/api/control/dispatch.rs:15) holds `network_mutations.write()` for the entire router apply/repair request. [src/core/router.rs:784](/home/user/Documents/programming/traffic-masq/src/core/router.rs:784) then waits for DHCP readiness, but [src/dhcp/client/supervisor.rs:907](/home/user/Documents/programming/traffic-masq/src/dhcp/client/supervisor.rs:907) acquires `network_mutations.read_owned()` before installing and publishing the lease. A new lease cannot become ready until the request releases its write lock, and the request will not release it until readiness succeeds or times out. A fresh DHCP uplink therefore times out and rolls back even with a working DHCP server. Startup router repair takes the same exclusive gate ([src/app/mod.rs:1400](/home/user/Documents/programming/traffic-masq/src/app/mod.rs:1400)). Existing already-bound leases can mask this defect.

Fix direction: permit transaction-owned DHCP progress while excluding unrelated mutations; do not hold a lock across a readiness wait whose producer needs that lock.

### 2. High: a queued writer can prevent interface convergence

Interface apply/rollback holds a shared network lock while awaiting convergence ([src/api/control/dispatch.rs:15](/home/user/Documents/programming/traffic-masq/src/api/control/dispatch.rs:15)). The converger must acquire another shared lock ([src/app/mod.rs:846](/home/user/Documents/programming/traffic-masq/src/app/mod.rs:846)). Tokio's lock is write-preferring: if a direct mutation/router request queues for the exclusive lock before the converger's next acquisition, the converger queues behind it. The writer waits for interface apply, while interface apply waits for the converger. The 10-second convergence deadline breaks the cycle by failing a valid transaction; its compensation can time out for the same reason. Pending-transaction rejection happens only after the writer acquires the lock, so it does not prevent this cycle.

Fix direction: separate mutation admission from convergence execution, or release admission locks before waiting on convergence while retaining explicit transaction ownership.

### 3. High: rollback can leave a newly configured interface changed and erase its journal

[src/core/transaction.rs:533](/home/user/Documents/programming/traffic-masq/src/core/transaction.rs:533) withdraws the tentative entry and treats a successful convergence pass as rollback completion. [src/app/mod.rs:654](/home/user/Documents/programming/traffic-masq/src/app/mod.rs:654) only visits interfaces still present in effective configuration. If the interface was absent from base configuration and overrides before apply, withdrawal removes it from that iteration. The proposed address and associated services can remain, but rollback clears the journal and pending token ([src/core/transaction.rs:550](/home/user/Documents/programming/traffic-masq/src/core/transaction.rs:550)). The pre-apply snapshot exists on disk but is only used by startup recovery, not this live rollback.

Fix direction: retain explicit restoration state for interfaces leaving desired configuration, and clear the recovery journal only after verifying restoration, including prior link state.

### 4. High: an unsuccessful interface rollback remains committable

[src/core/transaction.rs:516](/home/user/Documents/programming/traffic-masq/src/core/transaction.rs:516) never changes `PendingPhase::AwaitingCommit` before withdrawing the proposal. If rollback convergence or journal deletion fails, the pending record remains in that phase. `commit_with` only checks that phase ([src/core/transaction.rs:475](/home/user/Documents/programming/traffic-masq/src/core/transaction.rs:475)), so the old token can still persist the abandoned target even after rollback started or restored the runtime. The analogous router coordinator correctly uses `RollbackFailed`.

Fix direction: transition to `RollbackRequired` before withdrawal in manual, timeout, and shutdown rollback paths; reject commit from then on.

### 5. High: convergence reports success despite DHCP and observation failures

`apply_dhcp_reconcile_action` ([src/app/mod.rs:580](/home/user/Documents/programming/traffic-masq/src/app/mod.rs:580)) returns `()` and only logs configure/disable errors. `reconcile_dhcp_client` ([src/app/mod.rs:600](/home/user/Documents/programming/traffic-masq/src/app/mod.rs:600)) likewise suppresses disable/configuration failures and does not expose degraded client state. Failed address reads ([src/app/mod.rs:698](/home/user/Documents/programming/traffic-masq/src/app/mod.rs:698)), DHCP readiness checks, and missing interfaces also skip work without recording transaction failure. Consequently the transaction waiter can report a successful apply, or clear a rollback journal, without the requested state actually being established.

Fix direction: distinguish background deferred work from transaction success; propagate errors and explicit per-interface completion/readiness into the convergence result.

### 6. High: graceful shutdown stops convergence before pending rollback

The converger receives the daemon shutdown receiver ([src/app/mod.rs:1540](/home/user/Documents/programming/traffic-masq/src/app/mod.rs:1540)) and exits when that signal becomes true ([src/app/mod.rs:827](/home/user/Documents/programming/traffic-masq/src/app/mod.rs:827), [src/app/mod.rs:896](/home/user/Documents/programming/traffic-masq/src/app/mod.rs:896)). Only after the API has shut down does teardown call `rollback_all_pending` ([src/app/mod.rs:1576](/home/user/Documents/programming/traffic-masq/src/app/mod.rs:1576)). That function withdraws proposals and waits for a fresh pass from a converger that has already exited. Pending changes time out instead of being restored. `restore_baselines` also begins with `rollback_all_pending()?`, so this failure can prevent baseline restoration altogether. Journals survive, but immediate rollback on stop is broken.

Fix direction: give convergence a separate shutdown signal and stop it only after accepted operations and pending rollbacks have completed.

### 7. High: switching DHCP uplinks snapshots the wrong client

`snapshot_for` ([src/core/router_subsystems.rs:1051](/home/user/Documents/programming/traffic-masq/src/core/router_subsystems.rs:1051)) records only `runtime.status(target.interface)` when the candidate has DHCP enabled. Switching from a bound `wan0` to a new `wan1` records `None` if `wan1` has no client, rather than recording `wan0`. Applying the new DHCP target ([src/core/router_subsystems.rs:1159](/home/user/Documents/programming/traffic-masq/src/core/router_subsystems.rs:1159)) configures it without stopping the old client. Rollback delegates to `apply_uplink_dhcp(None)` ([src/core/router_subsystems.rs:1308](/home/user/Documents/programming/traffic-masq/src/core/router_subsystems.rs:1308)), which disables clients on all owned interfaces, including the previously working `wan0`, and has no saved client spec to restore. Even when later convergence repairs it, the coordinator can claim rollback completion while the uplink is down.

Fix direction: snapshot DHCP clients across the full affected interface set, including explicit absence, and apply/restore that set symmetrically.

### 8. Medium: route notifications never reconcile router routes or dataplane

The netlink listener subscribes to IPv4 route changes ([src/netlink/events.rs:65](/home/user/Documents/programming/traffic-masq/src/netlink/events.rs:65)), but its consumer only invokes `reconcile_network_runtime_once` ([src/app/mod.rs:860](/home/user/Documents/programming/traffic-masq/src/app/mod.rs:860)). That pass handles interfaces and DHCP/Wi-Fi services; it never reapplies committed router routes, VPN policy routing, or dataplane state. Deleting an owned static router route wakes the loop but leaves the route missing until an explicit repair/reapply or restart. The documented post-commit reconciliation guarantee is therefore broader than the actual event chain.

Fix direction: add scoped router route/dataplane reconciliation for committed intent, respecting transaction ownership and avoiding interference with pending snapshots.

### 9. Medium: legacy AP provisioning is not a durable multi-step transaction

[src/api/control/wifi.rs:208](/home/user/Documents/programming/traffic-masq/src/api/control/wifi.rs:208) overwrites the stored passphrase, then configures Wi-Fi, persists the Wi-Fi interface override (`:224`), and only afterward configures/persists DHCP (`:237`). Compensation snapshots live only in the request. A process crash after secret replacement or the first override write loses the old secret or leaves only part of the requested AP-plus-DHCP configuration committed. The router provisioning path has a durable secret journal; this legacy endpoint does not use it.

Fix direction: route compound AP provisioning through the durable coordinator/secret journal, or provide equivalent write-ahead recovery and a single committed intent transition.

## Event-chain coverage

| Entry/event | Path and assessment |
| --- | --- |
| Interface apply/edit | Validation → journal → tentative desired state → convergence → pending token. Findings 2, 3, 5. |
| Interface commit | Persist intent and token before withdrawing proposal. Ordering is sound; failed rollback phase is not (finding 4). |
| Interface manual/timeout rollback | Withdraw → convergence → journal cleanup. Findings 3–5. |
| Router apply/provisioning | Candidate/revision/fingerprint → snapshot journal → ordered subsystem apply/health → pending. Findings 1 and 7. |
| Router commit/rollback/timeout | Token validation, durable commit marker, snapshot restoration, retained failed-recovery state are present. DHCP snapshot coverage is incomplete. |
| Router provisioning secrets | Staging, token binding, manual and separate timeout secret restoration/re-convergence are implemented. Legacy AP provisioning differs (finding 9). |
| DHCP ACK/loss/cleanup | Ownership applier and durable lease state, with shared global gate. Gate conflicts with router readiness (finding 1). |
| Link/address/route/hotplug notifications | Event → effective-state pass. Missing/deferred/error work is not reliably represented in transaction results; router route repair is absent (findings 3, 5, 8). |
| Process death / Wi-Fi association | Periodic liveness task restarts supervisors and updates DHCP link readiness; suspended while router coordinator is non-idle. |
| Wi-Fi autoconnect | Rechecks gates/coordinator state after scans, then uses immediate profile activation. This is not a confirmation transaction. |
| Direct DHCP/Wi-Fi/VPN controls | Serialized against router/interface pending work, with operation-specific compensation/ownership handling. No universal confirmation window or durable group transaction. |
| API client disconnect | Accepted operations are detached from callers and drained at shutdown via `Operations`; this protection is present. |
| Daemon restart | Interface/router journals and committed tokens distinguish interrupted changes from committed state; provisioning secret recovery precedes supervisor startup. |
| Daemon shutdown | Shared stop signal violates the required convergence/rollback ordering (finding 6). |

## Validation

- `cargo test --all-targets --quiet` on the original module declarations: failed to compile with the E0761 errors below.
- With temporary explicit paths selecting the split TUI modules, `cargo test --lib -- --skip audit_`: **999 passed, 0 failed, 2 ignored**.
- Three temporary focused regression tests asserted the required behavior; **all three failed**, reproducing findings 3, 4, and 5:
  - `audit_rollback_of_previously_unconfigured_interface_restores_snapshot`: rollback returned success, but addresses were `[192.168.1.10, 192.168.50.1]` instead of just `[192.168.1.10]`.
  - `audit_failed_rollback_must_not_remain_committable`: after an injected convergence failure during rollback, `commit` still returned success.
  - `audit_dhcp_failure_must_fail_convergence`: the production reconciliation function returned an empty failure map despite an injected DHCP configure error.
- The other findings are based on the traced call/lock/state sequences, not executed end-to-end reproductions.
- All temporary regression tests and module-path edits were removed afterward. Only this review document is retained.

The unmodified tree cannot compile: [src/tui/mod.rs:38](/home/user/Documents/programming/traffic-masq/src/tui/mod.rs:38) and `:44` produce E0761 because both `src/tui/router.rs` and `src/tui/router/mod.rs`, and both `src/tui/wifi.rs` and `src/tui/wifi/mod.rs`, exist. This is a separate build blocker. Temporary explicit module paths were used only to run review tests; the original source files have been restored.

This is a source and fake-provider review, not a privileged network-namespace or hardware validation. Passing existing tests would not establish correctness of the cross-task lock and shutdown sequences above.
