# Recovery runbook

This guide is for operator-visible recovery diagnostics emitted by `traffic-masqd`.
It describes how to recover without discarding the evidence the daemon uses to
prove whether an interrupted network change committed or must be rolled back.

The default state directory is `/var/lib/traffic-masq`. If the installation uses
another configuration, check it first:

```sh
sudo traffic-masqd config path
sudo traffic-masqd config show
```

## First response

When `traffic-masqd start` reports that startup is blocked by persisted recovery
state, use this order:

1. **Preserve the diagnostic.** Save the complete `traffic-masqd start` output and
   the recent daemon log:

   ```sh
   sudo traffic-masqd logs --lines 100
   ```

2. **Stop repeated restart attempts before changing files.** If the service
   manager is retrying startup, stop it through `traffic-masqd` or the native init
   manager before taking a backup.

3. **Back up the complete state directory as one unit.** Prefer a filesystem
   snapshot. Otherwise, with the daemon stopped, copy the state directory to a
   new destination outside the state directory while preserving metadata. For
   the default path, for example:

   ```sh
   sudo cp -a -- /var/lib/traffic-masq /root/traffic-masq-state-recovery-copy
   ```

   Choose a destination that does not already exist. Treat the backup as
   sensitive: the state directory can contain credentials, profiles and
   provisioning material.

4. **Use the reported `recovery_code` first, then `invariant`, `journal` or
   `path`, and `operator_action`.** Every fatal recovery code maps to one stable
   section in this runbook. Do not infer a successful commit from text inside a
   corrupt journal.

5. **Repair the external cause or restore one coherent backup.** Do not edit
   transaction tokens, schema versions or revision numbers by hand. Do not
   restore only one transaction journal from a different backup.

6. **Start the daemon again and verify recovery.** A successful recovery no
   longer reports the same blocking invariant. Check:

   ```sh
   sudo traffic-masqd start
   sudo traffic-masqd status
   sudo traffic-masqd logs --lines 100
   ```

   Normal success is a ready daemon with no new startup-blocking recovery
   diagnostic. Recovery metadata is retired or quarantined by the daemon when it
   has sufficient proof; do not delete it merely because the daemon has started.

## Editing an unplugged interface

Offline Save, Forget, Reset and Wi-Fi edits validate the proposed configuration
and expected revision before stopping retained services. The daemon checks
Wi-Fi process records and stops only the recorded, owned processes. DHCP client
cleanup retains its lease proof if the old ifindex still exists under another
name, exact owned routes remain, or observation fails. Missing names do not
permit deleting kernel state from another device.

The new intent commits only after service cleanup succeeds and a fresh device
observation still reports the interface missing. Until that commit, the previous
saved intent remains the compensation target. A cleanup or definite persistence
failure may leave services stopped; convergence is notified and restores the
committed configuration when its dependencies are ready. Restart reads the same
committed intent and resolves surviving process/lease ownership records through
normal startup recovery. Credentials referenced by the old intent remain intact.

Wi-Fi client profiles can be read and edited even when the execution supervisor
is unavailable. Selecting a profile for a missing managed input interface uses
a revision-checked offline save with an explicit IPv4 policy. The selected
profile's credential is copied to an immutable interface version; later profile
updates or deletion do not alter that saved interface credential. Wi-Fi inventory
reports AP/client execution availability separately from the saved settings.
Liveness and queued association callbacks read current desired state under the
network mutation gate and skip tasks whose specification no longer matches.
Offline client deactivation also suspends session autoconnect after commit,
matching confirmed live deactivation; explicitly selecting a profile resumes it.

An interrupted Wi-Fi launch, an orphaned or changed process record, or a missing
supervisor with a persisted ownership record blocks the offline edit. Preserve
the diagnostic and state directory, repair the reported ownership/storage cause,
and retry; an interrupted launch may require startup recovery. Do not remove
ownership records just to make Save or Forget succeed. If commit persistence is
indeterminate, follow [TM-REC-209](#tm-rec-209); ordinary edits and runtime
convergence remain fenced until restart resolves durable storage.

## Recovery codes

Recovery conditions have stable `TM-REC-xxx` identifiers. Most are fatal startup blockers, while `TM-REC-207` and `TM-REC-208` describe degraded router recovery states in which the control plane remains available. The identifier is the primary operator reference; the invariant remains the machine-readable description of the condition. Codes are never reused for another invariant.

| Code | Invariant | Domain |
| --- | --- | --- |
| [`TM-REC-101`](#tm-rec-101) | `accessible_interface_recovery_store` | Interface recovery store |
| [`TM-REC-201`](#tm-rec-201) | `provable_router_recovery` | Router recovery umbrella |
| [`TM-REC-202`](#tm-rec-202) | `accessible_router_recovery_journal` | Router journal access |
| [`TM-REC-203`](#tm-rec-203) | `decodable_recovery_snapshot` | Router journal decoding |
| [`TM-REC-204`](#tm-rec-204) | `valid_recovery_snapshot` | Router journal structure |
| [`TM-REC-205`](#tm-rec-205) | `supported_schema` | Router journal schema |
| [`TM-REC-206`](#tm-rec-206) | `revision_order` | Router revision ordering |
| [`TM-REC-207`](#tm-rec-207) | `router_rollback_failed` | Degraded router rollback recovery |
| [`TM-REC-208`](#tm-rec-208) | `router_journal_cleanup_pending` | Recovered router state awaiting journal cleanup |
| [`TM-REC-209`](#tm-rec-209) | `commit_indeterminate` | Router commit outcome cannot be proven from storage |
| [`TM-REC-301`](#tm-rec-301) | `restore_provisioning_secrets` | Provisioning recovery umbrella |
| [`TM-REC-302`](#tm-rec-302) | `valid_provisioning_secret_snapshot` | Provisioning journal decoding |
| [`TM-REC-303`](#tm-rec-303) | `supported_provisioning_secret_schema` | Provisioning journal schema |

When reporting an incident, include the recovery code and invariant, but do not
include provisioning journal contents or secrets.

## Recovery actions

The `operator_action` field is deliberately small and stable. Use it together
with the recovery code as the first decision point.

| `operator_action` | Meaning | Safe response |
| --- | --- | --- |
| `inspect_recovery_state` | A higher-level startup step failed, but a more specific nested diagnostic should identify the cause. | Preserve state and inspect the complete error/log chain before changing anything. |
| `repair_storage_access` | The daemon cannot safely access a required recovery file or directory. | Repair the reported path type, permissions or backing storage; do not replace the recovery data with an empty file/directory. |
| `restore_coherent_backup` | Current persisted records cannot prove a safe recovery decision. | Restore the complete state directory from one internally consistent backup. |
| `use_compatible_daemon` | The journal schema is newer or otherwise unsupported by this binary. | Use a daemon version that supports the reported schema, or restore a coherent state backup. |
| `retry_rollback` | Runtime rollback failed after the journal was understood. | Repair the reported runtime/network cause and retry rollback while preserving the journal. |
| `await_cleanup` | Runtime recovery completed but journal housekeeping is still pending. | Preserve the metadata, repair storage access if necessary, and wait for automatic cleanup retry; do not recreate the journal. |

## Filesystem access failures

<a id="tm-rec-101"></a>
### `TM-REC-101` — `accessible_interface_recovery_store`

The daemon could not safely open or enumerate the interface recovery store. This
is a **global startup blocker** because it cannot prove which interface
transactions need recovery.

Typical report fields are:

```text
recovery_code=TM-REC-101
path=.../interface-transactions
expected_type=directory
expected_mode=0700
symlink_allowed=false
operator_action=repair_storage_access
```

Safe procedure:

1. Preserve the complete state directory.
2. Inspect every path component without following unexpected symlinks. The
   reported recovery-store object must be a real directory, not a symlink or a
   regular file.
3. Verify that the daemon/root can traverse the parent state directory and read
   the store. Private state directories are expected to use mode `0700`.
4. Resolve filesystem errors such as read-only media, failed mounts, full disks
   or I/O errors before changing permissions.
5. If the path has the wrong object type, preserve that object before replacing
   it. Do not create an empty store merely to bypass recovery.
6. Start the daemon again and verify that the invariant is gone.

A corrupt journal *inside* this directory is normally scoped to that interface;
a failure to access the directory itself is not.

<a id="tm-rec-202"></a>
### `TM-REC-202` — `accessible_router_recovery_journal`

The router recovery journal exists or may exist, but the daemon cannot safely
inspect/read it. The journal, when present, must be a private regular file and
must not be a symlink.

Typical fields are:

```text
recovery_code=TM-REC-202
journal=.../router-transaction.json
expected_type=regular_file_when_present
expected_mode=0600
symlink_allowed=false
operator_action=repair_storage_access
```

Safe procedure:

1. Preserve the complete state directory.
2. Check the reported path and parent directories. Do not follow or replace a
   symlink at the journal path.
3. Resolve permission or storage failures. A traffic-masq private journal is
   expected to use mode `0600`.
4. Do **not** truncate the file or replace it with `{}`. Its exact bytes may be
   required to prove recovery or retirement.
5. Restart and let the daemon decode and reconcile the original journal.

If the file becomes readable and a different invariant appears, continue with
that invariant below.

## Per-interface journal failures

### `valid_interface_snapshot`

A malformed, unsupported or interface-mismatched journal under
`<state_dir>/interface-transactions/` is isolated to that interface. Startup can
continue, but traffic-masq blocks recovery-dependent mutations for the affected
interface instead of guessing how to restore it.

Safe procedure:

1. Identify the affected interface and journal from the log/block reason.
2. Preserve the complete state directory before changing the journal.
3. Do not copy another interface's journal into its place and do not change the
   recorded interface name or token by hand.
4. Restore a matching journal/state backup for that interface only when you can
   prove it belongs to the same saved state; otherwise restore one coherent
   state-directory backup.
5. Restart or allow interface recovery to retry, then verify that the interface
   is no longer reported as blocked.

Unrelated interfaces and the control plane should remain available while this
journal is blocked.

## Router journal validation failures

<a id="tm-rec-201"></a>
### `TM-REC-201` — `provable_router_recovery`

This is the higher-level router startup invariant. With
`operator_action=inspect_recovery_state`, the nested diagnostic is the useful
cause. Read the complete error chain and follow the more specific router section
below. Do not remove the router journal just because this umbrella invariant is
shown.

The router journal is normally
`<state_dir>/router-transaction.json`. These failures are startup-blocking when
the daemon lacks an independent proof that the transaction committed.

<a id="tm-rec-203"></a>
### `TM-REC-203` — `decodable_recovery_snapshot`

The router journal is not valid JSON. Text that merely *looks* like a transaction
token inside malformed JSON is not trusted as commit proof.

Safe procedure:

1. Preserve the complete state directory and the journal exactly as found.
2. Do not repair JSON syntax, extract a token manually, or delete the journal.
3. Restore the **complete state directory** from one coherent backup that
   predates or consistently contains the interrupted transaction.
4. Restart and verify that recovery succeeds.

If no coherent backup exists, retain the state and diagnostic for manual
forensics; there is no safe automatic rule that can infer the missing commit
proof from corrupt bytes.

<a id="tm-rec-204"></a>
### `TM-REC-204` — `valid_recovery_snapshot`

The journal is syntactically valid JSON but does not have a valid router
transaction structure.

Treat it like `decodable_recovery_snapshot`: preserve it, do not hand-edit the
record, and restore the complete state directory from one coherent backup. The
reported `required_proof=independent_committed_transaction_token` means the
journal itself is not sufficient evidence of a successful commit.

<a id="tm-rec-205"></a>
### `TM-REC-205` — `supported_schema`

The journal structure is readable, but its schema version is not supported by
the running daemon. The diagnostic includes `journal_schema` and
`supported_schemas`.

Safe procedure:

1. Preserve the complete state directory before changing binaries.
2. Use a `traffic-masqd` version that supports the reported journal schema. Do
   not modify the schema number in the JSON.
3. Start that compatible daemon and allow it to complete recovery/retirement.
4. If a compatible daemon is unavailable, restore the complete state directory
   from one coherent backup that the current daemon can read.

Do not downgrade only the journal. State files can evolve together and must stay
consistent.

<a id="tm-rec-206"></a>
### `TM-REC-206` — `revision_order`

The router journal was created against a newer committed revision than the
runtime state currently reports. The diagnostic includes, for example:

```text
recovery_code=TM-REC-206
journal_base_revision=15
committed_revision=14
operator_action=restore_coherent_backup
```

This normally indicates that persisted files no longer come from one coherent
point in time.

Safe procedure:

1. Preserve the complete state directory.
2. Do not change either revision number manually.
3. Do not restore only `router-transaction.json` or only
   `runtime-overrides.json`.
4. Restore the **complete state directory** from one coherent backup.
5. Restart and verify that the revision-order diagnostic is gone.

## Provisioning-secret recovery failures

Router provisioning secrets are journaled separately because staged passphrases
are intentionally not stored in normal runtime overrides. The default journal is:

```text
<state_dir>/wifi/router-provisioning-secrets.json
```

Treat this file and its backups as sensitive. Do not paste its contents into bug
reports, terminal transcripts or support messages.

<a id="tm-rec-301"></a>
### `TM-REC-301` — `restore_provisioning_secrets`

This is a higher-level startup invariant. `operator_action=inspect_recovery_state`
means the nested error is the important part. Inspect the complete error/log
chain before modifying state.

If the nested cause is a filesystem/layout problem, preserve state and repair
access to the reported `wifi` directory or journal. Private state directories
are expected to be mode `0700`, private files mode `0600`, and recovery paths
must not be symlinks.

If the nested cause is one of the validation invariants below, follow that
specific runbook.

<a id="tm-rec-302"></a>
### `TM-REC-302` — `valid_provisioning_secret_snapshot`

The provisioning-secret journal cannot be decoded as the supported record type.
Do not edit or selectively reconstruct it.

Safe procedure:

1. Preserve the complete state directory securely.
2. Do not print, copy into tickets, or hand-edit the journal contents.
3. Restore the complete state directory from one coherent backup.
4. Start the daemon and verify that the provisioning recovery invariant is gone.

<a id="tm-rec-303"></a>
### `TM-REC-303` — `supported_provisioning_secret_schema`

The provisioning-secret journal is structurally valid but uses a schema this
binary does not support. The diagnostic reports `journal_schema` and
`supported_schemas`.

Safe procedure:

1. Preserve the complete state directory securely.
2. Use a daemon version supporting that schema; do not edit the version field.
3. Let the compatible daemon complete recovery.
4. If that binary is unavailable, restore one coherent state-directory backup.

## Degraded recovery that does not require deleting metadata

Not every recovery problem blocks the daemon process.

<a id="tm-rec-207"></a>
### `TM-REC-207` — `router_rollback_failed`

If the router journal was understood but rollback itself failed, the coordinator
can remain in `RollbackFailed` while the control plane stays available. New
router transactions remain blocked until recovery completes. The TUI shows the
individual rollback failures and `operator_action=retry_rollback`.

Safe response:

1. Inspect the reported rollback failures and current interfaces/routes.
2. Repair the external cause (for example, missing runtime resources or an
   ownership conflict) rather than editing the journal.
3. Retry the explicit rollback through the running control plane/TUI when the
   cause has been corrected. On the Router screen, press `r`; on the recovery
   transaction screen, use **Retry rollback** / `Enter`.
4. Keep the journal until the daemon retires it after successful rollback.
5. Recovery is complete when the coordinator returns to `idle` and new router
   transactions are admitted again.

<a id="tm-rec-208"></a>
### `TM-REC-208` — `router_journal_cleanup_pending`

Runtime recovery has already completed, but the recovery journal or its receipt
could not yet be retired. The control plane remains available, but new router
transactions stay blocked so completed recovery evidence cannot be overwritten.
The daemon retries housekeeping separately.

Safe response:

1. Preserve the journal and recovery receipt; do not recreate either file.
2. Inspect the state-directory filesystem, ownership, permissions and backing
   storage for the cleanup error reported in the daemon logs.
3. Repair the storage problem and allow housekeeping to retry automatically.
4. Refresh the TUI/status (`r` on the Router screen refreshes this recovery
   state). Recovery is complete when the coordinator returns to
   `idle`; do not manually delete metadata just to clear the status.

### Foreign-route conflicts

A route that traffic-masq cannot prove it owns is preserved rather than deleted.
The daemon can remain available in a degraded state. Inspect the conflicting
route and its owner, correct the external configuration if appropriate, then
retry recovery. Never delete an unrelated route solely to satisfy traffic-masq.

### Missing router interfaces after successful recovery

A configured router interface that is absent after rollback does not by itself
block startup convergence. Reconnect the adapter, check `ip link`, or correct the
interface name in router configuration. The daemon retries convergence when the
interface appears.

### Recovery completed but journal cleanup is pending

If the runtime/network recovery completed but journal retirement failed, the
daemon can report a cleanup-pending state and retry housekeeping separately. Do
not treat the leftover journal as evidence that rollback still needs to be run,
and do not delete it manually. Repair the reported filesystem/storage problem
and let the daemon retry retirement.

## What not to do

Do not use any of these as a shortcut around a recovery error:

- delete or truncate `router-transaction.json`;
- delete or edit `wifi/router-provisioning-secrets.json`;
- change a journal token, schema version or revision number by hand;
- copy one journal from a backup without the state files that belong to the same
  point in time;
- replace an inaccessible recovery directory with an empty one;
- turn a recovery path into a symlink;
- use `reset --force-offline` as a substitute for preserving and diagnosing an
  unresolved recovery transaction.

Those actions can remove the evidence needed to distinguish an already committed
change from an interrupted one.

## Recovery completion checklist

Before returning the machine to normal administration, verify all of the
following:

- `traffic-masqd start` no longer reports a startup-blocking recovery invariant;
- `traffic-masqd status` reports the daemon ready;
- recent logs contain no new fatal recovery diagnostic for the same state;
- any degraded router rollback has been explicitly completed before applying a
  new router transaction;
- recovery journals were retired/quarantined by the daemon rather than manually
  deleted;
- the preserved backup remains available until network behavior and committed
  configuration have been checked.

<a id="tm-rec-209"></a>
## TM-REC-209: commit outcome is indeterminate

The override replacement failed and restoring its previous contents also failed.
The file may contain the new commit token while the running daemon still holds
its previous revision. The daemon blocks configuration writes, network mutations,
confirmation and rollback, including timer and shutdown rollback. Shutdown preserves
interface and dataplane ownership for startup recovery.

Repair storage access, then restart the daemon. Keep the complete state directory;
do not delete a transaction journal or replace an individual override file.
Startup reloads the persisted commit proof: a matching token retains the committed
change; an uncommitted journal is rolled back. Unreadable or invalid proof continues
to block the affected recovery scope. A failed commit response in this state does
not establish whether the configuration was committed.

## Bounded automatic recovery

Interface and router recovery share a bounded cycle: at most **three attempts**,
**60 seconds per attempt**, and **180 seconds for the whole cycle**, including
retry delays. The confirmation window before rollback remains separate. Recovery
caused by a failed apply starts its retries without waiting for another full
confirmation window. Startup interface retries also consume the same persisted
cycle; restarting the daemon does not reset the attempt count or renew its
remaining budget. A monotonic deadline additionally prevents wall-clock changes
from extending a running cycle.

Failures are classified by error types and kernel error codes, not message text:

| `failure_kind` | Automatic response |
| --- | --- |
| `transient` | Retry within the remaining cycle, with increasing delay. |
| `device_missing` | Allow bounded retries for a reconnect, with longer delays. |
| `conflict` | Stop; preserve resources owned by another actor. |
| `incompatible` | Stop; repair the configuration/environment or restore compatible state. |
| `storage` | Stop; repair access while retaining the snapshot and control record. |
| `commit_indeterminate` | Preserve the existing commit fence; repair storage and restart. |
| `unknown` | Retry only within the bounded cycle; do not assume the operation had no effect. |

A missing adapter cannot leave automatic recovery waiting indefinitely. After the
budget or attempt limit is exhausted, the interface phase/router status becomes
`recovery_required`. A later device event does **not** resume the stopped cycle.
Inspect the current network, correct the cause, and explicitly retry rollback.
The retry starts a new cycle only after the previous cycle has stopped; repeated
manual requests during an active cycle do not renew its budget. Update the daemon
and TUI together to display this new status.

`PendingNetworkChange.recovery_progress` and
`RouterRecoveryNotice.recovery_progress` expose the failure kind, attempt count,
limit, deadline and whether automatic recovery remains enabled. Confirmation of
a partially restored change is disabled. The TUI displays these details and
keeps the existing explicit rollback action available.

The immutable snapshot journal is accompanied by a private
`<journal>.recovery-control` record bound to its exact SHA-256 digest. This record
is written before runtime mutations, including application before a confirmation
timer exists. An interrupted apply/rollback requires explicit recovery after
restart. Stopped control records fence background reconciliation and process
restarts, and shutdown preserves unresolved owned state instead of replaying
baselines. Startup does not independently restore router provisioning secrets
before the router recovery decision. Failed credential restoration prevents its
runtime consumers from being restarted by that rollback.

Keep the complete state directory, including these control records and recovery
receipts. Do not edit/delete them to renew the budget, and do not downgrade to a
daemon that ignores them while recovery is unresolved. If the control record is
unreadable or corrupt, even explicit rollback stays fenced until storage/state is
repaired. A failure to persist the decision is reported as unconfirmed persistence;
the running daemon still stops automatic work. A prior write-ahead attempt record
allows restart to recognize interruption when the final stop write failed.

A timeout does not prove that a kernel operation was cancelled or had no effect.
Retries re-observe runtime state through the existing ownership-aware rollback
paths. Independent subsystem rollback still collects failures; this phase does
not introduce a durable per-step completion ledger or automatic acceptance of a
partially restored network. The snapshot is retired only after restoration and
its dependent credentials/ownership are settled, or an independent committed
token proves rollback is obsolete. A cancelled commit write uses the existing
`commit_indeterminate` fence rather than guessing its outcome.

Forward recovery into a replacement configuration, transfer to external
management, and cross-host configuration migration remain separate operations;
this bounded recovery mechanism does not silently commit a failed candidate or
convert an old host's snapshot into portable configuration.

### Saved router intent and removal-only cleanup

Offline sharing/route Save first commits validated intent through the shared
revision-checked override writer. No runtime deletion happens on failed or
indeterminate commit. Cleanup then intersects proven nft permissions with the
committed intent and deletes obsolete routes carrying the daemon route protocol.
It never opens a rollback journal, installs candidate resources, or compensates
by restoring deleted permissions. Interrupted removal is idempotently resumed
from committed intent at startup and on missing-device reconciliation.

Cleanup requires valid nft ownership metadata and intact structure before
changing its table; ambiguous or drifted ownership is a blocker. Foreign tables
and routes, DHCP-owned routes, services, and global forwarding are preserved.
Default-route deletion still requires explicit permission. If a still-saved
route references a missing output name, scalar-matching owned routes are retained
until that dependency can be resolved: an absent name does not prove an ifindex.
Removing that route from intent permits exact owned deletion without the device.

Caller cancellation does not release router coordination while an nft blocking
write remains in flight. Cleanup runs to completion under coordinator state
ownership, and stale cleanup intent is rejected before mutation. API success
includes `cleanup_blockers` if deletion fails; saved intent remains authoritative.
Inspect router health and the reported ownership/storage cause, repair it, and
let convergence retry. Existing transaction/recovery fences remain in effect.
