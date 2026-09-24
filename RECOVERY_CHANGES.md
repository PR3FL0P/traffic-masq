# Recovery changes

## Behaviour

- Startup now has a recovery-only override admission path. It reads the durable
  router/interface commit proof independently from unrelated API/security fields,
  recovers interface scope before router provisioning scope, and builds router
  recovery state from only router-relevant overrides. The full strict override
  document is hydrated into the same manager only after router journal recovery
  completes. Invalid unrelated overrides can still reject normal startup, but no
  longer suppress durable network rollback.
- Configuration decoding is separated from normal-runtime admission. `run` and
  service-start paths may enter recovery with a semantically invalid API/auth or
  other unrelated setting; full `AppConfig::validate()` remains mandatory before
  normal convergence. When no router journal is pending, strict admission happens
  before any normal network mutation. A syntactically undecodable TOML file still
  requires the planned recovery-locator bootstrap work because custom recovery
  paths cannot be recovered safely from malformed syntax.
- Router and interface commit-proof fields are consumed independently. A malformed
  router token no longer suppresses interface recovery, and malformed interface
  proof fences only interfaces with pending transaction journals instead of
  suppressing unrelated router recovery. The JSON proof envelope and schema remain
  fail-closed because tokens are never inferred from undecodable bytes.
- Address-ownership records are isolated per interface. A malformed, future-schema,
  symlinked, or otherwise unsafe `<interface>.json` fences that interface while
  valid ownership records continue to load. Such a fence is non-retryable by the
  interface-transaction loop, and transaction rollback for the same interface is
  deferred so an untrusted ownership record cannot be bypassed. Failure to open or
  enumerate the ownership directory remains global because the record set is then
  unknowable.
- When a router journal is pending, DHCP and Wi-Fi supervisors are constructed in
  recovery mode without normal startup cleanup/reconciliation. Their committed-state
  startup pass runs only after router recovery and strict admission. DHCP-client
  lease enumeration is therefore no longer a precondition for reaching router
  rollback.
- A non-writable file-log directory no longer suppresses recovery: tracing falls
  back to stderr and normal startup continues to enforce the rest of its runtime
  invariants.
- Router recovery reuses the already-open network provider instead of opening extra
  rtnetlink handles. WireGuard netlink/genetlink setup is lazy, so an unused VPN
  backend cannot prevent an unrelated router journal from reaching recovery; the
  provider is opened only when a rollback/apply operation actually needs WireGuard.
- API socket binding and auth-database opening happen only after router recovery
  and strict override hydration. A local API/auth failure therefore cannot prevent
  recovery of journals left by a previous run. When a router journal is pending,
  shutdown requests are deferred until the recovery pass has completed.
- Router journal presence checks no longer use symlink-following `try_exists`. A
  dangling symlink or any non-regular journal path is fail-closed as TM-REC-202
  before legacy network/dataplane bootstrap. Runtime override reads likewise
  reject symlink targets rather than treating dangling links as missing state.
- A completed rollback or durable commit retires its journal through a separate
  housekeeping path. Unlink, receipt-write and fsync failures are logged as
  `recovered_but_journal_cleanup_pending`; housekeeping retries every 30 seconds.
  Router status exposes the same state. Completion wakes runtime convergence. New overlapping writes remain blocked
  until cleanup finishes, preventing stale recovery data from undoing newer work.
- A SHA-256 receipt binds completion to the exact journal bytes. Restart can skip
  rollback only for matching bytes. Orphan receipts are removed before a new
  journal is written, including when the new secret snapshot would be identical.
- An independently committed router token permits quarantine of obsolete router
  records as `*.stale` or unsupported/invalid snapshots as `*.corrupt`. The same
  proof retires obsolete provisioning-secret metadata before decoding its full
  schema, so a committed transaction cannot be wedged by a future/extra field.
  Malformed JSON still requires operator recovery because token text is never
  inferred from undecodable bytes. A newer global configuration revision alone
  is **not** proof: unrelated settings may have changed while an unconfirmed
  router transaction still needs rollback.
- Unknown/corrupt router snapshots without independent proof remain fatal rather
  than authorizing destructive recovery. Diagnostics include invariant, journal,
  object, operation and whether metadata removal is safe. Interface transaction
  corruption instead blocks that interface while other interfaces can recover.
- Fatal recovery diagnostics use typed operator actions rather than ad-hoc action
  strings. They also expose action-specific facts such as expected filesystem
  type/mode, journal schema, supported schemas and both sides of a revision
  mismatch, plus stable operator guidance that preserves recovery metadata.
- Fatal recovery diagnostics also carry stable `TM-REC-xxx` codes. The code,
  invariant and runbook anchor are defined by one typed `RecoveryCode`, so they
  cannot drift independently. Startup receipts include the code, and the launcher
  rejects a receipt whose code and invariant disagree before showing advice.
- Detached startup preserves typed fatal recovery diagnostics in a versioned,
  private startup report. `traffic-masqd start` clears stale reports before each
  serialized start attempt and renders the current invariant, affected path or
  journal, action-specific facts and operator guidance when startup fails.
  Ordinary startup failures never acquire a recovery label, and an unsafe stale
  report is ignored rather than trusted.
- A per-interface journal whose token independently matches the committed token
  is retired before full schema decoding; an unproven corrupt journal still blocks
  only that interface. Interface recovery-store enumeration retries bounded
  transient I/O failures; structural layout, symlink and permission failures
  remain fail-closed and carry an `operator_action` diagnostic. Startup isolates
  interface apply, Wi-Fi record discovery/cleanup and DHCP
  server/client recovery failures. Unavailable Wi-Fi supervisors do not abort
  other subsystems. Per-interface recovery gates cover API admission, runtime
  convergence, autoconnect and DHCP-client recovery/configuration. Interface
  confirmation and rollback resolve their scope from the transaction token, so
  an unrelated blocked interface cannot strand a pending change.
- Failed interface startup recovery is retried on network events and every 30
  seconds while unresolved. Only blocked startup journals are retried; live
  transaction journals are never replayed by the background pass. Missing or
  invalid recovery records remain blocked until valid recovery is possible.
- Degraded router recovery is exposed through the API and TUI with stable
  `TM-REC-207` / `TM-REC-208` notices. `RollbackFailed` disables commit and offers
  an explicit rollback retry, including after a daemon restart; cleanup-pending
  returns to the Router screen and remains visible while housekeeping retries.
- Router rollback failure retains the journal and a retryable coordinator state;
  control-plane inspection and explicit router rollback remain available. Since
  a router transaction spans dependent subsystems, its mutation gate remains
  conservative until the whole snapshot is restored. A failed ownership
  reconstruction retains its candidate intent and must succeed on retry before
  manual rollback can restore the snapshot or retire the journal.
- Foreign-route conflicts are typed and visible as blocked/degraded dataplane;
  the foreign route is preserved and daemon startup continues. Route rollback
  re-observes failed add/delete operations before deciding that recovery failed.
- An unrelated blocked interface no longer downgrades an unproven router-recovery
  error into degraded startup; router fatality is decided only from router state,
  foreign-route conflict, or cleanup-pending status.
- Legacy interface/dataplane bootstrap is deferred when a router journal exists.
  Failure to repair committed router intent is reported as degradation rather
  than aborting the control plane.

## Validation

Regression coverage includes recovery-only override proof parsing, independent
proof-field failures, semantic-invalid base-config decoding for recovery,
recovery-scoped router validation, per-interface ownership isolation, unsafe
private-store enumeration, strict hydration after router recovery, dangling override/router
journal symlinks, regular-file journal inspection, exact receipt identity, failed housekeeping,
newer-journal protection, repeated quarantine, interface isolation, orphan
receipts, restart after completed rollback, committed invalid-schema quarantine,
router cleanup status, corrupt interface journals, typed foreign-route conflicts,
and repeated route rollback.

Additional regressions exercise API commit/rollback with an unrelated blocked
interface, repeated ownership preparation before manual router rollback, and
runtime recovery after adapter reconnection without replaying live journals.

Run:

```sh
cargo fmt --check
cargo test --lib
```

Namespace and physical-network tests require their normal Linux network
capabilities and suitable hardware.
