# Recovery changes

## Behaviour

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

Regression coverage includes exact receipt identity, failed housekeeping,
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
