# Recovery isolation implementation notes

This change set narrows startup recovery dependencies without changing the durable router-journal
schema.

## Implemented

- Configuration deserialize and normal-runtime admission are separate. Startup recovery can run
  through semantic errors in unrelated API/auth settings; strict validation is still required
  before normal convergence and listeners.
- Router and interface commit-proof fields are consumed independently. An invalid proof field
  cannot suppress recovery of the other scope.
- Corrupt address-ownership documents are isolated per interface. The affected interface is fenced
  non-retryably and its interface transaction is not replayed through the ownership uncertainty.
- Recovery-sensitive JSON-directory enumeration rejects symlink/non-regular documents instead of
  silently hiding them.
- Provisioning-secret recovery is sequenced after independent interface recovery.
- When a router journal is pending, DHCP/DHCP-client/Wi-Fi runtimes are opened for rollback without
  normal startup reconciliation. Normal reconciliation is deferred until router recovery and strict
  admission complete.
- File logging falls back to stderr instead of preventing recovery.
- Router dataplane/coordinator wiring reuses one network provider; WireGuard provider initialization
  is lazy and occurs only when a VPN operation is actually required.
- Regression tests cover semantic-invalid recovery config, proof-field isolation, ownership
  isolation, unsafe store entries, non-retryable fences, and transaction recovery exclusion.

## Deliberately still fail-closed

- An unreadable/unenumerable recovery-store directory remains global because the set of pending
  records cannot be proven.
- An undecodable `runtime-overrides.json` envelope or unsupported envelope schema remains fatal to
  scopes whose independent commit proof cannot be extracted safely.
- Router journal/provisioning journal failures retain the existing typed recovery diagnostics and
  do not authorize destructive guesses.
- Runtime adapters that are actually needed to restore the durable snapshot may still fail recovery;
  those are recovery dependencies, not normal-start prerequisites.

## Follow-up architecture

1. **Recovery locator**: persist the recovery `state_dir`/bootstrap paths outside mutable TOML so a
   syntactically malformed main config cannot make journals undiscoverable.
2. **Per-scope proof storage**: split router and interface commit proof into independently readable
   durable records so corruption of the shared JSON envelope cannot couple the scopes.
3. **Router journal v3**: persist the previous committed router intent (or equivalent ownership set)
   in the transaction journal so crash rollback no longer needs to reconstruct committed intent from
   the current base config.

## Local validation limitation

The supplied execution environment does not contain `cargo`, `rustc`, or `rustfmt`. The change set
was therefore checked by source-level call-site review, delimiter/syntax-structure checks, and
`git diff --no-index --check`. It must still pass the project's normal `cargo fmt`, `cargo check`, and
test suite in CI or a Rust development environment before merge.
