# Architecture

`traffic-masqd` runs network operations. The terminal client, `traffic-masq`,
talks to it through the local HTTP API. In direct mode, the client reads
interface state itself and cannot make changes.

| Module | Responsibility |
| --- | --- |
| `api` | HTTP, authorization and control-operation limits |
| `core` | Configuration, ownership, plans, transactions and reconciliation |
| `crates/netlink` (`traffic-masq-netlink`) | Kernel interfaces, IPv4 addresses, routes, rules and change events |
| `firewall` | nftables and IPv4 forwarding |
| `dhcp`, `wifi`, `vpn` | DHCP and VPN runtimes; Wi-Fi service supervision |
| `state`, `atomic_file` | Persistent state and atomic file writes |
| `app` | Startup, shutdown, installation and init integration |
| `tui` | Input, screen state and rendering |

The root library re-exports `traffic-masq-netlink` as `traffic_masq::netlink`
for existing callers. The netlink crate depends only on kernel protocol and
runtime libraries; application orchestration depends on it, never the reverse.

## Applying changes

The daemon compares the requested configuration with the current network state
and builds a plan. It changes only resources it owns. Runtime overrides are
merged with the file configuration each time, so an earlier override does not
become the base for the next one.

Interface and router changes use commit-confirm transactions. Before applying
one, the daemon persists the rollback state it needs; router transactions keep a
full snapshot until the user commits the change or rollback succeeds. A commit
saves the requested configuration, and reconciliation then corrects differences
between committed intent and the running system.

Router provisioning rollback restores journaled Wi-Fi credentials before
restoring runtime services, so reconnecting the previous uplink can obtain a
fresh DHCP lease. The secret journal remains until runtime restoration succeeds;
secret I/O or runtime failures keep the transaction in rollback recovery and
prevent confirmation. This ordering also applies to timeout, shutdown and
failed-apply compensation.

Operator AP/client configuration, saved profile activation, and operator-triggered
AP/client deactivation use the same commit-confirm interface transactions as
provisioning. Internal autoconnect activation and timeout cleanup remain
immediate. DHCP and VPN controls plus Wi-Fi passphrase/reconnect/reload runtime
controls also remain immediate. Since runtime
effects can survive a daemon crash, subsystems establish durable ownership
proof before persistent runtime state is created: DHCP lease records include the applied route policy, Wi-Fi launches use
write-ahead process records, and WireGuard activation uses a durable intent plus
an interface launch marker. Startup recovery compares those proofs with
committed intent and only removes state whose ownership can still be verified.

The global mutation gate serializes admitted network mutations with transaction
execution. Desired-state convergence uses the compatible read side so an
interface transaction can wait for its worker; autonomous background writers
(such as supervised-process liveness repair) take exclusive runtime execution so
they cannot replay stale state across a convergence pass. Accepted control
operations keep running if the HTTP client disconnects. The executor
limits queued work and waits for accepted operations during shutdown. If a
request times out, the client must check the current state before retrying: the
change may already have taken effect.

Wi-Fi radio admission uses a shared policy: managed AP and STA interfaces may
not share a known physical PHY, including a temporary STA used for scanning.
The rule applies to interface transactions, router provisioning, profile
activation, autoconnect, startup and runtime reconciliation. Router provisioning
also checks allocations outside the selected interface pair. Unknown PHYs are
skipped and checked again during reconciliation when devices appear; this is
not capability-based support for concurrent AP/STA VIFs.

## Terminal client

Editors keep drafts until the user applies or discards them. Refreshes preserve
drafts and selection. Input and rendering must remain responsive during API
requests. Never retry a mutation automatically after a timeout, or include
passwords and session tokens in debug logs or operation messages.

Network decisions belong in `core` or the service module responsible for them.
HTTP handlers and TUI widgets translate input and show results; they do not
change kernel state directly.

### Commit uncertainty and confirmation timing

If both override replacement and its compensation fail, the daemon fences the
state directory as `commit_indeterminate`. It preserves pending journals and
refuses further writes and rollback until storage is repaired and the daemon is
restarted to resolve the on-disk commit proof. It must not compensate using its
potentially obsolete in-memory revision. Interface pending responses expose
`phase` (`awaiting_commit`, `rollback_required`, `commit_indeterminate`) and
`last_error`. Confirmation is available only in `awaiting_commit`; rollback is
blocked in `commit_indeterminate`.

Confirmation timers schedule rollback after the configured interval; they do
not promise that runtime restoration finishes by that time. Rollback waits for
already admitted operations and may need retries. An already admitted confirmation
can finish after the displayed expiry. `expires_at_unix` is an advisory wall-clock
display value; scheduling uses a monotonic timer. Clients should inspect pending
state after expiry or a request timeout, rather than infer a transaction outcome.

## Wi-Fi credential roles

AP and station credentials have separate interface-keyed stores:
`wifi/psk-ap/<interface>` and `wifi/psk-client/<interface>` under the state
directory. Supervisors never fall back to the legacy `wifi/psk/<interface>`
namespace. Updating or clearing one role does not change the other role's secret.
A protected AP/STA role transition cannot use `Keep`: it needs an explicit
passphrase or an explicit `passphrase_file`. Selecting a file on a role transition
clears any older stored credential for the target role so it cannot shadow that
file. Same-role edits can retain their existing credential.

Interface secret journals (version 3) and router provisioning secret journals
(version 2) record the credential role. Rollback and crash recovery restore only
that namespace. Older journals are still recovered into the legacy namespace
before migration; their role is not guessed from the proposed configuration.

After legacy journal recovery, startup migrates credentials according to the
committed interface configuration. The role-specific copy is persisted before
the old file is removed, so an interrupted migration can be repeated. Conflicting
source and destination values stop migration without overwriting either secret.
Entries without an unambiguous configured role move to `wifi/psk-unassigned/`,
which neither supervisor reads. Recovery-blocked interfaces are deferred until
recovery succeeds. Profile stores and explicitly configured external secret
files retain their existing paths.
