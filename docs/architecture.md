# Architecture

`traffic-masqd` runs network operations. The terminal client, `traffic-masq`,
talks to it through HTTP over a Unix socket or verified HTTPS. In direct mode,
the client reads interface state itself and cannot make changes.

| Module | Responsibility |
| --- | --- |
| `api` | HTTP, authorization and control-operation limits |
| `crates/protocol` (`traffic-masq-protocol`) | API wire DTOs and pure shared intent validation, independent of daemon internals |
| `crates/host-observation` (`traffic-masq-host-observation`) | Init-system observation, competing network-manager discovery and operator guidance |
| `crates/api-client` (`traffic-masq-api-client`) | Unix-socket HTTP and verified HTTPS transport, auth/session, request mapping and response decoding |
| `crates/tui` (`traffic-masq-tui`) | Standalone terminal client and read-only direct-mode observation |
| `core` | Configuration, ownership, plans, transactions and reconciliation |
| `crates/netlink` (`traffic-masq-netlink`) | Kernel interfaces, IPv4 addresses, routes, rules and change events |
| `crates/dataplane` (`traffic-masq-dataplane`) | nftables and IPv4 forwarding models, plans and reconciliation |
| `crates/dhcp-core` (`traffic-masq-dhcp-core`) | DHCP packets, server leases, and client state transitions |
| `crates/wireguard` (`traffic-masq-wireguard`) | WireGuard profile parsing and Linux netlink operations |
| `firewall` | Daemon command adapter for the dataplane crate |
| `dhcp`, `wifi`, `vpn` | DHCP and VPN runtimes, storage and ownership; Wi-Fi service supervision |
| `state`, `crates/atomic-file` | Persistent state and atomic file writes |
| `app` | Startup, shutdown, installation and init integration |

The root library re-exports `traffic-masq-netlink` as `traffic_masq::netlink`
for existing callers. The netlink crate depends only on kernel protocol and
runtime libraries; application orchestration depends on it, never the reverse.
The dataplane crate owns forwarding rules and depends on protocol and netlink.
The daemon supplies its bounded `nft` command executor at the `firewall`
boundary; the dataplane crate does not import daemon configuration or core.
The DHCP core contains no socket, store, or supervisor code. The daemon's DHCP
module re-exports its packet, lease, server, and client state-machine APIs.
The WireGuard crate owns the profile parser and kernel provider; the daemon
keeps profile storage, activation policy, and ownership recovery.
Host observation is a leaf shared by the daemon and terminal client. It owns
the `/proc` scan and init detection; protocol performs no host discovery.

Daemon startup constructs `ControlService::from_runtime` with a complete
`ControlRuntime` and explicit `ControlSubsystems`. The context supplies active
settings, the original file configuration, ownership baselines, and the same
desired state and mutation gate used by reconciliation. Construction also wires
transaction timers to that gate. Standalone constructors and service builders
remain available for tests and tooling without a converger; production does not
replace shared state after constructing the service.

`RouterManager` orders router apply and rollback stages. Its subsystem boundary
captures one router-scoped `RouterSnapshot` with `snapshot_for`, including
absent DHCP services and clients needed for rollback. `RouterSubsystems::plan_for`
collects a full plan; route, VPN, and dataplane planning remain available for
targeted drift repair. The production adapter delegates VPN hop ownership,
relay routing, policy, and compensation to a concrete VPN chain runtime while
`RouterManager` retains the transaction order. Wi-Fi startup checks for
hostapd and wpa_supplicant live with the Wi-Fi supervisors. AP radio capabilities
and regulatory domains are read directly through nl80211. The app's
`startup_recovery` module validates durable proofs before normal admission or
API binding; `router_startup` wires the production coordinator and restores
temporary route/dataplane baselines; `vpn_startup` prepares VPN control and
legacy policy migration; `reconcile` owns runtime network convergence and
integrity workers. After those workers stop and pending rollback is attempted,
`daemon_shutdown` chooses the final restore policy and cleans up runtime
resources. An uncertain commit keeps recovery evidence and prevents baseline
restoration.

DHCP client apply, quiesce, rollback and health hooks are required by
`RouterSubsystems`; adapters without an embedded client must explicitly reject
nonempty intent and recovery state. Production preflight rejects missing DHCP
and Wi-Fi runtimes before a plan can enter transaction execution.

`api::model` re-exports the protocol DTOs for current callers. The request
envelope now lives in protocol. Interface changes and router proposals use
protocol-owned DTOs converted to daemon configuration at the control boundary.
DHCP configuration requests use a protocol DTO converted at the same boundary.
The response envelope also lives in protocol. VPN views, router health,
coordinator and pending-change status, DHCP lease views, interface status and
plans, routes, Wi-Fi status, and the complete router plan are protocol DTOs.
The response alias `ControlResponse` contains no daemon model types. The TUI
crate depends on protocol, API client, netlink, host observation and atomic file storage without
depending on the daemon crate. Its binary provides the operator interface.
`config` re-exports shared interface, Wi-Fi and VPN enum values from protocol;
`core::router_provisioning` similarly re-exports downstream overrides.
The root `api::client::ApiClient` aliases the standalone `ControlApiClient`.
The client crate maps protocol
requests to REST endpoints and owns auth/session behavior without importing the
daemon crate.

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

Interface transaction ordering stays in `core::transaction`. Its `journal`
module owns the snapshot schema and durable storage, `credentials` prepares
role-specific secret edits and compensation, and `recovery` restores interrupted
transactions. Credential preparation is observational: the coordinator writes
the snapshot before applying a credential edit. Journal versions and legacy
credential recovery semantics remain unchanged. A rollback-only pending token
and cancellation guard exist before the first runtime mutation. Cancellation
hands compensation to a background owner that reacquires the per-interface
transaction lock and participates in the shared convergence reservation.
Journal registration retains operation and runtime reservations until its
durable snapshot has a pending owner; cancellation during storage cannot leave
a late journal write outside shutdown rollback. The desired state is supplied
at construction and cannot be replaced while a manager or its clones exist.
Blocking credential writes retain their runtime, interface-lane and credential
reservations until the worker finishes, so compensation cannot race a late
write. The handoff does not reset an existing recovery budget or erase a stopped
recovery decision.

Wi-Fi supervisors share an encapsulated `wifi::retry` policy. Only that module
updates attempt counters, backoff and interface-bound suspension. AP diagnostic
classification lives in `wifi::supervisor::health`; temporary STA scans and
their ownership cleanup live in `wifi::client::supervisor::scan`. AP and STA
readiness remain distinct: AP respawn keeps backoff until health reports
`ENABLED`, while STA preserves its existing control-endpoint readiness policy.

Router provisioning rollback restores journaled Wi-Fi credentials before
restoring runtime services, so reconnecting the previous uplink can obtain a
fresh DHCP lease. The secret journal remains until runtime restoration succeeds;
secret I/O or runtime failures keep the transaction in rollback recovery and
prevent confirmation. This ordering also applies to timeout, shutdown and
failed-apply compensation. The router coordinator binds staged secrets to its
token before runtime apply and owns their commit, rollback and timeout cleanup.
API handlers prepare credentials before registration and translate outcomes;
they do not run a second rollback or timeout worker. Rejection before registration
restores staged credentials without changing runtime consumers. Router apply
and repair register their journals and recovery guards in an owned task so a
cancelled storage await still leaves an inspectable recovery token.

The coordinator owns compensation for transactional router apply and repair;
the manager executes their stages without a separate inner rollback. Standalone
manager apply retains its own compensation. Coordinator transitions publish a
small status snapshot under a separate short-lived lock, so status and token
reads do not wait for apply, repair, or rollback I/O. Until application has a
known successful outcome, its published token remains rollback-only. Recovery
and commit-uncertainty diagnostics are overlaid when reading that snapshot.
Status API health probes have a one-second observation budget; a busy runtime
reports unknown readiness while the coordinator status remains available.
Explicit completion waits still join the operation owner before reporting idle.

Operator AP/client configuration, saved profile activation, and operator-triggered
AP/client deactivation use the same commit-confirm interface transactions as
provisioning. Internal autoconnect activation and timeout cleanup remain
immediate. DHCP route metric and default-route policy edits on enabled clients
use interface transactions; other DHCP and VPN controls plus Wi-Fi passphrase/reconnect/reload runtime
controls also remain immediate. Since runtime
effects can survive a daemon crash, subsystems establish durable ownership
proof before persistent runtime state is created: DHCP lease records include the applied route policy, Wi-Fi launches use
write-ahead process records, and WireGuard activation uses a durable intent plus
an interface launch marker. Startup recovery compares those proofs with
committed intent and only removes state whose ownership can still be verified.

The mutation gate separates serialized control admission from runtime execution.
Desired-state convergence holds a shared runtime reservation so an interface
transaction can wait for its worker. Compensation can join that reservation
even while an exclusive writer is queued. Per-interface transaction/runtime
locks and per-PHY radio locks serialize conflicting work; unrelated interfaces
converge concurrently and report completion independently. Intent changes
schedule new work while other lanes are still running. Queued jobs re-read
current intent after acquiring their lane, and in-flight kernel/process writes
are drained before global errors are returned. Autonomous background writers
(such as supervised-process liveness repair) take exclusive runtime execution so
they cannot replay stale state across a convergence pass. Accepted control
operations keep running if the HTTP client disconnects. The executor
limits queued work and waits for accepted operations during shutdown. If a
request times out, the client must check the current state before retrying: the
change may already have taken effect.

Async nftables operations reserve execution before entering the blocking pool
and transfer that reservation to the worker. Cancellation leaves the reservation
with queued or running work until it finishes; observation, rollback, and
removal-only cleanup wait for that outcome. The production executor shares the
reservation across router and VPN backends, including rebuilt VPN hop adapters.
Private state directory creation syncs the directory and its ancestors, including
on retries after a failed sync, before a caller can rely on durable records.

Immediate DHCP client configuration edits only DHCP policy on an already
managed input interface without a static address. Interface role, management
and static-address changes must pass through interface transactions first.
Runtime interface and router dataplane convergence retry unsuccessful passes
with exponential backoff from one to thirty seconds. Kernel notifications are
drained during that delay, so a failed repair cannot trigger itself repeatedly.
Changes to operator intent or recovery state wake the worker immediately;
successful passes return to waiting for events. An absent router interface is
checked before a repair journal is opened, leaving healthy LAN services intact.

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
`phase` (`awaiting_commit`, `rollback_required`, `recovery_required`,
`commit_indeterminate`) and
`last_error`. Confirmation is available only in `awaiting_commit`; rollback is
blocked in `commit_indeterminate`. In `recovery_required`, bounded automatic
recovery has stopped; inspect optional `recovery_progress` and explicitly retry
rollback. Device events do not resume a stopped cycle. Startup rechecks interface
journals in a fresh bounded cycle; router recovery requires explicit retry. See
[bounded automatic recovery](recovery.md#bounded-automatic-recovery).

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
