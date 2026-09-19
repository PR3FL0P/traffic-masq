# Architecture

`traffic-masqd` runs network operations. The terminal client, `traffic-masq`,
talks to it through the local HTTP API. In direct mode, the client reads
interface state itself and cannot make changes.

| Module | Responsibility |
| --- | --- |
| `api` | HTTP, authorization and control-operation limits |
| `core` | Configuration, ownership, plans, transactions and reconciliation |
| `netlink`, `firewall` | Kernel interfaces, routes and nftables |
| `dhcp`, `wifi`, `vpn` | DHCP and VPN runtimes; Wi-Fi service supervision |
| `state`, `atomic_file` | Persistent state and atomic file writes |
| `app` | Startup, shutdown, installation and init integration |
| `tui` | Input, screen state and rendering |

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

Standalone DHCP, Wi-Fi and VPN operations are immediate rather than
commit-confirm transactions. Because some of their effects survive a daemon
crash, they establish durable ownership proof before persistent runtime state is
created: DHCP lease records include the applied route policy, Wi-Fi launches use
write-ahead process records, and WireGuard activation uses a durable intent plus
an interface launch marker. Startup recovery compares those proofs with
committed intent and only removes state whose ownership can still be verified.

The global mutation gate serializes admitted network mutations with transaction
execution, while background convergence uses the compatible read side. Accepted
control operations keep running if the HTTP client disconnects. The executor
limits queued work and waits for accepted operations during shutdown. If a
request times out, the client must check the current state before retrying: the
change may already have taken effect.

## Terminal client

Editors keep drafts until the user applies or discards them. Refreshes preserve
drafts and selection. Input and rendering must remain responsive during API
requests. Never retry a mutation automatically after a timeout, or include
passwords and session tokens in debug logs or operation messages.

Network decisions belong in `core` or the service module responsible for them.
HTTP handlers and TUI widgets translate input and show results; they do not
change kernel state directly.
