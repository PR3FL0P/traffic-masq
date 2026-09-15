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

Before applying a router transaction, the daemon saves a snapshot. It keeps that
snapshot until the user commits the change or rollback succeeds. A commit saves
the requested configuration; reconciliation then corrects differences between
that configuration and the running system.

Accepted control operations keep running if the HTTP client disconnects. The
executor limits queued work and waits for accepted operations during shutdown.
If a request times out, the client must check the current state before retrying:
the change may already have taken effect.

## Terminal client

Editors keep drafts until the user applies or discards them. Refreshes preserve
drafts and selection. Input and rendering must remain responsive during API
requests. Never retry a mutation automatically after a timeout, or include
passwords and session tokens in debug logs or operation messages.

Network decisions belong in `core` or the service module responsible for them.
HTTP handlers and TUI widgets translate input and show results; they do not
change kernel state directly.
