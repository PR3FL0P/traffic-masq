# Operating guide

## Requirements

### Build

- Rust toolchain with Cargo
- a C compiler (`cc`, `gcc` or `clang`)
- `cmake`, on targets other than `x86_64-unknown-linux-gnu`

A C compiler is needed for two dependencies: the default `rustls` cryptography
backend uses C and assembly, and `sqlx` builds SQLite from source. On
`x86_64-unknown-linux-gnu` both invoke the compiler directly. Other targets use
CMake for the cryptography backend.

The supported build toolchain is Rust 1.95.0, pinned in `rust-toolchain.toml`.

### Runtime

- Linux
- root access for `traffic-masqd`
- kernel support for nftables and WireGuard
- `nft` in `PATH`, built with JSON support
- two or more network interfaces for router operation
- `hostapd` and `iw` for Wi-Fi access point mode
- `wpa_supplicant` for Wi-Fi client mode

The firewall is read back as JSON (`nft --json list ruleset`), so an nftables
built without libjansson fails at the first firewall change rather than at
startup.

`hostapd`, `iw` and `wpa_supplicant` are looked up at absolute paths, not through
`PATH`. The defaults are `/usr/sbin/hostapd`, `/usr/sbin/iw` and
`/usr/sbin/wpa_supplicant`; distributions that ship them elsewhere need
`wifi.hostapd_binary`, `wifi.iw_binary` and `wifi_client.wpa_supplicant_binary`
set in the configuration file. `iw` is used to validate AP channel/width against
the selected PHY and the kernel's effective regulatory restrictions before hostapd is changed.

WireGuard is configured over netlink, and both DHCP server and DHCP client are
part of the daemon, so `wireguard-tools`, `dhcpcd` and `dhclient` are not used.
The DHCP client requires root or `CAP_NET_RAW`.

## Build

```sh
cargo build --release --locked
```

The binaries are written to:

```text
target/release/traffic-masq
target/release/traffic-masqd
```

## Test

The default tests need no privileges and do not change the host network:

```sh
cargo test --locked
```

Run the eight network and VPN suites through the isolated runner:

```sh
sh packaging/test-namespaces.sh
# To run only the VPN suites:
sh packaging/test-namespaces.sh vpn_wireguard_namespace vpn_policy_namespace
```

You need Linux, iproute2, nftables, iputils-ping, wireguard-tools, `udhcpc`,
Python 3, util-linux and coreutils. Cargo builds as your user. Each suite then
runs in its own network, mount and PID namespaces, with private `/run`, `/proc`
and `/sys` mounts. A suite has ten minutes to finish; on exit, its remaining
processes are terminated.

The runner uses an unprivileged user namespace by default. If the host disables
user namespaces, use a disposable VM and run
`sh packaging/test-namespaces.sh --sudo`. This needs a valid sudo session or
passwordless sudo. Only test execution is elevated; Cargo still runs as your
user. Missing tools or kernel features fail the run instead of skipping tests.

VPN tests cover a real WireGuard handshake, tunnel traffic, policy changes,
blocked direct uplink traffic, tunnel teardown and reconnection. The runner
excludes Wi-Fi simulation and physical hardware tests.

Wi-Fi namespace tests also need `modprobe`, `modinfo` and `mac80211_hwsim`.
Physical tests use `TRAFFIC_MASQ_*` variables for interfaces, SSIDs and PSK files.
Some need Internet access, a second radio or someone to unplug a cable. Read
the selected test's setup and use a disposable host. Do not run all ignored
tests together on your workstation.

## Install

Build or unpack a release with both binaries in the same directory, then run:

```sh
sudo ./traffic-masqd install
```

The installer uses an English-language wizard. Its defaults grant TUI access
to the user who invoked sudo (or root alone if that user is unknown), select
routing dependencies, install missing packages, start the daemon and enable
boot autostart. Advanced settings and password setup are deferred. Review the
plan at the final prompt before applying it.

Set the password afterward with `sudo /usr/local/bin/traffic-masq`. Initial setup
requires a local root client; there is no default password. Select Wi-Fi or
WireGuard dependency presets if needed. Presets install prerequisites only;
network features remain disabled until you configure them.

For unattended installation, specify user access and password setup:

```sh
sudo ./traffic-masqd install --non-interactive --user alex \
  --dependency-presets router,wifi-ap --install-deps \
  --password-file /run/secrets/traffic-masq-password --start
```

Use `--skip-user-access` for root-only access, or `--defer-password` to set the
password later. The default dependency preset is `router`. Unattended installs
leave dependency installation and immediate startup off unless requested.

The default prefix is `/usr/local`; change it with `--prefix`. The daemon's
global `--config` option defaults to `/etc/traffic-masq/config.toml`.
Use `--dry-run` to inspect the plan without changing the machine.
Password files must be regular, non-symlink files with no group or other access;
their contents never appear in arguments, plans, logs, or errors.

The installer preserves existing configuration, credentials, profiles, state,
and ownership journals. It refuses replacement while the daemon is running and
refuses a conflicting configured socket group. A newly created configuration
manages no interfaces. Adding a user to `traffic-masq` requires signing out and
back in before that session can access the socket.

The installer supports apt, dnf and pacman. With other package managers it lists
what to install manually. On apt systems, install missing Wi-Fi packages yourself:
their package hooks may start services that compete with traffic-masq.

DHCP is built in and WireGuard uses netlink, so the installer adds neither DHCP
clients nor `wireguard-tools`. Kernel feature checks are advisory: a feature
may be available even if its module is not loaded yet.

`--init-system auto` (the default in both modes) detects the running init system
and registers boot autostart independently of `--start`. In a container or on an
unrecognized init system, auto leaves startup manual and says so in the plan.
Use `--init-system systemd|openrc|runit|sysv` to select one explicitly, or
`--init-system none` to omit integration (and remove a previous installer-owned
registration). `--start` starts through the selected manager and waits for API
readiness. Runit enables and starts simultaneously, so its registration requires
`--start`; `--runit-service-dir PATH` selects an existing scan directory if needed.

The compatibility `packaging/install.sh` forwards command-line flags to the daemon
for host installation. `DESTDIR`, `PREFIX`, and `BINARY_DIR` still provide
side-effect-free binary package staging: staging never discovers, enables, or
starts host services. See [init integration](../packaging/INIT.md) for lifecycle,
file ownership, recovery, and native commands.

The manual compile workflow builds an archive containing both binaries. Use the
local release script to produce a versioned archive and SHA-256 checksum. See
[release procedure](release.md). Target machines do not need Rust
or a C compiler.

## Reset all settings

To return traffic-masq to a clean, safe configuration while keeping the installation itself:

```sh
sudo traffic-masqd reset --dry-run
sudo traffic-masqd reset
```

The reset command requires a healthy running daemon for the normal path. It requests restoration of traffic-masq-owned network state, stops the daemon, and requires a matching shutdown acknowledgement before deleting recovery/ownership journals. It then clears traffic-masq persistent state (runtime overrides, credentials and sessions, DHCP lease state, Wi-Fi state/profiles, VPN profiles and ownership journals) and replaces the selected configuration with safe defaults. Installation/runtime paths and the socket access group are preserved so the installed service remains usable. Logs, binaries and init-service registration are preserved, and the daemon is left stopped. Start it explicitly when ready:

```sh
sudo traffic-masqd start
```

Use `--yes` for non-interactive reset. Destructive state directories are checked before deletion; shallow paths and symlinked paths are refused. A stopped or unhealthy daemon is refused by default because the command cannot prove that owned kernel state was restored. After a reboot (or when live traffic-masq-owned kernel state is otherwise known to be clean), `--force-offline` explicitly permits reset while the daemon is stopped.

## Configuration

Create the default configuration file:

```sh
sudo traffic-masqd config init
```

Default path:

```text
/etc/traffic-masq/config.toml
```

Validate the configuration:

```sh
sudo traffic-masqd config validate
```

Print the selected configuration:

```sh
sudo traffic-masqd config show
```

Configuration lookup order:

1. `--config <path>`
2. `TRAFFIC_MASQ_CONFIG`
3. `/etc/traffic-masq/config.toml`
4. built-in defaults

An explicitly selected file (`--config` or `TRAFFIC_MASQ_CONFIG`) must exist
and be readable; errors do not fall back to another source. The built-in
defaults do not manage network interfaces.

`config show` prints the selected file configuration (with defaults filled in),
not the runtime overrides saved by the TUI or API. Inspect the effective
interface/router settings through the TUI or API. `config validate` validates
the file configuration; it does not test live connectivity.

A complete configuration template is available at
[`examples/config.toml`](../examples/config.toml). Replace all interface names and
addresses before use.

The daemon also exposes a versioned JSON API on its Unix socket and, when
explicitly enabled, over HTTPS. See the [HTTP API reference](api.md) for
authentication, every route, request schemas, and transaction handling.

## Start

Start the daemon in the background:

```sh
sudo traffic-masqd start
```

Check its state:

```sh
sudo traffic-masqd status
```

Open the terminal client for initial password setup:

```sh
sudo traffic-masq
```

Later sessions may run without root if the user can access the daemon socket:

```sh
traffic-masq
```

## Terminal client

### Login and sessions

The client asks for the device password inside the TUI. By default, it remembers
its session for **5 minutes from password entry**, including across client restarts.
In **Settings**, toggle **Remember session**, edit **Remember for (minutes)**
(1–1440), then choose **Save session preferences (applies now)**. Disabling this
removes the saved token and requires a password on the next launch. These are
per-user, per-daemon-socket preferences and do not require a daemon restart.

Only a session token is saved, never the password. Files are private (`0600`) in
`$XDG_STATE_HOME/traffic-masq/client` (normally `~/.local/state/traffic-masq/client`),
inside a `0700` directory. Reopening the client does not extend the chosen duration.
The daemon still validates the session: password changes, revocation, and its
configured idle/absolute limits can require a password sooner.

### Navigation

The TUI keeps operation messages visible; press F1 to read a full message and
use Up/Down to scroll it. Tab/Shift+Tab moves focus forward/backward;
F2/F3 selects the previous/next main tab. Ctrl+C exits after any in-flight
action completes. Finish a form or leave it with Esc before changing
tabs. Long Wi-Fi lists scroll with the selection; deleting a profile requires
an explicit Y confirmation naming the profile.

### Routes and Internet sharing

In **Router**, Tab/Shift+Tab switches between routes and **Actions**. Up/Down
or Left/Right selects an action, and Enter or Space activates it. Esc returns
to the route list. Scrolling the route list keeps focus in the list.
Buttons wrap to fit the terminal. For a route outside the static route editor,
**Delete manually** (or Del on the selected route) displays an `ip -4 route del`
command to run on the daemon's machine. The TUI never executes that command or
changes the proposed configuration for that route. After running it, choose
**Refresh**. DHCP or another network manager may recreate the route; a lasting
change belongs in the configuration that creates it. Deleting a traffic-masq
static route continues to stage the change for **Plan / Apply**.

The **Router** tab has three sections, selected with **1 / 2 / 3** or by clicking
its section labels:

- **Routes** edits destinations, gateways, interfaces, tables and metrics.
- **Internet sharing** lists independent connections in **From / Through / NAT /
  Source subnet** columns. Select a row and **Edit**, or choose **Add** or **Delete**.
  Up/Down selects rows; Tab switches to actions; Left/Right selects an action.
- **Topology** shows configured connections and observed default routes. This is
  a configuration overview, not a verified packet path.

In the sharing editor, choose **Traffic from**, **Internet through** and
**Masquerade**. **Advanced** reveals the optional IPv4 **Source subnet**; leaving
it empty means any source. A scope such as `192.168.10.0/24` restricts both
forwarding and NAT. Enter on **Save connection** stages the change. Editing an
existing connection replaces that row, including when its interfaces change.
Esc cancels the current editor without discarding earlier staged changes.

From a selected route, press **n** or **Share via: n** to start a new sharing
connection with the route's output interface filled in. The resulting rule is
independent of the route: changing or deleting that route does not rewrite the
sharing rule.

Routes and sharing use the same draft. **Review / Apply** (or **Plan / Apply**
in Routes) previews all pending edits before applying them with a confirmation
timer. Refresh keeps your draft.

Connections refer to existing interfaces, including externally managed Ethernet
and VPN interfaces. Both must be up when applying. Creating a connection does
not take ownership of interface addresses, set up Wi-Fi, or configure DHCP.
Each source may have several allowed destinations. Return traffic for established
connections is allowed; other IPv4 forwarding to/from configured source
interfaces is blocked. Other interfaces and foreign firewall tables remain
outside these rules.

The equivalent configuration is:

```toml
[router]
enabled = true
forwarding = [
  { from = "lan0", to = "wan0", masquerade = true },
  { from = "lan1", to = "wg0", masquerade = true, source_subnet = "192.168.10.0/24" },
]
```

Routes determine which allowed destination a packet actually uses. Masquerading
rewrites the source address on egress; it does not select routes or nest VPN
encapsulation ([nftables NAT documentation](https://wiki.iptables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_%28NAT%29)).
An `Ethernet → VPN → VPN → Internet` path also needs the tunnels and their
endpoint/policy routes configured. This editor manages forwarding/NAT between
existing interfaces; it is not yet a VPN-chain routing editor. Explicit
`forwarding` and the legacy global `vpn_chain`/VPN policy cannot be combined.
Use direct global VPN policy with explicit connections and separately configured
tunnel routing. Existing legacy VPN-chain configurations continue to work.

Old configurations without `forwarding` retain their `uplink` and per-interface
`nat` behavior. Opening the editor imports those existing NAT pairs for review.
Once `forwarding` is present it is authoritative: `forwarding = []` removes all
owned connection rules and never resurrects the old implicit NAT rules.
The legacy `uplink` may remain to preserve its Wi-Fi/DHCP client services.

### Settings and running operations

Changes in **Settings** also require confirmation. The first Enter shows an
indented `Note: Confirm...` line; the second Enter applies the selected change.
Esc or moving to another setting cancels the confirmation. Explanatory text is
shown as an indented `Note:` directly after the setting it describes.

During an API refresh, input takes priority. While an action is in progress,
the TUI shows its elapsed time and rejects additional actions; Q requests exit
after the result. A timeout does not prove that a change failed: inspect the
current state before retrying. An expired session offers login again without
discarding drafts or extending rollback deadlines. Terminals smaller than 80×24
disable normal editing and mouse controls; Q still exits. An active confirmation
deadline remains visible, with Enter to commit and Esc to roll back. Recovery
states show their available recovery actions instead.

### Wi-Fi client connections

Tab switches between wireless interfaces and their actions; Esc returns to the
same interface. Lists and connection forms scroll to keep the selection visible.
In the connection form, arrows move focus and Enter/Space selects an IP option.
Use **Connect** or F10 to submit. This provisions the profile, credentials and
IPv4 policy together as a tentative change. Verify connectivity, then commit
before the deadline. On failure, inspect the reported pending/recovery state
before retrying. **Keep current static IP** uses the configured address, never a
currently observed DHCP lease.

Client **Connect** sends the profile and IPv4 policy to
`PUT /api/v1/wifi-client/{interface}/provision`. The backend stages the interface,
credential, Wi-Fi and DHCP state together and returns `NetworkChangePending`.
Confirm the candidate only after checking connectivity. Failure or rollback
restores the preceding configuration and credential. DHCP mode reuses existing
route/DNS policy; switching to static disables DHCP without discarding it.

The `active-profile` activation and deactivation endpoints are also tentative:
they return `NetworkChangePending` and must be committed after connectivity is
verified. Internal autoconnect uses a separate immediate activation path; the
provisioning endpoint remains the preferred interactive flow when IPv4 policy
must change together with the profile.

### Wi-Fi access points

The Wi-Fi screen includes unconfigured radios. **Create hotspot** accepts an IPv4
subnet and prepares a managed output interface in one backend transaction. DHCP
policy explicitly selects preserve, enable/configure, or disable. **Apply** is
tentative: verify connectivity and commit before the rollback timer expires.
**Saved AP profiles** uses the same navigation as client profiles: choose
**Management** to select an existing profile, or **Create new profile**. Each
profile offers **Apply profile**, **Edit profile**, and **Delete profile**.
Saving returns to the profile list without changing the running access point;
applying starts a tentative network change that must be confirmed. Deletion
requires confirmation and leaves the running AP unchanged. When editing, a blank
passphrase retains that profile's saved password. Existing profile IDs are fixed.

Scanning is unavailable on interfaces configured as access points, including
when hostapd is stopped or has failed to start. Deactivating either an access
point or an active Wi-Fi client from the TUI is tentative as well: the pending
screen must be committed to keep the deactivation, otherwise rollback restores
the previous interface state (and the AP credential when applicable).

If hostapd repeatedly reports `ACS: Unable to collect survey data`, automatic
channel selection (`channel = 0`) cannot obtain the measurements it needs from
the radio/driver. Edit the AP profile to use a fixed channel permitted by the
radio and country, then apply and confirm the change. Saving a profile alone
does not update the running AP. Repeated unsuccessful AP starts use exponential
restart backoff (up to five minutes); answering control-socket PING does not
reset that backoff until hostapd reports `ENABLED`.

## Daemon commands

```text
traffic-masqd [--config <path>] <command>
```

| Command | Function |
| --- | --- |
| `install` | Install both binaries and configure service integration; see [installation](#install). |
| `uninstall` | Remove installed binaries and service files, preserving configuration and state. |
| `reset [--dry-run] [--yes] [--force-offline]` | Clear configuration and persistent state; see [reset requirements](#reset-all-settings). |
| `run` | Run in the foreground (also the default when no command is supplied). |
| `start [--timeout-seconds N]` | Start in the background. |
| `stop [--timeout-seconds N]` | Stop the daemon. |
| `status` | Print process and API state. |
| `logs [-n N] [--follow]` | Read the daemon log. |
| `auth set-password` | Reset the password while the daemon is stopped. |
| `config path` | Print the selected configuration path. |
| `config show` | Print the selected configuration. |
| `config validate` | Validate the selected configuration. |
| `config init [--path PATH] [--force]` | Create a configuration file. |

## Client commands

```text
traffic-masq [--socket <path>] [--direct | --change-password | --check-conflicts]
```

| Option | Function |
| --- | --- |
| `--direct` | Read interface state without the daemon. |
| `--change-password` | Change the password through a running daemon. |
| `--check-conflicts` | Report detected competing network managers and resolution advice. |

Direct mode is read-only. DHCP, router, VPN, and settings operations are not
available in this mode.

## Runtime paths

Default paths are:

| Data | Path |
| --- | --- |
| State | `/var/lib/traffic-masq` |
| Logs | `/var/log/traffic-masq` |
| Socket | `/run/traffic-masq/traffic-masqd.sock` |
| PID file | `/run/traffic-masq/traffic-masqd.pid` |
| Authentication database | `/var/lib/traffic-masq/auth.sqlite3` |

## Network changes

The daemon can manage:

- interface addresses
- DHCP server and client state
- IPv4 forwarding
- nftables firewall and NAT rules
- Wi-Fi access point and client processes
- WireGuard interfaces
- policy routes and VPN kill switch rules

### Transactional and immediate changes

Interface and router changes use **Apply → Commit** transactions. Apply brings
the machine to the requested state and starts a timer, 60 seconds by default.
Committing within that window keeps the change. Expiry schedules rollback to the
previous committed configuration; rollback waits for already admitted operations
and may need retries. An already admitted confirmation can finish after the
displayed expiry. Inspect pending state to learn the outcome.

Standalone DHCP and VPN controls plus Wi-Fi runtime controls such as
reconnect/reload/passphrase updates take effect immediately and do not have an
interface/router confirmation timer. Operator-triggered Wi-Fi configuration,
profile activation, and AP/client deactivation instead use the same tentative
commit-confirm flow as other connectivity-sensitive interface changes. The
immediate subsystems write durable ownership or launch records before persistent
runtime state is created, then reconcile those records against committed
configuration on startup. This lets recovery remove only traffic-masq-owned
crash residue without treating foreign processes, leases or interfaces as its
own.

If an interface/router change cuts off your connection, the daemon rolls it
back locally after the timer expires and admitted operations finish. If commit
persistence and its compensation both fail, rollback is blocked until storage is
repaired and the daemon is restarted; see [TM-REC-209](recovery.md#tm-rec-209).
The daemon must still be running for the
timer to fire; after a crash, recovery runs on restart. Immediate DHCP/VPN and
Wi-Fi runtime-control operations also run their ownership recovery during startup. See
[recovery](../SECURITY.md#rollback-and-recovery) and the
[operator recovery runbook](recovery.md).

### What the daemon considers its own

Only interfaces with **Configure with traffic-masq** enabled receive interface
configuration. Every IPv4 address the daemon installs is recorded twice —
tagged in the kernel with `IFA_PROTO` where supported, and written to a journal
on disk before installation. Routes, nftables objects and supervised services
have equivalent ownership records or identifiers.

Changing the desired address removes only an old address recorded as owned by
traffic-masq. A pre-existing or externally created address is preserved, even
on an interface configured by traffic-masq. If an external address already
matches the requested address, it remains externally owned. Turning
**Configure with traffic-masq** off removes owned settings and leaves all
foreign settings intact.

### Removing an address

Having no owned static address is a valid configuration. Clearing the CIDR
field in the interface editor — with Backspace or the "Remove IPv4 address"
row — asks the daemon to remove its own static IPv4 address. The preview lists
the exact address to be removed. External and DHCP-owned addresses are not
included. The change uses the same rollback timer and commit flow as any other
interface change.

To remove an owned address, first enable **Configure with traffic-masq**;
IPv4 editing is disabled while it is off. An interface running a DHCP server cannot give up the address whose
subnet it serves; disable DHCP first.

Interfaces with role `none` (outside the router) are not modified until the
connectivity risk is explicitly confirmed. Interface router roles are `none`,
`input`, and `output`; VPN hop interfaces use the reserved `middle` role. `none`
does not disable the link or prevent access to the machine. The legacy
`management` spelling is accepted as `none`, with its confirmation protection
preserved. Legacy `disabled` configurations remain readable but are no longer
offered in the role selector.

In the interface editor, **Configure with traffic-masq** controls configuration
ownership independently of the router role. Address editing is unavailable
when it is off. **Plan / Apply** opens a read-only preview using the same flow
as the router preview: review the complete plan, then press **Enter** on
**Apply** to start the rollback timer, or **Esc** to cancel.
The API retains `managed` and `allow_management_change` for compatibility.

Test configuration changes on a separate Linux host before production use.

### Dashboard and convergence diagnostics

The dashboard's **Interfaces stat** panel shows link activity and
`traffic-masq:on/off/?` (managed, unmanaged, or ownership unavailable).
Press **2** for aggregate statistics, then **Down/Up** to browse individual
interfaces; **Home** returns to the aggregate view. The **DHCP Client** section
shows configured uplink DHCP clients; DHCP status is not part of the Dashboard.
The overview reports whether the VPN subsystem is enabled; this switch alone does not prove a tunnel is connected.

An absent router dataplane interface defers startup convergence after successful
rollback instead of stopping the daemon. The daemon retries when the interface
appears. Check `ip link`, reconnect the adapter, or correct its name in the router
configuration. Logs identify the missing interface and its role and include the
underlying error. A router rollback that has already reached `RollbackFailed`
can also leave the control plane available in degraded mode so the failure can
be inspected and rollback retried. By contrast, startup remains blocked when
persisted recovery evidence cannot be read or safely interpreted, such as an
inaccessible recovery store, an unproven corrupt/unsupported router journal, or
a revision contradiction. Startup diagnostics include a stable `TM-REC-xxx`
recovery code that maps directly to the matching section of the
[operator recovery runbook](recovery.md). TUI session logs wrap long diagnostics
and hints; use **Up/Down**, **PageUp/PageDown**, or **Home/End** to read them.

### DHCP editor defaults

When creating DHCP settings, the TUI reads the effective saved interface IPv4
configuration from the daemon. The router field uses that address, and the pool
uses the largest contiguous usable range on one side of it. Network, broadcast,
and router addresses are excluded; /31 and /32 have no suggested pool. Existing
DHCP settings are preserved when reopening the editor. Enter advances through
fields to Save. Saving still validates against the current interface subnet and
requires a managed output interface.

Check that the suggested pool does not overlap static addresses used by other
devices on your LAN. Adjust it before saving.

### Router transaction identity

The router apply response returns a transaction `token`. Both
`POST /api/v1/router/commit` and `POST /api/v1/router/rollback` require the JSON
body `{"token":"<token returned by apply>"}`. A stale token cannot confirm or
roll back another transaction. `GET /api/v1/router/pending` includes the current
token for inspecting recovery state. Update the client and daemon together;
requests without a token are rejected.


## Stop and uninstall

```sh
sudo traffic-masqd uninstall --dry-run
sudo traffic-masqd uninstall
```
Uninstall stops the daemon gracefully before removing both binaries and packaged
documentation. Configuration, passwords, state, logs, the access group and
dependency packages are preserved. Use `--yes` for unattended removal and
`--prefix /custom/path` if installed under a custom prefix. For a custom
configuration, pass `--config /path/to/config.toml` so the correct daemon is
stopped.
