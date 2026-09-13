# traffic-masq

Change the network on a Linux box you cannot afford to lose access to.

traffic-masq turns a Linux machine into a router, Wi-Fi access point and VPN
gateway. So do several mature projects. The difference is in how changes are
made and what happens when one of them is wrong:

- **A change reverts itself unless you confirm it.** Applying a new address
  starts a timer. Confirm within the timeout and the change is kept; say
  nothing — because you just locked yourself out — and the machine returns to
  the configuration it had. The same idea as `commit confirmed` on a Juniper,
  on an ordinary Linux host.
- **It changes only resources it created.** The daemon records every address,
  route, firewall object and supervised process it creates. Existing addresses,
  routes, firewall tables and processes remain under their current owner's
  control. Handing an interface back removes traffic-masq state and leaves
  foreign state intact.
- **It converges.** The running configuration is a goal, not a sequence of
  commands. Drift in traffic-masq-owned state is repaired; foreign state is
  ignored. If an interface is unplugged and returns, its owned configuration is
  restored. Interface and router changes can be previewed before they are
  applied.

It installs onto a machine that already has a working network, and leaves that
network alone until it is told which interfaces to manage. Nothing is
reflashed, and no operating system is replaced.

The project provides two binaries:

| Binary | Purpose |
| --- | --- |
| `traffic-masqd` | Privileged daemon that manages network state. |
| `traffic-masq` | Terminal client for daemon configuration and status. |

## Project status

Not production ready. The project is under active development and may change
without notice. Use at your own risk.

Known limits, so they are not discovered later:

- IPv4 only. IPv6 addresses and routes are not managed; the WireGuard
  configuration is the one place IPv6 appears.
- One machine. There is no fleet or central management.
- Boot service integration supports systemd, OpenRC, runit and SysVinit;
  other init systems use manual startup.

## Requirements

### Build

- Rust toolchain with Cargo
- a C compiler (`cc`, `gcc` or `clang`)
- `cmake`, on targets other than `x86_64-unknown-linux-gnu`

Two dependencies compile C rather than linking against a system library, so a
Rust toolchain alone is not enough: `rustls` builds its default cryptography
backend from C and assembly, and `sqlx` builds SQLite from source. On
`x86_64-unknown-linux-gnu` both use the compiler directly; elsewhere the
cryptography backend falls back to a CMake build.

No minimum Rust version is declared. The project is built with a current stable
toolchain.

### Runtime

- Linux
- root access for `traffic-masqd`
- kernel support for nftables and WireGuard
- `nft` in `PATH`, built with JSON support
- two or more network interfaces for router operation
- `hostapd` for Wi-Fi access point mode
- `wpa_supplicant` for Wi-Fi client mode

The firewall is read back as JSON (`nft --json list ruleset`), so an nftables
built without libjansson fails at the first firewall change rather than at
startup.

`hostapd` and `wpa_supplicant` are looked up at absolute paths, not through
`PATH`. The defaults are `/usr/sbin/hostapd` and `/usr/sbin/wpa_supplicant`;
distributions that ship them elsewhere need `wifi.hostapd_binary` and
`wifi_client.wpa_supplicant_binary` set in the configuration file.

WireGuard is configured over netlink, and both DHCP server and DHCP client are
part of the daemon, so `wireguard-tools`, `dhcpcd` and `dhclient` are not used.
The DHCP client requires root or `CAP_NET_RAW`.

## Build

```sh
cargo build --release
```

The binaries are written to:

```text
target/release/traffic-masq
target/release/traffic-masqd
```

## Test

The default suite changes no system state and needs no privileges:

```sh
cargo test
```

The tests that do change system state are marked `#[ignore]`, so the command
above skips them. They come in two kinds.

The namespace tests configure real interfaces inside network namespaces they
create themselves. They require root, `ip` from iproute2, `nft`, and — for the
Wi-Fi ones — `modprobe`, `modinfo` and the `mac80211_hwsim` kernel module:

```sh
sudo -E cargo test --test router_namespace -- --ignored
```

The `*_physical` tests drive real Wi-Fi hardware and are configured through
`TRAFFIC_MASQ_*` environment variables — interface names, SSIDs and PSK files.
Some also need Internet access, a second radio, or an operator to unplug a
cable, and refuse to run until the matching variable is set explicitly.

Run either kind on a host you can afford to disturb.

## Install

Build or unpack a release with both binaries in the same directory, then run:

```sh
sudo ./traffic-masqd install
```

The English-language wizard can be completed by pressing Enter at each prompt:
use the invoking sudo user for TUI access (root-only access when none is known),
select routing dependencies, install missing packages, start the daemon, enable
boot autostart using the detected init system, skip advanced settings, defer
password setup, and apply the displayed plan.
Initialize the password afterward using `sudo /usr/local/bin/traffic-masq`;
initialization requires a local root client and has no default password.
Wi-Fi and WireGuard dependency presets remain opt-in. It shows the complete plan before it
changes the machine. Dependency presets only check/install prerequisites; they
never activate routing, Wi-Fi, VPN, DHCP, or interface management.

For unattended installation, every ambiguous security choice is explicit:

```sh
sudo ./traffic-masqd install --non-interactive --user alex \
  --dependency-presets router,wifi-ap --install-deps \
  --password-file /run/secrets/traffic-masq-password --start
```

Use `--skip-user-access` instead of `--user`, and `--defer-password` instead of
`--password-file`, when intentional. Omitted presets default to `router`;
in non-interactive mode, dependency installation and startup default to off. `--prefix` defaults to
`/usr/local`, while `--config` defaults to `/etc/traffic-masq/config.toml` and
remains the daemon's global option. `--dry-run` prints the same preflight plan
without modifying files, accounts, packages, or processes.
Password files must be regular, non-symlink files with no group or other access;
their contents never appear in arguments, plans, logs, or errors.

The installer preserves existing configuration, credentials, profiles, state,
and ownership journals. It refuses replacement while the daemon is running and
refuses a conflicting configured socket group. A newly created configuration
manages no interfaces. Adding a user to `traffic-masq` requires signing out and
back in before that session can access the socket.

Automatic package commands are currently supported for apt, dnf, and pacman.
On apt systems, missing Wi-Fi packages must be installed manually because their
package hooks may start competing services. Unknown package managers receive a
manual-install diagnostic. DHCP is built in, WireGuard uses netlink, and neither
DHCP clients nor `wireguard-tools` are installed. Kernel support checks are
diagnostic because an unloaded module makes absence inconclusive.

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
starts host services. See [init integration](packaging/INIT.md) for lifecycle,
file ownership, recovery, and native commands.

The repository currently has no release-archive automation. Release publishing
must still package the two ready-built binaries together; target machines do
not need Rust or a C compiler.

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

The built-in defaults do not manage network interfaces.

A complete configuration template is available at
[`examples/config.toml`](examples/config.toml). Replace all interface names and
addresses before use.

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

The TUI keeps operation messages visible; press F1 to read a full message and
use Up/Down to scroll it. Finish a form or leave it with Esc before changing
tabs. Long Wi-Fi lists scroll with the selection; deleting a profile requires
an explicit Y confirmation naming the profile.

In **Router**, Down after the last route moves into **Actions**; Up/Down or
Left/Right selects an action, and Enter or Space activates it. Up from the first
action returns to the route list. Tab switches between routes and actions.
Buttons wrap to fit the terminal. For a route outside the static route editor,
**Delete manually** (or Del on the selected route) displays an `ip -4 route del`
command to run on the daemon's machine. The TUI never executes that command or
changes the proposed configuration for that route. After running it, choose
**Refresh**. DHCP or another network manager may recreate the route; a lasting
change belongs in the configuration that creates it. Deleting a traffic-masq
static route continues to stage the change for **Plan / Apply**.

Changes in **Settings** also require confirmation. The first Enter shows an
indented `Note: Confirm...` line; the second Enter applies the selected change.
Esc or moving to another setting cancels the confirmation. Explanatory text is
shown as an indented `Note:` directly after the setting it describes.

During an API refresh, input takes priority. While an action is in progress,
the TUI shows its elapsed time and rejects additional actions; Q requests exit
after the result. A timeout does not prove that a change failed: inspect the
current state before retrying. An expired session offers login again without
discarding drafts or extending rollback deadlines. Windows smaller than 60×15
disable hidden controls; Q still exits.

Editing an existing AP preserves unedited radio settings and DHCP. Creating a
new AP only derives DHCP when none is configured. AP Apply uses the existing
immediate API; it does not offer the interface/router commit-confirm timer.

## Daemon commands

```text
traffic-masqd [--config <path>] <command>
```

| Command | Function |
| --- | --- |
| `run` | Run in the foreground. |
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
traffic-masq [--socket <path>] [--direct | --change-password]
```

| Option | Function |
| --- | --- |
| `--direct` | Read interface state without the daemon. |
| `--change-password` | Change the password through a running daemon. |

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

### Confirming a change

Applying a change does not make it permanent. The daemon brings the machine to
the requested state and starts a timer, 60 seconds by default. Committing
within that window keeps the change; letting the timer expire returns the
machine to the configuration that was there before.

This is written for the case where the change is the reason you can no longer
reach the machine. Nothing has to be undone by hand, and nothing has to be
reachable for the revert to happen: it runs on the machine itself.

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

Two refusals are worth knowing about. With **Configure with traffic-masq** off,
IPv4 editing is disabled, so removing an owned address requires enabling it
first. An interface running a DHCP server cannot give up the address whose
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
when it is off. Review changes opens a read-only preview; selecting Apply
confirms the displayed connectivity risks and starts the rollback timer.
The API retains `managed` and `allow_management_change` for compatibility.

Test configuration changes on a separate Linux host before production use.

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

## License

Personal noncommercial use is available under the
[Traffic Masq Community License 1.0](LICENSE).

Use by an organization, employer, client, sole proprietor, or contractor
requires a separate commercial license. Contact `prefl0p@proton.me`.

### DHCP editor defaults

When creating DHCP settings, the TUI reads the effective saved interface IPv4
configuration from the daemon. The router field uses that address, and the pool
uses the largest contiguous usable range on one side of it. Network, broadcast,
and router addresses are excluded; /31 and /32 have no suggested pool. Existing
DHCP settings are preserved when reopening the editor. Enter advances through
fields to Save. Saving still validates against the current interface subnet and
requires a managed output interface.

A suggested range does not establish that other devices have no static addresses
in it: narrow the range to your LAN allocation plan before saving.
