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
- **It only touches what it was given.** Interfaces are managed one by one, and
  the daemon records every address it installs, both in the kernel and in a
  journal on disk. An address it did not install is never removed, and handing
  an interface back leaves nothing behind. Installing it does not mean handing
  over the machine.
- **It converges.** The running configuration is a goal, not a sequence of
  commands. If something else changes an interface, the change is noticed and
  undone; if an interface is unplugged and returns, it is configured again.
  Interface and router changes can be previewed before they are applied.

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
- No system service unit is installed; the daemon is started by hand.

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

The English-language wizard selects a local TUI user, dependency checks, initial
password, and optional immediate startup. It shows the complete plan before it
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
dependency installation and startup default to off. `--prefix` defaults to
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

No init system is required or configured. `--start` starts the daemon now and
waits for API readiness; boot autostart remains future work. The compatibility
`packaging/install.sh` delegates host installs to this command and retains
`DESTDIR`, `PREFIX`, and `BINARY_DIR` for side-effect-free package staging.

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

The TUI keeps operation messages visible; press F1 to read a full message and
use Up/Down to scroll it. Finish a form or leave it with Esc before changing
tabs. Long Wi-Fi lists scroll with the selection; deleting a profile requires
an explicit Y confirmation naming the profile.

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

Only interfaces marked as managed are configured. For those, every IPv4 address
the daemon installs is recorded twice — tagged in the kernel with `IFA_PROTO`,
and written to a journal on disk before the address is installed. Both are
checked at startup against what is actually on the links.

A managed interface ends up carrying exactly the address it is configured with,
so an address that was already on it is replaced. Once management is given up,
that authority ends: an address that neither the tag nor the journal accounts
for is never deleted, and marking an interface unmanaged removes what the
daemon installed and leaves the rest alone.

### Removing an address

Having no address is a configuration, not a missing one. Clearing the CIDR
field in the interface editor — with Backspace or the "Remove IPv4 address"
row — sends an empty `cidr`, and the daemon plans a delete for every IPv4
address the managed interface carries, whether it installed the address or
found it there. It goes through the same dry-run preview, rollback timer and
commit as any other change, and convergence holds it: an address that comes
back is taken off again on the next pass.

Two refusals are worth knowing about. An interface that is not managed is not
written to at all, so removing its address means enabling Managed first. And an
interface running a DHCP server cannot give up the address that server hands
out its subnet from — disable DHCP first.

Management interfaces are not modified unless `allow_management_change` is
enabled, and a change that would alter one is refused rather than attempted.

Test configuration changes on a separate Linux host before production use.

## Stop and uninstall

```sh
sudo traffic-masqd stop
sudo ./packaging/uninstall.sh
```
## AI Status

The project was rewritten from another programming language. AI was used to rewrite the code and tests.

## License

Personal noncommercial use is available under the
[Traffic Masq Community License 1.0](LICENSE).

Use by an organization, employer, client, sole proprietor, or contractor
requires a separate commercial license. Contact `prefl0p@proton.me`.
