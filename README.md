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

- Linux
- Rust toolchain with Cargo
- root access for `traffic-masqd`
- kernel support for nftables and WireGuard
- `nft` in `PATH`
- two or more network interfaces for router operation
- `hostapd` for Wi-Fi access point mode
- `wpa_supplicant` for Wi-Fi client mode

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

## Install

```sh
sudo ./packaging/install.sh
```

The installer creates the `traffic-masq` access group, adds the user invoking
`sudo`, creates `/etc/traffic-masq/config.toml` when absent, and configures the
daemon socket for that group. Sign out and back in once after the first install
so the new group membership takes effect.

The installation script installs the binaries and documentation and prepares
local group access to the daemon socket. It does not install a system service
or start the daemon automatically.

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

An address that neither the tag nor the journal accounts for is never deleted,
so an address put there by anything else survives. Marking an interface
unmanaged removes what the daemon installed and leaves the rest alone.

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
