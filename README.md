# traffic-masq

Linux router and VPN gateway manager.

The project provides two binaries:

| Binary | Purpose |
| --- | --- |
| `traffic-masqd` | Privileged daemon that manages network state. |
| `traffic-masq` | Terminal client for daemon configuration and status. |

## Project status 

Not production ready. The project is under active development and may change without notice. Use at your own risk.

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

The installation script copies the binaries and project documentation. It does
not install a system service.

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

Configuration changes use a rollback timer. The default timeout is 60 seconds.
An uncommitted change is reverted when the timer expires.

Management interfaces are not modified unless
`allow_management_change` is enabled.

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
