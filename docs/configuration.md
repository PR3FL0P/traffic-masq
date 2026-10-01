# Configuration reference

The TOML model is defined in [`src/config/mod.rs`](../src/config/mod.rs).
Configuration selection and validation commands are described in the
[operating guide](usage.md#configuration). [`examples/config.toml`](../examples/config.toml)
is a sharing example, not the built-in safe configuration: it manages `wlan0`
and enables routing. `traffic-masqd config init` creates safe defaults with no
managed interfaces instead.

## File configuration and saved changes

The daemon merges the selected file with persisted overrides in
`<runtime.state_dir>/runtime-overrides.json`. Committed TUI/API edits can therefore
supersede a later file edit. `config show` fills in file defaults but does not
show these overrides. Use the interface/router configuration API or the TUI to
inspect effective settings. API HTTPS and security settings expose active and
desired values; HTTPS changes need a restart.

File edits require a daemon restart. Validate first and keep the same `--config`
path when stopping and starting. Validation checks configuration invariants;
it does not test tool availability, certificate contents, radio capabilities
or connectivity. Startup performs recovery before full normal admission so
unrelated invalid API/auth settings cannot prevent restoration of network state.
Do not edit override or recovery JSON manually; use the API/TUI, or follow the
[recovery runbook](recovery.md) if normal operations are blocked.

A file needs `[runtime]`, `[network]`, `[dhcp]`, `[vpn]` and `[security]` with their
required fields. `[router]`, `[wifi]`, `[wifi_client]`, `[api]` and `[auth]` can be
omitted. Optional values below may be omitted; TOML has no `null` value.

## Runtime and storage

| `[runtime]` field | Built-in value | Meaning |
| --- | --- | --- |
| `state_dir` | `/var/lib/traffic-masq` | Overrides, ownership and recovery journals, Wi-Fi stores |
| `log_dir` | `/var/log/traffic-masq` | Daemon logs |
| `socket_path` | `/run/traffic-masq/traffic-masqd.sock` | Unix HTTP API |
| `pid_path` | `/run/traffic-masq/traffic-masqd.pid` | Daemon PID; process lock uses the additional `.lock` suffix |
| `socket_group` | omitted | Optional group for local socket access |
| `shutdown_policy` | `preserve_interfaces` | Preserve committed interface runtime state on shutdown, or `restore_interfaces` to restore owned changes |

The first four fields are required in a file. Pending transactions still require
cleanup on shutdown; the preserve policy does not commit an unconfirmed change.
Socket and PID/lock paths must differ. Group access needs a dedicated runtime
directory; see [service integration](../packaging/INIT.md).

Other stores have independent configured paths; changing `state_dir` alone does
not relocate them:

| Section / field | Built-in value |
| --- | --- |
| `[dhcp] leases_dir` | `/var/lib/traffic-masq/dhcp/leases` |
| `[dhcp] default_lease_seconds` | `86400` (positive integer) |
| `[vpn] wireguard_config_dir` | `/var/lib/traffic-masq/vpn/wireguard` |
| `[auth] database_path` | `/var/lib/traffic-masq/auth.sqlite3` |

The DHCP fields and VPN profile directory are required in a file.

## Interfaces

Each `[network.interfaces.<name>]` table configures one Linux interface.
Names are 1–15 ASCII letters, digits, dots, underscores or hyphens.

| Field | Default / requirement | Meaning |
| --- | --- | --- |
| `role` | required | `none`, `input`, `output`, `middle`, or legacy `disabled`; `management` aliases `none` |
| `managed` | `false` | Allow traffic-masq to configure owned resources |
| `ipv4` | omitted | Static host CIDR, e.g. `192.168.50.1/24` |
| `nat` | `true` | Legacy output masquerade; ignored when explicit router forwarding is present |
| `dhcp` | omitted | DHCP server table; managed output with static IPv4 required |
| `dhcp_client` | omitted | DHCP client table; input role required |
| `wifi` | omitted | AP table; managed output required |
| `wifi_client` | omitted | Station table; managed input required |

Managed static subnets must not overlap. An enabled DHCP client and static IPv4
cannot coexist. AP and station configuration cannot coexist on one interface;
managed AP and station interfaces also cannot share a known physical PHY.
`middle` denotes an unaddressed WireGuard hop and rejects static IPv4, DHCP
server and Wi-Fi blocks. Legacy `disabled` cannot be managed.

For a managed wired DHCP uplink, add this to a safe initialized configuration:

```toml
[network.interfaces.wan0]
role = "input"
managed = true

[network.interfaces.wan0.dhcp_client]
enabled = true
route_metric = 100
install_default_route = true
request_dns = true
send_release_on_shutdown = false
```

Those DHCP-client values are defaults. `wifi_owned` is internal bookkeeping for
DHCP enabled by Wi-Fi activation; leave it at its default `false`. `request_dns`
requests and records lease DNS servers; the client does not update the host's
resolver or `/etc/resolv.conf`.

For a DHCP server, see the example's `[network.interfaces.wlan0.dhcp]` table.
`pool_start`, `pool_end` and `router` are required. The pool must stay within the
interface subnet and exclude its address, network and broadcast addresses.
`router` must equal the interface address. `dns_servers` defaults to `[]` and
accepts at most 63 IPv4 addresses; these are advertised to clients. The daemon
provides no DNS resolver. `lease_seconds` is optional and otherwise uses
`dhcp.default_lease_seconds`; an explicit value must be positive.

## Router

`[router]` defaults to disabled, with no uplink, no explicit forwarding, no owned
routes, `allow_default_route_change = false` and an empty `vpn_chain`.

```toml
[router]
enabled = true
forwarding = [
  { from = "lan0", to = "wan0", masquerade = true, source_subnet = "192.168.50.0/24" }
]
owned_routes = []
allow_default_route_change = false
```

`forwarding` is authoritative when present. `[]` removes explicit connections;
omitting the field preserves legacy uplink/per-output `nat` behavior. Each rule
requires different `from` and `to` interfaces, defaults `masquerade` to `true`,
and optionally restricts traffic with `source_subnet` (a network CIDR without
host bits). Overlapping rules for the same interface pair are rejected.
Forwarding does not create addresses, upstream routes or VPN tunnels.
See [Internet sharing](usage.md#routes-and-internet-sharing) for firewall behavior.

The optional legacy `[router.uplink]` table contains `interface` and `mode`:
`external` requires an unmanaged input; `dhcp` requires a managed input with an
enabled DHCP client. Legacy managed outputs need static IPv4 subnets.

Static routes use array tables:

```toml
[[router.owned_routes]]
destination = "10.20.0.0/16"
gateway = "192.168.1.1"
output_interface = "wan0"
table = 254
metric = 100
```

`destination` and `table` are required; either `gateway` or `output_interface`
(or both) must be supplied. `metric` is optional. Destinations must have no host
bits; tables `0` and `255` are rejected. A default route requires
`allow_default_route_change = true`. Existing foreign routes are not adopted.

`vpn_chain = [{ profile_name = "first.conf" }, { profile_name = "second.conf" }]`
selects up to eight WireGuard hops, nearest the physical uplink first. Explicit
`forwarding` cannot coexist with a legacy VPN chain or global VPN mode `vpn`.
Configure tunnel routing separately for explicit interface pairs.

## Wi-Fi

Global settings have these defaults:

| Field | `[wifi]` (AP) | `[wifi_client]` (station) |
| --- | --- | --- |
| `enabled` | `false` | `false` |
| Binary | `hostapd_binary = "/usr/sbin/hostapd"` | `wpa_supplicant_binary = "/usr/sbin/wpa_supplicant"` |
| `runtime_dir` | `/run/traffic-masq/hostapd` | `/run/traffic-masq/wpa_supplicant` |
| `restart_backoff_seconds` | `5` | `5` |

`[wifi] iw_binary` defaults to `/usr/sbin/iw`. Binary and runtime paths must be
absolute; backoff must be positive. Global `enabled` is a startup binary-check
hint, not a runtime off switch: supervisors are available even when it is
`false`, and interface configuration/profile activation can start Wi-Fi later.
Remove or deactivate the interface's Wi-Fi configuration to stop it.

Example AP block for an already configured managed output:

```toml
[network.interfaces.wlan0.wifi]
ssid = "traffic-masq"
country_code = "UA"
band = "2g"
channel = 6
channel_width = "ht20"
security = "wpa2"
hidden = false
client_isolation = false
max_stations = 32
passphrase_file = "/etc/traffic-masq/ap.passphrase"
```

Only `ssid` is required structurally. Other shown values are defaults except
country (omitted), channel (`0`, automatic) and passphrase file (omitted).
SSID must contain 1–32 bytes without control characters. Bands are `2g`/`5g`;
widths are `ht20`/`ht40`/`vht80`; `vht80` needs `5g` and a compatible channel.
A country code is two uppercase ASCII letters and is required for `5g`.
Radio capability and regulatory checks still apply. `max_stations` is 1–2007.

AP and client security values are `wpa2`, `wpa3`, `wpa2_wpa3` or `open`.
Protected networks require an 8–63 character printable ASCII passphrase, from
an absolute `passphrase_file` or the role-specific stored secret set through
TUI/API. Open networks must omit `passphrase_file`. A role transition requires
an explicit credential; AP and client secrets are separate.

A station table accepts only `ssid`, optional `country_code`, `security`
(default `wpa2`) and optional `passphrase_file`:

```toml
[network.interfaces.wlan1.wifi_client]
ssid = "Upstream"
security = "wpa2"
passphrase_file = "/etc/traffic-masq/uplink.passphrase"
```

The interface needs a managed input role and a separate DHCP-client or static
IPv4 policy. Association alone supplies no IP address or route.

## VPN, HTTPS and authentication

`[vpn] enabled` defaults to `false`; enabling it allows profile activation.
`[vpn.policy] default_mode` defaults to `direct` and also accepts `vpn`.
`protected_subnets` currently accepts only `all_managed_output_subnets`.
VPN policy mode requires VPN and routing enabled, and no explicit forwarding.

`[api.tcp]` defaults to disabled at `127.0.0.1:8443`. To enable HTTPS, provide
`enabled = true`, a numeric `listen` socket address, and distinct PEM
`certificate_path` and `private_key_path`. Startup loads the certificate chain
and key. The Unix socket remains available; the TUI has no HTTPS connection
option. See [API access settings](api.md#request-schemas).

`[security] rollback_timeout_seconds` is required in a file, defaults to `60`
in the built-in configuration, and must be positive.

| `[auth]` field | Default |
| --- | --- |
| `session_idle_seconds` | `1800` |
| `session_absolute_seconds` | `28800` |
| `argon2_memory_kib` | `32768` |
| `argon2_iterations` | `3` |
| `argon2_parallelism` | `1` |
| `max_concurrent_logins` | `2` |

All numeric auth settings must be positive; idle expiry must not exceed absolute
expiry. Authentication uses the independently configured database path above.
There is no TOML device-password field: initialize it with a local root client
or the installer, or use `traffic-masqd auth set-password` while stopped.
