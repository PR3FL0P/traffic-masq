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

`route_metric` is the requested default-route priority; higher values have lower
priority. If another route already occupies that destination, table and metric,
the client warns and uses the next free higher metric. It preserves existing
routes and records the effective metric in the lease for renewals and restart.
The configured value stays unchanged. In **Router**, select the default route
marked `traffic-masq (dhcp)` and press **e** or Enter to open the DHCP client
settings, edit **Route metric**, then apply.

Those DHCP-client values are defaults. `wifi_owned` is internal bookkeeping for
DHCP enabled by Wi-Fi activation; leave it at its default `false`. `request_dns`
requests and records lease DNS servers; the client does not update the host's
resolver or `/etc/resolv.conf`.

The optional DHCP-client `hostname = "travel-router"` setting sends that name
as [DHCP option 12](https://www.rfc-editor.org/rfc/rfc2132.html#section-3.14).
Use an ASCII DNS name of up to 253 characters, with labels of 1 to 63 letters,
digits or hyphens; each label must start and end with a letter or digit.
Names such as `travel-router` and `router.home.example` are accepted. Omitting
`hostname` sends no name. In **DHCP Client settings**, edit **Hostname** and apply;
leaving the field empty removes it. The value persists across daemon restarts.
Changing it restarts the client so the next DHCP request carries the new name.
The DHCP server controls how the name is displayed or used for local DNS.

For a DHCP server, see the example's `[network.interfaces.wlan0.dhcp]` table.
`pool_start`, `pool_end` and `router` are required. The pool must stay within the
interface subnet and exclude its address, network and broadcast addresses.
`router` must equal the interface address. `dns_servers` defaults to `[]` and
accepts at most 63 IPv4 addresses; these are advertised to clients. The daemon
provides no DNS resolver. `lease_seconds` is optional and otherwise uses
`dhcp.default_lease_seconds`; an explicit value must be positive.

## Router

`[router]` has no global enabled switch. Routing intent is derived from an
uplink, non-empty explicit forwarding rules, owned routes, or a VPN chain.
With none of these, the router dataplane remains inactive. Old TOML files with
`router.enabled` still deserialize, but the key is ignored; remove it when migrating.

```toml
[router]
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

`route_host_traffic = true` (default `false`) additionally sends the router's own
locally generated traffic through the VPN chain. It requires a non-empty
`vpn_chain` and is part of the router intent, so it is planned, applied,
confirmed and rolled back with the rest of the router transaction. While it is
on:

- Router-originated IPv4 is marked for the tunnel and dropped if it would leave
  any interface other than the tunnel (a host kill switch).
- Traffic to loopback, to the managed LAN subnets, multicast/broadcast, DHCP
  (UDP 67/68) and to the resolved WireGuard endpoint of every hop stays direct.
  Endpoints are read from the current WireGuard kernel configuration when the
  policy is applied and checked; if they cannot be observed (or are IPv6), the
  change is refused. Hostname endpoints are resolved once when activating the tunnel.
- Router-originated IPv6 is blocked except loopback, link-local and multicast,
  because IPv6 is not tunnelled.

The router's DNS goes through the tunnel too. If the VPN does not provide a
resolver the host can reach, name resolution on the router can stop working;
`/etc/resolv.conf` is not changed. If WireGuard learns a new endpoint while the tunnel is up, the integrity check
detects the drift and re-applies the policy using the current kernel address.

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
TUI/API. The role-specific stored secret takes precedence over `passphrase_file`;
the file is read only when no stored secret exists. Open networks must omit
`passphrase_file`. A role transition requires
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

`[vpn] wireguard_import_dir` defaults to `/etc/wireguard`. The TUI import browser
lists regular `.conf` files there through the daemon; private keys are never
returned in the listing. Imports copy the selected file into `wireguard_config_dir`
with private permissions. The source directory and its permissions are unchanged.
Each protocol keeps its own source and profile store; currently only WireGuard
is supported. Hostname endpoints are resolved when connecting, and profile MTU
is applied to the tunnel. `DNS` is parsed but does not change the system resolver.
Autostart, per-profile IPv6 controls, and per-profile kill switches are not
implemented; the existing router traffic policy manages protected LAN traffic.

`[vpn] enabled` defaults to `false`; enabling it allows profile activation.
`[vpn.policy] default_mode` defaults to `direct` and also accepts `vpn`.
`protected_subnets` currently accepts only `all_managed_output_subnets`.
VPN policy mode requires `vpn.enabled = true`, active router intent, and no
explicit forwarding. Router activity is derived from its settings, not a switch.

`[api.tcp]` defaults to disabled at `127.0.0.1:8443`. To enable HTTPS, provide
`enabled = true`, a numeric `listen` socket address, and distinct PEM
`certificate_path` and `private_key_path`. Startup loads the certificate chain
and key. The Unix socket remains available. Connect the TUI with
`--server https://host:port` and optionally `--ca-cert /path/to/ca.pem`, or use
a saved `--connection`. Certificate trust and hostname verification are required.
See [remote client setup](usage.md#https-connections-and-saved-destinations)
and [API access settings](api.md#request-schemas).

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

### Interface MAC address

Managed Ethernet and Wi-Fi interfaces accept an optional `mac_address`, for example:

```toml
[network.interfaces.eth0]
role = "input"
managed = true
mac_address = "02:1a:7c:90:33:bf"
```

In the TUI, open **Interfaces**, edit an interface, enable **Configure with traffic-masq**, and select **Generate random MAC**. Each activation generates a locally administered unicast address. Review and apply the change, then confirm it using the usual network transaction confirmation. The selected address is saved and reused after daemon restarts; generating another address is an explicit action.

Changing a MAC briefly takes the link down and restarts its traffic-masq Wi-Fi and DHCP services. A canceled transaction restores the previous MAC and link state. The driver must support MAC changes. Unmanaged interfaces and WireGuard interfaces cannot have a configured MAC. Omitting the setting leaves the current MAC unchanged; it does not reset the hardware address.
