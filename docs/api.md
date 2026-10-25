# HTTP API

`traffic-masqd` exposes a versioned JSON API for the terminal client and other
local or remote automation. Version 1 is mounted at `/api/v1` and is served
over the Unix socket configured by `runtime.socket_path` (default
`/run/traffic-masq/traffic-masqd.sock`). Optional remote access uses HTTPS; the
daemon never exposes an unencrypted TCP listener.

The API is currently intended to be used together with the same release of the
daemon. Additive fields and response variants may appear within version 1, so
clients should ignore unknown object fields and handle unknown `type` values.
Request bodies are limited to 64 KiB. HTTP/1 connections close after one
request and have a 60-second server deadline; TLS handshakes have a 10-second
deadline. A lost response does not cancel an admitted control operation.

## Typed control endpoint

The terminal client sends commands to `POST /api/v1/control`. Its JSON body is
`traffic_masq_protocol::ControlRequest`, tagged by `type`, with the command's
fields alongside it. For example:

```json
{"type": "get_interface_config", "interface": "eth0"}
```

```json
{"type": "commit_network_change", "token": "<pending-token>"}
```

Responses use the same `ControlResponse` envelope as the REST routes below.
The control endpoint requires a bearer session, including read commands and
`ping`. Authorization depends on the decoded command, not the HTTP method:
reads and previews accept any authenticated role, while administrative commands
require `administrator`. Daemon logs and VPN source listings are administrative
reads. The same admission, recovery and transaction rules apply to both
transports. Invalid JSON returns HTTP 400, unknown commands or invalid payloads
return HTTP 422, and bodies exceeding 64 KiB return HTTP 413.

The client retains the public `GET /status` for availability checks before
login and translates a successful response to `Pong`. Other typed commands use
`/control` without automatic fallback or retries. Existing REST routes remain
available for automation. Use a client from the same release as the daemon;
older daemons do not expose `/control`.

Client deadlines follow the command: observations use 10 seconds; writes,
scans and dry-run plans use 65 seconds. Using POST for reads does not extend
their deadline. A timeout does not cancel an admitted server operation.

## Quick start

Check the daemon and authentication state without a session:

```sh
curl --unix-socket /run/traffic-masq/traffic-masqd.sock \
  http://localhost/api/v1/status
curl --unix-socket /run/traffic-masq/traffic-masqd.sock \
  http://localhost/api/v1/auth/status
```

Log in with the device password. Run this example in **Bash**, with shell
tracing (`set -x`) disabled. Your user must have access to the daemon socket;
initialize the password first through `sudo traffic-masq` if needed.
The subshell keeps credentials out of the parent shell, and pipes carry the
password and authorization header without putting them in process arguments:

```bash
(
  set -euo pipefail
  read -rsp 'Device password: ' TM_PASSWORD; printf '\n'
  TM_TOKEN=$(
    printf '%s' "$TM_PASSWORD" |
      jq -Rs '{password: ., client: "api-example"}' |
      curl --fail --silent --show-error \
        --unix-socket /run/traffic-masq/traffic-masqd.sock \
        --json @- http://localhost/api/v1/auth/login |
      jq -er '.token | select(type == "string" and length > 0)'
  )
  unset TM_PASSWORD

  printf 'Authorization: Bearer %s\n' "$TM_TOKEN" |
    curl --fail --silent --show-error \
      --unix-socket /run/traffic-masq/traffic-masqd.sock \
      --header @- http://localhost/api/v1/interfaces
)
```

The examples need `curl` with `--json` support and `jq` to build and read JSON.
Over HTTPS, replace the Unix-socket option and URL with the configured address,
for example `https://router.example:8443/api/v1/status`, and validate the daemon
certificate with the appropriate CA settings.

## Authentication and authorization

`GET /status`, `GET /auth/status`, `POST /auth/initialize`, and
`POST /auth/login` are public. Every other endpoint requires
`Authorization: Bearer <token>`.

There is one built-in device account, `device`, with the `administrator` role.
Passwords must contain at least 12 characters. Initial setup is accepted only
from a root process connected through the Unix socket; it cannot be performed
over HTTPS. A successful initialization or login returns:

```json
{
  "token": "<opaque token>",
  "principal": {
    "user_id": 1,
    "username": "device",
    "role": "administrator"
  },
  "idle_expires_at": 1760000000,
  "absolute_expires_at": 1760020000
}
```

Expiry values are Unix timestamps in seconds. Using a valid session refreshes
its idle expiry, up to its absolute expiry. Password changes revoke all active
sessions. Authentication attempts are rate- and concurrency-limited.

Read operations and dry-run plans accept any authenticated role. Operations
which change configuration or runtime state require `administrator`. Although
the wire model also defines `viewer` and `operator`, the current public account
management surface creates only the administrator device account.

## Response and error conventions

Control endpoints return a tagged JSON object. The `type` field identifies the
response variant and the remaining fields contain its data:

```json
{
  "type": "interfaces",
  "interfaces": []
}
```

Expected domain failures are also returned as typed responses, usually with
HTTP 200, for example:

```json
{
  "type": "vpn_error",
  "detail": {
    "kind": "not_found",
    "name": "office"
  }
}
```

Clients must therefore inspect both the HTTP status and the response `type`.
Authentication and authorization failures use an untagged JSON error body:

```json
{ "error": "authentication required" }
```

HTTP extraction failures, such as invalid JSON, an invalid request schema or an
oversized body, return plain-text errors rather than this JSON envelope. Clients
must check the response status and content type before decoding an error body.

Common statuses are `400` for syntactically invalid JSON or an invalid
authentication request, `401` for a missing, invalid or expired session,
`403` for insufficient access, `409` when the password is already initialized,
`413` for an oversized body, `422` for
JSON that does not match the request schema, `429` for authentication throttling,
and `500` for an internal authentication/server failure. Domain validation
failures inside authenticated control requests use a typed response.

Path parameters such as `{interface}`, `{id}`, `{name}`, and `{mac}` must be
percent-encoded as URL path segments.

## Endpoint reference

Body names in the tables refer to the [request schemas](#request-schemas).
`—` means that no request body is required.

### Service, authentication, and settings

| Method | Path | Body | Result or purpose | Access |
| --- | --- | --- | --- | --- |
| `GET` | `/logs?limit=500` | — | Recent daemon log snapshot; limit 1–1000 | Administrator |
| `GET` | `/status` | — | Service version, API version, and capabilities | Public |
| `GET` | `/auth/status` | — | `{ "initialized": bool }` | Public |
| `POST` | `/auth/initialize` | `{ "password": string }` | Initialize password and return a session | Local root only |
| `POST` | `/auth/login` | `{ "password": string, "client"?: string }` | Return a session | Public |
| `POST` | `/auth/logout` | — | Revoke current session; `204` | Authenticated |
| `GET` | `/auth/me` | — | Current principal | Authenticated |
| `POST` | `/auth/password` | `{ "current_password": string, "new_password": string }` | Change password; revoke sessions; `204` | Administrator |
| `GET` | `/access/https` | — | Active and desired HTTPS settings | Authenticated |
| `PUT` | `/access/https` | `ApiHttpsSettings` | Save HTTPS override; restart required | Administrator |
| `DELETE` | `/access/https` | — | Clear HTTPS override; restart required | Administrator |
| `GET` | `/security/settings` | — | Active and desired rollback timeout | Authenticated |
| `PUT` | `/security/settings` | `SecuritySettings` | Save rollback-timeout override | Administrator |
| `DELETE` | `/security/settings` | — | Clear rollback-timeout override | Administrator |

### Interfaces, DHCP, and routes

| Method | Path | Body | Result or purpose | Access |
| --- | --- | --- | --- | --- |
| `GET` | `/interface-inventory` | — | `interface_inventory`: saved intent, revision and observed presence | Authenticated |
| `GET` | `/wifi-inventory` | — | `wifi_inventory`: interface inventory plus AP/STA runtime availability | Authenticated |
| `PUT` | `/interfaces/{interface}/intent` | `InterfaceIntentWrite` | Save missing-device intent; `interface_intent_saved` | Administrator |
| `POST` | `/interfaces/{interface}/intent/forget` | `IntentRevision` | Remove intent and suppress base configuration | Administrator |
| `POST` | `/interfaces/{interface}/intent/reset` | `IntentRevision` | Clear override/suppression and restore base configuration | Administrator |
| `PUT` | `/interfaces/{interface}/wifi-intent` | `WifiIntentWrite` | Save missing-device Wi-Fi settings/optional secret | Administrator |
| `PUT` | `/interfaces/{interface}/wifi-client-intent` | `WifiClientIntentWrite` | Save library client profile and IPv4 policy for a missing device | Administrator |
| `GET` | `/interfaces` | — | Observed interfaces, addresses, ownership and default-route flags | Authenticated |
| `GET` | `/interfaces/{interface}/config` | — | Effective interface configuration | Authenticated |
| `POST` | `/interfaces/{interface}/plan` | `InterfaceChange` | Plan a complete replacement | Authenticated |
| `POST` | `/interfaces/{interface}/apply` | `InterfaceChange` | Tentatively apply; returns a pending change | Administrator |
| `POST` | `/interfaces/{interface}/edit/plan` | `InterfaceEdit` | Plan the simplified TUI edit form | Authenticated |
| `POST` | `/interfaces/{interface}/edit/apply` | `InterfaceEdit` | Tentatively apply simplified edit | Administrator |
| `GET` | `/network-transactions` | — | List pending interface/provisioning changes | Authenticated |
| `POST` | `/network-transactions/commit` | `Transaction` | Commit a pending change | Administrator |
| `POST` | `/network-transactions/rollback` | `Transaction` | Roll back a pending change | Administrator |
| `GET` | `/dhcp` | — | DHCP server health summary | Authenticated |
| `GET` | `/dhcp/{interface}` | — | DHCP server configuration/specification | Authenticated |
| `PUT` | `/dhcp/{interface}` | `DhcpInterfaceConfig` | Tentatively configure DHCP server; requires network confirmation | Administrator |
| `DELETE` | `/dhcp/{interface}` | — | Tentatively disable DHCP server; requires network confirmation | Administrator |
| `PUT` | `/dhcp/{interface}/settings` | `DhcpEdit` | Configure DHCP through the edit model | Administrator |
| `GET` | `/dhcp/{interface}/leases` | — | Active leases | Authenticated |
| `GET` | `/dhcp-client` | — | DHCP client status for all configured interfaces | Authenticated |
| `GET` | `/dhcp-client/{interface}` | — | One DHCP client status | Authenticated |
| `PUT` | `/dhcp-client/{interface}` | `DhcpClientConfig` | Tentatively configure DHCP client; requires network confirmation | Administrator |
| `DELETE` | `/dhcp-client/{interface}` | — | Tentatively disable DHCP client; requires network confirmation | Administrator |
| `POST` | `/dhcp-client/{interface}/renew` | — | Renew the lease | Administrator |
| `POST` | `/dhcp-client/{interface}/release` | — | Release the lease | Administrator |
| `GET` | `/route-inventory?include_local_table=false` | — | Saved router configuration/revision and configured/observed route inventory | Authenticated |
| `GET` | `/routes?include_local_table=false` | — | Observed IPv4 routes; local table is excluded by default | Authenticated |

### Router and provisioning

| Method | Path | Body | Result or purpose | Access |
| --- | --- | --- | --- | --- |
| `GET` | `/router/config` | — | Effective router configuration | Authenticated |
| `GET` | `/router/status` | — | Readiness, coordinator and recovery state | Authenticated |
| `PUT` | `/router/intent` | `{ "config": RouterConfig, "expected_revision": integer }` | Save sharing/owned-route intent with deferred execution and cleanup result | Administrator |
| `POST` | `/router/intent/preview` | `RouterProposal` | Validate saved intent and report device dependencies without runtime preflight | Authenticated |
| `POST` | `/router/plan` | `RouterProposal` | Build a plan without applying it | Authenticated |
| `POST` | `/router/apply` | `RouterProposal` | Tentatively apply and return a token | Administrator |
| `POST` | `/router/commit` | `Transaction` | Commit the router transaction | Administrator |
| `POST` | `/router/rollback` | `Transaction` | Roll back the router transaction | Administrator |
| `GET` | `/router/pending` | — | Pending token and recovery state | Authenticated |
| `POST` | `/router/provisioning/preview` | `RouterProvisioningPreview` | Preview Wi-Fi uplink/AP router setup | Authenticated |
| `POST` | `/router/provisioning/apply` | `RouterProvisioningApply` | Tentatively apply the complete setup | Administrator |
| `GET` | `/router/provisioning/status` | — | Provisioning readiness and failures | Authenticated |
| `POST` | `/router/provisioning/repair` | — | Reapply committed router intent without a confirmation timer | Administrator |

Repair requires an idle router coordinator and no pending interface transactions.
After a failed rollback, inspect `/router/pending` and explicitly retry
`POST /router/rollback` with its token before requesting repair.

`/router/intent/preview` works without router execution or present adapters. It
returns the candidate's base `revision`, effective router `config` (including
saved routes whose devices are missing), derived `desired`,
`execution_available`, and `device_readiness` with sorted missing-interface blockers. Observation failure
returns `unknown` with an observation blocker rather than claiming missing
devices. `ready` describes only device presence; it does not certify binaries,
route conflicts, ownership, or runtime readiness. Structural validation and
management-change authorization still apply. Preview neither saves intent nor
opens a transaction; `/router/plan` and `/router/apply` retain strict preflight.
The returned revision is not an applied dataplane revision.

`PUT /router/intent` saves sharing and owned-route configuration when current
or candidate dependencies are missing, or router execution is unavailable.
It requires the current revision from preview and retains structural validation.
Present dependencies require a confirmed live transaction; failed observation
rejects Save. Changing uplink, VPN chain, or derived interface policy requires a
live transaction too. There is no router enable/disable field: activity is
derived from uplink, forwarding, owned routes and VPN-chain intent.

`RouterIntentSaved` reports the committed revision, `deferred`, missing
interfaces, execution availability, and `cleanup_blockers`. A nonempty cleanup
blocker means **intent was saved but removed runtime resources may remain**;
it is not a failed Save and must not be retried with the old revision. Pending
transactions, recovery fences, and indeterminate persistence block Save.

After commit, cleanup only removes obsolete daemon-owned routes and previously
applied firewall permissions. It does not install new routes/rules, reconfigure
services, or change global IPv4 forwarding. Unavailable dependencies defer the
whole remaining dataplane. Startup and reconcile retry removal using the latest
committed intent, even while devices remain missing.

`GET /route-inventory` returns the effective saved router `config`, its
`revision`, and rows with independent optional `configured` and `observed`
values. Saved routes survive missing devices and observation failure; output
presence is `present`, `missing`, or `unknown`. `observation_error` reports
incomplete observation. Only exact daemon-owned matches merge with saved rows;
foreign routes remain separate. `/routes` keeps its observed-only contract.

Router status exposes `desired_revision` and `last_applied_revision` (nullable
when the corresponding state is unavailable). Last applied is historical evidence from a successful
commit, repair, or verification in the current daemon process; it resets on
restart until verified again. It does not certify current health, and offline
Save/removal-only cleanup does not advance it.

The TUI Routes and Sharing editors use saved inventory. Missing routes have no
invented runtime ifindex; unconfigured observed routes remain read-only.
Offline Plan reviews additions/removals and saves the latched revision through
`PUT /router/intent`. Unknown observation or a stale revision retains the draft;
press `c` on the router screen to discard it and reload. Ready live changes
continue to require the confirmed router transaction.

Router transactions and interface/network transactions have separate commit
endpoints. Use the endpoint corresponding to the apply response.

### VPN

| Method | Path | Body | Result or purpose | Access |
| --- | --- | --- | --- | --- |
| `GET` | `/vpn/sources` | — | List regular `.conf` files in the configured WireGuard import directory, without contents | Administrator |
| `POST` | `/vpn/sources/{name}` | — | Copy a source configuration into the private profile store | Administrator |
| `GET` | `/vpn/profiles` | — | List WireGuard profile metadata | Authenticated |
| `POST` | `/vpn/profiles` | `{ "name": string, "contents": string }` | Import a WireGuard configuration | Administrator |
| `DELETE` | `/vpn/profiles/{name}` | — | Delete an inactive profile | Administrator |
| `GET` | `/vpn/config` | — | Whether the VPN subsystem is enabled | Authenticated |
| `PUT` | `/vpn/config` | `{ "enabled": bool }` | Tentatively change VPN availability; requires router confirmation | Administrator |
| `GET` | `/vpn/status` | — | Active profile/interface, if any | Authenticated |
| `POST` | `/vpn/activate` | `{ "name": string }` | Tentatively activate a profile; requires router confirmation | Administrator |
| `POST` | `/vpn/deactivate` | — | Tentatively disconnect; requires router confirmation | Administrator |
| `GET` | `/vpn-policy/status` | — | Policy mode, tunnel health and protected subnets | Authenticated |
| `PUT` | `/vpn-policy/mode` | `{ "mode": "direct" | "vpn" }` | Tentatively set policy; requires router confirmation | Administrator |
| `DELETE` | `/vpn-policy/mode` | — | Tentatively clear policy override; requires router confirmation | Administrator |

### Wi-Fi access point

| Method | Path | Body | Result or purpose | Access |
| --- | --- | --- | --- | --- |
| `GET` | `/wifi` | — | AP runtime status | Authenticated |
| `GET` | `/wifi/{interface}` | — | AP specification | Authenticated |
| `PUT` | `/wifi/{interface}` | `WifiEdit` | Tentatively configure AP; secret is separate | Administrator |
| `DELETE` | `/wifi/{interface}` | — | Present adapter: pending change; absent saved AP: intent saved after cleanup | Administrator |
| `PUT` | `/wifi/{interface}/passphrase` | `{ "passphrase": string }` | Store AP passphrase | Administrator |
| `POST` | `/wifi/{interface}/provision` | `WifiApProvision` | Tentatively apply AP, secret and optional DHCP | Administrator |
| `GET` | `/wifi/{interface}/stations` | — | Associated stations | Authenticated |
| `POST` | `/wifi/{interface}/stations/{mac}/deauthenticate` | — | Disconnect a station | Administrator |
| `POST` | `/wifi/{interface}/reload` | — | Reload AP process | Administrator |
| `GET` | `/wifi-ap-profiles` | — | List reusable profiles without secrets | Authenticated |
| `PUT` | `/wifi-ap-profiles` | `WifiApProfileWrite` | Create or replace a profile | Administrator |
| `DELETE` | `/wifi-ap-profiles/{id}` | — | Delete a profile; running AP is unchanged | Administrator |
| `PUT` | `/wifi/{interface}/profile` | `{ "profile_id": string }` | Tentatively apply a saved profile | Administrator |

AP and client passphrases are scoped to their respective roles. AP provisioning
without a new passphrase can retain an existing AP credential, but cannot reuse
a client credential during a role switch. Supply a new AP passphrase for that
transition.

### Wi-Fi client

| Method | Path | Body | Result or purpose | Access |
| --- | --- | --- | --- | --- |
| `GET` | `/wifi-client` | — | Wi-Fi client runtime status | Authenticated |
| `GET` | `/wifi-client/{interface}` | — | Client specification | Authenticated |
| `PUT` | `/wifi-client/{interface}` | `WifiClientEdit` | Tentatively configure association; secret is separate | Administrator |
| `DELETE` | `/wifi-client/{interface}` | — | Present adapter: pending change; absent saved client: intent saved after cleanup | Administrator |
| `PUT` | `/wifi-client/{interface}/passphrase` | `{ "passphrase": string }` | Store client passphrase | Administrator |
| `POST` | `/wifi-client/{interface}/reconnect` | — | Request reconnection | Administrator |
| `POST` | `/wifi-client/{interface}/scan` | — | Scan and return networks | Administrator |
| `GET` | `/wifi-client/profiles` | — | List saved profile summaries | Authenticated |
| `POST` | `/wifi-client/profiles` | `WifiClientProfileWrite` | Create a saved profile | Administrator |
| `GET` | `/wifi-client/profiles/{id}` | — | Get a profile summary without its secret | Authenticated |
| `PUT` | `/wifi-client/profiles/{id}` | `WifiClientProfileWrite` | Update a profile; body `id` must match path | Administrator |
| `DELETE` | `/wifi-client/profiles/{id}` | — | Delete an inactive profile | Administrator |
| `PUT` | `/wifi-client/{interface}/provision` | `WifiClientProvision` | Tentatively apply profile plus IPv4 policy | Administrator |
| `PUT` | `/wifi-client/{interface}/active-profile` | `{ "profile_id": string }` | Tentatively activate a saved profile | Administrator |
| `DELETE` | `/wifi-client/{interface}/active-profile` | — | Deactivate current profile; present: pending change, absent: intent saved after cleanup | Administrator |

### Daemon log snapshots

`GET /logs?limit=500` returns `{"type":"daemon_logs","snapshot":{...}}`.
The snapshot contains chronological `lines`, source filenames in `sources`, and
`truncated`, which indicates an incomplete recent window. Limits outside 1–1000
return a domain error. The endpoint requires administrator authentication.

The reader examines only `traffic-masqd.log` and daily `traffic-masqd.log.YYYY-MM-DD`
files in the configured log directory, skips symlinks, and reads at most 256 KiB
from up to three recent files. Long lines are capped at 2048 characters and marked
truncated. Terminal escape sequences are removed. No client-supplied path is
accepted. Missing/unreadable log files return an error rather than claiming an
empty healthy log. This endpoint is read-only and remains usable during recovery.

## Request schemas

JSON enum values use `snake_case`. CIDRs are strings such as
`"192.168.50.1/24"`; IPv4 addresses are strings such as `"192.168.50.1"`.

`Transaction`

```json
{ "token": "<token returned by apply>" }
```

`InterfaceChange`

```json
{
  "config": {
    "role": "output",
    "managed": true,
    "ipv4": "192.168.50.1/24",
    "dhcp": null,
    "dhcp_client": null,
    "wifi": null,
    "wifi_client": null
  },
  "allow_management_change": false
}
```

Roles are `none`, `input`, `output`, and `middle`. Removed roles and unknown
configuration fields are rejected. Nested configuration objects
use the same shape as [`examples/config.toml`](../examples/config.toml).

`InterfaceEdit`

```json
{
  "cidr": "192.168.50.1/24",
  "role": "output",
  "managed": true,
  "allow_management_change": false
}
```

An empty `cidr` requests no owned static address.

Interface configuration objects and `InterfaceEdit` accept optional `mac_address` as a colon-separated MAC string, for example `"02:1a:7c:90:33:bf"`. The interface must be managed and support Ethernet addressing; zero and multicast addresses are rejected. Interface plans return `mac_address` only when a MAC change is needed. The TUI generates the random address before requesting a plan, so planning and applying use the same address. Changes use the existing confirmation and rollback flow, and committed addresses persist across daemon restarts.

`DhcpInterfaceConfig` and `DhcpEdit` share this shape:

```json
{
  "pool_start": "192.168.50.100",
  "pool_end": "192.168.50.200",
  "router": "192.168.50.1",
  "dns_servers": ["1.1.1.1", "9.9.9.9"],
  "lease_seconds": 86400
}
```

`DhcpClientConfig`

Configuring a DHCP client requires an already managed `input` interface with
no static IPv4 address. Apply and commit interface role, management or address
changes through the interface transaction endpoints first. The DHCP endpoint
changes only DHCP policy; it does not convert the interface or remove other
services.

Enabling, configuring or disabling a DHCP client returns
`NetworkChangePending` through the existing interface transaction. Confirm with
`CommitNetworkChange` or cancel with `RollbackNetworkChange`; timeout restores
the previous policy. Saved configuration changes only on commit. Recovery uses
the interface transaction journal and DHCP supervisor, without replaying an
expired lease. DHCP server configure/disable uses the same confirmation endpoints.
Renew and release-and-reacquire remain immediate operational actions.

```json
{
  "hostname": "travel-router",
  "route_metric": 100,
  "install_default_route": true,
  "request_dns": true,
  "send_release_on_shutdown": false
}
```

`hostname` is optional; omitted or `null` means no Host Name option is sent.
It accepts ASCII DNS names of 1 to 253 characters with labels of 1 to 63
letters, digits or hyphens, starting and ending with a letter or digit.
The same field is available in `config.dhcp_client`, DHCP client status
configuration and router plan DHCP client specifications. Changing the name
restarts the client; existing role, management and static IPv4 restrictions apply.

`RouterProposal`

```json
{
  "set_router": {
    "uplink": null,
    "forwarding": [
      { "from": "lan0", "to": "wan0", "masquerade": true }
    ],
    "owned_routes": [],
    "allow_default_route_change": false,
    "vpn_chain": [],
    "route_host_traffic": false
  },
  "clear_router": false,
  "set_interfaces": {},
  "remove_interfaces": []
}
```

Each `set_interfaces` value has the `InterfaceChange` shape. Omitted proposal
fields default to `null`, `false`, or an empty collection. `set_router` and
`clear_router` are mutually exclusive. This is a complete router replacement:
include the routes and settings you want to retain in `set_router`.

A forwarding rule accepts optional `source_subnet`, a network CIDR without host
bits such as `"192.168.50.0/24"`. `masquerade` defaults to `true`. Omitted or
`null` `forwarding` grants no forwarding permissions, as does `[]`. Explicit
forwarding requires direct global VPN policy. VPN chains require explicit
connection permissions too. See the [router configuration reference](configuration.md#router)
for uplink, static-route and VPN-chain fields.

`ApiHttpsSettings`

```json
{
  "enabled": true,
  "listen": "0.0.0.0:8443",
  "certificate_path": "/etc/traffic-masq/api.crt",
  "private_key_path": "/etc/traffic-masq/api.key"
}
```

Changing these desired settings does not rebind the running listener. Restart
the daemon after saving them. Use certificate files and a private key readable
by the daemon.

The terminal client supports `--server https://host:port` with `--ca-cert` for
an explicit CA/server certificate, or a system CA bundle. Certificate trust and
hostname validation are required. Initial password setup still requires local root.

`SecuritySettings`

```json
{ "rollback_timeout_seconds": 60 }
```

`WifiEdit`

```json
{
  "ssid": "traffic-masq",
  "country_code": "UA",
  "band": "5g",
  "channel": 36,
  "channel_width": "vht80",
  "security": "wpa2_wpa3",
  "hidden": false,
  "client_isolation": false,
  "max_stations": 32
}
```

Bands are `2g` and `5g`; widths are `ht20`, `ht40`, and `vht80`; AP security
is `wpa2`, `wpa2_wpa3`, `wpa3`, or `open`. `channel: 0` requests automatic
selection where supported.

`WifiApProvision`

```json
{
  "settings": { "ssid": "traffic-masq", "band": "2g", "channel": 6,
    "channel_width": "ht20", "security": "wpa2", "hidden": false,
    "client_isolation": false, "max_stations": 32 },
  "passphrase": "replace-with-a-secret",
  "clear_passphrase": false,
  "configure_dhcp": true,
  "subnet": "192.168.50.1/24",
  "disable_dhcp": false
}
```

`subnet` here is the interface host CIDR, such as `192.168.50.1/24`,
not the network address. DHCP uses that host as the router. In contrast,
`forwarding.source_subnet` requires a network CIDR such as `192.168.50.0/24`.

`WifiApProfileWrite` adds an `id` beside these fields; the provisioning fields
are flattened rather than nested under `configuration`:

```json
{
  "id": "guest",
  "settings": { "ssid": "Guest", "band": "2g", "channel": 6,
    "channel_width": "ht20", "security": "wpa2", "hidden": false,
    "client_isolation": true, "max_stations": 16 },
  "passphrase": "replace-with-a-secret",
  "configure_dhcp": true,
  "subnet": "192.168.60.1/24"
}
```

`WifiClientEdit`

```json
{ "ssid": "Upstream", "country_code": "UA", "security": "wpa2" }
```

SSID is 1–32 bytes; AP country is required for `5g`. Protected Wi-Fi
passphrases are 8–63 printable ASCII characters.

Client security is `wpa2`, `wpa3`, `wpa2_wpa3`, or `open`.

`WifiClientProfileWrite`

```json
{
  "id": "home",
  "ssid": "Upstream",
  "country_code": "UA",
  "security": "wpa2",
  "priority": 10,
  "autoconnect": true,
  "passphrase": "replace-with-a-secret",
  "clear_passphrase": false
}
```

For updates, omit `passphrase` to keep the saved value or set
`clear_passphrase: true` to remove it.

`WifiClientProvision`

```json
{
  "profile_id": "home",
  "ip_policy": { "kind": "dhcp" }
}
```

`ip_policy` is a tagged object: `{ "kind": "preserve" }`,
`{ "kind": "dhcp" }`, or
`{ "kind": "static", "cidr": "192.168.1.20/24" }`.

`RouterProvisioningPreview`

```json
{
  "provisioning": {
    "uplink": { "interface": "wlan0", "ssid": "Upstream",
      "country_code": "UA", "security": "wpa2" },
    "output": { "interface": "wlan1", "ssid": "Local",
      "country_code": "UA", "band": "2g", "channel": 6,
      "channel_width": "ht20", "security": "wpa2", "hidden": false,
      "client_isolation": false, "max_stations": 32 },
    "downstream": {},
    "allow_management_change": false
  },
  "uplink_secret_pending": true,
  "output_secret_pending": true
}
```

`RouterProvisioningApply` replaces the two `*_secret_pending` flags with
optional `uplink_passphrase` and `output_passphrase`. Downstream overrides may
specify `interface_ipv4`, `pool_start`, `pool_end`, `dns_servers`, and
`lease_seconds`; omitted values are derived by the daemon.

## Offline intent and inventory

`InterfaceIntentWrite` wraps the `InterfaceChange.config` object:

```json
{
  "config": { "role": "input", "managed": true, "ipv4": null },
  "allow_management_change": false,
  "expected_revision": 12
}
```

`IntentRevision` is `{ "expected_revision": 12 }`. `WifiIntentWrite` is
`{ "config": <InterfaceChange.config>, "expected_revision": 12,
"passphrase": <optional string> }`. It must preserve the effective role and
management policy; assign these through the interface intent endpoint first.
A supplied passphrase requires exactly one secured AP or STA configuration.
`WifiClientIntentWrite` is `{ "settings": <WifiClientProvision>,
"expected_revision": 12 }`; it requires an existing managed input intent and a
valid library profile, and applies its `ip_policy` without connecting.

All five writes require a fresh successful observation that the device is
absent. Present devices must use live confirmed transactions. The daemon checks
`expected_revision`, validates the candidate, cleans up owned runtime, observes
absence again, then commits with revision fencing. Invalid names/configuration,
stale revisions, observation errors, retained ownership requiring recovery,
cleanup failure or device reappearance reject the write. Observation/cleanup
failures preserve the old intent; cleanup may already have stopped services.
Pending router work or recovery fences also block conflicting mutations.
Storage failures can have uncertain outcomes as described in the recovery
runbook. These are typed domain errors, usually HTTP 200, not proof of success.

Forget removes overrides and suppresses base TOML configuration for that name;
reset removes override and suppression so base TOML becomes effective again.
Saving intent defers runtime work until required devices are present; it does
not apply a live change or create a confirmation token. Success has this shape:

```json
{
  "type": "interface_intent_saved",
  "interface": "wlan0",
  "revision": 13,
  "deferred": true,
  "missing_dependencies": ["wlan0"]
}
```

Inventory responses contain `type`, `revision`, `interfaces`, and nullable
`observation_error`. Interface inventory additionally contains
`suppressed_interfaces`. Each entry has `name`, nullable `configured` and
`observed`, `config_source` (`base`, `override`, `derived`, `none`), `presence`
(`present`, `missing`, `unknown`), `observation_stale`, `suppressed`, `readiness`
(`ready`, `disabled`, `waiting_device`, `unknown`), `blockers` and `references`.
Blockers are tagged by `kind`: `missing_interface` with `interface`, or
`observation_failed` with `message`. References name dependent router fields.
`ready` describes device presence, not successful connectivity or service health.
On observation failure cached observations remain visible, marked stale with
unknown presence; they must not be used as proof of absence.

Wi-Fi inventory instead wraps each entry as `interface`, nullable `ap_runtime`
and `client_runtime`, and adds `ap_execution_available` and
`client_execution_available`. Saved Wi-Fi intent remains visible even when the
respective executor is unavailable.

## Commit-confirm changes

Interface apply, AP and client configuration or provisioning, and saved AP or
client profile activation return:

```json
{
  "type": "network_change_pending",
  "change": {
    "token": "...",
    "interface": "wlan0",
    "rollback_timeout_seconds": 60,
    "expires_at_unix": 1760000060,
    "phase": "awaiting_commit",
    "last_error": null
  }
}
```

Choose the transaction endpoints from the apply response:

| Apply response `type` | Token field | Inspect pending state | Commit / rollback |
| --- | --- | --- | --- |
| `network_change_pending` | `change.token` | `GET /network-transactions` | `POST /network-transactions/commit` or `/network-transactions/rollback` |
| `router_transaction_pending` | `token` | `GET /router/pending` | `POST /router/commit` or `/router/rollback` |
| `router_provisioning_applied` | `token` | `GET /router/pending` | `POST /router/commit` or `/router/rollback` |

Complete router provisioning (`POST /router/provisioning/apply`) returns
`router_provisioning_applied` with `token` and `preview`; it uses the router
transaction endpoints. Despite the word `applied`, the change still needs
confirmation. All paths in the table are relative to `/api/v1`.

Send `{ "token": "<returned token>" }` to commit or roll back. A token cannot
confirm a later or different transaction. For network changes, `phase` is
`awaiting_commit`, `rollback_required`, `recovery_required`, or
`commit_indeterminate`. In `recovery_required` the bounded automatic recovery
cycle has stopped; inspect `recovery_progress` and explicitly request rollback
to retry. Device events do not resume a stopped recovery cycle. A new daemon
startup rechecks interface journals in a fresh bounded cycle; router recovery
retains its explicit retry requirement. The optional
`recovery_progress` contains `failure_kind`, `attempts`, `max_attempts`,
`deadline_unix`, `automatic_recovery`, and `last_error`; see
[bounded recovery](recovery.md#bounded-automatic-recovery). Commit is
available only in `awaiting_commit`; `commit_indeterminate` also blocks rollback
until storage is repaired and startup recovery resolves the outcome. See the
[recovery runbook](recovery.md#tm-rec-209).

`expires_at_unix` is for display. Rollback scheduling uses a monotonic clock,
and admitted operations can finish after that timestamp. A timeout or broken
connection does not prove that a mutation failed; inspect the matching pending
endpoint and current state before retrying. Never automatically retry a
mutation whose outcome is unknown.

DHCP client/server configuration and disable, and live AP/client passphrase
updates return `NetworkChangePending` and require network confirmation.
Standalone VPN enable/disable, connect/disconnect and Direct/VPN policy changes
return `RouterTransactionPending` and use the router commit/rollback endpoints.
Confirm Direct policy before disconnecting a protected tunnel. DHCP renew and
release-and-reacquire, Wi-Fi reconnect/reload and station deauthentication remain
immediate operational actions. Wi-Fi configuration, profile activation, and
operator-triggered AP/client deactivation on a present adapter require
confirmation even through non-provisioning endpoints. On an absent adapter
with a saved role, DELETE saves intent after verified cleanup and returns
`interface_intent_saved` without a token. Observation or cleanup failures leave
the previous intent intact; explicit offline endpoints require a revision.

## Secrets and operational safety

Treat passwords, bearer tokens, Wi-Fi passphrases, and imported WireGuard
profiles as secrets. Do not put them in URLs, process arguments, debug logs, or
recorded HTTP traces. AP and Wi-Fi client profile reads report whether a secret
exists but never return it.

Plan before apply where a plan endpoint exists. After applying a tentative
network change, verify connectivity and commit before the deadline. Keep a
local recovery path available when changing the management interface, routing,
firewall policy, Wi-Fi uplink, or HTTPS listener.

### Binding apply to a reviewed router plan

Router proposals accept optional `expected_revision` and `expected_fingerprint`.
`RouterPlan` returns `base_revision` and `observation_fingerprint`; send both back
with the same proposal when applying a reviewed plan. A changed committed revision
or observed snapshot rejects apply before effects. The coordinator also repeats
its snapshot validation under transaction ownership. TUI internet sharing uses
this protocol; clients omitting the optional expectations retain direct apply.
