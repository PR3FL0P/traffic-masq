# HTTP API

`traffic-masqd` exposes a versioned JSON API for the terminal client and other
local automation. Version 1 is mounted at `/api/v1` and is served over the Unix
socket configured by `runtime.socket_path` (default
`/run/traffic-masq/traffic-masqd.sock`). Optional remote access uses HTTPS; the
daemon never exposes an unencrypted TCP listener.

The API is currently intended to be used together with the same release of the
daemon. Additive fields and response variants may appear within version 1, so
clients should ignore unknown object fields and handle unknown `type` values.
Request bodies are limited to 64 KiB.

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
Authentication and HTTP-layer failures use an untagged error body:

```json
{ "error": "authentication required" }
```

Common statuses are `400` for an invalid authentication request, `401` for a
missing, invalid or expired session, `403` for insufficient access, `409` when
the password is already initialized, `413` for an oversized body, `422` for
malformed JSON, `429` for authentication throttling, and `500` for an internal
authentication/server failure. Domain validation failures inside authenticated
control requests use a typed response.

Path parameters such as `{interface}`, `{id}`, `{name}`, and `{mac}` must be
percent-encoded as URL path segments.

## Endpoint reference

Body names in the tables refer to the [request schemas](#request-schemas).
`—` means that no request body is required.

### Service, authentication, and settings

| Method | Path | Body | Result or purpose | Access |
| --- | --- | --- | --- | --- |
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
| `PUT` | `/dhcp/{interface}` | `DhcpInterfaceConfig` | Configure DHCP server immediately | Administrator |
| `DELETE` | `/dhcp/{interface}` | — | Disable DHCP server immediately | Administrator |
| `PUT` | `/dhcp/{interface}/settings` | `DhcpEdit` | Configure DHCP through the edit model | Administrator |
| `GET` | `/dhcp/{interface}/leases` | — | Active leases | Authenticated |
| `GET` | `/dhcp-client` | — | DHCP client status for all configured interfaces | Authenticated |
| `GET` | `/dhcp-client/{interface}` | — | One DHCP client status | Authenticated |
| `PUT` | `/dhcp-client/{interface}` | `DhcpClientConfig` | Configure DHCP client immediately | Administrator |
| `DELETE` | `/dhcp-client/{interface}` | — | Disable DHCP client immediately | Administrator |
| `POST` | `/dhcp-client/{interface}/renew` | — | Renew the lease | Administrator |
| `POST` | `/dhcp-client/{interface}/release` | — | Release the lease | Administrator |
| `GET` | `/routes?include_local_table=false` | — | Observed IPv4 routes; local table is excluded by default | Authenticated |

### Router and provisioning

| Method | Path | Body | Result or purpose | Access |
| --- | --- | --- | --- | --- |
| `GET` | `/router/config` | — | Effective router configuration | Authenticated |
| `GET` | `/router/status` | — | Readiness, coordinator and recovery state | Authenticated |
| `POST` | `/router/plan` | `RouterProposal` | Build a plan without applying it | Authenticated |
| `POST` | `/router/apply` | `RouterProposal` | Tentatively apply and return a token | Administrator |
| `POST` | `/router/commit` | `Transaction` | Commit the router transaction | Administrator |
| `POST` | `/router/rollback` | `Transaction` | Roll back the router transaction | Administrator |
| `GET` | `/router/pending` | — | Pending token and recovery state | Authenticated |
| `POST` | `/router/provisioning/preview` | `RouterProvisioningPreview` | Preview Wi-Fi uplink/AP router setup | Authenticated |
| `POST` | `/router/provisioning/apply` | `RouterProvisioningApply` | Tentatively apply the complete setup | Administrator |
| `GET` | `/router/provisioning/status` | — | Provisioning readiness and failures | Authenticated |
| `POST` | `/router/provisioning/repair` | — | Retry repair after a degraded rollback | Administrator |

Router transactions and interface/network transactions have separate commit
endpoints. Use the endpoint corresponding to the apply response.

### VPN

| Method | Path | Body | Result or purpose | Access |
| --- | --- | --- | --- | --- |
| `GET` | `/vpn/profiles` | — | List WireGuard profile metadata | Authenticated |
| `POST` | `/vpn/profiles` | `{ "name": string, "contents": string }` | Import a WireGuard configuration | Administrator |
| `DELETE` | `/vpn/profiles/{name}` | — | Delete an inactive profile | Administrator |
| `GET` | `/vpn/config` | — | Whether the VPN subsystem is enabled | Authenticated |
| `PUT` | `/vpn/config` | `{ "enabled": bool }` | Save enabled override | Administrator |
| `GET` | `/vpn/status` | — | Active profile/interface, if any | Authenticated |
| `POST` | `/vpn/activate` | `{ "name": string }` | Activate a profile immediately | Administrator |
| `POST` | `/vpn/deactivate` | — | Deactivate the current profile | Administrator |
| `GET` | `/vpn-policy/status` | — | Policy mode, tunnel health and protected subnets | Authenticated |
| `PUT` | `/vpn-policy/mode` | `{ "mode": "direct" | "vpn" }` | Set runtime policy override | Administrator |
| `DELETE` | `/vpn-policy/mode` | — | Clear policy override | Administrator |

### Wi-Fi access point

| Method | Path | Body | Result or purpose | Access |
| --- | --- | --- | --- | --- |
| `GET` | `/wifi` | — | AP runtime status | Authenticated |
| `GET` | `/wifi/{interface}` | — | AP specification | Authenticated |
| `PUT` | `/wifi/{interface}` | `WifiEdit` | Tentatively configure AP; secret is separate | Administrator |
| `DELETE` | `/wifi/{interface}` | — | Disable AP immediately | Administrator |
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
| `DELETE` | `/wifi-client/{interface}` | — | Disable client immediately | Administrator |
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
| `DELETE` | `/wifi-client/{interface}/active-profile` | — | Deactivate the current profile | Administrator |

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
    "wifi_client": null,
    "nat": true
  },
  "allow_management_change": false
}
```

Roles are `none`, `input`, `output`, `middle`, and the legacy `disabled`.
`management` is accepted as an alias for `none`. Nested configuration objects
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

```json
{
  "route_metric": 100,
  "install_default_route": true,
  "request_dns": true,
  "send_release_on_shutdown": false
}
```

`RouterProposal`

```json
{
  "set_router": {
    "enabled": true,
    "uplink": null,
    "forwarding": [
      { "from": "lan0", "to": "wan0", "masquerade": true }
    ],
    "owned_routes": [],
    "allow_default_route_change": false,
    "vpn_chain": []
  },
  "clear_router": false,
  "set_interfaces": {},
  "remove_interfaces": []
}
```

Each `set_interfaces` value has the `InterfaceChange` shape. Omitted proposal
fields default to `null`, `false`, or an empty collection. `set_router` and
`clear_router` are mutually exclusive.

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
  "subnet": "192.168.50.0/24",
  "disable_dhcp": false
}
```

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
  "subnet": "192.168.60.0/24"
}
```

`WifiClientEdit`

```json
{ "ssid": "Upstream", "country_code": "UA", "security": "wpa2" }
```

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
`awaiting_commit`, `rollback_required`, or `commit_indeterminate`. Commit is
available only in `awaiting_commit`; `commit_indeterminate` also blocks rollback
until storage is repaired and startup recovery resolves the outcome. See the
[recovery runbook](recovery.md#tm-rec-209).

`expires_at_unix` is for display. Rollback scheduling uses a monotonic clock,
and admitted operations can finish after that timestamp. A timeout or broken
connection does not prove that a mutation failed; inspect the matching pending
endpoint and current state before retrying. Never automatically retry a
mutation whose outcome is unknown.

DHCP and VPN controls, Wi-Fi deactivation, passphrase updates, and runtime
controls such as reconnect and reload still apply immediately. Their successful
responses do not require a commit. Wi-Fi configuration and profile activation
require confirmation even when called through the non-provisioning endpoints.

## Secrets and operational safety

Treat passwords, bearer tokens, Wi-Fi passphrases, and imported WireGuard
profiles as secrets. Do not put them in URLs, process arguments, debug logs, or
recorded HTTP traces. AP and Wi-Fi client profile reads report whether a secret
exists but never return it.

Plan before apply where a plan endpoint exists. After applying a tentative
network change, verify connectivity and commit before the deadline. Keep a
local recovery path available when changing the management interface, routing,
firewall policy, Wi-Fi uplink, or HTTPS listener.
