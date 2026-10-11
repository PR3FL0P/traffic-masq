# External resource conflicts and diagnostic coverage

This is an audit of the resource boundaries used by traffic-masq, not a guarantee
that every kernel failure is caused by competing software. Diagnostics observe
host state and suggest operator actions; they do not stop an unowned process,
unblock radios, or replace foreign network objects. Suggested commands are not
executed by the diagnostic code. Existing ownership-checked cleanup and rollback
remain responsible for the daemon's own resources.

## Evidence rules

* A running NetworkManager, networkd, ConnMan, dhcpcd or similar process is a
  candidate, not proof that it owns an interface, route or socket.
* Socket inode-to-FD correlation confirms a holding PID at observation time.
  A systemd cgroup may identify its service. PID reuse, process exits, namespaces
  and restricted `/proc` access limit this evidence.
* `/proc/locks` identifies the holder of a specific device/inode lock. PID-file
  contents alone do not establish ownership. Waiting lock requests are excluded.
* Kernel address/route protocols, WireGuard aliases and nftables comments are
  compared with persisted ownership proofs. They do not identify the original
  process. Unknown ownership must remain unknown in messages.
* Preflight is a snapshot, not a reservation. Mutations can still fail after a
  successful check. Preserve the underlying error chain and rollback evidence.

## Coverage matrix

| Resource / invariant | Guard and observation | User diagnostic / manual action | Limits |
| --- | --- | --- | --- |
| DHCP lease IPv4 address: preserve foreign addresses | `dhcp/client/ownership.rs`, kernel address tags and persisted lease | Interface/address conflict; inspect `ip -4 -details addr`, reconfigure the originating manager | No authoritative creator PID; static interface edits follow their separate ownership journal and explicit management policy |
| Routes: preserve foreign routes with the same destination/table/metric | DHCP ownership preflight and reread after failed add; `core/route.rs` | Wanted/existing route, gateway, interface, metric, protocol; choose an unused metric or release the originating configuration | Exact object comparison, not attribution to a manager; post-check races remain possible |
| VPN policy rules/routes: preserve foreign policy | `core/vpn_policy_manager.rs`, `vpn_policy.rs` conflicting objects | Observed rules/routes; inspect `ip -4 rule show` / `ip -4 route show table all` and reconfigure the policy owner | Kernel state does not retain installer PID |
| WireGuard link: require durable launch proof | `vpn/manager.rs`, ownership record and observed interface | Foreign interface or failed ownership proof; inspect `ip -details link` / `wg show`, resolve verified owner manually | Name or link kind alone does not grant ownership; UDP WireGuard endpoint collisions retain backend errors rather than socket PID diagnostics |
| hostapd / wpa_supplicant control endpoint: prove ownership before use/stop | Wi-Fi lifecycle and supervisors; `wifi/process/conflict.rs`, exact Unix socket path and inode/FD correlation | Confirmed PID, executable/service when available, exact socket path, candidate managers and manual service/interface release | Socket file inode differs from kernel socket inode; no PID means unknown ownership, not proof that NetworkManager owns it |
| Orphan Wi-Fi control socket file: no unverified unlink | Socket lstat and exact `/proc/net/unix` observation | When a socket file appears stale, stop daemon, verify exact path with `ss`, then remove it manually and retry | Incomplete observations do not justify stale-file advice; diagnostics never unlink it |
| DHCP server UDP port: do not coexist with foreign listener via reuse | `dhcp/runtime.rs`, host-observation `ports.rs` | Overlapping IPv4 address/port and confirmed PID/service; change listen address or release verified service manually | IPv6 wildcard/mapped sockets are candidates, since `/proc` omits `IPV6_V6ONLY`; bind failure preserves errno; DHCP client's packet transport has different semantics |
| HTTPS TCP bind | `api/server.rs`, host-observation TCP/TCP6 listeners | Failed address/port bind with PID/service candidates and `ss -ltnp`; configure listener/owner manually | Observe on `AddrInUse`; permission/address errors are reported separately; IPv6 dual-stack overlap is only a candidate |
| Local HTTP API Unix socket | `api/server.rs`, file type/identity and connection check | Active endpoint: exact path and manual `ss`/process inspection, choose another socket path | No automatic PID enrichment here; existing stale API socket cleanup requires connection refusal and unchanged file identity, unlike unowned Wi-Fi endpoints |
| Daemon, startup-attempt and service-install file locks | `app/process.rs`, `app/service.rs`, `app/init/store.rs`; `/proc/locks` device/inode | Confirmed holder PID when visible; wait or stop its verified service; never unlink a held lock | OFD locks may have no PID; permissions/namespace/exit can hide a holder; original I/O cause retained |
| Service unit/script/activation path: replace only proven artifacts | `app/init/store.rs`, exact content/receipt and symlink-target checks | Exact conflicting path, compare receipt/contents or inspect target; resolve installation manually | Edited files are not automatically attributed to a process |
| AP/STA same physical radio admission | `wifi/policy.rs`, shared PHY policy | Conflicting interfaces/PHY; inspect `iw dev`, disable one role or use another physical radio | Policy covers traffic-masq's requested roles; it does not enumerate all external nl80211 virtual interfaces |
| rfkill radio block | `wifi/process/rfkill.rs`, exact interface PHY-to-rfkill device match; AP/STA configure/spawn and scan | Block index, hard/soft state; hardware switch/firmware for hard block, manual `rfkill unblock` for soft block | No setter PID in sysfs; missing/unreadable sysfs or unmatched platform-wide kill switch is not declared unblocked; existing sessions can be blocked after preflight |
| nftables owned structure/metadata | Dataplane ownership metadata validation and drift detection | Inspect exact owned table and persisted metadata; manually reconcile competing firewall writer | nftables does not retain writer PID; unrelated foreign chains can drop traffic without violating owned-table shape |
| Forwarding / dataplane drift | Router subsystem health and convergence | Inspect `sysctl net.ipv4.ip_forward` / `nft list ruleset`, reconfigure competing policy | Existing convergence repairs managed desired state; global sysctl does not expose an exclusive owner or setter PID |
| State, recovery journals, secrets and ownership records | `core/recovery.rs`, private/atomic stores; stable recovery codes | Recovery code, invariant, path/operation and preservation guidance in [recovery runbook](recovery.md) | Corruption, permissions, read-only filesystems and failed fsync are not proof of a foreign manager; not every non-recovery store error has per-path enrichment |
| Link state, MAC, addresses and netlink mutation permission | Netlink adapter operation/object context and source error chain; interface transaction rollback | Kernel errno and operation/interface/object identify failed mutation; inspect interface and daemon privileges | No general exclusive link ownership in Linux; missing capabilities, device removal and driver errors cannot be reliably attributed to a manager |
| Internal transaction/radio/runtime reservations | Mutation and transaction coordinators | Busy, recovery-gated or indeterminate operation diagnostics | Internal serialization is not an external file/socket owner; do not advise stopping a network manager |

## Releasing a Wi-Fi interface and checking a stale socket

traffic-masq records the control socket's device/inode once ownership is proven,
before waiting for a successful readiness reply. After stopping an owned process,
it removes a matching inactive socket before clearing the ownership record. Failed
cleanup retains the record for recovery; active or replaced sockets are preserved.
Manual cleanup below is for endpoints whose ownership cannot be established,
including files left by earlier versions without a usable record.

When a Wi-Fi ownership error lists NetworkManager, inspect the specific interface:

```sh
nmcli -f GENERAL.STATE,GENERAL.REASON,GENERAL.NM-MANAGED device show wlan0
rfkill list
ip link show wlan0
```

`GENERAL.NM-MANAGED: yes` confirms that NetworkManager manages this interface.
`STATE: unavailable` does not mean unmanaged. `REASON: Device is now managed`
describes a transition, not the cause of Wi-Fi unavailability. The rfkill output
shows radio blocks; link `UP` alone does not establish an access-point connection.
None of these observations proves that NetworkManager holds the conflicting socket.

If `wlan0` should be managed by traffic-masq, release only that interface:

```sh
sudo nmcli device set wlan0 managed no
nmcli -f GENERAL.NM-MANAGED device show wlan0
```

Confirm `GENERAL.NM-MANAGED: no` before retrying. This can disconnect Wi-Fi on
`wlan0`; use another connection when administering the machine remotely.
To return the interface to NetworkManager, run
`sudo nmcli device set wlan0 managed yes`.

If the error also reports a stale socket, its file may have survived the exit of
wpa_supplicant. Stop the daemon and inspect the exact path reported in the error:

```sh
sudo systemctl stop traffic-masqd
sudo ss -xap
```

Only if no process uses `/run/traffic-masq/wpa_supplicant/wlan0`, remove that
single file and restart:

```sh
sudo rm -- '/run/traffic-masq/wpa_supplicant/wlan0'
sudo systemctl start traffic-masqd
```

If a process holds the socket, inspect its PID/service instead of removing the
file. Then retry the interface change. A log saying that the daemon is restoring
the previous configuration reports the start of rollback, not its completion.

## Boundaries of the audit

There is no single authoritative registry of network-manager ownership in Linux.
Continuous external rewrites, LSM/seccomp restrictions, namespace differences,
platform-wide radio blocks and rules outside the daemon-owned firewall table
cannot all be turned into a confirmed owner PID. Those cases retain raw error
or recovery evidence and require manual inspection. The project therefore has
resource-specific guards and diagnostics, rather than a claim of exhaustive
foreign-software detection.

No new runtime dependencies are required for this observation. `/proc` and
`/sys` are read directly. `ss`, `ps`, `lslocks`, `nmcli`, `rfkill`, `ip`, `wg`,
`nft` and `systemctl` in messages are optional operator tools, not newly spawned
helpers. Service advice is conditional on observed service evidence.

## Validation expectations

For each new conflict boundary, test a proven foreign owner, unknown owner and
non-conflicting state where meaningful. Assert that refused operations preserve
foreign resources. Include read failures, unrelated interfaces/ports and
address-family differences; avoid deriving process identity from a name alone.

The diagnostic tests use fixture `/proc` trees, a dropped Unix datagram socket,
real file-lock contention and a real occupied DHCP bind. The rfkill tests use a
fixture sysfs with two PHYs and verify that observed hard/soft blocks are not
modified. Hardware-dependent races and cross-namespace observations are not
covered by these unit tests.
