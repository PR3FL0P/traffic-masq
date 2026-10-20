# VPN and Route: current architecture and UI contract

This document describes the existing daemon boundaries used by the VPN UI.
Moving a control between screens does not change its API or execution model.

## Dependencies and ownership

| Resource | Dependencies | Owner and application path |
| --- | --- | --- |
| Saved WireGuard profile | Profile store, valid profile contents | VPN library; import/delete apply immediately |
| Standalone tunnel | Enabled VPN, saved profile, available owned `tm-wg0` | `VpnManager`; `VpnActivate` / `VpnDeactivate` apply immediately |
| Standalone traffic policy | Enabled VPN, global uplink, managed Output IPv4 subnets, externally managed forwarding; VPN mode additionally needs a healthy standalone interface | `VpnPolicyManager`; immediate Direct/VPN override, separate from router drafts |
| Global VPN chain | Enabled VPN, physical uplink, saved profiles; LAN traffic needs explicit forwarding rules | Router coordinator; shared draft, plan, apply, confirmation, rollback |
| Router's own traffic through VPN | Configured global chain and `route_host_traffic` | Router coordinator; exit policy includes kill switch and IPv6 egress blocking |
| VPN enabled setting | VPN control plane; disabling requires no saved chain, Direct effective policy, and no standalone active record | Persisted subsystem availability; not a disconnect-all operation |

Implementation references:

- [Control API](../src/api/control/vpn.rs), including profile-reference checks,
  disabling prerequisites and policy coexistence guards.
- [VPN manager](../src/vpn/manager.rs), including ownership evidence,
  activation intents, per-interface state and recovery.
- [Chain derivation](../src/core/router.rs) and
  [chain execution](../src/core/router_subsystems/vpn_chain.rs).
- [Standalone policy derivation](../src/core/vpn_policy_manager.rs).
- [Router configuration validation](../src/config/mod.rs).
- [Request admission and recovery gates](../src/api/control/dispatch.rs).

The standalone tunnel uses `tm-wg0`. Chain interfaces use `tm-wg-<index>`;
per-hop managers keep distinct durable ownership records. The same profile
library supplies both paths. A profile is configuration, not a unique runtime
connection. Standalone status is not an inventory of chain interfaces.

There is one ordered global chain, with at most eight hops. The first hop is
closest to the physical uplink. Relay hops route subsequent tunnels through
preceding hops; the exit hop applies protected-subnet policy and the kill switch.
The chain editor preserves explicit forwarding rules. Uplink and chain configuration
do not add forwarding or NAT permissions; configure those in Internet sharing. External uplinks
must be unmanaged Input interfaces; DHCP uplinks require managed Input interfaces
with an enabled DHCP client. Validation remains authoritative in the daemon.

The route model stores destination, gateway, output interface, table and metric.
It does not associate routes with profile names or expose named selectable chains.
The standalone policy derives protected subnets from managed Output interfaces;
it is not an arbitrary per-flow traffic selector. This standalone policy overlays
forwarding managed outside traffic-masq. It does not enable IPv4 forwarding or
create direct-mode NAT rules, and cannot coexist with daemon-managed explicit
forwarding in VPN mode.

## Guarantees preserved by the UI

1. Opening a profile does not activate it. The card pins its name, so list
   refreshes cannot silently retarget profile actions or deletion confirmation.
2. Standalone connect/disconnect only operates on `tm-wg0`. Selecting another
   profile never implicitly disconnects or replaces the active profile. Profiles
   in the saved chain direct the operator to Route. A separately active standalone
   instance can still be disconnected through its own profile.
3. Chain edits continue through the existing Uplink / VPN editor and shared Route
   draft. The existing plan, confirmation deadline, rollback and recovery flow
   remain in force. Navigating from a profile to Route preserves a staged draft.
4. Import and deletion retain daemon validation and reference protection.
   Referenced saved-chain profiles cannot be replaced/deleted through the API;
   standalone active-profile protection remains in the manager. The UI also
   prevents deletion of a profile referenced by its unapplied local Route draft.
   Deletion still requires confirmation of the pinned original name.
5. Standalone policy stays an immediate operation, even though its entry point
   is now in Route. It is labelled accordingly and is unavailable when a saved
   global chain exists. The API remains responsible for coexistence and recovery
   gates; the TUI does not combine policy calls into a router transaction.
   Direct VPN mutations require administrator authorization, pass shared network
   admission/execution gates, and are blocked by pending interface/router
   transactions or unresolved recovery state.
6. VPN settings retain the daemon's disabling prerequisites. Disabling does not
   delete saved profiles. Production startup builds the profile control plane
   while disabled, so the library remains available; an unavailable runtime or
   failed read is displayed as unavailable rather than an empty library.
7. Reads are separate observations, not an atomic network snapshot. Failed reads
   preserve useful partial data but invalidate current standalone status and saved
   chain usage. An uncertain connect/disconnect result requires a successful status
   refresh before another standalone mutation. Selection survives refresh by name.
8. Saved chain membership, unapplied draft membership, and observed standalone
   interface state have distinct labels. Interface up does not prove a WireGuard
   handshake, working connectivity, or enforced traffic protection. Chain health
   belongs to Route; profile rows never infer it from saved configuration.
9. Profile cards and lists use only API summaries. Opening a profile does not read
   or display private keys. Local-file import retains its existing secret handling.

## Limits of these guarantees

The UI's reference and freshness checks are advisory between requests; the daemon
owns validation and mutation serialization. Another client can change configuration
between observations. In particular, `VpnDeactivate` has no expected-profile
argument: a different client's replacement of the standalone tunnel between a
status read and disconnect is not atomically excluded by the UI. An unavailable
saved-chain read cannot establish non-use.
A local draft exists only in this TUI and is not known to other clients.

Standalone operations do not gain a commit timer by moving their controls. Their
existing persistence, compensation and ownership-recovery mechanisms remain in
place. A failed rollback or ambiguous persistence outcome is not reported as
successful recovery. These UI changes do not provide an atomic transaction spanning
profile import, standalone activation, policy changes and router changes.
