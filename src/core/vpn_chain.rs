//! The VPN hop chain: an ordered list of WireGuard hops between the router's
//! physical uplink and the LAN. Index 0 is closest to the uplink; only the
//! last hop protects LAN traffic (mark/route/killswitch), the rest merely
//! route their own tunnel's outbound traffic through the previous hop.

use serde::{Deserialize, Serialize};

use crate::core::vpn_policy::VpnPolicyReservedIds;
use crate::core::vpn_policy_manager::VpnPolicyDesired;

/// A route-only construct for a relay hop: "route my own tunnel's outbound
/// traffic through the previous hop's interface." No mark/killswitch —
/// relay hops don't protect LAN subnets, only their own tunnel's traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnHopRoutingDesired {
    /// This hop's own WireGuard interface (`tm-wg-<hop_index>`).
    pub hop_interface: String,
    /// The interface this hop's own outbound traffic should be routed
    /// through (the previous hop's interface, or the physical uplink for
    /// hop 0).
    pub upstream_interface: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VpnHopKind {
    /// Hops 0..N-2 of a chain of length N: route-only, no mark/killswitch.
    Relay { own_route: VpnHopRoutingDesired },
    /// The last hop: full mark/route/killswitch, exactly today's single-hop
    /// VPN policy mechanism.
    Exit { policy: VpnPolicyDesired },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnHopDesired {
    /// 0-based position in the chain; also used to derive `interface` and
    /// `reserved`.
    pub hop_index: u32,
    /// Which imported WireGuard profile drives this hop.
    pub profile_name: String,
    /// `tm-wg-<hop_index>`.
    pub interface: String,
    /// Hop 0: the real physical uplink interface name. Hop N>0: the
    /// previous hop's `interface`.
    pub upstream: String,
    pub reserved: VpnPolicyReservedIds,
    pub kind: VpnHopKind,
}

#[cfg(test)]
mod tests;
