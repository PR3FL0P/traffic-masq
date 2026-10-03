//! WireGuard profile parsing and Linux netlink operations.

mod provider;
mod wireguard;

pub use provider::{LazyNetlinkVpnProvider, NetlinkVpnProvider, ProviderError, VpnProvider};
pub use wireguard::{
    validate_wireguard_profile_name, ProfileError, WireGuardDriver, WireGuardEndpoint,
    WireGuardInterfaceConfig, WireGuardKey, WireGuardPeerConfig, WireGuardProfile,
};
