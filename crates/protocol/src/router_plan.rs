//! Wire-level pieces of a router plan.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use crate::{
    DhcpServiceView, ForwardingConfigView, InterfaceChangePlanView, InterfaceConfigView,
    OwnedIpv4RouteConfigView, WifiApSpecView, WifiClientSpecView,
};

/// Kernel interface name assigned to one hop in a router VPN chain.
pub fn hop_interface_name(hop_index: u32) -> String {
    format!("tm-wg-{hop_index}")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RouterRiskView {
    pub changes_default_route: bool,
    pub requires_management_confirmation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum DhcpPlanView {
    Start {
        desired: DhcpServiceView,
    },
    Stop {
        current: DhcpServiceView,
    },
    Reconfigure {
        current: DhcpServiceView,
        desired: DhcpServiceView,
    },
    Unchanged {
        current: DhcpServiceView,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum WifiPlanView<T> {
    Start { desired: T },
    Stop { current: T },
    Reconfigure { current: T, desired: T },
    Unchanged { current: T },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv4RouteSpecView {
    pub destination: Ipv4Net,
    pub gateway: Option<Ipv4Addr>,
    pub output_interface_index: Option<u32>,
    pub table: u32,
    pub metric: Option<u32>,
    pub protocol: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv4RouteInfoView {
    pub destination: Ipv4Net,
    pub gateway: Option<Ipv4Addr>,
    pub output_interface_index: Option<u32>,
    pub table: u32,
    pub metric: Option<u32>,
    pub protocol: u8,
    pub scope: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutePlanView {
    pub add: Vec<Ipv4RouteSpecView>,
    pub delete: Vec<Ipv4RouteInfoView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterInterfaceDesiredView {
    pub name: String,
    pub config: InterfaceConfigView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpClientSpecView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    pub interface: String,
    pub route_metric: u32,
    pub install_default_route: bool,
    pub request_dns: bool,
    pub send_release_on_shutdown: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnPolicyReservedIdsView {
    pub route_table: u32,
    pub rule_priority_start: u32,
    pub rule_priority_end: u32,
    pub fw_mark: u32,
    pub fw_mask: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnHopRoutingDesiredView {
    pub hop_interface: String,
    pub upstream_interface: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnPolicyDesiredView {
    /// Standalone policy supplies NAT; router chains use explicit forwarding NAT instead.
    #[serde(default = "default_masquerade_forwarded")]
    pub masquerade_forwarded: bool,
    pub protected_subnets: Vec<Ipv4Net>,
    pub vpn_interface: String,
    pub physical_uplink: String,
    #[serde(default)]
    pub route_host_traffic: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VpnHopKindView {
    Relay { own_route: VpnHopRoutingDesiredView },
    Exit { policy: VpnPolicyDesiredView },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnHopDesiredView {
    pub hop_index: u32,
    pub profile_name: String,
    pub interface: String,
    pub upstream: String,
    pub reserved: VpnPolicyReservedIdsView,
    pub kind: VpnHopKindView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VpnChainPlanView {
    pub hops: Vec<VpnHopDesiredView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterDataplaneDesiredView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forwarding: Option<Vec<ForwardingConfigView>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_forwards: Vec<crate::PortForwardConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnedFirewallIntegrityView {
    Intact,
    Drifted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterDataplaneSnapshotView {
    pub ipv4_forwarding: bool,
    pub owned: Option<RouterDataplaneDesiredView>,
    pub owned_firewall_integrity: OwnedFirewallIntegrityView,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "desired", rename_all = "snake_case")]
pub enum RouterDataplaneTargetView {
    Enabled(RouterDataplaneDesiredView),
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterDataplanePlanView {
    pub snapshot: RouterDataplaneSnapshotView,
    pub target: RouterDataplaneTargetView,
    pub requires_apply: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterDesiredView {
    pub enabled: bool,
    pub uplink_wifi: Option<WifiClientSpecView>,
    pub uplink_dhcp: Option<DhcpClientSpecView>,
    pub output_wifi: Vec<WifiApSpecView>,
    pub dhcp: Vec<DhcpServiceView>,
    pub routes: Vec<OwnedIpv4RouteConfigView>,
    pub allow_default_route_change: bool,
    pub vpn_chain: Vec<VpnHopDesiredView>,
    pub dataplane: RouterDataplaneTargetView,
    pub interfaces: Vec<RouterInterfaceDesiredView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterPlanView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_fingerprint: Option<String>,
    pub desired: RouterDesiredView,
    pub interfaces: Vec<InterfaceChangePlanView>,
    pub uplink_wifi: Vec<WifiPlanView<WifiClientSpecView>>,
    pub output_wifi: Vec<WifiPlanView<WifiApSpecView>>,
    pub dhcp: Vec<DhcpPlanView>,
    pub routes: RoutePlanView,
    pub vpn_chain: VpnChainPlanView,
    pub dataplane: RouterDataplanePlanView,
    pub risk: RouterRiskView,
}

fn default_masquerade_forwarded() -> bool {
    true
}
