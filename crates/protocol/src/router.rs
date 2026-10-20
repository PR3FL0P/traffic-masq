//! Router proposal payloads shared by the client and daemon.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use crate::{InterfaceConfigView, PortForwardConfig, UplinkMode};

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceOverrideRequestView {
    pub config: InterfaceConfigView,
    #[serde(default)]
    pub allow_management_change: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouterProposalRequestView {
    #[serde(default)]
    pub set_router: Option<RouterConfigView>,
    #[serde(default)]
    pub clear_router: bool,
    #[serde(default)]
    pub set_interfaces: BTreeMap<String, InterfaceOverrideRequestView>,
    #[serde(default)]
    pub remove_interfaces: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct RouterConfigView {
    pub uplink: Option<UplinkConfigView>,
    pub forwarding: Option<Vec<ForwardingConfigView>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_forwards: Vec<PortForwardConfig>,
    pub owned_routes: Vec<OwnedIpv4RouteConfigView>,
    pub allow_default_route_change: bool,
    #[serde(default)]
    pub vpn_chain: Vec<VpnHopConfigView>,
    /// Route the router's own traffic through the VPN chain (with kill switch).
    #[serde(default)]
    pub route_host_traffic: bool,
}

impl RouterConfigView {
    pub fn is_active(&self) -> bool {
        self.uplink.is_some()
            || self
                .forwarding
                .as_ref()
                .is_some_and(|rules| !rules.is_empty())
            || !self.port_forwards.is_empty()
            || !self.owned_routes.is_empty()
            || !self.vpn_chain.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UplinkConfigView {
    pub interface: String,
    pub mode: UplinkMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardingConfigView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_subnet: Option<Ipv4Net>,
    pub from: String,
    pub to: String,
    #[serde(default = "default_true")]
    pub masquerade: bool,
}

pub trait ForwardingRule {
    fn source_subnet(&self) -> Option<Ipv4Net>;
    fn ingress_interface(&self) -> &str;
    fn egress_interface(&self) -> &str;
}

impl ForwardingRule for ForwardingConfigView {
    fn source_subnet(&self) -> Option<Ipv4Net> {
        self.source_subnet
    }

    fn ingress_interface(&self) -> &str {
        &self.from
    }

    fn egress_interface(&self) -> &str {
        &self.to
    }
}

/// Validate forwarding intent before it is submitted to the daemon.
pub fn validate_forwarding<R: ForwardingRule>(rules: &[R]) -> Result<(), String> {
    for (index, rule) in rules.iter().enumerate() {
        validate_interface_name(rule.ingress_interface())?;
        validate_interface_name(rule.egress_interface())?;
        if rule.ingress_interface() == rule.egress_interface() {
            return Err("forwarding requires different ingress and egress interfaces".into());
        }
        if rule
            .source_subnet()
            .is_some_and(|subnet| subnet != subnet.trunc())
        {
            return Err("source subnet must be a network address (no host bits)".into());
        }
        if rules[..index].iter().any(|prior| {
            prior.ingress_interface() == rule.ingress_interface()
                && prior.egress_interface() == rule.egress_interface()
                && match (prior.source_subnet(), rule.source_subnet()) {
                    (Some(a), Some(b)) => a.contains(&b.addr()) || b.contains(&a.addr()),
                    _ => true,
                }
        }) {
            return Err(format!(
                "duplicate or overlapping forwarding connection: {} -> {}",
                rule.ingress_interface(),
                rule.egress_interface()
            ));
        }
    }
    Ok(())
}

pub fn validate_interface_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("interface name cannot be empty".into());
    }
    if name.len() > 15 {
        return Err("interface name exceeds Linux IFNAMSIZ limit".into());
    }
    if !name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.'))
    {
        return Err("interface name contains unsupported characters".into());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedIpv4RouteConfigView {
    pub destination: Ipv4Net,
    pub gateway: Option<Ipv4Addr>,
    pub output_interface: Option<String>,
    pub table: u32,
    pub metric: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnHopConfigView {
    pub profile_name: String,
}
