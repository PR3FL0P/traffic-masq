//! IPv4 DNAT intent shared by configuration, API and editors.
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortForwardProtocol {
    Tcp,
    Udp,
}

impl PortForwardProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortForwardConfig {
    pub from: String,
    pub to: String,
    pub protocol: PortForwardProtocol,
    pub external_port: u16,
    pub target_address: Ipv4Addr,
    pub target_port: u16,
    /// None matches any local IPv4 destination on the router.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_address: Option<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_subnet: Option<Ipv4Net>,
}

fn unicast(address: Ipv4Addr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_multicast()
        && !address.is_broadcast()
        && !address.is_link_local()
        && address.octets()[0] != 0
        && address.octets()[0] < 240
}

pub fn validate_port_forwards(rules: &[PortForwardConfig]) -> Result<(), String> {
    for (index, rule) in rules.iter().enumerate() {
        crate::validate_interface_name(&rule.from)?;
        crate::validate_interface_name(&rule.to)?;
        if rule.from == rule.to {
            return Err("port forwarding requires different ingress and egress interfaces; hairpin NAT is not supported".into());
        }
        if rule.external_port == 0 || rule.target_port == 0 {
            return Err("port forwarding ports must be in 1..=65535".into());
        }
        if !unicast(rule.target_address) || rule.destination_address.is_some_and(|ip| !unicast(ip))
        {
            return Err("port forwarding requires unicast IPv4 addresses".into());
        }
        if rule.source_subnet.is_some_and(|net| net != net.trunc()) {
            return Err("port forwarding source subnet must have no host bits".into());
        }
        if rules[..index].iter().any(|prior| {
            prior.from == rule.from
                && prior.protocol == rule.protocol
                && prior.external_port == rule.external_port
                && match (prior.destination_address, rule.destination_address) {
                    (Some(a), Some(b)) => a == b,
                    _ => true,
                }
                && match (prior.source_subnet, rule.source_subnet) {
                    (Some(a), Some(b)) => a.contains(&b.addr()) || b.contains(&a.addr()),
                    _ => true,
                }
        }) {
            return Err(format!(
                "overlapping port forward on {} {} port {}",
                rule.from,
                rule.protocol.as_str(),
                rule.external_port
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rule() -> PortForwardConfig {
        PortForwardConfig {
            from: "wan0".into(),
            to: "lan0".into(),
            protocol: PortForwardProtocol::Tcp,
            external_port: 8443,
            target_address: "192.168.10.20".parse().unwrap(),
            target_port: 443,
            destination_address: None,
            source_subnet: None,
        }
    }
    #[test]
    fn rejects_ambiguous_mappings_but_allows_disjoint_sources_and_protocols() {
        let a = rule();
        let mut b = a.clone();
        b.target_port = 444;
        assert!(validate_port_forwards(&[a.clone(), b.clone()]).is_err());
        b.protocol = PortForwardProtocol::Udp;
        assert!(validate_port_forwards(&[a.clone(), b]).is_ok());
        let mut b = a.clone();
        b.source_subnet = Some("192.0.2.0/24".parse().unwrap());
        assert!(validate_port_forwards(&[a.clone(), b.clone()]).is_err());
        let mut a = a;
        a.source_subnet = Some("198.51.100.0/24".parse().unwrap());
        assert!(validate_port_forwards(&[a, b]).is_ok());
    }
    #[test]
    fn rejects_invalid_ports_addresses_interfaces_and_networks() {
        for ip in [
            "0.0.0.0",
            "127.0.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "169.254.1.2",
        ] {
            let mut r = rule();
            r.target_address = ip.parse().unwrap();
            assert!(validate_port_forwards(&[r]).is_err(), "{ip}");
        }
        let mut r = rule();
        r.external_port = 0;
        assert!(validate_port_forwards(&[r]).is_err());
        let mut r = rule();
        r.to = r.from.clone();
        assert!(validate_port_forwards(&[r]).is_err());
        let mut r = rule();
        r.from = "bad\"name".into();
        assert!(validate_port_forwards(&[r]).is_err());
        let mut r = rule();
        r.source_subnet = Some("192.0.2.1/24".parse().unwrap());
        assert!(validate_port_forwards(&[r]).is_err());
    }
}
