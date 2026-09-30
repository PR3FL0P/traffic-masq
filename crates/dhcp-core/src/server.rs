use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

use crate::lease::LeaseManager;
use crate::packet::{DhcpMessageType, DhcpPacket, DHCP_FIXED_HEADER_LEN, DHCP_MAGIC_COOKIE};

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpServerConfig {
    pub server_ip: Ipv4Addr,
    pub router: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub dns_servers: Vec<Ipv4Addr>,
}

#[derive(Debug, Clone)]
pub struct DhcpHandler {
    config: DhcpServerConfig,
    leases: LeaseManager,
}

impl DhcpHandler {
    pub fn new(config: DhcpServerConfig, leases: LeaseManager) -> Self {
        Self { config, leases }
    }

    pub fn lease_snapshot(&self) -> Vec<crate::lease::DhcpLease> {
        self.leases.snapshot()
    }

    /// Parse a DHCP request and update lease state, returning an optional encoded reply.
    /// DISCOVER offers a lease, REQUEST acknowledges or rejects it, and RELEASE/DECLINE produce no reply.
    pub fn handle_packet(&mut self, input: &[u8]) -> Result<Option<Vec<u8>>> {
        let request = DhcpPacket::parse(input)?;
        let mac = client_mac(&request)?;

        match request.message_type() {
            Some(DhcpMessageType::Discover) => {
                let lease = self.leases.allocate(mac, request.requested_ip())?;
                self.offer_or_ack(&request, DhcpMessageType::Offer, lease.ip)
            }
            Some(DhcpMessageType::Request) => self.handle_request(&request, mac),
            Some(DhcpMessageType::Decline) => {
                if let Some(declined) = request.requested_ip().or_else(|| self.leased_ip(mac)) {
                    self.leases.decline(mac, declined, now_unix());
                }
                Ok(None)
            }
            Some(DhcpMessageType::Release) => {
                self.leases.release(mac);
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    /// Ignore requests selecting another server; ACK an available requested address or return NAK.
    fn handle_request(
        &mut self,
        request: &DhcpPacket<'_>,
        mac: [u8; 6],
    ) -> Result<Option<Vec<u8>>> {
        if let Some(selected) = request.server_identifier() {
            if selected != self.config.server_ip {
                self.leases.release(mac);
                return Ok(None);
            }
        }

        let Some(requested_ip) = request
            .requested_ip()
            .or_else(|| (!request.ciaddr.is_unspecified()).then_some(request.ciaddr))
        else {
            return Ok(Some(build_nak(request, &self.config)?));
        };

        match self.leases.allocate_exact(mac, requested_ip) {
            Ok(lease) => self.offer_or_ack(request, DhcpMessageType::Ack, lease.ip),
            Err(_) => Ok(Some(build_nak(request, &self.config)?)),
        }
    }

    fn offer_or_ack(
        &self,
        request: &DhcpPacket<'_>,
        message_type: DhcpMessageType,
        yiaddr: Ipv4Addr,
    ) -> Result<Option<Vec<u8>>> {
        let lease_seconds = u32::try_from(self.leases.lease_time().as_secs())
            .context("DHCP lease time does not fit in the option 51 field")?;
        Ok(Some(build_response(
            request,
            message_type,
            yiaddr,
            &self.config,
            lease_seconds,
        )?))
    }

    fn leased_ip(&self, mac: [u8; 6]) -> Option<Ipv4Addr> {
        self.leases
            .leases()
            .find(|lease| lease.mac == mac)
            .map(|lease| lease.ip)
    }
}

/// Extract the client MAC only for Ethernet packets with a six-byte hardware address.
fn client_mac(packet: &DhcpPacket<'_>) -> Result<[u8; 6]> {
    if packet.htype != 1 || packet.hlen != 6 {
        bail!(
            "unsupported DHCP hardware type/length: htype={}, hlen={}",
            packet.htype,
            packet.hlen
        );
    }

    let mut mac = [0_u8; 6];
    mac.copy_from_slice(&packet.chaddr[..6]);
    Ok(mac)
}

/// Encode an OFFER or ACK with server, lease, subnet, gateway, and DNS options.
fn build_response(
    request: &DhcpPacket<'_>,
    message_type: DhcpMessageType,
    yiaddr: Ipv4Addr,
    config: &DhcpServerConfig,
    lease_time_seconds: u32,
) -> Result<Vec<u8>> {
    let mut response = build_base_response(request, yiaddr, config.server_ip);

    push_option(&mut response, 53, &[message_type.as_u8()])?;
    push_option(&mut response, 54, &config.server_ip.octets())?;
    push_option(&mut response, 51, &lease_time_seconds.to_be_bytes())?;
    push_option(&mut response, 1, &config.subnet_mask.octets())?;
    push_option(&mut response, 3, &config.router.octets())?;

    if !config.dns_servers.is_empty() {
        let mut dns = Vec::with_capacity(config.dns_servers.len() * 4);
        for server in &config.dns_servers {
            dns.extend_from_slice(&server.octets());
        }
        push_option(&mut response, 6, &dns)?;
    }

    response.push(255);
    Ok(response)
}

fn build_nak(request: &DhcpPacket<'_>, config: &DhcpServerConfig) -> Result<Vec<u8>> {
    let mut response = build_base_response(request, Ipv4Addr::UNSPECIFIED, config.server_ip);
    push_option(&mut response, 53, &[DhcpMessageType::Nak.as_u8()])?;
    push_option(&mut response, 54, &config.server_ip.octets())?;
    response.push(255);
    Ok(response)
}

fn build_base_response(request: &DhcpPacket<'_>, yiaddr: Ipv4Addr, server_ip: Ipv4Addr) -> Vec<u8> {
    let mut response = vec![0_u8; DHCP_FIXED_HEADER_LEN + DHCP_MAGIC_COOKIE.len()];

    response[0] = 2;
    response[1] = request.htype;
    response[2] = request.hlen;
    response[3] = 0;
    response[4..8].copy_from_slice(&request.xid.to_be_bytes());
    response[8..10].copy_from_slice(&0_u16.to_be_bytes());
    response[10..12].copy_from_slice(&request.flags.to_be_bytes());
    response[12..16].copy_from_slice(&request.ciaddr.octets());
    response[16..20].copy_from_slice(&yiaddr.octets());
    response[20..24].copy_from_slice(&server_ip.octets());
    response[24..28].copy_from_slice(&request.giaddr.octets());
    response[28..44].copy_from_slice(&request.chaddr);
    response[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);

    response
}

/// Append a DHCP option, rejecting values too long for the one-byte length field.
fn push_option(response: &mut Vec<u8>, code: u8, value: &[u8]) -> Result<()> {
    let len = u8::try_from(value.len()).map_err(|_| {
        anyhow::anyhow!(
            "DHCP option {code} value is {} bytes, maximum is 255",
            value.len()
        )
    })?;
    response.push(code);
    response.push(len);
    response.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests;
