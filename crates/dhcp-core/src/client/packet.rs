use std::net::Ipv4Addr;

use anyhow::{bail, Result};

use crate::packet::{
    finish_options, push_option, DhcpMessageType, DhcpPacket, BOOTREPLY, BOOTREQUEST,
    DHCP_FIXED_HEADER_LEN, DHCP_MAGIC_COOKIE, ETHERNET_HLEN, ETHERNET_HTYPE,
    OPTION_CLIENT_IDENTIFIER, OPTION_DNS_SERVERS, OPTION_LEASE_TIME, OPTION_MESSAGE_TYPE,
    OPTION_PARAMETER_REQUEST_LIST, OPTION_REBINDING_TIME, OPTION_RENEWAL_TIME, OPTION_REQUESTED_IP,
    OPTION_ROUTERS, OPTION_SERVER_IDENTIFIER, OPTION_SUBNET_MASK,
};

const BROADCAST_FLAG: u16 = 0x8000;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientPacketOptions {
    pub parameter_request_list: Vec<u8>,
    pub client_identifier: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Build Ethernet BOOTREQUEST packets for one transaction and MAC.
/// Elapsed seconds saturate at u16::MAX; option payloads must fit 255 bytes.
/// Discover/select/init-reboot use zero ciaddr and broadcast; renew uses the
/// assigned ciaddr without broadcast, rebind uses it with broadcast.
/// The builder checks address usability and encoding, not socket routing.
pub struct ClientPacketBuilder {
    xid: u32,
    mac: [u8; 6],
    secs: u16,
    options: ClientPacketOptions,
}

impl ClientPacketBuilder {
    pub fn new(xid: u32, mac: [u8; 6]) -> Self {
        Self {
            xid,
            mac,
            secs: 0,
            options: ClientPacketOptions::default(),
        }
    }

    pub fn elapsed(mut self, elapsed: std::time::Duration) -> Self {
        self.secs = elapsed.as_secs().min(u16::MAX as u64) as u16;
        self
    }

    pub fn parameter_request_list(mut self, codes: impl Into<Vec<u8>>) -> Self {
        self.options.parameter_request_list = codes.into();
        self
    }

    pub fn client_identifier(mut self, identifier: impl Into<Vec<u8>>) -> Self {
        self.options.client_identifier = Some(identifier.into());
        self
    }

    pub fn discover(&self) -> Result<Vec<u8>> {
        self.build(DhcpMessageType::Discover, Ipv4Addr::UNSPECIFIED, true, &[])
    }

    pub fn selecting_request(
        &self,
        requested_ip: Ipv4Addr,
        server_identifier: Ipv4Addr,
    ) -> Result<Vec<u8>> {
        require_usable_address(requested_ip, "requested address")?;
        require_usable_address(server_identifier, "server identifier")?;
        self.build(
            DhcpMessageType::Request,
            Ipv4Addr::UNSPECIFIED,
            true,
            &[
                (OPTION_REQUESTED_IP, requested_ip.octets().to_vec()),
                (
                    OPTION_SERVER_IDENTIFIER,
                    server_identifier.octets().to_vec(),
                ),
            ],
        )
    }

    pub fn init_reboot_request(&self, requested_ip: Ipv4Addr) -> Result<Vec<u8>> {
        require_usable_address(requested_ip, "requested address")?;
        self.build(
            DhcpMessageType::Request,
            Ipv4Addr::UNSPECIFIED,
            true,
            &[(OPTION_REQUESTED_IP, requested_ip.octets().to_vec())],
        )
    }

    pub fn renew(&self, address: Ipv4Addr) -> Result<Vec<u8>> {
        require_usable_address(address, "client address")?;
        self.build(DhcpMessageType::Request, address, false, &[])
    }

    pub fn rebind(&self, address: Ipv4Addr) -> Result<Vec<u8>> {
        require_usable_address(address, "client address")?;
        self.build(DhcpMessageType::Request, address, true, &[])
    }

    pub fn decline(&self, address: Ipv4Addr, server_identifier: Ipv4Addr) -> Result<Vec<u8>> {
        require_usable_address(address, "declined address")?;
        require_usable_address(server_identifier, "server identifier")?;
        self.build(
            DhcpMessageType::Decline,
            Ipv4Addr::UNSPECIFIED,
            true,
            &[
                (OPTION_REQUESTED_IP, address.octets().to_vec()),
                (
                    OPTION_SERVER_IDENTIFIER,
                    server_identifier.octets().to_vec(),
                ),
            ],
        )
    }

    pub fn release(&self, address: Ipv4Addr, server_identifier: Ipv4Addr) -> Result<Vec<u8>> {
        require_usable_address(address, "client address")?;
        require_usable_address(server_identifier, "server identifier")?;
        self.build(
            DhcpMessageType::Release,
            address,
            false,
            &[(
                OPTION_SERVER_IDENTIFIER,
                server_identifier.octets().to_vec(),
            )],
        )
    }

    fn build(
        &self,
        message_type: DhcpMessageType,
        ciaddr: Ipv4Addr,
        broadcast: bool,
        state_options: &[(u8, Vec<u8>)],
    ) -> Result<Vec<u8>> {
        if self.options.parameter_request_list.len() > u8::MAX as usize {
            bail!("DHCP parameter request list exceeds 255 bytes");
        }
        if self.options.parameter_request_list.contains(&0)
            || self.options.parameter_request_list.contains(&255)
        {
            bail!("DHCP parameter request list contains a reserved option code");
        }
        if matches!(self.options.client_identifier.as_deref(), Some([])) {
            bail!("DHCP client identifier must not be empty");
        }

        let mut packet = vec![0; DHCP_FIXED_HEADER_LEN + DHCP_MAGIC_COOKIE.len()];
        packet[0] = BOOTREQUEST;
        packet[1] = ETHERNET_HTYPE;
        packet[2] = ETHERNET_HLEN;
        packet[4..8].copy_from_slice(&self.xid.to_be_bytes());
        packet[8..10].copy_from_slice(&self.secs.to_be_bytes());
        packet[10..12].copy_from_slice(&(if broadcast { BROADCAST_FLAG } else { 0 }).to_be_bytes());
        packet[12..16].copy_from_slice(&ciaddr.octets());
        packet[28..34].copy_from_slice(&self.mac);
        packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);

        push_option(&mut packet, OPTION_MESSAGE_TYPE, &[message_type.as_u8()])?;
        for (code, value) in state_options {
            push_option(&mut packet, *code, value)?;
        }
        if !self.options.parameter_request_list.is_empty() {
            push_option(
                &mut packet,
                OPTION_PARAMETER_REQUEST_LIST,
                &self.options.parameter_request_list,
            )?;
        }
        if let Some(identifier) = &self.options.client_identifier {
            push_option(&mut packet, OPTION_CLIENT_IDENTIFIER, identifier)?;
        }
        finish_options(&mut packet);
        Ok(packet)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ReplyContext {
    pub xid: u32,
    pub mac: [u8; 6],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub address: Ipv4Addr,
    pub server_identifier: Ipv4Addr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ack {
    pub address: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub prefix_len: u8,
    pub routers: Vec<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub lease_seconds: u32,
    pub server_identifier: Ipv4Addr,
    pub renewal_seconds: u32,
    pub rebinding_seconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nak {
    pub server_identifier: Ipv4Addr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatedReply {
    Offer(Offer),
    Ack(Ack),
    Nak(Nak),
}

impl ReplyContext {
    /// Validate an Ethernet BOOTREPLY for this xid/MAC with Offer type, usable
    /// assigned address and singleton server identifier. Parsing alone is not
    /// exchange validation; malformed or mismatched replies return Err.
    pub fn validate_offer(&self, packet: &DhcpPacket<'_>) -> Result<Offer> {
        self.correlate(packet)?;
        require_type(packet, DhcpMessageType::Offer)?;
        let address = assigned_address(packet, None)?;
        let server_identifier =
            required_address_option(packet, OPTION_SERVER_IDENTIFIER, "server identifier")?;
        Ok(Offer {
            address,
            server_identifier,
        })
    }

    /// Correlate xid/MAC and ACK type, optionally constrain server and address,
    /// and validate mask, lease/timer invariants and address lists. Absent T1/T2
    /// use defaults; require 0 < T1 < T2 < lease. Does not prove reachability,
    /// address uniqueness or ownership of kernel resources.
    pub fn validate_ack(
        &self,
        packet: &DhcpPacket<'_>,
        selected_server: Option<Ipv4Addr>,
        expected_address: Option<Ipv4Addr>,
    ) -> Result<Ack> {
        self.correlate(packet)?;
        require_type(packet, DhcpMessageType::Ack)?;
        let server_identifier =
            required_address_option(packet, OPTION_SERVER_IDENTIFIER, "server identifier")?;
        if selected_server.is_some_and(|selected| selected != server_identifier) {
            bail!("DHCP ACK came from an unexpected server");
        }
        let address = assigned_address(packet, expected_address)?;
        let subnet_mask = required_address_option(packet, OPTION_SUBNET_MASK, "subnet mask")?;
        let prefix_len = mask_prefix(subnet_mask)?;
        let lease_seconds = packet
            .strict_u32_option(OPTION_LEASE_TIME)?
            .ok_or_else(|| anyhow::anyhow!("DHCP ACK is missing lease time"))?;
        if lease_seconds == 0 {
            bail!("DHCP lease time must be nonzero");
        }
        let renewal_seconds = packet
            .strict_u32_option(OPTION_RENEWAL_TIME)?
            .unwrap_or(lease_seconds / 2);
        let rebinding_seconds = packet
            .strict_u32_option(OPTION_REBINDING_TIME)?
            .unwrap_or_else(|| lease_seconds.saturating_mul(7) / 8);
        if renewal_seconds == 0
            || renewal_seconds >= rebinding_seconds
            || rebinding_seconds >= lease_seconds
        {
            bail!("DHCP lease timers must satisfy 0 < T1 < T2 < lease");
        }
        let routers = address_list(packet, OPTION_ROUTERS, "router")?;
        let dns_servers = address_list(packet, OPTION_DNS_SERVERS, "DNS server")?;
        Ok(Ack {
            address,
            subnet_mask,
            prefix_len,
            routers,
            dns_servers,
            lease_seconds,
            server_identifier,
            renewal_seconds,
            rebinding_seconds,
        })
    }

    /// Correlate xid/MAC and NAK type with a usable singleton server identifier.
    /// Reject a server differing from selected_server when supplied.
    /// This validates the exchange, without changing any lease or runtime state.
    pub fn validate_nak(
        &self,
        packet: &DhcpPacket<'_>,
        selected_server: Option<Ipv4Addr>,
    ) -> Result<Nak> {
        self.correlate(packet)?;
        require_type(packet, DhcpMessageType::Nak)?;
        let server_identifier =
            required_address_option(packet, OPTION_SERVER_IDENTIFIER, "server identifier")?;
        if selected_server.is_some_and(|selected| selected != server_identifier) {
            bail!("DHCP NAK came from an unexpected server");
        }
        Ok(Nak { server_identifier })
    }

    fn correlate(&self, packet: &DhcpPacket<'_>) -> Result<()> {
        if packet.op != BOOTREPLY || packet.htype != ETHERNET_HTYPE || packet.hlen != ETHERNET_HLEN
        {
            bail!("DHCP reply is not an Ethernet BOOTREPLY");
        }
        if packet.xid != self.xid {
            bail!("DHCP reply transaction ID does not match");
        }
        if packet.chaddr[..6] != self.mac {
            bail!("DHCP reply hardware address does not match");
        }
        Ok(())
    }
}

fn require_type(packet: &DhcpPacket<'_>, expected: DhcpMessageType) -> Result<()> {
    if packet.strict_message_type()? != Some(expected) {
        bail!("unexpected DHCP reply message type");
    }
    Ok(())
}

fn assigned_address(packet: &DhcpPacket<'_>, expected: Option<Ipv4Addr>) -> Result<Ipv4Addr> {
    let address = if packet.yiaddr.is_unspecified() {
        expected.ok_or_else(|| anyhow::anyhow!("DHCP reply has no assigned address"))?
    } else {
        packet.yiaddr
    };
    require_usable_address(address, "assigned address")?;
    if expected.is_some_and(|expected| expected != address) {
        bail!("DHCP ACK assigned an unexpected address");
    }
    Ok(address)
}

fn required_address_option(packet: &DhcpPacket<'_>, code: u8, name: &str) -> Result<Ipv4Addr> {
    let address = packet
        .strict_ipv4_option(code)?
        .ok_or_else(|| anyhow::anyhow!("DHCP reply is missing {name}"))?;
    require_usable_address(address, name)?;
    Ok(address)
}

fn address_list(packet: &DhcpPacket<'_>, code: u8, name: &str) -> Result<Vec<Ipv4Addr>> {
    let addresses = packet.strict_ipv4_list_option(code)?.unwrap_or_default();
    for address in &addresses {
        require_usable_address(*address, name)?;
    }
    Ok(addresses)
}

fn require_usable_address(address: Ipv4Addr, name: &str) -> Result<()> {
    if address.is_unspecified() || address.is_broadcast() || address.is_multicast() {
        bail!("DHCP {name} is not a usable unicast IPv4 address");
    }
    Ok(())
}

fn mask_prefix(mask: Ipv4Addr) -> Result<u8> {
    let bits = u32::from(mask);
    let prefix = bits.leading_ones() as u8;
    let expected = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    if bits != expected {
        bail!("DHCP subnet mask is not contiguous");
    }
    Ok(prefix)
}

#[cfg(test)]
mod tests;
