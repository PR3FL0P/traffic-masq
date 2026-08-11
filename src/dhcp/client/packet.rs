use std::net::Ipv4Addr;

use anyhow::{bail, Result};

use crate::dhcp::packet::{
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
mod tests {
    use super::*;
    use crate::dhcp::packet::{OPTION_END, OPTION_MESSAGE_TYPE};

    const XID: u32 = 0x1234_5678;
    const MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 9];
    const ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 42);
    const SERVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

    fn builder() -> ClientPacketBuilder {
        ClientPacketBuilder::new(XID, MAC)
            .parameter_request_list(vec![1, 3, 6, 51, 54, 58, 59])
            .client_identifier(vec![1, 2, 0, 0, 0, 0, 9])
    }

    fn parsed(bytes: &[u8]) -> DhcpPacket<'_> {
        DhcpPacket::parse(bytes).expect("valid generated packet")
    }

    fn reply(message_type: DhcpMessageType, extra: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut bytes = vec![0; 240];
        bytes[0] = BOOTREPLY;
        bytes[1] = ETHERNET_HTYPE;
        bytes[2] = ETHERNET_HLEN;
        bytes[4..8].copy_from_slice(&XID.to_be_bytes());
        bytes[16..20].copy_from_slice(&ADDRESS.octets());
        bytes[28..34].copy_from_slice(&MAC);
        bytes[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
        push_option(&mut bytes, OPTION_MESSAGE_TYPE, &[message_type.as_u8()]).unwrap();
        for (code, value) in extra {
            push_option(&mut bytes, *code, value).unwrap();
        }
        bytes.push(OPTION_END);
        bytes
    }

    fn ack_options() -> Vec<(u8, Vec<u8>)> {
        vec![
            (OPTION_SERVER_IDENTIFIER, SERVER.octets().to_vec()),
            (
                OPTION_SUBNET_MASK,
                Ipv4Addr::new(255, 255, 255, 0).octets().to_vec(),
            ),
            (OPTION_ROUTERS, SERVER.octets().to_vec()),
            (
                OPTION_DNS_SERVERS,
                Ipv4Addr::new(203, 0, 113, 53).octets().to_vec(),
            ),
            (OPTION_LEASE_TIME, 3600_u32.to_be_bytes().to_vec()),
            (OPTION_RENEWAL_TIME, 1800_u32.to_be_bytes().to_vec()),
            (OPTION_REBINDING_TIME, 3150_u32.to_be_bytes().to_vec()),
        ]
    }

    #[test]
    fn discover_has_golden_header_options_end_and_padding() {
        let bytes = builder().discover().unwrap();
        assert_eq!(bytes.len(), 300);
        assert_eq!(
            &bytes[..4],
            &[BOOTREQUEST, ETHERNET_HTYPE, ETHERNET_HLEN, 0]
        );
        assert_eq!(&bytes[4..8], &XID.to_be_bytes());
        assert_eq!(&bytes[10..12], &BROADCAST_FLAG.to_be_bytes());
        assert_eq!(&bytes[28..34], &MAC);
        assert_eq!(&bytes[236..240], &DHCP_MAGIC_COOKIE);
        assert_eq!(
            &bytes[240..262],
            &[53, 1, 1, 55, 7, 1, 3, 6, 51, 54, 58, 59, 61, 7, 1, 2, 0, 0, 0, 0, 9, 255]
        );
        assert!(bytes[262..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn every_client_message_round_trips_with_correct_state_fields() {
        let packets = [
            builder().discover().unwrap(),
            builder().selecting_request(ADDRESS, SERVER).unwrap(),
            builder().init_reboot_request(ADDRESS).unwrap(),
            builder().renew(ADDRESS).unwrap(),
            builder().rebind(ADDRESS).unwrap(),
            builder().decline(ADDRESS, SERVER).unwrap(),
            builder().release(ADDRESS, SERVER).unwrap(),
        ];
        for bytes in &packets {
            let packet = parsed(bytes);
            assert_eq!(packet.op, BOOTREQUEST);
            assert_eq!(packet.xid, XID);
            assert_eq!(&packet.chaddr[..6], &MAC);
            assert!(packet.strict_message_type().unwrap().is_some());
        }
        let selecting = parsed(&packets[1]);
        assert_eq!(selecting.requested_ip(), Some(ADDRESS));
        assert_eq!(selecting.server_identifier(), Some(SERVER));
        let reboot = parsed(&packets[2]);
        assert_eq!(reboot.requested_ip(), Some(ADDRESS));
        assert_eq!(reboot.server_identifier(), None);
        for packet in [&packets[3], &packets[4]] {
            let packet = parsed(packet);
            assert_eq!(packet.ciaddr, ADDRESS);
            assert_eq!(packet.requested_ip(), None);
            assert_eq!(packet.server_identifier(), None);
        }
    }

    #[test]
    fn validates_typed_offer_ack_and_nak() {
        let context = ReplyContext { xid: XID, mac: MAC };
        let offer_bytes = reply(
            DhcpMessageType::Offer,
            &[(OPTION_SERVER_IDENTIFIER, SERVER.octets().to_vec())],
        );
        assert_eq!(
            context
                .validate_offer(&parsed(&offer_bytes))
                .unwrap()
                .address,
            ADDRESS
        );

        let ack_bytes = reply(DhcpMessageType::Ack, &ack_options());
        let ack = context
            .validate_ack(&parsed(&ack_bytes), Some(SERVER), Some(ADDRESS))
            .unwrap();
        assert_eq!(ack.prefix_len, 24);
        assert_eq!((ack.renewal_seconds, ack.rebinding_seconds), (1800, 3150));

        let nak_bytes = reply(
            DhcpMessageType::Nak,
            &[(OPTION_SERVER_IDENTIFIER, SERVER.octets().to_vec())],
        );
        assert_eq!(
            context
                .validate_nak(&parsed(&nak_bytes), Some(SERVER))
                .unwrap(),
            Nak {
                server_identifier: SERVER
            }
        );
    }

    #[test]
    fn derives_default_timers() {
        let mut options = ack_options();
        options.retain(|(code, _)| !matches!(*code, OPTION_RENEWAL_TIME | OPTION_REBINDING_TIME));
        let bytes = reply(DhcpMessageType::Ack, &options);
        let ack = ReplyContext { xid: XID, mac: MAC }
            .validate_ack(&parsed(&bytes), None, None)
            .unwrap();
        assert_eq!((ack.renewal_seconds, ack.rebinding_seconds), (1800, 3150));
    }

    #[test]
    fn rejects_wrong_reply_correlation_and_server() {
        let bytes = reply(DhcpMessageType::Ack, &ack_options());
        assert!(ReplyContext {
            xid: XID + 1,
            mac: MAC
        }
        .validate_ack(&parsed(&bytes), None, None)
        .is_err());
        assert!(ReplyContext {
            xid: XID,
            mac: [7; 6]
        }
        .validate_ack(&parsed(&bytes), None, None)
        .is_err());
        assert!(ReplyContext { xid: XID, mac: MAC }
            .validate_ack(&parsed(&bytes), Some(Ipv4Addr::new(192, 0, 2, 2)), None)
            .is_err());
        let mut not_reply = bytes;
        not_reply[0] = BOOTREQUEST;
        assert!(ReplyContext { xid: XID, mac: MAC }
            .validate_ack(&parsed(&not_reply), None, None)
            .is_err());
    }

    #[test]
    fn rejects_duplicate_or_malformed_singletons_and_lists() {
        let mut duplicate = ack_options();
        duplicate.push((OPTION_LEASE_TIME, 3600_u32.to_be_bytes().to_vec()));
        let bytes = reply(DhcpMessageType::Ack, &duplicate);
        assert!(ReplyContext { xid: XID, mac: MAC }
            .validate_ack(&parsed(&bytes), None, None)
            .is_err());

        let mut malformed = ack_options();
        malformed.retain(|(code, _)| *code != OPTION_DNS_SERVERS);
        malformed.push((OPTION_DNS_SERVERS, vec![1, 2, 3]));
        let bytes = reply(DhcpMessageType::Ack, &malformed);
        assert!(ReplyContext { xid: XID, mac: MAC }
            .validate_ack(&parsed(&bytes), None, None)
            .is_err());
    }

    #[test]
    fn rejects_invalid_masks_timers_addresses_and_builder_bounds() {
        let context = ReplyContext { xid: XID, mac: MAC };
        let mut options = ack_options();
        options.retain(|(code, _)| *code != OPTION_SUBNET_MASK);
        options.push((OPTION_SUBNET_MASK, [255, 0, 255, 0].to_vec()));
        assert!(context
            .validate_ack(&parsed(&reply(DhcpMessageType::Ack, &options)), None, None)
            .is_err());

        let mut options = ack_options();
        options.retain(|(code, _)| *code != OPTION_RENEWAL_TIME);
        options.push((OPTION_RENEWAL_TIME, 3500_u32.to_be_bytes().to_vec()));
        assert!(context
            .validate_ack(&parsed(&reply(DhcpMessageType::Ack, &options)), None, None)
            .is_err());

        assert!(builder().renew(Ipv4Addr::UNSPECIFIED).is_err());
        assert!(ClientPacketBuilder::new(XID, MAC)
            .parameter_request_list(vec![1; 256])
            .discover()
            .is_err());
        assert!(ClientPacketBuilder::new(XID, MAC)
            .client_identifier(Vec::<u8>::new())
            .discover()
            .is_err());
    }
}
