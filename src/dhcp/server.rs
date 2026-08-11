use std::net::Ipv4Addr;

use anyhow::{bail, Context, Result};

use crate::dhcp::lease::LeaseManager;
use crate::dhcp::packet::{DhcpMessageType, DhcpPacket, DHCP_FIXED_HEADER_LEN, DHCP_MAGIC_COOKIE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpServerConfig {
    pub server_ip: Ipv4Addr,
    pub router: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub dns_servers: Vec<Ipv4Addr>,
}

#[derive(Debug)]
pub struct DhcpHandler {
    config: DhcpServerConfig,
    leases: LeaseManager,
}

impl DhcpHandler {
    pub fn new(config: DhcpServerConfig, leases: LeaseManager) -> Self {
        Self { config, leases }
    }

    pub fn lease_snapshot(&self) -> Vec<crate::dhcp::lease::DhcpLease> {
        self.leases.snapshot()
    }

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
                    self.leases.decline(mac, declined);
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
mod tests {
    use std::time::Duration;

    use crate::dhcp::lease::{LeaseManager, LeasePoolConfig};

    use super::*;

    fn handler() -> DhcpHandler {
        let leases = LeaseManager::new(LeasePoolConfig {
            start: Ipv4Addr::new(192, 168, 50, 100),
            end: Ipv4Addr::new(192, 168, 50, 110),
            lease_time: Duration::from_secs(3600),
        })
        .expect("valid pool");

        DhcpHandler::new(
            DhcpServerConfig {
                server_ip: Ipv4Addr::new(192, 168, 50, 1),
                router: Ipv4Addr::new(192, 168, 50, 1),
                subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
                dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(1, 1, 1, 1)],
            },
            leases,
        )
    }

    fn request_packet(message_type: DhcpMessageType, requested_ip: Option<Ipv4Addr>) -> Vec<u8> {
        let mut packet = vec![0_u8; 240];
        packet[0] = 1;
        packet[1] = 1;
        packet[2] = 6;
        packet[4..8].copy_from_slice(&0x1122_3344_u32.to_be_bytes());
        packet[28..34].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
        packet.extend_from_slice(&[53, 1, message_type.as_u8()]);
        if let Some(ip) = requested_ip {
            packet.extend_from_slice(&[50, 4]);
            packet.extend_from_slice(&ip.octets());
        }
        packet.push(255);
        packet
    }

    fn response_type(response: &[u8]) -> DhcpMessageType {
        let parsed = DhcpPacket::parse(response).expect("response should parse");
        parsed.message_type().expect("response type")
    }

    #[test]
    fn discover_returns_offer() {
        let mut handler = handler();
        let response = handler
            .handle_packet(&request_packet(DhcpMessageType::Discover, None))
            .expect("handler result")
            .expect("offer response");

        let parsed = DhcpPacket::parse(&response).expect("valid DHCP response");
        assert_eq!(response_type(&response), DhcpMessageType::Offer);
        assert_eq!(parsed.yiaddr, Ipv4Addr::new(192, 168, 50, 100));
        assert_eq!(parsed.siaddr, Ipv4Addr::new(192, 168, 50, 1));
    }

    #[test]
    fn request_for_pool_address_returns_ack() {
        let mut handler = handler();
        let requested = Ipv4Addr::new(192, 168, 50, 105);
        let response = handler
            .handle_packet(&request_packet(DhcpMessageType::Request, Some(requested)))
            .expect("handler result")
            .expect("ack response");

        let parsed = DhcpPacket::parse(&response).expect("valid DHCP response");
        assert_eq!(response_type(&response), DhcpMessageType::Ack);
        assert_eq!(parsed.yiaddr, requested);
    }

    #[test]
    fn request_for_out_of_pool_address_returns_nak() {
        let mut handler = handler();
        let requested = Ipv4Addr::new(10, 0, 0, 10);
        let response = handler
            .handle_packet(&request_packet(DhcpMessageType::Request, Some(requested)))
            .expect("handler result")
            .expect("nak response");

        assert_eq!(response_type(&response), DhcpMessageType::Nak);
    }

    #[test]
    fn release_returns_no_response() {
        let mut handler = handler();
        let response = handler
            .handle_packet(&request_packet(DhcpMessageType::Release, None))
            .expect("handler result");

        assert!(response.is_none());
    }

    struct PacketBuilder {
        message_type: DhcpMessageType,
        mac: [u8; 6],
        requested_ip: Option<Ipv4Addr>,
        server_identifier: Option<Ipv4Addr>,
        ciaddr: Ipv4Addr,
    }

    impl PacketBuilder {
        fn new(message_type: DhcpMessageType) -> Self {
            Self {
                message_type,
                mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                requested_ip: None,
                server_identifier: None,
                ciaddr: Ipv4Addr::UNSPECIFIED,
            }
        }

        fn mac(mut self, mac: [u8; 6]) -> Self {
            self.mac = mac;
            self
        }

        fn requested_ip(mut self, ip: Ipv4Addr) -> Self {
            self.requested_ip = Some(ip);
            self
        }

        fn server_identifier(mut self, ip: Ipv4Addr) -> Self {
            self.server_identifier = Some(ip);
            self
        }

        fn ciaddr(mut self, ip: Ipv4Addr) -> Self {
            self.ciaddr = ip;
            self
        }

        fn build(self) -> Vec<u8> {
            let mut packet = vec![0_u8; 240];
            packet[0] = 1;
            packet[1] = 1;
            packet[2] = 6;
            packet[4..8].copy_from_slice(&0x1122_3344_u32.to_be_bytes());
            packet[12..16].copy_from_slice(&self.ciaddr.octets());
            packet[28..34].copy_from_slice(&self.mac);
            packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
            packet.extend_from_slice(&[53, 1, self.message_type.as_u8()]);
            if let Some(ip) = self.requested_ip {
                packet.extend_from_slice(&[50, 4]);
                packet.extend_from_slice(&ip.octets());
            }
            if let Some(ip) = self.server_identifier {
                packet.extend_from_slice(&[54, 4]);
                packet.extend_from_slice(&ip.octets());
            }
            packet.push(255);
            packet
        }
    }

    const OTHER_MAC: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

    #[test]
    fn request_selecting_another_server_is_ignored() {
        let mut handler = handler();
        let response = handler
            .handle_packet(
                &PacketBuilder::new(DhcpMessageType::Request)
                    .requested_ip(Ipv4Addr::new(192, 168, 50, 105))
                    .server_identifier(Ipv4Addr::new(192, 168, 50, 2))
                    .build(),
            )
            .expect("handler result");

        assert!(
            response.is_none(),
            "a request naming another server must not be answered"
        );
    }

    #[test]
    fn request_selecting_this_server_is_acked() {
        let mut handler = handler();
        let requested = Ipv4Addr::new(192, 168, 50, 105);
        let response = handler
            .handle_packet(
                &PacketBuilder::new(DhcpMessageType::Request)
                    .requested_ip(requested)
                    .server_identifier(Ipv4Addr::new(192, 168, 50, 1))
                    .build(),
            )
            .expect("handler result")
            .expect("ack response");

        assert_eq!(response_type(&response), DhcpMessageType::Ack);
        assert_eq!(
            DhcpPacket::parse(&response).expect("parse").yiaddr,
            requested
        );
    }

    #[test]
    fn request_for_an_address_leased_to_another_client_is_naked() {
        let mut handler = handler();
        let taken = Ipv4Addr::new(192, 168, 50, 105);
        handler
            .handle_packet(
                &PacketBuilder::new(DhcpMessageType::Request)
                    .mac(OTHER_MAC)
                    .requested_ip(taken)
                    .build(),
            )
            .expect("handler result")
            .expect("ack for the first client");

        let response = handler
            .handle_packet(
                &PacketBuilder::new(DhcpMessageType::Request)
                    .requested_ip(taken)
                    .build(),
            )
            .expect("handler result")
            .expect("response");

        assert_eq!(response_type(&response), DhcpMessageType::Nak);
    }

    #[test]
    fn renewing_request_without_option_50_uses_ciaddr() {
        let mut handler = handler();
        let held = Ipv4Addr::new(192, 168, 50, 103);
        handler
            .handle_packet(
                &PacketBuilder::new(DhcpMessageType::Request)
                    .requested_ip(held)
                    .build(),
            )
            .expect("handler result")
            .expect("initial ack");

        let response = handler
            .handle_packet(
                &PacketBuilder::new(DhcpMessageType::Request)
                    .ciaddr(held)
                    .build(),
            )
            .expect("handler result")
            .expect("renewal response");

        assert_eq!(response_type(&response), DhcpMessageType::Ack);
        assert_eq!(DhcpPacket::parse(&response).expect("parse").yiaddr, held);
    }

    #[test]
    fn request_without_address_or_ciaddr_is_naked() {
        let mut handler = handler();
        let response = handler
            .handle_packet(&PacketBuilder::new(DhcpMessageType::Request).build())
            .expect("handler result")
            .expect("nak response");

        assert_eq!(response_type(&response), DhcpMessageType::Nak);
    }

    #[test]
    fn declined_address_is_never_offered_again() {
        let mut handler = handler();
        let first = Ipv4Addr::new(192, 168, 50, 100);

        let offer = handler
            .handle_packet(&PacketBuilder::new(DhcpMessageType::Discover).build())
            .expect("handler result")
            .expect("offer");
        assert_eq!(DhcpPacket::parse(&offer).expect("parse").yiaddr, first);

        handler
            .handle_packet(
                &PacketBuilder::new(DhcpMessageType::Decline)
                    .requested_ip(first)
                    .build(),
            )
            .expect("handler result");

        let offer = handler
            .handle_packet(
                &PacketBuilder::new(DhcpMessageType::Discover)
                    .mac(OTHER_MAC)
                    .build(),
            )
            .expect("handler result")
            .expect("offer");
        assert_ne!(
            DhcpPacket::parse(&offer).expect("parse").yiaddr,
            first,
            "a declined address must not be handed out again"
        );
    }

    #[test]
    fn oversized_dns_option_is_an_error_not_a_panic() {
        let mut response = Vec::new();
        let oversized = vec![0_u8; 256];
        let error = push_option(&mut response, 6, &oversized)
            .expect_err("an oversized option must be rejected");
        assert!(error.to_string().contains("maximum is 255"));
    }
}
