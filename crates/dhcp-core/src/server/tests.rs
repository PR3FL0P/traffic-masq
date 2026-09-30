use std::time::Duration;

use crate::lease::{LeaseManager, LeasePoolConfig};

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
fn decline_for_an_address_leased_to_another_client_is_ignored() {
    let mut handler = handler();
    let victim_ip = Ipv4Addr::new(192, 168, 50, 100);

    handler
        .handle_packet(&PacketBuilder::new(DhcpMessageType::Discover).build())
        .expect("handler result")
        .expect("offer for the victim");

    // The attacker claims the victim's already-leased address in a spoofed
    // DECLINE; it must be rejected rather than evicting and poisoning it.
    handler
        .handle_packet(
            &PacketBuilder::new(DhcpMessageType::Decline)
                .mac(OTHER_MAC)
                .requested_ip(victim_ip)
                .build(),
        )
        .expect("handler result");

    let response = handler
        .handle_packet(
            &PacketBuilder::new(DhcpMessageType::Request)
                .requested_ip(victim_ip)
                .build(),
        )
        .expect("handler result")
        .expect("the victim can still renew their own address");

    assert_eq!(response_type(&response), DhcpMessageType::Ack);
}

#[test]
fn oversized_dns_option_is_an_error_not_a_panic() {
    let mut response = Vec::new();
    let oversized = vec![0_u8; 256];
    let error = push_option(&mut response, 6, &oversized)
        .expect_err("an oversized option must be rejected");
    assert!(error.to_string().contains("maximum is 255"));
}
