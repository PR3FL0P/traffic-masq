use super::*;
use crate::packet::{OPTION_END, OPTION_MESSAGE_TYPE};

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
