use super::*;

fn discover_packet() -> Vec<u8> {
    let mut packet = vec![0_u8; 240];
    packet[0] = 1;
    packet[1] = 1;
    packet[2] = 6;
    packet[4..8].copy_from_slice(&0x1234_5678_u32.to_be_bytes());
    packet[28..34].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
    packet.extend_from_slice(&[53, 1, DhcpMessageType::Discover.as_u8(), 255]);
    packet
}

#[test]
fn parses_discover_message_type() {
    let packet_data = discover_packet();
    let packet = DhcpPacket::parse(&packet_data).expect("packet should parse");
    assert_eq!(packet.op, 1);
    assert_eq!(packet.htype, 1);
    assert_eq!(packet.hlen, 6);
    assert_eq!(packet.xid, 0x1234_5678);
    assert_eq!(&packet.chaddr[..6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    assert_eq!(packet.message_type(), Some(DhcpMessageType::Discover));
}

#[test]
fn rejects_invalid_magic_cookie() {
    let mut packet = discover_packet();
    packet[236] = 0;
    assert!(DhcpPacket::parse(&packet).is_err());
}

#[test]
fn rejects_truncated_options() {
    let options = [53, 2, 1];
    assert!(parse_options(&options).is_err());
}
