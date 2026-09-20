use super::*;
use crate::dhcp::packet::{
    finish_options, push_option, DhcpMessageType, BOOTREPLY, DHCP_FIXED_HEADER_LEN,
    DHCP_MAGIC_COOKIE, ETHERNET_HLEN, ETHERNET_HTYPE, OPTION_LEASE_TIME, OPTION_MESSAGE_TYPE,
    OPTION_REBINDING_TIME, OPTION_RENEWAL_TIME, OPTION_SERVER_IDENTIFIER, OPTION_SUBNET_MASK,
};

const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const XID: u32 = 0x1234_5678;
const ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const SERVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

fn reply(xid: u32, kind: DhcpMessageType, address: Ipv4Addr, lease: Option<u32>) -> Vec<u8> {
    let mut bytes = vec![0; DHCP_FIXED_HEADER_LEN + DHCP_MAGIC_COOKIE.len()];
    bytes[0] = BOOTREPLY;
    bytes[1] = ETHERNET_HTYPE;
    bytes[2] = ETHERNET_HLEN;
    bytes[4..8].copy_from_slice(&xid.to_be_bytes());
    bytes[16..20].copy_from_slice(&address.octets());
    bytes[28..34].copy_from_slice(&MAC);
    bytes[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
    push_option(&mut bytes, OPTION_MESSAGE_TYPE, &[kind.as_u8()]).unwrap();
    push_option(&mut bytes, OPTION_SERVER_IDENTIFIER, &SERVER.octets()).unwrap();
    if let Some(lease) = lease {
        push_option(&mut bytes, OPTION_SUBNET_MASK, &[255, 255, 255, 0]).unwrap();
        push_option(&mut bytes, OPTION_LEASE_TIME, &lease.to_be_bytes()).unwrap();
        let t1 = lease / 2;
        let t2 = lease * 7 / 8;
        push_option(&mut bytes, OPTION_RENEWAL_TIME, &t1.to_be_bytes()).unwrap();
        push_option(&mut bytes, OPTION_REBINDING_TIME, &t2.to_be_bytes()).unwrap();
    }
    finish_options(&mut bytes);
    bytes
}

fn acquire(sm: &mut DhcpClientStateMachine, now: Duration, lease: u32) -> Lease {
    sm.link_ready(now, XID, None, 0);
    sm.receive(now, &reply(XID, DhcpMessageType::Offer, ADDRESS, None), 0);
    let actions = sm.receive(
        now,
        &reply(XID, DhcpMessageType::Ack, ADDRESS, Some(lease)),
        0,
    );
    match &actions[0] {
        Action::LeaseAcquired(lease) => lease.clone(),
        action => panic!("unexpected action: {action:?}"),
    }
}

fn sent(actions: &[Action]) -> (&[u8], SendKind) {
    match &actions[0] {
        Action::Send { packet, kind } => (packet, *kind),
        action => panic!("unexpected action: {action:?}"),
    }
}

#[test]
fn full_lifecycle_acquires_renews_rebinds_and_expires() {
    let mut sm = DhcpClientStateMachine::new(MAC);
    let lease = acquire(&mut sm, Duration::ZERO, 80);
    assert_eq!(lease.renewal_at, Duration::from_secs(40));

    let actions = sm.timeout(lease.renewal_at, 99, 0);
    assert_eq!(sent(&actions).1, SendKind::Unicast(SERVER));
    assert!(matches!(sm.state(), DhcpClientState::Renewing { .. }));

    let actions = sm.timeout(lease.rebinding_at, 100, 0);
    assert_eq!(sent(&actions).1, SendKind::Broadcast);
    assert!(matches!(sm.state(), DhcpClientState::Rebinding { .. }));

    let actions = sm.timeout(lease.expires_at, 101, 0);
    assert!(matches!(actions[0], Action::CleanupNeeded(_)));
    assert!(matches!(actions[1], Action::LeaseLost));
    assert_eq!(sent(&actions[2..]).1, SendKind::Broadcast);
    assert_eq!(sm.xid(), Some(101));
    assert!(matches!(sm.state(), DhcpClientState::Selecting));
}

#[test]
fn duplicate_offer_and_ack_preserve_bound_lease_deadline() {
    let mut sm = DhcpClientStateMachine::new(MAC);
    let initial = sm.link_ready(Duration::ZERO, XID, None, 0);
    assert_eq!(initial[1], Action::WakeAt(Duration::from_secs(4)));

    let offer = reply(XID, DhcpMessageType::Offer, ADDRESS, None);
    sm.receive(Duration::from_millis(100), &offer, 0);
    let request_deadline = Duration::from_millis(4_100);
    assert_eq!(sm.deadline(), Some(request_deadline));
    assert!(matches!(
        sm.receive(Duration::from_millis(200), &offer, 0)[0],
        Action::ReplyIgnored(_)
    ));
    assert_eq!(sm.deadline(), Some(request_deadline));

    let ack = reply(XID, DhcpMessageType::Ack, ADDRESS, Some(8));
    sm.receive(Duration::from_millis(300), &ack, 0);
    let renewal_deadline = Duration::from_millis(4_300);
    assert_eq!(sm.deadline(), Some(renewal_deadline));
    assert!(matches!(
        sm.receive(Duration::from_millis(400), &ack, 0)[0],
        Action::ReplyIgnored(IgnoreReason::NotExpected)
    ));
    assert_eq!(sm.deadline(), Some(renewal_deadline));

    let early = sm.timeout(request_deadline, 99, 0);
    assert_eq!(early, vec![Action::WakeAt(renewal_deadline)]);
    assert!(matches!(sm.state(), DhcpClientState::Bound { .. }));
    let renewal = sm.timeout(renewal_deadline, 99, 0);
    assert_eq!(sent(&renewal).1, SendKind::Unicast(SERVER));
}

#[test]
fn renewal_ack_replaces_schedule_and_returns_bound() {
    let mut sm = DhcpClientStateMachine::new(MAC);
    let lease = acquire(&mut sm, Duration::ZERO, 80);
    sm.timeout(lease.renewal_at, 99, 0);
    let actions = sm.receive(
        Duration::from_secs(41),
        &reply(99, DhcpMessageType::Ack, ADDRESS, Some(100)),
        0,
    );
    assert!(matches!(actions[0], Action::LeaseAcquired(_)));
    assert!(matches!(sm.state(), DhcpClientState::Bound { .. }));
}

#[test]
fn changed_renewal_network_releases_old_ownership_before_acquiring_new_lease() {
    for change_prefix in [false, true] {
        let mut sm = DhcpClientStateMachine::new(MAC);
        let mut previous = acquire(&mut sm, Duration::ZERO, 80);
        previous.routers = vec![SERVER];
        sm.state = DhcpClientState::Renewing {
            lease: previous.clone(),
        };
        let ack = Ack {
            address: ADDRESS,
            subnet_mask: if change_prefix {
                Ipv4Addr::new(255, 255, 255, 128)
            } else {
                previous.subnet_mask
            },
            prefix_len: if change_prefix {
                25
            } else {
                previous.prefix_len
            },
            // Removing a gateway must clean the old default route before
            // its durable ownership record is replaced by a route-less ACK.
            routers: if change_prefix {
                previous.routers.clone()
            } else {
                Vec::new()
            },
            dns_servers: Vec::new(),
            lease_seconds: 100,
            server_identifier: SERVER,
            renewal_seconds: 50,
            rebinding_seconds: 87,
        };
        let actions = sm.bind(ack, Duration::from_secs(41));
        assert_eq!(actions[0], Action::CleanupNeeded(previous));
        assert!(matches!(&actions[1], Action::LeaseAcquired(lease)
                if lease.prefix_len == if change_prefix { 25 } else { 24 }));
        assert!(matches!(actions[2], Action::WakeAt(_)));
    }
}

#[test]
fn wrong_xid_and_wrong_state_are_explicitly_ignored() {
    let mut sm = DhcpClientStateMachine::new(MAC);
    sm.link_ready(Duration::ZERO, XID, None, 0);
    let actions = sm.receive(
        Duration::ZERO,
        &reply(XID + 1, DhcpMessageType::Offer, ADDRESS, None),
        0,
    );
    assert!(matches!(actions[0], Action::ReplyIgnored(_)));
    assert!(matches!(sm.state(), DhcpClientState::Selecting));

    let ack = reply(XID, DhcpMessageType::Ack, ADDRESS, Some(80));
    assert!(matches!(
        sm.receive(Duration::ZERO, &ack, 0)[0],
        Action::ReplyIgnored(_)
    ));
}

#[test]
fn retries_are_bounded_jittered_and_keep_xid() {
    let mut sm = DhcpClientStateMachine::new(MAC);
    let first = sm.link_ready(Duration::ZERO, XID, None, 50_000);
    assert_eq!(first[1], Action::WakeAt(Duration::from_secs(5)));
    let mut now = Duration::from_secs(5);
    for expected in [7, 15, 31, 63, 63, 63] {
        let actions = sm.timeout(now, XID + 1, -50_000);
        let packet = DhcpPacket::parse(sent(&actions).0).unwrap();
        assert_eq!(packet.xid, XID);
        let Action::WakeAt(next) = actions[1] else {
            panic!()
        };
        assert_eq!(next - now, Duration::from_secs(expected));
        now = next;
    }
}

#[test]
fn nak_clears_lease_and_restarts_with_fresh_xid_after_backoff() {
    let mut sm = DhcpClientStateMachine::new(MAC);
    let lease = acquire(&mut sm, Duration::ZERO, 80);
    sm.timeout(lease.renewal_at, 99, 0);
    let actions = sm.receive(
        lease.renewal_at,
        &reply(99, DhcpMessageType::Nak, Ipv4Addr::UNSPECIFIED, None),
        0,
    );
    assert!(matches!(actions[0], Action::CleanupNeeded(_)));
    assert!(matches!(sm.state(), DhcpClientState::Backoff));
    sm.timeout(Duration::from_secs(44), 100, 0);
    assert_eq!(sm.xid(), Some(100));
    assert!(matches!(sm.state(), DhcpClientState::Selecting));
}

#[test]
fn init_reboot_succeeds_or_nak_falls_back_after_backoff() {
    let mut seed = DhcpClientStateMachine::new(MAC);
    let lease = acquire(&mut seed, Duration::ZERO, 80);
    let mut sm = DhcpClientStateMachine::new(MAC);
    let actions = sm.link_ready(Duration::from_secs(1), XID, Some(lease.clone()), 0);
    let packet = DhcpPacket::parse(sent(&actions).0).unwrap();
    assert_eq!(packet.xid, XID);
    assert!(matches!(sm.state(), DhcpClientState::Rebooting { .. }));
    sm.receive(
        Duration::from_secs(2),
        &reply(XID, DhcpMessageType::Ack, ADDRESS, Some(80)),
        0,
    );
    assert!(matches!(sm.state(), DhcpClientState::Bound { .. }));

    let mut fallback = DhcpClientStateMachine::new(MAC);
    fallback.link_ready(Duration::from_secs(1), XID, Some(lease), 0);
    fallback.receive(
        Duration::from_secs(1),
        &reply(XID, DhcpMessageType::Nak, Ipv4Addr::UNSPECIFIED, None),
        0,
    );
    fallback.timeout(Duration::from_secs(5), 777, 0);
    assert_eq!(fallback.xid(), Some(777));
    assert!(matches!(fallback.state(), DhcpClientState::Selecting));
}

#[test]
fn an_unanswered_init_reboot_expires_the_remembered_lease() {
    let mut seed = DhcpClientStateMachine::new(MAC);
    let lease = acquire(&mut seed, Duration::ZERO, 80);

    let mut sm = DhcpClientStateMachine::new(MAC);
    let start = sm.link_ready(Duration::ZERO, XID, Some(lease.clone()), 0);

    assert_eq!(start[1], Action::WakeAt(Duration::from_secs(4)));
    let mut now = Duration::from_secs(4);
    while now < lease.expires_at {
        let actions = sm.timeout(now, 555, 0);
        let Action::WakeAt(next) = actions[actions.len() - 1] else {
            panic!("every retry schedules the next wake")
        };
        assert!(next <= lease.expires_at);
        now = next;
    }

    let expired = sm.timeout(lease.expires_at, 777, 0);
    assert!(matches!(expired[0], Action::CleanupNeeded(_)));
    assert!(matches!(expired[1], Action::LeaseLost));
    assert_eq!(sent(&expired[2..]).1, SendKind::Broadcast);
    assert_eq!(sm.xid(), Some(777));
    assert!(matches!(sm.state(), DhcpClientState::Selecting));
}

#[test]
fn short_lease_deadlines_always_advance() {
    let mut sm = DhcpClientStateMachine::new(MAC);
    let lease = acquire(&mut sm, Duration::ZERO, 3);
    assert_eq!(lease.renewal_at, Duration::from_secs(1));
    let renew = sm.timeout(lease.renewal_at, 99, -1_000);
    let Action::WakeAt(next) = renew[1] else {
        panic!()
    };
    assert!(next > lease.renewal_at);
    assert!(next <= lease.rebinding_at);
    let rebind = sm.timeout(lease.rebinding_at, 100, -1_000);
    let Action::WakeAt(next) = rebind[1] else {
        panic!()
    };
    assert!(next > lease.rebinding_at);
    assert!(next <= lease.expires_at);
}

#[test]
fn link_loss_is_explicit_and_stops_timers() {
    let mut sm = DhcpClientStateMachine::new(MAC);
    acquire(&mut sm, Duration::ZERO, 80);
    assert_eq!(sm.link_lost(), vec![Action::LeaseLost]);
    assert!(matches!(sm.state(), DhcpClientState::WaitingForLink));
    assert!(sm.timeout(Duration::from_secs(100), 9, 0).is_empty());
    assert!(matches!(
        sm.receive(
            Duration::from_secs(100),
            &reply(XID, DhcpMessageType::Ack, ADDRESS, Some(80)),
            0
        )[0],
        Action::ReplyIgnored(IgnoreReason::NotExpected)
    ));
}

#[test]
fn secs_is_monotonic_and_saturates() {
    let mut sm = DhcpClientStateMachine::new(MAC);
    sm.link_ready(Duration::ZERO, XID, None, 0);
    let actions = sm.timeout(Duration::from_secs(70_000), 9, 0);
    let packet = DhcpPacket::parse(sent(&actions).0).unwrap();
    assert_eq!(packet.secs, u16::MAX);
}
