use super::*;
use std::collections::VecDeque;
use std::sync::Mutex;
use tokio::sync::Notify;

struct FakeTransport {
    incoming: Mutex<VecDeque<IngressDatagram>>,
    sent: Mutex<Vec<SendKind>>,
    packets: Mutex<Vec<Vec<u8>>>,
    receive_calls: std::sync::atomic::AtomicUsize,
    activity: Notify,
    notify: Notify,
}
impl FakeTransport {
    fn new(incoming: Vec<IngressDatagram>) -> Self {
        Self {
            incoming: Mutex::new(incoming.into()),
            sent: Mutex::new(Vec::new()),
            packets: Mutex::new(Vec::new()),
            receive_calls: std::sync::atomic::AtomicUsize::new(0),
            activity: Notify::new(),
            notify: Notify::new(),
        }
    }
}
#[async_trait]
impl DhcpClientTransport for FakeTransport {
    async fn receive(&self) -> Result<IngressDatagram> {
        self.receive_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.activity.notify_one();
        loop {
            if let Some(value) = self.incoming.lock().unwrap().pop_front() {
                return Ok(value);
            }
            self.notify.notified().await;
        }
    }
    async fn send(&self, packet: &[u8], kind: SendKind) -> Result<()> {
        self.sent.lock().unwrap().push(kind);
        self.packets.lock().unwrap().push(packet.to_vec());
        self.activity.notify_one();
        Ok(())
    }
}

struct FakeDad(bool);
#[async_trait]
impl DuplicateAddressDetector for FakeDad {
    async fn is_duplicate(
        &self,
        _interface: &str,
        _ifindex: u32,
        _address: Ipv4Addr,
    ) -> Result<bool> {
        Ok(self.0)
    }
}

struct FakeArpIo {
    received: Mutex<VecDeque<Vec<u8>>>,
    sends: Mutex<Vec<Vec<u8>>>,
    receive_calls: Mutex<usize>,
}

#[async_trait]
impl ArpPacketIo for FakeArpIo {
    async fn send(&self, frame: &[u8]) -> Result<()> {
        self.sends.lock().unwrap().push(frame.to_vec());
        Ok(())
    }

    async fn receive_until(&self, _deadline: Instant) -> Result<Option<Vec<u8>>> {
        *self.receive_calls.lock().unwrap() += 1;
        Ok(self.received.lock().unwrap().pop_front())
    }
}

#[test]
fn arp_probe_encoding_and_conflict_parsing_are_rootless() {
    let own = [0x02, 0, 0, 0, 0, 1];
    let other = [0x02, 0, 0, 0, 0, 2];
    let candidate = Ipv4Addr::new(192, 0, 2, 10);
    let probe = arp_probe(own, candidate);
    assert_eq!(&probe[..6], &[0xff; 6]);
    assert_eq!(&probe[6..12], &own);
    assert_eq!(&probe[28..32], &[0; 4]);
    assert_eq!(&probe[38..42], &candidate.octets());
    assert!(!arp_conflicts(&probe, own, candidate));

    let mut simultaneous_probe = arp_probe(other, candidate);
    assert!(arp_conflicts(&simultaneous_probe, own, candidate));
    simultaneous_probe[6] ^= 1;
    assert!(!arp_conflicts(&simultaneous_probe, own, candidate));

    let mut claim = arp_probe(other, Ipv4Addr::new(192, 0, 2, 1));
    claim[20..22].copy_from_slice(&2u16.to_be_bytes());
    claim[28..32].copy_from_slice(&candidate.octets());
    assert!(arp_conflicts(&claim, own, candidate));
    claim[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    assert!(!arp_conflicts(&claim, own, candidate));
}

#[tokio::test]
async fn arp_probe_fake_is_bounded_and_stops_on_conflict() {
    let own = [0x02, 0, 0, 0, 0, 1];
    let candidate = Ipv4Addr::new(198, 51, 100, 7);
    let no_reply = FakeArpIo {
        received: Mutex::new(VecDeque::new()),
        sends: Mutex::new(Vec::new()),
        receive_calls: Mutex::new(0),
    };
    assert!(!probe_with_io_timing(
        &no_reply,
        own,
        candidate,
        Duration::ZERO,
        [Duration::ZERO; ARP_PROBE_COUNT - 1],
    )
    .await
    .unwrap());
    assert_eq!(no_reply.sends.lock().unwrap().len(), ARP_PROBE_COUNT);
    assert_eq!(*no_reply.receive_calls.lock().unwrap(), ARP_PROBE_COUNT + 1);

    let conflict = FakeArpIo {
        received: Mutex::new(VecDeque::from([arp_probe(
            [0x02, 0, 0, 0, 0, 2],
            candidate,
        )
        .to_vec()])),
        sends: Mutex::new(Vec::new()),
        receive_calls: Mutex::new(0),
    };
    assert!(probe_with_io_timing(
        &conflict,
        own,
        candidate,
        Duration::ZERO,
        [Duration::ZERO; ARP_PROBE_COUNT - 1],
    )
    .await
    .unwrap());
    assert_eq!(conflict.sends.lock().unwrap().len(), 0);
    assert_eq!(*conflict.receive_calls.lock().unwrap(), 1);
}

#[tokio::test]
async fn actor_sends_discover_rejects_wrong_ifindex_and_cancels() {
    let transport = Arc::new(FakeTransport::new(Vec::new()));
    let config = DhcpClientRuntimeConfig {
        hostname: Some("travel-router".into()),
        interface: "lo".into(),
        interface_index: 1,
        hardware_address: [2, 0, 0, 0, 0, 1],
        server_port: 1067,
        client_port: 1068,
        max_packet_size: 576,
    };
    let actor = DhcpClientActor::new(
        config,
        transport.clone(),
        Arc::new(FakeDad(false)),
        NoopActionSink,
    )
    .unwrap();
    let (tx, rx) = watch::channel(false);
    let task = tokio::spawn(actor.run(rx));
    // A matching, valid OFFER is essential: a malformed packet would be
    // discarded even if the interface-index check were removed.
    tokio::time::timeout(Duration::from_secs(5), async {
        while transport
            .receive_calls
            .load(std::sync::atomic::Ordering::SeqCst)
            < 1
        {
            transport.activity.notified().await;
        }
    })
    .await
    .expect("actor ready after DISCOVER");
    let mut offer = transport.packets.lock().unwrap()[0][..240].to_vec();
    offer[0] = 2; // BOOTREPLY; keep the DISCOVER's transaction ID and MAC.
    offer[16..20].copy_from_slice(&[192, 0, 2, 10]);
    offer.extend_from_slice(&[53, 1, 2, 54, 4, 192, 0, 2, 1, 255]);
    transport
        .incoming
        .lock()
        .unwrap()
        .push_back(IngressDatagram {
            bytes: offer.clone(),
            interface_index: 99,
        });
    transport.notify.notify_one();
    tokio::time::timeout(Duration::from_secs(5), async {
        while transport
            .receive_calls
            .load(std::sync::atomic::Ordering::SeqCst)
            < 2
        {
            transport.activity.notified().await;
        }
    })
    .await
    .expect("actor processed foreign OFFER");
    assert_eq!(
        transport.sent.lock().unwrap().as_slice(),
        &[SendKind::Broadcast]
    );
    transport
        .incoming
        .lock()
        .unwrap()
        .push_back(IngressDatagram {
            bytes: offer,
            interface_index: 1,
        });
    transport.notify.notify_one();
    tokio::time::timeout(Duration::from_secs(5), async {
        while transport.sent.lock().unwrap().len() < 2 {
            transport.activity.notified().await;
        }
    })
    .await
    .expect("matching OFFER must produce REQUEST");
    let packets = transport.packets.lock().unwrap().clone();
    let request = traffic_masq_dhcp_core::packet::DhcpPacket::parse(&packets[1]).unwrap();
    assert_eq!(
        request.message_type(),
        Some(traffic_masq_dhcp_core::packet::DhcpMessageType::Request)
    );
    for packet in &packets {
        let packet = traffic_masq_dhcp_core::packet::DhcpPacket::parse(packet).unwrap();
        assert_eq!(
            packet.singleton_option(12, "travel-router".len()).unwrap(),
            Some(b"travel-router".as_slice())
        );
    }
    tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[test]
fn dhcp_frame_encoding_and_parsing_are_rootless() {
    let mac = [0x02, 0, 0, 0, 0, 1];
    let payload = b"golden-dhcp";
    let frame = encode_dhcp_frame(
        payload,
        mac,
        Ipv4Addr::UNSPECIFIED,
        DHCP_CLIENT_PORT,
        DHCP_SERVER_PORT,
    )
    .unwrap();
    assert_eq!(&frame[..6], &[0xff; 6]);
    assert_eq!(&frame[6..12], &mac);
    assert_eq!(&frame[12..14], &[0x08, 0x00]);
    assert_eq!(&frame[14..24], &[0x45, 0, 0, 39, 0, 0, 0x40, 0, 64, 17]);
    assert_eq!(internet_checksum(&frame[14..34]), 0);
    assert_eq!(&frame[26..30], &[0, 0, 0, 0]);
    assert_eq!(&frame[30..34], &[255; 4]);
    assert_eq!(&frame[34..40], &[0, 68, 0, 67, 0, 19]);
    assert!(parse_dhcp_frame(&frame, mac).is_none());
    let reply = encode_dhcp_frame(
        payload,
        [0x02, 0, 0, 0, 0, 2],
        Ipv4Addr::new(192, 0, 2, 1),
        DHCP_SERVER_PORT,
        DHCP_CLIENT_PORT,
    )
    .unwrap();
    assert_eq!(parse_dhcp_frame(&reply, mac), Some(payload.as_slice()));

    let mut hardware_unicast = reply.clone();
    hardware_unicast[..6].copy_from_slice(&mac);
    assert_eq!(
        parse_dhcp_frame(&hardware_unicast, mac),
        Some(payload.as_slice())
    );

    let mut bad_ip_checksum = reply.clone();
    bad_ip_checksum[22] ^= 1;
    assert!(parse_dhcp_frame(&bad_ip_checksum, mac).is_none());
    let mut bad_udp_checksum = reply.clone();
    *bad_udp_checksum.last_mut().unwrap() ^= 1;
    assert!(parse_dhcp_frame(&bad_udp_checksum, mac).is_none());
    let mut fragment = reply.clone();
    fragment[20..22].copy_from_slice(&0x2000u16.to_be_bytes());
    fragment[24..26].fill(0);
    let checksum = internet_checksum(&fragment[14..34]);
    fragment[24..26].copy_from_slice(&checksum.to_be_bytes());
    assert!(parse_dhcp_frame(&fragment, mac).is_none());
    assert!(parse_dhcp_frame(&reply[..reply.len() - 1], mac).is_none());
}

#[test]
fn rebind_frame_uses_ciaddr_as_ipv4_source() {
    let source = Ipv4Addr::new(192, 0, 2, 42);
    let frame = encode_dhcp_frame(
        b"request",
        [0x02, 0, 0, 0, 0, 1],
        source,
        DHCP_CLIENT_PORT,
        DHCP_SERVER_PORT,
    )
    .unwrap();
    assert_eq!(&frame[26..30], &source.octets());
    assert_eq!(internet_checksum(&frame[14..34]), 0);
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires CAP_NET_RAW to create the DHCP packet socket"]
async fn socket_has_required_options() {
    use nix::sys::socket::getsockopt;
    use std::os::fd::BorrowedFd;
    let config = DhcpClientRuntimeConfig {
        hostname: None,
        interface: "lo".into(),
        interface_index: 1,
        hardware_address: [2, 0, 0, 0, 0, 1],
        server_port: 1067,
        client_port: 0,
        max_packet_size: 576,
    };
    let socket = LinuxDhcpClientSocket::bind(config).unwrap();
    let fd = unsafe { BorrowedFd::borrow_raw(socket.raw_fd()) };
    assert!(getsockopt(&fd, sockopt::ReuseAddr).unwrap());
    assert!(getsockopt(&fd, sockopt::Broadcast).unwrap());
    assert!(getsockopt(&fd, sockopt::Ipv4PacketInfo).unwrap());
    assert_eq!(
        getsockopt(&fd, sockopt::BindToDevice).unwrap(),
        OsString::from("lo\0")
    );
}
