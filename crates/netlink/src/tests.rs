use async_trait::async_trait;

use super::*;

#[test]
fn interface_is_wireless_rejects_loopback_and_nonexistent_names() {
    #[cfg(target_os = "linux")]
    {
        assert!(!interface_is_wireless("lo"));
    }
    assert!(!interface_is_wireless(
        "definitely-not-a-real-interface-xyz"
    ));
}

#[test]
fn wireless_phy_is_absent_for_non_wireless_and_unknown_interfaces() {
    #[cfg(target_os = "linux")]
    {
        assert_eq!(wireless_phy("lo"), None);
    }
    assert_eq!(wireless_phy("definitely-not-a-real-interface-xyz"), None);
}

#[test]
fn route_spec_requires_next_hop_and_explicit_table() {
    let mut route = Ipv4RouteSpec {
        destination: "0.0.0.0/0".parse().expect("route"),
        gateway: None,
        output_interface_index: None,
        table: 254,
        metric: None,
        protocol: TRAFFIC_MASQ_ROUTE_PROTOCOL,
    };
    assert!(route.validate().is_err());

    route.gateway = Some(Ipv4Addr::new(192, 0, 2, 1));
    route.validate().expect("gateway route");

    route.table = 0;
    assert!(route.validate().is_err());

    route.table = 254;
    route.protocol = 0;
    assert!(route.validate().is_err());
}

#[test]
fn ipv4_rule_requires_explicit_table_and_selector() {
    let mut rule = Ipv4RuleSpec {
        source: None,
        destination: None,
        table: 100,
        priority: Some(1_000),
        fw_mark: None,
        fw_mask: None,
        input_interface: None,
        output_interface: None,
    };
    assert!(rule.validate().is_err());

    rule.fw_mark = Some(0x42);
    rule.validate()
        .expect("fwmark selector makes the rule valid");

    rule.table = 0;
    assert!(rule.validate().is_err());
}

#[test]
fn ipv4_rule_rejects_mask_without_mark() {
    let rule = Ipv4RuleSpec {
        source: Some("192.0.2.0/24".parse().expect("source")),
        destination: None,
        table: 100,
        priority: Some(1_000),
        fw_mark: None,
        fw_mask: Some(0xffff0000),
        input_interface: None,
        output_interface: None,
    };
    assert!(rule.validate().is_err());
}

#[test]
fn parses_supported_ipv4_lookup_rule() {
    let mut message = RuleMessage::default();
    message.header.family = AddressFamily::Inet;
    message.header.src_len = 24;
    message.header.dst_len = 24;
    message.header.table = 100;
    message.header.action = RuleAction::ToTable;
    message
        .attributes
        .push(RuleAttribute::Source(Ipv4Addr::new(192, 0, 2, 0).into()));
    message.attributes.push(RuleAttribute::Destination(
        Ipv4Addr::new(198, 51, 100, 0).into(),
    ));
    message.attributes.push(RuleAttribute::Priority(1_100));
    message.attributes.push(RuleAttribute::FwMark(0x42));
    message.attributes.push(RuleAttribute::FwMask(0xff));
    message
        .attributes
        .push(RuleAttribute::Iifname("lan0".into()));
    message
        .attributes
        .push(RuleAttribute::Oifname("tm-wg0".into()));

    let parsed = parse_ipv4_rule(&message)
        .expect("rule parse")
        .expect("supported rule");
    assert_eq!(parsed.source, Some("192.0.2.0/24".parse().expect("source")));
    assert_eq!(
        parsed.destination,
        Some("198.51.100.0/24".parse().expect("destination"))
    );
    assert_eq!(parsed.table, 100);
    assert_eq!(parsed.priority, Some(1_100));
    assert_eq!(parsed.fw_mark, Some(0x42));
    assert_eq!(parsed.fw_mask, Some(0xff));
    assert_eq!(parsed.input_interface.as_deref(), Some("lan0"));
    assert_eq!(parsed.output_interface.as_deref(), Some("tm-wg0"));
}

#[test]
fn parses_rule_with_kernel_assigned_protocol_and_unset_suppress_prefixlen() {
    let mut message = RuleMessage::default();
    message.header.family = AddressFamily::Inet;
    message.header.action = RuleAction::ToTable;
    message.attributes.push(RuleAttribute::Table(30_100));
    message
        .attributes
        .push(RuleAttribute::SuppressPrefixLen(u32::MAX));
    message
        .attributes
        .push(RuleAttribute::Protocol(RouteProtocol::Unspec));
    message.attributes.push(RuleAttribute::Priority(10_100));
    message.attributes.push(RuleAttribute::FwMark(0x5400_0000));
    message.attributes.push(RuleAttribute::FwMask(0xff00_0000));

    let parsed = parse_ipv4_rule(&message).expect("rule parse").expect(
        "rule with kernel-assigned protocol/suppress-prefixlen attributes must still be recognized",
    );
    assert_eq!(parsed.table, 30_100);
    assert_eq!(parsed.priority, Some(10_100));
    assert_eq!(parsed.fw_mark, Some(0x5400_0000));
    assert_eq!(parsed.fw_mask, Some(0xff00_0000));
}

#[test]
fn parses_builtin_system_rule_with_no_selectors() {
    let mut message = RuleMessage::default();
    message.header.family = AddressFamily::Inet;
    message.header.action = RuleAction::ToTable;
    message.attributes.push(RuleAttribute::Table(254));
    message
        .attributes
        .push(RuleAttribute::SuppressPrefixLen(u32::MAX));
    message
        .attributes
        .push(RuleAttribute::Protocol(RouteProtocol::Kernel));
    message.attributes.push(RuleAttribute::Priority(32_766));

    let parsed = parse_ipv4_rule(&message)
        .expect("rule parse")
        .expect("built-in system rule must parse, not be treated as unsupported");
    assert_eq!(parsed.table, 254);
    assert_eq!(parsed.priority, Some(32_766));
    assert_eq!(parsed.fw_mark, None);
}

#[test]
fn skips_rule_with_suppress_prefixlen_actually_set() {
    let mut message = RuleMessage::default();
    message.header.family = AddressFamily::Inet;
    message.header.action = RuleAction::ToTable;
    message.attributes.push(RuleAttribute::FwMark(0x42));
    message.attributes.push(RuleAttribute::SuppressPrefixLen(0));

    assert!(parse_ipv4_rule(&message).expect("parse").is_none());
}

#[test]
fn skips_rule_with_unsupported_match_extensions() {
    let mut message = RuleMessage::default();
    message.header.family = AddressFamily::Inet;
    message.header.action = RuleAction::ToTable;
    message.header.table = 100;
    message.attributes.push(RuleAttribute::FwMark(0x42));
    message.attributes.push(RuleAttribute::UidRange(
        netlink_packet_route::rule::RuleUidRange {
            start: 1000,
            end: 1000,
        },
    ));

    assert!(parse_ipv4_rule(&message).expect("parse").is_none());
}

struct TableFilterOnlyProvider {
    routes: Vec<Ipv4RouteInfo>,
}

#[async_trait]
impl NetworkProvider for TableFilterOnlyProvider {
    async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        Ok(Vec::new())
    }

    async fn list_ipv4_addresses(&self, _interface: &str) -> Result<Vec<Ipv4AddressInfo>> {
        Ok(Vec::new())
    }

    async fn set_link_up(&self, _name: &str) -> Result<()> {
        Ok(())
    }

    async fn set_link_down(&self, _name: &str) -> Result<()> {
        Ok(())
    }

    async fn add_ipv4_address(
        &self,
        _interface: &str,
        _address: Ipv4Addr,
        _prefix_len: u8,
        _ownership: AddressOwnership,
    ) -> Result<()> {
        Ok(())
    }

    async fn delete_ipv4_address(
        &self,
        _interface: &str,
        _address: Ipv4Addr,
        _prefix_len: u8,
    ) -> Result<()> {
        Ok(())
    }

    async fn list_ipv4_routes(&self) -> Result<Vec<Ipv4RouteInfo>> {
        Ok(self.routes.clone())
    }
}

#[tokio::test]
async fn default_route_table_filter_returns_only_requested_table() {
    let provider = TableFilterOnlyProvider {
        routes: vec![
            Ipv4RouteInfo {
                destination: "0.0.0.0/0".parse().expect("default route"),
                gateway: Some(Ipv4Addr::new(192, 0, 2, 1)),
                output_interface_index: Some(2),
                table: 100,
                metric: Some(50),
                protocol: TRAFFIC_MASQ_ROUTE_PROTOCOL,
                scope: 0,
            },
            Ipv4RouteInfo {
                destination: "198.51.100.0/24".parse().expect("subnet"),
                gateway: None,
                output_interface_index: Some(7),
                table: 254,
                metric: Some(100),
                protocol: TRAFFIC_MASQ_ROUTE_PROTOCOL,
                scope: 253,
            },
        ],
    };

    let filtered = provider
        .list_ipv4_routes_in_table(100)
        .await
        .expect("table filter");
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].table, 100);
    assert_eq!(
        filtered[0].destination,
        "0.0.0.0/0".parse().expect("default route")
    );
}

#[test]
fn route_owner_classification_and_display() {
    let cases = [
        (
            TRAFFIC_MASQ_ROUTE_PROTOCOL,
            RouteOwner::TrafficMasqStatic,
            true,
            true,
            "traffic-masq",
        ),
        (
            TRAFFIC_MASQ_DHCP_ROUTE_PROTOCOL,
            RouteOwner::TrafficMasqDhcp,
            true,
            false,
            "traffic-masq (dhcp)",
        ),
        (2, RouteOwner::Kernel, false, false, "[ext:kernel]"),
        (3, RouteOwner::Boot, false, false, "[ext:boot]"),
        (4, RouteOwner::Static, false, false, "[ext:static]"),
        (16, RouteOwner::Dhcp, false, false, "[ext:dhcp]"),
        (42, RouteOwner::Foreign(42), false, false, "[ext:proto 42]"),
        (0, RouteOwner::Untagged, false, false, "[?]"),
    ];

    for (proto, expected_owner, owned, editable, display) in cases {
        let owner = RouteOwner::from_protocol(proto);
        assert_eq!(owner, expected_owner);
        assert_eq!(owner.is_owned(), owned);
        assert_eq!(owner.is_editable(), editable);
        assert_eq!(owner.to_string(), display);
    }
}

#[test]
fn ipv4_route_spec_validates_gateway_and_table() {
    let valid = Ipv4RouteSpec {
        destination: "192.168.1.0/24".parse().unwrap(),
        gateway: Some(std::net::Ipv4Addr::new(192, 168, 1, 1)),
        output_interface_index: None,
        table: 254,
        metric: Some(100),
        protocol: TRAFFIC_MASQ_ROUTE_PROTOCOL,
    };
    assert!(valid.validate().is_ok());

    // Rejects 0.0.0.0
    let mut invalid_gw = valid.clone();
    invalid_gw.gateway = Some(std::net::Ipv4Addr::UNSPECIFIED);
    assert!(invalid_gw.validate().is_err());

    // Rejects broadcast 255.255.255.255
    invalid_gw.gateway = Some(std::net::Ipv4Addr::BROADCAST);
    assert!(invalid_gw.validate().is_err());

    // Rejects multicast 224.0.0.1
    invalid_gw.gateway = Some(std::net::Ipv4Addr::new(224, 0, 0, 1));
    assert!(invalid_gw.validate().is_err());

    // Rejects table 0 and 255
    let mut invalid_table = valid.clone();
    invalid_table.table = 0;
    assert!(invalid_table.validate().is_err());
    invalid_table.table = 255;
    assert!(invalid_table.validate().is_err());
}

#[tokio::test]
async fn rtnetlink_provider_serializes_shared_handle_requests() {
    let provider = Arc::new(RtnetlinkNetworkProvider::connect().expect("rtnetlink provider"));
    let guard = provider.request_lock.lock().await;

    let mut request = tokio::spawn({
        let provider = provider.clone();
        async move { provider.list_interfaces().await }
    });

    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), &mut request)
            .await
            .is_err(),
        "request unexpectedly bypassed the shared rtnetlink serialization lock"
    );

    drop(guard);
    tokio::time::timeout(std::time::Duration::from_secs(5), request)
        .await
        .expect("serialized request timed out")
        .expect("request task panicked")
        .expect("RTM_GETLINK failed after serialization lock was released");
}

#[tokio::test]
async fn concurrent_rtnetlink_reads_share_one_provider_without_overlap_errors() {
    let provider = Arc::new(RtnetlinkNetworkProvider::connect().expect("rtnetlink provider"));

    let (interfaces, routes, rules) = tokio::join!(
        provider.list_interfaces(),
        provider.list_ipv4_routes(),
        provider.list_ipv4_rules(),
    );

    interfaces.expect("interfaces");
    routes.expect("routes");
    rules.expect("rules");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn ipv4_address_read_uses_single_serialized_netlink_sequence() {
    let provider = RtnetlinkNetworkProvider::connect().expect("rtnetlink provider");
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        provider.list_ipv4_addresses("lo"),
    )
    .await
    .expect("nested RTM_GETLINK/RTM_GETADDR sequence deadlocked")
    .expect("IPv4 address read failed");
}

#[test]
fn ethernet_mac_allows_interfaces_without_ethernet_addresses() {
    assert_eq!(ethernet_mac(&[]), None);
    assert_eq!(ethernet_mac(&[LinkAttribute::Address(vec![])]), None);
    assert_eq!(ethernet_mac(&[LinkAttribute::Address(vec![0; 6])]), None);
    assert_eq!(ethernet_mac(&[LinkAttribute::Address(vec![0xff; 6])]), None);
    let mac = [2, 1, 2, 3, 4, 5];
    assert_eq!(
        ethernet_mac(&[LinkAttribute::Address(mac.to_vec())]),
        Some(mac)
    );
}

#[test]
fn route_dump_does_not_inherit_route_creation_filters() {
    let message = ipv4_route_dump_message();
    assert_eq!(message.header.address_family, AddressFamily::Inet);
    assert_eq!(message.header.table, 0);
    assert_eq!(message.header.protocol, RouteProtocol::Unspec);
    assert_eq!(message.header.kind, RouteType::Unspec);
    assert!(message.attributes.is_empty());
}
