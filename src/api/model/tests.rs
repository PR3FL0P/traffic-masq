use super::*;
use crate::config::{WifiBand, WifiChannelWidth, WifiSecurity};

#[test]
fn interface_request_view_preserves_nested_config_json() {
    use crate::config::{
        DhcpClientInterfaceConfig, InterfaceRole, WifiApConfig, WifiClientConfig,
        WifiClientSecurity,
    };

    let config = InterfaceConfig {
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some("192.0.2.1/24".parse().unwrap()),
        dhcp: Some(DhcpInterfaceConfig {
            pool_start: Ipv4Addr::new(192, 0, 2, 10),
            pool_end: Ipv4Addr::new(192, 0, 2, 20),
            router: Ipv4Addr::new(192, 0, 2, 1),
            dns_servers: vec![Ipv4Addr::new(1, 1, 1, 1)],
            lease_seconds: Some(3600),
        }),
        dhcp_client: Some(DhcpClientInterfaceConfig::default()),
        wifi: Some(WifiApConfig {
            ssid: "local".into(),
            country_code: Some("UA".into()),
            band: WifiBand::Ghz5,
            channel: 36,
            channel_width: WifiChannelWidth::Vht80,
            security: WifiSecurity::Wpa2Wpa3,
            hidden: false,
            client_isolation: true,
            max_stations: 24,
            passphrase_file: Some("/run/traffic-masq/ap.psk".into()),
        }),
        wifi_client: Some(WifiClientConfig {
            ssid: "upstream".into(),
            country_code: None,
            security: WifiClientSecurity::Wpa2,
            passphrase_file: None,
        }),
        nat: false,
    };
    let expected = serde_json::to_value(&config).unwrap();
    let view: traffic_masq_protocol::InterfaceConfigView = config.clone().into();
    assert_eq!(serde_json::to_value(&view).unwrap(), expected);
    assert_eq!(InterfaceConfig::from(view), config);

    let request = Request::ApplyInterface {
        interface: "lan0".into(),
        config: config.into(),
        allow_management_change: false,
    };
    assert_eq!(serde_json::to_value(request).unwrap()["config"], expected);
}

#[test]
fn router_proposal_view_preserves_nested_config_json() {
    use crate::config::{
        ForwardingConfig, InterfaceRole, OwnedIpv4RouteConfig, UplinkConfig, UplinkMode,
        VpnHopConfig,
    };

    let proposal = RouterProposalRequest {
        set_router: Some(RouterConfig {
            uplink: Some(UplinkConfig {
                interface: "wan0".into(),
                mode: UplinkMode::External,
            }),
            forwarding: Some(vec![ForwardingConfig {
                source_subnet: Some("192.0.2.0/24".parse().unwrap()),
                from: "lan0".into(),
                to: "wan0".into(),
                masquerade: false,
            }]),
            owned_routes: vec![OwnedIpv4RouteConfig {
                destination: "203.0.113.0/24".parse().unwrap(),
                gateway: Some(Ipv4Addr::new(192, 0, 2, 1)),
                output_interface: Some("wan0".into()),
                table: 254,
                metric: Some(50),
            }],
            allow_default_route_change: true,
            vpn_chain: vec![VpnHopConfig {
                profile_name: "exit".into(),
            }],
            route_host_traffic: false,
        }),
        clear_router: false,
        set_interfaces: BTreeMap::from([(
            "lan0".into(),
            InterfaceOverrideRequest {
                config: InterfaceConfig {
                    role: InterfaceRole::Output,
                    managed: true,
                    ipv4: Some("192.0.2.1/24".parse().unwrap()),
                    dhcp: None,
                    dhcp_client: None,
                    wifi: None,
                    wifi_client: None,
                    nat: true,
                },
                allow_management_change: false,
            },
        )]),
        remove_interfaces: vec!["old0".into()],
    };
    let expected = serde_json::to_value(&proposal).unwrap();
    let view: traffic_masq_protocol::RouterProposalRequestView = proposal.clone().into();
    assert_eq!(serde_json::to_value(&view).unwrap(), expected);
    assert_eq!(
        serde_json::to_value(RouterProposalRequest::from(view)).unwrap(),
        expected
    );
}

#[test]
fn dhcp_wire_request_converts_to_domain_config() {
    let json = serde_json::json!({
        "type": "configure_dhcp",
        "interface": "lan0",
        "config": {
            "pool_start": "192.0.2.10",
            "pool_end": "192.0.2.20",
            "router": "192.0.2.1",
            "dns_servers": ["1.1.1.1"],
            "lease_seconds": 3600
        }
    });
    let Request::ConfigureDhcp { config, .. } = serde_json::from_value::<Request>(json).unwrap()
    else {
        panic!("wrong request variant");
    };
    let domain: DhcpInterfaceConfig = config.into();
    assert_eq!(domain.pool_start, Ipv4Addr::new(192, 0, 2, 10));
    assert_eq!(domain.lease_seconds, Some(3600));
    assert_eq!(domain.dns_servers, vec![Ipv4Addr::new(1, 1, 1, 1)]);
}

#[test]
fn dhcp_service_view_preserves_wire_shape() {
    let spec = DhcpServiceSpec {
        interface: "lan0".into(),
        server_ip: Ipv4Addr::new(192, 0, 2, 1),
        prefix_len: 24,
        subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
        pool_start: Ipv4Addr::new(192, 0, 2, 10),
        pool_end: Ipv4Addr::new(192, 0, 2, 20),
        router: Ipv4Addr::new(192, 0, 2, 1),
        dns_servers: vec![Ipv4Addr::new(1, 1, 1, 1)],
        lease_seconds: 3600,
    };
    let expected = serde_json::to_value(&spec).unwrap();
    let view: DhcpServiceView = spec.into();
    assert_eq!(serde_json::to_value(view).unwrap(), expected);
}

#[test]
fn router_plan_actions_preserve_wire_shape() {
    use crate::core::router::{DhcpPlan, RouterRisk, WifiPlan};
    use traffic_masq_protocol::{DhcpPlanView, RouterRiskView, WifiPlanView};

    let spec = DhcpServiceSpec {
        interface: "lan0".into(),
        server_ip: Ipv4Addr::new(192, 0, 2, 1),
        prefix_len: 24,
        subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
        pool_start: Ipv4Addr::new(192, 0, 2, 10),
        pool_end: Ipv4Addr::new(192, 0, 2, 20),
        router: Ipv4Addr::new(192, 0, 2, 1),
        dns_servers: vec![Ipv4Addr::new(1, 1, 1, 1)],
        lease_seconds: 3600,
    };
    for plan in [
        DhcpPlan::Start {
            desired: spec.clone(),
        },
        DhcpPlan::Stop {
            current: spec.clone(),
        },
        DhcpPlan::Reconfigure {
            current: spec.clone(),
            desired: spec.clone(),
        },
        DhcpPlan::Unchanged { current: spec },
    ] {
        let expected = serde_json::to_value(&plan).unwrap();
        let view: DhcpPlanView = plan.into();
        assert_eq!(serde_json::to_value(&view).unwrap(), expected);
        let decoded: DhcpPlanView = serde_json::from_value(expected).unwrap();
        assert_eq!(decoded, view);
    }

    let risk = RouterRisk {
        changes_default_route: true,
        requires_management_confirmation: false,
    };
    let expected = serde_json::to_value(&risk).unwrap();
    let view: RouterRiskView = risk.into();
    assert_eq!(serde_json::to_value(view).unwrap(), expected);

    let wifi = WifiPlan::Start {
        desired: WifiApSpec {
            interface: "wlan0".into(),
            ssid: "test-net".into(),
            country_code: None,
            band: WifiBand::Ghz5,
            channel: 36,
            channel_width: WifiChannelWidth::Vht80,
            security: WifiSecurity::Wpa2Wpa3,
            hidden: false,
            client_isolation: false,
            max_stations: 16,
            passphrase_file: None,
        },
    };
    let expected = serde_json::to_value(&wifi).unwrap();
    let view: WifiPlanView<WifiApSpecView> = super::router_plan::wifi_plan_view(wifi);
    assert_eq!(serde_json::to_value(view).unwrap(), expected);
}

#[test]
fn route_plan_view_preserves_wire_shape() {
    use crate::core::route::RoutePlan;
    use crate::netlink::{Ipv4RouteInfo, Ipv4RouteSpec};
    use traffic_masq_protocol::RoutePlanView;

    let plan = RoutePlan {
        add: vec![Ipv4RouteSpec {
            destination: "203.0.113.0/24".parse().unwrap(),
            gateway: Some(Ipv4Addr::new(192, 0, 2, 1)),
            output_interface_index: Some(7),
            table: 254,
            metric: Some(50),
            protocol: 201,
        }],
        delete: vec![Ipv4RouteInfo {
            destination: "198.51.100.0/24".parse().unwrap(),
            gateway: None,
            output_interface_index: Some(8),
            table: 254,
            metric: None,
            protocol: 201,
            scope: 0,
        }],
    };
    let expected = serde_json::to_value(&plan).unwrap();
    let view: RoutePlanView = plan.into();
    assert_eq!(serde_json::to_value(&view).unwrap(), expected);
    assert_eq!(
        serde_json::from_value::<RoutePlanView>(expected).unwrap(),
        view
    );
}

#[test]
fn route_owner_view_matches_netlink_ownership_and_labels() {
    use traffic_masq_protocol::RouteOwnerView;

    for protocol in u8::MIN..=u8::MAX {
        let domain = crate::netlink::RouteOwner::from_protocol(protocol);
        let view = RouteOwnerView::from_protocol(protocol);
        assert_eq!(view.is_owned(), domain.is_owned());
        assert_eq!(view.is_editable(), domain.is_editable());
        assert_eq!(view.to_string(), domain.to_string());
        assert_eq!(view, super::route::route_owner_to_view(domain));
    }
}

#[test]
fn address_owner_view_matches_netlink_tags() {
    use crate::netlink::AddressOwner;
    use traffic_masq_protocol::AddressOwnerView;

    for protocol in std::iter::once(None).chain((u8::MIN..=u8::MAX).map(Some)) {
        let expected = match AddressOwner::from_protocol(protocol) {
            AddressOwner::TrafficMasqStatic => AddressOwnerView::TrafficMasqStatic,
            AddressOwner::TrafficMasqDhcp => AddressOwnerView::TrafficMasqDhcp,
            AddressOwner::Untagged => AddressOwnerView::Untagged,
            AddressOwner::Foreign(value) => AddressOwnerView::Foreign(value),
        };
        assert_eq!(AddressOwnerView::from_protocol(protocol), expected);
    }
}

#[test]
fn router_plan_view_preserves_complete_wire_shape() {
    use crate::core::route::{ManagedIpv4Route, RoutePlan};
    use crate::core::router::{
        RouterDesired, RouterInterfaceDesired, RouterPlan, RouterRisk, VpnChainPlan, WifiPlan,
    };
    use crate::core::vpn_chain::{VpnHopDesired, VpnHopKind, VpnHopRoutingDesired};
    use crate::core::vpn_policy::VpnPolicyReservedIds;
    use crate::firewall::{
        OutputNetwork, OwnedFirewallIntegrity, RouterDataplaneDesired, RouterDataplanePlan,
        RouterDataplaneSnapshot, RouterDataplaneTarget,
    };
    use traffic_masq_protocol::RouterPlanView;

    let forwarding = vec![crate::config::ForwardingConfig {
        source_subnet: Some("192.0.2.0/24".parse().unwrap()),
        from: "lan0".into(),
        to: "wan0".into(),
        masquerade: true,
    }];
    let dataplane = RouterDataplaneDesired {
        forwarding: Some(forwarding),
        uplink: String::new(),
        outputs: vec![OutputNetwork {
            interface: "lan0".into(),
            subnet: "192.0.2.0/24".parse().unwrap(),
        }],
    };
    let hop = VpnHopDesired {
        hop_index: 0,
        profile_name: "exit".into(),
        interface: "tm-wg-0".into(),
        upstream: "wan0".into(),
        reserved: VpnPolicyReservedIds::default(),
        kind: VpnHopKind::Relay {
            own_route: VpnHopRoutingDesired {
                hop_interface: "tm-wg-0".into(),
                upstream_interface: "wan0".into(),
            },
        },
    };
    let wifi = WifiApSpec {
        interface: "wlan0".into(),
        ssid: "lan".into(),
        country_code: Some("UA".into()),
        band: WifiBand::Ghz5,
        channel: 36,
        channel_width: WifiChannelWidth::Vht80,
        security: WifiSecurity::Wpa2Wpa3,
        hidden: false,
        client_isolation: true,
        max_stations: 16,
        passphrase_file: None,
    };
    let plan = RouterPlan {
        desired: RouterDesired {
            enabled: true,
            uplink_wifi: None,
            uplink_dhcp: None,
            output_wifi: vec![wifi.clone()],
            dhcp: vec![],
            routes: vec![ManagedIpv4Route {
                destination: "198.51.100.0/24".parse().unwrap(),
                gateway: Some(Ipv4Addr::new(192, 0, 2, 1)),
                output_interface: Some("wan0".into()),
                table: 254,
                metric: Some(50),
            }],
            allow_default_route_change: true,
            vpn_chain: vec![hop.clone()],
            dataplane: RouterDataplaneTarget::Enabled(dataplane.clone()),
            interfaces: vec![RouterInterfaceDesired {
                name: "lan0".into(),
                config: InterfaceConfig {
                    role: crate::config::InterfaceRole::Output,
                    managed: true,
                    ipv4: Some("192.0.2.1/24".parse().unwrap()),
                    dhcp: None,
                    dhcp_client: None,
                    wifi: None,
                    wifi_client: None,
                    nat: true,
                },
            }],
        },
        interfaces: vec![],
        uplink_wifi: vec![],
        output_wifi: vec![WifiPlan::Start { desired: wifi }],
        dhcp: vec![],
        routes: RoutePlan {
            add: vec![],
            delete: vec![],
        },
        vpn_chain: VpnChainPlan { hops: vec![hop] },
        dataplane: RouterDataplanePlan {
            snapshot: RouterDataplaneSnapshot {
                ipv4_forwarding: false,
                owned: None,
                owned_firewall_integrity: OwnedFirewallIntegrity::Intact,
            },
            target: RouterDataplaneTarget::Enabled(dataplane),
            requires_apply: true,
        },
        risk: RouterRisk {
            changes_default_route: true,
            requires_management_confirmation: true,
        },
    };
    let expected = serde_json::to_value(&plan).unwrap();
    let view: RouterPlanView = plan.into();
    assert_eq!(serde_json::to_value(&view).unwrap(), expected);
    assert_eq!(
        serde_json::from_value::<RouterPlanView>(expected).unwrap(),
        view
    );
}

#[test]
fn wifi_ap_spec_view_preserves_wire_shape() {
    let spec = WifiApSpec {
        interface: "wlan0".into(),
        ssid: "test-net".into(),
        country_code: Some("LV".into()),
        band: WifiBand::Ghz5,
        channel: 36,
        channel_width: WifiChannelWidth::Vht80,
        security: WifiSecurity::Wpa2Wpa3,
        hidden: true,
        client_isolation: true,
        max_stations: 24,
        passphrase_file: Some("/run/traffic-masq/wifi/wlan0.psk".into()),
    };
    let expected = serde_json::to_value(&spec).unwrap();
    let view: WifiApSpecView = spec.into();
    assert_eq!(serde_json::to_value(view).unwrap(), expected);
}

#[test]
fn validated_ap_config_derives_the_same_client_spec() {
    use crate::config::{InterfaceRole, WifiApConfig};

    let config = InterfaceConfig {
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some("192.0.2.1/24".parse().unwrap()),
        dhcp: None,
        dhcp_client: None,
        wifi: Some(WifiApConfig {
            ssid: "test-net".into(),
            country_code: Some("US".into()),
            band: WifiBand::Ghz5,
            channel: 36,
            channel_width: WifiChannelWidth::Vht80,
            security: WifiSecurity::Wpa2Wpa3,
            hidden: true,
            client_isolation: true,
            max_stations: 24,
            passphrase_file: Some("/run/traffic-masq/ap.psk".into()),
        }),
        wifi_client: None,
        nat: true,
    };
    config.validate("wlan0").unwrap();
    let expected: WifiApSpecView = WifiApSpec::from_interface_config("wlan0", &config)
        .unwrap()
        .unwrap()
        .into();
    let view: traffic_masq_protocol::InterfaceConfigView = config.clone().into();
    assert_eq!(
        WifiApSpecView::from_validated_interface_config("wlan0", &view),
        Some(expected)
    );
    let mut unmanaged = view;
    unmanaged.managed = false;
    assert!(WifiApSpecView::from_validated_interface_config("wlan0", &unmanaged).is_none());
}

#[test]
fn route_status_serde_roundtrip() {
    let status = RouteStatus {
        destination: "192.168.1.0/24".parse().expect("dest"),
        gateway: Some(Ipv4Addr::new(10, 0, 0, 1)),
        output_interface: Some("eth0".to_string()),
        output_interface_index: Some(2),
        table: 254,
        metric: Some(100),
        protocol: 201,
        scope: 0,
        owner: RouteOwner::TrafficMasqStatic,
    };

    let json = serde_json::to_string(&status).expect("serialize");
    let view: traffic_masq_protocol::RouteStatusView = status.clone().into();
    assert_eq!(
        serde_json::to_value(&view).unwrap(),
        serde_json::to_value(&status).unwrap()
    );
    assert_eq!(RouteStatus::from(view), status);
    let parsed: RouteStatus = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, status);
}

#[test]
fn interface_status_view_preserves_observed_json() {
    let address = Ipv4AddressInfo {
        interface_index: 7,
        address: Ipv4Addr::new(192, 0, 2, 5),
        prefix_len: 24,
        protocol: Some(201),
    };
    let status = InterfaceStatus {
        owned_ipv4_addresses: Some(vec![address.clone()]),
        interface: NetworkInterface {
            index: 7,
            name: "lan0".into(),
            is_up: true,
            rx_bytes: 123,
            tx_bytes: 456,
            is_wireless: false,
        },
        ipv4_addresses: vec![address],
        has_default_route: true,
    };
    let view: traffic_masq_protocol::InterfaceStatusView = status.clone().into();
    assert_eq!(
        serde_json::to_value(&view).unwrap(),
        serde_json::to_value(&status).unwrap()
    );
    assert_eq!(InterfaceStatus::from(view), status);
}

#[test]
fn wifi_client_spec_view_preserves_json() {
    let spec = crate::wifi::WifiClientSpec {
        interface: "wlan0".into(),
        ssid: "upstream".into(),
        country_code: Some("UA".into()),
        security: crate::config::WifiClientSecurity::Wpa2,
        passphrase_file: Some("/run/traffic-masq/client.psk".into()),
    };
    let view: traffic_masq_protocol::WifiClientSpecView = spec.clone().into();
    assert_eq!(
        serde_json::to_value(&view).unwrap(),
        serde_json::to_value(&spec).unwrap()
    );
    assert_eq!(crate::wifi::WifiClientSpec::from(view), spec);
}

#[test]
fn interface_plan_view_preserves_json() {
    use crate::core::interface::{DhcpChangeAction, InterfaceChangePlan};

    let address = Ipv4AddressInfo {
        interface_index: 7,
        address: Ipv4Addr::new(192, 0, 2, 5),
        prefix_len: 24,
        protocol: Some(201),
    };
    let plan = InterfaceChangePlan {
        interface: "lan0".into(),
        delete_ipv4: vec![address.clone()],
        retag_ipv4: Some(address.clone()),
        add_ipv4: Some(address),
        set_link_up: true,
        management_change: false,
        dhcp_action: DhcpChangeAction::Reconfigure,
        releasing_management: false,
    };
    let view: traffic_masq_protocol::InterfaceChangePlanView = plan.clone().into();
    assert_eq!(
        serde_json::to_value(&view).unwrap(),
        serde_json::to_value(&plan).unwrap()
    );
    assert_eq!(InterfaceChangePlan::from(view), plan);
}

#[test]
fn wifi_status_views_preserve_json() {
    use crate::wifi::lifecycle::WifiHealth;
    use crate::wifi::{HostapdState, WifiApStatus, WifiClientStatus, WpaState};

    let ap = WifiApStatus {
        interface: "wlan0".into(),
        spec: WifiApSpec {
            interface: "wlan0".into(),
            ssid: "local".into(),
            country_code: None,
            band: WifiBand::Ghz2,
            channel: 6,
            channel_width: WifiChannelWidth::Ht20,
            security: WifiSecurity::Open,
            hidden: false,
            client_isolation: false,
            max_stations: 32,
            passphrase_file: None,
        },
        pid: 123,
        hostapd_state: HostapdState::Enabled,
        num_stations: Some(2),
        health: WifiHealth::Healthy,
    };
    let ap_view: traffic_masq_protocol::WifiApStatusView = ap.clone().into();
    assert_eq!(
        serde_json::to_value(&ap_view).unwrap(),
        serde_json::to_value(&ap).unwrap()
    );
    assert_eq!(WifiApStatus::from(ap_view), ap);

    let client = WifiClientStatus {
        interface: "wlan1".into(),
        spec: crate::wifi::WifiClientSpec {
            interface: "wlan1".into(),
            ssid: "upstream".into(),
            country_code: None,
            security: crate::config::WifiClientSecurity::Wpa2,
            passphrase_file: None,
        },
        pid: 456,
        wpa_state: WpaState::Completed,
        bssid: Some(crate::wifi::MacAddr::new([1, 2, 3, 4, 5, 6])),
        freq: Some(2412),
        health: WifiHealth::Retrying {
            error: "temporary".into(),
            attempts: 2,
            retry_in_secs: Some(5),
            competing_managers: vec!["other".into()],
            advice: Some("retry".into()),
        },
    };
    let client_view: traffic_masq_protocol::WifiClientStatusView = client.clone().into();
    assert_eq!(
        serde_json::to_value(&client_view).unwrap(),
        serde_json::to_value(&client).unwrap()
    );
    assert_eq!(WifiClientStatus::from(client_view), client);
}

#[test]
fn request_and_response_route_variants_roundtrip() {
    let req = Request::ListRoutes {
        include_local_table: true,
    };
    let json_req = serde_json::to_string(&req).expect("serialize request");
    let parsed_req: Request = serde_json::from_str(&json_req).expect("deserialize request");
    match parsed_req {
        Request::ListRoutes {
            include_local_table,
        } => assert!(include_local_table),
        _ => panic!("wrong variant"),
    }

    let resp = Response::Routes {
        routes: vec![RouteStatus {
            destination: "0.0.0.0/0".parse().expect("dest"),
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            output_interface: Some("wan0".to_string()),
            output_interface_index: Some(3),
            table: 254,
            metric: None,
            protocol: 201,
            scope: 0,
            owner: RouteOwner::TrafficMasqStatic,
        }
        .into()],
    };
    let json_resp = serde_json::to_string(&resp).expect("serialize response");
    let parsed_resp: Response = serde_json::from_str(&json_resp).expect("deserialize response");
    match parsed_resp {
        Response::Routes { routes } => {
            assert_eq!(routes.len(), 1);
            assert_eq!(
                routes[0].owner,
                traffic_masq_protocol::RouteOwnerView::TrafficMasqStatic
            );
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn provision_request_body_keeps_wire_format_and_redacts_debug() {
    let secret = "correct horse battery";
    let body = ProvisionWifiAccessPointRequest {
        settings: WifiEditRequest {
            ssid: "test".to_string(),
            country_code: None,
            band: WifiBand::Ghz2,
            channel: 6,
            channel_width: WifiChannelWidth::Ht20,
            security: WifiSecurity::Wpa2,
            hidden: false,
            client_isolation: false,
            max_stations: 32,
        },
        passphrase: Some(secret.to_string()),
        clear_passphrase: false,
        configure_dhcp: false,
        subnet: None,
        disable_dhcp: false,
    };
    let json = serde_json::to_value(&body).expect("serialize");
    assert_eq!(json["passphrase"], secret);
    let debug = format!("{body:?}");
    assert!(!debug.contains(secret), "{debug}");
    assert!(debug.contains("redacted"), "{debug}");
}

#[test]
fn provision_request_debug_redacts_the_ap_passphrase() {
    let secret = "correct horse battery";
    let request = Request::ProvisionWifiAccessPoint {
        interface: "wlan0".to_string(),
        settings: WifiEditRequest {
            ssid: "test".to_string(),
            country_code: None,
            band: WifiBand::Ghz2,
            channel: 1,
            channel_width: WifiChannelWidth::Ht20,
            security: WifiSecurity::Wpa2,
            hidden: false,
            client_isolation: false,
            max_stations: 32,
        },
        passphrase: Some(secret.into()),
        clear_passphrase: false,
        configure_dhcp: false,
        subnet: None,
        disable_dhcp: false,
    };
    let debug = format!("{request:?}");
    assert!(!debug.contains(secret), "{debug}");
    assert!(debug.contains("redacted"), "{debug}");
}

#[test]
fn provision_request_without_clear_flag_remains_backward_compatible() {
    let json = serde_json::json!({
        "settings": {
            "ssid": "legacy-open",
            "max_stations": 32
        },
        "configure_dhcp": false
    });
    let request: ProvisionWifiAccessPointRequest =
        serde_json::from_value(json).expect("legacy request");
    assert!(!request.clear_passphrase);
    assert!(request.passphrase.is_none());
}

#[test]
fn wifi_set_passphrase_request_debug_is_redacted() {
    let secret = "correct horse battery";
    let request = Request::WifiSetPassphrase {
        interface: "wlan0".to_string(),
        passphrase: secret.into(),
    };
    let debug = format!("{request:?}");
    assert!(!debug.contains(secret), "{debug}");
    assert!(debug.contains("redacted"), "{debug}");
}
