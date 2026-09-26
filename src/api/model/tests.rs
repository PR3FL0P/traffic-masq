use super::*;

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
    let parsed: RouteStatus = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, status);
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
        }],
    };
    let json_resp = serde_json::to_string(&resp).expect("serialize response");
    let parsed_resp: Response = serde_json::from_str(&json_resp).expect("deserialize response");
    match parsed_resp {
        Response::Routes { routes } => {
            assert_eq!(routes.len(), 1);
            assert_eq!(routes[0].owner, RouteOwner::TrafficMasqStatic);
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
