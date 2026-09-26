use super::*;
use crate::api::model::Request;

#[tokio::test]
async fn silent_api_times_out_and_closes_connection() {
    use tokio::io::AsyncReadExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let client = ApiClient::new(path);
    let request = tokio::spawn(async move {
        client
            .send_with_timeout(
                Method::GET,
                "/api/v1/status",
                None,
                std::time::Duration::from_millis(50),
            )
            .await
    });
    let (mut peer, _) = listener.accept().await.unwrap();
    assert!(request
        .await
        .unwrap()
        .err()
        .expect("request timeout")
        .to_string()
        .contains("timed out"));
    tokio::task::yield_now().await;
    let mut bytes = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        peer.read_to_end(&mut bytes),
    )
    .await
    .unwrap()
    .unwrap();
}

#[test]
fn control_mutation_timeout_outlives_the_server_connection_deadline() {
    assert_eq!(
        control_request_timeout(&Method::GET),
        DEFAULT_REQUEST_TIMEOUT
    );
    for method in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
        assert_eq!(
            control_request_timeout(&method),
            CONTROL_MUTATION_REQUEST_TIMEOUT
        );
    }
    assert!(CONTROL_MUTATION_REQUEST_TIMEOUT > crate::api::HTTP_CONNECTION_TIMEOUT);
}

#[test]
fn percent_encodes_path_segments() {
    assert_eq!(encode_path_segment("eth0.100-guest_~"), "eth0.100-guest_~");
    assert_eq!(encode_path_segment("vlan/guest %"), "vlan%2Fguest%20%25");
    assert_eq!(encode_path_segment("é"), "%C3%A9");
}

#[test]
fn maps_ping_to_status_and_synthesizes_pong() {
    let mapped = map_request(&Request::Ping).expect("ping should map");

    assert_eq!(mapped.method, Method::GET);
    assert_eq!(mapped.path, "/api/v1/status");
    assert!(mapped.body.is_none());
    assert!(mapped.synthesize_pong);
}

#[test]
fn maps_all_dhcp_client_paths_without_using_server_dhcp_routes() {
    let cases = [
        (
            Request::GetDhcpClient {
                interface: "wan/0".into(),
            },
            Method::GET,
            "/api/v1/dhcp-client/wan%2F0",
        ),
        (
            Request::ConfigureDhcpClient {
                interface: "wan/0".into(),
                config: Default::default(),
            },
            Method::PUT,
            "/api/v1/dhcp-client/wan%2F0",
        ),
        (
            Request::DisableDhcpClient {
                interface: "wan/0".into(),
            },
            Method::DELETE,
            "/api/v1/dhcp-client/wan%2F0",
        ),
        (
            Request::RenewDhcpClient {
                interface: "wan/0".into(),
            },
            Method::POST,
            "/api/v1/dhcp-client/wan%2F0/renew",
        ),
        (
            Request::ReleaseDhcpClient {
                interface: "wan/0".into(),
            },
            Method::POST,
            "/api/v1/dhcp-client/wan%2F0/release",
        ),
    ];
    for (request, method, path) in cases {
        let mapped = map_request(&request).expect("DHCP client request should map");
        assert_eq!(mapped.method, method);
        assert_eq!(mapped.path, path);
        assert!(mapped.path.contains("dhcp-client"));
        assert!(!mapped.path.starts_with("/api/v1/dhcp/"));
    }
}

#[test]
fn maps_and_encodes_wifi_client_scan() {
    let mapped = map_request(&Request::WifiClientScan {
        interface: "wlan/guest".to_string(),
    })
    .expect("scan should map");

    assert_eq!(mapped.method, Method::POST);
    assert_eq!(mapped.path, "/api/v1/wifi-client/wlan%2Fguest/scan");
    assert!(mapped.body.is_none());
    assert!(!mapped.synthesize_pong);
}

#[test]
fn maps_provisioning_paths_under_the_existing_router_surface() {
    use crate::api::model::{
        ProvisioningOutputRequest, ProvisioningUplinkRequest, RouterProvisioningApplyRequest,
        RouterProvisioningPreviewRequest, RouterProvisioningRequest,
    };

    let provisioning = RouterProvisioningRequest {
        uplink: ProvisioningUplinkRequest {
            interface: "wlan-up".to_string(),
            ssid: "upstream".to_string(),
            country_code: None,
            security: Default::default(),
        },
        output: ProvisioningOutputRequest {
            interface: "wlan-out".to_string(),
            ssid: "traffic-masq".to_string(),
            country_code: None,
            band: Default::default(),
            channel: 6,
            channel_width: Default::default(),
            security: Default::default(),
            hidden: false,
            client_isolation: false,
            max_stations: 32,
        },
        downstream: Default::default(),
        allow_management_change: false,
    };

    let preview = map_request(&Request::RouterProvisioningPreview {
        request: RouterProvisioningPreviewRequest {
            provisioning: provisioning.clone(),
            uplink_secret_pending: true,
            output_secret_pending: true,
        },
    })
    .expect("preview should map");
    assert_eq!(preview.method, Method::POST);
    assert_eq!(preview.path, "/api/v1/router/provisioning/preview");
    let encoded = String::from_utf8(preview.body.expect("preview body")).expect("utf-8 body");
    assert!(!encoded.contains("passphrase"), "{encoded}");

    let apply = map_request(&Request::RouterProvisioningApply {
        request: RouterProvisioningApplyRequest {
            provisioning,
            uplink_passphrase: Some("upstream-secret".to_string()),
            output_passphrase: None,
        },
    })
    .expect("apply should map");
    assert_eq!(apply.method, Method::POST);
    assert_eq!(apply.path, "/api/v1/router/provisioning/apply");
    assert!(apply.body.is_some());

    let status = map_request(&Request::RouterProvisioningStatus).expect("status should map");
    assert_eq!(status.method, Method::GET);
    assert_eq!(status.path, "/api/v1/router/provisioning/status");
    assert!(status.body.is_none());

    let repair = map_request(&Request::RouterProvisioningRepair).expect("repair should map");
    assert_eq!(repair.method, Method::POST);
    assert_eq!(repair.path, "/api/v1/router/provisioning/repair");
    assert!(repair.body.is_none());
}

#[test]
fn maps_and_encodes_mutation_tokens() {
    let mapped = map_request(&Request::CommitNetworkChange {
        token: "pending/change".to_string(),
    })
    .expect("commit should map");

    assert_eq!(mapped.method, Method::POST);
    assert_eq!(mapped.path, "/api/v1/network-transactions/commit");
    assert!(mapped.body.is_some());
    assert!(!mapped.synthesize_pong);
}

#[test]
fn maps_route_management_requests() {
    let list_routes = map_request(&Request::ListRoutes {
        include_local_table: true,
    })
    .expect("list_routes should map");
    assert_eq!(list_routes.method, Method::GET);
    assert_eq!(list_routes.path, "/api/v1/routes?include_local_table=true");
    assert!(list_routes.body.is_none());

    let get_router_cfg =
        map_request(&Request::GetRouterConfig).expect("get_router_config should map");
    assert_eq!(get_router_cfg.method, Method::GET);
    assert_eq!(get_router_cfg.path, "/api/v1/router/config");
    assert!(get_router_cfg.body.is_none());
}

#[test]
fn maps_ap_profile_activation_with_encoded_interface_and_profile_body() {
    let mapped = map_request(&Request::ActivateWifiApProfile {
        interface: "wlan/0".into(),
        profile_id: "guest".into(),
    })
    .unwrap();
    assert_eq!(mapped.method, Method::PUT);
    assert_eq!(mapped.path, "/api/v1/wifi/wlan%2F0/profile");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&mapped.body.unwrap()).unwrap()["profile_id"],
        "guest"
    );
    let mapped = map_request(&Request::ListWifiApProfiles).unwrap();
    assert_eq!(mapped.path, "/api/v1/wifi-ap-profiles");
}
