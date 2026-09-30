use super::*;

#[tokio::test]
async fn editor_uses_saved_address_even_when_dashboard_is_empty() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("api.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        for body in [
            serde_json::json!({"type": "dhcp_config", "interface": "lan0", "spec": null}),
            serde_json::json!({"type": "interface_config", "interface": "lan0",
                "allow_management_change": false,
                "config": {"managed": true, "role": "output", "ipv4": "192.168.50.128/24", "nat": true}}),
        ] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
            }
            let body = body.to_string();
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).as_bytes()).await.unwrap();
        }
    });
    let mut app = TuiApp::default();
    app.dashboard
        .interfaces
        .push(traffic_masq_protocol::InterfaceStatusView {
            interface: traffic_masq_protocol::NetworkInterfaceView {
                index: 1,
                name: "lan0".into(),
                is_up: true,
                rx_bytes: 0,
                tx_bytes: 0,
                is_wireless: false,
            },
            ipv4_addresses: vec![],
            owned_ipv4_addresses: None,
            has_default_route: false,
        });
    let client = ApiClient::new(socket);
    open_dhcp_editor(&mut app, &client).await;
    server.await.unwrap();
    let editor = app.dhcp_editor.as_ref().expect("DHCP editor should open");
    assert_eq!(editor.router, "192.168.50.128");
    assert_eq!(editor.pool_start, "192.168.50.1");
    assert_eq!(editor.pool_end, "192.168.50.127");
    for _ in 0..5 {
        handle_dhcp_editor_key(&mut app, KeyCode::Enter, &client).await;
    }
    assert_eq!(app.dhcp_editor.unwrap().field, DhcpField::Save);
}

#[tokio::test]
async fn editor_falls_back_to_status_address_ignoring_link_local() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("api.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        for body in [
            serde_json::json!({"type": "dhcp_config", "interface": "lan0", "spec": null}),
            serde_json::json!({"type": "interface_config", "interface": "lan0",
                "allow_management_change": false,
                "config": null}),
        ] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
            }
            let body = body.to_string();
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).as_bytes()).await.unwrap();
        }
    });
    let mut app = TuiApp::default();
    app.dashboard
        .interfaces
        .push(traffic_masq_protocol::InterfaceStatusView {
            interface: traffic_masq_protocol::NetworkInterfaceView {
                index: 1,
                name: "lan0".into(),
                is_up: true,
                rx_bytes: 0,
                tx_bytes: 0,
                is_wireless: false,
            },
            ipv4_addresses: vec![
                traffic_masq_protocol::Ipv4AddressInfoView {
                    interface_index: 1,
                    address: "169.254.10.20".parse().unwrap(),
                    prefix_len: 16,
                    protocol: None,
                },
                traffic_masq_protocol::Ipv4AddressInfoView {
                    interface_index: 1,
                    address: "192.168.1.1".parse().unwrap(),
                    prefix_len: 24,
                    protocol: None,
                },
            ],
            owned_ipv4_addresses: None,
            has_default_route: false,
        });
    let client = ApiClient::new(socket);
    open_dhcp_editor(&mut app, &client).await;
    server.await.unwrap();
    let editor = app.dhcp_editor.as_ref().expect("DHCP editor should open");
    assert_eq!(editor.router, "192.168.1.1");
    assert_eq!(editor.pool_start, "192.168.1.2");
    assert_eq!(editor.pool_end, "192.168.1.254");
}

#[tokio::test]
async fn editor_leaves_fields_empty_if_only_link_local_address_present() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("api.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        for body in [
            serde_json::json!({"type": "dhcp_config", "interface": "lan0", "spec": null}),
            serde_json::json!({"type": "interface_config", "interface": "lan0",
                "allow_management_change": false,
                "config": null}),
        ] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
            }
            let body = body.to_string();
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).as_bytes()).await.unwrap();
        }
    });
    let mut app = TuiApp::default();
    app.dashboard
        .interfaces
        .push(traffic_masq_protocol::InterfaceStatusView {
            interface: traffic_masq_protocol::NetworkInterfaceView {
                index: 1,
                name: "lan0".into(),
                is_up: true,
                rx_bytes: 0,
                tx_bytes: 0,
                is_wireless: false,
            },
            ipv4_addresses: vec![traffic_masq_protocol::Ipv4AddressInfoView {
                interface_index: 1,
                address: "169.254.10.20".parse().unwrap(),
                prefix_len: 16,
                protocol: None,
            }],
            owned_ipv4_addresses: None,
            has_default_route: false,
        });
    let client = ApiClient::new(socket);
    open_dhcp_editor(&mut app, &client).await;
    server.await.unwrap();
    let editor = app.dhcp_editor.as_ref().expect("DHCP editor should open");
    assert_eq!(editor.router, "");
    assert_eq!(editor.pool_start, "");
    assert_eq!(editor.pool_end, "");
}

#[test]
fn formats_mac_address_with_zero_padding() {
    assert_eq!(
        format_mac_address([0x00, 0x01, 0x0a, 0x10, 0xab, 0xff]),
        "00:01:0a:10:ab:ff"
    );
}

#[test]
fn formats_lease_expiration_relative_to_current_time() {
    assert_eq!(
        format_lease_expiration(1_100, 1_000),
        "100s remaining (unix 1100)"
    );
    assert_eq!(format_lease_expiration(1_000, 1_000), "expired (unix 1000)");
}

#[test]
fn suggests_pool_spanning_usable_hosts_excluding_router() {
    let (start, end) = suggest_pool("192.168.1.1".parse().unwrap(), 24).unwrap();
    assert_eq!(start, "192.168.1.2".parse::<Ipv4Addr>().unwrap());
    assert_eq!(end, "192.168.1.254".parse::<Ipv4Addr>().unwrap());
}

#[test]
fn suggests_pool_when_router_is_last_usable_host() {
    let (start, end) = suggest_pool("192.168.1.254".parse().unwrap(), 24).unwrap();
    assert_eq!(start, "192.168.1.1".parse::<Ipv4Addr>().unwrap());
    assert_eq!(end, "192.168.1.253".parse::<Ipv4Addr>().unwrap());
}

#[test]
fn no_pool_suggested_when_subnet_too_small() {
    assert_eq!(suggest_pool("10.0.0.1".parse().unwrap(), 31), None);
    assert_eq!(suggest_pool("10.0.0.1".parse().unwrap(), 32), None);
}

#[test]
fn single_address_pool_when_only_one_host_remains() {
    let (start, end) = suggest_pool("10.0.0.1".parse().unwrap(), 30).unwrap();
    assert_eq!(start, end);
    assert_eq!(start, "10.0.0.2".parse::<Ipv4Addr>().unwrap());
}

#[test]
fn dhcp_field_reaches_every_action_row_and_clamps_at_both_ends() {
    assert_eq!(next_dhcp_field(DhcpField::PoolStart), DhcpField::PoolEnd);
    assert_eq!(next_dhcp_field(DhcpField::PoolEnd), DhcpField::Router);
    assert_eq!(next_dhcp_field(DhcpField::Router), DhcpField::DnsServers);
    assert_eq!(
        next_dhcp_field(DhcpField::DnsServers),
        DhcpField::LeaseSeconds
    );
    assert_eq!(next_dhcp_field(DhcpField::LeaseSeconds), DhcpField::Save);
    assert_eq!(next_dhcp_field(DhcpField::Save), DhcpField::Leases);
    assert_eq!(next_dhcp_field(DhcpField::Leases), DhcpField::Disable);
    assert_eq!(next_dhcp_field(DhcpField::Disable), DhcpField::Disable);

    assert_eq!(previous_dhcp_field(DhcpField::Disable), DhcpField::Leases);
    assert_eq!(previous_dhcp_field(DhcpField::Leases), DhcpField::Save);
    assert_eq!(
        previous_dhcp_field(DhcpField::PoolStart),
        DhcpField::PoolStart
    );
}

#[test]
fn dhcp_editor_active_value_is_none_for_action_rows_only() {
    let mut editor = DhcpEditor {
        interface: "lan0".to_string(),
        field: DhcpField::Save,
        pool_start: String::new(),
        pool_end: String::new(),
        router: String::new(),
        dns_servers: String::new(),
        lease_seconds: String::new(),
        cursor: 0,
    };
    assert!(editor.active_value_mut().is_none());
    editor.field = DhcpField::Leases;
    assert!(editor.active_value_mut().is_none());
    editor.field = DhcpField::Disable;
    assert!(editor.active_value_mut().is_none());
    editor.field = DhcpField::PoolStart;
    assert!(editor.active_value_mut().is_some());
}

#[tokio::test]
async fn dhcp_editor_cursor_navigation_and_editing() {
    let mut app = TuiApp {
        screen: Screen::DhcpEditor,
        dhcp_editor: Some(DhcpEditor {
            interface: "lan0".to_string(),
            field: DhcpField::PoolStart,
            pool_start: "192.168.1.10".to_string(),
            pool_end: "192.168.1.100".to_string(),
            router: "192.168.1.1".to_string(),
            dns_servers: "8.8.8.8".to_string(),
            lease_seconds: "86400".to_string(),
            cursor: 12,
        }),
        ..Default::default()
    };
    let client = ApiClient::new("/socket-that-must-not-be-opened");

    handle_dhcp_editor_key(&mut app, KeyCode::Left, &client).await;
    assert_eq!(app.dhcp_editor.as_ref().unwrap().cursor, 11);

    handle_dhcp_editor_key(&mut app, KeyCode::Char('5'), &client).await;
    assert_eq!(
        app.dhcp_editor.as_ref().unwrap().pool_start,
        "192.168.1.150"
    );
    assert_eq!(app.dhcp_editor.as_ref().unwrap().cursor, 12);

    handle_dhcp_editor_key(&mut app, KeyCode::Backspace, &client).await;
    assert_eq!(app.dhcp_editor.as_ref().unwrap().pool_start, "192.168.1.10");
    assert_eq!(app.dhcp_editor.as_ref().unwrap().cursor, 11);
}
