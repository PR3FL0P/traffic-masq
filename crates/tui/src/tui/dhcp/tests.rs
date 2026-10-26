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
            serde_json::json!({"type": "dhcp_dns_defaults", "settings": {"servers": ["1.1.1.1"]}}),
            serde_json::json!({"type": "interface_config", "interface": "lan0",
                "allow_management_change": false,
                "config": {"managed": true, "role": "output", "ipv4": "192.168.50.128/24"}}),
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
    assert_eq!(editor.dns_servers, "1.1.1.1");
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
            serde_json::json!({"type": "dhcp_dns_defaults", "settings": {"servers": ["9.9.9.9", "8.8.8.8"]}}),
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
    assert_eq!(editor.dns_servers, "9.9.9.9, 8.8.8.8");
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
            serde_json::json!({"type": "dhcp_dns_defaults", "settings": {"servers": []}}),
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
    assert!(editor.dns_servers.is_empty());
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
        offline_intent: None,
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
            offline_intent: None,
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

#[tokio::test]
async fn missing_dhcp_editor_saves_revision_checked_intent_without_live_apply() {
    use http_body_util::{BodyExt, Full};
    use hyper::{body::Bytes, server::conn::http1, service::service_fn};
    use hyper_util::rt::TokioIo;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("api.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        http1::Builder::new().serve_connection(TokioIo::new(stream), service_fn(|request: hyper::Request<hyper::body::Incoming>| async move {
            assert_eq!(request.method(), hyper::Method::POST);
            assert_eq!(request.uri().path(), "/api/v1/control");
            let body = request.into_body().collect().await.unwrap().to_bytes();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["type"], "save_interface_config");
            assert_eq!(body["interface"], "usb0");
            assert_eq!(body["expected_revision"], 42);
            assert!(body["config"].get("nat").is_none());
            assert_eq!(body["config"]["dhcp"]["pool_start"], "192.168.50.10");
            let response = serde_json::json!({"type": "interface_intent_saved", "interface": "usb0", "revision": 43, "deferred": true, "missing_dependencies": ["usb0"]});
            Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(Bytes::from(response.to_string()))))
        })).await.unwrap();
    });
    let config = traffic_masq_protocol::InterfaceConfigView {
        wifi_concurrent: false,
        mac_address: None,
        role: traffic_masq_protocol::InterfaceRole::Output,
        managed: true,
        ipv4: Some("192.168.50.1/24".parse().unwrap()),
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    };
    let mut app = TuiApp {
        screen: Screen::DhcpEditor,
        dhcp_editor: Some(DhcpEditor {
            interface: "usb0".into(),
            offline_intent: Some((42, config)),
            field: DhcpField::Save,
            pool_start: "192.168.50.10".into(),
            pool_end: "192.168.50.100".into(),
            router: "192.168.50.1".into(),
            dns_servers: String::new(),
            lease_seconds: "3600".into(),
            cursor: 0,
        }),
        ..Default::default()
    };
    let client = ApiClient::new(socket);
    submit_dhcp_config(&mut app, &client).await;
    server.await.unwrap();
    assert_eq!(app.screen, Screen::DhcpInterfaceList);
}

fn lease(ip: &str, mac: [u8; 6], expires_at_unix: u64) -> DhcpLeaseView {
    DhcpLeaseView {
        ip: ip.parse().unwrap(),
        mac,
        expires_at_unix,
    }
}

fn lease_view(leases: Vec<DhcpLeaseView>) -> DhcpLeasesView {
    DhcpLeasesView {
        interface: "lan0".into(),
        leases,
        scroll: 0,
        return_screen: Screen::DhcpEditor,
        query: String::new(),
        cursor: 0,
        searching: false,
        filter: LeaseFilter::All,
        sort_expiration: false,
        error: None,
        updated_at: 100,
        viewport_rows: 3,
    }
}

#[test]
fn lease_search_sort_and_expiration_boundary_are_consistent() {
    let mut view = lease_view(vec![
        lease("10.0.0.10", [0xaa, 0xbb, 0, 0, 0, 2], 200),
        lease("10.0.0.2", [0xaa, 0xbb, 0, 0, 0, 1], 100),
    ]);
    assert_eq!(view.filtered(100)[0].ip.to_string(), "10.0.0.2");
    view.query = "AA:BB".into();
    assert_eq!(view.filtered(100).len(), 2);
    view.query = "10.0.0.10".into();
    assert_eq!(view.filtered(100).len(), 1);
    view.query.clear();
    view.filter = LeaseFilter::Active;
    assert_eq!(view.filtered(100)[0].ip.to_string(), "10.0.0.10");
    view.filter = LeaseFilter::Expired;
    assert_eq!(view.filtered(100)[0].ip.to_string(), "10.0.0.2");
    view.filter = LeaseFilter::All;
    view.leases[0].expires_at_unix = 50;
    view.sort_expiration = true;
    assert_eq!(view.filtered(100)[0].ip.to_string(), "10.0.0.10");
}

#[tokio::test]
async fn failed_and_mismatched_lease_refreshes_retain_snapshot_then_recover() {
    let old = lease("10.0.0.2", [0; 6], u64::MAX);
    let mock = super::super::test_api::mock(vec![
        Response::Error {
            message: "DHCP unavailable".into(),
        },
        Response::Leases {
            interface: "other0".into(),
            leases: vec![],
        },
        Response::Leases {
            interface: "lan0".into(),
            leases: vec![],
        },
    ])
    .await;
    let mut app = TuiApp {
        dhcp_leases: Some(lease_view(vec![old.clone()])),
        ..Default::default()
    };
    {
        let view = app.dhcp_leases.as_mut().unwrap();
        view.query = "10.".into();
        view.filter = LeaseFilter::Active;
        view.sort_expiration = true;
        view.scroll = 20;
    }
    for _ in 0..2 {
        refresh_dhcp_leases(&mut app, &mock.client).await;
        let view = app.dhcp_leases.as_ref().unwrap();
        assert_eq!(view.leases, vec![old.clone()]);
        assert!(view.error.is_some());
        assert_eq!(view.updated_at, 100);
    }
    handle_dhcp_leases_key(&mut app, KeyCode::Char('r'), &mock.client).await;
    let view = app.dhcp_leases.as_ref().unwrap();
    assert!(view.error.is_none());
    assert!(view.leases.is_empty());
    assert_eq!(view.scroll, 0);
    assert_eq!(view.query, "10.");
    assert_eq!(view.filter, LeaseFilter::Active);
    assert!(view.sort_expiration);
    assert!(mock
        .calls
        .lock()
        .unwrap()
        .iter()
        .all(|call| call.method == "POST"
            && call.path == "/api/v1/control"
            && call.body["type"] == "list_leases"));
}

#[tokio::test]
async fn lease_search_treats_shortcuts_as_text_and_esc_first_exits_search() {
    let client = ApiClient::new("/nonexistent/lease-test.sock");
    let mut app = TuiApp {
        screen: Screen::DhcpLeases,
        dhcp_leases: Some(lease_view(vec![])),
        ..Default::default()
    };
    handle_dhcp_leases_key(&mut app, KeyCode::Char('/'), &client).await;
    for ch in ['f', 's', 'r'] {
        handle_dhcp_leases_key(&mut app, KeyCode::Char(ch), &client).await;
    }
    let view = app.dhcp_leases.as_ref().unwrap();
    assert_eq!(view.query, "fsr");
    assert_eq!(view.filter, LeaseFilter::All);
    assert!(!view.sort_expiration);
    assert!(view.error.is_none());
    handle_dhcp_leases_key(&mut app, KeyCode::Esc, &client).await;
    assert_eq!(app.screen, Screen::DhcpLeases);
    handle_dhcp_leases_key(&mut app, KeyCode::Esc, &client).await;
    assert_eq!(app.screen, Screen::DhcpEditor);
}

#[tokio::test]
async fn lease_end_scroll_fills_the_page_and_filtering_clamps_it() {
    let client = ApiClient::new("/nonexistent/lease-test.sock");
    let leases = (1..=30)
        .map(|i| lease(&format!("10.0.0.{i}"), [0; 6], u64::MAX))
        .collect();
    let mut app = TuiApp {
        dhcp_leases: Some(lease_view(leases)),
        ..Default::default()
    };
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| render_dhcp_leases(frame, frame.area(), &mut app))
        .unwrap();
    handle_dhcp_leases_key(&mut app, KeyCode::End, &client).await;
    assert_eq!(app.dhcp_leases.as_ref().unwrap().scroll, 14);
    app.dhcp_leases.as_mut().unwrap().query = "10.0.0.30".into();
    app.dhcp_leases.as_mut().unwrap().error = Some("test refresh failure".into());
    terminal
        .draw(|frame| render_dhcp_leases(frame, frame.area(), &mut app))
        .unwrap();
    assert_eq!(app.dhcp_leases.as_ref().unwrap().scroll, 0);
    let text = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(text.contains("STALE: test refresh failure"));
    assert!(text.contains("Showing 1/30"));
    assert!(text.contains("10.0.0.30"));
}
