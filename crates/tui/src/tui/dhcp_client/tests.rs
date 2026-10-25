use std::net::Ipv4Addr;

use ratatui::backend::TestBackend;
use ratatui::Terminal;

use super::*;
use traffic_masq_protocol::DhcpClientStatusView;

fn status_named(interface: &str, state: DhcpClientOperationalState) -> DhcpClientStatusView {
    DhcpClientStatusView {
        interface: interface.into(),
        state,
        address: Some(Ipv4Addr::new(192, 0, 2, 42)),
        prefix_length: Some(24),
        server: Some(Ipv4Addr::new(192, 0, 2, 1)),
        expires_at_unix: Some(2_000_000_000),
        dns_servers: vec![Ipv4Addr::new(192, 0, 2, 53)],
        degraded_reason: None,
        config: DhcpClientConfigRequest::default(),
    }
}

fn status(state: DhcpClientOperationalState) -> DhcpClientStatusView {
    status_named("wan0", state)
}

#[test]
fn uplink_dhcp_render_shows_status_details_and_separates_server_terminology() {
    for (state, label) in [
        (DhcpClientOperationalState::Waiting, "waiting"),
        (DhcpClientOperationalState::Running, "running"),
        (DhcpClientOperationalState::Degraded, "degraded"),
    ] {
        let mut app = TuiApp {
            dhcp_clients: vec![status(state)],
            dhcp_client_selected: Some("wan0".into()),
            ..Default::default()
        };
        let backend = TestBackend::new(100, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, frame.area(), &mut app))
            .unwrap();
        let rendered = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("DHCP Client"));
        assert!(rendered.contains("separate from the DHCP server"));
        assert!(rendered.contains(label));
        assert!(rendered.contains("192.0.2.42"));
        assert!(rendered.contains("192.0.2.1"));
        assert!(rendered.contains("192.0.2.53"));
    }
}

#[test]
fn uplink_dhcp_actions_use_the_selected_interface_name() {
    assert!(matches!(
        action_request("wan0", false, KeyCode::Char('c')),
        Some(Request::ConfigureDhcpClient { interface, config })
            if interface == "wan0" && config == DhcpClientConfigRequest::default()
    ));
    assert!(action_request("wan0", false, KeyCode::Char('r')).is_none());
    assert!(matches!(
        action_request("wan0", true, KeyCode::Char('r')),
        Some(Request::RenewDhcpClient { interface }) if interface == "wan0"
    ));
}

#[test]
fn selection_is_by_interface_name_not_status_index() {
    let mut app = TuiApp {
        dhcp_clients: vec![
            status(DhcpClientOperationalState::Running),
            status_named("lan9", DhcpClientOperationalState::Waiting),
        ],
        dhcp_client_selected: Some("lan9".into()),
        ..Default::default()
    };
    let names = row_names(&app);
    assert_eq!(names, vec!["wan0", "lan9"]);
    move_selection(&mut app, false);
    assert_eq!(app.dhcp_client_selected.as_deref(), Some("wan0"));
}

fn inventory_entry(
    name: &str,
    enabled: Option<bool>,
) -> traffic_masq_protocol::InterfaceInventoryEntry {
    serde_json::from_value(serde_json::json!({
        "name": name, "observed": null,
        "configured": {"role": "input", "managed": true,
            "dhcp_client": enabled.map(|enabled| serde_json::json!({"enabled": enabled}))},
        "config_source": "override", "presence": "missing", "observation_stale": false,
        "suppressed": false, "readiness": "waiting_device", "blockers": [], "references": []
    }))
    .unwrap()
}

async fn mock_api(
    responses: Vec<Response>,
) -> (
    tempfile::TempDir,
    ApiClient,
    tokio::task::JoinHandle<Vec<String>>,
) {
    use http_body_util::{BodyExt, Full};
    use hyper::{body::Bytes, server::conn::http1, service::service_fn};
    use hyper_util::rt::TokioIo;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("api.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let paths = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        for response in responses {
            let (stream, _) = listener.accept().await.unwrap();
            let paths = paths.clone();
            let response = serde_json::to_vec(&response).unwrap();
            http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                        let paths = paths.clone();
                        let response = response.clone();
                        async move {
                            assert_eq!(request.method(), hyper::Method::POST);
                            assert_eq!(request.uri().path(), "/api/v1/control");
                            let bytes = request.into_body().collect().await.unwrap().to_bytes();
                            let command: serde_json::Value =
                                serde_json::from_slice(&bytes).unwrap();
                            paths.lock().unwrap().push(format!(
                                "{} {}",
                                command["type"].as_str().unwrap(),
                                command["interface"].as_str().unwrap_or("")
                            ));
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                                Bytes::from(response),
                            )))
                        }
                    }),
                )
                .await
                .unwrap();
        }
        std::sync::Arc::try_unwrap(paths)
            .unwrap()
            .into_inner()
            .unwrap()
    });
    (dir, ApiClient::new(socket), server)
}

#[tokio::test]
async fn action_errors_and_unexpected_responses_never_report_success() {
    for response in [
        Response::Error {
            message: "network transaction pending".into(),
        },
        Response::DhcpClientInterface {
            status: status_named("other0", DhcpClientOperationalState::Running),
        },
        Response::DhcpClientDisabled {
            interface: "wan0".into(),
        },
    ] {
        let (_dir, client, server) = mock_api(vec![response]).await;
        let mut app = TuiApp {
            dhcp_client_selected: Some("wan0".into()),
            dhcp_clients: vec![status(DhcpClientOperationalState::Running)],
            ..Default::default()
        };
        handle_key(&mut app, KeyCode::Char('r'), &client).await;
        let paths = tokio::time::timeout(std::time::Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(app.logs.back().unwrap().level, LogLevel::Error);
        assert!(!app.logs.iter().any(|entry| entry.level == LogLevel::Info));
    }
}

#[tokio::test]
async fn successful_disable_refreshes_status_and_preserves_selection() {
    let (_dir, client, server) = mock_api(vec![
        Response::DhcpClientDisabled {
            interface: "wan0".into(),
        },
        Response::DhcpClientStatus { interfaces: vec![] },
    ])
    .await;
    let mut app = TuiApp {
        dhcp_client_selected: Some("wan0".into()),
        dhcp_clients: vec![status(DhcpClientOperationalState::Running)],
        ..Default::default()
    };
    app.dashboard.inventory = Some(vec![inventory_entry("wan0", Some(false))]);
    handle_key(&mut app, KeyCode::Char('d'), &client).await;
    let paths = tokio::time::timeout(std::time::Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(paths.len(), 2);
    assert_eq!(paths[0], "disable_dhcp_client wan0");
    assert_eq!(paths[1], "dhcp_client_status ");
    assert!(app.dhcp_clients.is_empty());
    assert_eq!(app.dhcp_client_selected.as_deref(), Some("wan0"));
    assert!(app.message.as_deref().unwrap().contains("disabled on wan0"));
}

#[tokio::test]
async fn resetting_route_policy_opens_network_confirmation() {
    let change = traffic_masq_protocol::PendingNetworkChange {
        recovery_progress: None,
        phase: Default::default(),
        last_error: None,
        token: "dhcp-reset".into(),
        interface: "wan0".into(),
        rollback_timeout_seconds: 60,
        expires_at_unix: super::super::current_unix_time() + 60,
    };
    let (_dir, client, server) = mock_api(vec![Response::NetworkChangePending {
        change: change.clone(),
    }])
    .await;
    let mut app = TuiApp {
        dhcp_client_selected: Some("wan0".into()),
        dhcp_clients: vec![status(DhcpClientOperationalState::Running)],
        ..Default::default()
    };
    handle_key(&mut app, KeyCode::Char('c'), &client).await;
    assert_eq!(app.screen, Screen::PendingChange);
    assert_eq!(app.pending_return_screen, Screen::DhcpClient);
    assert_eq!(app.pending.as_ref().unwrap().token, "dhcp-reset");
    assert_eq!(server.await.unwrap(), vec!["configure_dhcp_client wan0"]);
}

#[tokio::test]
async fn section_navigation_uses_inventory_selection_including_missing_devices() {
    let (_dir, client, server) =
        mock_api(vec![Response::DhcpClientStatus { interfaces: vec![] }]).await;
    let mut app = TuiApp {
        screen: Screen::InterfaceList,
        show_dhcp_client: true,
        selected_inventory_interface: 1,
        ..Default::default()
    };
    app.dashboard.inventory = Some(vec![
        inventory_entry("wan0", Some(false)),
        inventory_entry("usb0", None),
    ]);
    super::super::navigate_to_section(&mut app, super::super::Section::DhcpClient, &client, false)
        .await;
    tokio::time::timeout(std::time::Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(app.dhcp_client_selected.as_deref(), Some("usb0"));
    assert_eq!(row_names(&app), vec!["wan0", "usb0"]);
}

#[test]
fn client_list_shows_failure_reason_and_scrolls_with_correct_mouse_rows() {
    let mut failed = status_named("wan9", DhcpClientOperationalState::Degraded);
    failed.degraded_reason = Some("DHCP socket unavailable".into());
    let mut app = TuiApp {
        dhcp_clients: vec![status(DhcpClientOperationalState::Running), failed],
        dhcp_client_selected: Some("wan9".into()),
        ..Default::default()
    };
    let mut terminal = Terminal::new(TestBackend::new(80, 8)).unwrap();
    terminal
        .draw(|frame| render(frame, frame.area(), &mut app))
        .unwrap();
    let text: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(text.contains("DHCP socket unavailable"));
    assert!(text.contains("[d] disable"));
    assert_eq!(app.ui.list_row_height, 5);
    assert_eq!(app.ui.list_scroll_offset, 1);
    assert_eq!(app.ui.list_area.unwrap().y, 3);
}
