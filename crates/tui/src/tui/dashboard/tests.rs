use super::*;

fn status(index: u32) -> InterfaceStatus {
    InterfaceStatus {
        interface: traffic_masq_protocol::NetworkInterfaceView {
            index,
            name: format!("eth{index}"),
            is_up: true,
            rx_bytes: 0,
            tx_bytes: 0,
            is_wireless: false,
        },
        owned_ipv4_addresses: None,
        ipv4_addresses: vec![],
        has_default_route: false,
    }
}

#[test]
fn traffic_dashboard_keeps_selection_visible() {
    use ratatui::{backend::TestBackend, Terminal};
    let mut app = TuiApp::default();
    app.dashboard.interfaces = (0..12).map(status).collect();
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    for selected in [0, 5, 11] {
        app.selected_interface = selected;
        terminal
            .draw(|frame| super::super::render(frame, &mut app, false))
            .unwrap();
        let area = app.ui.list_area.unwrap();
        let selected_y = area.y
            + ((selected - app.ui.list_scroll_offset) as u16 * app.ui.list_row_height.max(1));
        assert!(selected_y < area.bottom());
        assert_eq!(
            terminal.backend().buffer()[(area.x, selected_y)].symbol(),
            "▶"
        );
    }
}

#[tokio::test]
async fn dashboard_switches_between_traffic_and_numeric_statistics() {
    use ratatui::{backend::TestBackend, Terminal};
    let mut app = TuiApp::default();
    app.dashboard.interfaces.push(status(1));
    let client = ApiClient::new("/socket-that-must-not-be-opened");

    for (key, pane, marker) in [
        (KeyCode::Char('1'), DashboardPane::Traffic, "Interfaces"),
        (
            KeyCode::Char('2'),
            DashboardPane::Statistics,
            "Statistics: eth1",
        ),
    ] {
        handle_dashboard_key(&mut app, key, &client, false).await;
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal
            .draw(|frame| super::super::render(frame, &mut app, false))
            .unwrap();
        assert_eq!(app.dashboard_pane, pane);
        let buffer = terminal.backend().buffer();
        let text: String = (0..24)
            .flat_map(|y| (0..100).map(move |x| buffer[(x, y)].symbol()))
            .collect();
        assert!(text.contains(marker), "missing {marker:?}: {text}");
    }

    handle_dashboard_key(&mut app, KeyCode::Down, &client, false).await;
    let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
    terminal
        .draw(|frame| super::super::render(frame, &mut app, false))
        .unwrap();
    let buffer = terminal.backend().buffer();
    let text: String = (0..24)
        .flat_map(|y| (0..100).map(move |x| buffer[(x, y)].symbol()))
        .collect();
    assert!(text.contains("Statistics: eth1"));
}

#[test]
fn dashboard_interface_rows_show_management_ownership() {
    use ratatui::{backend::TestBackend, Terminal};
    let mut app = TuiApp::default();
    app.dashboard.interfaces.push(status(1));
    app.dashboard.managed.insert("eth1".into(), true);
    let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
    terminal
        .draw(|frame| super::super::render(frame, &mut app, false))
        .unwrap();
    let buffer = terminal.backend().buffer();
    let text: String = (0..24)
        .flat_map(|y| (0..100).map(move |x| buffer[(x, y)].symbol()))
        .collect();
    assert!(text.contains("traffic-masq:on"));
}

#[test]
fn traffic_history_tracks_session_totals_rates_and_kernel_errors() {
    let mut history = TrafficHistory::default();
    let start = Instant::now();
    let first = InterfaceKernelCounters {
        rx_packets: 10,
        tx_packets: 20,
        rx_errors: 1,
        tx_errors: 2,
        rx_dropped: 3,
        tx_dropped: 4,
    };
    history.record_with_counters(1_000, 2_000, Some(first), start);
    let current = InterfaceKernelCounters {
        rx_packets: 110,
        tx_packets: 220,
        rx_errors: 3,
        tx_errors: 5,
        rx_dropped: 7,
        tx_dropped: 9,
    };
    history.record_with_counters(3_000, 6_000, Some(current), start + Duration::from_secs(2));

    assert_eq!(history.bytes_since_start(3_000, 6_000), (2_000, 4_000));
    assert_eq!(history.current_rx_rate, 1_000);
    assert_eq!(history.current_tx_rate, 2_000);
    assert_eq!(
        history.average_rates(3_000, 6_000, start + Duration::from_secs(2)),
        (1_000, 2_000)
    );
    assert_eq!(
        history.kernel_since_start(),
        Some(InterfaceKernelCounters {
            rx_packets: 100,
            tx_packets: 200,
            rx_errors: 2,
            tx_errors: 3,
            rx_dropped: 4,
            tx_dropped: 5,
        })
    );
}

#[test]
fn format_rate_scales_units_correctly() {
    assert_eq!(format_rate(0), "0 B/s");
    assert_eq!(format_rate(512), "512 B/s");
    assert_eq!(format_rate(1024), "1.0 KB/s");
    assert_eq!(format_rate(1024 * 1024), "1.0 MB/s");
    assert_eq!(format_rate(3 * 1024 * 1024), "3.0 MB/s");
}

#[test]
fn traffic_history_ignores_samples_taken_too_close_together() {
    let mut history = TrafficHistory::default();
    let start = Instant::now();
    history.record(1_000, 500, start);
    history.record(2_000, 1_000, start);
    assert_eq!(history.current_rx_rate, 0);
    assert_eq!(history.current_tx_rate, 0);
    assert!(history.rx_rate_history.is_empty());
}

#[test]
fn traffic_history_caps_backlog_length() {
    let mut history = TrafficHistory::default();
    let start = Instant::now();
    history.record(0, 0, start);
    for tick in 1..=(TRAFFIC_HISTORY_LEN as u64 + 10) {
        history.record(
            tick * 1_000,
            tick * 1_000,
            start + Duration::from_secs(tick),
        );
    }
    assert_eq!(history.rx_rate_history.len(), TRAFFIC_HISTORY_LEN);
    assert_eq!(history.tx_rate_history.len(), TRAFFIC_HISTORY_LEN);
}

#[test]
fn count_and_duration_formatting_are_stable() {
    assert_eq!(format_count(1_234_567), "1,234,567");
    assert_eq!(format_duration(Duration::from_secs(3_661)), "01:01:01");
    assert_eq!(format_duration(Duration::from_secs(90_061)), "1d 01:01:01");
}

fn render_text(app: &mut TuiApp, width: u16, height: u16) -> String {
    let mut terminal =
        ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
    terminal
        .draw(|f| super::super::render(f, app, false))
        .unwrap();
    let buffer = terminal.backend().buffer();
    (0..height)
        .map(|y| {
            (0..width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn dashboard_graphs_follow_each_interface_and_hide_in_small_windows() {
    use ratatui::{backend::TestBackend, Terminal};
    for (width, height, row_height) in [(100, 30, 3), (80, 12, 1), (50, 30, 3)] {
        let mut app = TuiApp::default();
        app.dashboard.interfaces = vec![status(1), status(2)];
        for index in [1, 2] {
            let mut history = TrafficHistory::default();
            let now = Instant::now();
            history.record(0, 0, now);
            history.record(2048, 4096, now + Duration::from_secs(1));
            app.traffic.insert(index, history);
        }
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| render_dashboard_traffic(frame, frame.area(), &mut app))
            .unwrap();
        assert_eq!(app.ui.list_row_height, row_height);
        let buffer = terminal.backend().buffer();
        let area = app.ui.list_area.unwrap();
        if row_height == 3 {
            for row in 0..2 {
                let y = area.y + row * 3;
                // The original layout auto-scales each graph independently.
                assert_eq!(buffer[(area.x, y + 1)].symbol(), "█");
                assert_eq!(buffer[(area.x, y + 2)].symbol(), "█");
            }
        } else {
            assert_eq!(area.height, 2);
        }
    }
}

#[tokio::test]
async fn all_statistics_remain_reachable_at_80x24() {
    let mut app = TuiApp::default();
    app.dashboard.interfaces.push(status(1));
    let client = ApiClient::new("/nonexistent.sock");
    handle_dashboard_key(&mut app, KeyCode::Char('2'), &client, false).await;
    render_text(&mut app, 80, 24);
    assert!(app.dashboard.statistics_max_scroll > 0);
    for _ in 0..10 {
        handle_dashboard_key(&mut app, KeyCode::PageDown, &client, false).await;
    }
    let text = render_text(&mut app, 80, 24);
    assert!(text.contains("since interface creation/reset"), "{text}");
    assert_eq!(
        app.dashboard.statistics_scroll,
        app.dashboard.statistics_max_scroll
    );
    handle_dashboard_key(&mut app, KeyCode::Home, &client, false).await;
    let text = render_text(&mut app, 80, 24);
    assert!(
        text.contains("forwarded traffic is counted more than once"),
        "{text}"
    );
}

#[test]
fn failed_update_retains_samples_and_reports_error() {
    let mut app = TuiApp::default();
    app.dashboard.interfaces.push(status(1));
    app.dashboard.last_success = Some(Instant::now());
    let mut history = TrafficHistory::default();
    history.record(100, 200, Instant::now());
    app.traffic.insert(1, history);
    accept_update(
        &mut app,
        DashboardData {
            error: Some("disconnected".into()),
            ..Default::default()
        },
    );
    record_traffic_samples(&mut app);
    assert_eq!(app.dashboard.interfaces.len(), 1);
    assert_eq!(app.traffic[&1].first.as_ref().unwrap().rx_bytes, 100);
    let text = render_text(&mut app, 80, 24);
    assert!(text.contains("disconnected"), "{text}");
    assert!(!text.contains("No interfaces detected"));
}

#[test]
fn partial_update_retains_last_known_configuration_without_flicker() {
    let mut app = TuiApp::default();
    app.dashboard.interfaces.push(status(1));
    app.dashboard.managed.insert("eth1".into(), true);
    app.dashboard
        .roles
        .insert("eth1".into(), InterfaceRole::Input);

    accept_update(
        &mut app,
        DashboardData {
            interfaces: vec![status(1)],
            interfaces_updated: Some(Instant::now()),
            error: Some("Interface configuration unavailable (eth1)".into()),
            ..Default::default()
        },
    );

    assert_eq!(app.dashboard.managed.get("eth1"), Some(&true));
    assert_eq!(app.dashboard.roles.get("eth1"), Some(&InterfaceRole::Input));
}

#[test]
fn explicit_unmanaged_update_replaces_last_known_managed_state() {
    let mut app = TuiApp::default();
    app.dashboard.interfaces.push(status(1));
    app.dashboard.managed.insert("eth1".into(), true);

    let mut update = DashboardData {
        interfaces: vec![status(1)],
        interfaces_updated: Some(Instant::now()),
        ..Default::default()
    };
    update.managed.insert("eth1".into(), false);
    accept_update(&mut app, update);

    assert_eq!(app.dashboard.managed.get("eth1"), Some(&false));
}

#[test]
fn initial_selection_prefers_wan_and_refresh_preserves_interface_identity() {
    let mut app = TuiApp::default();
    let mut data = DashboardData {
        interfaces: vec![status(1), status(2)],
        interfaces_updated: Some(Instant::now()),
        ..Default::default()
    };
    data.roles.insert("eth2".into(), InterfaceRole::Input);
    accept_update(&mut app, data);
    assert_eq!(app.selected_interface, 1);
    accept_update(
        &mut app,
        DashboardData {
            interfaces: vec![status(2), status(1)],
            interfaces_updated: Some(Instant::now()),
            ..Default::default()
        },
    );
    assert_eq!(app.selected_interface, 0);
}

#[test]
fn overview_shows_pending_count_and_vpn_configuration_without_dhcp() {
    let mut app = TuiApp::default();
    app.dashboard.vpn_enabled = Some(true);
    app.dashboard
        .pending_network_changes
        .push(PendingNetworkChange {
            recovery_progress: None,
            phase: Default::default(),
            last_error: None,
            interface: "eth1".into(),
            token: "secret-token".into(),
            rollback_timeout_seconds: 60,
            expires_at_unix: super::super::current_unix_time() + 60,
        });
    let text = render_text(&mut app, 80, 24);
    assert!(text.contains("Overview"));
    assert!(text.contains("pending"));
    assert!(text.contains("ON"));
    assert!(!text.contains("dhcp server"));
    assert!(!text.contains("DHCP Clients"));
    assert!(!text.contains("ATTENTION"));
    assert!(!text.contains("secret-token"));
}

#[tokio::test]
async fn partial_api_failure_does_not_clear_other_status_or_fetch_dhcp() {
    use crate::tui::api::model::Response;
    use http_body_util::Full;
    use hyper::{body::Bytes, server::conn::http1, service::service_fn};
    use hyper_util::rt::TokioIo;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("api.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..5 {
            let (stream, _) = listener.accept().await.unwrap();
            tasks.spawn(async move {
                http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                            assert_eq!(req.method(), hyper::Method::POST);
                            assert_eq!(req.uri().path(), "/api/v1/control");
                            let bytes = http_body_util::BodyExt::collect(req.into_body())
                                .await
                                .unwrap()
                                .to_bytes();
                            let command: serde_json::Value =
                                serde_json::from_slice(&bytes).unwrap();
                            let response = match command["type"].as_str().unwrap() {
                                "list_interface_inventory" => Response::Interfaces {
                                    interfaces: vec![status(1)],
                                },
                                "get_interface_config" => Response::InterfaceConfig {
                                    wifi_concurrent_support: None,
                                    interface: "eth1".into(),
                                    config: None,
                                    allow_management_change: false,
                                },
                                "list_routes" => Response::Error {
                                    message: "routes unavailable".into(),
                                },
                                "get_vpn_config" => Response::VpnConfig { enabled: false },
                                "pending_network_changes" => {
                                    Response::PendingNetworkChanges { changes: vec![] }
                                }
                                path => panic!("unexpected dashboard request: {path}"),
                            };
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                                Bytes::from(serde_json::to_vec(&response).unwrap()),
                            )))
                        }),
                    )
                    .await
                    .unwrap();
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
    });
    let data = tokio::time::timeout(
        Duration::from_secs(5),
        super::super::load_daemon_dashboard(&ApiClient::new(socket)),
    )
    .await
    .unwrap();
    server.await.unwrap();
    assert_eq!(data.interfaces.len(), 1);
    assert_eq!(data.vpn_enabled, Some(false));
    assert!(data.pending_known);
    assert!(data.routes.is_none());
    assert!(data.error.unwrap().contains("Routes unavailable"));
}
