use super::*;

fn status(index: u32) -> InterfaceStatus {
    InterfaceStatus {
        interface: crate::netlink::NetworkInterface {
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
        (
            KeyCode::Char('1'),
            DashboardPane::Traffic,
            "Interfaces stat",
        ),
        (
            KeyCode::Char('2'),
            DashboardPane::Statistics,
            "Statistics: all interfaces",
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
