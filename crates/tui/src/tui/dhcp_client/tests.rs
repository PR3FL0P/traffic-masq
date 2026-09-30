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
