use super::*;
use ratatui::{backend::TestBackend, Terminal};
use traffic_masq_protocol::{
    InterfaceStatusView as InterfaceStatus, Ipv4AddressInfoView as Ipv4AddressInfo,
    NetworkInterfaceView as NetworkInterface,
};

fn status(index: u32) -> InterfaceStatus {
    InterfaceStatus {
        interface: NetworkInterface {
            index,
            name: format!("eth{index}"),
            is_up: true,
            rx_bytes: 0,
            tx_bytes: 0,
            is_wireless: false,
        },
        ipv4_addresses: vec![],
        owned_ipv4_addresses: None,
        has_default_route: false,
    }
}

#[test]
fn mixed_addresses_have_individual_ownership_colors() {
    let mut status = status(1);
    let address = |last, protocol| Ipv4AddressInfo {
        interface_index: 1,
        address: std::net::Ipv4Addr::new(192, 0, 2, last),
        prefix_len: 24,
        protocol,
    };
    // Journal-owned address without a kernel tag, our DHCP, foreign and untagged.
    status.ipv4_addresses = vec![
        address(1, None),
        address(2, Some(202)),
        address(3, Some(16)),
        address(4, None),
    ];
    status.owned_ipv4_addresses = Some(status.ipv4_addresses[..2].to_vec());
    let spans = format_addresses(&status);
    assert_eq!(spans[0].content, "192.0.2.1/24");
    assert_eq!(spans[2].content, "192.0.2.2/24");
    for index in [4, 6] {
        assert!(spans[index].content.starts_with("[ext] "));
        assert_eq!(spans[index].style.fg, Some(theme::WARN));
    }
    status.owned_ipv4_addresses = None;
    let spans = format_addresses(&status);
    assert!(spans[0].content.starts_with("[?] "));
    assert_eq!(spans[0].style.fg, Some(theme::WARN));
    assert!(!spans[2].content.starts_with('['));
    assert!(spans[4].content.starts_with("[ext] "));
}

#[test]
fn interface_list_keeps_selected_row_visible_and_click_offset_correct() {
    let mut app = TuiApp::default();
    app.dashboard.interfaces = (0..20).map(status).collect();
    app.selected_interface = 19;
    let mut terminal = Terminal::new(TestBackend::new(80, 6)).unwrap();
    terminal
        .draw(|frame| render_interface_list(frame, frame.area(), &mut app))
        .unwrap();
    assert_eq!(app.ui.list_scroll_offset, 16);
    let buffer = terminal.backend().buffer();
    let last_row: String = (0..80).map(|x| buffer[(x, 4)].symbol()).collect();
    assert!(last_row.contains("eth19"));
}

#[test]
fn preview_buttons_are_visible_and_cancel_has_a_click_target() {
    let mut app = TuiApp {
        preview: Some(traffic_masq_protocol::InterfaceChangePlanView {
            mac_address: None,
            interface: "eth0".into(),
            delete_ipv4: vec![],
            retag_ipv4: None,
            add_ipv4: None,
            set_link_up: false,
            management_change: false,
            dhcp_action: traffic_masq_protocol::DhcpChangeActionView::Unchanged,
            releasing_management: false,
        }),
        preview_scroll: usize::MAX,
        ..Default::default()
    };
    let mut terminal = Terminal::new(TestBackend::new(80, 8)).unwrap();
    terminal
        .draw(|frame| render_preview(frame, frame.area(), &mut app))
        .unwrap();
    let (rect, _) = app
        .ui
        .buttons
        .iter()
        .find(|(_, slot)| *slot == 1)
        .expect("Cancel click target");
    assert!(rect.y < 7);
    let buffer = terminal.backend().buffer();
    let row: String = (0..80).map(|x| buffer[(x, rect.y)].symbol()).collect();
    assert!(row.contains("Cancel"));
}

#[tokio::test]
async fn interface_plan_requires_reaching_the_end_before_apply() {
    let mut app = TuiApp {
        screen: Screen::Preview,
        preview_max_scroll: 7,
        ..Default::default()
    };
    let client = ApiClient::new("/socket-that-must-not-be-opened");

    handle_preview_key(&mut app, KeyCode::Enter, &client).await;
    assert!(app
        .message
        .as_deref()
        .is_some_and(|message| message.contains("Review the complete interface plan")));

    handle_preview_key(&mut app, KeyCode::PageDown, &client).await;
    assert_eq!(app.preview_scroll, 7);
    handle_preview_key(&mut app, KeyCode::Up, &client).await;
    assert_eq!(app.preview_scroll, 6);
}

#[test]
fn missing_saved_interface_is_visible_without_observed_identity_at_80_columns() {
    use traffic_masq_protocol::{
        InterfaceConfigSource, InterfaceInventoryEntry, InterfacePresence, InterfaceReadiness,
    };
    let mut app = TuiApp::default();
    app.dashboard.inventory = Some(vec![InterfaceInventoryEntry {
        name: "usb-with-a-long-name".into(),
        observed: None,
        configured: None,
        config_source: InterfaceConfigSource::None,
        presence: InterfacePresence::Missing,
        readiness: InterfaceReadiness::Disabled,
        blockers: Vec::new(),
        observation_stale: false,
        suppressed: true,
        references: Vec::new(),
    }]);
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| render_interface_list(frame, frame.area(), &mut app))
        .unwrap();
    let text: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(text.contains("usb-with-a-long-name [forgotten]"));
    assert!(text.contains("missing"));
    assert_eq!(app.ui.list_count, 1);
    assert_eq!(
        selected_interface_name(&app).as_deref(),
        Some("usb-with-a-long-name")
    );
    assert!(app.dashboard.interfaces.is_empty());
}

#[test]
fn dhcp_inventory_has_its_own_title_and_colored_server_status() {
    use traffic_masq_protocol::{
        InterfaceConfigSource, InterfaceInventoryEntry, InterfacePresence, InterfaceReadiness,
    };
    let mut app = TuiApp::default();
    app.dashboard.inventory = Some(vec![InterfaceInventoryEntry {
        name: "wlan0".into(),
        observed: None,
        configured: None,
        config_source: InterfaceConfigSource::None,
        presence: InterfacePresence::Missing,
        readiness: InterfaceReadiness::Disabled,
        blockers: Vec::new(),
        observation_stale: false,
        suppressed: false,
        references: Vec::new(),
    }]);
    app.dhcp_interfaces = vec!["wlan0".into()];
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| super::super::dhcp::render_dhcp_interface_list(frame, frame.area(), &mut app))
        .unwrap();
    let buffer = terminal.backend().buffer();
    let text: String = buffer.content().iter().map(|cell| cell.symbol()).collect();
    assert!(text.contains("DHCP servers"));
    assert!(text.contains("active"));
    assert!(!text.contains("Interfaces |"));
    assert!(buffer
        .content()
        .iter()
        .any(|cell| cell.symbol() == "a" && cell.fg == theme::GOOD));
}
