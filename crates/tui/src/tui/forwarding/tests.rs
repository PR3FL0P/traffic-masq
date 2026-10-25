use super::*;

fn connection(from: &str, to: &str) -> ForwardingConfig {
    ForwardingConfig {
        from: from.into(),
        to: to.into(),
        masquerade: true,
        source_subnet: None,
    }
}

fn editor() -> ForwardingEditor {
    ForwardingEditor {
        rules: vec![connection("lan0", "wan0")],
        editing: Some(0),
        interfaces: vec!["lan0".into(), "wan0".into(), "wg0".into()],
        from: 0,
        to: 2,
        masquerade: false,
        advanced: true,
        source: "192.168.10.0/24".into(),
        cursor: 15,
        field: Field::Save,
        error: None,
        error_field: None,
    }
}

fn interface_status(
    name: &str,
    has_default_route: bool,
) -> traffic_masq_protocol::InterfaceStatusView {
    traffic_masq_protocol::InterfaceStatusView {
        owned_ipv4_addresses: None,
        interface: traffic_masq_protocol::NetworkInterfaceView {
            index: 1,
            name: name.into(),
            is_up: true,
            rx_bytes: 0,
            tx_bytes: 0,
            is_wireless: true,
        },
        ipv4_addresses: vec![],
        has_default_route,
    }
}

#[tokio::test]
async fn new_sharing_prefills_managed_lan_to_observed_default_route() {
    let mut app = TuiApp::default();
    app.router.staged = true; // Avoid API calls while opening the local draft.
    app.router.proposed_router_config.forwarding = Some(vec![]);
    app.dashboard.interfaces = vec![
        interface_status("wlp5s0f3u2", true),
        interface_status("wlp1s0", false),
    ];
    app.dashboard.managed.insert("wlp1s0".into(), true);
    app.dashboard
        .roles
        .insert("wlp1s0".into(), InterfaceRole::Output);
    app.dashboard.routes = Some(vec![traffic_masq_protocol::RouteStatusView {
        destination: "0.0.0.0/0".parse().unwrap(),
        gateway: Some("192.168.1.1".parse().unwrap()),
        output_interface: Some("wlp5s0f3u2".into()),
        output_interface_index: None,
        table: 254,
        metric: Some(600),
        protocol: 16,
        scope: 0,
        owner: traffic_masq_protocol::RouteOwnerView::Dhcp,
    }]);

    open(
        &mut app,
        &ApiClient::new("/must-not-be-used.sock"),
        false,
        None,
    )
    .await;

    let form = app.forwarding.as_ref().unwrap();
    assert_eq!(form.interfaces[form.from], "wlp1s0");
    assert_eq!(form.interfaces[form.to], "wlp5s0f3u2");
    let rules = form.save().unwrap();
    assert_eq!(rules, vec![connection("wlp1s0", "wlp5s0f3u2")]);
}

#[test]
fn default_route_without_metric_has_zero_priority_cost() {
    let mut app = TuiApp::default();
    let interfaces = vec!["lan0".into(), "wan0".into(), "wan1".into()];
    let route = |interface: &str, metric| traffic_masq_protocol::RouteStatusView {
        destination: "0.0.0.0/0".parse().unwrap(),
        gateway: None,
        output_interface: Some(interface.into()),
        output_interface_index: None,
        table: 254,
        metric,
        protocol: 4,
        scope: 0,
        owner: traffic_masq_protocol::RouteOwnerView::Static,
    };
    app.dashboard.routes = Some(vec![route("wan1", Some(600)), route("wan0", None)]);
    let (_, to) = preferred_new_connection_endpoints(&app, &interfaces, None);
    assert_eq!(interfaces[to], "wan0");
    let (_, to) = preferred_new_connection_endpoints(&app, &interfaces, Some("wan1"));
    assert_eq!(interfaces[to], "wan1", "explicit route selection wins");
}

#[tokio::test]
async fn failed_refresh_cannot_edit_or_delete_cached_sharing_rules() {
    for edit in [false, true] {
        let mut app = TuiApp {
            screen: Screen::Router,
            ..TuiApp::default()
        };
        app.router.topology.loaded = true;
        app.router.proposed_router_config.forwarding = Some(vec![connection("lan0", "wan0")]);
        app.dashboard.interfaces = vec![
            interface_status("lan0", false),
            interface_status("wan0", true),
        ];
        let before = app.router.proposed_router_config.clone();
        let client = ApiClient::new("/must-not-exist-sharing.sock");
        if edit {
            open(&mut app, &client, true, None).await;
        } else {
            delete(&mut app, &client).await;
        }
        assert!(app.forwarding.is_none());
        assert_eq!(app.screen, Screen::Router);
        assert!(!app.router.staged);
        assert_eq!(app.router.proposed_router_config, before);
    }
}

#[tokio::test]
async fn editing_replaces_the_selected_connection_and_preserves_route_intent() {
    let mut app = TuiApp::default();
    app.router.proposed_router_config.owned_routes.push(
        traffic_masq_protocol::OwnedIpv4RouteConfigView {
            destination: "10.0.0.0/8".parse().unwrap(),
            gateway: None,
            output_interface: Some("wan0".into()),
            table: 254,
            metric: None,
        },
    );
    let routes = app.router.proposed_router_config.owned_routes.clone();
    app.forwarding = Some(editor());
    app.screen = Screen::Forwarding;
    handle_key(
        &mut app,
        KeyCode::Enter,
        &ApiClient::new("/must-not-be-used.sock"),
    )
    .await;
    assert_eq!(app.screen, Screen::Router);
    assert_eq!(app.router.pane, RouterPane::Sharing);
    assert!(app.router.staged);
    assert_eq!(app.router.proposed_router_config.owned_routes, routes);
    let rules = app
        .router
        .proposed_router_config
        .forwarding
        .as_ref()
        .unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].to, "wg0");
    assert!(!rules[0].masquerade);
    assert_eq!(
        rules[0].source_subnet,
        Some("192.168.10.0/24".parse().unwrap())
    );
}

#[tokio::test]
async fn invalid_subnet_and_cancel_do_not_modify_the_draft() {
    let mut app = TuiApp::default();
    app.router.proposed_router_config.forwarding = Some(vec![connection("lan0", "wan0")]);
    app.router.staged = true;
    let before = app.router.proposed_router_config.clone();
    let mut form = editor();
    form.source = "192.168.10.3/24".into();
    app.forwarding = Some(form);
    app.screen = Screen::Forwarding;
    let client = ApiClient::new("/must-not-be-used.sock");
    handle_key(&mut app, KeyCode::Enter, &client).await;
    assert!(app.forwarding.as_ref().unwrap().error.is_some());
    assert_eq!(app.router.proposed_router_config, before);
    handle_key(&mut app, KeyCode::Esc, &client).await;
    assert_eq!(app.router.proposed_router_config, before);
    assert!(app.router.staged);
}

#[test]
fn disjoint_source_subnets_share_a_pair_but_overlap_is_rejected() {
    let mut form = editor();
    form.rules[0].to = "wg0".into();
    form.rules[0].source_subnet = Some("192.168.20.0/24".parse().unwrap());
    form.editing = None;
    assert_eq!(form.save().unwrap().len(), 2);
    form.source = "192.168.0.0/16".into();
    assert!(form.save().is_err());
    form.source.clear();
    assert!(form.save().is_err());
}

#[tokio::test]
async fn route_shortcut_prefills_egress_without_changing_routes_or_staging() {
    let mut app = TuiApp::default();
    app.router.staged = true; // A local draft avoids any API request.
    app.router.proposed_router_config.forwarding = Some(vec![connection("lan0", "wan0")]);
    let route = traffic_masq_protocol::RouteStatusView {
        destination: "10.0.0.0/8".parse().unwrap(),
        gateway: None,
        output_interface: Some("wg0".into()),
        output_interface_index: None,
        table: 254,
        metric: None,
        protocol: 4,
        scope: 0,
        owner: traffic_masq_protocol::RouteOwnerView::Static,
    };
    app.router.routes.push(route);
    let before = app.router.proposed_router_config.clone();
    open_from_route(&mut app, &ApiClient::new("/must-not-be-used.sock")).await;
    let form = app.forwarding.as_ref().unwrap();
    assert_eq!(form.interfaces[form.to], "wg0");
    assert_eq!(form.editing, None);
    assert_eq!(app.router.proposed_router_config, before);
}

#[tokio::test]
async fn section_keys_mouse_and_action_arrows_preserve_the_shared_draft() {
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
    use ratatui::{backend::TestBackend, Terminal};
    let mut app = TuiApp {
        screen: Screen::Router,
        ..Default::default()
    };
    app.ui.input_enabled = true;
    app.router.staged = true;
    app.router.proposed_router_config.forwarding = Some(vec![connection("lan0", "wan0")]);
    let before = app.router.proposed_router_config.clone();
    let client = ApiClient::new("/must-not-be-used.sock");
    super::super::handle_key(&mut app, KeyCode::Char('2'), &client, false).await;
    super::super::handle_key(&mut app, KeyCode::Tab, &client, false).await;
    super::super::handle_key(&mut app, KeyCode::Right, &client, false).await;
    assert_eq!(app.screen, Screen::Router);
    assert_eq!(app.router.pane, RouterPane::Sharing);
    assert_eq!(app.router.sharing_action, 1);
    super::super::handle_key(&mut app, KeyCode::Char('3'), &client, false).await;
    assert!(app.router.topology.open);
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| super::super::render(frame, &mut app, false))
        .unwrap();
    let rect = app.router.pane_tabs[0].0;
    super::super::handle_mouse(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: rect.x,
            row: rect.y,
            modifiers: KeyModifiers::NONE,
        },
        &client,
        false,
    )
    .await;
    assert_eq!(app.router.pane, RouterPane::Routes);
    assert!(!app.router.topology.open);
    assert_eq!(app.router.proposed_router_config, before);
    assert!(app.router.staged);
}

#[test]
fn sharing_sections_and_controls_fit_small_and_large_terminals() {
    use ratatui::{backend::TestBackend, Terminal};
    for (width, height) in [(80, 24), (100, 28), (120, 30)] {
        let mut app = TuiApp {
            screen: Screen::Router,
            ..Default::default()
        };
        app.router.pane = RouterPane::Sharing;
        app.router.proposed_router_config.forwarding = Some(vec![connection("lan0", "wg0"); 20]);
        app.router.selected_connection = 19;
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| super::super::render(frame, &mut app, false))
            .unwrap();
        assert_eq!(app.router.pane_tabs.len(), 4);
        assert_eq!(app.ui.buttons.len(), 5);
        assert!(app.ui.list_scroll_offset > 0);
        for (rect, _) in &app.ui.buttons {
            assert!(rect.right() <= width);
            assert!(rect.bottom() <= height - 4);
        }
    }
}

#[tokio::test]
async fn explicit_sharing_can_be_edited_from_saved_settings_without_devices() {
    use traffic_masq_protocol::{
        InterfaceConfigSource, InterfaceConfigView, InterfaceInventoryEntry, InterfacePresence,
        InterfaceReadiness,
    };
    let mut app = TuiApp::default();
    app.router.topology.loaded = true;
    app.router.staged = true;
    app.router.route_inventory = Some(vec![]);
    app.router.proposed_router_config.uplink = Some(traffic_masq_protocol::UplinkConfigView {
        interface: "unplugged_wan".into(),
        mode: traffic_masq_protocol::UplinkMode::External,
    });
    app.router.saved_interfaces.push(InterfaceInventoryEntry {
        name: "unplugged_lan".into(),
        observed: None,
        configured: Some(InterfaceConfigView {
            mac_address: None,
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some("192.168.50.1/24".parse().unwrap()),
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        }),
        config_source: InterfaceConfigSource::Base,
        presence: InterfacePresence::Missing,
        observation_stale: false,
        suppressed: false,
        readiness: InterfaceReadiness::WaitingDevice,
        blockers: vec![],
        references: vec![],
    });
    assert!(displayed_rules(&app.router).unwrap().is_empty());
    app.router.proposed_router_config.forwarding = Some(vec![ForwardingConfig {
        from: "unplugged_lan".into(),
        to: "unplugged_wan".into(),
        source_subnet: Some("192.168.50.0/24".parse().unwrap()),
        masquerade: true,
    }]);
    let rules = displayed_rules(&app.router).unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].from, "unplugged_lan");
    assert_eq!(rules[0].to, "unplugged_wan");
    assert_eq!(
        rules[0].source_subnet,
        Some("192.168.50.0/24".parse().unwrap())
    );
    assert!(app.router.plan.is_none());
    open(&mut app, &ApiClient::new("/must-not-be-used"), true, None).await;
    assert!(app.forwarding.is_some());
    assert_eq!(app.screen, Screen::Forwarding);
    app.forwarding.as_mut().unwrap().field = Field::Save;
    handle_key(
        &mut app,
        KeyCode::Enter,
        &ApiClient::new("/must-not-be-used"),
    )
    .await;
    assert_eq!(app.router.proposed_router_config.forwarding, Some(rules));
    assert!(app.router.proposed_router_config.is_active());
}

#[tokio::test]
async fn source_error_focuses_input_and_enter_can_reach_save_after_correction() {
    let mut e = editor();
    e.source = "192.168.10.3/24".into();
    let mut app = TuiApp {
        screen: Screen::Forwarding,
        forwarding: Some(e),
        ..Default::default()
    };
    let client = ApiClient::new("/must-not-connect");
    handle_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(app.forwarding.as_ref().unwrap().field, Field::Source);
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|f| super::super::render(f, &mut app, false))
        .unwrap();
    let text: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(text.contains("Source subnet must have no host bits"));
    let e = app.forwarding.as_mut().unwrap();
    e.source = "192.168.10.0/24".into();
    e.cursor = e.source.len();
    handle_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(app.forwarding.as_ref().unwrap().field, Field::Save);
    assert!(!app.router.staged);
    handle_key(&mut app, KeyCode::Enter, &client).await;
    assert!(app.router.staged);
    assert!(app.message.as_deref().unwrap().contains("not applied"));
}

#[tokio::test]
async fn new_connection_can_target_tunnels_from_the_unapplied_chain() {
    let mut app = TuiApp::default();
    app.router.staged = true;
    app.router.proposed_router_config.forwarding = Some(vec![]);
    app.router.proposed_router_config.vpn_chain = vec![
        traffic_masq_protocol::VpnHopConfigView {
            profile_name: "first.conf".into(),
        },
        traffic_masq_protocol::VpnHopConfigView {
            profile_name: "exit.conf".into(),
        },
    ];
    app.dashboard.interfaces = vec![
        interface_status("lan0", false),
        interface_status("wan0", true),
    ];
    open(&mut app, &ApiClient::new("/must-not-connect"), false, None).await;
    let form = app.forwarding.as_mut().unwrap();
    assert!(form.interfaces.iter().any(|name| name == "tm-wg-0"));
    form.to = form
        .interfaces
        .iter()
        .position(|name| name == "tm-wg-1")
        .unwrap();
    form.from = form
        .interfaces
        .iter()
        .position(|name| name == "lan0")
        .unwrap();
    let rules = form.save().unwrap();
    assert_eq!(rules[0].to, "tm-wg-1");
}

#[test]
fn sharing_editor_and_preview_show_both_current_endpoint_states_at_minimum_size() {
    use ratatui::{backend::TestBackend, Terminal};
    let mut app = TuiApp::default();
    app.dashboard.interfaces = vec![
        interface_status("lan0", false),
        interface_status("wan0", true),
    ];
    app.dashboard.interfaces[1].interface.is_up = false;
    app.dashboard.managed.insert("lan0".into(), true);
    app.dashboard.managed.insert("wan0".into(), false);
    let mut form = editor();
    form.to = 1;
    form.field = Field::From;
    app.forwarding = Some(form);
    app.screen = Screen::Forwarding;
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    let text = |terminal: &Terminal<TestBackend>| {
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>()
    };
    terminal
        .draw(|frame| super::super::render(frame, &mut app, false))
        .unwrap();
    let rendered = text(&terminal);
    assert!(rendered.contains("lan0 · UP · traffic-masq:on"));
    assert!(rendered.contains("wan0 · DOWN · traffic-masq:off"));
    assert!(
        app.ui.buttons.iter().any(|(_, slot)| *slot == 0),
        "Save remains reachable"
    );

    app.router.offline_preview = Some(super::super::router::OfflineRouterPreview {
        baseline: Default::default(),
        config: traffic_masq_protocol::RouterConfigView {
            forwarding: Some(vec![connection("lan0", "wan0")]),
            ..Default::default()
        },
        revision: 1,
        blockers: vec![],
    });
    app.screen = Screen::RouterPlan;
    terminal
        .draw(|frame| super::super::render(frame, &mut app, false))
        .unwrap();
    let rendered = text(&terminal);
    assert!(rendered.contains("Current: lan0 · UP · traffic-masq:on"));
    assert!(rendered.contains("Current: wan0 · DOWN · traffic-masq:off"));
}

#[tokio::test]
async fn sharing_status_rows_keep_mouse_selection_aligned() {
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
    use ratatui::{backend::TestBackend, Terminal};
    let mut app = TuiApp {
        screen: Screen::Router,
        ..Default::default()
    };
    app.router.pane = super::super::router::RouterPane::Sharing;
    app.router.staged = true;
    app.router.proposed_router_config.forwarding =
        Some(vec![connection("lan0", "wan0"), connection("lan1", "wan1")]);
    app.dashboard.interfaces = vec![
        interface_status("lan0", false),
        interface_status("wan0", true),
    ];
    app.dashboard.interfaces[1].interface.is_up = false;
    app.dashboard.managed.insert("lan0".into(), true);
    app.dashboard.managed.insert("wan0".into(), false);
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| super::super::render(frame, &mut app, false))
        .unwrap();
    let rendered = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(rendered.contains("UP tm:on"));
    assert!(rendered.contains("DOWN tm:off"));
    assert_eq!(app.ui.list_row_height, 3);
    let area = app.ui.list_area.unwrap();
    super::super::handle_mouse(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: area.x,
            row: area.y + 4,
            modifiers: KeyModifiers::NONE,
        },
        &ApiClient::new("/must-not-be-used.sock"),
        false,
    )
    .await;
    assert_eq!(app.router.selected_connection, 1);
}
