use super::controller::router_plan_needed;
use super::editor::{
    cycle_output_interface, delete_selected_route, manual_route_delete_command, save_route_editor,
};
use super::pending::router_pending_seconds_remaining;
use super::plan::{summarize_dhcp, summarize_output_interfaces};
use super::view::{
    describe_router_error, format_coordinator_status, format_forwarding_status, format_owner_badge,
    health_report_details, recovery_notice_summary, recovery_notice_text, router_action_buttons,
    summarize_uplink,
};
use super::*;
use std::net::Ipv4Addr;
use traffic_masq_protocol::{
    ForwardingConfigView, InterfaceConfigView, OwnedFirewallIntegrityView,
    RouterDataplaneDesiredView, RouterDataplanePlanView, RouterDataplaneSnapshotView,
    RouterInterfaceDesiredView,
};

fn dhcp_spec(interface: &str) -> DhcpServiceView {
    DhcpServiceView {
        interface: interface.to_string(),
        server_ip: Ipv4Addr::new(192, 168, 10, 1),
        prefix_len: 24,
        subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
        pool_start: Ipv4Addr::new(192, 168, 10, 10),
        pool_end: Ipv4Addr::new(192, 168, 10, 100),
        router: Ipv4Addr::new(192, 168, 10, 1),
        dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
        lease_seconds: 3_600,
    }
}

#[tokio::test]
async fn routing_toggle_stages_configuration_for_plan_review() {
    let client = ApiClient::new("/socket-that-must-not-be-opened");
    let mut app = TuiApp {
        screen: Screen::Router,
        ..Default::default()
    };
    app.router.topology.loaded = true;
    handle_router_key(&mut app, KeyCode::Char('e'), &client).await;
    assert!(app.router.staged);
    assert!(app.router.proposed_router_config.enabled);
    assert!(
        !app.router.enabled,
        "toggle must not skip plan/apply/commit"
    );
    assert_eq!(
        app.screen,
        Screen::Router,
        "failed preview must not proceed to apply"
    );
    handle_router_key(&mut app, KeyCode::Char('e'), &client).await;
    assert!(!app.router.proposed_router_config.enabled);
}

#[test]
fn router_action_cycles_forward_and_backward() {
    let action = RouterAction::AddRoute;
    assert_eq!(action.next(), RouterAction::EditRoute);
    assert_eq!(action.next().next(), RouterAction::DeleteRoute);
    assert_eq!(action.next().next().next(), RouterAction::PlanApply);
    assert_eq!(
        action.next().next().next().next(),
        RouterAction::ShareViaRoute
    );
    assert_eq!(
        action.next().next().next().next().next(),
        RouterAction::Refresh
    );
    assert_eq!(
        action.next().next().next().next().next().next(),
        RouterAction::Topology
    );
    assert_eq!(
        action.next().next().next().next().next().next().next(),
        RouterAction::ToggleEnabled
    );

    assert_eq!(action.prev(), RouterAction::ToggleEnabled);
    assert_eq!(action.prev().prev(), RouterAction::Topology);
    assert_eq!(action.prev().prev().prev(), RouterAction::Refresh);
}

#[test]
fn staged_explicit_forwarding_requires_a_plan_even_when_committed_router_is_disabled() {
    let mut router = RouterData {
        enabled: false,
        ..Default::default()
    };
    router.proposed_router_config.enabled = true;
    router.proposed_router_config.forwarding =
        Some(vec![traffic_masq_protocol::ForwardingConfigView {
            source_subnet: None,
            from: "lan0".to_string(),
            to: "wan0".to_string(),
            masquerade: true,
        }]);

    assert!(router_plan_needed(&router));
}

#[test]
fn route_editor_field_cycles_forward_and_backward() {
    let field = RouteEditorField::Destination;
    assert_eq!(field.next(), RouteEditorField::Gateway);
    assert_eq!(field.next().next(), RouteEditorField::OutputInterface);
    assert_eq!(field.next().next().next(), RouteEditorField::Metric);
    assert_eq!(field.next().next().next().next(), RouteEditorField::Table);
    assert_eq!(
        field.next().next().next().next().next(),
        RouteEditorField::AllowDefaultRouteChange
    );
    assert_eq!(
        field.next().next().next().next().next().next(),
        RouteEditorField::Save
    );
    assert_eq!(
        field.next().next().next().next().next().next().next(),
        RouteEditorField::Destination
    );

    assert_eq!(field.prev(), RouteEditorField::Save);
    assert_eq!(
        field.prev().prev(),
        RouteEditorField::AllowDefaultRouteChange
    );
}

#[test]
fn format_owner_badge_styles_appropriately() {
    let static_badge = format_owner_badge(RouteOwner::TrafficMasqStatic);
    assert_eq!(static_badge.content, "traffic-masq");
    assert_eq!(static_badge.style.fg, Some(theme::GOOD));

    let dhcp_badge = format_owner_badge(RouteOwner::TrafficMasqDhcp);
    assert_eq!(dhcp_badge.content, "traffic-masq (dhcp)");
    assert_eq!(dhcp_badge.style.fg, Some(theme::ACCENT));

    let kernel_badge = format_owner_badge(RouteOwner::Kernel);
    assert_eq!(kernel_badge.content, "[ext:kernel]");
    assert_eq!(kernel_badge.style.fg, Some(theme::WARN));
}

#[test]
fn cycle_output_interface_rotates_options() {
    let mut editor = RouteEditor {
        original_route: None,
        destination: "10.0.0.0/24".into(),
        gateway: String::new(),
        output_interface: None,
        metric: String::new(),
        table: "254".into(),
        allow_default_route_change: false,
        field: RouteEditorField::OutputInterface,
        cursor: 0,
        available_interfaces: vec!["eth0".into(), "wlan0".into()],
    };

    cycle_output_interface(&mut editor, true);
    assert_eq!(editor.output_interface, Some("eth0".into()));

    cycle_output_interface(&mut editor, true);
    assert_eq!(editor.output_interface, Some("wlan0".into()));

    cycle_output_interface(&mut editor, true);
    assert_eq!(editor.output_interface, None);

    cycle_output_interface(&mut editor, false);
    assert_eq!(editor.output_interface, Some("wlan0".into()));
}

#[test]
fn save_route_editor_validates_and_stages_route() {
    let mut app = TuiApp {
        screen: Screen::RouteEditor,
        ..Default::default()
    };
    app.router.editor = Some(RouteEditor {
        original_route: None,
        destination: "192.168.100.0/24".into(),
        gateway: "192.168.1.1".into(),
        output_interface: Some("eth0".into()),
        metric: "100".into(),
        table: "254".into(),
        allow_default_route_change: false,
        field: RouteEditorField::Save,
        cursor: 0,
        available_interfaces: vec!["eth0".into()],
    });

    save_route_editor(&mut app);

    assert_eq!(app.screen, Screen::Router);
    assert!(app.router.editor.is_none());
    assert!(app.router.staged);
    assert!(app.router.proposed_router_config.enabled);
    assert_eq!(app.router.proposed_router_config.owned_routes.len(), 1);
    let route = &app.router.proposed_router_config.owned_routes[0];
    assert_eq!(route.destination, "192.168.100.0/24".parse().unwrap());
    assert_eq!(route.gateway, Some(Ipv4Addr::new(192, 168, 1, 1)));
    assert_eq!(route.output_interface.as_deref(), Some("eth0"));
    assert_eq!(route.metric, Some(100));
    assert_eq!(route.table, 254);

    assert_eq!(app.router.routes.len(), 1);
    assert_eq!(app.router.routes[0].owner, RouteOwner::TrafficMasqStatic);
}

#[test]
fn save_route_editor_auto_appends_slash_32_for_bare_ips() {
    let mut app = TuiApp {
        screen: Screen::RouteEditor,
        ..Default::default()
    };
    app.router.editor = Some(RouteEditor {
        original_route: None,
        destination: "10.5.0.1".into(),
        gateway: "192.168.1.1".into(),
        output_interface: Some("eth0".into()),
        metric: "".into(),
        table: "254".into(),
        allow_default_route_change: false,
        field: RouteEditorField::Save,
        cursor: 0,
        available_interfaces: vec!["eth0".into()],
    });

    save_route_editor(&mut app);

    assert_eq!(app.screen, Screen::Router);
    assert_eq!(app.router.proposed_router_config.owned_routes.len(), 1);
    assert_eq!(
        app.router.proposed_router_config.owned_routes[0].destination,
        "10.5.0.1/32".parse().unwrap()
    );
    assert!(app.router.proposed_router_config.enabled);
}

#[test]
fn save_route_editor_rejects_host_bits_and_table_255() {
    let mut app = TuiApp {
        screen: Screen::RouteEditor,
        ..Default::default()
    };
    app.router.editor = Some(RouteEditor {
        original_route: None,
        destination: "192.168.100.5/24".into(),
        gateway: "192.168.1.1".into(),
        output_interface: Some("eth0".into()),
        metric: "".into(),
        table: "254".into(),
        allow_default_route_change: false,
        field: RouteEditorField::Save,
        cursor: 0,
        available_interfaces: vec!["eth0".into()],
    });

    save_route_editor(&mut app);
    assert_eq!(app.screen, Screen::RouteEditor);
    assert!(app.router.proposed_router_config.owned_routes.is_empty());

    // Test table 255 rejection
    app.router.editor.as_mut().unwrap().destination = "192.168.100.0/24".into();
    app.router.editor.as_mut().unwrap().table = "255".into();
    save_route_editor(&mut app);
    assert_eq!(app.screen, Screen::RouteEditor);
    assert!(app.router.proposed_router_config.owned_routes.is_empty());
}

#[test]
fn save_route_editor_rejects_missing_both_gateway_and_interface() {
    let mut app = TuiApp {
        screen: Screen::RouteEditor,
        ..Default::default()
    };
    app.router.editor = Some(RouteEditor {
        original_route: None,
        destination: "192.168.100.0/24".into(),
        gateway: "".into(),
        output_interface: None,
        metric: "".into(),
        table: "254".into(),
        allow_default_route_change: false,
        field: RouteEditorField::Save,
        cursor: 0,
        available_interfaces: vec![],
    });

    save_route_editor(&mut app);

    assert_eq!(app.screen, Screen::RouteEditor);
    assert!(app.router.proposed_router_config.owned_routes.is_empty());
}

#[test]
fn save_route_editor_rejects_unspecified_multicast_and_broadcast_gateways() {
    let mut app = TuiApp {
        screen: Screen::RouteEditor,
        ..Default::default()
    };

    for invalid_gw in ["0.0.0.0", "255.255.255.255", "224.0.0.1"] {
        app.router.editor = Some(RouteEditor {
            original_route: None,
            destination: "192.168.100.0/24".into(),
            gateway: invalid_gw.into(),
            output_interface: None,
            metric: "".into(),
            table: "254".into(),
            allow_default_route_change: false,
            field: RouteEditorField::Save,
            cursor: 0,
            available_interfaces: vec![],
        });

        save_route_editor(&mut app);
        assert_eq!(app.screen, Screen::RouteEditor);
        assert!(app.router.proposed_router_config.owned_routes.is_empty());
    }
}

#[test]
fn route_editor_retry_after_collision_replaces_original() {
    for owner in [RouteOwner::TrafficMasqStatic, RouteOwner::Static] {
        let original = route_config("10.1.0.0/24");
        let collision = route_config("10.2.0.0/24");
        let mut app = TuiApp {
            screen: Screen::RouteEditor,
            ..Default::default()
        };
        app.router.proposed_router_config.enabled = true;
        app.router.proposed_router_config.owned_routes = vec![original.clone()];
        if owner.is_editable() {
            app.router
                .proposed_router_config
                .owned_routes
                .push(collision.clone());
        }
        app.router.routes = vec![
            route_status(&original, RouteOwner::TrafficMasqStatic),
            route_status(&collision, owner),
        ];
        app.router.editor = Some(RouteEditor {
            original_route: Some(original.clone()),
            destination: collision.destination.to_string(),
            gateway: "192.168.1.1".into(),
            output_interface: Some("eth0".into()),
            metric: "100".into(),
            table: "254".into(),
            allow_default_route_change: false,
            field: RouteEditorField::Save,
            cursor: 0,
            available_interfaces: vec!["eth0".into()],
        });
        let before = app.router.proposed_router_config.clone();
        let before_routes = app.router.routes.clone();

        save_route_editor(&mut app);

        assert_eq!(app.screen, Screen::RouteEditor);
        assert_eq!(app.router.proposed_router_config, before);
        assert_eq!(app.router.routes, before_routes);
        assert!(!app.router.staged);
        let editor = app.router.editor.as_mut().expect("editor remains open");
        assert_eq!(editor.original_route.as_ref(), Some(&original));
        editor.destination = "10.3.0.0/24".into();

        save_route_editor(&mut app);

        assert_eq!(app.screen, Screen::Router);
        assert!(app.router.editor.is_none());
        assert!(app.router.staged);
        let routes = &app.router.proposed_router_config.owned_routes;
        assert_eq!(routes.len(), before.owned_routes.len());
        assert!(!routes.contains(&original));
        assert!(routes.contains(&route_config("10.3.0.0/24")));
        assert_eq!(app.router.routes.len(), before_routes.len());
        assert!(!app
            .router
            .routes
            .iter()
            .any(|r| r.destination == original.destination));
    }
}

fn route_config(destination: &str) -> OwnedIpv4RouteConfig {
    OwnedIpv4RouteConfig {
        destination: destination.parse().expect("destination"),
        gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
        output_interface: Some("eth0".into()),
        table: 254,
        metric: Some(100),
    }
}

fn route_status(route: &OwnedIpv4RouteConfig, owner: RouteOwner) -> RouteStatus {
    RouteStatus {
        destination: route.destination,
        gateway: route.gateway,
        output_interface: route.output_interface.clone(),
        output_interface_index: Some(2),
        table: route.table,
        metric: route.metric,
        protocol: if owner.is_editable() { 201 } else { 4 },
        scope: 0,
        owner,
    }
}

#[test]
fn deleting_last_default_route_preserves_permission_in_proposal() {
    let original = route_config("0.0.0.0/0");
    let config = RouterConfig {
        enabled: true,
        allow_default_route_change: true,
        owned_routes: vec![original.clone()],
        ..Default::default()
    };
    let mut app = TuiApp::default();
    app.router.proposed_router_config = config;
    app.router.routes = vec![route_status(&original, RouteOwner::TrafficMasqStatic)];

    delete_selected_route(&mut app);

    assert!(app.router.staged);
    assert!(app.router.routes.is_empty());
    let proposal = super::plan::current_router_proposal(&app);
    let router = proposal.set_router.expect("staged router config");
    assert!(router.owned_routes.is_empty());
    assert!(router.allow_default_route_change);
}

#[test]
fn delete_selected_route_shows_manual_command_for_external_and_stages_owned() {
    let mut app = TuiApp {
        screen: Screen::Router,
        ..Default::default()
    };
    app.router.proposed_router_config.enabled = true;
    let external_route = RouteStatus {
        destination: "10.0.0.0/8".parse().unwrap(),
        gateway: None,
        output_interface: Some("eth0".into()),
        output_interface_index: None,
        table: 254,
        metric: None,
        protocol: 2,
        scope: 253,
        owner: RouteOwner::Kernel,
    };
    let owned_route = RouteStatus {
        destination: "192.168.1.0/24".parse().unwrap(),
        gateway: Some(Ipv4Addr::new(10, 0, 0, 1)),
        output_interface: Some("eth0".into()),
        output_interface_index: None,
        table: 254,
        metric: Some(50),
        protocol: traffic_masq_netlink::TRAFFIC_MASQ_ROUTE_PROTOCOL,
        scope: 0,
        owner: RouteOwner::TrafficMasqStatic,
    };
    app.router.routes = vec![external_route, owned_route];
    app.router.proposed_router_config.owned_routes = vec![OwnedIpv4RouteConfig {
        destination: "192.168.1.0/24".parse().unwrap(),
        gateway: Some(Ipv4Addr::new(10, 0, 0, 1)),
        output_interface: Some("eth0".into()),
        table: 254,
        metric: Some(50),
    }];

    // External routes only produce instructions, leaving all state intact.
    let original_routes = app.router.routes.clone();
    let original_config = app.router.proposed_router_config.clone();
    app.router.selected_route = 0;
    delete_selected_route(&mut app);
    assert_eq!(app.router.routes, original_routes);
    assert_eq!(app.router.proposed_router_config, original_config);
    assert!(!app.router.staged);
    assert!(app.message_open);
    assert!(app.message.as_deref().unwrap().contains(
        "sudo ip -4 route del 10.0.0.0/8 dev 'eth0' table 254 metric 0 proto 2 scope 253"
    ));
    assert!(app
        .message
        .as_deref()
        .unwrap()
        .contains("To copy, hold down Shift"));

    // Delete owned route
    app.message_open = false;
    app.router.selected_route = 1;
    delete_selected_route(&mut app);
    assert_eq!(app.router.routes.len(), 1);
    assert!(app.router.proposed_router_config.owned_routes.is_empty());
    assert!(!app.router.proposed_router_config.enabled);
    assert!(app.router.staged);
    assert_eq!(app.router.warning_message, None);
}

#[test]
fn manual_delete_preserves_route_selectors_and_quotes_interface_names() {
    let mut route = route_status(&route_config("0.0.0.0/0"), RouteOwner::Dhcp);
    route.gateway = Some(Ipv4Addr::new(192, 0, 2, 1));
    route.output_interface = Some("eth'$(id);0".into());
    route.table = 1000;
    route.metric = Some(600);
    route.protocol = 16;
    assert_eq!(
        manual_route_delete_command(&route).unwrap(),
        "sudo ip -4 route del 0.0.0.0/0 via 192.0.2.1 dev 'eth'\\''$(id);0' table 1000 metric 600 proto 16 scope 0"
    );
    route.output_interface = None;
    assert!(manual_route_delete_command(&route).is_err());
}

#[tokio::test]
async fn router_plan_requires_reaching_the_end_before_apply() {
    let mut app = TuiApp {
        screen: Screen::RouterPlan,
        ..Default::default()
    };
    app.router.plan_max_scroll = 7;
    let client = ApiClient::new("/socket-that-must-not-be-opened");

    super::plan::handle_router_plan_key(&mut app, KeyCode::Enter, &client).await;
    assert!(app
        .message
        .as_deref()
        .is_some_and(|message| message.contains("Review the complete router plan")));

    super::plan::handle_router_plan_key(&mut app, KeyCode::PageDown, &client).await;
    assert_eq!(app.router.plan_scroll, 7);
    super::plan::handle_router_plan_key(&mut app, KeyCode::Up, &client).await;
    assert_eq!(app.router.plan_scroll, 6);
}

#[tokio::test]
async fn router_actions_are_reachable_with_arrows_and_activate_only_on_enter() {
    let mut app = TuiApp {
        screen: Screen::Router,
        ..Default::default()
    };
    app.ui.input_enabled = true;
    app.router.routes = vec![
        route_status(&route_config("10.0.0.0/8"), RouteOwner::Static),
        route_status(&route_config("172.16.0.0/12"), RouteOwner::Static),
    ];
    let client = ApiClient::new("/socket-that-must-not-be-opened");
    // Scrolling Down stays in RouteTable and clamps at the end of routes
    super::super::handle_key(&mut app, KeyCode::Down, &client, false).await;
    assert_eq!(app.router.focus, RouterFocus::RouteTable);
    assert_eq!(app.router.selected_route, 1);
    super::super::handle_key(&mut app, KeyCode::Down, &client, false).await;
    assert_eq!(app.router.focus, RouterFocus::RouteTable);
    assert_eq!(app.router.selected_route, 1);

    // Enter actions exclusively via Tab
    super::super::handle_key(&mut app, KeyCode::Tab, &client, false).await;
    assert_eq!(app.router.focus, RouterFocus::Actions);
    assert_eq!(app.router.action, RouterAction::AddRoute);

    // In actions, navigate between buttons
    super::super::handle_key(&mut app, KeyCode::Down, &client, false).await;
    assert_eq!(app.router.action, RouterAction::EditRoute);
    super::super::handle_key(&mut app, KeyCode::Down, &client, false).await;
    assert_eq!(app.router.action, RouterAction::DeleteRoute);
    assert_eq!(app.router.focus, RouterFocus::Actions);

    super::super::handle_key(&mut app, KeyCode::Enter, &client, false).await;
    assert!(app.message_open);
    assert!(app
        .message
        .as_deref()
        .unwrap()
        .contains("sudo ip -4 route del"));
    assert_eq!(app.router.routes.len(), 2);
    assert!(!app.router.staged);
    super::super::handle_key(&mut app, KeyCode::Esc, &client, false).await;
    assert!(!app.message_open);
    assert_eq!(app.screen, Screen::Router);
    for key in [KeyCode::Left, KeyCode::Right] {
        super::super::handle_key(&mut app, key, &client, false).await;
        assert_eq!(app.screen, Screen::Router);
    }
    for _ in 0..5 {
        super::super::handle_key(&mut app, KeyCode::Up, &client, false).await;
        assert_eq!(app.router.focus, RouterFocus::Actions);
    }
    super::super::handle_key(&mut app, KeyCode::Tab, &client, false).await;
    assert_eq!(app.router.focus, RouterFocus::RouteTable);
    super::super::handle_key(&mut app, KeyCode::Tab, &client, false).await;
    assert_eq!(app.router.focus, RouterFocus::Actions);
    super::super::handle_key(&mut app, KeyCode::BackTab, &client, false).await;
    assert_eq!(app.router.focus, RouterFocus::RouteTable);

    // Esc in Actions returns to RouteTable without leaving Router screen
    super::super::handle_key(&mut app, KeyCode::Tab, &client, false).await;
    assert_eq!(app.router.focus, RouterFocus::Actions);
    super::super::handle_key(&mut app, KeyCode::Esc, &client, false).await;
    assert_eq!(app.router.focus, RouterFocus::RouteTable);
    assert_eq!(app.screen, Screen::Router);

    // Esc in RouteTable returns to Dashboard
    super::super::handle_key(&mut app, KeyCode::Esc, &client, false).await;
    assert_eq!(app.screen, Screen::Dashboard);
}

#[tokio::test]
async fn empty_router_actions_require_tab_and_clamp_at_the_last() {
    let mut app = TuiApp::default();
    let client = ApiClient::new("/socket-that-must-not-be-opened");
    handle_router_key(&mut app, KeyCode::Down, &client).await;
    assert_eq!(app.router.focus, RouterFocus::RouteTable);

    handle_router_key(&mut app, KeyCode::Tab, &client).await;
    assert_eq!(app.router.focus, RouterFocus::Actions);

    for (action, _) in router_action_buttons(&app.router) {
        assert_eq!(app.router.action, action);
        handle_router_key(&mut app, KeyCode::Down, &client).await;
        assert_eq!(app.router.focus, RouterFocus::Actions);
    }
    assert_eq!(app.router.action, RouterAction::ToggleEnabled);

    handle_router_key(&mut app, KeyCode::Tab, &client).await;
    assert_eq!(app.router.focus, RouterFocus::RouteTable);
}

#[test]
fn router_buttons_wrap_and_remain_visible_at_supported_sizes() {
    use ratatui::{backend::TestBackend, Terminal};
    for (width, height) in [(80, 24), (100, 28), (120, 30)] {
        for warning in [None, Some("External route is read-only".to_string())] {
            let mut app = TuiApp {
                screen: Screen::Router,
                ..Default::default()
            };
            app.router.warning_message = warning;
            app.router.routes = vec![route_status(
                &route_config("10.0.0.0/8"),
                RouteOwner::Static,
            )];
            app.router.focus = RouterFocus::Actions;
            app.router.action = RouterAction::DeleteRoute;
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal
                .draw(|frame| super::super::render(frame, &mut app, false))
                .unwrap();
            let action_buttons = if width >= 112 {
                assert_eq!(app.ui.buttons.len(), 9, "{width}x{height}");
                &app.ui.buttons[1..]
            } else {
                assert_eq!(app.ui.buttons.len(), 8, "{width}x{height}");
                &app.ui.buttons[..]
            };
            let buffer = terminal.backend().buffer();
            for ((rect, slot), (_, label)) in action_buttons
                .iter()
                .zip(router_action_buttons(&app.router))
            {
                let text: String = (rect.x..rect.right())
                    .map(|x| buffer[(x, rect.y)].symbol())
                    .collect();
                assert_eq!(text, label, "button {slot} at {width}x{height}");
                assert!(rect.bottom() <= height - 4, "button must be above footer");
            }
            let (rect, _) = action_buttons[2];
            assert_eq!(buffer[(rect.x, rect.y)].bg, theme::SELECTED_BG);
        }
    }
}

#[test]
fn degraded_recovery_marks_router_mutations_as_blocked() {
    let router = RouterData {
        recovery: Some(RouterRecoveryNotice {
            recovery_progress: None,
            recovery_code: "TM-REC-207".into(),
            invariant: "router_rollback_failed".into(),
            summary: "rollback failed".into(),
            blocked_operation: "new router transactions".into(),
            operator_action: "retry_rollback".into(),
            operator_guidance: "retry rollback".into(),
            runbook: "docs/recovery.md#tm-rec-207".into(),
            failures: Vec::new(),
        }),
        ..Default::default()
    };

    let buttons = router_action_buttons(&router);
    assert_eq!(
        buttons[3],
        (RouterAction::PlanApply, "[Apply blocked: recovery]")
    );
    assert_eq!(
        buttons[7],
        (RouterAction::ToggleEnabled, "[Routing change blocked]")
    );
}

#[tokio::test]
async fn periodic_router_status_refresh_does_not_request_a_plan() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("api.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut bytes = [0; 1024];
        while !request.windows(4).any(|part| part == b"\r\n\r\n") {
            let count = stream.read(&mut bytes).await.unwrap();
            assert!(count > 0);
            request.extend_from_slice(&bytes[..count]);
        }

        let body = serde_json::to_vec(&Response::RouterStatus {
            enabled: true,
            ready: true,
            coordinator_status: CoordinatorStatus::Idle,
            health: RouterHealthReport::default(),
            recovery: None,
        })
        .unwrap();
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        stream.write_all(&body).await.unwrap();
        drop(stream);

        tokio::time::timeout(std::time::Duration::from_millis(200), listener.accept())
            .await
            .is_err()
    });

    let mut app = TuiApp::default();
    app.router.proposed_router_config.enabled = true;
    app.router.error = Some(RouterErrorDetail::StalePlan);
    super::controller::refresh_router_status(&mut app, &ApiClient::new(socket)).await;

    assert!(app.router.enabled);
    assert!(app.router.ready);
    assert!(app.router.proposed_router_config.enabled);
    assert!(matches!(
        app.router.error,
        Some(RouterErrorDetail::StalePlan)
    ));
    assert!(
        server.await.unwrap(),
        "periodic refresh made a second API request"
    );
}

#[tokio::test]
async fn failed_status_refresh_preserves_last_known_recovery() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("api.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut bytes = [0; 1024];
        while !request.windows(4).any(|part| part == b"\r\n\r\n") {
            let count = stream.read(&mut bytes).await.unwrap();
            assert!(count > 0);
            request.extend_from_slice(&bytes[..count]);
        }
        stream
            .write_all(
                b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
    });

    let mut app = TuiApp::default();
    app.router.coordinator_status = Some(CoordinatorStatus::RollbackFailed);
    app.router.recovery = Some(RouterRecoveryNotice {
        recovery_progress: None,
        recovery_code: "TM-REC-207".into(),
        invariant: "router_rollback_failed".into(),
        summary: "rollback failed".into(),
        blocked_operation: "new router transactions".into(),
        operator_action: "retry_rollback".into(),
        operator_guidance: "retry rollback".into(),
        runbook: "docs/recovery.md#tm-rec-207".into(),
        failures: vec!["route restore failed".into()],
    });

    load_router_data(&mut app, &ApiClient::new(socket)).await;
    server.await.unwrap();

    assert_eq!(
        app.router.coordinator_status,
        Some(CoordinatorStatus::RollbackFailed)
    );
    assert_eq!(
        app.router
            .recovery
            .as_ref()
            .map(|notice| notice.recovery_code.as_str()),
        Some("TM-REC-207")
    );
    assert!(app.router.recovery_blocks_mutations());
}

#[test]
fn coordinator_status_blocks_mutations_without_structured_notice() {
    for status in [
        CoordinatorStatus::CommitIndeterminate,
        CoordinatorStatus::RollbackFailed,
        CoordinatorStatus::RecoveredButJournalCleanupPending,
    ] {
        let router = RouterData {
            coordinator_status: Some(status),
            ..Default::default()
        };

        assert!(router.recovery_blocks_mutations());
        let buttons = router_action_buttons(&router);
        assert_eq!(
            buttons[3],
            (RouterAction::PlanApply, "[Apply blocked: recovery]")
        );
        assert_eq!(
            buttons[7],
            (RouterAction::ToggleEnabled, "[Routing change blocked]")
        );
    }
}

#[test]
fn router_pending_countdown_counts_down_and_floors_at_zero() {
    assert_eq!(router_pending_seconds_remaining(1_000, 60, 1_000), 60);
    assert_eq!(router_pending_seconds_remaining(1_000, 60, 1_040), 20);
    assert_eq!(router_pending_seconds_remaining(1_000, 60, 1_200), 0);
}

#[test]
fn describes_each_router_error_detail_distinctly() {
    let messages = [
        describe_router_error(&RouterErrorDetail::RouterDisabled),
        describe_router_error(&RouterErrorDetail::TransactionPending),
        describe_router_error(&RouterErrorDetail::RollbackRecoveryRequired),
        describe_router_error(&RouterErrorDetail::StaleCandidate {
            candidate_revision: 1,
            current_revision: 2,
        }),
        describe_router_error(&RouterErrorDetail::StalePlan),
        describe_router_error(&RouterErrorDetail::NoPendingTransaction),
        describe_router_error(&RouterErrorDetail::RollbackFailed {
            failures: vec!["dhcp restart failed".to_string()],
        }),
        describe_router_error(&RouterErrorDetail::Other {
            message: "boom".to_string(),
        }),
    ];

    for (index, message) in messages.iter().enumerate() {
        assert!(!message.is_empty());
        for (other_index, other) in messages.iter().enumerate() {
            if index != other_index {
                assert_ne!(message, other, "variants must not collapse into one string");
            }
        }
    }
    assert!(messages[3].contains('1') && messages[3].contains('2'));
    assert!(messages[6].contains("dhcp restart failed"));
    assert_eq!(messages[7], "boom");
}

#[test]
fn summarizes_only_output_interfaces_with_subnet() {
    let interfaces = vec![
        RouterInterfaceDesiredView {
            name: "wan0".to_string(),
            config: InterfaceConfigView {
                role: InterfaceRole::Input,
                managed: false,
                ipv4: None,
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
                nat: true,
            },
        },
        RouterInterfaceDesiredView {
            name: "lan0".to_string(),
            config: InterfaceConfigView {
                role: InterfaceRole::Output,
                managed: true,
                ipv4: Some("192.168.10.1/24".parse().unwrap()),
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
                nat: true,
            },
        },
    ];

    let summary = summarize_output_interfaces(&interfaces);

    assert_eq!(summary, vec!["lan0 (192.168.10.1/24)"]);
}

#[test]
fn summarizes_dhcp_with_known_and_missing_lease_counts() {
    let dhcp = vec![dhcp_spec("lan0"), dhcp_spec("lan1")];
    let lease_counts = vec![("lan0".to_string(), 3usize)];

    let summary = summarize_dhcp(&dhcp, &lease_counts);

    assert_eq!(
        summary,
        vec![
            "lan0 pool 192.168.10.10-192.168.10.100 (3 lease(s))".to_string(),
            "lan1 pool 192.168.10.10-192.168.10.100 (lease count unavailable)".to_string(),
        ]
    );
}

#[test]
fn summarizes_uplink_for_enabled_and_disabled_dataplane() {
    let enabled = RouterDataplaneTargetView::Enabled(RouterDataplaneDesiredView {
        forwarding: None,
        uplink: "wan0".to_string(),
        outputs: Vec::new(),
    });
    assert_eq!(summarize_uplink(&enabled), "wan0");
    assert_eq!(
        summarize_uplink(&RouterDataplaneTargetView::Disabled),
        "none (dataplane disabled)"
    );
}

#[test]
fn formats_forwarding_status_reflects_snapshot_target_and_drift() {
    let plan = RouterDataplanePlanView {
        snapshot: RouterDataplaneSnapshotView {
            ipv4_forwarding: true,
            owned: None,
            owned_firewall_integrity: OwnedFirewallIntegrityView::Intact,
        },
        target: RouterDataplaneTargetView::Enabled(RouterDataplaneDesiredView {
            forwarding: None,
            uplink: "wan0".to_string(),
            outputs: Vec::new(),
        }),
        requires_apply: true,
    };

    assert_eq!(
        format_forwarding_status(&plan),
        "forwarding on, NAT desired, drift: requires apply"
    );
}

#[test]
fn forwarding_status_does_not_claim_nat_for_non_masqueraded_rules() {
    let plan = RouterDataplanePlanView {
        snapshot: RouterDataplaneSnapshotView {
            ipv4_forwarding: true,
            owned: None,
            owned_firewall_integrity: OwnedFirewallIntegrityView::Intact,
        },
        target: RouterDataplaneTargetView::Enabled(RouterDataplaneDesiredView {
            forwarding: Some(vec![ForwardingConfigView {
                source_subnet: None,
                from: "lan0".to_string(),
                to: "wg0".to_string(),
                masquerade: false,
            }]),
            uplink: String::new(),
            outputs: Vec::new(),
        }),
        requires_apply: false,
    };

    assert_eq!(
        format_forwarding_status(&plan),
        "forwarding on, NAT disabled, in sync"
    );
}

#[test]
fn health_report_details_lists_only_failing_subsystems() {
    let health = RouterHealthReport {
        interfaces: None,
        routes: Some("route missing".to_string()),
        dhcp: None,
        uplink_dhcp: None,
        dataplane: Some("forwarding disabled".to_string()),
    };

    let details = health_report_details(&health);

    assert_eq!(
        details,
        vec![
            ("routes", "route missing".to_string()),
            ("dataplane", "forwarding disabled".to_string()),
        ]
    );
}

#[test]
fn health_report_details_lists_all_four_subsystems_when_all_unhealthy() {
    let health = RouterHealthReport {
        interfaces: Some("interface lan0 is down".to_string()),
        routes: Some("route missing".to_string()),
        dhcp: Some("dhcp interface lan0 unhealthy".to_string()),
        uplink_dhcp: None,
        dataplane: Some("forwarding disabled".to_string()),
    };

    let details = health_report_details(&health);

    assert_eq!(
        details,
        vec![
            ("interfaces", "interface lan0 is down".to_string()),
            ("routes", "route missing".to_string()),
            ("dhcp", "dhcp interface lan0 unhealthy".to_string()),
            ("dataplane", "forwarding disabled".to_string()),
        ]
    );
}

#[test]
fn health_report_details_is_empty_when_every_subsystem_is_healthy() {
    let health = RouterHealthReport {
        interfaces: None,
        routes: None,
        dhcp: None,
        uplink_dhcp: None,
        dataplane: None,
    };

    assert!(health_report_details(&health).is_empty());
}

#[test]
fn main_router_recovery_summary_stays_compact() {
    let notice = RouterRecoveryNotice {
        recovery_progress: None,
        recovery_code: "TM-REC-207".into(),
        invariant: "router_rollback_failed".into(),
        summary: "rollback failed".into(),
        blocked_operation: "new router transactions".into(),
        operator_action: "retry_rollback".into(),
        operator_guidance: "retry rollback".into(),
        runbook: "docs/recovery.md#tm-rec-207".into(),
        failures: vec!["one".into(), "two".into(), "three".into()],
    };

    let lines = recovery_notice_summary(&notice);
    assert!(lines.len() <= 5);
    assert!(lines.iter().any(|line| line.contains("Failures: 3")));
    assert!(!lines.iter().any(|line| line.contains("failure: one")));
}

#[test]
fn formats_structured_router_recovery_notice() {
    let notice = RouterRecoveryNotice {
        recovery_progress: None,
        recovery_code: "TM-REC-207".into(),
        invariant: "router_rollback_failed".into(),
        summary: "Previous router rollback did not fully restore runtime state.".into(),
        blocked_operation: "new router transactions".into(),
        operator_action: "retry_rollback".into(),
        operator_guidance:
            "repair the reported runtime failure and retry rollback without deleting the journal"
                .into(),
        runbook: "docs/recovery.md#tm-rec-207".into(),
        failures: vec![
            "dhcp restart failed".into(),
            "route restore failed".into(),
            "firewall restore failed".into(),
        ],
    };

    let lines = recovery_notice_text(&notice, Some(2));
    assert!(lines.iter().any(|line| line.contains("TM-REC-207")));
    assert!(lines
        .iter()
        .any(|line| line.contains("router_rollback_failed")));
    assert!(lines
        .iter()
        .any(|line| line.contains("new router transactions")));
    assert!(lines.iter().any(|line| line.contains("retry_rollback")));
    assert!(lines
        .iter()
        .any(|line| line.contains("dhcp restart failed")));
    assert!(lines
        .iter()
        .any(|line| line.contains("route restore failed")));
    assert!(!lines
        .iter()
        .any(|line| line.contains("firewall restore failed")));
    assert!(lines
        .iter()
        .any(|line| line.contains("... 1 more failure(s)")));
    assert!(lines
        .iter()
        .any(|line| line.contains("docs/recovery.md#tm-rec-207")));
}

#[test]
fn formats_coordinator_status_for_each_variant() {
    assert_eq!(format_coordinator_status(CoordinatorStatus::Idle), "idle");
    assert_eq!(
        format_coordinator_status(CoordinatorStatus::Pending),
        "pending"
    );
    assert_eq!(
        format_coordinator_status(CoordinatorStatus::RollbackFailed),
        "rollback failed (recovery required)"
    );
}
