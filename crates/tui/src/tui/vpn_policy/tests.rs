use super::*;

#[test]
fn toggle_mode_flips_between_the_only_two_modes() {
    assert_eq!(toggle_mode(VpnPolicyMode::Direct), VpnPolicyMode::Vpn);
    assert_eq!(toggle_mode(VpnPolicyMode::Vpn), VpnPolicyMode::Direct);
}

#[test]
fn vpn_policy_field_reaches_every_row_and_clamps_at_both_ends() {
    assert_eq!(
        next_vpn_policy_field(VpnPolicyField::Mode),
        VpnPolicyField::Apply
    );
    assert_eq!(
        next_vpn_policy_field(VpnPolicyField::Apply),
        VpnPolicyField::ClearOverride
    );
    assert_eq!(
        next_vpn_policy_field(VpnPolicyField::ClearOverride),
        VpnPolicyField::Reload
    );
    assert_eq!(
        next_vpn_policy_field(VpnPolicyField::Reload),
        VpnPolicyField::Reload
    );
    assert_eq!(
        previous_vpn_policy_field(VpnPolicyField::Reload),
        VpnPolicyField::ClearOverride
    );
    assert_eq!(
        previous_vpn_policy_field(VpnPolicyField::ClearOverride),
        VpnPolicyField::Apply
    );
    assert_eq!(
        previous_vpn_policy_field(VpnPolicyField::Apply),
        VpnPolicyField::Mode
    );
    assert_eq!(
        previous_vpn_policy_field(VpnPolicyField::Mode),
        VpnPolicyField::Mode
    );
}

#[test]
fn formats_each_mode_distinctly() {
    assert_ne!(
        format_mode(VpnPolicyMode::Direct),
        format_mode(VpnPolicyMode::Vpn)
    );
}

#[test]
fn describes_each_vpn_policy_error_detail_distinctly() {
    let messages = [
        describe_vpn_policy_error(&VpnPolicyErrorDetail::VpnDisabled),
        describe_vpn_policy_error(&VpnPolicyErrorDetail::NoProtectedSubnets),
        describe_vpn_policy_error(&VpnPolicyErrorDetail::TunnelUnhealthy {
            message: "no active VPN tunnel".to_string(),
        }),
        describe_vpn_policy_error(&VpnPolicyErrorDetail::ReservedNamespaceConflict {
            message: "foreign objects occupy the reserved namespace".to_string(),
        }),
        describe_vpn_policy_error(&VpnPolicyErrorDetail::Other {
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
    assert!(messages[2].contains("no active VPN tunnel"));
    assert!(messages[3].contains("foreign objects occupy the reserved namespace"));
    assert_eq!(messages[4], "boom");
}

fn healthy_status() -> VpnPolicyStatusView {
    VpnPolicyStatusView {
        mode: VpnPolicyMode::Vpn,
        mode_override_active: false,
        tunnel: None,
        tunnel_healthy: true,
        policy_active: true,
        kill_switch_active: true,
        protected_subnets: vec!["192.0.2.0/24".parse().unwrap()],
        physical_uplink: Some("wan0".into()),
    }
}

#[tokio::test]
async fn failed_policy_reads_are_stale_and_recovery_preserves_the_selected_mode() {
    for response in [
        Response::Error {
            message: "long network error ".repeat(100),
        },
        Response::Pong,
        Response::VpnPolicyError {
            detail: VpnPolicyErrorDetail::Other {
                message: "failed".into(),
            },
        },
    ] {
        let status = healthy_status();
        let mock = crate::tui::test_api::mock(vec![
            response,
            Response::VpnPolicyStatus {
                status: status.clone(),
            },
        ])
        .await;
        let mut app = TuiApp::default();
        app.vpn_policy.status = Some(status.clone());
        app.vpn_policy.pending_mode = VpnPolicyMode::Direct;
        refresh_vpn_policy_status(&mut app, &mock.client).await;
        assert_eq!(app.vpn_policy.status, Some(status));
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| render_vpn_policy(frame, frame.area(), &mut app))
            .unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(text.contains("STALE"));
        assert!(text.contains("Reload"));
        assert_eq!(app.ui.buttons.len(), 3);
        assert!(!terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .any(|cell| cell.fg == theme::GOOD));
        refresh_vpn_policy_status(&mut app, &mock.client).await;
        assert!(app.vpn_policy.read_error.is_none());
        assert!(app.vpn_policy.error.is_none());
        assert_eq!(app.vpn_policy.pending_mode, VpnPolicyMode::Direct);
    }
}

#[tokio::test]
async fn failed_first_load_and_unverified_mutation_never_show_fresh_protection() {
    let offline = ApiClient::new("/must-not-connect.sock");
    let mut app = TuiApp::default();
    load_vpn_policy_data(&mut app, &offline).await;
    assert!(app.vpn_policy.read_error.is_some());
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| render_vpn_policy(frame, frame.area(), &mut app))
        .unwrap();
    let text: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(text.contains("unavailable"));
    assert!(!text.contains("Loading..."));
    assert!(text.contains("Reload"));
    assert_eq!(app.ui.buttons.last().unwrap().1, 2);
    let recovered = crate::tui::test_api::mock(vec![Response::VpnPolicyStatus {
        status: healthy_status(),
    }])
    .await;
    for key in [KeyCode::Up, KeyCode::Down, KeyCode::Left] {
        handle_vpn_policy_key(&mut app, key, &recovered.client).await;
        assert_eq!(app.vpn_policy.field, VpnPolicyField::Reload);
        assert!(recovered.calls.lock().unwrap().is_empty());
    }
    handle_vpn_policy_key(&mut app, KeyCode::Enter, &recovered.client).await;
    assert_eq!(
        recovered.calls.lock().unwrap()[0].body["type"],
        "vpn_policy_status"
    );
    assert!(app.vpn_policy.read_error.is_none());
    assert!(app.vpn_policy.status.is_some());
    app.vpn_policy.status = Some(healthy_status());
    app.vpn_policy.read_error = None;
    vpn_policy_set_mode(&mut app, &offline).await;
    assert!(app
        .vpn_policy
        .read_error
        .as_ref()
        .unwrap()
        .contains("Unverified policy outcome"));
}

#[tokio::test]
async fn standalone_policy_is_a_route_screen_and_rejects_saved_chain_usage() {
    let mock = super::super::test_api::mock(vec![Response::RouterConfig {
        config: traffic_masq_protocol::RouterConfigView {
            vpn_chain: vec![traffic_masq_protocol::VpnHopConfigView {
                profile_name: "home.conf".into(),
            }],
            ..Default::default()
        },
    }])
    .await;
    let mut app = TuiApp {
        screen: Screen::Router,
        ..Default::default()
    };
    open(&mut app, &mock.client).await;
    assert_eq!(app.screen, Screen::Router);
    assert_eq!(mock.calls.lock().unwrap().len(), 1);
    app.screen = Screen::VpnPolicy;
    handle_vpn_policy_key(&mut app, KeyCode::Esc, &mock.client).await;
    assert_eq!(app.screen, Screen::Router);
}
