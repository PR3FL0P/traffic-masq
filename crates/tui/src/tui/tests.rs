use super::*;

async fn read_http_request(stream: &mut tokio::net::UnixStream) -> Vec<u8> {
    use tokio::io::AsyncReadExt;
    let mut request = Vec::new();
    let mut bytes = [0; 1024];
    loop {
        if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&request[..end]).unwrap();
            let length: usize = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .unwrap();
            if request.len() >= end + 4 + length {
                return request;
            }
        }
        let count = stream.read(&mut bytes).await.unwrap();
        assert!(count > 0);
        request.extend_from_slice(&bytes[..count]);
    }
}

#[tokio::test]
async fn rollback_click_sends_rollback_request() {
    use tokio::io::AsyncWriteExt;
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("api.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_http_request(&mut stream).await;
        stream.write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
        String::from_utf8(request).unwrap()
    });
    let mut app = TuiApp {
        confirmation: crate::tui::state::ConfirmationState {
            pending: Some(PendingNetworkChange {
                recovery_progress: None,
                phase: Default::default(),
                last_error: None,
                token: "test-token".into(),
                interface: "eth0".into(),
                rollback_timeout_seconds: 30,
                expires_at_unix: current_unix_time() + 30,
            }),
            ..Default::default()
        },
        screen: Screen::PendingChange,
        ..Default::default()
    };
    let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| render(frame, &mut app, false))
        .unwrap();
    let (rect, _) = *app.ui.buttons.iter().find(|(_, slot)| *slot == 1).unwrap();
    assert!(
        rect.y < 20,
        "rollback must fit inside the content panel at 80x24"
    );
    handle_mouse(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: rect.x,
            row: rect.y,
            modifiers: crossterm::event::KeyModifiers::NONE,
        },
        &ApiClient::new(socket),
        false,
    )
    .await;
    let request = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    assert!(request.starts_with("POST /api/v1/control "));
    assert!(request.contains(r#""type":"rollback_network_change""#));
}

#[tokio::test]
async fn wifi_click_opens_actions_for_clicked_interface() {
    let mut app = TuiApp {
        screen: Screen::Wifi,
        ..Default::default()
    };
    app.wifi.rows = vec![
        wifi::WifiRow {
            execution_available: true,
            presence: traffic_masq_protocol::InterfacePresence::Present,
            configured: None,
            revision: None,
            interface: "wlan0".into(),
            role: wifi::WifiRole::AccessPoint,
            ap: None,
            client: None,
        },
        wifi::WifiRow {
            execution_available: true,
            presence: traffic_masq_protocol::InterfacePresence::Present,
            configured: None,
            revision: None,
            interface: "wlan1".into(),
            role: wifi::WifiRole::Client,
            ap: None,
            client: None,
        },
    ];
    let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| render(frame, &mut app, false))
        .unwrap();
    assert!(!app.wifi.actions_open);
    let area = app.ui.list_area.unwrap();
    let client = ApiClient::new("/nonexistent.sock");
    handle_mouse(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: area.x,
            row: area.y + 1,
            modifiers: crossterm::event::KeyModifiers::NONE,
        },
        &client,
        false,
    )
    .await;
    assert!(app.wifi.actions_open);
    assert_eq!(app.wifi.selected_radio, 1);
    terminal
        .draw(|frame| render(frame, &mut app, false))
        .unwrap();
    let text: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(text.contains("Scan networks"));
    assert!(!text.contains("Configure access point"));
}

#[test]
fn switching_views_clears_physical_artifacts_once() {
    use ratatui::backend::Backend;
    let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
    let mut app = TuiApp::default();
    draw_app(&mut terminal, &mut app, false).unwrap();
    // Simulate terminal content unknown to ratatui's previous-frame buffer.
    let mut artifact = ratatui::buffer::Cell::default();
    artifact.set_symbol("X");
    terminal
        .backend_mut()
        .draw([(40, 10, &artifact)].into_iter())
        .unwrap();
    draw_app(&mut terminal, &mut app, false).unwrap();
    assert_eq!(terminal.backend().buffer()[(40, 10)].symbol(), "X");
    app.screen = Screen::Settings;
    draw_app(&mut terminal, &mut app, false).unwrap();
    let mut clean = Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
    clean.draw(|frame| render(frame, &mut app, false)).unwrap();
    assert_eq!(terminal.backend().buffer(), clean.backend().buffer());
    terminal
        .backend_mut()
        .draw([(40, 10, &artifact)].into_iter())
        .unwrap();
    app.message_open = true;
    draw_app(&mut terminal, &mut app, false).unwrap();
    assert_ne!(terminal.backend().buffer()[(40, 10)].symbol(), "X");
}

#[tokio::test]
async fn tab_focus_and_modified_keys_are_consistent() {
    let client = ApiClient::new("/nonexistent.sock");
    let mut app = TuiApp::default();
    app.ui.input_enabled = true;
    handle_key(&mut app, KeyCode::Tab, &client, false).await;
    assert_eq!(
        app.dashboard_ui.dashboard_pane,
        dashboard::DashboardPane::Statistics
    );
    handle_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Tab, KeyModifiers::SHIFT),
        &client,
        false,
    )
    .await;
    assert_eq!(
        app.dashboard_ui.dashboard_pane,
        dashboard::DashboardPane::Traffic
    );
    app.screen = Screen::Vpn;
    handle_key(&mut app, KeyCode::Tab, &client, false).await;
    assert_eq!(app.vpn.focus, vpn::VpnFocus::Connect);
    handle_key(&mut app, KeyCode::Right, &client, false).await;
    assert_eq!(app.screen, Screen::Vpn);
    assert_eq!(app.vpn.focus, vpn::VpnFocus::Details);
    handle_key(&mut app, KeyCode::Left, &client, false).await;
    handle_key(&mut app, KeyCode::BackTab, &client, false).await;
    assert_eq!(app.vpn.focus, vpn::VpnFocus::List);
    app.screen = Screen::Log;
    handle_key(&mut app, KeyCode::Tab, &client, false).await;
    assert_eq!(app.log_view.logs_focus, logs::LogFocus::Export);
    handle_key(&mut app, KeyCode::BackTab, &client, false).await;
    assert_eq!(app.log_view.logs_focus, logs::LogFocus::Scroll);

    app.screen = Screen::VpnImport;
    app.vpn_import = Some(VpnImportEditor {
        field: vpn::VpnImportField::Name,
        name: String::new(),
        path: String::new(),
        cursor: 0,
        sources: None,
        selected_source: 0,
    });
    handle_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL),
        &client,
        false,
    )
    .await;
    assert!(app.vpn_import.as_ref().unwrap().name.is_empty());
    handle_key(&mut app, KeyCode::Tab, &client, false).await;
    assert_eq!(
        app.vpn_import.as_ref().unwrap().field,
        vpn::VpnImportField::Path
    );
    handle_key(&mut app, KeyCode::BackTab, &client, false).await;
    assert_eq!(
        app.vpn_import.as_ref().unwrap().field,
        vpn::VpnImportField::Name
    );
    handle_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Char('n'), KeyModifiers::CONTROL),
        &client,
        false,
    )
    .await;
    assert_eq!(app.screen, Screen::VpnImport);
    handle_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
        &client,
        false,
    )
    .await;
    assert!(app.should_quit);
}

#[test]
fn footer_message_is_visible_at_supported_sizes() {
    for (width, height) in [(80, 24), (100, 30)] {
        let mut terminal =
            Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        let mut app = TuiApp::default();
        app.push_message(LogLevel::Error, "Validation failed");
        terminal
            .draw(|frame| render(frame, &mut app, false))
            .unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(text.contains("Validation failed"));
    }
}

#[test]
fn refreshing_preserves_footer_notification_and_does_not_flash_for_fast_reads() {
    for (width, height) in [(80, 24), (100, 30)] {
        let mut terminal =
            Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        let mut app = TuiApp::default();
        app.push_message(LogLevel::Info, "Settings saved");
        let snapshot = terminal
            .draw(|frame| render(frame, &mut app, false))
            .unwrap()
            .buffer
            .clone();

        terminal
            .draw(|frame| {
                render_operation_snapshot(frame, &snapshot, None, Duration::from_millis(100), true)
            })
            .unwrap();
        assert_eq!(terminal.backend().buffer(), &snapshot);

        for cancellable in [true, false] {
            terminal
                .draw(|frame| {
                    render_operation_snapshot(
                        frame,
                        &snapshot,
                        None,
                        Duration::from_secs(2),
                        cancellable,
                    )
                })
                .unwrap();
            let buffer = terminal.backend().buffer();
            let progress: String = (1..width - 1)
                .map(|x| buffer[(x, height - 3)].symbol())
                .collect();
            assert!(progress.contains(if cancellable {
                "Refreshing"
            } else {
                "Applying changes"
            }));
            for y in [height - 2, height - 1] {
                for x in 0..width {
                    assert_eq!(
                        buffer[(x, y)],
                        snapshot[(x, y)],
                        "notification and border must stay intact"
                    );
                }
            }
        }
    }
}

#[test]
fn operation_snapshot_redraws_safely_after_terminal_resize() {
    let mut old_terminal = Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
    let mut app = TuiApp::default();
    let snapshot = old_terminal
        .draw(|frame| render(frame, &mut app, false))
        .unwrap()
        .buffer
        .clone();

    let mut resized = Terminal::new(ratatui::backend::TestBackend::new(100, 30)).unwrap();
    resized
        .draw(|frame| {
            render_operation_snapshot(frame, &snapshot, None, Duration::from_secs(2), false)
        })
        .unwrap();
    let rendered = resized
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(rendered.contains("Applying changes"));
    assert!(!rendered.contains("traffic-masq"));
}

#[tokio::test]
async fn mouse_content_actions_are_ignored_outside_the_content_viewport() {
    let client = ApiClient::new("/socket-that-must-not-be-opened");
    let mut app = TuiApp {
        screen: Screen::Log,
        ..Default::default()
    };
    app.log_view.logs.push_back(logs::LogEntry {
        at_unix: 0,
        level: LogLevel::Info,
        message: "keep".into(),
    });
    app.log_view.logs_focus = logs::LogFocus::Clear;
    app.ui.input_enabled = true;
    app.ui.content_area = Some(ratatui::layout::Rect::new(0, 3, 80, 17));
    app.ui
        .buttons
        .push((ratatui::layout::Rect::new(1, 22, 10, 1), 1));

    handle_mouse(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 2,
            row: 22,
            modifiers: KeyModifiers::NONE,
        },
        &client,
        false,
    )
    .await;
    assert_eq!(app.log_view.logs.len(), 1);
}

#[tokio::test]
async fn resize_clears_hit_regions_and_blocks_hidden_actions() {
    let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(40, 10)).unwrap();
    let mut app = TuiApp {
        screen: Screen::Preview,
        ..Default::default()
    };
    app.ui
        .buttons
        .push((ratatui::layout::Rect::new(0, 0, 10, 2), 0));
    terminal
        .draw(|frame| render(frame, &mut app, false))
        .unwrap();
    assert!(app.ui.buttons.is_empty());
    assert!(app.ui.list_area.is_none());
    handle_key(
        &mut app,
        KeyCode::Enter,
        &ApiClient::new("/nonexistent.sock"),
        false,
    )
    .await;
    assert_eq!(app.screen, Screen::Preview);
    assert!(!app.ui.input_enabled);
}

#[test]
fn disconnected_dashboard_does_not_claim_rollback() {
    let mut app = TuiApp {
        confirmation: crate::tui::state::ConfirmationState {
            pending: Some(PendingNetworkChange {
                recovery_progress: None,
                phase: Default::default(),
                last_error: None,
                token: "keep".into(),
                interface: "eth0".into(),
                rollback_timeout_seconds: 60,
                expires_at_unix: 0,
            }),
            ..Default::default()
        },
        screen: Screen::PendingChange,
        ..Default::default()
    };
    app.dashboard.error = Some("connection lost".into());
    refresh_pending_screen(&mut app);
    assert_eq!(app.confirmation.pending.as_ref().unwrap().token, "keep");
    assert!(app.message.is_none());
    app.dashboard.error = None;
    app.dashboard.pending_known = true;
    refresh_pending_screen(&mut app);
    assert!(app.message.as_ref().unwrap().contains("outcome unknown"));
}

#[tokio::test]
async fn tabs_do_not_discard_editor_and_navigation_preserves_message() {
    let mut app = TuiApp {
        screen: Screen::WifiEditor,
        ..Default::default()
    };
    navigate_to_section(
        &mut app,
        Section::Dashboard,
        &ApiClient::new("/nonexistent.sock"),
        false,
    )
    .await;
    assert_eq!(app.screen, Screen::WifiEditor);
    app.ui.input_enabled = true;
    let message = app.message.clone();
    handle_key(
        &mut app,
        KeyCode::Up,
        &ApiClient::new("/nonexistent.sock"),
        false,
    )
    .await;
    assert_eq!(app.message, message);
}

#[test]
fn adjacent_section_cycles_forward_and_backward_through_all_nine() {
    assert_eq!(
        adjacent_section(Section::Dashboard, true, true, false),
        Section::Interfaces
    );
    assert_eq!(
        adjacent_section(Section::Vpn, true, true, false),
        Section::Wifi
    );
    assert_eq!(
        adjacent_section(Section::Wifi, true, true, false),
        Section::Settings
    );
    assert_eq!(
        adjacent_section(Section::Settings, true, true, false),
        Section::Log
    );
    assert_eq!(
        adjacent_section(Section::Log, true, true, false),
        Section::Dashboard
    );
    assert_eq!(
        adjacent_section(Section::Dashboard, false, true, false),
        Section::Log
    );
    assert_eq!(
        adjacent_section(Section::Interfaces, false, true, false),
        Section::Dashboard
    );
    assert_eq!(
        adjacent_section(Section::Interfaces, true, true, false),
        Section::Dhcp
    );
    assert_eq!(
        adjacent_section(Section::Dhcp, true, true, false),
        Section::DhcpClient
    );
    assert_eq!(
        adjacent_section(Section::DhcpClient, true, true, false),
        Section::Router
    );
}

#[test]
fn adjacent_section_cycles_without_dhcp_client_by_default() {
    assert_eq!(
        adjacent_section(Section::Dhcp, true, false, false),
        Section::Router
    );
    assert_eq!(
        adjacent_section(Section::Router, false, false, false),
        Section::Dhcp
    );
}

#[test]
fn direct_mode_section_navigation_skips_daemon_only_tabs() {
    assert_eq!(
        adjacent_section(Section::Interfaces, true, true, true),
        Section::Log
    );
    assert_eq!(
        adjacent_section(Section::Log, true, true, true),
        Section::Dashboard
    );
    assert_eq!(
        adjacent_section(Section::Dashboard, false, true, true),
        Section::Log
    );
}

#[test]
fn operation_exit_accepts_plain_q_but_normal_quit_stays_ctrl_c() {
    assert!(is_operation_exit_key(KeyEvent::new(
        KeyCode::Char('q'),
        KeyModifiers::NONE,
    )));
    assert!(is_operation_exit_key(KeyEvent::new(
        KeyCode::Char('Q'),
        KeyModifiers::SHIFT,
    )));
    assert!(!is_quit_key(KeyEvent::new(
        KeyCode::Char('q'),
        KeyModifiers::NONE,
    )));
}

#[tokio::test]
async fn navigating_to_disabled_dhcp_client_warns_and_aborts() {
    let mut app = TuiApp::default();
    assert!(!app.show_dhcp_client);
    navigate_to_section(
        &mut app,
        Section::DhcpClient,
        &ApiClient::new("/socket-that-must-not-be-opened"),
        false,
    )
    .await;
    assert_eq!(app.screen, Screen::Dashboard);
    assert!(app
        .message
        .as_ref()
        .unwrap()
        .contains("DHCP Client tab is disabled in Settings"));
}

#[test]
fn section_of_maps_sub_screens_to_their_parent_tab() {
    assert_eq!(section_of(Screen::Dashboard), Section::Dashboard);
    assert_eq!(section_of(Screen::PendingChange), Section::Dashboard);
    assert_eq!(section_of(Screen::InterfaceList), Section::Interfaces);
    assert_eq!(section_of(Screen::InterfaceEditor), Section::Interfaces);
    assert_eq!(section_of(Screen::Preview), Section::Interfaces);
    assert_eq!(section_of(Screen::DhcpInterfaceList), Section::Dhcp);
    assert_eq!(section_of(Screen::DhcpEditor), Section::Dhcp);
    assert_eq!(section_of(Screen::DhcpLeases), Section::Dhcp);
    assert_eq!(section_of(Screen::DhcpClient), Section::DhcpClient);
    assert_eq!(section_of(Screen::Router), Section::Router);
    assert_eq!(section_of(Screen::RouteEditor), Section::Router);
    assert_eq!(section_of(Screen::Forwarding), Section::Router);
    assert_eq!(section_of(Screen::RouterPlan), Section::Router);
    assert_eq!(section_of(Screen::RouterPending), Section::Router);
    assert_eq!(section_of(Screen::Vpn), Section::Vpn);
    assert_eq!(section_of(Screen::VpnImport), Section::Vpn);
    assert_eq!(section_of(Screen::VpnPolicy), Section::Router);
    assert_eq!(section_of(Screen::Settings), Section::Settings);
    assert_eq!(section_of(Screen::SettingsPassword), Section::Settings);
    assert_eq!(section_of(Screen::Access), Section::Settings);
    assert_eq!(section_of(Screen::DnsDefaults), Section::Settings);
    assert_eq!(section_of(Screen::Log), Section::Log);
}

#[test]
fn pending_change_uses_its_origin_section() {
    let mut app = TuiApp {
        confirmation: crate::tui::state::ConfirmationState {
            pending_return_screen: Screen::InterfaceList,
            ..Default::default()
        },
        screen: Screen::PendingChange,
        ..Default::default()
    };
    assert_eq!(section_of_app(&app), Section::Interfaces);

    app.confirmation.pending_return_screen = Screen::Wifi;
    assert_eq!(section_of_app(&app), Section::Wifi);

    app.confirmation.pending_return_screen = Screen::Dashboard;
    assert_eq!(section_of_app(&app), Section::Dashboard);
}

#[tokio::test]
async fn settings_tab_switching_and_editing_arrow_isolation() {
    let mut app = TuiApp {
        settings_ui: crate::tui::state::SettingsUiState {
            settings: Some(SecurityEditor {
                field: settings::SettingsField::RollbackTimeout,
                active: traffic_masq_protocol::SecuritySettings {
                    rollback_timeout_seconds: 60,
                },
                rollback_timeout_input: "60".into(),
                override_active: false,
                restart_required: false,
                remember_session: false,
                remember_minutes_input: "5".into(),
                show_dhcp_client: false,
                randomize_mac_default: true,
                confirmation: None,
                cursor: 2,
                editing: false,
            }),
            ..Default::default()
        },
        screen: Screen::Settings,
        ui: layout::UiLayout {
            input_enabled: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let client = ApiClient::new("/nonexistent.sock");

    // When not editing, Right navigates to Log section
    handle_key(&mut app, KeyCode::Right, &client, false).await;
    assert_eq!(app.screen, Screen::Log);

    // When on Log, Left navigates back to Settings section
    handle_key(&mut app, KeyCode::Left, &client, false).await;
    assert_eq!(app.screen, Screen::Settings);

    // When not editing, Left navigates to Wifi section
    handle_key(&mut app, KeyCode::Left, &client, false).await;
    assert_eq!(app.screen, Screen::Wifi);

    // Navigate back to Settings
    handle_key(&mut app, KeyCode::Right, &client, false).await;
    assert_eq!(app.screen, Screen::Settings);

    // Typing activates editing mode on RollbackTimeout.
    handle_key(&mut app, KeyCode::Char('0'), &client, false).await;
    assert!(app.settings_ui.settings.as_ref().unwrap().is_editing());

    // When editing, Left moves the cursor and does NOT switch sections
    handle_key(&mut app, KeyCode::Left, &client, false).await;
    assert_eq!(app.screen, Screen::Settings);
    assert_eq!(app.settings_ui.settings.as_ref().unwrap().cursor, 2);

    // When editing, Right moves the cursor and does NOT switch sections
    handle_key(&mut app, KeyCode::Right, &client, false).await;
    assert_eq!(app.screen, Screen::Settings);
    assert_eq!(app.settings_ui.settings.as_ref().unwrap().cursor, 3);

    // Enter finishes editing mode
    handle_key(&mut app, KeyCode::Enter, &client, false).await;
    assert!(!app.settings_ui.settings.as_ref().unwrap().is_editing());

    // Once editing is finished, Right navigates to Log section again
    handle_key(&mut app, KeyCode::Right, &client, false).await;
    assert_eq!(app.screen, Screen::Log);
}

#[tokio::test]
async fn router_screen_preserves_horizontal_navigation_and_requires_tab_for_actions() {
    let mut app = TuiApp {
        screen: Screen::Router,
        ..Default::default()
    };
    app.ui.input_enabled = true;
    let client = ApiClient::new("/nonexistent.sock");

    // When in Router screen with RouteTable focus, Right navigates to VPN
    handle_key(&mut app, KeyCode::Right, &client, false).await;
    assert_eq!(app.screen, Screen::Vpn);

    // Left navigates back to Router
    handle_key(&mut app, KeyCode::Left, &client, false).await;
    assert_eq!(app.screen, Screen::Router);
    assert_eq!(app.router.focus, router::RouterFocus::RouteTable);

    // Scrolling Down does NOT enter Actions; clamps and stays in RouteTable
    handle_key(&mut app, KeyCode::Down, &client, false).await;
    assert_eq!(app.router.focus, router::RouterFocus::RouteTable);

    // Right continues to navigate to VPN
    handle_key(&mut app, KeyCode::Right, &client, false).await;
    assert_eq!(app.screen, Screen::Vpn);

    // Navigate back to Router
    handle_key(&mut app, KeyCode::Left, &client, false).await;
    assert_eq!(app.screen, Screen::Router);

    // Tab enters Actions
    handle_key(&mut app, KeyCode::Tab, &client, false).await;
    assert_eq!(app.router.focus, router::RouterFocus::Actions);
    assert_eq!(app.router.action, router::RouterAction::AddRoute);

    // In Actions, Right moves to next action and does NOT switch sections
    handle_key(&mut app, KeyCode::Right, &client, false).await;
    assert_eq!(app.screen, Screen::Router);
    assert_eq!(app.router.action, router::RouterAction::EditRoute);

    // Tab exits Actions back to RouteTable
    handle_key(&mut app, KeyCode::Tab, &client, false).await;
    assert_eq!(app.router.focus, router::RouterFocus::RouteTable);

    // Now Right navigates to VPN again
    handle_key(&mut app, KeyCode::Right, &client, false).await;
    assert_eq!(app.screen, Screen::Vpn);
}

#[test]
fn format_message_lines_highlights_shift_copy_hint_in_red() {
    let text =
        "Delete route manually:\nsudo ip route del ...\n\nTo copy, hold down Shift\n\nEsc: close";
    let lines = format_message_lines(text);
    assert_eq!(lines.len(), 6);
    assert_eq!(lines[0].spans[0].style, Style::default());
    assert_eq!(lines[2].spans[0].style, Style::default());
    let hint_line = &lines[3];
    assert_eq!(hint_line.spans.len(), 1);
    assert_eq!(hint_line.spans[0].content, "To copy, hold down Shift");
    assert_eq!(hint_line.spans[0].style, Style::default().fg(theme::BAD));
}

#[tokio::test]
async fn wheel_scrolls_interface_preview_and_clamps_at_both_ends() {
    let client = ApiClient::new("/socket-that-must-not-be-opened");
    let mut app = TuiApp {
        interface_ui: crate::tui::state::InterfaceUiState {
            preview_max_scroll: 2,
            ..Default::default()
        },
        screen: Screen::Preview,
        ..Default::default()
    };
    app.ui.input_enabled = true;
    for (kind, expected) in [
        (MouseEventKind::ScrollDown, 1),
        (MouseEventKind::ScrollDown, 2),
        (MouseEventKind::ScrollDown, 2),
        (MouseEventKind::ScrollUp, 1),
        (MouseEventKind::ScrollUp, 0),
        (MouseEventKind::ScrollUp, 0),
    ] {
        handle_mouse(
            &mut app,
            MouseEvent {
                kind,
                column: 10,
                row: 10,
                modifiers: KeyModifiers::NONE,
            },
            &client,
            false,
        )
        .await;
        assert_eq!(app.interface_ui.preview_scroll, expected);
        assert_eq!(app.screen, Screen::Preview);
    }
}

#[tokio::test]
async fn wheel_cannot_focus_or_execute_log_actions() {
    let client = ApiClient::new("/socket-that-must-not-be-opened");
    let mut app = TuiApp {
        log_view: crate::tui::state::LogViewState {
            logs_focus: logs::LogFocus::Clear,
            logs_max_scroll: 1,
            ..Default::default()
        },
        screen: Screen::Log,
        ..Default::default()
    };
    app.ui.input_enabled = true;
    app.push_message(LogLevel::Info, "keep this entry");
    let count = app.log_view.logs.len();
    for kind in [
        MouseEventKind::ScrollDown,
        MouseEventKind::ScrollDown,
        MouseEventKind::ScrollDown,
        MouseEventKind::ScrollUp,
    ] {
        handle_mouse(
            &mut app,
            MouseEvent {
                kind,
                column: 10,
                row: 10,
                modifiers: KeyModifiers::NONE,
            },
            &client,
            false,
        )
        .await;
        assert_eq!(app.log_view.logs_focus, logs::LogFocus::Scroll);
        handle_key(&mut app, KeyCode::Enter, &client, false).await;
        assert_eq!(app.log_view.logs.len(), count);
    }
    assert_eq!(app.log_view.logs_scroll, 0);
}

#[tokio::test]
async fn wheel_returns_focus_to_lists_even_when_empty_or_at_the_boundary() {
    let client = ApiClient::new("/socket-that-must-not-be-opened");
    for screen in [Screen::Dashboard, Screen::Vpn, Screen::Router] {
        for kind in [MouseEventKind::ScrollUp, MouseEventKind::ScrollDown] {
            let mut app = TuiApp {
                screen,
                ..Default::default()
            };
            app.ui.input_enabled = true;
            app.dashboard_ui.dashboard_pane = dashboard::DashboardPane::Statistics;
            app.vpn.focus = vpn::VpnFocus::Delete;
            app.router.focus = RouterFocus::Actions;
            app.router.action = router::RouterAction::DeleteRoute;
            app.router.sharing_actions_focused = true;
            handle_mouse(
                &mut app,
                MouseEvent {
                    kind,
                    column: 10,
                    row: 10,
                    modifiers: KeyModifiers::NONE,
                },
                &client,
                false,
            )
            .await;
            match screen {
                Screen::Dashboard => {
                    assert_eq!(
                        app.dashboard_ui.dashboard_pane,
                        dashboard::DashboardPane::Statistics
                    )
                }
                Screen::Vpn => assert_eq!(app.vpn.focus, vpn::VpnFocus::List),
                Screen::Router => {
                    assert_eq!(app.router.focus, RouterFocus::RouteTable);
                    assert!(!app.router.sharing_actions_focused);
                    assert_eq!(app.router.action, router::RouterAction::DeleteRoute);
                }
                _ => unreachable!(),
            }
            assert_eq!(app.screen, screen);
        }
    }
}

#[tokio::test]
async fn mouse_scrolls_message_when_open_and_ignores_navigation() {
    let mut app = TuiApp {
        screen: Screen::Dashboard,
        message_open: true,
        message_scroll: 5,
        ..Default::default()
    };
    app.ui.input_enabled = true;
    let client = ApiClient::new("/nonexistent.sock");

    handle_mouse(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::ScrollUp,
            column: 10,
            row: 10,
            modifiers: crossterm::event::KeyModifiers::NONE,
        },
        &client,
        false,
    )
    .await;
    assert_eq!(app.message_scroll, 4);

    handle_mouse(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 10,
            row: 10,
            modifiers: crossterm::event::KeyModifiers::NONE,
        },
        &client,
        false,
    )
    .await;
    assert_eq!(app.message_scroll, 5);

    handle_mouse(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 0,
            row: 0,
            modifiers: crossterm::event::KeyModifiers::NONE,
        },
        &client,
        false,
    )
    .await;
    assert_eq!(app.screen, Screen::Dashboard);
    assert!(app.message_open);
}

#[tokio::test]
async fn small_terminal_escape_sends_rollback_request() {
    use tokio::io::AsyncWriteExt;
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("api.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_http_request(&mut stream).await;
        stream.write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
        String::from_utf8(request).unwrap()
    });
    let mut app = TuiApp {
        confirmation: crate::tui::state::ConfirmationState {
            pending: Some(PendingNetworkChange {
                recovery_progress: None,
                phase: Default::default(),
                last_error: None,
                token: "test-token".into(),
                interface: "eth0".into(),
                rollback_timeout_seconds: 30,
                expires_at_unix: current_unix_time() + 30,
            }),
            ..Default::default()
        },
        screen: Screen::PendingChange,
        ..Default::default()
    };
    let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(40, 10)).unwrap();
    terminal
        .draw(|frame| render(frame, &mut app, false))
        .unwrap();
    let text: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(text.contains("Esc: rollback"));
    assert!(text.contains("Rollback in"));
    handle_key(&mut app, KeyCode::Esc, &ApiClient::new(socket), false).await;
    let request = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    assert!(request.starts_with("POST /api/v1/control "));
    assert!(request.contains(r#""type":"rollback_network_change""#));
}

#[tokio::test]
async fn help_is_modal_and_does_not_activate_underlying_screen() {
    let mut app = TuiApp::default();
    let client = ApiClient::new("/nonexistent.sock");
    let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
    terminal.draw(|f| render(f, &mut app, false)).unwrap();
    handle_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL),
        &client,
        false,
    )
    .await;
    terminal.draw(|f| render(f, &mut app, false)).unwrap();
    assert!(app.help_open);
    handle_key(&mut app, KeyCode::Enter, &client, false).await;
    assert_eq!(app.screen, Screen::Dashboard);
    assert!(app.ui.buttons.is_empty());
    handle_key(&mut app, KeyCode::Esc, &client, false).await;
    assert!(!app.help_open);
    assert!(!app.should_quit);
}

#[tokio::test]
async fn small_terminal_enter_sends_commit_request() {
    use tokio::io::AsyncWriteExt;
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("api.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_http_request(&mut stream).await;
        stream.write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
        String::from_utf8(request).unwrap()
    });
    let mut app = TuiApp {
        confirmation: crate::tui::state::ConfirmationState {
            pending: Some(PendingNetworkChange {
                recovery_progress: None,
                phase: Default::default(),
                last_error: None,
                token: "test-token".into(),
                interface: "eth0".into(),
                rollback_timeout_seconds: 30,
                expires_at_unix: current_unix_time() + 30,
            }),
            ..Default::default()
        },
        screen: Screen::PendingChange,
        ..Default::default()
    };
    let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(40, 10)).unwrap();
    terminal
        .draw(|frame| render(frame, &mut app, false))
        .unwrap();
    let text: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(text.contains("Esc: rollback"));
    assert!(text.contains("Rollback in"));
    handle_key(&mut app, KeyCode::Enter, &ApiClient::new(socket), false).await;
    let request = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    assert!(request.starts_with("POST /api/v1/control "));
    assert!(request.contains(r#""type":"commit_network_change""#));
}

#[test]
fn pending_refresh_exposes_recovery_and_removes_confirmation_controls() {
    use traffic_masq_protocol::NetworkChangePhase;
    let initial = PendingNetworkChange {
        recovery_progress: None,
        token: "recovering".into(),
        interface: "eth0".into(),
        rollback_timeout_seconds: 60,
        expires_at_unix: current_unix_time() + 60,
        phase: NetworkChangePhase::AwaitingCommit,
        last_error: None,
    };
    for phase in [
        NetworkChangePhase::RollbackRequired,
        NetworkChangePhase::CommitIndeterminate,
    ] {
        let mut current = initial.clone();
        current.phase = phase;
        current.last_error = Some("storage unavailable".into());
        let mut app = TuiApp {
            confirmation: crate::tui::state::ConfirmationState {
                pending: Some(initial.clone()),
                ..Default::default()
            },
            screen: Screen::PendingChange,
            ..Default::default()
        };
        app.dashboard.pending_network_changes.push(current.clone());
        app.dashboard.pending_known = true;
        refresh_pending_screen(&mut app);
        assert_eq!(app.confirmation.pending, Some(current));
        assert_eq!(pending_deadline(&app), None);
        assert!(!layout::help_pairs(&app)
            .iter()
            .any(|(_, action)| *action == "commit"));
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(100, 24)).unwrap();
        terminal
            .draw(|frame| render(frame, &mut app, false))
            .unwrap();
        assert!(!app.ui.buttons.iter().any(|(_, slot)| *slot == 0));
        let text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(text.contains("storage unavailable"));
        assert!(!text.contains("[Commit]"));
    }
}

#[tokio::test]
async fn control_shortcuts_preserve_text_and_modal_focus() {
    let client = ApiClient::new("/nonexistent.sock");
    let mut app = TuiApp {
        screen: Screen::VpnImport,
        vpn_import: Some(VpnImportEditor {
            field: vpn::VpnImportField::Name,
            name: "draft".into(),
            path: String::new(),
            cursor: 5,
            sources: None,
            selected_source: 0,
        }),
        ..Default::default()
    };
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| render(frame, &mut app, false))
        .unwrap();
    for key in ['g', 'n', 'p', 'o'] {
        handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char(key), KeyModifiers::CONTROL),
            &client,
            false,
        )
        .await;
    }
    assert!(app.message_open);
    assert_eq!(app.screen, Screen::VpnImport);
    handle_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Char('g'), KeyModifiers::CONTROL),
        &client,
        false,
    )
    .await;
    assert!(!app.message_open);
    handle_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL),
        &client,
        false,
    )
    .await;
    handle_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Char('g'), KeyModifiers::CONTROL),
        &client,
        false,
    )
    .await;
    assert!(app.help_open);
    assert!(!app.message_open);
    handle_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL),
        &client,
        false,
    )
    .await;
    assert!(!app.help_open);
    assert_eq!(app.vpn_import.as_ref().unwrap().name, "draft");

    app.screen = Screen::Dashboard;
    handle_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Char('n'), KeyModifiers::CONTROL),
        &client,
        true,
    )
    .await;
    assert_eq!(app.screen, Screen::InterfaceList);
    handle_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL),
        &client,
        true,
    )
    .await;
    assert_eq!(app.screen, Screen::Dashboard);
}

#[tokio::test]
async fn missing_inventory_mouse_and_keyboard_selection_is_independent_of_live_statistics() {
    use traffic_masq_protocol::{
        InterfaceConfigSource, InterfaceInventoryEntry, InterfacePresence, InterfaceReadiness,
    };
    let row = InterfaceInventoryEntry {
        name: "usb0".into(),
        observed: None,
        configured: None,
        config_source: InterfaceConfigSource::None,
        presence: InterfacePresence::Missing,
        readiness: InterfaceReadiness::Disabled,
        blockers: Vec::new(),
        observation_stale: false,
        suppressed: true,
        references: Vec::new(),
    };
    let mut other = row.clone();
    other.name = "usb1".into();
    let mut app = TuiApp {
        screen: Screen::InterfaceList,
        ..Default::default()
    };
    app.dashboard.inventory = Some(vec![row, other]);
    app.ui.input_enabled = true;
    app.ui.list_area = Some(ratatui::layout::Rect::new(5, 5, 30, 5));
    app.ui.list_count = 2;
    app.ui.list_row_height = 1;
    let client = ApiClient::new("/must-not-open-a-socket");
    let mouse = |kind, row| MouseEvent {
        kind,
        column: 6,
        row,
        modifiers: crossterm::event::KeyModifiers::NONE,
    };
    handle_mouse(
        &mut app,
        mouse(MouseEventKind::Down(MouseButton::Left), 6),
        &client,
        false,
    )
    .await;
    assert_eq!(
        interfaces::selected_interface_name(&app).as_deref(),
        Some("usb1")
    );
    handle_mouse(&mut app, mouse(MouseEventKind::ScrollUp, 6), &client, false).await;
    assert_eq!(
        interfaces::selected_interface_name(&app).as_deref(),
        Some("usb0")
    );
    handle_mouse(
        &mut app,
        mouse(MouseEventKind::ScrollDown, 6),
        &client,
        false,
    )
    .await;
    assert_eq!(
        interfaces::selected_interface_name(&app).as_deref(),
        Some("usb1")
    );
    normalize_selection(&mut app);
    assert_eq!(app.interface_ui.selected_inventory_interface, 1);
    assert_eq!(app.interface_ui.selected_interface, 0);
}

#[tokio::test]
async fn tab_then_enter_sends_rollback_for_both_pending_screens() {
    for router in [false, true] {
        let mock = test_api::mock(vec![Response::Error {
            message: "test rejection; retain pending state".into(),
        }])
        .await;
        let mut app = TuiApp::default();
        if router {
            app.screen = Screen::RouterPending;
            app.router_ui.router_pending = Some(RouterPendingView {
                token: "demo".into(),
                expires_at_unix: Some(current_unix_time() + 60),
                rollback_failure: None,
                recovery: None,
                scroll: 0,
                max_scroll: 0,
            });
        } else {
            app.screen = Screen::PendingChange;
            app.confirmation.pending = Some(PendingNetworkChange {
                token: "demo".into(),
                interface: "lan0".into(),
                expires_at_unix: current_unix_time() + 60,
                rollback_timeout_seconds: 60,
                phase: Default::default(),
                last_error: None,
                recovery_progress: None,
            });
        }
        app.ui.input_enabled = true;
        handle_key(&mut app, KeyCode::Tab, &mock.client, false).await;
        assert_eq!(app.confirmation.pending_focus, 1);
        assert!(mock.calls.lock().unwrap().is_empty());
        handle_key(&mut app, KeyCode::Enter, &mock.client, false).await;
        let calls = mock.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].body["type"],
            if router {
                "router_rollback"
            } else {
                "rollback_network_change"
            }
        );
        assert!(app.confirmation.pending.is_some() || app.router_ui.router_pending.is_some());
    }
}

#[test]
fn pending_labels_keep_contrast_on_filled_empty_and_recovery_gauges() {
    use ratatui::{backend::TestBackend, style::Color, widgets::Block, Terminal};

    for router in [false, true] {
        for (remaining, recovery) in [(60, false), (5, false), (0, false), (0, true)] {
            if recovery && !router {
                continue; // Interface recovery uses diagnostics instead of a gauge.
            }
            for background in [Color::Black, Color::White] {
                let mut app = TuiApp::default();
                let now = current_unix_time();
                app.router_ui.router_pending = Some(RouterPendingView {
                    token: "contrast".into(),
                    expires_at_unix: Some(now + remaining),
                    rollback_failure: recovery.then(|| vec!["test failure".into()]),
                    recovery: None,
                    scroll: 0,
                    max_scroll: 0,
                });
                app.confirmation.pending = Some(PendingNetworkChange {
                    token: "contrast".into(),
                    interface: "lan0".into(),
                    expires_at_unix: now + remaining,
                    rollback_timeout_seconds: 60,
                    phase: Default::default(),
                    last_error: None,
                    recovery_progress: None,
                });
                let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
                terminal
                    .draw(|frame| {
                        let area = frame.area();
                        frame.render_widget(
                            Block::default().style(Style::default().bg(background)),
                            area,
                        );
                        if router {
                            router::render_router_pending(frame, area, &mut app);
                        } else {
                            interfaces::render_pending(frame, area, &mut app);
                        }
                    })
                    .unwrap();
                let cell = &terminal.backend().buffer()[(40, 2)];
                assert_ne!(cell.symbol(), " ");
                assert_eq!(cell.fg, Color::White);
                assert_eq!(cell.bg, Color::Black);
            }
        }
    }
}
