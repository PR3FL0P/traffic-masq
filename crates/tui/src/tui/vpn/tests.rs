use super::*;

#[test]
fn vpn_catalog_actions_are_compact_and_settings_are_separate() {
    use ratatui::{backend::TestBackend, Terminal};
    let mut app = TuiApp {
        screen: Screen::Vpn,
        ..Default::default()
    };
    app.vpn.enabled = Some(false);
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| super::super::render(frame, &mut app, false))
        .unwrap();
    assert_eq!(app.ui.buttons.len(), 4);
    assert_eq!(actions(Screen::VpnSettings), &[VpnFocus::ToggleEnabled]);
    assert!(!actions(Screen::Vpn).contains(&VpnFocus::Delete));
    assert!(!actions(Screen::Vpn).contains(&VpnFocus::ToggleEnabled));
    assert!(app.ui.list_area.unwrap().height >= 10);
}

#[test]
fn vpn_focus_defaults_to_list() {
    assert_eq!(VpnFocus::default(), VpnFocus::List);
}

#[test]
fn describes_each_vpn_error_detail_distinctly() {
    let messages = [
        describe_vpn_error(&VpnErrorDetail::VpnDisabled),
        describe_vpn_error(&VpnErrorDetail::NotFound {
            name: "home.conf".to_string(),
        }),
        describe_vpn_error(&VpnErrorDetail::InvalidProfile {
            message: "missing [Interface] section".to_string(),
        }),
        describe_vpn_error(&VpnErrorDetail::AlreadyActive),
        describe_vpn_error(&VpnErrorDetail::NotActive),
        describe_vpn_error(&VpnErrorDetail::ProfileInUse {
            name: "home.conf".to_string(),
        }),
        describe_vpn_error(&VpnErrorDetail::ForeignInterfaceConflict),
        describe_vpn_error(&VpnErrorDetail::Other {
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
    assert!(messages[1].contains("home.conf"));
    assert!(messages[2].contains("missing [Interface] section"));
    assert_eq!(messages[7], "boom");
}

#[test]
fn vpn_import_field_toggles_between_the_only_two_fields() {
    assert_eq!(
        toggle_vpn_import_field(VpnImportField::Name),
        VpnImportField::Path
    );
    assert_eq!(
        toggle_vpn_import_field(VpnImportField::Path),
        VpnImportField::Name
    );
}

#[test]
fn vpn_import_editor_active_value_targets_the_selected_field() {
    let mut editor = VpnImportEditor {
        field: VpnImportField::Name,
        name: "home".to_string(),
        path: "/etc/wireguard/home.conf".to_string(),
        cursor: 0,
        sources: None,
        selected_source: 0,
    };
    editor.active_value_mut().push_str(".conf");
    assert_eq!(editor.name, "home.conf");
    assert_eq!(editor.path, "/etc/wireguard/home.conf");

    editor.field = VpnImportField::Path;
    editor.active_value_mut().push('x');
    assert_eq!(editor.path, "/etc/wireguard/home.confx");
    assert_eq!(editor.name, "home.conf");
}

#[test]
fn vpn_import_editor_has_no_contents_field_to_retain_a_secret() {
    let editor = VpnImportEditor {
        field: VpnImportField::Name,
        name: "home.conf".to_string(),
        path: "/etc/wireguard/home.conf".to_string(),
        cursor: 0,
        sources: None,
        selected_source: 0,
    };
    let debug = format!("{editor:?}");
    assert!(debug.contains("name"));
    assert!(debug.contains("path"));
    assert!(!debug.contains("contents"));
    assert!(!debug.contains("PrivateKey"));
}

#[tokio::test]
async fn vpn_import_editor_cursor_navigation_and_editing() {
    let mut app = TuiApp::default();
    let mut editor = VpnImportEditor {
        field: VpnImportField::Name,
        name: "work".to_string(),
        path: "/tmp/vpn.conf".to_string(),
        cursor: 4,
        sources: None,
        selected_source: 0,
    };
    editor.cursor = editor.name.len();
    app.vpn_import = Some(editor);
    app.screen = Screen::VpnImport;
    let client = ApiClient::new("/nonexistent.sock");

    handle_vpn_import_key(&mut app, KeyCode::Left, &client).await;
    assert_eq!(app.vpn_import.as_ref().unwrap().cursor, 3);

    handle_vpn_import_key(&mut app, KeyCode::Char('1'), &client).await;
    assert_eq!(app.vpn_import.as_ref().unwrap().name, "wor1k");
    assert_eq!(app.vpn_import.as_ref().unwrap().cursor, 4);

    handle_vpn_import_key(&mut app, KeyCode::Backspace, &client).await;
    assert_eq!(app.vpn_import.as_ref().unwrap().name, "work");
    assert_eq!(app.vpn_import.as_ref().unwrap().cursor, 3);

    handle_vpn_import_key(&mut app, KeyCode::Down, &client).await;
    assert_eq!(app.vpn_import.as_ref().unwrap().field, VpnImportField::Path);
    assert_eq!(
        app.vpn_import.as_ref().unwrap().cursor,
        "/tmp/vpn.conf".len()
    );
}

#[tokio::test]
async fn vpn_source_browser_selection_is_bounded_and_local_path_remains_available() {
    let mut app = TuiApp {
        screen: Screen::VpnImport,
        vpn_import: Some(VpnImportEditor {
            field: VpnImportField::Name,
            name: String::new(),
            path: String::new(),
            cursor: 0,
            sources: Some((
                "/etc/wireguard".into(),
                vec!["home.conf".into(), "work.conf".into()],
            )),
            selected_source: 0,
        }),
        ..Default::default()
    };
    let client = ApiClient::new("/nonexistent.sock");
    for _ in 0..3 {
        handle_vpn_import_key(&mut app, KeyCode::Down, &client).await;
    }
    assert_eq!(app.vpn_import.as_ref().unwrap().selected_source, 1);
    for _ in 0..3 {
        handle_vpn_import_key(&mut app, KeyCode::Up, &client).await;
    }
    assert_eq!(app.vpn_import.as_ref().unwrap().selected_source, 0);
    handle_vpn_import_key(&mut app, KeyCode::Char('p'), &client).await;
    assert!(app.vpn_import.as_ref().unwrap().sources.is_none());
    handle_vpn_import_key(&mut app, KeyCode::Char('a'), &client).await;
    assert_eq!(app.vpn_import.as_ref().unwrap().name, "a");
}

#[tokio::test]
async fn deletion_requires_confirmation_and_retains_the_original_target() {
    let mock = super::super::test_api::mock(vec![Response::VpnError {
        detail: VpnErrorDetail::Other {
            message: "outcome unknown".into(),
        },
    }])
    .await;
    let mut app = TuiApp {
        screen: Screen::Vpn,
        ..Default::default()
    };
    app.vpn.profiles = ["first.conf", "second.conf"]
        .into_iter()
        .map(|name| VpnProfileSummary {
            name: name.into(),
            size_bytes: 10,
            modified_unix: None,
        })
        .collect();
    app.vpn.profiles_known = true;
    app.vpn.focus = VpnFocus::Delete;
    handle_vpn_key(&mut app, KeyCode::Enter, &mock.client).await;
    assert!(mock.calls.lock().unwrap().is_empty());
    handle_vpn_key(&mut app, KeyCode::Esc, &mock.client).await;
    assert!(app.vpn.delete_confirmation.is_none());
    handle_vpn_key(&mut app, KeyCode::Enter, &mock.client).await;
    // A background list update must not change the target being confirmed.
    app.vpn.profiles.reverse();
    handle_vpn_key(&mut app, KeyCode::Down, &mock.client).await;
    assert_eq!(app.vpn.delete_confirmation.as_deref(), Some("first.conf"));
    handle_vpn_key(&mut app, KeyCode::Enter, &mock.client).await;
    assert!(app.vpn.delete_confirmation.is_none());
    assert_eq!(mock.calls.lock().unwrap()[0].body["name"], "first.conf");
    handle_vpn_key(&mut app, KeyCode::Enter, &mock.client).await;
    assert_eq!(
        mock.calls.lock().unwrap().len(),
        1,
        "an uncertain delete must not retry on Enter"
    );
}

fn profile_app() -> TuiApp {
    let mut app = TuiApp {
        screen: Screen::Vpn,
        ..Default::default()
    };
    app.vpn.enabled = Some(true);
    app.vpn.status_known = true;
    app.vpn.profiles_known = true;
    app.vpn.chain = Some(Vec::new());
    app.vpn.profiles = ["home.conf", "work.conf"]
        .into_iter()
        .map(|name| VpnProfileSummary {
            name: name.into(),
            size_bytes: 100,
            modified_unix: None,
        })
        .collect();
    app
}

fn activated() -> Response {
    Response::VpnActivated {
        active: VpnActiveStatus {
            profile_name: "home.conf".into(),
            interface: "tm-wg0".into(),
            up: true,
        },
    }
}

#[tokio::test]
async fn enter_connects_from_list_without_route_reads_or_changing_the_router_draft() {
    for chain in [
        None,
        Some(vec![traffic_masq_protocol::VpnHopConfigView {
            profile_name: "home.conf".into(),
        }]),
    ] {
        let mock = super::super::test_api::mock(vec![activated(), Response::VpnDeactivated]).await;
        let mut app = profile_app();
        app.vpn.chain = chain;
        app.ui.input_enabled = true;
        app.router.staged = true;
        app.router.proposed_router_config.route_host_traffic = true;
        super::super::handle_key(&mut app, KeyCode::Enter, &mock.client, false).await;
        assert_eq!(app.screen, Screen::Vpn);
        assert!(standalone_selected(&app));
        super::super::handle_key(&mut app, KeyCode::Enter, &mock.client, false).await;
        assert!(app.vpn.active.is_none());
        assert!(app.router.staged);
        assert!(app.router.proposed_router_config.route_host_traffic);
        let calls = mock.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].body["type"], "vpn_activate");
        assert_eq!(calls[0].body["name"], "home.conf");
        assert_eq!(calls[1].body["type"], "vpn_deactivate");
    }
}

#[tokio::test]
async fn connect_enables_disabled_vpn_and_checks_runtime_before_activation() {
    let mock = super::super::test_api::mock(vec![
        Response::VpnConfig { enabled: true },
        Response::VpnStatus { active: None },
        activated(),
    ])
    .await;
    let mut app = profile_app();
    app.vpn.enabled = Some(false);
    app.vpn.status_known = false;
    handle_vpn_key(&mut app, KeyCode::Enter, &mock.client).await;
    assert_eq!(app.screen, Screen::Vpn);
    assert_eq!(app.vpn.enabled, Some(true));
    assert!(standalone_selected(&app));
    let calls = mock.calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].body["type"], "set_vpn_enabled");
    assert_eq!(calls[0].body["enabled"], true);
    assert_eq!(calls[1].body["type"], "vpn_status");
    assert_eq!(calls[2].body["type"], "vpn_activate");
}

#[tokio::test]
async fn settings_can_still_disable_vpn_and_refresh_the_library_without_runtime_or_route_reads() {
    let profiles = profile_app().vpn.profiles;
    let mock = super::super::test_api::mock(vec![
        Response::VpnConfig { enabled: false },
        Response::VpnConfig { enabled: false },
        Response::VpnProfiles { profiles },
    ])
    .await;
    let mut app = profile_app();
    app.screen = Screen::VpnSettings;
    app.vpn.focus = VpnFocus::ToggleEnabled;
    handle_vpn_key(&mut app, KeyCode::Enter, &mock.client).await;
    assert_eq!(app.vpn.enabled, Some(false));
    assert!(app.vpn.profiles_known);
    assert!(!app.vpn.status_known);
    let calls = mock.calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].body["type"], "set_vpn_enabled");
    assert_eq!(calls[0].body["enabled"], false);
    assert_eq!(calls[1].body["type"], "get_vpn_config");
    assert_eq!(calls[2].body["type"], "vpn_list_profiles");
}

#[tokio::test]
async fn an_empty_library_does_not_enable_vpn_on_enter() {
    let mock = super::super::test_api::mock(vec![]).await;
    let mut app = profile_app();
    app.vpn.enabled = Some(false);
    app.vpn.profiles.clear();
    handle_vpn_key(&mut app, KeyCode::Enter, &mock.client).await;
    assert_eq!(app.vpn.enabled, Some(false));
    assert!(mock.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn enable_failure_or_unknown_runtime_never_proceeds_or_retries_connect() {
    for responses in [
        vec![Response::Error {
            message: "enable outcome unknown".into(),
        }],
        vec![
            Response::VpnConfig { enabled: true },
            Response::Error {
                message: "runtime unavailable".into(),
            },
        ],
        vec![
            Response::VpnConfig { enabled: true },
            Response::VpnStatus {
                active: Some(VpnActiveStatus {
                    profile_name: "work.conf".into(),
                    interface: "tm-wg0".into(),
                    up: true,
                }),
            },
        ],
    ] {
        let expected = responses.len();
        let mock = super::super::test_api::mock(responses).await;
        let mut app = profile_app();
        app.vpn.enabled = Some(false);
        app.vpn.status_known = false;
        for _ in 0..2 {
            handle_vpn_key(&mut app, KeyCode::Enter, &mock.client).await;
        }
        assert_eq!(app.screen, Screen::Vpn);
        assert_eq!(mock.calls.lock().unwrap().len(), expected);
        assert!(!standalone_selected(&app));
    }
}

#[tokio::test]
async fn mouse_connect_uses_the_same_action_as_enter_in_the_profile_list() {
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
    use ratatui::{backend::TestBackend, Terminal};
    let mock = super::super::test_api::mock(vec![activated()]).await;
    let mut app = profile_app();
    app.ui.input_enabled = true;
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| super::super::render(frame, &mut app, false))
        .unwrap();
    let (rect, _) = app
        .ui
        .buttons
        .iter()
        .find(|(_, slot)| *slot == 0)
        .copied()
        .unwrap();
    super::super::handle_mouse(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: rect.x,
            row: rect.y,
            modifiers: KeyModifiers::NONE,
        },
        &mock.client,
        false,
    )
    .await;
    assert_eq!(app.screen, Screen::Vpn);
    assert!(standalone_selected(&app));
    assert_eq!(mock.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn details_opens_a_pinned_profile_without_connecting() {
    let mock = super::super::test_api::mock(vec![Response::RouterConfig {
        config: Default::default(),
    }])
    .await;
    let mut app = profile_app();
    app.vpn.focus = VpnFocus::Details;
    handle_vpn_key(&mut app, KeyCode::Enter, &mock.client).await;
    assert_eq!(app.screen, Screen::VpnProfile);
    assert_eq!(selected_name(&app), Some("home.conf"));
    assert_eq!(
        mock.calls.lock().unwrap()[0].body["type"],
        "get_router_config"
    );
    app.vpn.profiles.reverse();
    app.vpn.focus = VpnFocus::Delete;
    handle_vpn_key(&mut app, KeyCode::Enter, &mock.client).await;
    assert_eq!(app.vpn.delete_confirmation.as_deref(), Some("home.conf"));
}

#[tokio::test]
async fn standalone_action_connects_then_disconnects_selected_profile() {
    let mock = super::super::test_api::mock(vec![
        Response::VpnActivated {
            active: VpnActiveStatus {
                profile_name: "home.conf".into(),
                interface: "tm-wg0".into(),
                up: true,
            },
        },
        Response::VpnDeactivated,
    ])
    .await;
    let mut app = profile_app();
    app.vpn.focus = VpnFocus::Connect;
    handle_vpn_key(&mut app, KeyCode::Enter, &mock.client).await;
    assert!(standalone_selected(&app));
    handle_vpn_key(&mut app, KeyCode::Enter, &mock.client).await;
    assert!(app.vpn.active.is_none());
    assert!(app.vpn.status_known);
    let calls = mock.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].body["name"], "home.conf");
    assert_eq!(calls[1].body["type"], "vpn_deactivate");
}

#[tokio::test]
async fn uncertain_activation_requires_refresh_before_another_mutation() {
    let mock = super::super::test_api::mock(vec![Response::Error {
        message: "outcome unknown".into(),
    }])
    .await;
    let mut app = profile_app();
    app.vpn.focus = VpnFocus::Connect;
    handle_vpn_key(&mut app, KeyCode::Enter, &mock.client).await;
    assert!(!app.vpn.status_known);
    handle_vpn_key(&mut app, KeyCode::Enter, &mock.client).await;
    assert_eq!(mock.calls.lock().unwrap().len(), 1);
    assert!(profile_state(&app, "home.conf").contains("status unknown"));
}

#[tokio::test]
async fn cancelling_a_background_refresh_preserves_the_last_observation_at_every_read() {
    use http_body_util::Full;
    use hyper::{body::Bytes, server::conn::http1, service::service_fn};
    use hyper_util::rt::TokioIo;

    for stalled_read in 0..4 {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("vpn.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let client = ApiClient::new(socket);
        let (reached, mut waiting) = tokio::sync::mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            let responses = [
                Response::VpnConfig { enabled: true },
                Response::VpnProfiles { profiles: vec![] },
                Response::VpnStatus { active: None },
                Response::RouterConfig {
                    config: Default::default(),
                },
            ];
            for (index, response) in responses.into_iter().enumerate() {
                let (stream, _) = listener.accept().await.unwrap();
                let reached = reached.clone();
                let response = serde_json::to_vec(&response).unwrap();
                http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |_| {
                            let reached = reached.clone();
                            let response = response.clone();
                            async move {
                                if index == stalled_read {
                                    reached.send(()).unwrap();
                                    std::future::pending::<()>().await;
                                }
                                Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                                    Bytes::from(response),
                                )))
                            }
                        }),
                    )
                    .await
                    .unwrap();
            }
        });
        let mut app = profile_app();
        app.screen = Screen::VpnProfile;
        app.vpn.opened_profile = Some("home.conf".into());
        app.vpn.error = Some(VpnErrorDetail::NotActive);
        {
            let refresh = load_vpn_data(&mut app, &client);
            tokio::pin!(refresh);
            tokio::select! {
                result = waiting.recv() => assert!(result.is_some()),
                _ = &mut refresh => panic!("refresh must wait for the stalled response"),
            }
        }
        server.abort();
        assert_eq!(app.vpn.enabled, Some(true));
        assert!(app.vpn.status_known);
        assert!(app.vpn.profiles_known);
        assert_eq!(app.vpn.profiles.len(), 2);
        assert_eq!(app.vpn.chain, Some(vec![]));
        assert!(app.vpn.error.is_some());
        assert_eq!(selected_name(&app), Some("home.conf"));
        assert!(app.logs.is_empty());
    }
}

#[tokio::test]
async fn selecting_another_profile_never_disconnects_the_active_one() {
    let mock = super::super::test_api::mock(vec![]).await;
    let mut app = profile_app();
    app.vpn.active = Some(VpnActiveStatus {
        profile_name: "work.conf".into(),
        interface: "tm-wg0".into(),
        up: true,
    });
    app.vpn.focus = VpnFocus::Connect;
    handle_vpn_key(&mut app, KeyCode::Enter, &mock.client).await;
    assert_eq!(app.vpn.active.as_ref().unwrap().profile_name, "work.conf");
    assert!(mock.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn disabled_vpn_keeps_the_profile_library_and_never_reads_runtime_status() {
    let mut profiles = profile_app().vpn.profiles;
    profiles.reverse();
    let mock = super::super::test_api::mock(vec![
        Response::VpnConfig { enabled: false },
        Response::VpnProfiles { profiles },
    ])
    .await;
    let mut app = profile_app();
    load_vpn_data(&mut app, &mock.client).await;
    assert_eq!(app.vpn.enabled, Some(false));
    assert!(app.vpn.profiles_known);
    assert_eq!(selected_name(&app), Some("home.conf"));
    assert_eq!(app.vpn.profiles.len(), 2);
    assert!(!app.vpn.status_known);
    assert_eq!(mock.calls.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn failed_reads_preserve_partial_data_but_never_claim_fresh_runtime_or_chain_state() {
    let mock = super::super::test_api::mock(vec![
        Response::VpnConfig { enabled: true },
        Response::VpnProfiles {
            profiles: profile_app().vpn.profiles,
        },
        Response::Error {
            message: "status unavailable".into(),
        },
    ])
    .await;
    let mut app = profile_app();
    app.vpn.active = Some(VpnActiveStatus {
        profile_name: "home.conf".into(),
        interface: "tm-wg0".into(),
        up: true,
    });
    load_vpn_data(&mut app, &mock.client).await;
    assert!(app.vpn.profiles_known);
    assert!(!app.vpn.status_known);
    assert!(app.vpn.chain.is_none());
    assert!(!standalone_selected(&app));
    let state = profile_state(&app, "home.conf");
    assert!(state.contains("status unknown"));
    assert!(state.contains("chain usage: unknown"));
    assert!(!state.contains("connected"));
}

#[test]
fn saved_chain_usage_is_not_reported_as_runtime_connectivity_and_draft_blocks_deletion() {
    let mut app = profile_app();
    app.vpn.chain = Some(vec![traffic_masq_protocol::VpnHopConfigView {
        profile_name: "home.conf".into(),
    }]);
    let state = profile_state(&app, "home.conf");
    assert!(state.contains("disconnected"));
    assert!(state.contains("saved chain: hop 1"));
    app.router.staged = true;
    app.router.proposed_router_config.vpn_chain = app.vpn.chain.clone().unwrap();
    vpn_delete_selected(&mut app);
    assert!(app.vpn.delete_confirmation.is_none());
}

#[tokio::test]
async fn profile_and_settings_keep_actions_visible_and_dispatch_shared_keyboard_input() {
    use ratatui::{backend::TestBackend, Terminal};
    for screen in [Screen::VpnProfile, Screen::VpnSettings] {
        for (width, height) in [(80, 24), (120, 30)] {
            let mut app = profile_app();
            app.screen = screen;
            app.vpn.opened_profile = Some("home.conf".into());
            app.vpn.focus = actions(screen)[0];
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal
                .draw(|frame| super::super::render(frame, &mut app, false))
                .unwrap();
            assert!(app.ui.list_area.is_none());
            let buffer = terminal.backend().buffer();
            for (rect, _) in &app.ui.buttons {
                assert!(rect.bottom() <= height - 4);
                let text: String = (rect.x..rect.right())
                    .map(|x| buffer[(x, rect.y)].symbol())
                    .collect();
                assert!(text.contains('['));
                assert!(text.contains(']'));
            }
            let client = ApiClient::new("/nonexistent.sock");
            // Dispatch through the shared input router, not just the screen handler.
            super::super::handle_key(&mut app, KeyCode::Tab, &client, false).await;
            assert_eq!(app.screen, screen);
            if screen == Screen::VpnProfile {
                assert_eq!(app.vpn.focus, VpnFocus::Route);
            }
            super::super::handle_key(&mut app, KeyCode::Esc, &client, false).await;
            assert_eq!(app.screen, Screen::Vpn);
            assert_eq!(app.vpn.focus, VpnFocus::List);
        }
    }
}

#[tokio::test]
async fn profile_deletion_confirmation_is_modal_and_mouse_cancel_never_deletes() {
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
    use ratatui::{backend::TestBackend, Terminal};
    let mock = super::super::test_api::mock(vec![]).await;
    let mut app = profile_app();
    app.screen = Screen::VpnProfile;
    app.vpn.opened_profile = Some("home.conf".into());
    app.vpn.focus = VpnFocus::Delete;
    app.ui.input_enabled = true;
    super::super::handle_key(&mut app, KeyCode::Enter, &mock.client, false).await;
    assert!(super::super::confirmation::current(&app).is_some());
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| super::super::render(frame, &mut app, false))
        .unwrap();
    let (rect, _) = app
        .ui
        .buttons
        .iter()
        .find(|(_, slot)| *slot == 1)
        .copied()
        .unwrap();
    super::super::handle_mouse(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: rect.x,
            row: rect.y,
            modifiers: KeyModifiers::NONE,
        },
        &mock.client,
        false,
    )
    .await;
    assert!(app.vpn.delete_confirmation.is_none());
    assert_eq!(app.screen, Screen::VpnProfile);
    assert!(mock.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unknown_enable_outcome_invalidates_availability_and_catalog_has_no_toggle_shortcut() {
    let mock = super::super::test_api::mock(vec![Response::Error {
        message: "outcome unknown".into(),
    }])
    .await;
    let mut app = profile_app();
    app.screen = Screen::VpnSettings;
    app.vpn.focus = VpnFocus::ToggleEnabled;
    handle_vpn_key(&mut app, KeyCode::Enter, &mock.client).await;
    assert_eq!(app.vpn.enabled, None);
    assert!(!app.vpn.status_known);
    handle_vpn_key(&mut app, KeyCode::Esc, &mock.client).await;
    handle_vpn_key(&mut app, KeyCode::Char('e'), &mock.client).await;
    assert_eq!(mock.calls.lock().unwrap().len(), 1);
}
