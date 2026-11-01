use super::*;

#[test]
fn session_fields_are_reachable_and_save_stays_visible_on_small_terminal() {
    assert_eq!(
        next_settings_field(SettingsField::RememberSession),
        SettingsField::RememberMinutes
    );
    assert_eq!(
        next_settings_field(SettingsField::RememberMinutes),
        SettingsField::ShowDhcpClient
    );
    assert_eq!(
        next_settings_field(SettingsField::ShowDhcpClient),
        SettingsField::RandomizeMacDefault
    );
    assert_eq!(
        next_settings_field(SettingsField::SaveSession),
        SettingsField::ChangePassword
    );
    let mut app = TuiApp {
        settings_ui: crate::tui::state::SettingsUiState {
            settings: Some(SecurityEditor {
                field: SettingsField::SaveSession,
                active: SecuritySettings {
                    rollback_timeout_seconds: 30,
                },
                rollback_timeout_input: "30".into(),
                override_active: false,
                restart_required: false,
                remember_session: true,
                remember_minutes_input: "5".into(),
                show_dhcp_client: false,
                randomize_mac_default: true,
                confirmation: None,
                cursor: 0,
                editing: false,
            }),
            ..Default::default()
        },
        ..Default::default()
    };
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(60, 10)).unwrap();
    terminal
        .draw(|frame| render_settings(frame, frame.area(), &mut app))
        .unwrap();
    let text: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(text.contains("Save TUI preferences"));
    let (rect, _) = app.ui.buttons.iter().find(|(_, slot)| *slot == 6).unwrap();
    assert!(rect.y < 9);
}

#[tokio::test]
async fn mutating_settings_require_a_second_enter() {
    for field in [SettingsField::Reset, SettingsField::Save] {
        let mut app = TuiApp {
            settings_ui: crate::tui::state::SettingsUiState {
                settings: Some(SecurityEditor {
                    field,
                    active: SecuritySettings {
                        rollback_timeout_seconds: 30,
                    },
                    rollback_timeout_input: "30".into(),
                    override_active: false,
                    restart_required: false,
                    remember_session: true,
                    remember_minutes_input: "5".into(),
                    show_dhcp_client: false,
                    randomize_mac_default: true,
                    confirmation: None,
                    cursor: 0,
                    editing: false,
                }),
                ..Default::default()
            },
            ..Default::default()
        };

        handle_settings_key(
            &mut app,
            KeyCode::Enter,
            &ApiClient::new("/socket-that-must-not-be-opened"),
        )
        .await;

        assert_eq!(
            app.settings_ui.settings.as_ref().unwrap().confirmation,
            Some(field)
        );
        assert!(app.message.is_none(), "first Enter must not submit");
    }
}

#[test]
fn settings_field_clamps_at_both_ends_instead_of_wrapping() {
    assert_eq!(
        next_settings_field(SettingsField::RollbackTimeout),
        SettingsField::RememberSession
    );
    assert_eq!(
        next_settings_field(SettingsField::RememberMinutes),
        SettingsField::ShowDhcpClient
    );
    assert_eq!(
        next_settings_field(SettingsField::ShowDhcpClient),
        SettingsField::RandomizeMacDefault
    );
    assert_eq!(
        next_settings_field(SettingsField::ChangePassword),
        SettingsField::DnsDefaults
    );
    assert_eq!(
        next_settings_field(SettingsField::DnsDefaults),
        SettingsField::Access
    );
    assert_eq!(
        previous_settings_field(SettingsField::DnsDefaults),
        SettingsField::ChangePassword
    );
    assert_eq!(
        next_settings_field(SettingsField::Access),
        SettingsField::Reset
    );
    assert_eq!(
        next_settings_field(SettingsField::Reset),
        SettingsField::Save
    );
    assert_eq!(
        next_settings_field(SettingsField::Save),
        SettingsField::Reload
    );
    assert_eq!(
        next_settings_field(SettingsField::Reload),
        SettingsField::Reload
    );
    assert_eq!(
        previous_settings_field(SettingsField::Reload),
        SettingsField::Save
    );
    assert_eq!(
        previous_settings_field(SettingsField::Save),
        SettingsField::Reset
    );
    assert_eq!(
        previous_settings_field(SettingsField::Reset),
        SettingsField::Access
    );
    assert_eq!(
        previous_settings_field(SettingsField::Access),
        SettingsField::DnsDefaults
    );
    assert_eq!(
        previous_settings_field(SettingsField::SaveSession),
        SettingsField::RandomizeMacDefault
    );
    assert_eq!(
        previous_settings_field(SettingsField::ShowDhcpClient),
        SettingsField::RememberMinutes
    );
    assert_eq!(
        previous_settings_field(SettingsField::RollbackTimeout),
        SettingsField::RollbackTimeout
    );
}

#[test]
fn clicking_access_action_focuses_access_field() {
    let mut app = TuiApp {
        settings_ui: crate::tui::state::SettingsUiState {
            settings: Some(SecurityEditor {
                field: SettingsField::RollbackTimeout,
                active: SecuritySettings {
                    rollback_timeout_seconds: 30,
                },
                rollback_timeout_input: "30".into(),
                override_active: false,
                restart_required: false,
                remember_session: true,
                remember_minutes_input: "5".into(),
                show_dhcp_client: false,
                randomize_mac_default: true,
                confirmation: None,
                cursor: 0,
                editing: false,
            }),
            ..Default::default()
        },
        ..Default::default()
    };
    focus_action(&mut app, 7);
    assert_eq!(
        app.settings_ui.settings.as_ref().unwrap().field,
        SettingsField::Access
    );
}

#[test]
fn clicking_dhcp_client_action_focuses_show_dhcp_client_field() {
    let mut app = TuiApp {
        settings_ui: crate::tui::state::SettingsUiState {
            settings: Some(SecurityEditor {
                field: SettingsField::RollbackTimeout,
                active: SecuritySettings {
                    rollback_timeout_seconds: 30,
                },
                rollback_timeout_input: "30".into(),
                override_active: false,
                restart_required: false,
                remember_session: true,
                remember_minutes_input: "5".into(),
                show_dhcp_client: false,
                randomize_mac_default: true,
                confirmation: None,
                cursor: 0,
                editing: false,
            }),
            ..Default::default()
        },
        ..Default::default()
    };
    focus_action(&mut app, 8);
    assert_eq!(
        app.settings_ui.settings.as_ref().unwrap().field,
        SettingsField::ShowDhcpClient
    );
}

#[tokio::test]
async fn enter_on_access_setting_attempts_to_open_access_editor() {
    let mut app = TuiApp {
        settings_ui: crate::tui::state::SettingsUiState {
            settings: Some(SecurityEditor {
                field: SettingsField::Access,
                active: SecuritySettings {
                    rollback_timeout_seconds: 30,
                },
                rollback_timeout_input: "30".into(),
                override_active: false,
                restart_required: false,
                remember_session: true,
                remember_minutes_input: "5".into(),
                show_dhcp_client: false,
                randomize_mac_default: true,
                confirmation: None,
                cursor: 0,
                editing: false,
            }),
            ..Default::default()
        },
        screen: Screen::Settings,
        ..Default::default()
    };

    handle_settings_key(
        &mut app,
        KeyCode::Enter,
        &ApiClient::new("/socket-that-must-not-be-opened"),
    )
    .await;

    assert!(app.message.is_some());
}

#[test]
fn password_field_cycles_forward_and_backward_through_all_three() {
    assert_eq!(
        next_password_field(PasswordField::Current),
        PasswordField::New
    );
    assert_eq!(
        next_password_field(PasswordField::New),
        PasswordField::Confirm
    );
    assert_eq!(
        next_password_field(PasswordField::Confirm),
        PasswordField::Current
    );
    assert_eq!(
        previous_password_field(PasswordField::Current),
        PasswordField::Confirm
    );
    assert_eq!(
        previous_password_field(PasswordField::New),
        PasswordField::Current
    );
}

#[test]
fn password_editor_active_value_targets_the_selected_field() {
    let mut editor = PasswordChangeEditor::new();
    editor.active_value_mut().push_str("current-secret");
    assert_eq!(editor.current, "current-secret");
    assert!(editor.new_password.is_empty());

    editor.field = PasswordField::New;
    editor.active_value_mut().push_str("new-secret");
    assert_eq!(editor.new_password, "new-secret");
    assert_eq!(editor.current, "current-secret");

    editor.field = PasswordField::Confirm;
    editor.active_value_mut().push_str("new-secret");
    assert_eq!(editor.confirm, "new-secret");
}

#[test]
fn zeroize_all_clears_every_buffer() {
    let mut editor = PasswordChangeEditor::new();
    editor.current.push('a');
    editor.new_password.push('b');
    editor.confirm.push('c');

    editor.zeroize_all();

    assert!(editor.current.is_empty());
    assert!(editor.new_password.is_empty());
    assert!(editor.confirm.is_empty());
}

#[tokio::test]
async fn settings_editor_cursor_navigation_and_editing() {
    let mut app = TuiApp {
        settings_ui: crate::tui::state::SettingsUiState {
            settings: Some(SecurityEditor {
                field: SettingsField::RollbackTimeout,
                active: SecuritySettings {
                    rollback_timeout_seconds: 30,
                },
                rollback_timeout_input: "30".into(),
                override_active: false,
                restart_required: false,
                remember_session: true,
                remember_minutes_input: "5".into(),
                show_dhcp_client: false,
                randomize_mac_default: true,
                confirmation: None,
                cursor: 2,
                editing: true,
            }),
            ..Default::default()
        },
        screen: Screen::Settings,
        ..Default::default()
    };
    let client = ApiClient::new("/socket-that-must-not-be-opened");

    handle_settings_key(&mut app, KeyCode::Left, &client).await;
    assert_eq!(app.settings_ui.settings.as_ref().unwrap().cursor, 1);

    handle_settings_key(&mut app, KeyCode::Char('5'), &client).await;
    assert_eq!(
        app.settings_ui
            .settings
            .as_ref()
            .unwrap()
            .rollback_timeout_input,
        "350"
    );
    assert_eq!(app.settings_ui.settings.as_ref().unwrap().cursor, 2);

    handle_settings_key(&mut app, KeyCode::Backspace, &client).await;
    assert_eq!(
        app.settings_ui
            .settings
            .as_ref()
            .unwrap()
            .rollback_timeout_input,
        "30"
    );
    assert_eq!(app.settings_ui.settings.as_ref().unwrap().cursor, 1);
}

#[tokio::test]
async fn settings_enter_advances_text_fields_with_or_without_edits() {
    let mut app = TuiApp {
        settings_ui: crate::tui::state::SettingsUiState {
            settings: Some(SecurityEditor {
                field: SettingsField::RollbackTimeout,
                active: SecuritySettings {
                    rollback_timeout_seconds: 30,
                },
                rollback_timeout_input: "30".into(),
                override_active: false,
                restart_required: false,
                remember_session: true,
                remember_minutes_input: "5".into(),
                show_dhcp_client: false,
                randomize_mac_default: true,
                confirmation: None,
                cursor: 0,
                editing: false,
            }),
            ..Default::default()
        },
        screen: Screen::Settings,
        ..Default::default()
    };
    let client = ApiClient::new("/socket-that-must-not-be-opened");

    assert!(!app.settings_ui.settings.as_ref().unwrap().is_editing());

    // Typing enters editing; Enter advances without sending a request.
    handle_settings_key(&mut app, KeyCode::Char('1'), &client).await;
    assert!(app.settings_ui.settings.as_ref().unwrap().is_editing());
    handle_settings_key(&mut app, KeyCode::Enter, &client).await;
    assert!(!app.settings_ui.settings.as_ref().unwrap().is_editing());
    assert_eq!(
        app.settings_ui.settings.as_ref().unwrap().field,
        SettingsField::RememberSession
    );
    assert!(app.message.is_none());

    handle_settings_key(&mut app, KeyCode::Up, &client).await;
    handle_settings_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(
        app.settings_ui.settings.as_ref().unwrap().field,
        SettingsField::RememberSession
    );

    handle_settings_key(&mut app, KeyCode::Down, &client).await;
    assert_eq!(
        app.settings_ui.settings.as_ref().unwrap().field,
        SettingsField::RememberMinutes
    );
    handle_settings_key(&mut app, KeyCode::Char('2'), &client).await;
    assert!(app.settings_ui.settings.as_ref().unwrap().is_editing());
    handle_settings_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(
        app.settings_ui.settings.as_ref().unwrap().field,
        SettingsField::ShowDhcpClient
    );
}

#[tokio::test]
async fn password_editor_cursor_navigation_and_editing() {
    let mut app = TuiApp {
        screen: Screen::SettingsPassword,
        ..Default::default()
    };
    let mut editor = PasswordChangeEditor::new();
    editor.current = "secret".into();
    editor.cursor = 6;
    app.settings_ui.settings_password = Some(editor);
    let client = ApiClient::new("/socket-that-must-not-be-opened");

    handle_settings_password_key(&mut app, KeyCode::Left, &client).await;
    assert_eq!(
        app.settings_ui.settings_password.as_ref().unwrap().cursor,
        5
    );

    handle_settings_password_key(&mut app, KeyCode::Home, &client).await;
    assert_eq!(
        app.settings_ui.settings_password.as_ref().unwrap().cursor,
        0
    );

    handle_settings_password_key(&mut app, KeyCode::Char('a'), &client).await;
    assert_eq!(
        app.settings_ui.settings_password.as_ref().unwrap().current,
        "asecret"
    );
    assert_eq!(
        app.settings_ui.settings_password.as_ref().unwrap().cursor,
        1
    );
}

#[tokio::test]
async fn toggling_dhcp_client_tab_updates_editor_and_app_state() {
    let mut app = TuiApp {
        settings_ui: crate::tui::state::SettingsUiState {
            settings: Some(SecurityEditor {
                field: SettingsField::ShowDhcpClient,
                active: SecuritySettings {
                    rollback_timeout_seconds: 30,
                },
                rollback_timeout_input: "30".into(),
                override_active: false,
                restart_required: false,
                remember_session: true,
                remember_minutes_input: "5".into(),
                show_dhcp_client: false,
                randomize_mac_default: true,
                confirmation: None,
                cursor: 0,
                editing: false,
            }),
            ..Default::default()
        },
        screen: Screen::Settings,
        show_dhcp_client: false,
        randomize_mac_default: true,
        ..Default::default()
    };
    let client = ApiClient::new("/socket-that-must-not-be-opened");

    // Pressing Space toggles on
    handle_settings_key(&mut app, KeyCode::Char(' '), &client).await;
    assert!(app.settings_ui.settings.as_ref().unwrap().show_dhcp_client);
    assert!(app.show_dhcp_client);

    // Pressing Enter toggles off
    handle_settings_key(&mut app, KeyCode::Enter, &client).await;
    assert!(!app.settings_ui.settings.as_ref().unwrap().show_dhcp_client);
    assert!(!app.show_dhcp_client);
}

#[tokio::test]
async fn session_preferences_submit_on_first_enter() {
    let mut app = TuiApp {
        settings_ui: crate::tui::state::SettingsUiState {
            settings: Some(SecurityEditor {
                field: SettingsField::SaveSession,
                active: SecuritySettings {
                    rollback_timeout_seconds: 30,
                },
                rollback_timeout_input: "30".into(),
                override_active: false,
                restart_required: false,
                remember_session: true,
                remember_minutes_input: "invalid".into(),
                show_dhcp_client: false,
                randomize_mac_default: true,
                confirmation: None,
                cursor: 0,
                editing: false,
            }),
            ..Default::default()
        },
        ..Default::default()
    };
    handle_settings_key(
        &mut app,
        KeyCode::Enter,
        &ApiClient::new("/nonexistent.sock"),
    )
    .await;
    assert!(app
        .settings_ui
        .settings
        .as_ref()
        .unwrap()
        .confirmation
        .is_none());
    assert!(app
        .message
        .as_ref()
        .unwrap()
        .contains("whole number of minutes"));
}

#[tokio::test]
async fn clicking_password_submit_validates_form_regardless_of_focused_input() {
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
    use ratatui::{backend::TestBackend, Terminal};
    for field in PASSWORD_FIELDS {
        let mut app = TuiApp {
            settings_ui: crate::tui::state::SettingsUiState {
                settings_password: Some(PasswordChangeEditor {
                    field,
                    current: "current".into(),
                    new_password: "new".into(),
                    confirm: "mismatch".into(),
                    cursor: 0,
                }),
                ..Default::default()
            },
            screen: Screen::SettingsPassword,
            ..Default::default()
        };
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|f| super::super::render(f, &mut app, false))
            .unwrap();
        let (button, _) = app.ui.buttons[0];
        super::super::handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: button.x,
                row: button.y,
                modifiers: KeyModifiers::NONE,
            },
            &ApiClient::new("/must-not-connect"),
            false,
        )
        .await;
        assert!(
            app.message
                .as_deref()
                .unwrap_or_default()
                .contains("do not match"),
            "{field:?}"
        );
    }
}

#[tokio::test]
async fn automatic_mac_default_can_be_toggled_in_settings() {
    let mut app = TuiApp {
        settings_ui: crate::tui::state::SettingsUiState {
            settings: Some(SecurityEditor {
                field: SettingsField::RandomizeMacDefault,
                active: SecuritySettings {
                    rollback_timeout_seconds: 30,
                },
                rollback_timeout_input: "30".into(),
                override_active: false,
                restart_required: false,
                remember_session: true,
                remember_minutes_input: "5".into(),
                show_dhcp_client: false,
                randomize_mac_default: true,
                confirmation: None,
                cursor: 0,
                editing: false,
            }),
            ..Default::default()
        },
        screen: Screen::Settings,
        show_dhcp_client: false,
        randomize_mac_default: true,
        ..Default::default()
    };
    let client = ApiClient::new("/socket-that-must-not-be-opened");

    // Pressing Space toggles off
    handle_settings_key(&mut app, KeyCode::Char(' '), &client).await;
    assert!(
        !app.settings_ui
            .settings
            .as_ref()
            .unwrap()
            .randomize_mac_default
    );

    // Pressing Enter toggles on
    handle_settings_key(&mut app, KeyCode::Enter, &client).await;
    assert!(
        app.settings_ui
            .settings
            .as_ref()
            .unwrap()
            .randomize_mac_default
    );
}
