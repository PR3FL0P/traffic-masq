use super::*;

#[test]
fn enable_vpn_action_is_visible_at_minimum_terminal_size() {
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
    let (rect, _) = app
        .ui
        .buttons
        .iter()
        .find(|(_, slot)| *slot == 6)
        .expect("enable VPN button");
    let buffer = terminal.backend().buffer();
    let text: String = (rect.x..rect.right())
        .map(|x| buffer[(x, rect.y)].symbol())
        .collect();
    assert!(text.contains("Enable VPN"));
    assert!(rect.bottom() <= 20);
}

#[test]
fn vpn_action_focus_reaches_every_action_and_clamps_at_both_ends() {
    assert_eq!(
        next_vpn_action_focus(VpnFocus::Connect),
        VpnFocus::Disconnect
    );
    assert_eq!(
        next_vpn_action_focus(VpnFocus::Disconnect),
        VpnFocus::Import
    );
    assert_eq!(next_vpn_action_focus(VpnFocus::Import), VpnFocus::Delete);
    assert_eq!(next_vpn_action_focus(VpnFocus::Delete), VpnFocus::Policy);
    assert_eq!(next_vpn_action_focus(VpnFocus::Policy), VpnFocus::Refresh);
    assert_eq!(
        next_vpn_action_focus(VpnFocus::Refresh),
        VpnFocus::ToggleEnabled
    );
    assert_eq!(
        next_vpn_action_focus(VpnFocus::ToggleEnabled),
        VpnFocus::ToggleEnabled
    );
    assert_eq!(
        previous_vpn_action_focus(VpnFocus::Refresh),
        VpnFocus::Policy
    );
    assert_eq!(
        previous_vpn_action_focus(VpnFocus::Policy),
        VpnFocus::Delete
    );
    assert_eq!(
        previous_vpn_action_focus(VpnFocus::Delete),
        VpnFocus::Import
    );
    assert_eq!(
        previous_vpn_action_focus(VpnFocus::Import),
        VpnFocus::Disconnect
    );
    assert_eq!(
        previous_vpn_action_focus(VpnFocus::Disconnect),
        VpnFocus::Connect
    );
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
