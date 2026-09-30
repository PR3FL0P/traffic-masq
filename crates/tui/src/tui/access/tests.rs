use super::*;

#[test]
fn access_field_reaches_every_row_and_clamps_at_both_ends() {
    assert_eq!(next_field(AccessField::Enabled), AccessField::Listen);
    assert_eq!(
        next_field(AccessField::Listen),
        AccessField::CertificatePath
    );
    assert_eq!(
        next_field(AccessField::CertificatePath),
        AccessField::PrivateKeyPath
    );
    assert_eq!(next_field(AccessField::PrivateKeyPath), AccessField::Save);
    assert_eq!(next_field(AccessField::Save), AccessField::Reset);
    assert_eq!(next_field(AccessField::Reset), AccessField::Reload);
    assert_eq!(next_field(AccessField::Reload), AccessField::Reload);

    assert_eq!(previous_field(AccessField::Reload), AccessField::Reset);
    assert_eq!(previous_field(AccessField::Reset), AccessField::Save);
    assert_eq!(
        previous_field(AccessField::Save),
        AccessField::PrivateKeyPath
    );
    assert_eq!(previous_field(AccessField::Enabled), AccessField::Enabled);
}

#[test]
fn access_editor_active_value_is_none_for_toggle_and_action_rows() {
    let settings = ApiHttpsSettings {
        enabled: false,
        listen: String::new(),
        certificate_path: None,
        private_key_path: None,
    };
    let mut editor = AccessEditor {
        field: AccessField::Save,
        active: settings.clone(),
        desired: settings,
        override_active: false,
        restart_required: false,
        cursor: 0,
    };
    assert!(editor.active_value_mut().is_none());
    editor.field = AccessField::Reset;
    assert!(editor.active_value_mut().is_none());
    editor.field = AccessField::Reload;
    assert!(editor.active_value_mut().is_none());
    editor.field = AccessField::Enabled;
    assert!(editor.active_value_mut().is_none());
    editor.field = AccessField::Listen;
    assert!(editor.active_value_mut().is_some());
}

#[tokio::test]
async fn access_editor_cursor_navigation_and_editing() {
    let mut app = TuiApp {
        screen: Screen::Access,
        ..Default::default()
    };
    let settings = ApiHttpsSettings {
        enabled: false,
        listen: "127.0.0.1:8443".into(),
        certificate_path: None,
        private_key_path: None,
    };
    let editor = AccessEditor {
        field: AccessField::Listen,
        active: settings.clone(),
        desired: settings,
        override_active: false,
        restart_required: false,
        cursor: 14,
    };
    app.api_access = Some(editor);
    let client = ApiClient::new("/socket-that-must-not-be-opened");

    handle_access_key(&mut app, KeyCode::Left, &client).await;
    assert_eq!(app.api_access.as_ref().unwrap().cursor, 13);

    handle_access_key(&mut app, KeyCode::Right, &client).await;
    assert_eq!(app.api_access.as_ref().unwrap().cursor, 14);

    handle_access_key(&mut app, KeyCode::Home, &client).await;
    assert_eq!(app.api_access.as_ref().unwrap().cursor, 0);

    handle_access_key(&mut app, KeyCode::Char('a'), &client).await;
    assert_eq!(
        app.api_access.as_ref().unwrap().desired.listen,
        "a127.0.0.1:8443"
    );
    assert_eq!(app.api_access.as_ref().unwrap().cursor, 1);

    handle_access_key(&mut app, KeyCode::Backspace, &client).await;
    assert_eq!(
        app.api_access.as_ref().unwrap().desired.listen,
        "127.0.0.1:8443"
    );
    assert_eq!(app.api_access.as_ref().unwrap().cursor, 0);
}

#[tokio::test]
async fn esc_returns_to_settings_screen() {
    let mut app = TuiApp {
        screen: Screen::Access,
        ..Default::default()
    };
    let client = ApiClient::new("/socket-that-must-not-be-opened");
    handle_access_key(&mut app, KeyCode::Esc, &client).await;
    assert_eq!(app.screen, Screen::Settings);
}
