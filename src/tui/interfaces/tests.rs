use super::*;

fn default_route_editor(allow_management_change: bool) -> InterfaceEditor {
    InterfaceEditor {
        interface: "wlan0".into(),
        field: InterfaceEditorField::Save,
        cidr: "192.168.1.10/24".into(),
        role: InterfaceRole::Output,
        managed: true,
        allow_management_change,
        has_default_route: true,
        original_managed: true,
        original_cidr: "192.168.1.10/24".into(),
        current_addresses: vec!["192.168.1.10/24".into()],
        observed_addresses: vec![],
        current_wifi_summary: None,
        current_dhcp_summary: None,
        cursor: 0,
    }
}

fn unmanaged_editor() -> InterfaceEditor {
    let mut editor = default_route_editor(false);
    editor.original_managed = false;
    editor.managed = false;
    editor
}

#[test]
fn managed_output_on_default_route_requires_explicit_confirmation() {
    let error = default_route_editor(false).edit_request().unwrap_err();
    assert!(error.to_string().contains("default route"));
}

#[test]
fn managed_output_on_default_route_is_allowed_after_confirmation() {
    assert!(default_route_editor(true).edit_request().is_ok());
}

#[test]
fn managed_default_route_cannot_disable_management_without_confirmation() {
    let mut editor = default_route_editor(false);
    editor.managed = false;
    let error = editor.edit_request().unwrap_err();
    assert!(error.to_string().contains("default route"));
}

#[test]
fn managed_input_default_route_requires_confirmation() {
    let mut editor = default_route_editor(false);
    editor.role = InterfaceRole::Input;
    let error = editor.edit_request().unwrap_err();
    assert!(error.to_string().contains("default route"));
}

#[test]
fn unmanaged_interface_rejects_ip_edits_with_a_clear_error() {
    let mut editor = unmanaged_editor();
    editor.cidr = "192.168.1.11/24".into();
    let error = editor.edit_request().unwrap_err();
    assert_eq!(
        error.to_string(),
        "cannot change IP while the interface is unmanaged; enable Configure with traffic-masq first"
    );
}

#[test]
fn external_interface_can_change_router_role() {
    let mut editor = unmanaged_editor();
    editor.role = InterfaceRole::Input;
    let request = editor
        .edit_request()
        .expect("role is independent of address configuration");
    assert_eq!(request.role, InterfaceRole::Input);
    assert!(!request.managed);
}

#[test]
fn unmanaged_interface_names_every_field_it_refuses_to_change() {
    let mut editor = unmanaged_editor();
    editor.cidr = "192.168.1.11/24".into();
    editor.role = InterfaceRole::Input;
    let error = editor.edit_request().unwrap_err();
    assert_eq!(
        error.to_string(),
        "cannot change IP while the interface is unmanaged; enable Configure with traffic-masq first"
    );
}

#[test]
fn an_unmanaged_interface_can_still_be_saved_untouched() {
    // This is how a leftover traffic-masq address gets cleaned up, so it
    // must not be swallowed by the settings guard.
    assert!(unmanaged_editor().edit_request().is_ok());
}

#[test]
fn turning_management_on_is_not_a_settings_edit() {
    let mut editor = unmanaged_editor();
    editor.managed = true;
    editor.allow_management_change = true;
    editor.cidr = "192.168.1.11/24".into();
    assert!(editor.edit_request().is_ok());
}

/// Clearing the field is the removal request, and it has to survive the
/// trip to the daemon as an empty CIDR — that is what makes the planner
/// take the address off instead of leaving it alone.
#[test]
fn an_empty_cidr_on_a_managed_interface_asks_for_the_address_to_be_removed() {
    let mut editor = default_route_editor(true);
    editor.cidr.clear();
    let request = editor.edit_request().expect("removal must be a valid edit");
    assert!(request.cidr.is_empty());
    assert!(request.managed, "removal keeps the interface managed");
    assert_eq!(request.role, InterfaceRole::Output);
}

#[test]
fn removing_the_ip_of_an_unmanaged_interface_points_at_the_managed_switch() {
    let mut editor = unmanaged_editor();
    editor.cidr.clear();
    let error = editor.edit_request().unwrap_err();
    assert_eq!(
        error.to_string(),
        "cannot remove the IP while the interface is unmanaged; enable Configure with traffic-masq so traffic-masq may take the address off"
    );
}

#[test]
fn the_remove_row_clears_the_cidr_field() {
    let mut editor = default_route_editor(true);
    editor.remove_ipv4();
    assert!(editor.cidr.is_empty());
    assert_eq!(
        editor.current_addresses,
        vec!["192.168.1.10/24".to_string()],
        "the address that is about to go is still reported"
    );
}

#[test]
fn interface_editor_field_reaches_save_and_clamps_at_both_ends() {
    for pair in INTERFACE_EDITOR_FIELDS.windows(2) {
        assert_eq!(next_editor_field(pair[0]), pair[1]);
        assert_eq!(previous_editor_field(pair[1]), pair[0]);
    }
    assert_eq!(
        previous_editor_field(InterfaceEditorField::Cidr),
        InterfaceEditorField::Cidr
    );
    assert_eq!(
        next_editor_field(InterfaceEditorField::Save),
        InterfaceEditorField::Save
    );
}

#[test]
fn next_role_cycles_through_all_three_variants_without_repeating() {
    let start = InterfaceRole::None;
    let mut role = start;
    let mut seen = Vec::new();
    for _ in 0..3 {
        seen.push(role);
        role = next_role(role);
    }
    assert_eq!(role, start, "cycle must return to the starting role");
    seen.sort_by_key(|role| format!("{role:?}"));
    seen.dedup();
    assert_eq!(seen.len(), 3, "all three roles must be distinct");
}

#[tokio::test]
async fn interface_editor_cursor_navigation_and_editing() {
    let mut app = TuiApp {
        screen: Screen::InterfaceEditor,
        ..Default::default()
    };
    let mut editor = default_route_editor(true);
    editor.field = InterfaceEditorField::Cidr;
    editor.cidr = "192.168.1.1/24".into();
    editor.cursor = editor.cidr.len();
    app.editor = Some(editor);
    let client = ApiClient::new("/socket-that-must-not-be-opened");

    handle_editor_key(&mut app, KeyCode::Left, &client).await;
    assert_eq!(app.editor.as_ref().unwrap().cursor, 13);

    handle_editor_key(&mut app, KeyCode::Char('0'), &client).await;
    assert_eq!(app.editor.as_ref().unwrap().cidr, "192.168.1.1/204");
    assert_eq!(app.editor.as_ref().unwrap().cursor, 14);

    handle_editor_key(&mut app, KeyCode::Backspace, &client).await;
    assert_eq!(app.editor.as_ref().unwrap().cidr, "192.168.1.1/24");
    assert_eq!(app.editor.as_ref().unwrap().cursor, 13);

    handle_editor_key(&mut app, KeyCode::Home, &client).await;
    assert_eq!(app.editor.as_ref().unwrap().cursor, 0);

    handle_editor_key(&mut app, KeyCode::Delete, &client).await;
    assert_eq!(app.editor.as_ref().unwrap().cidr, "92.168.1.1/24");
    assert_eq!(app.editor.as_ref().unwrap().cursor, 0);
}

#[tokio::test]
async fn unmanaged_ip_edit_attempt_points_to_managed_mode() {
    let mut app = TuiApp {
        screen: Screen::InterfaceEditor,
        ..Default::default()
    };
    let mut editor = unmanaged_editor();
    editor.field = InterfaceEditorField::Cidr;
    app.editor = Some(editor);
    let client = ApiClient::new("/socket-that-must-not-be-opened");

    handle_editor_key(&mut app, KeyCode::Char('1'), &client).await;

    let message = app.message.as_deref().unwrap_or_default();
    assert!(message.contains("Enable Configure with traffic-masq"));
}
