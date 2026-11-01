use super::*;

#[tokio::test]
async fn disabling_a_missing_client_saves_without_enabled_wifi_or_dhcp() {
    use http_body_util::{BodyExt, Full};
    use hyper::{body::Bytes, server::conn::http1, service::service_fn};
    use hyper_util::rt::TokioIo;
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("api.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        http1::Builder::new()
            .serve_connection(
                TokioIo::new(stream),
                service_fn(
                    |request: hyper::Request<hyper::body::Incoming>| async move {
                        assert_eq!(request.method(), hyper::Method::POST);
                        assert_eq!(request.uri().path(), "/api/v1/control");
                        let body: serde_json::Value = serde_json::from_slice(
                            &request.into_body().collect().await.unwrap().to_bytes(),
                        )
                        .unwrap();
                        assert_eq!(body["type"], "save_interface_config");
                        assert_eq!(body["interface"], "wlan0");
                        assert_eq!(body["expected_revision"], 7);
                        assert_eq!(body["config"]["managed"], false);
                        assert!(body["config"]["wifi_client"].is_null());
                        assert!(body["config"]["dhcp_client"].is_null());
                        let response = Response::InterfaceIntentSaved {
                            interface: "wlan0".into(),
                            revision: 8,
                            deferred: true,
                            missing_dependencies: vec!["wlan0".into()],
                        };
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                            Bytes::from(serde_json::to_vec(&response).unwrap()),
                        )))
                    },
                ),
            )
            .await
            .unwrap();
    });
    let mut editor = default_route_editor(true);
    editor.cidr.clear();
    editor.original_cidr.clear();
    editor.current_addresses.clear();
    editor.role = InterfaceRole::Input;
    editor.managed = false;
    editor.offline_revision = Some(7);
    editor.saved_config = Some(
        serde_json::from_value(serde_json::json!({
            "role": "input", "managed": true,
            "wifi_client": {"ssid": "saved", "security": "open"},
            "dhcp_client": {"enabled": true}
        }))
        .unwrap(),
    );
    let mut app = TuiApp {
        interface_ui: crate::tui::state::InterfaceUiState {
            editor: Some(editor),
            ..Default::default()
        },
        screen: Screen::InterfaceEditor,
        ..Default::default()
    };
    let client = ApiClient::new(socket);
    handle_editor_key(&mut app, KeyCode::Enter, &client).await;
    server.await.unwrap();
    assert_eq!(app.screen, Screen::InterfaceList);
    assert!(app.confirmation.pending.is_none());
}

fn observed_address(
    protocol: Option<u8>,
    owned: Option<bool>,
) -> traffic_masq_protocol::InterfaceStatusView {
    let address = traffic_masq_protocol::Ipv4AddressInfoView {
        interface_index: 1,
        address: "198.18.0.1".parse().unwrap(),
        prefix_len: 24,
        protocol,
    };
    traffic_masq_protocol::InterfaceStatusView {
        interface: traffic_masq_protocol::NetworkInterfaceView {
            index: 1,
            name: "wlp1s0".into(),
            is_up: true,
            rx_bytes: 0,
            tx_bytes: 0,
            is_wireless: true,
        },
        owned_ipv4_addresses: owned.map(|owned| if owned { vec![address.clone()] } else { vec![] }),
        ipv4_addresses: vec![address],
        has_default_route: false,
    }
}

#[test]
fn editor_recovers_only_proven_static_addresses_after_settings_are_removed() {
    for (protocol, proof) in [
        (Some(201), None),
        (Some(201), Some(true)),
        (None, Some(true)),
    ] {
        let status = observed_address(protocol, proof);
        assert_eq!(
            editor_address_defaults(None, Some(&status)),
            ("198.18.0.1/24".into(), true)
        );
    }
    for (protocol, proof) in [
        (None, None),
        (None, Some(false)),
        (Some(201), Some(false)),
        (Some(202), Some(true)),
        (Some(16), Some(true)),
    ] {
        let status = observed_address(protocol, proof);
        assert_eq!(
            editor_address_defaults(None, Some(&status)),
            (String::new(), true)
        );
    }
}

#[test]
fn editor_keeps_explicit_saved_configuration_and_does_not_choose_between_owned_addresses() {
    let mut status = observed_address(Some(201), Some(true));
    let config = traffic_masq_protocol::InterfaceConfigView {
        wifi_concurrent: false,
        mac_address: None,
        managed: false,
        role: InterfaceRole::None,
        ipv4: None,
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    };
    assert_eq!(
        editor_address_defaults(Some(&config), Some(&status)),
        (String::new(), false)
    );
    let mut second = status.ipv4_addresses[0].clone();
    second.address = "198.18.0.2".parse().unwrap();
    status.ipv4_addresses.push(second.clone());
    status.owned_ipv4_addresses.as_mut().unwrap().push(second);
    assert_eq!(
        editor_address_defaults(None, Some(&status)),
        (String::new(), true)
    );
}

#[tokio::test]
async fn keyboard_ip_and_mac_edit_previews_applies_and_confirms_the_typed_addresses() {
    use http_body_util::{BodyExt, Full};
    use hyper::{body::Bytes, server::conn::http1, service::service_fn};
    use hyper_util::rt::TokioIo;
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("api.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let change = traffic_masq_protocol::PendingNetworkChange {
        recovery_progress: None,
        phase: Default::default(),
        last_error: None,
        token: "ip-test-token".into(),
        interface: "wlp1s0".into(),
        rollback_timeout_seconds: 60,
        expires_at_unix: current_unix_time() + 60,
    };
    let responses = vec![
        Response::InterfaceConfig {
            wifi_concurrent_support: None,
            interface: "wlp1s0".into(),
            config: None,
            allow_management_change: false,
        },
        Response::InterfacePlan {
            plan: traffic_masq_protocol::InterfaceChangePlanView {
                mac_address: Some("02:11:22:33:44:55".parse().unwrap()),
                interface: "wlp1s0".into(),
                delete_ipv4: vec![],
                retag_ipv4: None,
                add_ipv4: None,
                set_link_up: false,
                management_change: false,
                dhcp_action: traffic_masq_protocol::DhcpChangeActionView::Unchanged,
                releasing_management: false,
            },
        },
        Response::NetworkChangePending {
            change: change.clone(),
        },
        Response::NetworkChangeCommitted { change },
    ];
    let requests = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let observed = requests.clone();
    let server = tokio::spawn(async move {
        for response in responses {
            let (stream, _) =
                tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
            let requests = observed.clone();
            let body = serde_json::to_vec(&response).unwrap();
            http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                        let requests = requests.clone();
                        let body = body.clone();
                        async move {
                            assert_eq!(request.method(), hyper::Method::POST);
                            assert_eq!(request.uri().path(), "/api/v1/control");
                            let bytes = request.into_body().collect().await.unwrap().to_bytes();
                            let payload: serde_json::Value =
                                serde_json::from_slice(&bytes).unwrap();
                            let kind = payload["type"].as_str().unwrap().to_owned();
                            assert_eq!(payload["interface"].as_str().unwrap_or("wlp1s0"), "wlp1s0");
                            requests.lock().await.push((kind, payload));
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                                Bytes::from(body),
                            )))
                        }
                    }),
                )
                .await
                .unwrap();
        }
    });
    let client = ApiClient::new(socket);
    let mut app = TuiApp::default();
    app.ui.input_enabled = true;
    let mut status = observed_address(None, Some(false));
    status.ipv4_addresses.clear();
    app.dashboard.interfaces.push(status);
    open_editor(&mut app, &client).await;
    assert_eq!(app.screen, Screen::InterfaceEditor);
    assert!(app.interface_ui.editor.as_ref().unwrap().managed);
    for character in "198.18.0.1/24".chars() {
        handle_editor_key(&mut app, KeyCode::Char(character), &client).await;
    }
    for _ in 0..4 {
        super::super::handle_key(&mut app, KeyCode::Tab, &client, false).await;
    }
    assert_eq!(
        app.interface_ui.editor.as_ref().unwrap().field,
        InterfaceEditorField::Advanced
    );
    handle_editor_key(&mut app, KeyCode::Enter, &client).await;
    handle_editor_key(&mut app, KeyCode::Tab, &client).await;
    assert_eq!(
        app.interface_ui.editor.as_ref().unwrap().field,
        InterfaceEditorField::MacAddress
    );
    for character in "02:11:22:33:44:55".chars() {
        super::super::handle_key(&mut app, KeyCode::Char(character), &client, false).await;
    }
    submit_dry_run(&mut app, &client).await;
    assert_eq!(app.screen, Screen::Preview);
    handle_preview_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(app.screen, Screen::PendingChange);
    handle_pending_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(app.screen, Screen::InterfaceList);
    assert!(app.confirmation.pending.is_none());
    server.await.unwrap();
    let requests = requests.lock().await;
    assert_eq!(requests[0].0, "get_interface_config");
    let requests = &requests[1..];
    assert_eq!(requests[0].0, "dry_run_interface_edit");
    assert_eq!(requests[1].0, "apply_interface_edit");
    for (_, body) in &requests[..2] {
        assert_eq!(body["edit"]["cidr"], "198.18.0.1/24");
        assert_eq!(body["edit"]["managed"], true);
        assert_eq!(body["edit"]["mac_address"], "02:11:22:33:44:55");
    }
    assert_eq!(requests[2].0, "commit_network_change");
    assert_eq!(requests[2].1["token"], "ip-test-token");
}

fn default_route_editor(allow_management_change: bool) -> InterfaceEditor {
    InterfaceEditor {
        wifi_concurrent_support: None,
        wifi_concurrent: false,
        mac_address: String::new(),
        saved_config: None,
        offline_revision: None,
        intent_confirmation: None,
        advanced: false,
        exit_requested: false,
        original_role: InterfaceRole::Output,
        original_mac: String::new(),
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
    for offline in [false, true] {
        let fields = editor_fields(offline, true);
        for pair in fields.windows(2) {
            assert_eq!(next_editor_field(pair[0], offline, true), pair[1]);
            assert_eq!(previous_editor_field(pair[1], offline, true), pair[0]);
        }
        assert_eq!(previous_editor_field(fields[0], offline, true), fields[0]);
        let last = *fields.last().unwrap();
        assert_eq!(next_editor_field(last, offline, true), last);
    }
    assert_eq!(
        next_editor_field(InterfaceEditorField::Save, false, true),
        InterfaceEditorField::Save
    );
    assert_eq!(
        next_editor_field(InterfaceEditorField::Save, true, true),
        InterfaceEditorField::Forget
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
    app.interface_ui.editor = Some(editor);
    let client = ApiClient::new("/socket-that-must-not-be-opened");

    handle_editor_key(&mut app, KeyCode::Left, &client).await;
    assert_eq!(app.interface_ui.editor.as_ref().unwrap().cursor, 13);

    handle_editor_key(&mut app, KeyCode::Char('0'), &client).await;
    assert_eq!(
        app.interface_ui.editor.as_ref().unwrap().cidr,
        "192.168.1.1/204"
    );
    assert_eq!(app.interface_ui.editor.as_ref().unwrap().cursor, 14);

    handle_editor_key(&mut app, KeyCode::Backspace, &client).await;
    assert_eq!(
        app.interface_ui.editor.as_ref().unwrap().cidr,
        "192.168.1.1/24"
    );
    assert_eq!(app.interface_ui.editor.as_ref().unwrap().cursor, 13);

    handle_editor_key(&mut app, KeyCode::Home, &client).await;
    assert_eq!(app.interface_ui.editor.as_ref().unwrap().cursor, 0);

    handle_editor_key(&mut app, KeyCode::Delete, &client).await;
    assert_eq!(
        app.interface_ui.editor.as_ref().unwrap().cidr,
        "92.168.1.1/24"
    );
    assert_eq!(app.interface_ui.editor.as_ref().unwrap().cursor, 0);
}

#[tokio::test]
async fn unmanaged_ip_edit_attempt_points_to_managed_mode() {
    let mut app = TuiApp {
        screen: Screen::InterfaceEditor,
        ..Default::default()
    };
    let mut editor = unmanaged_editor();
    editor.field = InterfaceEditorField::Cidr;
    app.interface_ui.editor = Some(editor);
    let client = ApiClient::new("/socket-that-must-not-be-opened");

    handle_editor_key(&mut app, KeyCode::Char('1'), &client).await;

    let message = app.message.as_deref().unwrap_or_default();
    assert!(message.contains("Enable Configure with traffic-masq"));
}

#[tokio::test]
async fn random_mac_is_local_unicast_and_kept_in_the_apply_request() {
    let mut editor = default_route_editor(true);
    editor.field = InterfaceEditorField::RandomizeMac;
    editor.allow_management_change = true;
    let mut app = TuiApp {
        interface_ui: crate::tui::state::InterfaceUiState {
            editor: Some(editor),
            ..Default::default()
        },
        ..Default::default()
    };
    let client = ApiClient::new(std::path::PathBuf::from("/unused-mac-test.sock"));
    handle_editor_key(&mut app, KeyCode::Enter, &client).await;
    let editor = app.interface_ui.editor.as_ref().unwrap();
    let mac: traffic_masq_protocol::MacAddr = editor.mac_address.parse().unwrap();
    assert_eq!(mac.octets()[0] & 3, 2);
    assert_eq!(editor.edit_request().unwrap().mac_address, Some(mac));
    handle_editor_key(&mut app, KeyCode::Enter, &client).await;
    assert_ne!(
        app.interface_ui.editor.as_ref().unwrap().mac_address,
        mac.to_string()
    );
}

#[tokio::test]
async fn manual_mac_can_be_typed_edited_and_cleared() {
    let mut editor = default_route_editor(true);
    editor.field = InterfaceEditorField::MacAddress;
    let mut app = TuiApp {
        interface_ui: crate::tui::state::InterfaceUiState {
            editor: Some(editor),
            ..Default::default()
        },
        ..Default::default()
    };
    let client = ApiClient::new("/unused-mac-test.sock");
    for c in "02:AB:22:33:44:55".chars() {
        handle_editor_key(&mut app, KeyCode::Char(c), &client).await;
    }
    let mac = "02:ab:22:33:44:55".parse().unwrap();
    assert_eq!(
        app.interface_ui
            .editor
            .as_ref()
            .unwrap()
            .edit_request()
            .unwrap()
            .mac_address,
        Some(mac)
    );

    handle_editor_key(&mut app, KeyCode::Left, &client).await;
    handle_editor_key(&mut app, KeyCode::Backspace, &client).await;
    handle_editor_key(&mut app, KeyCode::Char('6'), &client).await;
    assert_eq!(
        app.interface_ui.editor.as_ref().unwrap().mac_address,
        "02:AB:22:33:44:65"
    );
    handle_editor_key(&mut app, KeyCode::Home, &client).await;
    handle_editor_key(&mut app, KeyCode::Delete, &client).await;
    assert!(app
        .interface_ui
        .editor
        .as_ref()
        .unwrap()
        .edit_request()
        .is_err());
    handle_editor_key(&mut app, KeyCode::End, &client).await;
    for _ in 0..16 {
        handle_editor_key(&mut app, KeyCode::Backspace, &client).await;
    }
    assert_eq!(
        app.interface_ui
            .editor
            .as_ref()
            .unwrap()
            .edit_request()
            .unwrap()
            .mac_address,
        None
    );
}

#[test]
fn manual_mac_rejects_invalid_zero_and_multicast_addresses() {
    let mut editor = default_route_editor(true);
    for invalid in [
        "02:11:22",
        "gg:11:22:33:44:55",
        "00:00:00:00:00:00",
        "01:11:22:33:44:55",
        "ff:ff:ff:ff:ff:ff",
    ] {
        editor.mac_address = invalid.into();
        assert!(editor.edit_request().is_err(), "accepted {invalid}");
    }
    // A manually supplied address need not have the locally administered bit set.
    editor.mac_address = "00:11:22:33:44:55".into();
    assert!(editor.edit_request().is_ok());
}

#[tokio::test]
async fn mac_controls_require_management_and_switching_it_off_clears_the_mac() {
    let mut editor = unmanaged_editor();
    editor.advanced = true;
    editor.field = InterfaceEditorField::MacAddress;
    let mut app = TuiApp {
        interface_ui: crate::tui::state::InterfaceUiState {
            editor: Some(editor),
            ..Default::default()
        },
        ..Default::default()
    };
    let client = ApiClient::new("/unused-mac-test.sock");
    handle_editor_key(&mut app, KeyCode::Char('0'), &client).await;
    assert!(app
        .interface_ui
        .editor
        .as_ref()
        .unwrap()
        .mac_address
        .is_empty());
    assert!(app
        .message
        .as_deref()
        .unwrap()
        .contains("MAC editing requires managed mode"));
    app.interface_ui.editor.as_mut().unwrap().field = InterfaceEditorField::RandomizeMac;
    handle_editor_key(&mut app, KeyCode::Enter, &client).await;
    assert!(app
        .interface_ui
        .editor
        .as_ref()
        .unwrap()
        .mac_address
        .is_empty());
    app.interface_ui.editor.as_mut().unwrap().managed = true;
    handle_editor_key(&mut app, KeyCode::Enter, &client).await;
    assert!(!app
        .interface_ui
        .editor
        .as_ref()
        .unwrap()
        .mac_address
        .is_empty());
    // Navigate to the manual field and modify the generated value.
    handle_editor_key(&mut app, KeyCode::BackTab, &client).await;
    assert_eq!(
        app.interface_ui.editor.as_ref().unwrap().field,
        InterfaceEditorField::MacAddress
    );
    assert_eq!(app.interface_ui.editor.as_ref().unwrap().cursor, 17);
    handle_editor_key(&mut app, KeyCode::Backspace, &client).await;
    assert_eq!(
        app.interface_ui.editor.as_ref().unwrap().mac_address.len(),
        16
    );
    handle_editor_key(&mut app, KeyCode::Up, &client).await;
    handle_editor_key(&mut app, KeyCode::Up, &client).await;
    assert_eq!(
        app.interface_ui.editor.as_ref().unwrap().field,
        InterfaceEditorField::Managed
    );
    handle_editor_key(&mut app, KeyCode::Enter, &client).await;
    assert!(!app.interface_ui.editor.as_ref().unwrap().managed);
    assert!(app
        .interface_ui
        .editor
        .as_ref()
        .unwrap()
        .mac_address
        .is_empty());
}

#[tokio::test]
async fn offline_forget_and_reset_confirm_with_enter_and_preserve_revision() {
    for (steps, request_type) in [
        (1, "forget_interface_config"),
        (2, "reset_interface_override"),
    ] {
        let mock = super::super::test_api::mock(vec![Response::Error {
            message: "stale revision".into(),
        }])
        .await;
        let mut editor = default_route_editor(false);
        editor.offline_revision = Some(7);
        editor.field = InterfaceEditorField::Save;
        let mut app = TuiApp {
            interface_ui: crate::tui::state::InterfaceUiState {
                editor: Some(editor),
                ..Default::default()
            },
            screen: Screen::InterfaceEditor,
            ..Default::default()
        };
        app.dashboard.base_config = Some(traffic_masq_protocol::InterfaceBaseConfigView {
            file: Some("/custom/router.toml".into()),
            interfaces: vec!["wlan0".into()],
        });
        for _ in 0..steps {
            handle_editor_key(&mut app, KeyCode::Tab, &mock.client).await;
        }
        handle_editor_key(&mut app, KeyCode::Enter, &mock.client).await;
        handle_editor_key(&mut app, KeyCode::Char('y'), &mock.client).await;
        assert!(mock.calls.lock().unwrap().is_empty());
        handle_editor_key(&mut app, KeyCode::Esc, &mock.client).await;
        assert!(app
            .interface_ui
            .editor
            .as_ref()
            .unwrap()
            .intent_confirmation
            .is_none());
        handle_editor_key(&mut app, KeyCode::Enter, &mock.client).await;
        handle_editor_key(&mut app, KeyCode::Enter, &mock.client).await;
        let calls = mock.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].body["type"], request_type);
        assert_eq!(calls[0].body["interface"], "wlan0");
        assert_eq!(calls[0].body["expected_revision"], 7);
    }
}

#[test]
fn offline_action_buttons_are_visible_clickable_and_hidden_for_present_devices() {
    use ratatui::{backend::TestBackend, Terminal};

    for (slot, field, label) in [
        (
            FORGET_BUTTON_SLOT,
            InterfaceEditorField::Forget,
            FORGET_LABEL,
        ),
        (RESET_BUTTON_SLOT, InterfaceEditorField::Reset, RESET_LABEL),
    ] {
        for height in [16, 40] {
            let mut editor = default_route_editor(false);
            editor.offline_revision = Some(7);
            editor.field = field;
            let mut app = TuiApp {
                interface_ui: crate::tui::state::InterfaceUiState {
                    editor: Some(editor),
                    ..Default::default()
                },
                ..Default::default()
            };
            let mut terminal = Terminal::new(TestBackend::new(100, height)).unwrap();
            terminal
                .draw(|frame| render_editor(frame, frame.area(), &mut app))
                .unwrap();
            let rect = app
                .ui
                .buttons
                .iter()
                .find(|(_, action)| *action == slot)
                .unwrap()
                .0;
            let buffer = terminal.backend().buffer();
            let text: String = (rect.x..rect.right())
                .map(|x| buffer[(x, rect.y)].symbol())
                .collect();
            assert!(text.contains(label), "button text: {text}");
            app.interface_ui.editor.as_mut().unwrap().field = InterfaceEditorField::Cidr;
            focus_action(&mut app, slot);
            assert_eq!(app.interface_ui.editor.as_ref().unwrap().field, field);

            app.interface_ui.editor.as_mut().unwrap().offline_revision = None;
            app.interface_ui.editor.as_mut().unwrap().field = InterfaceEditorField::Save;
            app.ui.buttons.clear();
            terminal
                .draw(|frame| render_editor(frame, frame.area(), &mut app))
                .unwrap();
            assert!(!app.ui.buttons.iter().any(|(_, action)| [
                FORGET_BUTTON_SLOT,
                RESET_BUTTON_SLOT
            ]
            .contains(action)));
        }
    }
}

#[tokio::test]
async fn basic_editor_skips_hidden_mac_fields_and_keeps_review_visible() {
    use ratatui::{backend::TestBackend, Terminal};
    let mut editor = default_route_editor(false);
    editor.field = InterfaceEditorField::Advanced;
    let mut app = TuiApp {
        interface_ui: crate::tui::state::InterfaceUiState {
            editor: Some(editor),
            ..Default::default()
        },
        screen: Screen::InterfaceEditor,
        ..Default::default()
    };
    let client = ApiClient::new("/nonexistent.sock");
    handle_editor_key(&mut app, KeyCode::Tab, &client).await;
    assert_eq!(
        app.interface_ui.editor.as_ref().unwrap().field,
        InterfaceEditorField::Save
    );
    handle_editor_key(&mut app, KeyCode::BackTab, &client).await;
    handle_editor_key(&mut app, KeyCode::Enter, &client).await;
    handle_editor_key(&mut app, KeyCode::Tab, &client).await;
    assert_eq!(
        app.interface_ui.editor.as_ref().unwrap().field,
        InterfaceEditorField::MacAddress
    );
    app.interface_ui.editor.as_mut().unwrap().mac_address = "invalid".into();
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| super::super::render(frame, &mut app, false))
        .unwrap();
    let text: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(text.contains("Invalid MAC"));
    assert!(text.contains("Review changes"));
    assert!(app.ui.buttons.iter().any(|(_, slot)| *slot == 0));
}

#[tokio::test]
async fn offline_restore_requires_a_reported_file_and_device_definition() {
    let client = ApiClient::new("/must-not-connect.sock");
    let mut editor = default_route_editor(false);
    editor.offline_revision = Some(7);
    editor.field = InterfaceEditorField::Reset;
    let mut app = TuiApp {
        interface_ui: crate::tui::state::InterfaceUiState {
            editor: Some(editor),
            ..Default::default()
        },
        screen: Screen::InterfaceEditor,
        ..Default::default()
    };
    for base in [
        None,
        Some(traffic_masq_protocol::InterfaceBaseConfigView {
            file: None,
            interfaces: vec![],
        }),
        Some(traffic_masq_protocol::InterfaceBaseConfigView {
            file: Some("/custom/router.toml".into()),
            interfaces: vec![],
        }),
    ] {
        app.dashboard.base_config = base;
        handle_editor_key(&mut app, KeyCode::Enter, &client).await;
        assert!(app
            .interface_ui
            .editor
            .as_ref()
            .unwrap()
            .intent_confirmation
            .is_none());
        assert!(app
            .message
            .as_deref()
            .unwrap()
            .contains("Restore unavailable"));
    }
    app.dashboard.base_config = Some(traffic_masq_protocol::InterfaceBaseConfigView {
        file: Some("/custom/router.toml".into()),
        interfaces: vec!["wlan0".into()],
    });
    handle_editor_key(&mut app, KeyCode::Enter, &client).await;
    let restore = confirmation(&app).unwrap().lines.join(" ");
    assert!(restore.contains("/custom/router.toml"));
    assert!(restore.contains("when the device returns"));
    app.interface_ui
        .editor
        .as_mut()
        .unwrap()
        .intent_confirmation = Some(true);
    let delete = confirmation(&app).unwrap().lines.join(" ");
    assert!(delete.contains("suppress the base definition"));
    assert!(delete.contains("passwords are retained"));
    assert!(delete.contains("base file is not edited"));
}

#[tokio::test]
async fn interface_exit_keeps_or_discards_draft_with_keyboard_focus() {
    let client = ApiClient::new("/must-not-connect.sock");
    let mut editor = default_route_editor(false);
    editor.cidr = "192.0.2.99/24".into();
    let mut app = TuiApp {
        interface_ui: crate::tui::state::InterfaceUiState {
            editor: Some(editor),
            ..Default::default()
        },
        screen: Screen::InterfaceEditor,
        ..Default::default()
    };
    app.ui.input_enabled = true;
    handle_editor_key(&mut app, KeyCode::Esc, &client).await;
    assert!(app.interface_ui.editor.as_ref().unwrap().exit_requested);
    super::super::handle_key(&mut app, KeyCode::Enter, &client, false).await;
    assert_eq!(app.screen, Screen::InterfaceList);
    assert_eq!(
        app.interface_ui.interface_drafts["wlan0"].cidr,
        "192.0.2.99/24"
    );
    app.dashboard
        .interfaces
        .push(observed_address(None, Some(false)));
    app.dashboard.interfaces[0].interface.name = "wlan0".into();
    let refreshed = crate::tui::test_api::mock(vec![
        draft_inventory_response(traffic_masq_protocol::InterfacePresence::Present, 8, None),
        Response::InterfaceConfig {
            interface: "wlan0".into(),
            config: None,
            allow_management_change: false,
            wifi_concurrent_support: None,
        },
    ])
    .await;
    open_editor(&mut app, &refreshed.client).await;
    assert_eq!(app.screen, Screen::InterfaceEditor);
    assert_eq!(
        app.interface_ui.editor.as_ref().unwrap().cidr,
        "192.0.2.99/24"
    );
    assert!(app.interface_ui.interface_drafts.is_empty());
    handle_editor_key(&mut app, KeyCode::Esc, &client).await;
    super::super::handle_key(&mut app, KeyCode::BackTab, &client, false).await;
    assert_eq!(app.confirmation.confirmation_focus, 2);
    super::super::handle_key(&mut app, KeyCode::Enter, &client, false).await;
    assert!(app.interface_ui.editor.is_none());
    assert!(app.interface_ui.interface_drafts.is_empty());
    assert_eq!(app.screen, Screen::InterfaceList);
}

#[tokio::test]
async fn failed_save_and_background_refresh_keep_the_interface_draft_and_revision() {
    let mock = crate::tui::test_api::mock(vec![Response::Error {
        message: "stale revision; refresh before saving".into(),
    }])
    .await;
    let mut editor = default_route_editor(true);
    editor.offline_revision = Some(7);
    editor.cidr = "192.0.2.99/24".into();
    editor.saved_config = Some(
        serde_json::from_value(
            serde_json::json!({"role":"output", "managed":true, "ipv4":"192.168.1.10/24"}),
        )
        .unwrap(),
    );
    let mut app = TuiApp {
        interface_ui: crate::tui::state::InterfaceUiState {
            editor: Some(editor),
            ..Default::default()
        },
        screen: Screen::InterfaceEditor,
        ..Default::default()
    };
    submit_dry_run(&mut app, &mock.client).await;
    assert_eq!(app.screen, Screen::InterfaceEditor);
    super::super::dashboard::accept_update(
        &mut app,
        super::super::DashboardData {
            intent_revision: Some(8),
            inventory: Some(vec![]),
            ..Default::default()
        },
    );
    let editor = app.interface_ui.editor.as_ref().unwrap();
    assert_eq!(editor.cidr, "192.0.2.99/24");
    assert_eq!(editor.offline_revision, Some(7));
    assert!(app.message.as_deref().unwrap().contains("stale revision"));
}

#[tokio::test]
async fn validation_focus_exposes_mac_error_and_plan_wrap_preserves_actions() {
    use ratatui::{backend::TestBackend, Terminal};
    let client = ApiClient::new("/must-not-connect.sock");
    for (width, height) in [(80, 24), (120, 38)] {
        let mut editor = default_route_editor(true);
        editor.mac_address = "invalid".into();
        editor.interface = "a-very-long-interface-name-to-check-review-and-error-layout".into();
        let mut app = TuiApp {
            interface_ui: crate::tui::state::InterfaceUiState {
                editor: Some(editor),
                ..Default::default()
            },
            screen: Screen::InterfaceEditor,
            ..Default::default()
        };
        submit_dry_run(&mut app, &client).await;
        assert!(app.interface_ui.editor.as_ref().unwrap().advanced);
        assert_eq!(
            app.interface_ui.editor.as_ref().unwrap().field,
            InterfaceEditorField::MacAddress
        );
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| super::super::render(frame, &mut app, false))
            .unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(text.contains("Invalid MAC"));
        assert!(text.contains("Review changes"));
    }
}

fn draft_inventory_response(
    presence: traffic_masq_protocol::InterfacePresence,
    revision: u64,
    config: Option<traffic_masq_protocol::InterfaceConfigView>,
) -> Response {
    use traffic_masq_protocol::{
        InterfaceConfigSource, InterfaceInventoryEntry, InterfacePresence, InterfaceReadiness,
    };
    let mut observed = observed_address(None, Some(false));
    observed.interface.name = "wlan0".into();
    Response::InterfaceInventory {
        base_config: None,
        revision,
        suppressed_interfaces: vec![],
        observation_error: None,
        interfaces: vec![InterfaceInventoryEntry {
            name: "wlan0".into(),
            observed: (presence == InterfacePresence::Present).then_some(observed),
            configured: config,
            config_source: InterfaceConfigSource::Override,
            presence,
            readiness: InterfaceReadiness::Ready,
            blockers: vec![],
            references: vec![],
            suppressed: false,
            observation_stale: false,
        }],
    }
}

#[tokio::test]
async fn resumed_interface_draft_refreshes_execution_mode_revision_and_review_baseline() {
    use traffic_masq_protocol::{DhcpChangeActionView, InterfaceChangePlanView, InterfacePresence};
    for presence in [InterfacePresence::Present, InterfacePresence::Missing] {
        let mut draft = default_route_editor(false);
        draft.offline_revision = (presence == InterfacePresence::Present).then_some(7);
        draft.cidr = "192.0.2.99/24".into();
        draft.mac_address = "02:11:22:33:44:55".into();
        draft.field = InterfaceEditorField::Reset;
        let config = serde_json::from_value(serde_json::json!({
            "role":"input","managed":true,"ipv4":"192.0.2.2/24","mac_address":"02:aa:bb:cc:dd:ee"
        }))
        .unwrap();
        let response = if presence == InterfacePresence::Present {
            Response::InterfacePlan {
                plan: InterfaceChangePlanView {
                    interface: "wlan0".into(),
                    mac_address: None,
                    delete_ipv4: vec![],
                    retag_ipv4: None,
                    add_ipv4: None,
                    set_link_up: false,
                    management_change: false,
                    dhcp_action: DhcpChangeActionView::Unchanged,
                    releasing_management: false,
                },
            }
        } else {
            Response::InterfaceIntentSaved {
                interface: "wlan0".into(),
                revision: 10,
                deferred: true,
                missing_dependencies: vec!["wlan0".into()],
            }
        };
        let mut responses = vec![draft_inventory_response(presence, 9, Some(config))];
        if presence == InterfacePresence::Present {
            responses.push(Response::InterfaceConfig {
                interface: "wlan0".into(),
                config: None,
                allow_management_change: false,
                wifi_concurrent_support: None,
            });
        }
        responses.push(response);
        let mock = crate::tui::test_api::mock(responses).await;
        let mut app = TuiApp {
            screen: Screen::InterfaceList,
            ..Default::default()
        };
        let mut status = observed_address(None, Some(false));
        status.interface.name = "wlan0".into();
        app.dashboard.interfaces.push(status);
        app.interface_ui
            .interface_drafts
            .insert("wlan0".into(), draft);
        open_editor(&mut app, &mock.client).await;
        let editor = app.interface_ui.editor.as_ref().unwrap();
        assert_eq!(
            editor.offline_revision,
            (presence == InterfacePresence::Missing).then_some(9)
        );
        assert_eq!(editor.cidr, "192.0.2.99/24");
        assert_eq!(editor.mac_address, "02:11:22:33:44:55");
        assert_eq!(editor.original_cidr, "192.0.2.2/24");
        assert_eq!(editor.original_mac, "02:aa:bb:cc:dd:ee");
        assert_eq!(
            editor.role,
            InterfaceRole::Input,
            "unchanged fields should follow current config"
        );
        assert!(app.interface_ui.interface_drafts.is_empty());
        if presence == InterfacePresence::Present {
            assert_eq!(editor.field, InterfaceEditorField::Save);
        }
        submit_dry_run(&mut app, &mock.client).await;
        let calls = mock.calls.lock().unwrap();
        let submit_index = if presence == InterfacePresence::Present {
            2
        } else {
            1
        };
        assert_eq!(calls.len(), submit_index + 1);
        assert_eq!(
            calls[submit_index].body["type"],
            if presence == InterfacePresence::Present {
                "dry_run_interface_edit"
            } else {
                "save_interface_config"
            }
        );
        if presence == InterfacePresence::Missing {
            assert_eq!(calls[submit_index].body["expected_revision"], 9);
        }
    }
}

#[tokio::test]
async fn failed_draft_observation_keeps_edits_and_does_not_open_stale_editor() {
    use traffic_masq_protocol::InterfacePresence;
    let mut stale = draft_inventory_response(InterfacePresence::Present, 9, None);
    if let Response::InterfaceInventory { interfaces, .. } = &mut stale {
        interfaces[0].observation_stale = true;
    }
    let mut failed = draft_inventory_response(InterfacePresence::Missing, 9, None);
    if let Response::InterfaceInventory {
        observation_error, ..
    } = &mut failed
    {
        *observation_error = Some("netlink failed".into());
    }
    for response in [
        Response::Error {
            message: "unavailable".into(),
        },
        draft_inventory_response(InterfacePresence::Unknown, 9, None),
        stale,
        failed,
    ] {
        let mock = crate::tui::test_api::mock(vec![response]).await;
        let mut app = TuiApp {
            screen: Screen::InterfaceList,
            ..Default::default()
        };
        let mut status = observed_address(None, Some(false));
        status.interface.name = "wlan0".into();
        app.dashboard.interfaces.push(status);
        let mut draft = default_route_editor(true);
        draft.cidr = "192.0.2.99/24".into();
        draft.offline_revision = Some(7);
        app.interface_ui
            .interface_drafts
            .insert("wlan0".into(), draft);
        open_editor(&mut app, &mock.client).await;
        assert_eq!(app.screen, Screen::InterfaceList);
        assert!(app.interface_ui.editor.is_none());
        assert_eq!(
            app.interface_ui.interface_drafts["wlan0"].cidr,
            "192.0.2.99/24"
        );
        assert_eq!(
            app.interface_ui.interface_drafts["wlan0"].offline_revision,
            Some(7)
        );
        assert_eq!(mock.calls.lock().unwrap().len(), 1);
    }
}

#[test]
fn receive_and_share_is_preserved_in_interface_edit_request() {
    let mut editor = default_route_editor(true);
    editor.managed = true;
    editor.role = InterfaceRole::Input;
    editor.wifi_concurrent = true;
    let request = editor.edit_request().unwrap();
    assert!(request.wifi_concurrent);
    assert_eq!(request.role, InterfaceRole::Input);
    assert!(editor.dirty());
}

#[tokio::test]
async fn returning_wifi_adapter_refreshes_combined_role_support_for_offline_draft() {
    use traffic_masq_protocol::{InterfacePresence, WifiConcurrentSupport};
    let mut inventory = draft_inventory_response(InterfacePresence::Present, 8, None);
    if let Response::InterfaceInventory { interfaces, .. } = &mut inventory {
        interfaces[0]
            .observed
            .as_mut()
            .unwrap()
            .interface
            .is_wireless = true;
    }
    let mock = super::super::test_api::mock(vec![
        inventory,
        Response::InterfaceConfig {
            interface: "wlan0".into(),
            config: None,
            allow_management_change: false,
            wifi_concurrent_support: Some(WifiConcurrentSupport {
                supported: true,
                reason: None,
            }),
        },
    ])
    .await;
    let mut draft = unmanaged_editor();
    draft.interface = "wlan0".into();
    draft.offline_revision = Some(7);
    draft.wifi_concurrent_support = None;
    let mut app = TuiApp::default();
    let mut observed = observed_address(None, Some(false));
    observed.interface.name = "wlan0".into();
    app.dashboard.interfaces.push(observed);
    app.interface_ui
        .interface_drafts
        .insert("wlan0".into(), draft);

    open_editor(&mut app, &mock.client).await;

    let editor = app.interface_ui.editor.as_mut().unwrap();
    assert_eq!(editor.offline_revision, None);
    editor.role = InterfaceRole::Output;
    editor.cycle_role();
    assert!(editor.wifi_concurrent);
    assert!(editor.managed);
    assert_eq!(editor.role, InterfaceRole::Input);
    let calls = mock.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1].body["type"], "get_interface_config");
}

#[tokio::test]
async fn combined_role_keyboard_selection_requires_driver_support_and_enables_management() {
    for supported in [false, true] {
        let mut editor = unmanaged_editor();
        editor.role = InterfaceRole::Output;
        editor.field = InterfaceEditorField::Role;
        editor.wifi_concurrent_support = Some(traffic_masq_protocol::WifiConcurrentSupport {
            supported,
            reason: (!supported).then(|| "driver does not support AP + STA".into()),
        });
        let mut app = TuiApp {
            interface_ui: crate::tui::state::InterfaceUiState {
                editor: Some(editor),
                ..Default::default()
            },
            ..Default::default()
        };
        let client = ApiClient::new("/unused-role-test.sock");
        handle_editor_key(&mut app, KeyCode::Enter, &client).await;
        let editor = app.interface_ui.editor.as_ref().unwrap();
        assert_eq!(editor.wifi_concurrent, supported);
        assert_eq!(
            editor.role,
            if supported {
                InterfaceRole::Input
            } else {
                InterfaceRole::None
            }
        );
        if supported {
            assert!(editor.managed);
            assert_eq!(
                role_label(editor.role, editor.wifi_concurrent),
                "Input + Output"
            );
            app.interface_ui
                .editor
                .as_mut()
                .unwrap()
                .allow_management_change = true;
            let request = app
                .interface_ui
                .editor
                .as_ref()
                .unwrap()
                .edit_request()
                .unwrap();
            assert!(request.wifi_concurrent);
            assert_eq!(request.role, InterfaceRole::Input);
            handle_editor_key(&mut app, KeyCode::Char(' '), &client).await;
            assert!(!app.interface_ui.editor.as_ref().unwrap().wifi_concurrent);
            assert_eq!(
                app.interface_ui.editor.as_ref().unwrap().role,
                InterfaceRole::None
            );
        }
    }
}

#[test]
fn saved_combined_role_can_be_left_when_adapter_support_is_unavailable() {
    let mut editor = default_route_editor(true);
    editor.role = InterfaceRole::Input;
    editor.wifi_concurrent = true;
    editor.wifi_concurrent_support = None;
    editor.cycle_role();
    assert_eq!(editor.role, InterfaceRole::None);
    assert!(!editor.wifi_concurrent);
    editor.role = InterfaceRole::Output;
    editor.cycle_role();
    assert_eq!(
        editor.role,
        InterfaceRole::None,
        "unknown support must not offer a combined role"
    );
}

#[tokio::test]
async fn opening_editor_uses_daemon_capability_and_restores_saved_combined_role() {
    let config: traffic_masq_protocol::InterfaceConfigView = serde_json::from_value(
        serde_json::json!({"role": "input", "managed": true, "wifi_concurrent": true}),
    )
    .unwrap();
    let support = traffic_masq_protocol::WifiConcurrentSupport {
        supported: true,
        reason: None,
    };
    let mock = super::super::test_api::mock(vec![Response::InterfaceConfig {
        interface: "wlp1s0".into(),
        config: Some(config),
        allow_management_change: false,
        wifi_concurrent_support: Some(support.clone()),
    }])
    .await;
    let mut app = TuiApp::default();
    app.dashboard
        .interfaces
        .push(observed_address(None, Some(false)));
    open_editor(&mut app, &mock.client).await;
    let editor = app.interface_ui.editor.as_ref().unwrap();
    assert_eq!(editor.wifi_concurrent_support, Some(support));
    assert_eq!(
        role_label(editor.role, editor.wifi_concurrent),
        "Input + Output"
    );
}
