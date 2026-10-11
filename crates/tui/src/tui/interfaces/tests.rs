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
                        assert_eq!(request.method(), hyper::Method::PUT);
                        assert_eq!(request.uri().path(), "/api/v1/interfaces/wlan0/intent");
                        let body: serde_json::Value = serde_json::from_slice(
                            &request.into_body().collect().await.unwrap().to_bytes(),
                        )
                        .unwrap();
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
        screen: Screen::InterfaceEditor,
        editor: Some(editor),
        ..Default::default()
    };
    let client = ApiClient::new(socket);
    handle_editor_key(&mut app, KeyCode::Enter, &client).await;
    server.await.unwrap();
    assert_eq!(app.screen, Screen::InterfaceList);
    assert!(app.pending.is_none());
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
        mac_address: None,
        managed: false,
        role: InterfaceRole::None,
        ipv4: None,
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
        nat: true,
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
async fn keyboard_ip_edit_previews_applies_and_confirms_the_typed_address() {
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
            interface: "wlp1s0".into(),
            config: None,
            allow_management_change: false,
        },
        Response::InterfacePlan {
            plan: traffic_masq_protocol::InterfaceChangePlanView {
                mac_address: None,
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
                            let path = request.uri().path().to_owned();
                            let method = request.method().clone();
                            let bytes = request.into_body().collect().await.unwrap().to_bytes();
                            let payload: serde_json::Value = if method == hyper::Method::GET {
                                assert!(bytes.is_empty());
                                serde_json::Value::Null
                            } else {
                                assert_eq!(method, hyper::Method::POST);
                                serde_json::from_slice(&bytes).unwrap()
                            };
                            requests.lock().await.push((path, payload));
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
    let mut status = observed_address(None, Some(false));
    status.ipv4_addresses.clear();
    app.dashboard.interfaces.push(status);
    open_editor(&mut app, &client).await;
    assert_eq!(app.screen, Screen::InterfaceEditor);
    assert!(app.editor.as_ref().unwrap().managed);
    for character in "198.18.0.1/24".chars() {
        handle_editor_key(&mut app, KeyCode::Char(character), &client).await;
    }
    submit_dry_run(&mut app, &client).await;
    assert_eq!(app.screen, Screen::Preview);
    handle_preview_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(app.screen, Screen::PendingChange);
    handle_pending_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(app.screen, Screen::InterfaceList);
    assert!(app.pending.is_none());
    server.await.unwrap();
    let requests = requests.lock().await;
    assert_eq!(requests[0].0, "/api/v1/interfaces/wlp1s0/config");
    let requests = &requests[1..];
    assert_eq!(requests[0].0, "/api/v1/interfaces/wlp1s0/edit/plan");
    assert_eq!(requests[1].0, "/api/v1/interfaces/wlp1s0/edit/apply");
    for (_, body) in &requests[..2] {
        assert_eq!(body["cidr"], "198.18.0.1/24");
        assert_eq!(body["managed"], true);
    }
    assert_eq!(requests[2].0, "/api/v1/network-transactions/commit");
    assert_eq!(requests[2].1["token"], "ip-test-token");
}

fn default_route_editor(allow_management_change: bool) -> InterfaceEditor {
    InterfaceEditor {
        mac_address: None,
        saved_config: None,
        offline_revision: None,
        intent_confirmation: None,
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

#[tokio::test]
async fn random_mac_is_local_unicast_and_kept_in_the_apply_request() {
    let mut editor = default_route_editor(true);
    editor.field = InterfaceEditorField::RandomizeMac;
    editor.allow_management_change = true;
    let mut app = TuiApp {
        editor: Some(editor),
        ..Default::default()
    };
    let client = ApiClient::new(std::path::PathBuf::from("/unused-mac-test.sock"));
    handle_editor_key(&mut app, KeyCode::Enter, &client).await;
    let editor = app.editor.as_ref().unwrap();
    let mac = editor.mac_address.unwrap();
    assert_eq!(mac.octets()[0] & 3, 2);
    assert_eq!(editor.edit_request().unwrap().mac_address, Some(mac));
    handle_editor_key(&mut app, KeyCode::Enter, &client).await;
    assert_ne!(app.editor.as_ref().unwrap().mac_address, Some(mac));
}
