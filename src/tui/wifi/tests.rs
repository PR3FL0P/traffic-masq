use super::*;

async fn mock_api(
    responses: Vec<Response>,
) -> (
    tempfile::TempDir,
    ApiClient,
    tokio::task::JoinHandle<Vec<String>>,
) {
    use http_body_util::{BodyExt, Full};
    use hyper::{body::Bytes, server::conn::http1, service::service_fn};
    use hyper_util::rt::TokioIo;
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("api.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let paths = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
        for response in responses {
            let (stream, _) =
                tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
            let body = serde_json::to_vec(&response).unwrap();
            let paths = paths.clone();
            http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                        let paths = paths.clone();
                        let body = body.clone();
                        async move {
                            paths.lock().await.push(format!(
                                "{} {}",
                                request.method(),
                                request.uri().path()
                            ));
                            request.into_body().collect().await.unwrap();
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                                Bytes::from(body),
                            )))
                        }
                    }),
                )
                .await
                .unwrap();
        }
        let result = paths.lock().await.clone();
        result
    });
    (directory, ApiClient::new(socket), server)
}

fn radio(name: &str) -> WifiRow {
    WifiRow {
        interface: name.into(),
        role: WifiRole::Client,
        ap: None,
        client: None,
    }
}

#[test]
fn refresh_preserves_radio_and_action_identity() {
    let mut app = TuiApp::default();
    app.wifi.rows = vec![radio("wlan0"), radio("wlan1")];
    open_radio(&mut app, 1);
    focus_action(&mut app, 2);
    app.wifi.replace_rows(vec![radio("wlan1")]);
    assert_eq!(app.wifi.selected_radio, 0);
    assert_eq!(app.wifi.selected, 3);
    assert!(app.wifi.actions_open);
    let mut changed_role = radio("wlan1");
    changed_role.role = WifiRole::AccessPoint;
    app.wifi.replace_rows(vec![changed_role]);
    assert!(!app.wifi.actions_open);
    assert_eq!(app.wifi.selected, 0);
    app.wifi.replace_rows(Vec::new());
    assert_eq!(app.wifi.selected, 0);
}

#[tokio::test]
async fn radio_actions_scroll_and_return_to_the_original_radio() {
    let client = ApiClient::new("/nonexistent.sock");
    let mut app = TuiApp {
        screen: Screen::Wifi,
        ..Default::default()
    };
    app.wifi.rows = (0..20).map(|i| radio(&format!("wlan{i}"))).collect();
    app.wifi.selected = 19;
    app.wifi.selected_radio = 19;
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| super::super::render(frame, &mut app, false))
        .unwrap();
    assert!(app.ui.list_scroll_offset > 0);
    let area = app.ui.list_area.unwrap();
    assert!(area.bottom() <= 20);
    super::super::handle_key(&mut app, KeyCode::Tab, &client, false).await;
    assert!(app.wifi.actions_open);
    handle_wifi_key(&mut app, KeyCode::End, &client).await;
    terminal
        .draw(|frame| super::super::render(frame, &mut app, false))
        .unwrap();
    for (rect, _) in &app.ui.buttons {
        assert!(rect.bottom() <= 20);
    }
    assert!(app
        .ui
        .buttons
        .iter()
        .any(|(_, slot)| *slot == actions(WifiRole::Client).len() - 1));
    handle_wifi_key(&mut app, KeyCode::Esc, &client).await;
    app.wifi.selected = 2;
    app.wifi.selected_radio = 2;
    handle_wifi_key(&mut app, KeyCode::Tab, &client).await;
    handle_wifi_key(&mut app, KeyCode::Up, &client).await;
    assert_eq!(app.wifi.selected, 2);
    assert_eq!(app.wifi.selected_radio, 2);
}

#[tokio::test]
async fn connect_navigation_does_not_change_choice_or_submit() {
    let mut app = TuiApp {
        screen: Screen::WifiConnectPrompt,
        wifi_connect: Some(WifiConnectPrompt::new(
            "wlan0".into(),
            "home".into(),
            "Home".into(),
            None,
        )),
        ..Default::default()
    };
    let client = ApiClient::new("/nonexistent.sock");
    handle_wifi_connect_prompt_key(&mut app, KeyCode::Down, &client).await;
    assert_eq!(
        app.wifi_connect.as_ref().unwrap().choice,
        WifiIpChoice::Dhcp
    );
    handle_wifi_connect_prompt_key(&mut app, KeyCode::Up, &client).await;
    handle_wifi_connect_prompt_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(
        app.wifi_connect.as_ref().unwrap().field,
        WifiConnectField::Submit
    );
    assert!(app.message.is_none());
    let prompt = app.wifi_connect.as_mut().unwrap();
    prompt.choice = WifiIpChoice::NewStatic;
    prompt.current_static_ip = Some("192.168.1.5/24".into());
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| super::super::render(frame, &mut app, false))
        .unwrap();
    assert_eq!(app.ui.buttons.len(), 2);
    for (rect, _) in &app.ui.buttons {
        assert!(rect.bottom() <= 20);
    }
    let (rect, _) = app.ui.buttons[1];
    super::super::handle_mouse(
        &mut app,
        crossterm::event::MouseEvent {
            kind: crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
            column: rect.x,
            row: rect.y,
            modifiers: crossterm::event::KeyModifiers::NONE,
        },
        &client,
        false,
    )
    .await;
    assert!(app.wifi_connect.is_none());
}

#[tokio::test]
async fn dhcp_is_configured_before_profile_activation() {
    use crate::api::model::{DhcpClientOperationalState, DhcpClientStatusView};
    let (_directory, client, server) = mock_api(vec![
        Response::DhcpClientInterface {
            status: DhcpClientStatusView {
                interface: "wlan0".into(),
                state: DhcpClientOperationalState::Waiting,
                address: None,
                prefix_length: None,
                server: None,
                expires_at_unix: None,
                dns_servers: Vec::new(),
                degraded_reason: None,
                config: Default::default(),
            },
        },
        Response::Error {
            message: "activation failed".into(),
        },
    ])
    .await;
    let mut app = TuiApp {
        screen: Screen::WifiConnectPrompt,
        wifi_connect: Some(WifiConnectPrompt::new(
            "wlan0".into(),
            "home".into(),
            "Home".into(),
            None,
        )),
        ..Default::default()
    };
    submit_wifi_connect(&mut app, &client).await;
    let paths = server.await.unwrap();
    assert_eq!(paths[0], "PUT /api/v1/dhcp-client/wlan0");
    assert!(paths[1].ends_with("/active-profile"));
    assert!(app.wifi_connect.is_some());
    assert!(app
        .message
        .as_deref()
        .unwrap()
        .contains("IP configuration was updated"));
}

#[tokio::test]
async fn failed_dhcp_stop_blocks_static_edit_and_activation() {
    let (_directory, client, server) = mock_api(vec![Response::DhcpClientError {
        detail: crate::api::model::DhcpClientErrorDetail::OwnershipConflict {
            message: "not owned".into(),
        },
    }])
    .await;
    let mut prompt = WifiConnectPrompt::new("wlan0".into(), "home".into(), "Home".into(), None);
    prompt.choice = WifiIpChoice::NewStatic;
    prompt.static_cidr = "192.168.1.5/24".into();
    let mut app = TuiApp {
        screen: Screen::WifiConnectPrompt,
        wifi_connect: Some(prompt),
        ..Default::default()
    };
    submit_wifi_connect(&mut app, &client).await;
    assert_eq!(
        server.await.unwrap(),
        vec!["DELETE /api/v1/dhcp-client/wlan0"]
    );
    assert_eq!(app.screen, Screen::WifiConnectPrompt);
    assert!(app.message.as_deref().unwrap().contains("not stopped"));
}

#[tokio::test]
async fn static_ip_is_committed_before_profile_activation() {
    let change = crate::core::transaction::PendingNetworkChange {
        token: "static-token".into(),
        interface: "wlan0".into(),
        rollback_timeout_seconds: 60,
        expires_at_unix: super::super::current_unix_time() + 60,
    };
    let (_directory, client, server) = mock_api(vec![
        Response::DhcpClientDisabled {
            interface: "wlan0".into(),
        },
        Response::NetworkChangePending {
            change: change.clone(),
        },
        Response::NetworkChangeCommitted { change },
        Response::Error {
            message: "activation failed".into(),
        },
    ])
    .await;
    let mut prompt = WifiConnectPrompt::new("wlan0".into(), "home".into(), "Home".into(), None);
    prompt.choice = WifiIpChoice::NewStatic;
    prompt.static_cidr = "192.168.1.5/24".into();
    let mut app = TuiApp {
        screen: Screen::WifiConnectPrompt,
        wifi_connect: Some(prompt),
        ..Default::default()
    };
    submit_wifi_connect(&mut app, &client).await;
    let paths = server.await.unwrap();
    assert_eq!(paths.len(), 4);
    assert_eq!(paths[0], "DELETE /api/v1/dhcp-client/wlan0");
    assert_eq!(paths[1], "POST /api/v1/interfaces/wlan0/edit/apply");
    assert_eq!(paths[2], "POST /api/v1/network-transactions/commit");
    assert!(paths[3].ends_with("/active-profile"));
    assert!(app.wifi_connect.is_some());
}

#[tokio::test]
async fn failed_static_commit_retains_pending_transaction() {
    let change = crate::core::transaction::PendingNetworkChange {
        token: "pending-token".into(),
        interface: "wlan0".into(),
        rollback_timeout_seconds: 60,
        expires_at_unix: super::super::current_unix_time() + 60,
    };
    let (_directory, client, server) = mock_api(vec![
        Response::NetworkChangePending { change },
        Response::Error {
            message: "commit rejected".into(),
        },
    ])
    .await;
    let mut app = TuiApp::default();
    assert!(!apply_wifi_static_ip(&mut app, &client, "wlan0", "192.168.1.5/24").await);
    assert_eq!(server.await.unwrap().len(), 2);
    assert_eq!(app.screen, Screen::PendingChange);
    assert_eq!(app.pending.as_ref().unwrap().token, "pending-token");
}

fn scan(
    ssid: &str,
    signal: i32,
    security: WpaSupplicantScanSecurity,
    mac: &str,
) -> WpaSupplicantScanResult {
    WpaSupplicantScanResult {
        bssid: mac.parse().unwrap(),
        frequency_mhz: 2412,
        signal_dbm: signal,
        ssid: ssid.into(),
        raw_flags: String::new(),
        security,
    }
}

#[tokio::test]
async fn ap_options_open_only_on_activation_and_radio_edits_reach_request() {
    let mut app = TuiApp::default();
    app.wifi.rows.push(WifiRow {
        interface: "wlan0".into(),
        role: WifiRole::AccessPoint,
        ap: None,
        client: None,
    });
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| render_wifi(frame, frame.area(), &mut app))
        .unwrap();
    let text: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(!text.contains("Configure access point"));
    assert_eq!(app.wifi.selected, 0);
    let client = ApiClient::new("/nonexistent.sock");
    handle_wifi_key(&mut app, KeyCode::Down, &client).await;
    assert!(!app.wifi.actions_open);
    handle_wifi_key(&mut app, KeyCode::Enter, &client).await;
    terminal
        .draw(|frame| render_wifi(frame, frame.area(), &mut app))
        .unwrap();
    let text: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(text.contains("Configure access point"));
    handle_wifi_key(&mut app, KeyCode::Esc, &client).await;
    assert!(!app.wifi.actions_open);
    app.wifi_editor = Some(WifiEditor::from_row(&app.wifi.rows[0]));
    let client = ApiClient::new("/nonexistent.sock");
    for field in [
        WifiField::Band,
        WifiField::Channel,
        WifiField::Hidden,
        WifiField::ClientIsolation,
        WifiField::MaxStations,
    ] {
        app.wifi_editor.as_mut().unwrap().field = field;
        handle_wifi_editor_key(&mut app, KeyCode::Enter, &client).await;
    }
    let editor = app.wifi_editor.as_mut().unwrap();
    editor.ssid = "Updated SSID".into();
    let Request::ProvisionWifiAccessPoint { settings, .. } = ap_provision_request(editor) else {
        panic!("wrong request")
    };
    assert_eq!(settings.band, WifiBand::Ghz5);
    assert_eq!(settings.channel, 32);
    assert!(settings.hidden && settings.client_isolation);
    assert_eq!(settings.max_stations, 33);
    assert_eq!(settings.ssid, "Updated SSID");
}

#[test]
fn scan_sort_is_strongest_first_hidden_last_and_stable_by_identity() {
    let mut rows = vec![
        scan(
            "",
            -20,
            WpaSupplicantScanSecurity::Open,
            "00:00:00:00:00:04",
        ),
        scan(
            "weak",
            -80,
            WpaSupplicantScanSecurity::Open,
            "00:00:00:00:00:03",
        ),
        scan(
            "same",
            -40,
            WpaSupplicantScanSecurity::Open,
            "00:00:00:00:00:02",
        ),
        scan(
            "same",
            -40,
            WpaSupplicantScanSecurity::Open,
            "00:00:00:00:00:01",
        ),
    ];
    sort_scan_results(&mut rows);
    assert_eq!(
        rows.iter().map(|r| r.ssid.as_str()).collect::<Vec<_>>(),
        vec!["same", "same", "weak", ""]
    );
    assert_eq!(rows[0].bssid.to_string(), "00:00:00:00:00:01");
}

#[test]
fn scan_security_maps_supported_and_refuses_enterprise_and_unknown() {
    assert_eq!(
        map_scan_security(WpaSupplicantScanSecurity::Wpa2Psk),
        Ok(WifiClientSecurity::Wpa2)
    );
    assert_eq!(
        map_scan_security(WpaSupplicantScanSecurity::Wpa3Sae),
        Ok(WifiClientSecurity::Wpa3)
    );
    assert!(map_scan_security(WpaSupplicantScanSecurity::EnterpriseOrUnsupported).is_err());
    assert!(map_scan_security(WpaSupplicantScanSecurity::Unknown).is_err());
}

#[test]
fn profile_editor_builds_create_and_update_payload_without_echoing_saved_secret() {
    let editor = WifiProfileEditor {
        interface: "wlan0".into(),
        original_id: Some("home".into()),
        field: ProfileField::Save,
        id: "home".into(),
        ssid: "Home".into(),
        security: WifiClientSecurity::Wpa2,
        country: " pl ".into(),
        priority: "10".into(),
        autoconnect: false,
        passphrase: String::new(),
        has_passphrase: true,
        cursor: 0,
    };
    let request = editor.request().unwrap();
    assert_eq!(request.country_code.as_deref(), Some("PL"));
    assert_eq!(request.priority, 10);
    assert!(request.passphrase.is_none());
}

#[test]
fn ap_request_is_atomic_and_enables_derived_dhcp_by_default() {
    let row = WifiRow {
        interface: "wlan0".into(),
        role: WifiRole::AccessPoint,
        ap: None,
        client: None,
    };
    let editor = WifiEditor::from_row(&row);
    let settings = ap_settings(&editor);
    assert_eq!(settings.ssid, "traffic-masq");
    assert_eq!(settings.band, WifiBand::Ghz2);
    assert_eq!(settings.channel, 0);
    assert_eq!(settings.channel_width, WifiChannelWidth::Ht20);
    assert_eq!(settings.security, WifiSecurity::Wpa2);
    assert_eq!(settings.max_stations, 32);
    assert!(!settings.hidden && !settings.client_isolation);
    assert!(editor.configure_dhcp);
    assert!(matches!(
        ap_provision_request(&editor),
        Request::ProvisionWifiAccessPoint {
            configure_dhcp: true,
            ..
        }
    ));
}

#[tokio::test]
async fn ap_apply_enters_shared_commit_confirm_screen() {
    let change = crate::core::transaction::PendingNetworkChange {
        token: "ap-token".into(),
        interface: "wlan0".into(),
        rollback_timeout_seconds: 60,
        expires_at_unix: super::super::current_unix_time() + 60,
    };
    let (_directory, client, server) = mock_api(vec![Response::NetworkChangePending {
        change: change.clone(),
    }])
    .await;
    let row = WifiRow {
        interface: "wlan0".into(),
        role: WifiRole::AccessPoint,
        ap: None,
        client: None,
    };
    let mut editor = WifiEditor::from_row(&row);
    editor.passphrase = "correct horse battery".into();
    editor.field = WifiField::Apply;
    let mut app = TuiApp {
        screen: Screen::WifiEditor,
        wifi_editor: Some(editor),
        ..Default::default()
    };

    handle_wifi_editor_key(&mut app, KeyCode::Enter, &client).await;

    assert_eq!(
        server.await.unwrap(),
        vec!["POST /api/v1/wifi/wlan0/provision"]
    );
    assert_eq!(app.screen, Screen::PendingChange);
    assert_eq!(app.pending_return_screen, Screen::Wifi);
    assert_eq!(app.pending, Some(change));
    assert!(app.wifi_editor.is_none());
}

#[test]
fn existing_ap_request_preserves_unedited_radio_settings() {
    let row = WifiRow {
        interface: "wlan0".into(),
        role: WifiRole::AccessPoint,
        ap: None,
        client: None,
    };
    let mut editor = WifiEditor::from_row(&row);
    editor.original_spec = Some(crate::wifi::WifiApSpec {
        interface: "wlan0".into(),
        ssid: "old".into(),
        country_code: Some("US".into()),
        band: WifiBand::Ghz5,
        channel: 36,
        channel_width: WifiChannelWidth::Ht20,
        security: WifiSecurity::Wpa2,
        hidden: true,
        client_isolation: true,
        max_stations: 7,
        passphrase_file: None,
    });
    editor.existing = true;
    editor.configure_dhcp = false;
    editor.ssid = "new".into();
    if let Request::ProvisionWifiAccessPoint {
        settings,
        configure_dhcp,
        ..
    } = ap_provision_request(&editor)
    {
        assert_eq!(settings.ssid, "new");
        assert_eq!(settings.band, WifiBand::Ghz5);
        assert_eq!(settings.channel, 36);
        assert!(settings.hidden && settings.client_isolation);
        assert_eq!(settings.max_stations, 7);
        assert!(!configure_dhcp);
    } else {
        panic!("wrong request");
    }
    editor.passphrase = "never-print-this".into();
    assert!(!format!("{editor:?}").contains("never-print-this"));
}

#[test]
fn scan_scrolls_selected_network_into_view() {
    let mut app = TuiApp {
        wifi_scan: Some(WifiScanPicker {
            interface: "wlan0".into(),
            networks: (0..40)
                .map(|i| {
                    scan(
                        &format!("network-{i}"),
                        -40,
                        WpaSupplicantScanSecurity::Open,
                        "00:00:00:00:00:01",
                    )
                })
                .collect(),
            selected: 39,
        }),
        ..Default::default()
    };
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| render_wifi_scan(frame, frame.area(), &mut app))
        .unwrap();
    let text: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(text.contains("network-39"));
    assert!(app.ui.list_scroll_offset > 0);
}

#[tokio::test]
async fn long_profile_list_keeps_delete_visible_and_requires_confirmation() {
    let mut app = TuiApp {
        wifi_profiles: Some(WifiProfilesView {
            interface: "wlan0".into(),
            mode: WifiProfilesMode::Management,
            selected: 39,
            selected_profile: 39,
            delete_confirmation: None,
            profiles: (0..40)
                .map(|i| WifiClientProfileSummary {
                    id: format!("p{i}"),
                    ssid: format!("network{i}"),
                    country_code: None,
                    security: WifiClientSecurity::Open,
                    priority: 0,
                    autoconnect: false,
                    created_at: 0,
                    modified_at: 0,
                    has_passphrase: false,
                })
                .collect(),
        }),
        ..Default::default()
    };
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| render_wifi_profiles(frame, frame.area(), &mut app))
        .unwrap();
    let text: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(text.contains("p39"));
    assert!(!text.contains("Create profile"));
    let client = ApiClient::new("/nonexistent.sock");
    handle_wifi_profiles_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(
        app.wifi_profiles.as_ref().unwrap().mode,
        WifiProfilesMode::ProfileActions
    );
    handle_wifi_profiles_key(&mut app, KeyCode::Down, &client).await;
    handle_wifi_profiles_key(&mut app, KeyCode::Down, &client).await;
    assert_eq!(
        WifiProfileAction::from_index(app.wifi_profiles.as_ref().unwrap().selected),
        Some(WifiProfileAction::Delete)
    );
    handle_wifi_profiles_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(
        app.wifi_profiles
            .as_ref()
            .unwrap()
            .delete_confirmation
            .as_deref(),
        Some("p39")
    );
    handle_wifi_profiles_key(&mut app, KeyCode::Esc, &client).await;
    assert!(app
        .wifi_profiles
        .as_ref()
        .unwrap()
        .delete_confirmation
        .is_none());
}

#[tokio::test]
async fn wifi_profiles_menu_shows_management_and_create_new() {
    let mut app = TuiApp {
        wifi_profiles: Some(WifiProfilesView {
            interface: "wlan0".into(),
            mode: WifiProfilesMode::Menu,
            selected: 0,
            selected_profile: 0,
            delete_confirmation: None,
            profiles: vec![WifiClientProfileSummary {
                id: "home".into(),
                ssid: "HomeNet".into(),
                country_code: None,
                security: WifiClientSecurity::Wpa2,
                priority: 10,
                autoconnect: false,
                created_at: 0,
                modified_at: 0,
                has_passphrase: true,
            }],
        }),
        ..Default::default()
    };
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| render_wifi_profiles(frame, frame.area(), &mut app))
        .unwrap();
    let text: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(text.contains("Management"));
    assert!(text.contains("Create new"));
    // Top menu does not mix in profile table
    assert!(!text.contains("HomeNet"));

    let client = ApiClient::new("/nonexistent.sock");
    // Down moves to Create new
    handle_wifi_profiles_key(&mut app, KeyCode::Down, &client).await;
    assert_eq!(
        WifiProfilesMenuAction::from_index(app.wifi_profiles.as_ref().unwrap().selected),
        Some(WifiProfilesMenuAction::CreateNew)
    );

    // Enter on Create new opens WifiProfileEditor
    handle_wifi_profiles_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(app.screen, Screen::WifiProfileEditor);
    assert!(app.wifi_profile_editor.is_some());

    // Cancel editor returns to profiles
    handle_wifi_profile_editor_key(&mut app, KeyCode::Esc, &client).await;
    assert_eq!(app.screen, Screen::WifiProfiles);

    // Now select Management
    handle_wifi_profiles_key(&mut app, KeyCode::Up, &client).await;
    assert_eq!(
        WifiProfilesMenuAction::from_index(app.wifi_profiles.as_ref().unwrap().selected),
        Some(WifiProfilesMenuAction::Management)
    );
    handle_wifi_profiles_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(
        app.wifi_profiles.as_ref().unwrap().mode,
        WifiProfilesMode::Management
    );

    // In Management, HomeNet is displayed cleanly
    terminal
        .draw(|frame| render_wifi_profiles(frame, frame.area(), &mut app))
        .unwrap();
    let mgmt_text: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(mgmt_text.contains("HomeNet"));
    assert!(mgmt_text.contains("home"));

    // Enter in Management opens ProfileActions
    handle_wifi_profiles_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(
        app.wifi_profiles.as_ref().unwrap().mode,
        WifiProfilesMode::ProfileActions
    );
    terminal
        .draw(|frame| render_wifi_profiles(frame, frame.area(), &mut app))
        .unwrap();
    let actions_text: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(actions_text.contains("Activate / Connect"));
    assert!(actions_text.contains("Edit profile"));
    assert!(actions_text.contains("Delete profile"));
    assert!(actions_text.contains("Deactivate client"));
    assert!(actions_text.contains("Back to profile list"));

    // Esc in ProfileActions goes back to Management
    handle_wifi_profiles_key(&mut app, KeyCode::Esc, &client).await;
    assert_eq!(
        app.wifi_profiles.as_ref().unwrap().mode,
        WifiProfilesMode::Management
    );

    // Esc in Management goes back to Menu
    handle_wifi_profiles_key(&mut app, KeyCode::Esc, &client).await;
    assert_eq!(
        app.wifi_profiles.as_ref().unwrap().mode,
        WifiProfilesMode::Menu
    );

    // Esc in Menu exits to Wifi screen
    handle_wifi_profiles_key(&mut app, KeyCode::Esc, &client).await;
    assert_eq!(app.screen, Screen::Wifi);
}

#[test]
fn unconfigured_radio_never_defaults_to_ap_and_role_mapping_is_strict() {
    let status = InterfaceStatus {
        owned_ipv4_addresses: None,
        interface: crate::netlink::NetworkInterface {
            index: 1,
            name: "wlan0".into(),
            is_up: true,
            rx_bytes: 0,
            tx_bytes: 0,
            is_wireless: true,
        },
        ipv4_addresses: vec![],
        has_default_route: false,
    };
    assert_eq!(build_rows(&[status], &[], &[])[0].role, WifiRole::Unknown);
    assert_eq!(
        role_from_interface(InterfaceRole::Output, true),
        WifiRole::AccessPoint
    );
    assert_eq!(
        role_from_interface(InterfaceRole::Input, false),
        WifiRole::Unknown
    );
    assert_eq!(
        role_from_interface(InterfaceRole::Input, true),
        WifiRole::Client
    );
    assert_eq!(
        role_from_interface(InterfaceRole::Output, false),
        WifiRole::Unknown
    );
}

#[test]
fn primary_navigation_moves_from_radios_into_role_actions() {
    let data = WifiData {
        rows: vec![
            WifiRow {
                interface: "wlan0".into(),
                role: WifiRole::Client,
                ap: None,
                client: None,
            },
            WifiRow {
                interface: "wlan1".into(),
                role: WifiRole::AccessPoint,
                ap: None,
                client: None,
            },
        ],
        selected: 2,
        selected_radio: 0,
        actions_open: true,
        ..WifiData::default()
    };
    assert_eq!(data.focused_radio().unwrap().interface, "wlan0");
    assert_eq!(data.cursor_limit(), 6);
    assert_eq!(actions(WifiRole::Client)[0].1, "Scan networks");
}

#[tokio::test]
async fn wifi_editor_cursor_navigation_and_editing() {
    let mut app = TuiApp::default();
    let row = WifiRow {
        interface: "wlan0".into(),
        role: WifiRole::AccessPoint,
        ap: None,
        client: None,
    };
    let mut editor = WifiEditor::from_row(&row);
    editor.field = WifiField::Ssid;
    editor.ssid = "MyNet".into();
    editor.cursor = editor.ssid.len();
    app.wifi_editor = Some(editor);
    app.screen = Screen::WifiEditor;
    let client = ApiClient::new("/nonexistent.sock");

    handle_wifi_editor_key(&mut app, KeyCode::Left, &client).await;
    assert_eq!(app.wifi_editor.as_ref().unwrap().cursor, 4);

    handle_wifi_editor_key(&mut app, KeyCode::Char('1'), &client).await;
    assert_eq!(app.wifi_editor.as_ref().unwrap().ssid, "MyNe1t");
    assert_eq!(app.wifi_editor.as_ref().unwrap().cursor, 5);

    handle_wifi_editor_key(&mut app, KeyCode::Backspace, &client).await;
    assert_eq!(app.wifi_editor.as_ref().unwrap().ssid, "MyNet");
    assert_eq!(app.wifi_editor.as_ref().unwrap().cursor, 4);
}

#[tokio::test]
async fn wifi_profile_editor_cursor_navigation_and_editing() {
    let mut app = TuiApp::default();
    let mut editor = WifiProfileEditor {
        interface: "wlan0".into(),
        original_id: None,
        field: ProfileField::Ssid,
        id: "net-1".into(),
        ssid: "Office".into(),
        security: WifiClientSecurity::Wpa2,
        country: String::new(),
        priority: "0".into(),
        autoconnect: false,
        passphrase: String::new(),
        has_passphrase: false,
        cursor: 6,
    };
    editor.cursor = editor.ssid.len();
    app.wifi_profile_editor = Some(editor);
    app.screen = Screen::WifiProfileEditor;
    let client = ApiClient::new("/nonexistent.sock");

    handle_wifi_profile_editor_key(&mut app, KeyCode::Home, &client).await;
    assert_eq!(app.wifi_profile_editor.as_ref().unwrap().cursor, 0);

    handle_wifi_profile_editor_key(&mut app, KeyCode::Char('X'), &client).await;
    assert_eq!(app.wifi_profile_editor.as_ref().unwrap().ssid, "XOffice");
    assert_eq!(app.wifi_profile_editor.as_ref().unwrap().cursor, 1);

    handle_wifi_profile_editor_key(&mut app, KeyCode::Delete, &client).await;
    assert_eq!(app.wifi_profile_editor.as_ref().unwrap().ssid, "Xffice");
    assert_eq!(app.wifi_profile_editor.as_ref().unwrap().cursor, 1);
}

#[test]
fn wifi_connect_prompt_choices_omits_keep_static_when_no_static_ip() {
    let prompt_no_static =
        WifiConnectPrompt::new("wlan0".into(), "prof1".into(), "HomeNet".into(), None);
    assert_eq!(
        prompt_no_static.available_choices(),
        vec![WifiIpChoice::Dhcp, WifiIpChoice::NewStatic]
    );
    let fields = prompt_no_static.focusable_fields();
    assert_eq!(
        fields,
        vec![
            WifiConnectField::Choice(WifiIpChoice::Dhcp),
            WifiConnectField::Choice(WifiIpChoice::NewStatic),
            WifiConnectField::Submit,
            WifiConnectField::Cancel,
        ]
    );

    let prompt_with_static = WifiConnectPrompt::new(
        "wlan0".into(),
        "prof1".into(),
        "HomeNet".into(),
        Some("192.168.1.50/24".into()),
    );
    assert_eq!(
        prompt_with_static.available_choices(),
        vec![
            WifiIpChoice::Dhcp,
            WifiIpChoice::KeepStatic,
            WifiIpChoice::NewStatic
        ]
    );
    let fields_with_static = prompt_with_static.focusable_fields();
    assert_eq!(
        fields_with_static,
        vec![
            WifiConnectField::Choice(WifiIpChoice::Dhcp),
            WifiConnectField::Choice(WifiIpChoice::KeepStatic),
            WifiConnectField::Choice(WifiIpChoice::NewStatic),
            WifiConnectField::Submit,
            WifiConnectField::Cancel,
        ]
    );
}

#[tokio::test]
async fn wifi_connect_prompt_key_handling() {
    let prompt = WifiConnectPrompt::new(
        "wlan0".into(),
        "prof1".into(),
        "HomeNet".into(),
        Some("192.168.1.50/24".into()),
    );
    let mut app = TuiApp {
        screen: Screen::WifiConnectPrompt,
        wifi_connect: Some(prompt),
        ..Default::default()
    };
    let client = ApiClient::new("/nonexistent.sock");

    // Move down to KeepStatic
    handle_wifi_connect_prompt_key(&mut app, KeyCode::Down, &client).await;
    let p = app.wifi_connect.as_ref().unwrap();
    assert_eq!(p.field, WifiConnectField::Choice(WifiIpChoice::KeepStatic));
    assert_eq!(p.choice, WifiIpChoice::Dhcp);

    // Move down to NewStatic
    handle_wifi_connect_prompt_key(&mut app, KeyCode::Down, &client).await;
    let p = app.wifi_connect.as_ref().unwrap();
    assert_eq!(p.field, WifiConnectField::Choice(WifiIpChoice::NewStatic));
    assert_eq!(p.choice, WifiIpChoice::Dhcp);

    // Enter on NewStatic focuses StaticCidr
    handle_wifi_connect_prompt_key(&mut app, KeyCode::Enter, &client).await;
    let p = app.wifi_connect.as_ref().unwrap();
    assert_eq!(p.field, WifiConnectField::StaticCidr);

    // Backspace removes character from CIDR
    handle_wifi_connect_prompt_key(&mut app, KeyCode::Backspace, &client).await;
    let p = app.wifi_connect.as_ref().unwrap();
    assert_eq!(p.static_cidr, "192.168.1.50/2");

    // Type char
    handle_wifi_connect_prompt_key(&mut app, KeyCode::Char('5'), &client).await;
    let p = app.wifi_connect.as_ref().unwrap();
    assert_eq!(p.static_cidr, "192.168.1.50/25");

    // Home key moves cursor to 0
    handle_wifi_connect_prompt_key(&mut app, KeyCode::Home, &client).await;
    let p = app.wifi_connect.as_ref().unwrap();
    assert_eq!(p.cursor, 0);

    // Delete removes first character
    handle_wifi_connect_prompt_key(&mut app, KeyCode::Delete, &client).await;
    let p = app.wifi_connect.as_ref().unwrap();
    assert_eq!(p.static_cidr, "92.168.1.50/25");
    assert_eq!(p.cursor, 0);

    // Insert character at start
    handle_wifi_connect_prompt_key(&mut app, KeyCode::Char('1'), &client).await;
    let p = app.wifi_connect.as_ref().unwrap();
    assert_eq!(p.static_cidr, "192.168.1.50/25");
    assert_eq!(p.cursor, 1);

    // End key moves cursor to end
    handle_wifi_connect_prompt_key(&mut app, KeyCode::End, &client).await;
    let p = app.wifi_connect.as_ref().unwrap();
    assert_eq!(p.cursor, p.static_cidr.len());

    // Left key moves cursor left
    handle_wifi_connect_prompt_key(&mut app, KeyCode::Left, &client).await;
    let p = app.wifi_connect.as_ref().unwrap();
    assert_eq!(p.cursor, p.static_cidr.len() - 1);

    // Right key moves cursor right
    handle_wifi_connect_prompt_key(&mut app, KeyCode::Right, &client).await;
    let p = app.wifi_connect.as_ref().unwrap();
    assert_eq!(p.cursor, p.static_cidr.len());

    // Esc closes prompt
    handle_wifi_connect_prompt_key(&mut app, KeyCode::Esc, &client).await;
    assert!(app.wifi_connect.is_none());
    assert_eq!(app.screen, Screen::Wifi);
}

#[test]
fn wifi_profile_actions_list_area_excludes_header_for_mouse_clicks() {
    let mut app = TuiApp {
        wifi_profiles: Some(WifiProfilesView {
            interface: "wlan0".into(),
            mode: WifiProfilesMode::ProfileActions,
            selected: 0,
            selected_profile: 0,
            delete_confirmation: None,
            profiles: vec![WifiClientProfileSummary {
                id: "p0".into(),
                ssid: "net0".into(),
                country_code: None,
                security: WifiClientSecurity::Open,
                priority: 0,
                autoconnect: false,
                created_at: 0,
                modified_at: 0,
                has_passphrase: false,
            }],
        }),
        ..Default::default()
    };
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| render_wifi_profiles(frame, frame.area(), &mut app))
        .unwrap();

    let list_area = app.ui.list_area.expect("list_area must be populated");
    assert_eq!(app.ui.list_count, WifiProfileAction::ALL.len());
    assert_eq!(app.ui.list_scroll_offset, 0);
    // Header height is 2 lines, panel top border is 1 line, so list_area starts at y = 3
    assert_eq!(list_area.y, 3);
}

#[test]
fn render_wifi_displays_conflict_advice_when_competing_managers_present() {
    use crate::wifi::{HostapdState, WifiApSpec};

    let mut app = TuiApp {
        wifi: WifiData {
            rows: vec![WifiRow {
                interface: "wlp1s0".to_string(),
                role: WifiRole::AccessPoint,
                ap: Some(WifiApStatus {
                    interface: "wlp1s0".to_string(),
                    spec: WifiApSpec {
                        interface: "wlp1s0".to_string(),
                        ssid: "TestAP".to_string(),
                        country_code: Some("US".to_string()),
                        band: crate::config::WifiBand::Ghz2,
                        channel: 6,
                        channel_width: crate::config::WifiChannelWidth::Ht20,
                        security: crate::config::WifiSecurity::Open,
                        hidden: false,
                        client_isolation: false,
                        max_stations: 32,
                        passphrase_file: None,
                    },
                    pid: 0,
                    hostapd_state: HostapdState::Disabled,
                    num_stations: None,
                    health: WifiHealth::Retrying {
                        error: "ctrl socket timeout".to_string(),
                        attempts: 3,
                        retry_in_secs: Some(10),
                        competing_managers: vec!["iwd".to_string()],
                        advice: Some("Stop service: sudo sv down iwd".to_string()),
                    },
                }),
                client: None,
            }],
            selected: 0,
            selected_radio: 0,
            actions_open: false,
            ap_disabled: false,
            client_disabled: false,
            error: None,
        },
        ..Default::default()
    };

    let backend = ratatui::backend::TestBackend::new(100, 24);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| render_wifi(frame, frame.area(), &mut app))
        .unwrap();

    let buffer = terminal.backend().buffer();
    let content = (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n");

    assert!(content.contains("Conflict"));
    assert!(content.contains("iwd"));
    assert!(content.contains("sudo sv down iwd"));
}

#[test]
fn describe_row_state_reports_connected_when_healthy() {
    use crate::wifi::client::ctrl::WpaState;
    use crate::wifi::client::WifiClientSpec;

    let row = WifiRow {
        interface: "wlan0".to_string(),
        role: WifiRole::Client,
        ap: None,
        client: Some(WifiClientStatus {
            interface: "wlan0".to_string(),
            pid: 1234,
            spec: WifiClientSpec {
                interface: "wlan0".to_string(),
                ssid: "HomeNetwork".to_string(),
                security: WifiClientSecurity::Wpa2,
                passphrase_file: None,
                country_code: None,
            },
            wpa_state: WpaState::Completed,
            bssid: None,
            freq: None,
            health: WifiHealth::Healthy,
        }),
    };

    assert_eq!(describe_row_state(&row), "connected to HomeNetwork");
}

#[test]
fn describe_row_state_reports_joining_starting_when_starting() {
    use crate::wifi::client::ctrl::WpaState;
    use crate::wifi::client::WifiClientSpec;

    let row = WifiRow {
        interface: "wlan0".to_string(),
        role: WifiRole::Client,
        ap: None,
        client: Some(WifiClientStatus {
            interface: "wlan0".to_string(),
            pid: 1234,
            spec: WifiClientSpec {
                interface: "wlan0".to_string(),
                ssid: "HomeNetwork".to_string(),
                security: WifiClientSecurity::Wpa2,
                passphrase_file: None,
                country_code: None,
            },
            wpa_state: WpaState::Associating,
            bssid: None,
            freq: None,
            health: WifiHealth::Starting,
        }),
    };

    assert_eq!(describe_row_state(&row), "joining HomeNetwork — starting…");
}

#[test]
fn describe_row_state_respects_role_precedence() {
    use crate::wifi::client::ctrl::WpaState;
    use crate::wifi::client::WifiClientSpec;
    use crate::wifi::{HostapdState, WifiApSpec};

    let client_status = WifiClientStatus {
        interface: "wlan0".to_string(),
        pid: 1234,
        spec: WifiClientSpec {
            interface: "wlan0".to_string(),
            ssid: "ClientSSID".to_string(),
            security: WifiClientSecurity::Wpa2,
            passphrase_file: None,
            country_code: None,
        },
        wpa_state: WpaState::Completed,
        bssid: None,
        freq: None,
        health: WifiHealth::Healthy,
    };

    let ap_status = WifiApStatus {
        interface: "wlan0".to_string(),
        spec: WifiApSpec {
            interface: "wlan0".to_string(),
            ssid: "ApSSID".to_string(),
            country_code: None,
            band: WifiBand::Ghz2,
            channel: 1,
            channel_width: WifiChannelWidth::Ht20,
            security: WifiSecurity::Wpa2,
            hidden: false,
            client_isolation: false,
            max_stations: 10,
            passphrase_file: None,
        },
        pid: 5678,
        hostapd_state: HostapdState::Enabled,
        num_stations: None,
        health: WifiHealth::Healthy,
    };

    // When role is Client, must display client state even if AP is present
    let client_row = WifiRow {
        interface: "wlan0".to_string(),
        role: WifiRole::Client,
        ap: Some(ap_status.clone()),
        client: Some(client_status.clone()),
    };
    assert_eq!(describe_row_state(&client_row), "connected to ClientSSID");

    // When role is AccessPoint, must display AP state even if client is present
    let ap_row = WifiRow {
        interface: "wlan0".to_string(),
        role: WifiRole::AccessPoint,
        ap: Some(ap_status),
        client: Some(client_status),
    };
    assert_eq!(describe_row_state(&ap_row), "serving ApSSID");
}

#[test]
fn describe_row_state_reports_not_configured_when_empty() {
    let row = WifiRow {
        interface: "wlan0".to_string(),
        role: WifiRole::Client,
        ap: None,
        client: None,
    };
    assert_eq!(describe_row_state(&row), "not configured");
}

#[test]
fn render_wifi_client_conflict_advice_when_ap_also_present() {
    use crate::wifi::client::ctrl::WpaState;
    use crate::wifi::client::WifiClientSpec;
    use crate::wifi::{HostapdState, WifiApSpec};

    let mut app = TuiApp {
        wifi: WifiData {
            rows: vec![WifiRow {
                interface: "wlp1s0".to_string(),
                role: WifiRole::Client,
                ap: Some(WifiApStatus {
                    interface: "wlp1s0".to_string(),
                    spec: WifiApSpec {
                        interface: "wlp1s0".to_string(),
                        ssid: "OldAP".to_string(),
                        country_code: None,
                        band: WifiBand::Ghz2,
                        channel: 6,
                        channel_width: WifiChannelWidth::Ht20,
                        security: WifiSecurity::Open,
                        hidden: false,
                        client_isolation: false,
                        max_stations: 32,
                        passphrase_file: None,
                    },
                    pid: 0,
                    hostapd_state: HostapdState::Disabled,
                    num_stations: None,
                    health: WifiHealth::Healthy,
                }),
                client: Some(WifiClientStatus {
                    interface: "wlp1s0".to_string(),
                    pid: 0,
                    spec: WifiClientSpec {
                        interface: "wlp1s0".to_string(),
                        ssid: "TargetClient".to_string(),
                        security: WifiClientSecurity::Wpa2,
                        passphrase_file: None,
                        country_code: None,
                    },
                    wpa_state: WpaState::Disconnected,
                    bssid: None,
                    freq: None,
                    health: WifiHealth::Retrying {
                        error: "wpa_supplicant failed to bind".to_string(),
                        attempts: 2,
                        retry_in_secs: Some(5),
                        competing_managers: vec!["NetworkManager".to_string()],
                        advice: Some("systemctl stop NetworkManager".to_string()),
                    },
                }),
            }],
            selected: 0,
            selected_radio: 0,
            actions_open: false,
            ap_disabled: false,
            client_disabled: false,
            error: None,
        },
        ..Default::default()
    };

    let backend = ratatui::backend::TestBackend::new(100, 24);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| render_wifi(frame, frame.area(), &mut app))
        .unwrap();

    let buffer = terminal.backend().buffer();
    let content = (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n");

    assert!(content.contains("Conflict"));
    assert!(content.contains("NetworkManager"));
    assert!(content.contains("systemctl stop NetworkManager"));
}

#[test]
fn scan_security_label_distinguishes_transition_mode() {
    assert_eq!(
        scan_security_label(WpaSupplicantScanSecurity::Wpa2Wpa3Transition),
        "wpa2/wpa3 transition"
    );
    assert_eq!(
        scan_security_label(WpaSupplicantScanSecurity::Wpa2Psk),
        "wpa2"
    );
    assert_eq!(
        scan_security_label(WpaSupplicantScanSecurity::Wpa3Sae),
        "wpa3"
    );
    assert_eq!(scan_security_label(WpaSupplicantScanSecurity::Open), "open");
}

#[tokio::test]
async fn request_simple_surfaces_wifi_error_and_client_error() {
    use crate::api::model::WifiClientErrorDetail;

    let (_directory, client, server) = mock_api(vec![
        Response::WifiClientError {
            detail: WifiClientErrorDetail::ScanBusy,
        },
        Response::WifiError {
            detail: WifiErrorDetail::HostapdMissing,
        },
    ])
    .await;

    let mut app = TuiApp::default();
    request_simple(
        &mut app,
        &client,
        Request::WifiClientReconnect {
            interface: "wlan0".to_string(),
        },
        "reconnected",
    )
    .await;

    let last_log = app.logs.back().expect("must have logged an error");
    assert_eq!(last_log.level, LogLevel::Error);
    assert!(last_log.message.contains("ScanBusy"));

    request_simple(
        &mut app,
        &client,
        Request::WifiReload {
            interface: "wlan0".to_string(),
        },
        "reloaded",
    )
    .await;

    let last_log = app.logs.back().expect("must have logged an error");
    assert_eq!(last_log.level, LogLevel::Error);
    assert!(last_log.message.contains("HostapdMissing"));

    let _ = server.await;
}

#[test]
fn open_ap_request_discards_typed_passphrase_and_requests_clear() {
    let row = WifiRow {
        interface: "wlan0".into(),
        role: WifiRole::AccessPoint,
        ap: None,
        client: None,
    };
    let mut editor = WifiEditor::from_row(&row);
    editor.security = WifiSecurity::Open;
    editor.passphrase = "stale password".into();
    match ap_provision_request(&editor) {
        Request::ProvisionWifiAccessPoint {
            passphrase,
            clear_passphrase,
            ..
        } => {
            assert!(passphrase.is_none());
            assert!(clear_passphrase);
        }
        other => panic!("unexpected request: {other:?}"),
    }
}

#[test]
fn unicode_ssids_have_nonempty_stable_distinct_profile_ids() {
    let home = profile_id_for_ssid("Дім");
    assert!(!home.is_empty());
    assert!(home.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    assert_eq!(home, profile_id_for_ssid("Дім"));
    assert_ne!(home, profile_id_for_ssid("Гості"));
}

#[tokio::test]
async fn ap_profile_load_restores_radio_options_without_exposing_password() {
    let mut editor = WifiEditor::from_row(&radio("wlan0"));
    let mut settings = ap_settings(&editor);
    settings.ssid = "Guests".into();
    settings.hidden = true;
    settings.client_isolation = true;
    settings.channel = 11;
    editor
        .profiles
        .push(crate::api::model::WifiApProfileSummary {
            id: "guest".into(),
            settings,
            configure_dhcp: false,
            has_passphrase: true,
        });
    editor.field = WifiField::SavedProfile;
    editor.passphrase = "unsaved-secret".into();
    let mut app = TuiApp {
        screen: Screen::WifiEditor,
        wifi_editor: Some(editor),
        ..Default::default()
    };
    handle_wifi_editor_key(
        &mut app,
        KeyCode::Enter,
        &ApiClient::new("/nonexistent.sock"),
    )
    .await;
    let loaded = app.wifi_editor.as_ref().unwrap();
    assert_eq!(loaded.ssid, "Guests");
    assert_eq!(loaded.profile_id, "guest");
    assert!(loaded.passphrase.is_empty());
    assert!(loaded.loaded_profile);
    assert!(loaded.existing);
    assert!(!loaded.configure_dhcp);
    assert_eq!(ap_settings(loaded).channel, 11);
    assert!(ap_settings(loaded).hidden);
}

#[tokio::test]
async fn failed_interface_read_does_not_open_connection_prompt() {
    let (_dir, client, server) = mock_api(vec![Response::Error {
        message: "read failed".into(),
    }])
    .await;
    let mut app = TuiApp::default();
    open_wifi_connect_prompt(
        &mut app,
        &client,
        "wlan0".into(),
        "home".into(),
        "Home".into(),
    )
    .await;
    assert!(app.wifi_connect.is_none());
    assert_eq!(server.await.unwrap().len(), 1);
}

#[test]
fn open_client_profile_discards_password_typed_before_security_change() {
    let network = WpaSupplicantScanResult {
        bssid: "02:00:00:00:00:01".parse().unwrap(),
        frequency_mhz: 2412,
        signal_dbm: -40,
        ssid: "guest".into(),
        raw_flags: "[ESS]".into(),
        security: WpaSupplicantScanSecurity::Open,
    };
    let mut editor = WifiProfileEditor::from_scan("wlan0".into(), &network).unwrap();
    editor.passphrase = "typed-password".into();
    let request = editor.request().unwrap();
    assert!(request.passphrase.is_none());
    assert!(request.clear_passphrase);
}
