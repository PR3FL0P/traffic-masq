use super::*;

#[tokio::test]
async fn scan_request_opens_the_network_picker_with_returned_networks() {
    let networks = vec![scan(
        "nearby",
        -42,
        WpaSupplicantScanSecurity::Wpa2Psk,
        "02:00:00:00:00:01",
    )];
    let (_directory, client, server) = mock_api(vec![Response::WifiClientScanResults {
        interface: "wlp1s0".into(),
        results: networks.clone(),
    }])
    .await;
    let mut app = TuiApp::default();
    app.wifi.rows.push(radio("wlp1s0"));
    start_scan(&mut app, &client, "wlp1s0".into()).await;
    assert_eq!(server.await.unwrap(), vec!["wifi_client_scan wlp1s0"]);
    assert_eq!(app.screen, Screen::WifiScan);
    let picker = app.wifi_scan.unwrap();
    assert_eq!(picker.interface, "wlp1s0");
    assert_eq!(picker.networks, networks);
}

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
                            assert_eq!(request.method(), hyper::Method::POST);
                            assert_eq!(request.uri().path(), "/api/v1/control");
                            let bytes = request.into_body().collect().await.unwrap().to_bytes();
                            let command: serde_json::Value =
                                serde_json::from_slice(&bytes).unwrap();
                            let kind = command["type"].as_str().unwrap();
                            let interface = command["interface"].as_str().unwrap_or("");
                            paths
                                .lock()
                                .await
                                .push(format!("{kind} {interface}").trim_end().to_owned());
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
        execution_available: true,
        presence: traffic_masq_protocol::InterfacePresence::Present,
        configured: None,
        revision: None,
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
async fn connect_failure_uses_one_backend_operation() {
    let (_directory, client, server) = mock_api(vec![Response::Error {
        message: "activation failed".into(),
    }])
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
    assert_eq!(server.await.unwrap(), vec!["provision_wifi_client wlan0"]);
    assert!(app.wifi_connect.is_some());
    assert_eq!(app.message.as_deref(), Some("activation failed"));
}

#[tokio::test]
async fn static_connect_retains_pending_transaction_without_auto_commit() {
    let change = traffic_masq_protocol::PendingNetworkChange {
        recovery_progress: None,
        phase: Default::default(),
        last_error: None,
        token: "pending-token".into(),
        interface: "wlan0".into(),
        rollback_timeout_seconds: 60,
        expires_at_unix: super::super::current_unix_time() + 60,
    };
    let (_directory, client, server) =
        mock_api(vec![Response::NetworkChangePending { change }]).await;
    let mut prompt = WifiConnectPrompt::new("wlan0".into(), "home".into(), "Home".into(), None);
    prompt.choice = WifiIpChoice::NewStatic;
    prompt.static_cidr = "192.168.1.5/24".into();
    let mut app = TuiApp {
        screen: Screen::WifiConnectPrompt,
        wifi_connect: Some(prompt),
        ..Default::default()
    };
    submit_wifi_connect(&mut app, &client).await;
    assert_eq!(server.await.unwrap(), vec!["provision_wifi_client wlan0"]);
    assert_eq!(app.screen, Screen::PendingChange);
    assert_eq!(app.pending.as_ref().unwrap().token, "pending-token");
    assert!(app.wifi_connect.is_none());
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
        ssid_bytes: Vec::new(),
        raw_flags: String::new(),
        security,
    }
}

#[tokio::test]
async fn ap_options_open_only_on_activation_and_radio_edits_reach_request() {
    let mut app = TuiApp::default();
    app.wifi.rows.push(WifiRow {
        execution_available: true,
        presence: traffic_masq_protocol::InterfacePresence::Present,
        configured: None,
        revision: None,
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
    handle_wifi_key(&mut app, KeyCode::Up, &client).await;
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
        execution_available: true,
        presence: traffic_masq_protocol::InterfacePresence::Present,
        configured: None,
        revision: None,
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
            subnet: None,
            disable_dhcp: false,
            ..
        }
    ));
}

#[tokio::test]
async fn ap_apply_enters_shared_commit_confirm_screen() {
    let change = traffic_masq_protocol::PendingNetworkChange {
        recovery_progress: None,
        phase: Default::default(),
        last_error: None,
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
        execution_available: true,
        presence: traffic_masq_protocol::InterfacePresence::Present,
        configured: None,
        revision: None,
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
    assert!(app.wifi_editor.as_ref().unwrap().reviewing);
    assert!(app.pending.is_none());
    handle_wifi_editor_key(&mut app, KeyCode::Enter, &client).await;

    assert_eq!(
        server.await.unwrap(),
        vec!["provision_wifi_access_point wlan0"]
    );
    assert_eq!(app.screen, Screen::PendingChange);
    assert_eq!(app.pending_return_screen, Screen::Wifi);
    assert_eq!(app.pending, Some(change));
    assert!(app.wifi_editor.is_none());
}

#[test]
fn existing_ap_request_preserves_unedited_radio_settings() {
    let row = WifiRow {
        execution_available: true,
        presence: traffic_masq_protocol::InterfacePresence::Present,
        configured: None,
        revision: None,
        interface: "wlan0".into(),
        role: WifiRole::AccessPoint,
        ap: None,
        client: None,
    };
    let mut editor = WifiEditor::from_row(&row);
    editor.original_spec = Some(WifiApSpecView {
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
    // Navigation and unrelated keys keep the explicit confirmation open.
    handle_wifi_profiles_key(&mut app, KeyCode::Down, &client).await;
    handle_wifi_profiles_key(&mut app, KeyCode::Char('y'), &client).await;
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
    assert!(text.contains("Delete saved Wi-Fi profile?"));
    assert!(text.contains("Profile: p39"));
    assert!(text.contains("SSID: network39"));
    assert!(text.contains("[Delete]"));
    assert!(text.contains("[Cancel]"));
    assert!(app.ui.list_area.is_none());
    handle_wifi_profiles_key(&mut app, KeyCode::Esc, &client).await;
    assert!(app
        .wifi_profiles
        .as_ref()
        .unwrap()
        .delete_confirmation
        .is_none());
    handle_wifi_profiles_key(&mut app, KeyCode::Enter, &client).await;
    let (_dir, client, server) = mock_api(vec![
        Response::WifiClientProfileDeleted { id: "p39".into() },
        Response::WifiClientProfiles { profiles: vec![] },
    ])
    .await;
    handle_wifi_profiles_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(
        server.await.unwrap(),
        vec!["delete_wifi_client_profile", "list_wifi_client_profiles"]
    );
    assert!(app.pending.is_none());
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
        interface: traffic_masq_protocol::NetworkInterfaceView {
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
    assert!(actions(WifiRole::Unknown)
        .iter()
        .all(|(action, _)| matches!(action, PrimaryAction::Refresh)));
    assert!(!actions(WifiRole::AccessPoint)
        .iter()
        .any(|(action, _)| matches!(action, PrimaryAction::Scan | PrimaryAction::Profiles)));
    assert!(
        !actions(WifiRole::Client).iter().any(|(action, _)| matches!(
            action,
            PrimaryAction::ConfigureAp | PrimaryAction::ApProfiles
        ))
    );
}

#[test]
fn primary_navigation_moves_from_radios_into_role_actions() {
    let data = WifiData {
        rows: vec![
            WifiRow {
                execution_available: true,
                presence: traffic_masq_protocol::InterfacePresence::Present,
                configured: None,
                revision: None,
                interface: "wlan0".into(),
                role: WifiRole::Client,
                ap: None,
                client: None,
            },
            WifiRow {
                execution_available: true,
                presence: traffic_masq_protocol::InterfacePresence::Present,
                configured: None,
                revision: None,
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
    assert_eq!(
        data.cursor_limit(),
        data.rows.len() + actions(WifiRole::Client).len() - 1
    );
    assert_eq!(actions(WifiRole::Client)[0].1, "Scan networks");
}

#[tokio::test]
async fn wifi_editor_cursor_navigation_and_editing() {
    let mut app = TuiApp::default();
    let row = WifiRow {
        execution_available: true,
        presence: traffic_masq_protocol::InterfacePresence::Present,
        configured: None,
        revision: None,
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
    use traffic_masq_protocol::{HostapdStateView as HostapdState, WifiApSpecView as WifiApSpec};

    let mut app = TuiApp {
        wifi: WifiData {
            rows: vec![WifiRow {
                execution_available: true,
                presence: traffic_masq_protocol::InterfacePresence::Present,
                configured: None,
                revision: None,
                interface: "wlp1s0".to_string(),
                role: WifiRole::AccessPoint,
                ap: Some(WifiApStatus {
                    interface: "wlp1s0".to_string(),
                    spec: WifiApSpec {
                        interface: "wlp1s0".to_string(),
                        ssid: "TestAP".to_string(),
                        country_code: Some("US".to_string()),
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
    use traffic_masq_protocol::{WifiClientSpecView as WifiClientSpec, WpaStateView as WpaState};

    let row = WifiRow {
        execution_available: true,
        presence: traffic_masq_protocol::InterfacePresence::Present,
        configured: None,
        revision: None,
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
    use traffic_masq_protocol::{WifiClientSpecView as WifiClientSpec, WpaStateView as WpaState};

    let row = WifiRow {
        execution_available: true,
        presence: traffic_masq_protocol::InterfacePresence::Present,
        configured: None,
        revision: None,
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
    use traffic_masq_protocol::{
        HostapdStateView as HostapdState, WifiApSpecView as WifiApSpec,
        WifiClientSpecView as WifiClientSpec, WpaStateView as WpaState,
    };

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
        execution_available: true,
        presence: traffic_masq_protocol::InterfacePresence::Present,
        configured: None,
        revision: None,
        interface: "wlan0".to_string(),
        role: WifiRole::Client,
        ap: Some(ap_status.clone()),
        client: Some(client_status.clone()),
    };
    assert_eq!(describe_row_state(&client_row), "connected to ClientSSID");

    // When role is AccessPoint, must display AP state even if client is present
    let ap_row = WifiRow {
        execution_available: true,
        presence: traffic_masq_protocol::InterfacePresence::Present,
        configured: None,
        revision: None,
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
        execution_available: true,
        presence: traffic_masq_protocol::InterfacePresence::Present,
        configured: None,
        revision: None,
        interface: "wlan0".to_string(),
        role: WifiRole::Client,
        ap: None,
        client: None,
    };
    assert_eq!(describe_row_state(&row), "not configured");
}

#[test]
fn render_wifi_client_conflict_advice_when_ap_also_present() {
    use traffic_masq_protocol::{
        HostapdStateView as HostapdState, WifiApSpecView as WifiApSpec,
        WifiClientSpecView as WifiClientSpec, WpaStateView as WpaState,
    };

    let mut app = TuiApp {
        wifi: WifiData {
            rows: vec![WifiRow {
                execution_available: true,
                presence: traffic_masq_protocol::InterfacePresence::Present,
                configured: None,
                revision: None,
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
    use traffic_masq_protocol::WifiClientErrorDetail;

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

#[tokio::test]
async fn request_simple_enters_pending_change_for_transactional_deactivation() {
    let change = traffic_masq_protocol::PendingNetworkChange {
        recovery_progress: None,
        phase: Default::default(),
        last_error: None,
        token: "wifi-disable-token".into(),
        interface: "wlan0".into(),
        rollback_timeout_seconds: 60,
        expires_at_unix: super::super::current_unix_time() + 60,
    };
    let (_directory, client, server) = mock_api(vec![Response::NetworkChangePending {
        change: change.clone(),
    }])
    .await;
    let mut app = TuiApp::default();

    request_simple(
        &mut app,
        &client,
        Request::DisableWifi {
            interface: "wlan0".to_string(),
        },
        "Wi-Fi deactivated",
    )
    .await;

    assert_eq!(app.pending, Some(change));
    assert_eq!(app.screen, Screen::PendingChange);
    assert_eq!(app.pending_return_screen, Screen::Wifi);
    let _ = server.await;
}

#[tokio::test]
async fn profile_deactivation_enters_pending_change_and_returns_to_profiles() {
    let change = traffic_masq_protocol::PendingNetworkChange {
        recovery_progress: None,
        phase: Default::default(),
        last_error: None,
        token: "wifi-profile-disable-token".into(),
        interface: "wlan0".into(),
        rollback_timeout_seconds: 60,
        expires_at_unix: super::super::current_unix_time() + 60,
    };
    let (_directory, client, server) = mock_api(vec![Response::NetworkChangePending {
        change: change.clone(),
    }])
    .await;
    let mut app = TuiApp {
        screen: Screen::WifiProfiles,
        wifi_profiles: Some(WifiProfilesView {
            interface: "wlan0".into(),
            mode: WifiProfilesMode::ProfileActions,
            selected: 3,
            selected_profile: 0,
            delete_confirmation: None,
            profiles: vec![WifiClientProfileSummary {
                id: "home".into(),
                ssid: "HomeNet".into(),
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

    handle_wifi_profiles_key(&mut app, KeyCode::Enter, &client).await;

    assert_eq!(app.pending, Some(change));
    assert_eq!(app.screen, Screen::PendingChange);
    assert_eq!(app.pending_return_screen, Screen::WifiProfiles);
    let paths = server.await.unwrap();
    assert_eq!(paths, vec!["deactivate_wifi_client_profile wlan0"]);
}

#[test]
fn open_ap_request_discards_typed_passphrase_and_requests_clear() {
    let row = WifiRow {
        execution_available: true,
        presence: traffic_masq_protocol::InterfacePresence::Present,
        configured: None,
        revision: None,
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

#[test]
fn ap_profile_edit_restores_settings_without_exposing_password() {
    let profile = ap_test_profile();
    let mut app = TuiApp::default();
    ap_profiles::open_ap_profile_editor(&mut app, "wlan0".into(), Some(&profile));
    let loaded = app.wifi_editor.as_ref().unwrap();
    assert_eq!(loaded.ssid, "Guests");
    assert_eq!(loaded.profile_id, "guest");
    assert!(loaded.passphrase.is_empty());
    assert!(loaded.profile_mode);
    assert!(loaded.existing);
    assert!(!loaded.configure_dhcp);
    assert_eq!(ap_settings(loaded).channel, 11);
    assert!(ap_settings(loaded).hidden);
    assert!(!loaded.fields().contains(&WifiField::ProfileId));
    assert!(!loaded.fields().contains(&WifiField::Apply));
    assert!(loaded.fields().contains(&WifiField::SaveProfile));
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
        ssid_bytes: Vec::new(),
        raw_flags: "[ESS]".into(),
        security: WpaSupplicantScanSecurity::Open,
    };
    let mut editor = WifiProfileEditor::from_scan("wlan0".into(), &network).unwrap();
    editor.passphrase = "typed-password".into();
    let request = editor.request().unwrap();
    assert!(request.passphrase.is_none());
    assert!(request.clear_passphrase);
}

#[tokio::test]
async fn ap_unsaved_edits_require_explicit_discard() {
    let mut app = TuiApp {
        screen: Screen::WifiEditor,
        wifi_editor: Some(WifiEditor::from_row(&radio("wlan0"))),
        ..Default::default()
    };
    let client = ApiClient::new("/nonexistent.sock");
    handle_wifi_editor_key(&mut app, KeyCode::Char('x'), &client).await;
    handle_wifi_editor_key(&mut app, KeyCode::Esc, &client).await;
    assert!(app.wifi_editor.as_ref().unwrap().discard_requested);
    handle_wifi_editor_key(&mut app, KeyCode::Esc, &client).await;
    assert!(!app.wifi_editor.as_ref().unwrap().discard_requested);
    assert!(app.wifi_editor.as_ref().unwrap().ssid.ends_with('x'));
    handle_wifi_editor_key(&mut app, KeyCode::Esc, &client).await;
    handle_wifi_editor_key(&mut app, KeyCode::Delete, &client).await;
    assert!(app.wifi_editor.is_none());
    assert_eq!(app.screen, Screen::Wifi);
}

#[test]
fn ap_warnings_and_focused_action_fit_minimum_terminal() {
    let mut editor = WifiEditor::from_row(&radio("wlan0"));
    editor.field = WifiField::Apply;
    let mut app = TuiApp {
        screen: Screen::WifiEditor,
        wifi_editor: Some(editor),
        ..Default::default()
    };
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| crate::tui::render(frame, &mut app, false))
        .unwrap();
    let text: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(text.contains("Review AP + passphrase + DHCP"));
    assert!(text.contains("DNS is not advertised"));
    assert!(text.contains("confirm before the rollback timer expires"));
}

fn ap_test_profile() -> traffic_masq_protocol::WifiApProfileSummary {
    let mut settings = ap_settings(&WifiEditor::from_row(&radio("wlan0")));
    settings.ssid = "Guests".into();
    settings.channel = 11;
    settings.hidden = true;
    settings.client_isolation = true;
    traffic_masq_protocol::WifiApProfileSummary {
        id: "guest".into(),
        settings,
        configure_dhcp: false,
        disable_dhcp: false,
        subnet: None,
        has_passphrase: true,
    }
}

fn ap_profiles_app(mode: WifiProfilesMode) -> TuiApp {
    TuiApp {
        screen: Screen::WifiApProfiles,
        wifi_ap_profiles: Some(WifiApProfilesView {
            interface: "wlan0".into(),
            profiles: vec![ap_test_profile()],
            mode,
            selected: 0,
            selected_profile: 0,
            delete_confirmation: None,
        }),
        ..Default::default()
    }
}

#[tokio::test]
async fn ap_profiles_menu_create_edit_and_back_match_client_flow() {
    let mut app = ap_profiles_app(WifiProfilesMode::Menu);
    let client = ApiClient::new("/nonexistent.sock");
    handle_wifi_ap_profiles_key(&mut app, KeyCode::Down, &client).await;
    handle_wifi_ap_profiles_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(app.screen, Screen::WifiEditor);
    let editor = app.wifi_editor.as_ref().unwrap();
    assert!(editor.profile_mode && !editor.existing);
    assert!(editor.profile_id.is_empty() && editor.passphrase.is_empty());
    assert!(editor.fields().contains(&WifiField::ProfileId));
    handle_wifi_editor_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(app.wifi_editor.as_ref().unwrap().field, WifiField::Ssid);
    handle_wifi_editor_key(&mut app, KeyCode::Esc, &client).await;
    assert_eq!(app.screen, Screen::WifiApProfiles);
    handle_wifi_ap_profiles_key(&mut app, KeyCode::Up, &client).await;
    handle_wifi_ap_profiles_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(
        app.wifi_ap_profiles.as_ref().unwrap().mode,
        WifiProfilesMode::Management
    );
    handle_wifi_ap_profiles_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(
        app.wifi_ap_profiles.as_ref().unwrap().mode,
        WifiProfilesMode::ProfileActions
    );
    handle_wifi_ap_profiles_key(&mut app, KeyCode::Down, &client).await;
    handle_wifi_ap_profiles_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(app.wifi_editor.as_ref().unwrap().profile_id, "guest");
    handle_wifi_editor_key(&mut app, KeyCode::Esc, &client).await;
    handle_wifi_ap_profiles_key(&mut app, KeyCode::Esc, &client).await;
    assert_eq!(
        app.wifi_ap_profiles.as_ref().unwrap().mode,
        WifiProfilesMode::Management
    );
    handle_wifi_ap_profiles_key(&mut app, KeyCode::Esc, &client).await;
    assert_eq!(
        app.wifi_ap_profiles.as_ref().unwrap().mode,
        WifiProfilesMode::Menu
    );
    handle_wifi_ap_profiles_key(&mut app, KeyCode::Esc, &client).await;
    assert_eq!(app.screen, Screen::Wifi);
}

#[tokio::test]
async fn ap_profile_save_does_not_activate_and_returns_to_selected_profile() {
    let mut app = ap_profiles_app(WifiProfilesMode::ProfileActions);
    ap_profiles::open_ap_profile_editor(&mut app, "wlan0".into(), Some(&ap_test_profile()));
    app.wifi_editor.as_mut().unwrap().field = WifiField::SaveProfile;
    let (_dir, client, server) = mock_api(vec![Response::WifiApProfileSaved {
        profile: ap_test_profile(),
    }])
    .await;
    handle_wifi_editor_key(&mut app, KeyCode::Enter, &client).await;
    let paths = server.await.unwrap();
    assert_eq!(paths.len(), 1);
    assert_eq!(paths, vec!["save_wifi_ap_profile"]);
    assert!(app.wifi_editor.is_none());
    assert!(app.pending.is_none());
    assert_eq!(app.screen, Screen::WifiApProfiles);
    let view = app.wifi_ap_profiles.as_ref().unwrap();
    assert_eq!(view.mode, WifiProfilesMode::Management);
    assert_eq!(view.profiles[view.selected].id, "guest");
}

#[tokio::test]
async fn ap_profile_apply_uses_saved_profile_and_commit_confirmation() {
    let mut app = ap_profiles_app(WifiProfilesMode::ProfileActions);
    let change = traffic_masq_protocol::PendingNetworkChange {
        recovery_progress: None,
        phase: Default::default(),
        last_error: None,
        token: "ap-profile-token".into(),
        interface: "wlan0".into(),
        rollback_timeout_seconds: 60,
        expires_at_unix: super::super::current_unix_time() + 60,
    };
    let (_dir, client, server) = mock_api(vec![Response::NetworkChangePending {
        change: change.clone(),
    }])
    .await;
    handle_wifi_ap_profiles_key(&mut app, KeyCode::Enter, &client).await;
    let paths = server.await.unwrap();
    assert_eq!(paths.len(), 1);
    assert_eq!(paths, vec!["activate_wifi_ap_profile wlan0"]);
    assert_eq!(app.pending, Some(change));
    assert_eq!(app.screen, Screen::PendingChange);
    assert_eq!(app.pending_return_screen, Screen::WifiApProfiles);
}

#[tokio::test]
async fn ap_profile_delete_requires_confirmation_and_keeps_network_unchanged() {
    let mut app = ap_profiles_app(WifiProfilesMode::ProfileActions);
    app.wifi_ap_profiles.as_mut().unwrap().selected = 2;
    let offline = ApiClient::new("/nonexistent.sock");
    handle_wifi_ap_profiles_key(&mut app, KeyCode::Enter, &offline).await;
    assert_eq!(
        app.wifi_ap_profiles
            .as_ref()
            .unwrap()
            .delete_confirmation
            .as_deref(),
        Some("guest")
    );
    handle_wifi_ap_profiles_key(&mut app, KeyCode::Down, &offline).await;
    handle_wifi_ap_profiles_key(&mut app, KeyCode::Char('y'), &offline).await;
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| super::super::render(frame, &mut app, false))
        .unwrap();
    let text: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(text.contains("Delete saved Wi-Fi profile?"));
    assert!(text.contains("Profile: guest"));
    assert!(text.contains("[Delete]"));
    assert!(text.contains("[Cancel]"));
    assert!(app.ui.list_area.is_none());
    assert_eq!(
        super::super::layout::help_pairs(&app),
        vec![("Enter", "Delete"), ("Esc", "cancel")]
    );
    let (cancel, _) = app.ui.buttons[1];
    super::super::handle_mouse(
        &mut app,
        crossterm::event::MouseEvent {
            kind: crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
            column: cancel.x,
            row: cancel.y,
            modifiers: crossterm::event::KeyModifiers::NONE,
        },
        &offline,
        false,
    )
    .await;
    assert!(app
        .wifi_ap_profiles
        .as_ref()
        .unwrap()
        .delete_confirmation
        .is_none());
    assert_eq!(app.wifi_ap_profiles.as_ref().unwrap().profiles.len(), 1);
    handle_wifi_ap_profiles_key(&mut app, KeyCode::Enter, &offline).await;
    let (_dir, client, server) = mock_api(vec![
        Response::WifiApProfileDeleted { id: "guest".into() },
        Response::WifiApProfiles { profiles: vec![] },
    ])
    .await;
    terminal
        .draw(|frame| super::super::render(frame, &mut app, false))
        .unwrap();
    let (delete, _) = app.ui.buttons[0];
    super::super::handle_mouse(
        &mut app,
        crossterm::event::MouseEvent {
            kind: crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
            column: delete.x,
            row: delete.y,
            modifiers: crossterm::event::KeyModifiers::NONE,
        },
        &client,
        false,
    )
    .await;
    let paths = server.await.unwrap();
    assert_eq!(paths.len(), 2);
    assert_eq!(paths[0], "delete_wifi_ap_profile");
    assert_eq!(paths[1], "list_wifi_ap_profiles");
    assert!(app.wifi_ap_profiles.as_ref().unwrap().profiles.is_empty());
    assert!(app.pending.is_none());
}

#[tokio::test]
async fn ap_scan_is_unavailable_even_without_running_status() {
    let mut app = TuiApp::default();
    let mut row = radio("wlan0");
    row.role = WifiRole::AccessPoint;
    app.wifi.rows.push(row);
    assert!(!actions(WifiRole::AccessPoint)
        .iter()
        .any(|(action, _)| matches!(action, PrimaryAction::Scan)));
    start_scan(
        &mut app,
        &ApiClient::new("/nonexistent.sock"),
        "wlan0".into(),
    )
    .await;
    assert!(app.wifi_scan.is_none());
    assert!(app.logs.back().unwrap().message.contains("unavailable"));
}

#[tokio::test]
async fn ap_profile_rejects_invalid_subnet_and_duplicate_id_without_saving() {
    let mut app = ap_profiles_app(WifiProfilesMode::Menu);
    ap_profiles::open_ap_profile_editor(&mut app, "wlan0".into(), None);
    let editor = app.wifi_editor.as_mut().unwrap();
    editor.profile_id = "guest".into();
    editor.subnet = "invalid subnet".into();
    editor.field = WifiField::SaveProfile;
    let client = ApiClient::new("/nonexistent.sock");
    handle_wifi_editor_key(&mut app, KeyCode::Enter, &client).await;
    assert!(app.logs.back().unwrap().message.contains("Invalid IPv4"));
    app.wifi_editor.as_mut().unwrap().subnet.clear();
    handle_wifi_editor_key(&mut app, KeyCode::Enter, &client).await;
    assert!(app.logs.back().unwrap().message.contains("already exists"));
    assert!(app.wifi_editor.is_some());
}

#[test]
fn ap_profile_actions_fit_small_terminal_and_mouse_skips_header() {
    let mut app = ap_profiles_app(WifiProfilesMode::ProfileActions);
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| render_wifi_ap_profiles(frame, frame.area(), &mut app))
        .unwrap();
    let text: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(text.contains("Apply profile"));
    assert!(text.contains("Edit profile"));
    assert!(text.contains("Delete profile"));
    assert!(!text.contains("Scan"));
    assert_eq!(app.ui.list_area.unwrap().y, 3);
    assert_eq!(app.ui.list_count, 4);
}

#[test]
fn configured_network_role_determines_wifi_role_before_activation() {
    use traffic_masq_protocol::{InterfaceConfigView, InterfaceRole};
    let mut config = InterfaceConfigView {
        mac_address: None,
        role: InterfaceRole::Input,
        managed: true,
        ipv4: None,
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
        nat: false,
    };
    assert_eq!(configured_role(Some(&config)), WifiRole::Client);
    config.role = InterfaceRole::Output;
    assert_eq!(configured_role(Some(&config)), WifiRole::AccessPoint);
    config.managed = false;
    assert_eq!(configured_role(Some(&config)), WifiRole::Unknown);
    assert_eq!(configured_role(None), WifiRole::Unknown);
}

#[test]
fn profile_libraries_are_navigable_without_radios() {
    let data = WifiData::default();
    assert_eq!(data.cursor_limit(), 1);
    let mut app = TuiApp::default();
    focus_action(&mut app, 1);
    assert_eq!(app.wifi.selected, 1);
    assert!(!app.wifi.actions_open);
}

#[tokio::test]
async fn standalone_profile_libraries_open_without_interfaces() {
    let (_dir, client, server) = mock_api(vec![
        Response::WifiClientProfiles { profiles: vec![] },
        Response::WifiApProfiles { profiles: vec![] },
    ])
    .await;
    let mut app = TuiApp {
        screen: Screen::Wifi,
        ..Default::default()
    };
    handle_wifi_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(app.screen, Screen::WifiProfiles);
    handle_wifi_profiles_key(&mut app, KeyCode::Down, &client).await;
    handle_wifi_profiles_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(app.screen, Screen::WifiProfileEditor);
    assert!(app
        .wifi_profile_editor
        .as_ref()
        .unwrap()
        .interface
        .is_empty());
    app.screen = Screen::Wifi;
    handle_wifi_key(&mut app, KeyCode::End, &client).await;
    handle_wifi_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(app.screen, Screen::WifiApProfiles);
    handle_wifi_ap_profiles_key(&mut app, KeyCode::Down, &client).await;
    handle_wifi_ap_profiles_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(app.screen, Screen::WifiEditor);
    assert!(app.wifi_editor.as_ref().unwrap().profile_mode);
    assert_eq!(server.await.unwrap().len(), 2);
    assert_eq!(
        WifiProfileAction::for_interface(""),
        &[
            WifiProfileAction::Edit,
            WifiProfileAction::Delete,
            WifiProfileAction::Back,
        ]
    );
}

#[tokio::test]
async fn saving_standalone_client_profile_returns_to_library_without_connecting() {
    let profile = WifiClientProfileSummary {
        id: "home".into(),
        ssid: "Home".into(),
        country_code: None,
        security: WifiClientSecurity::Open,
        priority: 0,
        autoconnect: false,
        created_at: 0,
        modified_at: 0,
        has_passphrase: false,
    };
    let (_dir, client, server) = mock_api(vec![
        Response::WifiClientProfile {
            profile: profile.clone(),
        },
        Response::WifiClientProfiles {
            profiles: vec![profile],
        },
    ])
    .await;
    let mut app = TuiApp::default();
    profiles::open_create_profile(&mut app, String::new());
    let editor = app.wifi_profile_editor.as_mut().unwrap();
    editor.id = "home".into();
    editor.ssid = "Home".into();
    editor.security = WifiClientSecurity::Open;
    editor.field = ProfileField::Save;
    handle_wifi_profile_editor_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(app.screen, Screen::WifiProfiles);
    assert!(app.wifi_connect.is_none());
    assert_eq!(app.wifi_profiles.as_ref().unwrap().profiles.len(), 1);
    assert_eq!(server.await.unwrap().len(), 2);
}

#[tokio::test]
async fn control_o_submits_wifi_connection_from_any_field() {
    let (_dir, client, server) = mock_api(vec![Response::WifiClientError {
        detail: traffic_masq_protocol::WifiClientErrorDetail::Other {
            message: "test rejection".into(),
        },
    }])
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
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| super::super::render(frame, &mut app, false))
        .unwrap();
    super::super::handle_key_event(
        &mut app,
        crossterm::event::KeyEvent::new(
            KeyCode::Char('o'),
            crossterm::event::KeyModifiers::CONTROL,
        ),
        &client,
        false,
    )
    .await;
    assert!(app.wifi_connect.as_ref().unwrap().reviewing);
    handle_wifi_connect_prompt_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(server.await.unwrap(), vec!["provision_wifi_client wlan0"]);
}

#[test]
fn saved_missing_ap_opens_editor_without_fake_runtime_and_unknown_is_distinct() {
    let config: traffic_masq_protocol::InterfaceConfigView =
        serde_json::from_value(serde_json::json!({
            "role": "output", "managed": true, "ipv4": "192.168.50.1/24", "nat": true,
            "wifi": {"ssid": "saved-ap", "security": "wpa2", "channel": 11, "hidden": true}
        }))
        .unwrap();
    let mut row = radio("usb0");
    row.presence = traffic_masq_protocol::InterfacePresence::Missing;
    row.configured = Some(config);
    row.revision = Some(7);
    row.role = WifiRole::AccessPoint;
    assert!(row.ap.is_none());
    assert!(describe_row_state(&row).contains("saved-ap"));
    assert!(describe_row_state(&row).contains("missing"));
    let editor = WifiEditor::from_row(&row);
    assert_eq!(editor.ssid, "saved-ap");
    assert_eq!(editor.original_spec.as_ref().unwrap().channel, 11);
    assert!(editor.original_spec.as_ref().unwrap().hidden);
    assert_eq!(editor.offline_intent.as_ref().unwrap().0, 7);
    assert!(!editor.configure_dhcp);
    row.presence = traffic_masq_protocol::InterfacePresence::Unknown;
    assert!(describe_row_state(&row).contains("observation unavailable"));
    assert!(!describe_row_state(&row).contains("missing"));
    assert!(WifiEditor::from_row(&row).offline_intent.is_none());
}

fn saved_client_inventory(presence: traffic_masq_protocol::InterfacePresence) -> Response {
    let config = serde_json::from_value(serde_json::json!({
        "role": "input", "managed": true, "ipv4": "192.0.2.10/24",
        "wifi_client": { "ssid": "saved-uplink", "security": "open" }
    }))
    .unwrap();
    Response::WifiInventory {
        revision: 7,
        ap_execution_available: false,
        client_execution_available: false,
        observation_error: None,
        interfaces: vec![traffic_masq_protocol::WifiInventoryEntry {
            interface: traffic_masq_protocol::InterfaceInventoryEntry {
                name: "wlan0".into(),
                observed: None,
                configured: Some(config),
                config_source: traffic_masq_protocol::InterfaceConfigSource::Base,
                presence,
                observation_stale: false,
                suppressed: false,
                readiness: traffic_masq_protocol::InterfaceReadiness::WaitingDevice,
                blockers: Vec::new(),
                references: Vec::new(),
            },
            ap_runtime: None,
            client_runtime: None,
        }],
    }
}

fn saved_client_interface_inventory(
    presence: traffic_masq_protocol::InterfacePresence,
) -> Response {
    let Response::WifiInventory {
        revision,
        interfaces,
        observation_error,
        ..
    } = saved_client_inventory(presence)
    else {
        unreachable!()
    };
    Response::InterfaceInventory {
        base_config: None,
        revision,
        interfaces: interfaces
            .into_iter()
            .map(|entry| entry.interface)
            .collect(),
        observation_error,
        suppressed_interfaces: Vec::new(),
    }
}

#[tokio::test]
async fn missing_client_without_wifi_settings_can_reopen_a_saved_profile_prompt() {
    let mut inventory =
        saved_client_interface_inventory(traffic_masq_protocol::InterfacePresence::Missing);
    if let Response::InterfaceInventory { interfaces, .. } = &mut inventory {
        interfaces[0].configured.as_mut().unwrap().wifi_client = None;
    }
    let (_dir, client, server) = mock_api(vec![inventory]).await;
    let mut app = TuiApp::default();
    open_wifi_connect_prompt(
        &mut app,
        &client,
        "wlan0".into(),
        "home".into(),
        "Home".into(),
    )
    .await;
    assert_eq!(
        app.wifi_connect.as_ref().unwrap().expected_revision,
        Some(7)
    );
    assert_eq!(server.await.unwrap(), vec!["list_interface_inventory"]);
}

#[tokio::test]
async fn missing_client_profile_prompt_saves_without_live_transaction_or_runtime() {
    use traffic_masq_protocol::InterfacePresence;
    let (_dir, client, server) = mock_api(vec![
        saved_client_interface_inventory(InterfacePresence::Missing),
        Response::InterfaceIntentSaved {
            interface: "wlan0".into(),
            revision: 8,
            deferred: true,
            missing_dependencies: vec!["wlan0".into()],
        },
        saved_client_inventory(InterfacePresence::Missing),
    ])
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
    let prompt = app.wifi_connect.as_ref().unwrap();
    assert_eq!(prompt.expected_revision, Some(7));
    assert_eq!(prompt.current_static_ip.as_deref(), Some("192.0.2.10/24"));
    submit_wifi_connect(&mut app, &client).await;
    assert_eq!(
        server.await.unwrap(),
        vec![
            "list_interface_inventory",
            "save_wifi_client_profile wlan0",
            "list_wifi_inventory"
        ]
    );
    assert!(app.pending.is_none());
    assert!(app.wifi_connect.is_none());
    assert_eq!(app.screen, Screen::Wifi);
    assert!(app.wifi.client_disabled);
    assert!(!app.wifi.rows[0].execution_available);
    let description = describe_row_state(&app.wifi.rows[0]);
    assert!(description.contains("missing") && description.contains("execution unavailable"));
}

#[tokio::test]
async fn unknown_client_observation_does_not_open_a_profile_prompt() {
    let (_dir, client, server) = mock_api(vec![saved_client_interface_inventory(
        traffic_masq_protocol::InterfacePresence::Unknown,
    )])
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
    assert_eq!(server.await.unwrap(), vec!["list_interface_inventory"]);
}

#[tokio::test]
async fn offline_profile_stale_error_keeps_the_prompt_and_revision_for_review() {
    let (_dir, client, server) = mock_api(vec![Response::Error {
        message: "stale revision".into(),
    }])
    .await;
    let mut prompt = WifiConnectPrompt::new("wlan0".into(), "home".into(), "Home".into(), None);
    prompt.expected_revision = Some(7);
    let mut app = TuiApp {
        screen: Screen::WifiConnectPrompt,
        wifi_connect: Some(prompt),
        ..Default::default()
    };
    submit_wifi_connect(&mut app, &client).await;
    assert_eq!(
        server.await.unwrap(),
        vec!["save_wifi_client_profile wlan0"]
    );
    assert_eq!(
        app.wifi_connect.as_ref().unwrap().expected_revision,
        Some(7)
    );
    assert!(app.pending.is_none());
}

#[tokio::test]
async fn connecting_with_a_known_pending_transaction_opens_recovery_without_another_request() {
    let client = ApiClient::new(std::path::PathBuf::from(
        "/nonexistent/traffic-masq-api.sock",
    ));
    let change = traffic_masq_protocol::PendingNetworkChange {
        recovery_progress: None,
        phase: traffic_masq_protocol::NetworkChangePhase::RecoveryRequired,
        last_error: Some("interface identity changed".into()),
        token: "recovery-token".into(),
        interface: "wlp5s0f3u3".into(),
        rollback_timeout_seconds: 60,
        expires_at_unix: 0,
    };
    let mut app = TuiApp {
        screen: Screen::WifiConnectPrompt,
        wifi_connect: Some(WifiConnectPrompt::new(
            "wlp5s0f3u3".into(),
            "home".into(),
            "Home".into(),
            None,
        )),
        ..Default::default()
    };
    app.dashboard.pending_network_changes.push(change.clone());
    submit_wifi_connect(&mut app, &client).await;
    assert_eq!(app.screen, Screen::PendingChange);
    assert_eq!(app.pending, Some(change));
    assert!(app.wifi_connect.is_none());
    assert_eq!(app.pending_return_screen, Screen::Wifi);
    assert_eq!(
        app.message.as_deref(),
        Some("Inspect the pending network transaction before reconnecting Wi-Fi")
    );
}

#[tokio::test]
async fn connect_prompt_backtab_moves_to_previous_field_without_changing_policy() {
    let mut prompt = WifiConnectPrompt::new("wlan0".into(), "home".into(), "Home".into(), None);
    prompt.choice = WifiIpChoice::NewStatic;
    prompt.field = WifiConnectField::Submit;
    let mut app = TuiApp {
        wifi_connect: Some(prompt),
        ..Default::default()
    };
    handle_wifi_connect_prompt_key(
        &mut app,
        KeyCode::BackTab,
        &ApiClient::new("/nonexistent.sock"),
    )
    .await;
    let prompt = app.wifi_connect.as_ref().unwrap();
    assert_eq!(prompt.field, WifiConnectField::StaticCidr);
    assert_eq!(prompt.choice, WifiIpChoice::NewStatic);
}

#[test]
fn connect_prompt_button_targets_match_live_and_offline_labels() {
    for offline in [false, true] {
        for field in [WifiConnectField::Submit, WifiConnectField::Cancel] {
            let mut prompt =
                WifiConnectPrompt::new("wlan0".into(), "home".into(), "Home".into(), None);
            prompt.expected_revision = offline.then_some(42);
            prompt.field = field;
            let mut app = TuiApp {
                wifi_connect: Some(prompt),
                ..Default::default()
            };
            let mut terminal =
                ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
            terminal
                .draw(|frame| render_wifi_connect_prompt(frame, frame.area(), &mut app))
                .unwrap();
            let (submit, _) = app.ui.buttons.iter().find(|(_, slot)| *slot == 0).unwrap();
            let (cancel, _) = app.ui.buttons.iter().find(|(_, slot)| *slot == 1).unwrap();
            let buffer = terminal.backend().buffer();
            let label: String = (cancel.x..cancel.right())
                .map(|x| buffer[(x, cancel.y)].symbol())
                .collect();
            assert_eq!(
                label,
                if field == WifiConnectField::Cancel {
                    "▶ [ Cancel (Esc) ]"
                } else {
                    "  [ Cancel ]"
                }
            );
            assert_eq!(cancel.x, submit.right() + 4);
        }
    }
}

#[tokio::test]
async fn wifi_and_ap_review_are_read_only_and_return_to_the_same_draft() {
    let client = ApiClient::new("/must-not-connect.sock");
    let mut prompt = WifiConnectPrompt::new(
        "wlan0".into(),
        "home".into(),
        "Home".into(),
        Some("192.0.2.1/24".into()),
    );
    prompt.field = WifiConnectField::Submit;
    let mut app = TuiApp {
        screen: Screen::WifiConnectPrompt,
        wifi_connect: Some(prompt),
        ..Default::default()
    };
    handle_wifi_connect_prompt_key(&mut app, KeyCode::Enter, &client).await;
    assert!(app.wifi_connect.as_ref().unwrap().reviewing);
    assert!(app.message.is_none());
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| crate::tui::render(frame, &mut app, false))
        .unwrap();
    let text: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(text.contains("192.0.2.1/24 → DHCP"));
    assert!(text.contains("Network unchanged"));
    assert_eq!(app.ui.buttons.len(), 2);
    handle_wifi_connect_prompt_key(&mut app, KeyCode::Esc, &client).await;
    assert!(!app.wifi_connect.as_ref().unwrap().reviewing);
    let mut editor = WifiEditor::from_row(&radio("wlan0"));
    editor.field = WifiField::Apply;
    app.wifi_editor = Some(editor);
    app.screen = Screen::WifiEditor;
    handle_wifi_editor_key(&mut app, KeyCode::Enter, &client).await;
    assert!(app.wifi_editor.as_ref().unwrap().reviewing);
    assert!(app.message.is_none());
    handle_wifi_editor_key(&mut app, KeyCode::Esc, &client).await;
    assert!(!app.wifi_editor.as_ref().unwrap().reviewing);
}

#[tokio::test]
async fn access_point_draft_resumes_without_reloading_or_losing_credentials() {
    let client = ApiClient::new("/must-not-connect.sock");
    let mut row = radio("wlan0");
    row.role = WifiRole::AccessPoint;
    let mut editor = WifiEditor::from_row(&row);
    editor.passphrase = "draft secret".into();
    editor.dirty = true;
    let mut app = TuiApp {
        screen: Screen::WifiEditor,
        wifi_editor: Some(editor),
        ..Default::default()
    };
    handle_wifi_editor_key(&mut app, KeyCode::Esc, &client).await;
    handle_wifi_editor_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(app.ap_drafts["wlan0"].passphrase, "draft secret");
    app.wifi.rows = vec![row];
    open_radio(&mut app, 0);
    handle_wifi_key(&mut app, KeyCode::Enter, &client).await;
    assert_eq!(app.screen, Screen::WifiEditor);
    assert_eq!(app.wifi_editor.as_ref().unwrap().passphrase, "draft secret");
    assert!(app.ap_drafts.is_empty());
}

#[tokio::test]
async fn saved_profile_from_radio_opens_ipv4_policy_without_management_menus() {
    let profile = WifiClientProfileSummary {
        created_at: 0,
        modified_at: 0,
        id: "home".into(),
        ssid: "Home".into(),
        security: WifiClientSecurity::Wpa2,
        country_code: None,
        priority: 1,
        autoconnect: true,
        has_passphrase: true,
    };
    let mock = crate::tui::test_api::mock(vec![
        Response::WifiClientProfiles {
            profiles: vec![profile],
        },
        saved_client_interface_inventory(traffic_masq_protocol::InterfacePresence::Present),
    ])
    .await;
    let mut app = TuiApp {
        screen: Screen::Wifi,
        ..Default::default()
    };
    app.wifi.rows = vec![radio("wlan0")];
    open_radio(&mut app, 0);
    focus_action(&mut app, 1);
    handle_wifi_key(&mut app, KeyCode::Enter, &mock.client).await;
    assert_eq!(
        app.wifi_profiles.as_ref().unwrap().mode,
        WifiProfilesMode::Connect
    );
    handle_wifi_profiles_key(&mut app, KeyCode::Enter, &mock.client).await;
    assert_eq!(app.screen, Screen::WifiConnectPrompt);
    assert_eq!(app.wifi_connect.as_ref().unwrap().profile_id, "home");
    assert_eq!(mock.calls.lock().unwrap().len(), 2);
}

#[test]
fn radio_card_shows_policy_and_frequent_ap_actions_at_both_sizes() {
    for (width, height) in [(80, 24), (120, 38)] {
        let mut row = radio("wlan0");
        row.role = WifiRole::AccessPoint;
        let mut app = TuiApp {
            screen: Screen::Wifi,
            ..Default::default()
        };
        app.wifi.rows = vec![row];
        open_radio(&mut app, 0);
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::tui::render(frame, &mut app, false))
            .unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(text.contains("SSID:"));
        assert!(text.contains("IPv4:"));
        assert!(text.contains("Connected devices"));
        assert!(matches!(
            actions(WifiRole::AccessPoint)[1].0,
            PrimaryAction::Stations
        ));
        assert!(app.ui.buttons.iter().any(|(_, slot)| *slot == 1));
    }
}
