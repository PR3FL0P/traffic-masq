//! Reproducible documentation frames from the actual renderer, with synthetic data.
use super::*;
use ratatui::backend::TestBackend;
use traffic_masq_protocol::{InterfaceConfigView, InterfaceRole};

fn save_frame(dir: &std::path::Path, index: usize, title: &str, app: &mut TuiApp) {
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|frame| render(frame, app, false)).unwrap();
    let cells: Vec<_> = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| {
            serde_json::json!([
                cell.symbol(),
                format!("{:?}", cell.fg),
                format!("{:?}", cell.bg)
            ])
        })
        .collect();
    let document = serde_json::json!({"title": title, "width": 80, "height": 24, "cells": cells});
    std::fs::write(
        dir.join(format!("{index:02}.json")),
        serde_json::to_vec(&document).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
#[ignore = "exports demonstration frames; use packaging/render-tui-demo.py"]
async fn export_walkthrough() {
    let dir =
        PathBuf::from(std::env::var_os("TRAFFIC_MASQ_DEMO_DIR").expect("TRAFFIC_MASQ_DEMO_DIR"));
    std::fs::create_dir_all(&dir).unwrap();
    let config: InterfaceConfigView = serde_json::from_value(serde_json::json!({
        "role": "output", "managed": true, "ipv4": "192.168.50.1/24", "nat": true
    }))
    .unwrap();
    let mock = test_api::mock(vec![
        Response::InterfaceConfig {
            interface: "lan0".into(),
            config: Some(config.clone()),
            allow_management_change: false,
        },
        Response::InterfaceConfig {
            interface: "wlan0".into(),
            config: Some(config.clone()),
            allow_management_change: false,
        },
    ])
    .await;
    let mut app = TuiApp {
        screen: Screen::InterfaceList,
        connected_endpoint: Some("Demo data · 80×24".into()),
        ..Default::default()
    };
    let status = InterfaceStatus {
        interface: traffic_masq_protocol::NetworkInterfaceView {
            index: 1,
            name: "lan0".into(),
            is_up: true,
            rx_bytes: 1024,
            tx_bytes: 2048,
            is_wireless: false,
        },
        ipv4_addresses: vec![Ipv4AddressInfoView {
            interface_index: 1,
            address: "192.168.50.1".parse().unwrap(),
            prefix_len: 24,
            protocol: Some(201),
        }],
        owned_ipv4_addresses: None,
        has_default_route: false,
    };
    app.dashboard.interfaces = vec![status];
    app.dashboard
        .roles
        .insert("lan0".into(), InterfaceRole::Output);
    app.dashboard.managed.insert("lan0".into(), true);
    save_frame(&dir, 0, "Interface inventory", &mut app);
    interfaces::open_editor(&mut app, &mock.client).await;
    save_frame(&dir, 1, "Main settings and contextual help", &mut app);
    let editor = app.editor.as_mut().unwrap();
    editor.advanced = true;
    editor.field = interfaces::InterfaceEditorField::MacAddress;
    save_frame(&dir, 2, "Advanced MAC settings", &mut app);
    let editor = app.editor.as_mut().unwrap();
    editor.cidr = "192.168.60.1/24".into();
    app.preview = Some(InterfaceChangePlanView {
        mac_address: None,
        interface: "lan0".into(),
        delete_ipv4: app.dashboard.interfaces[0].ipv4_addresses.clone(),
        retag_ipv4: None,
        add_ipv4: Some(Ipv4AddressInfoView {
            interface_index: 1,
            address: "192.168.60.1".parse().unwrap(),
            prefix_len: 24,
            protocol: Some(201),
        }),
        set_link_up: true,
        management_change: false,
        dhcp_action: traffic_masq_protocol::DhcpChangeActionView::Unchanged,
        releasing_management: false,
    });
    app.screen = Screen::Preview;
    save_frame(
        &dir,
        3,
        "Review before applying: network unchanged",
        &mut app,
    );
    app.preview_scroll = usize::MAX;
    save_frame(
        &dir,
        4,
        "Apply temporarily after reviewing the complete plan",
        &mut app,
    );
    app.pending = Some(PendingNetworkChange {
        recovery_progress: None,
        token: "demo-change".into(),
        interface: "lan0".into(),
        rollback_timeout_seconds: 60,
        expires_at_unix: current_unix_time() + 45,
        phase: Default::default(),
        last_error: None,
    });
    app.screen = Screen::PendingChange;
    save_frame(&dir, 5, "Confirm connectivity or roll back now", &mut app);
    app.pending = None;
    app.screen = Screen::InterfaceEditor;
    let editor = app.editor.as_mut().unwrap();
    editor.interface = "usb-lan0".into();
    editor.offline_revision = Some(7);
    editor.field = interfaces::InterfaceEditorField::Save;
    editor.advanced = false;
    app.dashboard.base_config = Some(traffic_masq_protocol::InterfaceBaseConfigView {
        file: Some("/etc/traffic-masq/config.toml".into()),
        interfaces: vec!["usb-lan0".into()],
    });
    save_frame(&dir, 6, "Absent device: save, delete or restore", &mut app);
    app.editor.as_mut().unwrap().intent_confirmation = Some(true);
    save_frame(
        &dir,
        7,
        "Delete suppresses the base definition; profiles stay",
        &mut app,
    );
    app.editor.as_mut().unwrap().intent_confirmation = Some(false);
    save_frame(&dir, 8, "Restore from the actual base file", &mut app);
    app.editor.as_mut().unwrap().intent_confirmation = None;
    app.editor.as_mut().unwrap().exit_requested = true;
    save_frame(&dir, 9, "Keep a draft or discard edits", &mut app);
    app.editor = None;
    app.screen = Screen::Wifi;
    app.wifi.rows = vec![wifi::WifiRow {
        execution_available: true,
        presence: traffic_masq_protocol::InterfacePresence::Present,
        configured: None,
        revision: Some(7),
        interface: "wlan0".into(),
        role: wifi::WifiRole::Client,
        ap: None,
        client: None,
    }];
    wifi::open_radio(&mut app, 0);
    save_frame(
        &dir,
        10,
        "Client radio: scan, connect profile, disconnect",
        &mut app,
    );
    app.wifi_connect = Some(wifi::WifiConnectPrompt::new(
        "wlan0".into(),
        "home".into(),
        "Home Wi-Fi".into(),
        Some("192.0.2.20/24".into()),
    ));
    app.screen = Screen::WifiConnectPrompt;
    save_frame(
        &dir,
        11,
        "Select IPv4 policy on the connection screen",
        &mut app,
    );
    app.wifi_connect.as_mut().unwrap().field = wifi::WifiConnectField::Submit;
    wifi::handle_wifi_connect_prompt_key(&mut app, KeyCode::Enter, &mock.client).await;
    save_frame(
        &dir,
        12,
        "Review Wi-Fi connection before applying",
        &mut app,
    );
    app.wifi_connect = None;
    app.wifi.rows[0].role = wifi::WifiRole::AccessPoint;
    app.wifi.rows[0].configured = Some(config);
    app.screen = Screen::Wifi;
    wifi::open_radio(&mut app, 0);
    save_frame(
        &dir,
        13,
        "AP radio: configure and connected devices",
        &mut app,
    );
    wifi::handle_wifi_key(&mut app, KeyCode::Enter, &mock.client).await;
    app.wifi_editor.as_mut().unwrap().passphrase = "demonstration-password".into();
    app.wifi_editor.as_mut().unwrap().field = wifi::WifiField::Apply;
    save_frame(&dir, 14, "Configure access point", &mut app);
    wifi::handle_wifi_editor_key(&mut app, KeyCode::Enter, &mock.client).await;
    save_frame(&dir, 15, "Review AP, DHCP and passphrase policy", &mut app);
    app.screen = Screen::Log;
    app.push_message(
        LogLevel::Info,
        "Demo finished. Ctrl+G opens operation details; Ctrl+K opens help.",
    );
    save_frame(&dir, 16, "Operation log and details", &mut app);
}
