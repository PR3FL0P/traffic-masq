use super::*;

pub(crate) fn render_wifi_scan(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let Some(scan) = &app.wifi_scan else { return };
    let area = crate::tui::interface_status::render_context(frame, area, app, &scan.interface);
    let block = panel(&format!("Scan results on {}", scan.interface));
    let inner = block.inner(area);
    let offset = scan
        .selected
        .saturating_sub(inner.height.saturating_sub(1) as usize);
    app.ui.list_area = Some(inner);
    app.ui.list_count = scan.networks.len();
    app.ui.list_row_height = 1;
    app.ui.list_scroll_offset = offset;
    let lines = scan
        .networks
        .iter()
        .enumerate()
        .map(|(index, network)| {
            Line::styled(
                format!(
                    "{}{:>4} dBm  {:<32} {}",
                    if index == scan.selected { "▶ " } else { "  " },
                    network.signal_dbm,
                    if network.ssid.is_empty() {
                        "<hidden>"
                    } else {
                        &network.ssid
                    },
                    if std::str::from_utf8(&network.ssid_bytes).is_err() {
                        "unsupported: binary SSID"
                    } else {
                        scan_security_label(network.security)
                    }
                ),
                selected_style(index == scan.selected),
            )
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(lines.into_iter().skip(offset).collect::<Vec<_>>()).block(block),
        area,
    );
}

pub(crate) async fn handle_wifi_scan_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    let Some(scan) = app.wifi_scan.as_mut() else {
        app.screen = Screen::Wifi;
        return;
    };
    match key {
        KeyCode::Esc => {
            app.wifi_scan = None;
            app.screen = Screen::Wifi;
        }
        KeyCode::Up => scan.selected = scan.selected.saturating_sub(1),
        KeyCode::Down => {
            scan.selected = (scan.selected + 1).min(scan.networks.len().saturating_sub(1))
        }
        KeyCode::Home => scan.selected = 0,
        KeyCode::End => scan.selected = scan.networks.len().saturating_sub(1),
        KeyCode::Enter => {
            let Some(network) = scan.networks.get(scan.selected) else {
                return;
            };
            let interface = scan.interface.clone();
            let network = network.clone();
            if !network.ssid.is_empty()
                && std::str::from_utf8(&network.ssid_bytes).is_ok()
                && map_scan_security(network.security).is_ok()
            {
                match client.request(&Request::ListWifiClientProfiles).await {
                    Ok(Response::WifiClientProfiles { mut profiles }) => {
                        profiles.sort_by(|a, b| {
                            b.priority.cmp(&a.priority).then_with(|| a.id.cmp(&b.id))
                        });
                        if let Some(profile) = profiles.into_iter().find(|profile| {
                            profile.ssid == network.ssid
                                && Some(profile.security)
                                    == map_scan_security(network.security).ok()
                        }) {
                            open_wifi_connect_prompt(
                                app,
                                client,
                                interface,
                                profile.id,
                                profile.ssid,
                            )
                            .await;
                            return;
                        }
                    }
                    Ok(response) => {
                        report_unexpected(app, response);
                        return;
                    }
                    Err(error) => {
                        app.push_message(LogLevel::Warn, error.to_string());
                        return;
                    }
                }
            }
            match WifiProfileEditor::from_scan(interface, &network) {
                Ok(editor) => {
                    app.wifi_profile_editor = Some(editor);
                    app.screen = Screen::WifiProfileEditor;
                }
                Err(message) => app.push_message(LogLevel::Warn, message),
            }
        }
        _ => {}
    }
}
