use super::*;
use crate::tui::{input, layout};

pub(crate) fn render_wifi_editor(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let Some(editor) = &app.wifi_editor else {
        return;
    };
    let mut lines = Vec::new();
    let settings = ap_settings(editor);
    let values = [
        (WifiField::Ssid, "SSID", editor.ssid.clone()),
        (
            WifiField::Security,
            "Security",
            describe_ap_security(editor.security).into(),
        ),
        (
            WifiField::Passphrase,
            "Passphrase",
            masked(&editor.passphrase, editor.existing),
        ),
        (
            WifiField::CountryCode,
            "Country",
            editor.country_code.clone(),
        ),
        (WifiField::Band, "Band", settings.band.to_string()),
        (
            WifiField::Channel,
            "Channel",
            if settings.channel == 0 {
                "Auto".into()
            } else {
                settings.channel.to_string()
            },
        ),
        (
            WifiField::ChannelWidth,
            "Width",
            format!("{:?}", settings.channel_width),
        ),
        (
            WifiField::Hidden,
            "Hidden SSID",
            settings.hidden.to_string(),
        ),
        (
            WifiField::ClientIsolation,
            "Isolation",
            settings.client_isolation.to_string(),
        ),
        (
            WifiField::MaxStations,
            "Max clients",
            settings.max_stations.to_string(),
        ),
        (
            WifiField::Dhcp,
            "Configure DHCP",
            editor.configure_dhcp.to_string(),
        ),
        (
            WifiField::Apply,
            "",
            if editor.configure_dhcp {
                "Apply AP + passphrase + DHCP"
            } else {
                "Apply AP; preserve DHCP"
            }
            .into(),
        ),
    ];
    for (field, label, value) in values {
        let active = editor.field == field;
        let style = selected_style(active);
        let prefix = format!("{}{label:<14}", if active { "▶ " } else { "  " });
        let mut spans = vec![Span::styled(prefix, style)];
        if active && matches!(field, WifiField::Ssid | WifiField::CountryCode) {
            spans.extend(input::render_value_with_cursor(
                &value,
                editor.cursor,
                true,
                style,
            ));
        } else if active && field == WifiField::Passphrase {
            if editor.passphrase.is_empty() && editor.existing {
                spans.push(Span::styled(
                    "•••••• (saved; leave blank to keep) ",
                    Style::default().fg(theme::MUTED),
                ));
                spans.extend(input::render_masked_with_cursor(
                    0, 0, true, '•', style,
                ));
            } else {
                spans.extend(input::render_masked_with_cursor(
                    input::grapheme_count(&editor.passphrase),
                    editor.cursor,
                    true,
                    '•',
                    style,
                ));
            }
        } else {
            spans.push(Span::styled(value, style));
        }
        lines.push(Line::from(spans));
    }
    lines.push(Line::from(""));
    lines.push(Line::styled(
        if editor.configure_dhcp {
            "Creates derived DHCP from output IPv4; DNS is not advertised."
        } else {
            "Existing DHCP is preserved. Enter/Space changes radio options; +/- adjusts client limit."
        },
        Style::default().fg(theme::WARN),
    ));
    lines.push(Line::styled(
        "Apply updates the AP immediately; no commit-confirm timer is provided by this API.",
        Style::default().fg(theme::MUTED),
    ));
    frame.render_widget(
        Paragraph::new(
            lines
                .clone()
                .into_iter()
                .skip(layout::focused_lines_offset(
                    &lines,
                    area.height.saturating_sub(2),
                ))
                .collect::<Vec<_>>(),
        )
        .block(panel(&format!("Access point on {}", editor.interface))),
        area,
    );
}

pub(crate) async fn handle_wifi_editor_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    let Some(editor) = app.wifi_editor.as_mut() else {
        app.screen = Screen::Wifi;
        return;
    };
    match key {
        KeyCode::Esc => {
            app.wifi_editor = None;
            app.screen = Screen::Wifi;
        }
        KeyCode::Up => {
            editor.field = move_field(&WIFI_FIELDS, editor.field, false);
            editor.reset_cursor();
        }
        KeyCode::Down => {
            editor.field = move_field(&WIFI_FIELDS, editor.field, true);
            editor.reset_cursor();
        }
        KeyCode::Enter if editor.field == WifiField::Security => {
            editor.security = cycle_ap_security(editor.security)
        }
        KeyCode::Char(' ') if editor.field == WifiField::Security => {
            editor.security = cycle_ap_security(editor.security)
        }
        KeyCode::Enter | KeyCode::Char(' ') | KeyCode::Char('+') | KeyCode::Char('-')
            if matches!(
                editor.field,
                WifiField::Band
                    | WifiField::Channel
                    | WifiField::ChannelWidth
                    | WifiField::Hidden
                    | WifiField::ClientIsolation
                    | WifiField::MaxStations
                    | WifiField::Dhcp
            ) =>
        {
            let mut settings = ap_settings(editor);
            match editor.field {
                WifiField::Band => {
                    settings.band = if settings.band == WifiBand::Ghz2 {
                        WifiBand::Ghz5
                    } else {
                        WifiBand::Ghz2
                    };
                    settings.channel = 0;
                    settings.channel_width = WifiChannelWidth::Ht20;
                }
                WifiField::Channel => {
                    settings.channel = settings
                        .band
                        .channels()
                        .iter()
                        .copied()
                        .find(|c| *c > settings.channel)
                        .unwrap_or(0);
                }
                WifiField::ChannelWidth => {
                    settings.channel_width = match settings.channel_width {
                        WifiChannelWidth::Ht20 => WifiChannelWidth::Ht40,
                        WifiChannelWidth::Ht40 if settings.band == WifiBand::Ghz5 => {
                            WifiChannelWidth::Vht80
                        }
                        _ => WifiChannelWidth::Ht20,
                    }
                }
                WifiField::Hidden => settings.hidden = !settings.hidden,
                WifiField::ClientIsolation => {
                    settings.client_isolation = !settings.client_isolation
                }
                WifiField::MaxStations => {
                    settings.max_stations = if key == KeyCode::Char('-') {
                        settings.max_stations.saturating_sub(1).max(1)
                    } else {
                        settings.max_stations.saturating_add(1)
                    }
                }
                WifiField::Dhcp => editor.configure_dhcp = !editor.configure_dhcp,
                _ => unreachable!(),
            }
            editor.radio_settings = Some(settings);
        }
        KeyCode::Enter if editor.field == WifiField::Apply => apply_ap_editor(app, client).await,
        KeyCode::Enter => {
            editor.field = move_field(&WIFI_FIELDS, editor.field, true);
            editor.reset_cursor();
        }
        other => {
            if let Some(mut text_editor) = editor.active_editor() {
                text_editor.handle_key(other);
            }
        }
    }
}

pub(super) fn ap_provision_request(editor: &WifiEditor) -> Request {
    Request::ProvisionWifiAccessPoint {
        interface: editor.interface.clone(),
        settings: ap_settings(editor),
        passphrase: (!editor.passphrase.is_empty()).then(|| editor.passphrase.clone()),
        configure_dhcp: editor.configure_dhcp,
    }
}

pub(super) fn ap_settings(editor: &WifiEditor) -> WifiEditRequest {
    let mut settings = editor
        .radio_settings
        .clone()
        .unwrap_or_else(|| WifiEditRequest {
            ssid: editor.ssid.clone(),
            country_code: editor.country_code(),
            band: editor
                .original_spec
                .as_ref()
                .map_or(DEFAULT_BAND, |s| s.band),
            channel: editor
                .original_spec
                .as_ref()
                .map_or(DEFAULT_CHANNEL, |s| s.channel),
            channel_width: editor
                .original_spec
                .as_ref()
                .map_or(DEFAULT_CHANNEL_WIDTH, |s| s.channel_width),
            security: editor.security,
            hidden: editor.original_spec.as_ref().is_some_and(|s| s.hidden),
            client_isolation: editor
                .original_spec
                .as_ref()
                .is_some_and(|s| s.client_isolation),
            max_stations: editor
                .original_spec
                .as_ref()
                .map_or(DEFAULT_MAX_STATIONS, |s| s.max_stations),
        });
    settings.ssid = editor.ssid.clone();
    settings.country_code = editor.country_code();
    settings.security = editor.security;
    settings
}

async fn apply_ap_editor(app: &mut TuiApp, client: &ApiClient) {
    let Some(editor) = app.wifi_editor.clone() else {
        return;
    };
    if editor.ssid.trim().is_empty() {
        app.push_message(LogLevel::Warn, "SSID cannot be empty");
        return;
    }
    if editor.security != WifiSecurity::Open && editor.passphrase.is_empty() && !editor.existing {
        app.push_message(LogLevel::Warn, "This security mode requires a passphrase");
        return;
    }
    match client.request(&ap_provision_request(&editor)).await {
        Ok(Response::WifiAccessPointProvisioned { dhcp, .. }) => {
            app.push_message(
                LogLevel::Info,
                if dhcp.is_some() {
                    "Access point and derived DHCP configured"
                } else {
                    "Access point configured"
                },
            );
            app.wifi_editor = None;
            app.screen = Screen::Wifi;
            load_wifi_data(app, client).await;
        }
        Ok(Response::WifiError { detail }) => {
            app.push_message(LogLevel::Error, format!("{detail:?}"))
        }
        Ok(response) => report_unexpected(app, response),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}
