use super::*;
use crate::tui::{input, layout};

pub(crate) fn render_wifi_editor(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let Some(editor) = &app.wifi_editor else {
        return;
    };
    if let Some(selected) = editor.profile_picker {
        let height = area.height.saturating_sub(2) as usize;
        let offset = selected.saturating_sub(height.saturating_sub(1));
        let lines: Vec<Line<'_>> = editor
            .profiles
            .iter()
            .enumerate()
            .skip(offset)
            .map(|(i, p)| {
                Line::styled(
                    format!(
                        "{}{} — {}",
                        if i == selected { "▶ " } else { "  " },
                        p.id,
                        p.settings.ssid
                    ),
                    selected_style(i == selected),
                )
            })
            .collect();
        frame.render_widget(
            Paragraph::new(lines).block(panel("Load profile — ↑/↓ select, Enter load, Esc cancel")),
            area,
        );
        return;
    }
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
            "DHCP policy",
            if editor.configure_dhcp {
                "Enable / configure"
            } else if editor.disable_dhcp {
                "Disable"
            } else {
                "Preserve existing"
            }
            .into(),
        ),
        (WifiField::Subnet, "IPv4 subnet", editor.subnet.clone()),
        (
            WifiField::ProfileId,
            "Profile ID",
            editor.profile_id.clone(),
        ),
        (
            WifiField::SavedProfile,
            "Load profile",
            if editor.profiles.is_empty() {
                "(none saved)".into()
            } else {
                "Enter: choose saved profile".into()
            },
        ),
        (
            WifiField::SaveProfile,
            "",
            "Save / update profile (no network changes)".into(),
        ),
        (WifiField::DeleteProfile, "", "Delete profile by ID".into()),
        (
            WifiField::Apply,
            "",
            if editor.loaded_profile {
                "Apply saved profile (save edits separately)"
            } else if editor.configure_dhcp {
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
        if active
            && matches!(
                field,
                WifiField::Ssid | WifiField::CountryCode | WifiField::ProfileId | WifiField::Subnet
            )
        {
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
                spans.extend(input::render_masked_with_cursor(0, 0, true, '•', style));
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
    let block = panel(&format!(
        "Access point on {}{}",
        editor.interface,
        if editor.dirty { " *" } else { "" }
    ));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let body_height = inner.height.saturating_sub(3);
    let offset = layout::focused_lines_offset(&lines, body_height);
    frame.render_widget(
        Paragraph::new(lines.into_iter().skip(offset).collect::<Vec<_>>()),
        Rect::new(inner.x, inner.y, inner.width, body_height),
    );
    let warning = if editor.discard_requested {
        "Unsaved edits. Enter: discard and leave; Esc: keep editing."
    } else if editor.configure_dhcp {
        "DHCP: derive pool from LAN subnet; DNS is not advertised."
    } else if editor.disable_dhcp {
        "DHCP: stop the server on this interface."
    } else {
        "DHCP: preserve existing configuration."
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(warning),
            Line::from("Apply is tentative; confirm before the rollback timer expires."),
            Line::from("↑/↓: scroll fields | Enter/Space: choose | +/-: client limit"),
        ])
        .style(Style::default().fg(theme::WARN)),
        Rect::new(
            inner.x,
            inner.y + body_height,
            inner.width,
            inner.height - body_height,
        ),
    );
}

pub(crate) async fn handle_wifi_editor_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    let Some(editor) = app.wifi_editor.as_mut() else {
        app.screen = Screen::Wifi;
        return;
    };
    if editor.discard_requested {
        match key {
            KeyCode::Enter => {
                app.wifi_editor = None;
                app.screen = Screen::Wifi;
            }
            KeyCode::Esc => editor.discard_requested = false,
            _ => {}
        }
        return;
    }
    if let Some(selected) = editor.profile_picker {
        match key {
            KeyCode::Up => editor.profile_picker = Some(selected.saturating_sub(1)),
            KeyCode::Down => {
                editor.profile_picker =
                    Some((selected + 1).min(editor.profiles.len().saturating_sub(1)))
            }
            KeyCode::Esc => editor.profile_picker = None,
            KeyCode::Enter => {
                if let Some(profile) = editor.profiles.get(selected).cloned() {
                    editor.profile_id = profile.id;
                    editor.ssid = profile.settings.ssid.clone();
                    editor.country_code = profile.settings.country_code.clone().unwrap_or_default();
                    editor.security = profile.settings.security;
                    editor.configure_dhcp = profile.configure_dhcp;
                    editor.disable_dhcp = profile.disable_dhcp;
                    editor.subnet = profile.subnet.map(|ip| ip.to_string()).unwrap_or_default();
                    editor.existing = profile.has_passphrase;
                    editor.radio_settings = Some(profile.settings);
                    editor.passphrase.zeroize();
                    editor.passphrase.clear();
                    editor.loaded_profile = true;
                    editor.profile_picker = None;
                    editor.reset_cursor();
                }
            }
            _ => {}
        }
        return;
    }
    match key {
        KeyCode::Esc if editor.dirty => editor.discard_requested = true,
        KeyCode::Esc => {
            app.wifi_editor = None;
            app.screen = Screen::Wifi;
        }
        KeyCode::Enter if editor.field == WifiField::SavedProfile => {
            if editor.dirty {
                app.push_message(
                    LogLevel::Warn,
                    "Save your AP edits before loading another profile, or Esc to discard.",
                );
            } else if !editor.profiles.is_empty() {
                editor.profile_picker = Some(
                    editor
                        .profiles
                        .iter()
                        .position(|p| p.id == editor.profile_id)
                        .unwrap_or(0),
                );
            }
        }
        KeyCode::Enter if editor.field == WifiField::SaveProfile => {
            save_ap_profile(app, client).await;
        }
        KeyCode::Enter if editor.field == WifiField::DeleteProfile => {
            let id = editor.profile_id.clone();
            match client
                .request(&Request::DeleteWifiApProfile { id: id.clone() })
                .await
            {
                Ok(Response::WifiApProfileDeleted { .. }) => {
                    let editor = app.wifi_editor.as_mut().unwrap();
                    editor.profiles.retain(|p| p.id != id);
                    editor.loaded_profile = false;
                    editor.existing = editor
                        .original_spec
                        .as_ref()
                        .is_some_and(|s| s.requires_passphrase());
                    app.push_message(
                        LogLevel::Info,
                        "AP profile deleted; running AP is unchanged",
                    );
                }
                Ok(response) => report_unexpected(app, response),
                Err(error) => app.push_message(LogLevel::Error, error.to_string()),
            }
        }
        KeyCode::Up | KeyCode::BackTab => {
            editor.field = move_field(&WIFI_FIELDS, editor.field, false);
            editor.reset_cursor();
        }
        KeyCode::Down | KeyCode::Tab => {
            editor.field = move_field(&WIFI_FIELDS, editor.field, true);
            editor.reset_cursor();
        }
        KeyCode::Enter if editor.field == WifiField::Security => {
            editor.dirty = true;
            editor.security = cycle_ap_security(editor.security)
        }
        KeyCode::Char(' ') if editor.field == WifiField::Security => {
            editor.dirty = true;
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
            editor.dirty = true;
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
                        settings
                            .max_stations
                            .saturating_add(1)
                            .min(crate::config::MAX_WIFI_STATIONS)
                    }
                }
                WifiField::Dhcp => {
                    if editor.configure_dhcp {
                        editor.configure_dhcp = false;
                        editor.disable_dhcp = true;
                    } else if editor.disable_dhcp {
                        editor.disable_dhcp = false;
                    } else {
                        editor.configure_dhcp = true;
                    }
                }
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
            let before = editor.active_value().map(str::to_owned);
            if let Some(mut text_editor) = editor.active_editor() {
                text_editor.handle_key(other);
            }
            if before.as_deref() != editor.active_value() {
                editor.dirty = true;
            }
            if let Some(mut value) = before {
                value.zeroize();
            }
        }
    }
}

pub(super) fn ap_provision_request(editor: &WifiEditor) -> Request {
    Request::ProvisionWifiAccessPoint {
        interface: editor.interface.clone(),
        settings: ap_settings(editor),
        passphrase: (editor.security != WifiSecurity::Open && !editor.passphrase.is_empty())
            .then(|| editor.passphrase.clone()),
        clear_passphrase: editor.security == WifiSecurity::Open,
        configure_dhcp: editor.configure_dhcp,
        subnet: editor.subnet.trim().parse().ok(),
        disable_dhcp: editor.disable_dhcp,
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
    if editor.loaded_profile && editor.dirty {
        app.push_message(
            LogLevel::Warn,
            "Save / update profile before applying your edited profile.",
        );
        return;
    }
    if editor.ssid.trim().is_empty() {
        app.push_message(LogLevel::Warn, "SSID cannot be empty");
        return;
    }
    if editor.security != WifiSecurity::Open && editor.passphrase.is_empty() && !editor.existing {
        app.push_message(LogLevel::Warn, "This security mode requires a passphrase");
        return;
    }
    if !editor.subnet.trim().is_empty() && editor.subnet.trim().parse::<ipnet::Ipv4Net>().is_err() {
        app.push_message(LogLevel::Warn, "Invalid IPv4 subnet / CIDR");
        return;
    }
    let request = if editor.loaded_profile {
        Request::ActivateWifiApProfile {
            interface: editor.interface.clone(),
            profile_id: editor.profile_id.clone(),
        }
    } else {
        ap_provision_request(&editor)
    };
    match client.request(&request).await {
        Ok(Response::NetworkChangePending { change }) => {
            app.push_message(
                LogLevel::Info,
                "Access point change applied tentatively; confirm it before the rollback timer expires",
            );
            app.pending = Some(change);
            app.pending_return_screen = Screen::Wifi;
            app.wifi_editor = None;
            app.screen = Screen::PendingChange;
        }
        Ok(Response::WifiError { detail }) => {
            app.push_message(LogLevel::Error, format!("{detail:?}"))
        }
        Ok(response) => report_unexpected(app, response),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

async fn save_ap_profile(app: &mut TuiApp, client: &ApiClient) -> bool {
    let Some(editor) = app.wifi_editor.as_ref() else {
        return false;
    };
    let request = Request::SaveWifiApProfile {
        profile: crate::api::model::WifiApProfileWriteRequest {
            id: editor.profile_id.clone(),
            configuration: crate::api::model::ProvisionWifiAccessPointRequest {
                settings: ap_settings(editor),
                passphrase: (editor.security.requires_passphrase()
                    && !editor.passphrase.is_empty())
                .then(|| editor.passphrase.clone()),
                clear_passphrase: !editor.security.requires_passphrase(),
                configure_dhcp: editor.configure_dhcp,
                subnet: editor.subnet.trim().parse().ok(),
                disable_dhcp: editor.disable_dhcp,
            },
        },
    };
    match client.request(&request).await {
        Ok(Response::WifiApProfileSaved { profile }) => {
            let editor = app.wifi_editor.as_mut().unwrap();
            editor.profiles.retain(|p| p.id != profile.id);
            editor.existing = profile.has_passphrase;
            editor.profiles.push(profile);
            editor.profiles.sort_by(|a, b| a.id.cmp(&b.id));
            editor.loaded_profile = true;
            editor.dirty = false;
            app.push_message(LogLevel::Info, "AP profile saved");
            true
        }
        Ok(response) => {
            report_unexpected(app, response);
            false
        }
        Err(error) => {
            app.push_message(LogLevel::Error, error.to_string());
            false
        }
    }
}
