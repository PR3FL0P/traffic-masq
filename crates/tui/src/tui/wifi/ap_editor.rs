use super::*;
use crate::tui::{
    api::model::{ProvisionWifiAccessPointRequest, WifiApProfileWriteRequest},
    input, layout,
};

pub(crate) fn render_wifi_editor(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    if let Some(dialog) = discard_confirmation(app) {
        dialog.render(
            frame,
            area,
            &mut app.ui,
            app.confirmation.confirmation_focus,
            app.confirmation.confirmation_scroll,
        );
        return;
    }
    let Some(editor) = &app.wifi_ui.wifi_editor else {
        return;
    };
    if editor.reviewing {
        let settings = ap_settings(editor);
        let mut lines = vec![
            format!(
                "Device: {}",
                crate::tui::interface_status::describe(app, &editor.interface)
            ),
            format!(
                "SSID: {} → {}",
                editor
                    .original_spec
                    .as_ref()
                    .map(|spec| spec.ssid.as_str())
                    .unwrap_or("none"),
                editor.ssid
            ),
            format!(
                "Security: {} → {}",
                editor
                    .original_spec
                    .as_ref()
                    .map(|spec| describe_ap_security(spec.security))
                    .unwrap_or("none"),
                describe_ap_security(editor.security)
            ),
        ];
        if let Some(parent) = &editor.concurrent_parent {
            lines.push(format!(
                "Input + Output: channel follows {parent}, width 20 MHz"
            ));
        } else {
            lines.extend(radio_review_lines(editor.original_spec.as_ref(), &settings));
        }
        lines.extend([
            format!(
                "IPv4 subnet: {}",
                if editor.subnet.is_empty() {
                    "preserve existing"
                } else {
                    &editor.subnet
                }
            ),
            format!(
                "DHCP: {}",
                if editor.configure_dhcp {
                    "configure from subnet"
                } else if editor.disable_dhcp {
                    "disable"
                } else {
                    "preserve existing"
                }
            ),
            format!(
                "Passphrase: {}",
                if editor.security == WifiSecurity::Open {
                    "remove passphrase (open network)"
                } else if editor.passphrase.is_empty() && editor.existing {
                    "preserve existing"
                } else if editor.passphrase.is_empty() {
                    "not set (required)"
                } else {
                    "set entered passphrase"
                }
            ),
        ]);
        layout::render_change_review(
            frame,
            area,
            &mut app.ui,
            "Access point · Review changes",
            lines,
            layout::ChangeReviewState {
                offline: editor.offline_intent.is_some(),
                cancel_selected: editor.field != WifiField::Apply,
                scroll: &mut app.interface_ui.preview_scroll,
                max_scroll: &mut app.interface_ui.preview_max_scroll,
            },
        );
        return;
    }
    let area = if editor.offline_intent.is_some() && !editor.profile_mode {
        layout::render_offline_intent_warning(frame, area)
    } else {
        area
    };

    let mut lines = if editor.profile_mode {
        Vec::new()
    } else {
        vec![Line::from(crate::tui::interface_status::describe(
            app,
            &editor.interface,
        ))]
    };
    if let Some(parent) = &editor.concurrent_parent {
        lines.push(Line::from(format!(
            "Input + Output: channel follows {parent}, width 20 MHz"
        )));
    }
    let settings = ap_settings(editor);
    let values = [
        (
            WifiField::ProfileId,
            "Profile ID",
            editor.profile_id.clone(),
        ),
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
            WifiField::SaveProfile,
            "",
            if editor.original_profile_id.is_some() {
                "Update profile"
            } else {
                "Create profile"
            }
            .into(),
        ),
        (
            WifiField::Apply,
            "",
            if editor.offline_intent.is_some() {
                "Review AP settings for device return"
            } else if editor.configure_dhcp {
                "Review AP + passphrase + DHCP"
            } else if editor.disable_dhcp {
                "Review AP; disable DHCP"
            } else {
                "Review AP; preserve DHCP"
            }
            .into(),
        ),
    ];
    let fields = editor.fields();
    for (field, label, value) in values {
        if !fields.contains(&field) {
            continue;
        }
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
            spans.extend(input::render_passphrase_with_cursor(
                &editor.passphrase,
                editor.cursor,
                editor.existing,
                style,
            ));
        } else {
            spans.push(Span::styled(value, style));
        }
        lines.push(Line::from(spans));
    }
    let block = panel(&format!(
        "{} on {}{}",
        if editor.profile_mode {
            format!("AP profile {}", editor.profile_id)
        } else {
            "Access point".to_string()
        },
        editor.interface,
        if editor.dirty { " *" } else { "" }
    ));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let body_height = inner.height.saturating_sub(3);
    let offset = layout::focused_lines_offset(&lines, body_height);
    if let Some(index) = fields
        .iter()
        .position(|field| matches!(field, WifiField::Apply | WifiField::SaveProfile))
    {
        if index >= offset && index < offset + body_height as usize {
            app.ui.buttons.push((
                Rect::new(inner.x, inner.y + (index - offset) as u16, inner.width, 1),
                0,
            ));
        }
    }
    frame.render_widget(
        Paragraph::new(lines.into_iter().skip(offset).collect::<Vec<_>>()),
        Rect::new(inner.x, inner.y, inner.width, body_height),
    );
    let warning = if editor.configure_dhcp {
        "DHCP: derive pool from LAN subnet; new servers use Settings DNS defaults."
    } else if editor.disable_dhcp {
        "DHCP: stop the server on this interface."
    } else {
        "DHCP: preserve existing configuration."
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(warning),
            Line::from(if editor.profile_mode {
                "Saving a profile does not change the running access point."
            } else if editor.offline_intent.is_some() {
                "Save applies automatically when the interface returns."
            } else {
                "Apply is tentative; confirm before the rollback timer expires."
            }),
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
    let Some(editor) = app.wifi_ui.wifi_editor.as_mut() else {
        app.screen = Screen::Wifi;
        return;
    };
    if editor.discard_requested {
        match key {
            KeyCode::Enter => {
                let mut draft = app.wifi_ui.wifi_editor.take().unwrap();
                draft.discard_requested = false;
                let key = draft_key(&draft);
                let profile_mode = draft.profile_mode;
                app.wifi_ui.ap_drafts.insert(key, draft);
                app.screen = if profile_mode {
                    Screen::WifiApProfiles
                } else {
                    Screen::Wifi
                };
                app.push_message(
                    LogLevel::Info,
                    "Draft kept for this session; reopen the editor to resume",
                );
            }
            KeyCode::Delete => close_editor(app),
            KeyCode::Esc => editor.discard_requested = false,
            _ => {}
        }
        return;
    }
    if editor.reviewing {
        if layout::scroll_change_review(
            key,
            &mut app.interface_ui.preview_scroll,
            app.interface_ui.preview_max_scroll,
        ) {
            return;
        }
        match key {
            KeyCode::Esc => {
                editor.reviewing = false;
                editor.field = WifiField::Apply;
            }
            KeyCode::Enter if editor.field != WifiField::Apply => {
                editor.reviewing = false;
                editor.field = WifiField::Apply;
            }
            KeyCode::Enter => apply_ap_editor(app, client).await,
            KeyCode::Tab
            | KeyCode::BackTab
            | KeyCode::Left
            | KeyCode::Right
            | KeyCode::Up
            | KeyCode::Down => {
                editor.field = if editor.field == WifiField::Apply {
                    WifiField::Ssid
                } else {
                    WifiField::Apply
                };
            }
            _ => {}
        }
        return;
    }
    match key {
        KeyCode::Esc if editor.dirty => editor.discard_requested = true,
        KeyCode::Esc => close_editor(app),
        KeyCode::Enter if editor.field == WifiField::SaveProfile && editor.profile_mode => {
            save_ap_profile(app, client).await;
        }
        KeyCode::Up | KeyCode::BackTab => {
            editor.field = move_field(&editor.fields(), editor.field, false);
            editor.reset_cursor();
        }
        KeyCode::Down | KeyCode::Tab => {
            editor.field = move_field(&editor.fields(), editor.field, true);
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
                            .min(traffic_masq_protocol::MAX_WIFI_STATIONS)
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
        KeyCode::Enter if editor.field == WifiField::Apply && !editor.profile_mode => {
            editor.reviewing = true;
            app.interface_ui.preview_scroll = 0;
        }
        KeyCode::Enter => {
            editor.field = move_field(&editor.fields(), editor.field, true);
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
    let configuration = ap_configuration(editor);
    Request::ProvisionWifiAccessPoint {
        interface: editor.interface.clone(),
        settings: configuration.settings,
        passphrase: configuration.passphrase,
        clear_passphrase: configuration.clear_passphrase,
        configure_dhcp: configuration.configure_dhcp,
        subnet: configuration.subnet,
        disable_dhcp: configuration.disable_dhcp,
    }
}

fn ap_configuration(editor: &WifiEditor) -> ProvisionWifiAccessPointRequest {
    ProvisionWifiAccessPointRequest {
        settings: ap_settings(editor),
        passphrase: (editor.security.requires_passphrase() && !editor.passphrase.is_empty())
            .then(|| editor.passphrase.clone()),
        clear_passphrase: !editor.security.requires_passphrase(),
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
    let Some(editor) = app.wifi_ui.wifi_editor.clone() else {
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
    if !editor.subnet.trim().is_empty() && editor.subnet.trim().parse::<ipnet::Ipv4Net>().is_err() {
        app.push_message(LogLevel::Warn, "Invalid IPv4 subnet / CIDR");
        return;
    }
    let request = if let Some((expected_revision, mut config)) = editor.offline_intent.clone() {
        let settings = ap_settings(&editor);
        let previous_secret = config
            .wifi
            .as_ref()
            .and_then(|wifi| wifi.passphrase_file.clone());
        config.wifi = Some(traffic_masq_protocol::WifiApConfigView {
            ssid: settings.ssid,
            country_code: settings.country_code,
            band: settings.band,
            channel: settings.channel,
            channel_width: settings.channel_width,
            security: settings.security,
            hidden: settings.hidden,
            client_isolation: settings.client_isolation,
            max_stations: settings.max_stations,
            passphrase_file: if settings.security == WifiSecurity::Open {
                None
            } else {
                previous_secret
            },
        });
        if !editor.subnet.trim().is_empty() {
            config.ipv4 = editor.subnet.trim().parse().ok();
        }
        if editor.disable_dhcp {
            config.dhcp = None;
        }
        if editor.configure_dhcp {
            let Some(cidr) = config.ipv4 else {
                app.push_message(
                    LogLevel::Warn,
                    "A saved IPv4 subnet is required to configure DHCP offline",
                );
                return;
            };
            let (pool_start, pool_end) = match traffic_masq_protocol::suggest_pool(cidr) {
                Ok(pool) => pool,
                Err(message) => {
                    app.push_message(LogLevel::Warn, message);
                    return;
                }
            };
            let dns_servers = match config.dhcp.as_ref() {
                Some(dhcp) => dhcp.dns_servers.clone(),
                None => match super::super::dns_defaults::fetch(client).await {
                    Ok(defaults) => defaults.servers,
                    Err(error) => {
                        app.push_message(LogLevel::Error, error.to_string());
                        return;
                    }
                },
            };
            config.dhcp = Some(traffic_masq_protocol::DhcpInterfaceConfigView {
                pool_start,
                pool_end,
                router: cidr.addr(),
                dns_servers,
                lease_seconds: None,
            });
        }
        Request::SaveWifiInterface {
            interface: editor.interface.clone(),
            config,
            expected_revision,
            passphrase: (!editor.passphrase.is_empty() && editor.security != WifiSecurity::Open)
                .then(|| editor.passphrase.clone()),
        }
    } else {
        ap_provision_request(&editor)
    };
    match client.request(&request).await {
        Ok(Response::InterfaceIntentSaved { interface, .. }) => {
            app.push_message(
                LogLevel::Info,
                format!("Saved immediately for {interface}; applies on device return. No automatic rollback."),
            );
            app.wifi_ui.wifi_editor = None;
            app.screen = Screen::Wifi;
            load_wifi_data(app, client).await;
        }
        Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
        Ok(Response::NetworkChangePending { change }) => {
            app.push_message(
                LogLevel::Info,
                "Access point change applied tentatively; confirm it before the rollback timer expires",
            );
            app.confirmation.pending_focus = 0;
            app.confirmation.pending = Some(change);
            app.confirmation.pending_return_screen = Screen::Wifi;
            app.wifi_ui.wifi_editor = None;
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
    let Some(editor) = app.wifi_ui.wifi_editor.as_ref() else {
        return false;
    };
    if !editor.subnet.trim().is_empty() && editor.subnet.trim().parse::<ipnet::Ipv4Net>().is_err() {
        app.push_message(LogLevel::Warn, "Invalid IPv4 subnet / CIDR");
        return false;
    }
    if editor.original_profile_id.is_none()
        && app
            .wifi_ui
            .wifi_ap_profiles
            .as_ref()
            .is_some_and(|view| view.profiles.iter().any(|p| p.id == editor.profile_id))
    {
        app.push_message(
            LogLevel::Warn,
            "A profile with this ID already exists; select it and choose Edit profile",
        );
        return false;
    }
    let request = Request::SaveWifiApProfile {
        profile: WifiApProfileWriteRequest {
            id: editor.profile_id.clone(),
            configuration: ap_configuration(editor),
        },
    };
    match client.request(&request).await {
        Ok(Response::WifiApProfileSaved { profile }) => {
            let interface = app.wifi_ui.wifi_editor.as_ref().unwrap().interface.clone();
            if let Some(view) = app.wifi_ui.wifi_ap_profiles.as_mut() {
                view.profiles.retain(|p| p.id != profile.id);
                let id = profile.id.clone();
                view.profiles.push(profile);
                view.profiles.sort_by(|a, b| a.id.cmp(&b.id));
                view.selected_profile = view.profiles.iter().position(|p| p.id == id).unwrap_or(0);
                view.selected = view.selected_profile;
                view.mode = WifiProfilesMode::Management;
            }
            app.wifi_ui.wifi_editor = None;
            app.screen = Screen::WifiApProfiles;
            app.push_message(LogLevel::Info, "AP profile saved");
            if app.wifi_ui.wifi_ap_profiles.is_none() {
                ap_profiles::open_ap_profiles(app, client, interface, WifiProfilesMode::Management)
                    .await;
            }
            true
        }
        Ok(Response::WifiError { detail }) => {
            app.push_message(LogLevel::Error, format!("{detail:?}"));
            false
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

fn close_editor(app: &mut TuiApp) {
    let profile_mode = app
        .wifi_ui
        .wifi_editor
        .as_ref()
        .is_some_and(|editor| editor.profile_mode);
    app.wifi_ui.wifi_editor = None;
    app.screen = if profile_mode {
        Screen::WifiApProfiles
    } else {
        Screen::Wifi
    };
}

pub(in crate::tui) fn discard_confirmation(
    app: &TuiApp,
) -> Option<crate::tui::confirmation::Dialog> {
    let editor = app.wifi_ui.wifi_editor.as_ref()?;
    editor
        .discard_requested
        .then(|| crate::tui::confirmation::Dialog {
            secondary: Some("Discard edits"),
            title: "Leave access point editor?",
            action: "Keep draft",
            lines: vec![
                if editor.profile_mode {
                    format!("AP profile: {}", editor.profile_id)
                } else {
                    format!("Interface: {}", editor.interface)
                },
                "Keep draft retains edits and entered credentials in memory for this session. Discard removes them without changing the network.".into(),
                "Cancel returns to editing.".into(),
            ],
        })
}

pub(super) fn draft_key(editor: &WifiEditor) -> String {
    if editor.profile_mode {
        format!(
            "profile:{}",
            editor.original_profile_id.as_deref().unwrap_or("new")
        )
    } else {
        editor.interface.clone()
    }
}

/// Include all AP radio policies in both editor and saved-profile reviews.
pub(super) fn radio_review_lines(
    before: Option<&WifiApSpecView>,
    settings: &WifiEditRequest,
) -> Vec<String> {
    let previous = |value: Option<String>| value.unwrap_or_else(|| "not reported".into());
    vec![
        format!(
            "Country: {} → {}",
            previous(before.map(|spec| spec.country_code.as_deref().unwrap_or("unset").to_owned())),
            settings.country_code.as_deref().unwrap_or("unset")
        ),
        format!(
            "Radio: {} → {} / channel {} / {:?}",
            previous(before.map(|spec| format!(
                "{} / channel {} / {:?}",
                spec.band, spec.channel, spec.channel_width
            ))),
            settings.band,
            settings.channel,
            settings.channel_width
        ),
        format!(
            "Hidden SSID: {} → {}",
            previous(before.map(|spec| spec.hidden.to_string())),
            settings.hidden
        ),
        format!(
            "Client isolation: {} → {}",
            previous(before.map(|spec| spec.client_isolation.to_string())),
            settings.client_isolation
        ),
        format!(
            "Max clients: {} → {}",
            previous(before.map(|spec| spec.max_stations.to_string())),
            settings.max_stations
        ),
    ]
}
