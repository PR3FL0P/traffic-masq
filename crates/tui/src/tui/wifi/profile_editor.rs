use super::*;
use crate::tui::{input, layout};

pub(crate) fn render_wifi_profile_editor(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    app: &mut TuiApp,
) {
    let Some(editor) = &app.wifi_profile_editor else {
        return;
    };
    let values = [
        (ProfileField::Id, "Id", editor.id.clone()),
        (ProfileField::Ssid, "SSID", editor.ssid.clone()),
        (
            ProfileField::Security,
            "Security",
            client_security_label(editor.security).into(),
        ),
        (ProfileField::Country, "Country", editor.country.clone()),
        (ProfileField::Priority, "Priority", editor.priority.clone()),
        (
            ProfileField::Autoconnect,
            "Autoconnect",
            if editor.autoconnect {
                "[x] On"
            } else {
                "[ ] Off"
            }
            .into(),
        ),
        (
            ProfileField::Passphrase,
            "Passphrase",
            masked(&editor.passphrase, editor.has_passphrase),
        ),
        (
            ProfileField::Save,
            "",
            if editor.original_id.is_some() {
                "Update profile".into()
            } else {
                "Create profile".into()
            },
        ),
    ];
    let lines = values
        .into_iter()
        .map(|(field, label, value)| {
            let active = editor.field == field;
            let style = selected_style(active);
            let prefix = format!("{}{label:<14}", if active { "▶ " } else { "  " });
            let mut spans = vec![Span::styled(prefix, style)];
            if active
                && matches!(
                    field,
                    ProfileField::Id
                        | ProfileField::Ssid
                        | ProfileField::Country
                        | ProfileField::Priority
                )
            {
                spans.extend(input::render_value_with_cursor(
                    &value,
                    editor.cursor,
                    true,
                    style,
                ));
            } else if active && field == ProfileField::Passphrase {
                spans.extend(input::render_passphrase_with_cursor(
                    &editor.passphrase,
                    editor.cursor,
                    editor.has_passphrase,
                    style,
                ));
            } else {
                spans.push(Span::styled(value, style));
            }
            Line::from(spans)
        })
        .collect::<Vec<_>>();
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
        .block(panel("Wi-Fi profile editor")),
        area,
    );
}

pub(crate) async fn handle_wifi_profile_editor_key(
    app: &mut TuiApp,
    key: KeyCode,
    client: &ApiClient,
) {
    let Some(editor) = app.wifi_profile_editor.as_mut() else {
        app.screen = Screen::WifiProfiles;
        return;
    };
    match key {
        KeyCode::Esc => {
            app.wifi_profile_editor = None;
            app.screen = if app.wifi_profiles.is_some() {
                Screen::WifiProfiles
            } else {
                Screen::WifiScan
            };
        }
        KeyCode::Up => {
            editor.field = move_field(&PROFILE_FIELDS, editor.field, false);
            if editor.original_id.is_some() && editor.field == ProfileField::Id {
                editor.field = ProfileField::Save;
            }
            editor.reset_cursor();
        }
        KeyCode::Down => {
            editor.field = move_field(&PROFILE_FIELDS, editor.field, true);
            if editor.original_id.is_some() && editor.field == ProfileField::Id {
                editor.field = ProfileField::Ssid;
            }
            editor.reset_cursor();
        }
        KeyCode::Enter | KeyCode::Char(' ') if editor.field == ProfileField::Autoconnect => {
            editor.autoconnect = !editor.autoconnect;
        }
        KeyCode::Enter if editor.field == ProfileField::Security => {
            editor.security = cycle_client_security(editor.security)
        }
        KeyCode::Char(' ') if editor.field == ProfileField::Security => {
            editor.security = cycle_client_security(editor.security)
        }
        KeyCode::Enter if editor.field == ProfileField::Save => save_profile(app, client).await,
        KeyCode::Enter => {
            editor.field = move_field(&PROFILE_FIELDS, editor.field, true);
            if editor.original_id.is_some() && editor.field == ProfileField::Id {
                editor.field = ProfileField::Ssid;
            }
            editor.reset_cursor();
        }
        other => {
            if let Some(mut text_editor) = editor.active_editor() {
                text_editor.handle_key(other);
            }
        }
    }
}

async fn save_profile(app: &mut TuiApp, client: &ApiClient) {
    let Some(editor) = app.wifi_profile_editor.clone() else {
        return;
    };
    let profile = match editor.request() {
        Ok(profile) => profile,
        Err(message) => {
            app.push_message(LogLevel::Warn, message);
            return;
        }
    };
    let request = if let Some(id) = editor.original_id.clone() {
        Request::UpdateWifiClientProfile { id, profile }
    } else {
        Request::CreateWifiClientProfile { profile }
    };
    match client.request(&request).await {
        Ok(Response::WifiClientProfile {
            profile: saved_profile,
            ..
        }) => {
            app.push_message(LogLevel::Info, "Wi-Fi profile saved");
            let interface = editor.interface.clone();
            let is_new = editor.original_id.is_none();
            let profile_id = saved_profile.id.clone();
            let ssid = saved_profile.ssid.clone();
            app.wifi_profile_editor = None;
            app.screen = Screen::Wifi;
            if is_new && !interface.is_empty() {
                open_wifi_connect_prompt(app, client, interface, profile_id, ssid).await;
            } else {
                open_profiles(app, client, interface, WifiProfilesMode::Management).await;
            }
        }
        Ok(Response::WifiClientProfileError { detail }) => {
            app.push_message(LogLevel::Error, format!("{detail:?}"))
        }
        Ok(response) => report_unexpected(app, response),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}
