use crossterm::event::KeyCode;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use crate::api::client::ApiClient;
use crate::api::model::{ApiHttpsSettings, Request, Response};

use super::layout::panel;
use super::logs::LogLevel;
use super::theme;
use super::{Screen, TuiApp};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AccessField {
    Enabled,
    Listen,
    CertificatePath,
    PrivateKeyPath,
    Save,
    Reset,
    Reload,
}

#[derive(Debug, Clone)]
pub(crate) struct AccessEditor {
    pub(crate) field: AccessField,
    pub(crate) active: ApiHttpsSettings,
    pub(crate) desired: ApiHttpsSettings,
    pub(crate) override_active: bool,
    pub(crate) restart_required: bool,
}

impl AccessEditor {
    fn active_value_mut(&mut self) -> Option<&mut String> {
        match self.field {
            AccessField::Enabled | AccessField::Save | AccessField::Reset | AccessField::Reload => {
                None
            }
            AccessField::Listen => Some(&mut self.desired.listen),
            AccessField::CertificatePath => Some(
                self.desired
                    .certificate_path
                    .get_or_insert_with(String::new),
            ),
            AccessField::PrivateKeyPath => Some(
                self.desired
                    .private_key_path
                    .get_or_insert_with(String::new),
            ),
        }
    }
}

const ACCESS_FIELDS: [AccessField; 7] = [
    AccessField::Enabled,
    AccessField::Listen,
    AccessField::CertificatePath,
    AccessField::PrivateKeyPath,
    AccessField::Save,
    AccessField::Reset,
    AccessField::Reload,
];
const ACCESS_SAVE_LABEL: &str = "Save (applies after daemon restart)";
const ACCESS_RESET_LABEL: &str = "Reset to base config";
const ACCESS_RELOAD_LABEL: &str = "Reload";

pub(crate) async fn open_access_editor(app: &mut TuiApp, client: &ApiClient) {
    match client.request(&Request::GetApiHttpsConfig).await {
        Ok(Response::ApiHttpsConfig {
            active,
            desired,
            override_active,
            restart_required,
        }) => {
            app.api_access = Some(AccessEditor {
                field: AccessField::Enabled,
                active,
                desired,
                override_active,
                restart_required,
            });
            app.screen = Screen::Access;
        }
        Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected daemon response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

pub(crate) async fn refresh_access_status(app: &mut TuiApp, client: &ApiClient) {
    let Some(editor) = app.api_access.as_mut() else {
        return;
    };
    if let Ok(Response::ApiHttpsConfig {
        active,
        override_active,
        restart_required,
        ..
    }) = client.request(&Request::GetApiHttpsConfig).await
    {
        editor.active = active;
        editor.override_active = override_active;
        editor.restart_required = restart_required;
    }
}

pub(crate) fn render_access(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let Some(editor) = &app.api_access else {
        return;
    };

    let row = |label: &str, value: String, field: AccessField| {
        let active = editor.field == field;
        let marker = if active { "▶ " } else { "  " };
        let style = if active {
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        Line::styled(format!("{marker}{label}: {value}"), style)
    };

    let action_row = |label: &str, field: AccessField| {
        let active = editor.field == field;
        let marker = if active { "▶ " } else { "  " };
        let style = if active {
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme::ACCENT)
        };
        Line::styled(format!("{marker}{label}"), style)
    };

    let active_summary = format!(
        "Current process: {} on {}",
        if editor.active.enabled {
            "HTTPS enabled"
        } else {
            "HTTPS disabled"
        },
        editor.active.listen
    );
    let mut lines = vec![
        Line::from(active_summary),
        Line::styled(
            format!(
                "Current cert/key: {} | {}",
                editor.active.certificate_path.as_deref().unwrap_or("<none>"),
                editor.active.private_key_path.as_deref().unwrap_or("<none>"),
            ),
            Style::default().fg(theme::MUTED),
        ),
        Line::from(""),
        Line::styled(
            format!(
                "Saved override: {} | restart required: {}",
                editor.override_active, editor.restart_required
            ),
            Style::default().fg(if editor.restart_required {
                theme::WARN
            } else {
                theme::GOOD
            }),
        ),
        row(
            "Enabled after restart",
            editor.desired.enabled.to_string(),
            AccessField::Enabled,
        ),
        row(
            "Listen after restart",
            format!("{}_", editor.desired.listen),
            AccessField::Listen,
        ),
        row(
            "Certificate path",
            format!(
                "{}_",
                editor.desired.certificate_path.as_deref().unwrap_or_default()
            ),
            AccessField::CertificatePath,
        ),
        row(
            "Private key path",
            format!(
                "{}_",
                editor.desired.private_key_path.as_deref().unwrap_or_default()
            ),
            AccessField::PrivateKeyPath,
        ),
        Line::styled(
            "HTTPS settings are persisted immediately but only take effect after restarting traffic-masqd.",
            Style::default().fg(theme::WARN),
        ),
        Line::styled(
            "Expose only on trusted interfaces; remote access still requires bearer authentication over TLS.",
            Style::default().fg(theme::MUTED),
        ),
        Line::styled(
            "j/k: move | Enter/Space: activate | type to edit",
            Style::default().fg(theme::MUTED),
        ),
        Line::from(""),
    ];

    let mut button_rows: Vec<(u16, &str, usize)> = Vec::new();

    button_rows.push((lines.len() as u16, ACCESS_SAVE_LABEL, 0));
    lines.push(action_row(ACCESS_SAVE_LABEL, AccessField::Save));

    button_rows.push((lines.len() as u16, ACCESS_RESET_LABEL, 1));
    lines.push(action_row(ACCESS_RESET_LABEL, AccessField::Reset));

    button_rows.push((lines.len() as u16, ACCESS_RELOAD_LABEL, 2));
    lines.push(action_row(ACCESS_RELOAD_LABEL, AccessField::Reload));

    let block = panel("HTTPS access");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    for (row_index, label, slot) in button_rows {
        app.ui.buttons.push((
            Rect {
                x: inner.x,
                y: inner.y + row_index,
                width: label.len() as u16,
                height: 1,
            },
            slot,
        ));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

pub(crate) fn focus_action(app: &mut TuiApp, slot: usize) {
    if let Some(editor) = app.api_access.as_mut() {
        editor.field = match slot {
            0 => AccessField::Save,
            1 => AccessField::Reset,
            _ => AccessField::Reload,
        };
    }
}

pub(crate) async fn handle_access_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    let Some(editor) = app.api_access.as_mut() else {
        app.screen = Screen::Dashboard;
        return;
    };

    match key {
        KeyCode::Esc => app.screen = Screen::Dashboard,
        KeyCode::Up => editor.field = previous_field(editor.field),
        KeyCode::Down => editor.field = next_field(editor.field),
        KeyCode::Enter => match editor.field {
            AccessField::Enabled => editor.desired.enabled = !editor.desired.enabled,
            AccessField::Listen | AccessField::CertificatePath | AccessField::PrivateKeyPath => {}
            AccessField::Save => submit_access_settings(app, client).await,
            AccessField::Reset => reset_access_settings(app, client).await,
            AccessField::Reload => open_access_editor(app, client).await,
        },
        KeyCode::Backspace => {
            if let Some(value) = editor.active_value_mut() {
                value.pop();
            }
        }
        KeyCode::Char(character) if !character.is_control() => {
            if let Some(value) = editor.active_value_mut() {
                value.push(character);
            }
        }
        _ => {}
    }
}

pub(crate) async fn submit_access_settings(app: &mut TuiApp, client: &ApiClient) {
    let Some(editor) = &app.api_access else {
        return;
    };
    match client
        .request(&Request::ConfigureApiHttpsSettings {
            settings: editor.desired.clone(),
        })
        .await
    {
        Ok(Response::ApiHttpsConfig {
            active,
            desired,
            override_active,
            restart_required,
        }) => {
            app.api_access = Some(AccessEditor {
                field: AccessField::Enabled,
                active,
                desired,
                override_active,
                restart_required,
            });
            app.push_message(
                LogLevel::Info,
                "HTTPS settings saved; restart traffic-masqd to apply them",
            );
        }
        Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected daemon response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

pub(crate) async fn reset_access_settings(app: &mut TuiApp, client: &ApiClient) {
    match client.request(&Request::ResetApiHttpsSettings).await {
        Ok(Response::ApiHttpsConfig {
            active,
            desired,
            override_active,
            restart_required,
        }) => {
            app.api_access = Some(AccessEditor {
                field: AccessField::Enabled,
                active,
                desired,
                override_active,
                restart_required,
            });
            app.push_message(
                LogLevel::Info,
                "HTTPS override cleared; base config will be used after daemon restart",
            );
        }
        Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected daemon response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

fn next_field(current: AccessField) -> AccessField {
    let index = ACCESS_FIELDS
        .iter()
        .position(|field| *field == current)
        .unwrap_or(0);
    ACCESS_FIELDS[(index + 1).min(ACCESS_FIELDS.len() - 1)]
}

fn previous_field(current: AccessField) -> AccessField {
    let index = ACCESS_FIELDS
        .iter()
        .position(|field| *field == current)
        .unwrap_or(0);
    ACCESS_FIELDS[index.saturating_sub(1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_field_reaches_every_row_and_clamps_at_both_ends() {
        assert_eq!(next_field(AccessField::Enabled), AccessField::Listen);
        assert_eq!(
            next_field(AccessField::Listen),
            AccessField::CertificatePath
        );
        assert_eq!(
            next_field(AccessField::CertificatePath),
            AccessField::PrivateKeyPath
        );
        assert_eq!(next_field(AccessField::PrivateKeyPath), AccessField::Save);
        assert_eq!(next_field(AccessField::Save), AccessField::Reset);
        assert_eq!(next_field(AccessField::Reset), AccessField::Reload);
        assert_eq!(next_field(AccessField::Reload), AccessField::Reload);

        assert_eq!(previous_field(AccessField::Reload), AccessField::Reset);
        assert_eq!(previous_field(AccessField::Reset), AccessField::Save);
        assert_eq!(
            previous_field(AccessField::Save),
            AccessField::PrivateKeyPath
        );
        assert_eq!(previous_field(AccessField::Enabled), AccessField::Enabled);
    }

    #[test]
    fn access_editor_active_value_is_none_for_toggle_and_action_rows() {
        let settings = ApiHttpsSettings {
            enabled: false,
            listen: String::new(),
            certificate_path: None,
            private_key_path: None,
        };
        let mut editor = AccessEditor {
            field: AccessField::Save,
            active: settings.clone(),
            desired: settings,
            override_active: false,
            restart_required: false,
        };
        assert!(editor.active_value_mut().is_none());
        editor.field = AccessField::Reset;
        assert!(editor.active_value_mut().is_none());
        editor.field = AccessField::Reload;
        assert!(editor.active_value_mut().is_none());
        editor.field = AccessField::Enabled;
        assert!(editor.active_value_mut().is_none());
        editor.field = AccessField::Listen;
        assert!(editor.active_value_mut().is_some());
    }
}
