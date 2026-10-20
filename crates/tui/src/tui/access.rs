use crossterm::event::KeyCode;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use crate::tui::api::client::ApiClient;
use crate::tui::api::model::{ApiHttpsSettings, Request, Response};

use super::layout::{field_row, panel, text_field_row};
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
    pub(crate) cursor: usize,
}

impl AccessEditor {
    pub(crate) fn reset_cursor(&mut self) {
        self.cursor = self
            .active_value()
            .map(super::input::grapheme_count)
            .unwrap_or(0);
    }

    pub(crate) fn active_value(&self) -> Option<&str> {
        match self.field {
            AccessField::Listen => Some(&self.desired.listen),
            AccessField::CertificatePath => self.desired.certificate_path.as_deref(),
            AccessField::PrivateKeyPath => self.desired.private_key_path.as_deref(),
            _ => None,
        }
    }

    pub(crate) fn active_editor(&mut self) -> Option<super::input::TextEditor<'_>> {
        let cursor = &mut self.cursor;
        match self.field {
            AccessField::Enabled | AccessField::Save | AccessField::Reset | AccessField::Reload => {
                None
            }
            AccessField::Listen => Some(super::input::TextEditor::new(
                &mut self.desired.listen,
                cursor,
            )),
            AccessField::CertificatePath => Some(super::input::TextEditor::new(
                self.desired
                    .certificate_path
                    .get_or_insert_with(String::new),
                cursor,
            )),
            AccessField::PrivateKeyPath => Some(super::input::TextEditor::new(
                self.desired
                    .private_key_path
                    .get_or_insert_with(String::new),
                cursor,
            )),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn active_value_mut(&mut self) -> Option<&mut String> {
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
                cursor: 0,
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

    let field_style = |field: AccessField| {
        if editor.field == field {
            Style::default().fg(theme::ACCENT)
        } else {
            Style::default()
        }
    };
    let row = |label: &str, value: String, field: AccessField| {
        field_row(
            &format!("{label}: {value}"),
            editor.field == field,
            field_style(field),
        )
    };
    let text_row = |label: &str, value: &str, field: AccessField| {
        text_field_row(
            label,
            value,
            editor.field == field,
            editor.cursor,
            true,
            field_style(field),
        )
    };

    let action_row = |label: &str, field: AccessField| {
        field_row(
            label,
            editor.field == field,
            Style::default().fg(theme::ACCENT),
        )
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
        text_row(
            "Listen after restart",
            &editor.desired.listen,
            AccessField::Listen,
        ),
        text_row(
            "Certificate path",
            editor.desired.certificate_path.as_deref().unwrap_or_default(),
            AccessField::CertificatePath,
        ),
        text_row(
            "Private key path",
            editor.desired.private_key_path.as_deref().unwrap_or_default(),
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
            "arrows: move | Enter: activate | type or arrows to edit",
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
        editor.reset_cursor();
    }
}

pub(crate) async fn handle_access_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    let Some(editor) = app.api_access.as_mut() else {
        app.screen = Screen::Settings;
        return;
    };

    match key {
        KeyCode::Esc => app.screen = Screen::Settings,
        KeyCode::Up => {
            editor.field = previous_field(editor.field);
            editor.reset_cursor();
        }
        KeyCode::Down => {
            editor.field = next_field(editor.field);
            editor.reset_cursor();
        }
        KeyCode::Enter => match editor.field {
            AccessField::Enabled => editor.desired.enabled = !editor.desired.enabled,
            AccessField::Listen | AccessField::CertificatePath | AccessField::PrivateKeyPath => {
                editor.field = next_field(editor.field);
                editor.reset_cursor();
            }
            AccessField::Save => submit_access_settings(app, client).await,
            AccessField::Reset => reset_access_settings(app, client).await,
            AccessField::Reload => open_access_editor(app, client).await,
        },
        other => {
            if let Some(mut text_ed) = editor.active_editor() {
                text_ed.handle_key(other);
            }
        }
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
                cursor: 0,
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
                cursor: 0,
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
    super::input::move_clamped(&ACCESS_FIELDS, current, true)
}

fn previous_field(current: AccessField) -> AccessField {
    super::input::move_clamped(&ACCESS_FIELDS, current, false)
}

#[cfg(test)]
mod tests;
