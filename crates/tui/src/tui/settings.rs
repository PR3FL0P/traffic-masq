use crossterm::event::KeyCode;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use zeroize::Zeroize;

use crate::tui::api::client::ApiClient;
use crate::tui::api::model::{Request, Response, SecuritySettings};

use super::layout::{field_row, panel, text_field_row};
use super::logs::LogLevel;
use super::theme;
use super::{Screen, TuiApp};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SettingsField {
    RollbackTimeout,
    RememberSession,
    RememberMinutes,
    ShowDhcpClient,
    RandomizeMacDefault,
    SaveSession,
    ChangePassword,
    Access,
    DnsDefaults,
    Reset,
    Save,
    Reload,
}

const SETTINGS_FIELDS: [SettingsField; 12] = [
    SettingsField::RollbackTimeout,
    SettingsField::RememberSession,
    SettingsField::RememberMinutes,
    SettingsField::ShowDhcpClient,
    SettingsField::RandomizeMacDefault,
    SettingsField::SaveSession,
    SettingsField::ChangePassword,
    SettingsField::DnsDefaults,
    SettingsField::Access,
    SettingsField::Reset,
    SettingsField::Save,
    SettingsField::Reload,
];

#[derive(Debug, Clone)]
pub(crate) struct SecurityEditor {
    pub(crate) field: SettingsField,
    pub(crate) active: SecuritySettings,
    pub(crate) rollback_timeout_input: String,
    pub(crate) override_active: bool,
    pub(crate) restart_required: bool,
    pub(crate) remember_session: bool,
    pub(crate) remember_minutes_input: String,
    pub(crate) show_dhcp_client: bool,
    pub(crate) randomize_mac_default: bool,
    pub(crate) confirmation: Option<SettingsField>,
    pub(crate) cursor: usize,
    pub(crate) editing: bool,
}

impl SecurityEditor {
    pub(crate) fn is_editing(&self) -> bool {
        self.editing
            && matches!(
                self.field,
                SettingsField::RollbackTimeout | SettingsField::RememberMinutes
            )
    }

    pub(crate) fn active_text_input(&mut self) -> Option<(&mut String, &mut usize)> {
        match self.field {
            SettingsField::RollbackTimeout => {
                Some((&mut self.rollback_timeout_input, &mut self.cursor))
            }
            SettingsField::RememberMinutes => {
                Some((&mut self.remember_minutes_input, &mut self.cursor))
            }
            _ => None,
        }
    }

    pub(crate) fn reset_cursor(&mut self) {
        self.cursor = match self.field {
            SettingsField::RollbackTimeout => {
                super::input::grapheme_count(&self.rollback_timeout_input)
            }
            SettingsField::RememberMinutes => {
                super::input::grapheme_count(&self.remember_minutes_input)
            }
            _ => 0,
        };
    }
}

const SECURITY_SAVE_LABEL: &str = "Save (applies after daemon restart)";
const SECURITY_RESET_LABEL: &str = "Reset to base config";
const SECURITY_PASSWORD_LABEL: &str = "Change device password";
const SECURITY_ACCESS_LABEL: &str = "HTTPS access settings";
const SECURITY_RELOAD_LABEL: &str = "Reload";

fn note(text: impl Into<String>, style: Style) -> Line<'static> {
    Line::styled(format!("\tNote: {}", text.into()), style)
}

pub(super) fn confirmation(app: &TuiApp) -> Option<super::confirmation::Dialog> {
    let editor = app.settings_ui.settings.as_ref()?;
    let (title, action, lines) = match editor.confirmation? {
        SettingsField::Reset => (
            "Reset security settings?",
            "Reset",
            vec![
                "Target: security settings override".into(),
                "Remove the override and restore security settings from the base configuration."
                    .into(),
                "This changes the rollback timeout used by network transactions.".into(),
            ],
        ),
        SettingsField::Save => (
            "Save rollback timeout?",
            "Save",
            vec![
                "Target: security settings override".into(),
                format!(
                    "Rollback timeout: {} seconds",
                    editor.rollback_timeout_input
                ),
                "This timeout is used by network transactions.".into(),
            ],
        ),
        _ => return None,
    };
    Some(super::confirmation::Dialog {
        secondary: None,
        title,
        action,
        lines,
    })
}

pub(crate) fn render_settings(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    if let Some(dialog) = confirmation(app) {
        dialog.render(
            frame,
            area,
            &mut app.ui,
            app.confirmation.confirmation_focus,
            app.confirmation.confirmation_scroll,
        );
        return;
    }
    let Some(editor) = &app.settings_ui.settings else {
        return;
    };

    let row = |label: String, field: SettingsField, base: Style| {
        field_row(&label, editor.field == field, base)
    };
    let text_row = |label: &str, value: &str, field: SettingsField, base: Style| {
        text_field_row(
            label,
            value,
            editor.field == field,
            editor.cursor,
            editor.is_editing(),
            base,
        )
    };

    let mut lines = vec![
        Line::from(format!(
            "Current process: rollback timeout {}s",
            editor.active.rollback_timeout_seconds
        )),
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
        text_row(
            "Rollback timeout after restart (seconds)",
            &editor.rollback_timeout_input,
            SettingsField::RollbackTimeout,
            Style::default().fg(theme::ACCENT),
        ),
        note(
            "Saved immediately; takes effect after restarting traffic-masqd.",
            Style::default().fg(theme::WARN),
        ),
        note(
            if editor.is_editing() {
                "←/→ move cursor · 0-9 edit · Enter: next"
            } else {
                "Tab/Enter: next · type digits to edit"
            },
            Style::default().fg(theme::MUTED),
        ),
        Line::from(""),
    ];

    let mut button_rows: Vec<(u16, &str, usize)> = Vec::new();
    button_rows.push((lines.len() as u16, "Remember session: enabled", 4));
    lines.push(row(
        format!(
            "Remember session: {}",
            if editor.remember_session {
                "enabled"
            } else {
                "disabled"
            }
        ),
        SettingsField::RememberSession,
        Style::default().fg(theme::ACCENT),
    ));
    button_rows.push((lines.len() as u16, "Remember for (minutes):", 5));
    lines.push(text_row(
        "Remember for (minutes)",
        &editor.remember_minutes_input,
        SettingsField::RememberMinutes,
        Style::default().fg(theme::ACCENT),
    ));
    button_rows.push((lines.len() as u16, "DHCP client tab: enabled", 8));
    lines.push(row(
        format!(
            "DHCP client tab: {}",
            if editor.show_dhcp_client {
                "enabled"
            } else {
                "disabled"
            }
        ),
        SettingsField::ShowDhcpClient,
        Style::default().fg(theme::ACCENT),
    ));
    button_rows.push((
        lines.len() as u16,
        "Automatic MAC for new interfaces: enabled",
        10,
    ));
    lines.push(row(
        format!(
            "Automatic MAC for new interfaces: {}",
            if editor.randomize_mac_default {
                "enabled"
            } else {
                "disabled"
            }
        ),
        SettingsField::RandomizeMacDefault,
        Style::default().fg(theme::ACCENT),
    ));
    lines.push(note(
        "Sets the initial checkbox for new interfaces; saved interface policies take precedence.",
        Style::default().fg(theme::MUTED),
    ));
    button_rows.push((lines.len() as u16, "Save TUI preferences (applies now)", 6));
    lines.push(row(
        "Save TUI preferences (applies now)".into(),
        SettingsField::SaveSession,
        Style::default().fg(theme::ACCENT),
    ));
    lines.push(note(
        "Duration starts at password entry; daemon expiry may be earlier.",
        Style::default().fg(theme::MUTED),
    ));
    lines.push(Line::from(""));

    button_rows.push((lines.len() as u16, SECURITY_PASSWORD_LABEL, 0));
    lines.push(row(
        SECURITY_PASSWORD_LABEL.to_string(),
        SettingsField::ChangePassword,
        Style::default().fg(theme::ACCENT),
    ));

    button_rows.push((lines.len() as u16, "Default DNS for new DHCP servers", 9));
    lines.push(row(
        "Default DNS for new DHCP servers".into(),
        SettingsField::DnsDefaults,
        Style::default().fg(theme::ACCENT),
    ));

    button_rows.push((lines.len() as u16, SECURITY_ACCESS_LABEL, 7));
    lines.push(row(
        SECURITY_ACCESS_LABEL.to_string(),
        SettingsField::Access,
        Style::default().fg(theme::ACCENT),
    ));

    lines.push(Line::from(""));

    button_rows.push((lines.len() as u16, SECURITY_RESET_LABEL, 1));
    lines.push(row(
        SECURITY_RESET_LABEL.to_string(),
        SettingsField::Reset,
        Style::default().fg(theme::ACCENT),
    ));

    button_rows.push((lines.len() as u16, SECURITY_SAVE_LABEL, 2));
    lines.push(row(
        SECURITY_SAVE_LABEL.to_string(),
        SettingsField::Save,
        Style::default().fg(theme::ACCENT),
    ));

    button_rows.push((lines.len() as u16, SECURITY_RELOAD_LABEL, 3));
    lines.push(row(
        SECURITY_RELOAD_LABEL.to_string(),
        SettingsField::Reload,
        Style::default().fg(theme::ACCENT),
    ));

    let block = panel("Settings");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let offset = super::layout::focused_lines_offset(&lines, inner.height) as u16;
    for (row_index, label, slot) in button_rows {
        if row_index < offset || row_index - offset >= inner.height {
            continue;
        }
        app.ui.buttons.push((
            Rect {
                x: inner.x,
                y: inner.y + row_index - offset,
                width: (label.len() as u16).min(inner.width),
                height: 1,
            },
            slot,
        ));
    }
    frame.render_widget(Paragraph::new(lines).scroll((offset, 0)), inner);
}

pub(crate) fn focus_action(app: &mut TuiApp, slot: usize) {
    if let Some(editor) = app.settings_ui.settings.as_mut() {
        editor.field = match slot {
            0 => SettingsField::ChangePassword,
            1 => SettingsField::Reset,
            2 => SettingsField::Save,
            4 => SettingsField::RememberSession,
            5 => SettingsField::RememberMinutes,
            6 => SettingsField::SaveSession,
            7 => SettingsField::Access,
            8 => SettingsField::ShowDhcpClient,
            9 => SettingsField::DnsDefaults,
            10 => SettingsField::RandomizeMacDefault,
            _ => SettingsField::Reload,
        };
        editor.editing = false;
        editor.reset_cursor();
    }
}

pub(crate) async fn handle_settings_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    let Some(editor) = app.settings_ui.settings.as_mut() else {
        app.screen = Screen::Dashboard;
        return;
    };

    if editor.confirmation.is_some() && !matches!(key, KeyCode::Enter | KeyCode::Esc) {
        return;
    }
    match key {
        KeyCode::Esc if editor.is_editing() => {
            editor.editing = false;
        }
        KeyCode::Esc if editor.confirmation.is_some() => editor.confirmation = None,
        KeyCode::Esc => app.screen = Screen::Dashboard,
        KeyCode::Up => {
            editor.confirmation = None;
            editor.editing = false;
            editor.field = previous_settings_field(editor.field);
            editor.reset_cursor();
        }
        KeyCode::Down => {
            editor.confirmation = None;
            editor.editing = false;
            editor.field = next_settings_field(editor.field);
            editor.reset_cursor();
        }
        KeyCode::Char(' ') if editor.field == SettingsField::RememberSession => {
            editor.remember_session = !editor.remember_session;
        }
        KeyCode::Char(' ') if editor.field == SettingsField::ShowDhcpClient => {
            editor.show_dhcp_client = !editor.show_dhcp_client;
            app.show_dhcp_client = editor.show_dhcp_client;
        }
        KeyCode::Char(' ') if editor.field == SettingsField::RandomizeMacDefault => {
            editor.randomize_mac_default = !editor.randomize_mac_default;
        }
        KeyCode::Enter => match editor.field {
            SettingsField::RandomizeMacDefault => {
                editor.randomize_mac_default = !editor.randomize_mac_default;
            }
            SettingsField::RollbackTimeout | SettingsField::RememberMinutes => {
                editor.editing = false;
                editor.field = next_settings_field(editor.field);
                editor.reset_cursor();
            }
            SettingsField::RememberSession => editor.remember_session = !editor.remember_session,
            SettingsField::ShowDhcpClient => {
                editor.show_dhcp_client = !editor.show_dhcp_client;
                app.show_dhcp_client = editor.show_dhcp_client;
            }
            SettingsField::Reset | SettingsField::Save
                if editor.confirmation != Some(editor.field) =>
            {
                editor.confirmation = Some(editor.field);
            }
            SettingsField::SaveSession => {
                editor.confirmation = None;
                save_session_preferences(app, client).await;
            }
            SettingsField::ChangePassword => {
                app.settings_ui.settings_password = Some(PasswordChangeEditor::new());
                app.screen = Screen::SettingsPassword;
            }
            SettingsField::DnsDefaults => super::dns_defaults::open(app, client).await,
            SettingsField::Access => {
                super::access::open_access_editor(app, client).await;
            }
            SettingsField::Reset => {
                editor.confirmation = None;
                reset_security_settings(app, client).await;
            }
            SettingsField::Save => {
                editor.confirmation = None;
                submit_security_settings(app, client).await;
            }
            SettingsField::Reload => load_settings_data(app, client).await,
        },
        key if editor.is_editing()
            || (editor.active_text_input().is_some()
                && (matches!(key, KeyCode::Char(c) if c.is_ascii_digit())
                    || matches!(key, KeyCode::Backspace | KeyCode::Delete))) =>
        {
            editor.editing = true;
            if let Some((input, cursor)) = editor.active_text_input() {
                super::input::TextEditor::new(input, cursor)
                    .handle_key_filtered(key, |c| c.is_ascii_digit());
            }
        }
        _ => {}
    }
}

async fn save_session_preferences(app: &mut TuiApp, client: &ApiClient) {
    let Some(editor) = &app.settings_ui.settings else {
        return;
    };
    let Ok(minutes) = editor.remember_minutes_input.trim().parse::<u64>() else {
        app.push_message(
            LogLevel::Warn,
            "Session duration must be a whole number of minutes",
        );
        return;
    };
    let preferences = super::session::SessionPreferences {
        remember: editor.remember_session,
        minutes,
        show_dhcp_client: editor.show_dhcp_client,
        randomize_mac_default: editor.randomize_mac_default,
    };
    app.show_dhcp_client = preferences.show_dhcp_client;
    app.randomize_mac_default = preferences.randomize_mac_default;
    let result = async {
        let store = super::session::SessionStore::for_client(client)?;
        store.save_preferences(&preferences, client).await
    }
    .await;
    match result {
        Ok(()) => app.push_message(
            LogLevel::Info,
            if preferences.remember {
                "TUI preferences saved; session duration starts at the last password entry"
            } else {
                "TUI preferences saved; session saving disabled; the next launch will require a password"
            },
        ),
        Err(error) => app.push_message(
            LogLevel::Error,
            format!("Could not save TUI preferences: {error}"),
        ),
    }
}

fn previous_settings_field(field: SettingsField) -> SettingsField {
    super::input::move_clamped(&SETTINGS_FIELDS, field, false)
}

fn next_settings_field(field: SettingsField) -> SettingsField {
    super::input::move_clamped(&SETTINGS_FIELDS, field, true)
}

pub(crate) async fn load_settings_data(app: &mut TuiApp, client: &ApiClient) {
    match client.request(&Request::GetSecurityConfig).await {
        Ok(Response::SecurityConfig {
            active,
            desired,
            override_active,
            restart_required,
        }) => {
            let preferences = match super::session::SessionStore::for_client(client)
                .and_then(|store| store.preferences())
            {
                Ok(preferences) => preferences,
                Err(error) => {
                    app.push_message(
                        LogLevel::Warn,
                        format!("Could not load session preferences: {error}"),
                    );
                    super::session::SessionPreferences::default()
                }
            };
            app.show_dhcp_client = preferences.show_dhcp_client;
            app.randomize_mac_default = preferences.randomize_mac_default;
            let rollback_timeout_input = desired.rollback_timeout_seconds.to_string();
            let cursor = super::input::grapheme_count(&rollback_timeout_input);
            app.settings_ui.settings = Some(SecurityEditor {
                remember_session: preferences.remember,
                remember_minutes_input: preferences.minutes.to_string(),
                show_dhcp_client: preferences.show_dhcp_client,
                randomize_mac_default: preferences.randomize_mac_default,
                confirmation: None,
                field: SettingsField::RollbackTimeout,
                active,
                rollback_timeout_input,
                override_active,
                restart_required,
                cursor,
                editing: false,
            });
        }
        Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected daemon response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

pub(crate) async fn refresh_settings_status(app: &mut TuiApp, client: &ApiClient) {
    let Some(editor) = app.settings_ui.settings.as_mut() else {
        return;
    };
    if let Ok(Response::SecurityConfig {
        active,
        override_active,
        restart_required,
        ..
    }) = client.request(&Request::GetSecurityConfig).await
    {
        editor.active = active;
        editor.override_active = override_active;
        editor.restart_required = restart_required;
    }
}

pub(crate) async fn submit_security_settings(app: &mut TuiApp, client: &ApiClient) {
    let Some(editor) = &app.settings_ui.settings else {
        return;
    };
    let Ok(rollback_timeout_seconds) = editor.rollback_timeout_input.trim().parse::<u64>() else {
        app.push_message(
            LogLevel::Warn,
            "Rollback timeout must be a positive whole number of seconds",
        );
        return;
    };

    match client
        .request(&Request::ConfigureSecuritySettings {
            settings: SecuritySettings {
                rollback_timeout_seconds,
            },
        })
        .await
    {
        Ok(Response::SecurityConfig {
            active,
            desired,
            override_active,
            restart_required,
        }) => {
            let preferences = match super::session::SessionStore::for_client(client)
                .and_then(|store| store.preferences())
            {
                Ok(preferences) => preferences,
                Err(error) => {
                    app.push_message(
                        LogLevel::Warn,
                        format!("Could not load session preferences: {error}"),
                    );
                    super::session::SessionPreferences::default()
                }
            };
            app.show_dhcp_client = preferences.show_dhcp_client;
            app.randomize_mac_default = preferences.randomize_mac_default;
            let rollback_timeout_input = desired.rollback_timeout_seconds.to_string();
            let cursor = super::input::grapheme_count(&rollback_timeout_input);
            app.settings_ui.settings = Some(SecurityEditor {
                remember_session: preferences.remember,
                remember_minutes_input: preferences.minutes.to_string(),
                show_dhcp_client: preferences.show_dhcp_client,
                randomize_mac_default: preferences.randomize_mac_default,
                confirmation: None,
                field: SettingsField::RollbackTimeout,
                active,
                rollback_timeout_input,
                override_active,
                restart_required,
                cursor,
                editing: false,
            });
            app.push_message(
                LogLevel::Info,
                "Rollback timeout saved; restart traffic-masqd to apply it",
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

async fn reset_security_settings(app: &mut TuiApp, client: &ApiClient) {
    match client.request(&Request::ResetSecuritySettings).await {
        Ok(Response::SecurityConfig {
            active,
            desired,
            override_active,
            restart_required,
        }) => {
            let preferences = match super::session::SessionStore::for_client(client)
                .and_then(|store| store.preferences())
            {
                Ok(preferences) => preferences,
                Err(error) => {
                    app.push_message(
                        LogLevel::Warn,
                        format!("Could not load session preferences: {error}"),
                    );
                    super::session::SessionPreferences::default()
                }
            };
            app.show_dhcp_client = preferences.show_dhcp_client;
            app.randomize_mac_default = preferences.randomize_mac_default;
            let rollback_timeout_input = desired.rollback_timeout_seconds.to_string();
            let cursor = super::input::grapheme_count(&rollback_timeout_input);
            app.settings_ui.settings = Some(SecurityEditor {
                remember_session: preferences.remember,
                remember_minutes_input: preferences.minutes.to_string(),
                show_dhcp_client: preferences.show_dhcp_client,
                randomize_mac_default: preferences.randomize_mac_default,
                confirmation: None,
                field: SettingsField::RollbackTimeout,
                active,
                rollback_timeout_input,
                override_active,
                restart_required,
                cursor,
                editing: false,
            });
            app.push_message(
                LogLevel::Info,
                "Security override cleared; base config will be used after daemon restart",
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PasswordField {
    Current,
    New,
    Confirm,
}

const PASSWORD_FIELDS: [PasswordField; 3] = [
    PasswordField::Current,
    PasswordField::New,
    PasswordField::Confirm,
];

pub(crate) struct PasswordChangeEditor {
    pub(crate) field: PasswordField,
    pub(crate) current: String,
    pub(crate) new_password: String,
    pub(crate) confirm: String,
    pub(crate) cursor: usize,
}

impl Drop for PasswordChangeEditor {
    fn drop(&mut self) {
        self.zeroize_all();
    }
}

impl PasswordChangeEditor {
    fn new() -> Self {
        Self {
            field: PasswordField::Current,
            current: String::new(),
            new_password: String::new(),
            confirm: String::new(),
            cursor: 0,
        }
    }

    fn reset_cursor(&mut self) {
        self.cursor = super::input::grapheme_count(self.active_value());
    }

    fn active_value(&self) -> &str {
        match self.field {
            PasswordField::Current => &self.current,
            PasswordField::New => &self.new_password,
            PasswordField::Confirm => &self.confirm,
        }
    }

    #[allow(dead_code)]
    fn active_value_mut(&mut self) -> &mut String {
        match self.field {
            PasswordField::Current => &mut self.current,
            PasswordField::New => &mut self.new_password,
            PasswordField::Confirm => &mut self.confirm,
        }
    }

    fn active_editor(&mut self) -> super::input::TextEditor<'_> {
        match self.field {
            PasswordField::Current => {
                super::input::TextEditor::new(&mut self.current, &mut self.cursor)
            }
            PasswordField::New => {
                super::input::TextEditor::new(&mut self.new_password, &mut self.cursor)
            }
            PasswordField::Confirm => {
                super::input::TextEditor::new(&mut self.confirm, &mut self.cursor)
            }
        }
    }

    fn zeroize_all(&mut self) {
        self.current.zeroize();
        self.new_password.zeroize();
        self.confirm.zeroize();
    }
}

fn next_password_field(current: PasswordField) -> PasswordField {
    super::input::move_wrapped(&PASSWORD_FIELDS, current, true)
}

fn previous_password_field(current: PasswordField) -> PasswordField {
    super::input::move_wrapped(&PASSWORD_FIELDS, current, false)
}

const PASSWORD_SUBMIT_LABEL: &str = "Submit";

pub(crate) fn render_settings_password(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    app: &mut TuiApp,
) {
    let Some(editor) = &app.settings_ui.settings_password else {
        return;
    };

    let field_line = |label: &str, value: &str, field: PasswordField| -> Line<'static> {
        let active = editor.field == field;
        let marker = if active { "▶ " } else { "  " };
        let style = if active {
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let mut spans = vec![Span::styled(format!("{marker}{label}: "), style)];
        spans.extend(super::input::render_masked_with_cursor(
            super::input::grapheme_count(value),
            editor.cursor,
            active,
            '•',
            style,
        ));
        Line::from(spans)
    };

    let mut lines = vec![
        field_line("Current password", &editor.current, PasswordField::Current),
        field_line("New password", &editor.new_password, PasswordField::New),
        field_line(
            "Confirm new password",
            &editor.confirm,
            PasswordField::Confirm,
        ),
        Line::from(""),
        note(
            "Tab: next | Enter: next / submit on confirmation | Esc: cancel",
            Style::default().fg(theme::MUTED),
        ),
        note(
            "Changing the device password revokes every other active session; this TUI \
             session is re-authenticated automatically with the new password.",
            Style::default().fg(theme::WARN),
        ),
        Line::from(""),
    ];

    let block = panel("Change device password");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    app.ui.buttons.push((
        Rect {
            x: inner.x,
            y: inner.y + lines.len() as u16,
            width: PASSWORD_SUBMIT_LABEL.len() as u16,
            height: 1,
        },
        0,
    ));
    lines.push(Line::styled(
        PASSWORD_SUBMIT_LABEL,
        Style::default()
            .fg(theme::SELECTED_FG)
            .bg(theme::SELECTED_BG)
            .add_modifier(Modifier::BOLD),
    ));
    frame.render_widget(Paragraph::new(lines), inner);
}

pub(crate) fn focus_password_submit(app: &mut TuiApp) {
    if let Some(editor) = app.settings_ui.settings_password.as_mut() {
        editor.field = PasswordField::Confirm;
        editor.reset_cursor();
    }
}

pub(crate) async fn handle_settings_password_key(
    app: &mut TuiApp,
    key: KeyCode,
    client: &ApiClient,
) {
    let Some(editor) = app.settings_ui.settings_password.as_mut() else {
        app.screen = Screen::Settings;
        return;
    };

    match key {
        KeyCode::Esc => {
            if let Some(editor) = app.settings_ui.settings_password.as_mut() {
                editor.zeroize_all();
            }
            app.settings_ui.settings_password = None;
            app.screen = Screen::Settings;
        }
        KeyCode::Down => {
            editor.field = next_password_field(editor.field);
            editor.reset_cursor();
        }
        KeyCode::Up => {
            editor.field = previous_password_field(editor.field);
            editor.reset_cursor();
        }
        KeyCode::Enter if editor.field != PasswordField::Confirm => {
            editor.field = next_password_field(editor.field);
            editor.reset_cursor();
        }
        KeyCode::Enter => submit_password_change(app, client).await,
        other => {
            editor.active_editor().handle_key(other);
        }
    }
}

async fn submit_password_change(app: &mut TuiApp, client: &ApiClient) {
    let Some(editor) = &app.settings_ui.settings_password else {
        return;
    };
    if editor.current.is_empty() || editor.new_password.is_empty() {
        app.push_message(LogLevel::Warn, "Current and new password are required");
        return;
    }
    if editor.new_password != editor.confirm {
        app.push_message(LogLevel::Warn, "New password and confirmation do not match");
        return;
    }

    let mut current = editor.current.clone();
    let mut new_password = editor.new_password.clone();

    let change_result = client.change_password(&current, &new_password).await;
    current.zeroize();

    match change_result {
        Ok(()) => {
            let login_result = client.login(&new_password).await;
            new_password.zeroize();
            if let Some(editor) = app.settings_ui.settings_password.as_mut() {
                editor.zeroize_all();
            }
            app.settings_ui.settings_password = None;
            app.screen = Screen::Settings;
            match login_result {
                Ok(_) => match super::session::remember(client).await {
                    Ok(_) => app.push_message(
                        LogLevel::Info,
                        "Device password changed; other sessions were revoked",
                    ),
                    Err(error) => app.push_message(
                        LogLevel::Warn,
                        format!("Password changed, but could not save session: {error}"),
                    ),
                },
                Err(error) => app.push_message(
                    LogLevel::Error,
                    format!("Password changed but re-authentication failed: {error}"),
                ),
            }
        }
        Err(error) => {
            new_password.zeroize();
            if let Some(editor) = app.settings_ui.settings_password.as_mut() {
                editor.zeroize_all();
            }
            app.push_message(LogLevel::Error, error.to_string());
        }
    }
}

#[cfg(test)]
mod tests;
