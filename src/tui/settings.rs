use crossterm::event::KeyCode;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::Paragraph;
use zeroize::Zeroize;

use crate::api::client::ApiClient;
use crate::api::model::{Request, Response, SecuritySettings};

use super::layout::panel;
use super::logs::LogLevel;
use super::theme;
use super::{Screen, TuiApp};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SettingsField {
    RollbackTimeout,
    RememberSession,
    RememberMinutes,
    SaveSession,
    ChangePassword,
    Reset,
    Save,
    Reload,
}

const SETTINGS_FIELDS: [SettingsField; 8] = [
    SettingsField::RollbackTimeout,
    SettingsField::RememberSession,
    SettingsField::RememberMinutes,
    SettingsField::SaveSession,
    SettingsField::ChangePassword,
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
    pub(crate) confirmation: Option<SettingsField>,
}

const SECURITY_SAVE_LABEL: &str = "Save (applies after daemon restart)";
const SECURITY_RESET_LABEL: &str = "Reset to base config";
const SECURITY_PASSWORD_LABEL: &str = "Change device password";
const SECURITY_RELOAD_LABEL: &str = "Reload";

fn note(text: impl Into<String>, style: Style) -> Line<'static> {
    Line::styled(format!("\tNote: {}", text.into()), style)
}

pub(crate) fn render_settings(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let Some(editor) = &app.settings else {
        return;
    };

    let row = |label: String, field: SettingsField, base: Style| {
        let active = editor.field == field;
        let marker = if active { "▶ " } else { "  " };
        let style = if active {
            base.add_modifier(Modifier::BOLD)
        } else {
            base
        };
        Line::styled(format!("{marker}{label}"), style)
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
        row(
            format!(
                "Rollback timeout after restart (seconds): {}_",
                editor.rollback_timeout_input
            ),
            SettingsField::RollbackTimeout,
            Style::default().fg(theme::ACCENT),
        ),
        note(
            "Saved immediately; takes effect after restarting traffic-masqd.",
            Style::default().fg(theme::WARN),
        ),
        note(
            "Arrows move · Enter activates · type digits to edit durations",
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
    lines.push(row(
        format!("Remember for (minutes): {}_", editor.remember_minutes_input),
        SettingsField::RememberMinutes,
        Style::default().fg(theme::ACCENT),
    ));
    button_rows.push((
        lines.len() as u16,
        "Save session preferences (applies now)",
        6,
    ));
    lines.push(row(
        "Save session preferences (applies now)".into(),
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

    if let Some(field) = editor.confirmation {
        let action = match field {
            SettingsField::SaveSession => "save session preferences",
            SettingsField::Reset => "reset security settings to the base config",
            SettingsField::Save => "save the rollback timeout override",
            _ => "apply this change",
        };
        lines.push(note(
            format!("Confirm: press Enter again to {action}; Esc cancels."),
            Style::default()
                .fg(theme::WARN)
                .add_modifier(Modifier::BOLD),
        ));
    }

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
    if let Some(editor) = app.settings.as_mut() {
        editor.field = match slot {
            0 => SettingsField::ChangePassword,
            1 => SettingsField::Reset,
            2 => SettingsField::Save,
            4 => SettingsField::RememberSession,
            5 => SettingsField::RememberMinutes,
            6 => SettingsField::SaveSession,
            _ => SettingsField::Reload,
        };
    }
}

pub(crate) async fn handle_settings_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    let Some(editor) = app.settings.as_mut() else {
        app.screen = Screen::Dashboard;
        return;
    };

    match key {
        KeyCode::Esc if editor.confirmation.is_some() => editor.confirmation = None,
        KeyCode::Esc => app.screen = Screen::Dashboard,
        KeyCode::Up => {
            editor.confirmation = None;
            editor.field = previous_settings_field(editor.field);
        }
        KeyCode::Down => {
            editor.confirmation = None;
            editor.field = next_settings_field(editor.field);
        }
        KeyCode::Backspace if editor.field == SettingsField::RollbackTimeout => {
            editor.rollback_timeout_input.pop();
        }
        KeyCode::Backspace if editor.field == SettingsField::RememberMinutes => {
            editor.remember_minutes_input.pop();
        }
        KeyCode::Char(' ') if editor.field == SettingsField::RememberSession => {
            editor.remember_session = !editor.remember_session;
        }
        KeyCode::Enter => match editor.field {
            SettingsField::RollbackTimeout | SettingsField::RememberMinutes => {}
            SettingsField::RememberSession => editor.remember_session = !editor.remember_session,
            SettingsField::SaveSession | SettingsField::Reset | SettingsField::Save
                if editor.confirmation != Some(editor.field) =>
            {
                editor.confirmation = Some(editor.field);
            }
            SettingsField::SaveSession => save_session_preferences(app, client).await,
            SettingsField::ChangePassword => {
                app.settings_password = Some(PasswordChangeEditor::new());
                app.screen = Screen::SettingsPassword;
            }
            SettingsField::Reset => reset_security_settings(app, client).await,
            SettingsField::Save => submit_security_settings(app, client).await,
            SettingsField::Reload => load_settings_data(app, client).await,
        },
        KeyCode::Char(character)
            if character.is_ascii_digit() && editor.field == SettingsField::RememberMinutes =>
        {
            editor.remember_minutes_input.push(character);
        }
        KeyCode::Char(character)
            if character.is_ascii_digit() && editor.field == SettingsField::RollbackTimeout =>
        {
            editor.rollback_timeout_input.push(character);
        }
        _ => {}
    }
}

async fn save_session_preferences(app: &mut TuiApp, client: &ApiClient) {
    let Some(editor) = &app.settings else {
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
    };
    let result = async {
        let store = super::session::SessionStore::for_client(client)?;
        store.save_preferences(&preferences, client).await
    }
    .await;
    match result {
        Ok(()) => app.push_message(
            LogLevel::Info,
            if preferences.remember {
                "Session preferences saved; duration starts at the last password entry"
            } else {
                "Session saving disabled; the next launch will require a password"
            },
        ),
        Err(error) => app.push_message(
            LogLevel::Error,
            format!("Could not save session preferences: {error}"),
        ),
    }
}

fn previous_settings_field(field: SettingsField) -> SettingsField {
    let index = SETTINGS_FIELDS
        .iter()
        .position(|candidate| *candidate == field)
        .unwrap_or(0);
    SETTINGS_FIELDS[index.saturating_sub(1)]
}

fn next_settings_field(field: SettingsField) -> SettingsField {
    let index = SETTINGS_FIELDS
        .iter()
        .position(|candidate| *candidate == field)
        .unwrap_or(0);
    SETTINGS_FIELDS[(index + 1).min(SETTINGS_FIELDS.len() - 1)]
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
            app.settings = Some(SecurityEditor {
                remember_session: preferences.remember,
                remember_minutes_input: preferences.minutes.to_string(),
                confirmation: None,
                field: SettingsField::RollbackTimeout,
                active,
                rollback_timeout_input: desired.rollback_timeout_seconds.to_string(),
                override_active,
                restart_required,
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
    let Some(editor) = app.settings.as_mut() else {
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
    let Some(editor) = &app.settings else {
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
            app.settings = Some(SecurityEditor {
                remember_session: preferences.remember,
                remember_minutes_input: preferences.minutes.to_string(),
                confirmation: None,
                field: SettingsField::RollbackTimeout,
                active,
                rollback_timeout_input: desired.rollback_timeout_seconds.to_string(),
                override_active,
                restart_required,
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
            app.settings = Some(SecurityEditor {
                remember_session: preferences.remember,
                remember_minutes_input: preferences.minutes.to_string(),
                confirmation: None,
                field: SettingsField::RollbackTimeout,
                active,
                rollback_timeout_input: desired.rollback_timeout_seconds.to_string(),
                override_active,
                restart_required,
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
        }
    }

    fn active_value_mut(&mut self) -> &mut String {
        match self.field {
            PasswordField::Current => &mut self.current,
            PasswordField::New => &mut self.new_password,
            PasswordField::Confirm => &mut self.confirm,
        }
    }

    fn zeroize_all(&mut self) {
        self.current.zeroize();
        self.new_password.zeroize();
        self.confirm.zeroize();
    }
}

fn next_password_field(current: PasswordField) -> PasswordField {
    let index = PASSWORD_FIELDS
        .iter()
        .position(|field| *field == current)
        .unwrap_or(0);
    PASSWORD_FIELDS[(index + 1) % PASSWORD_FIELDS.len()]
}

fn previous_password_field(current: PasswordField) -> PasswordField {
    let index = PASSWORD_FIELDS
        .iter()
        .position(|field| *field == current)
        .unwrap_or(0);
    PASSWORD_FIELDS[(index + PASSWORD_FIELDS.len() - 1) % PASSWORD_FIELDS.len()]
}

const PASSWORD_SUBMIT_LABEL: &str = "Submit";

pub(crate) fn render_settings_password(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    app: &mut TuiApp,
) {
    let Some(editor) = &app.settings_password else {
        return;
    };

    let field_line = |label: &str, value: &str, field: PasswordField| {
        let active = editor.field == field;
        let marker = if active { "▶ " } else { "  " };
        let style = if active {
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let masked = "•".repeat(value.chars().count());
        Line::styled(format!("{marker}{label}: {masked}"), style)
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
            "Up/Down or Tab: switch field | Enter: submit | Esc: cancel",
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

pub(crate) async fn handle_settings_password_key(
    app: &mut TuiApp,
    key: KeyCode,
    client: &ApiClient,
) {
    let Some(editor) = app.settings_password.as_mut() else {
        app.screen = Screen::Settings;
        return;
    };

    match key {
        KeyCode::Esc => {
            if let Some(editor) = app.settings_password.as_mut() {
                editor.zeroize_all();
            }
            app.settings_password = None;
            app.screen = Screen::Settings;
        }
        KeyCode::Down => editor.field = next_password_field(editor.field),
        KeyCode::Up => editor.field = previous_password_field(editor.field),
        KeyCode::Backspace => {
            editor.active_value_mut().pop();
        }
        KeyCode::Enter => submit_password_change(app, client).await,
        KeyCode::Char(character) if !character.is_control() => {
            editor.active_value_mut().push(character);
        }
        _ => {}
    }
}

async fn submit_password_change(app: &mut TuiApp, client: &ApiClient) {
    let Some(editor) = &app.settings_password else {
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
            if let Some(editor) = app.settings_password.as_mut() {
                editor.zeroize_all();
            }
            app.settings_password = None;
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
            if let Some(editor) = app.settings_password.as_mut() {
                editor.zeroize_all();
            }
            app.push_message(LogLevel::Error, error.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_fields_are_reachable_and_save_stays_visible_on_small_terminal() {
        assert_eq!(
            next_settings_field(SettingsField::RememberSession),
            SettingsField::RememberMinutes
        );
        assert_eq!(
            next_settings_field(SettingsField::RememberMinutes),
            SettingsField::SaveSession
        );
        assert_eq!(
            next_settings_field(SettingsField::SaveSession),
            SettingsField::ChangePassword
        );
        let mut app = TuiApp::default();
        app.settings = Some(SecurityEditor {
            field: SettingsField::SaveSession,
            active: SecuritySettings {
                rollback_timeout_seconds: 30,
            },
            rollback_timeout_input: "30".into(),
            override_active: false,
            restart_required: false,
            remember_session: true,
            remember_minutes_input: "5".into(),
            confirmation: None,
        });
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(60, 10)).unwrap();
        terminal
            .draw(|frame| render_settings(frame, frame.area(), &mut app))
            .unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(text.contains("Save session preferences"));
        let (rect, _) = app.ui.buttons.iter().find(|(_, slot)| *slot == 6).unwrap();
        assert!(rect.y < 9);
    }

    #[tokio::test]
    async fn mutating_settings_require_a_second_enter() {
        for field in [
            SettingsField::SaveSession,
            SettingsField::Reset,
            SettingsField::Save,
        ] {
            let mut app = TuiApp::default();
            app.settings = Some(SecurityEditor {
                field,
                active: SecuritySettings {
                    rollback_timeout_seconds: 30,
                },
                rollback_timeout_input: "30".into(),
                override_active: false,
                restart_required: false,
                remember_session: true,
                remember_minutes_input: "5".into(),
                confirmation: None,
            });

            handle_settings_key(
                &mut app,
                KeyCode::Enter,
                &ApiClient::new("/socket-that-must-not-be-opened"),
            )
            .await;

            assert_eq!(app.settings.as_ref().unwrap().confirmation, Some(field));
            assert!(app.message.is_none(), "first Enter must not submit");
        }
    }

    #[test]
    fn settings_field_clamps_at_both_ends_instead_of_wrapping() {
        assert_eq!(
            next_settings_field(SettingsField::RollbackTimeout),
            SettingsField::RememberSession
        );
        assert_eq!(
            next_settings_field(SettingsField::ChangePassword),
            SettingsField::Reset
        );
        assert_eq!(
            next_settings_field(SettingsField::Reset),
            SettingsField::Save
        );
        assert_eq!(
            next_settings_field(SettingsField::Save),
            SettingsField::Reload
        );
        assert_eq!(
            next_settings_field(SettingsField::Reload),
            SettingsField::Reload
        );
        assert_eq!(
            previous_settings_field(SettingsField::Reload),
            SettingsField::Save
        );
        assert_eq!(
            previous_settings_field(SettingsField::Save),
            SettingsField::Reset
        );
        assert_eq!(
            previous_settings_field(SettingsField::RollbackTimeout),
            SettingsField::RollbackTimeout
        );
    }

    #[test]
    fn password_field_cycles_forward_and_backward_through_all_three() {
        assert_eq!(
            next_password_field(PasswordField::Current),
            PasswordField::New
        );
        assert_eq!(
            next_password_field(PasswordField::New),
            PasswordField::Confirm
        );
        assert_eq!(
            next_password_field(PasswordField::Confirm),
            PasswordField::Current
        );
        assert_eq!(
            previous_password_field(PasswordField::Current),
            PasswordField::Confirm
        );
        assert_eq!(
            previous_password_field(PasswordField::New),
            PasswordField::Current
        );
    }

    #[test]
    fn password_editor_active_value_targets_the_selected_field() {
        let mut editor = PasswordChangeEditor::new();
        editor.active_value_mut().push_str("current-secret");
        assert_eq!(editor.current, "current-secret");
        assert!(editor.new_password.is_empty());

        editor.field = PasswordField::New;
        editor.active_value_mut().push_str("new-secret");
        assert_eq!(editor.new_password, "new-secret");
        assert_eq!(editor.current, "current-secret");

        editor.field = PasswordField::Confirm;
        editor.active_value_mut().push_str("new-secret");
        assert_eq!(editor.confirm, "new-secret");
    }

    #[test]
    fn zeroize_all_clears_every_buffer() {
        let mut editor = PasswordChangeEditor::new();
        editor.current.push('a');
        editor.new_password.push('b');
        editor.confirm.push('c');

        editor.zeroize_all();

        assert!(editor.current.is_empty());
        assert!(editor.new_password.is_empty());
        assert!(editor.confirm.is_empty());
    }
}
