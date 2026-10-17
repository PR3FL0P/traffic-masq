use crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use zeroize::Zeroize;

use crate::tui::api::client::ApiClient;
use crate::tui::api::model::{
    Request, Response, VpnActiveStatus, VpnErrorDetail, VpnProfileSummary,
};

use super::layout::panel;
use super::logs::LogLevel;
use super::theme;
use super::{Screen, TuiApp};

#[derive(Debug, Default, Clone)]
pub(crate) struct VpnData {
    pub(crate) profiles: Vec<VpnProfileSummary>,
    pub(crate) active: Option<VpnActiveStatus>,
    pub(crate) selected_profile: usize,
    pub(crate) error: Option<VpnErrorDetail>,
    pub(crate) focus: VpnFocus,
    pub(crate) enabled: Option<bool>,
    pub(crate) delete_confirmation: Option<String>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VpnFocus {
    #[default]
    List,
    Connect,
    Disconnect,
    Import,
    Delete,
    Policy,
    Refresh,
    ToggleEnabled,
}

const VPN_ACTION_FOCUS: [VpnFocus; 7] = [
    VpnFocus::Connect,
    VpnFocus::Disconnect,
    VpnFocus::Import,
    VpnFocus::Delete,
    VpnFocus::Policy,
    VpnFocus::Refresh,
    VpnFocus::ToggleEnabled,
];

fn next_vpn_action_focus(focus: VpnFocus) -> VpnFocus {
    super::input::move_clamped(&VPN_ACTION_FOCUS, focus, true)
}

fn previous_vpn_action_focus(focus: VpnFocus) -> VpnFocus {
    super::input::move_clamped(&VPN_ACTION_FOCUS, focus, false)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VpnImportField {
    Name,
    Path,
}

#[derive(Debug, Clone)]
pub(crate) struct VpnImportEditor {
    pub(crate) field: VpnImportField,
    pub(crate) name: String,
    pub(crate) path: String,
    pub(crate) cursor: usize,
    pub(crate) sources: Option<(String, Vec<String>)>,
    pub(crate) selected_source: usize,
}

impl VpnImportEditor {
    #[allow(dead_code)]
    fn active_value_mut(&mut self) -> &mut String {
        match self.field {
            VpnImportField::Name => &mut self.name,
            VpnImportField::Path => &mut self.path,
        }
    }

    pub(crate) fn active_value(&self) -> &str {
        match self.field {
            VpnImportField::Name => &self.name,
            VpnImportField::Path => &self.path,
        }
    }

    pub(crate) fn reset_cursor(&mut self) {
        self.cursor = super::input::grapheme_count(self.active_value());
    }

    pub(crate) fn active_editor(&mut self) -> super::input::TextEditor<'_> {
        let cursor = &mut self.cursor;
        match self.field {
            VpnImportField::Name => super::input::TextEditor::new(&mut self.name, cursor),
            VpnImportField::Path => super::input::TextEditor::new(&mut self.path, cursor),
        }
    }
}

pub(super) fn confirmation(app: &TuiApp) -> Option<super::confirmation::Dialog> {
    let name = app.vpn.delete_confirmation.as_ref()?;
    Some(super::confirmation::Dialog {
        secondary: None,
        title: "Delete saved VPN profile?",
        action: "Delete",
        lines: vec![
            format!("Profile: {name}"),
            "The saved VPN configuration and its keys will be deleted.".into(),
            "Deletion is immediate and cannot be undone.".into(),
        ],
    })
}

pub(crate) fn render_vpn(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    if let Some(dialog) = confirmation(app) {
        dialog.render(
            frame,
            area,
            &mut app.ui,
            app.confirmation_focus,
            app.confirmation_scroll,
        );
        return;
    }
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(3)])
        .split(area);

    let mut status_lines = vec![Line::styled(
        match app.vpn.enabled {
            Some(true) => "VPN: enabled",
            Some(false) => "VPN: disabled — press e to enable",
            None => "VPN: status unavailable",
        },
        Style::default().fg(if app.vpn.enabled == Some(true) {
            theme::GOOD
        } else {
            theme::WARN
        }),
    )];
    match &app.vpn.active {
        Some(active) => status_lines.push(Line::styled(
            format!(
                "Active: {} on {} ({})",
                active.profile_name,
                active.interface,
                if active.up { "up" } else { "down" }
            ),
            Style::default().fg(if active.up { theme::GOOD } else { theme::WARN }),
        )),
        None => status_lines.push(Line::styled(
            "Active: none",
            Style::default().fg(theme::MUTED),
        )),
    }
    if let Some(detail) = &app.vpn.error {
        status_lines.push(Line::styled(
            format!("Error: {}", describe_vpn_error(detail)),
            Style::default().fg(theme::BAD).add_modifier(Modifier::BOLD),
        ));
    }
    frame.render_widget(
        Paragraph::new(status_lines).block(panel("VPN status")),
        chunks[0],
    );

    let block = panel("Profiles");
    let inner = block.inner(chunks[1]);
    frame.render_widget(block, chunks[1]);

    let profile_and_actions = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(7)])
        .split(inner);
    let list_area = profile_and_actions[0];
    let actions_area = profile_and_actions[1];

    let visible_profiles = list_area.height.max(1) as usize;
    let max_scroll = app.vpn.profiles.len().saturating_sub(visible_profiles);
    let scroll = app
        .vpn
        .selected_profile
        .saturating_sub(visible_profiles.saturating_sub(1))
        .min(max_scroll);
    app.ui.list_area = Some(list_area);
    app.ui.list_row_height = 1;
    app.ui.list_count = app.vpn.profiles.len();
    app.ui.list_scroll_offset = scroll;

    let list_focused = app.vpn.focus == VpnFocus::List;
    let profile_lines: Vec<Line> = if app.vpn.profiles.is_empty() {
        vec![Line::styled(
            "(none imported)",
            Style::default().fg(theme::MUTED),
        )]
    } else {
        app.vpn
            .profiles
            .iter()
            .enumerate()
            .skip(scroll)
            .take(visible_profiles)
            .map(|(index, profile)| {
                let selected = index == app.vpn.selected_profile;
                let marker = if selected { "▶" } else { " " };
                let style = if selected && list_focused {
                    Style::default()
                        .fg(theme::ACCENT)
                        .add_modifier(Modifier::BOLD)
                } else if selected {
                    Style::default().fg(theme::ACCENT)
                } else {
                    Style::default()
                };
                Line::styled(
                    format!("{marker} {} ({} bytes)", profile.name, profile.size_bytes),
                    style,
                )
            })
            .collect()
    };
    frame.render_widget(Paragraph::new(profile_lines), list_area);

    let action = |label: &str, active: bool| {
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
    let mut action_lines = Vec::with_capacity(6);
    for (slot, (label, focus)) in [
        (VPN_CONNECT_LABEL, VpnFocus::Connect),
        (VPN_DISCONNECT_LABEL, VpnFocus::Disconnect),
        (VPN_IMPORT_LABEL, VpnFocus::Import),
        (VPN_DELETE_LABEL, VpnFocus::Delete),
        (VPN_POLICY_LABEL, VpnFocus::Policy),
        (VPN_REFRESH_LABEL, VpnFocus::Refresh),
        (
            if app.vpn.enabled == Some(true) {
                "Disable VPN: e"
            } else {
                "Enable VPN: e"
            },
            VpnFocus::ToggleEnabled,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        app.ui.buttons.push((
            Rect {
                x: actions_area.x,
                y: actions_area.y + slot as u16,
                width: label.len() as u16,
                height: 1,
            },
            slot,
        ));
        action_lines.push(action(label, app.vpn.focus == focus));
    }
    frame.render_widget(Paragraph::new(action_lines), actions_area);
}

const VPN_CONNECT_LABEL: &str = "Connect selected profile";
const VPN_DISCONNECT_LABEL: &str = "Disconnect";
const VPN_IMPORT_LABEL: &str = "Import profile";
const VPN_DELETE_LABEL: &str = "Delete selected profile";
const VPN_POLICY_LABEL: &str = "Traffic policy";
const VPN_REFRESH_LABEL: &str = "Refresh";

const VPN_IMPORT_SAVE_LABEL: &str = "Import";

pub(crate) fn render_vpn_import(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let Some(editor) = &app.vpn_import else {
        return;
    };
    if let Some((directory, names)) = &editor.sources {
        let mut lines = vec![
            Line::styled(
                format!("WireGuard configs: {directory}"),
                Style::default().fg(theme::ACCENT),
            ),
            Line::from(
                "Up/Down: select | Enter: import | r: refresh | p: local file | Esc: cancel",
            ),
            Line::from(""),
        ];
        if names.is_empty() {
            lines.push(Line::from(
                "No .conf files found. Put your WireGuard config in this directory.",
            ));
        }
        let visible_rows = area.height.saturating_sub(5).max(1) as usize;
        let start = editor.selected_source.saturating_sub(visible_rows - 1);
        for (index, name) in names.iter().enumerate().skip(start).take(visible_rows) {
            lines.push(Line::styled(
                format!(
                    "{} {name}",
                    if index == editor.selected_source {
                        "▶"
                    } else {
                        " "
                    }
                ),
                Style::default().fg(if index == editor.selected_source {
                    theme::ACCENT
                } else {
                    theme::MUTED
                }),
            ));
        }
        frame.render_widget(
            Paragraph::new(lines).block(panel("Import WireGuard profile")),
            area,
        );
        return;
    }
    let field_line = |label: &str, value: &str, field: VpnImportField| {
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
        spans.extend(super::input::render_value_with_cursor(
            value,
            editor.cursor,
            active,
            style,
        ));
        Line::from(spans)
    };
    let mut lines = vec![
        field_line("Name", &editor.name, VpnImportField::Name),
        field_line("File path", &editor.path, VpnImportField::Path),
        Line::from(""),
        Line::styled(
            "Up/Down or Tab: switch field | Enter: import | Esc: cancel",
            Style::default().fg(theme::MUTED),
        ),
        Line::styled(
            "The file is read from this TUI's local filesystem and sent once over the \
             authenticated API connection; its contents (including the private key) are \
             never stored by the TUI.",
            Style::default().fg(theme::MUTED),
        ),
        Line::from(""),
    ];

    let button_row_index = lines.len() as u16;
    lines.push(Line::styled(
        VPN_IMPORT_SAVE_LABEL,
        Style::default()
            .fg(theme::SELECTED_FG)
            .bg(theme::SELECTED_BG)
            .add_modifier(Modifier::BOLD),
    ));

    let block = panel("Import VPN profile");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    app.ui.buttons.push((
        Rect {
            x: inner.x,
            y: inner.y + button_row_index,
            width: VPN_IMPORT_SAVE_LABEL.len() as u16,
            height: 1,
        },
        0,
    ));
    frame.render_widget(Paragraph::new(lines), inner);
}

pub(crate) fn focus_action(app: &mut TuiApp, slot: usize) {
    if let Some(focus) = VPN_ACTION_FOCUS.get(slot) {
        app.vpn.focus = *focus;
    }
}

pub(crate) async fn handle_vpn_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    if app.vpn.delete_confirmation.is_some() {
        match key {
            KeyCode::Esc => app.vpn.delete_confirmation = None,
            KeyCode::Enter => {
                let name = app
                    .vpn
                    .delete_confirmation
                    .take()
                    .expect("confirmation open");
                vpn_delete_profile(app, client, name).await;
            }
            _ => {}
        }
        return;
    }
    let key = match key {
        KeyCode::Left if app.vpn.focus != VpnFocus::List => KeyCode::Up,
        KeyCode::Right if app.vpn.focus != VpnFocus::List => KeyCode::Down,
        _ => key,
    };
    match key {
        KeyCode::Char('e') => toggle_vpn_enabled(app, client).await,
        KeyCode::Tab | KeyCode::BackTab => {
            let fields = [
                VpnFocus::List,
                VpnFocus::Connect,
                VpnFocus::Disconnect,
                VpnFocus::Import,
                VpnFocus::Delete,
                VpnFocus::Policy,
                VpnFocus::Refresh,
                VpnFocus::ToggleEnabled,
            ];
            app.vpn.focus = super::input::move_wrapped(&fields, app.vpn.focus, key == KeyCode::Tab);
        }
        KeyCode::Esc if app.vpn.focus != VpnFocus::List => {
            app.vpn.focus = VpnFocus::List;
        }
        KeyCode::Esc => app.screen = Screen::Dashboard,
        KeyCode::Up => match app.vpn.focus {
            VpnFocus::List => {
                app.vpn.selected_profile = app.vpn.selected_profile.saturating_sub(1);
            }
            VpnFocus::Connect => {
                app.vpn.focus = VpnFocus::List;
                if !app.vpn.profiles.is_empty() {
                    app.vpn.selected_profile = app.vpn.profiles.len() - 1;
                }
            }
            focus => app.vpn.focus = previous_vpn_action_focus(focus),
        },
        KeyCode::Down => match app.vpn.focus {
            VpnFocus::List if app.vpn.selected_profile + 1 < app.vpn.profiles.len() => {
                app.vpn.selected_profile += 1;
            }
            VpnFocus::List => app.vpn.focus = VpnFocus::Connect,
            focus => app.vpn.focus = next_vpn_action_focus(focus),
        },
        KeyCode::Home => app.vpn.selected_profile = 0,
        KeyCode::End => {
            app.vpn.selected_profile = app.vpn.profiles.len().saturating_sub(1);
        }
        KeyCode::Enter => match app.vpn.focus {
            VpnFocus::List | VpnFocus::Connect => vpn_activate_selected(app, client).await,
            VpnFocus::Disconnect => vpn_deactivate(app, client).await,
            VpnFocus::Import => open_vpn_import(app, client).await,
            VpnFocus::Delete => vpn_delete_selected(app),
            VpnFocus::Policy => open_vpn_policy(app, client).await,
            VpnFocus::Refresh => load_vpn_data(app, client).await,
            VpnFocus::ToggleEnabled => toggle_vpn_enabled(app, client).await,
        },
        _ => {}
    }
}

async fn toggle_vpn_enabled(app: &mut TuiApp, client: &ApiClient) {
    let Some(enabled) = app.vpn.enabled else {
        load_vpn_data(app, client).await;
        app.push_message(LogLevel::Warn, "Refresh VPN status before changing it");
        return;
    };
    match client
        .request(&Request::SetVpnEnabled { enabled: !enabled })
        .await
    {
        Ok(Response::VpnConfig { enabled }) => {
            app.vpn.enabled = Some(enabled);
            app.push_message(
                LogLevel::Info,
                if enabled {
                    "VPN enabled and saved"
                } else {
                    "VPN disabled and saved"
                },
            );
            load_vpn_data(app, client).await;
        }
        Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

async fn open_vpn_import(app: &mut TuiApp, client: &ApiClient) {
    let sources = match client.request(&Request::VpnListSources).await {
        Ok(Response::VpnSources {
            directory,
            profiles,
        }) => Some((directory, profiles.into_iter().map(|p| p.name).collect())),
        Ok(Response::Error { message }) => {
            app.push_message(LogLevel::Error, message);
            None
        }
        Err(error) => {
            app.push_message(LogLevel::Error, error.to_string());
            None
        }
        _ => None,
    };
    app.vpn_import = Some(VpnImportEditor {
        field: VpnImportField::Name,
        name: String::new(),
        path: String::new(),
        cursor: 0,
        sources,
        selected_source: 0,
    });
    app.screen = Screen::VpnImport;
}

async fn open_vpn_policy(app: &mut TuiApp, client: &ApiClient) {
    super::vpn_policy::load_vpn_policy_data(app, client).await;
    app.screen = Screen::VpnPolicy;
}

pub(crate) async fn handle_vpn_import_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    let Some(editor) = app.vpn_import.as_mut() else {
        app.screen = Screen::Vpn;
        return;
    };

    if let Some((_, names)) = &editor.sources {
        match key {
            KeyCode::Up => editor.selected_source = editor.selected_source.saturating_sub(1),
            KeyCode::Down => {
                editor.selected_source =
                    (editor.selected_source + 1).min(names.len().saturating_sub(1))
            }
            KeyCode::Char('p') => editor.sources = None,
            KeyCode::Char('r') => open_vpn_import(app, client).await,
            KeyCode::Enter => vpn_import_submit(app, client).await,
            KeyCode::Esc => {
                app.vpn_import = None;
                app.screen = Screen::Vpn;
            }
            _ => {}
        }
        return;
    }
    match key {
        KeyCode::Esc => {
            app.vpn_import = None;
            app.screen = Screen::Vpn;
        }
        KeyCode::Up | KeyCode::Down | KeyCode::Tab | KeyCode::BackTab => {
            editor.field = toggle_vpn_import_field(editor.field);
            editor.reset_cursor();
        }
        KeyCode::Enter => vpn_import_submit(app, client).await,
        other => {
            editor.active_editor().handle_key(other);
        }
    }
}

fn toggle_vpn_import_field(field: VpnImportField) -> VpnImportField {
    match field {
        VpnImportField::Name => VpnImportField::Path,
        VpnImportField::Path => VpnImportField::Name,
    }
}

pub(crate) async fn load_vpn_data(app: &mut TuiApp, client: &ApiClient) {
    app.vpn.error = None;
    app.vpn.enabled = None;
    match client.request(&Request::GetVpnConfig).await {
        Ok(Response::VpnConfig { enabled }) => {
            app.vpn.enabled = Some(enabled);
            if !enabled {
                app.vpn.profiles.clear();
                app.vpn.active = None;
                return;
            }
        }
        Ok(Response::Error { message }) => {
            app.push_message(LogLevel::Error, message);
            return;
        }
        Ok(response) => {
            app.push_message(
                LogLevel::Error,
                format!("Unexpected response: {response:?}"),
            );
            return;
        }
        Err(error) => {
            app.push_message(LogLevel::Error, error.to_string());
            return;
        }
    }

    match client.request(&Request::VpnListProfiles).await {
        Ok(Response::VpnProfiles { profiles }) => app.vpn.profiles = profiles,
        Ok(Response::VpnError { detail }) => {
            app.vpn.error = Some(detail);
            return;
        }
        Ok(response) => {
            app.push_message(
                LogLevel::Error,
                format!("Unexpected response: {response:?}"),
            );
            return;
        }
        Err(error) => {
            app.push_message(LogLevel::Error, error.to_string());
            return;
        }
    }
    if app.vpn.selected_profile >= app.vpn.profiles.len() {
        app.vpn.selected_profile = app.vpn.profiles.len().saturating_sub(1);
    }

    match client.request(&Request::VpnStatus).await {
        Ok(Response::VpnStatus { active }) => app.vpn.active = active,
        Ok(Response::VpnError { detail }) => app.vpn.error = Some(detail),
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

async fn vpn_activate_selected(app: &mut TuiApp, client: &ApiClient) {
    let Some(name) = app
        .vpn
        .profiles
        .get(app.vpn.selected_profile)
        .map(|profile| profile.name.clone())
    else {
        app.push_message(LogLevel::Warn, "No profile selected");
        return;
    };

    match client.request(&Request::VpnActivate { name }).await {
        Ok(Response::VpnActivated { active }) => {
            app.push_message(
                LogLevel::Info,
                format!(
                    "VPN connected: {} (interface {})",
                    active.profile_name, active.interface
                ),
            );
            app.vpn.active = Some(active);
        }
        Ok(Response::VpnError { detail }) => {
            app.push_message(LogLevel::Error, describe_vpn_error(&detail))
        }
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

async fn vpn_deactivate(app: &mut TuiApp, client: &ApiClient) {
    match client.request(&Request::VpnDeactivate).await {
        Ok(Response::VpnDeactivated) => {
            app.push_message(LogLevel::Info, "VPN disconnected");
            app.vpn.active = None;
        }
        Ok(Response::VpnError { detail }) => {
            app.push_message(LogLevel::Error, describe_vpn_error(&detail))
        }
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

fn vpn_delete_selected(app: &mut TuiApp) {
    let Some(name) = app
        .vpn
        .profiles
        .get(app.vpn.selected_profile)
        .map(|profile| profile.name.clone())
    else {
        app.push_message(LogLevel::Warn, "No profile selected");
        return;
    };

    app.vpn.delete_confirmation = Some(name);
}

async fn vpn_delete_profile(app: &mut TuiApp, client: &ApiClient, name: String) {
    match client.request(&Request::VpnDeleteProfile { name }).await {
        Ok(Response::VpnProfileDeleted { name }) => {
            app.push_message(LogLevel::Info, format!("Deleted profile {name}"));
            load_vpn_data(app, client).await;
        }
        Ok(Response::VpnError { detail }) => {
            app.push_message(LogLevel::Error, describe_vpn_error(&detail))
        }
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

pub(crate) async fn vpn_import_submit(app: &mut TuiApp, client: &ApiClient) {
    let Some(editor) = &app.vpn_import else {
        app.screen = Screen::Vpn;
        return;
    };
    if let Some((_, names)) = &editor.sources {
        let Some(name) = names.get(editor.selected_source).cloned() else {
            return;
        };
        match client.request(&Request::VpnImportFromSource { name }).await {
            Ok(Response::VpnProfileImported { name }) => {
                app.push_message(LogLevel::Info, format!("Imported profile {name}"));
                app.vpn_import = None;
                app.screen = Screen::Vpn;
                load_vpn_data(app, client).await;
            }
            Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
            Ok(Response::VpnError { detail }) => {
                app.push_message(LogLevel::Error, describe_vpn_error(&detail))
            }
            Ok(response) => app.push_message(
                LogLevel::Error,
                format!("Unexpected response: {response:?}"),
            ),
            Err(error) => app.push_message(LogLevel::Error, error.to_string()),
        }
        return;
    }
    let name = editor.name.trim().to_string();
    let path = editor.path.trim().to_string();
    if name.is_empty() || path.is_empty() {
        app.push_message(
            LogLevel::Warn,
            "Both profile name and file path are required",
        );
        return;
    }

    let mut contents = match std::fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) => {
            app.push_message(LogLevel::Error, format!("Failed to read {path}: {error}"));
            return;
        }
    };
    let result = client
        .request(&Request::VpnImportProfile {
            name,
            contents: contents.clone(),
        })
        .await;
    contents.zeroize();

    match result {
        Ok(Response::VpnProfileImported { name }) => {
            app.push_message(LogLevel::Info, format!("Imported profile {name}"));
            app.vpn_import = None;
            app.screen = Screen::Vpn;
            load_vpn_data(app, client).await;
        }
        Ok(Response::VpnError { detail }) => {
            app.push_message(LogLevel::Error, describe_vpn_error(&detail))
        }
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

fn describe_vpn_error(detail: &VpnErrorDetail) -> String {
    match detail {
        VpnErrorDetail::VpnDisabled => {
            "VPN is disabled; enable it in the VPN tab with e".to_string()
        }
        VpnErrorDetail::NotFound { name } => format!("Profile '{name}' not found"),
        VpnErrorDetail::InvalidProfile { message } => format!("Invalid profile: {message}"),
        VpnErrorDetail::AlreadyActive => {
            "A VPN tunnel is already active; disconnect before activating another profile"
                .to_string()
        }
        VpnErrorDetail::NotActive => "No VPN tunnel is currently active".to_string(),
        VpnErrorDetail::ProfileInUse { name } => {
            format!("Profile '{name}' is in use; disconnect or remove it from the router VPN chain first")
        }
        VpnErrorDetail::ForeignInterfaceConflict => {
            "tm-wg0 is occupied by an interface this daemon does not own; remove it manually"
                .to_string()
        }
        VpnErrorDetail::Other { message } => message.clone(),
    }
}

#[cfg(test)]
mod tests;
