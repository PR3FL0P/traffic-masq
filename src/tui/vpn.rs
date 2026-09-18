use crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use zeroize::Zeroize;

use crate::api::client::ApiClient;
use crate::api::model::{Request, Response, VpnActiveStatus, VpnErrorDetail, VpnProfileSummary};

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
}

const VPN_ACTION_FOCUS: [VpnFocus; 6] = [
    VpnFocus::Connect,
    VpnFocus::Disconnect,
    VpnFocus::Import,
    VpnFocus::Delete,
    VpnFocus::Policy,
    VpnFocus::Refresh,
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
        self.cursor = self.active_value().chars().count();
    }

    pub(crate) fn active_editor(&mut self) -> super::input::TextEditor<'_> {
        let cursor = &mut self.cursor;
        match self.field {
            VpnImportField::Name => super::input::TextEditor::new(&mut self.name, cursor),
            VpnImportField::Path => super::input::TextEditor::new(&mut self.path, cursor),
        }
    }
}

pub(crate) fn render_vpn(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(3)])
        .split(area);

    let mut status_lines = Vec::new();
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

    app.ui.list_area = Some(inner);
    app.ui.list_row_height = 1;
    app.ui.list_count = app.vpn.profiles.len();
    app.ui.list_scroll_offset = 0;

    let list_focused = app.vpn.focus == VpnFocus::List;
    let mut lines: Vec<Line> = if app.vpn.profiles.is_empty() {
        vec![Line::styled(
            "(none imported)",
            Style::default().fg(theme::MUTED),
        )]
    } else {
        app.vpn
            .profiles
            .iter()
            .enumerate()
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

    lines.push(Line::from(""));
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
    for (slot, (label, focus)) in [
        (VPN_CONNECT_LABEL, VpnFocus::Connect),
        (VPN_DISCONNECT_LABEL, VpnFocus::Disconnect),
        (VPN_IMPORT_LABEL, VpnFocus::Import),
        (VPN_DELETE_LABEL, VpnFocus::Delete),
        (VPN_POLICY_LABEL, VpnFocus::Policy),
        (VPN_REFRESH_LABEL, VpnFocus::Refresh),
    ]
    .into_iter()
    .enumerate()
    {
        app.ui.buttons.push((
            Rect {
                x: inner.x,
                y: inner.y + lines.len() as u16,
                width: label.len() as u16,
                height: 1,
            },
            slot,
        ));
        lines.push(action(label, app.vpn.focus == focus));
    }

    frame.render_widget(Paragraph::new(lines), inner);
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
    let key = match key {
        KeyCode::Left if app.vpn.focus != VpnFocus::List => KeyCode::Up,
        KeyCode::Right if app.vpn.focus != VpnFocus::List => KeyCode::Down,
        _ => key,
    };
    match key {
        KeyCode::Tab | KeyCode::BackTab => {
            let fields = [
                VpnFocus::List,
                VpnFocus::Connect,
                VpnFocus::Disconnect,
                VpnFocus::Import,
                VpnFocus::Delete,
                VpnFocus::Policy,
                VpnFocus::Refresh,
            ];
            app.vpn.focus =
                super::input::move_wrapped(&fields, app.vpn.focus, key == KeyCode::Tab);
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
            VpnFocus::Import => open_vpn_import(app),
            VpnFocus::Delete => vpn_delete_selected(app, client).await,
            VpnFocus::Policy => open_vpn_policy(app, client).await,
            VpnFocus::Refresh => load_vpn_data(app, client).await,
        },
        _ => {}
    }
}

fn open_vpn_import(app: &mut TuiApp) {
    app.vpn_import = Some(VpnImportEditor {
        field: VpnImportField::Name,
        name: String::new(),
        path: String::new(),
        cursor: 0,
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

async fn vpn_delete_selected(app: &mut TuiApp, client: &ApiClient) {
    let Some(name) = app
        .vpn
        .profiles
        .get(app.vpn.selected_profile)
        .map(|profile| profile.name.clone())
    else {
        app.push_message(LogLevel::Warn, "No profile selected");
        return;
    };

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
            "VPN is not enabled (vpn.enabled is false in the daemon config)".to_string()
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
mod tests {
    use super::*;

    #[test]
    fn vpn_action_focus_reaches_every_action_and_clamps_at_both_ends() {
        assert_eq!(
            next_vpn_action_focus(VpnFocus::Connect),
            VpnFocus::Disconnect
        );
        assert_eq!(
            next_vpn_action_focus(VpnFocus::Disconnect),
            VpnFocus::Import
        );
        assert_eq!(next_vpn_action_focus(VpnFocus::Import), VpnFocus::Delete);
        assert_eq!(next_vpn_action_focus(VpnFocus::Delete), VpnFocus::Policy);
        assert_eq!(next_vpn_action_focus(VpnFocus::Policy), VpnFocus::Refresh);
        assert_eq!(next_vpn_action_focus(VpnFocus::Refresh), VpnFocus::Refresh);
        assert_eq!(
            previous_vpn_action_focus(VpnFocus::Refresh),
            VpnFocus::Policy
        );
        assert_eq!(
            previous_vpn_action_focus(VpnFocus::Policy),
            VpnFocus::Delete
        );
        assert_eq!(
            previous_vpn_action_focus(VpnFocus::Delete),
            VpnFocus::Import
        );
        assert_eq!(
            previous_vpn_action_focus(VpnFocus::Import),
            VpnFocus::Disconnect
        );
        assert_eq!(
            previous_vpn_action_focus(VpnFocus::Disconnect),
            VpnFocus::Connect
        );
    }

    #[test]
    fn vpn_focus_defaults_to_list() {
        assert_eq!(VpnFocus::default(), VpnFocus::List);
    }

    #[test]
    fn describes_each_vpn_error_detail_distinctly() {
        let messages = [
            describe_vpn_error(&VpnErrorDetail::VpnDisabled),
            describe_vpn_error(&VpnErrorDetail::NotFound {
                name: "home.conf".to_string(),
            }),
            describe_vpn_error(&VpnErrorDetail::InvalidProfile {
                message: "missing [Interface] section".to_string(),
            }),
            describe_vpn_error(&VpnErrorDetail::AlreadyActive),
            describe_vpn_error(&VpnErrorDetail::NotActive),
            describe_vpn_error(&VpnErrorDetail::ProfileInUse {
                name: "home.conf".to_string(),
            }),
            describe_vpn_error(&VpnErrorDetail::ForeignInterfaceConflict),
            describe_vpn_error(&VpnErrorDetail::Other {
                message: "boom".to_string(),
            }),
        ];

        for (index, message) in messages.iter().enumerate() {
            assert!(!message.is_empty());
            for (other_index, other) in messages.iter().enumerate() {
                if index != other_index {
                    assert_ne!(message, other, "variants must not collapse into one string");
                }
            }
        }
        assert!(messages[1].contains("home.conf"));
        assert!(messages[2].contains("missing [Interface] section"));
        assert_eq!(messages[7], "boom");
    }

    #[test]
    fn vpn_import_field_toggles_between_the_only_two_fields() {
        assert_eq!(
            toggle_vpn_import_field(VpnImportField::Name),
            VpnImportField::Path
        );
        assert_eq!(
            toggle_vpn_import_field(VpnImportField::Path),
            VpnImportField::Name
        );
    }

    #[test]
    fn vpn_import_editor_active_value_targets_the_selected_field() {
        let mut editor = VpnImportEditor {
            field: VpnImportField::Name,
            name: "home".to_string(),
            path: "/etc/wireguard/home.conf".to_string(),
            cursor: 0,
        };
        editor.active_value_mut().push_str(".conf");
        assert_eq!(editor.name, "home.conf");
        assert_eq!(editor.path, "/etc/wireguard/home.conf");

        editor.field = VpnImportField::Path;
        editor.active_value_mut().push('x');
        assert_eq!(editor.path, "/etc/wireguard/home.confx");
        assert_eq!(editor.name, "home.conf");
    }

    #[test]
    fn vpn_import_editor_has_no_contents_field_to_retain_a_secret() {
        let editor = VpnImportEditor {
            field: VpnImportField::Name,
            name: "home.conf".to_string(),
            path: "/etc/wireguard/home.conf".to_string(),
            cursor: 0,
        };
        let debug = format!("{editor:?}");
        assert!(debug.contains("name"));
        assert!(debug.contains("path"));
        assert!(!debug.contains("contents"));
        assert!(!debug.contains("PrivateKey"));
    }

    #[tokio::test]
    async fn vpn_import_editor_cursor_navigation_and_editing() {
        let mut app = TuiApp::default();
        let mut editor = VpnImportEditor {
            field: VpnImportField::Name,
            name: "work".to_string(),
            path: "/tmp/vpn.conf".to_string(),
            cursor: 4,
        };
        editor.cursor = editor.name.len();
        app.vpn_import = Some(editor);
        app.screen = Screen::VpnImport;
        let client = ApiClient::new("/nonexistent.sock");

        handle_vpn_import_key(&mut app, KeyCode::Left, &client).await;
        assert_eq!(app.vpn_import.as_ref().unwrap().cursor, 3);

        handle_vpn_import_key(&mut app, KeyCode::Char('1'), &client).await;
        assert_eq!(app.vpn_import.as_ref().unwrap().name, "wor1k");
        assert_eq!(app.vpn_import.as_ref().unwrap().cursor, 4);

        handle_vpn_import_key(&mut app, KeyCode::Backspace, &client).await;
        assert_eq!(app.vpn_import.as_ref().unwrap().name, "work");
        assert_eq!(app.vpn_import.as_ref().unwrap().cursor, 3);

        handle_vpn_import_key(&mut app, KeyCode::Down, &client).await;
        assert_eq!(app.vpn_import.as_ref().unwrap().field, VpnImportField::Path);
        assert_eq!(
            app.vpn_import.as_ref().unwrap().cursor,
            "/tmp/vpn.conf".len()
        );
    }
}
