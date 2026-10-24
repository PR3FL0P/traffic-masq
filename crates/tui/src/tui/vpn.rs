use crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Layout, Rect};
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
    pub(crate) opened_profile: Option<String>,
    pub(crate) status_known: bool,
    pub(crate) profiles_known: bool,
    pub(crate) chain: Option<Vec<traffic_masq_protocol::VpnHopConfigView>>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VpnFocus {
    #[default]
    List,
    Connect,
    Details,
    Import,
    Settings,
    Delete,
    Route,
    ToggleEnabled,
}

fn actions(screen: Screen) -> &'static [VpnFocus] {
    match screen {
        Screen::VpnProfile => &[VpnFocus::Connect, VpnFocus::Route, VpnFocus::Delete],
        Screen::VpnSettings => &[VpnFocus::ToggleEnabled],
        _ => &[
            VpnFocus::Connect,
            VpnFocus::Details,
            VpnFocus::Import,
            VpnFocus::Settings,
        ],
    }
}

fn selected_name(app: &TuiApp) -> Option<&str> {
    if app.screen == Screen::VpnProfile {
        app.vpn.opened_profile.as_deref()
    } else {
        app.vpn
            .profiles
            .get(app.vpn.selected_profile)
            .map(|p| p.name.as_str())
    }
}

fn standalone_selected(app: &TuiApp) -> bool {
    app.vpn.status_known
        && app
            .vpn
            .active
            .as_ref()
            .is_some_and(|active| Some(active.profile_name.as_str()) == selected_name(app))
}

async fn open_route(app: &mut TuiApp, client: &ApiClient) {
    super::router::load_router_data(app, client).await;
    app.screen = Screen::Router;
}

fn profile_state(app: &TuiApp, name: &str) -> String {
    let tunnel = connection_state(app, name);
    let chain = match &app.vpn.chain {
        None => "chain usage: unknown".into(),
        Some(chain) => {
            let hops: Vec<_> = chain
                .iter()
                .enumerate()
                .filter(|(_, hop)| hop.profile_name == name)
                .map(|(i, _)| (i + 1).to_string())
                .collect();
            if hops.is_empty() {
                "not in saved chain".into()
            } else {
                format!("saved chain: hop {}", hops.join(", "))
            }
        }
    };
    format!("{tunnel} | {chain}")
}

fn connection_state(app: &TuiApp, name: &str) -> &'static str {
    if app.vpn.enabled == Some(false) {
        "VPN disabled"
    } else if !app.vpn.status_known {
        "status unknown"
    } else if let Some(active) = app.vpn.active.as_ref().filter(|a| a.profile_name == name) {
        if active.up {
            "connected"
        } else {
            "interface down"
        }
    } else {
        "disconnected"
    }
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
    let block = panel(match app.screen {
        Screen::VpnProfile => "VPN profile",
        Screen::VpnSettings => "VPN settings",
        _ => "VPN profiles",
    });
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let regions = Layout::vertical([Constraint::Min(1), Constraint::Length(3)]).split(inner);
    let content = regions[0];
    let mut lines = vec![Line::styled(
        match app.vpn.enabled {
            Some(true) => "VPN enabled",
            Some(false) => "VPN disabled — Connect also enables VPN",
            None => "VPN availability unknown — r: refresh",
        },
        Style::default().fg(theme::MUTED),
    )];
    if app.vpn.enabled == Some(true) && app.vpn.status_known {
        if let Some(active) = &app.vpn.active {
            lines.push(Line::from(format!(
                "Active: {} on {} ({})",
                active.profile_name,
                active.interface,
                if active.up { "up" } else { "down" }
            )));
        }
    }
    if let Some(detail) = &app.vpn.error {
        lines.push(Line::styled(
            describe_vpn_error(detail),
            Style::default().fg(theme::BAD),
        ));
    }
    if app.screen == Screen::VpnSettings {
        lines.extend([
            Line::from("Enable/disable changes subsystem availability and is saved immediately."),
            Line::from("To disable: remove the saved chain in Route, select Direct policy,"),
            Line::from("then disconnect the standalone tunnel. This is not an emergency stop."),
            Line::from("Saved profiles remain in the library while VPN is disabled."),
        ]);
    } else if app.screen == Screen::VpnProfile {
        if let Some(name) = selected_name(app) {
            lines.push(Line::styled(
                name.to_owned(),
                Style::default().fg(theme::ACCENT),
            ));
            lines.push(Line::from(profile_state(app, name)));
            lines.push(Line::from(
                "Traffic routing and VPN chains are configured in Route.",
            ));
            if app.router.staged {
                let hops: Vec<_> = app
                    .router
                    .proposed_router_config
                    .vpn_chain
                    .iter()
                    .enumerate()
                    .filter(|(_, hop)| hop.profile_name == name)
                    .map(|(i, _)| (i + 1).to_string())
                    .collect();
                lines.push(Line::from(format!(
                    "Unapplied Route draft: {}",
                    if hops.is_empty() {
                        "profile not in chain".into()
                    } else {
                        format!("hop {}", hops.join(", "))
                    }
                )));
            }
            lines.push(Line::from(
                "Connect/disconnect applies immediately to tm-wg0. Chain tunnels are separate.",
            ));
            if let Some(active) = &app.vpn.active {
                if active.profile_name != name && app.vpn.status_known {
                    lines.push(Line::from(format!(
                        "Disconnect profile '{}' before connecting another.",
                        active.profile_name
                    )));
                }
            }
            lines.push(Line::from(
                "Additional action: delete saved profile (confirmation required).",
            ));
        }
    } else {
        if !app.vpn.profiles_known {
            lines.push(Line::styled(
                "Profile library unavailable; displayed entries may be stale.",
                Style::default().fg(theme::WARN),
            ));
        }
        let header = lines.len() as u16;
        let list = Rect::new(
            content.x,
            content.y.saturating_add(header),
            content.width,
            content.height.saturating_sub(header),
        );
        let visible = list.height.max(1) as usize;
        let scroll = app
            .vpn
            .selected_profile
            .saturating_sub(visible - 1)
            .min(app.vpn.profiles.len().saturating_sub(visible));
        app.ui.list_area = Some(list);
        app.ui.list_row_height = 1;
        app.ui.list_count = app.vpn.profiles.len();
        app.ui.list_scroll_offset = scroll;
        if app.vpn.profiles.is_empty() {
            lines.push(Line::from(if app.vpn.profiles_known {
                "(none imported)"
            } else {
                "(library unavailable)"
            }));
        }
        for (index, profile) in app
            .vpn
            .profiles
            .iter()
            .enumerate()
            .skip(scroll)
            .take(visible)
        {
            let selected = index == app.vpn.selected_profile;
            lines.push(Line::styled(
                format!(
                    "{} {} — {}",
                    if selected { "▶" } else { " " },
                    profile.name,
                    connection_state(app, &profile.name)
                ),
                if selected {
                    Style::default().fg(theme::ACCENT)
                } else {
                    Style::default()
                },
            ));
        }
    }
    let lines = if app.screen == Screen::Vpn {
        lines
    } else {
        super::layout::wrap_lines(lines, content.width)
    };
    frame.render_widget(Paragraph::new(lines), content);
    let mut x = regions[1].x;
    let mut y = regions[1].y;
    for (slot, focus) in actions(app.screen).iter().enumerate() {
        let label = match focus {
            VpnFocus::Connect if standalone_selected(app) => "[Disconnect]",
            VpnFocus::Connect => "[Connect]",
            VpnFocus::Details => "[Open profile]",
            VpnFocus::Import => "[Import]",
            VpnFocus::Settings => "[VPN settings]",
            VpnFocus::Delete => "[Delete profile]",
            VpnFocus::Route => "[Open Route]",
            VpnFocus::ToggleEnabled if app.vpn.enabled == Some(true) => "[Disable VPN]",
            VpnFocus::ToggleEnabled => "[Enable VPN]",
            VpnFocus::List => continue,
        };
        let width = label.len() as u16;
        if x + width > regions[1].right() {
            x = regions[1].x;
            y += 1;
        }
        let rect = Rect::new(x, y, width.min(regions[1].width), 1).intersection(regions[1]);
        if rect.is_empty() {
            continue;
        }
        app.ui.buttons.push((rect, slot));
        frame.render_widget(
            Paragraph::new(label).style(if app.vpn.focus == *focus {
                Style::default()
                    .fg(theme::SELECTED_FG)
                    .bg(theme::SELECTED_BG)
            } else {
                Style::default().fg(theme::ACCENT)
            }),
            rect,
        );
        x += width + 1;
    }
    frame.render_widget(
        Paragraph::new(
            if app.screen == Screen::Vpn && app.vpn.focus == VpnFocus::List {
                "r: refresh | Enter: connect / disconnect | Tab: actions | Esc: back"
            } else {
                "r: refresh | Enter: activate action | Esc: back"
            },
        )
        .style(Style::default().fg(theme::MUTED)),
        Rect::new(
            regions[1].x,
            regions[1].bottom().saturating_sub(1),
            regions[1].width,
            1,
        ),
    );
}

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
            "Tab: next | Enter: next / import from path | Esc: cancel",
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
    if let Some(focus) = actions(app.screen).get(slot) {
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
    let fields: Vec<_> = if app.screen == Screen::Vpn {
        std::iter::once(VpnFocus::List)
            .chain(actions(app.screen).iter().copied())
            .collect()
    } else {
        actions(app.screen).to_vec()
    };
    match key {
        KeyCode::Char('r') => load_vpn_data(app, client).await,
        KeyCode::Esc if app.screen != Screen::Vpn => {
            app.screen = Screen::Vpn;
            app.vpn.opened_profile = None;
            app.vpn.focus = VpnFocus::List;
        }
        KeyCode::Esc if app.vpn.focus != VpnFocus::List => app.vpn.focus = VpnFocus::List,
        KeyCode::Esc => app.screen = Screen::Dashboard,
        KeyCode::Tab | KeyCode::BackTab => {
            app.vpn.focus = super::input::move_wrapped(&fields, app.vpn.focus, key == KeyCode::Tab);
        }
        KeyCode::Up if app.vpn.focus == VpnFocus::List => {
            app.vpn.selected_profile = app.vpn.selected_profile.saturating_sub(1);
        }
        KeyCode::Down if app.vpn.focus == VpnFocus::List => {
            if app.vpn.selected_profile + 1 < app.vpn.profiles.len() {
                app.vpn.selected_profile += 1;
            } else {
                app.vpn.focus = VpnFocus::Connect;
            }
        }
        KeyCode::Up | KeyCode::Left => {
            app.vpn.focus = super::input::move_clamped(&fields, app.vpn.focus, false)
        }
        KeyCode::Down | KeyCode::Right => {
            app.vpn.focus = super::input::move_clamped(&fields, app.vpn.focus, true)
        }
        KeyCode::Home => app.vpn.selected_profile = 0,
        KeyCode::End => app.vpn.selected_profile = app.vpn.profiles.len().saturating_sub(1),
        KeyCode::Enter => match app.vpn.focus {
            VpnFocus::Details => {
                if app.vpn.profiles_known {
                    if let Some(name) = selected_name(app).map(str::to_owned) {
                        app.vpn.opened_profile = Some(name);
                        app.screen = Screen::VpnProfile;
                        app.vpn.focus = VpnFocus::Connect;
                        load_vpn_chain_usage(app, client).await;
                    }
                }
            }
            VpnFocus::List | VpnFocus::Connect => {
                if standalone_selected(app) {
                    vpn_deactivate(app, client).await;
                } else {
                    vpn_activate_selected(app, client).await;
                }
            }
            VpnFocus::Import => open_vpn_import(app, client).await,
            VpnFocus::Delete => vpn_delete_selected(app),
            VpnFocus::Route => open_route(app, client).await,
            VpnFocus::Settings => {
                app.screen = Screen::VpnSettings;
                app.vpn.focus = VpnFocus::ToggleEnabled;
            }
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
    if set_vpn_enabled(app, client, !enabled).await {
        load_vpn_data(app, client).await;
    }
}

async fn set_vpn_enabled(app: &mut TuiApp, client: &ApiClient, enabled: bool) -> bool {
    app.vpn.enabled = None;
    app.vpn.status_known = false;
    match client.request(&Request::SetVpnEnabled { enabled }).await {
        Ok(Response::VpnConfig { enabled: actual }) if actual == enabled => {
            app.vpn.enabled = Some(enabled);
            app.push_message(
                LogLevel::Info,
                if enabled {
                    "VPN enabled and saved"
                } else {
                    "VPN disabled and saved"
                },
            );
            return true;
        }
        Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
    false
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
        KeyCode::Enter if editor.field == VpnImportField::Name => {
            editor.field = VpnImportField::Path;
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
    let selected = selected_name(app).map(str::to_owned);
    // The event loop cancels background reads when input arrives. Collect the
    // observations before replacing known state, so Enter can use the previous
    // snapshot when it interrupts a refresh. Completed failures still invalidate it.
    let config = client.request(&Request::GetVpnConfig).await;
    let profiles = client.request(&Request::VpnListProfiles).await;
    let status = if matches!(&config, Ok(Response::VpnConfig { enabled: true })) {
        Some(client.request(&Request::VpnStatus).await)
    } else {
        None
    };
    let chain = if app.screen == Screen::VpnProfile {
        Some(client.request(&Request::GetRouterConfig).await)
    } else {
        None
    };
    app.vpn.error = None;
    app.vpn.enabled = None;
    app.vpn.status_known = false;
    app.vpn.profiles_known = false;
    app.vpn.chain = None;
    match config {
        Ok(Response::VpnConfig { enabled }) => app.vpn.enabled = Some(enabled),
        result => app.push_message(
            LogLevel::Warn,
            format!("VPN availability unavailable: {result:?}"),
        ),
    }
    match profiles {
        Ok(Response::VpnProfiles { profiles }) => {
            app.vpn.profiles = profiles;
            app.vpn.profiles_known = true;
            app.vpn.selected_profile = selected
                .as_ref()
                .and_then(|name| app.vpn.profiles.iter().position(|p| &p.name == name))
                .unwrap_or(
                    app.vpn
                        .selected_profile
                        .min(app.vpn.profiles.len().saturating_sub(1)),
                );
        }
        Ok(Response::VpnError { detail }) => app.vpn.error = Some(detail),
        result => app.push_message(
            LogLevel::Warn,
            format!("VPN profile library unavailable: {result:?}"),
        ),
    }
    if let Some(status) = status {
        accept_vpn_status(app, status);
    }
    if let Some(chain) = chain {
        accept_vpn_chain_usage(app, chain);
    }
}

async fn load_vpn_chain_usage(app: &mut TuiApp, client: &ApiClient) {
    let result = client.request(&Request::GetRouterConfig).await;
    accept_vpn_chain_usage(app, result);
}

fn accept_vpn_chain_usage(app: &mut TuiApp, result: anyhow::Result<Response>) {
    app.vpn.chain = None;
    match result {
        Ok(Response::RouterConfig { config }) => app.vpn.chain = Some(config.vpn_chain),
        result => app.push_message(
            LogLevel::Warn,
            format!("VPN chain usage unavailable: {result:?}"),
        ),
    }
}

async fn refresh_vpn_status(app: &mut TuiApp, client: &ApiClient) {
    let result = client.request(&Request::VpnStatus).await;
    accept_vpn_status(app, result);
}

fn accept_vpn_status(app: &mut TuiApp, result: anyhow::Result<Response>) {
    app.vpn.status_known = false;
    match result {
        Ok(Response::VpnStatus { active }) => {
            app.vpn.active = active;
            app.vpn.status_known = true;
        }
        Ok(Response::VpnError { detail }) => app.vpn.error = Some(detail),
        result => app.push_message(
            LogLevel::Warn,
            format!("VPN connection status unavailable: {result:?}"),
        ),
    }
}

async fn vpn_activate_selected(app: &mut TuiApp, client: &ApiClient) {
    if !app.vpn.profiles_known || app.vpn.enabled.is_none() {
        app.push_message(
            LogLevel::Warn,
            "Refresh VPN availability and profile library before connecting",
        );
        return;
    }
    let Some(name) = selected_name(app).map(str::to_owned) else {
        app.push_message(LogLevel::Warn, "No profile selected");
        return;
    };
    if !app.vpn.profiles.iter().any(|p| p.name == name) {
        app.push_message(
            LogLevel::Warn,
            "Profile is no longer in the library; return to the list",
        );
        return;
    }
    if app.vpn.enabled == Some(false) {
        if !set_vpn_enabled(app, client, true).await {
            return;
        }
        refresh_vpn_status(app, client).await;
    }
    if !app.vpn.status_known {
        app.push_message(
            LogLevel::Warn,
            "Refresh VPN connection status before connecting",
        );
        return;
    }
    if let Some(active) = &app.vpn.active {
        app.push_message(
            LogLevel::Warn,
            format!("Disconnect profile '{}' first", active.profile_name),
        );
        return;
    }

    app.vpn.status_known = false;
    match client.request(&Request::VpnActivate { name }).await {
        Ok(Response::VpnActivated { active }) => {
            app.vpn.error = None;
            app.push_message(
                LogLevel::Info,
                format!(
                    "VPN connected: {} (interface {})",
                    active.profile_name, active.interface
                ),
            );
            app.vpn.active = Some(active);
            app.vpn.status_known = true;
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
    if !app.vpn.status_known {
        app.push_message(
            LogLevel::Warn,
            "Refresh VPN connection status before disconnecting",
        );
        return;
    }
    app.vpn.status_known = false;
    match client.request(&Request::VpnDeactivate).await {
        Ok(Response::VpnDeactivated) => {
            app.vpn.error = None;
            app.push_message(LogLevel::Info, "VPN disconnected");
            app.vpn.active = None;
            app.vpn.status_known = true;
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
    if !app.vpn.profiles_known {
        app.push_message(LogLevel::Warn, "Refresh profile library before deleting");
        return;
    }
    let Some(name) = selected_name(app).map(str::to_owned) else {
        app.push_message(LogLevel::Warn, "No profile selected");
        return;
    };

    if app.router.staged
        && app
            .router
            .proposed_router_config
            .vpn_chain
            .iter()
            .any(|hop| hop.profile_name == name)
    {
        app.push_message(
            LogLevel::Warn,
            "Profile is used by the unapplied Route draft; remove it from the draft first",
        );
        return;
    }
    app.vpn.delete_confirmation = Some(name);
}

async fn vpn_delete_profile(app: &mut TuiApp, client: &ApiClient, name: String) {
    match client.request(&Request::VpnDeleteProfile { name }).await {
        Ok(Response::VpnProfileDeleted { name }) => {
            app.push_message(LogLevel::Info, format!("Deleted profile {name}"));
            load_vpn_data(app, client).await;
            app.screen = Screen::Vpn;
            app.vpn.opened_profile = None;
            app.vpn.focus = VpnFocus::List;
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
        VpnErrorDetail::VpnDisabled => "VPN is disabled; enable it in VPN settings".to_string(),
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
