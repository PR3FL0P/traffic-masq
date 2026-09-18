use anyhow::Result;
use crossterm::event::KeyCode;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::api::client::ApiClient;
use crate::api::model::{InterfaceEditRequest, Request, Response};
use crate::config::InterfaceRole;

use super::layout::panel;
use super::logs::LogLevel;
use super::theme;
use super::{current_unix_time, format_addresses, Screen, TuiApp};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InterfaceEditorField {
    Cidr,
    RemoveIpv4,
    Role,
    Managed,
    Save,
}

const INTERFACE_EDITOR_FIELDS: [InterfaceEditorField; 5] = [
    InterfaceEditorField::Cidr,
    InterfaceEditorField::RemoveIpv4,
    InterfaceEditorField::Role,
    InterfaceEditorField::Managed,
    InterfaceEditorField::Save,
];

#[derive(Debug, Clone)]
pub(crate) struct InterfaceEditor {
    pub(crate) interface: String,
    pub(crate) field: InterfaceEditorField,
    pub(crate) cidr: String,
    pub(crate) role: InterfaceRole,
    pub(crate) managed: bool,
    pub(crate) allow_management_change: bool,
    pub(crate) has_default_route: bool,
    pub(crate) original_managed: bool,
    pub(crate) original_cidr: String,
    /// Observed addresses, kept separate from the requested static address.
    /// The dry-run plan is authoritative about which ones will be removed.
    pub(crate) current_addresses: Vec<String>,
    pub(crate) observed_addresses: Vec<Span<'static>>,
    /// What the router-owned AP/DHCP currently running on this interface
    /// look like, so the operator sees exactly what unmanaging it will
    /// leave stranded (see `validate_router_service_management` on the
    /// daemon side, which refuses the save outright unless confirmed).
    pub(crate) current_wifi_summary: Option<String>,
    pub(crate) current_dhcp_summary: Option<String>,
    pub(crate) cursor: usize,
}

impl InterfaceEditor {
    pub(crate) fn reset_cursor(&mut self) {
        if self.field == InterfaceEditorField::Cidr {
            self.cursor = self.cidr.chars().count();
        } else {
            self.cursor = 0;
        }
    }

    /// Ask for the address to be taken off. An empty CIDR field is the request:
    /// the daemon plans deletion only for addresses it owns.
    pub(crate) fn remove_ipv4(&mut self) {
        self.cidr.clear();
        self.cursor = 0;
    }

    pub(crate) fn edit_request(&self) -> Result<InterfaceEditRequest> {
        // Router participation is independent of address ownership.
        // Address edits require traffic-masq configuration to be enabled.
        if !self.managed {
            // Taking an address off is still writing to the interface, and an
            // unmanaged interface is one we do not write to. Say which switch
            // unblocks it instead of reporting a generic edit refusal.
            if self.cidr.trim().is_empty() && !self.original_cidr.trim().is_empty() {
                anyhow::bail!(
                    "cannot remove the IP while the interface is unmanaged; enable Configure with traffic-masq so traffic-masq may take the address off"
                );
            }
            let mut changed = Vec::new();
            if self.cidr.trim() != self.original_cidr.trim() {
                changed.push("IP");
            }
            if !changed.is_empty() {
                anyhow::bail!(
                    "cannot change {} while the interface is unmanaged; enable Configure with traffic-masq first",
                    changed.join(" and ")
                );
            }
        }
        if !self.cidr.trim().is_empty() {
            let _: ipnet::Ipv4Net = self.cidr.trim().parse()?;
        }
        if self.has_default_route
            && self.role == InterfaceRole::Output
            && self.managed
            && !self.allow_management_change
        {
            anyhow::bail!(
                "this interface carries the default route; review changes and confirm Apply to accept the connectivity risk"
            );
        }
        if self.original_managed
            && (!self.managed || self.role != InterfaceRole::Output)
            && !self.allow_management_change
            && (self.current_wifi_summary.is_some() || self.current_dhcp_summary.is_some())
        {
            let running = [&self.current_wifi_summary, &self.current_dhcp_summary]
                .into_iter()
                .flatten()
                .cloned()
                .collect::<Vec<_>>()
                .join(" and ");
            anyhow::bail!(
                "this interface still runs {running} started by the router; review changes and confirm Apply"
            );
        }
        Ok(InterfaceEditRequest {
            cidr: if self.managed {
                self.cidr.trim().to_string()
            } else {
                String::new()
            },
            role: self.role,
            managed: self.managed,
            allow_management_change: self.allow_management_change,
        })
    }
}

pub(crate) fn render_interface_list(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let block = panel("Interfaces | [ext] external, [?] ownership unknown");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    app.ui.list_area = Some(inner);
    app.ui.list_row_height = 1;
    app.ui.list_count = app.dashboard.interfaces.len();
    let visible = inner.height as usize;
    let offset = app
        .selected_interface
        .saturating_sub(visible.saturating_sub(1));
    app.ui.list_scroll_offset = offset;

    let lines = app
        .dashboard
        .interfaces
        .iter()
        .enumerate()
        .skip(offset)
        .take(visible)
        .map(|(index, status)| {
            let selected = index == app.selected_interface;
            let marker = if selected { "▶" } else { " " };
            let addresses = format_addresses(status);
            let style = if selected {
                Style::default()
                    .fg(theme::ACCENT)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let status_span = if status.interface.is_up {
                Span::styled("up  ", Style::default().fg(theme::GOOD))
            } else {
                Span::styled("down", Style::default().fg(theme::MUTED))
            };
            let is_managed = app
                .dashboard
                .managed
                .get(&status.interface.name)
                .copied()
                .unwrap_or(false);
            let managed_span = if is_managed {
                Span::styled("traffic-masq ", Style::default().fg(theme::GOOD))
            } else {
                Span::styled("external     ", Style::default().fg(theme::WARN))
            };
            let mut line = Line::from(vec![
                Span::styled(format!("{marker} {:<12}", status.interface.name), style),
                status_span,
                Span::raw("  "),
                managed_span,
                Span::raw("  "),
            ]);
            line.spans.extend(addresses);
            line
        })
        .collect::<Vec<_>>();

    frame.render_widget(Paragraph::new(lines), inner);
}

const REMOVE_IPV4_LABEL: &str = "Remove IPv4 address (clear the field)";
/// Slot 0 and 1 are already spoken for by Save and the cancel strip below it.
const REMOVE_IPV4_BUTTON_SLOT: usize = 2;

pub(crate) fn render_editor(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let Some(editor) = &app.editor else {
        return;
    };

    let row = |label: &str, value: String, field: InterfaceEditorField| {
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
    let action_row = |label: &str, field: InterfaceEditorField| {
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

    let active = editor.field == InterfaceEditorField::Cidr;
    let cidr_label_style = if active {
        Style::default()
            .fg(theme::ACCENT)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme::ACCENT)
    };
    let cidr_marker = if active { "▶ " } else { "  " };
    let mut cidr_spans = vec![Span::styled(
        format!("{cidr_marker}IPv4 CIDR: "),
        cidr_label_style,
    )];
    cidr_spans.extend(super::input::render_value_with_cursor(
        &editor.cidr,
        editor.cursor,
        active && editor.managed,
        cidr_label_style,
    ));

    let mut lines = vec![
        Line::from(format!("Interface: {}", editor.interface)),
        Line::from(cidr_spans),
    ];
    if !editor.managed {
        lines.push(Line::styled(
            "IPv4 editing is disabled. Enable Configure with traffic-masq to change addresses.",
            Style::default().fg(theme::MUTED),
        ));
    }
    if !editor.cidr.trim().is_empty() && editor.cidr.trim().parse::<ipnet::Ipv4Net>().is_err() {
        lines.push(Line::styled(
            "  Invalid CIDR — expected address/prefix, e.g. 192.168.1.10/24",
            Style::default().fg(theme::BAD),
        ));
    }
    let mut observed = Line::from("  Observed: ");
    observed.spans.extend(editor.observed_addresses.clone());
    lines.push(observed);
    lines.push(Line::styled(
        "  [ext] external; [?] ownership unknown",
        Style::default().fg(theme::WARN),
    ));
    let remove_row_index = lines.len() as u16;
    lines.push(action_row(
        REMOVE_IPV4_LABEL,
        InterfaceEditorField::RemoveIpv4,
    ));
    // An empty field is the instruction to take the address off, so it has to
    // read as one. Silence here is how "I cleared it and nothing happened"
    // starts.
    if editor.cidr.trim().is_empty() {
        let removal = if editor.current_addresses.is_empty() {
            Line::styled(
                "  No static IPv4 requested",
                Style::default().fg(theme::MUTED),
            )
        } else {
            Line::styled(
                format!(
                    "  Observed on {}: {}. Preview shows which owned addresses will be removed",
                    editor.interface,
                    editor.current_addresses.join(", ")
                ),
                Style::default().fg(theme::WARN),
            )
        };
        lines.push(removal);
    }
    lines.extend([
        row(
            "Router role",
            format!("{:?}", editor.role),
            InterfaceEditorField::Role,
        ),
        row(
            "Configure with traffic-masq",
            if editor.managed { "On" } else { "Off" }.to_string(),
            InterfaceEditorField::Managed,
        ),
    ]);
    lines.push(Line::styled(
        "None: outside the router. Review changes before applying.",
        Style::default().fg(theme::MUTED),
    ));
    if !editor.managed && editor.cidr.trim() != editor.original_cidr.trim() {
        let message = if editor.cidr.trim().is_empty() {
            "Cannot remove the IP while the interface is unmanaged; enable Configure with traffic-masq first"
        } else {
            "Cannot change IP while the interface is unmanaged; enable Configure with traffic-masq first"
        };
        lines.push(Line::styled(message, Style::default().fg(theme::BAD)));
    }
    if editor.original_managed && !editor.managed {
        lines.push(Line::styled(
            "Saving will remove traffic-masq-owned settings and stop managing this interface",
            Style::default().fg(theme::WARN),
        ));
    }
    lines.push(Line::styled(
        "j/k or arrows: move | Enter/Space: activate | type digits, '.', '/' to edit CIDR (e.g. 192.168.1.10/24)",
        Style::default().fg(theme::MUTED),
    ));
    lines.push(Line::styled(
        "Empty CIDR removes owned static IPv4 only; external addresses are preserved",
        Style::default().fg(theme::MUTED),
    ));
    lines.push(Line::from(""));

    const SAVE_LABEL: &str = "Review changes";
    let button_row_index = lines.len() as u16;
    lines.push(action_row(SAVE_LABEL, InterfaceEditorField::Save));

    let block = panel("Interface editor");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let offset = super::layout::focused_lines_offset(&lines, inner.height);
    for (row, width, slot) in [
        (button_row_index, SAVE_LABEL.len(), 0),
        (
            remove_row_index,
            REMOVE_IPV4_LABEL.len() + 2,
            REMOVE_IPV4_BUTTON_SLOT,
        ),
    ] {
        if row as usize >= offset && (row as usize) < offset + inner.height as usize {
            app.ui.buttons.push((
                Rect::new(
                    inner.x,
                    inner.y + (row as usize - offset) as u16,
                    (width as u16).min(inner.width),
                    1,
                ),
                slot,
            ));
        }
    }
    frame.render_widget(
        Paragraph::new(lines.into_iter().skip(offset).collect::<Vec<_>>()),
        inner,
    );
}

const PREVIEW_APPLY_LABEL: &str = "Apply";
const PREVIEW_RELEASE_LABEL: &str = "Remove settings and stop managing";
const PREVIEW_CANCEL_LABEL: &str = "Cancel";

pub(crate) fn render_preview(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let Some(plan) = &app.preview else {
        return;
    };
    let delete = if plan.delete_ipv4.is_empty() {
        "none".to_string()
    } else {
        plan.delete_ipv4
            .iter()
            .map(|address| format!("{}/{}", address.address, address.prefix_len))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let add = plan
        .add_ipv4
        .as_ref()
        .map(|address| format!("{}/{}", address.address, address.prefix_len))
        .unwrap_or_else(|| "none".to_string());
    let retag = plan
        .retag_ipv4
        .as_ref()
        .map(|address| format!("{}/{}", address.address, address.prefix_len))
        .unwrap_or_else(|| "none".to_string());
    let mut lines = vec![
        Line::from(format!("Interface: {}", plan.interface)),
        Line::from(format!("Delete IPv4: {delete}")),
        Line::from(format!("Claim existing IPv4: {retag}")),
        Line::from(format!("Add IPv4: {add}")),
        Line::from(format!("Set link up: {}", plan.set_link_up)),
        Line::from(format!(
            "Outside-router interface affected: {}",
            plan.management_change
        )),
        Line::from(format!("DHCP action: {:?}", plan.dhcp_action)),
        Line::from(format!(
            "Stop managing interface: {}",
            plan.releasing_management
        )),
        Line::styled(
            "Applying starts an automatic rollback timer.",
            Style::default().fg(theme::WARN),
        ),
        Line::from(""),
    ];

    if let Some(editor) = &app.editor {
        if editor.has_default_route {
            lines.push(Line::styled(
                "This interface carries the default route; connectivity may be interrupted.",
                Style::default().fg(theme::WARN),
            ));
        }
        if plan.management_change || !plan.delete_ipv4.is_empty() {
            lines.push(Line::styled(
                "Changing addresses or router participation may disconnect existing sessions.",
                Style::default().fg(theme::WARN),
            ));
        }
        if editor.original_managed && (!editor.managed || editor.role != InterfaceRole::Output) {
            for service in [&editor.current_wifi_summary, &editor.current_dhcp_summary]
                .into_iter()
                .flatten()
            {
                lines.push(Line::styled(format!("Router-started {service} keeps running until the router config is re-applied."), Style::default().fg(theme::WARN)));
            }
        }
    }

    let block = panel("Dry-run preview");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let apply_label = if plan.releasing_management {
        PREVIEW_RELEASE_LABEL
    } else {
        PREVIEW_APPLY_LABEL
    };
    let apply_row = lines.len();
    let choice = |label: &str, selected: bool| {
        let marker = if selected { "▶ " } else { "  " };
        let style = if selected {
            Style::default()
                .fg(theme::SELECTED_FG)
                .bg(theme::SELECTED_BG)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        Line::styled(format!("{marker}{label}"), style)
    };
    lines.push(choice(apply_label, app.preview_apply_selected));
    lines.push(choice(PREVIEW_CANCEL_LABEL, !app.preview_apply_selected));
    lines.push(Line::styled(
        "Up/Down: select | PgUp/PgDn: scroll | Enter: confirm | Esc: cancel",
        Style::default().fg(theme::MUTED),
    ));
    let offset = app
        .preview_scroll
        .unwrap_or_else(|| super::layout::focused_lines_offset(&lines, inner.height))
        .min(lines.len().saturating_sub(inner.height as usize));
    for (slot, label) in [apply_label, PREVIEW_CANCEL_LABEL].iter().enumerate() {
        let row = apply_row + slot;
        if row >= offset && row < offset + inner.height as usize {
            app.ui.buttons.push((
                Rect::new(
                    inner.x,
                    inner.y + (row - offset) as u16,
                    (label.len() as u16 + 2).min(inner.width),
                    1,
                ),
                slot,
            ));
        }
    }
    frame.render_widget(
        Paragraph::new(lines.into_iter().skip(offset).collect::<Vec<_>>()),
        inner,
    );
}

const PENDING_COMMIT_LABEL: &str = "Commit";
const PENDING_ROLLBACK_LABEL: &str = "Rollback";

pub(crate) fn render_pending(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let Some(change) = &app.pending else {
        return;
    };
    let seconds = change.expires_at_unix.saturating_sub(current_unix_time());
    let mut lines = vec![
        Line::from(format!("Interface: {}", change.interface)),
        Line::styled(
            format!("Automatic rollback in: {seconds}s"),
            Style::default().fg(if seconds <= 10 {
                theme::BAD
            } else {
                theme::WARN
            }),
        ),
        Line::styled(
            "Commit only after verifying connectivity.",
            Style::default().fg(theme::MUTED),
        ),
        Line::from(""),
    ];

    let block = panel("Pending change");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    app.ui.buttons.push((
        Rect {
            x: inner.x,
            y: inner.y + lines.len() as u16,
            width: PENDING_COMMIT_LABEL.len() as u16,
            height: 1,
        },
        0,
    ));
    lines.push(Line::styled(
        PENDING_COMMIT_LABEL,
        Style::default()
            .fg(theme::ACCENT)
            .add_modifier(Modifier::BOLD),
    ));
    app.ui.buttons.push((
        Rect {
            x: inner.x,
            y: inner.y + lines.len() as u16,
            width: PENDING_ROLLBACK_LABEL.len() as u16,
            height: 1,
        },
        1,
    ));
    lines.push(Line::styled(
        PENDING_ROLLBACK_LABEL,
        Style::default()
            .fg(theme::ACCENT)
            .add_modifier(Modifier::BOLD),
    ));
    frame.render_widget(Paragraph::new(lines), inner);
}

pub(crate) fn focus_action(app: &mut TuiApp, slot: usize) {
    if let Some(editor) = app.editor.as_mut() {
        editor.field = if slot == REMOVE_IPV4_BUTTON_SLOT {
            InterfaceEditorField::RemoveIpv4
        } else {
            InterfaceEditorField::Save
        };
        editor.reset_cursor();
    }
}

pub(crate) async fn handle_interface_list_key(
    app: &mut TuiApp,
    key: KeyCode,
    client: &ApiClient,
    direct: bool,
) {
    match key {
        KeyCode::Esc => app.screen = Screen::Dashboard,
        KeyCode::Up | KeyCode::Char('k') => {
            app.selected_interface = app.selected_interface.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j')
            if app.selected_interface + 1 < app.dashboard.interfaces.len() =>
        {
            app.selected_interface += 1;
        }
        KeyCode::Home => app.selected_interface = 0,
        KeyCode::End => {
            app.selected_interface = app.dashboard.interfaces.len().saturating_sub(1);
        }
        KeyCode::Enter if !direct => open_editor(app, client).await,
        KeyCode::Enter => {
            app.push_message(LogLevel::Warn, "Direct mode is read-only");
        }
        _ => {}
    }
}

pub(crate) async fn open_editor(app: &mut TuiApp, client: &ApiClient) {
    let Some(status) = app.dashboard.interfaces.get(app.selected_interface) else {
        return;
    };
    let name = status.interface.name.clone();

    match client
        .request(&Request::GetInterfaceConfig {
            interface: name.clone(),
        })
        .await
    {
        Ok(Response::InterfaceConfig {
            config,
            allow_management_change,
            ..
        }) => {
            let cidr = config
                .as_ref()
                .and_then(|interface| interface.ipv4)
                .map(|network| network.to_string())
                .unwrap_or_default();

            let current_addresses = status
                .ipv4_addresses
                .iter()
                .map(|address| format!("{}/{}", address.address, address.prefix_len))
                .collect();
            let original_managed = config.as_ref().is_some_and(|interface| interface.managed);
            let original_cidr = cidr.clone();
            let original_role = config
                .as_ref()
                .map_or(InterfaceRole::None, |interface| interface.role);
            let current_wifi_summary = config
                .as_ref()
                .and_then(|interface| interface.wifi.as_ref())
                .map(|wifi| format!("access point '{}'", wifi.ssid));
            let current_dhcp_summary = config
                .as_ref()
                .and_then(|interface| interface.dhcp.as_ref())
                .map(|dhcp| format!("DHCP pool {}-{}", dhcp.pool_start, dhcp.pool_end));
            let cursor = cidr.chars().count();
            app.editor = Some(InterfaceEditor {
                interface: name,
                field: InterfaceEditorField::Cidr,
                cidr,
                role: original_role,
                managed: original_managed,
                allow_management_change,
                has_default_route: status.has_default_route,
                original_managed,
                original_cidr,
                observed_addresses: format_addresses(status),
                current_addresses,
                current_wifi_summary,
                current_dhcp_summary,
                cursor,
            });
            app.preview = None;
            app.screen = Screen::InterfaceEditor;
        }
        Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected response while loading interface config: {response:?}"),
        ),
        Err(error) => app.push_message(
            LogLevel::Error,
            format!("Failed to load interface config: {error}"),
        ),
    }
}

pub(crate) async fn handle_editor_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    let Some(editor) = app.editor.as_mut() else {
        app.screen = Screen::InterfaceList;
        return;
    };

    match key {
        KeyCode::Esc => app.screen = Screen::InterfaceList,
        KeyCode::Up | KeyCode::Char('k') if editor.field != InterfaceEditorField::Cidr => {
            editor.field = previous_editor_field(editor.field);
            editor.reset_cursor();
        }
        KeyCode::Up => {
            editor.field = previous_editor_field(editor.field);
            editor.reset_cursor();
        }
        KeyCode::Down | KeyCode::Char('j') if editor.field != InterfaceEditorField::Cidr => {
            editor.field = next_editor_field(editor.field);
            editor.reset_cursor();
        }
        KeyCode::Down => {
            editor.field = next_editor_field(editor.field);
            editor.reset_cursor();
        }
        KeyCode::Enter | KeyCode::Char(' ') => match editor.field {
            InterfaceEditorField::Cidr => {}
            InterfaceEditorField::RemoveIpv4 => {
                if editor.managed {
                    editor.remove_ipv4();
                }
            }
            InterfaceEditorField::Role => editor.role = next_role(editor.role),
            InterfaceEditorField::Managed => editor.managed = !editor.managed,
            InterfaceEditorField::Save => submit_dry_run(app, client).await,
        },
        other if editor.field == InterfaceEditorField::Cidr && editor.managed => {
            let cursor = &mut editor.cursor;
            super::input::TextEditor::new(&mut editor.cidr, cursor)
                .handle_key_filtered(other, |c| c.is_ascii_digit() || matches!(c, '.' | '/'));
        }
        _ => {}
    }
}

fn previous_editor_field(field: InterfaceEditorField) -> InterfaceEditorField {
    super::input::move_clamped(&INTERFACE_EDITOR_FIELDS, field, false)
}

fn next_editor_field(field: InterfaceEditorField) -> InterfaceEditorField {
    super::input::move_clamped(&INTERFACE_EDITOR_FIELDS, field, true)
}

pub(crate) async fn submit_dry_run(app: &mut TuiApp, client: &ApiClient) {
    let Some(editor) = &mut app.editor else {
        return;
    };
    // Preview is read-only. The separate Apply action confirms these risks.
    editor.allow_management_change = true;
    let interface = editor.interface.clone();
    let edit = match editor.edit_request() {
        Ok(edit) => edit,
        Err(error) => {
            app.push_message(LogLevel::Warn, format!("Invalid interface edit: {error}"));
            return;
        }
    };
    match client
        .request(&Request::DryRunInterfaceEdit { interface, edit })
        .await
    {
        Ok(Response::InterfacePlan { plan }) => {
            app.preview = Some(plan);
            app.preview_apply_selected = false;
            app.preview_scroll = None;
            app.screen = Screen::Preview;
        }
        Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

pub(crate) async fn handle_preview_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    match key {
        KeyCode::Esc => app.screen = Screen::InterfaceEditor,
        KeyCode::Up | KeyCode::Down | KeyCode::Left | KeyCode::Right => {
            app.preview_apply_selected = !app.preview_apply_selected;
            app.preview_scroll = None;
        }
        KeyCode::PageUp | KeyCode::Home => app.preview_scroll = Some(0),
        KeyCode::PageDown | KeyCode::End => app.preview_scroll = None,
        KeyCode::Enter if app.preview_apply_selected => apply_preview(app, client).await,
        KeyCode::Enter => app.screen = Screen::InterfaceEditor,
        _ => {}
    }
}

pub(crate) fn focus_preview_action(app: &mut TuiApp, slot: usize) {
    app.preview_apply_selected = slot == 0;
    app.preview_scroll = None;
}

async fn apply_preview(app: &mut TuiApp, client: &ApiClient) {
    let Some(editor) = &app.editor else {
        app.screen = Screen::InterfaceList;
        return;
    };
    let edit = match editor.edit_request() {
        Ok(edit) => edit,
        Err(error) => {
            app.push_message(LogLevel::Error, error.to_string());
            return;
        }
    };

    match client
        .request(&Request::ApplyInterfaceEdit {
            interface: editor.interface.clone(),
            edit,
        })
        .await
    {
        Ok(Response::NetworkChangePending { change }) => {
            app.pending = Some(change);
            app.screen = Screen::PendingChange;
        }
        Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

pub(crate) async fn handle_pending_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    match key {
        KeyCode::Enter => finish_pending(app, client, true).await,
        KeyCode::Esc => finish_pending(app, client, false).await,
        _ => {}
    }
}

async fn finish_pending(app: &mut TuiApp, client: &ApiClient, commit: bool) {
    let Some(change) = &app.pending else {
        app.screen = Screen::Dashboard;
        return;
    };
    let request = if commit {
        Request::CommitNetworkChange {
            token: change.token.clone(),
        }
    } else {
        Request::RollbackNetworkChange {
            token: change.token.clone(),
        }
    };

    match client.request(&request).await {
        Ok(Response::NetworkChangeCommitted { .. }) if commit => {
            app.push_message(LogLevel::Info, "Network change committed");
            app.pending = None;
            app.screen = Screen::Dashboard;
        }
        Ok(Response::NetworkChangeRolledBack { .. }) if !commit => {
            app.push_message(LogLevel::Info, "Network change rolled back");
            app.pending = None;
            app.screen = Screen::Dashboard;
        }
        Ok(Response::Error { message }) => {
            app.push_message(LogLevel::Error, message);
        }
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

fn next_role(role: InterfaceRole) -> InterfaceRole {
    match role {
        InterfaceRole::None => InterfaceRole::Input,
        InterfaceRole::Input => InterfaceRole::Output,
        InterfaceRole::Output => InterfaceRole::None,
        // `Middle` (a VPN-hop chain slot) isn't part of this TUI's manual
        // role cycle yet — that's the later topology-view plan's job. It
        // falls back to `None` rather than being reachable here.
        InterfaceRole::Disabled | InterfaceRole::Middle => InterfaceRole::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_route_editor(allow_management_change: bool) -> InterfaceEditor {
        InterfaceEditor {
            interface: "wlan0".into(),
            field: InterfaceEditorField::Save,
            cidr: "192.168.1.10/24".into(),
            role: InterfaceRole::Output,
            managed: true,
            allow_management_change,
            has_default_route: true,
            original_managed: true,
            original_cidr: "192.168.1.10/24".into(),
            current_addresses: vec!["192.168.1.10/24".into()],
            observed_addresses: vec![],
            current_wifi_summary: None,
            current_dhcp_summary: None,
            cursor: 0,
        }
    }

    fn unmanaged_editor() -> InterfaceEditor {
        let mut editor = default_route_editor(false);
        editor.original_managed = false;
        editor.managed = false;
        editor
    }

    #[test]
    fn managed_output_on_default_route_requires_explicit_confirmation() {
        let error = default_route_editor(false).edit_request().unwrap_err();
        assert!(error.to_string().contains("default route"));
    }

    #[test]
    fn managed_output_on_default_route_is_allowed_after_confirmation() {
        assert!(default_route_editor(true).edit_request().is_ok());
    }

    #[test]
    fn unmanaged_interface_rejects_ip_edits_with_a_clear_error() {
        let mut editor = unmanaged_editor();
        editor.cidr = "192.168.1.11/24".into();
        let error = editor.edit_request().unwrap_err();
        assert_eq!(
            error.to_string(),
            "cannot change IP while the interface is unmanaged; enable Configure with traffic-masq first"
        );
    }

    #[test]
    fn external_interface_can_change_router_role() {
        let mut editor = unmanaged_editor();
        editor.role = InterfaceRole::Input;
        let request = editor
            .edit_request()
            .expect("role is independent of address configuration");
        assert_eq!(request.role, InterfaceRole::Input);
        assert!(!request.managed);
    }

    #[test]
    fn unmanaged_interface_names_every_field_it_refuses_to_change() {
        let mut editor = unmanaged_editor();
        editor.cidr = "192.168.1.11/24".into();
        editor.role = InterfaceRole::Input;
        let error = editor.edit_request().unwrap_err();
        assert_eq!(
            error.to_string(),
            "cannot change IP while the interface is unmanaged; enable Configure with traffic-masq first"
        );
    }

    #[test]
    fn an_unmanaged_interface_can_still_be_saved_untouched() {
        // This is how a leftover traffic-masq address gets cleaned up, so it
        // must not be swallowed by the settings guard.
        assert!(unmanaged_editor().edit_request().is_ok());
    }

    #[test]
    fn turning_management_on_is_not_a_settings_edit() {
        let mut editor = unmanaged_editor();
        editor.managed = true;
        editor.allow_management_change = true;
        editor.cidr = "192.168.1.11/24".into();
        assert!(editor.edit_request().is_ok());
    }

    /// Clearing the field is the removal request, and it has to survive the
    /// trip to the daemon as an empty CIDR — that is what makes the planner
    /// take the address off instead of leaving it alone.
    #[test]
    fn an_empty_cidr_on_a_managed_interface_asks_for_the_address_to_be_removed() {
        let mut editor = default_route_editor(true);
        editor.cidr.clear();
        let request = editor.edit_request().expect("removal must be a valid edit");
        assert!(request.cidr.is_empty());
        assert!(request.managed, "removal keeps the interface managed");
        assert_eq!(request.role, InterfaceRole::Output);
    }

    #[test]
    fn removing_the_ip_of_an_unmanaged_interface_points_at_the_managed_switch() {
        let mut editor = unmanaged_editor();
        editor.cidr.clear();
        let error = editor.edit_request().unwrap_err();
        assert_eq!(
            error.to_string(),
            "cannot remove the IP while the interface is unmanaged; enable Configure with traffic-masq so traffic-masq may take the address off"
        );
    }

    #[test]
    fn the_remove_row_clears_the_cidr_field() {
        let mut editor = default_route_editor(true);
        editor.remove_ipv4();
        assert!(editor.cidr.is_empty());
        assert_eq!(
            editor.current_addresses,
            vec!["192.168.1.10/24".to_string()],
            "the address that is about to go is still reported"
        );
    }

    #[test]
    fn interface_editor_field_reaches_save_and_clamps_at_both_ends() {
        for pair in INTERFACE_EDITOR_FIELDS.windows(2) {
            assert_eq!(next_editor_field(pair[0]), pair[1]);
            assert_eq!(previous_editor_field(pair[1]), pair[0]);
        }
        assert_eq!(
            previous_editor_field(InterfaceEditorField::Cidr),
            InterfaceEditorField::Cidr
        );
        assert_eq!(
            next_editor_field(InterfaceEditorField::Save),
            InterfaceEditorField::Save
        );
    }

    #[test]
    fn next_role_cycles_through_all_three_variants_without_repeating() {
        let start = InterfaceRole::None;
        let mut role = start;
        let mut seen = Vec::new();
        for _ in 0..3 {
            seen.push(role);
            role = next_role(role);
        }
        assert_eq!(role, start, "cycle must return to the starting role");
        seen.sort_by_key(|role| format!("{role:?}"));
        seen.dedup();
        assert_eq!(seen.len(), 3, "all three roles must be distinct");
    }

    #[tokio::test]
    async fn interface_editor_cursor_navigation_and_editing() {
        let mut app = TuiApp {
            screen: Screen::InterfaceEditor,
            ..Default::default()
        };
        let mut editor = default_route_editor(true);
        editor.field = InterfaceEditorField::Cidr;
        editor.cidr = "192.168.1.1/24".into();
        editor.cursor = editor.cidr.len();
        app.editor = Some(editor);
        let client = ApiClient::new("/socket-that-must-not-be-opened");

        handle_editor_key(&mut app, KeyCode::Left, &client).await;
        assert_eq!(app.editor.as_ref().unwrap().cursor, 13);

        handle_editor_key(&mut app, KeyCode::Char('0'), &client).await;
        assert_eq!(app.editor.as_ref().unwrap().cidr, "192.168.1.1/204");
        assert_eq!(app.editor.as_ref().unwrap().cursor, 14);

        handle_editor_key(&mut app, KeyCode::Backspace, &client).await;
        assert_eq!(app.editor.as_ref().unwrap().cidr, "192.168.1.1/24");
        assert_eq!(app.editor.as_ref().unwrap().cursor, 13);

        handle_editor_key(&mut app, KeyCode::Home, &client).await;
        assert_eq!(app.editor.as_ref().unwrap().cursor, 0);

        handle_editor_key(&mut app, KeyCode::Delete, &client).await;
        assert_eq!(app.editor.as_ref().unwrap().cidr, "92.168.1.1/24");
        assert_eq!(app.editor.as_ref().unwrap().cursor, 0);
    }
}

#[cfg(test)]
mod rendering_tests {
    use super::*;
    use crate::api::model::InterfaceStatus;
    use crate::netlink::{Ipv4AddressInfo, NetworkInterface};
    use ratatui::{backend::TestBackend, Terminal};

    fn status(index: u32) -> InterfaceStatus {
        InterfaceStatus {
            interface: NetworkInterface {
                index,
                name: format!("eth{index}"),
                is_up: true,
                rx_bytes: 0,
                tx_bytes: 0,
                is_wireless: false,
            },
            ipv4_addresses: vec![],
            owned_ipv4_addresses: None,
            has_default_route: false,
        }
    }

    #[test]
    fn mixed_addresses_have_individual_ownership_colors() {
        let mut status = status(1);
        let address = |last, protocol| Ipv4AddressInfo {
            interface_index: 1,
            address: std::net::Ipv4Addr::new(192, 0, 2, last),
            prefix_len: 24,
            protocol,
        };
        // Journal-owned address without a kernel tag, our DHCP, foreign and untagged.
        status.ipv4_addresses = vec![
            address(1, None),
            address(2, Some(202)),
            address(3, Some(16)),
            address(4, None),
        ];
        status.owned_ipv4_addresses = Some(status.ipv4_addresses[..2].to_vec());
        let spans = format_addresses(&status);
        assert_eq!(spans[0].content, "192.0.2.1/24");
        assert_eq!(spans[2].content, "192.0.2.2/24");
        for index in [4, 6] {
            assert!(spans[index].content.starts_with("[ext] "));
            assert_eq!(spans[index].style.fg, Some(theme::WARN));
        }
        status.owned_ipv4_addresses = None;
        let spans = format_addresses(&status);
        assert!(spans[0].content.starts_with("[?] "));
        assert_eq!(spans[0].style.fg, Some(theme::WARN));
        assert!(!spans[2].content.starts_with('['));
        assert!(spans[4].content.starts_with("[ext] "));
    }

    #[test]
    fn interface_list_keeps_selected_row_visible_and_click_offset_correct() {
        let mut app = TuiApp::default();
        app.dashboard.interfaces = (0..20).map(status).collect();
        app.selected_interface = 19;
        let mut terminal = Terminal::new(TestBackend::new(80, 6)).unwrap();
        terminal
            .draw(|frame| render_interface_list(frame, frame.area(), &mut app))
            .unwrap();
        assert_eq!(app.ui.list_scroll_offset, 16);
        let buffer = terminal.backend().buffer();
        let last_row: String = (0..80).map(|x| buffer[(x, 4)].symbol()).collect();
        assert!(last_row.contains("eth19"));
    }

    #[test]
    fn preview_buttons_are_visible_and_cancel_has_a_click_target() {
        let mut app = TuiApp {
            preview: Some(crate::core::interface::InterfaceChangePlan {
                interface: "eth0".into(),
                delete_ipv4: vec![],
                retag_ipv4: None,
                add_ipv4: None,
                set_link_up: false,
                management_change: false,
                dhcp_action: crate::core::interface::DhcpChangeAction::Unchanged,
                releasing_management: false,
            }),
            preview_apply_selected: false,
            ..Default::default()
        };
        let mut terminal = Terminal::new(TestBackend::new(80, 8)).unwrap();
        terminal
            .draw(|frame| render_preview(frame, frame.area(), &mut app))
            .unwrap();
        let (rect, _) = app
            .ui
            .buttons
            .iter()
            .find(|(_, slot)| *slot == 1)
            .expect("Cancel click target");
        assert!(rect.y < 7);
        let buffer = terminal.backend().buffer();
        let row: String = (0..80).map(|x| buffer[(x, rect.y)].symbol()).collect();
        assert!(row.contains("Cancel"));
    }
}
