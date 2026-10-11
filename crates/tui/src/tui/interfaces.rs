use anyhow::Result;
use crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Gauge, Paragraph};

use crate::tui::api::client::ApiClient;
use crate::tui::api::model::{InterfaceEditRequest, Request, Response};
use traffic_masq_protocol::InterfaceRole;

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
    MacAddress,
    RandomizeMac,
    Save,
}

const INTERFACE_EDITOR_FIELDS: [InterfaceEditorField; 7] = [
    InterfaceEditorField::Cidr,
    InterfaceEditorField::RemoveIpv4,
    InterfaceEditorField::Role,
    InterfaceEditorField::Managed,
    InterfaceEditorField::MacAddress,
    InterfaceEditorField::RandomizeMac,
    InterfaceEditorField::Save,
];

#[derive(Debug, Clone)]
pub(crate) struct InterfaceEditor {
    pub(crate) mac_address: String,
    pub(crate) interface: String,
    pub(crate) saved_config: Option<traffic_masq_protocol::InterfaceConfigView>,
    pub(crate) offline_revision: Option<u64>,
    pub(crate) intent_confirmation: Option<bool>,
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
        self.cursor = match self.field {
            InterfaceEditorField::Cidr => super::input::grapheme_count(&self.cidr),
            InterfaceEditorField::MacAddress => super::input::grapheme_count(&self.mac_address),
            _ => 0,
        };
    }

    /// Ask for the address to be taken off. An empty CIDR field is the request:
    /// the daemon plans deletion only for addresses it owns.
    pub(crate) fn remove_ipv4(&mut self) {
        self.cidr.clear();
        self.cursor = 0;
    }

    fn parsed_mac_address(&self) -> Result<Option<traffic_masq_protocol::MacAddr>> {
        if self.mac_address.trim().is_empty() {
            return Ok(None);
        }
        let mac: traffic_masq_protocol::MacAddr =
            self.mac_address.trim().parse().map_err(|_| {
                anyhow::anyhow!(
                    "Invalid MAC address — expected six hex pairs, e.g. 02:11:22:33:44:55"
                )
            })?;
        anyhow::ensure!(
            mac.octets() != [0; 6] && mac.octets()[0] & 1 == 0,
            "MAC address must be a non-zero unicast address"
        );
        Ok(Some(mac))
    }

    pub(crate) fn edit_request(&self) -> Result<InterfaceEditRequest> {
        let mac_address = self.parsed_mac_address()?;
        // Router participation is independent of address ownership.
        // Address edits require traffic-masq configuration to be enabled.
        if mac_address.is_some() && !self.managed {
            anyhow::bail!("MAC address requires Configure with traffic-masq");
        }
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
            && (self.original_managed || self.managed)
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
            mac_address,
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

pub(crate) fn selected_interface_name(app: &TuiApp) -> Option<String> {
    match &app.dashboard.inventory {
        Some(entries) => entries
            .get(app.selected_inventory_interface)
            .map(|entry| entry.name.clone()),
        None => app
            .dashboard
            .interfaces
            .get(app.selected_interface)
            .map(|status| status.interface.name.clone()),
    }
}

pub(crate) fn interface_selection(app: &TuiApp) -> usize {
    if app.dashboard.inventory.is_some() {
        app.selected_inventory_interface
    } else {
        app.selected_interface
    }
}

pub(crate) fn set_interface_selection(app: &mut TuiApp, index: usize) {
    if app.dashboard.inventory.is_some() {
        app.selected_inventory_interface = index;
    } else {
        app.selected_interface = index;
    }
}

pub(crate) fn interface_count(app: &TuiApp) -> usize {
    app.dashboard
        .inventory
        .as_ref()
        .map_or(app.dashboard.interfaces.len(), Vec::len)
}

pub(crate) fn render_interface_list(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    render_interface_inventory(frame, area, app, false);
}

pub(crate) fn render_interface_inventory(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    app: &mut TuiApp,
    dhcp: bool,
) {
    if let Some(entries) = &app.dashboard.inventory {
        let block = panel(if dhcp {
            "DHCP servers | Enter: configure"
        } else {
            "Interfaces | Enter: edit"
        });
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let name_width = entries
            .iter()
            .map(|entry| entry.name.chars().count() + if entry.suppressed { 12 } else { 0 })
            .max()
            .unwrap_or(16)
            .max(16);
        let header = format!(
            "  {:<name_width$} {:<8} {:<6} {:<20} IPv4",
            "Interface",
            "Device",
            "Link",
            if dhcp { "DHCP server" } else { "Management" }
        );
        frame.render_widget(
            Paragraph::new(header).style(
                Style::default()
                    .fg(theme::MUTED)
                    .add_modifier(Modifier::BOLD),
            ),
            Rect {
                height: inner.height.min(1),
                ..inner
            },
        );
        let rows = Rect {
            y: inner.y.saturating_add(1),
            height: inner.height.saturating_sub(1),
            ..inner
        };
        app.ui.list_area = Some(rows);
        app.ui.list_row_height = 1;
        app.ui.list_count = entries.len();
        let offset = app
            .selected_inventory_interface
            .saturating_sub((rows.height as usize).saturating_sub(1));
        app.ui.list_scroll_offset = offset;
        let lines: Vec<Line> = entries
            .iter()
            .enumerate()
            .skip(offset)
            .take(rows.height as usize)
            .map(|(index, entry)| {
                let marker = if index == app.selected_inventory_interface {
                    "▶"
                } else {
                    " "
                };
                let presence = match entry.presence {
                    traffic_masq_protocol::InterfacePresence::Present => "present",
                    traffic_masq_protocol::InterfacePresence::Missing => "missing",
                    traffic_masq_protocol::InterfacePresence::Unknown => "unknown",
                };
                let link = if presence == "present" {
                    match entry.observed.as_ref() {
                        Some(status) if status.interface.is_up => "up",
                        Some(_) => "down",
                        None => "?",
                    }
                } else {
                    "—"
                };
                let configured = entry
                    .configured
                    .as_ref()
                    .and_then(|config| config.ipv4)
                    .map(|ip| format!(" saved:{ip}"))
                    .unwrap_or_default();
                let addresses = entry
                    .observed
                    .as_ref()
                    .map(|status| {
                        status
                            .ipv4_addresses
                            .iter()
                            .map(|address| format!("{}/{}", address.address, address.prefix_len))
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                let style = if index == app.selected_inventory_interface {
                    Style::default()
                        .fg(theme::ACCENT)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                let presence_color = match presence {
                    "present" => theme::MUTED,
                    "missing" | "unknown" => theme::WARN,
                    _ => theme::MUTED,
                };
                let mut spans = vec![
                    Span::styled(
                        format!(
                            "{marker} {:<name_width$} ",
                            if entry.suppressed {
                                format!("{} [forgotten]", entry.name)
                            } else {
                                entry.name.clone()
                            }
                        ),
                        style,
                    ),
                    Span::styled(
                        format!("{presence:<8} "),
                        Style::default().fg(presence_color),
                    ),
                    Span::styled(
                        format!("{link:<6} "),
                        Style::default().fg(if link == "up" {
                            theme::GOOD
                        } else {
                            theme::MUTED
                        }),
                    ),
                ];
                if !dhcp {
                    let (owner, color) =
                        if entry.presence == traffic_masq_protocol::InterfacePresence::Unknown {
                            ("unknown", theme::WARN)
                        } else if entry
                            .configured
                            .as_ref()
                            .is_some_and(|config| config.managed)
                        {
                            if presence == "missing" {
                                ("saved: traffic-masq", theme::WARN)
                            } else {
                                ("traffic-masq", theme::GOOD)
                            }
                        } else {
                            ("unmanaged", theme::MUTED)
                        };
                    spans.push(Span::styled(
                        format!("{owner:<20} "),
                        Style::default().fg(color),
                    ));
                }
                if dhcp {
                    let active = app.dhcp_interfaces.iter().any(|name| name == &entry.name);
                    let saved = entry
                        .configured
                        .as_ref()
                        .is_some_and(|config| config.dhcp.is_some());
                    let (label, color) = if active {
                        ("active", theme::GOOD)
                    } else if saved {
                        ("configured", theme::WARN)
                    } else {
                        ("disabled", theme::MUTED)
                    };
                    spans.push(Span::styled(
                        format!("{label:<20} "),
                        Style::default().fg(color),
                    ));
                }
                spans.push(Span::raw(format!("{addresses}{configured}")));
                Line::from(spans)
            })
            .collect();
        frame.render_widget(Paragraph::new(lines), rows);
        return;
    }
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
            let is_managed = app.dashboard.managed.get(&status.interface.name).copied();
            let managed_span = match is_managed {
                Some(true) => Span::styled("traffic-masq ", Style::default().fg(theme::GOOD)),
                Some(false) => Span::styled("external     ", Style::default().fg(theme::WARN)),
                None => Span::styled("unknown      ", Style::default().fg(theme::WARN)),
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

    if let Some(forget) = editor.intent_confirmation {
        let entry = app
            .dashboard
            .inventory
            .as_ref()
            .and_then(|entries| entries.iter().find(|entry| entry.name == editor.interface));
        let action = if forget {
            "Forget saved configuration (including base)"
        } else {
            "Reset override and restore base configuration"
        };
        let references = entry
            .map(|entry| entry.references.join(", "))
            .unwrap_or_default();
        let origin = entry
            .map(|entry| format!("{:?}", entry.config_source))
            .unwrap_or_default();
        let text = format!("{action}: {}\nSource: {origin}\nReferences retained: {references}\nProfiles and credentials are retained.\nPress y to confirm; Esc to cancel.", editor.interface);
        frame.render_widget(
            Paragraph::new(text)
                .wrap(ratatui::widgets::Wrap { trim: false })
                .block(panel("Saved interface configuration")),
            area,
        );
        return;
    }

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
    if editor.offline_revision.is_some() {
        lines.push(Line::from(
            "Missing: Save stores settings; F5 forget; F6 reset to base",
        ));
    }
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
            match editor.role {
                InterfaceRole::Input => "Input — Internet / WAN",
                InterfaceRole::Output => "Output — local network / LAN",
                InterfaceRole::None => "None — outside the router",
                InterfaceRole::Middle => "Middle — VPN hop",
                InterfaceRole::Disabled => "Disabled",
            }
            .to_string(),
            InterfaceEditorField::Role,
        ),
        row(
            "Configure with traffic-masq",
            if editor.managed { "On" } else { "Off" }.to_string(),
            InterfaceEditorField::Managed,
        ),
    ]);
    let mac_active = editor.field == InterfaceEditorField::MacAddress;
    let mac_style = Style::default().fg(theme::ACCENT);
    let mut mac_spans = vec![Span::styled(
        format!(
            "{}MAC address (manual): ",
            if mac_active { "▶ " } else { "  " }
        ),
        mac_style,
    )];
    mac_spans.extend(super::input::render_value_with_cursor(
        &editor.mac_address,
        editor.cursor,
        mac_active && editor.managed,
        mac_style,
    ));
    lines.push(Line::from(mac_spans));
    if let Err(error) = editor.parsed_mac_address() {
        lines.push(Line::styled(
            format!("  {error}"),
            Style::default().fg(theme::BAD),
        ));
    }
    lines.push(action_row(
        "Generate random MAC (Enter)",
        InterfaceEditorField::RandomizeMac,
    ));
    lines.push(Line::styled(
        "  Type MAC manually or generate above; empty MAC keeps the current address",
        Style::default().fg(theme::MUTED),
    ));
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
            "Applying will remove traffic-masq-owned settings and stop managing this interface",
            Style::default().fg(theme::WARN),
        ));
    }
    lines.push(Line::styled(
        "Tab or up/down: move | Enter/Space: activate | type to edit IPv4 CIDR or MAC",
        Style::default().fg(theme::MUTED),
    ));
    lines.push(Line::styled(
        "Empty CIDR removes owned static IPv4 only; external addresses are preserved",
        Style::default().fg(theme::MUTED),
    ));
    lines.push(Line::from(""));

    let save_label = if editor.offline_revision.is_some() {
        "[Save for device return]"
    } else {
        "[Plan / Apply]"
    };
    let button_row_index = lines.len() as u16;
    lines.push(action_row(save_label, InterfaceEditorField::Save));

    let block = panel("Interface editor");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let offset = super::layout::focused_lines_offset(&lines, inner.height);
    for (row, width, slot) in [
        (button_row_index, save_label.len() + 2, 0),
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

const PREVIEW_APPLY_LABEL: &str = "[Apply]  apply changes (Enter)";
const PREVIEW_RELEASE_LABEL: &str = "[Apply]  remove settings and stop managing (Enter)";
const PREVIEW_CANCEL_LABEL: &str = "[Cancel] return without applying (Esc)";

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
        Line::from(format!(
            "Set MAC: {}",
            plan.mac_address
                .map_or_else(|| "unchanged".into(), |mac| mac.to_string())
        )),
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

    let block = panel("Interface plan preview");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let apply_label = if plan.releasing_management {
        PREVIEW_RELEASE_LABEL
    } else {
        PREVIEW_APPLY_LABEL
    };
    let cancel_row = lines.len();
    lines.push(Line::styled(
        PREVIEW_CANCEL_LABEL,
        Style::default().fg(theme::ACCENT),
    ));
    let apply_row = lines.len();
    lines.push(Line::styled(
        apply_label,
        Style::default()
            .fg(theme::SELECTED_FG)
            .bg(theme::SELECTED_BG)
            .add_modifier(Modifier::BOLD),
    ));

    let visible_rows = inner.height.max(1) as usize;
    app.preview_max_scroll = lines.len().saturating_sub(visible_rows);
    app.preview_scroll = app.preview_scroll.min(app.preview_max_scroll);
    let offset = app.preview_scroll;
    for (row, label, slot) in [
        (cancel_row, PREVIEW_CANCEL_LABEL, 1),
        (apply_row, apply_label, 0),
    ] {
        if row >= offset && row < offset.saturating_add(visible_rows) {
            app.ui.buttons.push((
                Rect::new(
                    inner.x,
                    inner.y + (row - offset) as u16,
                    (label.len() as u16).min(inner.width),
                    1,
                ),
                slot,
            ));
        }
    }
    frame.render_widget(
        Paragraph::new(lines).scroll((offset.min(u16::MAX as usize) as u16, 0)),
        inner,
    );
}

const PENDING_COMMIT_LABEL: &str = "[Commit]";
const PENDING_ROLLBACK_LABEL: &str = "[Rollback]";

pub(crate) fn render_pending(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let Some(change) = &app.pending else {
        return;
    };
    let seconds = change.expires_at_unix.saturating_sub(current_unix_time());
    let timeout = change.rollback_timeout_seconds;
    let ratio = if timeout > 0 {
        (seconds as f64 / timeout as f64).clamp(0.0, 1.0)
    } else {
        0.0
    };
    let gauge_color = if seconds > timeout / 2 {
        theme::GOOD
    } else if seconds > timeout / 4 {
        theme::WARN
    } else {
        theme::BAD
    };
    let mut lines = vec![
        Line::styled(
            format!("Pending transaction: {}", change.token),
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Line::from(format!("Interface: {}", change.interface)),
        Line::from(format!("Rollback scheduled in: {seconds}s / {timeout}s")),
    ];

    if let Some(progress) = &change.recovery_progress {
        lines.push(Line::from(format!(
            "Cause: {:?}; attempts {}/{}; automatic recovery {}",
            progress.failure_kind,
            progress.attempts,
            progress.max_attempts,
            if progress.automatic_recovery {
                "active"
            } else {
                "stopped"
            }
        )));
    }
    if let Some(error) = &change.last_error {
        lines.push(Line::from(format!("Last error: {error}")));
    }
    if !change.can_commit() {
        let message = if change.can_rollback() {
            "Rollback recovery required. Confirmation is disabled; Esc retries rollback."
        } else {
            "Commit outcome unknown. Repair storage access and restart the daemon."
        };
        lines[2] = Line::from(message);
        let block = panel("Network change recovery");
        let inner = block.inner(area);
        frame.render_widget(block, area);
        frame.render_widget(
            Paragraph::new(lines).wrap(ratatui::widgets::Wrap { trim: false }),
            inner,
        );
        return;
    }
    let block = panel("Network change pending confirmation");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(4),
        ])
        .split(inner);

    frame.render_widget(
        Gauge::default()
            .block(panel("Rollback countdown"))
            .gauge_style(Style::default().fg(gauge_color))
            .ratio(ratio)
            .label(format!("{seconds}s")),
        chunks[0],
    );
    frame.render_widget(Paragraph::new(lines), chunks[1]);

    app.ui.buttons.push((
        Rect::new(
            chunks[2].x,
            chunks[2].y,
            PENDING_COMMIT_LABEL.len() as u16,
            1,
        ),
        0,
    ));
    app.ui.buttons.push((
        Rect::new(
            chunks[2].x,
            chunks[2].y.saturating_add(1),
            PENDING_ROLLBACK_LABEL.len() as u16,
            1,
        ),
        1,
    ));
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(
                "[Commit]  persist changes (Enter)",
                Style::default()
                    .fg(theme::SELECTED_FG)
                    .bg(theme::GOOD)
                    .add_modifier(Modifier::BOLD),
            ),
            Line::styled(
                "[Rollback]  restore previous state (Esc)",
                Style::default()
                    .fg(theme::SELECTED_FG)
                    .bg(theme::WARN)
                    .add_modifier(Modifier::BOLD),
            ),
            Line::styled(
                "Commit only after verifying connectivity",
                Style::default().fg(theme::MUTED),
            ),
        ]),
        chunks[2],
    );
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
            set_interface_selection(app, interface_selection(app).saturating_sub(1));
        }
        KeyCode::Down | KeyCode::Char('j')
            if interface_selection(app) + 1 < interface_count(app) =>
        {
            set_interface_selection(app, interface_selection(app) + 1);
        }
        KeyCode::Home => set_interface_selection(app, 0),
        KeyCode::End => {
            set_interface_selection(app, interface_count(app).saturating_sub(1));
        }
        KeyCode::Enter if !direct => open_editor(app, client).await,
        KeyCode::Enter => {
            app.push_message(LogLevel::Warn, "Direct mode is read-only");
        }
        _ => {}
    }
}

pub(crate) async fn open_editor(app: &mut TuiApp, client: &ApiClient) {
    let Some(name) = selected_interface_name(app) else {
        return;
    };
    let status = app
        .dashboard
        .interfaces
        .iter()
        .find(|status| status.interface.name == name)
        .cloned();
    let entry = app
        .dashboard
        .inventory
        .as_ref()
        .and_then(|entries| entries.iter().find(|entry| entry.name == name));
    let offline_revision = entry
        .filter(|entry| entry.presence == traffic_masq_protocol::InterfacePresence::Missing)
        .and(app.dashboard.intent_revision);

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
            let (cidr, managed) = editor_address_defaults(config.as_ref(), status.as_ref());

            let current_addresses = status
                .as_ref()
                .into_iter()
                .flat_map(|status| status.ipv4_addresses.iter())
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
            let cursor = super::input::grapheme_count(&cidr);
            app.editor = Some(InterfaceEditor {
                mac_address: config
                    .as_ref()
                    .and_then(|config| config.mac_address)
                    .map(|mac| mac.to_string())
                    .unwrap_or_default(),
                interface: name,
                saved_config: config.clone(),
                offline_revision,
                intent_confirmation: None,
                field: InterfaceEditorField::Cidr,
                cidr,
                role: original_role,
                managed,
                allow_management_change,
                has_default_route: status
                    .as_ref()
                    .is_some_and(|status| status.has_default_route),
                original_managed,
                original_cidr,
                observed_addresses: status
                    .as_ref()
                    .map(format_addresses)
                    .unwrap_or_else(|| vec![Span::raw("unavailable")]),
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

fn editor_address_defaults(
    config: Option<&traffic_masq_protocol::InterfaceConfigView>,
    status: Option<&traffic_masq_protocol::InterfaceStatusView>,
) -> (String, bool) {
    if let Some(config) = config {
        return (
            config.ipv4.map(|ip| ip.to_string()).unwrap_or_default(),
            config.managed,
        );
    }
    // This is an editor draft, not recovered desired state. The daemon's
    // ownership proof can prefill our sole static address after settings were
    // removed; it never authorizes adopting an external or DHCP address.
    let mut owned = status.into_iter().flat_map(|status| {
        status.ipv4_addresses.iter().filter(move |address| {
            matches!(
                address.owner(),
                traffic_masq_protocol::AddressOwnerView::TrafficMasqStatic
                    | traffic_masq_protocol::AddressOwnerView::Untagged
            ) && status.owned_ipv4_addresses.as_ref().map_or_else(
                || address.owner() == traffic_masq_protocol::AddressOwnerView::TrafficMasqStatic,
                |owned| owned.contains(address),
            )
        })
    });
    let first = owned.next();
    let cidr = match (first, owned.next()) {
        (Some(address), None) => format!("{}/{}", address.address, address.prefix_len),
        _ => String::new(),
    };
    // A new interface has no saved instruction to keep management disabled.
    // Kernel changes still require the usual preview, apply and confirmation.
    (cidr, true)
}

pub(crate) async fn handle_editor_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    let Some(editor) = app.editor.as_mut() else {
        app.screen = Screen::InterfaceList;
        return;
    };

    if let Some(forget) = editor.intent_confirmation {
        if key == KeyCode::Esc {
            editor.intent_confirmation = None;
            return;
        }
        if key != KeyCode::Char('y') {
            return;
        }
        let Some(expected_revision) = editor.offline_revision else {
            return;
        };
        let interface = editor.interface.clone();
        let request = if forget {
            Request::ForgetInterfaceConfig {
                interface,
                expected_revision,
            }
        } else {
            Request::ResetInterfaceOverride {
                interface,
                expected_revision,
            }
        };
        match client.request(&request).await {
            Ok(Response::InterfaceIntentSaved {
                interface,
                deferred,
                ..
            }) => {
                app.push_message(
                    LogLevel::Info,
                    if deferred {
                        format!("Saved configuration updated for {interface}; application deferred")
                    } else {
                        format!("Saved configuration updated for {interface}")
                    },
                );
                app.screen = Screen::InterfaceList;
            }
            Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
            result => app.push_message(
                LogLevel::Error,
                format!("Configuration update failed: {result:?}"),
            ),
        }
        return;
    }

    let mut unmanaged_ip_attempt = false;
    let mut unmanaged_mac_attempt = false;

    match key {
        KeyCode::F(5) if editor.offline_revision.is_some() => {
            editor.intent_confirmation = Some(true);
        }
        KeyCode::F(6) if editor.offline_revision.is_some() => {
            editor.intent_confirmation = Some(false);
        }
        KeyCode::Esc => app.screen = Screen::InterfaceList,
        KeyCode::Up | KeyCode::Char('k') if editor.field != InterfaceEditorField::Cidr => {
            editor.field = previous_editor_field(editor.field);
            editor.reset_cursor();
        }
        KeyCode::Up | KeyCode::BackTab => {
            editor.field = previous_editor_field(editor.field);
            editor.reset_cursor();
        }
        KeyCode::Down | KeyCode::Char('j') if editor.field != InterfaceEditorField::Cidr => {
            editor.field = next_editor_field(editor.field);
            editor.reset_cursor();
        }
        KeyCode::Down | KeyCode::Tab => {
            editor.field = next_editor_field(editor.field);
            editor.reset_cursor();
        }
        KeyCode::Enter | KeyCode::Char(' ') => match editor.field {
            InterfaceEditorField::Cidr | InterfaceEditorField::MacAddress => {}
            InterfaceEditorField::RemoveIpv4 => {
                if editor.managed {
                    editor.remove_ipv4();
                } else {
                    unmanaged_ip_attempt = true;
                }
            }
            InterfaceEditorField::Role => editor.role = next_role(editor.role),
            InterfaceEditorField::Managed => {
                editor.managed = !editor.managed;
                if !editor.managed {
                    editor.mac_address.clear();
                }
            }
            InterfaceEditorField::RandomizeMac => {
                if editor.managed {
                    use rand::RngCore;
                    let mut octets = [0; 6];
                    rand::rngs::OsRng.fill_bytes(&mut octets);
                    octets[0] = (octets[0] & 0xfc) | 0x02;
                    editor.mac_address = traffic_masq_protocol::MacAddr::new(octets).to_string();
                } else {
                    unmanaged_mac_attempt = true;
                }
            }
            InterfaceEditorField::Save => submit_dry_run(app, client).await,
        },
        other if editor.field == InterfaceEditorField::MacAddress && editor.managed => {
            super::input::TextEditor::new(&mut editor.mac_address, &mut editor.cursor)
                .handle_key_filtered(other, |c| c.is_ascii_hexdigit() || c == ':');
        }
        KeyCode::Char(c)
            if editor.field == InterfaceEditorField::MacAddress
                && (c.is_ascii_hexdigit() || c == ':') =>
        {
            unmanaged_mac_attempt = true;
        }
        KeyCode::Backspace | KeyCode::Delete
            if editor.field == InterfaceEditorField::MacAddress =>
        {
            unmanaged_mac_attempt = true;
        }
        other if editor.field == InterfaceEditorField::Cidr && editor.managed => {
            let cursor = &mut editor.cursor;
            super::input::TextEditor::new(&mut editor.cidr, cursor)
                .handle_key_filtered(other, |c| c.is_ascii_digit() || matches!(c, '.' | '/'));
        }
        KeyCode::Char(c)
            if editor.field == InterfaceEditorField::Cidr
                && (c.is_ascii_digit() || matches!(c, '.' | '/')) =>
        {
            unmanaged_ip_attempt = true;
        }
        KeyCode::Backspace | KeyCode::Delete if editor.field == InterfaceEditorField::Cidr => {
            unmanaged_ip_attempt = true;
        }
        _ => {}
    }

    if unmanaged_mac_attempt {
        app.push_message(
            LogLevel::Warn,
            "MAC editing requires managed mode. Enable Configure with traffic-masq first.",
        );
    }
    if unmanaged_ip_attempt {
        app.push_message(
            LogLevel::Warn,
            "IP editing requires managed mode. Enable Configure with traffic-masq first.",
        );
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
    if let Some(expected_revision) = editor.offline_revision {
        let Some(mut config) = editor.saved_config.clone() else {
            app.push_message(LogLevel::Warn, "No saved interface configuration to edit");
            return;
        };
        config.ipv4 = if edit.cidr.is_empty() {
            None
        } else {
            edit.cidr.parse().ok()
        };
        config.role = edit.role;
        config.managed = edit.managed;
        config.mac_address = edit.mac_address;
        if config.role != InterfaceRole::Output || !config.managed {
            config.dhcp = None;
            config.wifi = None;
        }
        if config.role != InterfaceRole::Input || !config.managed || config.ipv4.is_some() {
            config.dhcp_client = None;
        }
        if config.role != InterfaceRole::Input || !config.managed {
            config.wifi_client = None;
        }
        match client
            .request(&Request::SaveInterfaceConfig {
                interface,
                config,
                allow_management_change: edit.allow_management_change,
                expected_revision,
            })
            .await
        {
            Ok(Response::InterfaceIntentSaved { interface, .. }) => {
                app.push_message(
                    LogLevel::Info,
                    format!("Saved; application waits for interface {interface}"),
                );
                app.screen = Screen::InterfaceList;
            }
            Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
            result => app.push_message(LogLevel::Error, format!("Save failed: {result:?}")),
        }
        return;
    }
    match client
        .request(&Request::DryRunInterfaceEdit { interface, edit })
        .await
    {
        Ok(Response::InterfacePlan { plan }) => {
            app.preview = Some(plan);
            app.preview_scroll = 0;
            app.preview_max_scroll = 0;
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
    const PAGE: usize = 10;
    match key {
        KeyCode::Esc => app.screen = Screen::InterfaceEditor,
        KeyCode::Up | KeyCode::Char('k') => {
            app.preview_scroll = app.preview_scroll.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.preview_scroll = app
                .preview_scroll
                .saturating_add(1)
                .min(app.preview_max_scroll);
        }
        KeyCode::PageUp => app.preview_scroll = app.preview_scroll.saturating_sub(PAGE),
        KeyCode::PageDown => {
            app.preview_scroll = app
                .preview_scroll
                .saturating_add(PAGE)
                .min(app.preview_max_scroll);
        }
        KeyCode::Home => app.preview_scroll = 0,
        KeyCode::End => app.preview_scroll = app.preview_max_scroll,
        KeyCode::Enter if app.preview_scroll >= app.preview_max_scroll => {
            apply_preview(app, client).await;
        }
        KeyCode::Enter => app.push_message(
            LogLevel::Warn,
            "Review the complete interface plan before applying; scroll to the end first.",
        ),
        _ => {}
    }
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
            app.pending_return_screen = Screen::InterfaceList;
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
        app.screen = app.pending_return_screen;
        return;
    };
    if (commit && !change.can_commit()) || (!commit && !change.can_rollback()) {
        if !commit {
            app.screen = app.pending_return_screen;
        }
        return;
    }
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
            app.preview = None;
            app.editor = None;
            app.screen = app.pending_return_screen;
        }
        Ok(Response::NetworkChangeRolledBack { .. }) if !commit => {
            app.push_message(LogLevel::Info, "Network change rolled back");
            app.pending = None;
            app.preview = None;
            app.editor = None;
            app.screen = app.pending_return_screen;
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
mod tests;

#[cfg(test)]
mod rendering_tests;
