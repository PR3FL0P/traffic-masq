//! Read-only topology from router configuration and the displayed route list.
//! Connections describe configured relationships, not a resolved packet path.

use crossterm::event::KeyCode;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

use traffic_masq_protocol::hop_interface_name;
use traffic_masq_protocol::InterfaceRole;

use super::layout::panel;
use super::router::RouterData;
use super::{theme, TuiApp};

#[derive(Debug, Default, Clone)]
pub(crate) struct TopologyView {
    pub(crate) open: bool,
    pub(crate) loaded: bool,
    scroll: (u16, u16),
    max_scroll: (u16, u16),
    page_height: u16,
}

impl TopologyView {
    pub(crate) fn show(&mut self) {
        self.open = true;
        self.scroll = (0, 0);
    }

    pub(crate) fn handle_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc | KeyCode::Char('t') | KeyCode::Enter | KeyCode::Char(' ') => {
                self.open = false;
                self.scroll = (0, 0);
            }
            KeyCode::Up => self.scroll.0 = self.scroll.0.saturating_sub(1),
            KeyCode::Down => self.scroll.0 = self.scroll.0.saturating_add(1).min(self.max_scroll.0),
            KeyCode::Left => self.scroll.1 = self.scroll.1.saturating_sub(4),
            KeyCode::Right => {
                self.scroll.1 = self.scroll.1.saturating_add(4).min(self.max_scroll.1)
            }
            KeyCode::PageUp => self.scroll.0 = self.scroll.0.saturating_sub(self.page_height),
            KeyCode::PageDown => {
                self.scroll.0 = self
                    .scroll
                    .0
                    .saturating_add(self.page_height)
                    .min(self.max_scroll.0);
            }
            KeyCode::Home => self.scroll = (0, 0),
            KeyCode::End => self.scroll.0 = self.max_scroll.0,
            _ => {}
        }
    }
}

fn node(label: impl Into<String>, owned: Option<bool>, selected: bool) -> Line<'static> {
    let mut style = Style::default().fg(match owned {
        Some(true) => theme::GOOD,
        Some(false) => theme::WARN,
        None => theme::TEXT,
    });
    if selected {
        style = style.add_modifier(Modifier::BOLD | Modifier::UNDERLINED);
    }
    Line::styled(
        format!("{}{}", if selected { "▶ " } else { "  " }, label.into()),
        style,
    )
}

fn note(text: impl Into<String>) -> Line<'static> {
    Line::styled(text.into(), Style::default().fg(theme::MUTED))
}

fn arrow() -> Line<'static> {
    note("      ↓")
}

fn topology_lines(router: &RouterData, expanded: bool) -> Vec<Line<'static>> {
    let rows = router.route_rows();
    let selected_row = rows.get(router.selected_route);
    let selected_route = selected_row.and_then(super::router::row_config);
    let selected = selected_route.as_ref();
    let related =
        |name: &str| selected.is_some_and(|route| route.output_interface.as_deref() == Some(name));
    let desired = router.plan.as_ref().map(|plan| &plan.desired);
    let interfaces = desired.map_or(&[][..], |desired| desired.interfaces.as_slice());
    let mut lines = Vec::new();
    if !router.topology.loaded {
        lines.push(Line::styled(
            "Refresh incomplete / no data",
            Style::default().fg(theme::WARN),
        ));
    }
    if router.staged {
        lines.push(Line::styled(
            "Includes staged configuration edits",
            Style::default().fg(theme::WARN),
        ));
    }

    if let Some(connections) = &router.proposed_router_config.forwarding {
        lines.push(note("IPv4 forwarding connections"));
        for (index, connection) in connections.iter().enumerate() {
            lines.push(node(
                format!(
                    "{} {} → {}",
                    if index + 1 == connections.len() {
                        "└─"
                    } else {
                        "├─"
                    },
                    connection.from,
                    connection.to
                ),
                None,
                related(&connection.from) || related(&connection.to),
            ));
            lines.push(note(format!(
                "    {} · source {}",
                if connection.masquerade {
                    "Masquerade"
                } else {
                    "No NAT"
                },
                connection
                    .source_subnet
                    .map_or("any".into(), |subnet| subnet.to_string())
            )));
        }
        if connections.is_empty() {
            lines.push(note("  No forwarding connections"));
        }
        lines.push(note("Routes determine the packet path."));
        if expanded {
            lines.push(note("Observed default routes"));
            for route in router
                .routes
                .iter()
                .filter(|route| route.destination.prefix_len() == 0)
            {
                lines.push(note(format!(
                    "  {} via {} (table {})",
                    route.output_interface.as_deref().unwrap_or("unknown"),
                    route
                        .gateway
                        .map_or("on-link".into(), |gateway| gateway.to_string()),
                    route.table
                )));
            }
        }
    } else {
        lines.push(note("Local networks / Wi-Fi"));
        let mut has_lan = false;
        for interface in interfaces
            .iter()
            .filter(|interface| interface.config.role == InterfaceRole::Output)
        {
            has_lan = true;
            lines.push(node(
                format!(
                    "{}{}",
                    interface.name,
                    if interface.config.managed {
                        ""
                    } else {
                        " [ext]"
                    }
                ),
                Some(interface.config.managed),
                related(&interface.name),
            ));
            if let Some(address) = interface.config.ipv4 {
                lines.push(note(format!(
                    "    {}{}",
                    address.trunc(),
                    if interface.config.nat {
                        " NAT"
                    } else {
                        " no NAT"
                    }
                )));
            }
        }
        if !has_lan {
            lines.push(note(if desired.is_some() {
                "  No configured LAN"
            } else {
                "  LAN data unavailable"
            }));
        }
        lines.push(arrow());
        lines.push(node(
            format!(
                "Router: {}",
                if router.enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            ),
            None,
            false,
        ));
        lines.push(note(match &router.plan {
            Some(plan) => format!(
                "  Forwarding: {} (snapshot)",
                if plan.dataplane.snapshot.ipv4_forwarding {
                    "on"
                } else {
                    "off"
                }
            ),
            None => "  Forwarding: unknown".into(),
        }));

        // Configuration orders hops from the physical uplink towards the LAN.
        // Display the reverse order for outbound LAN traffic / tunnel transport.
        let chain = &router.proposed_router_config.vpn_chain;
        if chain.is_empty() {
            lines.push(note("  VPN: none configured"));
        } else {
            for (index, hop) in chain.iter().enumerate().rev() {
                lines.push(arrow());
                let interface = hop_interface_name(index as u32);
                lines.push(node(
                    format!("VPN: {interface}"),
                    Some(true),
                    related(&interface),
                ));
                if expanded {
                    lines.push(note(format!("    Profile: {}", hop.profile_name)));
                }
            }
        }
        lines.push(arrow());
        let uplink = router
            .proposed_router_config
            .uplink
            .as_ref()
            .map(|uplink| uplink.interface.as_str());
        if let Some(uplink) = uplink {
            let managed = interfaces
                .iter()
                .find(|interface| interface.name == uplink)
                .map(|interface| interface.config.managed);
            lines.push(node(
                format!(
                    "Uplink: {uplink}{}",
                    match managed {
                        Some(true) => "",
                        Some(false) => " [ext]",
                        None => " [?]",
                    }
                ),
                Some(managed.unwrap_or(false)),
                related(uplink),
            ));
            let gateways: Vec<_> = router
                .routes
                .iter()
                .filter(|route| {
                    route.destination.prefix_len() == 0
                        && route.output_interface.as_deref() == Some(uplink)
                })
                .collect();
            lines.push(note(format!("  Default candidates: {}", gateways.len())));
            for route in gateways {
                lines.push(node(
                    route.gateway.map_or_else(
                        || "Direct (no gateway)".into(),
                        |gateway| format!("Gateway: {gateway}"),
                    ),
                    Some(route.owner.is_owned()),
                    selected.is_some_and(|selected| {
                        selected.destination == route.destination
                            && selected.output_interface == route.output_interface
                    }),
                ));
                lines.push(note(format!(
                    "    table {} / metric {}",
                    route.table,
                    route.metric.unwrap_or(0)
                )));
            }
        } else {
            lines.push(node("Uplink: not configured", Some(false), false));
            lines.push(note("  Observed default routes:"));
            let mut found = false;
            for route in router
                .routes
                .iter()
                .filter(|route| route.destination.prefix_len() == 0)
            {
                found = true;
                lines.push(node(
                    format!(
                        "dev {}",
                        route.output_interface.as_deref().unwrap_or("unknown")
                    ),
                    Some(route.owner.is_owned()),
                    selected.is_some_and(|selected| {
                        selected.destination == route.destination
                            && selected.output_interface == route.output_interface
                    }),
                ));
                lines.push(node(
                    route.gateway.map_or_else(
                        || "Direct (no gateway)".into(),
                        |gateway| format!("Gateway: {gateway}"),
                    ),
                    Some(route.owner.is_owned()),
                    selected.is_some_and(|selected| {
                        selected.destination == route.destination
                            && selected.output_interface == route.output_interface
                    }),
                ));
                lines.push(note(format!(
                    "    table {} / metric {}",
                    route.table,
                    route.metric.unwrap_or(0)
                )));
            }
            if !found {
                lines.push(note("    None in route list"));
            }
        }
        // A dotted edge explicitly leaves Internet reachability unresolved.
        lines.push(note("      ⋮"));
        lines.push(node("Internet: not tested", None, false));
    }
    lines.push(Line::default());
    lines.push(note("Selected route (route list)"));
    if let Some(route) = selected {
        lines.push(node(
            route.destination.to_string(),
            Some(selected_row.is_some_and(|row| row.configured.is_some())),
            true,
        ));
        lines.push(node(
            selected_row
                .and_then(|row| row.observed.as_ref())
                .map_or_else(
                    || "saved / not observed".into(),
                    |route| route.owner.to_string(),
                ),
            Some(selected_row.is_some_and(|row| row.configured.is_some())),
            false,
        ));
        lines.push(note(format!(
            "  dev {}",
            route.output_interface.as_deref().unwrap_or("unknown")
        )));
        lines.push(note(route.gateway.map_or_else(
            || "  Direct / on-link".into(),
            |gateway| format!("  via {gateway}"),
        )));
        lines.push(note(format!(
            "  table {} / metric {}",
            route.table,
            route.metric.unwrap_or(0)
        )));
    } else {
        lines.push(note("  No route selected"));
    }
    lines
}

/// Wrap styled labels before computing scroll bounds so every continuation is reachable.
fn wrap_lines(lines: Vec<Line<'static>>, width: u16) -> Vec<Line<'static>> {
    let width = usize::from(width.max(1));
    let mut result = Vec::new();
    for line in lines {
        let mut current = Line::default().style(line.style);
        let mut used = 0;
        for span in line.spans {
            let mut chunk = String::new();
            for grapheme in span.content.graphemes(true) {
                let size = grapheme.width();
                if used > 0 && used + size > width {
                    current
                        .spans
                        .push(Span::styled(std::mem::take(&mut chunk), span.style));
                    result.push(current);
                    current = Line::default().style(line.style);
                    used = 0;
                }
                chunk.push_str(grapheme);
                used += size;
            }
            if !chunk.is_empty() {
                current.spans.push(Span::styled(chunk, span.style));
            }
        }
        result.push(current);
    }
    result
}

pub(crate) fn render(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp, expanded: bool) {
    let block = panel("Topology");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    // Keep this qualification visible even when the diagram is scrolled.
    frame.render_widget(
        Paragraph::new("Configured links; not a probe\n▶ related; yellow: external"),
        Rect::new(inner.x, inner.y, inner.width, inner.height.min(2)),
    );
    let content = Rect::new(
        inner.x,
        inner.y.saturating_add(2),
        inner.width,
        inner.height.saturating_sub(3),
    );
    let lines = wrap_lines(topology_lines(&app.router, expanded), content.width);
    let max_width = lines
        .iter()
        .map(Line::width)
        .max()
        .unwrap_or(0)
        .min(u16::MAX as usize) as u16;
    let view = &mut app.router.topology;
    view.page_height = content.height.max(1);
    view.max_scroll = (
        (lines.len().min(u16::MAX as usize) as u16).saturating_sub(content.height),
        max_width.saturating_sub(content.width),
    );
    view.scroll.0 = view.scroll.0.min(view.max_scroll.0);
    view.scroll.1 = if expanded {
        view.scroll.1.min(view.max_scroll.1)
    } else {
        0
    };
    let line_count = lines.len();
    frame.render_widget(Paragraph::new(lines).scroll(view.scroll), content);
    if inner.height > 2 {
        let footer = Rect::new(inner.x, inner.bottom() - 1, inner.width, 1);
        let (label, button_len) = if expanded {
            let text = "[Back: t / Esc / Enter]";
            (text, text.len() as u16)
        } else {
            let button_text = "[t: expand]";
            ("[t: expand] PgUp/PgDn: scroll", button_text.len() as u16)
        };
        let position = format!(" {}/{}", view.scroll.0 + 1, line_count);
        let label = if footer.width as usize >= label.len() + position.len() {
            format!("{label}{position}")
        } else {
            label.to_string()
        };
        frame.render_widget(
            Paragraph::new(label).style(Style::default().fg(theme::ACCENT)),
            footer,
        );
        // The topology action is also the close action in the expanded view.
        app.ui.buttons.push((
            Rect::new(footer.x, footer.y, button_len.min(footer.width), 1),
            6,
        ));
    }
}

#[cfg(test)]
mod tests;
