use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use unicode_width::UnicodeWidthStr;

use super::theme;
use super::{active_sections, section_of_app, Screen, Section, TuiApp};

pub(crate) fn panel(title: &str) -> Block<'static> {
    Block::default()
        .title(Span::styled(
            format!(" {title} "),
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme::BORDER))
}

pub(crate) fn focused_lines_offset(lines: &[Line<'_>], height: u16) -> usize {
    lines
        .iter()
        .position(|line| line.spans.iter().any(|span| span.content.starts_with("▶ ")))
        .unwrap_or(0)
        .saturating_sub(height.saturating_sub(1) as usize)
}

#[derive(Debug, Default, Clone)]
pub(crate) struct UiLayout {
    pub(crate) input_enabled: bool,
    pub(crate) content_area: Option<Rect>,
    pub(crate) tabs: Vec<(Rect, Section)>,
    pub(crate) list_area: Option<Rect>,
    pub(crate) list_row_height: u16,
    pub(crate) list_count: usize,

    pub(crate) list_scroll_offset: usize,

    pub(crate) buttons: Vec<(Rect, usize)>,
}

impl UiLayout {
    /// Constrain every interactive region to the screen content viewport.
    /// Rendering may intentionally overflow a Paragraph and be clipped by
    /// ratatui, but invisible rows must never remain mouse-active in the
    /// header/footer or outside the terminal.
    pub(crate) fn clip_interactions(&mut self, bounds: Rect) {
        self.content_area = Some(bounds);
        self.buttons = self
            .buttons
            .drain(..)
            .filter_map(|(rect, slot)| intersect_rect(rect, bounds).map(|rect| (rect, slot)))
            .collect();

        if let Some(area) = self.list_area {
            let clipped = intersect_rect(area, bounds);
            if let Some(clipped) = clipped {
                let hidden_rows = clipped
                    .y
                    .saturating_sub(area.y)
                    .checked_div(self.list_row_height.max(1))
                    .unwrap_or(0) as usize;
                self.list_scroll_offset = self.list_scroll_offset.saturating_add(hidden_rows);
                self.list_area = Some(clipped);
            } else {
                self.list_area = None;
                self.list_count = 0;
            }
        }
    }
}

fn intersect_rect(a: Rect, b: Rect) -> Option<Rect> {
    let left = a.x.max(b.x);
    let top = a.y.max(b.y);
    let right = a.right().min(b.right());
    let bottom = a.bottom().min(b.bottom());
    (left < right && top < bottom).then(|| Rect::new(left, top, right - left, bottom - top))
}

pub(crate) fn point_in_rect(point: (u16, u16), rect: Rect) -> bool {
    let (x, y) = point;
    x >= rect.x && x < rect.x + rect.width && y >= rect.y && y < rect.y + rect.height
}

pub(crate) fn section_at(tabs: &[(Rect, Section)], point: (u16, u16)) -> Option<Section> {
    tabs.iter()
        .find(|(rect, _)| point_in_rect(point, *rect))
        .map(|(_, section)| *section)
}

pub(crate) fn render_header(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    app: &mut TuiApp,
    direct: bool,
) {
    let mode_label = if direct {
        "direct/recovery mode"
    } else {
        "daemon"
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme::BORDER))
        .title(Line::from(vec![
            Span::styled(
                " traffic-masq ",
                Style::default()
                    .fg(theme::ACCENT)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("[{mode_label}] "),
                Style::default().fg(theme::MUTED),
            ),
        ]));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let sections = active_sections(app.show_dhcp_client);
    let segments = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(vec![
            Constraint::Ratio(1, sections.len() as u32);
            sections.len()
        ])
        .split(inner);
    app.ui.tabs = segments
        .iter()
        .copied()
        .zip(sections.iter().copied())
        .collect();

    let active = section_of_app(app);
    for (index, section) in sections.iter().enumerate() {
        let selected = *section == active;
        let available = super::section_available(*section, direct);
        let style = if selected {
            Style::default()
                .fg(theme::SELECTED_FG)
                .bg(theme::SELECTED_BG)
                .add_modifier(Modifier::BOLD)
        } else if available {
            Style::default().fg(theme::TEXT)
        } else {
            Style::default().fg(theme::MUTED)
        };
        let full = section.title();
        let short = match section {
            Section::Dashboard => "Dash",
            Section::Interfaces => "Ifaces",
            Section::Dhcp => "DHCP-S",
            Section::DhcpClient => "DHCP-C",
            Section::Router => "Router",
            Section::Vpn => "VPN",
            Section::Wifi => "Wi-Fi",
            Section::Settings => "Settings",
            Section::Log => "Log",
        };
        let label = if segments[index].width as usize >= full.width() + 2 {
            format!(" {full} ")
        } else {
            short.to_string()
        };
        frame.render_widget(
            Paragraph::new(label)
                .style(style)
                .alignment(Alignment::Center),
            segments[index],
        );
    }
}

pub(crate) fn render_footer(frame: &mut ratatui::Frame<'_>, area: Rect, app: &TuiApp) {
    let mut spans = Vec::new();
    let help = help_pairs(app);
    let available_width = area.width.saturating_sub(2) as usize;
    let mut used = 0;
    // Keep meanings visible even when only the most relevant controls fit.
    let help = if help
        .iter()
        .map(|(k, d)| k.width() + d.width() + 3)
        .sum::<usize>()
        > available_width
    {
        let mut compact: Vec<_> = help
            .iter()
            .copied()
            .filter(|(key, _)| matches!(*key, "Enter" | "Esc" | "↑/↓"))
            .collect();
        compact.push(("F4", "all keys"));
        compact
    } else {
        help
    };
    for (key, description) in help {
        let width = key.width() + description.width() + 3;
        if used + width > available_width {
            break;
        }
        if used > 0 {
            spans.push(Span::raw("  "));
        }
        spans.push(Span::styled(
            key,
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(
            format!(":{description}"),
            Style::default().fg(theme::TEXT),
        ));
        used += width;
    }

    let message_line = if let Some(text) = app.message.as_deref() {
        let color = app
            .logs
            .back()
            .map(|entry| entry.level.color())
            .unwrap_or(theme::WARN);
        Line::styled(text, Style::default().fg(color))
    } else if let Some(text) = app.dashboard.error.as_deref() {
        Line::styled(text, Style::default().fg(theme::WARN))
    } else {
        Line::styled("Ready", Style::default().fg(theme::GOOD))
    };

    frame.render_widget(
        Paragraph::new(vec![Line::from(spans), message_line])
            .block(panel("F1:msg F4:help F2/3:tabs Tab:focus ^C:quit")),
        area,
    );
}

pub(crate) fn help_pairs(app: &TuiApp) -> Vec<(&'static str, &'static str)> {
    if app.screen == Screen::PendingChange {
        if let Some(change) = &app.pending {
            if !change.can_rollback() {
                return vec![("Esc", "back")];
            }
            if !change.can_commit() {
                return vec![("Esc", "retry rollback")];
            }
        }
    }
    if app.screen == Screen::RouterPending
        && app
            .router_pending
            .as_ref()
            .is_some_and(|view| view.commit_indeterminate())
    {
        return vec![("↑/↓", "details"), ("PgUp/Dn", "page"), ("Esc", "back")];
    }
    if app.screen == Screen::Router && app.router.topology.open {
        vec![("Arrows", "scroll"), ("PgUp/Dn", "page"), ("Esc/t", "back")]
    } else if app.screen == Screen::Router && app.router.pane == super::router::RouterPane::Sharing
    {
        vec![
            ("↑/↓", "connection"),
            ("Tab", "focus"),
            ("Enter", "activate"),
            ("Esc", "back"),
        ]
    } else if app.screen == Screen::Vpn && app.vpn.focus != super::vpn::VpnFocus::List
        || app.screen == Screen::Log && app.logs_focus != super::logs::LogFocus::Scroll
        || app.screen == Screen::Wifi && app.wifi.actions_open
    {
        vec![("Arrows", "action"), ("Enter", "activate"), ("Esc", "list")]
    } else if app.screen == Screen::Settings
        && app
            .settings
            .as_ref()
            .is_some_and(|editor| editor.is_editing())
    {
        vec![
            ("←/→", "cursor"),
            ("Tab/S-Tab", "field"),
            ("Enter/Esc", "finish"),
        ]
    } else if app.screen == Screen::RouterPending
        && app
            .router_pending
            .as_ref()
            .is_some_and(|view| view.recovery_required())
    {
        vec![
            ("↑/↓", "details"),
            ("PgUp/Dn", "page"),
            ("Enter", "retry rollback"),
            ("Esc", "back"),
        ]
    } else if app.screen == Screen::Router && app.router.recovery_blocks_mutations() {
        vec![
            ("r", "recovery action"),
            ("1/2/3", "router section"),
            ("↑/↓", "move"),
            ("Tab", "focus"),
            ("Enter", "activate"),
            ("Esc", "back"),
        ]
    } else {
        screen_help_pairs(app.screen)
    }
}

pub(crate) fn screen_help_pairs(screen: Screen) -> Vec<(&'static str, &'static str)> {
    match screen {
        Screen::Dashboard => vec![
            ("1/2/Tab", "view"),
            ("PgUp/Dn", "stats scroll"),
            ("↑/↓", "interface"),
            ("←/→", "section"),
            ("Enter", "open"),
            ("Esc", "quit"),
        ],
        Screen::Wifi => vec![
            ("↑/↓", "move"),
            ("←/→", "section"),
            ("Enter", "activate"),
            ("Esc", "back"),
        ],
        Screen::WifiEditor | Screen::WifiProfileEditor | Screen::WifiConnectPrompt => vec![
            ("↑/↓", "move"),
            ("Enter", "activate"),
            ("type", "edit value"),
            ("Esc", "back"),
        ],
        Screen::WifiScan => vec![
            ("↑/↓", "network"),
            ("Enter", "create profile"),
            ("Esc", "back"),
        ],
        Screen::WifiProfiles | Screen::WifiApProfiles => {
            vec![("↑/↓", "move"), ("Enter", "select"), ("Esc", "back")]
        }
        Screen::InterfaceList | Screen::DhcpInterfaceList | Screen::Vpn => vec![
            ("↑/↓", "move"),
            ("←/→", "section"),
            ("Enter", "select"),
            ("Esc", "back"),
        ],
        Screen::DhcpClient => vec![
            ("↑/↓", "interface"),
            ("c/r/x/d", "action"),
            ("←/→", "section"),
            ("Esc", "back"),
        ],
        Screen::Router => vec![
            ("1/2/3", "router section"),
            ("n", "share via route"),
            ("↑/↓", "move"),
            ("t", "topology"),
            ("Tab", "focus"),
            ("Enter", "activate"),
            ("Del", "delete"),
            ("Esc", "back"),
        ],
        Screen::Access
        | Screen::InterfaceEditor
        | Screen::DhcpEditor
        | Screen::RouteEditor
        | Screen::VpnPolicy => vec![
            ("↑/↓", "move"),
            ("Enter", "activate"),
            ("type", "edit value"),
            ("Esc", "back"),
        ],
        Screen::Settings => vec![
            ("↑/↓", "move"),
            ("←/→", "section"),
            ("Enter", "activate"),
            ("type", "edit value"),
            ("Esc", "back"),
        ],
        Screen::VpnImport | Screen::SettingsPassword => vec![
            ("↑/↓", "field"),
            ("type", "value"),
            ("Enter", "submit"),
            ("Esc", "cancel"),
        ],
        Screen::DhcpLeases => vec![
            ("↑/↓", "scroll"),
            ("PgUp/PgDn", "page"),
            ("Enter", "refresh"),
            ("Esc", "back"),
        ],
        Screen::Preview | Screen::RouterPlan => vec![
            ("↑/↓", "review"),
            ("PgUp/Dn", "page"),
            ("End", "end"),
            ("Enter", "apply at end"),
            ("Esc", "back"),
        ],
        Screen::Forwarding => vec![
            ("↑/↓", "field"),
            ("←/→", "choose"),
            ("Enter", "select/save"),
            ("Esc", "cancel"),
        ],
        Screen::PendingChange => vec![("Enter", "commit"), ("Esc", "rollback")],
        Screen::RouterPending => vec![
            ("↑/↓", "details"),
            ("PgUp/Dn", "page"),
            ("Enter", "commit"),
            ("Esc", "rollback"),
        ],
        Screen::Log => vec![
            ("↑/↓", "scroll"),
            ("PgUp/PgDn", "page"),
            ("←/→", "section"),
            ("Enter", "activate"),
            ("Esc", "back"),
        ],
    }
}

#[cfg(test)]
mod tests;
