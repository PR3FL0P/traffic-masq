use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};

use super::theme;
use super::{active_sections, section_of, Screen, Section, TuiApp};

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
    pub(crate) tabs: Vec<(Rect, Section)>,
    pub(crate) list_area: Option<Rect>,
    pub(crate) list_row_height: u16,
    pub(crate) list_count: usize,

    pub(crate) list_scroll_offset: usize,

    pub(crate) buttons: Vec<(Rect, usize)>,
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

    let active = section_of(app.screen);
    for (index, section) in sections.iter().enumerate() {
        let selected = *section == active;
        let style = if selected {
            Style::default()
                .fg(theme::SELECTED_FG)
                .bg(theme::SELECTED_BG)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme::TEXT)
        };
        let label = format!(" {} ", section.title());
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
    let help = if app.screen == Screen::Router && app.router.topology.open {
        vec![("Arrows", "scroll"), ("PgUp/Dn", "page"), ("Esc/t", "back")]
    } else {
        screen_help_pairs(app.screen)
    };
    for (index, (key, description)) in help.into_iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled("  ", Style::default().fg(theme::MUTED)));
        }
        spans.push(Span::styled(
            key,
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(":", Style::default().fg(theme::MUTED)));
        spans.push(Span::styled(description, Style::default().fg(theme::TEXT)));
    }
    spans.push(Span::styled(
        "   mouse enabled",
        Style::default().fg(theme::MUTED),
    ));

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
            .block(panel("Status — F1: full message")),
        area,
    );
}

fn screen_help_pairs(screen: Screen) -> Vec<(&'static str, &'static str)> {
    match screen {
        Screen::Dashboard => vec![
            ("↑/↓", "move"),
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
        Screen::WifiProfiles => vec![("↑/↓", "move"), ("Enter", "select"), ("Esc", "back")],
        Screen::InterfaceList | Screen::DhcpInterfaceList | Screen::DhcpClient | Screen::Vpn => {
            vec![
                ("↑/↓", "move"),
                ("←/→", "section"),
                ("Enter", "select"),
                ("Esc", "back"),
            ]
        }
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
        Screen::Preview | Screen::RouterPlan => vec![("Enter", "apply"), ("Esc", "back")],
        Screen::Forwarding => vec![
            ("↑/↓", "field"),
            ("←/→", "choose"),
            ("Enter", "select/save"),
            ("Esc", "cancel"),
        ],
        Screen::PendingChange | Screen::RouterPending => {
            vec![("Enter", "commit"), ("Esc", "rollback")]
        }
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
mod tests {
    use super::*;

    #[test]
    fn point_in_rect_matches_inclusive_top_left_exclusive_bottom_right() {
        let rect = Rect::new(2, 3, 4, 5);
        assert!(point_in_rect((2, 3), rect));
        assert!(point_in_rect((5, 7), rect));
        assert!(!point_in_rect((6, 3), rect));
        assert!(!point_in_rect((2, 8), rect));
        assert!(!point_in_rect((1, 3), rect));
    }

    #[test]
    fn section_at_finds_the_tab_containing_the_click_point() {
        let tabs = [
            (Rect::new(0, 0, 8, 1), Section::Dashboard),
            (Rect::new(8, 0, 8, 1), Section::Interfaces),
            (Rect::new(16, 0, 8, 1), Section::Dhcp),
            (Rect::new(24, 0, 8, 1), Section::DhcpClient),
            (Rect::new(32, 0, 8, 1), Section::Router),
            (Rect::new(40, 0, 8, 1), Section::Vpn),
            (Rect::new(48, 0, 8, 1), Section::Wifi),
            (Rect::new(56, 0, 8, 1), Section::Settings),
            (Rect::new(64, 0, 8, 1), Section::Log),
        ];
        assert_eq!(section_at(&tabs, (3, 0)), Some(Section::Dashboard));
        assert_eq!(section_at(&tabs, (11, 0)), Some(Section::Interfaces));
        assert_eq!(section_at(&tabs, (19, 0)), Some(Section::Dhcp));
        assert_eq!(section_at(&tabs, (27, 0)), Some(Section::DhcpClient));
        assert_eq!(section_at(&tabs, (35, 0)), Some(Section::Router));
        assert_eq!(section_at(&tabs, (43, 0)), Some(Section::Vpn));
        assert_eq!(section_at(&tabs, (51, 0)), Some(Section::Wifi));
        assert_eq!(section_at(&tabs, (59, 0)), Some(Section::Settings));
        assert_eq!(section_at(&tabs, (67, 0)), Some(Section::Log));
        assert_eq!(section_at(&tabs, (73, 0)), None);
    }

    #[test]
    fn section_at_works_without_dhcp_client_tab() {
        let tabs = [
            (Rect::new(0, 0, 8, 1), Section::Dashboard),
            (Rect::new(8, 0, 8, 1), Section::Interfaces),
            (Rect::new(16, 0, 8, 1), Section::Dhcp),
            (Rect::new(24, 0, 8, 1), Section::Router),
            (Rect::new(32, 0, 8, 1), Section::Vpn),
            (Rect::new(40, 0, 8, 1), Section::Wifi),
            (Rect::new(48, 0, 8, 1), Section::Settings),
            (Rect::new(56, 0, 8, 1), Section::Log),
        ];
        assert_eq!(section_at(&tabs, (19, 0)), Some(Section::Dhcp));
        assert_eq!(section_at(&tabs, (27, 0)), Some(Section::Router));
    }
}
