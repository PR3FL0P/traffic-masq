use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Sparkline};

use crossterm::event::KeyCode;

use crate::api::client::ApiClient;
use crate::api::model::InterfaceStatus;
use crate::core::transaction::PendingNetworkChange;

use super::layout::panel;
use super::logs::LogLevel;
use super::theme;
use super::{format_addresses, Screen, TuiApp};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DashboardFocus {
    #[default]
    List,
    Interfaces,
    PendingChanges,
}

pub(crate) const DASHBOARD_ACTIONS: [DashboardFocus; 2] =
    [DashboardFocus::Interfaces, DashboardFocus::PendingChanges];

pub(crate) const DASHBOARD_ACTION_LABELS: [&str; 2] = ["Interfaces", "Pending network changes"];

fn next_dashboard_action(focus: DashboardFocus) -> DashboardFocus {
    super::input::move_clamped(&DASHBOARD_ACTIONS, focus, true)
}

fn previous_dashboard_action(focus: DashboardFocus) -> DashboardFocus {
    super::input::move_clamped(&DASHBOARD_ACTIONS, focus, false)
}

pub(crate) fn focus_action(app: &mut TuiApp, slot: usize) {
    if let Some(focus) = DASHBOARD_ACTIONS.get(slot) {
        app.dashboard_focus = *focus;
    }
}

pub(crate) async fn handle_dashboard_key(
    app: &mut TuiApp,
    key: KeyCode,
    _client: &ApiClient,
    direct: bool,
) {
    let key = match key {
        KeyCode::Left if app.dashboard_focus != DashboardFocus::List => KeyCode::Up,
        KeyCode::Right if app.dashboard_focus != DashboardFocus::List => KeyCode::Down,
        _ => key,
    };
    match key {
        KeyCode::Tab | KeyCode::BackTab => {
            let fields = [
                DashboardFocus::List,
                DashboardFocus::Interfaces,
                DashboardFocus::PendingChanges,
            ];
            app.dashboard_focus =
                super::input::move_wrapped(&fields, app.dashboard_focus, key == KeyCode::Tab);
        }
        KeyCode::Esc if app.dashboard_focus != DashboardFocus::List => {
            app.dashboard_focus = DashboardFocus::List;
        }
        KeyCode::Esc => app.should_quit = true,
        KeyCode::Up => match app.dashboard_focus {
            DashboardFocus::List => {
                app.selected_interface = app.selected_interface.saturating_sub(1);
            }
            DashboardFocus::Interfaces => {
                app.dashboard_focus = DashboardFocus::List;
                app.selected_interface = app.dashboard.interfaces.len().saturating_sub(1);
            }
            focus => app.dashboard_focus = previous_dashboard_action(focus),
        },
        KeyCode::Down => match app.dashboard_focus {
            DashboardFocus::List if app.selected_interface + 1 < app.dashboard.interfaces.len() => {
                app.selected_interface += 1;
            }
            DashboardFocus::List => app.dashboard_focus = DashboardFocus::Interfaces,
            focus => app.dashboard_focus = next_dashboard_action(focus),
        },
        KeyCode::Home => app.selected_interface = 0,
        KeyCode::End => {
            app.selected_interface = app.dashboard.interfaces.len().saturating_sub(1);
        }
        KeyCode::Enter => match app.dashboard_focus {
            DashboardFocus::List | DashboardFocus::Interfaces => {
                app.screen = Screen::InterfaceList;
            }
            DashboardFocus::PendingChanges => {
                if direct {
                    app.push_message(
                        LogLevel::Warn,
                        "Network transactions require the daemon API; unavailable in direct/offline mode",
                    );
                } else if let Some(change) = app.dashboard.pending_network_changes.first().cloned()
                {
                    app.pending = Some(change);
                    app.pending_return_screen = Screen::Dashboard;
                    app.screen = Screen::PendingChange;
                } else {
                    app.push_message(LogLevel::Warn, "No pending network changes");
                }
            }
        },
        _ => {}
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TrafficSample {
    rx_bytes: u64,
    tx_bytes: u64,
    at: Instant,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct TrafficHistory {
    last: Option<TrafficSample>,
    rx_rate_history: VecDeque<u64>,
    tx_rate_history: VecDeque<u64>,
    pub(crate) current_rx_rate: u64,
    pub(crate) current_tx_rate: u64,
}

pub(crate) const TRAFFIC_HISTORY_LEN: usize = 96;
pub(crate) const TRAFFIC_MIN_SAMPLE_INTERVAL: Duration = Duration::from_millis(400);

impl TrafficHistory {
    pub(crate) fn rx_rates(&self) -> &[u64] {
        debug_assert!(
            self.rx_rate_history.as_slices().1.is_empty(),
            "rx_rate_history must be contiguous"
        );
        self.rx_rate_history.as_slices().0
    }

    pub(crate) fn tx_rates(&self) -> &[u64] {
        debug_assert!(
            self.tx_rate_history.as_slices().1.is_empty(),
            "tx_rate_history must be contiguous"
        );
        self.tx_rate_history.as_slices().0
    }

    pub(crate) fn record(&mut self, rx_bytes: u64, tx_bytes: u64, now: Instant) {
        let Some(last) = self.last.clone() else {
            self.last = Some(TrafficSample {
                rx_bytes,
                tx_bytes,
                at: now,
            });
            return;
        };

        let elapsed = now.saturating_duration_since(last.at);
        if elapsed < TRAFFIC_MIN_SAMPLE_INTERVAL {
            return;
        }

        let seconds = elapsed.as_secs_f64();
        self.current_rx_rate = (rx_bytes.saturating_sub(last.rx_bytes) as f64 / seconds) as u64;
        self.current_tx_rate = (tx_bytes.saturating_sub(last.tx_bytes) as f64 / seconds) as u64;
        push_capped(&mut self.rx_rate_history, self.current_rx_rate);
        push_capped(&mut self.tx_rate_history, self.current_tx_rate);
        self.last = Some(TrafficSample {
            rx_bytes,
            tx_bytes,
            at: now,
        });
    }
}

fn push_capped(queue: &mut VecDeque<u64>, value: u64) {
    queue.push_back(value);
    if queue.len() > TRAFFIC_HISTORY_LEN {
        queue.pop_front();
    }
    queue.make_contiguous();
}

pub(crate) fn format_rate(bytes_per_sec: u64) -> String {
    const UNITS: [&str; 5] = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"];
    let mut value = bytes_per_sec as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value:.0} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[derive(Debug, Default)]
pub(crate) struct DashboardData {
    pub(crate) interfaces: Vec<InterfaceStatus>,
    pub(crate) managed: std::collections::HashMap<String, bool>,
    pub(crate) dhcp_interfaces: Vec<String>,
    pub(crate) pending_network_changes: Vec<PendingNetworkChange>,
    pub(crate) error: Option<String>,
}

pub(crate) fn record_traffic_samples(app: &mut TuiApp) {
    let now = Instant::now();
    let present: HashSet<u32> = app
        .dashboard
        .interfaces
        .iter()
        .map(|status| status.interface.index)
        .collect();
    app.traffic.retain(|index, _| present.contains(index));

    for status in &app.dashboard.interfaces {
        app.traffic
            .entry(status.interface.index)
            .or_default()
            .record(status.interface.rx_bytes, status.interface.tx_bytes, now);
    }
}

pub(crate) fn render_dashboard(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    app: &mut TuiApp,
    direct: bool,
) {
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(6),
            Constraint::Length(4),
        ])
        .split(area);
    render_dashboard_summary(frame, sections[0], app, direct);
    render_dashboard_traffic(frame, sections[1], app);
    render_dashboard_actions(frame, sections[2], app);
}

fn render_dashboard_actions(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let block = panel("Actions");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines = Vec::with_capacity(DASHBOARD_ACTIONS.len());
    for (slot, (focus, label)) in DASHBOARD_ACTIONS
        .iter()
        .zip(DASHBOARD_ACTION_LABELS.iter())
        .enumerate()
    {
        let selected = app.dashboard_focus == *focus;
        let style = if selected {
            Style::default()
                .fg(theme::SELECTED_FG)
                .bg(theme::SELECTED_BG)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme::ACCENT)
        };
        let marker = if selected { "▶ " } else { "  " };
        let text = format!("{marker}{label}");
        app.ui.buttons.push((
            Rect {
                x: inner.x,
                y: inner.y + lines.len() as u16,
                width: text.len() as u16,
                height: 1,
            },
            slot,
        ));
        lines.push(Line::styled(text, style));
    }

    frame.render_widget(Paragraph::new(lines), inner);
}

pub(crate) fn render_dashboard_summary(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    app: &TuiApp,
    direct: bool,
) {
    let block = panel("Overview");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mode_text = if direct { "direct" } else { "daemon" };
    let dhcp_count = app.dashboard.dhcp_interfaces.len();
    let pending_count = app.dashboard.pending_network_changes.len();
    let iface_count = app.dashboard.interfaces.len();

    let card = |value: String, label: &'static str, color: Color| {
        Paragraph::new(vec![
            Line::styled(
                value,
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
            Line::styled(label, Style::default().fg(theme::MUTED)),
        ])
        .alignment(Alignment::Center)
    };

    let pending_color = if pending_count > 0 {
        theme::WARN
    } else {
        theme::TEXT
    };

    if inner.width < 70 {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Ratio(1, 2); 2])
            .split(inner);
        let top = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Ratio(1, 2); 2])
            .split(rows[0]);
        let bottom = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Ratio(1, 2); 2])
            .split(rows[1]);

        frame.render_widget(card(mode_text.to_string(), "mode", theme::ACCENT), top[0]);
        frame.render_widget(
            card(iface_count.to_string(), "interfaces", theme::TEXT),
            top[1],
        );
        frame.render_widget(
            card(dhcp_count.to_string(), "dhcp active", theme::GOOD),
            bottom[0],
        );
        frame.render_widget(
            card(pending_count.to_string(), "pending changes", pending_color),
            bottom[1],
        );
        return;
    }

    let cards = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(1, 4); 4])
        .split(inner);

    frame.render_widget(card(mode_text.to_string(), "mode", theme::ACCENT), cards[0]);
    frame.render_widget(
        card(iface_count.to_string(), "interfaces", theme::TEXT),
        cards[1],
    );
    frame.render_widget(
        card(dhcp_count.to_string(), "dhcp active", theme::GOOD),
        cards[2],
    );
    frame.render_widget(
        card(pending_count.to_string(), "pending changes", pending_color),
        cards[3],
    );
}

pub(crate) fn render_dashboard_traffic(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    app: &mut TuiApp,
) {
    if app.dashboard.interfaces.is_empty() {
        let block = panel("Interface traffic");
        let inner = block.inner(area);
        frame.render_widget(block, area);
        frame.render_widget(
            Paragraph::new("No interfaces detected").style(Style::default().fg(theme::MUTED)),
            inner,
        );
        app.ui.list_area = None;
        app.ui.list_count = 0;
        app.ui.list_scroll_offset = 0;
        return;
    }

    // On a short terminal, prioritize interfaces over history graphs.
    let row_height = if area.height < 14 { 1 } else { 3 };
    let total = app.dashboard.interfaces.len();

    let max_visible = ((area.height.saturating_sub(2)) / row_height).max(1) as usize;
    let visible = total.min(max_visible);

    let max_offset = total.saturating_sub(visible);
    let offset = app
        .selected_interface
        .saturating_sub(visible / 2)
        .min(max_offset);

    let title = if visible < total {
        format!(
            "Interface traffic ({}-{} of {total}, ↑/↓ to scroll)",
            offset + 1,
            offset + visible
        )
    } else {
        "Interface traffic | [ext] external, [?] ownership unknown".to_string()
    };
    let block = panel(&title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    app.ui.list_area = Some(Rect::new(
        inner.x,
        inner.y,
        inner.width,
        (visible as u16 * row_height).min(inner.height),
    ));
    app.ui.list_row_height = row_height;
    app.ui.list_count = total;
    app.ui.list_scroll_offset = offset;

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(vec![Constraint::Length(row_height); visible])
        .split(inner);

    let selected_interface = app.selected_interface;
    for (row, (index, status)) in app
        .dashboard
        .interfaces
        .iter()
        .enumerate()
        .skip(offset)
        .take(visible)
        .enumerate()
    {
        let history = app.traffic.get(&status.interface.index);
        render_traffic_row(
            frame,
            rows[row],
            status,
            history,
            index == selected_interface,
        );
    }
}

fn render_traffic_row(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    status: &InterfaceStatus,
    history: Option<&TrafficHistory>,
    selected: bool,
) {
    let marker = if selected { "▶" } else { " " };
    let name_style = if selected {
        Style::default()
            .fg(theme::ACCENT)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().add_modifier(Modifier::BOLD)
    };
    let up_span = if status.interface.is_up {
        Span::styled("● up", Style::default().fg(theme::GOOD))
    } else {
        Span::styled("● down", Style::default().fg(theme::MUTED))
    };
    let (rx_rate, tx_rate) = history
        .map(|history| (history.current_rx_rate, history.current_tx_rate))
        .unwrap_or((0, 0));

    let mut header = Line::from(vec![
        Span::styled(
            format!("{marker} {:<12}", status.interface.name),
            name_style,
        ),
        up_span,
        Span::raw("   "),
        Span::styled(
            format!("↓ {:>10}", format_rate(rx_rate)),
            Style::default().fg(theme::ACCENT),
        ),
        Span::raw("   "),
        Span::styled(
            format!("↑ {:>10}", format_rate(tx_rate)),
            Style::default().fg(theme::ACCENT_ALT),
        ),
        Span::raw("   "),
    ]);
    header.spans.extend(format_addresses(status));
    frame.render_widget(
        Paragraph::new(header),
        Rect::new(area.x, area.y, area.width, area.height.min(1)),
    );
    if area.height < 3 {
        return;
    }

    let rx_slice = history.map(|history| history.rx_rates()).unwrap_or(&[]);
    let tx_slice = history.map(|history| history.tx_rates()).unwrap_or(&[]);

    frame.render_widget(
        Sparkline::default()
            .data(rx_slice)
            .style(Style::default().fg(theme::ACCENT)),
        Rect::new(area.x, area.y + 1, area.width, 1),
    );
    frame.render_widget(
        Sparkline::default()
            .data(tx_slice)
            .style(Style::default().fg(theme::ACCENT_ALT)),
        Rect::new(area.x, area.y + 2, area.width, 1),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimum_terminal_fills_traffic_view_and_keeps_selection_visible() {
        use ratatui::{backend::TestBackend, Terminal};
        let mut app = TuiApp::default();
        app.dashboard.interfaces = (0..12)
            .map(|index| InterfaceStatus {
                interface: crate::netlink::NetworkInterface {
                    index,
                    name: format!("eth{index}"),
                    is_up: true,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    is_wireless: false,
                },
                owned_ipv4_addresses: None,
                ipv4_addresses: vec![],
                has_default_route: false,
            })
            .collect();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        for selected in [0, 5, 11] {
            app.selected_interface = selected;
            terminal
                .draw(|frame| super::super::render(frame, &mut app, false))
                .unwrap();
            let area = app.ui.list_area.unwrap();
            assert_eq!(app.ui.list_row_height, 1);
            assert!(area.height >= 6);
            let buffer = terminal.backend().buffer();
            for y in area.y..area.bottom() {
                let text: String = (area.x..area.right())
                    .map(|x| buffer[(x, y)].symbol())
                    .collect();
                assert!(text.contains("eth"), "empty interface row: {text:?}");
            }
            let selected_y = area.y + (selected - app.ui.list_scroll_offset) as u16;
            assert!(selected_y < area.bottom());
            assert_eq!(buffer[(area.x, selected_y)].symbol(), "▶");
        }
    }

    #[test]
    fn dashboard_focus_reaches_every_action_and_clamps_at_both_ends() {
        assert_eq!(
            next_dashboard_action(DashboardFocus::Interfaces),
            DashboardFocus::PendingChanges
        );
        assert_eq!(
            next_dashboard_action(DashboardFocus::PendingChanges),
            DashboardFocus::PendingChanges
        );
        assert_eq!(
            previous_dashboard_action(DashboardFocus::PendingChanges),
            DashboardFocus::Interfaces
        );
        assert_eq!(
            previous_dashboard_action(DashboardFocus::Interfaces),
            DashboardFocus::Interfaces
        );
    }

    #[test]
    fn every_dashboard_action_has_a_label() {
        assert_eq!(DASHBOARD_ACTIONS.len(), DASHBOARD_ACTION_LABELS.len());

        assert!(DASHBOARD_ACTION_LABELS
            .iter()
            .all(|label| !label.is_empty()));
    }

    #[test]
    fn clicking_an_action_row_focuses_exactly_that_row() {
        let mut app = TuiApp::default();
        focus_action(&mut app, 1);
        assert_eq!(app.dashboard_focus, DashboardFocus::PendingChanges);

        focus_action(&mut app, 99);
        assert_eq!(app.dashboard_focus, DashboardFocus::PendingChanges);
    }

    #[test]
    fn format_rate_scales_units_correctly() {
        assert_eq!(format_rate(0), "0 B/s");
        assert_eq!(format_rate(512), "512 B/s");
        assert_eq!(format_rate(1024), "1.0 KB/s");
        assert_eq!(format_rate(1024 * 1024), "1.0 MB/s");
        assert_eq!(format_rate(3 * 1024 * 1024), "3.0 MB/s");
    }

    #[test]
    fn traffic_history_ignores_samples_taken_too_close_together() {
        let mut history = TrafficHistory::default();
        let start = Instant::now();
        history.record(1_000, 500, start);

        history.record(2_000, 1_000, start);
        assert_eq!(history.current_rx_rate, 0);
        assert_eq!(history.current_tx_rate, 0);
        assert!(history.rx_rate_history.is_empty());
    }

    #[test]
    fn traffic_history_computes_rate_from_byte_delta_over_elapsed_time() {
        let mut history = TrafficHistory::default();
        let start = Instant::now();
        history.record(0, 0, start);
        let later = start + Duration::from_secs(1);
        history.record(1_000, 2_000, later);
        assert_eq!(history.current_rx_rate, 1_000);
        assert_eq!(history.current_tx_rate, 2_000);
        assert_eq!(history.rx_rate_history.len(), 1);
        assert_eq!(history.tx_rate_history.len(), 1);
    }

    #[test]
    fn traffic_history_caps_backlog_length() {
        let mut history = TrafficHistory::default();
        let start = Instant::now();
        history.record(0, 0, start);
        for tick in 1..=(TRAFFIC_HISTORY_LEN as u64 + 10) {
            let at = start + Duration::from_secs(tick);
            history.record(tick * 1_000, tick * 1_000, at);
        }
        assert_eq!(history.rx_rate_history.len(), TRAFFIC_HISTORY_LEN);
        assert_eq!(history.tx_rate_history.len(), TRAFFIC_HISTORY_LEN);
    }
}
