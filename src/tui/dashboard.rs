use std::collections::{HashSet, VecDeque};
use std::path::Path;
use std::time::{Duration, Instant};

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Sparkline};

use crossterm::event::KeyCode;

use crate::api::client::ApiClient;
use crate::api::model::{InterfaceStatus, RouteStatus, VpnPolicyStatusView};
use crate::config::InterfaceRole;
use crate::core::transaction::PendingNetworkChange;

use super::layout::panel;
use super::theme;
use super::{format_addresses, Screen, TuiApp};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DashboardPane {
    #[default]
    Traffic,
    Statistics,
}

pub(crate) async fn handle_dashboard_key(
    app: &mut TuiApp,
    key: KeyCode,
    _client: &ApiClient,
    _direct: bool,
) {
    if matches!(
        key,
        KeyCode::Up
            | KeyCode::Down
            | KeyCode::Home
            | KeyCode::End
            | KeyCode::Tab
            | KeyCode::BackTab
            | KeyCode::Char('1' | '2')
    ) {
        app.dashboard.statistics_scroll = 0;
    }
    match key {
        KeyCode::PageDown if app.dashboard_pane == DashboardPane::Statistics => {
            app.dashboard.statistics_scroll = app
                .dashboard
                .statistics_scroll
                .saturating_add(5)
                .min(app.dashboard.statistics_max_scroll);
        }
        KeyCode::PageUp if app.dashboard_pane == DashboardPane::Statistics => {
            app.dashboard.statistics_scroll = app.dashboard.statistics_scroll.saturating_sub(5);
        }
        KeyCode::Char('1') => app.dashboard_pane = DashboardPane::Traffic,
        KeyCode::Char('2') => {
            app.dashboard_pane = DashboardPane::Statistics;
            app.dashboard_statistics_index = app.selected_interface + 1;
        }
        KeyCode::Tab | KeyCode::BackTab => {
            app.dashboard_pane = match app.dashboard_pane {
                DashboardPane::Traffic => {
                    app.dashboard_statistics_index = app.selected_interface + 1;
                    DashboardPane::Statistics
                }
                DashboardPane::Statistics => DashboardPane::Traffic,
            };
        }
        KeyCode::Esc => app.should_quit = true,
        KeyCode::Up => match app.dashboard_pane {
            DashboardPane::Traffic => {
                app.selected_interface = app.selected_interface.saturating_sub(1)
            }
            DashboardPane::Statistics => {
                app.dashboard_statistics_index = app.dashboard_statistics_index.saturating_sub(1)
            }
        },
        KeyCode::Down => match app.dashboard_pane {
            DashboardPane::Traffic => {
                app.selected_interface = (app.selected_interface + 1)
                    .min(app.dashboard.interfaces.len().saturating_sub(1));
            }
            DashboardPane::Statistics => {
                app.dashboard_statistics_index =
                    (app.dashboard_statistics_index + 1).min(app.dashboard.interfaces.len());
            }
        },
        KeyCode::Home => match app.dashboard_pane {
            DashboardPane::Traffic => app.selected_interface = 0,
            DashboardPane::Statistics => app.dashboard_statistics_index = 0,
        },
        KeyCode::End => match app.dashboard_pane {
            DashboardPane::Traffic => {
                app.selected_interface = app.dashboard.interfaces.len().saturating_sub(1)
            }
            DashboardPane::Statistics => {
                app.dashboard_statistics_index = app.dashboard.interfaces.len()
            }
        },
        KeyCode::Enter => {
            if app.dashboard_pane == DashboardPane::Statistics && app.dashboard_statistics_index > 0
            {
                app.selected_interface = app.dashboard_statistics_index - 1;
            }
            app.screen = Screen::InterfaceList;
        }
        _ => {}
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TrafficSample {
    rx_bytes: u64,
    tx_bytes: u64,
    at: Instant,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct InterfaceKernelCounters {
    rx_packets: u64,
    tx_packets: u64,
    rx_errors: u64,
    tx_errors: u64,
    rx_dropped: u64,
    tx_dropped: u64,
}

impl InterfaceKernelCounters {
    fn saturating_sub(self, baseline: Self) -> Self {
        Self {
            rx_packets: self.rx_packets.saturating_sub(baseline.rx_packets),
            tx_packets: self.tx_packets.saturating_sub(baseline.tx_packets),
            rx_errors: self.rx_errors.saturating_sub(baseline.rx_errors),
            tx_errors: self.tx_errors.saturating_sub(baseline.tx_errors),
            rx_dropped: self.rx_dropped.saturating_sub(baseline.rx_dropped),
            tx_dropped: self.tx_dropped.saturating_sub(baseline.tx_dropped),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ConnectionStats {
    active: Option<u64>,
    limit: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct TrafficHistory {
    first: Option<TrafficSample>,
    last: Option<TrafficSample>,
    rx_rate_history: VecDeque<u64>,
    tx_rate_history: VecDeque<u64>,
    sample_times: VecDeque<Instant>,
    pub(crate) current_rx_rate: u64,
    pub(crate) current_tx_rate: u64,
    peak_rx_rate: u64,
    peak_tx_rate: u64,
    first_kernel: Option<InterfaceKernelCounters>,
    current_kernel: Option<InterfaceKernelCounters>,
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

    #[cfg(test)]
    fn record(&mut self, rx_bytes: u64, tx_bytes: u64, now: Instant) {
        self.record_with_counters(rx_bytes, tx_bytes, None, now);
    }

    fn record_with_counters(
        &mut self,
        rx_bytes: u64,
        tx_bytes: u64,
        counters: Option<InterfaceKernelCounters>,
        now: Instant,
    ) {
        if self.first.is_none() {
            let sample = TrafficSample {
                rx_bytes,
                tx_bytes,
                at: now,
            };
            self.first = Some(sample.clone());
            self.last = Some(sample);
            self.first_kernel = counters;
            self.current_kernel = counters;
            return;
        }

        if self.first_kernel.is_none() && counters.is_some() {
            self.first_kernel = counters;
        }
        self.current_kernel = counters;
        let Some(last) = self.last.clone() else {
            return;
        };
        let elapsed = now.saturating_duration_since(last.at);
        if elapsed < TRAFFIC_MIN_SAMPLE_INTERVAL {
            return;
        }

        let seconds = elapsed.as_secs_f64();
        self.current_rx_rate = (rx_bytes.saturating_sub(last.rx_bytes) as f64 / seconds) as u64;
        self.current_tx_rate = (tx_bytes.saturating_sub(last.tx_bytes) as f64 / seconds) as u64;
        self.peak_rx_rate = self.peak_rx_rate.max(self.current_rx_rate);
        self.peak_tx_rate = self.peak_tx_rate.max(self.current_tx_rate);
        push_capped(&mut self.rx_rate_history, self.current_rx_rate);
        push_capped(&mut self.tx_rate_history, self.current_tx_rate);
        self.sample_times.push_back(now);
        if self.sample_times.len() > TRAFFIC_HISTORY_LEN {
            self.sample_times.pop_front();
        }
        self.last = Some(TrafficSample {
            rx_bytes,
            tx_bytes,
            at: now,
        });
    }

    fn observed_for(&self, now: Instant) -> Duration {
        self.first
            .as_ref()
            .map(|sample| now.saturating_duration_since(sample.at))
            .unwrap_or_default()
    }

    fn bytes_since_start(&self, current_rx: u64, current_tx: u64) -> (u64, u64) {
        self.first
            .as_ref()
            .map(|first| {
                (
                    current_rx.saturating_sub(first.rx_bytes),
                    current_tx.saturating_sub(first.tx_bytes),
                )
            })
            .unwrap_or_default()
    }

    fn average_rates(&self, current_rx: u64, current_tx: u64, now: Instant) -> (u64, u64) {
        let elapsed = self.observed_for(now).as_secs_f64();
        if elapsed <= 0.0 {
            return (0, 0);
        }
        let (rx, tx) = self.bytes_since_start(current_rx, current_tx);
        ((rx as f64 / elapsed) as u64, (tx as f64 / elapsed) as u64)
    }

    fn kernel_since_start(&self) -> Option<InterfaceKernelCounters> {
        Some(self.current_kernel?.saturating_sub(self.first_kernel?))
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
    pub(crate) roles: std::collections::HashMap<String, InterfaceRole>,
    pub(crate) routes: Option<Vec<RouteStatus>>,
    pub(crate) vpn_status: Option<VpnPolicyStatusView>,
    pub(crate) interfaces_updated: Option<Instant>,
    pub(crate) last_success: Option<Instant>,
    pub(crate) pending_known: bool,
    pub(crate) statistics_scroll: u16,
    pub(crate) statistics_max_scroll: u16,
    pub(crate) vpn_enabled: Option<bool>,
    pub(crate) pending_network_changes: Vec<PendingNetworkChange>,
    pub(crate) error: Option<String>,
    pub(crate) pane_tabs: Vec<(Rect, DashboardPane)>,
    pub(crate) connections: ConnectionStats,
}

pub(crate) fn accept_update(app: &mut TuiApp, mut updated: DashboardData) {
    let selected = app
        .dashboard
        .interfaces
        .get(app.selected_interface)
        .map(|s| s.interface.name.clone());
    updated.statistics_scroll = app.dashboard.statistics_scroll;
    updated.statistics_max_scroll = app.dashboard.statistics_max_scroll;
    if updated.error.is_some() {
        updated.last_success = app.dashboard.last_success;
    }
    if updated.interfaces_updated.is_none() {
        updated.interfaces = std::mem::take(&mut app.dashboard.interfaces);
    }
    // A dashboard refresh is assembled from several independent API calls. A
    // failed per-interface/configuration call must not turn a previously known
    // managed interface into an apparently external one for a single frame.
    // Keep the last known value only where this refresh has no answer; an
    // explicit `false` from the daemon still replaces `true` immediately.
    let present = updated
        .interfaces
        .iter()
        .map(|status| status.interface.name.as_str())
        .collect::<HashSet<_>>();
    for (name, managed) in &app.dashboard.managed {
        if present.contains(name.as_str()) {
            updated.managed.entry(name.clone()).or_insert(*managed);
        }
    }
    for (name, role) in &app.dashboard.roles {
        if present.contains(name.as_str()) {
            updated.roles.entry(name.clone()).or_insert(*role);
        }
    }
    if updated.routes.is_none() {
        updated.routes = app.dashboard.routes.clone();
    }
    if updated.vpn_enabled.is_none() {
        updated.vpn_enabled = app.dashboard.vpn_enabled;
    }
    if updated.vpn_status.is_none() && updated.vpn_enabled == Some(true) {
        updated.vpn_status = app.dashboard.vpn_status.clone();
    }
    if !updated.pending_known && app.dashboard.pending_known {
        updated.pending_network_changes = app.dashboard.pending_network_changes.clone();
        updated.pending_known = true;
    }
    app.selected_interface = selected
        .as_ref()
        .and_then(|name| {
            updated
                .interfaces
                .iter()
                .position(|s| &s.interface.name == name)
        })
        .or_else(|| {
            updated
                .interfaces
                .iter()
                .position(|s| updated.roles.get(&s.interface.name) == Some(&InterfaceRole::Input))
        })
        .or_else(|| updated.interfaces.iter().position(|s| s.has_default_route))
        .unwrap_or(0);
    app.dashboard = updated;
}

pub(crate) fn record_traffic_samples(app: &mut TuiApp) {
    if app.dashboard.interfaces_updated.is_none() {
        return;
    }
    let now = Instant::now();
    let present: HashSet<u32> = app
        .dashboard
        .interfaces
        .iter()
        .map(|status| status.interface.index)
        .collect();
    app.traffic.retain(|index, _| present.contains(index));

    for status in &app.dashboard.interfaces {
        let counters = read_interface_counters(&status.interface.name);
        app.traffic
            .entry(status.interface.index)
            .or_default()
            .record_with_counters(
                status.interface.rx_bytes,
                status.interface.tx_bytes,
                counters,
                now,
            );
    }
    app.dashboard.connections = read_connection_stats();
}

pub(crate) fn render_dashboard(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    app: &mut TuiApp,
    direct: bool,
) {
    let sections = Layout::vertical([
        Constraint::Length(5),
        Constraint::Length(1),
        Constraint::Min(0),
    ])
    .split(area);
    render_dashboard_summary(frame, sections[0], app, direct);
    app.dashboard.pane_tabs.clear();
    let mut x = sections[1].x;
    for (label, pane) in [
        ("[1 Interfaces stat]", DashboardPane::Traffic),
        ("[2 Statistics]", DashboardPane::Statistics),
    ] {
        let rect = Rect::new(x, sections[1].y, label.len() as u16, 1);
        app.dashboard.pane_tabs.push((rect, pane));
        frame.render_widget(
            Paragraph::new(label).style(if app.dashboard_pane == pane {
                Style::default()
                    .fg(theme::SELECTED_FG)
                    .bg(theme::SELECTED_BG)
            } else {
                Style::default().fg(theme::MUTED)
            }),
            rect,
        );
        x += rect.width + 1;
    }

    match app.dashboard_pane {
        DashboardPane::Traffic => render_dashboard_traffic(frame, sections[2], app),
        DashboardPane::Statistics => render_numeric_statistics(frame, sections[2], app),
    }
}

fn render_numeric_statistics(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    app.ui.list_area = None;
    app.ui.list_count = 0;
    app.ui.list_scroll_offset = 0;
    if app.dashboard_statistics_index == 0 {
        render_global_statistics(frame, area, app);
        return;
    }

    let interface_index = app.dashboard_statistics_index.saturating_sub(1);
    let Some(status) = app.dashboard.interfaces.get(interface_index) else {
        frame.render_widget(
            Paragraph::new("No interfaces detected").block(panel("Statistics")),
            area,
        );
        return;
    };

    let name = &status.interface.name;
    let history = app.traffic.get(&status.interface.index);
    let now = Instant::now();
    let (session_rx, session_tx) = history
        .map(|history| {
            history.bytes_since_start(status.interface.rx_bytes, status.interface.tx_bytes)
        })
        .unwrap_or_default();
    let (avg_rx, avg_tx) = history
        .map(|history| {
            history.average_rates(status.interface.rx_bytes, status.interface.tx_bytes, now)
        })
        .unwrap_or_default();
    let (current_rx, current_tx, peak_rx, peak_tx, observed) = history
        .map(|history| {
            (
                history.current_rx_rate,
                history.current_tx_rate,
                history.peak_rx_rate,
                history.peak_tx_rate,
                history.observed_for(now),
            )
        })
        .unwrap_or_default();

    let managed = app
        .dashboard
        .managed
        .get(name)
        .map(|managed| if *managed { "yes" } else { "no" })
        .unwrap_or("n/a");
    let link = if status.interface.is_up { "up" } else { "down" };
    let default_route = if status.has_default_route {
        "yes"
    } else {
        "no"
    };
    let addresses = if status.ipv4_addresses.is_empty() {
        "none".to_string()
    } else {
        status
            .ipv4_addresses
            .iter()
            .map(|address| format!("{}/{}", address.address, address.prefix_len))
            .collect::<Vec<_>>()
            .join(", ")
    };

    let mut lines = vec![
        stat_line(
            "Observed",
            format_duration(observed),
            format!("link {link}  managed {managed}  default route {default_route}"),
        ),
        stat_line("IPv4", addresses, String::new()),
        stat_line(
            "Traffic since start",
            format!(
                "RX {}  TX {}",
                format_bytes(session_rx),
                format_bytes(session_tx)
            ),
            format!(
                "total {}",
                format_bytes(session_rx.saturating_add(session_tx))
            ),
        ),
        stat_line(
            "Current rate",
            format!(
                "RX {}  TX {}",
                format_rate(current_rx),
                format_rate(current_tx)
            ),
            String::new(),
        ),
        stat_line(
            "Average rate",
            format!("RX {}  TX {}", format_rate(avg_rx), format_rate(avg_tx)),
            String::new(),
        ),
        stat_line(
            "Peak rate",
            format!("RX {}  TX {}", format_rate(peak_rx), format_rate(peak_tx)),
            String::new(),
        ),
    ];

    if let Some(counters) = history.and_then(TrafficHistory::kernel_since_start) {
        lines.extend([
            stat_line(
                "Packets since start",
                format!(
                    "RX {}  TX {}",
                    format_count(counters.rx_packets),
                    format_count(counters.tx_packets)
                ),
                String::new(),
            ),
            stat_line(
                "Errors since start",
                format!(
                    "RX {}  TX {}",
                    format_count(counters.rx_errors),
                    format_count(counters.tx_errors)
                ),
                format!(
                    "total {}",
                    format_count(counters.rx_errors.saturating_add(counters.tx_errors))
                ),
            ),
            stat_line(
                "Drops since start",
                format!(
                    "RX {}  TX {}",
                    format_count(counters.rx_dropped),
                    format_count(counters.tx_dropped)
                ),
                String::new(),
            ),
        ]);
    } else {
        lines.extend([
            stat_line("Packets since start", "n/a".to_string(), String::new()),
            stat_line("Errors since start", "n/a".to_string(), String::new()),
            stat_line("Drops since start", "n/a".to_string(), String::new()),
        ]);
    }

    lines.push(stat_line(
        "Connections",
        format_connection_stats(app.dashboard.connections),
        "conntrack, system-wide".to_string(),
    ));
    lines.push(stat_line(
        "Kernel traffic total",
        format!(
            "RX {}  TX {}",
            format_bytes(status.interface.rx_bytes),
            format_bytes(status.interface.tx_bytes)
        ),
        "since interface creation/reset".to_string(),
    ));

    render_statistics_lines(
        frame,
        area,
        &format!("Statistics: {name}"),
        lines,
        &mut app.dashboard,
    );
}

fn render_global_statistics(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let now = Instant::now();
    let mut observed = Duration::ZERO;
    let mut session_rx = 0u64;
    let mut session_tx = 0u64;
    let mut current_rx = 0u64;
    let mut current_tx = 0u64;
    let mut average_rx = 0u64;
    let mut average_tx = 0u64;
    let mut kernel = InterfaceKernelCounters::default();
    let mut have_kernel = false;

    let mut up = 0usize;
    let mut managed = 0usize;
    let mut kernel_rx = 0u64;
    let mut kernel_tx = 0u64;
    for status in &app.dashboard.interfaces {
        if status.interface.is_up {
            up += 1;
        }
        if app
            .dashboard
            .managed
            .get(&status.interface.name)
            .copied()
            .unwrap_or(false)
        {
            managed += 1;
        }
        kernel_rx = kernel_rx.saturating_add(status.interface.rx_bytes);
        kernel_tx = kernel_tx.saturating_add(status.interface.tx_bytes);

        let Some(history) = app.traffic.get(&status.interface.index) else {
            continue;
        };
        observed = observed.max(history.observed_for(now));
        let (rx, tx) =
            history.bytes_since_start(status.interface.rx_bytes, status.interface.tx_bytes);
        session_rx = session_rx.saturating_add(rx);
        session_tx = session_tx.saturating_add(tx);
        current_rx = current_rx.saturating_add(history.current_rx_rate);
        current_tx = current_tx.saturating_add(history.current_tx_rate);
        let (rx, tx) =
            history.average_rates(status.interface.rx_bytes, status.interface.tx_bytes, now);
        average_rx = average_rx.saturating_add(rx);
        average_tx = average_tx.saturating_add(tx);
        if let Some(counters) = history.kernel_since_start() {
            have_kernel = true;
            kernel.rx_packets = kernel.rx_packets.saturating_add(counters.rx_packets);
            kernel.tx_packets = kernel.tx_packets.saturating_add(counters.tx_packets);
            kernel.rx_errors = kernel.rx_errors.saturating_add(counters.rx_errors);
            kernel.tx_errors = kernel.tx_errors.saturating_add(counters.tx_errors);
            kernel.rx_dropped = kernel.rx_dropped.saturating_add(counters.rx_dropped);
            kernel.tx_dropped = kernel.tx_dropped.saturating_add(counters.tx_dropped);
        }
    }

    let total = app.dashboard.interfaces.len();
    let mut lines = vec![
        stat_line(
            "Observed",
            format_duration(observed),
            format!("{up}/{total} links up  {managed}/{total} managed"),
        ),
        stat_line(
            "Traffic since start",
            format!(
                "RX {}  TX {}",
                format_bytes(session_rx),
                format_bytes(session_tx)
            ),
            format!(
                "total {}",
                format_bytes(session_rx.saturating_add(session_tx))
            ),
        ),
        stat_line(
            "Current rate",
            format!(
                "RX {}  TX {}",
                format_rate(current_rx),
                format_rate(current_tx)
            ),
            "all interfaces".to_string(),
        ),
        stat_line(
            "Average rate",
            format!(
                "RX {}  TX {}",
                format_rate(average_rx),
                format_rate(average_tx)
            ),
            "all interfaces".to_string(),
        ),
    ];

    if have_kernel {
        lines.extend([
            stat_line(
                "Packets since start",
                format!(
                    "RX {}  TX {}",
                    format_count(kernel.rx_packets),
                    format_count(kernel.tx_packets)
                ),
                "all interfaces".to_string(),
            ),
            stat_line(
                "Errors since start",
                format!(
                    "RX {}  TX {}",
                    format_count(kernel.rx_errors),
                    format_count(kernel.tx_errors)
                ),
                format!(
                    "total {}",
                    format_count(kernel.rx_errors.saturating_add(kernel.tx_errors))
                ),
            ),
            stat_line(
                "Drops since start",
                format!(
                    "RX {}  TX {}",
                    format_count(kernel.rx_dropped),
                    format_count(kernel.tx_dropped)
                ),
                "all interfaces".to_string(),
            ),
        ]);
    }

    lines.push(stat_line(
        "Connections",
        format_connection_stats(app.dashboard.connections),
        "conntrack, system-wide".to_string(),
    ));
    lines.push(stat_line(
        "Kernel traffic total",
        format!(
            "RX {}  TX {}",
            format_bytes(kernel_rx),
            format_bytes(kernel_tx)
        ),
        "all interfaces".to_string(),
    ));

    lines.insert(
        0,
        Line::styled(
            "Sum of interface counters; forwarded traffic is counted more than once.",
            Style::default().fg(theme::WARN),
        ),
    );
    render_statistics_lines(
        frame,
        area,
        "Statistics: all interfaces",
        lines,
        &mut app.dashboard,
    );
}

fn render_statistics_lines(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    title: &str,
    lines: Vec<Line<'static>>,
    data: &mut DashboardData,
) {
    let block = panel(&format!("{title} | ↑/↓ select; PgUp/Dn scroll"));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let mut wrapped = Vec::new();
    for line in lines {
        use unicode_segmentation::UnicodeSegmentation;
        use unicode_width::UnicodeWidthStr;
        let mut row = Vec::new();
        let mut width = 0;
        for span in line.spans {
            for grapheme in span.content.graphemes(true) {
                let size = grapheme.width();
                if width + size > inner.width as usize && !row.is_empty() {
                    wrapped.push(Line::from(std::mem::take(&mut row)));
                    width = 0;
                }
                row.push(Span::styled(grapheme.to_owned(), span.style));
                width += size;
            }
        }
        wrapped.push(Line::from(row));
    }
    data.statistics_max_scroll = wrapped
        .len()
        .saturating_sub(inner.height as usize)
        .min(u16::MAX as usize) as u16;
    data.statistics_scroll = data.statistics_scroll.min(data.statistics_max_scroll);
    frame.render_widget(
        Paragraph::new(wrapped).scroll((data.statistics_scroll, 0)),
        inner,
    );
}

fn stat_line(label: &'static str, value: String, note: String) -> Line<'static> {
    let mut spans = vec![
        Span::styled(format!("{label:<21}"), Style::default().fg(theme::MUTED)),
        Span::styled(value, Style::default().fg(theme::TEXT)),
    ];
    if !note.is_empty() {
        spans.push(Span::styled(
            format!("   {note}"),
            Style::default().fg(theme::MUTED),
        ));
    }
    Line::from(spans)
}

fn format_connection_stats(stats: ConnectionStats) -> String {
    match (stats.active, stats.limit) {
        (Some(active), Some(limit)) => {
            format!(
                "{} active / {} limit",
                format_count(active),
                format_count(limit)
            )
        }
        (Some(active), None) => format!("{} active", format_count(active)),
        _ => "n/a".to_string(),
    }
}

fn format_duration(duration: Duration) -> String {
    let total = duration.as_secs();
    let days = total / 86_400;
    let hours = (total % 86_400) / 3_600;
    let minutes = (total % 3_600) / 60;
    let seconds = total % 60;
    if days > 0 {
        format!("{days}d {hours:02}:{minutes:02}:{seconds:02}")
    } else {
        format!("{hours:02}:{minutes:02}:{seconds:02}")
    }
}

fn format_count(value: u64) -> String {
    let digits = value.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(ch);
    }
    grouped
}

fn read_connection_stats() -> ConnectionStats {
    ConnectionStats {
        active: read_u64("/proc/sys/net/netfilter/nf_conntrack_count"),
        limit: read_u64("/proc/sys/net/netfilter/nf_conntrack_max"),
    }
}

fn read_interface_counters(interface: &str) -> Option<InterfaceKernelCounters> {
    let root = Path::new("/sys/class/net")
        .join(interface)
        .join("statistics");
    Some(InterfaceKernelCounters {
        rx_packets: read_u64(root.join("rx_packets"))?,
        tx_packets: read_u64(root.join("tx_packets"))?,
        rx_errors: read_u64(root.join("rx_errors"))?,
        tx_errors: read_u64(root.join("tx_errors"))?,
        rx_dropped: read_u64(root.join("rx_dropped"))?,
        tx_dropped: read_u64(root.join("tx_dropped"))?,
    })
}

fn read_u64(path: impl AsRef<Path>) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn format_bytes(bytes: u64) -> String {
    format_rate(bytes).trim_end_matches("/s").to_owned()
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
    let pending_count = app.dashboard.pending_network_changes.len();
    let iface_count = app.dashboard.interfaces.len();
    let (vpn_text, vpn_color) = match app.dashboard.vpn_enabled {
        Some(true) => ("ON".to_string(), theme::GOOD),
        Some(false) => ("OFF".to_string(), theme::MUTED),
        None if direct => ("n/a".to_string(), theme::MUTED),
        None => ("?".to_string(), theme::WARN),
    };

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
        card(pending_count.to_string(), "pending", pending_color),
        cards[2],
    );
    frame.render_widget(card(vpn_text, "vpn", vpn_color), cards[3]);
}

pub(crate) fn render_dashboard_traffic(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    app: &mut TuiApp,
) {
    if app.dashboard.interfaces.is_empty() {
        let block = panel("Interfaces stat");
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
            "Interfaces stat ({}-{} of {total}, ↑/↓ to scroll)",
            offset + 1,
            offset + visible
        )
    } else {
        "Interfaces stat | [ext] external, [?] ownership unknown".to_string()
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
        let managed = app.dashboard.managed.get(&status.interface.name).copied();
        render_traffic_row(
            frame,
            rows[row],
            status,
            history,
            managed,
            index == selected_interface,
        );
    }
}

fn render_traffic_row(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    status: &InterfaceStatus,
    history: Option<&TrafficHistory>,
    managed: Option<bool>,
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
            match managed {
                Some(true) => "traffic-masq:on",
                Some(false) => "traffic-masq:off",
                None => "traffic-masq:?",
            },
            Style::default().fg(if managed == Some(true) {
                theme::GOOD
            } else {
                theme::WARN
            }),
        ),
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

    let rx_slice = history.map(TrafficHistory::rx_rates).unwrap_or(&[]);
    let tx_slice = history.map(TrafficHistory::tx_rates).unwrap_or(&[]);
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
mod tests;
