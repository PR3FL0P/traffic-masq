use crossterm::event::KeyCode;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::Paragraph;
use serde::{Deserialize, Serialize};

use super::layout::panel;
use super::theme;
use super::{Screen, TuiApp};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum LogLevel {
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub(crate) fn color(self) -> ratatui::style::Color {
        match self {
            LogLevel::Info => theme::GOOD,
            LogLevel::Warn => theme::WARN,
            LogLevel::Error => theme::BAD,
        }
    }

    fn label(self) -> &'static str {
        match self {
            LogLevel::Info => "INFO ",
            LogLevel::Warn => "WARN ",
            LogLevel::Error => "ERROR",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LogEntry {
    pub(crate) at_unix: u64,
    pub(crate) level: LogLevel,
    pub(crate) message: String,
}

pub(crate) const LOG_HISTORY_LEN: usize = 500;
const LOG_FILE_LIMIT: usize = 4 * 1024 * 1024;

/// Restore history without replaying old messages into the status line.
pub(super) async fn restore(app: &mut TuiApp, store: &super::session::SessionStore) {
    let store = store.clone();
    let result = tokio::task::spawn_blocking(move || {
        store.read_bounded::<std::collections::VecDeque<LogEntry>>("logs", LOG_FILE_LIMIT)
    })
    .await
    .map_err(anyhow::Error::from)
    .and_then(|result| result);
    match result {
        Ok(Some(mut entries)) => {
            while entries.len() > LOG_HISTORY_LEN {
                entries.pop_front();
            }
            app.log_view.logs = entries;
            app.log_view.logs_scroll = usize::MAX;
        }
        Ok(None) => {}
        Err(error) => app.push_message(
            LogLevel::Warn,
            format!("Could not restore client log: {error}"),
        ),
    }
}

/// Serialize writes on the blocking pool, outside cancellable UI operations.
pub(super) async fn flush(app: &mut TuiApp, store: &super::session::SessionStore) {
    if !app.log_view.logs_dirty {
        return;
    }
    let store = store.clone();
    let entries = app.log_view.logs.clone();
    let result =
        tokio::task::spawn_blocking(move || store.write_bounded("logs", &entries, LOG_FILE_LIMIT))
            .await
            .map_err(anyhow::Error::from)
            .and_then(|result| result);
    if let Err(error) = result {
        app.push_message(
            LogLevel::Warn,
            format!("Could not save client log: {error}"),
        );
    }
    // Retry on the next real message, rather than logging failures forever.
    app.log_view.logs_dirty = false;
}

pub(crate) fn with_troubleshooting_hint(level: LogLevel, message: String) -> String {
    if level == LogLevel::Info || message.contains("Hint:") {
        return message;
    }

    let lower = message.to_ascii_lowercase();
    if lower.contains("enable configure with traffic-masq") {
        return message;
    }
    let hint = if lower.contains("convergence is deferred") {
        Some("verify that the configured interface still exists; if it was renamed or removed, update or remove its traffic-masq interface configuration")
    } else if lower.contains("unmanaged") || lower.contains("managed mode") {
        Some(
            "open Interfaces and enable Configure with traffic-masq before changing the IP address",
        )
    } else if lower.contains("vpn disabled") {
        Some("open VPN and enable the VPN subsystem before activating a profile")
    } else if lower.contains("wpa_supplicant")
        && (lower.contains("missing") || lower.contains("unavailable"))
    {
        Some("install/start wpa_supplicant and retry the Wi-Fi client operation")
    } else if lower.contains("permission denied") {
        Some("check traffic-masqd privileges and the API socket/file permissions")
    } else if lower.contains("ownership conflict") {
        Some("another network manager may own this interface; stop the conflicting manager or release the interface before retrying")
    } else if lower.contains("dhcp client")
        && (lower.contains("disabled") || lower.contains("runtime is unavailable"))
    {
        Some("enable/configure the DHCP client for the uplink interface and retry")
    } else {
        None
    };

    match hint {
        Some(hint) => format!("{message} | Hint: {hint}"),
        None => message,
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LogFocus {
    #[default]
    Scroll,
    Export,
    Clear,
}

const LOG_ACTIONS: [LogFocus; 2] = [LogFocus::Export, LogFocus::Clear];
const LOG_ACTION_LABELS: [&str; 2] = ["Export log to a file", "Clear log"];

pub(crate) fn focus_action(app: &mut TuiApp, slot: usize) {
    if let Some(focus) = LOG_ACTIONS.get(slot) {
        app.log_view.logs_focus = *focus;
    }
}

fn render_log_actions(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let block = panel("Actions");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines = Vec::with_capacity(LOG_ACTIONS.len());
    for (slot, (focus, label)) in LOG_ACTIONS.iter().zip(LOG_ACTION_LABELS.iter()).enumerate() {
        let selected = app.log_view.logs_focus == *focus;
        let style = if selected {
            Style::default()
                .fg(theme::SELECTED_FG)
                .bg(theme::SELECTED_BG)
                .add_modifier(ratatui::style::Modifier::BOLD)
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

fn format_time_hms(unix_time: u64) -> String {
    let seconds_of_day = unix_time % 86_400;
    let hours = seconds_of_day / 3_600;
    let minutes = (seconds_of_day % 3_600) / 60;
    let seconds = seconds_of_day % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}Z")
}

pub(crate) fn render_log(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    if let Some(dialog) = super::confirmation::current(app) {
        dialog.render(
            frame,
            area,
            &mut app.ui,
            app.confirmation.confirmation_focus,
            app.confirmation.confirmation_scroll,
        );
        return;
    }
    let sections = ratatui::layout::Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            ratatui::layout::Constraint::Min(3),
            ratatui::layout::Constraint::Length(4),
        ])
        .split(area);
    let area = sections[0];
    render_log_actions(frame, sections[1], app);

    if app.log_view.logs.is_empty() {
        app.log_view.logs_scroll = 0;
        app.log_view.logs_max_scroll = 0;
        let block = panel("Session log | 2: daemon logs");
        let inner = block.inner(area);
        frame.render_widget(block, area);
        frame.render_widget(
            Paragraph::new("No log entries yet").style(Style::default().fg(theme::MUTED)),
            inner,
        );
        return;
    }

    // Scroll visual rows so long diagnostics and their hints remain readable.
    let width = area.width.saturating_sub(2).max(1) as usize;
    let lines: Vec<Line> = app
        .log_view
        .logs
        .iter()
        .flat_map(|entry| {
            let text = format!(
                "[{}] {}  {}",
                format_time_hms(entry.at_unix),
                entry.level.label(),
                entry.message
            );
            wrap_log_message(&text, width)
                .into_iter()
                .map(move |line| Line::styled(line, Style::default().fg(entry.level.color())))
        })
        .collect();
    let total = lines.len();
    let visible = (area.height.saturating_sub(2) as usize).max(1).min(total);
    let max_offset = total.saturating_sub(visible);

    app.log_view.logs_max_scroll = max_offset;
    app.log_view.logs_scroll = app.log_view.logs_scroll.min(max_offset);
    let offset = app.log_view.logs_scroll;

    let title = if visible < total {
        format!(
            "Session log ({}-{} of {total})",
            offset + 1,
            offset + visible
        )
    } else {
        "Session log | 2: daemon logs".to_string()
    };
    let block = panel(&title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    frame.render_widget(
        Paragraph::new(
            lines
                .into_iter()
                .skip(offset)
                .take(visible)
                .collect::<Vec<_>>(),
        ),
        inner,
    );
}

pub(super) fn wrap_log_message(message: &str, width: usize) -> Vec<String> {
    use unicode_segmentation::UnicodeSegmentation;
    use unicode_width::UnicodeWidthStr;

    let mut rows = Vec::new();
    for line in message.split('\n') {
        let mut row = String::new();
        let mut used = 0;
        for word in line.split_word_bounds() {
            if used + word.width() > width.max(1) && word.width() <= width.max(1) && !row.is_empty()
            {
                rows.push(std::mem::take(&mut row));
                used = 0;
            }
            for grapheme in word.graphemes(true) {
                let size = grapheme.width();
                if used + size > width.max(1) && !row.is_empty() {
                    rows.push(std::mem::take(&mut row));
                    used = 0;
                }
                row.push_str(grapheme);
                used += size;
            }
        }
        rows.push(row);
    }
    rows
}

pub(crate) fn handle_log_key(app: &mut TuiApp, key: KeyCode) {
    if app.log_view.logs_clear_confirmation {
        match key {
            KeyCode::Esc => app.log_view.logs_clear_confirmation = false,
            KeyCode::Enter => {
                app.log_view.logs_clear_confirmation = false;
                app.log_view.logs.clear();
                app.log_view.logs_scroll = 0;
                app.log_view.logs_max_scroll = 0;
                app.push_message(LogLevel::Info, "Log cleared");
                app.log_view.logs_scroll = 0;
            }
            _ => {}
        }
        return;
    }
    const PAGE: usize = 10;
    let max_scroll = app.log_view.logs_max_scroll;

    let key = match key {
        KeyCode::Left if app.log_view.logs_focus != LogFocus::Scroll => KeyCode::Up,
        KeyCode::Right if app.log_view.logs_focus != LogFocus::Scroll => KeyCode::Down,
        _ => key,
    };
    match key {
        KeyCode::Tab | KeyCode::BackTab => {
            let fields = [LogFocus::Scroll, LogFocus::Export, LogFocus::Clear];
            app.log_view.logs_focus =
                super::input::move_wrapped(&fields, app.log_view.logs_focus, key == KeyCode::Tab);
        }
        KeyCode::Esc if app.log_view.logs_focus != LogFocus::Scroll => {
            app.log_view.logs_focus = LogFocus::Scroll;
        }
        KeyCode::Esc => app.screen = Screen::Dashboard,
        KeyCode::Down => match app.log_view.logs_focus {
            LogFocus::Scroll if app.log_view.logs_scroll < max_scroll => {
                app.log_view.logs_scroll =
                    app.log_view.logs_scroll.saturating_add(1).min(max_scroll);
            }
            LogFocus::Scroll => app.log_view.logs_focus = LogFocus::Export,
            LogFocus::Export => app.log_view.logs_focus = LogFocus::Clear,
            LogFocus::Clear => {}
        },
        KeyCode::Up => match app.log_view.logs_focus {
            LogFocus::Scroll => {
                app.log_view.logs_scroll = app.log_view.logs_scroll.saturating_sub(1)
            }
            LogFocus::Export => app.log_view.logs_focus = LogFocus::Scroll,
            LogFocus::Clear => app.log_view.logs_focus = LogFocus::Export,
        },
        KeyCode::PageDown => {
            app.log_view.logs_focus = LogFocus::Scroll;
            app.log_view.logs_scroll = app
                .log_view
                .logs_scroll
                .saturating_add(PAGE)
                .min(max_scroll);
        }
        KeyCode::PageUp => {
            app.log_view.logs_focus = LogFocus::Scroll;
            app.log_view.logs_scroll = app.log_view.logs_scroll.saturating_sub(PAGE);
        }
        KeyCode::Home => {
            app.log_view.logs_focus = LogFocus::Scroll;
            app.log_view.logs_scroll = 0;
        }
        KeyCode::End => {
            app.log_view.logs_focus = LogFocus::Scroll;
            app.log_view.logs_scroll = max_scroll;
        }
        KeyCode::Enter => match app.log_view.logs_focus {
            LogFocus::Scroll => {}
            LogFocus::Export => export_log(app),
            LogFocus::Clear => {
                app.log_view.logs_clear_confirmation = true;
            }
        },
        _ => {}
    }
}

fn export_log(app: &mut TuiApp) {
    let contents: String = app
        .log_view
        .logs
        .iter()
        .map(|entry| {
            format!(
                "[{}] {}  {}\n",
                entry.at_unix,
                entry.level.label(),
                entry.message
            )
        })
        .collect();

    let unix_now = super::current_unix_time();
    let path = std::env::temp_dir().join(format!("traffic-masq-session-{unix_now}.log"));
    match std::fs::write(&path, contents) {
        Ok(()) => {
            app.push_message(
                LogLevel::Info,
                format!("Log exported to {}", path.display()),
            );
        }
        Err(error) => {
            app.push_message(LogLevel::Error, format!("Failed to export log: {error}"));
        }
    }
}

#[cfg(test)]
mod tests;
