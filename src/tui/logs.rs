use crossterm::event::KeyCode;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use super::layout::panel;
use super::theme;
use super::{Screen, TuiApp};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone)]
pub(crate) struct LogEntry {
    pub(crate) at_unix: u64,
    pub(crate) level: LogLevel,
    pub(crate) message: String,
}

pub(crate) const LOG_HISTORY_LEN: usize = 500;

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
        app.logs_focus = *focus;
    }
}

fn render_log_actions(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let block = panel("Actions");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines = Vec::with_capacity(LOG_ACTIONS.len());
    for (slot, (focus, label)) in LOG_ACTIONS.iter().zip(LOG_ACTION_LABELS.iter()).enumerate() {
        let selected = app.logs_focus == *focus;
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
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

pub(crate) fn render_log(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let sections = ratatui::layout::Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            ratatui::layout::Constraint::Min(3),
            ratatui::layout::Constraint::Length(4),
        ])
        .split(area);
    let area = sections[0];
    render_log_actions(frame, sections[1], app);

    if app.logs.is_empty() {
        let block = panel("Session log");
        let inner = block.inner(area);
        frame.render_widget(block, area);
        frame.render_widget(
            Paragraph::new("No log entries yet").style(Style::default().fg(theme::MUTED)),
            inner,
        );
        return;
    }

    let total = app.logs.len();
    let visible = (area.height.saturating_sub(2) as usize).max(1).min(total);
    let max_offset = total.saturating_sub(visible);

    if app.logs_scroll >= max_offset.saturating_sub(1) {
        app.logs_scroll = max_offset;
    }
    let offset = app.logs_scroll.min(max_offset);

    let title = if visible < total {
        format!(
            "Session log ({}-{} of {total})",
            offset + 1,
            offset + visible
        )
    } else {
        "Session log".to_string()
    };
    let block = panel(&title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let lines: Vec<Line> = app
        .logs
        .iter()
        .skip(offset)
        .take(visible)
        .map(|entry| {
            Line::styled(
                format!(
                    "[{}] {}  {}",
                    format_time_hms(entry.at_unix),
                    entry.level.label(),
                    entry.message
                ),
                Style::default().fg(entry.level.color()),
            )
        })
        .collect();

    frame.render_widget(Paragraph::new(lines), inner);
}

pub(crate) fn handle_log_key(app: &mut TuiApp, key: KeyCode) {
    let total = app.logs.len();
    const PAGE: usize = 10;

    match key {
        KeyCode::Esc => app.screen = Screen::Dashboard,
        KeyCode::Down => match app.logs_focus {
            LogFocus::Scroll if app.logs_scroll < total => {
                app.logs_scroll = app.logs_scroll.saturating_add(1).min(total);
            }
            LogFocus::Scroll => app.logs_focus = LogFocus::Export,
            LogFocus::Export => app.logs_focus = LogFocus::Clear,
            LogFocus::Clear => {}
        },
        KeyCode::Up => match app.logs_focus {
            LogFocus::Scroll => app.logs_scroll = app.logs_scroll.saturating_sub(1),
            LogFocus::Export => app.logs_focus = LogFocus::Scroll,
            LogFocus::Clear => app.logs_focus = LogFocus::Export,
        },
        KeyCode::PageDown => {
            app.logs_focus = LogFocus::Scroll;
            app.logs_scroll = app.logs_scroll.saturating_add(PAGE).min(total);
        }
        KeyCode::PageUp => {
            app.logs_focus = LogFocus::Scroll;
            app.logs_scroll = app.logs_scroll.saturating_sub(PAGE);
        }
        KeyCode::Home => {
            app.logs_focus = LogFocus::Scroll;
            app.logs_scroll = 0;
        }
        KeyCode::End => {
            app.logs_focus = LogFocus::Scroll;
            app.logs_scroll = total;
        }
        KeyCode::Enter => match app.logs_focus {
            LogFocus::Scroll => {}
            LogFocus::Export => export_log(app),
            LogFocus::Clear => {
                app.logs.clear();
                app.logs_scroll = 0;
                app.push_message(LogLevel::Info, "Log cleared");
            }
        },
        _ => {}
    }
}

fn export_log(app: &mut TuiApp) {
    let contents: String = app
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
mod tests {
    use super::*;

    #[test]
    fn scrolling_past_the_last_entry_moves_onto_the_action_rows() {
        let mut app = TuiApp::default();
        app.logs.push_back(LogEntry {
            at_unix: 0,
            level: LogLevel::Info,
            message: "one".to_string(),
        });

        handle_log_key(&mut app, KeyCode::Down);
        assert_eq!(app.logs_focus, LogFocus::Scroll);
        assert_eq!(app.logs_scroll, 1);

        handle_log_key(&mut app, KeyCode::Down);
        assert_eq!(app.logs_focus, LogFocus::Export);
        handle_log_key(&mut app, KeyCode::Down);
        assert_eq!(app.logs_focus, LogFocus::Clear);
        handle_log_key(&mut app, KeyCode::Down);
        assert_eq!(
            app.logs_focus,
            LogFocus::Clear,
            "must clamp at the last row"
        );

        handle_log_key(&mut app, KeyCode::Up);
        assert_eq!(app.logs_focus, LogFocus::Export);
        handle_log_key(&mut app, KeyCode::Up);
        assert_eq!(app.logs_focus, LogFocus::Scroll);
    }

    #[test]
    fn enter_on_the_clear_row_empties_the_log() {
        let mut app = TuiApp::default();
        app.logs.push_back(LogEntry {
            at_unix: 0,
            level: LogLevel::Info,
            message: "one".to_string(),
        });
        app.logs_focus = LogFocus::Clear;

        handle_log_key(&mut app, KeyCode::Enter);

        assert_eq!(app.logs.len(), 1);
        assert_eq!(app.logs.back().expect("entry").message, "Log cleared");
        assert_eq!(app.logs_scroll, 0);
    }

    #[test]
    fn paging_returns_the_cursor_to_the_scroll_region() {
        let mut app = TuiApp {
            logs_focus: LogFocus::Clear,
            ..Default::default()
        };
        handle_log_key(&mut app, KeyCode::PageUp);
        assert_eq!(app.logs_focus, LogFocus::Scroll);
    }
}
