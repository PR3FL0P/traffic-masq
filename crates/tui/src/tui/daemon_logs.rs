use super::{
    api::{
        client::ApiClient,
        model::{Request, Response},
    },
    input,
    layout::panel,
    logs::LogLevel,
    theme, Screen, TuiApp,
};
use crossterm::event::KeyCode;
use ratatui::{
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};
use traffic_masq_protocol::DaemonLogSnapshot;

#[derive(Default)]
pub(crate) struct View {
    snapshot: Option<DaemonLogSnapshot>,
    error: Option<String>,
    filter: String,
    cursor: usize,
    editing: bool,
    level: Level,
    scroll: usize,
    max_scroll: usize,
    follow: bool,
}
#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Level {
    #[default]
    All,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}
const LEVELS: [Level; 6] = [
    Level::All,
    Level::Error,
    Level::Warn,
    Level::Info,
    Level::Debug,
    Level::Trace,
];
impl Level {
    fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
            Self::Trace => "TRACE",
        }
    }
    fn matches(self, line: &str) -> bool {
        self == Self::All || {
            let mut words = line.split_whitespace();
            let first = words.next().unwrap_or("");
            let level = if LEVELS[1..].iter().any(|level| level.label() == first) {
                first
            } else {
                words.next().unwrap_or("")
            };
            level == self.label()
        }
    }
}
impl View {
    fn lines(&self) -> Vec<&str> {
        let query = self.filter.to_lowercase();
        self.snapshot
            .iter()
            .flat_map(|s| &s.lines)
            .filter(|line| self.level.matches(line) && line.to_lowercase().contains(&query))
            .map(String::as_str)
            .collect()
    }
}

pub(crate) async fn open(app: &mut TuiApp, client: &ApiClient) {
    app.screen = Screen::DaemonLogs;
    app.daemon_logs.follow = true;
    refresh(app, client).await;
}
pub(crate) async fn refresh(app: &mut TuiApp, client: &ApiClient) {
    match client.request(&Request::DaemonLogs { limit: 1000 }).await {
        Ok(Response::DaemonLogs { snapshot }) => {
            app.daemon_logs.snapshot = Some(snapshot);
            app.daemon_logs.error = None;
        }
        Ok(Response::Error { message }) => app.daemon_logs.error = Some(message),
        Ok(_) => app.daemon_logs.error = Some("Unexpected daemon log response".into()),
        Err(error) => app.daemon_logs.error = Some(error.to_string()),
    }
}
pub(crate) async fn tick(app: &mut TuiApp, client: &ApiClient) {
    if app.daemon_logs.follow && !app.daemon_logs.editing {
        refresh(app, client).await;
    }
}
pub(crate) fn render(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let view = &mut app.daemon_logs;
    let block = panel("Daemon logs | Esc/1: session log");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let style = Style::default().fg(theme::ACCENT);
    let mut filter = vec![Span::raw(format!(
        "Level: {} | Search: ",
        view.level.label()
    ))];
    filter.extend(input::render_value_with_cursor(
        &view.filter,
        view.cursor,
        view.editing,
        style,
    ));
    let summary = if let Some(error) = &view.error {
        format!("STALE / unavailable: {error}")
    } else if view.snapshot.as_ref().is_some_and(|s| s.truncated) {
        "Recent log window only; older lines may be omitted".into()
    } else {
        "Recent daemon log snapshot".into()
    };
    let header = vec![
        Line::from(filter),
        Line::styled(summary, Style::default().fg(theme::WARN)),
        Line::from(if view.follow {
            "Following | ↑/PgUp: pause | End: follow | /: search | l: level | e: export"
        } else {
            "Paused | r: refresh | End: follow | /: search | l: level | e: export"
        }),
    ];
    frame.render_widget(
        Paragraph::new(header),
        Rect::new(inner.x, inner.y, inner.width, inner.height.min(3)),
    );
    let body = Rect::new(
        inner.x,
        inner.y + 3,
        inner.width,
        inner.height.saturating_sub(3),
    );
    let lines = view
        .lines()
        .iter()
        .flat_map(|line| super::logs::wrap_log_message(line, body.width as usize))
        .map(Line::from)
        .collect::<Vec<_>>();
    view.max_scroll = lines.len().saturating_sub(body.height as usize);
    view.scroll = if view.follow {
        view.max_scroll
    } else {
        view.scroll.min(view.max_scroll)
    };
    if lines.is_empty() {
        frame.render_widget(Paragraph::new("No matching log lines"), body);
    } else {
        frame.render_widget(
            Paragraph::new(
                lines
                    .into_iter()
                    .skip(view.scroll)
                    .take(body.height as usize)
                    .collect::<Vec<_>>(),
            ),
            body,
        );
    }
}
pub(crate) async fn handle_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    let view = &mut app.daemon_logs;
    if view.editing {
        match key {
            KeyCode::Esc | KeyCode::Enter => view.editing = false,
            other => {
                input::TextEditor::new(&mut view.filter, &mut view.cursor).handle_key(other);
                view.scroll = 0;
            }
        }
        return;
    }
    match key {
        KeyCode::Esc | KeyCode::Char('1') => app.screen = Screen::Log,
        KeyCode::Char('/') => {
            view.editing = true;
            view.follow = false;
            view.cursor = input::grapheme_count(&view.filter);
        }
        KeyCode::Char('l') => {
            view.level = input::move_wrapped(&LEVELS, view.level, true);
            view.scroll = 0;
        }
        KeyCode::Up | KeyCode::PageUp => {
            view.follow = false;
            view.scroll = view
                .scroll
                .saturating_sub(if key == KeyCode::Up { 1 } else { 10 });
        }
        KeyCode::Down | KeyCode::PageDown => {
            view.follow = false;
            view.scroll =
                (view.scroll + if key == KeyCode::Down { 1 } else { 10 }).min(view.max_scroll);
        }
        KeyCode::Home => {
            view.follow = false;
            view.scroll = 0;
        }
        KeyCode::End => {
            view.follow = true;
            refresh(app, client).await;
        }
        KeyCode::Char('r') => refresh(app, client).await,
        KeyCode::Char('e') => {
            let Some(snapshot) = &view.snapshot else {
                app.push_message(LogLevel::Warn, "No daemon log snapshot to export");
                return;
            };
            let contents = format!("traffic-masq daemon log report\nServer: {}\nCaptured/exported at: {} UTC epoch seconds\nSources: {}\nLimited window: {}\nObservation error: {}\nLevel: {} | Search: {}\n\n{}\n", client.endpoint_label(), super::current_unix_time(), snapshot.sources.join(", "), snapshot.truncated, view.error.as_deref().unwrap_or("none"), view.level.label(), view.filter, view.lines().join("\n"));
            match export(&contents) {
                Ok(path) => app.push_message(
                    LogLevel::Info,
                    format!("Daemon log report exported to {}", path.display()),
                ),
                Err(error) => app.push_message(LogLevel::Error, format!("Export failed: {error}")),
            }
        }
        _ => {}
    }
}
fn export(contents: &str) -> std::io::Result<std::path::PathBuf> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "traffic-masq-daemon-{}-{nonce}.log",
        std::process::id()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    Ok(path)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn severity_and_search_filter_snapshot_and_export_is_private() {
        let view = View {
            level: Level::Error,
            filter: "wifi".into(),
            snapshot: Some(DaemonLogSnapshot {
                lines: vec![
                    "2026-10-08T00:00:00Z ERROR traffic_masq::wifi: failed".into(),
                    "2026-10-08T00:00:00Z INFO wifi: ERROR in text".into(),
                ],
                sources: vec![],
                truncated: false,
            }),
            ..Default::default()
        };
        assert_eq!(view.lines().len(), 1);
        let path = export("test diagnostic").unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_file(path).unwrap();
    }
    #[tokio::test]
    async fn paused_log_does_not_poll_and_failed_refresh_preserves_snapshot() {
        let mock = super::super::test_api::mock(vec![Response::Error {
            message: "log directory unavailable".into(),
        }])
        .await;
        let mut app = TuiApp {
            screen: Screen::DaemonLogs,
            ..Default::default()
        };
        app.daemon_logs.snapshot = Some(DaemonLogSnapshot {
            lines: vec!["WARN saved".into()],
            sources: vec![],
            truncated: false,
        });
        tick(&mut app, &mock.client).await;
        assert!(mock.calls.lock().unwrap().is_empty());
        handle_key(&mut app, KeyCode::Char('r'), &mock.client).await;
        assert_eq!(app.daemon_logs.lines(), ["WARN saved"]);
        assert!(app.daemon_logs.error.is_some());
        handle_key(&mut app, KeyCode::Char('/'), &mock.client).await;
        handle_key(&mut app, KeyCode::Char('W'), &mock.client).await;
        assert_eq!(app.daemon_logs.filter, "W");
        assert_eq!(mock.calls.lock().unwrap().len(), 1);
        handle_key(&mut app, KeyCode::Esc, &mock.client).await;
        assert_eq!(app.screen, Screen::DaemonLogs);
        handle_key(&mut app, KeyCode::Esc, &mock.client).await;
        assert_eq!(app.screen, Screen::Log);
    }
}
