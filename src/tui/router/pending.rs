use super::*;

pub(crate) fn render_router_pending(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let Some(view) = app.router_pending.as_mut() else {
        return;
    };
    let now = current_unix_time();
    let timeout = app.router_rollback_timeout_seconds;
    let remaining = router_pending_seconds_remaining(view.applied_at_unix, timeout, now);
    let ratio = if timeout > 0 {
        (remaining as f64 / timeout as f64).clamp(0.0, 1.0)
    } else {
        0.0
    };

    let gauge_color = if remaining > timeout / 2 {
        theme::GOOD
    } else if remaining > timeout / 4 {
        theme::WARN
    } else {
        theme::BAD
    };

    let mut detail_lines = vec![
        Line::styled(
            format!("Pending transaction: {}", view.token),
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Line::from(format!("Automatic rollback in: {remaining}s / {timeout}s")),
    ];
    if let Some(failures) = &view.rollback_failure {
        detail_lines.push(Line::from(""));
        detail_lines.push(Line::styled(
            "ROLLBACK FAILED — manual recovery required:",
            Style::default().fg(theme::BAD).add_modifier(Modifier::BOLD),
        ));
        for failure in failures {
            detail_lines.push(Line::styled(
                format!("  {failure}"),
                Style::default().fg(theme::BAD),
            ));
        }
    }

    let block = panel("Router change pending confirmation");
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

    let gauge = Gauge::default()
        .block(panel("Rollback countdown"))
        .gauge_style(Style::default().fg(gauge_color))
        .ratio(ratio)
        .label(format!("{remaining}s"));
    frame.render_widget(gauge, chunks[0]);

    let visible_rows = chunks[1].height.max(1) as usize;
    view.max_scroll = detail_lines.len().saturating_sub(visible_rows);
    view.scroll = view.scroll.min(view.max_scroll);
    frame.render_widget(
        Paragraph::new(detail_lines).scroll((view.scroll.min(u16::MAX as usize) as u16, 0)),
        chunks[1],
    );

    let action_lines = vec![
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
            "Up/Down or PgUp/PgDn scrolls diagnostics",
            Style::default().fg(theme::MUTED),
        ),
    ];
    app.ui.buttons.push((
        Rect::new(chunks[2].x, chunks[2].y, "[Commit]".len() as u16, 1),
        0,
    ));
    app.ui.buttons.push((
        Rect::new(
            chunks[2].x,
            chunks[2].y.saturating_add(1),
            "[Rollback]".len() as u16,
            1,
        ),
        1,
    ));
    frame.render_widget(Paragraph::new(action_lines), chunks[2]);
}

pub(super) fn router_pending_seconds_remaining(
    applied_at_unix: u64,
    timeout_seconds: u64,
    now_unix: u64,
) -> u64 {
    let elapsed = now_unix.saturating_sub(applied_at_unix);
    timeout_seconds.saturating_sub(elapsed)
}

pub(crate) async fn handle_router_pending_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    match key {
        KeyCode::Up | KeyCode::Char('k') => {
            if let Some(view) = app.router_pending.as_mut() {
                view.scroll = view.scroll.saturating_sub(1);
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if let Some(view) = app.router_pending.as_mut() {
                view.scroll = view.scroll.saturating_add(1).min(view.max_scroll);
            }
        }
        KeyCode::PageUp => {
            if let Some(view) = app.router_pending.as_mut() {
                view.scroll = view.scroll.saturating_sub(10);
            }
        }
        KeyCode::PageDown => {
            if let Some(view) = app.router_pending.as_mut() {
                view.scroll = view.scroll.saturating_add(10).min(view.max_scroll);
            }
        }
        KeyCode::Home => {
            if let Some(view) = app.router_pending.as_mut() {
                view.scroll = 0;
            }
        }
        KeyCode::End => {
            if let Some(view) = app.router_pending.as_mut() {
                view.scroll = view.max_scroll;
            }
        }
        KeyCode::Enter => finish_router_pending(app, client, true).await,
        KeyCode::Esc => finish_router_pending(app, client, false).await,
        _ => {}
    }
}

async fn finish_router_pending(app: &mut TuiApp, client: &ApiClient, commit: bool) {
    let Some(pending) = app.router_pending.as_ref() else {
        app.screen = Screen::Router;
        return;
    };
    let token = pending.token.clone();
    let request = if commit {
        Request::RouterCommit { token }
    } else {
        Request::RouterRollback { token }
    };

    match client.request(&request).await {
        Ok(Response::RouterCommitted { revision }) if commit => {
            app.push_message(
                LogLevel::Info,
                format!("Router config committed (revision {revision})"),
            );
            app.router_pending = None;
            app.router.staged = false;
            app.screen = Screen::Router;
            load_router_data(app, client).await;
        }
        Ok(Response::RouterRolledBack) if !commit => {
            app.push_message(LogLevel::Info, "Router transaction rolled back");
            app.router_pending = None;
            app.router.staged = false;
            app.screen = Screen::Router;
            load_router_data(app, client).await;
        }
        Ok(Response::RouterError { detail }) => {
            app.push_message(LogLevel::Error, describe_router_error(&detail));
        }
        Ok(Response::RouterPendingTransaction {
            status: CoordinatorStatus::RollbackFailed,
            rollback_failure,
            ..
        }) => {
            if let Some(view) = app.router_pending.as_mut() {
                view.rollback_failure = rollback_failure;
            }
        }
        Ok(response) => {
            app.push_message(
                LogLevel::Error,
                format!("Unexpected response: {response:?}"),
            );
        }
        Err(error) => {
            app.push_message(LogLevel::Error, error.to_string());
        }
    }
}

pub(crate) async fn refresh_router_pending_screen(app: &mut TuiApp, client: &ApiClient) {
    if app.router_pending.is_none() {
        return;
    }
    match client.request(&Request::RouterPendingTransaction).await {
        Ok(Response::RouterPendingTransaction {
            status: CoordinatorStatus::Idle,
            ..
        }) => {
            app.router_pending = None;
            app.router.staged = false;
            if app.screen == Screen::RouterPending {
                app.screen = Screen::Router;
                load_router_data(app, client).await;
            }
        }
        Ok(Response::RouterPendingTransaction {
            status: CoordinatorStatus::RollbackFailed,
            rollback_failure,
            ..
        }) => {
            if let Some(view) = app.router_pending.as_mut() {
                view.rollback_failure = rollback_failure;
            }
        }
        Ok(Response::RouterPendingTransaction {
            status: CoordinatorStatus::Pending,
            ..
        }) => {}
        _ => {}
    }
}
