use super::*;

pub(crate) fn render_router_pending(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let Some(view) = &app.router_pending else {
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

    let mut lines = vec![
        Line::styled(
            format!("Pending transaction: {}", view.token),
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Line::from(format!("Automatic rollback in: {remaining}s / {timeout}s")),
        Line::from(""),
    ];

    if let Some(failures) = &view.rollback_failure {
        lines.push(Line::styled(
            "ROLLBACK FAILED — manual recovery required:",
            Style::default().fg(theme::BAD).add_modifier(Modifier::BOLD),
        ));
        for failure in failures {
            lines.push(Line::styled(
                format!("  {failure}"),
                Style::default().fg(theme::BAD),
            ));
        }
        lines.push(Line::from(""));
    }

    lines.push(Line::styled(
        "Press Enter to COMMIT (persist changes).",
        Style::default().fg(theme::GOOD),
    ));
    lines.push(Line::styled(
        "Press Esc to ROLLBACK immediately.",
        Style::default().fg(theme::WARN),
    ));
    lines.push(Line::from(""));

    let block = panel("Router change pending confirmation");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(8)])
        .split(inner);

    let gauge = Gauge::default()
        .block(panel("Rollback countdown"))
        .gauge_style(Style::default().fg(gauge_color))
        .ratio(ratio)
        .label(format!("{remaining}s"));
    frame.render_widget(gauge, chunks[0]);

    for (slot, (label, is_commit)) in [
        (ROUTER_PENDING_COMMIT_LABEL, true),
        (ROUTER_PENDING_ROLLBACK_LABEL, false),
    ]
    .into_iter()
    .enumerate()
    {
        let button_text = format!("[{label}]");
        let button_y = chunks[1].y + lines.len() as u16;
        app.ui.buttons.push((
            Rect {
                x: chunks[1].x,
                y: button_y,
                width: button_text.len() as u16,
                height: 1,
            },
            slot,
        ));
        let style = if is_commit {
            Style::default()
                .fg(theme::SELECTED_FG)
                .bg(theme::GOOD)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
                .fg(theme::SELECTED_FG)
                .bg(theme::WARN)
                .add_modifier(Modifier::BOLD)
        };
        lines.push(Line::styled(button_text, style));
    }

    frame.render_widget(Paragraph::new(lines), chunks[1]);
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
