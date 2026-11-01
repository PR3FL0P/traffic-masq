//! Inspect saved router readiness and explicitly reconcile it through the daemon.
use super::{
    api::{
        client::ApiClient,
        model::{Request, Response},
    },
    layout::panel,
    logs::LogLevel,
    theme, Screen, TuiApp,
};
use crossterm::event::KeyCode;
use ratatui::{layout::Rect, style::Style, text::Line, widgets::Paragraph};
use traffic_masq_protocol::{CoordinatorStatus, ProvisioningStage, RouterProvisioningStatusView};

#[derive(Default)]
pub(crate) struct View {
    status: Option<RouterProvisioningStatusView>,
    error: Option<String>,
    confirming: bool,
    scroll: usize,
    max_scroll: usize,
}
impl View {
    fn can_repair(&self, staged: bool) -> bool {
        !staged
            && self.error.is_none()
            && self.status.as_ref().is_some_and(|s| {
                s.enabled
                    && s.stage == ProvisioningStage::Degraded
                    && s.coordinator == CoordinatorStatus::Idle
            })
    }
}

pub(crate) async fn open(app: &mut TuiApp, client: &ApiClient) {
    app.screen = Screen::RouterHealth;
    app.router_ui.router_health = View::default();
    refresh(app, client).await;
}
async fn refresh(app: &mut TuiApp, client: &ApiClient) {
    app.router_ui.router_health.confirming = false;
    match client.request(&Request::RouterProvisioningStatus).await {
        Ok(Response::RouterProvisioningStatus { status }) => {
            app.router_ui.router_health.status = Some(status);
            app.router_ui.router_health.error = None;
        }
        other => app.router_ui.router_health.error = Some(error_message(other)),
    }
}
fn error_message(response: anyhow::Result<Response>) -> String {
    match response {
        Ok(Response::Error { message }) => message,
        Ok(Response::RouterProvisioningError { detail }) => format!("{detail:?}"),
        Ok(_) => "Unexpected router health response".into(),
        Err(error) => error.to_string(),
    }
}
pub(super) fn confirmation(app: &TuiApp) -> Option<super::confirmation::Dialog> {
    if !app.router_ui.router_health.confirming {
        return None;
    }
    let mut lines = vec![
        "Target: saved router configuration".into(),
        "Reapplies saved state immediately; network traffic may be interrupted.".into(),
        "This operation has no rollback timer.".into(),
    ];
    if let Some(status) = &app.router_ui.router_health.status {
        for (name, reason) in [
            ("Interfaces", &status.readiness.interfaces),
            ("Routes", &status.readiness.routes),
            ("DHCP server", &status.readiness.dhcp),
            ("Dataplane", &status.readiness.dataplane),
        ] {
            if let Some(reason) = reason {
                lines.push(format!("{name}: {reason}"));
            }
        }
    }
    Some(super::confirmation::Dialog {
        secondary: None,
        title: "Repair saved router state?",
        action: "Repair",
        lines,
    })
}

pub(crate) fn render(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    if let Some(dialog) = confirmation(app) {
        dialog.render(
            frame,
            area,
            &mut app.ui,
            app.confirmation.confirmation_focus,
            app.confirmation.confirmation_scroll,
        );
        return;
    }
    let interface_lines = app
        .router
        .saved_router_config
        .as_ref()
        .map(|config| super::interface_status::router_lines(app, &[config]))
        .unwrap_or_default();
    let view = &mut app.router_ui.router_health;
    let block = panel("Router health | saved configuration");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let mut lines = vec![Line::from(
        "r: refresh | f: repair | Esc: back | arrows/PgUp/PgDn: scroll",
    )];
    if let Some(error) = &view.error {
        lines.push(Line::styled(
            format!("STALE / unavailable: {error}"),
            Style::default().fg(theme::WARN),
        ));
    }
    lines.extend(interface_lines);
    if app.router.staged {
        lines.push(Line::from(
            "Draft retained. Apply or discard it in Route before repair.",
        ));
    }
    if let Some(status) = &view.status {
        lines.push(Line::from(format!(
            "Stage: {:?} | enabled: {} | ready: {}",
            status.stage, status.enabled, status.ready
        )));
        lines.push(Line::from(format!(
            "Transaction coordinator: {:?}",
            status.coordinator
        )));
        lines.push(Line::from(
            "Checks below report blockers for saved state; clear does not verify Internet access.",
        ));
        let health = &status.readiness;
        for (name, reason) in [
            ("Interfaces", &health.interfaces),
            ("Routes", &health.routes),
            ("DHCP server", &health.dhcp),
            ("Dataplane", &health.dataplane),
        ] {
            lines.push(Line::from(format!(
                "{name}: {}",
                reason.as_deref().unwrap_or("no blocker reported")
            )));
        }
        lines.push(Line::from(format!(
            "Uplink DHCP: {}",
            health
                .uplink_dhcp
                .as_ref()
                .map(|reason| format!("{reason:?}"))
                .unwrap_or_else(|| "no blocker reported".into())
        )));
        for failure in &status.failures {
            lines.push(Line::styled(
                format!("Failure: {failure}"),
                Style::default().fg(theme::WARN),
            ));
        }
        if !view.can_repair(app.router.staged) {
            lines.push(Line::from("Repair requires fresh degraded status, enabled routing, no draft and an idle coordinator."));
            if status.coordinator != CoordinatorStatus::Idle {
                lines.push(Line::from(
                    "Return to Route to resolve the pending transaction or recovery first.",
                ));
            }
        }
    }
    let wrapped = lines
        .into_iter()
        .flat_map(|line| {
            let style = line.style;
            super::logs::wrap_log_message(&line.to_string(), inner.width as usize)
                .into_iter()
                .map(move |text| Line::styled(text, style))
        })
        .collect::<Vec<_>>();
    view.max_scroll = wrapped.len().saturating_sub(inner.height as usize);
    view.scroll = view.scroll.min(view.max_scroll);
    frame.render_widget(
        Paragraph::new(
            wrapped
                .into_iter()
                .skip(view.scroll)
                .take(inner.height as usize)
                .collect::<Vec<_>>(),
        ),
        inner,
    );
}
pub(crate) async fn handle_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    if app.router_ui.router_health.confirming {
        match key {
            KeyCode::Esc => app.router_ui.router_health.confirming = false,
            KeyCode::Enter => {
                app.router_ui.router_health.confirming = false;
                if !app.router_ui.router_health.can_repair(app.router.staged) {
                    return;
                }
                match client.request(&Request::RouterProvisioningRepair).await {
                    Ok(Response::RouterProvisioningRepaired { status }) => {
                        let ready = status.ready;
                        app.router_ui.router_health.status = Some(status);
                        app.router_ui.router_health.error = None;
                        app.push_message(
                            if ready {
                                LogLevel::Info
                            } else {
                                LogLevel::Warn
                            },
                            if ready {
                                "Saved router state repaired; readiness checks passed"
                            } else {
                                "Repair completed; readiness blockers remain"
                            },
                        );
                    }
                    other => {
                        app.router_ui.router_health.error = Some(error_message(other));
                        app.push_message(
                            LogLevel::Warn,
                            "Repair was not confirmed successful; refresh status before retrying",
                        );
                    }
                }
            }
            _ => {}
        }
        return;
    }
    match key {
        KeyCode::Esc => {
            app.screen = Screen::Router;
            super::router::refresh_router_data(app, client).await;
        }
        KeyCode::Char('r') => refresh(app, client).await,
        KeyCode::Char('f') => {
            refresh(app, client).await;
            app.router_ui.router_health.confirming =
                app.router_ui.router_health.can_repair(app.router.staged);
            app.router_ui.router_health.scroll = 0;
        }
        KeyCode::Up => {
            app.router_ui.router_health.scroll =
                app.router_ui.router_health.scroll.saturating_sub(1)
        }
        KeyCode::PageUp => {
            app.router_ui.router_health.scroll =
                app.router_ui.router_health.scroll.saturating_sub(10)
        }
        KeyCode::Down => {
            app.router_ui.router_health.scroll =
                (app.router_ui.router_health.scroll + 1).min(app.router_ui.router_health.max_scroll)
        }
        KeyCode::PageDown => {
            app.router_ui.router_health.scroll = (app.router_ui.router_health.scroll + 10)
                .min(app.router_ui.router_health.max_scroll)
        }
        KeyCode::Home => app.router_ui.router_health.scroll = 0,
        KeyCode::End => app.router_ui.router_health.scroll = app.router_ui.router_health.max_scroll,
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use traffic_masq_protocol::RouterHealthReport;

    fn status(stage: ProvisioningStage) -> RouterProvisioningStatusView {
        RouterProvisioningStatusView {
            stage,
            enabled: true,
            ready: stage == ProvisioningStage::Ready,
            coordinator: CoordinatorStatus::Idle,
            readiness: RouterHealthReport {
                routes: (stage == ProvisioningStage::Degraded)
                    .then(|| "saved route missing".into()),
                ..Default::default()
            },
            failures: vec![],
        }
    }
    fn snapshot(stage: ProvisioningStage) -> Response {
        Response::RouterProvisioningStatus {
            status: status(stage),
        }
    }

    #[tokio::test]
    async fn repair_requires_refresh_and_confirmation_and_cancel_does_not_mutate() {
        let mock = super::super::test_api::mock(vec![
            snapshot(ProvisioningStage::Degraded),
            snapshot(ProvisioningStage::Degraded),
            snapshot(ProvisioningStage::Degraded),
            Response::RouterProvisioningRepaired {
                status: status(ProvisioningStage::Ready),
            },
        ])
        .await;
        let mut app = TuiApp::default();
        open(&mut app, &mock.client).await;
        handle_key(&mut app, KeyCode::Char('f'), &mock.client).await;
        assert!(app.router_ui.router_health.confirming);
        handle_key(&mut app, KeyCode::Esc, &mock.client).await;
        assert!(!app.router_ui.router_health.confirming);
        assert_eq!(app.screen, Screen::RouterHealth);
        assert!(
            mock.calls
                .lock()
                .unwrap()
                .iter()
                .all(|call| call.method == "POST"
                    && call.body["type"] == "router_provisioning_status")
        );
        handle_key(&mut app, KeyCode::Char('f'), &mock.client).await;
        handle_key(&mut app, KeyCode::Enter, &mock.client).await;
        assert!(app.router_ui.router_health.status.as_ref().unwrap().ready);
        let calls = mock.calls.lock().unwrap();
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[3].method, "POST");
        assert_eq!(calls[3].path, "/api/v1/control");
        assert_eq!(calls[3].body["type"], "router_provisioning_repair");
    }

    #[tokio::test]
    async fn failed_refresh_retains_snapshot_and_disables_repair() {
        let mock = super::super::test_api::mock(vec![
            snapshot(ProvisioningStage::Degraded),
            Response::Error {
                message: "status unavailable".into(),
            },
        ])
        .await;
        let mut app = TuiApp::default();
        open(&mut app, &mock.client).await;
        handle_key(&mut app, KeyCode::Char('f'), &mock.client).await;
        handle_key(&mut app, KeyCode::Enter, &mock.client).await;
        assert!(!app.router_ui.router_health.confirming);
        assert!(app.router_ui.router_health.status.is_some());
        assert!(app.router_ui.router_health.error.is_some());
        assert_eq!(mock.calls.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn ambiguous_repair_failure_cannot_be_retried_without_refresh() {
        let mock = super::super::test_api::mock(vec![
            snapshot(ProvisioningStage::Degraded),
            snapshot(ProvisioningStage::Degraded),
            Response::Error {
                message: "repair failed".into(),
            },
        ])
        .await;
        let mut app = TuiApp::default();
        open(&mut app, &mock.client).await;
        handle_key(&mut app, KeyCode::Char('f'), &mock.client).await;
        handle_key(&mut app, KeyCode::Enter, &mock.client).await;
        handle_key(&mut app, KeyCode::Enter, &mock.client).await;
        assert!(!app.router_ui.router_health.can_repair(false));
        assert_eq!(mock.calls.lock().unwrap().len(), 3);
    }

    #[test]
    fn pending_recovery_disabled_ready_and_drafts_block_repair() {
        let mut view = View {
            status: Some(status(ProvisioningStage::Degraded)),
            ..Default::default()
        };
        assert!(view.can_repair(false));
        assert!(!view.can_repair(true));
        for coordinator in [
            CoordinatorStatus::Pending,
            CoordinatorStatus::RollbackFailed,
            CoordinatorStatus::RecoveryRequired,
            CoordinatorStatus::CommitIndeterminate,
            CoordinatorStatus::RecoveredButJournalCleanupPending,
        ] {
            view.status.as_mut().unwrap().coordinator = coordinator;
            assert!(!view.can_repair(false));
        }
        view.status = Some(status(ProvisioningStage::Ready));
        assert!(!view.can_repair(false));
        view.status = Some(status(ProvisioningStage::Degraded));
        view.status.as_mut().unwrap().enabled = false;
        assert!(!view.can_repair(false));
    }

    #[test]
    fn confirmation_and_blockers_are_visible_at_minimum_terminal_size() {
        let mut app = TuiApp::default();
        app.router_ui.router_health.status = Some(status(ProvisioningStage::Degraded));
        app.router_ui.router_health.confirming = true;
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| render(frame, frame.area(), &mut app))
            .unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(text.contains("[Repair]"));
        assert!(text.contains("no rollback timer"));
        assert!(text.contains("saved route missing"));
    }
}
