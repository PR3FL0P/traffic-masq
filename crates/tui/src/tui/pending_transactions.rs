use super::*;
use ratatui::{
    layout::Rect,
    widgets::{Block, Borders, List, ListItem, ListState},
};
use traffic_masq_protocol::{CoordinatorStatus, RouterRecoveryNotice};

#[derive(Clone)]
pub(super) struct RouterTransaction {
    token: String,
    status: CoordinatorStatus,
    expires_at_unix: Option<u64>,
    rollback_failure: Option<Vec<String>>,
    recovery: Option<RouterRecoveryNotice>,
}

#[derive(Default)]
pub(super) struct View {
    pub(super) router: Option<RouterTransaction>,
    selected: Option<String>,
    error: Option<String>,
    list: ListState,
}

fn tokens(app: &TuiApp) -> Vec<String> {
    let mut tokens: Vec<_> = app
        .dashboard
        .pending_network_changes
        .iter()
        .map(|change| change.token.clone())
        .collect();
    if let Some(router) = &app.pending_transactions.router {
        tokens.push(router.token.clone());
    }
    tokens
}

pub(super) async fn refresh(app: &mut TuiApp, client: &ApiClient) {
    match client.request(&Request::RouterPendingTransaction).await {
        Ok(Response::RouterPendingTransaction {
            token: Some(token),
            status,
            expires_at_unix,
            rollback_failure,
            recovery,
        }) => {
            app.pending_transactions.router = Some(RouterTransaction {
                token,
                status,
                expires_at_unix,
                rollback_failure,
                recovery,
            });
            app.pending_transactions.error = None;
        }
        Ok(Response::RouterPendingTransaction { token: None, .. }) => {
            app.pending_transactions.router = None;
            app.pending_transactions.error = None;
        }
        other => {
            // Keep the last observation, but make its uncertainty visible.
            app.pending_transactions.error =
                Some(format!("Router pending status unavailable: {other:?}"));
        }
    }
    let tokens = tokens(app);
    if !app
        .pending_transactions
        .selected
        .as_ref()
        .is_some_and(|selected| tokens.contains(selected))
    {
        app.pending_transactions.selected = tokens.first().cloned();
    }
}

pub(super) fn render(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let now = current_unix_time();
    let mut rows = Vec::new();
    if !app.dashboard.pending_known {
        rows.push(ListItem::new(
            "Network pending status unavailable — cached rows may be stale",
        ));
    }
    for change in &app.dashboard.pending_network_changes {
        rows.push(ListItem::new(format!(
            "{} | {:?} | rollback in {}s | {}",
            change.interface,
            change.phase,
            change.expires_at_unix.saturating_sub(now),
            change.token
        )));
    }
    if let Some(RouterTransaction {
        token,
        status,
        expires_at_unix,
        ..
    }) = &app.pending_transactions.router
    {
        let timer = expires_at_unix
            .map(|deadline| format!("rollback in {}s", deadline.saturating_sub(now)))
            .unwrap_or_else(|| "deadline unavailable / recovery".into());
        rows.push(ListItem::new(format!(
            "Router / VPN | {status:?} | {timer} | {token}"
        )));
    }
    let tokens = tokens(app);
    let selected = app
        .pending_transactions
        .selected
        .as_ref()
        .and_then(|token| tokens.iter().position(|t| t == token));
    app.pending_transactions
        .list
        .select(selected.map(|i| i + usize::from(!app.dashboard.pending_known)));
    if let Some(error) = &app.pending_transactions.error {
        rows.push(ListItem::new(error.clone()));
    }
    if rows.is_empty() {
        rows.push(ListItem::new("No pending transactions"));
    }
    let list = List::new(rows)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Pending transactions — Enter: view / cancel · Esc: back "),
        )
        .highlight_style(Style::default().fg(theme::SELECTED_FG).bg(theme::ACCENT))
        .highlight_symbol("▶ ");
    frame.render_stateful_widget(list, area, &mut app.pending_transactions.list);
}

pub(super) async fn handle_key(app: &mut TuiApp, key: KeyCode, _client: &ApiClient) {
    let tokens = tokens(app);
    let index = app
        .pending_transactions
        .selected
        .as_ref()
        .and_then(|token| tokens.iter().position(|t| t == token))
        .unwrap_or(0);
    match key {
        KeyCode::Esc => app.screen = Screen::Dashboard,
        KeyCode::Up | KeyCode::Down => {
            let index = if key == KeyCode::Up {
                index.saturating_sub(1)
            } else {
                (index + 1).min(tokens.len().saturating_sub(1))
            };
            app.pending_transactions.selected = tokens.get(index).cloned();
        }
        KeyCode::Enter => {
            let Some(token) = tokens.get(index) else {
                return;
            };
            if let Some(change) = app
                .dashboard
                .pending_network_changes
                .iter()
                .find(|change| &change.token == token)
                .cloned()
            {
                app.confirmation.pending = Some(change);
                app.confirmation.pending_focus = 1;
                app.confirmation.pending_return_screen = Screen::PendingTransactions;
                app.screen = Screen::PendingChange;
            } else if let Some(RouterTransaction {
                token,
                rollback_failure,
                recovery,
                expires_at_unix,
                ..
            }) = app.pending_transactions.router.clone()
            {
                router::open_pending(app, token, Screen::PendingTransactions, None);
                let view = app.router_ui.router_pending.as_mut().unwrap();
                // Never restart another window's confirmation countdown.
                view.expires_at_unix = expires_at_unix;
                view.rollback_failure = rollback_failure;
                view.recovery = recovery;
                app.confirmation.pending_focus = 1;
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use traffic_masq_protocol::{CoordinatorStatus, NetworkChangePhase};

    fn network_change() -> PendingNetworkChange {
        PendingNetworkChange {
            token: "from-another-window".into(),
            interface: "eth0".into(),
            rollback_timeout_seconds: 60,
            expires_at_unix: current_unix_time() + 30,
            phase: NetworkChangePhase::AwaitingCommit,
            last_error: None,
            recovery_progress: None,
        }
    }

    fn list_text(app: &mut TuiApp) -> String {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 40)).unwrap();
        terminal
            .draw(|frame| render(frame, frame.area(), app))
            .unwrap();
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn failed_network_refresh_preserves_cache_without_claiming_freshness() {
        for changes in [vec![], vec![network_change()]] {
            let mut app = TuiApp::default();
            app.dashboard.pending_known = true;
            app.dashboard.pending_network_changes = changes.clone();
            // An unrelated prior message must not hide the warning in the list.
            app.message = Some("Authenticated".into());
            for _ in 0..2 {
                dashboard::accept_update(&mut app, DashboardData::default());
                assert!(!app.dashboard.pending_known);
                assert_eq!(app.dashboard.pending_network_changes, changes);
                let text = list_text(&mut app);
                assert!(
                    text.contains("Network pending status unavailable"),
                    "{text}"
                );
                assert!(!text.contains("No pending transactions"), "{text}");
                if let Some(change) = changes.first() {
                    assert!(text.contains(&change.token));
                }
            }
            dashboard::accept_update(
                &mut app,
                DashboardData {
                    pending_known: true,
                    ..Default::default()
                },
            );
            assert!(app.dashboard.pending_network_changes.is_empty());
            assert!(list_text(&mut app).contains("No pending transactions"));
        }
    }

    #[tokio::test]
    async fn failed_router_refresh_never_claims_an_empty_pending_list() {
        let mock = test_api::mock(vec![Response::Error {
            message: "unavailable".into(),
        }])
        .await;
        let mut app = TuiApp::default();
        app.dashboard.pending_known = true;
        refresh(&mut app, &mock.client).await;
        let text = list_text(&mut app);
        assert!(text.contains("Router pending status unavailable"));
        assert!(!text.contains("No pending transactions"));
    }

    #[test]
    fn pending_screen_only_retires_tokens_after_a_successful_pending_read() {
        let mut app = TuiApp {
            screen: Screen::PendingChange,
            ..Default::default()
        };
        app.confirmation.pending_return_screen = Screen::PendingTransactions;
        app.confirmation.pending = Some(network_change());
        refresh_pending_screen(&mut app);
        assert_eq!(app.screen, Screen::PendingChange);
        assert!(app.confirmation.pending.is_some());

        app.dashboard.pending_known = true;
        // Other dashboard observations may fail without invalidating pending state.
        app.dashboard.error = Some("Routes unavailable".into());
        refresh_pending_screen(&mut app);
        assert_eq!(app.screen, Screen::PendingTransactions);
        assert!(app.confirmation.pending.is_none());
    }

    #[tokio::test]
    async fn fresh_window_opens_and_rolls_back_network_change() {
        let change = network_change();
        let mock = test_api::mock(vec![
            Response::RouterPendingTransaction {
                token: None,
                status: CoordinatorStatus::Idle,
                rollback_failure: None,
                recovery: None,
                expires_at_unix: None,
            },
            Response::NetworkChangeRolledBack {
                change: change.clone(),
            },
        ])
        .await;
        let mut app = TuiApp::default();
        app.dashboard.pending_network_changes = vec![change.clone()];
        dashboard::handle_dashboard_key(&mut app, KeyCode::Char('p'), &mock.client, false).await;
        assert_eq!(app.screen, Screen::PendingTransactions);
        handle_key(&mut app, KeyCode::Enter, &mock.client).await;
        assert_eq!(app.screen, Screen::PendingChange);
        assert_eq!(app.confirmation.pending.as_ref(), Some(&change));
        assert_eq!(app.confirmation.pending_focus, 1);
        interfaces::handle_pending_key(&mut app, KeyCode::Enter, &mock.client).await;
        assert_eq!(app.screen, Screen::PendingTransactions);
        assert!(app.confirmation.pending.is_none());
        let calls = mock.calls.lock().unwrap();
        assert_eq!(calls[1].body["type"], "rollback_network_change");
        assert_eq!(calls[1].body["token"], change.token);
    }

    #[tokio::test]
    async fn discovered_router_keeps_original_deadline_and_recovery() {
        let deadline = current_unix_time() + 12;
        let mock = test_api::mock(vec![Response::RouterPendingTransaction {
            token: Some("router-other-window".into()),
            status: CoordinatorStatus::Pending,
            rollback_failure: None,
            recovery: None,
            expires_at_unix: Some(deadline),
        }])
        .await;
        let mut app = TuiApp::default();
        refresh(&mut app, &mock.client).await;
        handle_key(&mut app, KeyCode::Enter, &mock.client).await;
        assert_eq!(app.screen, Screen::RouterPending);
        assert_eq!(pending_deadline(&app), Some(deadline));
        assert_eq!(app.confirmation.pending_focus, 1);
    }

    #[tokio::test]
    async fn refresh_preserves_selection_by_token_and_removes_finished_router() {
        let mock = test_api::mock(vec![Response::RouterPendingTransaction {
            token: None,
            status: CoordinatorStatus::Idle,
            rollback_failure: None,
            recovery: None,
            expires_at_unix: None,
        }])
        .await;
        let mut app = TuiApp::default();
        let change = network_change();
        app.pending_transactions.selected = Some(change.token.clone());
        app.dashboard.pending_network_changes = vec![
            change.clone(),
            PendingNetworkChange {
                token: "another".into(),
                ..change.clone()
            },
        ];
        app.dashboard.pending_network_changes.reverse();
        refresh(&mut app, &mock.client).await;
        assert_eq!(
            app.pending_transactions.selected.as_deref(),
            Some(change.token.as_str())
        );
        assert!(app.pending_transactions.router.is_none());
    }

    fn router_pending(expires_at_unix: Option<u64>) -> Response {
        Response::RouterPendingTransaction {
            token: Some("external-router".into()),
            status: CoordinatorStatus::Pending,
            rollback_failure: None,
            recovery: None,
            expires_at_unix,
        }
    }

    fn router_idle() -> Response {
        Response::RouterPendingTransaction {
            token: None,
            status: CoordinatorStatus::Idle,
            rollback_failure: None,
            recovery: None,
            expires_at_unix: None,
        }
    }

    fn pending_screen_text(app: &mut TuiApp) -> String {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 40)).unwrap();
        terminal
            .draw(|frame| router::render_router_pending(frame, frame.area(), app))
            .unwrap();
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[tokio::test]
    async fn external_router_completion_preserves_unrelated_local_route_draft() {
        // Completion can be initiated here or observed after another client finishes.
        for action in ["commit", "rollback", "observe"] {
            let outcome = match action {
                "commit" => Response::RouterCommitted { revision: 8 },
                "rollback" => Response::RouterRolledBack,
                _ => router_idle(),
            };
            let mock = test_api::mock(vec![
                router_pending(Some(current_unix_time() + 30)),
                outcome,
                router_idle(),
            ])
            .await;
            let mut app = TuiApp::default();
            app.router.staged = true;
            app.router.proposed_router_config.route_host_traffic = true;
            let draft = app.router.proposed_router_config.clone();
            refresh(&mut app, &mock.client).await;
            handle_key(&mut app, KeyCode::Enter, &mock.client).await;
            if action == "observe" {
                router::refresh_router_pending_screen(&mut app, &mock.client).await;
            } else {
                app.confirmation.pending_focus = usize::from(action == "rollback");
                router::handle_router_pending_key(&mut app, KeyCode::Enter, &mock.client).await;
            }
            assert_eq!(app.screen, Screen::PendingTransactions);
            assert!(app.router.staged, "{action} must preserve the local draft");
            assert_eq!(app.router.proposed_router_config, draft);
            assert!(app.router_ui.router_pending.is_none());
            assert!(app.pending_transactions.router.is_none());
            assert!(!mock
                .calls
                .lock()
                .unwrap()
                .iter()
                .any(|call| call.body["type"] == "list_route_inventory"));
        }
    }

    #[tokio::test]
    async fn external_router_deadline_is_not_limited_by_client_timeout() {
        let deadline = current_unix_time() + 600;
        let mock = test_api::mock(vec![router_pending(Some(deadline))]).await;
        let mut app = TuiApp::default();
        refresh(&mut app, &mock.client).await;
        handle_key(&mut app, KeyCode::Enter, &mock.client).await;
        assert_eq!(pending_deadline(&app), Some(deadline));
        let text = pending_screen_text(&mut app);
        let seconds: u64 = text
            .split("Rollback in ")
            .nth(1)
            .unwrap()
            .split('s')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(seconds > 500 && seconds <= 600, "{text}");
    }

    #[tokio::test]
    async fn unknown_router_deadline_stays_unknown_on_open_and_refresh() {
        let mock = test_api::mock(vec![
            router_pending(None),
            router_pending(Some(current_unix_time() + 120)),
            router_pending(None),
        ])
        .await;
        let mut app = TuiApp::default();
        refresh(&mut app, &mock.client).await;
        handle_key(&mut app, KeyCode::Enter, &mock.client).await;
        assert_eq!(pending_deadline(&app), None);
        let text = pending_screen_text(&mut app);
        assert!(text.contains("deadline unavailable"));
        assert!(!text.contains("Rollback in 0s"));
        router::refresh_router_pending_screen(&mut app, &mock.client).await;
        assert!(pending_deadline(&app).unwrap() > current_unix_time() + 60);
        router::refresh_router_pending_screen(&mut app, &mock.client).await;
        assert_eq!(pending_deadline(&app), None);
    }

    #[tokio::test]
    async fn leaving_external_router_recovery_preserves_draft_and_returns_to_list() {
        let mock = test_api::mock(vec![
            Response::RouterPendingTransaction {
                token: Some("external-router".into()),
                status: CoordinatorStatus::RollbackFailed,
                rollback_failure: Some(vec!["rollback failed".into()]),
                recovery: None,
                expires_at_unix: None,
            },
            router_idle(),
        ])
        .await;
        let mut app = TuiApp::default();
        app.router.staged = true;
        refresh(&mut app, &mock.client).await;
        handle_key(&mut app, KeyCode::Enter, &mock.client).await;
        router::handle_router_pending_key(&mut app, KeyCode::Esc, &mock.client).await;
        assert_eq!(app.screen, Screen::PendingTransactions);
        assert!(app.router.staged);
        assert!(mock
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|call| call.body["type"] == "router_pending_transaction"));
    }
}
