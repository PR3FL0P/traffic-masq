use super::plan::{current_router_proposal, lease_counts_for_plan};
use super::*;

pub(crate) fn focus_action(app: &mut TuiApp, slot: usize) {
    if app.router.pane == RouterPane::Sharing {
        app.router.sharing_actions_focused = true;
        app.router.sharing_action = slot;
        return;
    }
    app.router.focus = RouterFocus::Actions;
    app.router.action = match slot {
        0 => RouterAction::AddRoute,
        1 => RouterAction::EditRoute,
        2 => RouterAction::DeleteRoute,
        3 => RouterAction::PlanApply,
        4 => RouterAction::ShareViaRoute,
        6 => RouterAction::Topology,
        7 => RouterAction::ToggleEnabled,
        _ => RouterAction::Refresh,
    };
}

/// Dispatch router-screen input to editing, planning, apply, confirmation, and rollback actions.
pub(crate) async fn handle_router_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    match key {
        KeyCode::Char('r') if app.router.recovery_blocks_mutations() => {
            handle_router_recovery_action(app, client).await;
            return;
        }
        KeyCode::Char('c') if app.router.staged => {
            app.router.staged = false;
            app.router.offline_preview = None;
            app.router.editor = None;
            load_router_data(app, client).await;
            app.push_message(
                LogLevel::Info,
                "Router draft discarded; saved configuration reloaded",
            );
            return;
        }
        KeyCode::Char('e') => {
            if app.router.recovery_blocks_mutations() {
                app.push_message(
                    LogLevel::Warn,
                    "Router changes are blocked until recovery completes; press r for recovery status/action",
                );
            } else {
                toggle_router_enabled(app, client).await;
            }
            return;
        }
        KeyCode::Char('1') => {
            select_pane(app, RouterPane::Routes);
            return;
        }
        KeyCode::Char('2') => {
            select_pane(app, RouterPane::Sharing);
            return;
        }
        KeyCode::Char('3') => {
            select_pane(app, RouterPane::Topology);
            return;
        }
        KeyCode::Char('t') => {
            select_pane(
                app,
                if app.router.pane == RouterPane::Topology {
                    RouterPane::Routes
                } else {
                    RouterPane::Topology
                },
            );
            return;
        }
        _ => {}
    }
    if app.router.pane == RouterPane::Sharing {
        super::super::forwarding::handle_list_key(app, key, client).await;
        return;
    }
    if app.router.topology.open {
        app.router.topology.handle_key(key);
        if !app.router.topology.open {
            select_pane(app, RouterPane::Routes);
        }
        return;
    }
    match key {
        KeyCode::Char('n') => super::super::forwarding::open_from_route(app, client).await,
        KeyCode::PageUp | KeyCode::PageDown => app.router.topology.handle_key(key),
        KeyCode::Esc => {
            if app.router.focus == RouterFocus::Actions {
                app.router.focus = RouterFocus::RouteTable;
                app.router.warning_message = None;
            } else {
                app.screen = Screen::Dashboard;
            }
        }
        KeyCode::Tab => {
            app.router.focus = match app.router.focus {
                RouterFocus::RouteTable => RouterFocus::Actions,
                RouterFocus::Actions => RouterFocus::RouteTable,
            };
            app.router.warning_message = None;
        }
        KeyCode::BackTab => {
            app.router.focus = match app.router.focus {
                RouterFocus::RouteTable => RouterFocus::Actions,
                RouterFocus::Actions => RouterFocus::RouteTable,
            };
            app.router.warning_message = None;
        }
        _ => match app.router.focus {
            RouterFocus::RouteTable => match key {
                KeyCode::Up => {
                    if app.router.selected_route > 0 {
                        app.router.selected_route -= 1;
                    }
                    app.router.warning_message = None;
                }
                KeyCode::Down => {
                    if !app.router.route_rows().is_empty()
                        && app.router.selected_route + 1 < app.router.route_rows().len()
                    {
                        app.router.selected_route += 1;
                    }
                    app.router.warning_message = None;
                }
                KeyCode::Enter => {
                    open_route_editor_for_selected(app, client).await;
                }
                KeyCode::Delete => {
                    delete_selected_route(app);
                }
                _ => {}
            },
            RouterFocus::Actions => match key {
                KeyCode::Up => {
                    app.router.action = app.router.action.prev();
                    app.router.warning_message = None;
                }
                KeyCode::Down => {
                    if app.router.action != RouterAction::ToggleEnabled {
                        app.router.action = app.router.action.next();
                    }
                    app.router.warning_message = None;
                }
                KeyCode::Left => {
                    app.router.action = app.router.action.prev();
                    app.router.warning_message = None;
                }
                KeyCode::Right => {
                    app.router.action = app.router.action.next();
                    app.router.warning_message = None;
                }
                KeyCode::Enter | KeyCode::Char(' ') => match app.router.action {
                    RouterAction::ToggleEnabled if app.router.recovery_blocks_mutations() => {
                        app.push_message(
                            LogLevel::Warn,
                            "Router changes are blocked until recovery completes; press r for recovery status/action",
                        );
                    }
                    RouterAction::ToggleEnabled => toggle_router_enabled(app, client).await,
                    RouterAction::AddRoute => open_route_editor_for_add(app, client).await,
                    RouterAction::EditRoute => open_route_editor_for_selected(app, client).await,
                    RouterAction::DeleteRoute => delete_selected_route(app),
                    RouterAction::PlanApply if app.router.recovery_blocks_mutations() => {
                        app.push_message(
                            LogLevel::Warn,
                            "Router apply is blocked until recovery completes; press r for recovery status/action",
                        );
                    }
                    RouterAction::PlanApply => open_router_plan(app, client).await,
                    RouterAction::ShareViaRoute => {
                        super::super::forwarding::open_from_route(app, client).await
                    }
                    RouterAction::Refresh => refresh_router_data(app, client).await,
                    RouterAction::Topology => select_pane(app, RouterPane::Topology),
                },
                _ => {}
            },
        },
    }
}

async fn handle_router_recovery_action(app: &mut TuiApp, client: &ApiClient) {
    match client.request(&Request::RouterPendingTransaction).await {
        Ok(Response::RouterPendingTransaction {
            status: CoordinatorStatus::CommitIndeterminate,
            ..
        }) => {
            app.push_message(LogLevel::Error, "Commit outcome is unknown. Repair storage access and restart the daemon; rollback is blocked.");
            load_router_data(app, client).await;
        }
        Ok(Response::RouterPendingTransaction {
            token: Some(token),
            status: CoordinatorStatus::RollbackFailed | CoordinatorStatus::RecoveryRequired,
            recovery,
            ..
        }) => {
            if let Some(recovery) = recovery {
                app.router.recovery = Some(recovery);
            }
            match client.request(&Request::RouterRollback { token }).await {
                Ok(Response::RouterRolledBack) => {
                    app.push_message(LogLevel::Info, "Router rollback recovery completed");
                    app.router_pending = None;
                    app.router.staged = false;
                    load_router_data(app, client).await;
                }
                Ok(Response::RouterError { detail }) => {
                    app.push_message(LogLevel::Error, describe_router_error(&detail));
                    load_router_data(app, client).await;
                }
                Ok(response) => app.push_message(
                    LogLevel::Error,
                    format!("Unexpected recovery response: {response:?}"),
                ),
                Err(error) => app.push_message(LogLevel::Error, error.to_string()),
            }
        }
        Ok(Response::RouterPendingTransaction {
            status: CoordinatorStatus::RecoveredButJournalCleanupPending,
            ..
        }) => {
            app.push_message(
                LogLevel::Info,
                "Router recovery is complete; journal cleanup retries automatically",
            );
            app.router_pending = None;
            app.router.staged = false;
            load_router_data(app, client).await;
        }
        Ok(Response::RouterPendingTransaction {
            status: CoordinatorStatus::Idle,
            ..
        }) => {
            app.push_message(LogLevel::Info, "Router recovery is already complete");
            app.router_pending = None;
            app.router.staged = false;
            load_router_data(app, client).await;
        }
        Ok(Response::RouterPendingTransaction {
            status: CoordinatorStatus::RollbackFailed | CoordinatorStatus::RecoveryRequired,
            token: None,
            ..
        }) => app.push_message(
            LogLevel::Error,
            "Rollback recovery is required but the daemon did not provide a transaction token",
        ),
        Ok(Response::RouterPendingTransaction {
            status: CoordinatorStatus::Pending,
            ..
        }) => app.push_message(
            LogLevel::Warn,
            "Router transaction is still pending confirmation; open the pending transaction screen",
        ),
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected recovery status response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

async fn toggle_router_enabled(app: &mut TuiApp, client: &ApiClient) {
    if !app.router.topology.loaded {
        load_router_data(app, client).await;
        if !app.router.topology.loaded {
            app.push_message(
                LogLevel::Error,
                "Load router configuration before changing routing",
            );
            return;
        }
    }
    app.router.proposed_router_config.enabled = !app.router.proposed_router_config.enabled;
    app.router.staged = true;
    open_router_plan(app, client).await;
}

pub(crate) async fn refresh_router_data(app: &mut TuiApp, client: &ApiClient) {
    load_router_data(app, client).await;
}

/// Refresh only volatile router status.
///
/// This is intentionally cheaper than `load_router_data`: the TUI calls it from
/// its periodic refresh loop, so it must not request a dry-run router plan or
/// reload editor configuration/routes. Full router data is loaded explicitly on
/// screen entry, user refresh, and after router mutations.
pub(crate) async fn refresh_router_status(app: &mut TuiApp, client: &ApiClient) {
    let _ = load_router_status(app, client).await;
}

/// Report whether current editor state requires a new router preview.
pub(super) fn router_plan_needed(router: &RouterData) -> bool {
    router.enabled
        || router.proposed_router_config.enabled
        || router.proposed_router_config.uplink.is_some()
        || !router.proposed_router_config.owned_routes.is_empty()
        || router
            .proposed_router_config
            .forwarding
            .as_ref()
            .is_some_and(|rules| !rules.is_empty())
}

async fn load_router_status(app: &mut TuiApp, client: &ApiClient) -> bool {
    match client.request(&Request::RouterStatus).await {
        Ok(Response::RouterStatus {
            desired_revision,
            last_applied_revision,
            enabled,
            ready,
            coordinator_status,
            health,
            recovery,
        }) => {
            app.router.desired_revision = desired_revision;
            app.router.last_applied_revision = last_applied_revision;
            app.router.enabled = enabled;
            app.router.ready = ready;
            app.router.coordinator_status = Some(coordinator_status);
            app.router.recovery = recovery;
            app.router.health = health;
            true
        }
        Ok(Response::RouterError { detail }) => {
            app.router.error = Some(detail);
            app.router.topology.loaded = false;
            app.router.plan = None;
            false
        }
        Ok(Response::Error { message }) => {
            app.push_message(LogLevel::Error, message);
            app.router.topology.loaded = false;
            app.router.plan = None;
            false
        }
        Ok(response) => {
            app.push_message(
                LogLevel::Error,
                format!("Unexpected response: {response:?}"),
            );
            app.router.topology.loaded = false;
            app.router.plan = None;
            false
        }
        Err(error) => {
            app.push_message(LogLevel::Error, error.to_string());
            app.router.topology.loaded = false;
            app.router.plan = None;
            false
        }
    }
}

/// Refresh router configuration, status, and pending transaction state from the daemon.
pub(crate) async fn load_router_data(app: &mut TuiApp, client: &ApiClient) {
    app.router.error = None;
    // Saved inventory remains usable even when execution status is unavailable.
    let _ = load_router_status(app, client).await;
    if !app.router.staged {
        let selected = app
            .router
            .route_rows()
            .get(app.router.selected_route)
            .and_then(row_config);
        match client
            .request(&Request::ListRouteInventory {
                include_local_table: false,
            })
            .await
        {
            Ok(Response::RouteInventory {
                revision,
                config,
                routes,
                observation_error,
            }) => {
                app.router.saved_router_config = Some(config.clone());
                app.router.proposed_router_config = config;
                app.router.editor_revision = Some(revision);
                app.router.routes = routes
                    .iter()
                    .filter_map(|row| row.observed.clone())
                    .collect();
                app.router.route_inventory = Some(routes);
                app.router.observation_error = observation_error;
                app.router.topology.loaded = true;
                let rows = app.router.route_rows();
                app.router.selected_route = selected
                    .as_ref()
                    .and_then(|selected| {
                        rows.iter()
                            .position(|row| row_config(row).as_ref() == Some(selected))
                    })
                    .unwrap_or(app.router.selected_route.min(rows.len().saturating_sub(1)));
            }
            Ok(response) => {
                app.push_message(
                    LogLevel::Error,
                    format!("Could not load saved routes: {response:?}"),
                );
                app.router.topology.loaded = false;
                return;
            }
            Err(error) => {
                app.router.observation_error = Some(error.to_string());
                app.push_message(LogLevel::Error, error.to_string());
                return;
            }
        }
        match client.request(&Request::ListInterfaceInventory).await {
            Ok(Response::InterfaceInventory {
                interfaces,
                revision,
                ..
            }) if Some(revision) == app.router.editor_revision => {
                app.router.saved_interfaces = interfaces;
            }
            _ => {
                app.router.saved_interfaces.clear();
                app.router.topology.loaded = false;
                app.push_message(LogLevel::Error, "Could not load interface settings at the router revision; refresh before editing sharing");
                return;
            }
        }
    }

    if !router_plan_needed(&app.router) {
        app.router.plan = None;
        app.router.lease_counts = Vec::new();
        return;
    }

    let proposal = current_router_proposal(app);
    match client
        .request(&Request::RouterIntentPreview {
            proposal: proposal.clone(),
        })
        .await
    {
        Ok(Response::RouterIntentPreview {
            device_readiness: traffic_masq_protocol::InterfaceReadiness::Ready,
            execution_available: true,
            ..
        }) => {
            if !app.router.staged {
                app.router.saved_device_readiness =
                    Some(traffic_masq_protocol::InterfaceReadiness::Ready);
            }
        }
        Ok(Response::RouterIntentPreview {
            device_readiness, ..
        }) => {
            if !app.router.staged {
                app.router.saved_device_readiness = Some(device_readiness);
            }
            app.router.plan = None;
            return;
        }
        Ok(response) => {
            app.push_message(
                LogLevel::Error,
                format!("Could not inspect router intent: {response:?}"),
            );
            app.router.plan = None;
            return;
        }
        Err(error) => {
            app.push_message(LogLevel::Error, error.to_string());
            app.router.plan = None;
            return;
        }
    }
    match client.request(&Request::RouterPlan { proposal }).await {
        Ok(Response::RouterPlan { plan }) => {
            app.router.lease_counts = lease_counts_for_plan(client, &plan).await;
            app.router.plan = Some(plan);
        }
        Ok(Response::RouterError { detail }) => {
            app.router.error = Some(detail);
            app.router.plan = None;
        }
        Ok(Response::Error { message }) => {
            app.push_message(LogLevel::Error, message);
            app.router.plan = None;
        }
        Ok(response) => {
            app.push_message(
                LogLevel::Error,
                format!("Unexpected response: {response:?}"),
            );
            app.router.plan = None;
        }
        Err(error) => {
            app.push_message(LogLevel::Error, error.to_string());
            app.router.plan = None;
        }
    }
}
