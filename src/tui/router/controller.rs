use super::*;
use super::plan::{current_router_proposal, lease_counts_for_plan};

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
        _ => RouterAction::Refresh,
    };
}

pub(crate) async fn handle_router_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    match key {
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
                    if !app.router.routes.is_empty()
                        && app.router.selected_route + 1 < app.router.routes.len()
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
                    if app.router.action != RouterAction::Topology {
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
                    RouterAction::AddRoute => open_route_editor_for_add(app, client).await,
                    RouterAction::EditRoute => open_route_editor_for_selected(app, client).await,
                    RouterAction::DeleteRoute => delete_selected_route(app),
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

pub(crate) async fn refresh_router_data(app: &mut TuiApp, client: &ApiClient) {
    load_router_data(app, client).await;
}

pub(crate) async fn load_router_data(app: &mut TuiApp, client: &ApiClient) {
    app.router.error = None;

    match client.request(&Request::RouterStatus).await {
        Ok(Response::RouterStatus {
            enabled,
            ready,
            coordinator_status,
            health,
        }) => {
            app.router.enabled = enabled;
            app.router.ready = ready;
            app.router.coordinator_status = Some(coordinator_status);
            app.router.health = health;
        }
        Ok(Response::RouterError { detail }) => {
            app.router.error = Some(detail);
            app.router.topology.loaded = false;
            app.router.plan = None;
            return;
        }
        Ok(response) => {
            app.push_message(
                LogLevel::Error,
                format!("Unexpected response: {response:?}"),
            );
            app.router.topology.loaded = false;
            app.router.plan = None;
            return;
        }
        Err(error) => {
            app.push_message(LogLevel::Error, error.to_string());
            app.router.topology.loaded = false;
            app.router.plan = None;
            return;
        }
    }

    let mut topology_loaded = true;
    if !app.router.staged {
        if let Ok(Response::RouterConfig { config }) =
            client.request(&Request::GetRouterConfig).await
        {
            app.router.proposed_router_config = config;
        } else {
            topology_loaded = false;
        }

        if let Ok(Response::Routes { routes }) = client
            .request(&Request::ListRoutes {
                include_local_table: false,
            })
            .await
        {
            app.router.routes = routes;
            if app.router.selected_route >= app.router.routes.len() && !app.router.routes.is_empty()
            {
                app.router.selected_route = app.router.routes.len() - 1;
            }
        } else {
            topology_loaded = false;
        }
    }
    app.router.topology.loaded = topology_loaded;

    if !app.router.enabled && app.router.proposed_router_config.owned_routes.is_empty() {
        app.router.plan = None;
        app.router.lease_counts = Vec::new();
        return;
    }

    let proposal = current_router_proposal(app);
    match client.request(&Request::RouterPlan { proposal }).await {
        Ok(Response::RouterPlan { plan }) => {
            app.router.lease_counts = lease_counts_for_plan(client, &plan).await;
            app.router.plan = Some(plan);
        }
        Ok(Response::RouterError { detail }) => {
            app.router.error = Some(detail);
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
