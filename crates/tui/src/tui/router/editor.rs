use super::*;

pub(super) fn cycle_output_interface(editor: &mut RouteEditor, forward: bool) {
    let mut options = vec![None];
    for iface in &editor.available_interfaces {
        options.push(Some(iface.clone()));
    }
    let current_idx = options
        .iter()
        .position(|opt| opt == &editor.output_interface)
        .unwrap_or(0);
    let next_idx = if forward {
        (current_idx + 1) % options.len()
    } else {
        (current_idx + options.len() - 1) % options.len()
    };
    editor.output_interface = options[next_idx].clone();
}

pub(super) fn save_route_editor(app: &mut TuiApp) {
    let Some(ref mut editor) = app.router.editor else {
        return;
    };

    let dest_raw = editor.destination.trim();
    if dest_raw.is_empty() {
        app.push_message(LogLevel::Error, "Destination prefix is required");
        return;
    }
    let dest_str = if !dest_raw.contains('/') {
        format!("{dest_raw}/32")
    } else {
        dest_raw.to_string()
    };
    let destination: Ipv4Net = match dest_str.parse() {
        Ok(dest) => dest,
        Err(err) => {
            app.push_message(
                LogLevel::Error,
                format!("Invalid destination prefix: {err}"),
            );
            return;
        }
    };
    if destination.addr() != destination.network() {
        app.push_message(
            LogLevel::Error,
            format!(
                "Destination prefix {} has host bits set (did you mean {}?)",
                destination,
                destination.trunc()
            ),
        );
        return;
    }

    let gw_str = editor.gateway.trim();
    let gateway = if gw_str.is_empty() {
        None
    } else {
        match gw_str.parse::<Ipv4Addr>() {
            Ok(gw) => {
                if gw.is_unspecified() || gw.is_broadcast() || gw.is_multicast() {
                    app.push_message(
                        LogLevel::Error,
                        format!("Gateway cannot be unspecified, multicast, or broadcast: {gw}"),
                    );
                    return;
                }
                Some(gw)
            }
            Err(err) => {
                app.push_message(LogLevel::Error, format!("Invalid gateway IPv4: {err}"));
                return;
            }
        }
    };

    let output_interface = editor.output_interface.clone();
    if gateway.is_none() && output_interface.is_none() {
        app.push_message(
            LogLevel::Error,
            "At least one of gateway or output interface must be specified",
        );
        return;
    }

    let table_str = editor.table.trim();
    let table = match table_str.parse::<u32>() {
        Ok(255) => {
            app.push_message(
                LogLevel::Error,
                "Routing table 255 (local) is reserved by the kernel",
            );
            return;
        }
        Ok(t) if t > 0 => t,
        _ => {
            app.push_message(LogLevel::Error, "Routing table must be a positive integer");
            return;
        }
    };

    let metric_str = editor.metric.trim();
    let metric = if metric_str.is_empty() {
        None
    } else {
        match metric_str.parse::<u32>() {
            Ok(m) => Some(m),
            Err(err) => {
                app.push_message(LogLevel::Error, format!("Invalid metric: {err}"));
                return;
            }
        }
    };

    let allow_default = editor.allow_default_route_change;
    let original = editor.original_route.clone();

    let new_route = OwnedIpv4RouteConfig {
        destination,
        gateway,
        output_interface: output_interface.clone(),
        table,
        metric,
    };

    // Keep the proposal and editor intact until all validation succeeds.
    let original_index = original.as_ref().and_then(|orig| {
        app.router
            .proposed_router_config
            .owned_routes
            .iter()
            .position(|r| {
                r.table == orig.table
                    && r.destination.trunc() == orig.destination.trunc()
                    && r.metric.unwrap_or(0) == orig.metric.unwrap_or(0)
            })
    });

    // Check duplicate in proposed_router_config
    if app
        .router
        .proposed_router_config
        .owned_routes
        .iter()
        .enumerate()
        .any(|(index, r)| {
            Some(index) != original_index
                && r.table == new_route.table
                && r.destination.trunc() == new_route.destination.trunc()
                && r.metric.unwrap_or(0) == new_route.metric.unwrap_or(0)
        })
    {
        app.push_message(
            LogLevel::Error,
            format!(
                "destination prefix {} in table {} collides with existing route with identical metric {}",
                destination,
                table,
                metric.unwrap_or(0)
            ),
        );
        return;
    }

    // Check collision against external routes in current route list
    if app.router.routes.iter().any(|r| {
        !r.owner.is_editable()
            && r.table == new_route.table
            && r.destination.trunc() == new_route.destination.trunc()
            && r.metric.unwrap_or(0) == new_route.metric.unwrap_or(0)
    }) {
        app.push_message(
            LogLevel::Error,
            format!(
                "destination prefix {} in table {} collides with existing route with identical metric {}",
                destination,
                table,
                metric.unwrap_or(0)
            ),
        );
        return;
    }

    if let Some(index) = original_index {
        app.router.proposed_router_config.owned_routes.remove(index);
    }

    if destination.prefix_len() == 0 && allow_default {
        app.router.proposed_router_config.allow_default_route_change = true;
    }

    app.router
        .proposed_router_config
        .owned_routes
        .push(new_route.clone());

    if app.router.route_inventory.is_none() {
        // Update app.router.routes to reflect staged route in table:
        if let Some(ref orig) = original {
            if let Some(pos) = app.router.routes.iter().position(|r| {
                r.table == orig.table
                    && r.destination == orig.destination
                    && r.metric.unwrap_or(0) == orig.metric.unwrap_or(0)
            }) {
                app.router.routes.remove(pos);
            }
        }
        app.router.routes.push(RouteStatus {
            destination: new_route.destination,
            gateway: new_route.gateway,
            output_interface: new_route.output_interface,
            output_interface_index: None,
            table: new_route.table,
            metric: new_route.metric,
            protocol: traffic_masq_netlink::TRAFFIC_MASQ_ROUTE_PROTOCOL,
            scope: 0,
            owner: RouteOwner::TrafficMasqStatic,
        });
        // Sort routes deterministically:
        app.router.routes.sort_by(|a, b| {
            let table_order = |t: u32| match t {
                254 => 0,
                255 => 2,
                _ => 1,
            };
            table_order(a.table)
                .cmp(&table_order(b.table))
                .then_with(|| a.table.cmp(&b.table))
                .then_with(|| b.destination.prefix_len().cmp(&a.destination.prefix_len()))
                .then_with(|| a.destination.network().cmp(&b.destination.network()))
                .then_with(|| a.metric.unwrap_or(0).cmp(&b.metric.unwrap_or(0)))
        });
    }
    app.router.staged = true;
    app.router.editor = None;
    app.screen = Screen::Router;
    app.push_message(
        LogLevel::Info,
        format!("Route {destination} added to draft — not applied. Review / Apply to continue"),
    );
}

pub(super) fn delete_selected_route(app: &mut TuiApp) {
    let rows = app.router.route_rows();
    let Some(row) = rows.get(app.router.selected_route) else {
        return;
    };
    let Some(config) = row_config(row) else {
        return;
    };
    if row.configured.is_none() {
        let Some(route) = row.observed.as_ref() else {
            return;
        };
        let dhcp_advice = if route.owner == RouteOwner::TrafficMasqDhcp {
            let interface = route
                .output_interface
                .as_deref()
                .unwrap_or("the route's interface");
            if route.destination.prefix_len() == 0 {
                format!(
                    "This route is managed by the traffic-masq DHCP client.\n\
                     For a lasting change in the TUI: Router -> select this route -> Edit route, \
                     or DHCP Client -> select {interface} -> e / Enter \
                     (enable the DHCP Client tab in Settings if hidden).\n\
                     Set Install default route to false, choose Apply, then confirm the network change \
                     before its rollback timer expires. To change priority instead, edit Route metric.\n\n\
                     Manual deletion below changes only the live kernel route, not saved DHCP policy. \
                     It can disconnect you, has no automatic rollback, and the DHCP client may recreate it.\n\n"
                )
            } else {
                format!(
                    "This route is managed by the traffic-masq DHCP client.\n\
                     It is the local subnet route for the leased address; \
                     Install default route does not control it and there is no separate switch to disable it.\n\
                     For a lasting change, use Interfaces -> {interface} to configure a static IPv4 \
                     address (which disables DHCP), or turn Configure with traffic-masq off. \
                     Review Plan / Apply and confirm the network change. \
                     This also changes the leased address and can disconnect you.\n\n\
                     Manual deletion below changes only the live kernel route, not saved DHCP policy. \
                     It can disconnect you, has no automatic rollback, and the DHCP client may recreate it.\n\n"
                )
            }
        } else {
            String::new()
        };
        let message = match manual_route_delete_command(route) {
            Ok(command) => format!(
                "Delete route manually: {}\n\n\
                 {dhcp_advice}\
                 Run this command in a terminal on the machine running traffic-masqd:\n\n\
                 {command}\n\n\
                 To copy, hold down Shift\n\n\
                 traffic-masq only displays this command; it does not execute it.\n\
                 Removing this route can interrupt connections that use it.\n\
                 The kernel, DHCP client or network manager may recreate the route. \
                 For a lasting change, update the configuration that creates it.\n\n\
                 After running it, return to Router and choose Refresh.\n\n\
                 Esc: close",
                route.destination,
            ),
            Err(message) => format!("{dhcp_advice}{message}"),
        };
        app.push_message(LogLevel::Warn, message);
        app.message_scroll = 0;
        app.message_open = true;
        return;
    }
    let target_dest = config.destination;
    let target_table = config.table;
    let target_metric = config.metric.unwrap_or(0);
    if target_dest.prefix_len() == 0 {
        app.router.proposed_router_config.allow_default_route_change = true;
    }

    if let Some(pos) = app
        .router
        .proposed_router_config
        .owned_routes
        .iter()
        .position(|r| {
            r.table == target_table
                && r.destination.trunc() == target_dest.trunc()
                && r.metric.unwrap_or(0) == target_metric
        })
    {
        app.router.proposed_router_config.owned_routes.remove(pos);
    }
    if app.router.route_inventory.is_none() {
        app.router.routes.remove(app.router.selected_route);
    }
    app.router.staged = true;
    if app.router.selected_route >= app.router.route_rows().len()
        && !app.router.route_rows().is_empty()
    {
        app.router.selected_route = app.router.route_rows().len() - 1;
    }
    app.router.staged = true;
    app.router.warning_message = None;
    app.push_message(
        LogLevel::Info,
        format!("Removed route {target_dest} from proposed routes"),
    );
}

pub(super) fn manual_route_delete_command(route: &RouteStatus) -> Result<String, &'static str> {
    // Never drop a known output-interface constraint from a deletion command.
    if route.output_interface.is_none() && route.output_interface_index.is_some() {
        return Err("Cannot generate the command: the route's interface name is unavailable. Refresh the route list first.");
    }
    let mut command = format!("sudo ip -4 route del {}", route.destination);
    if let Some(gateway) = route.gateway {
        command.push_str(&format!(" via {gateway}"));
    }
    if let Some(interface) = &route.output_interface {
        // Interface names are data, including any shell metacharacters.
        let quoted = format!("'{}'", interface.replace('\'', "'\\''"));
        command.push_str(&format!(" dev {quoted}"));
    }
    command.push_str(&format!(
        " table {} metric {} proto {} scope {}",
        route.table,
        route.metric.unwrap_or(0),
        route.protocol,
        route.scope,
    ));
    Ok(command)
}

pub(super) async fn open_route_editor_for_selected(app: &mut TuiApp, client: &ApiClient) {
    let rows = app.router.route_rows();
    let Some(row) = rows.get(app.router.selected_route) else {
        return;
    };
    // DHCP routes are configured through the client policy, rather than by
    // replacing the observed kernel route with a static route.
    if let Some(interface) = row
        .observed
        .as_ref()
        .filter(|route| {
            route.owner == RouteOwner::TrafficMasqDhcp && route.destination.prefix_len() == 0
        })
        .and_then(|route| route.output_interface.clone())
    {
        super::super::dhcp_client_editor::open(app, client, interface).await;
        return;
    }
    let Some(orig) = row.configured.clone() else {
        app.router.warning_message =
            Some("Observed route is read-only; it has no saved intent".into());
        app.push_message(
            LogLevel::Warn,
            "Observed route is read-only; it has no saved intent",
        );
        return;
    };
    let mut available_interfaces = fetch_available_interfaces(app, client).await;
    if let Some(name) = &orig.output_interface {
        available_interfaces.push(name.clone());
    }
    available_interfaces.sort();
    available_interfaces.dedup();
    let dest_str = orig.destination.to_string();
    let cursor = super::super::input::grapheme_count(&dest_str);
    app.router.editor = Some(RouteEditor {
        original_route: Some(orig.clone()),
        destination: dest_str,
        gateway: orig.gateway.map(|g| g.to_string()).unwrap_or_default(),
        output_interface: orig.output_interface,
        metric: orig.metric.map(|m| m.to_string()).unwrap_or_default(),
        table: orig.table.to_string(),
        allow_default_route_change: orig.destination.prefix_len() == 0,
        field: RouteEditorField::Destination,
        cursor,
        available_interfaces,
    });
    app.router.warning_message = None;
    app.screen = Screen::RouteEditor;
}

pub(super) async fn open_route_editor_for_add(app: &mut TuiApp, client: &ApiClient) {
    let available_interfaces = fetch_available_interfaces(app, client).await;
    app.router.editor = Some(RouteEditor {
        original_route: None,
        destination: String::new(),
        gateway: String::new(),
        output_interface: None,
        metric: String::new(),
        table: "254".to_string(),
        allow_default_route_change: false,
        field: RouteEditorField::Destination,
        cursor: 0,
        available_interfaces,
    });
    app.router.warning_message = None;
    app.screen = Screen::RouteEditor;
}

pub(super) async fn fetch_available_interfaces(app: &TuiApp, client: &ApiClient) -> Vec<String> {
    if !app.router.saved_interfaces.is_empty() {
        return app
            .router
            .saved_interfaces
            .iter()
            .map(|entry| entry.name.clone())
            .collect();
    }
    if !app.dashboard.interfaces.is_empty() {
        return app
            .dashboard
            .interfaces
            .iter()
            .map(|i| i.interface.name.clone())
            .collect();
    }
    match client.request(&Request::ListInterfaces).await {
        Ok(Response::Interfaces { interfaces }) => {
            interfaces.into_iter().map(|i| i.interface.name).collect()
        }
        _ => Vec::new(),
    }
}

pub(crate) fn render_route_editor(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let Some(editor) = &app.router.editor else {
        return;
    };
    let title = if editor.original_route.is_some() {
        "Route Editor - Edit Route"
    } else {
        "Route Editor - Add Route"
    };
    let block = panel(title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let field = |label: &str, value: &str, active: bool| {
        let marker = if active { "▶ " } else { "  " };
        let style = if active {
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let mut spans = vec![Span::styled(format!("{marker}{:<32}: ", label), style)];
        spans.extend(super::super::input::render_value_with_cursor(
            value,
            editor.cursor,
            active,
            style,
        ));
        Line::from(spans)
    };

    let selector = |label: &str, value: &str, active: bool| {
        let marker = if active { "▶ " } else { "  " };
        let style = if active {
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        Line::styled(
            format!("{marker}{:<32}: < {} > (Space to cycle)", label, value),
            style,
        )
    };

    let toggle = |label: &str, val: bool, active: bool| {
        let marker = if active { "▶ " } else { "  " };
        let style = if active {
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let check = if val { "[x] Yes" } else { "[ ] No" };
        Line::styled(
            format!("{marker}{:<32}: {} (Space/Enter to toggle)", label, check),
            style,
        )
    };

    let action = |label: &str, active: bool| {
        let marker = if active { "▶ " } else { "  " };
        let style = if active {
            Style::default()
                .fg(theme::SELECTED_FG)
                .bg(theme::SELECTED_BG)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme::ACCENT)
        };
        Line::styled(format!("{marker}{label}"), style)
    };

    let iface_display = editor
        .output_interface
        .as_deref()
        .unwrap_or("none (gateway lookup)");

    let mut lines = vec![
        field(
            "Destination CIDR (e.g. 10.0.0.0/24)",
            &editor.destination,
            editor.field == RouteEditorField::Destination,
        ),
        field(
            "Gateway IPv4 (optional)",
            &editor.gateway,
            editor.field == RouteEditorField::Gateway,
        ),
        selector(
            "Output interface",
            iface_display,
            editor.field == RouteEditorField::OutputInterface,
        ),
        field(
            "Metric / Priority (optional)",
            &editor.metric,
            editor.field == RouteEditorField::Metric,
        ),
        field(
            "Routing table (main = 254)",
            &editor.table,
            editor.field == RouteEditorField::Table,
        ),
        toggle(
            "Allow default route change (0.0.0.0/0)",
            editor.allow_default_route_change,
            editor.field == RouteEditorField::AllowDefaultRouteChange,
        ),
        Line::from(""),
    ];

    let save_row = lines.len() as u16;
    let save_label = "[Save route]";
    app.ui.buttons.push((
        Rect {
            x: inner.x,
            y: inner.y + save_row,
            width: save_label.len() as u16 + 2,
            height: 1,
        },
        0,
    ));
    lines.push(action(save_label, editor.field == RouteEditorField::Save));

    lines.push(Line::from(""));
    lines.push(Line::styled(
        "Navigation: Tab/Down: next | BackTab/Up: prev | Space: toggle/cycle | Enter: save/next | Esc: cancel",
        Style::default().fg(theme::MUTED),
    ));

    frame.render_widget(Paragraph::new(lines), inner);
}

pub(crate) fn focus_route_editor_action(app: &mut TuiApp, _slot: usize) {
    if let Some(editor) = app.router.editor.as_mut() {
        editor.field = RouteEditorField::Save;
    }
}

pub(crate) async fn handle_route_editor_key(app: &mut TuiApp, key: KeyCode, _client: &ApiClient) {
    let Some(ref mut editor) = app.router.editor else {
        app.screen = Screen::Router;
        return;
    };

    match key {
        KeyCode::Esc => {
            app.router.editor = None;
            app.screen = Screen::Router;
        }
        KeyCode::Tab | KeyCode::Down => {
            editor.field = editor.field.next();
            editor.reset_cursor();
        }
        KeyCode::BackTab | KeyCode::Up => {
            editor.field = editor.field.prev();
            editor.reset_cursor();
        }
        KeyCode::Enter => match editor.field {
            RouteEditorField::Destination
            | RouteEditorField::Gateway
            | RouteEditorField::OutputInterface
            | RouteEditorField::Metric
            | RouteEditorField::Table => {
                editor.field = editor.field.next();
                editor.reset_cursor();
            }
            RouteEditorField::AllowDefaultRouteChange => {
                editor.allow_default_route_change = !editor.allow_default_route_change;
            }
            RouteEditorField::Save => {
                save_route_editor(app);
            }
        },
        KeyCode::Char(' ') => match editor.field {
            RouteEditorField::OutputInterface => {
                cycle_output_interface(editor, true);
            }
            RouteEditorField::AllowDefaultRouteChange => {
                editor.allow_default_route_change = !editor.allow_default_route_change;
            }
            RouteEditorField::Save => {
                save_route_editor(app);
            }
            RouteEditorField::Destination
            | RouteEditorField::Gateway
            | RouteEditorField::Metric
            | RouteEditorField::Table => {}
        },
        KeyCode::Left => match editor.field {
            RouteEditorField::OutputInterface => {
                cycle_output_interface(editor, false);
            }
            _ => {
                let mut text_ed = editor.active_editor();
                if let Some(ref mut ed) = text_ed {
                    ed.move_left();
                }
            }
        },
        KeyCode::Right => match editor.field {
            RouteEditorField::OutputInterface => {
                cycle_output_interface(editor, true);
            }
            _ => {
                let mut text_ed = editor.active_editor();
                if let Some(ref mut ed) = text_ed {
                    ed.move_right();
                }
            }
        },
        _ => {
            let field = editor.field;
            let mut text_ed = editor.active_editor();
            if let Some(ref mut ed) = text_ed {
                match field {
                    RouteEditorField::Destination => {
                        ed.handle_key_filtered(key, |c| c.is_ascii_digit() || c == '.' || c == '/');
                    }
                    RouteEditorField::Gateway => {
                        ed.handle_key_filtered(key, |c| c.is_ascii_digit() || c == '.');
                    }
                    RouteEditorField::Metric | RouteEditorField::Table => {
                        ed.handle_key_filtered(key, |c| c.is_ascii_digit());
                    }
                    _ => {}
                }
            }
        }
    }
}
