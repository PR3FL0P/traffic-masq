use super::*;

pub(super) fn format_owner_badge(owner: RouteOwner) -> Span<'static> {
    match owner {
        RouteOwner::TrafficMasqStatic => Span::styled(
            owner.to_string(),
            Style::default()
                .fg(theme::GOOD)
                .add_modifier(Modifier::BOLD),
        ),
        RouteOwner::TrafficMasqDhcp => {
            Span::styled(owner.to_string(), Style::default().fg(theme::ACCENT))
        }
        _ => Span::styled(owner.to_string(), Style::default().fg(theme::WARN)),
    }
}

pub(super) fn router_action_buttons(router: &RouterData) -> [(RouterAction, &'static str); 8] {
    let manual_delete = router
        .routes
        .get(router.selected_route)
        .is_some_and(|route| !route.owner.is_editable());
    [
        (RouterAction::AddRoute, "[Add route]"),
        (RouterAction::EditRoute, "[Edit route]"),
        (
            RouterAction::DeleteRoute,
            if manual_delete {
                "[Delete manually]"
            } else {
                "[Delete route]"
            },
        ),
        (RouterAction::PlanApply, "[Plan / Apply]"),
        (RouterAction::ShareViaRoute, "[Share via: n]"),
        (RouterAction::Refresh, "[Refresh]"),
        (RouterAction::Topology, "[Topology: t]"),
        (
            RouterAction::ToggleEnabled,
            if router.proposed_router_config.enabled {
                "[Disable routing: e]"
            } else {
                "[Enable routing: e]"
            },
        ),
    ]
}

pub(super) fn router_button_positions(
    buttons: &[(RouterAction, &str)],
    width: u16,
) -> Vec<(u16, u16)> {
    let (mut x, mut y) = (0, 0);
    buttons
        .iter()
        .map(|(_, label)| {
            let length = label.len() as u16;
            if x > 0 && x + length > width {
                x = 0;
                y += 1;
            }
            let position = (x, y);
            x += length + 2;
            position
        })
        .collect()
}

pub(crate) fn render_router(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let sections = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).split(area);
    app.router.pane_tabs.clear();
    let mut x = sections[0].x;
    for (label, pane) in [
        ("[1 Routes]", RouterPane::Routes),
        ("[2 Internet sharing]", RouterPane::Sharing),
        ("[3 Topology]", RouterPane::Topology),
    ] {
        let rect = Rect::new(x, sections[0].y, label.len() as u16, 1);
        app.router.pane_tabs.push((rect, pane));
        frame.render_widget(
            Paragraph::new(label).style(if app.router.pane == pane {
                Style::default()
                    .fg(theme::SELECTED_FG)
                    .bg(theme::SELECTED_BG)
            } else {
                Style::default().fg(theme::MUTED)
            }),
            rect,
        );
        x += rect.width + 1;
    }
    let area = sections[1];
    if app.router.pane == RouterPane::Sharing {
        super::super::forwarding::render_list(frame, area, app);
        return;
    }
    if app.router.topology.open {
        router_topology::render(frame, area, app, true);
        return;
    }
    let area = if area.width >= 112 {
        let columns = Layout::horizontal([Constraint::Length(30), Constraint::Min(82)]).split(area);
        router_topology::render(frame, columns[0], app, false);
        columns[1]
    } else {
        area
    };
    let router = &app.router;

    let mut status_lines = vec![Line::from(vec![
        Span::styled("Ready: ", Style::default().fg(theme::MUTED)),
        Span::styled(
            format!("{:<6}", router.ready),
            Style::default().fg(if router.ready {
                theme::GOOD
            } else {
                theme::WARN
            }),
        ),
        Span::raw(" | "),
        Span::styled("Enabled: ", Style::default().fg(theme::MUTED)),
        Span::styled(
            format!("{:<6}", router.enabled),
            Style::default().fg(if router.enabled {
                theme::GOOD
            } else {
                theme::MUTED
            }),
        ),
        Span::raw(" | "),
        Span::styled("Coordinator: ", Style::default().fg(theme::MUTED)),
        Span::styled(
            router
                .coordinator_status
                .map(format_coordinator_status)
                .unwrap_or("unknown"),
            Style::default().fg(theme::TEXT),
        ),
    ])];

    if let Some(plan) = &router.plan {
        status_lines.push(Line::from(vec![
            Span::styled("Uplink: ", Style::default().fg(theme::MUTED)),
            Span::styled(
                summarize_uplink(&plan.dataplane.target),
                Style::default().fg(theme::TEXT),
            ),
            Span::raw(" | "),
            Span::styled("Forwarding: ", Style::default().fg(theme::MUTED)),
            Span::styled(
                format_forwarding_status(&plan.dataplane),
                Style::default().fg(theme::TEXT),
            ),
        ]));
    }

    if router.staged {
        status_lines.push(Line::styled(
            format!(
                "Staged configuration: {} owned route(s); review all changes with [Plan / Apply]",
                router.proposed_router_config.owned_routes.len()
            ),
            Style::default()
                .fg(theme::WARN)
                .add_modifier(Modifier::BOLD),
        ));
    }

    for (subsystem, detail) in health_report_details(&router.health) {
        status_lines.push(Line::styled(
            format!("  {subsystem}: {detail}"),
            Style::default().fg(theme::BAD),
        ));
    }

    if let Some(detail) = &router.error {
        status_lines.push(Line::styled(
            format!("Error: {}", describe_router_error(detail)),
            Style::default().fg(theme::BAD).add_modifier(Modifier::BOLD),
        ));
    }

    let buttons = router_action_buttons(router);
    let button_positions = router_button_positions(&buttons, area.width.saturating_sub(2));
    let base_actions_height = button_positions.last().map_or(0, |(_, y)| y + 1) + 2;
    let warning_rows =
        u16::from(router.warning_message.is_some() && area.height >= base_actions_height + 4);
    let actions_height = base_actions_height + warning_rows;
    let status_height = (status_lines.len() as u16 + 2)
        .clamp(3, 8)
        .min(area.height.saturating_sub(actions_height + 3));

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(status_height),
            Constraint::Min(3),
            Constraint::Length(actions_height),
        ])
        .split(area);

    let status_block = panel("Router Status");
    let status_inner = status_block.inner(chunks[0]);
    frame.render_widget(status_block, chunks[0]);
    frame.render_widget(Paragraph::new(status_lines), status_inner);

    let table_title = match router.focus {
        RouterFocus::RouteTable => "Routes | n: share via selected interface; Tab: actions",
        RouterFocus::Actions => "Routes [Esc/Tab: focus table]",
    };
    let table_block = panel(table_title);
    let table_inner = table_block.inner(chunks[1]);
    frame.render_widget(table_block, chunks[1]);

    let headers = [
        "",
        "Destination",
        "Gateway",
        "Interface",
        "Metric",
        "Table",
        "Owner",
    ];
    let route_cells: Vec<_> = router
        .routes
        .iter()
        .map(|route| {
            [
                route.destination.to_string(),
                route
                    .gateway
                    .map(|g| g.to_string())
                    .unwrap_or_else(|| "direct".into()),
                route.output_interface.clone().unwrap_or_else(|| "-".into()),
                route
                    .metric
                    .map(|m| m.to_string())
                    .unwrap_or_else(|| "-".into()),
                match route.table {
                    254 => "main (254)".into(),
                    255 => "local (255)".into(),
                    table => table.to_string(),
                },
            ]
        })
        .collect();
    // Measure all routes so columns stay aligned while scrolling, including
    // long interface names and the full range of metric/table values.
    let mut widths = vec![Constraint::Length(1)];
    for column in 0..5 {
        let width = route_cells
            .iter()
            .map(|cells| Span::raw(cells[column].as_str()).width())
            .max()
            .unwrap_or(0)
            .max(headers[column + 1].len());
        widths.push(Constraint::Length(width as u16));
    }
    widths.push(Constraint::Min(5));
    let header = Row::new(headers).style(
        Style::default()
            .fg(theme::MUTED)
            .add_modifier(Modifier::BOLD),
    );
    let mut rows = Vec::new();

    let header_offset = 1;
    let available_rows = table_inner.height.saturating_sub(header_offset as u16) as usize;
    let scroll = if router.selected_route >= available_rows && available_rows > 0 {
        router.selected_route.saturating_sub(available_rows - 1)
    } else {
        0
    };

    app.ui.list_area = Some(Rect::new(
        table_inner.x,
        table_inner.y.saturating_add(header_offset as u16),
        table_inner.width,
        table_inner.height.saturating_sub(header_offset as u16),
    ));
    app.ui.list_row_height = 1;
    app.ui.list_count = router.routes.len();
    app.ui.list_scroll_offset = scroll;

    if !router.routes.is_empty() {
        for (index, route) in router
            .routes
            .iter()
            .enumerate()
            .skip(scroll)
            .take(available_rows)
        {
            let is_selected = index == router.selected_route;
            let marker = if is_selected { "▶" } else { " " };
            let mut style = if !route.owner.is_owned() {
                Style::default().fg(theme::WARN)
            } else if is_selected {
                Style::default().fg(theme::ACCENT)
            } else {
                Style::default()
            };
            if is_selected && router.focus == RouterFocus::RouteTable {
                style = style.add_modifier(Modifier::BOLD);
            }
            let mut cells = vec![Cell::from(marker)];
            cells.extend(
                route_cells[index]
                    .iter()
                    .map(|value| Cell::from(value.as_str())),
            );
            cells.push(Cell::from(format_owner_badge(route.owner)));
            rows.push(Row::new(cells).style(style));
        }
    }
    frame.render_widget(
        Table::new(rows, widths).header(header).column_spacing(2),
        table_inner,
    );
    if router.routes.is_empty() {
        frame.render_widget(
            Paragraph::new("   No routes found.").style(Style::default().fg(theme::MUTED)),
            app.ui.list_area.unwrap(),
        );
    }

    let actions_block = panel("Actions | Arrows: move; Enter: activate; Esc/Tab: routes");
    let actions_inner = actions_block.inner(chunks[2]);
    frame.render_widget(actions_block, chunks[2]);

    if let Some(ref warn) = router.warning_message.as_ref().filter(|_| warning_rows > 0) {
        frame.render_widget(
            Paragraph::new(format!("⚠ {warn}")).style(
                Style::default()
                    .fg(theme::WARN)
                    .add_modifier(Modifier::BOLD),
            ),
            Rect::new(
                actions_inner.x,
                actions_inner.y,
                actions_inner.width,
                actions_inner.height.min(1),
            ),
        );
    }

    for (slot, ((action, label), (x, y))) in buttons.iter().zip(button_positions).enumerate() {
        let is_active = router.focus == RouterFocus::Actions && router.action == *action;
        let style = if is_active {
            Style::default()
                .fg(theme::SELECTED_FG)
                .bg(theme::SELECTED_BG)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme::ACCENT)
        };

        let rect = Rect::new(
            actions_inner.x + x,
            actions_inner.y + warning_rows + y,
            label.len() as u16,
            1,
        )
        .intersection(actions_inner);
        if !rect.is_empty() {
            app.ui.buttons.push((rect, slot));
            frame.render_widget(Paragraph::new(*label).style(style), rect);
        }
    }
}

pub(super) fn health_report_details(health: &RouterHealthReport) -> Vec<(&'static str, String)> {
    let mut details = Vec::new();
    if let Some(detail) = &health.interfaces {
        details.push(("interfaces", detail.clone()));
    }
    if let Some(detail) = &health.routes {
        details.push(("routes", detail.clone()));
    }
    if let Some(detail) = &health.dhcp {
        details.push(("dhcp", detail.clone()));
    }
    if let Some(detail) = &health.uplink_dhcp {
        details.push(("uplink DHCP", format!("{detail:?}")));
    }
    if let Some(detail) = &health.dataplane {
        details.push(("dataplane", detail.clone()));
    }
    details
}

pub(super) fn format_coordinator_status(status: CoordinatorStatus) -> &'static str {
    match status {
        CoordinatorStatus::Idle => "idle",
        CoordinatorStatus::Pending => "pending",
        CoordinatorStatus::RollbackFailed => "rollback failed (recovery required)",
    }
}

pub(super) fn summarize_uplink(target: &RouterDataplaneTarget) -> String {
    match target {
        RouterDataplaneTarget::Enabled(desired) => {
            if desired.forwarding.is_some() {
                "per-connection".into()
            } else {
                desired.uplink.clone()
            }
        }
        RouterDataplaneTarget::Disabled => "none (dataplane disabled)".to_string(),
    }
}

pub(super) fn format_forwarding_status(dataplane: &crate::firewall::RouterDataplanePlan) -> String {
    let forwarding = if dataplane.snapshot.ipv4_forwarding {
        "forwarding on"
    } else {
        "forwarding off"
    };
    let nat = match &dataplane.target {
        RouterDataplaneTarget::Enabled(desired)
            if desired
                .forwarding
                .as_ref()
                .is_none_or(|rules| rules.iter().any(|rule| rule.masquerade)) =>
        {
            "NAT desired"
        }
        RouterDataplaneTarget::Enabled(_) => "NAT disabled",
        RouterDataplaneTarget::Disabled => "NAT disabled",
    };
    let apply = if dataplane.requires_apply {
        "drift: requires apply"
    } else {
        "in sync"
    };
    format!("{forwarding}, {nat}, {apply}")
}

pub(super) fn describe_router_error(detail: &RouterErrorDetail) -> String {
    match detail {
        RouterErrorDetail::RouterDisabled => {
            "Router has no committed intent yet; configure Forwarding / NAT".to_string()
        }
        RouterErrorDetail::TransactionPending => {
            "Another router transaction is already pending; commit or roll it back first"
                .to_string()
        }
        RouterErrorDetail::RollbackRecoveryRequired => {
            "A previous rollback failed; the coordinator needs recovery before a new transaction"
                .to_string()
        }
        RouterErrorDetail::StaleCandidate {
            candidate_revision,
            current_revision,
        } => format!(
            "Candidate is stale: built from revision {candidate_revision}, current is {current_revision}"
        ),
        RouterErrorDetail::StalePlan => {
            "Observed system state drifted between plan and apply; re-plan and retry".to_string()
        }
        RouterErrorDetail::NoPendingTransaction => {
            "There is no pending router transaction to commit or roll back".to_string()
        }
        RouterErrorDetail::RollbackFailed { failures } => {
            format!("Rollback failed: {}", failures.join("; "))
        }
        RouterErrorDetail::Other { message } => message.clone(),
    }
}
