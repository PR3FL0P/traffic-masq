use super::*;

pub(super) fn current_router_proposal(app: &TuiApp) -> RouterProposalRequest {
    RouterProposalRequest {
        set_router: Some(app.router.proposed_router_config.clone()),
        ..Default::default()
    }
}

pub(super) async fn lease_counts_for_plan(
    client: &ApiClient,
    services: &[DhcpServiceView],
) -> Vec<(String, usize)> {
    let mut counts = Vec::with_capacity(services.len());
    for dhcp in services {
        if let Ok(Response::Leases { interface, leases }) = client
            .request(&Request::ListLeases {
                interface: dhcp.interface.clone(),
            })
            .await
        {
            if interface == dhcp.interface {
                counts.push((interface, leases.len()));
            }
        }
    }
    counts
}

pub(super) fn resolve_ifindex_name(app: &TuiApp, index: Option<u32>) -> Option<String> {
    let index = index?;
    app.dashboard
        .interfaces
        .iter()
        .find(|i| i.interface.index == index)
        .map(|i| i.interface.name.clone())
        .or_else(|| Some(format!("oif:{index}")))
}

pub(crate) fn render_router_plan(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    if let Some(preview) = &app.router.offline_preview {
        let mut lines = vec![
            Line::from(format!(
                "Save router intent at revision {}",
                preview.revision
            )),
            Line::from("Saved settings will wait for dependencies; no new rules are applied."),
        ];
        for blocker in &preview.blockers {
            lines.push(Line::from(match blocker {
                traffic_masq_protocol::InterfaceReadinessBlocker::MissingInterface {
                    interface,
                } => format!("Waiting for interface: {interface}"),
                traffic_masq_protocol::InterfaceReadinessBlocker::ObservationFailed { message } => {
                    format!("Observation unknown: {message}")
                }
            }));
        }
        lines.push(Line::from(format!(
            "Routing: {}",
            if preview.config.enabled {
                "enabled"
            } else {
                "disabled"
            }
        )));
        let route_lines = |label: &str, route: &OwnedIpv4RouteConfig| {
            vec![
                Line::from(format!(
                    "{label}: {} via {}",
                    route.destination,
                    route
                        .gateway
                        .map_or("direct".into(), |gateway| gateway.to_string())
                )),
                Line::from(format!(
                    "  dev {} table {} metric {}",
                    route.output_interface.as_deref().unwrap_or("-"),
                    route.table,
                    route.metric.unwrap_or(0)
                )),
            ]
        };
        for route in &preview.config.owned_routes {
            lines.extend(route_lines("Saved route", route));
        }
        for route in &preview.baseline.owned_routes {
            if !preview.config.owned_routes.contains(route) {
                lines.extend(route_lines("Removed route", route));
            }
        }
        for rule in preview.config.forwarding.as_deref().unwrap_or(&[]) {
            lines.push(Line::from(format!(
                "Share: {} → {} ({})",
                rule.from,
                rule.to,
                if rule.masquerade { "NAT" } else { "no NAT" }
            )));
            lines.push(Line::from(format!(
                "  source {}",
                rule.source_subnet
                    .map_or("any".into(), |subnet| subnet.to_string())
            )));
        }
        for rule in preview.baseline.forwarding.as_deref().unwrap_or(&[]) {
            if !preview
                .config
                .forwarding
                .as_deref()
                .unwrap_or(&[])
                .contains(rule)
            {
                lines.push(Line::from(format!(
                    "Removed share: {} → {}",
                    rule.from, rule.to
                )));
            }
        }
        if preview.baseline.forwarding.is_none()
            && preview.config.forwarding.is_some()
            && preview.baseline.uplink.is_some()
        {
            lines.push(Line::from("Legacy sharing will use explicit saved rules."));
        }
        if preview.config.allow_default_route_change {
            lines.push(Line::styled(
                "Default route changes are permitted.",
                Style::default().fg(theme::WARN),
            ));
        }
        lines.push(Line::from("Removed owned rules are cleaned up after Save."));
        lines.push(Line::from("Esc: cancel | Enter at end: Save intent"));
        let block = panel("Saved router intent preview");
        let inner = block.inner(area);
        frame.render_widget(block, area);
        app.router.plan_max_scroll = lines.len().saturating_sub(inner.height.max(1) as usize);
        app.router.plan_scroll = app.router.plan_scroll.min(app.router.plan_max_scroll);
        frame.render_widget(
            Paragraph::new(lines).scroll((app.router.plan_scroll.min(u16::MAX as usize) as u16, 0)),
            inner,
        );
        return;
    }
    let Some(plan) = &app.router.plan else {
        return;
    };
    let mut lines = vec![
        Line::from(format!(
            "Routing: {}",
            if plan.desired.enabled {
                "enabled"
            } else {
                "disabled"
            }
        )),
        Line::from(format!(
            "Uplink: {}",
            summarize_uplink(&plan.dataplane.target)
        )),
    ];
    if let RouterDataplaneTargetView::Enabled(desired) = &plan.dataplane.target {
        if let Some(connections) = &desired.forwarding {
            for connection in connections {
                lines.push(Line::from(format!(
                    "Share: {} → {} ({}, source {})",
                    connection.from,
                    connection.to,
                    if connection.masquerade {
                        "masquerade"
                    } else {
                        "no NAT"
                    },
                    connection
                        .source_subnet
                        .map_or("any".into(), |subnet| subnet.to_string())
                )));
            }
        }
    }
    for line in summarize_output_interfaces(&plan.desired.interfaces) {
        lines.push(Line::from(format!("Output: {line}")));
    }
    for line in summarize_dhcp(&plan.desired.dhcp, &app.router.lease_counts) {
        lines.push(Line::from(format!("DHCP: {line}")));
    }
    for line in super::super::router_settings::plan_lines(
        &app.router.proposed_router_config,
        app.router.saved_router_config.as_ref(),
    ) {
        lines.extend(
            super::super::logs::wrap_log_message(
                &line,
                area.width.saturating_sub(2).max(1) as usize,
            )
            .into_iter()
            .map(Line::from),
        );
    }
    lines.push(Line::from(format!(
        "Interface changes: {}",
        plan.interfaces.len()
    )));
    lines.push(Line::from(format!(
        "Route changes: add={} delete={}",
        plan.routes.add.len(),
        plan.routes.delete.len()
    )));
    for route in &plan.routes.add {
        let gw = route
            .gateway
            .map(|g| format!(" via {g}"))
            .unwrap_or_default();
        let iface = resolve_ifindex_name(app, route.output_interface_index)
            .map(|i| format!(" dev {i}"))
            .unwrap_or_default();
        let metric = route
            .metric
            .map(|m| format!(" metric {m}"))
            .unwrap_or_default();
        lines.push(Line::styled(
            format!(
                "  + {}{gw}{iface}{metric} (table {})",
                route.destination, route.table
            ),
            Style::default().fg(theme::GOOD),
        ));
    }
    for route in &plan.routes.delete {
        let gw = route
            .gateway
            .map(|g| format!(" via {g}"))
            .unwrap_or_default();
        let iface = resolve_ifindex_name(app, route.output_interface_index)
            .map(|i| format!(" dev {i}"))
            .unwrap_or_default();
        let metric = route
            .metric
            .map(|m| format!(" metric {m}"))
            .unwrap_or_default();
        lines.push(Line::styled(
            format!(
                "  - {}{gw}{iface}{metric} (table {})",
                route.destination, route.table
            ),
            Style::default().fg(theme::BAD),
        ));
    }
    lines.push(Line::from(format!(
        "Forwarding/NAT: {}",
        format_forwarding_status(&plan.dataplane)
    )));
    if plan.risk.changes_default_route {
        lines.push(Line::styled(
            "WARNING: this plan changes the default route",
            Style::default().fg(theme::BAD).add_modifier(Modifier::BOLD),
        ));
    }
    if plan.risk.requires_management_confirmation {
        lines.push(Line::styled(
            "WARNING: this plan touches the outside-router interface",
            Style::default().fg(theme::BAD).add_modifier(Modifier::BOLD),
        ));
    }
    for warning in ap_without_dhcp_warnings(&plan.desired) {
        lines.push(Line::styled(
            format!("WARNING: {warning}"),
            Style::default().fg(theme::WARN),
        ));
    }
    lines.push(Line::styled(
        "Applying starts an automatic rollback timer.",
        Style::default().fg(theme::WARN),
    ));
    lines.push(Line::from(""));

    let block = panel("Router plan preview");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let cancel_row = lines.len();
    lines.push(Line::styled(
        ROUTER_CANCEL_LABEL,
        Style::default().fg(theme::ACCENT),
    ));
    let apply_row = lines.len();
    lines.push(Line::styled(
        ROUTER_APPLY_LABEL,
        Style::default()
            .fg(theme::SELECTED_FG)
            .bg(theme::SELECTED_BG)
            .add_modifier(Modifier::BOLD),
    ));

    let visible_rows = inner.height.max(1) as usize;
    app.router.plan_max_scroll = lines.len().saturating_sub(visible_rows);
    app.router.plan_scroll = app.router.plan_scroll.min(app.router.plan_max_scroll);
    let offset = app.router.plan_scroll;

    if cancel_row >= offset && cancel_row < offset.saturating_add(visible_rows) {
        app.ui.buttons.push((
            Rect {
                x: inner.x,
                y: inner.y + (cancel_row - offset) as u16,
                width: (ROUTER_CANCEL_LABEL.len() as u16).min(inner.width),
                height: 1,
            },
            1,
        ));
    }
    if apply_row >= offset && apply_row < offset.saturating_add(visible_rows) {
        app.ui.buttons.push((
            Rect {
                x: inner.x,
                y: inner.y + (apply_row - offset) as u16,
                width: (ROUTER_APPLY_LABEL.len() as u16).min(inner.width),
                height: 1,
            },
            0,
        ));
    }

    frame.render_widget(
        Paragraph::new(lines).scroll((offset.min(u16::MAX as usize) as u16, 0)),
        inner,
    );
}

pub(super) fn summarize_output_interfaces(
    interfaces: &[RouterInterfaceDesiredView],
) -> Vec<String> {
    interfaces
        .iter()
        .filter(|interface| interface.config.role == InterfaceRole::Output)
        .map(|interface| {
            let subnet = interface
                .config
                .ipv4
                .map(|network| network.to_string())
                .unwrap_or_else(|| "no ipv4".to_string());
            format!("{} ({subnet})", interface.name)
        })
        .collect()
}

pub(super) fn summarize_dhcp(
    dhcp: &[traffic_masq_protocol::DhcpServiceView],
    lease_counts: &[(String, usize)],
) -> Vec<String> {
    dhcp.iter()
        .map(|spec| {
            let leases = lease_counts
                .iter()
                .find(|(interface, _)| interface == &spec.interface)
                .map(|(_, count)| *count);
            match leases {
                Some(count) => format!(
                    "{} pool {}-{} ({count} lease(s))",
                    spec.interface, spec.pool_start, spec.pool_end
                ),
                None => format!(
                    "{} pool {}-{} (lease count unavailable)",
                    spec.interface, spec.pool_start, spec.pool_end
                ),
            }
        })
        .collect()
}

pub(super) fn ap_without_dhcp_warnings(desired: &RouterDesiredView) -> Vec<String> {
    desired
        .interfaces
        .iter()
        .filter(|iface| iface.config.role == InterfaceRole::Output && iface.config.wifi.is_some())
        .filter(|iface| !desired.dhcp.iter().any(|spec| spec.interface == iface.name))
        .map(|iface| {
            format!(
                "{} has an access point configured but no DHCP server running on it — clients won't get an automatic IP",
                iface.name
            )
        })
        .collect()
}

pub(crate) async fn open_router_plan(app: &mut TuiApp, client: &ApiClient) {
    app.router.offline_preview = None;
    let proposal = current_router_proposal(app);
    match client
        .request(&Request::RouterIntentPreview { proposal })
        .await
    {
        Ok(Response::RouterIntentPreview {
            revision,
            config,
            device_readiness,
            blockers,
            execution_available,
            ..
        }) => {
            if app
                .router
                .editor_revision
                .is_some_and(|editor_revision| editor_revision != revision)
            {
                app.push_message(LogLevel::Error, "Router configuration changed while editing; draft retained. Press c in Router to discard and reload before saving.");
                return;
            }
            if device_readiness == traffic_masq_protocol::InterfaceReadiness::Unknown {
                app.push_message(LogLevel::Error, "Device observation is unknown; router draft retained. Retry preview after observation recovers.");
                return;
            }
            if !execution_available
                || device_readiness == traffic_masq_protocol::InterfaceReadiness::WaitingDevice
                || app.router.saved_device_readiness
                    == Some(traffic_masq_protocol::InterfaceReadiness::WaitingDevice)
            {
                let Some(editor_revision) = app.router.editor_revision else {
                    app.push_message(
                        LogLevel::Error,
                        "Load saved router configuration and its revision before saving.",
                    );
                    return;
                };
                app.router.offline_preview = Some(OfflineRouterPreview {
                    baseline: app
                        .router
                        .saved_router_config
                        .clone()
                        .unwrap_or_else(|| app.router.proposed_router_config.clone()),
                    config,
                    revision: editor_revision,
                    blockers,
                });
                app.router.plan = None;
                app.router.plan_scroll = 0;
                app.router.plan_max_scroll = 0;
                app.screen = Screen::RouterPlan;
                return;
            }
        }
        Ok(Response::RouterError { detail }) => {
            app.push_message(LogLevel::Error, describe_router_error(&detail));
            return;
        }
        Ok(response) => {
            app.push_message(
                LogLevel::Error,
                format!("Could not preview router intent: {response:?}"),
            );
            return;
        }
        Err(error) => {
            app.push_message(LogLevel::Error, error.to_string());
            return;
        }
    }
    let proposal = current_router_proposal(app);
    match client.request(&Request::RouterPlan { proposal }).await {
        Ok(Response::RouterPlan { plan }) => {
            app.router.lease_counts = lease_counts_for_plan(client, &plan.desired.dhcp).await;
            app.router.plan = Some(plan);
            app.router.plan_scroll = 0;
            app.router.plan_max_scroll = 0;
            app.screen = Screen::RouterPlan;
        }
        Ok(Response::RouterError { detail }) => {
            app.router.error = Some(detail.clone());
            app.push_message(LogLevel::Error, describe_router_error(&detail));
        }
        Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
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

pub(crate) async fn handle_router_plan_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    const PAGE: usize = 10;
    match key {
        KeyCode::Esc => app.screen = Screen::Router,
        KeyCode::Up | KeyCode::Char('k') => {
            app.router.plan_scroll = app.router.plan_scroll.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.router.plan_scroll = app
                .router
                .plan_scroll
                .saturating_add(1)
                .min(app.router.plan_max_scroll);
        }
        KeyCode::PageUp => {
            app.router.plan_scroll = app.router.plan_scroll.saturating_sub(PAGE);
        }
        KeyCode::PageDown => {
            app.router.plan_scroll = app
                .router
                .plan_scroll
                .saturating_add(PAGE)
                .min(app.router.plan_max_scroll);
        }
        KeyCode::Home => app.router.plan_scroll = 0,
        KeyCode::End => app.router.plan_scroll = app.router.plan_max_scroll,
        KeyCode::Enter if app.router.plan_scroll >= app.router.plan_max_scroll => {
            router_apply_current_plan(app, client).await;
        }
        KeyCode::Enter => app.push_message(
            LogLevel::Warn,
            "Review the complete router plan before applying; scroll to the end first.",
        ),
        _ => {}
    }
}

async fn router_apply_current_plan(app: &mut TuiApp, client: &ApiClient) {
    if let Some(preview) = app.router.offline_preview.clone() {
        let saved_config = preview.config.clone();
        match client
            .request(&Request::SaveRouterIntent {
                config: preview.config,
                expected_revision: preview.revision,
            })
            .await
        {
            Ok(Response::RouterIntentSaved {
                revision,
                missing_dependencies,
                cleanup_blockers,
                execution_available,
                ..
            }) => {
                app.router.saved_router_config = Some(saved_config.clone());
                app.router.proposed_router_config = saved_config.clone();
                app.router.route_inventory = Some(
                    saved_config
                        .owned_routes
                        .iter()
                        .map(|config| traffic_masq_protocol::RouteInventoryEntry {
                            configured: Some(config.clone()),
                            observed: None,
                            output_presence: config
                                .output_interface
                                .as_ref()
                                .map(|_| traffic_masq_protocol::InterfacePresence::Unknown),
                        })
                        .collect(),
                );
                app.router.routes.clear();
                app.router.observation_error =
                    Some("Runtime observation pending after Save".into());
                app.router.desired_revision = Some(revision);
                app.router.staged = false;
                app.router.offline_preview = None;
                app.router.editor_revision = Some(revision);
                app.screen = Screen::Router;
                let waiting = if !missing_dependencies.is_empty() {
                    format!("waiting for {}", missing_dependencies.join(", "))
                } else if !execution_available {
                    "execution unavailable".into()
                } else {
                    "application deferred".into()
                };
                super::controller::load_router_data(app, client).await;
                app.push_message(
                    LogLevel::Info,
                    format!("Saved router intent revision {revision}; {waiting}"),
                );
                for blocker in cleanup_blockers {
                    app.push_message(
                        LogLevel::Warn,
                        format!("Saved; cleanup incomplete: {blocker}"),
                    );
                }
            }
            Ok(Response::RouterError { detail }) => {
                app.push_message(LogLevel::Error, describe_router_error(&detail))
            }
            Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
            Ok(response) => app.push_message(
                LogLevel::Error,
                format!("Unexpected Save response: {response:?}"),
            ),
            Err(error) => app.push_message(LogLevel::Error, error.to_string()),
        }
        return;
    }
    let proposal = current_router_proposal(app);
    match client.request(&Request::RouterApply { proposal }).await {
        Ok(Response::RouterTransactionPending { token, .. }) => {
            app.router_pending = Some(RouterPendingView {
                token,
                applied_at_unix: current_unix_time(),
                rollback_failure: None,
                recovery: None,
                scroll: 0,
                max_scroll: 0,
            });
            app.screen = Screen::RouterPending;
        }
        Ok(Response::RouterError { detail }) => {
            app.push_message(LogLevel::Error, describe_router_error(&detail));
        }
        Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}
