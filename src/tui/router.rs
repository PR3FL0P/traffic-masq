use std::net::Ipv4Addr;

use crossterm::event::KeyCode;
use ipnet::Ipv4Net;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Gauge, Paragraph, Row, Table};

use crate::api::client::ApiClient;
use crate::api::model::{Request, Response, RouteStatus, RouterErrorDetail, RouterProposalRequest};
use crate::config::{InterfaceRole, OwnedIpv4RouteConfig, RouterConfig};
use crate::core::router::{RouterDesired, RouterHealthReport, RouterInterfaceDesired, RouterPlan};
use crate::core::router_transaction::CoordinatorStatus;
use crate::dhcp::supervisor::DhcpServiceSpec;
use crate::firewall::RouterDataplaneTarget;
use crate::netlink::RouteOwner;

use super::layout::panel;
use super::logs::LogLevel;
use super::theme;
use super::{current_unix_time, Screen, TuiApp};

#[derive(Debug, Default, Clone)]
pub(crate) struct RouterData {
    pub(crate) enabled: bool,
    pub(crate) ready: bool,
    pub(crate) coordinator_status: Option<CoordinatorStatus>,
    pub(crate) health: RouterHealthReport,
    pub(crate) routes: Vec<RouteStatus>,
    pub(crate) selected_route: usize,
    pub(crate) proposed_router_config: RouterConfig,
    pub(crate) staged: bool,
    pub(crate) plan: Option<RouterPlan>,
    pub(crate) editor: Option<RouteEditor>,
    pub(crate) focus: RouterFocus,
    pub(crate) action: RouterAction,
    pub(crate) lease_counts: Vec<(String, usize)>,
    pub(crate) error: Option<RouterErrorDetail>,
    pub(crate) warning_message: Option<String>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouterFocus {
    #[default]
    RouteTable,
    Actions,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouterAction {
    #[default]
    AddRoute,
    EditRoute,
    DeleteRoute,
    PlanApply,
    Provision,
    Refresh,
}

impl RouterAction {
    pub(crate) fn next(self) -> Self {
        match self {
            Self::AddRoute => Self::EditRoute,
            Self::EditRoute => Self::DeleteRoute,
            Self::DeleteRoute => Self::PlanApply,
            Self::PlanApply => Self::Provision,
            Self::Provision => Self::Refresh,
            Self::Refresh => Self::AddRoute,
        }
    }

    pub(crate) fn prev(self) -> Self {
        match self {
            Self::AddRoute => Self::Refresh,
            Self::EditRoute => Self::AddRoute,
            Self::DeleteRoute => Self::EditRoute,
            Self::PlanApply => Self::DeleteRoute,
            Self::Provision => Self::PlanApply,
            Self::Refresh => Self::Provision,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteEditorField {
    #[default]
    Destination,
    Gateway,
    OutputInterface,
    Metric,
    Table,
    AllowDefaultRouteChange,
    Save,
}

impl RouteEditorField {
    pub(crate) fn next(self) -> Self {
        match self {
            Self::Destination => Self::Gateway,
            Self::Gateway => Self::OutputInterface,
            Self::OutputInterface => Self::Metric,
            Self::Metric => Self::Table,
            Self::Table => Self::AllowDefaultRouteChange,
            Self::AllowDefaultRouteChange => Self::Save,
            Self::Save => Self::Destination,
        }
    }

    pub(crate) fn prev(self) -> Self {
        match self {
            Self::Destination => Self::Save,
            Self::Gateway => Self::Destination,
            Self::OutputInterface => Self::Gateway,
            Self::Metric => Self::OutputInterface,
            Self::Table => Self::Metric,
            Self::AllowDefaultRouteChange => Self::Table,
            Self::Save => Self::AllowDefaultRouteChange,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RouteEditor {
    pub(crate) original_route: Option<OwnedIpv4RouteConfig>,
    pub(crate) destination: String,
    pub(crate) gateway: String,
    pub(crate) output_interface: Option<String>,
    pub(crate) metric: String,
    pub(crate) table: String,
    pub(crate) allow_default_route_change: bool,
    pub(crate) field: RouteEditorField,
    pub(crate) cursor: usize,
    pub(crate) available_interfaces: Vec<String>,
}

impl RouteEditor {
    pub(crate) fn reset_cursor(&mut self) {
        self.cursor = match self.field {
            RouteEditorField::Destination => self.destination.chars().count(),
            RouteEditorField::Gateway => self.gateway.chars().count(),
            RouteEditorField::Metric => self.metric.chars().count(),
            RouteEditorField::Table => self.table.chars().count(),
            _ => 0,
        };
    }

    pub(crate) fn active_editor(&mut self) -> Option<super::input::TextEditor<'_>> {
        let cursor = &mut self.cursor;
        match self.field {
            RouteEditorField::Destination => {
                Some(super::input::TextEditor::new(&mut self.destination, cursor))
            }
            RouteEditorField::Gateway => {
                Some(super::input::TextEditor::new(&mut self.gateway, cursor))
            }
            RouteEditorField::Metric => {
                Some(super::input::TextEditor::new(&mut self.metric, cursor))
            }
            RouteEditorField::Table => Some(super::input::TextEditor::new(&mut self.table, cursor)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RouterPendingView {
    pub(crate) token: String,
    #[allow(dead_code)]
    pub(crate) plan: RouterPlan,
    pub(crate) applied_at_unix: u64,
    pub(crate) rollback_failure: Option<Vec<String>>,
}

fn format_owner_badge(owner: RouteOwner) -> Span<'static> {
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

fn cycle_output_interface(editor: &mut RouteEditor, forward: bool) {
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

fn save_route_editor(app: &mut TuiApp) {
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

    app.router.proposed_router_config.enabled = true;
    app.router
        .proposed_router_config
        .owned_routes
        .push(new_route.clone());

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
        protocol: crate::netlink::TRAFFIC_MASQ_ROUTE_PROTOCOL,
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

    app.router.staged = true;
    app.router.editor = None;
    app.screen = Screen::Router;
    app.push_message(
        LogLevel::Info,
        format!("Staged route {destination} in router configuration"),
    );
}

fn delete_selected_route(app: &mut TuiApp) {
    if app.router.routes.is_empty() || app.router.selected_route >= app.router.routes.len() {
        return;
    }
    let route = &app.router.routes[app.router.selected_route];
    if !route.owner.is_editable() {
        app.router.warning_message = Some("External route cannot be deleted".to_string());
        app.push_message(LogLevel::Warn, "External route cannot be deleted");
        return;
    }
    let target_dest = route.destination;
    let target_table = route.table;
    let target_metric = route.metric.unwrap_or(0);

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
    if app.router.proposed_router_config.owned_routes.is_empty()
        && app.router.proposed_router_config.uplink.is_none()
    {
        app.router.proposed_router_config.enabled = false;
    }
    app.router.routes.remove(app.router.selected_route);
    if app.router.selected_route >= app.router.routes.len() && !app.router.routes.is_empty() {
        app.router.selected_route = app.router.routes.len() - 1;
    }
    app.router.staged = true;
    app.router.warning_message = None;
    app.push_message(
        LogLevel::Info,
        format!("Removed route {target_dest} from proposed routes"),
    );
}

async fn open_route_editor_for_selected(app: &mut TuiApp, client: &ApiClient) {
    if app.router.routes.is_empty() || app.router.selected_route >= app.router.routes.len() {
        return;
    }
    let route = &app.router.routes[app.router.selected_route];
    if !route.owner.is_editable() {
        app.router.warning_message = Some("External route is read-only".to_string());
        app.push_message(LogLevel::Warn, "External route is read-only");
        return;
    }
    let orig = OwnedIpv4RouteConfig {
        destination: route.destination,
        gateway: route.gateway,
        output_interface: route.output_interface.clone(),
        table: route.table,
        metric: route.metric,
    };
    let available_interfaces = fetch_available_interfaces(app, client).await;
    let dest_str = orig.destination.to_string();
    let cursor = dest_str.chars().count();
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

async fn open_route_editor_for_add(app: &mut TuiApp, client: &ApiClient) {
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

async fn fetch_available_interfaces(app: &TuiApp, client: &ApiClient) -> Vec<String> {
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

pub(crate) fn render_router(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
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
                "Staged proposal: {} owned route(s) (use [Plan / Apply] to review and apply)",
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

    let status_height = (status_lines.len() as u16 + 2).clamp(3, 8);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(status_height),
            Constraint::Min(6),
            Constraint::Length(5),
        ])
        .split(area);

    let status_block = panel("Router Status");
    let status_inner = status_block.inner(chunks[0]);
    frame.render_widget(status_block, chunks[0]);
    frame.render_widget(Paragraph::new(status_lines), status_inner);

    let table_title = match router.focus {
        RouterFocus::RouteTable => {
            "Routes [Table Focused - Up/Down: select, Enter: edit, Del: remove, Tab: actions]"
        }
        RouterFocus::Actions => "Routes [Tab: focus table]",
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

    let actions_block = panel("Actions");
    let actions_inner = actions_block.inner(chunks[2]);
    frame.render_widget(actions_block, chunks[2]);

    let mut action_lines = Vec::new();

    if let Some(ref warn) = router.warning_message {
        action_lines.push(Line::styled(
            format!("⚠ {warn}"),
            Style::default()
                .fg(theme::WARN)
                .add_modifier(Modifier::BOLD),
        ));
    }

    let buttons = [
        (RouterAction::AddRoute, "[Add route]"),
        (RouterAction::EditRoute, "[Edit route]"),
        (RouterAction::DeleteRoute, "[Delete route]"),
        (RouterAction::PlanApply, "[Plan / Apply]"),
        (RouterAction::Provision, "[Set up router]"),
        (RouterAction::Refresh, "[Refresh]"),
    ];

    let mut button_spans = Vec::new();
    let button_y = actions_inner.y + action_lines.len() as u16;
    let mut current_x = actions_inner.x;

    for (slot, (action, label)) in buttons.iter().enumerate() {
        let is_active = router.focus == RouterFocus::Actions && router.action == *action;
        let style = if is_active {
            Style::default()
                .fg(theme::SELECTED_FG)
                .bg(theme::SELECTED_BG)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme::ACCENT)
        };

        if slot > 0 {
            button_spans.push(Span::raw("  "));
            current_x += 2;
        }

        app.ui.buttons.push((
            Rect {
                x: current_x,
                y: button_y,
                width: label.len() as u16,
                height: 1,
            },
            slot,
        ));
        button_spans.push(Span::styled(*label, style));
        current_x += label.len() as u16;
    }
    action_lines.push(Line::from(button_spans));

    frame.render_widget(Paragraph::new(action_lines), actions_inner);
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
        spans.extend(super::input::render_value_with_cursor(
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

fn resolve_ifindex_name(app: &TuiApp, index: Option<u32>) -> Option<String> {
    let index = index?;
    app.dashboard
        .interfaces
        .iter()
        .find(|i| i.interface.index == index)
        .map(|i| i.interface.name.clone())
        .or_else(|| Some(format!("oif:{index}")))
}

const ROUTER_APPLY_LABEL: &str = "Apply";

pub(crate) fn render_router_plan(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let Some(plan) = &app.router.plan else {
        return;
    };
    let mut lines = vec![Line::from(format!(
        "Uplink: {}",
        summarize_uplink(&plan.dataplane.target)
    ))];
    for line in summarize_output_interfaces(&plan.desired.interfaces) {
        lines.push(Line::from(format!("Output: {line}")));
    }
    for line in summarize_dhcp(&plan.desired.dhcp, &app.router.lease_counts) {
        lines.push(Line::from(format!("DHCP: {line}")));
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
    app.ui.buttons.push((
        Rect {
            x: inner.x,
            y: inner.y + lines.len() as u16,
            width: ROUTER_APPLY_LABEL.len() as u16,
            height: 1,
        },
        0,
    ));
    lines.push(Line::styled(
        ROUTER_APPLY_LABEL,
        Style::default()
            .fg(theme::SELECTED_FG)
            .bg(theme::SELECTED_BG)
            .add_modifier(Modifier::BOLD),
    ));
    frame.render_widget(Paragraph::new(lines), inner);
}

const ROUTER_PENDING_COMMIT_LABEL: &str = "Commit";
const ROUTER_PENDING_ROLLBACK_LABEL: &str = "Rollback";

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

pub(crate) fn focus_action(app: &mut TuiApp, slot: usize) {
    app.router.focus = RouterFocus::Actions;
    app.router.action = match slot {
        0 => RouterAction::AddRoute,
        1 => RouterAction::EditRoute,
        2 => RouterAction::DeleteRoute,
        3 => RouterAction::PlanApply,
        4 => RouterAction::Provision,
        _ => RouterAction::Refresh,
    };
}

pub(crate) async fn handle_router_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    match key {
        KeyCode::Esc => app.screen = Screen::Dashboard,
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
                    RouterAction::Provision => super::provisioning::open(app),
                    RouterAction::Refresh => refresh_router_data(app, client).await,
                },
                _ => {}
            },
        },
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

async fn open_router_plan(app: &mut TuiApp, client: &ApiClient) {
    let proposal = RouterProposalRequest {
        set_router: Some(app.router.proposed_router_config.clone()),
        ..Default::default()
    };
    match client.request(&Request::RouterPlan { proposal }).await {
        Ok(Response::RouterPlan { plan }) => {
            let mut lease_counts = Vec::new();
            for dhcp in &plan.desired.dhcp {
                let count = match client
                    .request(&Request::ListLeases {
                        interface: dhcp.interface.clone(),
                    })
                    .await
                {
                    Ok(Response::Leases { leases, .. }) => leases.len(),
                    _ => 0,
                };
                lease_counts.push((dhcp.interface.clone(), count));
            }
            app.router.lease_counts = lease_counts;
            app.router.plan = Some(plan);
            app.screen = Screen::RouterPlan;
        }
        Ok(Response::RouterError { detail }) => {
            app.router.error = Some(detail.clone());
            app.push_message(LogLevel::Error, describe_router_error(&detail));
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

pub(crate) async fn handle_router_plan_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    match key {
        KeyCode::Esc => app.screen = Screen::Router,
        KeyCode::Enter => router_apply_current_plan(app, client).await,
        _ => {}
    }
}

pub(crate) async fn handle_router_pending_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    match key {
        KeyCode::Enter => finish_router_pending(app, client, true).await,
        KeyCode::Esc => finish_router_pending(app, client, false).await,
        _ => {}
    }
}

pub(crate) async fn refresh_router_data(app: &mut TuiApp, client: &ApiClient) {
    app.router.staged = false;
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
            return;
        }
        Ok(response) => {
            app.push_message(
                LogLevel::Error,
                format!("Unexpected response: {response:?}"),
            );
            return;
        }
        Err(error) => {
            app.push_message(LogLevel::Error, error.to_string());
            return;
        }
    }

    if !app.router.staged {
        if let Ok(Response::RouterConfig { config }) =
            client.request(&Request::GetRouterConfig).await
        {
            app.router.proposed_router_config = config;
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
        }
    }

    if !app.router.enabled && app.router.proposed_router_config.owned_routes.is_empty() {
        app.router.plan = None;
        app.router.lease_counts = Vec::new();
        return;
    }

    let proposal = RouterProposalRequest {
        set_router: Some(app.router.proposed_router_config.clone()),
        ..Default::default()
    };
    match client.request(&Request::RouterPlan { proposal }).await {
        Ok(Response::RouterPlan { plan }) => {
            let mut lease_counts = Vec::new();
            for dhcp in &plan.desired.dhcp {
                let count = match client
                    .request(&Request::ListLeases {
                        interface: dhcp.interface.clone(),
                    })
                    .await
                {
                    Ok(Response::Leases { leases, .. }) => leases.len(),
                    _ => 0,
                };
                lease_counts.push((dhcp.interface.clone(), count));
            }
            app.router.lease_counts = lease_counts;
            app.router.plan = Some(plan);
        }
        Ok(Response::RouterError { detail }) => app.router.error = Some(detail),
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

async fn router_apply_current_plan(app: &mut TuiApp, client: &ApiClient) {
    let proposal = RouterProposalRequest {
        set_router: Some(app.router.proposed_router_config.clone()),
        ..Default::default()
    };
    match client.request(&Request::RouterApply { proposal }).await {
        Ok(Response::RouterTransactionPending { token, plan }) => {
            app.router_pending = Some(RouterPendingView {
                token,
                plan,
                applied_at_unix: current_unix_time(),
                rollback_failure: None,
            });
            app.screen = Screen::RouterPending;
        }
        Ok(Response::RouterError { detail }) => {
            app.push_message(LogLevel::Error, describe_router_error(&detail));
        }
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

async fn finish_router_pending(app: &mut TuiApp, client: &ApiClient, commit: bool) {
    if app.router_pending.is_none() {
        app.screen = Screen::Router;
        return;
    }

    let request = if commit {
        Request::RouterCommit
    } else {
        Request::RouterRollback
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

fn health_report_details(health: &RouterHealthReport) -> Vec<(&'static str, String)> {
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

fn format_coordinator_status(status: CoordinatorStatus) -> &'static str {
    match status {
        CoordinatorStatus::Idle => "idle",
        CoordinatorStatus::Pending => "pending",
        CoordinatorStatus::RollbackFailed => "rollback failed (recovery required)",
    }
}

fn summarize_uplink(target: &RouterDataplaneTarget) -> String {
    match target {
        RouterDataplaneTarget::Enabled(desired) => desired.uplink.clone(),
        RouterDataplaneTarget::Disabled => "none (dataplane disabled)".to_string(),
    }
}

fn summarize_output_interfaces(interfaces: &[RouterInterfaceDesired]) -> Vec<String> {
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

fn summarize_dhcp(dhcp: &[DhcpServiceSpec], lease_counts: &[(String, usize)]) -> Vec<String> {
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

fn ap_without_dhcp_warnings(desired: &RouterDesired) -> Vec<String> {
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

fn format_forwarding_status(dataplane: &crate::firewall::RouterDataplanePlan) -> String {
    let forwarding = if dataplane.snapshot.ipv4_forwarding {
        "forwarding on"
    } else {
        "forwarding off"
    };
    let nat = match &dataplane.target {
        RouterDataplaneTarget::Enabled(_) => "NAT desired",
        RouterDataplaneTarget::Disabled => "NAT disabled",
    };
    let apply = if dataplane.requires_apply {
        "drift: requires apply"
    } else {
        "in sync"
    };
    format!("{forwarding}, {nat}, {apply}")
}

fn describe_router_error(detail: &RouterErrorDetail) -> String {
    match detail {
        RouterErrorDetail::RouterDisabled => {
            "Router has no committed intent yet; use Provision to set one up".to_string()
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

fn router_pending_seconds_remaining(
    applied_at_unix: u64,
    timeout_seconds: u64,
    now_unix: u64,
) -> u64 {
    let elapsed = now_unix.saturating_sub(applied_at_unix);
    timeout_seconds.saturating_sub(elapsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::InterfaceConfig;
    use crate::firewall::{RouterDataplaneDesired, RouterDataplanePlan, RouterDataplaneSnapshot};
    use std::net::Ipv4Addr;

    fn dhcp_spec(interface: &str) -> DhcpServiceSpec {
        DhcpServiceSpec {
            interface: interface.to_string(),
            server_ip: Ipv4Addr::new(192, 168, 10, 1),
            prefix_len: 24,
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            pool_start: Ipv4Addr::new(192, 168, 10, 10),
            pool_end: Ipv4Addr::new(192, 168, 10, 100),
            router: Ipv4Addr::new(192, 168, 10, 1),
            dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
            lease_seconds: 3_600,
        }
    }

    #[test]
    fn router_action_cycles_forward_and_backward() {
        let action = RouterAction::AddRoute;
        assert_eq!(action.next(), RouterAction::EditRoute);
        assert_eq!(action.next().next(), RouterAction::DeleteRoute);
        assert_eq!(action.next().next().next(), RouterAction::PlanApply);
        assert_eq!(action.next().next().next().next(), RouterAction::Provision);
        assert_eq!(
            action.next().next().next().next().next(),
            RouterAction::Refresh
        );
        assert_eq!(
            action.next().next().next().next().next().next(),
            RouterAction::AddRoute
        );

        assert_eq!(action.prev(), RouterAction::Refresh);
        assert_eq!(action.prev().prev(), RouterAction::Provision);
    }

    #[test]
    fn route_editor_field_cycles_forward_and_backward() {
        let field = RouteEditorField::Destination;
        assert_eq!(field.next(), RouteEditorField::Gateway);
        assert_eq!(field.next().next(), RouteEditorField::OutputInterface);
        assert_eq!(field.next().next().next(), RouteEditorField::Metric);
        assert_eq!(field.next().next().next().next(), RouteEditorField::Table);
        assert_eq!(
            field.next().next().next().next().next(),
            RouteEditorField::AllowDefaultRouteChange
        );
        assert_eq!(
            field.next().next().next().next().next().next(),
            RouteEditorField::Save
        );
        assert_eq!(
            field.next().next().next().next().next().next().next(),
            RouteEditorField::Destination
        );

        assert_eq!(field.prev(), RouteEditorField::Save);
        assert_eq!(
            field.prev().prev(),
            RouteEditorField::AllowDefaultRouteChange
        );
    }

    #[test]
    fn format_owner_badge_styles_appropriately() {
        let static_badge = format_owner_badge(RouteOwner::TrafficMasqStatic);
        assert_eq!(static_badge.content, "traffic-masq");
        assert_eq!(static_badge.style.fg, Some(theme::GOOD));

        let dhcp_badge = format_owner_badge(RouteOwner::TrafficMasqDhcp);
        assert_eq!(dhcp_badge.content, "traffic-masq (dhcp)");
        assert_eq!(dhcp_badge.style.fg, Some(theme::ACCENT));

        let kernel_badge = format_owner_badge(RouteOwner::Kernel);
        assert_eq!(kernel_badge.content, "[ext:kernel]");
        assert_eq!(kernel_badge.style.fg, Some(theme::WARN));
    }

    #[test]
    fn cycle_output_interface_rotates_options() {
        let mut editor = RouteEditor {
            original_route: None,
            destination: "10.0.0.0/24".into(),
            gateway: String::new(),
            output_interface: None,
            metric: String::new(),
            table: "254".into(),
            allow_default_route_change: false,
            field: RouteEditorField::OutputInterface,
            cursor: 0,
            available_interfaces: vec!["eth0".into(), "wlan0".into()],
        };

        cycle_output_interface(&mut editor, true);
        assert_eq!(editor.output_interface, Some("eth0".into()));

        cycle_output_interface(&mut editor, true);
        assert_eq!(editor.output_interface, Some("wlan0".into()));

        cycle_output_interface(&mut editor, true);
        assert_eq!(editor.output_interface, None);

        cycle_output_interface(&mut editor, false);
        assert_eq!(editor.output_interface, Some("wlan0".into()));
    }

    #[test]
    fn save_route_editor_validates_and_stages_route() {
        let mut app = TuiApp {
            screen: Screen::RouteEditor,
            ..Default::default()
        };
        app.router.editor = Some(RouteEditor {
            original_route: None,
            destination: "192.168.100.0/24".into(),
            gateway: "192.168.1.1".into(),
            output_interface: Some("eth0".into()),
            metric: "100".into(),
            table: "254".into(),
            allow_default_route_change: false,
            field: RouteEditorField::Save,
            cursor: 0,
            available_interfaces: vec!["eth0".into()],
        });

        save_route_editor(&mut app);

        assert_eq!(app.screen, Screen::Router);
        assert!(app.router.editor.is_none());
        assert!(app.router.staged);
        assert!(app.router.proposed_router_config.enabled);
        assert_eq!(app.router.proposed_router_config.owned_routes.len(), 1);
        let route = &app.router.proposed_router_config.owned_routes[0];
        assert_eq!(route.destination, "192.168.100.0/24".parse().unwrap());
        assert_eq!(route.gateway, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(route.output_interface.as_deref(), Some("eth0"));
        assert_eq!(route.metric, Some(100));
        assert_eq!(route.table, 254);

        assert_eq!(app.router.routes.len(), 1);
        assert_eq!(app.router.routes[0].owner, RouteOwner::TrafficMasqStatic);
    }

    #[test]
    fn save_route_editor_auto_appends_slash_32_for_bare_ips() {
        let mut app = TuiApp {
            screen: Screen::RouteEditor,
            ..Default::default()
        };
        app.router.editor = Some(RouteEditor {
            original_route: None,
            destination: "10.5.0.1".into(),
            gateway: "192.168.1.1".into(),
            output_interface: Some("eth0".into()),
            metric: "".into(),
            table: "254".into(),
            allow_default_route_change: false,
            field: RouteEditorField::Save,
            cursor: 0,
            available_interfaces: vec!["eth0".into()],
        });

        save_route_editor(&mut app);

        assert_eq!(app.screen, Screen::Router);
        assert_eq!(app.router.proposed_router_config.owned_routes.len(), 1);
        assert_eq!(
            app.router.proposed_router_config.owned_routes[0].destination,
            "10.5.0.1/32".parse().unwrap()
        );
        assert!(app.router.proposed_router_config.enabled);
    }

    #[test]
    fn save_route_editor_rejects_host_bits_and_table_255() {
        let mut app = TuiApp {
            screen: Screen::RouteEditor,
            ..Default::default()
        };
        app.router.editor = Some(RouteEditor {
            original_route: None,
            destination: "192.168.100.5/24".into(),
            gateway: "192.168.1.1".into(),
            output_interface: Some("eth0".into()),
            metric: "".into(),
            table: "254".into(),
            allow_default_route_change: false,
            field: RouteEditorField::Save,
            cursor: 0,
            available_interfaces: vec!["eth0".into()],
        });

        save_route_editor(&mut app);
        assert_eq!(app.screen, Screen::RouteEditor);
        assert!(app.router.proposed_router_config.owned_routes.is_empty());

        // Test table 255 rejection
        app.router.editor.as_mut().unwrap().destination = "192.168.100.0/24".into();
        app.router.editor.as_mut().unwrap().table = "255".into();
        save_route_editor(&mut app);
        assert_eq!(app.screen, Screen::RouteEditor);
        assert!(app.router.proposed_router_config.owned_routes.is_empty());
    }

    #[test]
    fn save_route_editor_rejects_missing_both_gateway_and_interface() {
        let mut app = TuiApp {
            screen: Screen::RouteEditor,
            ..Default::default()
        };
        app.router.editor = Some(RouteEditor {
            original_route: None,
            destination: "192.168.100.0/24".into(),
            gateway: "".into(),
            output_interface: None,
            metric: "".into(),
            table: "254".into(),
            allow_default_route_change: false,
            field: RouteEditorField::Save,
            cursor: 0,
            available_interfaces: vec![],
        });

        save_route_editor(&mut app);

        assert_eq!(app.screen, Screen::RouteEditor);
        assert!(app.router.proposed_router_config.owned_routes.is_empty());
    }

    #[test]
    fn save_route_editor_rejects_unspecified_multicast_and_broadcast_gateways() {
        let mut app = TuiApp {
            screen: Screen::RouteEditor,
            ..Default::default()
        };

        for invalid_gw in ["0.0.0.0", "255.255.255.255", "224.0.0.1"] {
            app.router.editor = Some(RouteEditor {
                original_route: None,
                destination: "192.168.100.0/24".into(),
                gateway: invalid_gw.into(),
                output_interface: None,
                metric: "".into(),
                table: "254".into(),
                allow_default_route_change: false,
                field: RouteEditorField::Save,
                cursor: 0,
                available_interfaces: vec![],
            });

            save_route_editor(&mut app);
            assert_eq!(app.screen, Screen::RouteEditor);
            assert!(app.router.proposed_router_config.owned_routes.is_empty());
        }
    }

    #[test]
    fn route_editor_retry_after_collision_replaces_original() {
        for owner in [RouteOwner::TrafficMasqStatic, RouteOwner::Static] {
            let original = route_config("10.1.0.0/24");
            let collision = route_config("10.2.0.0/24");
            let mut app = TuiApp {
                screen: Screen::RouteEditor,
                ..Default::default()
            };
            app.router.proposed_router_config.enabled = true;
            app.router.proposed_router_config.owned_routes = vec![original.clone()];
            if owner.is_editable() {
                app.router
                    .proposed_router_config
                    .owned_routes
                    .push(collision.clone());
            }
            app.router.routes = vec![
                route_status(&original, RouteOwner::TrafficMasqStatic),
                route_status(&collision, owner),
            ];
            app.router.editor = Some(RouteEditor {
                original_route: Some(original.clone()),
                destination: collision.destination.to_string(),
                gateway: "192.168.1.1".into(),
                output_interface: Some("eth0".into()),
                metric: "100".into(),
                table: "254".into(),
                allow_default_route_change: false,
                field: RouteEditorField::Save,
                cursor: 0,
                available_interfaces: vec!["eth0".into()],
            });
            let before = app.router.proposed_router_config.clone();
            let before_routes = app.router.routes.clone();

            save_route_editor(&mut app);

            assert_eq!(app.screen, Screen::RouteEditor);
            assert_eq!(app.router.proposed_router_config, before);
            assert_eq!(app.router.routes, before_routes);
            assert!(!app.router.staged);
            let editor = app.router.editor.as_mut().expect("editor remains open");
            assert_eq!(editor.original_route.as_ref(), Some(&original));
            editor.destination = "10.3.0.0/24".into();

            save_route_editor(&mut app);

            assert_eq!(app.screen, Screen::Router);
            assert!(app.router.editor.is_none());
            assert!(app.router.staged);
            let routes = &app.router.proposed_router_config.owned_routes;
            assert_eq!(routes.len(), before.owned_routes.len());
            assert!(!routes.contains(&original));
            assert!(routes.contains(&route_config("10.3.0.0/24")));
            assert_eq!(app.router.routes.len(), before_routes.len());
            assert!(!app
                .router
                .routes
                .iter()
                .any(|r| r.destination == original.destination));
        }
    }

    fn route_config(destination: &str) -> OwnedIpv4RouteConfig {
        OwnedIpv4RouteConfig {
            destination: destination.parse().expect("destination"),
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            output_interface: Some("eth0".into()),
            table: 254,
            metric: Some(100),
        }
    }

    fn route_status(route: &OwnedIpv4RouteConfig, owner: RouteOwner) -> RouteStatus {
        RouteStatus {
            destination: route.destination,
            gateway: route.gateway,
            output_interface: route.output_interface.clone(),
            output_interface_index: Some(2),
            table: route.table,
            metric: route.metric,
            protocol: if owner.is_editable() { 201 } else { 4 },
            scope: 0,
            owner,
        }
    }

    #[test]
    fn deleting_last_default_route_preserves_permission_in_candidate() {
        use crate::core::router_candidate::{RouterCandidate, RouterIntentProposal};

        let original = route_config("0.0.0.0/0");
        let config = crate::config::AppConfig {
            router: RouterConfig {
                enabled: true,
                allow_default_route_change: true,
                owned_routes: vec![original.clone()],
                ..Default::default()
            },
            ..Default::default()
        };
        let mut app = TuiApp::default();
        app.router.proposed_router_config = config.router.clone();
        app.router.routes = vec![route_status(&original, RouteOwner::TrafficMasqStatic)];

        delete_selected_route(&mut app);

        assert!(app.router.staged);
        assert!(app.router.routes.is_empty());
        let candidate = RouterCandidate::build(
            &config,
            &crate::state::overrides::RuntimeOverrides::default(),
            &RouterIntentProposal::new().set_router(app.router.proposed_router_config),
        )
        .expect("deleting the last standalone route builds a valid candidate");
        assert!(candidate.desired().routes.is_empty());
        assert!(candidate.desired().allow_default_route_change);
    }

    #[test]
    fn delete_selected_route_blocks_external_and_deletes_owned() {
        let mut app = TuiApp {
            screen: Screen::Router,
            ..Default::default()
        };
        app.router.proposed_router_config.enabled = true;
        let external_route = RouteStatus {
            destination: "10.0.0.0/8".parse().unwrap(),
            gateway: None,
            output_interface: Some("eth0".into()),
            output_interface_index: None,
            table: 254,
            metric: None,
            protocol: 3, // Kernel
            scope: 0,
            owner: RouteOwner::Kernel,
        };
        let owned_route = RouteStatus {
            destination: "192.168.1.0/24".parse().unwrap(),
            gateway: Some(Ipv4Addr::new(10, 0, 0, 1)),
            output_interface: Some("eth0".into()),
            output_interface_index: None,
            table: 254,
            metric: Some(50),
            protocol: crate::netlink::TRAFFIC_MASQ_ROUTE_PROTOCOL,
            scope: 0,
            owner: RouteOwner::TrafficMasqStatic,
        };
        app.router.routes = vec![external_route, owned_route];
        app.router.proposed_router_config.owned_routes = vec![OwnedIpv4RouteConfig {
            destination: "192.168.1.0/24".parse().unwrap(),
            gateway: Some(Ipv4Addr::new(10, 0, 0, 1)),
            output_interface: Some("eth0".into()),
            table: 254,
            metric: Some(50),
        }];

        // Attempt to delete external route
        app.router.selected_route = 0;
        delete_selected_route(&mut app);
        assert_eq!(app.router.routes.len(), 2);
        assert_eq!(
            app.router.warning_message.as_deref(),
            Some("External route cannot be deleted")
        );
        assert!(app.router.proposed_router_config.enabled);

        // Delete owned route
        app.router.selected_route = 1;
        delete_selected_route(&mut app);
        assert_eq!(app.router.routes.len(), 1);
        assert!(app.router.proposed_router_config.owned_routes.is_empty());
        assert!(!app.router.proposed_router_config.enabled);
        assert!(app.router.staged);
        assert_eq!(app.router.warning_message, None);
    }

    #[test]
    fn router_pending_countdown_counts_down_and_floors_at_zero() {
        assert_eq!(router_pending_seconds_remaining(1_000, 60, 1_000), 60);
        assert_eq!(router_pending_seconds_remaining(1_000, 60, 1_040), 20);
        assert_eq!(router_pending_seconds_remaining(1_000, 60, 1_200), 0);
    }

    #[test]
    fn describes_each_router_error_detail_distinctly() {
        let messages = [
            describe_router_error(&RouterErrorDetail::RouterDisabled),
            describe_router_error(&RouterErrorDetail::TransactionPending),
            describe_router_error(&RouterErrorDetail::RollbackRecoveryRequired),
            describe_router_error(&RouterErrorDetail::StaleCandidate {
                candidate_revision: 1,
                current_revision: 2,
            }),
            describe_router_error(&RouterErrorDetail::StalePlan),
            describe_router_error(&RouterErrorDetail::NoPendingTransaction),
            describe_router_error(&RouterErrorDetail::RollbackFailed {
                failures: vec!["dhcp restart failed".to_string()],
            }),
            describe_router_error(&RouterErrorDetail::Other {
                message: "boom".to_string(),
            }),
        ];

        for (index, message) in messages.iter().enumerate() {
            assert!(!message.is_empty());
            for (other_index, other) in messages.iter().enumerate() {
                if index != other_index {
                    assert_ne!(message, other, "variants must not collapse into one string");
                }
            }
        }
        assert!(messages[3].contains('1') && messages[3].contains('2'));
        assert!(messages[6].contains("dhcp restart failed"));
        assert_eq!(messages[7], "boom");
    }

    #[test]
    fn summarizes_only_output_interfaces_with_subnet() {
        let interfaces = vec![
            RouterInterfaceDesired {
                name: "wan0".to_string(),
                config: InterfaceConfig {
                    role: InterfaceRole::Input,
                    managed: false,
                    ipv4: None,
                    dhcp: None,
                    dhcp_client: None,
                    wifi: None,
                    wifi_client: None,
                    nat: true,
                },
            },
            RouterInterfaceDesired {
                name: "lan0".to_string(),
                config: InterfaceConfig {
                    role: InterfaceRole::Output,
                    managed: true,
                    ipv4: Some("192.168.10.1/24".parse().unwrap()),
                    dhcp: None,
                    dhcp_client: None,
                    wifi: None,
                    wifi_client: None,
                    nat: true,
                },
            },
        ];

        let summary = summarize_output_interfaces(&interfaces);

        assert_eq!(summary, vec!["lan0 (192.168.10.1/24)"]);
    }

    #[test]
    fn summarizes_dhcp_with_known_and_missing_lease_counts() {
        let dhcp = vec![dhcp_spec("lan0"), dhcp_spec("lan1")];
        let lease_counts = vec![("lan0".to_string(), 3usize)];

        let summary = summarize_dhcp(&dhcp, &lease_counts);

        assert_eq!(
            summary,
            vec![
                "lan0 pool 192.168.10.10-192.168.10.100 (3 lease(s))".to_string(),
                "lan1 pool 192.168.10.10-192.168.10.100 (lease count unavailable)".to_string(),
            ]
        );
    }

    #[test]
    fn summarizes_uplink_for_enabled_and_disabled_dataplane() {
        let enabled = RouterDataplaneTarget::Enabled(RouterDataplaneDesired {
            uplink: "wan0".to_string(),
            outputs: Vec::new(),
        });
        assert_eq!(summarize_uplink(&enabled), "wan0");
        assert_eq!(
            summarize_uplink(&RouterDataplaneTarget::Disabled),
            "none (dataplane disabled)"
        );
    }

    #[test]
    fn formats_forwarding_status_reflects_snapshot_target_and_drift() {
        let plan = RouterDataplanePlan {
            snapshot: RouterDataplaneSnapshot {
                ipv4_forwarding: true,
                owned: None,
                owned_firewall_integrity: crate::firewall::OwnedFirewallIntegrity::Intact,
            },
            target: RouterDataplaneTarget::Enabled(RouterDataplaneDesired {
                uplink: "wan0".to_string(),
                outputs: Vec::new(),
            }),
            requires_apply: true,
        };

        assert_eq!(
            format_forwarding_status(&plan),
            "forwarding on, NAT desired, drift: requires apply"
        );
    }

    #[test]
    fn health_report_details_lists_only_failing_subsystems() {
        let health = RouterHealthReport {
            interfaces: None,
            routes: Some("route missing".to_string()),
            dhcp: None,
            uplink_dhcp: None,
            dataplane: Some("forwarding disabled".to_string()),
        };

        let details = health_report_details(&health);

        assert_eq!(
            details,
            vec![
                ("routes", "route missing".to_string()),
                ("dataplane", "forwarding disabled".to_string()),
            ]
        );
    }

    #[test]
    fn health_report_details_lists_all_four_subsystems_when_all_unhealthy() {
        let health = RouterHealthReport {
            interfaces: Some("interface lan0 is down".to_string()),
            routes: Some("route missing".to_string()),
            dhcp: Some("dhcp interface lan0 unhealthy".to_string()),
            uplink_dhcp: None,
            dataplane: Some("forwarding disabled".to_string()),
        };

        let details = health_report_details(&health);

        assert_eq!(
            details,
            vec![
                ("interfaces", "interface lan0 is down".to_string()),
                ("routes", "route missing".to_string()),
                ("dhcp", "dhcp interface lan0 unhealthy".to_string()),
                ("dataplane", "forwarding disabled".to_string()),
            ]
        );
    }

    #[test]
    fn health_report_details_is_empty_when_every_subsystem_is_healthy() {
        let health = RouterHealthReport {
            interfaces: None,
            routes: None,
            dhcp: None,
            uplink_dhcp: None,
            dataplane: None,
        };

        assert!(health_report_details(&health).is_empty());
    }

    #[test]
    fn formats_coordinator_status_for_each_variant() {
        assert_eq!(format_coordinator_status(CoordinatorStatus::Idle), "idle");
        assert_eq!(
            format_coordinator_status(CoordinatorStatus::Pending),
            "pending"
        );
        assert_eq!(
            format_coordinator_status(CoordinatorStatus::RollbackFailed),
            "rollback failed (recovery required)"
        );
    }
}
