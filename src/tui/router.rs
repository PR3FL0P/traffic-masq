use crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::Gauge;
use ratatui::widgets::Paragraph;

use crate::api::client::ApiClient;
use crate::api::model::{Request, Response, RouterErrorDetail, RouterProposalRequest};
use crate::config::InterfaceRole;
use crate::core::router::{RouterDesired, RouterHealthReport, RouterInterfaceDesired, RouterPlan};
use crate::core::router_transaction::CoordinatorStatus;
use crate::dhcp::supervisor::DhcpServiceSpec;
use crate::firewall::RouterDataplaneTarget;

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
    pub(crate) plan: Option<RouterPlan>,
    pub(crate) lease_counts: Vec<(String, usize)>,
    pub(crate) error: Option<RouterErrorDetail>,
    pub(crate) field: RouterField,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouterField {
    #[default]
    Provision,
    Plan,
    Refresh,
}

fn toggle_router_field(field: RouterField) -> RouterField {
    match field {
        RouterField::Provision => RouterField::Plan,
        RouterField::Plan => RouterField::Refresh,
        RouterField::Refresh => RouterField::Provision,
    }
}

fn toggle_router_field_reverse(field: RouterField) -> RouterField {
    match field {
        RouterField::Provision => RouterField::Refresh,
        RouterField::Plan => RouterField::Provision,
        RouterField::Refresh => RouterField::Plan,
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RouterPendingView {
    pub(crate) token: String,
    pub(crate) plan: RouterPlan,
    pub(crate) applied_at_unix: u64,
    pub(crate) rollback_failure: Option<Vec<String>>,
}

const ROUTER_PLAN_LABEL: &str = "Plan";
const ROUTER_REFRESH_LABEL: &str = "Refresh";

pub(crate) fn render_router(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let router = &app.router;
    let mut lines = vec![
        Line::styled(
            format!("Ready: {}", router.ready),
            Style::default().fg(if router.ready {
                theme::GOOD
            } else {
                theme::WARN
            }),
        ),
        Line::from(format!("Enabled: {}", router.enabled)),
        Line::from(format!(
            "Coordinator status: {}",
            router
                .coordinator_status
                .map(format_coordinator_status)
                .unwrap_or("unknown")
        )),
    ];

    for (subsystem, detail) in health_report_details(&router.health) {
        lines.push(Line::styled(
            format!("  {subsystem}: {detail}"),
            Style::default().fg(theme::BAD),
        ));
    }

    if let Some(plan) = &router.plan {
        lines.push(Line::from(format!(
            "Active uplink: {}",
            summarize_uplink(&plan.dataplane.target)
        )));
        for line in summarize_output_interfaces(&plan.desired.interfaces) {
            lines.push(Line::from(format!("  output: {line}")));
        }
        for line in summarize_dhcp(&plan.desired.dhcp, &router.lease_counts) {
            lines.push(Line::from(format!("  dhcp: {line}")));
        }
        for line in ap_without_dhcp_warnings(&plan.desired) {
            lines.push(Line::styled(
                format!("  warning: {line}"),
                Style::default().fg(theme::WARN),
            ));
        }
        lines.push(Line::from(format!(
            "Forwarding/NAT: {}",
            format_forwarding_status(&plan.dataplane)
        )));
    }

    if let Some(detail) = &router.error {
        lines.push(Line::styled(
            format!("Error: {}", describe_router_error(detail)),
            Style::default().fg(theme::BAD).add_modifier(Modifier::BOLD),
        ));
    }
    lines.push(Line::from(""));

    let action = |label: &str, active: bool| {
        let marker = if active { "▶ " } else { "  " };
        let style = if active {
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme::ACCENT)
        };
        Line::styled(format!("{marker}{label}"), style)
    };

    let block = panel("Router");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    for (slot, (label, field)) in [
        ("Set up router", RouterField::Provision),
        (ROUTER_PLAN_LABEL, RouterField::Plan),
        (ROUTER_REFRESH_LABEL, RouterField::Refresh),
    ]
    .into_iter()
    .enumerate()
    {
        app.ui.buttons.push((
            Rect {
                x: inner.x,
                y: inner.y + lines.len() as u16,
                width: label.len() as u16,
                height: 1,
            },
            slot,
        ));
        lines.push(action(label, router.field == field));
    }
    frame.render_widget(Paragraph::new(lines), inner);
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
    let Some(pending) = &app.router_pending else {
        return;
    };
    let remaining = router_pending_seconds_remaining(
        pending.applied_at_unix,
        app.router_rollback_timeout_seconds,
        current_unix_time(),
    );

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(3)])
        .split(area);

    let ratio = if app.router_rollback_timeout_seconds == 0 {
        0.0
    } else {
        (remaining as f64 / app.router_rollback_timeout_seconds as f64).clamp(0.0, 1.0)
    };
    let gauge_color = if remaining <= 10 {
        theme::BAD
    } else {
        theme::WARN
    };
    frame.render_widget(
        Gauge::default()
            .block(panel("Automatic rollback countdown"))
            .gauge_style(Style::default().fg(gauge_color))
            .ratio(ratio)
            .label(format!("{remaining}s remaining")),
        chunks[0],
    );

    let mut lines = vec![
        Line::from(format!("Token: {}", pending.token)),
        Line::from(format!(
            "Uplink: {}",
            summarize_uplink(&pending.plan.dataplane.target)
        )),
        Line::styled(
            "Commit only after verifying connectivity.",
            Style::default().fg(theme::MUTED),
        ),
    ];
    if let Some(failures) = &pending.rollback_failure {
        lines.push(Line::styled(
            "Rollback previously failed; coordinator is in recovery. Retry rollback:",
            Style::default().fg(theme::BAD).add_modifier(Modifier::BOLD),
        ));
        for failure in failures {
            lines.push(Line::styled(
                format!("  - {failure}"),
                Style::default().fg(theme::BAD),
            ));
        }
    }
    lines.push(Line::from(""));

    let block = panel("Router pending transaction");
    let inner = block.inner(chunks[1]);
    frame.render_widget(block, chunks[1]);
    app.ui.buttons.push((
        Rect {
            x: inner.x,
            y: inner.y + lines.len() as u16,
            width: ROUTER_PENDING_COMMIT_LABEL.len() as u16,
            height: 1,
        },
        0,
    ));
    lines.push(Line::styled(
        ROUTER_PENDING_COMMIT_LABEL,
        Style::default()
            .fg(theme::ACCENT)
            .add_modifier(Modifier::BOLD),
    ));
    app.ui.buttons.push((
        Rect {
            x: inner.x,
            y: inner.y + lines.len() as u16,
            width: ROUTER_PENDING_ROLLBACK_LABEL.len() as u16,
            height: 1,
        },
        1,
    ));
    lines.push(Line::styled(
        ROUTER_PENDING_ROLLBACK_LABEL,
        Style::default()
            .fg(theme::ACCENT)
            .add_modifier(Modifier::BOLD),
    ));
    frame.render_widget(Paragraph::new(lines), inner);
}

pub(crate) fn focus_action(app: &mut TuiApp, slot: usize) {
    app.router.field = match slot {
        0 => RouterField::Provision,
        1 => RouterField::Plan,
        _ => RouterField::Refresh,
    };
}

pub(crate) async fn handle_router_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    match key {
        KeyCode::Esc => app.screen = Screen::Dashboard,
        KeyCode::Up => app.router.field = toggle_router_field_reverse(app.router.field),
        KeyCode::Down => app.router.field = toggle_router_field(app.router.field),
        KeyCode::Enter => match app.router.field {
            RouterField::Provision => super::provisioning::open(app),
            RouterField::Plan => open_router_plan(app, client).await,
            RouterField::Refresh => load_router_data(app, client).await,
        },
        _ => {}
    }
}

async fn open_router_plan(app: &mut TuiApp, client: &ApiClient) {
    load_router_data(app, client).await;
    if app.router.plan.is_some() {
        app.screen = Screen::RouterPlan;
    } else if !app.router.enabled {
        app.push_message(
            LogLevel::Warn,
            "Router has no committed intent yet, so there is nothing to plan; use Provision to set one up",
        );
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

    if !app.router.enabled {
        app.router.plan = None;
        app.router.lease_counts = Vec::new();
        return;
    }

    match client
        .request(&Request::RouterPlan {
            proposal: RouterProposalRequest::default(),
        })
        .await
    {
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
    match client
        .request(&Request::RouterApply {
            proposal: RouterProposalRequest::default(),
        })
        .await
    {
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
            app.screen = Screen::Router;
        }
        Ok(Response::RouterRolledBack) if !commit => {
            app.push_message(LogLevel::Info, "Router transaction rolled back");
            app.router_pending = None;
            app.screen = Screen::Router;
        }
        Ok(Response::RouterError {
            detail: RouterErrorDetail::RollbackFailed { failures },
        }) => {
            app.push_message(
                LogLevel::Error,
                "Rollback failed; coordinator requires recovery",
            );
            if let Some(pending) = app.router_pending.as_mut() {
                pending.rollback_failure = Some(failures);
            }
        }
        Ok(Response::RouterError {
            detail: RouterErrorDetail::NoPendingTransaction,
        }) => {
            app.push_message(
                LogLevel::Error,
                "No pending router transaction (already resolved)",
            );
            app.router_pending = None;
            app.screen = Screen::Router;
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

pub(crate) async fn refresh_router_pending_screen(app: &mut TuiApp, client: &ApiClient) {
    if app.router_pending.is_none() {
        return;
    }

    match client.request(&Request::RouterPendingTransaction).await {
        Ok(Response::RouterPendingTransaction {
            status: CoordinatorStatus::Idle,
            ..
        }) => {
            app.push_message(
                LogLevel::Info,
                "Router transaction is no longer pending (committed or automatically rolled back)",
            );
            app.router_pending = None;
            if app.screen == Screen::RouterPending {
                app.screen = Screen::Router;
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
    fn toggle_router_field_cycles_through_setup_plan_and_refresh() {
        assert_eq!(
            toggle_router_field(RouterField::Provision),
            RouterField::Plan
        );
        assert_eq!(toggle_router_field(RouterField::Plan), RouterField::Refresh);
        assert_eq!(
            toggle_router_field(RouterField::Refresh),
            RouterField::Provision
        );
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
