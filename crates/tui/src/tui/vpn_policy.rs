use crossterm::event::KeyCode;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use crate::tui::api::client::ApiClient;
use crate::tui::api::model::{Request, Response, VpnPolicyErrorDetail, VpnPolicyStatusView};
use traffic_masq_protocol::VpnPolicyMode;

use super::layout::panel;
use super::logs::LogLevel;
use super::theme;
use super::Screen;
use super::TuiApp;

#[derive(Debug, Default, Clone)]
pub(crate) struct VpnPolicyData {
    pub(crate) status: Option<VpnPolicyStatusView>,
    pub(crate) pending_mode: VpnPolicyMode,
    pub(crate) error: Option<VpnPolicyErrorDetail>,
    pub(crate) read_error: Option<String>,
    pub(crate) field: VpnPolicyField,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VpnPolicyField {
    #[default]
    Mode,
    Apply,
    ClearOverride,
    Reload,
}

const VPN_POLICY_FIELDS: [VpnPolicyField; 4] = [
    VpnPolicyField::Mode,
    VpnPolicyField::Apply,
    VpnPolicyField::ClearOverride,
    VpnPolicyField::Reload,
];

pub(crate) fn next_vpn_policy_field(field: VpnPolicyField) -> VpnPolicyField {
    super::input::move_clamped(&VPN_POLICY_FIELDS, field, true)
}

pub(crate) fn previous_vpn_policy_field(field: VpnPolicyField) -> VpnPolicyField {
    super::input::move_clamped(&VPN_POLICY_FIELDS, field, false)
}

const VPN_POLICY_APPLY_LABEL: &str = "Apply selected mode";
const VPN_POLICY_CLEAR_LABEL: &str = "Clear override";
const VPN_POLICY_RELOAD_LABEL: &str = "Reload";

/// Standalone policy uses the router coordinator, separately from a local router draft.
pub(crate) async fn open(app: &mut TuiApp, client: &ApiClient) {
    match client.request(&Request::GetRouterConfig).await {
        Ok(Response::RouterConfig { config }) if config.vpn_chain.is_empty() => {}
        Ok(Response::RouterConfig { .. }) => {
            app.push_message(LogLevel::Warn, "A global VPN chain is configured; manage traffic through Uplink / VPN. Standalone policy is unavailable.");
            return;
        }
        _ => {
            app.push_message(
                LogLevel::Warn,
                "Saved VPN chain usage unavailable; refresh Route before opening standalone policy",
            );
            return;
        }
    }
    load_vpn_policy_data(app, client).await;
    app.screen = Screen::VpnPolicy;
}

pub(crate) fn render_vpn_policy(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let data = &app.vpn_policy;
    let mut lines = vec![
        Line::styled("Standalone policy (tm-wg0): apply temporarily, then confirm to save.", Style::default().fg(theme::WARN)),
        Line::from("Unavailable with a saved global VPN chain. Tunnel up does not prove traffic protection."),
    ];
    let stale = data.read_error.is_some() || data.error.is_some();
    if let Some(error) = &data.read_error {
        lines.extend(
            super::logs::wrap_log_message(error, area.width.saturating_sub(2) as usize)
                .into_iter()
                .map(|line| Line::styled(line, Style::default().fg(theme::WARN))),
        );
    }

    let Some(status) = &data.status else {
        if stale {
            lines.insert(
                0,
                Line::styled(
                    "VPN status unavailable; protection is unverified.",
                    Style::default().fg(theme::WARN),
                ),
            );
        }
        if let Some(detail) = &data.error {
            lines.push(Line::styled(
                format!("Error: {}", describe_vpn_policy_error(detail)),
                Style::default().fg(theme::BAD).add_modifier(Modifier::BOLD),
            ));
        } else if data.read_error.is_none() {
            lines.push(Line::styled(
                "Loading...",
                Style::default().fg(theme::MUTED),
            ));
        }
        let block = panel("Standalone VPN policy — confirmation required");
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let regions = ratatui::layout::Layout::vertical([
            ratatui::layout::Constraint::Min(0),
            ratatui::layout::Constraint::Length(1),
        ])
        .split(inner);
        frame.render_widget(Paragraph::new(lines), regions[0]);
        frame.render_widget(
            Paragraph::new("▶ [Reload]").style(Style::default().fg(theme::ACCENT)),
            regions[1],
        );
        if !regions[1].is_empty() {
            app.ui.buttons.push((regions[1], 2));
        }
        return;
    };

    lines.push(Line::styled(
        format!(
            "{} mode: {}{}",
            if stale { "Last known" } else { "Current" },
            format_mode(status.mode),
            if status.mode_override_active {
                " (override)"
            } else {
                " (base default)"
            }
        ),
        Style::default()
            .fg(theme::TEXT)
            .add_modifier(Modifier::BOLD),
    ));
    lines.push(Line::styled(
        format!("Policy enforced: {}", status.policy_active),
        Style::default().fg(if stale {
            theme::WARN
        } else if status.policy_active {
            theme::GOOD
        } else {
            theme::MUTED
        }),
    ));
    lines.push(Line::styled(
        format!(
            "Kill switch: {}",
            if status.kill_switch_active {
                "active"
            } else {
                "inactive"
            }
        ),
        Style::default().fg(if stale {
            theme::WARN
        } else if status.kill_switch_active {
            theme::GOOD
        } else {
            theme::MUTED
        }),
    ));
    match &status.tunnel {
        Some(tunnel) => lines.push(Line::styled(
            format!(
                "Tunnel: {} on {} ({}, {})",
                tunnel.profile_name,
                tunnel.interface,
                if tunnel.up { "up" } else { "down" },
                if status.tunnel_healthy {
                    "policy-ready"
                } else {
                    "not policy-ready"
                }
            ),
            Style::default().fg(if stale {
                theme::WARN
            } else if status.tunnel_healthy {
                theme::GOOD
            } else {
                theme::WARN
            }),
        )),
        None => lines.push(Line::styled(
            "Tunnel: none active",
            Style::default().fg(theme::MUTED),
        )),
    }
    if status.protected_subnets.is_empty() {
        lines.push(Line::styled(
            "Protected subnets: none",
            Style::default().fg(theme::MUTED),
        ));
    } else {
        let subnets = status
            .protected_subnets
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(Line::from(format!("Protected subnets: {subnets}")));
    }
    lines.push(Line::from(format!(
        "Physical uplink: {}",
        status.physical_uplink.as_deref().unwrap_or("none")
    )));

    if let Some(detail) = &data.error {
        lines.push(Line::styled(
            format!("Error: {}", describe_vpn_policy_error(detail)),
            Style::default().fg(theme::BAD).add_modifier(Modifier::BOLD),
        ));
    }

    lines.push(Line::from(""));
    let mode_row_active = data.field == VpnPolicyField::Mode;
    lines.push(Line::styled(
        format!(
            "{}Select mode: {}",
            if mode_row_active { "▶ " } else { "  " },
            format_mode(data.pending_mode)
        ),
        Style::default()
            .fg(theme::ACCENT)
            .add_modifier(Modifier::BOLD),
    ));
    lines.push(Line::styled(
        "Up/Down: move | Enter: activate selected row | Esc: back",
        Style::default().fg(theme::MUTED),
    ));
    lines.push(Line::from(""));

    let row = |label: &str, field: VpnPolicyField| {
        let active = data.field == field;
        let marker = if active { "▶ " } else { "  " };
        let style = if active {
            Style::default()
                .fg(theme::SELECTED_FG)
                .bg(theme::SELECTED_BG)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD)
        };
        Line::styled(format!("{marker}{label}"), style)
    };

    let block = panel("Standalone VPN policy — confirmation required");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let chunks = ratatui::layout::Layout::vertical([
        ratatui::layout::Constraint::Length(u16::from(stale)),
        ratatui::layout::Constraint::Min(0),
        ratatui::layout::Constraint::Length(3),
    ])
    .split(inner);
    if stale {
        frame.render_widget(
            Paragraph::new("STALE: current VPN protection is unverified.")
                .style(Style::default().fg(theme::WARN)),
            chunks[0],
        );
    }
    let lines = super::layout::wrap_lines(lines, chunks[1].width);
    let offset = super::layout::focused_lines_offset(&lines, chunks[1].height);
    frame.render_widget(
        Paragraph::new(lines.into_iter().skip(offset).collect::<Vec<_>>()),
        chunks[1],
    );
    for (index, (label, field)) in [
        (VPN_POLICY_APPLY_LABEL, VpnPolicyField::Apply),
        (VPN_POLICY_CLEAR_LABEL, VpnPolicyField::ClearOverride),
        (VPN_POLICY_RELOAD_LABEL, VpnPolicyField::Reload),
    ]
    .into_iter()
    .enumerate()
    {
        let rect = Rect::new(chunks[2].x, chunks[2].y + index as u16, chunks[2].width, 1)
            .intersection(chunks[2]);
        if !rect.is_empty() {
            frame.render_widget(Paragraph::new(row(label, field)), rect);
            app.ui.buttons.push((rect, index));
        }
    }
}

pub(crate) fn focus_action(app: &mut TuiApp, slot: usize) {
    app.vpn_policy.field = match slot {
        0 => VpnPolicyField::Apply,
        1 => VpnPolicyField::ClearOverride,
        _ => VpnPolicyField::Reload,
    };
}

pub(crate) async fn handle_vpn_policy_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    if app.vpn_policy.status.is_none() {
        app.vpn_policy.field = VpnPolicyField::Reload;
        match key {
            KeyCode::Esc => app.screen = Screen::Router,
            KeyCode::Enter => load_vpn_policy_data(app, client).await,
            _ => {}
        }
        return;
    }
    match key {
        KeyCode::Esc => app.screen = Screen::Router,
        KeyCode::Up => {
            app.vpn_policy.field = previous_vpn_policy_field(app.vpn_policy.field);
        }
        KeyCode::Down => {
            app.vpn_policy.field = next_vpn_policy_field(app.vpn_policy.field);
        }
        KeyCode::Enter => match app.vpn_policy.field {
            VpnPolicyField::Mode => {
                app.vpn_policy.pending_mode = toggle_mode(app.vpn_policy.pending_mode);
            }
            VpnPolicyField::Apply => vpn_policy_set_mode(app, client).await,
            VpnPolicyField::ClearOverride => vpn_policy_clear_mode(app, client).await,
            VpnPolicyField::Reload => load_vpn_policy_data(app, client).await,
        },
        _ => {}
    }
}

fn toggle_mode(mode: VpnPolicyMode) -> VpnPolicyMode {
    match mode {
        VpnPolicyMode::Direct => VpnPolicyMode::Vpn,
        VpnPolicyMode::Vpn => VpnPolicyMode::Direct,
    }
}

pub(crate) async fn load_vpn_policy_data(app: &mut TuiApp, client: &ApiClient) {
    read_policy(app, client, true).await;
}

pub(crate) async fn refresh_vpn_policy_status(app: &mut TuiApp, client: &ApiClient) {
    read_policy(app, client, false).await;
}

async fn read_policy(app: &mut TuiApp, client: &ApiClient, initialize: bool) {
    let result = client.request(&Request::VpnPolicyStatus).await;
    app.vpn_policy.error = None;
    app.vpn_policy.read_error = None;
    match result {
        Ok(Response::VpnPolicyStatus { status }) => {
            if initialize {
                app.vpn_policy.pending_mode = status.mode;
            }
            app.vpn_policy.status = Some(status);
            app.vpn_policy.error = None;
            app.vpn_policy.read_error = None;
        }
        Ok(Response::VpnPolicyError { detail }) => {
            app.vpn_policy.error = Some(detail);
            app.vpn_policy.read_error = None;
        }
        Ok(Response::Error { message }) => app.vpn_policy.read_error = Some(message),
        Ok(response) => {
            app.vpn_policy.read_error = Some(format!("Unexpected policy response: {response:?}"))
        }
        Err(error) => app.vpn_policy.read_error = Some(format!("Policy refresh failed: {error}")),
    }
    if app.vpn_policy.status.is_none() {
        app.vpn_policy.field = VpnPolicyField::Reload;
    }
}

async fn vpn_policy_set_mode(app: &mut TuiApp, client: &ApiClient) {
    let mode = app.vpn_policy.pending_mode;
    match client.request(&Request::VpnPolicySetMode { mode }).await {
        Ok(Response::RouterError { detail }) => {
            app.push_message(
                LogLevel::Error,
                super::router::describe_router_error(&detail),
            );
        }
        Ok(Response::RouterTransactionPending { token, plan }) => {
            super::router::open_pending(app, token, Screen::VpnPolicy, Some(plan));
        }
        Ok(Response::Error { message }) => policy_action_error(app, message),
        Ok(Response::VpnPolicyStatus { status }) => {
            app.push_message(
                LogLevel::Info,
                format!(
                    "VPN traffic policy mode set to {}",
                    format_mode(status.mode)
                ),
            );
            app.vpn_policy.pending_mode = status.mode;
            app.vpn_policy.status = Some(status);
            app.vpn_policy.error = None;
            app.vpn_policy.read_error = None;
        }
        Ok(Response::VpnPolicyError { detail }) => {
            app.push_message(LogLevel::Error, describe_vpn_policy_error(&detail));
            app.vpn_policy.error = Some(detail);
        }
        Ok(response) => {
            policy_action_error(app, format!("Unverified policy outcome: {response:?}"))
        }
        Err(error) => policy_action_error(app, format!("Unverified policy outcome: {error}")),
    }
}

async fn vpn_policy_clear_mode(app: &mut TuiApp, client: &ApiClient) {
    match client.request(&Request::VpnPolicyClearMode).await {
        Ok(Response::RouterError { detail }) => {
            app.push_message(
                LogLevel::Error,
                super::router::describe_router_error(&detail),
            );
        }
        Ok(Response::RouterTransactionPending { token, plan }) => {
            super::router::open_pending(app, token, Screen::VpnPolicy, Some(plan));
        }
        Ok(Response::Error { message }) => policy_action_error(app, message),
        Ok(Response::VpnPolicyStatus { status }) => {
            app.push_message(LogLevel::Info, "VPN traffic policy mode override cleared");
            app.vpn_policy.pending_mode = status.mode;
            app.vpn_policy.status = Some(status);
            app.vpn_policy.error = None;
            app.vpn_policy.read_error = None;
        }
        Ok(Response::VpnPolicyError { detail }) => {
            app.push_message(LogLevel::Error, describe_vpn_policy_error(&detail));
            app.vpn_policy.error = Some(detail);
        }
        Ok(response) => {
            policy_action_error(app, format!("Unverified policy outcome: {response:?}"))
        }
        Err(error) => policy_action_error(app, format!("Unverified policy outcome: {error}")),
    }
}

fn format_mode(mode: VpnPolicyMode) -> &'static str {
    match mode {
        VpnPolicyMode::Direct => "direct",
        VpnPolicyMode::Vpn => "vpn",
    }
}

fn describe_vpn_policy_error(detail: &VpnPolicyErrorDetail) -> String {
    match detail {
        VpnPolicyErrorDetail::VpnDisabled => {
            "VPN is disabled; enable it in VPN settings".to_string()
        }
        VpnPolicyErrorDetail::NoProtectedSubnets => {
            "No router uplink or managed output subnet to protect; configure the router first"
                .to_string()
        }
        VpnPolicyErrorDetail::TunnelUnhealthy { message } => {
            format!("VPN tunnel is not ready: {message}")
        }
        VpnPolicyErrorDetail::ReservedNamespaceConflict { message } => {
            format!("Reserved routing/firewall namespace conflict: {message}")
        }
        VpnPolicyErrorDetail::Other { message } => message.clone(),
    }
}

#[cfg(test)]
mod tests;

fn policy_action_error(app: &mut TuiApp, message: String) {
    app.vpn_policy.error = None;
    app.vpn_policy.read_error = Some(message.clone());
    app.push_message(LogLevel::Error, message);
}
