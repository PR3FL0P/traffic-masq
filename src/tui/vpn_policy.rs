use crossterm::event::KeyCode;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use crate::api::client::ApiClient;
use crate::api::model::{Request, Response, VpnPolicyErrorDetail, VpnPolicyStatusView};
use crate::config::VpnPolicyMode;

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

fn vpn_policy_field_index(field: VpnPolicyField) -> usize {
    VPN_POLICY_FIELDS
        .iter()
        .position(|candidate| *candidate == field)
        .expect("field is always one of VPN_POLICY_FIELDS")
}

pub(crate) fn next_vpn_policy_field(field: VpnPolicyField) -> VpnPolicyField {
    let index = vpn_policy_field_index(field).saturating_add(1);
    VPN_POLICY_FIELDS[index.min(VPN_POLICY_FIELDS.len() - 1)]
}

pub(crate) fn previous_vpn_policy_field(field: VpnPolicyField) -> VpnPolicyField {
    let index = vpn_policy_field_index(field).saturating_sub(1);
    VPN_POLICY_FIELDS[index]
}

const VPN_POLICY_APPLY_LABEL: &str = "Apply selected mode";
const VPN_POLICY_CLEAR_LABEL: &str = "Clear override";
const VPN_POLICY_RELOAD_LABEL: &str = "Reload";

pub(crate) fn render_vpn_policy(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let data = &app.vpn_policy;
    let mut lines = Vec::new();

    let Some(status) = &data.status else {
        if let Some(detail) = &data.error {
            lines.push(Line::styled(
                format!("Error: {}", describe_vpn_policy_error(detail)),
                Style::default().fg(theme::BAD).add_modifier(Modifier::BOLD),
            ));
        } else {
            lines.push(Line::styled(
                "Loading...",
                Style::default().fg(theme::MUTED),
            ));
        }
        frame.render_widget(
            Paragraph::new(lines).block(panel("VPN traffic policy")),
            area,
        );
        return;
    };

    lines.push(Line::styled(
        format!(
            "Current mode: {}{}",
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
        Style::default().fg(if status.policy_active {
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
        Style::default().fg(if status.kill_switch_active {
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
            Style::default().fg(if status.tunnel_healthy {
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
        "Up/Down/j/k: move | Enter/Space: activate selected row | Esc: back",
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

    let block = panel("VPN traffic policy");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    app.ui.buttons.push((
        Rect {
            x: inner.x,
            y: inner.y + lines.len() as u16,
            width: VPN_POLICY_APPLY_LABEL.len() as u16,
            height: 1,
        },
        0,
    ));
    lines.push(row(VPN_POLICY_APPLY_LABEL, VpnPolicyField::Apply));
    app.ui.buttons.push((
        Rect {
            x: inner.x,
            y: inner.y + lines.len() as u16,
            width: VPN_POLICY_CLEAR_LABEL.len() as u16,
            height: 1,
        },
        1,
    ));
    lines.push(row(VPN_POLICY_CLEAR_LABEL, VpnPolicyField::ClearOverride));
    app.ui.buttons.push((
        Rect {
            x: inner.x,
            y: inner.y + lines.len() as u16,
            width: VPN_POLICY_RELOAD_LABEL.len() as u16,
            height: 1,
        },
        2,
    ));
    lines.push(row(VPN_POLICY_RELOAD_LABEL, VpnPolicyField::Reload));

    frame.render_widget(Paragraph::new(lines), inner);
}

pub(crate) fn focus_action(app: &mut TuiApp, slot: usize) {
    app.vpn_policy.field = match slot {
        0 => VpnPolicyField::Apply,
        1 => VpnPolicyField::ClearOverride,
        _ => VpnPolicyField::Reload,
    };
}

pub(crate) async fn handle_vpn_policy_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    match key {
        KeyCode::Esc => app.screen = Screen::Vpn,
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
    app.vpn_policy.error = None;
    match client.request(&Request::VpnPolicyStatus).await {
        Ok(Response::VpnPolicyStatus { status }) => {
            app.vpn_policy.pending_mode = status.mode;
            app.vpn_policy.status = Some(status);
        }
        Ok(Response::VpnPolicyError { detail }) => app.vpn_policy.error = Some(detail),
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

pub(crate) async fn refresh_vpn_policy_status(app: &mut TuiApp, client: &ApiClient) {
    match client.request(&Request::VpnPolicyStatus).await {
        Ok(Response::VpnPolicyStatus { status }) => {
            app.vpn_policy.error = None;
            app.vpn_policy.status = Some(status);
        }
        Ok(Response::VpnPolicyError { detail }) => app.vpn_policy.error = Some(detail),
        Ok(_) | Err(_) => {}
    }
}

async fn vpn_policy_set_mode(app: &mut TuiApp, client: &ApiClient) {
    let mode = app.vpn_policy.pending_mode;
    match client.request(&Request::VpnPolicySetMode { mode }).await {
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
        }
        Ok(Response::VpnPolicyError { detail }) => {
            app.push_message(LogLevel::Error, describe_vpn_policy_error(&detail));
            app.vpn_policy.error = Some(detail);
        }
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

async fn vpn_policy_clear_mode(app: &mut TuiApp, client: &ApiClient) {
    match client.request(&Request::VpnPolicyClearMode).await {
        Ok(Response::VpnPolicyStatus { status }) => {
            app.push_message(LogLevel::Info, "VPN traffic policy mode override cleared");
            app.vpn_policy.pending_mode = status.mode;
            app.vpn_policy.status = Some(status);
        }
        Ok(Response::VpnPolicyError { detail }) => {
            app.push_message(LogLevel::Error, describe_vpn_policy_error(&detail));
            app.vpn_policy.error = Some(detail);
        }
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
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
            "VPN is not enabled (vpn.enabled is false in the daemon config)".to_string()
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
mod tests {
    use super::*;

    #[test]
    fn toggle_mode_flips_between_the_only_two_modes() {
        assert_eq!(toggle_mode(VpnPolicyMode::Direct), VpnPolicyMode::Vpn);
        assert_eq!(toggle_mode(VpnPolicyMode::Vpn), VpnPolicyMode::Direct);
    }

    #[test]
    fn vpn_policy_field_reaches_every_row_and_clamps_at_both_ends() {
        assert_eq!(
            next_vpn_policy_field(VpnPolicyField::Mode),
            VpnPolicyField::Apply
        );
        assert_eq!(
            next_vpn_policy_field(VpnPolicyField::Apply),
            VpnPolicyField::ClearOverride
        );
        assert_eq!(
            next_vpn_policy_field(VpnPolicyField::ClearOverride),
            VpnPolicyField::Reload
        );
        assert_eq!(
            next_vpn_policy_field(VpnPolicyField::Reload),
            VpnPolicyField::Reload
        );
        assert_eq!(
            previous_vpn_policy_field(VpnPolicyField::Reload),
            VpnPolicyField::ClearOverride
        );
        assert_eq!(
            previous_vpn_policy_field(VpnPolicyField::ClearOverride),
            VpnPolicyField::Apply
        );
        assert_eq!(
            previous_vpn_policy_field(VpnPolicyField::Apply),
            VpnPolicyField::Mode
        );
        assert_eq!(
            previous_vpn_policy_field(VpnPolicyField::Mode),
            VpnPolicyField::Mode
        );
    }

    #[test]
    fn formats_each_mode_distinctly() {
        assert_ne!(
            format_mode(VpnPolicyMode::Direct),
            format_mode(VpnPolicyMode::Vpn)
        );
    }

    #[test]
    fn describes_each_vpn_policy_error_detail_distinctly() {
        let messages = [
            describe_vpn_policy_error(&VpnPolicyErrorDetail::VpnDisabled),
            describe_vpn_policy_error(&VpnPolicyErrorDetail::NoProtectedSubnets),
            describe_vpn_policy_error(&VpnPolicyErrorDetail::TunnelUnhealthy {
                message: "no active VPN tunnel".to_string(),
            }),
            describe_vpn_policy_error(&VpnPolicyErrorDetail::ReservedNamespaceConflict {
                message: "foreign objects occupy the reserved namespace".to_string(),
            }),
            describe_vpn_policy_error(&VpnPolicyErrorDetail::Other {
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
        assert!(messages[2].contains("no active VPN tunnel"));
        assert!(messages[3].contains("foreign objects occupy the reserved namespace"));
        assert_eq!(messages[4], "boom");
    }
}
