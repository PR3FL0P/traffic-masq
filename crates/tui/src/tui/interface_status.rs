//! Current interface observations, kept separate from editor drafts and plans.
use traffic_masq_protocol::{InterfacePresence, InterfaceReadiness, NetworkChangePhase};

use super::TuiApp;

struct Status {
    link: &'static str,
    owner: &'static str,
    state: &'static str,
}

fn status(app: &TuiApp, name: &str) -> Status {
    let entries = app
        .dashboard
        .inventory
        .as_deref()
        .unwrap_or(&app.router.saved_interfaces);
    let entry = entries.iter().find(|entry| entry.name == name);
    let observed = entry.and_then(|entry| entry.observed.as_ref()).or_else(|| {
        app.dashboard
            .interfaces
            .iter()
            .find(|status| status.interface.name == name)
    });
    let stale = entry.is_some_and(|entry| entry.observation_stale)
        || app
            .dashboard
            .interfaces_updated
            .is_some_and(|time| time.elapsed().as_secs() >= 10);
    let link = match entry.map(|entry| entry.presence) {
        Some(InterfacePresence::Missing) if !stale => "MISSING",
        Some(InterfacePresence::Unknown) => "UNKNOWN",
        _ if stale => match observed {
            Some(status) if status.interface.is_up => "last UP (stale)",
            Some(_) => "last DOWN (stale)",
            None => "UNKNOWN (stale)",
        },
        _ => match observed {
            Some(status) if status.interface.is_up => "UP",
            Some(_) => "DOWN",
            None => "UNKNOWN",
        },
    };
    let managed = entry
        .map(|entry| {
            entry
                .configured
                .as_ref()
                .is_some_and(|config| config.managed)
        })
        .or_else(|| app.dashboard.managed.get(name).copied());
    let owner = match managed {
        Some(true) => "on",
        Some(false) => "off",
        None => "?",
    };
    let state = if let Some(change) = app
        .pending
        .as_ref()
        .filter(|change| change.interface == name)
        .or_else(|| {
            app.dashboard
                .pending_network_changes
                .iter()
                .find(|change| change.interface == name)
        }) {
        match change.phase {
            NetworkChangePhase::AwaitingCommit => "awaiting confirmation",
            NetworkChangePhase::RollbackRequired => "rollback required",
            NetworkChangePhase::RecoveryRequired => "recovery required",
            NetworkChangePhase::CommitIndeterminate => "commit indeterminate",
        }
    } else if stale || entry.is_some_and(|entry| entry.presence == InterfacePresence::Unknown) {
        "unknown"
    } else {
        match entry.map(|entry| entry.readiness) {
            Some(InterfaceReadiness::Ready) => "config ready",
            Some(InterfaceReadiness::Disabled) => "disabled",
            Some(InterfaceReadiness::WaitingDevice) => "waiting for device",
            _ => "unknown",
        }
    };
    Status { link, owner, state }
}

pub(super) fn state_label(app: &TuiApp, name: &str) -> &'static str {
    status(app, name).state
}

pub(super) fn summary(app: &TuiApp, name: &str) -> String {
    let status = status(app, name);
    format!(
        "{} · traffic-masq:{} · {}",
        status.link, status.owner, status.state
    )
}

pub(super) fn cell(app: &TuiApp, name: &str) -> ratatui::text::Text<'static> {
    let status = status(app, name);
    let link = if status.link.contains("stale") {
        "STALE"
    } else {
        status.link
    };
    let state = match status.state {
        "awaiting confirmation" => "confirm pending",
        "rollback required" => "rollback needed",
        "recovery required" => "recovery needed",
        "commit indeterminate" => "commit unknown",
        "waiting for device" => "waiting device",
        state => state,
    };
    ratatui::text::Text::from(vec![
        ratatui::text::Line::from(name.to_owned()),
        ratatui::text::Line::from(format!("{link} tm:{}", status.owner)),
        ratatui::text::Line::from(state),
    ])
}

pub(super) fn describe(app: &TuiApp, name: &str) -> String {
    format!("{name} · {}", summary(app, name))
}

pub(super) fn render_context(
    frame: &mut ratatui::Frame<'_>,
    area: ratatui::layout::Rect,
    app: &TuiApp,
    name: &str,
) -> ratatui::layout::Rect {
    if name.is_empty() {
        return area;
    }
    let lines = super::layout::wrap_lines(
        vec![ratatui::text::Line::from(describe(app, name))],
        area.width,
    );
    let height = (lines.len() as u16).min(area.height);
    frame.render_widget(
        ratatui::widgets::Paragraph::new(lines),
        ratatui::layout::Rect { height, ..area },
    );
    ratatui::layout::Rect {
        y: area.y.saturating_add(height),
        height: area.height.saturating_sub(height),
        ..area
    }
}

/// Include both draft and previous dependencies so removal previews stay inspectable.
pub(super) fn router_lines(
    app: &TuiApp,
    configs: &[&traffic_masq_protocol::RouterConfigView],
) -> Vec<ratatui::text::Line<'static>> {
    let mut names = std::collections::BTreeSet::new();
    for config in configs {
        if let Some(uplink) = &config.uplink {
            names.insert(uplink.interface.to_owned());
        }
        for rule in config.forwarding.as_deref().unwrap_or(&[]) {
            names.insert(rule.from.to_owned());
            names.insert(rule.to.to_owned());
        }
        for route in &config.owned_routes {
            if let Some(name) = &route.output_interface {
                names.insert(name.to_owned());
            }
        }
        for (index, _) in config.vpn_chain.iter().enumerate() {
            names.insert(traffic_masq_protocol::hop_interface_name(index as u32));
        }
        for rule in &config.port_forwards {
            names.insert(rule.from.to_owned());
            names.insert(rule.to.to_owned());
        }
    }
    names
        .into_iter()
        .map(|name| ratatui::text::Line::from(format!("Current: {}", describe(app, &name))))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use traffic_masq_protocol::{InterfaceInventoryEntry, PendingNetworkChange};

    fn entry() -> InterfaceInventoryEntry {
        serde_json::from_value(serde_json::json!({
            "name": "lan0",
            "observed": {"interface": {"name": "lan0", "index": 1, "is_up": true}, "ipv4_addresses": []},
            "configured": {"role": "output", "managed": true},
            "config_source": "override", "presence": "present", "observation_stale": false,
            "suppressed": false, "readiness": "ready", "blockers": [], "references": []
        })).unwrap()
    }

    #[test]
    fn link_management_and_readiness_are_independent() {
        let mut app = TuiApp::default();
        let mut row = entry();
        row.observed.as_mut().unwrap().interface.is_up = false;
        app.dashboard.inventory = Some(vec![row.clone()]);
        assert_eq!(
            summary(&app, "lan0"),
            "DOWN · traffic-masq:on · config ready"
        );
        row.observed.as_mut().unwrap().interface.is_up = true;
        row.configured.as_mut().unwrap().managed = false;
        row.readiness = InterfaceReadiness::Disabled;
        app.dashboard.inventory = Some(vec![row]);
        assert_eq!(summary(&app, "lan0"), "UP · traffic-masq:off · disabled");
        assert_eq!(
            summary(&app, "unseen0"),
            "UNKNOWN · traffic-masq:? · unknown"
        );
    }

    #[test]
    fn missing_unknown_and_cached_observations_are_not_reported_as_down() {
        let mut app = TuiApp::default();
        let mut row = entry();
        row.observed = None;
        row.presence = InterfacePresence::Missing;
        row.readiness = InterfaceReadiness::WaitingDevice;
        app.dashboard.inventory = Some(vec![row]);
        assert_eq!(
            summary(&app, "lan0"),
            "MISSING · traffic-masq:on · waiting for device"
        );
        let mut row = entry();
        row.presence = InterfacePresence::Unknown;
        app.dashboard.inventory = Some(vec![row]);
        assert_eq!(summary(&app, "lan0"), "UNKNOWN · traffic-masq:on · unknown");
        let mut row = entry();
        row.observation_stale = true;
        app.dashboard.inventory = Some(vec![row]);
        assert_eq!(
            summary(&app, "lan0"),
            "last UP (stale) · traffic-masq:on · unknown"
        );
    }

    #[test]
    fn recovery_phases_override_configuration_readiness() {
        let mut app = TuiApp::default();
        app.dashboard.inventory = Some(vec![entry()]);
        for (phase, expected) in [
            (NetworkChangePhase::AwaitingCommit, "awaiting confirmation"),
            (NetworkChangePhase::RollbackRequired, "rollback required"),
            (NetworkChangePhase::RecoveryRequired, "recovery required"),
            (
                NetworkChangePhase::CommitIndeterminate,
                "commit indeterminate",
            ),
        ] {
            app.dashboard.pending_network_changes = vec![PendingNetworkChange {
                recovery_progress: None,
                token: "pending".into(),
                interface: "lan0".into(),
                rollback_timeout_seconds: 60,
                expires_at_unix: 0,
                phase,
                last_error: None,
            }];
            assert_eq!(
                summary(&app, "lan0"),
                format!("UP · traffic-masq:on · {expected}")
            );
        }
    }

    #[test]
    fn failed_refresh_marks_retained_observations_stale() {
        let mut app = TuiApp::default();
        app.dashboard.inventory = Some(vec![entry()]);
        super::super::dashboard::accept_update(&mut app, Default::default());
        assert_eq!(
            summary(&app, "lan0"),
            "last UP (stale) · traffic-masq:on · unknown"
        );
    }

    #[test]
    fn current_inventory_takes_precedence_over_router_snapshot() {
        let mut app = TuiApp::default();
        app.router.saved_interfaces = vec![entry()];
        assert!(summary(&app, "lan0").starts_with("UP"));
        app.dashboard.inventory = Some(vec![]);
        assert_eq!(summary(&app, "lan0"), "UNKNOWN · traffic-masq:? · unknown");
    }
}
