//! Current interface observations, kept separate from editor drafts and plans.
use traffic_masq_protocol::{InterfacePresence, InterfaceReadiness, NetworkChangePhase};

use super::{theme, TuiApp};
use ratatui::{
    style::{Color, Style},
    text::{Line, Span},
};

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
        .confirmation
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

/// One palette for observed links across lists, sharing and editors.
pub(super) fn link_color(link: &str) -> Color {
    match link.to_ascii_uppercase().as_str() {
        "UP" => theme::GOOD,
        "DOWN" => theme::MUTED,
        _ => theme::WARN,
    }
}

fn state_color(state: &str) -> Color {
    match state {
        "config ready" => theme::GOOD,
        "disabled" => theme::MUTED,
        "rollback required" | "recovery required" | "commit indeterminate" => theme::BAD,
        _ => theme::WARN,
    }
}

/// Derive the relationship from saved intent, never from an AP-looking name alone.
pub(super) fn relationship(app: &TuiApp, name: &str) -> Option<String> {
    let entries = app
        .dashboard
        .inventory
        .as_deref()
        .unwrap_or(&app.router.saved_interfaces);
    // These are complete snapshots. Combining them can resurrect a relationship
    // removed in a newer revision, including after the parent was forgotten.
    let inventory_revision = if app.dashboard.inventory.is_some() {
        app.dashboard.intent_revision
    } else {
        app.router.editor_revision
    };
    let wifi_revision = app
        .wifi
        .intent_revision
        .or_else(|| app.wifi.rows.iter().filter_map(|row| row.revision).max());
    let use_wifi = wifi_revision > inventory_revision
        || (app.dashboard.inventory.is_none() && entries.is_empty());
    let parents = entries
        .iter()
        .filter(|_| !use_wifi)
        .filter_map(|entry| {
            entry
                .configured
                .as_ref()
                .filter(|config| config.wifi_concurrent)
                .map(|_| entry.name.as_str())
        })
        .chain(app.wifi.rows.iter().filter(|_| use_wifi).filter_map(|row| {
            row.configured
                .as_ref()
                .filter(|config| config.wifi_concurrent)
                .map(|_| row.interface.as_str())
        }));
    for parent in parents {
        let ap = traffic_masq_protocol::concurrent_ap_name(parent);
        if name == ap {
            return Some(format!("Wi-Fi AP of {parent}"));
        }
        if name == parent {
            return Some(format!("Wi-Fi input; AP: {ap}"));
        }
    }
    None
}

pub(super) fn context_lines(app: &TuiApp, name: &str) -> Vec<Line<'static>> {
    let mut header = summary_line(app, name);
    header.spans.insert(0, Span::raw(format!("{name} · ")));
    let mut lines = vec![header];
    if let Some(relation) = relationship(app, name) {
        let is_ap = relation.starts_with("Wi-Fi AP of ");
        lines.push(Line::styled(relation, Style::default().fg(theme::ACCENT)));
        lines.push(Line::from(if is_ap {
            "Shared radio: channel follows the input. Interfaces: Output + LAN address; Wi-Fi: SSID/password + DHCP; Internet sharing: From this AP, Through its input."
        } else {
            "Connect this input in Wi-Fi. Configure the linked AP for local clients; both share one radio and channel."
        }));
    }
    lines
}

pub(super) fn summary_line(app: &TuiApp, name: &str) -> Line<'static> {
    let status = status(app, name);
    Line::from(vec![
        Span::styled(status.link, Style::default().fg(link_color(status.link))),
        Span::raw(format!(" · traffic-masq:{} · ", status.owner)),
        Span::styled(status.state, Style::default().fg(state_color(status.state))),
    ])
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
    let mut lines = vec![
        Line::from(name.to_owned()),
        Line::from(vec![
            Span::styled(link, Style::default().fg(link_color(status.link))),
            Span::raw(format!(" tm:{}", status.owner)),
        ]),
        Line::styled(state, Style::default().fg(state_color(status.state))),
    ];
    if let Some(relation) = relationship(app, name) {
        lines.push(Line::styled(
            relation.trim_start_matches("Wi-Fi ").to_owned(),
            Style::default().fg(theme::ACCENT),
        ));
    }
    ratatui::text::Text::from(lines)
}

pub(super) fn describe(app: &TuiApp, name: &str) -> String {
    format!(
        "{name}{} · {}",
        relationship(app, name).map_or_else(String::new, |relation| format!(" ({relation})")),
        summary(app, name)
    )
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
    let lines = super::layout::wrap_styled_lines(context_lines(app, name), area.width);
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
    fn shared_status_palette_keeps_unknown_and_recovery_distinct() {
        let mut app = TuiApp::default();
        let mut row = entry();
        for (up, stale, expected) in [
            (true, false, theme::GOOD),
            (false, false, theme::MUTED),
            (true, true, theme::WARN),
        ] {
            row.observed.as_mut().unwrap().interface.is_up = up;
            row.observation_stale = stale;
            app.dashboard.inventory = Some(vec![row.clone()]);
            assert_eq!(
                cell(&app, "lan0").lines[1].spans[0].style.fg,
                Some(expected)
            );
            assert_eq!(summary_line(&app, "lan0").spans[0].style.fg, Some(expected));
        }
        assert_eq!(state_color("config ready"), theme::GOOD);
        assert_eq!(state_color("awaiting confirmation"), theme::WARN);
        assert_eq!(state_color("recovery required"), theme::BAD);
        assert_eq!(state_color("disabled"), theme::MUTED);
    }

    #[test]
    fn concurrent_ap_relationship_is_bidirectional_and_explains_configuration() {
        let mut app = TuiApp::default();
        let mut parent = entry();
        parent.name = "wlan0".into();
        parent.configured.as_mut().unwrap().wifi_concurrent = true;
        app.router.saved_interfaces = vec![parent];
        let ap = traffic_masq_protocol::concurrent_ap_name("wlan0");
        assert_eq!(
            relationship(&app, &ap).as_deref(),
            Some("Wi-Fi AP of wlan0")
        );
        assert!(relationship(&app, "wlan0").unwrap().contains(&ap));
        assert_eq!(relationship(&app, "ap-foreign"), None);
        assert_eq!(cell(&app, &ap).lines.len(), 4);
        let hints = context_lines(&app, &ap).last().unwrap().to_string();
        for hint in [
            "SSID/password",
            "DHCP",
            "From this AP",
            "Through its input",
            "channel",
        ] {
            assert!(hints.contains(hint));
        }
        app.router.saved_interfaces[0]
            .configured
            .as_mut()
            .unwrap()
            .wifi_concurrent = false;
        assert_eq!(relationship(&app, &ap), None);
    }

    #[test]
    fn concurrent_relationship_uses_the_latest_snapshot() {
        use super::super::wifi::{WifiRole, WifiRow};
        let mut app = TuiApp::default();
        let mut parent = entry();
        parent.name = "wlan0".into();
        parent.configured.as_mut().unwrap().wifi_concurrent = true;
        app.wifi.rows.push(WifiRow {
            execution_available: true,
            presence: InterfacePresence::Present,
            configured: parent.configured.clone(),
            revision: Some(1),
            interface: parent.name.clone(),
            role: WifiRole::Client,
            ap: None,
            client: None,
        });
        parent.configured.as_mut().unwrap().wifi_concurrent = false;
        app.dashboard.inventory = Some(vec![parent]);
        app.dashboard.intent_revision = Some(2);
        let ap = traffic_masq_protocol::concurrent_ap_name("wlan0");
        assert_eq!(relationship(&app, &ap), None);
        assert_eq!(relationship(&app, "wlan0"), None);

        // Forgetting the parent must also suppress its cached relationship.
        app.dashboard.inventory = Some(vec![]);
        assert_eq!(relationship(&app, &ap), None);

        // A newer Wi-Fi snapshot can enable the relationship again.
        app.wifi.rows[0].revision = Some(3);
        assert_eq!(
            relationship(&app, &ap).as_deref(),
            Some("Wi-Fi AP of wlan0")
        );
        assert!(relationship(&app, "wlan0").unwrap().contains(&ap));

        let mut older_parent = entry();
        older_parent.name = "wlan0".into();
        older_parent.configured = app.wifi.rows[0].configured.clone();
        app.dashboard.inventory = Some(vec![older_parent]);
        app.wifi.rows[0]
            .configured
            .as_mut()
            .unwrap()
            .wifi_concurrent = false;
        assert_eq!(relationship(&app, &ap), None);

        // Even an empty newer snapshot supersedes the old parent.
        app.wifi.rows.clear();
        app.wifi.intent_revision = Some(4);
        assert_eq!(relationship(&app, &ap), None);
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
