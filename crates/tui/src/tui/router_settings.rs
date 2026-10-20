//! Uplink and global VPN-chain editor. Changes join the existing router draft.
use super::{
    api::{
        client::ApiClient,
        model::{Request, Response},
    },
    input,
    layout::panel,
    logs::LogLevel,
    theme, Screen, TuiApp,
};
use crossterm::event::KeyCode;
use ratatui::{
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};
use traffic_masq_protocol::{RouterConfigView, UplinkConfigView, UplinkMode, VpnHopConfigView};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    Uplink,
    Mode,
    Profile,
    Add,
    Hop,
    Earlier,
    Later,
    Remove,
    DefaultRoute,
    HostTraffic,
    Review,
    Cancel,
}
const FIELDS: [Field; 12] = [
    Field::Uplink,
    Field::Mode,
    Field::Profile,
    Field::Add,
    Field::Hop,
    Field::Earlier,
    Field::Later,
    Field::Remove,
    Field::DefaultRoute,
    Field::HostTraffic,
    Field::Review,
    Field::Cancel,
];

pub(crate) struct Editor {
    config: RouterConfigView,
    original: RouterConfigView,
    exit_requested: bool,
    uplink: String,
    mode: UplinkMode,
    profiles: Vec<String>,
    profile: usize,
    hop: usize,
    field: Field,
    cursor: usize,
    scroll: usize,
}
impl Editor {
    fn new(config: RouterConfigView, profiles: Vec<String>) -> Self {
        let uplink = config
            .uplink
            .as_ref()
            .map(|u| u.interface.clone())
            .unwrap_or_default();
        Self {
            mode: config
                .uplink
                .as_ref()
                .map(|u| u.mode)
                .unwrap_or(UplinkMode::External),
            original: config.clone(),
            config,
            exit_requested: false,
            cursor: input::grapheme_count(&uplink),
            uplink,
            profiles,
            profile: 0,
            hop: 0,
            field: Field::Uplink,
            scroll: 0,
        }
    }
    fn dirty(&self) -> bool {
        self.config != self.original
            || self.uplink
                != self
                    .original
                    .uplink
                    .as_ref()
                    .map(|uplink| uplink.interface.as_str())
                    .unwrap_or("")
            || self.mode
                != self
                    .original
                    .uplink
                    .as_ref()
                    .map_or(UplinkMode::External, |uplink| uplink.mode)
    }
    fn candidate(&self) -> Result<RouterConfigView, &'static str> {
        if self.uplink.trim().is_empty() && !self.config.vpn_chain.is_empty() {
            return Err("VPN chain requires a physical uplink");
        }
        if self.config.route_host_traffic && self.config.vpn_chain.is_empty() {
            return Err("Routing router traffic through the VPN requires a VPN chain");
        }
        let mut config = self.config.clone();
        config.uplink = if self.uplink.trim().is_empty() {
            None
        } else {
            Some(UplinkConfigView {
                interface: self.uplink.trim().into(),
                mode: self.mode,
            })
        };
        Ok(config)
    }
    fn move_hop(&mut self, later: bool) {
        if self.hop >= self.config.vpn_chain.len() {
            return;
        }
        let next = if later {
            (self.hop + 1).min(self.config.vpn_chain.len() - 1)
        } else {
            self.hop.saturating_sub(1)
        };
        self.config.vpn_chain.swap(self.hop, next);
        self.hop = next;
    }
    fn remove_hop(&mut self) {
        if self.hop < self.config.vpn_chain.len() {
            self.config.vpn_chain.remove(self.hop);
            self.hop = self.hop.min(self.config.vpn_chain.len().saturating_sub(1));
        }
    }
    fn label(&self, field: Field) -> String {
        match field {
            Field::Uplink => "Physical uplink (blank = none): ".into(),
            Field::Mode => format!("Uplink addressing: {:?}", self.mode),
            Field::Profile => format!(
                "Profile to add: {}",
                self.profiles
                    .get(self.profile)
                    .map(String::as_str)
                    .unwrap_or("none; import in VPN first")
            ),
            Field::Add => "Add profile at LAN end of chain".into(),
            Field::Hop => format!(
                "Selected hop {}/{}: {}",
                if self.config.vpn_chain.is_empty() {
                    0
                } else {
                    self.hop + 1
                },
                self.config.vpn_chain.len(),
                self.config
                    .vpn_chain
                    .get(self.hop)
                    .map(|h| h.profile_name.as_str())
                    .unwrap_or("none")
            ),
            Field::Earlier => "Move selected hop toward physical uplink".into(),
            Field::Later => "Move selected hop toward LAN".into(),
            Field::Remove => "Remove selected hop".into(),
            Field::DefaultRoute => format!(
                "Permit default-route changes: {}",
                self.config.allow_default_route_change
            ),
            Field::HostTraffic => format!(
                "[{}] Route router's own traffic through VPN (kill switch, IPv6 blocked)",
                if self.config.route_host_traffic {
                    "x"
                } else {
                    " "
                }
            ),
            Field::Review => "Stage settings and review complete router plan".into(),
            Field::Cancel => "Cancel editor (keep previous router draft)".into(),
        }
    }
}

pub(crate) async fn open(app: &mut TuiApp, client: &ApiClient) {
    if !app.router.staged {
        super::router::load_router_data(app, client).await;
    }
    if app.router.recovery_blocks_mutations()
        || app.router.coordinator_status == Some(traffic_masq_protocol::CoordinatorStatus::Pending)
    {
        app.push_message(
            LogLevel::Warn,
            "Finish router confirmation or recovery before editing",
        );
        return;
    }
    if app.router.saved_router_config.is_none()
        || (!app.router.staged && !app.router.topology.loaded)
    {
        app.push_message(
            LogLevel::Error,
            "Could not load saved router configuration; refresh and retry",
        );
        return;
    }
    let profiles = match client.request(&Request::VpnListProfiles).await {
        Ok(Response::VpnProfiles { profiles }) => profiles.into_iter().map(|p| p.name).collect(),
        Ok(_) | Err(_) => {
            app.push_message(
                LogLevel::Warn,
                "VPN profile library unavailable; existing hops can still be reordered or removed",
            );
            Vec::new()
        }
    };
    app.router_settings = Some(Editor::new(
        app.router.proposed_router_config.clone(),
        profiles,
    ));
    app.screen = Screen::RouterSettings;
}
pub(crate) fn focus_action(app: &mut TuiApp, slot: usize) {
    if let (Some(editor), Some(field)) = (app.router_settings.as_mut(), FIELDS.get(slot)) {
        editor.field = *field;
    }
}
pub(crate) fn render(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    if let Some(dialog) = exit_confirmation(app) {
        dialog.render(
            frame,
            area,
            &mut app.ui,
            app.confirmation_focus,
            app.confirmation_scroll,
        );
        return;
    }
    let Some(e) = &mut app.router_settings else {
        return;
    };
    let block = panel("Router uplink and VPN chain");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let note = "Sharing requires explicit rules in Internet sharing; uplink and VPN add no rules.";
    let heading = vec![
        Line::styled(note, Style::default().fg(theme::WARN)),
        Line::from("Chain order: physical uplink -> hop 1 -> ... -> last hop -> LAN."),
        Line::from("Enter cycles choices; Left/Right selects profile/hop. Esc cancels editor."),
    ];
    frame.render_widget(
        Paragraph::new(heading),
        Rect::new(inner.x, inner.y, inner.width, inner.height.min(3)),
    );
    let body = Rect::new(
        inner.x,
        inner.y + 3,
        inner.width,
        inner.height.saturating_sub(3),
    );
    let visible = body.height.max(1) as usize;
    let selected = FIELDS.iter().position(|f| *f == e.field).unwrap_or(0);
    e.scroll = e.scroll.min(selected);
    if selected >= e.scroll + visible {
        e.scroll = selected + 1 - visible;
    }
    let mut lines = Vec::new();
    for (slot, field) in FIELDS.iter().enumerate().skip(e.scroll).take(visible) {
        let active = e.field == *field;
        let style = Style::default().fg(if active { theme::ACCENT } else { theme::TEXT });
        let mut spans = vec![Span::styled(
            format!("{} {}", if active { "▶" } else { " " }, e.label(*field)),
            style,
        )];
        if *field == Field::Uplink {
            spans.extend(input::render_value_with_cursor(
                &e.uplink, e.cursor, active, style,
            ));
        }
        app.ui.buttons.push((
            Rect::new(body.x, body.y + lines.len() as u16, body.width, 1),
            slot,
        ));
        lines.push(Line::from(spans));
    }
    frame.render_widget(Paragraph::new(lines), body);
}
pub(crate) async fn handle_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    let Some(e) = &mut app.router_settings else {
        return;
    };
    if e.exit_requested {
        match key {
            KeyCode::Esc => e.exit_requested = false,
            KeyCode::Enter => {
                app.router_settings = None;
                app.screen = Screen::Router;
            }
            _ => {}
        }
        return;
    }
    match key {
        KeyCode::Esc => request_exit(app),
        KeyCode::Up | KeyCode::Down => {
            e.field = input::move_clamped(&FIELDS, e.field, key == KeyCode::Down)
        }
        KeyCode::Left | KeyCode::Right if e.field == Field::Profile || e.field == Field::Hop => {
            let (index, count) = if e.field == Field::Profile {
                (&mut e.profile, e.profiles.len())
            } else {
                (&mut e.hop, e.config.vpn_chain.len())
            };
            *index = if key == KeyCode::Right {
                (*index + 1).min(count.saturating_sub(1))
            } else {
                index.saturating_sub(1)
            };
        }
        KeyCode::Enter => match e.field {
            Field::Mode => {
                e.mode = if e.mode == UplinkMode::External {
                    UplinkMode::Dhcp
                } else {
                    UplinkMode::External
                }
            }
            Field::Profile => {
                if !e.profiles.is_empty() {
                    e.profile = (e.profile + 1) % e.profiles.len();
                }
            }
            Field::Hop => {
                if !e.config.vpn_chain.is_empty() {
                    e.hop = (e.hop + 1) % e.config.vpn_chain.len();
                }
            }
            Field::Add => {
                if let Some(name) = e.profiles.get(e.profile) {
                    e.config.vpn_chain.push(VpnHopConfigView {
                        profile_name: name.clone(),
                    });
                    e.hop = e.config.vpn_chain.len() - 1;
                }
            }
            Field::Earlier => e.move_hop(false),
            Field::Later => e.move_hop(true),
            Field::Remove => e.remove_hop(),
            Field::DefaultRoute => {
                e.config.allow_default_route_change = !e.config.allow_default_route_change
            }
            Field::HostTraffic => {
                e.config.route_host_traffic = !e.config.route_host_traffic;
            }
            Field::Review => {
                let candidate = match e.candidate() {
                    Ok(c) => c,
                    Err(message) => {
                        app.push_message(LogLevel::Error, message);
                        return;
                    }
                };
                app.router.proposed_router_config = candidate;
                app.router.staged = true;
                app.router_settings = None;
                app.screen = Screen::Router;
                super::router::open_router_plan(app, client).await;
            }
            Field::Cancel => request_exit(app),
            Field::Uplink => e.field = Field::Mode,
        },
        other if e.field == Field::Uplink => {
            input::TextEditor::new(&mut e.uplink, &mut e.cursor).handle_key(other);
        }
        _ => {}
    }
}

fn on_off(value: bool) -> &'static str {
    if value {
        "on"
    } else {
        "off"
    }
}

/// Include this exact draft configuration in the shared plan review, including removed hops/rules.
pub(crate) fn plan_lines(
    current: &RouterConfigView,
    previous: Option<&RouterConfigView>,
) -> Vec<String> {
    let uplink = |c: &RouterConfigView| {
        c.uplink
            .as_ref()
            .map(|u| format!("{} ({:?})", u.interface, u.mode))
            .unwrap_or_else(|| "none".into())
    };
    let mut lines = vec![
        format!("Configured physical uplink: {}", uplink(current)),
        format!(
            "Sharing policy: {}",
            if current
                .forwarding
                .as_ref()
                .is_some_and(|rules| !rules.is_empty())
            {
                "explicit rules"
            } else {
                "no forwarding permissions"
            }
        ),
    ];
    if let Some(previous) = previous {
        if previous.uplink != current.uplink {
            lines.push(format!("Previous physical uplink: {}", uplink(previous)));
        }
        for rule in previous.forwarding.iter().flatten() {
            if !current
                .forwarding
                .iter()
                .flatten()
                .any(|current| current == rule)
            {
                lines.push(format!(
                    "Removed share: {} -> {} ({:?})",
                    rule.from, rule.to, rule.source_subnet
                ));
            }
        }
        for (i, hop) in previous.vpn_chain.iter().enumerate() {
            lines.push(format!("Previous VPN hop {}: {}", i + 1, hop.profile_name));
        }
    }
    if previous.is_some_and(|previous| previous.route_host_traffic != current.route_host_traffic) {
        lines.push(format!(
            "Router's own traffic through VPN: {} (was {})",
            on_off(current.route_host_traffic),
            on_off(previous.is_some_and(|previous| previous.route_host_traffic)),
        ));
    } else if current.route_host_traffic {
        lines.push("Router's own traffic through VPN: on (kill switch, IPv6 blocked)".into());
    }
    if current.vpn_chain.is_empty() {
        lines.push("New VPN chain: none".into());
    }
    for (i, hop) in current.vpn_chain.iter().enumerate() {
        lines.push(format!(
            "New VPN hop {} (uplink -> LAN order): {}",
            i + 1,
            hop.profile_name
        ));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chain_editor_preserves_explicit_forwarding_and_other_configuration() {
        let config = RouterConfigView {
            forwarding: Some(vec![traffic_masq_protocol::ForwardingConfigView {
                from: "lan0".into(),
                to: "wan0".into(),
                source_subnet: None,
                masquerade: true,
            }]),
            allow_default_route_change: true,
            vpn_chain: vec![
                VpnHopConfigView {
                    profile_name: "a".into(),
                },
                VpnHopConfigView {
                    profile_name: "b".into(),
                },
            ],
            ..Default::default()
        };
        let forwarding = config.forwarding.clone();
        let mut e = Editor::new(config, vec![]);
        e.uplink = "wan0".into();
        e.move_hop(true);
        assert_eq!(e.config.vpn_chain[0].profile_name, "b");
        e.remove_hop();
        assert_eq!(e.config.vpn_chain.len(), 1);
        let candidate = e.candidate().unwrap();
        assert_eq!(candidate.forwarding, forwarding);
        assert!(candidate.allow_default_route_change);
        assert_eq!(candidate.uplink.unwrap().interface, "wan0");
    }
    #[tokio::test]
    async fn cancel_retains_the_preexisting_router_draft() {
        let config = RouterConfigView {
            ..Default::default()
        };
        let mut app = TuiApp {
            screen: Screen::RouterSettings,
            router_settings: Some(Editor::new(config.clone(), vec![])),
            ..Default::default()
        };
        app.router.proposed_router_config = config.clone();
        app.router.staged = true;
        app.router_settings.as_mut().unwrap().uplink = "changed".into();
        handle_key(&mut app, KeyCode::Esc, &ApiClient::new("/unused")).await;
        assert!(app.router_settings.as_ref().unwrap().exit_requested);
        handle_key(&mut app, KeyCode::Enter, &ApiClient::new("/unused")).await;
        assert_eq!(app.router.proposed_router_config, config);
        assert!(app.router.staged);
    }
    #[tokio::test]
    async fn stage_uses_shared_plan_api_and_retains_draft_on_preview_error() {
        let mock = super::super::test_api::mock(vec![Response::Error {
            message: "missing radio".into(),
        }])
        .await;
        let config = RouterConfigView {
            ..Default::default()
        };
        let mut e = Editor::new(config, vec!["vpn1".into(), "vpn2".into()]);
        e.uplink = "wan0".into();
        e.mode = UplinkMode::Dhcp;
        e.config.vpn_chain = vec![
            VpnHopConfigView {
                profile_name: "vpn2".into(),
            },
            VpnHopConfigView {
                profile_name: "vpn1".into(),
            },
        ];
        e.field = Field::Review;
        let mut app = TuiApp {
            screen: Screen::RouterSettings,
            router_settings: Some(e),
            ..Default::default()
        };
        handle_key(&mut app, KeyCode::Enter, &mock.client).await;
        assert!(app.router.staged);
        assert_eq!(
            app.router.proposed_router_config.vpn_chain[0].profile_name,
            "vpn2"
        );
        let calls = mock.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].path, "/api/v1/control");
        assert_eq!(calls[0].body["type"], "router_intent_preview");
        assert_eq!(
            calls[0].body["proposal"]["set_router"]["uplink"]["interface"],
            "wan0"
        );
        assert_eq!(
            calls[0].body["proposal"]["set_router"]["vpn_chain"][1]["profile_name"],
            "vpn1"
        );
    }

    #[test]
    fn host_traffic_requires_a_chain_and_is_staged_and_planned() {
        let mut e = Editor::new(RouterConfigView::default(), vec![]);
        e.uplink = "wan0".into();
        e.config.route_host_traffic = true;
        assert!(
            e.candidate().is_err(),
            "flag without a chain must be rejected"
        );

        e.config.vpn_chain = vec![VpnHopConfigView {
            profile_name: "vpn1".into(),
        }];
        let candidate = e.candidate().unwrap();
        assert!(candidate.route_host_traffic);

        let previous = RouterConfigView::default();
        let lines = plan_lines(&candidate, Some(&previous));
        assert!(lines
            .iter()
            .any(|line| line.contains("own traffic through VPN: on (was off)")));
        assert!(e.label(Field::HostTraffic).starts_with("[x]"));
    }

    #[tokio::test]
    async fn enter_toggles_host_traffic() {
        let mut e = Editor::new(RouterConfigView::default(), vec![]);
        e.field = Field::HostTraffic;
        let mut app = TuiApp {
            screen: Screen::RouterSettings,
            router_settings: Some(e),
            ..Default::default()
        };
        let client = ApiClient::new("/unused");
        handle_key(&mut app, KeyCode::Enter, &client).await;
        assert!(
            app.router_settings
                .as_ref()
                .unwrap()
                .config
                .route_host_traffic
        );
        handle_key(&mut app, KeyCode::Enter, &client).await;
        assert!(
            !app.router_settings
                .as_ref()
                .unwrap()
                .config
                .route_host_traffic
        );
    }

    #[test]
    fn minimum_terminal_shows_focused_actions_and_review_lists_removed_rules() {
        let mut app = TuiApp {
            screen: Screen::RouterSettings,
            router_settings: Some(Editor::new(RouterConfigView::default(), vec![])),
            ..Default::default()
        };
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        for field in FIELDS {
            app.router_settings.as_mut().unwrap().field = field;
            terminal
                .draw(|f| super::super::render(f, &mut app, false))
                .unwrap();
            let slot = FIELDS.iter().position(|f| *f == field).unwrap();
            assert!(app.ui.buttons.iter().any(|(_, i)| *i == slot));
        }
        let previous = RouterConfigView {
            forwarding: Some(vec![traffic_masq_protocol::ForwardingConfigView {
                from: "lan0".into(),
                to: "wan0".into(),
                source_subnet: None,
                masquerade: true,
            }]),
            vpn_chain: vec![VpnHopConfigView {
                profile_name: "old".into(),
            }],
            ..Default::default()
        };
        let text = plan_lines(&RouterConfigView::default(), Some(&previous)).join("\n");
        assert!(text.contains("Removed share: lan0 -> wan0"));
        assert!(text.contains("Previous VPN hop 1: old"));
        assert!(text.contains("New VPN chain: none"));
    }
}

pub(super) fn exit_confirmation(app: &TuiApp) -> Option<super::confirmation::Dialog> {
    app.router_settings.as_ref()?.exit_requested.then(|| {
        super::confirmation::discard_edits_dialog(
            "Leave router settings?",
            "Router uplink and VPN chain".into(),
        )
    })
}
fn request_exit(app: &mut TuiApp) {
    if app.router_settings.as_ref().is_some_and(Editor::dirty) {
        app.router_settings.as_mut().unwrap().exit_requested = true;
    } else {
        app.router_settings = None;
        app.screen = Screen::Router;
    }
}

#[cfg(test)]
mod exit_tests {
    use super::*;
    #[tokio::test]
    async fn invalid_chain_can_be_kept_or_explicitly_discarded_without_staging() {
        let client = ApiClient::new("/must-not-connect.sock");
        let mut editor = Editor::new(RouterConfigView::default(), vec![]);
        editor.config.vpn_chain.push(VpnHopConfigView {
            profile_name: "draft".into(),
        });
        editor.field = Field::Cancel;
        let mut app = TuiApp {
            screen: Screen::RouterSettings,
            router_settings: Some(editor),
            ..Default::default()
        };
        handle_key(&mut app, KeyCode::Enter, &client).await;
        assert!(exit_confirmation(&app).is_some());
        handle_key(&mut app, KeyCode::Esc, &client).await;
        assert_eq!(
            app.router_settings.as_ref().unwrap().config.vpn_chain.len(),
            1
        );
        assert!(!app.router.staged);
        handle_key(&mut app, KeyCode::Esc, &client).await;
        handle_key(&mut app, KeyCode::Enter, &client).await;
        assert!(app.router_settings.is_none());
        assert!(!app.router.staged);
    }
}
