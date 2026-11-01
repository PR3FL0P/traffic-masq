//! Port forwarding edits stage the same router proposal as routes and sharing.
use super::{
    layout::{panel, wrap_styled_lines as wrap_lines},
    logs::LogLevel,
    router::{self, RouterPane},
    theme, Screen, TuiApp,
};
use crate::tui::api::client::ApiClient;
use crossterm::event::KeyCode;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};
use traffic_masq_protocol::{validate_port_forwards, PortForwardConfig, PortForwardProtocol};

const LABELS: [&str; 8] = [
    "Incoming interface",
    "Target interface",
    "Protocol",
    "External port",
    "Target IPv4",
    "Target port",
    "External IPv4 (empty = local addresses)",
    "Source subnet (empty = any)",
];
const ACTIONS: [&str; 5] = [
    "[Add]",
    "[Edit]",
    "[Delete]",
    "[Review / Apply]",
    "[Refresh]",
];
#[derive(Debug, Clone)]
pub(crate) struct Editor {
    values: [String; 8],
    cursors: [usize; 8],
    field: usize,
    rules: Vec<PortForwardConfig>,
    editing: Option<usize>,
    error: Option<String>,
    error_field: Option<usize>,
}
impl Editor {
    fn save(&self) -> Result<Vec<PortForwardConfig>, super::input::FormError<usize>> {
        use super::input::FormError;
        let v = &self.values;
        for field in [0, 1] {
            traffic_masq_protocol::validate_interface_name(v[field].trim())
                .map_err(|message| FormError::field(field, message))?;
        }
        if v[0].trim() == v[1].trim() {
            return Err(FormError::field(
                1,
                "Choose a different target interface; hairpin NAT is not supported",
            ));
        }
        let rule = PortForwardConfig {
            from: v[0].trim().into(),
            to: v[1].trim().into(),
            protocol: match v[2].as_str() {
                "tcp" => PortForwardProtocol::Tcp,
                "udp" => PortForwardProtocol::Udp,
                _ => return Err(FormError::field(2, "Choose TCP or UDP")),
            },
            external_port: v[3]
                .trim()
                .parse::<u16>()
                .ok()
                .filter(|port| *port > 0)
                .ok_or_else(|| FormError::field(3, "External port must be in 1..=65535"))?,
            target_address: v[4]
                .trim()
                .parse()
                .map_err(|_| FormError::field(4, "Enter a target IPv4 address"))?,
            target_port: v[5]
                .trim()
                .parse::<u16>()
                .ok()
                .filter(|port| *port > 0)
                .ok_or_else(|| FormError::field(5, "Target port must be in 1..=65535"))?,
            destination_address: if v[6].trim().is_empty() {
                None
            } else {
                Some(v[6].trim().parse().map_err(|_| {
                    FormError::field(6, "Enter an external IPv4 address or leave it empty")
                })?)
            },
            source_subnet: if v[7].trim().is_empty() {
                None
            } else {
                Some(v[7].trim().parse().map_err(|_| {
                    FormError::field(7, "Enter an IPv4 source subnet or leave it empty")
                })?)
            },
        };
        for (field, address) in [
            (4, Some(rule.target_address)),
            (6, rule.destination_address),
        ] {
            if let Some(address) = address {
                traffic_masq_protocol::validate_port_forward_address(address)
                    .map_err(|message| FormError::field(field, message))?;
            }
        }
        if rule.source_subnet.is_some_and(|net| net != net.trunc()) {
            return Err(FormError::field(7, "Source subnet must have no host bits"));
        }
        let mut rules = self.rules.clone();
        if let Some(index) = self.editing {
            rules[index] = rule;
        } else {
            rules.push(rule);
        }
        validate_port_forwards(&rules).map_err(FormError::form)?;
        Ok(rules)
    }
}
pub(crate) fn describe(prefix: &str, r: &PortForwardConfig) -> String {
    format!(
        "{prefix}: {} {} {}:{} → {} {}:{} (source {})",
        r.from,
        r.protocol.as_str(),
        r.destination_address
            .map_or("local".into(), |ip| ip.to_string()),
        r.external_port,
        r.to,
        r.target_address,
        r.target_port,
        r.source_subnet.map_or("any".into(), |net| net.to_string())
    )
}
async fn refresh_for_edit(app: &mut TuiApp, client: &ApiClient) -> bool {
    if !app.router.staged {
        router::load_router_data(app, client).await;
    }
    if !app.router.topology.loaded {
        app.push_message(
            LogLevel::Error,
            "Could not load saved router configuration; refresh and try again",
        );
        return false;
    }
    if !app.router.proposed_router_config.vpn_chain.is_empty() {
        app.push_message(
            LogLevel::Warn,
            "Port forwarding requires per-interface tunnel routing instead of the global VPN chain",
        );
        return false;
    }
    true
}
async fn open(app: &mut TuiApp, client: &ApiClient, edit: bool) {
    let selected = app
        .router
        .proposed_router_config
        .port_forwards
        .get(app.router.selected_port_forward)
        .cloned();
    if !refresh_for_edit(app, client).await {
        return;
    }
    let rules = app.router.proposed_router_config.port_forwards.clone();
    let editing = if edit {
        let Some(index) = selected
            .as_ref()
            .and_then(|r| rules.iter().position(|other| other == r))
        else {
            app.push_message(
                LogLevel::Warn,
                "The selected port forward changed; select it again",
            );
            return;
        };
        Some(index)
    } else {
        None
    };
    let from = app
        .router
        .proposed_router_config
        .uplink
        .as_ref()
        .map(|u| u.interface.clone())
        .unwrap_or_default();
    let to = app
        .router
        .saved_interfaces
        .iter()
        .find(|e| {
            e.configured
                .as_ref()
                .is_some_and(|c| c.role == traffic_masq_protocol::InterfaceRole::Output)
        })
        .map(|e| e.name.clone())
        .unwrap_or_default();
    let values = if let Some(index) = editing {
        let r = &rules[index];
        [
            r.from.clone(),
            r.to.clone(),
            r.protocol.as_str().into(),
            r.external_port.to_string(),
            r.target_address.to_string(),
            r.target_port.to_string(),
            r.destination_address
                .map_or(String::new(), |ip| ip.to_string()),
            r.source_subnet.map_or(String::new(), |net| net.to_string()),
        ]
    } else {
        [
            from,
            to,
            "tcp".into(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        ]
    };
    let cursors = std::array::from_fn(|i| super::input::grapheme_count(&values[i]));
    app.router_ui.port_forwarding = Some(Editor {
        values,
        cursors,
        field: 0,
        rules,
        editing,
        error: None,
        error_field: None,
    });
    app.screen = Screen::PortForwarding;
}
fn stage(app: &mut TuiApp, rules: Vec<PortForwardConfig>) {
    app.router.selected_port_forward = app
        .router
        .selected_port_forward
        .min(rules.len().saturating_sub(1));
    app.router.proposed_router_config.port_forwards = rules;
    app.router.staged = true;
    app.router.error = None;
    app.push_message(
        LogLevel::Info,
        "Router draft updated — not applied. Review / Apply to continue.",
    );
}
async fn delete(app: &mut TuiApp, client: &ApiClient) {
    let Some(selected) = app
        .router
        .proposed_router_config
        .port_forwards
        .get(app.router.selected_port_forward)
        .cloned()
    else {
        return;
    };
    if !refresh_for_edit(app, client).await {
        return;
    }
    let mut rules = app.router.proposed_router_config.port_forwards.clone();
    if let Some(index) = rules.iter().position(|r| r == &selected) {
        rules.remove(index);
        stage(app, rules);
    } else {
        app.push_message(
            LogLevel::Warn,
            "The selected port forward changed; select it again",
        );
    }
}
pub(crate) fn render_list(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(3),
    ])
    .split(area);
    frame.render_widget(
        Paragraph::new(if app.router.staged {
            "Draft — not applied. Review / Apply to continue"
        } else {
            "IPv4 TCP/UDP port forwarding to another host"
        })
        .style(Style::default().fg(theme::MUTED)),
        chunks[0],
    );
    let block = panel("Port forwarding");
    let inner = block.inner(chunks[1]);
    let rules = &app.router.proposed_router_config.port_forwards;
    app.router.selected_port_forward = app
        .router
        .selected_port_forward
        .min(rules.len().saturating_sub(1));
    // Equal-height wrapped rows preserve keyboard and mouse selection by rule index.
    let wrapped: Vec<_> = rules
        .iter()
        .enumerate()
        .map(|(i, rule)| {
            wrap_lines(
                vec![
                    Line::from(describe(
                        if i == app.router.selected_port_forward {
                            "▶"
                        } else {
                            " "
                        },
                        rule,
                    )),
                    Line::from(format!(
                        "  From: {}",
                        super::interface_status::describe(app, &rule.from)
                    )),
                    Line::from(format!(
                        "  Through: {}",
                        super::interface_status::describe(app, &rule.to)
                    )),
                ],
                inner.width,
            )
        })
        .collect();
    let row_height = wrapped.iter().map(Vec::len).max().unwrap_or(1).max(1);
    let visible = (usize::from(inner.height) / row_height).max(1);
    let scroll = app.router.selected_port_forward.saturating_sub(visible - 1);
    let mut lines = Vec::new();
    for (i, row) in wrapped.into_iter().enumerate().skip(scroll).take(visible) {
        let style = if i == app.router.selected_port_forward && !app.router.sharing_actions_focused
        {
            Style::default()
                .fg(theme::SELECTED_FG)
                .bg(theme::SELECTED_BG)
        } else {
            Style::default()
        };
        let padding = row_height - row.len();
        lines.extend(row.into_iter().map(|line| line.style(style)));
        lines.extend((0..padding).map(|_| Line::from("")));
    }
    if lines.is_empty() {
        lines.push(Line::from("No port forwards. Choose Add."));
    }
    frame.render_widget(Paragraph::new(lines).block(block), chunks[1]);
    app.ui.list_area = Some(Rect {
        height: (visible * row_height).min(inner.height as usize) as u16,
        ..inner
    });
    app.ui.list_row_height = row_height as u16;
    app.ui.list_count = rules.len();
    app.ui.list_scroll_offset = scroll;
    let block = panel("Port forwarding actions");
    let inner = block.inner(chunks[2]);
    frame.render_widget(block, chunks[2]);
    let mut x = inner.x;
    for (index, label) in ACTIONS.iter().enumerate() {
        let rect = Rect::new(x, inner.y, label.len() as u16, 1);
        frame.render_widget(
            Paragraph::new(*label).style(
                if app.router.sharing_actions_focused && app.router.sharing_action == index {
                    Style::default()
                        .fg(theme::SELECTED_FG)
                        .bg(theme::SELECTED_BG)
                } else {
                    Style::default().fg(theme::ACCENT)
                },
            ),
            rect,
        );
        app.ui.buttons.push((rect, index));
        x += rect.width + 1;
    }
}
pub(crate) async fn handle_list_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    match key {
        KeyCode::Esc => {
            if app.router.sharing_actions_focused {
                app.router.sharing_actions_focused = false;
            } else {
                router::select_pane(app, RouterPane::Routes);
            }
        }
        KeyCode::Tab | KeyCode::BackTab => {
            app.router.sharing_actions_focused = !app.router.sharing_actions_focused
        }
        KeyCode::Char('a') => open(app, client, false).await,
        KeyCode::Delete => delete(app, client).await,
        KeyCode::Up if !app.router.sharing_actions_focused => {
            app.router.selected_port_forward = app.router.selected_port_forward.saturating_sub(1)
        }
        KeyCode::Down if !app.router.sharing_actions_focused => {
            app.router.selected_port_forward = (app.router.selected_port_forward + 1).min(
                app.router
                    .proposed_router_config
                    .port_forwards
                    .len()
                    .saturating_sub(1),
            )
        }
        KeyCode::Left | KeyCode::Up if app.router.sharing_actions_focused => {
            app.router.sharing_action = app.router.sharing_action.saturating_sub(1)
        }
        KeyCode::Right | KeyCode::Down if app.router.sharing_actions_focused => {
            app.router.sharing_action = (app.router.sharing_action + 1).min(4)
        }
        KeyCode::Enter | KeyCode::Char(' ') => {
            if !app.router.sharing_actions_focused {
                if !app.router.proposed_router_config.port_forwards.is_empty() {
                    open(app, client, true).await;
                }
                return;
            }
            match app.router.sharing_action {
                0 => open(app, client, false).await,
                1 => {
                    if !app.router.proposed_router_config.port_forwards.is_empty() {
                        open(app, client, true).await;
                    }
                }
                2 => delete(app, client).await,
                3 => router::open_router_plan(app, client).await,
                _ => router::refresh_router_data(app, client).await,
            }
        }
        _ => {}
    }
}
pub(crate) fn render(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let Some(e) = &app.router_ui.port_forwarding else {
        return;
    };
    let block = panel(if e.editing.is_some() {
        "Edit port forward"
    } else {
        "Add port forward"
    });
    let inner = block.inner(area);
    let mut lines = Vec::new();
    let mut focus_row = 0;
    for (i, label) in LABELS.iter().enumerate() {
        let selected = i == e.field;
        let style = if e.error_field == Some(i) {
            Style::default().fg(theme::BAD)
        } else if selected {
            Style::default()
                .fg(theme::SELECTED_FG)
                .bg(theme::SELECTED_BG)
        } else {
            Style::default()
        };
        let mut spans = vec![Span::styled(
            format!("{} {label}: ", if selected { "▶" } else { " " }),
            style,
        )];
        if selected && i != 2 {
            spans.extend(super::input::render_value_with_cursor(
                &e.values[i],
                e.cursors[i],
                true,
                style,
            ));
        } else {
            spans.push(Span::styled(e.values[i].clone(), style));
        }
        if selected {
            focus_row = lines.len();
        }
        lines.extend(wrap_lines(vec![Line::from(spans)], inner.width));
        if i < 2 && !e.values[i].trim().is_empty() {
            lines.extend(wrap_lines(
                vec![Line::from(format!(
                    "  Current: {}",
                    super::interface_status::summary(app, e.values[i].trim())
                ))],
                inner.width,
            ));
        }
        if e.error_field == Some(i) {
            if let Some(error) = &e.error {
                lines.extend(wrap_lines(
                    vec![Line::styled(
                        format!("  Error: {error}"),
                        Style::default().fg(theme::BAD),
                    )],
                    inner.width,
                ));
            }
        }
    }
    let save_row = lines.len();
    if e.field == 8 {
        focus_row = save_row;
    }
    lines.push(Line::styled(
        if e.field == 8 {
            "▶ [Save port forward]"
        } else {
            "  [Save port forward]"
        },
        Style::default().fg(theme::ACCENT),
    ));
    lines.extend(wrap_lines(
        vec![Line::from(
            "Enter: next / activate | Tab: next | Esc: cancel",
        )],
        inner.width,
    ));
    if e.error_field.is_none() {
        if let Some(error) = &e.error {
            lines.extend(wrap_lines(
                vec![Line::styled(
                    format!("Rule conflict: {error}"),
                    Style::default().fg(theme::BAD),
                )],
                inner.width,
            ));
        }
    }
    let offset = if e.error.is_some() && e.error_field.is_none() && e.field == 8 {
        lines.len().saturating_sub(inner.height as usize)
    } else if e.error_field == Some(e.field) {
        focus_row
    } else {
        // Leave room below the focused input for its validation message.
        focus_row.saturating_sub(inner.height.saturating_sub(3) as usize)
    };
    if save_row >= offset && save_row < offset + inner.height as usize {
        app.ui.buttons.push((
            Rect::new(
                inner.x,
                inner.y + (save_row - offset) as u16,
                22.min(inner.width),
                1,
            ),
            0,
        ));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((offset as u16, 0))
            .block(block),
        area,
    );
}
pub(crate) fn focus_action(app: &mut TuiApp, _: usize) {
    if let Some(e) = &mut app.router_ui.port_forwarding {
        e.field = 8;
    }
}
pub(crate) fn handle_key(app: &mut TuiApp, key: KeyCode) {
    let Some(e) = &mut app.router_ui.port_forwarding else {
        app.screen = Screen::Router;
        return;
    };
    match key {
        KeyCode::Esc => {
            app.router_ui.port_forwarding = None;
            app.screen = Screen::Router;
        }
        KeyCode::Up | KeyCode::BackTab => e.field = e.field.saturating_sub(1),
        KeyCode::Down | KeyCode::Tab => e.field = (e.field + 1).min(8),
        KeyCode::Enter if e.field == 8 => match e.save() {
            Ok(rules) => {
                let selected = e.editing.unwrap_or(rules.len() - 1);
                stage(app, rules);
                app.router.selected_port_forward = selected;
                app.router_ui.port_forwarding = None;
                app.screen = Screen::Router;
                router::select_pane(app, RouterPane::Ports);
            }
            Err(error) => {
                e.error_field = error.field;
                if let Some(field) = error.field {
                    e.field = field;
                }
                e.error = Some(error.message);
            }
        },
        KeyCode::Left | KeyCode::Right | KeyCode::Char(' ') | KeyCode::Enter if e.field == 2 => {
            e.values[2] = if e.values[2] == "tcp" { "udp" } else { "tcp" }.into();
            if e.error_field.is_none() || e.error_field == Some(2) {
                e.error = None;
                e.error_field = None;
            }
        }
        KeyCode::Enter if e.field < 8 => e.field += 1,
        key if e.field < 8 && e.field != 2 => {
            let previous = e.values[e.field].clone();
            super::input::TextEditor::new(&mut e.values[e.field], &mut e.cursors[e.field])
                .handle_key(key);
            if previous != e.values[e.field]
                && (e.error_field.is_none() || e.error_field == Some(e.field))
            {
                e.error = None;
                e.error_field = None;
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn editor() -> Editor {
        Editor {
            values: [
                "wan0",
                "lan0",
                "tcp",
                "8443",
                "192.168.10.20",
                "443",
                "",
                "203.0.113.0/24",
            ]
            .map(String::from),
            cursors: [0; 8],
            field: 8,
            rules: vec![],
            editing: None,
            error: None,
            error_field: None,
        }
    }
    #[test]
    fn save_stages_intent_and_escape_preserves_the_existing_draft() {
        let mut app = TuiApp::default();
        app.router.proposed_router_config.forwarding = Some(vec![]);
        app.router_ui.port_forwarding = Some(editor());
        app.screen = Screen::PortForwarding;
        handle_key(&mut app, KeyCode::Enter);
        assert!(app.router.staged);
        assert_eq!(app.router.pane, RouterPane::Ports);
        assert_eq!(app.screen, Screen::Router);
        let config = app.router.proposed_router_config.clone();
        assert_eq!(config.port_forwards[0].external_port, 8443);
        assert_eq!(config.port_forwards[0].target_port, 443);
        assert_eq!(config.forwarding, Some(vec![]));
        let mut e = editor();
        e.editing = Some(0);
        e.rules = config.port_forwards.clone();
        e.values[5] = "444".into();
        app.router_ui.port_forwarding = Some(e);
        handle_key(&mut app, KeyCode::Esc);
        assert_eq!(app.router.proposed_router_config, config);
    }
    #[test]
    fn invalid_or_overlapping_rules_keep_the_form_open() {
        let mut app = TuiApp::default();
        let mut e = editor();
        e.rules = e.save().unwrap();
        app.router_ui.port_forwarding = Some(e);
        handle_key(&mut app, KeyCode::Enter);
        assert!(app
            .router_ui
            .port_forwarding
            .as_ref()
            .unwrap()
            .error
            .as_ref()
            .unwrap()
            .contains("overlapping"));
        assert!(!app.router.staged);
        app.router_ui.port_forwarding.as_mut().unwrap().values[3] = "0".into();
        handle_key(&mut app, KeyCode::Enter);
        assert!(app
            .router_ui
            .port_forwarding
            .as_ref()
            .unwrap()
            .error
            .as_ref()
            .unwrap()
            .contains("1..=65535"));
    }
    #[test]
    fn renders_mapping_and_source_restriction_in_plan_and_small_forms() {
        use ratatui::{backend::TestBackend, Terminal};
        let e = editor();
        let rule = &e.save().unwrap()[0];
        let text = describe("Port forward", rule);
        for expected in ["8443", "192.168.10.20:443", "203.0.113.0/24"] {
            assert!(text.contains(expected));
        }
        for (width, height) in [(80, 24), (32, 10), (12, 4)] {
            let mut app = TuiApp {
                router_ui: crate::tui::state::RouterUiState {
                    port_forwarding: Some(e.clone()),
                    ..Default::default()
                },
                ..Default::default()
            };
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal.draw(|f| render(f, f.area(), &mut app)).unwrap();
        }
    }

    #[test]
    fn validation_error_allows_returning_to_fields_and_saving_a_correction() {
        use ratatui::{backend::TestBackend, Terminal};

        fn rendered_text(app: &mut TuiApp, terminal: &mut Terminal<TestBackend>) -> String {
            terminal.draw(|f| render(f, f.area(), app)).unwrap();
            terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|cell| cell.symbol())
                .collect()
        }

        for (width, height) in [(80, 4), (32, 10)] {
            let mut e = editor();
            e.values[3] = "0".into();
            let mut app = TuiApp {
                router_ui: crate::tui::state::RouterUiState {
                    port_forwarding: Some(e),
                    ..Default::default()
                },
                ..Default::default()
            };
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();

            handle_key(&mut app, KeyCode::Enter);
            assert!(rendered_text(&mut app, &mut terminal).contains("External port must be"));

            assert_eq!(app.router_ui.port_forwarding.as_ref().unwrap().field, 3);
            for _ in 0..3 {
                handle_key(&mut app, KeyCode::Up);
            }
            assert!(rendered_text(&mut app, &mut terminal).contains("▶ Incoming interface: wan0"));
            assert!(app
                .router_ui
                .port_forwarding
                .as_ref()
                .unwrap()
                .error
                .is_some());

            for _ in 0..3 {
                handle_key(&mut app, KeyCode::Tab);
            }
            assert!(rendered_text(&mut app, &mut terminal).contains("▶ External port: 0"));
            handle_key(&mut app, KeyCode::End);
            handle_key(&mut app, KeyCode::Backspace);
            for digit in "8443".chars() {
                handle_key(&mut app, KeyCode::Char(digit));
            }
            assert!(rendered_text(&mut app, &mut terminal).contains("▶ External port: 8443"));

            for _ in 0..5 {
                handle_key(&mut app, KeyCode::Tab);
            }
            handle_key(&mut app, KeyCode::Enter);
            assert!(app.router_ui.port_forwarding.is_none());
            assert!(app.router.staged);
            assert_eq!(
                app.router.proposed_router_config.port_forwards[0].external_port,
                8443
            );
        }
    }
}

#[cfg(test)]
mod ux_tests {
    use super::*;
    use ratatui::{backend::TestBackend, Terminal};

    fn form() -> Editor {
        Editor {
            values: [
                "wan0",
                "lan0",
                "tcp",
                "8443",
                "192.168.10.20",
                "443",
                "198.51.100.20",
                "203.0.113.0/24",
            ]
            .map(String::from),
            cursors: [0; 8],
            field: 0,
            rules: vec![],
            editing: None,
            error: None,
            error_field: None,
        }
    }

    #[tokio::test]
    async fn enter_advances_text_and_tab_moves_without_changing_protocol() {
        let mut app = TuiApp {
            router_ui: crate::tui::state::RouterUiState {
                port_forwarding: Some(form()),
                ..Default::default()
            },
            screen: Screen::PortForwarding,
            ..Default::default()
        };
        let client = ApiClient::new("/must-not-connect");
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|f| super::super::render(f, &mut app, false))
            .unwrap();
        for field in [0, 1, 3, 4, 5, 6, 7] {
            app.router_ui.port_forwarding.as_mut().unwrap().field = field;
            super::super::handle_key(&mut app, KeyCode::Enter, &client, false).await;
            assert_eq!(
                app.router_ui.port_forwarding.as_ref().unwrap().field,
                field + 1
            );
            assert!(!app.router.staged);
        }
        app.router_ui.port_forwarding.as_mut().unwrap().field = 2;
        super::super::handle_key(&mut app, KeyCode::Tab, &client, false).await;
        assert_eq!(
            app.router_ui.port_forwarding.as_ref().unwrap().values[2],
            "tcp"
        );
        super::super::handle_key(&mut app, KeyCode::BackTab, &client, false).await;
        super::super::handle_key(&mut app, KeyCode::Enter, &client, false).await;
        assert_eq!(
            app.router_ui.port_forwarding.as_ref().unwrap().values[2],
            "udp"
        );
    }

    #[test]
    fn field_error_and_input_are_visible_together_at_minimum_size() {
        let mut e = form();
        e.values[7] = "203.0.113.5/24".into();
        e.field = 8;
        let mut app = TuiApp {
            router_ui: crate::tui::state::RouterUiState {
                port_forwarding: Some(e),
                ..Default::default()
            },
            screen: Screen::PortForwarding,
            ..Default::default()
        };
        handle_key(&mut app, KeyCode::Enter);
        assert_eq!(app.router_ui.port_forwarding.as_ref().unwrap().field, 7);
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|f| super::super::render(f, &mut app, false))
            .unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(text.contains("Source subnet (empty = any)"));
        assert!(text.contains("Source subnet must have no host bits"));
        assert!(terminal
            .backend()
            .buffer()
            .content
            .iter()
            .any(|c| c.symbol() == "S" && c.fg == theme::BAD));
        assert!(!app.router.staged);
    }

    #[tokio::test]
    async fn wrapped_rules_show_restrictions_and_mouse_selects_continuation_rows() {
        use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
        let mut e = form();
        e.values[0] = "incoming-long15".into();
        e.values[1] = "target-long15".into();
        let rule = e.save().unwrap().remove(0);
        let mut app = TuiApp {
            screen: Screen::Router,
            ..Default::default()
        };
        router::select_pane(&mut app, RouterPane::Ports);
        app.router.proposed_router_config.port_forwards = vec![rule; 12];
        app.router.selected_port_forward = 10;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|f| super::super::render(f, &mut app, false))
            .unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(text.contains("203.0.113.0/24"));
        assert!(text.contains("198.51.100.20"));
        assert!(app.ui.list_row_height > 1);
        let area = app.ui.list_area.unwrap();
        let first = app.ui.list_scroll_offset;
        let client = ApiClient::new("/must-not-connect");
        let row = area.y + app.ui.list_row_height - 1;
        super::super::handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: area.x,
                row,
                modifiers: KeyModifiers::NONE,
            },
            &client,
            false,
        )
        .await;
        assert_eq!(app.router.selected_port_forward, first);
    }
}
