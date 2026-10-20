//! Port forwarding edits stage the same router proposal as routes and sharing.
use super::{
    layout::{focused_lines_offset, panel},
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
}
impl Editor {
    fn save(&self) -> anyhow::Result<Vec<PortForwardConfig>> {
        let v = &self.values;
        let rule = PortForwardConfig {
            from: v[0].trim().into(),
            to: v[1].trim().into(),
            protocol: match v[2].as_str() {
                "tcp" => PortForwardProtocol::Tcp,
                "udp" => PortForwardProtocol::Udp,
                _ => anyhow::bail!("Choose TCP or UDP"),
            },
            external_port: v[3]
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("External port must be in 1..=65535"))?,
            target_address: v[4]
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("Enter a target IPv4 address"))?,
            target_port: v[5]
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("Target port must be in 1..=65535"))?,
            destination_address: if v[6].trim().is_empty() {
                None
            } else {
                Some(v[6].trim().parse().map_err(|_| {
                    anyhow::anyhow!("Enter an external IPv4 address or leave it empty")
                })?)
            },
            source_subnet: if v[7].trim().is_empty() {
                None
            } else {
                Some(v[7].trim().parse().map_err(|_| {
                    anyhow::anyhow!("Enter an IPv4 source subnet or leave it empty")
                })?)
            },
        };
        let mut rules = self.rules.clone();
        if let Some(index) = self.editing {
            rules[index] = rule;
        } else {
            rules.push(rule);
        }
        validate_port_forwards(&rules).map_err(anyhow::Error::msg)?;
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
    app.port_forwarding = Some(Editor {
        values,
        cursors,
        field: 0,
        rules,
        editing,
        error: None,
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
            "Draft changes — Review / Apply to confirm"
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
    let scroll = app
        .router
        .selected_port_forward
        .saturating_sub(usize::from(inner.height).saturating_sub(1));
    let mut lines: Vec<_> = rules
        .iter()
        .enumerate()
        .skip(scroll)
        .map(|(i, r)| {
            Line::styled(
                describe(
                    if i == app.router.selected_port_forward {
                        "▶"
                    } else {
                        " "
                    },
                    r,
                ),
                if i == app.router.selected_port_forward && !app.router.sharing_actions_focused {
                    Style::default()
                        .fg(theme::SELECTED_FG)
                        .bg(theme::SELECTED_BG)
                } else {
                    Style::default()
                },
            )
        })
        .collect();
    if lines.is_empty() {
        lines.push(Line::from("No port forwards. Choose Add."));
    }
    frame.render_widget(Paragraph::new(lines).block(block), chunks[1]);
    app.ui.list_area = Some(inner);
    app.ui.list_row_height = 1;
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
    let Some(e) = &app.port_forwarding else {
        return;
    };
    let mut lines = Vec::new();
    for (i, label) in LABELS.iter().enumerate() {
        let selected = i == e.field;
        let style = if selected {
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
        lines.push(Line::from(spans));
    }
    lines.push(Line::styled(
        if e.field == 8 {
            "▶ [Save port forward]"
        } else {
            "  [Save port forward]"
        },
        Style::default().fg(theme::ACCENT),
    ));
    lines.push(Line::from("Protocol: ←/→ | Tab: next | Esc: cancel"));
    if let Some(error) = &e.error {
        lines.push(Line::styled(error.clone(), Style::default().fg(theme::BAD)));
    }
    let block = panel(if e.editing.is_some() {
        "Edit port forward"
    } else {
        "Add port forward"
    });
    let inner = block.inner(area);
    let offset = if e.error.is_some() && e.field == 8 {
        lines.len().saturating_sub(inner.height as usize)
    } else {
        focused_lines_offset(&lines, inner.height)
    };
    if 8 >= offset && 8 < offset + inner.height as usize {
        app.ui
            .buttons
            .push((Rect::new(inner.x, inner.y + (8 - offset) as u16, 22, 1), 0));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((offset as u16, 0))
            .block(block),
        area,
    );
}
pub(crate) fn focus_action(app: &mut TuiApp, _: usize) {
    if let Some(e) = &mut app.port_forwarding {
        e.field = 8;
    }
}
pub(crate) fn handle_key(app: &mut TuiApp, key: KeyCode) {
    let Some(e) = &mut app.port_forwarding else {
        app.screen = Screen::Router;
        return;
    };
    match key {
        KeyCode::Esc => {
            app.port_forwarding = None;
            app.screen = Screen::Router;
        }
        KeyCode::Up | KeyCode::BackTab => e.field = e.field.saturating_sub(1),
        KeyCode::Down | KeyCode::Tab => e.field = (e.field + 1).min(8),
        KeyCode::Enter if e.field == 8 => match e.save() {
            Ok(rules) => {
                let selected = e.editing.unwrap_or(rules.len() - 1);
                stage(app, rules);
                app.router.selected_port_forward = selected;
                app.port_forwarding = None;
                app.screen = Screen::Router;
                router::select_pane(app, RouterPane::Ports);
            }
            Err(error) => e.error = Some(error.to_string()),
        },
        KeyCode::Left | KeyCode::Right | KeyCode::Char(' ') | KeyCode::Enter if e.field == 2 => {
            e.values[2] = if e.values[2] == "tcp" { "udp" } else { "tcp" }.into()
        }
        key if e.field < 8 && e.field != 2 => {
            super::input::TextEditor::new(&mut e.values[e.field], &mut e.cursors[e.field])
                .handle_key(key);
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
        }
    }
    #[test]
    fn save_stages_intent_and_escape_preserves_the_existing_draft() {
        let mut app = TuiApp::default();
        app.router.proposed_router_config.forwarding = Some(vec![]);
        app.port_forwarding = Some(editor());
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
        app.port_forwarding = Some(e);
        handle_key(&mut app, KeyCode::Esc);
        assert_eq!(app.router.proposed_router_config, config);
    }
    #[test]
    fn invalid_or_overlapping_rules_keep_the_form_open() {
        let mut app = TuiApp::default();
        let mut e = editor();
        e.rules = e.save().unwrap();
        app.port_forwarding = Some(e);
        handle_key(&mut app, KeyCode::Enter);
        assert!(app
            .port_forwarding
            .as_ref()
            .unwrap()
            .error
            .as_ref()
            .unwrap()
            .contains("overlapping"));
        assert!(!app.router.staged);
        app.port_forwarding.as_mut().unwrap().values[3] = "0".into();
        handle_key(&mut app, KeyCode::Enter);
        assert!(app
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
                port_forwarding: Some(e.clone()),
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
                port_forwarding: Some(e),
                ..Default::default()
            };
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();

            handle_key(&mut app, KeyCode::Enter);
            assert!(rendered_text(&mut app, &mut terminal).contains("port forwarding ports"));

            for _ in 0..8 {
                handle_key(&mut app, KeyCode::Up);
            }
            assert!(rendered_text(&mut app, &mut terminal).contains("▶ Incoming interface: wan0"));
            assert!(app.port_forwarding.as_ref().unwrap().error.is_some());

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
            assert!(app.port_forwarding.is_none());
            assert!(app.router.staged);
            assert_eq!(
                app.router.proposed_router_config.port_forwards[0].external_port,
                8443
            );
        }
    }
}
