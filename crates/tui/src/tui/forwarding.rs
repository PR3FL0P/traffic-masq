//! Internet sharing is independent of the route list. Editing only stages intent.
use std::collections::HashSet;

use super::{
    layout::{focused_lines_offset, panel},
    logs::LogLevel,
    router::{RouterData, RouterPane},
    theme, Screen, TuiApp,
};
use crate::tui::api::{
    client::ApiClient,
    model::{Request, Response},
};
use crossterm::event::KeyCode;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Cell, Paragraph, Row, Table},
};
use traffic_masq_protocol::{
    validate_forwarding, ForwardingConfigView as ForwardingConfig, InterfaceRole,
    RouterDataplaneTargetView, RouterProposalRequestView as RouterProposalRequest,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    From,
    To,
    Masquerade,
    Advanced,
    Source,
    Save,
}

#[derive(Debug, Clone)]
pub(crate) struct ForwardingEditor {
    rules: Vec<ForwardingConfig>,
    editing: Option<usize>,
    interfaces: Vec<String>,
    from: usize,
    to: usize,
    masquerade: bool,
    advanced: bool,
    source: String,
    cursor: usize,
    field: Field,
    error: Option<String>,
}

impl ForwardingEditor {
    fn fields(&self) -> Vec<Field> {
        let mut fields = vec![Field::From, Field::To, Field::Masquerade, Field::Advanced];
        if self.advanced {
            fields.push(Field::Source);
        }
        fields.push(Field::Save);
        fields
    }

    fn save(&self) -> anyhow::Result<Vec<ForwardingConfig>> {
        let source_subnet = if self.source.trim().is_empty() {
            None
        } else {
            Some(self.source.trim().parse::<ipnet::Ipv4Net>().map_err(|_| {
                anyhow::anyhow!("Enter an IPv4 subnet, e.g. 192.168.10.0/24, or leave it empty")
            })?)
        };
        let rule = ForwardingConfig {
            from: self.interfaces[self.from].clone(),
            to: self.interfaces[self.to].clone(),
            masquerade: self.masquerade,
            source_subnet,
        };
        let mut rules = self.rules.clone();
        if let Some(index) = self.editing {
            rules[index] = rule;
        } else {
            rules.push(rule);
        }
        validate_forwarding(&rules).map_err(anyhow::Error::msg)?;
        Ok(rules)
    }
}

/// None means the old implicit rules have not been loaded, not an empty list.
pub(crate) fn displayed_rules(router: &RouterData) -> Option<Vec<ForwardingConfig>> {
    if let Some(rules) = &router.proposed_router_config.forwarding {
        return Some(rules.clone());
    }
    if !router.topology.loaded {
        return None;
    }
    if router.proposed_router_config.uplink.is_none() {
        return Some(vec![]);
    }
    let plan = router.plan.as_ref()?;
    if let RouterDataplaneTargetView::Enabled(desired) = &plan.dataplane.target {
        Some(
            desired
                .outputs
                .iter()
                .map(|output| ForwardingConfig {
                    from: output.interface.clone(),
                    to: desired.uplink.clone(),
                    masquerade: true,
                    source_subnet: None,
                })
                .collect(),
        )
    } else {
        None
    }
}

async fn load_rules(app: &mut TuiApp, client: &ApiClient) -> Option<Vec<ForwardingConfig>> {
    if !app.router.staged {
        match client.request(&Request::GetRouterConfig).await {
            Ok(Response::RouterConfig { config }) => app.router.proposed_router_config = config,
            _ => {
                app.push_message(
                    LogLevel::Error,
                    "Could not load sharing configuration; refresh and try again",
                );
                return None;
            }
        }
    }
    if !app.router.proposed_router_config.vpn_chain.is_empty() {
        app.push_message(LogLevel::Warn, "The global VPN chain uses legacy forwarding. Configure its tunnel routing before switching to per-interface sharing.");
        return None;
    }
    if let Some(rules) = &app.router.proposed_router_config.forwarding {
        return Some(rules.clone());
    }
    if app.router.proposed_router_config.uplink.is_none() {
        return Some(vec![]);
    }
    let mut legacy = app.router.proposed_router_config.clone();
    legacy.enabled = true;
    let proposal = RouterProposalRequest {
        set_router: Some(legacy),
        ..Default::default()
    };
    if let Ok(Response::RouterPlan { plan }) =
        client.request(&Request::RouterPlan { proposal }).await
    {
        if let RouterDataplaneTargetView::Enabled(desired) = plan.dataplane.target {
            return Some(
                desired
                    .outputs
                    .into_iter()
                    .map(|output| ForwardingConfig {
                        from: output.interface,
                        to: desired.uplink.clone(),
                        masquerade: true,
                        source_subnet: None,
                    })
                    .collect(),
            );
        }
    }
    app.push_message(
        LogLevel::Error,
        "Could not load existing sharing rules; refresh and review the router plan",
    );
    None
}

pub(crate) async fn open_from_route(app: &mut TuiApp, client: &ApiClient) {
    let Some(interface) = app
        .router
        .routes
        .get(app.router.selected_route)
        .and_then(|route| route.output_interface.clone())
    else {
        app.push_message(
            LogLevel::Warn,
            "Select a route with an output interface first",
        );
        return;
    };
    open(app, client, false, Some(interface)).await;
}

async fn open(app: &mut TuiApp, client: &ApiClient, edit: bool, egress: Option<String>) {
    let selected = displayed_rules(&app.router)
        .and_then(|rules| rules.get(app.router.selected_connection).cloned());
    let Some(rules) = load_rules(app, client).await else {
        return;
    };
    let editing = if edit {
        let Some(index) = selected
            .as_ref()
            .and_then(|selected| rules.iter().position(|rule| rule == selected))
        else {
            app.push_message(
                LogLevel::Warn,
                "The selected connection changed; refresh and select it again",
            );
            return;
        };
        Some(index)
    } else {
        None
    };
    let mut interfaces: Vec<_> = app
        .dashboard
        .interfaces
        .iter()
        .map(|status| status.interface.name.clone())
        .collect();
    for rule in &rules {
        interfaces.extend([rule.from.clone(), rule.to.clone()]);
    }
    if let Some(egress) = &egress {
        interfaces.push(egress.clone());
    }
    interfaces.sort();
    interfaces.dedup();
    if interfaces.len() < 2 {
        app.push_message(
            LogLevel::Warn,
            "Sharing needs two interfaces. Create/connect interfaces or VPN tunnels first.",
        );
        return;
    }
    let rule = editing.map(|index| &rules[index]);
    let (default_from, default_to) =
        preferred_new_connection_endpoints(app, &interfaces, egress.as_deref());
    let to = rule
        .and_then(|rule| interfaces.iter().position(|name| name == &rule.to))
        .unwrap_or(default_to);
    let from = rule
        .and_then(|rule| interfaces.iter().position(|name| name == &rule.from))
        .unwrap_or(default_from);
    let source = rule
        .and_then(|rule| rule.source_subnet)
        .map_or(String::new(), |subnet| subnet.to_string());
    let editor = ForwardingEditor {
        interfaces,
        editing,
        from,
        to,
        masquerade: rule.is_none_or(|rule| rule.masquerade),
        advanced: !source.is_empty(),
        cursor: super::input::grapheme_count(&source),
        source,
        rules,
        field: Field::From,
        error: None,
    };
    app.forwarding = Some(editor);
    app.screen = Screen::Forwarding;
}

fn preferred_new_connection_endpoints(
    app: &TuiApp,
    interfaces: &[String],
    explicit_egress: Option<&str>,
) -> (usize, usize) {
    let fallback_to = usize::from(interfaces.len() > 1);
    let to = explicit_egress
        .and_then(|egress| interfaces.iter().position(|name| name == egress))
        .or_else(|| {
            app.dashboard.routes.as_ref().and_then(|routes| {
                routes
                    .iter()
                    .filter(|route| route.destination.prefix_len() == 0)
                    .filter_map(|route| {
                        let name = route.output_interface.as_ref()?;
                        let index = interfaces.iter().position(|candidate| candidate == name)?;
                        Some((route.table != 254, route.metric.unwrap_or(u32::MAX), index))
                    })
                    .min()
                    .map(|(_, _, index)| index)
            })
        })
        .or_else(|| {
            app.dashboard.interfaces.iter().find_map(|status| {
                status.has_default_route.then(|| {
                    interfaces
                        .iter()
                        .position(|name| name == &status.interface.name)
                })?
            })
        })
        .unwrap_or(fallback_to);

    let from = interfaces
        .iter()
        .enumerate()
        .find(|(index, name)| {
            *index != to
                && app.dashboard.managed.get(*name).copied().unwrap_or(false)
                && app.dashboard.roles.get(*name) == Some(&InterfaceRole::Output)
        })
        .map(|(index, _)| index)
        .or_else(|| {
            app.dashboard.interfaces.iter().find_map(|status| {
                if status.has_default_route {
                    return None;
                }
                interfaces
                    .iter()
                    .position(|name| name == &status.interface.name)
                    .filter(|index| *index != to)
            })
        })
        .unwrap_or_else(|| usize::from(to == 0));

    (from, to)
}

fn stage(app: &mut TuiApp, rules: Vec<ForwardingConfig>) {
    app.router.selected_connection = app
        .router
        .selected_connection
        .min(rules.len().saturating_sub(1));
    app.router.proposed_router_config.forwarding = Some(rules);
    app.router.proposed_router_config.enabled = true;
    app.router.staged = true;
    app.router.error = None;
}

const ACTIONS: [&str; 5] = [
    "[Add]",
    "[Edit]",
    "[Delete]",
    "[Review / Apply]",
    "[Refresh]",
];

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
            "Sharing permissions and NAT; routes choose the path"
        })
        .style(Style::default().fg(theme::MUTED)),
        chunks[0],
    );
    let block = panel("Internet sharing");
    let inner = block.inner(chunks[1]);
    let rules = displayed_rules(&app.router);
    let rules_slice = rules.as_deref().unwrap_or(&[]);
    app.router.selected_connection = app
        .router
        .selected_connection
        .min(rules_slice.len().saturating_sub(1));
    let visible = usize::from(inner.height.saturating_sub(1));
    let scroll = app
        .router
        .selected_connection
        .saturating_sub(visible.saturating_sub(1));
    let observed: Option<HashSet<&str>> = app.dashboard.interfaces_updated.map(|_| {
        app.dashboard
            .interfaces
            .iter()
            .map(|status| status.interface.name.as_str())
            .collect()
    });
    let rows = rules_slice
        .iter()
        .enumerate()
        .skip(scroll)
        .take(visible)
        .map(|(index, rule)| {
            let (from_missing, to_missing) = observed.as_ref().map_or((false, false), |names| {
                (
                    !names.contains(rule.from.as_str()),
                    !names.contains(rule.to.as_str()),
                )
            });
            let status = if observed.is_none() {
                "Unknown"
            } else {
                match (from_missing, to_missing) {
                    (true, true) => "Both missing",
                    (true, false) => "From missing",
                    (false, true) => "Through missing",
                    (false, false) => "Present",
                }
            };
            let interface_style = |missing| {
                if missing {
                    Style::default().fg(theme::WARN)
                } else {
                    Style::default()
                }
            };
            Row::new(vec![
                Cell::from(if index == app.router.selected_connection {
                    "▶"
                } else {
                    " "
                }),
                Cell::from(rule.from.clone()).style(interface_style(from_missing)),
                Cell::from(rule.to.clone()).style(interface_style(to_missing)),
                Cell::from(if rule.masquerade { "On" } else { "Off" }),
                Cell::from(
                    rule.source_subnet
                        .map_or("Any".into(), |subnet| subnet.to_string()),
                ),
                Cell::from(status).style(interface_style(from_missing || to_missing)),
            ])
            .style(
                if index == app.router.selected_connection && !app.router.sharing_actions_focused {
                    Style::default()
                        .fg(theme::SELECTED_FG)
                        .bg(theme::SELECTED_BG)
                } else {
                    Style::default()
                },
            )
        });
    let table = Table::new(
        rows,
        [
            Constraint::Length(1),
            Constraint::Min(15),
            Constraint::Min(15),
            Constraint::Length(4),
            Constraint::Length(18),
            Constraint::Length(15),
        ],
    )
    .header(
        Row::new(["", "From", "Through", "NAT", "Source subnet", "Interfaces"])
            .style(Style::default().fg(theme::MUTED)),
    )
    .block(block);
    frame.render_widget(table, chunks[1]);
    app.ui.list_area = Some(Rect::new(
        inner.x,
        inner.y.saturating_add(1),
        inner.width,
        inner.height.saturating_sub(1),
    ));
    app.ui.list_row_height = 1;
    app.ui.list_count = rules_slice.len();
    app.ui.list_scroll_offset = scroll;
    if rules_slice.is_empty() {
        frame.render_widget(
            Paragraph::new(if rules.is_some() {
                "No connections. Choose Add."
            } else {
                "Legacy/unavailable data — refresh before editing"
            }),
            app.ui.list_area.unwrap(),
        );
    }
    let block = panel("Sharing actions");
    let inner = block.inner(chunks[2]);
    frame.render_widget(block, chunks[2]);
    let mut x = inner.x;
    for (index, label) in ACTIONS.into_iter().enumerate() {
        let rect = Rect::new(x, inner.y, label.len() as u16, 1);
        frame.render_widget(
            Paragraph::new(label).style(
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
    let len = displayed_rules(&app.router).map_or(0, |rules| rules.len());
    match key {
        KeyCode::Esc => {
            if app.router.sharing_actions_focused {
                app.router.sharing_actions_focused = false;
            } else {
                super::router::select_pane(app, RouterPane::Routes);
            }
        }
        KeyCode::Tab | KeyCode::BackTab => {
            app.router.sharing_actions_focused = !app.router.sharing_actions_focused
        }
        KeyCode::Char('a') => open(app, client, false, None).await,
        KeyCode::Delete => delete(app, client).await,
        KeyCode::Up if !app.router.sharing_actions_focused => {
            app.router.selected_connection = app.router.selected_connection.saturating_sub(1)
        }
        KeyCode::Down
            if !app.router.sharing_actions_focused && app.router.selected_connection + 1 < len =>
        {
            app.router.selected_connection += 1;
        }
        KeyCode::Left | KeyCode::Up if app.router.sharing_actions_focused => {
            app.router.sharing_action = app.router.sharing_action.saturating_sub(1)
        }
        KeyCode::Right | KeyCode::Down if app.router.sharing_actions_focused => {
            app.router.sharing_action = (app.router.sharing_action + 1).min(ACTIONS.len() - 1)
        }
        KeyCode::Enter | KeyCode::Char(' ') => {
            if !app.router.sharing_actions_focused {
                if len > 0 {
                    open(app, client, true, None).await;
                }
                return;
            }
            match app.router.sharing_action {
                0 => open(app, client, false, None).await,
                1 => {
                    if len > 0 {
                        open(app, client, true, None).await;
                    }
                }
                2 => delete(app, client).await,
                3 => super::router::open_router_plan(app, client).await,
                _ => super::router::refresh_router_data(app, client).await,
            }
        }
        _ => {}
    }
}

async fn delete(app: &mut TuiApp, client: &ApiClient) {
    let selected = displayed_rules(&app.router)
        .and_then(|rules| rules.get(app.router.selected_connection).cloned());
    let Some(selected) = selected else {
        return;
    };
    let Some(mut rules) = load_rules(app, client).await else {
        return;
    };
    if let Some(index) = rules.iter().position(|rule| rule == &selected) {
        rules.remove(index);
        stage(app, rules);
    } else {
        app.push_message(
            LogLevel::Warn,
            "The selected connection changed; refresh and select it again",
        );
    }
}

pub(crate) fn render(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let Some(editor) = &app.forwarding else {
        return;
    };
    let mut lines = vec![];
    for field in editor.fields() {
        let selected = editor.field == field;
        let style = if selected {
            Style::default()
                .fg(theme::SELECTED_FG)
                .bg(theme::SELECTED_BG)
        } else {
            Style::default().fg(theme::TEXT)
        };
        let label = match field {
            Field::From => format!("Traffic from: {}", editor.interfaces[editor.from]),
            Field::To => format!("Internet through: {}", editor.interfaces[editor.to]),
            Field::Masquerade => format!(
                "Masquerade: {}",
                if editor.masquerade { "on" } else { "off" }
            ),
            Field::Advanced => format!(
                "Advanced: {}",
                if editor.advanced {
                    "expanded"
                } else {
                    "collapsed"
                }
            ),
            Field::Source => format!(
                "Source subnet: {}",
                if editor.source.is_empty() {
                    "Any (empty)"
                } else {
                    &editor.source
                }
            ),
            Field::Save => "[Save connection]".into(),
        };
        if field == Field::Source && selected {
            let mut spans = vec![Span::styled("▶ Source subnet: ", style)];
            spans.extend(super::input::render_value_with_cursor(
                &editor.source,
                editor.cursor,
                true,
                style,
            ));
            lines.push(Line::from(spans));
        } else {
            lines.push(Line::styled(
                format!("{}{}", if selected { "▶ " } else { "  " }, label),
                style,
            ));
        }
    }
    if let Some(error) = &editor.error {
        lines.push(Line::styled(error.clone(), Style::default().fg(theme::BAD)));
    }
    let block = panel(if editor.editing.is_some() {
        "Edit sharing connection"
    } else {
        "Add sharing connection"
    });
    let inner = block.inner(area);
    let offset = if editor.error.is_some() {
        lines.len().saturating_sub(inner.height as usize)
    } else {
        focused_lines_offset(&lines, inner.height)
    };
    if let Some(row) = editor
        .fields()
        .iter()
        .position(|field| *field == Field::Save)
        .filter(|row| *row >= offset && *row < offset + inner.height as usize)
    {
        app.ui.buttons.push((
            Rect::new(inner.x, inner.y + (row - offset) as u16, 19, 1),
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

pub(crate) fn focus_action(app: &mut TuiApp, _slot: usize) {
    if let Some(editor) = &mut app.forwarding {
        editor.field = Field::Save;
    }
}

pub(crate) async fn handle_key(app: &mut TuiApp, key: KeyCode, _client: &ApiClient) {
    let Some(editor) = &mut app.forwarding else {
        app.screen = Screen::Router;
        return;
    };
    match key {
        KeyCode::Esc => {
            app.forwarding = None;
            app.screen = Screen::Router;
        }
        KeyCode::Up | KeyCode::BackTab | KeyCode::Down | KeyCode::Tab => {
            let fields = editor.fields();
            let forward = !matches!(key, KeyCode::Up | KeyCode::BackTab);
            editor.field = super::input::move_clamped(&fields, editor.field, forward);
        }
        KeyCode::Enter if editor.field == Field::Save => match editor.save() {
            Ok(rules) => {
                let selected = editor.editing.unwrap_or(rules.len() - 1);
                stage(app, rules);
                app.router.selected_connection = selected;
                app.forwarding = None;
                app.screen = Screen::Router;
                super::router::select_pane(app, RouterPane::Sharing);
            }
            Err(error) => editor.error = Some(error.to_string()),
        },
        key if editor.field == Field::Source => {
            super::input::TextEditor::new(&mut editor.source, &mut editor.cursor).handle_key(key);
        }
        KeyCode::Left | KeyCode::Right | KeyCode::Enter | KeyCode::Char(' ') => {
            let delta = if key == KeyCode::Left {
                editor.interfaces.len() - 1
            } else {
                1
            };
            match editor.field {
                Field::From => editor.from = (editor.from + delta) % editor.interfaces.len(),
                Field::To => editor.to = (editor.to + delta) % editor.interfaces.len(),
                Field::Masquerade => editor.masquerade = !editor.masquerade,
                Field::Advanced => editor.advanced = !editor.advanced,
                _ => {}
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests;
