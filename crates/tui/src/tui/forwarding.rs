//! Internet sharing is independent of the route list. Editing only stages intent.
use std::collections::HashSet;

use super::{
    layout::{panel, wrap_styled_lines as wrap_lines},
    logs::LogLevel,
    router::{RouterData, RouterPane},
    theme, Screen, TuiApp,
};
use crate::tui::api::client::ApiClient;
use crossterm::event::KeyCode;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Cell, Paragraph, Row, Table},
};
use traffic_masq_protocol::{
    validate_forwarding, ForwardingConfigView as ForwardingConfig, InterfaceRole,
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
    error_field: Option<Field>,
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

    fn save(&self) -> Result<Vec<ForwardingConfig>, super::input::FormError<Field>> {
        use super::input::FormError;
        let source_subnet = if self.source.trim().is_empty() {
            None
        } else {
            Some(self.source.trim().parse::<ipnet::Ipv4Net>().map_err(|_| {
                FormError::field(
                    Field::Source,
                    "Enter an IPv4 subnet, e.g. 192.168.10.0/24, or leave it empty",
                )
            })?)
        };
        if self.from == self.to {
            return Err(FormError::field(
                Field::To,
                "Choose a different egress interface",
            ));
        }
        if source_subnet.is_some_and(|net| net != net.trunc()) {
            return Err(FormError::field(
                Field::Source,
                "Source subnet must have no host bits",
            ));
        }
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
        validate_forwarding(&rules).map_err(FormError::form)?;
        Ok(rules)
    }
}

/// None means saved configuration has not been loaded.
pub(crate) fn displayed_rules(router: &RouterData) -> Option<Vec<ForwardingConfig>> {
    if !router.topology.loaded && router.proposed_router_config.forwarding.is_none() {
        return None;
    }
    Some(
        router
            .proposed_router_config
            .forwarding
            .clone()
            .unwrap_or_default(),
    )
}

async fn load_rules(app: &mut TuiApp, client: &ApiClient) -> Option<Vec<ForwardingConfig>> {
    if !app.router.staged {
        super::router::load_router_data(app, client).await;
        if !app.router.topology.loaded {
            app.push_message(
                LogLevel::Error,
                "Could not refresh saved sharing configuration; refresh and try again",
            );
            return None;
        }
    }
    let rules = displayed_rules(&app.router);
    if rules.is_none() {
        app.push_message(
            LogLevel::Error,
            "Could not load saved sharing configuration; refresh and try again",
        );
    }
    rules
}

pub(crate) async fn open_from_route(app: &mut TuiApp, client: &ApiClient) {
    let Some(interface) = app
        .router
        .route_rows()
        .get(app.router.selected_route)
        .and_then(super::router::row_config)
        .and_then(|route| route.output_interface)
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
    let mut interfaces = super::router::sharing_interface_names(app);
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
        error_field: None,
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
                        Some((route.table != 254, route.metric.unwrap_or(0), index))
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
    app.router.staged = true;
    app.push_message(
        LogLevel::Info,
        "Router draft updated — not applied. Review / Apply to continue.",
    );
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
            "Draft — not applied. Review / Apply to continue"
        } else {
            "Sharing permissions and NAT; tm:on/off = traffic-masq control"
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
    let visible = usize::from(inner.height.saturating_sub(1) / 3);
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
            let inventory_unknown = [&rule.from, &rule.to].iter().any(|name| {
                app.router.saved_interfaces.iter().any(|entry| {
                    entry.name == **name
                        && entry.presence == traffic_masq_protocol::InterfacePresence::Unknown
                })
            });
            let (from_missing, to_missing) = observed.as_ref().map_or((false, false), |names| {
                (
                    !names.contains(rule.from.as_str()),
                    !names.contains(rule.to.as_str()),
                )
            });
            let status = if observed.is_none() || inventory_unknown {
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
                Cell::from(super::interface_status::cell(app, &rule.from))
                    .style(interface_style(from_missing)),
                Cell::from(super::interface_status::cell(app, &rule.to))
                    .style(interface_style(to_missing)),
                Cell::from(if rule.masquerade { "On" } else { "Off" }),
                Cell::from(
                    rule.source_subnet
                        .map_or("Any".into(), |subnet| subnet.to_string()),
                ),
                Cell::from(status).style(interface_style(from_missing || to_missing)),
            ])
            .height(3)
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
    app.ui.list_row_height = 3;
    app.ui.list_count = rules_slice.len();
    app.ui.list_scroll_offset = scroll;
    if rules_slice.is_empty() {
        frame.render_widget(
            Paragraph::new(if rules.is_some() {
                "No connections. Choose Add."
            } else {
                "Unavailable data — refresh before editing"
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
    let block = panel(if editor.editing.is_some() {
        "Edit sharing connection"
    } else {
        "Add sharing connection"
    });
    let inner = block.inner(area);
    let mut lines = vec![];
    let mut focus_row = 0;
    let mut save_row = 0;
    for field in editor.fields() {
        let selected = editor.field == field;
        let style = if editor.error_field == Some(field) {
            Style::default().fg(theme::BAD)
        } else if selected {
            Style::default()
                .fg(theme::SELECTED_FG)
                .bg(theme::SELECTED_BG)
        } else {
            Style::default().fg(theme::TEXT)
        };
        let label = match field {
            Field::From => format!(
                "Traffic from: {}",
                super::interface_status::describe(app, &editor.interfaces[editor.from])
            ),
            Field::To => format!(
                "Internet through: {}",
                super::interface_status::describe(app, &editor.interfaces[editor.to])
            ),
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
        if selected {
            focus_row = lines.len();
        }
        if field == Field::Save {
            save_row = lines.len();
        }
        let mut row = Vec::new();
        if field == Field::Source && selected {
            let mut spans = vec![Span::styled("▶ Source subnet: ", style)];
            spans.extend(super::input::render_value_with_cursor(
                &editor.source,
                editor.cursor,
                true,
                style,
            ));
            row.push(Line::from(spans));
        } else {
            row.push(Line::styled(
                format!("{}{}", if selected { "▶ " } else { "  " }, label),
                style,
            ));
        }
        lines.extend(wrap_lines(row, inner.width));
        if editor.error_field == Some(field) {
            if let Some(error) = &editor.error {
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
    if editor.error_field.is_none() {
        if let Some(error) = &editor.error {
            lines.extend(wrap_lines(
                vec![Line::styled(
                    format!("Rule conflict: {error}"),
                    Style::default().fg(theme::BAD),
                )],
                inner.width,
            ));
        }
    }
    let offset =
        if editor.error.is_some() && editor.error_field.is_none() && editor.field == Field::Save {
            lines.len().saturating_sub(inner.height as usize)
        } else if editor.error_field == Some(editor.field) {
            focus_row
        } else {
            focus_row.saturating_sub(inner.height.saturating_sub(3) as usize)
        };
    if save_row >= offset && save_row < offset + inner.height as usize {
        app.ui.buttons.push((
            Rect::new(
                inner.x,
                inner.y + (save_row - offset) as u16,
                19.min(inner.width),
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
            Err(error) => {
                editor.error_field = error.field;
                if let Some(field) = error.field {
                    editor.field = field;
                    if field == Field::Source {
                        editor.advanced = true;
                    }
                }
                editor.error = Some(error.message);
            }
        },
        KeyCode::Enter if editor.field == Field::Source => editor.field = Field::Save,
        key if editor.field == Field::Source => {
            let handled = super::input::TextEditor::new(&mut editor.source, &mut editor.cursor)
                .handle_key(key);
            if handled {
                editor.error = None;
                editor.error_field = None;
            }
        }
        KeyCode::Left | KeyCode::Right | KeyCode::Enter | KeyCode::Char(' ') => {
            editor.error = None;
            editor.error_field = None;
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
