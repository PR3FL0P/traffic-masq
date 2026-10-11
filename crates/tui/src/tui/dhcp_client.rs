use crossterm::event::KeyCode;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::tui::api::client::ApiClient;
use crate::tui::api::model::{
    DhcpClientConfigRequest, DhcpClientOperationalState, Request, Response,
};

use super::layout::panel;
use super::logs::LogLevel;
use super::theme;
use super::{Screen, TuiApp};

fn row_names(app: &TuiApp) -> Vec<String> {
    let mut names = app
        .dhcp_clients
        .iter()
        .map(|status| status.interface.clone())
        .collect::<Vec<_>>();
    if let Some(entries) = &app.dashboard.inventory {
        for entry in entries {
            if entry
                .configured
                .as_ref()
                .is_some_and(|config| config.dhcp_client.is_some())
                && !names.contains(&entry.name)
            {
                names.push(entry.name.clone());
            }
        }
    }
    if let Some(selected) = app.dhcp_client_selected.as_ref() {
        let known = app.dashboard.inventory.as_ref().map_or_else(
            || {
                app.dashboard
                    .interfaces
                    .iter()
                    .any(|status| &status.interface.name == selected)
            },
            |entries| entries.iter().any(|entry| &entry.name == selected),
        );
        if known && !names.iter().any(|name| name == selected) {
            names.push(selected.clone());
        }
    }
    names
}

fn selected_row(app: &TuiApp, names: &[String]) -> usize {
    app.dhcp_client_selected
        .as_ref()
        .and_then(|selected| names.iter().position(|name| name == selected))
        .unwrap_or(0)
}

pub(crate) fn select_row(app: &mut TuiApp, index: usize) {
    if let Some(name) = row_names(app).get(index).cloned() {
        app.dhcp_client_selected = Some(name);
    }
}

pub(crate) fn move_selection(app: &mut TuiApp, forward: bool) {
    let names = row_names(app);
    if names.is_empty() {
        return;
    }
    let current = selected_row(app, &names);
    let next = if forward {
        (current + 1).min(names.len() - 1)
    } else {
        current.saturating_sub(1)
    };
    app.dhcp_client_selected = Some(names[next].clone());
}

pub(crate) fn render(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let block = panel("DHCP Client");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.height == 0 {
        return;
    }
    frame.render_widget(
        Paragraph::new("Dynamic IPv4 uplinks — separate from the DHCP server")
            .style(Style::default().fg(theme::MUTED)),
        Rect::new(inner.x, inner.y, inner.width, 1),
    );

    frame.render_widget(
        Paragraph::new("Route policy changes require confirmation. Other actions are immediate. [c] resets DHCP policy.")
            .style(Style::default().fg(theme::WARN)),
        Rect::new(
            inner.x,
            inner.y.saturating_add(1),
            inner.width,
            inner.height.saturating_sub(1).min(1),
        ),
    );
    let list_area = Rect::new(
        inner.x,
        inner.y.saturating_add(2),
        inner.width,
        inner.height.saturating_sub(2),
    );
    let names = row_names(app);
    let selected = selected_row(app, &names);
    let visible_items = (list_area.height / 4).max(1) as usize;
    if selected < app.dhcp_client_scroll {
        app.dhcp_client_scroll = selected;
    } else if selected >= app.dhcp_client_scroll.saturating_add(visible_items) {
        app.dhcp_client_scroll = selected + 1 - visible_items;
    }
    let max_scroll = names.len().saturating_sub(visible_items);
    app.dhcp_client_scroll = app.dhcp_client_scroll.min(max_scroll);

    app.ui.list_area = Some(list_area);
    app.ui.list_row_height = 4;
    app.ui.list_count = names.len();
    app.ui.list_scroll_offset = app.dhcp_client_scroll;

    if names.is_empty() {
        frame.render_widget(
            Paragraph::new(
                "No interfaces available. Select an interface on the Interfaces tab first.",
            )
            .style(Style::default().fg(theme::MUTED)),
            list_area,
        );
        return;
    }

    let mut lines = Vec::new();
    for name in names
        .iter()
        .skip(app.dhcp_client_scroll)
        .take(visible_items)
    {
        let is_selected = names.get(selected) == Some(name);
        let entry = app
            .dashboard
            .inventory
            .as_ref()
            .and_then(|entries| entries.iter().find(|entry| &entry.name == name));
        let saved = entry
            .and_then(|entry| entry.configured.as_ref())
            .and_then(|config| config.dhcp_client.as_ref());
        let presence = match entry.map(|entry| entry.presence) {
            Some(traffic_masq_protocol::InterfacePresence::Missing) => " (Missing)",
            Some(traffic_masq_protocol::InterfacePresence::Unknown) => " (observation unavailable)",
            _ => "",
        };
        let status = app
            .dhcp_clients
            .iter()
            .find(|status| status.interface.as_str() == name.as_str());
        let marker = if is_selected { "▶" } else { " " };
        let name_style = if is_selected {
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };

        if let Some(status) = status {
            let state = match status.state {
                DhcpClientOperationalState::Waiting => "waiting",
                DhcpClientOperationalState::Running => "running",
                DhcpClientOperationalState::Degraded => "degraded",
            };
            let state_color = match status.state {
                DhcpClientOperationalState::Waiting => theme::WARN,
                DhcpClientOperationalState::Running => theme::GOOD,
                DhcpClientOperationalState::Degraded => theme::BAD,
            };
            lines.push(Line::from(vec![
                Span::styled(format!("{marker} {name:<12}{presence} "), name_style),
                Span::styled(state, Style::default().fg(state_color)),
                Span::raw(format!(
                    "  address {}  server {}",
                    status
                        .address
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "—".into()),
                    status
                        .server
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "—".into())
                )),
            ]));
            lines.push(Line::from(format!(
                "  expiry {}  DNS {}",
                status
                    .expires_at_unix
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "—".into()),
                if status.dns_servers.is_empty() {
                    "—".into()
                } else {
                    status
                        .dns_servers
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            )));
            lines.push(Line::styled(
                status
                    .degraded_reason
                    .as_ref()
                    .map(|reason| format!("  {reason}"))
                    .unwrap_or_else(|| {
                        format!(
                            "  hostname {}  metric {}  default route {}  request DNS {}",
                            status.config.hostname.as_deref().unwrap_or("(not sent)"),
                            status.config.route_metric,
                            status.config.install_default_route,
                            status.config.request_dns
                        )
                    }),
                Style::default().fg(if status.degraded_reason.is_some() {
                    theme::BAD
                } else {
                    theme::MUTED
                }),
            ));
            lines.push(Line::styled(
                "  [e] edit  [c] reset defaults  [r] renew  [x] release/reacquire  [d] disable",
                Style::default().fg(theme::ACCENT),
            ));
        } else {
            lines.push(Line::from(vec![
                Span::styled(format!("{marker} {name:<12}{presence} "), name_style),
                Span::styled(
                    match saved {
                        Some(config) if config.enabled => "configured; runtime unavailable",
                        Some(_) => "disabled",
                        None => "not configured",
                    },
                    Style::default().fg(theme::MUTED),
                ),
            ]));
            lines.push(Line::styled(
                "  Requires managed Input without static IPv4 (set in Interfaces).",
                Style::default().fg(theme::MUTED),
            ));
            lines.push(Line::styled(
                "  [e] configure  [c] enable with defaults",
                Style::default().fg(theme::ACCENT),
            ));
            lines.push(Line::from(""));
        }
    }
    frame.render_widget(Paragraph::new(lines), list_area);
}

pub(crate) async fn refresh(app: &mut TuiApp, client: &ApiClient) {
    match client.request(&Request::DhcpClientStatus).await {
        Ok(Response::DhcpClientStatus { interfaces }) => {
            app.dhcp_clients = interfaces;
            let names = row_names(app);
            if !app
                .dhcp_client_selected
                .as_ref()
                .is_some_and(|selected| names.iter().any(|name| name == selected))
            {
                app.dhcp_client_selected = names.first().cloned();
            }
        }
        Ok(Response::DhcpClientError { detail }) => app.push_message(
            LogLevel::Warn,
            format!("Uplink DHCP unavailable: {detail:?}"),
        ),
        Ok(_) => app.push_message(LogLevel::Error, "Unexpected uplink DHCP response"),
        Err(error) => app.push_message(
            LogLevel::Error,
            format!("Failed to refresh uplink DHCP: {error}"),
        ),
    }
}

pub(crate) async fn handle_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    match key {
        KeyCode::Esc => {
            app.screen = Screen::Dashboard;
            return;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            move_selection(app, false);
            return;
        }
        KeyCode::Down | KeyCode::Char('j') => {
            move_selection(app, true);
            return;
        }
        KeyCode::Home => {
            select_row(app, 0);
            return;
        }
        KeyCode::End => {
            let last = row_names(app).len().saturating_sub(1);
            select_row(app, last);
            return;
        }
        _ => {}
    }

    let names = row_names(app);
    let Some(interface) = names.get(selected_row(app, &names)).cloned() else {
        if matches!(
            key,
            KeyCode::Char('c') | KeyCode::Char('r') | KeyCode::Char('x') | KeyCode::Char('d')
        ) {
            app.push_message(LogLevel::Warn, "Select an interface first");
        }
        return;
    };
    app.dhcp_client_selected = Some(interface.clone());
    if matches!(key, KeyCode::Char('e') | KeyCode::Enter) {
        super::dhcp_client_editor::open(app, client, interface).await;
        return;
    }
    let configured = app
        .dhcp_clients
        .iter()
        .any(|status| status.interface.as_str() == interface.as_str());
    let request = action_request(&interface, configured, key);
    let Some(request) = request else {
        if matches!(
            key,
            KeyCode::Char('r') | KeyCode::Char('x') | KeyCode::Char('d')
        ) && !configured
        {
            app.push_message(
                LogLevel::Warn,
                format!("DHCP client is not configured on {interface}"),
            );
        }
        return;
    };

    match client.request(&request).await {
        Ok(Response::NetworkChangePending { change })
            if change.interface == interface
                && matches!(request, Request::ConfigureDhcpClient { .. }) =>
        {
            app.pending = Some(change);
            app.pending_return_screen = Screen::DhcpClient;
            app.screen = Screen::PendingChange;
        }
        Ok(Response::DhcpClientError { detail }) => app.push_message(
            LogLevel::Error,
            format!("Uplink DHCP action failed: {detail:?}"),
        ),
        Ok(Response::DhcpClientInterface { status })
            if status.interface == interface
                && !matches!(request, Request::DisableDhcpClient { .. }) =>
        {
            app.push_message(
                LogLevel::Info,
                format!("Uplink DHCP action accepted on {interface}; check lease status"),
            );
            refresh(app, client).await;
        }
        Ok(Response::DhcpClientDisabled {
            interface: disabled,
        }) if disabled == interface && matches!(request, Request::DisableDhcpClient { .. }) => {
            app.push_message(
                LogLevel::Info,
                format!("DHCP client disabled on {interface}"),
            );
            refresh(app, client).await;
        }
        Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected uplink DHCP action response: {response:?}"),
        ),
        Err(error) => app.push_message(
            LogLevel::Error,
            format!("Uplink DHCP action failed: {error}"),
        ),
    }
}

fn action_request(interface: &str, configured: bool, key: KeyCode) -> Option<Request> {
    match key {
        KeyCode::Char('c') => Some(Request::ConfigureDhcpClient {
            interface: interface.to_string(),
            config: DhcpClientConfigRequest::default(),
        }),
        KeyCode::Char('r') if configured => Some(Request::RenewDhcpClient {
            interface: interface.to_string(),
        }),
        KeyCode::Char('x') if configured => Some(Request::ReleaseDhcpClient {
            interface: interface.to_string(),
        }),
        KeyCode::Char('d') if configured => Some(Request::DisableDhcpClient {
            interface: interface.to_string(),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
