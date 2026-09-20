use crossterm::event::KeyCode;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::api::client::ApiClient;
use crate::api::model::{DhcpClientConfigRequest, DhcpClientOperationalState, Request, Response};

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
    if let Some(selected) = app.dhcp_client_selected.as_ref() {
        let present = app
            .dashboard
            .interfaces
            .iter()
            .any(|status| status.interface.name.as_str() == selected.as_str());
        if present && !names.iter().any(|name| name == selected) {
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

    let list_area = Rect::new(
        inner.x,
        inner.y.saturating_add(1),
        inner.width,
        inner.height.saturating_sub(1),
    );
    let names = row_names(app);
    let selected = selected_row(app, &names);
    let visible_items = (list_area.height / 3).max(1) as usize;
    if selected < app.dhcp_client_scroll {
        app.dhcp_client_scroll = selected;
    } else if selected >= app.dhcp_client_scroll.saturating_add(visible_items) {
        app.dhcp_client_scroll = selected + 1 - visible_items;
    }
    let max_scroll = names.len().saturating_sub(visible_items);
    app.dhcp_client_scroll = app.dhcp_client_scroll.min(max_scroll);

    app.ui.list_area = Some(list_area);
    app.ui.list_row_height = 3;
    app.ui.list_count = names.len();
    app.ui.list_scroll_offset = app.dhcp_client_scroll;

    if names.is_empty() {
        frame.render_widget(
            Paragraph::new("No interfaces available. Select an interface on the Interfaces tab first.")
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
        let is_selected = app.dhcp_client_selected.as_deref() == Some(name.as_str());
        let status = app.dhcp_clients.iter().find(|status| status.interface.as_str() == name.as_str());
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
                Span::styled(format!("{marker} {:<12}", name), name_style),
                Span::styled(state, Style::default().fg(state_color)),
                Span::raw(format!(
                    "  address {}  server {}",
                    status.address.map(|v| v.to_string()).unwrap_or_else(|| "—".into()),
                    status.server.map(|v| v.to_string()).unwrap_or_else(|| "—".into())
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
                "  [c] configure defaults  [r] renew/revalidate  [x] release/reacquire  [d] delete",
                Style::default().fg(theme::ACCENT),
            ));
        } else {
            lines.push(Line::from(vec![
                Span::styled(format!("{marker} {:<12}", name), name_style),
                Span::styled("not configured", Style::default().fg(theme::MUTED)),
            ]));
            lines.push(Line::styled(
                "  Selected on Interfaces; no managed DHCP client exists yet.",
                Style::default().fg(theme::MUTED),
            ));
            lines.push(Line::styled(
                "  [c] configure sensible defaults",
                Style::default().fg(theme::ACCENT),
            ));
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

    let Some(interface) = app.dhcp_client_selected.clone() else {
        if matches!(key, KeyCode::Char('c') | KeyCode::Char('r') | KeyCode::Char('x') | KeyCode::Char('d')) {
            app.push_message(LogLevel::Warn, "Select an interface first");
        }
        return;
    };
    let configured = app
        .dhcp_clients
        .iter()
        .any(|status| status.interface.as_str() == interface.as_str());
    let request = action_request(&interface, configured, key);
    let Some(request) = request else {
        if matches!(key, KeyCode::Char('r') | KeyCode::Char('x') | KeyCode::Char('d')) && !configured {
            app.push_message(
                LogLevel::Warn,
                format!("DHCP client is not configured on {interface}"),
            );
        }
        return;
    };

    match client.request(&request).await {
        Ok(Response::DhcpClientError { detail }) => app.push_message(
            LogLevel::Error,
            format!("Uplink DHCP action failed: {detail:?}"),
        ),
        Ok(_) => {
            app.push_message(LogLevel::Info, "Uplink DHCP action applied");
            refresh(app, client).await;
        }
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
mod tests {
    use std::net::Ipv4Addr;

    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use super::*;
    use crate::api::model::DhcpClientStatusView;

    fn status_named(interface: &str, state: DhcpClientOperationalState) -> DhcpClientStatusView {
        DhcpClientStatusView {
            interface: interface.into(),
            state,
            address: Some(Ipv4Addr::new(192, 0, 2, 42)),
            prefix_length: Some(24),
            server: Some(Ipv4Addr::new(192, 0, 2, 1)),
            expires_at_unix: Some(2_000_000_000),
            dns_servers: vec![Ipv4Addr::new(192, 0, 2, 53)],
            degraded_reason: None,
            config: DhcpClientConfigRequest::default(),
        }
    }

    fn status(state: DhcpClientOperationalState) -> DhcpClientStatusView {
        status_named("wan0", state)
    }

    #[test]
    fn uplink_dhcp_render_shows_status_details_and_separates_server_terminology() {
        for (state, label) in [
            (DhcpClientOperationalState::Waiting, "waiting"),
            (DhcpClientOperationalState::Running, "running"),
            (DhcpClientOperationalState::Degraded, "degraded"),
        ] {
            let mut app = TuiApp {
                dhcp_clients: vec![status(state)],
                dhcp_client_selected: Some("wan0".into()),
                ..Default::default()
            };
            let backend = TestBackend::new(100, 10);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal
                .draw(|frame| render(frame, frame.area(), &mut app))
                .unwrap();
            let rendered = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|cell| cell.symbol())
                .collect::<String>();
            assert!(rendered.contains("DHCP Client"));
            assert!(rendered.contains("separate from the DHCP server"));
            assert!(rendered.contains(label));
            assert!(rendered.contains("192.0.2.42"));
            assert!(rendered.contains("192.0.2.1"));
            assert!(rendered.contains("192.0.2.53"));
        }
    }

    #[test]
    fn uplink_dhcp_actions_use_the_selected_interface_name() {
        assert!(matches!(
            action_request("wan0", false, KeyCode::Char('c')),
            Some(Request::ConfigureDhcpClient { interface, config })
                if interface == "wan0" && config == DhcpClientConfigRequest::default()
        ));
        assert!(action_request("wan0", false, KeyCode::Char('r')).is_none());
        assert!(matches!(
            action_request("wan0", true, KeyCode::Char('r')),
            Some(Request::RenewDhcpClient { interface }) if interface == "wan0"
        ));
    }

    #[test]
    fn selection_is_by_interface_name_not_status_index() {
        let mut app = TuiApp {
            dhcp_clients: vec![
                status(DhcpClientOperationalState::Running),
                status_named("lan9", DhcpClientOperationalState::Waiting),
            ],
            dhcp_client_selected: Some("lan9".into()),
            ..Default::default()
        };
        let names = row_names(&app);
        assert_eq!(names, vec!["wan0", "lan9"]);
        move_selection(&mut app, false);
        assert_eq!(app.dhcp_client_selected.as_deref(), Some("wan0"));
    }
}
