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
use super::TuiApp;

pub(crate) fn render(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let block = panel("DHCP Client");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    app.ui.list_area = Some(inner);
    app.ui.list_row_height = 3;
    app.ui.list_count = app.dhcp_clients.len();
    app.ui.list_scroll_offset = 0;

    let mut lines = vec![Line::styled(
        "Dynamic IPv4 uplinks — separate from the DHCP server",
        Style::default().fg(theme::MUTED),
    )];
    for (index, status) in app.dhcp_clients.iter().enumerate() {
        let selected = index == app.selected_interface;
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
        let marker = if selected { "▶" } else { " " };
        lines.push(Line::from(vec![
            Span::styled(
                format!("{marker} {:<12}", status.interface),
                if selected {
                    Style::default()
                        .fg(theme::ACCENT)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                },
            ),
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
            "  [c] configure defaults  [r] renew/revalidate  [x] release/reacquire  [d] delete",
            Style::default().fg(theme::ACCENT),
        ));
    }
    if app.dhcp_clients.is_empty() {
        lines.push(Line::from("No managed uplink DHCP clients. Select an interface on the Interfaces tab, then press c here to configure sensible defaults."));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

pub(crate) async fn refresh(app: &mut TuiApp, client: &ApiClient) {
    match client.request(&Request::DhcpClientStatus).await {
        Ok(Response::DhcpClientStatus { interfaces }) => {
            app.dhcp_clients = interfaces;
            app.selected_interface = app
                .selected_interface
                .min(app.dhcp_clients.len().saturating_sub(1));
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
    let configured = app
        .dhcp_clients
        .get(app.selected_interface)
        .map(|s| s.interface.clone());
    let fallback = app
        .dashboard
        .interfaces
        .get(app.selected_interface)
        .map(|s| s.interface.name.clone());
    let request = action_request(configured.clone(), fallback, key);
    if matches!(key, KeyCode::Up | KeyCode::Char('k')) {
        app.selected_interface = app.selected_interface.saturating_sub(1);
        return;
    }
    if matches!(key, KeyCode::Down | KeyCode::Char('j')) {
        app.selected_interface =
            (app.selected_interface + 1).min(app.dhcp_clients.len().saturating_sub(1));
        return;
    }

    let Some(request) = request else {
        app.push_message(LogLevel::Warn, "Select an interface first");
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

fn action_request(
    configured: Option<String>,
    fallback: Option<String>,
    key: KeyCode,
) -> Option<Request> {
    match key {
        KeyCode::Char('c') => {
            configured
                .or(fallback)
                .map(|interface| Request::ConfigureDhcpClient {
                    interface,
                    config: DhcpClientConfigRequest::default(),
                })
        }
        KeyCode::Char('r') => configured.map(|interface| Request::RenewDhcpClient { interface }),
        KeyCode::Char('x') => configured.map(|interface| Request::ReleaseDhcpClient { interface }),
        KeyCode::Char('d') => configured.map(|interface| Request::DisableDhcpClient { interface }),
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

    fn status(state: DhcpClientOperationalState) -> DhcpClientStatusView {
        DhcpClientStatusView {
            interface: "wan0".into(),
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

    #[test]
    fn uplink_dhcp_render_shows_status_details_and_separates_server_terminology() {
        for (state, label) in [
            (DhcpClientOperationalState::Waiting, "waiting"),
            (DhcpClientOperationalState::Running, "running"),
            (DhcpClientOperationalState::Degraded, "degraded"),
        ] {
            let mut app = TuiApp::default();
            app.dhcp_clients = vec![status(state)];
            let backend = TestBackend::new(100, 10);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal
                .draw(|frame| render(frame, frame.area(), &mut app))
                .unwrap();
            let rendered = terminal
                .backend()
                .buffer()
                .content()
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
    fn uplink_dhcp_actions_map_to_dedicated_client_requests_with_defaults() {
        assert!(
            matches!(action_request(None, Some("wan0".into()), KeyCode::Char('c')), Some(Request::ConfigureDhcpClient { interface, config }) if interface == "wan0" && config == DhcpClientConfigRequest::default())
        );
        assert!(
            matches!(action_request(Some("wan0".into()), None, KeyCode::Char('r')), Some(Request::RenewDhcpClient { interface }) if interface == "wan0")
        );
        assert!(
            matches!(action_request(Some("wan0".into()), None, KeyCode::Char('x')), Some(Request::ReleaseDhcpClient { interface }) if interface == "wan0")
        );
        assert!(
            matches!(action_request(Some("wan0".into()), None, KeyCode::Char('d')), Some(Request::DisableDhcpClient { interface }) if interface == "wan0")
        );
    }
}
