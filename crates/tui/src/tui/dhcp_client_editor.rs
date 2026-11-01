use crossterm::event::KeyCode;
use ratatui::{
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};
use traffic_masq_protocol::{DhcpClientConfigRequest, InterfaceConfigView};

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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    Metric,
    Hostname,
    DefaultRoute,
    Dns,
    Release,
    Apply,
    Cancel,
}
const FIELDS: [Field; 7] = [
    Field::Metric,
    Field::Hostname,
    Field::DefaultRoute,
    Field::Dns,
    Field::Release,
    Field::Apply,
    Field::Cancel,
];

pub(crate) struct Editor {
    interface: String,
    config: DhcpClientConfigRequest,
    original: DhcpClientConfigRequest,
    exit_requested: bool,
    metric: String,
    hostname: String,
    cursor: usize,
    field: Field,
}

impl Editor {
    fn new(interface: String, config: DhcpClientConfigRequest) -> Self {
        let metric = config.route_metric.to_string();
        let hostname = config.hostname.clone().unwrap_or_default();
        Self {
            interface,
            original: config.clone(),
            config,
            exit_requested: false,
            cursor: metric.len(),
            metric,
            hostname,
            field: Field::Metric,
        }
    }
    fn dirty(&self) -> bool {
        self.config != self.original
            || self.metric != self.original.route_metric.to_string()
            || self.hostname != self.original.hostname.as_deref().unwrap_or("")
    }
    fn request(&self) -> Result<Request, &'static str> {
        let mut config = self.config.clone();
        config.route_metric = self
            .metric
            .trim()
            .parse()
            .map_err(|_| "Metric must be an integer from 0 to 4294967295")?;
        let hostname = self.hostname.trim();
        config.hostname = if hostname.is_empty() {
            None
        } else {
            traffic_masq_protocol::validate_dhcp_hostname(hostname)?;
            Some(hostname.to_string())
        };
        Ok(Request::ConfigureDhcpClient {
            interface: self.interface.clone(),
            config,
        })
    }
}

fn saved_policy(config: Option<InterfaceConfigView>) -> DhcpClientConfigRequest {
    config
        .and_then(|c| c.dhcp_client)
        .map(|c| DhcpClientConfigRequest {
            hostname: c.hostname,
            route_metric: c.route_metric,
            install_default_route: c.install_default_route,
            request_dns: c.request_dns,
            send_release_on_shutdown: c.send_release_on_shutdown,
        })
        .unwrap_or_default()
}

pub(crate) async fn open(app: &mut TuiApp, client: &ApiClient, interface: String) {
    match client
        .request(&Request::GetInterfaceConfig {
            interface: interface.clone(),
        })
        .await
    {
        Ok(Response::InterfaceConfig {
            interface: returned,
            config,
            ..
        }) if returned == interface => {
            app.dhcp_ui.dhcp_client_editor = Some(Editor::new(interface, saved_policy(config)));
            app.screen = Screen::DhcpClientEditor;
        }
        Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
        Ok(_) => app.push_message(
            LogLevel::Error,
            "Could not load DHCP client settings; editor was not opened",
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

pub(crate) fn focus_action(app: &mut TuiApp, slot: usize) {
    if let (Some(editor), Some(field)) = (app.dhcp_ui.dhcp_client_editor.as_mut(), FIELDS.get(slot))
    {
        editor.field = *field;
        editor.cursor = input::grapheme_count(if editor.field == Field::Hostname {
            &editor.hostname
        } else {
            &editor.metric
        });
    }
}

pub(crate) fn render(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    if let Some(dialog) = exit_confirmation(app) {
        dialog.render(
            frame,
            area,
            &mut app.ui,
            app.confirmation.confirmation_focus,
            app.confirmation.confirmation_scroll,
        );
        return;
    }
    let Some(editor) = &app.dhcp_ui.dhcp_client_editor else {
        return;
    };
    let block = panel("DHCP Client settings");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let mut lines = vec![
        Line::from(format!(
            "Interface: {}",
            super::interface_status::describe(app, &editor.interface)
        )),
        Line::styled(
            "DHCP client configuration requires confirmation with a rollback timer.",
            Style::default().fg(theme::WARN),
        ),
        Line::from(""),
    ];
    for (index, field) in FIELDS.iter().enumerate() {
        let selected = editor.field == *field;
        let style = Style::default().fg(if selected { theme::ACCENT } else { theme::TEXT });
        let label = match field {
            Field::Metric => "Route metric".to_string(),
            Field::Hostname => "Hostname (empty: do not send)".to_string(),
            Field::DefaultRoute => format!(
                "Install default route: {}",
                editor.config.install_default_route
            ),
            Field::Dns => format!("Request DNS: {}", editor.config.request_dns),
            Field::Release => format!(
                "Send Release on shutdown: {}",
                editor.config.send_release_on_shutdown
            ),
            Field::Apply => "Apply DHCP client settings now".into(),
            Field::Cancel => "Cancel".into(),
        };
        let mut spans = vec![Span::styled(
            format!("{} {label}", if selected { "▶" } else { " " }),
            style,
        )];
        if matches!(field, Field::Metric | Field::Hostname) {
            let value = if *field == Field::Hostname {
                &editor.hostname
            } else {
                &editor.metric
            };
            spans.push(Span::raw(": "));
            spans.extend(input::render_value_with_cursor(
                value,
                editor.cursor,
                selected,
                style,
            ));
        }
        app.ui.buttons.push((
            Rect::new(inner.x, inner.y + lines.len() as u16, inner.width, 1),
            index,
        ));
        lines.push(Line::from(spans));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(
        "Enter toggles options. Esc: back (confirms discarding edits).",
    ));
    frame.render_widget(Paragraph::new(lines), inner);
}

pub(crate) async fn handle_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    let Some(editor) = app.dhcp_ui.dhcp_client_editor.as_mut() else {
        return;
    };
    if editor.exit_requested {
        match key {
            KeyCode::Esc => editor.exit_requested = false,
            KeyCode::Enter => {
                app.dhcp_ui.dhcp_client_editor = None;
                app.screen = Screen::DhcpClient;
            }
            _ => {}
        }
        return;
    }
    match key {
        KeyCode::Esc => request_exit(app),
        KeyCode::Up | KeyCode::Down => {
            editor.field = input::move_clamped(&FIELDS, editor.field, key == KeyCode::Down);
            editor.cursor = input::grapheme_count(if editor.field == Field::Hostname {
                &editor.hostname
            } else {
                &editor.metric
            });
        }
        KeyCode::Enter => match editor.field {
            Field::DefaultRoute => {
                editor.config.install_default_route = !editor.config.install_default_route
            }
            Field::Dns => editor.config.request_dns = !editor.config.request_dns,
            Field::Release => {
                editor.config.send_release_on_shutdown = !editor.config.send_release_on_shutdown
            }
            Field::Cancel => request_exit(app),
            Field::Apply => {
                let request = match editor.request() {
                    Ok(request) => request,
                    Err(message) => {
                        app.push_message(LogLevel::Error, message);
                        return;
                    }
                };
                let interface = editor.interface.clone();
                match client.request(&request).await {
                    Ok(Response::NetworkChangePending { change }) if change.interface == interface => {
                        app.dhcp_ui.dhcp_client_editor = None;
                        app.confirmation.pending_focus = 0;
                        app.confirmation.pending = Some(change);
                        app.confirmation.pending_return_screen = Screen::DhcpClient;
                        app.screen = Screen::PendingChange;
                    }
                    Ok(Response::DhcpClientInterface { status }) if status.interface == interface => {
                        app.dhcp_ui.dhcp_client_editor = None;
                        app.screen = Screen::DhcpClient;
                        app.push_message(LogLevel::Info, format!("DHCP client settings applied on {interface}"));
                        super::dhcp_client::refresh(app, client).await;
                    }
                    Ok(Response::DhcpClientError { detail }) => app.push_message(LogLevel::Error, format!("DHCP client settings failed: {detail:?}")),
                    Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
                    Ok(_) => app.push_message(LogLevel::Error, "Unexpected DHCP client response; inspect current state before retrying"),
                    Err(error) => app.push_message(LogLevel::Error, format!("Apply outcome unverified: {error}. Inspect current state before retrying")),
                }
            }
            Field::Metric => {
                editor.field = Field::Hostname;
                editor.cursor = input::grapheme_count(&editor.hostname);
            }
            Field::Hostname => editor.field = Field::DefaultRoute,
        },
        other if matches!(editor.field, Field::Metric | Field::Hostname) => {
            let value = if editor.field == Field::Hostname {
                &mut editor.hostname
            } else {
                &mut editor.metric
            };
            input::TextEditor::new(value, &mut editor.cursor).handle_key(other);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metric_edit_preserves_all_other_options_and_interface() {
        let config = DhcpClientConfigRequest {
            hostname: Some("travel-router".into()),
            route_metric: 321,
            install_default_route: false,
            request_dns: false,
            send_release_on_shutdown: true,
        };
        let mut editor = Editor::new("wan9".into(), config.clone());
        editor.metric = "0".into();
        let Request::ConfigureDhcpClient {
            interface,
            config: edited,
        } = editor.request().unwrap()
        else {
            panic!()
        };
        assert_eq!(interface, "wan9");
        assert_eq!(
            edited,
            DhcpClientConfigRequest {
                route_metric: 0,
                ..config
            }
        );
        for invalid in ["", "-1", "4294967296", "abc"] {
            editor.metric = invalid.into();
            assert!(editor.request().is_err());
        }
    }
    #[tokio::test]
    async fn route_policy_apply_opens_confirmation_and_can_rollback() {
        let change = traffic_masq_protocol::PendingNetworkChange {
            recovery_progress: None,
            phase: Default::default(),
            last_error: None,
            token: "dhcp-policy".into(),
            interface: "wan0".into(),
            rollback_timeout_seconds: 60,
            expires_at_unix: super::super::current_unix_time() + 60,
        };
        let mock = super::super::test_api::mock(vec![
            Response::NetworkChangePending {
                change: change.clone(),
            },
            Response::NetworkChangeRolledBack {
                change: change.clone(),
            },
        ])
        .await;
        let mut app = TuiApp::default();
        let mut editor = Editor::new("wan0".into(), DhcpClientConfigRequest::default());
        editor.config.install_default_route = false;
        editor.field = Field::Apply;
        app.dhcp_ui.dhcp_client_editor = Some(editor);
        handle_key(&mut app, KeyCode::Enter, &mock.client).await;
        assert_eq!(app.screen, Screen::PendingChange);
        assert_eq!(
            app.confirmation.pending.as_ref().unwrap().token,
            "dhcp-policy"
        );
        assert_eq!(app.confirmation.pending_return_screen, Screen::DhcpClient);
        super::super::interfaces::handle_pending_key(&mut app, KeyCode::Esc, &mock.client).await;
        assert_eq!(app.screen, Screen::DhcpClient);
        assert!(app.confirmation.pending.is_none());
        assert_eq!(
            mock.calls.lock().unwrap()[1].body["type"],
            "rollback_network_change"
        );
    }

    #[tokio::test]
    async fn loads_saved_policy_and_keeps_draft_on_rejected_apply() {
        let config = serde_json::from_value(serde_json::json!({"role":"input","managed":true,"ipv4":null,"dhcp":null,"dhcp_client":{"hostname":"saved-router","route_metric":777,"install_default_route":false,"request_dns":false,"send_release_on_shutdown":true}})).unwrap();
        let mock = super::super::test_api::mock(vec![
            Response::InterfaceConfig {
                wifi_concurrent_support: None,
                interface: "wan9".into(),
                config: Some(config),
                allow_management_change: false,
            },
            Response::Error {
                message: "transaction pending".into(),
            },
        ])
        .await;
        let mut app = TuiApp::default();
        open(&mut app, &mock.client, "wan9".into()).await;
        assert_eq!(app.screen, Screen::DhcpClientEditor);
        assert_eq!(
            app.dhcp_ui.dhcp_client_editor.as_ref().unwrap().metric,
            "777"
        );
        let editor = app.dhcp_ui.dhcp_client_editor.as_mut().unwrap();
        assert_eq!(editor.hostname, "saved-router");
        editor.hostname = "new-router".into();
        editor.metric = "42".into();
        editor.field = Field::Apply;
        handle_key(&mut app, KeyCode::Enter, &mock.client).await;
        assert_eq!(app.screen, Screen::DhcpClientEditor);
        assert_eq!(
            app.dhcp_ui.dhcp_client_editor.as_ref().unwrap().metric,
            "42"
        );
        {
            let calls = mock.calls.lock().unwrap();
            assert_eq!(calls[1].method, "POST");
            assert_eq!(calls[1].path, "/api/v1/control");
            assert_eq!(calls[1].body["type"], "configure_dhcp_client");
            assert_eq!(calls[1].body["interface"], "wan9");
            assert_eq!(
                calls[1].body["config"],
                serde_json::json!({"hostname":"new-router","route_metric":42,"install_default_route":false,"request_dns":false,"send_release_on_shutdown":true})
            );
        }
        handle_key(&mut app, KeyCode::Esc, &mock.client).await;
        assert!(
            app.dhcp_ui
                .dhcp_client_editor
                .as_ref()
                .unwrap()
                .exit_requested
        );
        handle_key(&mut app, KeyCode::Enter, &mock.client).await;
        assert!(app.dhcp_ui.dhcp_client_editor.is_none());
    }
}

#[cfg(test)]
mod hostname_tests {
    use super::*;

    #[test]
    fn hostname_draft_is_validated_and_can_be_cleared() {
        let mut editor = Editor::new("wan0".into(), DhcpClientConfigRequest::default());
        editor.hostname = " travel-router.example ".into();
        let Request::ConfigureDhcpClient { config, .. } = editor.request().unwrap() else {
            panic!()
        };
        assert_eq!(config.hostname.as_deref(), Some("travel-router.example"));
        for invalid in ["bad name", "-router", "router-", "bad..name", "роутер"] {
            editor.hostname = invalid.into();
            assert!(editor.request().is_err());
        }
        editor.hostname.clear();
        let Request::ConfigureDhcpClient { config, .. } = editor.request().unwrap() else {
            panic!()
        };
        assert_eq!(config.hostname, None);
    }

    #[tokio::test]
    async fn hostname_field_accepts_text_and_keeps_cursor_on_focus_changes() {
        let client = ApiClient::new(std::path::PathBuf::from("/unused-hostname-test.sock"));
        let mut app = TuiApp {
            dhcp_ui: crate::tui::state::DhcpUiState {
                dhcp_client_editor: Some(Editor::new(
                    "wan0".into(),
                    DhcpClientConfigRequest::default(),
                )),
                ..Default::default()
            },
            ..Default::default()
        };
        handle_key(&mut app, KeyCode::Down, &client).await;
        handle_key(&mut app, KeyCode::Char('a'), &client).await;
        handle_key(&mut app, KeyCode::Char('b'), &client).await;
        handle_key(&mut app, KeyCode::Up, &client).await;
        handle_key(&mut app, KeyCode::Down, &client).await;
        handle_key(&mut app, KeyCode::Backspace, &client).await;
        assert_eq!(
            app.dhcp_ui.dhcp_client_editor.as_ref().unwrap().hostname,
            "a"
        );
    }
}

pub(super) fn exit_confirmation(app: &TuiApp) -> Option<super::confirmation::Dialog> {
    let editor = app.dhcp_ui.dhcp_client_editor.as_ref()?;
    editor.exit_requested.then(|| {
        super::confirmation::discard_edits_dialog(
            "Leave DHCP client editor?",
            format!("Interface: {}", editor.interface),
        )
    })
}
fn request_exit(app: &mut TuiApp) {
    if app
        .dhcp_ui
        .dhcp_client_editor
        .as_ref()
        .is_some_and(Editor::dirty)
    {
        app.dhcp_ui
            .dhcp_client_editor
            .as_mut()
            .unwrap()
            .exit_requested = true;
    } else {
        app.dhcp_ui.dhcp_client_editor = None;
        app.screen = Screen::DhcpClient;
    }
}

#[cfg(test)]
mod exit_tests {
    use super::*;
    #[tokio::test]
    async fn invalid_dhcp_input_is_retained_until_discard_is_confirmed() {
        let client = ApiClient::new("/must-not-connect.sock");
        let mut editor = Editor::new("wan0".into(), DhcpClientConfigRequest::default());
        editor.metric = "invalid metric".into();
        editor.field = Field::Cancel;
        let mut app = TuiApp {
            dhcp_ui: crate::tui::state::DhcpUiState {
                dhcp_client_editor: Some(editor),
                ..Default::default()
            },
            screen: Screen::DhcpClientEditor,
            ..Default::default()
        };
        app.ui.input_enabled = true;
        handle_key(&mut app, KeyCode::Enter, &client).await;
        assert!(exit_confirmation(&app).is_some());
        crate::tui::handle_key(&mut app, KeyCode::Tab, &client, false).await;
        crate::tui::handle_key(&mut app, KeyCode::Enter, &client, false).await;
        assert!(exit_confirmation(&app).is_none());
        assert_eq!(
            app.dhcp_ui.dhcp_client_editor.as_ref().unwrap().metric,
            "invalid metric"
        );
        handle_key(&mut app, KeyCode::Esc, &client).await;
        crate::tui::handle_key(&mut app, KeyCode::Enter, &client, false).await;
        assert!(app.dhcp_ui.dhcp_client_editor.is_none());
        assert_eq!(app.screen, Screen::DhcpClient);
    }
}
