use std::net::Ipv4Addr;

use crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::tui::api::client::ApiClient;
use crate::tui::api::model::{DhcpEditRequest, Request, Response};
use traffic_masq_protocol::DhcpLeaseView;

use super::layout::panel;
use super::logs::LogLevel;
use super::theme;
use super::{current_unix_time, Screen, TuiApp};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DhcpField {
    PoolStart,
    PoolEnd,
    Router,
    DnsServers,
    LeaseSeconds,
    Save,
    Leases,
    Disable,
}

#[derive(Debug, Clone)]
pub(crate) struct DhcpEditor {
    pub(crate) interface: String,
    pub(crate) offline_intent: Option<(u64, traffic_masq_protocol::InterfaceConfigView)>,
    pub(crate) field: DhcpField,
    pub(crate) pool_start: String,
    pub(crate) pool_end: String,
    pub(crate) router: String,
    pub(crate) dns_servers: String,
    pub(crate) lease_seconds: String,
    pub(crate) cursor: usize,
}

impl DhcpEditor {
    fn edit_request(&self) -> anyhow::Result<DhcpEditRequest> {
        let dns_servers = self
            .dns_servers
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::parse)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let lease_seconds = if self.lease_seconds.trim().is_empty() {
            None
        } else {
            Some(self.lease_seconds.trim().parse()?)
        };

        Ok(DhcpEditRequest {
            pool_start: self.pool_start.trim().parse()?,
            pool_end: self.pool_end.trim().parse()?,
            router: self.router.trim().parse()?,
            dns_servers,
            lease_seconds,
        })
    }

    #[allow(dead_code)]
    fn active_value_mut(&mut self) -> Option<&mut String> {
        match self.field {
            DhcpField::PoolStart => Some(&mut self.pool_start),
            DhcpField::PoolEnd => Some(&mut self.pool_end),
            DhcpField::Router => Some(&mut self.router),
            DhcpField::DnsServers => Some(&mut self.dns_servers),
            DhcpField::LeaseSeconds => Some(&mut self.lease_seconds),
            DhcpField::Save | DhcpField::Leases | DhcpField::Disable => None,
        }
    }

    pub(crate) fn active_value(&self) -> Option<&str> {
        match self.field {
            DhcpField::PoolStart => Some(&self.pool_start),
            DhcpField::PoolEnd => Some(&self.pool_end),
            DhcpField::Router => Some(&self.router),
            DhcpField::DnsServers => Some(&self.dns_servers),
            DhcpField::LeaseSeconds => Some(&self.lease_seconds),
            DhcpField::Save | DhcpField::Leases | DhcpField::Disable => None,
        }
    }

    pub(crate) fn reset_cursor(&mut self) {
        self.cursor = self.active_value().map_or(0, super::input::grapheme_count);
    }

    pub(crate) fn active_editor(&mut self) -> Option<super::input::TextEditor<'_>> {
        let cursor = &mut self.cursor;
        match self.field {
            DhcpField::PoolStart => {
                Some(super::input::TextEditor::new(&mut self.pool_start, cursor))
            }
            DhcpField::PoolEnd => Some(super::input::TextEditor::new(&mut self.pool_end, cursor)),
            DhcpField::Router => Some(super::input::TextEditor::new(&mut self.router, cursor)),
            DhcpField::DnsServers => {
                Some(super::input::TextEditor::new(&mut self.dns_servers, cursor))
            }
            DhcpField::LeaseSeconds => Some(super::input::TextEditor::new(
                &mut self.lease_seconds,
                cursor,
            )),
            DhcpField::Save | DhcpField::Leases | DhcpField::Disable => None,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DhcpLeasesView {
    pub(crate) interface: String,
    pub(crate) leases: Vec<DhcpLeaseView>,
    pub(crate) scroll: usize,
    pub(crate) return_screen: Screen,
}

pub(crate) fn render_dhcp_interface_list(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    app: &mut TuiApp,
) {
    if app.dashboard.inventory.is_some() {
        super::interfaces::render_interface_inventory(frame, area, app, true);
        return;
    }
    let block = panel("DHCP interfaces");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let visible = inner.height.max(1) as usize;
    let max_scroll = app.dashboard.interfaces.len().saturating_sub(visible);
    let offset = app
        .selected_interface
        .saturating_sub(visible.saturating_sub(1))
        .min(max_scroll);
    app.ui.list_area = Some(inner);
    app.ui.list_row_height = 1;
    app.ui.list_count = app.dashboard.interfaces.len();
    app.ui.list_scroll_offset = offset;

    let lines = app
        .dashboard
        .interfaces
        .iter()
        .enumerate()
        .skip(offset)
        .take(visible)
        .map(|(index, status)| {
            let selected = index == app.selected_interface;
            let marker = if selected { "▶" } else { " " };
            let style = if selected {
                Style::default()
                    .fg(theme::ACCENT)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let dhcp_active = app
                .dhcp_interfaces
                .iter()
                .any(|name| name == &status.interface.name);
            let dhcp_span = if dhcp_active {
                Span::styled("dhcp active", Style::default().fg(theme::GOOD))
            } else {
                Span::styled("no dhcp", Style::default().fg(theme::MUTED))
            };
            Line::from(vec![
                Span::styled(format!("{marker} {:<12}", status.interface.name), style),
                dhcp_span,
            ])
        })
        .collect::<Vec<_>>();

    if lines.is_empty() {
        frame.render_widget(
            Paragraph::new("No interfaces detected").style(Style::default().fg(theme::MUTED)),
            inner,
        );
        return;
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

const DHCP_SAVE_LABEL: &str = "Apply DHCP now";
const DHCP_LEASES_LABEL: &str = "View leases";
const DHCP_DISABLE_LABEL: &str = "Disable DHCP";

pub(crate) fn render_dhcp_editor(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let Some(editor) = &app.dhcp_editor else {
        return;
    };
    let field = |label: &str, value: &str, active: bool| {
        let marker = if active { "▶" } else { " " };
        let style = if active {
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let mut spans = vec![Span::styled(format!("{marker} {label}: "), style)];
        spans.extend(super::input::render_value_with_cursor(
            value,
            editor.cursor,
            active,
            style,
        ));
        Line::from(spans)
    };
    let action = |label: &str, active: bool| {
        let marker = if active { "▶ " } else { "  " };
        let style = if active {
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme::ACCENT)
        };
        Line::styled(format!("{marker}{label}"), style)
    };
    let mut lines = vec![
        Line::from(format!("Interface: {}", editor.interface)),
        field(
            "Pool start",
            &editor.pool_start,
            editor.field == DhcpField::PoolStart,
        ),
        field(
            "Pool end",
            &editor.pool_end,
            editor.field == DhcpField::PoolEnd,
        ),
        field("Router", &editor.router, editor.field == DhcpField::Router),
        field(
            "DNS servers (comma-separated)",
            &editor.dns_servers,
            editor.field == DhcpField::DnsServers,
        ),
        field(
            "Lease seconds",
            &editor.lease_seconds,
            editor.field == DhcpField::LeaseSeconds,
        ),
        Line::styled(
            "Applies immediately; no automatic rollback timer.",
            Style::default().fg(theme::MUTED),
        ),
        Line::styled(
            "arrows: move | Enter: activate | type digits, '.', ',' to edit",
            Style::default().fg(theme::MUTED),
        ),
        Line::from(""),
    ];

    let mut button_rows: Vec<(u16, &str, usize)> = Vec::new();

    button_rows.push((lines.len() as u16, DHCP_SAVE_LABEL, 0));
    lines.push(action(DHCP_SAVE_LABEL, editor.field == DhcpField::Save));

    button_rows.push((lines.len() as u16, DHCP_LEASES_LABEL, 1));
    lines.push(action(DHCP_LEASES_LABEL, editor.field == DhcpField::Leases));

    button_rows.push((lines.len() as u16, DHCP_DISABLE_LABEL, 2));
    lines.push(action(
        DHCP_DISABLE_LABEL,
        editor.field == DhcpField::Disable,
    ));

    let block = panel("DHCP editor");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    for (row_index, label, slot) in button_rows {
        app.ui.buttons.push((
            Rect {
                x: inner.x,
                y: inner.y + row_index,
                width: label.len() as u16,
                height: 1,
            },
            slot,
        ));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

pub(crate) fn render_dhcp_leases(frame: &mut ratatui::Frame<'_>, area: Rect, app: &TuiApp) {
    let Some(view) = &app.dhcp_leases else {
        return;
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(3)])
        .split(area);
    frame.render_widget(
        Paragraph::new(format!(
            "Interface: {} | Active leases: {}",
            view.interface,
            view.leases.len()
        ))
        .block(panel("DHCP leases")),
        chunks[0],
    );

    let now = current_unix_time();
    let lines = if view.leases.is_empty() {
        vec![Line::styled(
            "No active DHCP leases",
            Style::default().fg(theme::MUTED),
        )]
    } else {
        view.leases
            .iter()
            .map(|lease| {
                let expiration = format_lease_expiration(lease.expires_at_unix, now);
                let style = if lease.is_expired_at(now) {
                    Style::default().fg(theme::BAD)
                } else if lease.expires_at_unix.saturating_sub(now) <= 60 {
                    Style::default().fg(theme::WARN)
                } else {
                    Style::default()
                };
                Line::styled(
                    format!(
                        "{:<15}  {}  {expiration}",
                        lease.ip,
                        format_mac_address(lease.mac)
                    ),
                    style,
                )
            })
            .collect()
    };
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((view.scroll.min(u16::MAX as usize) as u16, 0))
            .block(panel("IPv4             MAC                Expiration")),
        chunks[1],
    );
}

pub(crate) fn focus_action(app: &mut TuiApp, slot: usize) {
    if let Some(editor) = app.dhcp_editor.as_mut() {
        editor.field = match slot {
            0 => DhcpField::Save,
            1 => DhcpField::Leases,
            _ => DhcpField::Disable,
        };
        editor.reset_cursor();
    }
}

pub(crate) async fn handle_dhcp_interface_list_key(
    app: &mut TuiApp,
    key: KeyCode,
    client: &ApiClient,
) {
    match key {
        KeyCode::Esc => app.screen = Screen::Dashboard,
        KeyCode::Up => {
            super::interfaces::set_interface_selection(
                app,
                super::interfaces::interface_selection(app).saturating_sub(1),
            );
        }
        KeyCode::Down
            if super::interfaces::interface_selection(app) + 1
                < super::interfaces::interface_count(app) =>
        {
            super::interfaces::set_interface_selection(
                app,
                super::interfaces::interface_selection(app) + 1,
            );
        }
        KeyCode::Home => super::interfaces::set_interface_selection(app, 0),
        KeyCode::End => {
            super::interfaces::set_interface_selection(
                app,
                super::interfaces::interface_count(app).saturating_sub(1),
            );
        }

        KeyCode::Enter => open_dhcp_editor(app, client).await,
        _ => {}
    }
}

fn suggest_pool(address: Ipv4Addr, prefix_len: u8) -> Option<(Ipv4Addr, Ipv4Addr)> {
    let cidr = ipnet::Ipv4Net::new(address, prefix_len).ok()?;
    traffic_masq_protocol::suggest_pool(cidr).ok()
}

fn is_candidate_ipv4(addr: Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len >= 31 {
        return false;
    }
    if addr.is_loopback()
        || addr.is_link_local()
        || addr.is_unspecified()
        || addr.is_broadcast()
        || addr.is_multicast()
    {
        return false;
    }
    true
}

fn candidate_cidr_from_status(
    status: &traffic_masq_protocol::InterfaceStatusView,
) -> Option<ipnet::Ipv4Net> {
    let owned = status.owned_ipv4_addresses.as_deref().unwrap_or(&[]);
    let addresses = if !owned.is_empty() {
        owned
    } else {
        &status.ipv4_addresses
    };

    if let Some(info) = addresses
        .iter()
        .find(|info| is_candidate_ipv4(info.address, info.prefix_len) && info.address.is_private())
    {
        return ipnet::Ipv4Net::new(info.address, info.prefix_len).ok();
    }

    addresses
        .iter()
        .find(|info| is_candidate_ipv4(info.address, info.prefix_len))
        .and_then(|info| ipnet::Ipv4Net::new(info.address, info.prefix_len).ok())
}

pub(crate) async fn open_dhcp_editor(app: &mut TuiApp, client: &ApiClient) {
    let Some(interface) = super::interfaces::selected_interface_name(app) else {
        return;
    };
    let status = app
        .dashboard
        .interfaces
        .iter()
        .find(|status| status.interface.name == interface)
        .cloned();
    let offline_intent = app
        .dashboard
        .inventory
        .as_ref()
        .and_then(|entries| entries.iter().find(|entry| entry.name == interface))
        .filter(|entry| entry.presence == traffic_masq_protocol::InterfacePresence::Missing)
        .and_then(|entry| Some((app.dashboard.intent_revision?, entry.configured.clone()?)));

    match client
        .request(&Request::GetDhcpConfig {
            interface: interface.clone(),
        })
        .await
    {
        Ok(Response::DhcpConfig {
            spec: Some(spec), ..
        }) => {
            let pool_start = spec.pool_start.to_string();
            let cursor = super::input::grapheme_count(&pool_start);
            app.dhcp_editor = Some(DhcpEditor {
                interface,
                offline_intent,
                field: DhcpField::PoolStart,
                pool_start,
                pool_end: spec.pool_end.to_string(),
                router: spec.router.to_string(),
                dns_servers: spec
                    .dns_servers
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
                lease_seconds: spec.lease_seconds.to_string(),
                cursor,
            });
            app.screen = Screen::DhcpEditor;
        }
        Ok(Response::DhcpConfig { spec: None, .. }) => {
            // Read the effective configuration at editor-open time: the dashboard
            // can still contain addresses from before the user's last edit.
            let configured_cidr = match client
                .request(&Request::GetInterfaceConfig {
                    interface: interface.clone(),
                })
                .await
            {
                Ok(Response::InterfaceConfig {
                    interface: name,
                    config,
                    ..
                }) if name == interface => config.and_then(|config| config.ipv4),
                Ok(Response::Error { message }) => {
                    app.push_message(LogLevel::Error, message);
                    return;
                }
                Ok(response) => {
                    app.push_message(
                        LogLevel::Error,
                        format!("Unexpected response: {response:?}"),
                    );
                    return;
                }
                Err(error) => {
                    app.push_message(LogLevel::Error, error.to_string());
                    return;
                }
            };
            let cidr = configured_cidr
                .filter(|cidr| is_candidate_ipv4(cidr.addr(), cidr.prefix_len()))
                .or_else(|| status.as_ref().and_then(candidate_cidr_from_status));
            let router = cidr.map(|cidr| cidr.addr().to_string()).unwrap_or_default();
            let (pool_start, pool_end) = cidr
                .and_then(|cidr| suggest_pool(cidr.addr(), cidr.prefix_len()))
                .map(|(start, end)| (start.to_string(), end.to_string()))
                .unwrap_or_default();
            let cursor = super::input::grapheme_count(&pool_start);
            app.dhcp_editor = Some(DhcpEditor {
                interface,
                offline_intent,
                field: DhcpField::PoolStart,
                pool_start,
                pool_end,
                router,
                dns_servers: "8.8.8.8".to_string(),
                lease_seconds: "86400".to_string(),
                cursor,
            });
            app.screen = Screen::DhcpEditor;
        }
        Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

pub(crate) async fn open_dhcp_leases(
    app: &mut TuiApp,
    client: &ApiClient,
    interface: String,
    return_screen: Screen,
) {
    match client
        .request(&Request::ListLeases {
            interface: interface.clone(),
        })
        .await
    {
        Ok(Response::Leases {
            interface: response_interface,
            mut leases,
        }) if response_interface == interface => {
            leases.sort_by_key(|lease| u32::from(lease.ip));
            let count = leases.len();
            app.dhcp_leases = Some(DhcpLeasesView {
                interface,
                leases,
                scroll: 0,
                return_screen,
            });
            app.push_message(LogLevel::Info, format!("Loaded {count} DHCP lease(s)"));
            app.screen = Screen::DhcpLeases;
        }
        Ok(Response::Leases {
            interface: response_interface,
            ..
        }) => {
            app.push_message(
                LogLevel::Error,
                format!("Unexpected lease response for interface {response_interface}"),
            );
        }
        Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

pub(crate) async fn refresh_dhcp_leases(app: &mut TuiApp, client: &ApiClient) {
    let Some(view) = app.dhcp_leases.as_mut() else {
        return;
    };
    let interface = view.interface.clone();
    if let Ok(Response::Leases {
        interface: response_interface,
        mut leases,
    }) = client
        .request(&Request::ListLeases {
            interface: interface.clone(),
        })
        .await
    {
        if response_interface == interface {
            leases.sort_by_key(|lease| u32::from(lease.ip));
            if let Some(view) = app.dhcp_leases.as_mut() {
                view.leases = leases;
            }
        }
    }
}

pub(crate) async fn handle_dhcp_leases_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    let Some(view) = app.dhcp_leases.as_mut() else {
        app.screen = Screen::DhcpInterfaceList;
        return;
    };

    match key {
        KeyCode::Esc => app.screen = view.return_screen,
        KeyCode::Up => view.scroll = view.scroll.saturating_sub(1),
        KeyCode::Down if view.scroll + 1 < view.leases.len() => {
            view.scroll += 1;
        }
        KeyCode::PageUp => view.scroll = view.scroll.saturating_sub(10),
        KeyCode::PageDown => {
            view.scroll = view
                .scroll
                .saturating_add(10)
                .min(view.leases.len().saturating_sub(1));
        }
        KeyCode::Home => view.scroll = 0,
        KeyCode::End => view.scroll = view.leases.len().saturating_sub(1),
        KeyCode::Enter => {
            let interface = view.interface.clone();
            let return_screen = view.return_screen;
            open_dhcp_leases(app, client, interface, return_screen).await;
        }
        _ => {}
    }
}

pub(crate) async fn handle_dhcp_editor_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    let Some(editor) = app.dhcp_editor.as_mut() else {
        app.screen = Screen::DhcpInterfaceList;
        return;
    };

    match key {
        KeyCode::Esc => app.screen = Screen::DhcpInterfaceList,
        KeyCode::Up => {
            editor.field = previous_dhcp_field(editor.field);
            editor.reset_cursor();
        }
        KeyCode::Down => {
            editor.field = next_dhcp_field(editor.field);
            editor.reset_cursor();
        }
        KeyCode::Enter => match editor.field {
            DhcpField::PoolStart
            | DhcpField::PoolEnd
            | DhcpField::Router
            | DhcpField::DnsServers
            | DhcpField::LeaseSeconds => {
                editor.field = next_dhcp_field(editor.field);
                editor.reset_cursor();
            }
            DhcpField::Save => submit_dhcp_config(app, client).await,
            DhcpField::Leases => {
                let interface = editor.interface.clone();
                open_dhcp_leases(app, client, interface, Screen::DhcpEditor).await;
            }
            DhcpField::Disable => disable_dhcp_for_current_editor(app, client).await,
        },
        other => {
            if let Some(mut text_editor) = editor.active_editor() {
                text_editor
                    .handle_key_filtered(other, |c| c.is_ascii_digit() || matches!(c, '.' | ','));
            }
        }
    }
}

async fn disable_dhcp_for_current_editor(app: &mut TuiApp, client: &ApiClient) {
    let Some(editor) = &app.dhcp_editor else {
        return;
    };
    let interface = editor.interface.clone();
    if let Some((expected_revision, mut config)) = editor.offline_intent.clone() {
        config.dhcp = None;
        save_offline_dhcp(app, client, interface, config, expected_revision).await;
        return;
    }
    match client.request(&Request::DisableDhcp { interface }).await {
        Ok(Response::DhcpDisabled { interface }) => {
            app.push_message(LogLevel::Info, format!("DHCP disabled on {interface}"));
            app.screen = Screen::DhcpInterfaceList;
        }
        Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

pub(crate) async fn submit_dhcp_config(app: &mut TuiApp, client: &ApiClient) {
    let Some(editor) = &app.dhcp_editor else {
        return;
    };
    let interface = editor.interface.clone();
    let settings = match editor.edit_request() {
        Ok(settings) => settings,
        Err(error) => {
            app.push_message(LogLevel::Warn, format!("Invalid DHCP settings: {error}"));
            return;
        }
    };
    if let Some((expected_revision, mut config)) = editor.offline_intent.clone() {
        config.dhcp = Some(traffic_masq_protocol::DhcpInterfaceConfigView {
            pool_start: settings.pool_start,
            pool_end: settings.pool_end,
            router: settings.router,
            dns_servers: settings.dns_servers,
            lease_seconds: settings.lease_seconds,
        });
        save_offline_dhcp(app, client, interface, config, expected_revision).await;
        return;
    }
    match client
        .request(&Request::ConfigureDhcpSettings {
            interface,
            settings,
        })
        .await
    {
        Ok(Response::DhcpConfigured { spec }) => {
            app.push_message(
                LogLevel::Info,
                format!("DHCP configured on {}", spec.interface),
            );
            app.screen = Screen::DhcpInterfaceList;
        }
        Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

async fn save_offline_dhcp(
    app: &mut TuiApp,
    client: &ApiClient,
    interface: String,
    config: traffic_masq_protocol::InterfaceConfigView,
    expected_revision: u64,
) {
    match client
        .request(&Request::SaveInterfaceConfig {
            interface,
            config,
            allow_management_change: false,
            expected_revision,
        })
        .await
    {
        Ok(Response::InterfaceIntentSaved { interface, .. }) => {
            app.push_message(
                LogLevel::Info,
                format!("Saved DHCP settings; application waits for interface {interface}"),
            );
            app.screen = Screen::DhcpInterfaceList;
        }
        Ok(Response::Error { message }) => app.push_message(LogLevel::Error, message),
        result => app.push_message(LogLevel::Error, format!("Save failed: {result:?}")),
    }
}

const DHCP_EDITOR_FIELDS: [DhcpField; 8] = [
    DhcpField::PoolStart,
    DhcpField::PoolEnd,
    DhcpField::Router,
    DhcpField::DnsServers,
    DhcpField::LeaseSeconds,
    DhcpField::Save,
    DhcpField::Leases,
    DhcpField::Disable,
];

fn next_dhcp_field(field: DhcpField) -> DhcpField {
    super::input::move_clamped(&DHCP_EDITOR_FIELDS, field, true)
}

fn previous_dhcp_field(field: DhcpField) -> DhcpField {
    super::input::move_clamped(&DHCP_EDITOR_FIELDS, field, false)
}

fn format_mac_address(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn format_lease_expiration(expires_at_unix: u64, now_unix: u64) -> String {
    if expires_at_unix <= now_unix {
        format!("expired (unix {expires_at_unix})")
    } else {
        format!(
            "{}s remaining (unix {expires_at_unix})",
            expires_at_unix - now_unix
        )
    }
}

#[cfg(test)]
mod tests;
