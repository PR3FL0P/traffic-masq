use std::net::Ipv4Addr;

use crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Layout, Rect};
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum LeaseFilter {
    #[default]
    All,
    Active,
    Expired,
}
impl LeaseFilter {
    fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Active => "active",
            Self::Expired => "expired",
        }
    }
}
#[derive(Debug, Clone)]
pub(crate) struct DhcpLeasesView {
    pub(crate) interface: String,
    pub(crate) leases: Vec<DhcpLeaseView>,
    pub(crate) scroll: usize,
    pub(crate) return_screen: Screen,
    query: String,
    cursor: usize,
    searching: bool,
    filter: LeaseFilter,
    sort_expiration: bool,
    error: Option<String>,
    updated_at: u64,
    viewport_rows: usize,
}
impl DhcpLeasesView {
    fn filtered(&self, now: u64) -> Vec<&DhcpLeaseView> {
        let query = self.query.to_ascii_lowercase();
        let mut leases = self
            .leases
            .iter()
            .filter(|lease| {
                let state_matches = match self.filter {
                    LeaseFilter::All => true,
                    LeaseFilter::Active => !lease.is_expired_at(now),
                    LeaseFilter::Expired => lease.is_expired_at(now),
                };
                state_matches
                    && (lease.ip.to_string().contains(&query)
                        || format_mac_address(lease.mac)
                            .to_ascii_lowercase()
                            .contains(&query))
            })
            .collect::<Vec<_>>();
        if self.sort_expiration {
            leases.sort_by_key(|lease| (lease.expires_at_unix, u32::from(lease.ip), lease.mac));
        } else {
            leases.sort_by_key(|lease| (u32::from(lease.ip), lease.mac));
        }
        leases
    }
    fn max_scroll(&self) -> usize {
        self.filtered(current_unix_time())
            .len()
            .saturating_sub(self.viewport_rows.max(1))
    }
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
        .interface_ui
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
            let selected = index == app.interface_ui.selected_interface;
            let marker = if selected { "▶" } else { " " };
            let style = if selected {
                Style::default()
                    .fg(theme::ACCENT)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let dhcp_active = app
                .dhcp_ui
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
                Span::raw(format!(
                    " · {}",
                    super::interface_status::summary(app, &status.interface.name)
                )),
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

const DHCP_SAVE_LABEL: &str = "Apply DHCP temporarily";
const DHCP_LEASES_LABEL: &str = "View leases";
const DHCP_DISABLE_LABEL: &str = "Disable DHCP";

pub(crate) fn render_dhcp_editor(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let Some(editor) = &app.dhcp_ui.dhcp_editor else {
        return;
    };
    let area = if editor.offline_intent.is_some() {
        super::layout::render_offline_intent_warning(frame, area)
    } else {
        area
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
    let offline = editor.offline_intent.is_some();
    let save_label = if offline {
        "Save DHCP for device return"
    } else {
        DHCP_SAVE_LABEL
    };
    let disable_label = if offline {
        "Remove saved DHCP settings"
    } else {
        DHCP_DISABLE_LABEL
    };
    let mut lines = vec![
        Line::from(format!(
            "Interface: {}",
            super::interface_status::describe(app, &editor.interface)
        )),
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
            if offline {
                "Device missing: saves settings for when it returns."
            } else {
                "Applies temporarily; confirmation is required to save."
            },
            Style::default().fg(theme::MUTED),
        ),
        Line::styled(
            "arrows: move | Enter: activate | type digits, '.', ',' to edit",
            Style::default().fg(theme::MUTED),
        ),
        Line::from(""),
    ];

    let mut button_rows: Vec<(u16, &str, usize)> = Vec::new();

    button_rows.push((lines.len() as u16, save_label, 0));
    lines.push(action(save_label, editor.field == DhcpField::Save));

    button_rows.push((lines.len() as u16, DHCP_LEASES_LABEL, 1));
    lines.push(action(DHCP_LEASES_LABEL, editor.field == DhcpField::Leases));

    button_rows.push((lines.len() as u16, disable_label, 2));
    lines.push(action(disable_label, editor.field == DhcpField::Disable));

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

pub(crate) fn render_dhcp_leases(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let interface_status = app
        .dhcp_ui
        .dhcp_leases
        .as_ref()
        .map(|view| super::interface_status::describe(app, &view.interface))
        .unwrap_or_default();
    let Some(view) = &mut app.dhcp_ui.dhcp_leases else {
        return;
    };
    let chunks = Layout::vertical([Constraint::Length(6), Constraint::Min(3)]).split(area);
    let now = current_unix_time();
    let filtered = view.filtered(now);
    let count = filtered.len();
    let active = view
        .leases
        .iter()
        .filter(|lease| !lease.is_expired_at(now))
        .count();
    let mut search = vec![Span::raw("Search IP/MAC: ")];
    search.extend(super::input::render_value_with_cursor(
        &view.query,
        view.cursor,
        view.searching,
        Style::default().fg(theme::ACCENT),
    ));
    let status = match &view.error {
        Some(error) => Line::styled(format!("STALE: {error}"), Style::default().fg(theme::WARN)),
        None => Line::from(interface_status),
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(format!(
                "{} | Showing {count}/{} | Active {active} | Expired {}",
                view.interface,
                view.leases.len(),
                view.leases.len() - active
            )),
            Line::from(format!(
                "Filter: {} | Sort: {} | / search · f filter · s sort · r refresh",
                view.filter.label(),
                if view.sort_expiration {
                    "expiration"
                } else {
                    "IP"
                }
            )),
            Line::from(search),
            status,
        ])
        .block(panel("DHCP leases")),
        chunks[0],
    );
    let block = panel("IPv4             MAC                Expiration");
    let inner = block.inner(chunks[1]);
    let lines = if filtered.is_empty() {
        vec![Line::styled(
            if view.leases.is_empty() {
                "No DHCP leases in this snapshot"
            } else {
                "No matching DHCP leases"
            },
            Style::default().fg(theme::MUTED),
        )]
    } else {
        filtered
            .into_iter()
            .map(|lease| {
                let expiration = format_lease_expiration(lease.expires_at_unix, now);
                let color = if lease.is_expired_at(now) {
                    theme::BAD
                } else if lease.expires_at_unix.saturating_sub(now) <= 60 {
                    theme::WARN
                } else {
                    theme::ACCENT
                };
                Line::styled(
                    format!(
                        "{:<15}  {}  {expiration}",
                        lease.ip,
                        format_mac_address(lease.mac)
                    ),
                    Style::default().fg(color),
                )
            })
            .collect()
    };
    view.viewport_rows = inner.height as usize;
    view.scroll = view
        .scroll
        .min(count.saturating_sub(view.viewport_rows.max(1)));
    frame.render_widget(block, chunks[1]);
    frame.render_widget(
        Paragraph::new(
            lines
                .into_iter()
                .skip(view.scroll)
                .take(view.viewport_rows)
                .collect::<Vec<_>>(),
        ),
        inner,
    );
}

pub(crate) fn focus_action(app: &mut TuiApp, slot: usize) {
    if let Some(editor) = app.dhcp_ui.dhcp_editor.as_mut() {
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
            app.dhcp_ui.dhcp_editor = Some(DhcpEditor {
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
            let defaults = match super::dns_defaults::fetch(client).await {
                Ok(defaults) => defaults,
                Err(error) => {
                    app.push_message(LogLevel::Error, error.to_string());
                    return;
                }
            };
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
            app.dhcp_ui.dhcp_editor = Some(DhcpEditor {
                interface,
                offline_intent,
                field: DhcpField::PoolStart,
                pool_start,
                pool_end,
                router,
                dns_servers: super::dns_defaults::format_servers(&defaults),
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
            app.dhcp_ui.dhcp_leases = Some(DhcpLeasesView {
                interface,
                leases,
                scroll: 0,
                return_screen,
                query: String::new(),
                cursor: 0,
                searching: false,
                filter: LeaseFilter::All,
                sort_expiration: false,
                error: None,
                updated_at: current_unix_time(),
                viewport_rows: 1,
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
    let Some(view) = app.dhcp_ui.dhcp_leases.as_mut() else {
        return;
    };
    match client
        .request(&Request::ListLeases {
            interface: view.interface.clone(),
        })
        .await
    {
        Ok(Response::Leases { interface, leases }) if interface == view.interface => {
            view.leases = leases;
            view.error = None;
            view.updated_at = current_unix_time();
            view.scroll = view.scroll.min(view.max_scroll());
        }
        Ok(Response::Leases { interface, .. }) => {
            view.error = Some(format!(
                "Unexpected lease response for interface {interface}"
            ))
        }
        Ok(Response::Error { message }) => view.error = Some(message),
        Ok(_) => view.error = Some("Unexpected lease response".into()),
        Err(error) => view.error = Some(error.to_string()),
    }
}

pub(crate) async fn handle_dhcp_leases_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    let Some(view) = app.dhcp_ui.dhcp_leases.as_mut() else {
        app.screen = Screen::DhcpInterfaceList;
        return;
    };
    if view.searching {
        match key {
            KeyCode::Esc | KeyCode::Enter => view.searching = false,
            other => {
                super::input::TextEditor::new(&mut view.query, &mut view.cursor).handle_key(other);
                view.scroll = 0;
            }
        }
        return;
    }
    match key {
        KeyCode::Esc => app.screen = view.return_screen,
        KeyCode::Char('/') => {
            view.searching = true;
            view.cursor = super::input::grapheme_count(&view.query);
        }
        KeyCode::Char('f') => {
            view.filter = match view.filter {
                LeaseFilter::All => LeaseFilter::Active,
                LeaseFilter::Active => LeaseFilter::Expired,
                LeaseFilter::Expired => LeaseFilter::All,
            };
            view.scroll = 0;
        }
        KeyCode::Char('s') => {
            view.sort_expiration = !view.sort_expiration;
            view.scroll = 0;
        }
        KeyCode::Up => view.scroll = view.scroll.saturating_sub(1),
        KeyCode::Down => view.scroll = view.scroll.saturating_add(1).min(view.max_scroll()),
        KeyCode::PageUp => view.scroll = view.scroll.saturating_sub(view.viewport_rows.max(1)),
        KeyCode::PageDown => {
            view.scroll = view
                .scroll
                .saturating_add(view.viewport_rows.max(1))
                .min(view.max_scroll())
        }
        KeyCode::Home => view.scroll = 0,
        KeyCode::End => view.scroll = view.max_scroll(),
        KeyCode::Enter | KeyCode::Char('r') => refresh_dhcp_leases(app, client).await,
        _ => {}
    }
}

pub(crate) async fn handle_dhcp_editor_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    let Some(editor) = app.dhcp_ui.dhcp_editor.as_mut() else {
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
    let Some(editor) = &app.dhcp_ui.dhcp_editor else {
        return;
    };
    let interface = editor.interface.clone();
    if let Some((expected_revision, mut config)) = editor.offline_intent.clone() {
        config.dhcp = None;
        save_offline_dhcp(app, client, interface, config, expected_revision).await;
        return;
    }
    match client.request(&Request::DisableDhcp { interface }).await {
        Ok(Response::NetworkChangePending { change }) => {
            app.confirmation.pending = Some(change);
            app.confirmation.pending_focus = 0;
            app.confirmation.pending_return_screen = Screen::DhcpInterfaceList;
            app.screen = Screen::PendingChange;
        }
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
    let Some(editor) = &app.dhcp_ui.dhcp_editor else {
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
        Ok(Response::NetworkChangePending { change }) => {
            app.confirmation.pending = Some(change);
            app.confirmation.pending_focus = 0;
            app.confirmation.pending_return_screen = Screen::DhcpInterfaceList;
            app.screen = Screen::PendingChange;
        }
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
