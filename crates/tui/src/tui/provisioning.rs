//! Wi-Fi uplink -> AP setup, using the daemon's whole-router transaction.
use crossterm::event::KeyCode;
use ratatui::{
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};
use traffic_masq_protocol::*;
use zeroize::Zeroize;

use super::{
    api::{
        client::ApiClient,
        model::{Request, Response},
    },
    current_unix_time, input,
    layout::panel,
    logs::LogLevel,
    router::RouterPendingView,
    theme, Screen, TuiApp,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    Uplink,
    UplinkSsid,
    UplinkSecurity,
    UplinkPassword,
    Output,
    OutputSsid,
    OutputSecurity,
    OutputPassword,
    Country,
    Band,
    Channel,
    Width,
    Isolation,
    Address,
    PoolStart,
    PoolEnd,
    Dns,
    Lease,
    AllowManagement,
    Next,
    Back,
}
const UPLINK: &[Field] = &[
    Field::Uplink,
    Field::UplinkSsid,
    Field::UplinkSecurity,
    Field::UplinkPassword,
    Field::Next,
    Field::Back,
];
const OUTPUT: &[Field] = &[
    Field::Output,
    Field::OutputSsid,
    Field::OutputSecurity,
    Field::OutputPassword,
    Field::Country,
    Field::Band,
    Field::Channel,
    Field::Width,
    Field::Isolation,
    Field::Next,
    Field::Back,
];
const LAN: &[Field] = &[
    Field::Address,
    Field::PoolStart,
    Field::PoolEnd,
    Field::Dns,
    Field::Lease,
    Field::AllowManagement,
    Field::Next,
    Field::Back,
];

pub(crate) struct Wizard {
    step: usize,
    field: Field,
    cursor: usize,
    scroll: usize,
    radios: Vec<String>,
    uplink: String,
    uplink_ssid: String,
    uplink_security: WifiClientSecurity,
    uplink_password: String,
    output: String,
    output_ssid: String,
    output_security: WifiSecurity,
    output_password: String,
    country: String,
    band: WifiBand,
    channel: String,
    width: WifiChannelWidth,
    isolation: bool,
    address: String,
    pool_start: String,
    pool_end: String,
    dns: String,
    lease: String,
    allow_management: bool,
    review: Option<Review>,
    discard: bool,
}

struct Review {
    request: RouterProvisioningRequest,
    preview: RouterProvisioningPreviewView,
    previous: RouterConfigView,
    scroll: usize,
    max_scroll: usize,
    rendered: bool,
    uncertain: bool,
}

impl Drop for Wizard {
    fn drop(&mut self) {
        self.uplink_password.zeroize();
        self.output_password.zeroize();
    }
}

impl Wizard {
    fn new(radios: Vec<String>) -> Self {
        Self {
            step: 0,
            field: Field::Uplink,
            cursor: 0,
            scroll: 0,
            uplink: radios.first().cloned().unwrap_or_default(),
            output: radios.get(1).cloned().unwrap_or_default(),
            radios,
            uplink_ssid: String::new(),
            uplink_security: WifiClientSecurity::Wpa2,
            uplink_password: String::new(),
            output_ssid: "traffic-masq".into(),
            output_security: WifiSecurity::Wpa2,
            output_password: String::new(),
            country: String::new(),
            band: WifiBand::Ghz2,
            channel: "0".into(),
            width: WifiChannelWidth::Ht20,
            isolation: false,
            address: String::new(),
            pool_start: String::new(),
            pool_end: String::new(),
            dns: String::new(),
            lease: "3600".into(),
            allow_management: false,
            review: None,
            discard: false,
        }
    }
    fn fields(&self) -> &'static [Field] {
        match self.step {
            0 => UPLINK,
            1 => OUTPUT,
            _ => LAN,
        }
    }
    fn text(&mut self) -> Option<&mut String> {
        match self.field {
            Field::Uplink => Some(&mut self.uplink),
            Field::UplinkSsid => Some(&mut self.uplink_ssid),
            Field::UplinkPassword => Some(&mut self.uplink_password),
            Field::Output => Some(&mut self.output),
            Field::OutputSsid => Some(&mut self.output_ssid),
            Field::OutputPassword => Some(&mut self.output_password),
            Field::Country => Some(&mut self.country),
            Field::Channel => Some(&mut self.channel),
            Field::Address => Some(&mut self.address),
            Field::PoolStart => Some(&mut self.pool_start),
            Field::PoolEnd => Some(&mut self.pool_end),
            Field::Dns => Some(&mut self.dns),
            Field::Lease => Some(&mut self.lease),
            _ => None,
        }
    }
    fn reset_cursor(&mut self) {
        self.cursor = self.text().map_or(0, |s| input::grapheme_count(s));
    }
    fn go(&mut self, step: usize) {
        self.step = step;
        self.field = self.fields()[0];
        self.scroll = 0;
        self.reset_cursor();
    }
    fn request(&self) -> Result<RouterProvisioningRequest, String> {
        let uplink = self.uplink.trim().to_string();
        let output = self.output.trim().to_string();
        validate_interface_name(&uplink)?;
        validate_interface_name(&output)?;
        if uplink == output {
            return Err("Select two different radios; the daemon also checks their PHYs".into());
        }
        if self.uplink_ssid.is_empty() || self.output_ssid.is_empty() {
            return Err("Both SSIDs are required".into());
        }
        if self.uplink_ssid.len() > 32 || self.output_ssid.len() > 32 {
            return Err("SSID must be at most 32 bytes".into());
        }
        let country = if self.country.trim().is_empty() {
            None
        } else {
            let country = self.country.trim().to_ascii_uppercase();
            if country.len() != 2 || !country.bytes().all(|b| b.is_ascii_alphabetic()) {
                return Err("Country must be a two-letter code".into());
            }
            Some(country)
        };
        let channel = self
            .channel
            .trim()
            .parse()
            .map_err(|_| "Channel must be an integer (0 = automatic)")?;
        let parse_ip = |value: &str| {
            if value.trim().is_empty() {
                Ok(None)
            } else {
                value
                    .trim()
                    .parse()
                    .map(Some)
                    .map_err(|_| "Invalid DHCP pool IPv4 address".to_string())
            }
        };
        let interface_ipv4 = if self.address.trim().is_empty() {
            None
        } else {
            Some(
                self.address
                    .trim()
                    .parse()
                    .map_err(|_| "Invalid LAN IPv4 address/prefix")?,
            )
        };
        let pool_start = parse_ip(&self.pool_start)?;
        let pool_end = parse_ip(&self.pool_end)?;
        if pool_start.is_some() != pool_end.is_some() {
            return Err("Specify both DHCP pool endpoints, or leave both automatic".into());
        }
        if pool_start.is_some() && interface_ipv4.is_none() {
            return Err("A custom DHCP pool requires an explicit LAN address/prefix".into());
        }
        let dns_servers = self
            .dns
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.parse()
                    .map_err(|_| "Invalid DNS IPv4 address".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let lease_seconds = self
            .lease
            .trim()
            .parse::<u32>()
            .map_err(|_| "Lease must be a positive number of seconds")?;
        if lease_seconds == 0 {
            return Err("Lease must be greater than zero".into());
        }
        Ok(RouterProvisioningRequest {
            uplink: ProvisioningUplinkRequest {
                interface: uplink,
                ssid: self.uplink_ssid.clone(),
                country_code: country.clone(),
                security: self.uplink_security,
            },
            output: ProvisioningOutputRequest {
                interface: output,
                ssid: self.output_ssid.clone(),
                country_code: country,
                band: self.band,
                channel,
                channel_width: self.width,
                security: self.output_security,
                hidden: false,
                client_isolation: self.isolation,
                max_stations: 32,
            },
            downstream: ProvisioningDownstreamOverrides {
                interface_ipv4,
                pool_start,
                pool_end,
                dns_servers,
                lease_seconds: Some(lease_seconds),
            },
            allow_management_change: self.allow_management,
        })
    }
    fn value(&self, field: Field) -> (&'static str, String) {
        match field {
            Field::Uplink => ("Uplink radio (Enter cycles)", self.uplink.clone()),
            Field::UplinkSsid => ("Upstream SSID", self.uplink_ssid.clone()),
            Field::UplinkSecurity => ("Upstream security", format!("{:?}", self.uplink_security)),
            Field::UplinkPassword => ("Upstream password", String::new()),
            Field::Output => ("AP radio (Enter cycles)", self.output.clone()),
            Field::OutputSsid => ("AP SSID", self.output_ssid.clone()),
            Field::OutputSecurity => ("AP security", format!("{:?}", self.output_security)),
            Field::OutputPassword => ("AP password", String::new()),
            Field::Country => ("Country", self.country.clone()),
            Field::Band => ("Band", self.band.to_string()),
            Field::Channel => ("Channel (0 = auto)", self.channel.clone()),
            Field::Width => ("Channel width", format!("{:?}", self.width)),
            Field::Isolation => ("Client isolation", self.isolation.to_string()),
            Field::Address => ("LAN IPv4/prefix (blank = auto)", self.address.clone()),
            Field::PoolStart => ("DHCP start (blank = auto)", self.pool_start.clone()),
            Field::PoolEnd => ("DHCP end (blank = auto)", self.pool_end.clone()),
            Field::Dns => ("DNS IPv4 addresses", self.dns.clone()),
            Field::Lease => ("Lease seconds", self.lease.clone()),
            Field::AllowManagement => (
                "Allow management interface changes",
                self.allow_management.to_string(),
            ),
            Field::Next => (
                if self.step == 2 {
                    "Review complete setup"
                } else {
                    "Next"
                },
                String::new(),
            ),
            Field::Back => (
                if self.step == 0 {
                    "Cancel"
                } else {
                    "Previous step"
                },
                String::new(),
            ),
        }
    }
}

pub(crate) async fn open(app: &mut TuiApp, client: &ApiClient) {
    if app.router.staged
        || app.router.recovery_blocks_mutations()
        || app.router.coordinator_status == Some(CoordinatorStatus::Pending)
        || !app.dashboard.pending_network_changes.is_empty()
        || app.router_pending.is_some()
        || app.pending.is_some()
    {
        app.push_message(
            LogLevel::Warn,
            "Finish the current router draft, pending change or recovery before setup",
        );
        return;
    }
    super::wifi::load_wifi_data(app, client).await;
    let radios = app
        .wifi
        .rows
        .iter()
        .filter(|r| r.presence == InterfacePresence::Present)
        .map(|r| r.interface.clone())
        .collect();
    let mut wizard = Wizard::new(radios);
    wizard.reset_cursor();
    app.provisioning = Some(wizard);
    app.screen = Screen::Provisioning;
}

pub(crate) fn focus_action(app: &mut TuiApp, slot: usize) {
    if let Some(w) = &mut app.provisioning {
        if w.review.is_none() && !w.discard {
            if let Some(field) = w.fields().get(slot) {
                w.field = *field;
                w.reset_cursor();
            }
        }
    }
}

fn review_text(review: &Review) -> String {
    let p = &review.preview;
    let mut lines = vec![
        "This setup REPLACES the selected interface configurations and router policy.".into(),
        "Existing owned static routes, sharing rules and the VPN chain are replaced.".into(),
        format!(
            "Uplink: {} / SSID {} / {:?} / DHCP",
            p.uplink.interface, p.uplink.ssid, p.uplink.security
        ),
        format!(
            "AP: {} / SSID {} / {:?}",
            p.output.interface, p.output.ssid, p.output.security
        ),
        format!(
            "Radio: {} channel {} {:?}; country {}",
            p.output.band,
            p.output.channel,
            p.output.channel_width,
            p.output.country_code.as_deref().unwrap_or("unset")
        ),
        format!(
            "AP: hidden {}, isolation {}, max clients {}",
            p.output.hidden, p.output.client_isolation, p.output.max_stations
        ),
        format!(
            "LAN: {} | gateway {}",
            p.downstream.interface_ipv4, p.downstream.router
        ),
        format!(
            "DHCP: {} - {} | lease {}s",
            p.downstream.pool_start, p.downstream.pool_end, p.downstream.lease_seconds
        ),
        format!(
            "DNS: {}",
            if p.downstream.dns_servers.is_empty() {
                "NONE (clients receive no DNS servers)".into()
            } else {
                p.downstream
                    .dns_servers
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ),
        format!(
            "Routing enabled; NAT/forwarding: {} -> {}",
            p.output.interface, p.uplink.interface
        ),
        format!(
            "Management changes permitted: {}",
            review.request.allow_management_change
        ),
    ];
    if let Some(uplink) = &review.previous.uplink {
        lines.push(format!(
            "Previous uplink: {} ({:?})",
            uplink.interface, uplink.mode
        ));
    }
    for route in &review.previous.owned_routes {
        lines.push(format!(
            "Remove owned route: {} via {:?} dev {:?} table {} metric {:?}",
            route.destination, route.gateway, route.output_interface, route.table, route.metric
        ));
    }
    for rule in review.previous.forwarding.iter().flatten() {
        lines.push(format!(
            "Replace sharing: {} -> {} ({:?})",
            rule.from, rule.to, rule.source_subnet
        ));
    }
    for hop in &review.previous.vpn_chain {
        lines.push(format!("Remove VPN hop: {}", hop.profile_name));
    }
    for warning in &p.warnings {
        lines.push(format!("Warning: {warning:?}"));
    }
    lines.push("Apply starts the rollback timer. Verify connectivity, then Commit.".into());
    lines.join("\n")
}

pub(super) fn confirmation(app: &TuiApp) -> Option<super::confirmation::Dialog> {
    app.provisioning
        .as_ref()?
        .discard
        .then(|| super::confirmation::Dialog {
            secondary: None,
            title: "Discard router setup draft?",
            action: "Discard",
            lines: vec![
                "Target: current Wi-Fi router setup draft".into(),
                "Unsaved settings and entered credentials will be discarded.".into(),
                "Cancel returns to editing.".into(),
            ],
        })
}

pub(crate) fn render(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    if let Some(dialog) = confirmation(app) {
        dialog.render(
            frame,
            area,
            &mut app.ui,
            app.confirmation_focus,
            app.confirmation_scroll,
        );
        return;
    }
    let Some(w) = &mut app.provisioning else {
        return;
    };
    let block = panel("Wi-Fi router setup");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if let Some(review) = &mut w.review {
        let body = Rect::new(
            inner.x,
            inner.y,
            inner.width,
            inner.height.saturating_sub(2),
        );
        let lines = super::logs::wrap_log_message(&review_text(review), body.width as usize);
        review.max_scroll = lines.len().saturating_sub(body.height as usize);
        let paragraph = Paragraph::new(lines.into_iter().map(Line::from).collect::<Vec<_>>());
        review.scroll = review.scroll.min(review.max_scroll);
        review.rendered = true;
        frame.render_widget(
            paragraph.scroll((review.scroll.min(u16::MAX as usize) as u16, 0)),
            body,
        );
        let bottom = Rect::new(
            inner.x,
            inner.y + body.height,
            inner.width,
            inner.height.min(2),
        );
        frame.render_widget(Paragraph::new(if review.uncertain { "Apply not confirmed. Inspect Router state before any retry.\nEsc: leave setup" } else if review.scroll < review.max_scroll { "Scroll to the end to review all changes.\nPgUp/PgDn/End: scroll | Esc: edit" } else { "[Enter: Apply complete setup]    [Esc: edit]\nConnectivity must be confirmed before the rollback deadline." }).style(Style::default().fg(theme::WARN)), bottom);
        // Explicit buttons share the same keyboard paths and review gate.
        if !review.uncertain && review.scroll >= review.max_scroll {
            app.ui
                .buttons
                .push((Rect::new(bottom.x, bottom.y, bottom.width.min(31), 1), 0));
        }
        return;
    }
    let title = match w.step {
        0 => "1/3: Wi-Fi Internet connection",
        1 => "2/3: Local access point",
        _ => "3/3: LAN and DHCP",
    };
    let header = vec![
        Line::from(title),
        Line::styled(
            "Requires two separate radios. Replaces router policy and selected interfaces.",
            Style::default().fg(theme::WARN),
        ),
        Line::from("Blank passwords retain credentials already saved for the same role."),
    ];
    frame.render_widget(
        Paragraph::new(header),
        Rect::new(inner.x, inner.y, inner.width, 3.min(inner.height)),
    );
    let body = Rect::new(
        inner.x,
        inner.y + 3,
        inner.width,
        inner.height.saturating_sub(4),
    );
    let fields = w.fields();
    let selected = fields.iter().position(|f| *f == w.field).unwrap_or(0);
    let visible = body.height.max(1) as usize;
    w.scroll = w.scroll.min(selected);
    if selected >= w.scroll + visible {
        w.scroll = selected + 1 - visible;
    }
    let mut lines = Vec::new();
    for (slot, field) in fields.iter().enumerate().skip(w.scroll).take(visible) {
        let (label, value) = w.value(*field);
        let active = *field == w.field;
        let style = Style::default().fg(if active { theme::ACCENT } else { theme::TEXT });
        let mut spans = vec![Span::styled(
            format!("{} {label}: ", if active { "▶" } else { " " }),
            style,
        )];
        if matches!(field, Field::UplinkPassword | Field::OutputPassword) {
            let password = if *field == Field::UplinkPassword {
                &w.uplink_password
            } else {
                &w.output_password
            };
            spans.extend(input::render_masked_with_cursor(
                input::grapheme_count(password),
                w.cursor,
                active,
                '*',
                style,
            ));
        } else {
            spans.extend(input::render_value_with_cursor(
                &value, w.cursor, active, style,
            ));
        }
        app.ui.buttons.push((
            Rect::new(body.x, body.y + lines.len() as u16, body.width, 1),
            slot,
        ));
        lines.push(Line::from(spans));
    }
    frame.render_widget(Paragraph::new(lines), body);
}

pub(crate) async fn handle_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    let Some(w) = &mut app.provisioning else {
        return;
    };
    if w.discard {
        match key {
            KeyCode::Enter => {
                app.provisioning = None;
                app.screen = Screen::Router;
            }
            KeyCode::Esc => w.discard = false,
            _ => {}
        }
        return;
    }
    if let Some(review) = &mut w.review {
        match key {
            KeyCode::Esc if review.uncertain => {
                app.provisioning = None;
                app.screen = Screen::Router;
                super::router::refresh_router_data(app, client).await;
            }
            KeyCode::Esc => w.review = None,
            KeyCode::Up => review.scroll = review.scroll.saturating_sub(1),
            KeyCode::Down => review.scroll = (review.scroll + 1).min(review.max_scroll),
            KeyCode::PageUp => review.scroll = review.scroll.saturating_sub(8),
            KeyCode::PageDown => review.scroll = (review.scroll + 8).min(review.max_scroll),
            KeyCode::Home => review.scroll = 0,
            KeyCode::End => review.scroll = review.max_scroll,
            KeyCode::Enter
                if review.rendered && review.scroll >= review.max_scroll && !review.uncertain =>
            {
                apply(app, client).await
            }
            _ => {}
        }
        return;
    }
    match key {
        KeyCode::Esc => w.discard = true,
        KeyCode::Up | KeyCode::Down => {
            w.field = input::move_clamped(w.fields(), w.field, key == KeyCode::Down);
            w.reset_cursor();
        }
        KeyCode::Enter => match w.field {
            Field::Back if w.step == 0 => w.discard = true,
            Field::Back => w.go(w.step - 1),
            Field::Next if w.step < 2 => w.go(w.step + 1),
            Field::Next => preview(app, client).await,
            Field::UplinkSecurity => {
                w.uplink_security = input::move_wrapped(
                    &[
                        WifiClientSecurity::Wpa2,
                        WifiClientSecurity::Wpa3,
                        WifiClientSecurity::Wpa2Wpa3,
                        WifiClientSecurity::Open,
                    ],
                    w.uplink_security,
                    true,
                )
            }
            Field::OutputSecurity => {
                w.output_security = input::move_wrapped(
                    &[
                        WifiSecurity::Wpa2,
                        WifiSecurity::Wpa3,
                        WifiSecurity::Wpa2Wpa3,
                        WifiSecurity::Open,
                    ],
                    w.output_security,
                    true,
                )
            }
            Field::Band => {
                w.band = if w.band == WifiBand::Ghz2 {
                    WifiBand::Ghz5
                } else {
                    WifiBand::Ghz2
                }
            }
            Field::Width => {
                w.width = input::move_wrapped(
                    &[
                        WifiChannelWidth::Ht20,
                        WifiChannelWidth::Ht40,
                        WifiChannelWidth::Vht80,
                    ],
                    w.width,
                    true,
                )
            }
            Field::Isolation => w.isolation = !w.isolation,
            Field::AllowManagement => w.allow_management = !w.allow_management,
            Field::Uplink | Field::Output => {
                let current = if w.field == Field::Uplink {
                    &mut w.uplink
                } else {
                    &mut w.output
                };
                if !w.radios.is_empty() {
                    let index = w
                        .radios
                        .iter()
                        .position(|r| r == current)
                        .map_or(0, |i| (i + 1) % w.radios.len());
                    *current = w.radios[index].clone();
                }
                w.reset_cursor();
            }
            _ => {
                w.field = input::move_clamped(w.fields(), w.field, true);
                w.reset_cursor();
            }
        },
        other => {
            let mut cursor = w.cursor;
            if let Some(text) = w.text() {
                input::TextEditor::new(text, &mut cursor).handle_key(other);
            }
            w.cursor = cursor;
        }
    }
}

fn error(app: &mut TuiApp, response: Response) {
    let message = match response {
        Response::Error { message } => message,
        Response::RouterProvisioningError { detail } => format!("Setup: {detail:?}"),
        other => format!("Unexpected setup response: {other:?}"),
    };
    app.push_message(LogLevel::Error, message);
}

async fn preview(app: &mut TuiApp, client: &ApiClient) {
    let Some(w) = &app.provisioning else {
        return;
    };
    let mut request = match w.request() {
        Ok(r) => r,
        Err(e) => {
            app.push_message(LogLevel::Error, e);
            return;
        }
    };
    let read = Request::RouterProvisioningPreview {
        request: RouterProvisioningPreviewRequest {
            provisioning: request.clone(),
            uplink_secret_pending: request.uplink.security.requires_passphrase()
                && !w.uplink_password.is_empty(),
            output_secret_pending: request.output.security.requires_passphrase()
                && !w.output_password.is_empty(),
        },
    };
    let previous = match client.request(&Request::GetRouterConfig).await {
        Ok(Response::RouterConfig { config }) => config,
        Ok(response) => {
            error(app, response);
            return;
        }
        Err(e) => {
            app.push_message(LogLevel::Error, e.to_string());
            return;
        }
    };
    match client.request(&read).await {
        Ok(Response::RouterProvisioningPreview { preview }) => {
            // Freeze automatically selected LAN values so Apply cannot silently choose another subnet.
            request.downstream = ProvisioningDownstreamOverrides {
                interface_ipv4: Some(preview.downstream.interface_ipv4),
                pool_start: Some(preview.downstream.pool_start),
                pool_end: Some(preview.downstream.pool_end),
                dns_servers: preview.downstream.dns_servers.clone(),
                lease_seconds: Some(preview.downstream.lease_seconds),
            };
            if let Some(w) = &mut app.provisioning {
                w.review = Some(Review {
                    request,
                    preview,
                    previous,
                    scroll: 0,
                    max_scroll: 0,
                    rendered: false,
                    uncertain: false,
                });
            }
        }
        Ok(response) => error(app, response),
        Err(e) => app.push_message(LogLevel::Error, e.to_string()),
    }
}

async fn apply(app: &mut TuiApp, client: &ApiClient) {
    // Obtain the active timeout before writing. Never guess the confirmation deadline.
    match client.request(&Request::GetSecurityConfig).await {
        Ok(Response::SecurityConfig { active, .. }) => {
            app.router_rollback_timeout_seconds = active.rollback_timeout_seconds
        }
        Ok(response) => {
            error(app, response);
            return;
        }
        Err(e) => {
            app.push_message(LogLevel::Error, e.to_string());
            return;
        }
    }
    let Some(w) = &mut app.provisioning else {
        return;
    };
    let Some(review) = &mut w.review else {
        return;
    };
    review.uncertain = true;
    let mut request = Request::RouterProvisioningApply {
        request: RouterProvisioningApplyRequest {
            provisioning: review.request.clone(),
            uplink_passphrase: (review.request.uplink.security.requires_passphrase()
                && !w.uplink_password.is_empty())
            .then(|| w.uplink_password.clone()),
            output_passphrase: (review.request.output.security.requires_passphrase()
                && !w.output_password.is_empty())
            .then(|| w.output_password.clone()),
        },
    };
    let started = current_unix_time();
    let response = client.request(&request).await;
    if let Request::RouterProvisioningApply { request } = &mut request {
        request.uplink_passphrase.zeroize();
        request.output_passphrase.zeroize();
    }
    match response {
        Ok(Response::RouterProvisioningApplied { token, .. }) => {
            app.pending_focus = 0;
            app.router_pending = Some(RouterPendingView {
                token,
                applied_at_unix: started,
                rollback_failure: None,
                recovery: None,
                scroll: 0,
                max_scroll: 0,
            });
            app.provisioning = None;
            app.screen = Screen::RouterPending;
            app.push_message(
                LogLevel::Info,
                "Wi-Fi router setup applied. Verify connectivity and Commit before rollback.",
            );
        }
        Ok(response) => {
            error(app, response);
        }
        Err(e) => app.push_message(
            LogLevel::Error,
            format!("Setup outcome unknown: {e}. Inspect Router state; do not repeat Apply"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn setup_validates_interfaces_and_pool_and_preserves_ssid() {
        let mut w = Wizard::new(vec!["wlan0".into(), "wlan1".into()]);
        w.uplink_ssid = " upstream ".into();
        let request = w.request().unwrap();
        assert_eq!(request.uplink.ssid, " upstream ");
        assert!(!request.allow_management_change);
        w.output = "wlan0".into();
        assert!(w.request().is_err());
        w.output = "wlan1".into();
        w.pool_start = "192.168.5.100".into();
        assert!(w.request().is_err());
        w.pool_end = "192.168.5.200".into();
        assert!(w.request().is_err());
        w.address = "192.168.5.1/24".into();
        assert!(w.request().is_ok());
        w.dns = "1.1.1.1, 9.9.9.9".into();
        assert_eq!(w.request().unwrap().downstream.dns_servers.len(), 2);
    }
    fn setup() -> Wizard {
        let mut w = Wizard::new(vec!["wlan0".into(), "wlan1".into()]);
        w.uplink_ssid = "upstream".into();
        w.uplink_password = "secret-upstream".into();
        w.output_password = "secret-downstream".into();
        w.go(2);
        w.field = Field::Next;
        w
    }
    fn preview_fixture() -> RouterProvisioningPreviewView {
        serde_json::from_value(serde_json::json!({
            "uplink": {"interface":"wlan0","ssid":"upstream","country_code":null,"security":"wpa2","mode":"dhcp","secret_available":true},
            "output": {"interface":"wlan1","ssid":"traffic-masq","country_code":null,"band":"2g","channel":0,"channel_width":"ht20","security":"wpa2","hidden":false,"client_isolation":false,"max_stations":32,"secret_available":true},
            "downstream": {"subnet":"192.168.77.0/24","interface_ipv4":"192.168.77.1/24","router":"192.168.77.1","pool_start":"192.168.77.100","pool_end":"192.168.77.200","dns_servers":[],"lease_seconds":3600},
            "warnings":[{"kind":"no_downstream_dns"}]
        })).unwrap()
    }
    #[tokio::test]
    async fn preview_freezes_auto_network_and_apply_uses_router_confirmation() {
        let preview = preview_fixture();
        let mock = super::super::test_api::mock(vec![
            Response::RouterConfig {
                config: RouterConfigView {
                    owned_routes: (0..8)
                        .map(|i| OwnedIpv4RouteConfigView {
                            destination: format!("10.{i}.0.0/16").parse().unwrap(),
                            gateway: None,
                            output_interface: Some("eth1".into()),
                            table: 254,
                            metric: None,
                        })
                        .collect(),
                    ..Default::default()
                },
            },
            Response::RouterProvisioningPreview {
                preview: preview.clone(),
            },
            Response::SecurityConfig {
                active: SecuritySettings {
                    rollback_timeout_seconds: 90,
                },
                desired: SecuritySettings {
                    rollback_timeout_seconds: 90,
                },
                override_active: false,
                restart_required: false,
            },
            Response::RouterProvisioningApplied {
                token: "setup-token".into(),
                preview,
            },
        ])
        .await;
        let mut app = TuiApp {
            screen: Screen::Provisioning,
            provisioning: Some(setup()),
            ..Default::default()
        };
        handle_key(&mut app, KeyCode::Enter, &mock.client).await;
        handle_key(&mut app, KeyCode::Enter, &mock.client).await;
        assert_eq!(
            mock.calls.lock().unwrap().len(),
            2,
            "unrendered preview cannot apply"
        );
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|f| super::super::render(f, &mut app, false))
            .unwrap();
        assert!(
            app.provisioning
                .as_ref()
                .unwrap()
                .review
                .as_ref()
                .unwrap()
                .max_scroll
                > 0
        );
        handle_key(&mut app, KeyCode::Enter, &mock.client).await;
        assert_eq!(
            mock.calls.lock().unwrap().len(),
            2,
            "unread review cannot apply"
        );
        handle_key(&mut app, KeyCode::End, &mock.client).await;
        terminal
            .draw(|f| super::super::render(f, &mut app, false))
            .unwrap();
        handle_key(&mut app, KeyCode::Enter, &mock.client).await;
        assert_eq!(app.screen, Screen::RouterPending);
        assert!(app.provisioning.is_none());
        assert_eq!(app.router_pending.as_ref().unwrap().token, "setup-token");
        assert_eq!(app.router_rollback_timeout_seconds, 90);
        let calls = mock.calls.lock().unwrap();
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[3].path, "/api/v1/control");
        assert_eq!(calls[3].body["type"], "router_provisioning_apply");
        assert_eq!(
            calls[3].body["request"]["provisioning"]["downstream"]["interface_ipv4"],
            "192.168.77.1/24"
        );
        assert_eq!(
            calls[3].body["request"]["uplink_passphrase"],
            "secret-upstream"
        );
        assert_eq!(
            calls[3].body["request"]["output_passphrase"],
            "secret-downstream"
        );
        assert!(!calls.iter().any(|c| c.body["type"] == "router_commit"));
        assert!(!format!("{:?}", calls[1].body).contains("secret-upstream"));
    }

    #[tokio::test]
    async fn unknown_apply_response_fences_retry_and_draft_secrets_are_masked() {
        let mock = super::super::test_api::mock(vec![
            Response::SecurityConfig {
                active: SecuritySettings {
                    rollback_timeout_seconds: 60,
                },
                desired: SecuritySettings {
                    rollback_timeout_seconds: 60,
                },
                override_active: false,
                restart_required: false,
            },
            Response::RouterRolledBack,
        ])
        .await;
        let mut w = setup();
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        w.go(0);
        w.field = Field::UplinkPassword;
        let mut app = TuiApp {
            screen: Screen::Provisioning,
            provisioning: Some(w),
            ..Default::default()
        };
        terminal
            .draw(|f| super::super::render(f, &mut app, false))
            .unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(!text.contains("secret-upstream"));
        assert!(text.contains("********"));
        let w = app.provisioning.as_mut().unwrap();
        w.review = Some(Review {
            request: w.request().unwrap(),
            preview: preview_fixture(),
            previous: RouterConfigView::default(),
            scroll: 0,
            max_scroll: 0,
            rendered: true,
            uncertain: false,
        });
        handle_key(&mut app, KeyCode::Enter, &mock.client).await;
        assert!(
            app.provisioning
                .as_ref()
                .unwrap()
                .review
                .as_ref()
                .unwrap()
                .uncertain
        );
        handle_key(&mut app, KeyCode::Enter, &mock.client).await;
        assert_eq!(mock.calls.lock().unwrap().len(), 2);
        assert!(app.router_pending.is_none());
    }

    #[tokio::test]
    async fn cancel_requires_confirmation_and_discards_credentials() {
        let client = ApiClient::new("/must-not-be-opened");
        let mut app = TuiApp {
            screen: Screen::Provisioning,
            provisioning: Some(setup()),
            ..Default::default()
        };
        handle_key(&mut app, KeyCode::Esc, &client).await;
        assert!(app.provisioning.as_ref().unwrap().discard);
        handle_key(&mut app, KeyCode::Esc, &client).await;
        assert!(!app.provisioning.as_ref().unwrap().discard);
        handle_key(&mut app, KeyCode::Esc, &client).await;
        handle_key(&mut app, KeyCode::Enter, &client).await;
        assert!(app.provisioning.is_none());
        assert_eq!(app.screen, Screen::Router);
    }
}
