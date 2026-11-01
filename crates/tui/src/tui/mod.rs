use ratatui::text::{Line, Span};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyModifiers,
    MouseButton, MouseEvent, MouseEventKind,
};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::{execute, terminal};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout};
use ratatui::style::Style;
use ratatui::widgets::Paragraph;
use ratatui::Terminal;
use zeroize::Zeroize;

use crate::tui::api::client::ApiClient;
use crate::tui::api::model::{DhcpClientStatusView, Request, Response};
use traffic_masq_netlink::{NetworkProvider, RtnetlinkNetworkProvider};
use traffic_masq_protocol::{InterfaceChangePlanView, PendingNetworkChange};
use traffic_masq_protocol::{InterfaceStatusView as InterfaceStatus, Ipv4AddressInfoView};

mod access;
pub(crate) mod api;
mod confirmation;
pub mod connections;
mod daemon_logs;
mod dashboard;
mod dhcp;
mod dhcp_client;
mod dhcp_client_editor;
mod dns_defaults;
mod forwarding;
mod input;
mod interface_status;
mod interfaces;
mod layout;
mod logs;
mod port_forwarding;
mod router;
mod router_health;
mod router_settings;
mod router_topology;
mod session;
mod settings;
mod state;
#[cfg(test)]
mod test_api;
mod vpn;
mod vpn_policy;
mod wifi;
mod wifi_stations;

use access::AccessEditor;
use dashboard::DashboardData;
use dhcp::{DhcpEditor, DhcpLeasesView};
use interfaces::InterfaceEditor;
use layout::UiLayout;
use logs::LogLevel;
use router::{RouterData, RouterFocus, RouterPendingView};
use settings::{PasswordChangeEditor, SecurityEditor};
use state::*;
use vpn::{VpnData, VpnImportEditor};
use vpn_policy::VpnPolicyData;

pub(crate) mod theme {
    use ratatui::style::Color;

    pub const ACCENT: Color = Color::Cyan;
    pub const ACCENT_ALT: Color = Color::Magenta;
    pub const GOOD: Color = Color::Green;
    pub const WARN: Color = Color::Yellow;
    pub const BAD: Color = Color::Red;
    pub const MUTED: Color = Color::DarkGray;
    pub const TEXT: Color = Color::White;
    pub const BORDER: Color = Color::DarkGray;
    pub const SELECTED_BG: Color = Color::Cyan;
    pub const SELECTED_FG: Color = Color::Black;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Dashboard,
    Access,
    InterfaceList,
    InterfaceEditor,
    DhcpInterfaceList,
    DhcpEditor,
    DhcpLeases,
    DhcpClient,
    DhcpClientEditor,
    WifiStations,
    Preview,
    PendingChange,
    Router,
    RouterSettings,
    RouterHealth,
    RouterPlan,
    RouterPending,
    RouteEditor,
    Forwarding,
    PortForwarding,
    Vpn,
    VpnProfile,
    VpnSettings,
    VpnImport,
    VpnPolicy,
    Wifi,
    WifiEditor,
    WifiScan,
    WifiProfiles,
    WifiApProfiles,
    WifiProfileEditor,
    WifiConnectPrompt,
    Settings,
    SettingsPassword,
    DnsDefaults,
    Log,
    DaemonLogs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Section {
    Dashboard,
    Interfaces,
    Dhcp,
    DhcpClient,
    Router,
    Vpn,
    Wifi,
    Settings,
    Log,
}

const ALL_SECTIONS: [Section; 9] = [
    Section::Dashboard,
    Section::Interfaces,
    Section::Dhcp,
    Section::DhcpClient,
    Section::Router,
    Section::Vpn,
    Section::Wifi,
    Section::Settings,
    Section::Log,
];

const DEFAULT_SECTIONS: [Section; 8] = [
    Section::Dashboard,
    Section::Interfaces,
    Section::Dhcp,
    Section::Router,
    Section::Vpn,
    Section::Wifi,
    Section::Settings,
    Section::Log,
];

pub(crate) fn active_sections(show_dhcp_client: bool) -> &'static [Section] {
    if show_dhcp_client {
        &ALL_SECTIONS
    } else {
        &DEFAULT_SECTIONS
    }
}

impl Section {
    fn title(self) -> &'static str {
        match self {
            Section::Dashboard => "Dashboard",
            Section::Interfaces => "Interfaces",
            Section::Dhcp => "DHCP Server",
            Section::DhcpClient => "DHCP Client",
            Section::Router => "Route",
            Section::Vpn => "VPN",
            Section::Wifi => "Wi-Fi",
            Section::Settings => "Settings",
            Section::Log => "Log",
        }
    }
}

fn section_of(screen: Screen) -> Section {
    match screen {
        Screen::Dashboard | Screen::PendingChange => Section::Dashboard,
        Screen::InterfaceList | Screen::InterfaceEditor | Screen::Preview => Section::Interfaces,
        Screen::DhcpInterfaceList | Screen::DhcpEditor | Screen::DhcpLeases => Section::Dhcp,
        Screen::DhcpClient | Screen::DhcpClientEditor => Section::DhcpClient,
        Screen::Router
        | Screen::RouteEditor
        | Screen::RouterHealth
        | Screen::RouterSettings
        | Screen::RouterPlan
        | Screen::RouterPending
        | Screen::Forwarding
        | Screen::PortForwarding
        | Screen::VpnPolicy => Section::Router,
        Screen::Vpn | Screen::VpnImport | Screen::VpnProfile | Screen::VpnSettings => Section::Vpn,
        Screen::Wifi
        | Screen::WifiStations
        | Screen::WifiEditor
        | Screen::WifiScan
        | Screen::WifiProfiles
        | Screen::WifiApProfiles
        | Screen::WifiProfileEditor
        | Screen::WifiConnectPrompt => Section::Wifi,
        Screen::Settings | Screen::SettingsPassword | Screen::Access | Screen::DnsDefaults => {
            Section::Settings
        }
        Screen::Log | Screen::DaemonLogs => Section::Log,
    }
}

fn section_of_app(app: &TuiApp) -> Section {
    if app.screen == Screen::PendingChange {
        section_of(app.confirmation.pending_return_screen)
    } else {
        section_of(app.screen)
    }
}

fn section_available(section: Section, direct: bool) -> bool {
    !direct
        || matches!(
            section,
            Section::Dashboard | Section::Interfaces | Section::Log
        )
}

fn adjacent_section(
    current: Section,
    forward: bool,
    show_dhcp_client: bool,
    direct: bool,
) -> Section {
    let sections = active_sections(show_dhcp_client);
    let index = sections
        .iter()
        .position(|section| *section == current)
        .unwrap_or(0);
    let len = sections.len();
    for step in 1..=len {
        let next_index = if forward {
            (index + step) % len
        } else {
            (index + len - (step % len)) % len
        };
        if section_available(sections[next_index], direct) {
            return sections[next_index];
        }
    }
    current
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ViewIdentity {
    screen: Screen,
    help_open: bool,
    message_open: bool,
    router_pane: router::RouterPane,
    topology_open: bool,
    wifi_actions_open: bool,
    wifi_profiles_mode: Option<wifi::WifiProfilesMode>,
    wifi_ap_profiles_mode: Option<wifi::WifiProfilesMode>,
}

struct TuiApp {
    screen: Screen,
    connected_endpoint: Option<String>,
    last_drawn_view: Option<ViewIdentity>,
    dashboard: DashboardData,
    api_access: Option<AccessEditor>,
    router: RouterData,
    vpn: VpnData,
    vpn_import: Option<VpnImportEditor>,
    vpn_policy: VpnPolicyData,
    wifi: wifi::WifiData,
    pub(crate) show_dhcp_client: bool,
    ui: UiLayout,
    message: Option<String>,
    help_open: bool,
    message_open: bool,
    message_scroll: u16,
    should_quit: bool,
    interface_ui: InterfaceUiState,
    confirmation: ConfirmationState,
    dhcp_ui: DhcpUiState,
    router_ui: RouterUiState,
    wifi_ui: WifiUiState,
    log_view: LogViewState,
    settings_ui: SettingsUiState,
    dashboard_ui: DashboardUiState,
}

impl Default for TuiApp {
    fn default() -> Self {
        Self {
            screen: Screen::Dashboard,
            connected_endpoint: None,
            last_drawn_view: None,
            dashboard: DashboardData::default(),
            api_access: None,
            router: RouterData::default(),
            vpn: VpnData::default(),
            vpn_import: None,
            vpn_policy: VpnPolicyData::default(),
            wifi: wifi::WifiData::default(),
            show_dhcp_client: false,
            ui: UiLayout::default(),
            message: None,
            help_open: false,
            message_open: false,
            message_scroll: 0,
            should_quit: false,
            interface_ui: InterfaceUiState::default(),
            confirmation: ConfirmationState::default(),
            dhcp_ui: DhcpUiState::default(),
            router_ui: RouterUiState::default(),
            wifi_ui: WifiUiState::default(),
            log_view: LogViewState::default(),
            settings_ui: SettingsUiState::default(),
            dashboard_ui: DashboardUiState::default(),
        }
    }
}

impl TuiApp {
    pub(crate) fn push_message(&mut self, level: logs::LogLevel, text: impl Into<String>) {
        let follow_log_tail = self.log_view.logs_scroll >= self.log_view.logs_max_scroll;
        let text = logs::with_troubleshooting_hint(level, text.into());
        self.message = Some(text.clone());
        self.log_view.logs.push_back(logs::LogEntry {
            at_unix: current_unix_time(),
            level,
            message: text,
        });
        self.log_view.logs_dirty = true;
        if self.log_view.logs.len() > logs::LOG_HISTORY_LEN {
            self.log_view.logs.pop_front();
        }
        if follow_log_tail {
            // The exact maximum depends on the rendered viewport. A sentinel
            // is clamped to that maximum on the next render, preserving
            // follow-tail without snapping back after a deliberate Up.
            self.log_view.logs_scroll = usize::MAX;
        }
    }
}

/// Prompt for the current and replacement passwords, update the daemon, and clear cached credentials.
pub async fn change_device_password(socket_path: PathBuf) -> Result<()> {
    change_device_password_with_client(ApiClient::new(socket_path)).await
}

pub async fn change_device_password_with_client(client: ApiClient) -> Result<()> {
    client
        .request(&Request::Ping)
        .await
        .context("traffic-masqd is unavailable")?;
    if !client.auth_initialized().await? {
        anyhow::bail!(
            "device password is not initialized; start the TUI as root for first-time setup"
        );
    }

    let mut current = rpassword::prompt_password("Current device password: ")?;
    let login_result = client.login(&current).await;
    if let Err(error) = login_result {
        current.zeroize();
        return Err(error);
    }

    let mut new_password = rpassword::prompt_password("New device password: ")?;
    let mut repeated = rpassword::prompt_password("Repeat device password: ")?;
    if new_password != repeated {
        let _ = client.logout().await;
        current.zeroize();
        new_password.zeroize();
        repeated.zeroize();
        anyhow::bail!("passwords do not match");
    }

    let result = client.change_password(&current, &new_password).await;
    if result.is_err() {
        let _ = client.logout().await;
    }
    current.zeroize();
    new_password.zeroize();
    repeated.zeroize();
    result?;
    if let Ok(store) = session::SessionStore::for_client(&client) {
        if let Err(error) = store.clear() {
            eprintln!("Could not remove the revoked saved session: {error}");
        }
    }
    println!("Device password updated; all active sessions were revoked.");
    Ok(())
}

struct TerminalGuard;
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        let _ = execute!(io::stdout(), DisableMouseCapture);
        let _ = execute!(io::stdout(), crossterm::cursor::Show);
    }
}

/// Initialize the terminal and run the interactive UI in daemon or direct-observation mode.
/// Restore terminal settings when the session ends or an error unwinds the terminal guard.
pub async fn run_tui(socket_path: PathBuf, direct: bool) -> Result<()> {
    run_tui_with_client(ApiClient::new(socket_path), direct).await
}

pub async fn run_tui_with_client(client: ApiClient, direct: bool) -> Result<()> {
    if direct && client.socket_path().is_none() {
        anyhow::bail!("direct mode cannot use an HTTPS server");
    }
    if !direct {
        client
            .request(&Request::Ping)
            .await
            .context("traffic-masqd is unavailable")?;
        if client.auth_initialized().await? {
            match session::SessionStore::for_client(&client) {
                Ok(store) => {
                    if let Err(error) = store.restore(&client).await {
                        client.forget_authentication().await;
                        eprintln!(
                            "Saved session unavailable: {error}. Please enter your password."
                        );
                    }
                }
                Err(error) => eprintln!("Session storage unavailable: {error}"),
            }
        } else {
            if client.socket_path().is_none() {
                anyhow::bail!(
                    "Initialize the device password locally on the server before using HTTPS"
                );
            }
            if !nix::unistd::Uid::effective().is_root() {
                anyhow::bail!("Initial password setup requires root. Run sudo traffic-masqd auth set-password while the daemon is stopped, then restart it and run this TUI as your authorized user.");
            }
            println!(
                "First-time setup: run this TUI as root to initialize the shared device password."
            );
            let mut password = rpassword::prompt_password("New device password: ")?;
            let mut repeated = rpassword::prompt_password("Repeat device password: ")?;
            if password != repeated {
                password.zeroize();
                repeated.zeroize();
                anyhow::bail!("passwords do not match");
            }
            let initialize_result = client.initialize(&password).await;
            password.zeroize();
            repeated.zeroize();
            initialize_result?;
        }
        if client.is_authenticated().await {
            if let Err(error) = session::remember(&client).await {
                eprintln!("Could not save session: {error}");
            }
        }
    }

    if !direct {
        println!("Connecting to {}", client.endpoint_label());
    }
    enable_raw_mode()?;
    let terminal_guard = TerminalGuard;
    let mut stdout = io::stdout();
    execute!(
        stdout,
        EnterAlternateScreen,
        EnableMouseCapture,
        crossterm::cursor::Hide
    )?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_loop(&mut terminal, &client, direct).await;

    drop(terminal_guard);

    if !direct {
        let remembered = match session::remember(&client).await {
            Ok(remembered) => remembered,
            Err(error) => {
                eprintln!("Could not save session: {error}");
                false
            }
        };
        if !remembered {
            if let Err(error) = client.logout().await {
                tracing::warn!(%error, "failed to revoke TUI session during logout");
            }
        }
    }
    result
}

/// Process input and refresh UI state until the user exits or an unrecoverable error occurs.
async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    client: &ApiClient,
    direct: bool,
) -> Result<()> {
    let direct_network = if direct {
        RtnetlinkNetworkProvider::connect().ok()
    } else {
        None
    };
    let mut app = TuiApp {
        connected_endpoint: client
            .remote_session_identity()
            .map(|_| client.endpoint_label()),
        ..Default::default()
    };
    if !direct {
        if let Ok(store) = session::SessionStore::for_client(client) {
            if let Ok(preferences) = store.preferences() {
                app.show_dhcp_client = preferences.show_dhcp_client;
            }
        }
    }
    let mut has_authenticated = client.is_authenticated().await;
    let mut last_refresh: Option<Instant> = None;
    let mut queued_input: Option<Event> = None;

    let log_store = match if direct {
        session::SessionStore::direct()
    } else {
        session::SessionStore::for_client(client)
    } {
        Ok(store) => {
            logs::restore(&mut app, &store).await;
            Some(store)
        }
        Err(error) => {
            app.push_message(
                LogLevel::Warn,
                format!("Client log storage unavailable: {error}"),
            );
            None
        }
    };

    let result = async {
        while !app.should_quit {
            if let Some(store) = &log_store {
                logs::flush(&mut app, store).await;
            }
            if !direct && !client.is_authenticated().await {
                if !reauthenticate(terminal, client, pending_deadline(&app), !has_authenticated)
                    .await?
                {
                    break;
                }
                app.last_drawn_view = None;
                has_authenticated = true;
                last_refresh = None;
                match session::remember(client).await {
                    Ok(_) => app.push_message(
                        LogLevel::Info,
                        "Authenticated. Inspect pending state before retrying any operation.",
                    ),
                    Err(error) => app.push_message(
                        LogLevel::Warn,
                        format!("Authenticated, but could not save session: {error}"),
                    ),
                }
            }

            let refresh_interval = if pending_deadline(&app).is_some() {
                Duration::from_millis(500)
            } else {
                Duration::from_secs(1)
            };

            let should_refresh = last_refresh.is_none_or(|t| t.elapsed() >= refresh_interval);

            if should_refresh {
                let snapshot = draw_app(terminal, &mut app, direct)?.buffer.clone();
                let deadline = pending_deadline(&app);
                let refresh = async {
                    let updated = if direct {
                        load_direct_dashboard(direct_network.as_ref()).await
                    } else {
                        load_daemon_dashboard(client).await
                    };
                    dashboard::accept_update(&mut app, updated);
                    if !direct
                        && matches!(
                            app.screen,
                            Screen::DhcpInterfaceList | Screen::DhcpEditor | Screen::DhcpLeases
                        )
                    {
                        if let Ok(Response::DhcpStatus {
                            running_interfaces, ..
                        }) = client.request(&Request::DhcpStatus).await
                        {
                            app.dhcp_ui.dhcp_interfaces = running_interfaces;
                        }
                    }
                    normalize_selection(&mut app);
                    refresh_pending_screen(&mut app);
                    dashboard::record_traffic_samples(&mut app);

                    if !direct && matches!(app.screen, Screen::Router | Screen::RouterPlan) {
                        router::refresh_router_status(&mut app, client).await;
                    }
                    if !direct {
                        router::refresh_router_pending_screen(&mut app, client).await;
                    }
                    if !direct && app.screen == Screen::Settings {
                        settings::refresh_settings_status(&mut app, client).await;
                    }
                    if !direct && app.screen == Screen::Access {
                        access::refresh_access_status(&mut app, client).await;
                    }
                    if !direct && app.screen == Screen::WifiStations {
                        wifi_stations::refresh(&mut app, client).await;
                    }
                    if !direct && app.screen == Screen::DaemonLogs {
                        daemon_logs::tick(&mut app, client).await;
                    }
                    if !direct && app.screen == Screen::Wifi {
                        wifi::load_wifi_data(&mut app, client).await;
                    }
                    if !direct && app.screen == Screen::VpnPolicy {
                        vpn_policy::refresh_vpn_policy_status(&mut app, client).await;
                    }
                    if !direct && app.screen == Screen::DhcpLeases {
                        dhcp::refresh_dhcp_leases(&mut app, client).await;
                    }
                    if !direct && app.screen == Screen::DhcpClient {
                        dhcp_client::refresh(&mut app, client).await;
                    }
                    if !direct
                        && matches!(
                            app.screen,
                            Screen::Vpn | Screen::VpnProfile | Screen::VpnSettings
                        )
                    {
                        vpn::load_vpn_data(&mut app, client).await;
                    }
                };
                let interrupted = drive_ui(terminal, snapshot, deadline, refresh, true).await?;
                if interrupted.is_some() {
                    queued_input = interrupted;
                } else {
                    last_refresh = Some(Instant::now());
                    draw_app(terminal, &mut app, direct)?;
                }
            }

            let poll_timeout = refresh_interval
                .saturating_sub(last_refresh.map_or(Duration::ZERO, |t| t.elapsed()))
                .min(Duration::from_millis(100));

            let input = if queued_input.is_some() {
                queued_input.take()
            } else if event::poll(poll_timeout)? {
                let ev = event::read()?;
                match ev {
                    Event::Mouse(m) if matches!(m.kind, MouseEventKind::Moved) => None,
                    Event::Key(k) if k.kind != event::KeyEventKind::Press => None,
                    _ => Some(ev),
                }
            } else {
                None
            };
            if let Some(input) = input {
                let snapshot = draw_app(terminal, &mut app, direct)?.buffer.clone();
                let deadline = pending_deadline(&app);
                let action = async {
                    match input {
                        Event::Key(key) if key.kind == event::KeyEventKind::Press => {
                            handle_key_event(&mut app, key, client, direct).await;
                        }
                        Event::Mouse(mouse) => {
                            handle_mouse(&mut app, mouse, client, direct).await;
                        }
                        _ => {}
                    }
                };
                if drive_ui(terminal, snapshot, deadline, action, false)
                    .await?
                    .is_some()
                {
                    app.should_quit = true;
                }
                draw_app(terminal, &mut app, direct)?;
            }

            if terminal::size().is_err() {
                break;
            }
        }

        Ok(())
    }
    .await;
    // Flush on normal exit and on terminal/authentication errors alike.
    if let Some(store) = &log_store {
        logs::flush(&mut app, store).await;
    }
    result
}

// Reads may be cancelled to prioritize input. Actions are never cancelled or
// retried: a lost response does not imply that a mutation was not applied.
fn pending_deadline(app: &TuiApp) -> Option<u64> {
    app.confirmation
        .pending
        .as_ref()
        .filter(|p| p.can_commit())
        .map(|p| p.expires_at_unix)
        .or_else(|| {
            app.router_ui
                .router_pending
                .as_ref()
                .filter(|pending| !pending.recovery_required())
                .map(|pending| {
                    pending
                        .applied_at_unix
                        .saturating_add(app.router_ui.router_rollback_timeout_seconds)
                })
        })
}

async fn drive_ui(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    snapshot: ratatui::buffer::Buffer,
    deadline: Option<u64>,
    operation: impl std::future::Future<Output = ()>,
    cancellable: bool,
) -> Result<Option<Event>> {
    tokio::pin!(operation);
    let started = std::time::Instant::now();
    let mut exit_requested = None;
    loop {
        tokio::select! {
            biased;
            _ = &mut operation => return Ok(exit_requested),
            _ = tokio::time::sleep(Duration::from_millis(50)) => {
                let elapsed = started.elapsed();
                let should_render = !cancellable
                    || elapsed >= Duration::from_millis(500)
                    || deadline.is_some();
                if should_render {
                    terminal.draw(|frame| {
                        render_operation_snapshot(
                            frame, &snapshot, deadline, elapsed, cancellable,
                        );
                    })?;
                }
                while event::poll(Duration::ZERO)? {
                    let input = event::read()?;
                    if matches!(input, Event::Key(k) if k.kind != event::KeyEventKind::Press) { continue; }
                    if matches!(input, Event::Mouse(m) if matches!(m.kind, MouseEventKind::Moved)) { continue; }
                    if cancellable { return Ok(Some(input)); }
                    if matches!(input, Event::Key(k) if is_operation_exit_key(k)) { exit_requested = Some(input); }
                }
            }
        }
    }
}

/// Reuse the current frame while an API request runs. If the terminal is
/// resized, discard the stale snapshot and redraw progress in the new geometry.
/// Routine refreshes should finish without flashing a progress indicator.
fn render_operation_snapshot(
    frame: &mut ratatui::Frame<'_>,
    snapshot: &ratatui::buffer::Buffer,
    deadline: Option<u64>,
    elapsed: Duration,
    cancellable: bool,
) {
    let area = frame.area();
    if area == snapshot.area {
        *frame.buffer_mut() = snapshot.clone();
    } else {
        frame.render_widget(ratatui::widgets::Clear, area);
    }
    if cancellable && elapsed < Duration::from_millis(500) {
        return;
    }
    if area.width < MIN_TERMINAL_WIDTH || area.height < MIN_TERMINAL_HEIGHT {
        let message = if cancellable {
            "Refreshing… resize to at least 80x24"
        } else {
            "Applying changes… resize to at least 80x24. Q: exit after result"
        };
        frame.render_widget(
            Paragraph::new(message)
                .alignment(Alignment::Center)
                .style(Style::default().fg(theme::WARN)),
            area,
        );
        return;
    }
    let remaining = deadline
        .map(|d| {
            format!(
                "; rollback deadline in {}s (outcome unverified)",
                d.saturating_sub(current_unix_time())
            )
        })
        .unwrap_or_default();
    let message = format!(
        "{} {}s{remaining}. {}",
        if cancellable {
            "Refreshing"
        } else {
            "Applying changes"
        },
        elapsed.as_secs(),
        if cancellable {
            "Displayed data may be stale; input interrupts refresh"
        } else {
            "Q: exit after result; other actions disabled"
        },
    );
    // The first inner footer row contains key hints. The second contains the
    // notification; progress must never overwrite it or the bottom border.
    let banner =
        ratatui::layout::Rect::new(area.x + 1, area.y + area.height - 3, area.width - 2, 1);
    frame.render_widget(ratatui::widgets::Clear, banner);
    frame.render_widget(
        Paragraph::new(message).style(Style::default().fg(theme::MUTED)),
        banner,
    );
}

/// Run the authentication flow after session loss and restore access to protected screens.
async fn reauthenticate(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    client: &ApiClient,
    deadline: Option<u64>,
    initial: bool,
) -> Result<bool> {
    terminal.clear()?;
    let mut password = zeroize::Zeroizing::new(String::new());
    let mut cursor = 0;
    let mut message = if initial {
        "Enter device password; Enter: sign in; Esc: exit."
    } else {
        "Session expired or revoked. Enter device password; Esc: exit. Drafts are preserved; rollback deadlines continue."
    }.to_string();
    loop {
        let snapshot = terminal
            .draw(|frame| {
                let mut spans = vec![Span::styled(
                    format!(
                        "Server: {}\n{message}\n\nDevice password: ",
                        client.endpoint_label()
                    ),
                    Style::default(),
                )];
                spans.extend(input::render_masked_with_cursor(
                    input::grapheme_count(password.as_str()),
                    cursor,
                    true,
                    '*',
                    Style::default(),
                ));
                frame.render_widget(
                    Paragraph::new(Line::from(spans))
                        .wrap(ratatui::widgets::Wrap { trim: true })
                        .block(layout::panel("traffic-masq · Sign in")),
                    frame.area(),
                );
            })?
            .buffer
            .clone();
        if event::poll(Duration::ZERO)? {
            if let Event::Key(key) = event::read()? {
                if key.kind != event::KeyEventKind::Press {
                    continue;
                }
                if is_quit_key(key) {
                    return Ok(false);
                }
                if key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SUPER)
                {
                    continue;
                }
                match key.code {
                    KeyCode::Esc => return Ok(false),
                    KeyCode::Enter => {
                        let mut result = None;
                        let exit = drive_ui(
                            terminal,
                            snapshot,
                            deadline,
                            async {
                                result = Some(client.login(&password).await);
                            },
                            false,
                        )
                        .await?;
                        password.zeroize();
                        cursor = 0;
                        if exit.is_some() {
                            return Ok(false);
                        }
                        match result.context("authentication operation did not finish")? {
                            Ok(_) => return Ok(true),
                            Err(error) => message = format!("{error}. Try again; Esc: exit."),
                        }
                    }
                    other => {
                        input::TextEditor::new(&mut password, &mut cursor).handle_key(other);
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Switch sections and load the data required by the destination screen.
async fn navigate_to_section(app: &mut TuiApp, section: Section, client: &ApiClient, direct: bool) {
    if confirmation::current(app).is_some()
        || !matches!(
            app.screen,
            Screen::Dashboard
                | Screen::InterfaceList
                | Screen::DhcpInterfaceList
                | Screen::DhcpClient
                | Screen::Wifi
                | Screen::Router
                | Screen::Vpn
                | Screen::Settings
                | Screen::Log
        )
    {
        app.push_message(
            LogLevel::Warn,
            "Finish this operation or use Esc before changing tabs.",
        );
        return;
    }
    match section {
        Section::Dashboard => app.screen = Screen::Dashboard,
        Section::Interfaces => app.screen = Screen::InterfaceList,
        Section::Dhcp => {
            if direct {
                app.push_message(
                    LogLevel::Warn,
                    "DHCP management requires the daemon API; unavailable in direct/offline mode",
                );
            } else {
                app.screen = Screen::DhcpInterfaceList;
            }
        }
        Section::DhcpClient => {
            if !app.show_dhcp_client {
                app.push_message(LogLevel::Warn, "DHCP Client tab is disabled in Settings");
            } else if direct {
                app.push_message(
                    LogLevel::Warn,
                    "DHCP Client management requires the daemon API",
                );
            } else {
                app.dhcp_ui.dhcp_client_selected = interfaces::selected_interface_name(app);
                app.dhcp_ui.dhcp_client_scroll = 0;
                app.screen = Screen::DhcpClient;
                dhcp_client::refresh(app, client).await;
            }
        }
        Section::Wifi => {
            if direct {
                app.push_message(
                    LogLevel::Warn,
                    "Wi-Fi management requires the daemon API; unavailable in direct/offline mode",
                );
            } else {
                app.screen = Screen::Wifi;
                app.wifi.actions_open = false;
                app.wifi.selected = app.wifi.selected_radio;
                wifi::load_wifi_data(app, client).await;
            }
        }
        Section::Router => {
            if direct {
                app.push_message(
                    LogLevel::Warn,
                    "Router management requires the daemon API; unavailable in direct/offline mode",
                );
            } else {
                app.router.focus = RouterFocus::RouteTable;
                app.router.sharing_actions_focused = false;
                router::load_router_data(app, client).await;
                app.screen = Screen::Router;
            }
        }
        Section::Vpn => {
            if direct {
                app.push_message(
                    LogLevel::Warn,
                    "VPN management requires the daemon API; unavailable in direct/offline mode",
                );
            } else {
                vpn::load_vpn_data(app, client).await;
                vpn::enter_list(app);
            }
        }
        Section::Settings => {
            if direct {
                app.push_message(
                    LogLevel::Warn,
                    "Settings require the daemon API; unavailable in direct/offline mode",
                );
            } else {
                settings::load_settings_data(app, client).await;
                app.screen = Screen::Settings;
            }
        }
        Section::Log => app.screen = Screen::Log,
    }
}

async fn handle_mouse(app: &mut TuiApp, mouse: MouseEvent, client: &ApiClient, direct: bool) {
    if !app.ui.input_enabled || app.help_open {
        return;
    }
    if app.message_open {
        match mouse.kind {
            MouseEventKind::ScrollUp => {
                app.message_scroll = app.message_scroll.saturating_sub(1);
            }
            MouseEventKind::ScrollDown => {
                app.message_scroll = app.message_scroll.saturating_add(1);
            }
            _ => {}
        }
        return;
    }
    let point = (mouse.column, mouse.row);
    if confirmation::current(app).is_some() {
        match mouse.kind {
            MouseEventKind::ScrollUp => {
                app.confirmation.confirmation_scroll =
                    app.confirmation.confirmation_scroll.saturating_sub(1);
                return;
            }
            MouseEventKind::ScrollDown => {
                app.confirmation.confirmation_scroll = app
                    .confirmation
                    .confirmation_scroll
                    .saturating_add(1)
                    .min(app.ui.dialog_max_scroll);
                return;
            }
            _ => {}
        }
        if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left))
            && app
                .ui
                .content_area
                .is_some_and(|area| layout::point_in_rect(point, area))
        {
            if let Some(key) = app
                .ui
                .buttons
                .iter()
                .find(|(rect, _)| layout::point_in_rect(point, *rect))
                .and_then(|(_, slot)| confirmation::key_for_slot(*slot))
            {
                app.confirmation.confirmation_focus = if key == KeyCode::Delete {
                    2
                } else if key == KeyCode::Esc {
                    1
                } else {
                    0
                };
                handle_key(app, key, client, direct).await;
            }
        }
        return;
    }
    if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
        if let Some(section) = layout::section_at(&app.ui.tabs, point) {
            navigate_to_section(app, section, client, direct).await;
            return;
        }
    }
    if app
        .ui
        .content_area
        .is_some_and(|area| !layout::point_in_rect(point, area))
    {
        return;
    }

    if wifi::change_review_open(app) {
        match mouse.kind {
            MouseEventKind::ScrollUp => {
                app.interface_ui.preview_scroll = app.interface_ui.preview_scroll.saturating_sub(1);
                return;
            }
            MouseEventKind::ScrollDown => {
                app.interface_ui.preview_scroll = app
                    .interface_ui
                    .preview_scroll
                    .saturating_add(1)
                    .min(app.interface_ui.preview_max_scroll);
                return;
            }
            _ => {}
        }
    }

    // Wheel input belongs to the list/viewport, even when a button had focus.
    // In particular, scrolling must not select a destructive action for Enter.
    if matches!(
        mouse.kind,
        MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
    ) {
        match app.screen {
            Screen::Vpn => app.vpn.focus = vpn::VpnFocus::List,
            Screen::Router if !app.router.topology.open => {
                app.router.focus = RouterFocus::RouteTable;
                app.router.sharing_actions_focused = false;
            }
            Screen::Log => {
                app.log_view.logs_focus = logs::LogFocus::Scroll;
                app.log_view.logs_scroll = if mouse.kind == MouseEventKind::ScrollUp {
                    app.log_view.logs_scroll.saturating_sub(1)
                } else {
                    app.log_view
                        .logs_scroll
                        .saturating_add(1)
                        .min(app.log_view.logs_max_scroll)
                };
                return;
            }
            _ => {}
        }
    }

    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            if app.screen == Screen::Dashboard {
                if let Some((_, pane)) = app
                    .dashboard
                    .pane_tabs
                    .iter()
                    .find(|(rect, _)| layout::point_in_rect(point, *rect))
                    .copied()
                {
                    app.dashboard_ui.dashboard_pane = pane;
                    if pane == dashboard::DashboardPane::Statistics {
                        app.dashboard_ui.dashboard_statistics_index =
                            app.interface_ui.selected_interface + 1;
                        app.dashboard.statistics_scroll = 0;
                    }
                    return;
                }
            }
            if app.screen == Screen::Router {
                if let Some((_, pane)) = app
                    .router
                    .pane_tabs
                    .iter()
                    .find(|(rect, _)| layout::point_in_rect(point, *rect))
                    .copied()
                {
                    router::select_pane(app, pane);
                    return;
                }
            }
            if let Some(&(_, slot)) = app
                .ui
                .buttons
                .iter()
                .find(|(rect, _)| layout::point_in_rect(point, *rect))
            {
                focus_action_slot(app, slot);
                let key = if matches!(
                    app.screen,
                    Screen::Preview
                        | Screen::PendingChange
                        | Screen::RouterPlan
                        | Screen::RouterPending
                ) && slot == 1
                {
                    KeyCode::Esc
                } else {
                    KeyCode::Enter
                };
                handle_key(app, key, client, direct).await;
                return;
            }
            if let Some(area) = app.ui.list_area {
                if layout::point_in_rect(point, area) {
                    let row_height = app.ui.list_row_height.max(1);
                    let index = app.ui.list_scroll_offset
                        + (mouse.row.saturating_sub(area.y) / row_height) as usize;
                    if index < app.ui.list_count {
                        match app.screen {
                            Screen::Dashboard => {
                                app.interface_ui.selected_interface = index;
                                app.dashboard_ui.dashboard_pane = dashboard::DashboardPane::Traffic;
                            }
                            Screen::InterfaceList | Screen::DhcpInterfaceList => {
                                interfaces::set_interface_selection(app, index);
                            }
                            Screen::WifiStations => wifi_stations::select_row(app, index),
                            Screen::DhcpClient => {
                                dhcp_client::select_row(app, index);
                            }
                            Screen::Vpn => {
                                app.vpn.selected_profile = index;
                                app.vpn.focus = vpn::VpnFocus::List;
                            }
                            Screen::Wifi => {
                                wifi::open_radio(app, index);
                            }
                            Screen::Router => {
                                if app.router.pane == router::RouterPane::Ports {
                                    app.router.selected_port_forward = index;
                                    app.router.sharing_actions_focused = false;
                                } else if app.router.pane == router::RouterPane::Sharing {
                                    app.router.selected_connection = index;
                                    app.router.sharing_actions_focused = false;
                                } else {
                                    app.router.selected_route = index;
                                    app.router.focus = RouterFocus::RouteTable;
                                }
                            }
                            Screen::WifiScan => {
                                if let Some(scan) = app.wifi_ui.wifi_scan.as_mut() {
                                    scan.selected = index;
                                }
                            }
                            Screen::WifiApProfiles => {
                                if let Some(view) = app.wifi_ui.wifi_ap_profiles.as_mut() {
                                    view.select(index);
                                }
                            }
                            Screen::WifiProfiles => {
                                if let Some(view) = app.wifi_ui.wifi_profiles.as_mut() {
                                    match view.mode {
                                        wifi::WifiProfilesMode::Menu => {
                                            if index < wifi::WifiProfilesMenuAction::ALL.len() {
                                                view.selected = index;
                                            }
                                        }
                                        wifi::WifiProfilesMode::Management
                                        | wifi::WifiProfilesMode::Connect => {
                                            if index < view.profiles.len() {
                                                view.selected = index;
                                                view.selected_profile = index;
                                            }
                                        }
                                        wifi::WifiProfilesMode::ProfileActions => {
                                            if index
                                                < wifi::WifiProfileAction::for_interface(
                                                    &view.interface,
                                                )
                                                .len()
                                            {
                                                view.selected = index;
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        MouseEventKind::ScrollUp => match app.screen {
            Screen::Preview => interfaces::handle_preview_key(app, KeyCode::Up, client).await,
            Screen::Wifi => wifi::handle_wifi_key(app, KeyCode::Up, client).await,
            Screen::WifiScan => wifi::handle_wifi_scan_key(app, KeyCode::Up, client).await,
            Screen::WifiProfiles => wifi::handle_wifi_profiles_key(app, KeyCode::Up, client).await,
            Screen::WifiApProfiles => {
                wifi::handle_wifi_ap_profiles_key(app, KeyCode::Up, client).await
            }
            Screen::Dashboard => {
                dashboard::handle_dashboard_key(app, KeyCode::Up, client, direct).await;
            }
            Screen::InterfaceList | Screen::DhcpInterfaceList => {
                interfaces::set_interface_selection(
                    app,
                    interfaces::interface_selection(app).saturating_sub(1),
                );
            }
            Screen::WifiStations => wifi_stations::handle_key(app, KeyCode::Up, client).await,
            Screen::RouterHealth => router_health::handle_key(app, KeyCode::Up, client).await,
            Screen::DaemonLogs => daemon_logs::handle_key(app, KeyCode::Up, client).await,
            Screen::DhcpClient => dhcp_client::move_selection(app, false),
            Screen::Router => router::handle_router_key(app, KeyCode::Up, client).await,
            Screen::RouterPlan => {
                router::handle_router_plan_key(app, KeyCode::Up, client).await;
            }
            Screen::RouterPending => {
                router::handle_router_pending_key(app, KeyCode::Up, client).await;
            }
            Screen::Vpn => {
                app.vpn.focus = vpn::VpnFocus::List;
                app.vpn.selected_profile = app.vpn.selected_profile.saturating_sub(1);
            }
            Screen::DhcpLeases => {
                dhcp::handle_dhcp_leases_key(app, KeyCode::Up, client).await;
            }
            _ => {}
        },
        MouseEventKind::ScrollDown => match app.screen {
            Screen::Preview => interfaces::handle_preview_key(app, KeyCode::Down, client).await,
            Screen::Wifi => wifi::handle_wifi_key(app, KeyCode::Down, client).await,
            Screen::WifiScan => wifi::handle_wifi_scan_key(app, KeyCode::Down, client).await,
            Screen::WifiApProfiles => {
                wifi::handle_wifi_ap_profiles_key(app, KeyCode::Down, client).await
            }
            Screen::WifiProfiles => {
                wifi::handle_wifi_profiles_key(app, KeyCode::Down, client).await
            }
            Screen::Dashboard => {
                dashboard::handle_dashboard_key(app, KeyCode::Down, client, direct).await;
            }
            Screen::InterfaceList | Screen::DhcpInterfaceList
                if interfaces::interface_selection(app) + 1 < interfaces::interface_count(app) =>
            {
                interfaces::set_interface_selection(app, interfaces::interface_selection(app) + 1);
            }
            Screen::WifiStations => wifi_stations::handle_key(app, KeyCode::Down, client).await,
            Screen::RouterHealth => router_health::handle_key(app, KeyCode::Down, client).await,
            Screen::DaemonLogs => daemon_logs::handle_key(app, KeyCode::Down, client).await,
            Screen::DhcpClient => dhcp_client::move_selection(app, true),
            Screen::Router => router::handle_router_key(app, KeyCode::Down, client).await,
            Screen::RouterPlan => {
                router::handle_router_plan_key(app, KeyCode::Down, client).await;
            }
            Screen::RouterPending => {
                router::handle_router_pending_key(app, KeyCode::Down, client).await;
            }
            Screen::Vpn if app.vpn.selected_profile + 1 < app.vpn.profiles.len() => {
                app.vpn.focus = vpn::VpnFocus::List;
                app.vpn.selected_profile += 1;
            }
            Screen::DhcpLeases => {
                dhcp::handle_dhcp_leases_key(app, KeyCode::Down, client).await;
            }
            _ => {}
        },
        _ => {}
    }
}

const MIN_TERMINAL_WIDTH: u16 = 80;
const MIN_TERMINAL_HEIGHT: u16 = 24;

pub(crate) fn format_message_lines(text: &str) -> Vec<Line<'_>> {
    const SHIFT_HINT: &str = "to copy, hold down shift";
    text.lines()
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            if let Some(idx) = lower.find(SHIFT_HINT) {
                let before = &line[..idx];
                let matched = &line[idx..idx + SHIFT_HINT.len()];
                let after = &line[idx + SHIFT_HINT.len()..];
                let mut spans = Vec::new();
                if !before.is_empty() {
                    spans.push(Span::raw(before));
                }
                spans.push(Span::styled(matched, Style::default().fg(theme::BAD)));
                if !after.is_empty() {
                    spans.push(Span::raw(after));
                }
                Line::from(spans)
            } else {
                Line::from(vec![Span::raw(line)])
            }
        })
        .collect()
}

/// Invalidate both the physical screen and ratatui's diff buffer once per view
/// transition. Ordinary updates retain incremental rendering.
fn draw_app<'a, B: ratatui::backend::Backend>(
    terminal: &'a mut Terminal<B>,
    app: &mut TuiApp,
    direct: bool,
) -> Result<ratatui::CompletedFrame<'a>, B::Error> {
    let view = ViewIdentity {
        screen: app.screen,
        help_open: app.help_open,
        message_open: app.message_open,
        router_pane: app.router.pane,
        topology_open: app.router.topology.open,
        wifi_actions_open: app.wifi.actions_open,
        wifi_profiles_mode: app.wifi_ui.wifi_profiles.as_ref().map(|view| view.mode),
        wifi_ap_profiles_mode: app.wifi_ui.wifi_ap_profiles.as_ref().map(|view| view.mode),
    };
    if app.last_drawn_view != Some(view) {
        terminal.clear()?;
    }
    let frame = terminal.draw(|frame| render(frame, app, direct))?;
    app.last_drawn_view = Some(view);
    Ok(frame)
}

fn is_quit_key(key: KeyEvent) -> bool {
    key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL)
}

fn is_operation_exit_key(key: KeyEvent) -> bool {
    is_quit_key(key)
        || (matches!(key.code, KeyCode::Char('q') | KeyCode::Char('Q'))
            && !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SUPER))
}

async fn handle_key_event(app: &mut TuiApp, key: KeyEvent, client: &ApiClient, direct: bool) {
    if is_quit_key(key) {
        app.should_quit = true;
        return;
    }
    if key.modifiers == KeyModifiers::CONTROL && app.ui.input_enabled {
        match key.code {
            KeyCode::Char('k') => app.help_open = !app.help_open,
            _ if app.help_open => {}
            KeyCode::Char('g') => {
                app.message_open = !app.message_open;
                app.message_scroll = 0;
            }
            _ if app.message_open => {}
            KeyCode::Char('p' | 'n') => {
                let target = adjacent_section(
                    section_of_app(app),
                    key.code == KeyCode::Char('n'),
                    app.show_dhcp_client,
                    direct,
                );
                navigate_to_section(app, target, client, direct).await;
            }
            KeyCode::Char('o') if app.screen == Screen::WifiConnectPrompt => {
                if let Some(prompt) = app.wifi_ui.wifi_connect.as_mut() {
                    prompt.field = wifi::WifiConnectField::Submit;
                }
                handle_key(app, KeyCode::Enter, client, direct).await;
            }
            _ => {}
        }
        return;
    }
    // Modified letters must never be inserted into a text field as plain text.
    if key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SUPER)
    {
        return;
    }
    let code = if key.code == KeyCode::Tab && key.modifiers.contains(KeyModifiers::SHIFT) {
        KeyCode::BackTab
    } else {
        key.code
    };
    handle_key(app, code, client, direct).await;
}

fn render(frame: &mut ratatui::Frame<'_>, app: &mut TuiApp, direct: bool) {
    let area = frame.area();
    frame.render_widget(ratatui::widgets::Clear, area);
    app.ui = UiLayout::default();
    if area.width < MIN_TERMINAL_WIDTH || area.height < MIN_TERMINAL_HEIGHT {
        let recovery_hint = app.confirmation.pending.as_ref().filter(|change| !change.can_commit()).map(|change| {
            if change.can_rollback() { "Rollback recovery required. Esc: retry rollback. Q: exit." }
            else { "Commit outcome unknown. Repair storage and restart the daemon. Esc: back. Q: exit." }
        }).or_else(|| app.router_ui.router_pending.as_ref().filter(|view| view.recovery_required()).map(|view| {
            if view.commit_indeterminate() { "Commit outcome unknown. Repair storage and restart the daemon. Esc: back. Q: exit." }
            else { "Rollback recovery required. Enter: retry rollback. Esc: back. Q: exit." }
        }));
        if let Some(hint) = recovery_hint {
            frame.render_widget(
                Paragraph::new(hint).wrap(ratatui::widgets::Wrap { trim: false }),
                area,
            );
            return;
        }
        if let Some(deadline) = pending_deadline(app) {
            frame.render_widget(
                Paragraph::new(format!(
                    "Rollback in {}s\nEnter: commit\nEsc: rollback\nQ: exit (timer continues)",
                    deadline.saturating_sub(current_unix_time())
                ))
                .wrap(ratatui::widgets::Wrap { trim: false })
                .style(Style::default().fg(theme::WARN)),
                area,
            );
            return;
        }
        frame.render_widget(
            Paragraph::new("Terminal too small — resize to at least 80x24. Q: exit. Pending changes keep their original rollback deadlines.")
                .alignment(Alignment::Center)
                .style(Style::default().fg(theme::WARN)),
            area,
        );
        return;
    }
    app.ui.input_enabled = true;
    if app.help_open {
        let mut lines = vec![
            Line::from("Ctrl+P/Ctrl+N: previous/next section | Ctrl+C: quit"),
            Line::from("Tab/Shift+Tab: focus | Ctrl+G: full operation message"),
            Line::from(""),
        ];
        lines.extend(
            layout::help_pairs(app)
                .into_iter()
                .map(|(key, action)| Line::from(format!("{key}: {action}"))),
        );
        lines.extend([
            Line::from(""),
            Line::from("First setup: Interfaces (LAN IP + Output role), then DHCP Server,"),
            Line::from("then Route > Internet sharing (LAN through WAN)."),
            Line::from("Verify connectivity before committing each tentative change."),
        ]);
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(ratatui::widgets::Wrap { trim: false })
                .block(layout::panel("Help — Esc/Ctrl+K: close")),
            area,
        );
        return;
    }
    if app.message_open {
        let text = if app.screen == Screen::Dashboard {
            app.dashboard.error.as_deref().or(app.message.as_deref())
        } else {
            app.message.as_deref().or(app.dashboard.error.as_deref())
        }
        .unwrap_or("No message");
        frame.render_widget(
            Paragraph::new(format_message_lines(text))
                .wrap(ratatui::widgets::Wrap { trim: false })
                .scroll((app.message_scroll, 0))
                .block(layout::panel(
                    "Message — Up/Down: scroll; Esc/Ctrl+G: close",
                )),
            area,
        );
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(4),
        ])
        .split(area);

    app.ui.buttons.clear();

    layout::render_header(frame, chunks[0], app, direct);

    match app.screen {
        Screen::Dashboard => dashboard::render_dashboard(frame, chunks[1], app, direct),
        Screen::DnsDefaults => dns_defaults::render(frame, chunks[1], app),
        Screen::Access => access::render_access(frame, chunks[1], app),
        Screen::InterfaceList => interfaces::render_interface_list(frame, chunks[1], app),
        Screen::InterfaceEditor => interfaces::render_editor(frame, chunks[1], app),
        Screen::DhcpInterfaceList => dhcp::render_dhcp_interface_list(frame, chunks[1], app),
        Screen::DhcpEditor => dhcp::render_dhcp_editor(frame, chunks[1], app),
        Screen::DhcpLeases => dhcp::render_dhcp_leases(frame, chunks[1], app),
        Screen::DhcpClient => dhcp_client::render(frame, chunks[1], app),
        Screen::DhcpClientEditor => dhcp_client_editor::render(frame, chunks[1], app),
        Screen::WifiStations => wifi_stations::render(frame, chunks[1], app),
        Screen::Preview => interfaces::render_preview(frame, chunks[1], app),
        Screen::PendingChange => interfaces::render_pending(frame, chunks[1], app),
        Screen::Router => router::render_router(frame, chunks[1], app),
        Screen::RouterHealth => router_health::render(frame, chunks[1], app),
        Screen::RouterSettings => router_settings::render(frame, chunks[1], app),
        Screen::RouteEditor => router::render_route_editor(frame, chunks[1], app),
        Screen::RouterPlan => router::render_router_plan(frame, chunks[1], app),
        Screen::RouterPending => router::render_router_pending(frame, chunks[1], app),
        Screen::Forwarding => forwarding::render(frame, chunks[1], app),
        Screen::PortForwarding => port_forwarding::render(frame, chunks[1], app),
        Screen::Vpn | Screen::VpnProfile | Screen::VpnSettings => {
            vpn::render_vpn(frame, chunks[1], app)
        }
        Screen::VpnImport => vpn::render_vpn_import(frame, chunks[1], app),
        Screen::VpnPolicy => vpn_policy::render_vpn_policy(frame, chunks[1], app),
        Screen::Wifi => wifi::render_wifi(frame, chunks[1], app),
        Screen::WifiEditor => wifi::render_wifi_editor(frame, chunks[1], app),
        Screen::WifiScan => wifi::render_wifi_scan(frame, chunks[1], app),
        Screen::WifiProfiles => wifi::render_wifi_profiles(frame, chunks[1], app),
        Screen::WifiApProfiles => wifi::render_wifi_ap_profiles(frame, chunks[1], app),
        Screen::WifiProfileEditor => wifi::render_wifi_profile_editor(frame, chunks[1], app),
        Screen::WifiConnectPrompt => wifi::render_wifi_connect_prompt(frame, chunks[1], app),
        Screen::Settings => settings::render_settings(frame, chunks[1], app),
        Screen::SettingsPassword => settings::render_settings_password(frame, chunks[1], app),
        Screen::Log => logs::render_log(frame, chunks[1], app),
        Screen::DaemonLogs => daemon_logs::render(frame, chunks[1], app),
    }

    // Mouse geometry is a derived view of what is actually visible. Never let
    // a renderer leave an off-screen control active in the shell chrome.
    app.ui.clip_interactions(chunks[1]);
    layout::render_footer(frame, chunks[2], app);
}

fn focus_action_slot(app: &mut TuiApp, slot: usize) {
    match app.screen {
        Screen::Dashboard => {}
        Screen::PendingChange | Screen::RouterPending => {
            app.confirmation.pending_focus = slot.min(1)
        }
        Screen::DnsDefaults => dns_defaults::focus_action(app, slot),
        Screen::Access => access::focus_action(app, slot),
        Screen::InterfaceEditor => interfaces::focus_action(app, slot),
        Screen::DhcpEditor => dhcp::focus_action(app, slot),
        Screen::DhcpClientEditor => dhcp_client_editor::focus_action(app, slot),
        Screen::WifiStations => wifi_stations::focus_action(app, slot),
        Screen::Router => router::focus_action(app, slot),
        Screen::RouterSettings => router_settings::focus_action(app, slot),
        Screen::Forwarding => forwarding::focus_action(app, slot),
        Screen::PortForwarding => port_forwarding::focus_action(app, slot),
        Screen::RouteEditor => router::focus_route_editor_action(app, slot),
        Screen::Vpn | Screen::VpnProfile | Screen::VpnSettings => vpn::focus_action(app, slot),
        Screen::VpnPolicy => vpn_policy::focus_action(app, slot),
        Screen::VpnImport => vpn::focus_import_submit(app),
        Screen::SettingsPassword => settings::focus_password_submit(app),
        Screen::WifiEditor => wifi::focus_editor_action(app, slot),
        Screen::WifiApProfiles => {
            if let Some(view) = app.wifi_ui.wifi_ap_profiles.as_mut() {
                if view.apply_review {
                    view.review_cancel = slot == 1;
                }
            }
        }
        Screen::Wifi => wifi::focus_action(app, slot),
        Screen::WifiConnectPrompt => {
            if let Some(prompt) = app.wifi_ui.wifi_connect.as_mut() {
                prompt.field = if slot == 0 {
                    wifi::WifiConnectField::Submit
                } else {
                    wifi::WifiConnectField::Cancel
                };
            }
        }
        Screen::Settings => settings::focus_action(app, slot),
        Screen::Log => logs::focus_action(app, slot),
        _ => {}
    }
}

async fn handle_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient, direct: bool) {
    if !app.ui.input_enabled {
        if (app.confirmation.pending.is_some() || app.router_ui.router_pending.is_some())
            && matches!(key, KeyCode::Enter | KeyCode::Esc)
        {
            app.confirmation.pending_focus = 0;
            match app.screen {
                Screen::PendingChange => interfaces::handle_pending_key(app, key, client).await,
                Screen::RouterPending => router::handle_router_pending_key(app, key, client).await,
                _ => {}
            }
            return;
        }
        if matches!(key, KeyCode::Char('q') | KeyCode::Char('Q')) {
            app.should_quit = true;
        }
        return;
    }
    if app.help_open {
        if key == KeyCode::Esc {
            app.help_open = false;
        }
        return;
    }
    if app.message_open {
        match key {
            KeyCode::Esc => app.message_open = false,
            KeyCode::Up => app.message_scroll = app.message_scroll.saturating_sub(1),
            KeyCode::Down => app.message_scroll = app.message_scroll.saturating_add(1),
            _ => {}
        }
        return;
    }

    let key = if let Some(dialog) = confirmation::current(app) {
        let count = if dialog.secondary.is_some() { 3 } else { 2 };
        match key {
            KeyCode::PageUp => {
                app.confirmation.confirmation_scroll =
                    app.confirmation.confirmation_scroll.saturating_sub(5);
                return;
            }
            KeyCode::PageDown => {
                app.confirmation.confirmation_scroll = app
                    .confirmation
                    .confirmation_scroll
                    .saturating_add(5)
                    .min(app.ui.dialog_max_scroll);
                return;
            }
            KeyCode::Home => {
                app.confirmation.confirmation_scroll = 0;
                return;
            }
            KeyCode::End => {
                app.confirmation.confirmation_scroll = app.ui.dialog_max_scroll;
                return;
            }
            KeyCode::Tab | KeyCode::Down | KeyCode::Right => {
                app.confirmation.confirmation_focus =
                    (app.confirmation.confirmation_focus + 1) % count;
                return;
            }
            KeyCode::BackTab | KeyCode::Up | KeyCode::Left => {
                app.confirmation.confirmation_focus =
                    (app.confirmation.confirmation_focus + count - 1) % count;
                return;
            }
            KeyCode::Enter => confirmation::key_for_slot(app.confirmation.confirmation_focus)
                .unwrap_or(KeyCode::Esc),
            KeyCode::Esc => KeyCode::Esc,
            KeyCode::Delete if dialog.secondary.is_some() => KeyCode::Delete,
            _ => return,
        }
    } else {
        app.confirmation.confirmation_focus = 0;
        app.confirmation.confirmation_scroll = 0;
        key
    };

    // Forms and simple lists share forward/backward focus navigation. Screens
    // with separate panes handle Tab themselves so it skips the whole list.
    let key = match (app.screen, key) {
        (
            Screen::Dashboard
            | Screen::Vpn
            | Screen::VpnProfile
            | Screen::VpnSettings
            | Screen::Log
            | Screen::Router
            | Screen::Forwarding
            | Screen::PortForwarding
            | Screen::WifiStations
            | Screen::PendingChange
            | Screen::RouterPending
            | Screen::Wifi,
            _,
        ) => key,
        (_, KeyCode::Tab) => KeyCode::Down,
        (_, KeyCode::BackTab) => KeyCode::Up,
        _ => key,
    };

    if matches!(
        app.screen,
        Screen::Dashboard
            | Screen::InterfaceList
            | Screen::DhcpInterfaceList
            | Screen::DhcpClient
            | Screen::Router
            | Screen::Vpn
            | Screen::Wifi
            | Screen::Settings
            | Screen::Log
    ) {
        let horizontal_focus = match app.screen {
            Screen::Settings => app
                .settings_ui
                .settings
                .as_ref()
                .is_some_and(|s| s.is_editing()),
            Screen::Dashboard => false,
            Screen::Vpn => app.vpn.focus != vpn::VpnFocus::List,
            Screen::Log => app.log_view.logs_focus != logs::LogFocus::Scroll,
            Screen::Wifi => app.wifi.actions_open,
            Screen::Router => {
                app.router.focus == RouterFocus::Actions
                    || (matches!(
                        app.router.pane,
                        router::RouterPane::Sharing | router::RouterPane::Ports
                    ) && app.router.sharing_actions_focused)
                    || app.router.topology.open
            }
            _ => false,
        };
        if !horizontal_focus && matches!(key, KeyCode::Left | KeyCode::Right) {
            let target = adjacent_section(
                section_of_app(app),
                key == KeyCode::Right,
                app.show_dhcp_client,
                direct,
            );
            navigate_to_section(app, target, client, direct).await;
            return;
        }
    }

    match app.screen {
        Screen::Dashboard => dashboard::handle_dashboard_key(app, key, client, direct).await,
        Screen::DnsDefaults => dns_defaults::handle_key(app, key, client).await,
        Screen::Access => access::handle_access_key(app, key, client).await,
        Screen::InterfaceList => {
            interfaces::handle_interface_list_key(app, key, client, direct).await
        }
        Screen::InterfaceEditor => interfaces::handle_editor_key(app, key, client).await,
        Screen::DhcpInterfaceList => dhcp::handle_dhcp_interface_list_key(app, key, client).await,
        Screen::DhcpEditor => dhcp::handle_dhcp_editor_key(app, key, client).await,
        Screen::DhcpLeases => dhcp::handle_dhcp_leases_key(app, key, client).await,
        Screen::DhcpClient => dhcp_client::handle_key(app, key, client).await,
        Screen::DhcpClientEditor => dhcp_client_editor::handle_key(app, key, client).await,
        Screen::WifiStations => wifi_stations::handle_key(app, key, client).await,
        Screen::Preview => interfaces::handle_preview_key(app, key, client).await,
        Screen::PendingChange => interfaces::handle_pending_key(app, key, client).await,
        Screen::Router => router::handle_router_key(app, key, client).await,
        Screen::RouterHealth => router_health::handle_key(app, key, client).await,
        Screen::RouterSettings => router_settings::handle_key(app, key, client).await,
        Screen::RouteEditor => router::handle_route_editor_key(app, key, client).await,
        Screen::RouterPlan => router::handle_router_plan_key(app, key, client).await,
        Screen::RouterPending => router::handle_router_pending_key(app, key, client).await,
        Screen::Forwarding => forwarding::handle_key(app, key, client).await,
        Screen::PortForwarding => port_forwarding::handle_key(app, key),
        Screen::Vpn | Screen::VpnProfile | Screen::VpnSettings => {
            vpn::handle_vpn_key(app, key, client).await
        }
        Screen::VpnImport => vpn::handle_vpn_import_key(app, key, client).await,
        Screen::VpnPolicy => vpn_policy::handle_vpn_policy_key(app, key, client).await,
        Screen::Wifi => wifi::handle_wifi_key(app, key, client).await,
        Screen::WifiEditor => wifi::handle_wifi_editor_key(app, key, client).await,
        Screen::WifiScan => wifi::handle_wifi_scan_key(app, key, client).await,
        Screen::WifiProfiles => wifi::handle_wifi_profiles_key(app, key, client).await,
        Screen::WifiApProfiles => wifi::handle_wifi_ap_profiles_key(app, key, client).await,
        Screen::WifiProfileEditor => wifi::handle_wifi_profile_editor_key(app, key, client).await,
        Screen::WifiConnectPrompt => wifi::handle_wifi_connect_prompt_key(app, key, client).await,
        Screen::Settings => settings::handle_settings_key(app, key, client).await,
        Screen::SettingsPassword => settings::handle_settings_password_key(app, key, client).await,
        Screen::Log if key == KeyCode::Char('2') => {
            if direct {
                app.push_message(LogLevel::Warn, "Daemon logs require a daemon connection");
            } else {
                daemon_logs::open(app, client).await;
            }
        }
        Screen::Log => logs::handle_log_key(app, key),
        Screen::DaemonLogs => daemon_logs::handle_key(app, key, client).await,
    }
    if confirmation::current(app).is_none() {
        app.confirmation.confirmation_focus = 0;
        app.confirmation.confirmation_scroll = 0;
    }
}

fn refresh_pending_screen(app: &mut TuiApp) {
    if app.screen != Screen::PendingChange {
        return;
    }
    let Some(change) = &app.confirmation.pending else {
        app.screen = app.confirmation.pending_return_screen;
        return;
    };
    if app.dashboard.error.is_some() {
        return;
    }

    if let Some(current) = app
        .dashboard
        .pending_network_changes
        .iter()
        .find(|pending| pending.token == change.token)
    {
        app.confirmation.pending = Some(current.clone());
        return;
    }
    if current_unix_time() >= change.expires_at_unix {
        app.push_message(
            LogLevel::Info,
            "Network transaction is no longer pending; outcome unknown. Inspect current interface state.",
        );
        app.confirmation.pending = None;
        app.interface_ui.preview = None;
        app.interface_ui.editor = None;
        app.screen = app.confirmation.pending_return_screen;
    }
}

fn normalize_selection(app: &mut TuiApp) {
    app.interface_ui.selected_inventory_interface =
        app.interface_ui.selected_inventory_interface.min(
            app.dashboard
                .inventory
                .as_ref()
                .map_or(0, |entries| entries.len().saturating_sub(1)),
        );
    if app.dashboard.interfaces.is_empty() {
        app.interface_ui.selected_interface = 0;
    } else if app.interface_ui.selected_interface >= app.dashboard.interfaces.len() {
        app.interface_ui.selected_interface = app.dashboard.interfaces.len() - 1;
    }
    app.dashboard_ui.dashboard_statistics_index = app
        .dashboard_ui
        .dashboard_statistics_index
        .min(app.dashboard.interfaces.len());
}

fn address_marker(status: &InterfaceStatus, address: &Ipv4AddressInfoView) -> &'static str {
    if let Some(owned) = &status.owned_ipv4_addresses {
        if owned.contains(address) {
            ""
        } else {
            "[ext] "
        }
    } else {
        match address.owner() {
            traffic_masq_protocol::AddressOwnerView::TrafficMasqStatic
            | traffic_masq_protocol::AddressOwnerView::TrafficMasqDhcp => "",
            traffic_masq_protocol::AddressOwnerView::Untagged => "[?] ",
            traffic_masq_protocol::AddressOwnerView::Foreign(_) => "[ext] ",
        }
    }
}

fn format_addresses(status: &InterfaceStatus) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    for address in &status.ipv4_addresses {
        if !spans.is_empty() {
            spans.push(Span::raw(", "));
        }
        let marker = address_marker(status, address);
        spans.push(Span::styled(
            format!("{marker}{}/{}", address.address, address.prefix_len),
            Style::default().fg(if marker.is_empty() {
                theme::MUTED
            } else {
                theme::WARN
            }),
        ));
    }
    if spans.is_empty() {
        spans.push(Span::raw("-"));
    }
    spans
}

/// Collect dashboard state from the daemon, retaining request failures as visible status.
async fn load_daemon_dashboard(client: &ApiClient) -> DashboardData {
    let mut data = DashboardData::default();
    let mut errors = Vec::new();
    let (interfaces, pending, routes, vpn_enabled) = tokio::join!(
        client.request(&Request::ListInterfaceInventory),
        client.request(&Request::PendingNetworkChanges),
        client.request(&Request::ListRoutes {
            include_local_table: false
        }),
        client.request(&Request::GetVpnConfig),
    );
    match interfaces {
        Ok(Response::InterfaceInventory {
            base_config,
            interfaces,
            revision,
            observation_error,
            ..
        }) => {
            data.interfaces = interfaces
                .iter()
                .filter_map(|entry| entry.observed.clone())
                .collect();
            for entry in &interfaces {
                if let Some(config) = &entry.configured {
                    data.managed.insert(entry.name.clone(), config.managed);
                    data.roles.insert(entry.name.clone(), config.role);
                }
            }
            data.base_config = base_config;
            data.inventory = Some(interfaces);
            data.intent_revision = Some(revision);
            data.interfaces_updated = Some(Instant::now());
            if let Some(error) = observation_error {
                errors.push(format!("Interface observation unavailable: {error}"));
            }
        }
        Ok(Response::Interfaces { interfaces }) => {
            data.interfaces = interfaces;
            data.interfaces_updated = Some(Instant::now());
        }
        other => errors.push(format!("Interfaces unavailable: {other:?}")),
    }
    match pending {
        Ok(Response::PendingNetworkChanges { changes }) => {
            data.pending_network_changes = changes;
            data.pending_known = true;
        }
        other => errors.push(format!("Pending changes unavailable: {other:?}")),
    }
    match routes {
        Ok(Response::Routes { routes }) => data.routes = Some(routes),
        other => errors.push(format!("Routes unavailable: {other:?}")),
    }
    match vpn_enabled {
        Ok(Response::VpnConfig { enabled }) => data.vpn_enabled = Some(enabled),
        other => errors.push(format!("VPN configuration unavailable: {other:?}")),
    }
    use futures_util::StreamExt;
    let configs = futures_util::stream::iter(data.interfaces.iter().map(|status| async move {
        let name = status.interface.name.clone();
        let result = client
            .request(&Request::GetInterfaceConfig {
                interface: name.clone(),
            })
            .await;
        (name, result)
    }))
    .buffer_unordered(4)
    .collect::<Vec<_>>()
    .await;
    for (name, result) in configs {
        match result {
            Ok(Response::InterfaceConfig { config, .. }) => {
                data.managed
                    .insert(name.clone(), config.as_ref().is_some_and(|c| c.managed));
                data.roles.insert(
                    name,
                    config.map_or(traffic_masq_protocol::InterfaceRole::None, |c| c.role),
                );
            }
            other => errors.push(format!(
                "Interface configuration unavailable ({name}): {other:?}"
            )),
        }
    }
    if data.vpn_enabled == Some(true) {
        match client.request(&Request::VpnPolicyStatus).await {
            Ok(Response::VpnPolicyStatus { status }) => data.vpn_status = Some(status),
            other => errors.push(format!("VPN tunnel/policy unavailable: {other:?}")),
        }
    }
    if errors.is_empty() {
        data.last_success = Some(Instant::now());
    } else {
        data.error = Some(errors.join("\n"));
    }
    data
}

/// Observe local network state for the direct-mode dashboard without daemon mutations.
async fn load_direct_dashboard(network: Option<&RtnetlinkNetworkProvider>) -> DashboardData {
    let Some(network) = network else {
        return DashboardData {
            error: Some("failed to initialize rtnetlink direct mode".to_string()),
            ..DashboardData::default()
        };
    };

    let interfaces = match network.list_interfaces().await {
        Ok(interfaces) => interfaces,
        Err(error) => {
            return DashboardData {
                error: Some(error.to_string()),
                ..DashboardData::default()
            }
        }
    };

    let (routes, route_error) = match network.list_ipv4_routes().await {
        Ok(routes) => (routes, None),
        Err(error) => (Vec::new(), Some(error.to_string())),
    };
    let mut statuses = Vec::new();
    for interface in interfaces {
        match network.list_ipv4_addresses(&interface.name).await {
            Ok(ipv4_addresses) => statuses.push(InterfaceStatus {
                owned_ipv4_addresses: None,
                has_default_route: routes.iter().any(|route| {
                    route.destination.prefix_len() == 0
                        && route.output_interface_index == Some(interface.index)
                }),
                interface: traffic_masq_protocol::NetworkInterfaceView {
                    index: interface.index,
                    name: interface.name,
                    is_up: interface.is_up,
                    rx_bytes: interface.rx_bytes,
                    tx_bytes: interface.tx_bytes,
                    is_wireless: interface.is_wireless,
                },
                ipv4_addresses: ipv4_addresses
                    .into_iter()
                    .map(|address| Ipv4AddressInfoView {
                        interface_index: address.interface_index,
                        address: address.address,
                        prefix_len: address.prefix_len,
                        protocol: address.protocol,
                    })
                    .collect(),
            }),
            Err(error) => {
                return DashboardData {
                    interfaces: statuses,
                    error: Some(error.to_string()),
                    ..DashboardData::default()
                }
            }
        }
    }

    let route_statuses = routes
        .iter()
        .map(|route| {
            let name = statuses
                .iter()
                .find(|s| Some(s.interface.index) == route.output_interface_index)
                .map(|s| s.interface.name.clone());
            traffic_masq_protocol::RouteStatusView {
                destination: route.destination,
                gateway: route.gateway,
                output_interface: name,
                output_interface_index: route.output_interface_index,
                table: route.table,
                metric: route.metric,
                protocol: route.protocol,
                scope: route.scope,
                owner: traffic_masq_protocol::RouteOwnerView::from_protocol(route.protocol),
            }
        })
        .collect();
    DashboardData {
        interfaces: statuses,
        routes: route_error.is_none().then_some(route_statuses),
        interfaces_updated: Some(Instant::now()),
        last_success: route_error.is_none().then(Instant::now),
        error: route_error,
        ..Default::default()
    }
}

fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests;
