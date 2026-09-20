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

use crate::api::client::ApiClient;
use crate::api::model::{DhcpClientStatusView, InterfaceStatus, Request, Response};
use crate::core::interface::InterfaceChangePlan;
use crate::core::transaction::PendingNetworkChange;
use crate::netlink::{NetworkProvider, RtnetlinkNetworkProvider};

mod access;
mod dashboard;
mod dhcp;
mod dhcp_client;
mod forwarding;
mod input;
mod interfaces;
mod layout;
mod logs;
mod router;
mod router_topology;
mod session;
mod settings;
mod vpn;
mod vpn_policy;
mod wifi;

use access::AccessEditor;
use dashboard::DashboardData;
use dhcp::{DhcpEditor, DhcpLeasesView};
use interfaces::InterfaceEditor;
use layout::UiLayout;
use logs::LogLevel;
use router::{RouterData, RouterFocus, RouterPendingView};
use settings::{PasswordChangeEditor, SecurityEditor};
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
    Preview,
    PendingChange,
    Router,
    RouterPlan,
    RouterPending,
    RouteEditor,
    Forwarding,
    Vpn,
    VpnImport,
    VpnPolicy,
    Wifi,
    WifiEditor,
    WifiScan,
    WifiProfiles,
    WifiProfileEditor,
    WifiConnectPrompt,
    Settings,
    SettingsPassword,
    Log,
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
            Section::Router => "Router",
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
        Screen::DhcpClient => Section::DhcpClient,
        Screen::Router
        | Screen::RouteEditor
        | Screen::RouterPlan
        | Screen::RouterPending
        | Screen::Forwarding => Section::Router,
        Screen::Vpn | Screen::VpnImport | Screen::VpnPolicy => Section::Vpn,
        Screen::Wifi
        | Screen::WifiEditor
        | Screen::WifiScan
        | Screen::WifiProfiles
        | Screen::WifiProfileEditor
        | Screen::WifiConnectPrompt => Section::Wifi,
        Screen::Settings | Screen::SettingsPassword | Screen::Access => Section::Settings,
        Screen::Log => Section::Log,
    }
}

fn section_of_app(app: &TuiApp) -> Section {
    if app.screen == Screen::PendingChange {
        section_of(app.pending_return_screen)
    } else {
        section_of(app.screen)
    }
}

fn section_available(section: Section, direct: bool) -> bool {
    !direct || matches!(section, Section::Dashboard | Section::Interfaces | Section::Log)
}

fn adjacent_section(current: Section, forward: bool, show_dhcp_client: bool, direct: bool) -> Section {
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
    message_open: bool,
    router_pane: router::RouterPane,
    topology_open: bool,
    wifi_actions_open: bool,
    wifi_profiles_mode: Option<wifi::WifiProfilesMode>,
}

struct TuiApp {
    screen: Screen,
    last_drawn_view: Option<ViewIdentity>,
    dashboard: DashboardData,
    selected_interface: usize,

    dashboard_focus: dashboard::DashboardFocus,
    api_access: Option<AccessEditor>,
    editor: Option<InterfaceEditor>,
    dhcp_editor: Option<DhcpEditor>,
    dhcp_leases: Option<DhcpLeasesView>,
    dhcp_clients: Vec<DhcpClientStatusView>,
    dhcp_client_selected: Option<String>,
    dhcp_client_scroll: usize,
    preview: Option<InterfaceChangePlan>,
    preview_scroll: usize,
    preview_max_scroll: usize,
    pending: Option<PendingNetworkChange>,
    pending_return_screen: Screen,
    router: RouterData,
    router_pending: Option<RouterPendingView>,
    forwarding: Option<forwarding::ForwardingEditor>,
    router_rollback_timeout_seconds: u64,
    vpn: VpnData,
    vpn_import: Option<VpnImportEditor>,
    vpn_policy: VpnPolicyData,
    wifi: wifi::WifiData,
    wifi_editor: Option<wifi::WifiEditor>,
    wifi_scan: Option<wifi::WifiScanPicker>,
    wifi_profiles: Option<wifi::WifiProfilesView>,
    wifi_profile_editor: Option<wifi::WifiProfileEditor>,
    wifi_connect: Option<wifi::WifiConnectPrompt>,
    settings: Option<SecurityEditor>,
    settings_password: Option<PasswordChangeEditor>,
    pub(crate) show_dhcp_client: bool,
    traffic: HashMap<u32, dashboard::TrafficHistory>,
    ui: UiLayout,
    message: Option<String>,
    message_open: bool,
    message_scroll: u16,
    should_quit: bool,
    logs: VecDeque<logs::LogEntry>,
    logs_scroll: usize,
    logs_max_scroll: usize,
    logs_focus: logs::LogFocus,
}

impl Default for TuiApp {
    fn default() -> Self {
        Self {
            screen: Screen::Dashboard,
            last_drawn_view: None,
            dashboard: DashboardData::default(),
            selected_interface: 0,
            dashboard_focus: dashboard::DashboardFocus::default(),
            api_access: None,
            editor: None,
            dhcp_editor: None,
            dhcp_leases: None,
            dhcp_clients: Vec::new(),
            dhcp_client_selected: None,
            dhcp_client_scroll: 0,
            preview: None,
            preview_scroll: 0,
            preview_max_scroll: 0,
            pending: None,
            pending_return_screen: Screen::Dashboard,
            router: RouterData::default(),
            router_pending: None,
            forwarding: None,
            router_rollback_timeout_seconds: 60,
            vpn: VpnData::default(),
            vpn_import: None,
            vpn_policy: VpnPolicyData::default(),
            wifi: wifi::WifiData::default(),
            wifi_editor: None,
            wifi_scan: None,
            wifi_profiles: None,
            wifi_profile_editor: None,
            wifi_connect: None,
            settings: None,
            settings_password: None,
            show_dhcp_client: false,
            traffic: HashMap::new(),
            ui: UiLayout::default(),
            message: None,
            message_open: false,
            message_scroll: 0,
            should_quit: false,
            logs: VecDeque::new(),
            logs_scroll: 0,
            logs_max_scroll: 0,
            logs_focus: logs::LogFocus::default(),
        }
    }
}

impl TuiApp {
    pub(crate) fn push_message(&mut self, level: logs::LogLevel, text: impl Into<String>) {
        let follow_log_tail = self.logs_scroll >= self.logs_max_scroll;
        let text = text.into();
        self.message = Some(text.clone());
        self.logs.push_back(logs::LogEntry {
            at_unix: current_unix_time(),
            level,
            message: text,
        });
        if self.logs.len() > logs::LOG_HISTORY_LEN {
            self.logs.pop_front();
        }
        if follow_log_tail {
            // The exact maximum depends on the rendered viewport. A sentinel
            // is clamped to that maximum on the next render, preserving
            // follow-tail without snapping back after a deliberate Up.
            self.logs_scroll = usize::MAX;
        }
    }
}

pub async fn change_device_password(socket_path: PathBuf) -> Result<()> {
    let client = ApiClient::new(socket_path);
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

pub async fn run_tui(socket_path: PathBuf, direct: bool) -> Result<()> {
    let client = ApiClient::new(socket_path);
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
    let mut app = TuiApp::default();
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

    while !app.should_quit {
        if !direct && !client.is_authenticated().await {
            if !reauthenticate(terminal, client, pending_deadline(&app), !has_authenticated).await?
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
                app.dashboard = if direct {
                    load_direct_dashboard(direct_network.as_ref()).await
                } else {
                    load_daemon_dashboard(client).await
                };
                normalize_selection(&mut app);
                refresh_pending_screen(&mut app);
                dashboard::record_traffic_samples(&mut app);

                if !direct && matches!(app.screen, Screen::Router | Screen::RouterPlan) {
                    router::load_router_data(&mut app, client).await;
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
                if !direct && app.screen == Screen::Vpn {
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

// Reads may be cancelled to prioritize input. Actions are never cancelled or
// retried: a lost response does not imply that a mutation was not applied.
fn pending_deadline(app: &TuiApp) -> Option<u64> {
    app.pending.as_ref().map(|p| p.expires_at_unix).or_else(|| {
        app.router_pending.as_ref().map(|p| {
            p.applied_at_unix
                .saturating_add(app.router_rollback_timeout_seconds)
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
            "Operation in progress… resize to at least 80x24. Q: exit after result"
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
            "Operation in progress"
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
                    format!("{message}\n\nDevice password: "),
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

async fn navigate_to_section(app: &mut TuiApp, section: Section, client: &ApiClient, direct: bool) {
    if !matches!(
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
    ) {
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
                app.dhcp_client_selected = app
                    .dashboard
                    .interfaces
                    .get(app.selected_interface)
                    .map(|status| status.interface.name.clone());
                app.dhcp_client_scroll = 0;
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
                app.screen = Screen::Vpn;
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
    if !app.ui.input_enabled {
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

    // Wheel input belongs to the list/viewport, even when a button had focus.
    // In particular, scrolling must not select a destructive action for Enter.
    if matches!(
        mouse.kind,
        MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
    ) {
        match app.screen {
            Screen::Dashboard => app.dashboard_focus = dashboard::DashboardFocus::List,
            Screen::Vpn => app.vpn.focus = vpn::VpnFocus::List,
            Screen::Router if !app.router.topology.open => {
                app.router.focus = RouterFocus::RouteTable;
                app.router.sharing_actions_focused = false;
            }
            Screen::Log => {
                app.logs_focus = logs::LogFocus::Scroll;
                app.logs_scroll = if mouse.kind == MouseEventKind::ScrollUp {
                    app.logs_scroll.saturating_sub(1)
                } else {
                    app.logs_scroll.saturating_add(1).min(app.logs_max_scroll)
                };
                return;
            }
            _ => {}
        }
    }

    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
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
                            Screen::Dashboard
                            | Screen::InterfaceList
                            | Screen::DhcpInterfaceList => {
                                app.selected_interface = index;
                                if app.screen == Screen::Dashboard {
                                    app.dashboard_focus = dashboard::DashboardFocus::List;
                                }
                            }
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
                                if app.router.pane == router::RouterPane::Sharing {
                                    app.router.selected_connection = index;
                                    app.router.sharing_actions_focused = false;
                                } else {
                                    app.router.selected_route = index;
                                    app.router.focus = RouterFocus::RouteTable;
                                }
                            }
                            Screen::WifiScan => {
                                if let Some(scan) = app.wifi_scan.as_mut() {
                                    scan.selected = index;
                                }
                            }
                            Screen::WifiProfiles => {
                                if let Some(view) = app.wifi_profiles.as_mut() {
                                    match view.mode {
                                        wifi::WifiProfilesMode::Menu => {
                                            if index < wifi::WifiProfilesMenuAction::ALL.len() {
                                                view.selected = index;
                                            }
                                        }
                                        wifi::WifiProfilesMode::Management => {
                                            if index < view.profiles.len() {
                                                view.selected = index;
                                                view.selected_profile = index;
                                            }
                                        }
                                        wifi::WifiProfilesMode::ProfileActions => {
                                            if index < wifi::WifiProfileAction::ALL.len() {
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
            Screen::WifiScan => wifi::handle_wifi_scan_key(app, KeyCode::Up),
            Screen::WifiProfiles => wifi::handle_wifi_profiles_key(app, KeyCode::Up, client).await,
            Screen::Dashboard | Screen::InterfaceList | Screen::DhcpInterfaceList => {
                app.selected_interface = app.selected_interface.saturating_sub(1);
            }
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
                if let Some(view) = app.dhcp_leases.as_mut() {
                    view.scroll = view.scroll.saturating_sub(1);
                }
            }
            _ => {}
        },
        MouseEventKind::ScrollDown => match app.screen {
            Screen::Preview => interfaces::handle_preview_key(app, KeyCode::Down, client).await,
            Screen::Wifi => wifi::handle_wifi_key(app, KeyCode::Down, client).await,
            Screen::WifiScan => wifi::handle_wifi_scan_key(app, KeyCode::Down),
            Screen::WifiProfiles => {
                wifi::handle_wifi_profiles_key(app, KeyCode::Down, client).await
            }
            Screen::Dashboard | Screen::InterfaceList | Screen::DhcpInterfaceList
                if app.selected_interface + 1 < app.dashboard.interfaces.len() =>
            {
                app.selected_interface += 1;
            }
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
                if let Some(view) = app.dhcp_leases.as_mut() {
                    if view.scroll + 1 < view.leases.len() {
                        view.scroll += 1;
                    }
                }
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
) -> io::Result<ratatui::CompletedFrame<'a>> {
    let view = ViewIdentity {
        screen: app.screen,
        message_open: app.message_open,
        router_pane: app.router.pane,
        topology_open: app.router.topology.open,
        wifi_actions_open: app.wifi.actions_open,
        wifi_profiles_mode: app.wifi_profiles.as_ref().map(|view| view.mode),
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
        frame.render_widget(
            Paragraph::new("Terminal too small — resize to at least 80x24. Q: exit. Pending changes keep their original rollback deadlines.")
                .alignment(Alignment::Center)
                .style(Style::default().fg(theme::WARN)),
            area,
        );
        return;
    }
    app.ui.input_enabled = true;
    if app.message_open {
        let text = app
            .message
            .as_deref()
            .or(app.dashboard.error.as_deref())
            .unwrap_or("No message");
        frame.render_widget(
            Paragraph::new(format_message_lines(text))
                .wrap(ratatui::widgets::Wrap { trim: false })
                .scroll((app.message_scroll, 0))
                .block(layout::panel("Message — Up/Down: scroll; Esc/F1: close")),
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
        Screen::Access => access::render_access(frame, chunks[1], app),
        Screen::InterfaceList => interfaces::render_interface_list(frame, chunks[1], app),
        Screen::InterfaceEditor => interfaces::render_editor(frame, chunks[1], app),
        Screen::DhcpInterfaceList => dhcp::render_dhcp_interface_list(frame, chunks[1], app),
        Screen::DhcpEditor => dhcp::render_dhcp_editor(frame, chunks[1], app),
        Screen::DhcpLeases => dhcp::render_dhcp_leases(frame, chunks[1], app),
        Screen::DhcpClient => dhcp_client::render(frame, chunks[1], app),
        Screen::Preview => interfaces::render_preview(frame, chunks[1], app),
        Screen::PendingChange => interfaces::render_pending(frame, chunks[1], app),
        Screen::Router => router::render_router(frame, chunks[1], app),
        Screen::RouteEditor => router::render_route_editor(frame, chunks[1], app),
        Screen::RouterPlan => router::render_router_plan(frame, chunks[1], app),
        Screen::RouterPending => router::render_router_pending(frame, chunks[1], app),
        Screen::Forwarding => forwarding::render(frame, chunks[1], app),
        Screen::Vpn => vpn::render_vpn(frame, chunks[1], app),
        Screen::VpnImport => vpn::render_vpn_import(frame, chunks[1], app),
        Screen::VpnPolicy => vpn_policy::render_vpn_policy(frame, chunks[1], app),
        Screen::Wifi => wifi::render_wifi(frame, chunks[1], app),
        Screen::WifiEditor => wifi::render_wifi_editor(frame, chunks[1], app),
        Screen::WifiScan => wifi::render_wifi_scan(frame, chunks[1], app),
        Screen::WifiProfiles => wifi::render_wifi_profiles(frame, chunks[1], app),
        Screen::WifiProfileEditor => wifi::render_wifi_profile_editor(frame, chunks[1], app),
        Screen::WifiConnectPrompt => wifi::render_wifi_connect_prompt(frame, chunks[1], app),
        Screen::Settings => settings::render_settings(frame, chunks[1], app),
        Screen::SettingsPassword => settings::render_settings_password(frame, chunks[1], app),
        Screen::Log => logs::render_log(frame, chunks[1], app),
    }

    // Mouse geometry is a derived view of what is actually visible. Never let
    // a renderer leave an off-screen control active in the shell chrome.
    app.ui.clip_interactions(chunks[1]);
    layout::render_footer(frame, chunks[2], app);
}

fn focus_action_slot(app: &mut TuiApp, slot: usize) {
    match app.screen {
        Screen::Dashboard => dashboard::focus_action(app, slot),
        Screen::Access => access::focus_action(app, slot),
        Screen::InterfaceEditor => interfaces::focus_action(app, slot),
        Screen::DhcpEditor => dhcp::focus_action(app, slot),
        Screen::Router => router::focus_action(app, slot),
        Screen::Forwarding => forwarding::focus_action(app, slot),
        Screen::RouteEditor => router::focus_route_editor_action(app, slot),
        Screen::Vpn => vpn::focus_action(app, slot),
        Screen::VpnPolicy => vpn_policy::focus_action(app, slot),
        Screen::Wifi => wifi::focus_action(app, slot),
        Screen::WifiConnectPrompt => {
            if let Some(prompt) = app.wifi_connect.as_mut() {
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
        if matches!(key, KeyCode::Char('q') | KeyCode::Char('Q')) {
            app.should_quit = true;
        }
        return;
    }
    if key == KeyCode::F(1) {
        app.message_open = !app.message_open;
        app.message_scroll = 0;
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

    if matches!(key, KeyCode::F(2) | KeyCode::F(3)) {
        let target = adjacent_section(
            section_of_app(app),
            key == KeyCode::F(3),
            app.show_dhcp_client,
            direct,
        );
        navigate_to_section(app, target, client, direct).await;
        return;
    }

    // Forms and simple lists share forward/backward focus navigation. Screens
    // with separate panes handle Tab themselves so it skips the whole list.
    let key = match (app.screen, key) {
        (
            Screen::Dashboard
            | Screen::Vpn
            | Screen::Log
            | Screen::Router
            | Screen::Forwarding
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
            Screen::Settings => app.settings.as_ref().is_some_and(|s| s.is_editing()),
            Screen::Dashboard => app.dashboard_focus != dashboard::DashboardFocus::List,
            Screen::Vpn => app.vpn.focus != vpn::VpnFocus::List,
            Screen::Log => app.logs_focus != logs::LogFocus::Scroll,
            Screen::Wifi => app.wifi.actions_open,
            Screen::Router => {
                app.router.focus == RouterFocus::Actions
                    || (app.router.pane == router::RouterPane::Sharing
                        && app.router.sharing_actions_focused)
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
        Screen::Access => access::handle_access_key(app, key, client).await,
        Screen::InterfaceList => {
            interfaces::handle_interface_list_key(app, key, client, direct).await
        }
        Screen::InterfaceEditor => interfaces::handle_editor_key(app, key, client).await,
        Screen::DhcpInterfaceList => dhcp::handle_dhcp_interface_list_key(app, key, client).await,
        Screen::DhcpEditor => dhcp::handle_dhcp_editor_key(app, key, client).await,
        Screen::DhcpLeases => dhcp::handle_dhcp_leases_key(app, key, client).await,
        Screen::DhcpClient => dhcp_client::handle_key(app, key, client).await,
        Screen::Preview => interfaces::handle_preview_key(app, key, client).await,
        Screen::PendingChange => interfaces::handle_pending_key(app, key, client).await,
        Screen::Router => router::handle_router_key(app, key, client).await,
        Screen::RouteEditor => router::handle_route_editor_key(app, key, client).await,
        Screen::RouterPlan => router::handle_router_plan_key(app, key, client).await,
        Screen::RouterPending => router::handle_router_pending_key(app, key, client).await,
        Screen::Forwarding => forwarding::handle_key(app, key, client).await,
        Screen::Vpn => vpn::handle_vpn_key(app, key, client).await,
        Screen::VpnImport => vpn::handle_vpn_import_key(app, key, client).await,
        Screen::VpnPolicy => vpn_policy::handle_vpn_policy_key(app, key, client).await,
        Screen::Wifi => wifi::handle_wifi_key(app, key, client).await,
        Screen::WifiEditor => wifi::handle_wifi_editor_key(app, key, client).await,
        Screen::WifiScan => wifi::handle_wifi_scan_key(app, key),
        Screen::WifiProfiles => wifi::handle_wifi_profiles_key(app, key, client).await,
        Screen::WifiProfileEditor => wifi::handle_wifi_profile_editor_key(app, key, client).await,
        Screen::WifiConnectPrompt => wifi::handle_wifi_connect_prompt_key(app, key, client).await,
        Screen::Settings => settings::handle_settings_key(app, key, client).await,
        Screen::SettingsPassword => settings::handle_settings_password_key(app, key, client).await,
        Screen::Log => logs::handle_log_key(app, key),
    }
}

fn refresh_pending_screen(app: &mut TuiApp) {
    if app.screen != Screen::PendingChange {
        return;
    }
    let Some(change) = &app.pending else {
        app.screen = app.pending_return_screen;
        return;
    };
    if app.dashboard.error.is_some() {
        return;
    }

    let still_pending = app
        .dashboard
        .pending_network_changes
        .iter()
        .any(|pending| pending.token == change.token);
    if !still_pending && current_unix_time() >= change.expires_at_unix {
        app.push_message(
            LogLevel::Info,
            "Network transaction is no longer pending; outcome unknown. Inspect current interface state.",
        );
        app.pending = None;
        app.preview = None;
        app.editor = None;
        app.screen = app.pending_return_screen;
    }
}

fn normalize_selection(app: &mut TuiApp) {
    if app.dashboard.interfaces.is_empty() {
        app.selected_interface = 0;
    } else if app.selected_interface >= app.dashboard.interfaces.len() {
        app.selected_interface = app.dashboard.interfaces.len() - 1;
    }
}

fn address_marker(
    status: &InterfaceStatus,
    address: &crate::netlink::Ipv4AddressInfo,
) -> &'static str {
    if let Some(owned) = &status.owned_ipv4_addresses {
        if owned.contains(address) {
            ""
        } else {
            "[ext] "
        }
    } else {
        match address.owner() {
            crate::netlink::AddressOwner::TrafficMasqStatic
            | crate::netlink::AddressOwner::TrafficMasqDhcp => "",
            crate::netlink::AddressOwner::Foreign(_) => "[ext] ",
            crate::netlink::AddressOwner::Untagged => "[?] ",
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

async fn load_daemon_dashboard(client: &ApiClient) -> DashboardData {
    let interfaces = match client.request(&Request::ListInterfaces).await {
        Ok(Response::Interfaces { interfaces }) => interfaces,
        Ok(Response::Error { message }) => {
            return DashboardData {
                error: Some(message),
                ..DashboardData::default()
            }
        }
        Ok(response) => return unexpected_dashboard_response(response),
        Err(error) => {
            return DashboardData {
                error: Some(error.to_string()),
                ..DashboardData::default()
            }
        }
    };

    use futures_util::StreamExt;
    let configs = futures_util::stream::iter(interfaces.iter().map(|status| async move {
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
    let mut managed = std::collections::HashMap::new();
    for (name, result) in configs {
        match result {
            Ok(Response::InterfaceConfig { config, .. }) => {
                managed.insert(name, config.is_some_and(|c| c.managed));
            }
            other => {
                return DashboardData {
                    interfaces,
                    error: Some(format!(
                        "Could not refresh interface configuration: {other:?}"
                    )),
                    ..DashboardData::default()
                }
            }
        }
    }

    let dhcp_interfaces = match client.request(&Request::DhcpStatus).await {
        Ok(Response::DhcpStatus {
            running_interfaces,
            unhealthy_interfaces,
        }) => {
            if !unhealthy_interfaces.is_empty() {
                return DashboardData {
                    interfaces,
                    managed,
                    error: Some(format!(
                        "DHCP unhealthy on: {}",
                        unhealthy_interfaces.join(", ")
                    )),
                    ..DashboardData::default()
                };
            }
            running_interfaces
        }
        Ok(Response::Error { message }) => {
            return DashboardData {
                interfaces,
                managed,
                error: Some(message),
                ..DashboardData::default()
            }
        }
        Ok(response) => return unexpected_dashboard_response(response),
        Err(error) => {
            return DashboardData {
                interfaces,
                managed,
                error: Some(error.to_string()),
                ..DashboardData::default()
            }
        }
    };

    let pending_network_changes = match client.request(&Request::PendingNetworkChanges).await {
        Ok(Response::PendingNetworkChanges { changes }) => changes,
        Ok(Response::Error { message }) => {
            return DashboardData {
                interfaces,
                managed,
                dhcp_interfaces,
                error: Some(message),
                ..DashboardData::default()
            }
        }
        Ok(response) => return unexpected_dashboard_response(response),
        Err(error) => {
            return DashboardData {
                interfaces,
                managed,
                dhcp_interfaces,
                error: Some(error.to_string()),
                ..DashboardData::default()
            }
        }
    };

    DashboardData {
        interfaces,
        managed,
        dhcp_interfaces,
        pending_network_changes,
        error: None,
    }
}

fn unexpected_dashboard_response(response: Response) -> DashboardData {
    DashboardData {
        error: Some(format!("Unexpected daemon response: {response:?}")),
        ..DashboardData::default()
    }
}

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

    let routes = network.list_ipv4_routes().await.unwrap_or_default();
    let mut statuses = Vec::new();
    for interface in interfaces {
        match network.list_ipv4_addresses(&interface.name).await {
            Ok(ipv4_addresses) => statuses.push(InterfaceStatus {
                owned_ipv4_addresses: None,
                has_default_route: routes.iter().any(|route| {
                    route.destination.prefix_len() == 0
                        && route.output_interface_index == Some(interface.index)
                }),
                interface,
                ipv4_addresses,
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

    DashboardData {
        interfaces: statuses,
        managed: std::collections::HashMap::new(),
        dhcp_interfaces: Vec::new(),
        pending_network_changes: Vec::new(),
        error: None,
    }
}

fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rollback_click_sends_rollback_request() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("api.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut bytes = [0; 1024];
            while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                let count = stream.read(&mut bytes).await.unwrap();
                assert!(count > 0);
                request.extend_from_slice(&bytes[..count]);
            }
            stream.write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
            String::from_utf8(request).unwrap()
        });
        let mut app = TuiApp {
            screen: Screen::PendingChange,
            pending: Some(crate::core::transaction::PendingNetworkChange {
                token: "test-token".into(),
                interface: "eth0".into(),
                rollback_timeout_seconds: 30,
                expires_at_unix: current_unix_time() + 30,
            }),
            ..Default::default()
        };
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| render(frame, &mut app, false))
            .unwrap();
        let (rect, _) = *app.ui.buttons.iter().find(|(_, slot)| *slot == 1).unwrap();
        assert!(
            rect.y < 20,
            "rollback must fit inside the content panel at 80x24"
        );
        handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: rect.x,
                row: rect.y,
                modifiers: crossterm::event::KeyModifiers::NONE,
            },
            &ApiClient::new(socket),
            false,
        )
        .await;
        let request = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        assert!(request.starts_with("POST /api/v1/network-transactions/rollback "));
    }

    #[tokio::test]
    async fn wifi_click_opens_actions_for_clicked_interface() {
        let mut app = TuiApp {
            screen: Screen::Wifi,
            ..Default::default()
        };
        app.wifi.rows = vec![
            wifi::WifiRow {
                interface: "wlan0".into(),
                role: wifi::WifiRole::AccessPoint,
                ap: None,
                client: None,
            },
            wifi::WifiRow {
                interface: "wlan1".into(),
                role: wifi::WifiRole::Client,
                ap: None,
                client: None,
            },
        ];
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| render(frame, &mut app, false))
            .unwrap();
        assert!(!app.wifi.actions_open);
        let area = app.ui.list_area.unwrap();
        let client = ApiClient::new("/nonexistent.sock");
        handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: area.x,
                row: area.y + 1,
                modifiers: crossterm::event::KeyModifiers::NONE,
            },
            &client,
            false,
        )
        .await;
        assert!(app.wifi.actions_open);
        assert_eq!(app.wifi.selected_radio, 1);
        terminal
            .draw(|frame| render(frame, &mut app, false))
            .unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(text.contains("Scan networks"));
        assert!(!text.contains("Configure access point"));
    }

    #[test]
    fn switching_views_clears_physical_artifacts_once() {
        use ratatui::backend::Backend;
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        let mut app = TuiApp::default();
        draw_app(&mut terminal, &mut app, false).unwrap();
        // Simulate terminal content unknown to ratatui's previous-frame buffer.
        let mut artifact = ratatui::buffer::Cell::default();
        artifact.set_symbol("X");
        terminal
            .backend_mut()
            .draw([(40, 10, &artifact)].into_iter())
            .unwrap();
        draw_app(&mut terminal, &mut app, false).unwrap();
        assert_eq!(terminal.backend().buffer()[(40, 10)].symbol(), "X");
        app.screen = Screen::Settings;
        draw_app(&mut terminal, &mut app, false).unwrap();
        let mut clean = Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        clean.draw(|frame| render(frame, &mut app, false)).unwrap();
        assert_eq!(terminal.backend().buffer(), clean.backend().buffer());
        terminal
            .backend_mut()
            .draw([(40, 10, &artifact)].into_iter())
            .unwrap();
        app.message_open = true;
        draw_app(&mut terminal, &mut app, false).unwrap();
        assert_ne!(terminal.backend().buffer()[(40, 10)].symbol(), "X");
    }

    #[tokio::test]
    async fn tab_focus_and_modified_keys_are_consistent() {
        let client = ApiClient::new("/nonexistent.sock");
        let mut app = TuiApp::default();
        app.ui.input_enabled = true;
        handle_key(&mut app, KeyCode::Tab, &client, false).await;
        assert_eq!(app.dashboard_focus, dashboard::DashboardFocus::Interfaces);
        handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Tab, KeyModifiers::SHIFT),
            &client,
            false,
        )
        .await;
        assert_eq!(app.dashboard_focus, dashboard::DashboardFocus::List);
        app.screen = Screen::Vpn;
        handle_key(&mut app, KeyCode::Tab, &client, false).await;
        assert_eq!(app.vpn.focus, vpn::VpnFocus::Connect);
        handle_key(&mut app, KeyCode::Right, &client, false).await;
        assert_eq!(app.screen, Screen::Vpn);
        assert_eq!(app.vpn.focus, vpn::VpnFocus::Disconnect);
        handle_key(&mut app, KeyCode::Left, &client, false).await;
        handle_key(&mut app, KeyCode::BackTab, &client, false).await;
        assert_eq!(app.vpn.focus, vpn::VpnFocus::List);
        app.screen = Screen::Log;
        handle_key(&mut app, KeyCode::Tab, &client, false).await;
        assert_eq!(app.logs_focus, logs::LogFocus::Export);
        handle_key(&mut app, KeyCode::BackTab, &client, false).await;
        assert_eq!(app.logs_focus, logs::LogFocus::Scroll);

        app.screen = Screen::VpnImport;
        app.vpn_import = Some(VpnImportEditor {
            field: vpn::VpnImportField::Name,
            name: String::new(),
            path: String::new(),
            cursor: 0,
        });
        handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL),
            &client,
            false,
        )
        .await;
        assert!(app.vpn_import.as_ref().unwrap().name.is_empty());
        handle_key(&mut app, KeyCode::Tab, &client, false).await;
        assert_eq!(
            app.vpn_import.as_ref().unwrap().field,
            vpn::VpnImportField::Path
        );
        handle_key(&mut app, KeyCode::BackTab, &client, false).await;
        assert_eq!(
            app.vpn_import.as_ref().unwrap().field,
            vpn::VpnImportField::Name
        );
        handle_key(&mut app, KeyCode::F(3), &client, false).await;
        assert_eq!(app.screen, Screen::VpnImport);
        handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
            &client,
            false,
        )
        .await;
        assert!(app.should_quit);
    }

    #[test]
    fn footer_message_is_visible_at_supported_sizes() {
        for (width, height) in [(80, 24), (100, 30)] {
            let mut terminal =
                Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
            let mut app = TuiApp::default();
            app.push_message(LogLevel::Error, "Validation failed");
            terminal
                .draw(|frame| render(frame, &mut app, false))
                .unwrap();
            let text: String = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|c| c.symbol())
                .collect();
            assert!(text.contains("Validation failed"));
        }
    }

    #[test]
    fn refreshing_preserves_footer_notification_and_does_not_flash_for_fast_reads() {
        for (width, height) in [(80, 24), (100, 30)] {
            let mut terminal =
                Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
            let mut app = TuiApp::default();
            app.push_message(LogLevel::Info, "Settings saved");
            let snapshot = terminal
                .draw(|frame| render(frame, &mut app, false))
                .unwrap()
                .buffer
                .clone();

            terminal
                .draw(|frame| {
                    render_operation_snapshot(
                        frame,
                        &snapshot,
                        None,
                        Duration::from_millis(100),
                        true,
                    )
                })
                .unwrap();
            assert_eq!(terminal.backend().buffer(), &snapshot);

            for cancellable in [true, false] {
                terminal
                    .draw(|frame| {
                        render_operation_snapshot(
                            frame,
                            &snapshot,
                            None,
                            Duration::from_secs(2),
                            cancellable,
                        )
                    })
                    .unwrap();
                let buffer = terminal.backend().buffer();
                let progress: String = (1..width - 1)
                    .map(|x| buffer[(x, height - 3)].symbol())
                    .collect();
                assert!(progress.contains(if cancellable {
                    "Refreshing"
                } else {
                    "Operation in progress"
                }));
                for y in [height - 2, height - 1] {
                    for x in 0..width {
                        assert_eq!(
                            buffer[(x, y)],
                            snapshot[(x, y)],
                            "notification and border must stay intact"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn operation_snapshot_redraws_safely_after_terminal_resize() {
        let mut old_terminal =
            Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        let mut app = TuiApp::default();
        let snapshot = old_terminal
            .draw(|frame| render(frame, &mut app, false))
            .unwrap()
            .buffer
            .clone();

        let mut resized = Terminal::new(ratatui::backend::TestBackend::new(100, 30)).unwrap();
        resized
            .draw(|frame| {
                render_operation_snapshot(
                    frame,
                    &snapshot,
                    None,
                    Duration::from_secs(2),
                    false,
                )
            })
            .unwrap();
        let rendered = resized
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("Operation in progress"));
        assert!(!rendered.contains("traffic-masq"));
    }

    #[tokio::test]
    async fn mouse_content_actions_are_ignored_outside_the_content_viewport() {
        let client = ApiClient::new("/socket-that-must-not-be-opened");
        let mut app = TuiApp {
            screen: Screen::Log,
            ..Default::default()
        };
        app.logs.push_back(logs::LogEntry {
            at_unix: 0,
            level: LogLevel::Info,
            message: "keep".into(),
        });
        app.logs_focus = logs::LogFocus::Clear;
        app.ui.input_enabled = true;
        app.ui.content_area = Some(ratatui::layout::Rect::new(0, 3, 80, 17));
        app.ui
            .buttons
            .push((ratatui::layout::Rect::new(1, 22, 10, 1), 1));

        handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: 2,
                row: 22,
                modifiers: KeyModifiers::NONE,
            },
            &client,
            false,
        )
        .await;
        assert_eq!(app.logs.len(), 1);
    }

    #[tokio::test]
    async fn resize_clears_hit_regions_and_blocks_hidden_actions() {
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(40, 10)).unwrap();
        let mut app = TuiApp {
            screen: Screen::Preview,
            ..Default::default()
        };
        app.ui
            .buttons
            .push((ratatui::layout::Rect::new(0, 0, 10, 2), 0));
        terminal
            .draw(|frame| render(frame, &mut app, false))
            .unwrap();
        assert!(app.ui.buttons.is_empty());
        assert!(app.ui.list_area.is_none());
        handle_key(
            &mut app,
            KeyCode::Enter,
            &ApiClient::new("/nonexistent.sock"),
            false,
        )
        .await;
        assert_eq!(app.screen, Screen::Preview);
        assert!(!app.ui.input_enabled);
    }

    #[test]
    fn disconnected_dashboard_does_not_claim_rollback() {
        let mut app = TuiApp {
            screen: Screen::PendingChange,
            pending: Some(PendingNetworkChange {
                token: "keep".into(),
                interface: "eth0".into(),
                rollback_timeout_seconds: 60,
                expires_at_unix: 0,
            }),
            ..Default::default()
        };
        app.dashboard.error = Some("connection lost".into());
        refresh_pending_screen(&mut app);
        assert_eq!(app.pending.as_ref().unwrap().token, "keep");
        assert!(app.message.is_none());
        app.dashboard.error = None;
        refresh_pending_screen(&mut app);
        assert!(app.message.as_ref().unwrap().contains("outcome unknown"));
    }

    #[tokio::test]
    async fn tabs_do_not_discard_editor_and_navigation_preserves_message() {
        let mut app = TuiApp {
            screen: Screen::WifiEditor,
            ..Default::default()
        };
        navigate_to_section(
            &mut app,
            Section::Dashboard,
            &ApiClient::new("/nonexistent.sock"),
            false,
        )
        .await;
        assert_eq!(app.screen, Screen::WifiEditor);
        app.ui.input_enabled = true;
        let message = app.message.clone();
        handle_key(
            &mut app,
            KeyCode::Up,
            &ApiClient::new("/nonexistent.sock"),
            false,
        )
        .await;
        assert_eq!(app.message, message);
    }

    #[test]
    fn adjacent_section_cycles_forward_and_backward_through_all_nine() {
        assert_eq!(
            adjacent_section(Section::Dashboard, true, true, false),
            Section::Interfaces
        );
        assert_eq!(adjacent_section(Section::Vpn, true, true, false), Section::Wifi);
        assert_eq!(
            adjacent_section(Section::Wifi, true, true, false),
            Section::Settings
        );
        assert_eq!(
            adjacent_section(Section::Settings, true, true, false),
            Section::Log
        );
        assert_eq!(
            adjacent_section(Section::Log, true, true, false),
            Section::Dashboard
        );
        assert_eq!(
            adjacent_section(Section::Dashboard, false, true, false),
            Section::Log
        );
        assert_eq!(
            adjacent_section(Section::Interfaces, false, true, false),
            Section::Dashboard
        );
        assert_eq!(
            adjacent_section(Section::Interfaces, true, true, false),
            Section::Dhcp
        );
        assert_eq!(
            adjacent_section(Section::Dhcp, true, true, false),
            Section::DhcpClient
        );
        assert_eq!(
            adjacent_section(Section::DhcpClient, true, true, false),
            Section::Router
        );
    }

    #[test]
    fn adjacent_section_cycles_without_dhcp_client_by_default() {
        assert_eq!(
            adjacent_section(Section::Dhcp, true, false, false),
            Section::Router
        );
        assert_eq!(
            adjacent_section(Section::Router, false, false, false),
            Section::Dhcp
        );
    }

    #[test]
    fn direct_mode_section_navigation_skips_daemon_only_tabs() {
        assert_eq!(
            adjacent_section(Section::Interfaces, true, true, true),
            Section::Log
        );
        assert_eq!(
            adjacent_section(Section::Log, true, true, true),
            Section::Dashboard
        );
        assert_eq!(
            adjacent_section(Section::Dashboard, false, true, true),
            Section::Log
        );
    }

    #[test]
    fn operation_exit_accepts_plain_q_but_normal_quit_stays_ctrl_c() {
        assert!(is_operation_exit_key(KeyEvent::new(
            KeyCode::Char('q'),
            KeyModifiers::NONE,
        )));
        assert!(is_operation_exit_key(KeyEvent::new(
            KeyCode::Char('Q'),
            KeyModifiers::SHIFT,
        )));
        assert!(!is_quit_key(KeyEvent::new(
            KeyCode::Char('q'),
            KeyModifiers::NONE,
        )));
    }

    #[tokio::test]
    async fn navigating_to_disabled_dhcp_client_warns_and_aborts() {
        let mut app = TuiApp::default();
        assert!(!app.show_dhcp_client);
        navigate_to_section(
            &mut app,
            Section::DhcpClient,
            &ApiClient::new("/socket-that-must-not-be-opened"),
            false,
        )
        .await;
        assert_eq!(app.screen, Screen::Dashboard);
        assert!(app
            .message
            .as_ref()
            .unwrap()
            .contains("DHCP Client tab is disabled in Settings"));
    }

    #[test]
    fn section_of_maps_sub_screens_to_their_parent_tab() {
        assert_eq!(section_of(Screen::Dashboard), Section::Dashboard);
        assert_eq!(section_of(Screen::PendingChange), Section::Dashboard);
        assert_eq!(section_of(Screen::InterfaceList), Section::Interfaces);
        assert_eq!(section_of(Screen::InterfaceEditor), Section::Interfaces);
        assert_eq!(section_of(Screen::Preview), Section::Interfaces);
        assert_eq!(section_of(Screen::DhcpInterfaceList), Section::Dhcp);
        assert_eq!(section_of(Screen::DhcpEditor), Section::Dhcp);
        assert_eq!(section_of(Screen::DhcpLeases), Section::Dhcp);
        assert_eq!(section_of(Screen::DhcpClient), Section::DhcpClient);
        assert_eq!(section_of(Screen::Router), Section::Router);
        assert_eq!(section_of(Screen::RouteEditor), Section::Router);
        assert_eq!(section_of(Screen::Forwarding), Section::Router);
        assert_eq!(section_of(Screen::RouterPlan), Section::Router);
        assert_eq!(section_of(Screen::RouterPending), Section::Router);
        assert_eq!(section_of(Screen::Vpn), Section::Vpn);
        assert_eq!(section_of(Screen::VpnImport), Section::Vpn);
        assert_eq!(section_of(Screen::VpnPolicy), Section::Vpn);
        assert_eq!(section_of(Screen::Settings), Section::Settings);
        assert_eq!(section_of(Screen::SettingsPassword), Section::Settings);
        assert_eq!(section_of(Screen::Access), Section::Settings);
        assert_eq!(section_of(Screen::Log), Section::Log);
    }

    #[test]
    fn pending_change_uses_its_origin_section() {
        let mut app = TuiApp {
            screen: Screen::PendingChange,
            pending_return_screen: Screen::InterfaceList,
            ..Default::default()
        };
        assert_eq!(section_of_app(&app), Section::Interfaces);

        app.pending_return_screen = Screen::Wifi;
        assert_eq!(section_of_app(&app), Section::Wifi);

        app.pending_return_screen = Screen::Dashboard;
        assert_eq!(section_of_app(&app), Section::Dashboard);
    }

    #[tokio::test]
    async fn settings_tab_switching_and_editing_arrow_isolation() {
        let mut app = TuiApp {
            screen: Screen::Settings,
            ui: layout::UiLayout {
                input_enabled: true,
                ..Default::default()
            },
            settings: Some(SecurityEditor {
                field: settings::SettingsField::RollbackTimeout,
                active: crate::api::model::SecuritySettings {
                    rollback_timeout_seconds: 60,
                },
                rollback_timeout_input: "60".into(),
                override_active: false,
                restart_required: false,
                remember_session: false,
                remember_minutes_input: "5".into(),
                show_dhcp_client: false,
                confirmation: None,
                cursor: 2,
                editing: false,
            }),
            ..Default::default()
        };
        let client = ApiClient::new("/nonexistent.sock");

        // When not editing, Right navigates to Log section
        handle_key(&mut app, KeyCode::Right, &client, false).await;
        assert_eq!(app.screen, Screen::Log);

        // When on Log, Left navigates back to Settings section
        handle_key(&mut app, KeyCode::Left, &client, false).await;
        assert_eq!(app.screen, Screen::Settings);

        // When not editing, Left navigates to Wifi section
        handle_key(&mut app, KeyCode::Left, &client, false).await;
        assert_eq!(app.screen, Screen::Wifi);

        // Navigate back to Settings
        handle_key(&mut app, KeyCode::Right, &client, false).await;
        assert_eq!(app.screen, Screen::Settings);

        // Enter activates editing mode on RollbackTimeout
        handle_key(&mut app, KeyCode::Enter, &client, false).await;
        assert!(app.settings.as_ref().unwrap().is_editing());

        // When editing, Left moves the cursor and does NOT switch sections
        handle_key(&mut app, KeyCode::Left, &client, false).await;
        assert_eq!(app.screen, Screen::Settings);
        assert_eq!(app.settings.as_ref().unwrap().cursor, 1);

        // When editing, Right moves the cursor and does NOT switch sections
        handle_key(&mut app, KeyCode::Right, &client, false).await;
        assert_eq!(app.screen, Screen::Settings);
        assert_eq!(app.settings.as_ref().unwrap().cursor, 2);

        // Enter finishes editing mode
        handle_key(&mut app, KeyCode::Enter, &client, false).await;
        assert!(!app.settings.as_ref().unwrap().is_editing());

        // Once editing is finished, Right navigates to Log section again
        handle_key(&mut app, KeyCode::Right, &client, false).await;
        assert_eq!(app.screen, Screen::Log);
    }

    #[tokio::test]
    async fn router_screen_preserves_horizontal_navigation_and_requires_tab_for_actions() {
        let mut app = TuiApp {
            screen: Screen::Router,
            ..Default::default()
        };
        app.ui.input_enabled = true;
        let client = ApiClient::new("/nonexistent.sock");

        // When in Router screen with RouteTable focus, Right navigates to VPN
        handle_key(&mut app, KeyCode::Right, &client, false).await;
        assert_eq!(app.screen, Screen::Vpn);

        // Left navigates back to Router
        handle_key(&mut app, KeyCode::Left, &client, false).await;
        assert_eq!(app.screen, Screen::Router);
        assert_eq!(app.router.focus, router::RouterFocus::RouteTable);

        // Scrolling Down does NOT enter Actions; clamps and stays in RouteTable
        handle_key(&mut app, KeyCode::Down, &client, false).await;
        assert_eq!(app.router.focus, router::RouterFocus::RouteTable);

        // Right continues to navigate to VPN
        handle_key(&mut app, KeyCode::Right, &client, false).await;
        assert_eq!(app.screen, Screen::Vpn);

        // Navigate back to Router
        handle_key(&mut app, KeyCode::Left, &client, false).await;
        assert_eq!(app.screen, Screen::Router);

        // Tab enters Actions
        handle_key(&mut app, KeyCode::Tab, &client, false).await;
        assert_eq!(app.router.focus, router::RouterFocus::Actions);
        assert_eq!(app.router.action, router::RouterAction::AddRoute);

        // In Actions, Right moves to next action and does NOT switch sections
        handle_key(&mut app, KeyCode::Right, &client, false).await;
        assert_eq!(app.screen, Screen::Router);
        assert_eq!(app.router.action, router::RouterAction::EditRoute);

        // Tab exits Actions back to RouteTable
        handle_key(&mut app, KeyCode::Tab, &client, false).await;
        assert_eq!(app.router.focus, router::RouterFocus::RouteTable);

        // Now Right navigates to VPN again
        handle_key(&mut app, KeyCode::Right, &client, false).await;
        assert_eq!(app.screen, Screen::Vpn);
    }

    #[test]
    fn format_message_lines_highlights_shift_copy_hint_in_red() {
        let text = "Delete route manually:\nsudo ip route del ...\n\nTo copy, hold down Shift\n\nEsc: close";
        let lines = format_message_lines(text);
        assert_eq!(lines.len(), 6);
        assert_eq!(lines[0].spans[0].style, Style::default());
        assert_eq!(lines[2].spans[0].style, Style::default());
        let hint_line = &lines[3];
        assert_eq!(hint_line.spans.len(), 1);
        assert_eq!(hint_line.spans[0].content, "To copy, hold down Shift");
        assert_eq!(hint_line.spans[0].style, Style::default().fg(theme::BAD));
    }

    #[tokio::test]
    async fn wheel_scrolls_interface_preview_and_clamps_at_both_ends() {
        let client = ApiClient::new("/socket-that-must-not-be-opened");
        let mut app = TuiApp {
            screen: Screen::Preview,
            preview_max_scroll: 2,
            ..Default::default()
        };
        app.ui.input_enabled = true;
        for (kind, expected) in [
            (MouseEventKind::ScrollDown, 1),
            (MouseEventKind::ScrollDown, 2),
            (MouseEventKind::ScrollDown, 2),
            (MouseEventKind::ScrollUp, 1),
            (MouseEventKind::ScrollUp, 0),
            (MouseEventKind::ScrollUp, 0),
        ] {
            handle_mouse(
                &mut app,
                MouseEvent {
                    kind,
                    column: 10,
                    row: 10,
                    modifiers: KeyModifiers::NONE,
                },
                &client,
                false,
            )
            .await;
            assert_eq!(app.preview_scroll, expected);
            assert_eq!(app.screen, Screen::Preview);
        }
    }

    #[tokio::test]
    async fn wheel_cannot_focus_or_execute_log_actions() {
        let client = ApiClient::new("/socket-that-must-not-be-opened");
        let mut app = TuiApp {
            screen: Screen::Log,
            logs_focus: logs::LogFocus::Clear,
            logs_max_scroll: 1,
            ..Default::default()
        };
        app.ui.input_enabled = true;
        app.push_message(LogLevel::Info, "keep this entry");
        let count = app.logs.len();
        for kind in [
            MouseEventKind::ScrollDown,
            MouseEventKind::ScrollDown,
            MouseEventKind::ScrollDown,
            MouseEventKind::ScrollUp,
        ] {
            handle_mouse(
                &mut app,
                MouseEvent {
                    kind,
                    column: 10,
                    row: 10,
                    modifiers: KeyModifiers::NONE,
                },
                &client,
                false,
            )
            .await;
            assert_eq!(app.logs_focus, logs::LogFocus::Scroll);
            handle_key(&mut app, KeyCode::Enter, &client, false).await;
            assert_eq!(app.logs.len(), count);
        }
        assert_eq!(app.logs_scroll, 0);
    }

    #[tokio::test]
    async fn wheel_returns_focus_to_lists_even_when_empty_or_at_the_boundary() {
        let client = ApiClient::new("/socket-that-must-not-be-opened");
        for screen in [Screen::Dashboard, Screen::Vpn, Screen::Router] {
            for kind in [MouseEventKind::ScrollUp, MouseEventKind::ScrollDown] {
                let mut app = TuiApp {
                    screen,
                    ..Default::default()
                };
                app.ui.input_enabled = true;
                app.dashboard_focus = dashboard::DashboardFocus::Interfaces;
                app.vpn.focus = vpn::VpnFocus::Delete;
                app.router.focus = RouterFocus::Actions;
                app.router.action = router::RouterAction::DeleteRoute;
                app.router.sharing_actions_focused = true;
                handle_mouse(
                    &mut app,
                    MouseEvent {
                        kind,
                        column: 10,
                        row: 10,
                        modifiers: KeyModifiers::NONE,
                    },
                    &client,
                    false,
                )
                .await;
                match screen {
                    Screen::Dashboard => {
                        assert_eq!(app.dashboard_focus, dashboard::DashboardFocus::List)
                    }
                    Screen::Vpn => assert_eq!(app.vpn.focus, vpn::VpnFocus::List),
                    Screen::Router => {
                        assert_eq!(app.router.focus, RouterFocus::RouteTable);
                        assert!(!app.router.sharing_actions_focused);
                        assert_eq!(app.router.action, router::RouterAction::DeleteRoute);
                    }
                    _ => unreachable!(),
                }
                assert_eq!(app.screen, screen);
            }
        }
    }

    #[tokio::test]
    async fn mouse_scrolls_message_when_open_and_ignores_navigation() {
        let mut app = TuiApp {
            screen: Screen::Dashboard,
            message_open: true,
            message_scroll: 5,
            ..Default::default()
        };
        app.ui.input_enabled = true;
        let client = ApiClient::new("/nonexistent.sock");

        handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::ScrollUp,
                column: 10,
                row: 10,
                modifiers: crossterm::event::KeyModifiers::NONE,
            },
            &client,
            false,
        )
        .await;
        assert_eq!(app.message_scroll, 4);

        handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::ScrollDown,
                column: 10,
                row: 10,
                modifiers: crossterm::event::KeyModifiers::NONE,
            },
            &client,
            false,
        )
        .await;
        assert_eq!(app.message_scroll, 5);

        handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: 0,
                row: 0,
                modifiers: crossterm::event::KeyModifiers::NONE,
            },
            &client,
            false,
        )
        .await;
        assert_eq!(app.screen, Screen::Dashboard);
        assert!(app.message_open);
    }
}
