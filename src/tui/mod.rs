use ratatui::text::{Line, Span};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, MouseButton, MouseEvent,
    MouseEventKind,
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
mod input;
mod interfaces;
mod layout;
mod logs;
mod provisioning;
mod router;
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
use router::{RouterData, RouterPendingView};
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
    RouterProvisioning,
    RouterProvisioningNetworks,
    RouterProvisioningConfirm,
    RouterProvisioningPending,
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
enum Section {
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

const SECTIONS: [Section; 9] = [
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

impl Section {
    fn title(self) -> &'static str {
        match self {
            Section::Dashboard => "Dashboard",
            Section::Interfaces => "Interfaces",
            Section::Dhcp => "DHCP Server",
            Section::DhcpClient => "Uplink DHCP",
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
        | Screen::RouterPlan
        | Screen::RouterPending
        | Screen::RouterProvisioning
        | Screen::RouterProvisioningNetworks
        | Screen::RouterProvisioningConfirm
        | Screen::RouterProvisioningPending => Section::Router,
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

fn adjacent_section(current: Section, forward: bool) -> Section {
    let index = SECTIONS
        .iter()
        .position(|section| *section == current)
        .unwrap_or(0);
    let len = SECTIONS.len();
    let next_index = if forward {
        (index + 1) % len
    } else {
        (index + len - 1) % len
    };
    SECTIONS[next_index]
}

struct TuiApp {
    screen: Screen,
    dashboard: DashboardData,
    selected_interface: usize,

    dashboard_focus: dashboard::DashboardFocus,
    api_access: Option<AccessEditor>,
    editor: Option<InterfaceEditor>,
    dhcp_editor: Option<DhcpEditor>,
    dhcp_leases: Option<DhcpLeasesView>,
    dhcp_clients: Vec<DhcpClientStatusView>,
    preview: Option<InterfaceChangePlan>,
    preview_apply_selected: bool,
    preview_scroll: Option<usize>,
    pending: Option<PendingNetworkChange>,
    router: RouterData,
    router_pending: Option<RouterPendingView>,
    provisioning: Option<provisioning::ProvisioningWizard>,
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
    traffic: HashMap<u32, dashboard::TrafficHistory>,
    ui: UiLayout,
    message: Option<String>,
    message_open: bool,
    message_scroll: u16,
    should_quit: bool,
    logs: VecDeque<logs::LogEntry>,
    logs_scroll: usize,
    logs_focus: logs::LogFocus,
}

impl Default for TuiApp {
    fn default() -> Self {
        Self {
            screen: Screen::Dashboard,
            dashboard: DashboardData::default(),
            selected_interface: 0,
            dashboard_focus: dashboard::DashboardFocus::default(),
            api_access: None,
            editor: None,
            dhcp_editor: None,
            dhcp_leases: None,
            dhcp_clients: Vec::new(),
            preview: None,
            preview_apply_selected: true,
            preview_scroll: None,
            pending: None,
            router: RouterData::default(),
            router_pending: None,
            provisioning: None,
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
            traffic: HashMap::new(),
            ui: UiLayout::default(),
            message: None,
            message_open: false,
            message_scroll: 0,
            should_quit: false,
            logs: VecDeque::new(),
            logs_scroll: 0,
            logs_focus: logs::LogFocus::default(),
        }
    }
}

impl TuiApp {
    pub(crate) fn push_message(&mut self, level: logs::LogLevel, text: impl Into<String>) {
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
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
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
    let mut has_authenticated = client.is_authenticated().await;

    while !app.should_quit {
        if !direct && !client.is_authenticated().await {
            if !reauthenticate(terminal, client, pending_deadline(&app), !has_authenticated).await?
            {
                break;
            }
            has_authenticated = true;
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
        let snapshot = terminal
            .draw(|frame| render(frame, &mut app, direct))?
            .buffer
            .clone();
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
            if !direct && app.screen == Screen::RouterProvisioningPending {
                provisioning::refresh_pending(&mut app, client).await;
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
            if !direct && app.screen == Screen::Vpn {
                vpn::load_vpn_data(&mut app, client).await;
            }
        };
        let queued = drive_ui(terminal, snapshot, deadline, refresh, true).await?;

        terminal.draw(|frame| render(frame, &mut app, direct))?;

        let input = if queued.is_some() {
            queued
        } else if event::poll(Duration::from_millis(100))? {
            Some(event::read()?)
        } else {
            None
        };
        if let Some(input) = input {
            let snapshot = terminal
                .draw(|frame| render(frame, &mut app, direct))?
                .buffer
                .clone();
            let deadline = pending_deadline(&app);
            let action = async {
                match input {
                    Event::Key(key) if key.kind == event::KeyEventKind::Press => {
                        handle_key(&mut app, key.code, client, direct).await;
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
    app.pending
        .as_ref()
        .map(|p| p.expires_at_unix)
        .or_else(|| {
            app.router_pending.as_ref().map(|p| {
                p.applied_at_unix
                    .saturating_add(app.router_rollback_timeout_seconds)
            })
        })
        .or_else(|| provisioning::pending_deadline(app))
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
                terminal.draw(|frame| {
                    render_operation_snapshot(
                        frame, &snapshot, deadline, started.elapsed(), cancellable,
                    );
                })?;
                if event::poll(Duration::ZERO)? {
                    let input = event::read()?;
                    if matches!(input, Event::Key(k) if k.kind != event::KeyEventKind::Press) { continue; }
                    if cancellable { return Ok(Some(input)); }
                    if matches!(input, Event::Key(k) if k.code == KeyCode::Char('q')) { exit_requested = Some(input); }
                }
            }
        }
    }
}

/// Keep the notification and footer border intact while an API request runs.
/// Routine refreshes should finish without flashing a progress indicator.
fn render_operation_snapshot(
    frame: &mut ratatui::Frame<'_>,
    snapshot: &ratatui::buffer::Buffer,
    deadline: Option<u64>,
    elapsed: Duration,
    cancellable: bool,
) {
    let area = frame.area();
    if area != snapshot.area {
        return;
    }
    *frame.buffer_mut() = snapshot.clone();
    if (cancellable && elapsed < Duration::from_millis(500))
        || area.width < MIN_TERMINAL_WIDTH
        || area.height < MIN_TERMINAL_HEIGHT
    {
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
                    password.chars().count(),
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
            if direct {
                app.push_message(
                    LogLevel::Warn,
                    "Uplink DHCP management requires the daemon API",
                );
            } else {
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
    let point = (mouse.column, mouse.row);
    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            if let Some(section) = layout::section_at(&app.ui.tabs, point) {
                navigate_to_section(app, section, client, direct).await;
                return;
            }
            if let Some(&(_, slot)) = app
                .ui
                .buttons
                .iter()
                .find(|(rect, _)| layout::point_in_rect(point, *rect))
            {
                focus_action_slot(app, slot);
                let key = if app.screen == Screen::PendingChange && slot == 1 {
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
                            Screen::Vpn => {
                                app.vpn.selected_profile = index;
                                app.vpn.focus = vpn::VpnFocus::List;
                            }
                            Screen::Wifi => {
                                wifi::open_radio(app, index);
                            }
                            Screen::WifiScan => {
                                if let Some(scan) = app.wifi_scan.as_mut() {
                                    scan.selected = index;
                                }
                            }
                            Screen::WifiProfiles => {
                                if let Some(view) = app.wifi_profiles.as_mut() {
                                    view.selected = index;
                                    if index < view.profiles.len() {
                                        view.selected_profile = index;
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
            Screen::Wifi => wifi::handle_wifi_key(app, KeyCode::Up, client).await,
            Screen::WifiScan => wifi::handle_wifi_scan_key(app, KeyCode::Up),
            Screen::WifiProfiles => wifi::handle_wifi_profiles_key(app, KeyCode::Up, client).await,
            Screen::Dashboard | Screen::InterfaceList | Screen::DhcpInterfaceList => {
                app.selected_interface = app.selected_interface.saturating_sub(1);
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

const MIN_TERMINAL_WIDTH: u16 = 60;
const MIN_TERMINAL_HEIGHT: u16 = 15;

fn render(frame: &mut ratatui::Frame<'_>, app: &mut TuiApp, direct: bool) {
    let area = frame.area();
    app.ui = UiLayout::default();
    if area.width < MIN_TERMINAL_WIDTH || area.height < MIN_TERMINAL_HEIGHT {
        frame.render_widget(
            Paragraph::new("Terminal too small — resize to at least 60x15. Q: exit. Pending changes keep their original rollback deadlines.")
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
            Paragraph::new(text)
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
        Screen::RouterPlan => router::render_router_plan(frame, chunks[1], app),
        Screen::RouterPending => router::render_router_pending(frame, chunks[1], app),
        Screen::RouterProvisioning => provisioning::render_wizard(frame, chunks[1], app),
        Screen::RouterProvisioningNetworks => provisioning::render_networks(frame, chunks[1], app),
        Screen::RouterProvisioningConfirm => {
            provisioning::render_confirmation(frame, chunks[1], app)
        }
        Screen::RouterProvisioningPending => provisioning::render_pending(frame, chunks[1], app),
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

    layout::render_footer(frame, chunks[2], app);
}

fn focus_action_slot(app: &mut TuiApp, slot: usize) {
    match app.screen {
        Screen::Dashboard => dashboard::focus_action(app, slot),
        Screen::Access => access::focus_action(app, slot),
        Screen::InterfaceEditor => interfaces::focus_action(app, slot),
        Screen::Preview => interfaces::focus_preview_action(app, slot),
        Screen::DhcpEditor => dhcp::focus_action(app, slot),
        Screen::Router => router::focus_action(app, slot),
        Screen::Vpn => vpn::focus_action(app, slot),
        Screen::VpnPolicy => vpn_policy::focus_action(app, slot),
        Screen::Wifi => wifi::focus_action(app, slot),
        Screen::Settings => settings::focus_action(app, slot),
        Screen::Log => logs::focus_action(app, slot),
        _ => {}
    }
}

async fn handle_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient, direct: bool) {
    if !app.ui.input_enabled {
        if key == KeyCode::Char('q') {
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
        match key {
            KeyCode::Left => {
                let is_editing_settings_text = app.screen == Screen::Settings
                    && app.settings.as_ref().is_some_and(|s| s.is_editing());
                if !is_editing_settings_text {
                    let target = adjacent_section(section_of(app.screen), false);
                    navigate_to_section(app, target, client, direct).await;
                    return;
                }
            }
            KeyCode::Right => {
                let is_editing_settings_text = app.screen == Screen::Settings
                    && app.settings.as_ref().is_some_and(|s| s.is_editing());
                if !is_editing_settings_text {
                    let target = adjacent_section(section_of(app.screen), true);
                    navigate_to_section(app, target, client, direct).await;
                    return;
                }
            }
            _ => {}
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
        Screen::RouterPlan => router::handle_router_plan_key(app, key, client).await,
        Screen::RouterPending => router::handle_router_pending_key(app, key, client).await,
        Screen::RouterProvisioning => provisioning::handle_wizard_key(app, key, client).await,
        Screen::RouterProvisioningNetworks => provisioning::handle_network_key(app, key).await,
        Screen::RouterProvisioningConfirm => {
            provisioning::handle_confirmation_key(app, key, client).await
        }
        Screen::RouterProvisioningPending => {
            provisioning::handle_pending_key(app, key, client).await
        }
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
        app.screen = Screen::Dashboard;
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
        app.screen = Screen::Dashboard;
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
        let mut app = TuiApp::default();
        app.screen = Screen::PendingChange;
        app.pending = Some(crate::core::transaction::PendingNetworkChange {
            token: "test-token".into(),
            interface: "eth0".into(),
            rollback_timeout_seconds: 30,
            expires_at_unix: current_unix_time() + 30,
        });
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(60, 15)).unwrap();
        terminal
            .draw(|frame| render(frame, &mut app, false))
            .unwrap();
        let (rect, _) = *app.ui.buttons.iter().find(|(_, slot)| *slot == 1).unwrap();
        assert!(
            rect.y < 10,
            "rollback must fit inside the content panel at 60x15"
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
        let mut app = TuiApp::default();
        app.screen = Screen::Wifi;
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
    fn footer_message_is_visible_at_supported_sizes() {
        for (width, height) in [(80, 24), (60, 15)] {
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
        for (width, height) in [(80, 24), (60, 15)] {
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

    #[tokio::test]
    async fn resize_clears_hit_regions_and_blocks_hidden_actions() {
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(40, 10)).unwrap();
        let mut app = TuiApp::default();
        app.screen = Screen::Preview;
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
        let mut app = TuiApp::default();
        app.screen = Screen::PendingChange;
        app.pending = Some(PendingNetworkChange {
            token: "keep".into(),
            interface: "eth0".into(),
            rollback_timeout_seconds: 60,
            expires_at_unix: 0,
        });
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
        let mut app = TuiApp::default();
        app.screen = Screen::WifiEditor;
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
            adjacent_section(Section::Dashboard, true),
            Section::Interfaces
        );
        assert_eq!(adjacent_section(Section::Vpn, true), Section::Wifi);
        assert_eq!(adjacent_section(Section::Wifi, true), Section::Settings);
        assert_eq!(adjacent_section(Section::Settings, true), Section::Log);
        assert_eq!(adjacent_section(Section::Log, true), Section::Dashboard);
        assert_eq!(adjacent_section(Section::Dashboard, false), Section::Log);
        assert_eq!(
            adjacent_section(Section::Interfaces, false),
            Section::Dashboard
        );
        assert_eq!(adjacent_section(Section::Interfaces, true), Section::Dhcp);
        assert_eq!(adjacent_section(Section::Dhcp, true), Section::DhcpClient);
        assert_eq!(adjacent_section(Section::DhcpClient, true), Section::Router);
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
        assert_eq!(section_of(Screen::RouterProvisioning), Section::Router);
        assert_eq!(
            section_of(Screen::RouterProvisioningPending),
            Section::Router
        );
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
}
