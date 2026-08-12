use std::collections::{HashMap, VecDeque};
use std::io;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
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
mod interfaces;
mod layout;
mod logs;
mod provisioning;
mod router;
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
        Screen::Dashboard | Screen::PendingChange | Screen::Access => Section::Dashboard,
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
        | Screen::WifiProfileEditor => Section::Wifi,
        Screen::Settings | Screen::SettingsPassword => Section::Settings,
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
    settings: Option<SecurityEditor>,
    settings_password: Option<PasswordChangeEditor>,
    traffic: HashMap<u32, dashboard::TrafficHistory>,
    ui: UiLayout,
    message: Option<String>,
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
            settings: None,
            settings_password: None,
            traffic: HashMap::new(),
            ui: UiLayout::default(),
            message: None,
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
        .map_err(|error| anyhow::anyhow!("traffic-masqd is unavailable: {error}"))?;
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
    println!("Device password updated; all active sessions were revoked.");
    Ok(())
}

pub async fn run_tui(socket_path: PathBuf, direct: bool) -> Result<()> {
    let client = ApiClient::new(socket_path);
    if !direct {
        client
            .request(&Request::Ping)
            .await
            .map_err(|error| anyhow::anyhow!("traffic-masqd is unavailable: {error}"))?;
        if client.auth_initialized().await? {
            let mut password = rpassword::prompt_password("Device password: ")?;
            let login_result = client.login(&password).await;
            password.zeroize();
            login_result?;
        } else {
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
        println!("Authenticated");
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_loop(&mut terminal, &client, direct).await;

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if !direct {
        if let Err(error) = client.logout().await {
            tracing::warn!(%error, "failed to revoke TUI session during logout");
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

    while !app.should_quit {
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

        terminal.draw(|frame| render(frame, &mut app, direct))?;

        if event::poll(Duration::from_millis(250))? {
            match event::read()? {
                Event::Key(key) => {
                    handle_key(&mut app, key.code, client, direct).await;
                }
                Event::Mouse(mouse) => {
                    handle_mouse(&mut app, mouse, client, direct).await;
                }
                _ => {}
            }
        }

        if terminal::size().is_err() {
            break;
        }
    }

    Ok(())
}

async fn navigate_to_section(app: &mut TuiApp, section: Section, client: &ApiClient, direct: bool) {
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
                handle_key(app, KeyCode::Enter, client, direct).await;
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
                            }
                            Screen::Vpn => {
                                app.vpn.selected_profile = index;
                                app.vpn.focus = vpn::VpnFocus::List;
                            }
                            Screen::Wifi => {
                                app.wifi.selected = index;
                                app.wifi.selected_radio = index;
                            }
                            Screen::WifiScan => {
                                if let Some(scan) = app.wifi_scan.as_mut() {
                                    scan.selected = index;
                                }
                            }
                            Screen::WifiProfiles => {
                                if let Some(view) = app.wifi_profiles.as_mut() {
                                    view.selected = index;
                                    view.selected_profile = index;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        MouseEventKind::ScrollUp => match app.screen {
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
    if area.width < MIN_TERMINAL_WIDTH || area.height < MIN_TERMINAL_HEIGHT {
        frame.render_widget(
            Paragraph::new("Terminal too small — resize to at least 60x15 to continue")
                .alignment(Alignment::Center)
                .style(Style::default().fg(theme::WARN)),
            area,
        );
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(3),
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
    app.message = None;

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
                let target = adjacent_section(section_of(app.screen), false);
                navigate_to_section(app, target, client, direct).await;
                return;
            }
            KeyCode::Right => {
                let target = adjacent_section(section_of(app.screen), true);
                navigate_to_section(app, target, client, direct).await;
                return;
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

    let still_pending = app
        .dashboard
        .pending_network_changes
        .iter()
        .any(|pending| pending.token == change.token);
    if !still_pending && current_unix_time() >= change.expires_at_unix {
        app.push_message(
            LogLevel::Info,
            "Network change was automatically rolled back",
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

fn format_addresses(status: &InterfaceStatus) -> String {
    let addresses = status
        .ipv4_addresses
        .iter()
        .map(|address| format!("{}/{}", address.address, address.prefix_len))
        .collect::<Vec<_>>()
        .join(", ");
    if addresses.is_empty() {
        "-".to_string()
    } else {
        addresses
    }
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

    let dhcp_interfaces = match client.request(&Request::DhcpStatus).await {
        Ok(Response::DhcpStatus {
            running_interfaces,
            unhealthy_interfaces,
        }) => {
            if !unhealthy_interfaces.is_empty() {
                return DashboardData {
                    interfaces,
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
                error: Some(message),
                ..DashboardData::default()
            }
        }
        Ok(response) => return unexpected_dashboard_response(response),
        Err(error) => {
            return DashboardData {
                interfaces,
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
                dhcp_interfaces,
                error: Some(message),
                ..DashboardData::default()
            }
        }
        Ok(response) => return unexpected_dashboard_response(response),
        Err(error) => {
            return DashboardData {
                interfaces,
                dhcp_interfaces,
                error: Some(error.to_string()),
                ..DashboardData::default()
            }
        }
    };

    DashboardData {
        interfaces,
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

    let mut statuses = Vec::new();
    for interface in interfaces {
        match network.list_ipv4_addresses(&interface.name).await {
            Ok(ipv4_addresses) => statuses.push(InterfaceStatus {
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
        assert_eq!(section_of(Screen::Log), Section::Log);
    }
}
