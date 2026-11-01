use super::*;

#[derive(Default)]
pub(super) struct InterfaceUiState {
    pub(super) selected_interface: usize,
    pub(super) selected_inventory_interface: usize,
    pub(super) editor: Option<InterfaceEditor>,
    pub(super) interface_drafts: HashMap<String, InterfaceEditor>,
    pub(super) preview: Option<InterfaceChangePlanView>,
    pub(super) preview_scroll: usize,
    pub(super) preview_max_scroll: usize,
}

pub(super) struct ConfirmationState {
    pub(super) confirmation_focus: usize,
    pub(super) confirmation_scroll: u16,
    pub(super) pending: Option<PendingNetworkChange>,
    pub(super) pending_return_screen: Screen,
    pub(super) pending_focus: usize,
}

impl Default for ConfirmationState {
    fn default() -> Self {
        Self {
            confirmation_focus: 0,
            confirmation_scroll: 0,
            pending: None,
            pending_return_screen: Screen::Dashboard,
            pending_focus: 0,
        }
    }
}

#[derive(Default)]
pub(super) struct DhcpUiState {
    pub(super) dhcp_editor: Option<DhcpEditor>,
    pub(super) dhcp_leases: Option<DhcpLeasesView>,
    pub(super) dhcp_clients: Vec<DhcpClientStatusView>,
    pub(super) dhcp_interfaces: Vec<String>,
    pub(super) dhcp_client_selected: Option<String>,
    pub(super) dhcp_client_scroll: usize,
    pub(super) dhcp_client_editor: Option<dhcp_client_editor::Editor>,
}

pub(super) struct RouterUiState {
    pub(super) router_settings: Option<router_settings::Editor>,
    pub(super) router_health: router_health::View,
    pub(super) router_pending: Option<RouterPendingView>,
    pub(super) router_pending_return_screen: Screen,
    pub(super) router_pending_plan: Option<traffic_masq_protocol::RouterPlanView>,
    pub(super) router_rollback_timeout_seconds: u64,
    pub(super) forwarding: Option<forwarding::ForwardingEditor>,
    pub(super) port_forwarding: Option<port_forwarding::Editor>,
}

impl Default for RouterUiState {
    fn default() -> Self {
        Self {
            router_settings: None,
            router_health: router_health::View::default(),
            router_pending: None,
            router_pending_return_screen: Screen::Router,
            router_pending_plan: None,
            router_rollback_timeout_seconds: 60,
            forwarding: None,
            port_forwarding: None,
        }
    }
}

#[derive(Default)]
pub(super) struct WifiUiState {
    pub(super) wifi_stations: Option<wifi_stations::View>,
    pub(super) wifi_editor: Option<wifi::WifiEditor>,
    pub(super) wifi_scan: Option<wifi::WifiScanPicker>,
    pub(super) wifi_profiles: Option<wifi::WifiProfilesView>,
    pub(super) wifi_ap_profiles: Option<wifi::WifiApProfilesView>,
    pub(super) wifi_profile_editor: Option<wifi::WifiProfileEditor>,
    pub(super) wifi_connect: Option<wifi::WifiConnectPrompt>,
    pub(super) ap_drafts: HashMap<String, wifi::WifiEditor>,
}

#[derive(Default)]
pub(super) struct LogViewState {
    pub(super) logs: VecDeque<logs::LogEntry>,
    pub(super) logs_dirty: bool,
    pub(super) logs_clear_confirmation: bool,
    pub(super) logs_scroll: usize,
    pub(super) logs_max_scroll: usize,
    pub(super) logs_focus: logs::LogFocus,
    pub(super) daemon_logs: daemon_logs::View,
}

#[derive(Default)]
pub(super) struct SettingsUiState {
    pub(super) settings: Option<SecurityEditor>,
    pub(super) dns_defaults: Option<dns_defaults::Editor>,
    pub(super) settings_password: Option<PasswordChangeEditor>,
}

#[derive(Default)]
pub(super) struct DashboardUiState {
    pub(super) dashboard_pane: dashboard::DashboardPane,
    pub(super) dashboard_statistics_index: usize,
    pub(super) traffic: HashMap<u32, dashboard::TrafficHistory>,
}
