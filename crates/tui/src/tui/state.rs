use super::*;

pub(super) struct InterfaceUiState {
    pub(super) selected_interface: usize,
    pub(super) selected_inventory_interface: usize,
    pub(super) editor: Option<InterfaceEditor>,
    pub(super) interface_drafts: HashMap<String, InterfaceEditor>,
    pub(super) preview: Option<InterfaceChangePlanView>,
    pub(super) preview_scroll: usize,
    pub(super) preview_max_scroll: usize,
}

impl Default for InterfaceUiState {
    fn default() -> Self {
        Self {
            selected_interface: 0,
            selected_inventory_interface: 0,
            editor: None,
            interface_drafts: HashMap::new(),
            preview: None,
            preview_scroll: 0,
            preview_max_scroll: 0,
        }
    }
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

pub(super) struct DhcpUiState {
    pub(super) dhcp_editor: Option<DhcpEditor>,
    pub(super) dhcp_leases: Option<DhcpLeasesView>,
    pub(super) dhcp_clients: Vec<DhcpClientStatusView>,
    pub(super) dhcp_interfaces: Vec<String>,
    pub(super) dhcp_client_selected: Option<String>,
    pub(super) dhcp_client_scroll: usize,
    pub(super) dhcp_client_editor: Option<dhcp_client_editor::Editor>,
}

impl Default for DhcpUiState {
    fn default() -> Self {
        Self {
            dhcp_editor: None,
            dhcp_leases: None,
            dhcp_clients: Vec::new(),
            dhcp_interfaces: Vec::new(),
            dhcp_client_selected: None,
            dhcp_client_scroll: 0,
            dhcp_client_editor: None,
        }
    }
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

impl Default for WifiUiState {
    fn default() -> Self {
        Self {
            wifi_stations: None,
            wifi_editor: None,
            wifi_scan: None,
            wifi_profiles: None,
            wifi_ap_profiles: None,
            wifi_profile_editor: None,
            wifi_connect: None,
            ap_drafts: HashMap::new(),
        }
    }
}

pub(super) struct LogViewState {
    pub(super) logs: VecDeque<logs::LogEntry>,
    pub(super) logs_dirty: bool,
    pub(super) logs_clear_confirmation: bool,
    pub(super) logs_scroll: usize,
    pub(super) logs_max_scroll: usize,
    pub(super) logs_focus: logs::LogFocus,
    pub(super) daemon_logs: daemon_logs::View,
}

impl Default for LogViewState {
    fn default() -> Self {
        Self {
            logs: VecDeque::new(),
            logs_dirty: false,
            logs_clear_confirmation: false,
            logs_scroll: 0,
            logs_max_scroll: 0,
            logs_focus: logs::LogFocus::default(),
            daemon_logs: daemon_logs::View::default(),
        }
    }
}

pub(super) struct SettingsUiState {
    pub(super) settings: Option<SecurityEditor>,
    pub(super) dns_defaults: Option<dns_defaults::Editor>,
    pub(super) settings_password: Option<PasswordChangeEditor>,
}

impl Default for SettingsUiState {
    fn default() -> Self {
        Self {
            settings: None,
            dns_defaults: None,
            settings_password: None,
        }
    }
}

pub(super) struct DashboardUiState {
    pub(super) dashboard_pane: dashboard::DashboardPane,
    pub(super) dashboard_statistics_index: usize,
    pub(super) traffic: HashMap<u32, dashboard::TrafficHistory>,
}

impl Default for DashboardUiState {
    fn default() -> Self {
        Self {
            dashboard_pane: dashboard::DashboardPane::default(),
            dashboard_statistics_index: 0,
            traffic: HashMap::new(),
        }
    }
}
