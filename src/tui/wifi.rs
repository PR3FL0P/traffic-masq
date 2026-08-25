use crossterm::event::KeyCode;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use crate::api::client::ApiClient;
use crate::api::model::{
    InterfaceStatus, Request, Response, WifiClientProfileWriteRequest, WifiEditRequest,
    WifiErrorDetail,
};
use crate::config::{InterfaceRole, WifiBand, WifiChannelWidth, WifiClientSecurity, WifiSecurity};
use crate::wifi::supervisor::WifiHealth;
use crate::wifi::{
    WifiApStatus, WifiClientProfileSummary, WifiClientStatus, WpaSupplicantScanResult,
    WpaSupplicantScanSecurity,
};

use super::layout::panel;
use super::logs::LogLevel;
use super::{theme, Screen, TuiApp};

const DEFAULT_BAND: WifiBand = WifiBand::Ghz2;
const DEFAULT_CHANNEL: u8 = 0;
const DEFAULT_CHANNEL_WIDTH: WifiChannelWidth = WifiChannelWidth::Ht20;
const DEFAULT_MAX_STATIONS: u16 = 32;
const CONFIGURE_DHCP_BY_DEFAULT: bool = true;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WifiRole {
    AccessPoint,
    Client,
    Unknown,
}

#[derive(Debug, Clone)]
pub(crate) struct WifiRow {
    pub(crate) interface: String,
    pub(crate) role: WifiRole,
    pub(crate) ap: Option<WifiApStatus>,
    pub(crate) client: Option<WifiClientStatus>,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct WifiData {
    pub(crate) rows: Vec<WifiRow>,

    pub(crate) selected: usize,

    pub(crate) selected_radio: usize,
    pub(crate) ap_disabled: bool,
    pub(crate) client_disabled: bool,
    pub(crate) error: Option<String>,
}

impl WifiData {
    fn focused_radio(&self) -> Option<&WifiRow> {
        if self.rows.is_empty() {
            None
        } else {
            self.rows.get(self.selected_radio.min(self.rows.len() - 1))
        }
    }

    fn cursor_limit(&self) -> usize {
        let Some(row) = self.focused_radio() else {
            return 0;
        };
        self.rows.len() + actions(row.role).len() - 1
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WifiField {
    #[default]
    Ssid,
    Security,
    Passphrase,
    CountryCode,
    Apply,
}

const WIFI_FIELDS: [WifiField; 5] = [
    WifiField::Ssid,
    WifiField::Security,
    WifiField::Passphrase,
    WifiField::CountryCode,
    WifiField::Apply,
];

fn move_field<T: Copy + PartialEq>(fields: &[T], field: T, forward: bool) -> T {
    let index = fields
        .iter()
        .position(|candidate| *candidate == field)
        .unwrap_or(0);
    fields[if forward {
        (index + 1).min(fields.len() - 1)
    } else {
        index.saturating_sub(1)
    }]
}

#[derive(Debug, Clone)]
pub(crate) struct WifiEditor {
    pub(crate) interface: String,
    pub(crate) field: WifiField,
    pub(crate) ssid: String,
    pub(crate) security: WifiSecurity,
    pub(crate) passphrase: String,
    pub(crate) country_code: String,
    pub(crate) existing: bool,
    pub(crate) configure_dhcp: bool,
}

impl WifiEditor {
    fn from_row(row: &WifiRow) -> Self {
        let (ssid, security, country_code) = row.ap.as_ref().map_or_else(
            || (String::new(), WifiSecurity::Wpa2, String::new()),
            |status| {
                (
                    status.spec.ssid.clone(),
                    status.spec.security,
                    status.spec.country_code.clone().unwrap_or_default(),
                )
            },
        );
        Self {
            interface: row.interface.clone(),
            field: WifiField::Ssid,
            ssid,
            security,
            passphrase: String::new(),
            country_code,
            existing: row.ap.is_some(),
            configure_dhcp: CONFIGURE_DHCP_BY_DEFAULT,
        }
    }

    fn active_value_mut(&mut self) -> Option<&mut String> {
        match self.field {
            WifiField::Ssid => Some(&mut self.ssid),
            WifiField::Passphrase => Some(&mut self.passphrase),
            WifiField::CountryCode => Some(&mut self.country_code),
            _ => None,
        }
    }

    fn country_code(&self) -> Option<String> {
        normalized_country(&self.country_code)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct WifiScanPicker {
    pub(crate) interface: String,
    pub(crate) networks: Vec<WpaSupplicantScanResult>,
    pub(crate) selected: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct WifiProfilesView {
    pub(crate) interface: String,
    pub(crate) profiles: Vec<WifiClientProfileSummary>,

    pub(crate) selected: usize,

    pub(crate) selected_profile: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProfileField {
    Id,
    Ssid,
    Security,
    Country,
    Priority,
    Passphrase,
    Save,
}

const PROFILE_FIELDS: [ProfileField; 7] = [
    ProfileField::Id,
    ProfileField::Ssid,
    ProfileField::Security,
    ProfileField::Country,
    ProfileField::Priority,
    ProfileField::Passphrase,
    ProfileField::Save,
];

#[derive(Debug, Clone)]
pub(crate) struct WifiProfileEditor {
    pub(crate) interface: String,
    pub(crate) original_id: Option<String>,
    pub(crate) field: ProfileField,
    pub(crate) id: String,
    pub(crate) ssid: String,
    pub(crate) security: WifiClientSecurity,
    pub(crate) country: String,
    pub(crate) priority: String,
    pub(crate) passphrase: String,
    pub(crate) has_passphrase: bool,
}

impl WifiProfileEditor {
    fn from_scan(
        interface: String,
        network: &WpaSupplicantScanResult,
    ) -> Result<Self, &'static str> {
        let security = map_scan_security(network.security)?;
        Ok(Self {
            interface,
            original_id: None,
            field: ProfileField::Id,
            id: profile_id_for_ssid(&network.ssid),
            ssid: network.ssid.clone(),
            security,
            country: String::new(),
            priority: "0".into(),
            passphrase: String::new(),
            has_passphrase: false,
        })
    }

    fn from_profile(interface: String, profile: &WifiClientProfileSummary) -> Self {
        Self {
            interface,
            original_id: Some(profile.id.clone()),
            field: ProfileField::Id,
            id: profile.id.clone(),
            ssid: profile.ssid.clone(),
            security: profile.security,
            country: profile.country_code.clone().unwrap_or_default(),
            priority: profile.priority.to_string(),
            passphrase: String::new(),
            has_passphrase: profile.has_passphrase,
        }
    }

    fn active_value_mut(&mut self) -> Option<&mut String> {
        match self.field {
            ProfileField::Id => Some(&mut self.id),
            ProfileField::Ssid => Some(&mut self.ssid),
            ProfileField::Country => Some(&mut self.country),
            ProfileField::Priority => Some(&mut self.priority),
            ProfileField::Passphrase => Some(&mut self.passphrase),
            _ => None,
        }
    }

    fn request(&self) -> Result<WifiClientProfileWriteRequest, &'static str> {
        if self.id.trim().is_empty() || self.ssid.trim().is_empty() {
            return Err("Profile id and SSID are required");
        }
        let priority = self
            .priority
            .trim()
            .parse()
            .map_err(|_| "Priority must be an integer")?;
        if self.security != WifiClientSecurity::Open
            && self.passphrase.is_empty()
            && !self.has_passphrase
        {
            return Err("This security mode requires a passphrase");
        }
        Ok(WifiClientProfileWriteRequest {
            id: self.id.trim().to_string(),
            ssid: self.ssid.clone(),
            country_code: normalized_country(&self.country),
            security: self.security,
            priority,
            passphrase: (!self.passphrase.is_empty()).then(|| self.passphrase.clone()),
            clear_passphrase: self.security == WifiClientSecurity::Open && self.has_passphrase,
        })
    }
}

#[derive(Clone, Copy)]
enum PrimaryAction {
    ConfigureAp,
    Scan,
    Profiles,
    Reconnect,
    Deactivate,
    Reload,
    Refresh,
}

fn actions(role: WifiRole) -> &'static [(PrimaryAction, &'static str)] {
    match role {
        WifiRole::AccessPoint => &[
            (PrimaryAction::ConfigureAp, "Configure access point"),
            (PrimaryAction::Reload, "Reload access point"),
            (PrimaryAction::Deactivate, "Deactivate access point"),
            (PrimaryAction::Refresh, "Refresh"),
        ],
        WifiRole::Client => &[
            (PrimaryAction::Scan, "Scan networks"),
            (PrimaryAction::Profiles, "Saved profiles"),
            (PrimaryAction::Reconnect, "Reconnect"),
            (PrimaryAction::Deactivate, "Deactivate"),
            (PrimaryAction::Refresh, "Refresh"),
        ],
        WifiRole::Unknown => &[(PrimaryAction::Refresh, "Refresh role and status")],
    }
}

fn selected_style(selected: bool) -> Style {
    if selected {
        Style::default()
            .fg(theme::SELECTED_FG)
            .bg(theme::SELECTED_BG)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme::TEXT)
    }
}

pub(crate) fn render_wifi(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let block = panel("Wi-Fi");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let mut lines = Vec::new();
    if let Some(error) = &app.wifi.error {
        lines.push(Line::styled(
            format!("Error: {error}"),
            Style::default().fg(theme::BAD),
        ));
    }
    if app.wifi.rows.is_empty() {
        lines.push(Line::styled(
            "No wireless interfaces found.",
            Style::default().fg(theme::MUTED),
        ));
    }
    for (index, row) in app.wifi.rows.iter().enumerate() {
        lines.push(Line::styled(
            format!(
                "{}{}  {:<12} {}",
                if index == app.wifi.selected {
                    "▶ "
                } else {
                    "  "
                },
                row.interface,
                role_label(row.role),
                describe_row_state(row)
            ),
            selected_style(index == app.wifi.selected),
        ));
    }
    if let Some(row) = app.wifi.focused_radio() {
        lines.push(Line::from(""));
        for (slot, (_, label)) in actions(row.role).iter().enumerate() {
            let cursor = app.wifi.rows.len() + slot;
            let text = format!(
                "{}{}",
                if app.wifi.selected == cursor {
                    "▶ "
                } else {
                    "  "
                },
                label
            );
            app.ui.buttons.push((
                Rect::new(inner.x, inner.y + lines.len() as u16, text.len() as u16, 1),
                slot,
            ));
            lines.push(Line::styled(
                text,
                selected_style(app.wifi.selected == cursor),
            ));
        }
        if row.role == WifiRole::Unknown {
            lines.push(Line::styled("Role is unknown; configure the interface as managed output (AP) or unmanaged input (client) first.", Style::default().fg(theme::WARN)));
        }
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

pub(crate) fn focus_action(app: &mut TuiApp, slot: usize) {
    app.wifi.selected = app.wifi.rows.len() + slot;
}

pub(crate) async fn handle_wifi_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    match key {
        KeyCode::Esc => app.screen = Screen::Dashboard,
        KeyCode::Up => {
            app.wifi.selected = app.wifi.selected.saturating_sub(1);
            if app.wifi.selected < app.wifi.rows.len() {
                app.wifi.selected_radio = app.wifi.selected;
            }
        }
        KeyCode::Down => {
            app.wifi.selected = (app.wifi.selected + 1).min(app.wifi.cursor_limit());
            if app.wifi.selected < app.wifi.rows.len() {
                app.wifi.selected_radio = app.wifi.selected;
            }
        }
        KeyCode::Enter => activate_primary(app, client).await,
        _ => {}
    }
}

async fn activate_primary(app: &mut TuiApp, client: &ApiClient) {
    let Some(row) = app.wifi.focused_radio().cloned() else {
        return;
    };
    if app.wifi.selected < app.wifi.rows.len() {
        app.wifi.selected_radio = app.wifi.selected;
        app.wifi.selected = app.wifi.rows.len();
        return;
    }
    let slot = app.wifi.selected - app.wifi.rows.len();
    let Some((action, _)) = actions(row.role).get(slot).copied() else {
        return;
    };
    match action {
        PrimaryAction::ConfigureAp => {
            if !subsystem_disabled(app, row.role) {
                app.wifi_editor = Some(WifiEditor::from_row(&row));
                app.screen = Screen::WifiEditor;
            }
        }
        PrimaryAction::Scan => start_scan(app, client, row.interface).await,
        PrimaryAction::Profiles => open_profiles(app, client, row.interface).await,
        PrimaryAction::Reconnect => {
            request_simple(
                app,
                client,
                Request::WifiClientReconnect {
                    interface: row.interface,
                },
                "Reconnecting Wi-Fi client",
            )
            .await
        }
        PrimaryAction::Deactivate => {
            let request = if row.role == WifiRole::Client {
                Request::DeactivateWifiClientProfile {
                    interface: row.interface,
                }
            } else {
                Request::DisableWifi {
                    interface: row.interface,
                }
            };
            request_simple(app, client, request, "Wi-Fi deactivated").await;
        }
        PrimaryAction::Reload => {
            request_simple(
                app,
                client,
                Request::WifiReload {
                    interface: row.interface,
                },
                "Access point reloaded",
            )
            .await
        }
        PrimaryAction::Refresh => load_wifi_data(app, client).await,
    }
}

fn subsystem_disabled(app: &mut TuiApp, role: WifiRole) -> bool {
    let disabled = match role {
        WifiRole::AccessPoint => app.wifi.ap_disabled,
        WifiRole::Client => app.wifi.client_disabled,
        WifiRole::Unknown => true,
    };
    if disabled {
        app.push_message(
            LogLevel::Warn,
            "The selected Wi-Fi subsystem is disabled or its role is unknown",
        );
    }
    disabled
}

async fn request_simple(app: &mut TuiApp, client: &ApiClient, request: Request, success: &str) {
    match client.request(&request).await {
        Ok(Response::WifiConfigured { .. })
        | Ok(Response::WifiClientConfigured { .. })
        | Ok(Response::WifiClientDisabled { .. })
        | Ok(Response::WifiDisabled { .. }) => {
            app.push_message(LogLevel::Info, success);
            load_wifi_data(app, client).await;
        }
        Ok(response) => report_unexpected(app, response),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

pub(crate) fn render_wifi_editor(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let Some(editor) = &app.wifi_editor else {
        return;
    };
    let mut lines = Vec::new();
    let values = [
        (WifiField::Ssid, "SSID", editor.ssid.clone()),
        (
            WifiField::Security,
            "Security",
            describe_ap_security(editor.security).into(),
        ),
        (
            WifiField::Passphrase,
            "Passphrase",
            masked(&editor.passphrase, editor.existing),
        ),
        (
            WifiField::CountryCode,
            "Country",
            editor.country_code.clone(),
        ),
        (WifiField::Apply, "", "Apply AP + passphrase + DHCP".into()),
    ];
    for (field, label, value) in values {
        lines.push(Line::styled(
            format!(
                "{}{label:<14}{value}",
                if editor.field == field { "▶ " } else { "  " }
            ),
            selected_style(editor.field == field),
        ));
    }
    lines.push(Line::from(""));
    lines.push(Line::styled("DHCP is enabled by default and is automatically derived/applied from the output IPv4: router and pool are derived; DNS is not advertised.", Style::default().fg(theme::WARN)));
    lines.push(Line::styled(
        "One Enter on Apply provisions the AP, passphrase, and DHCP atomically.",
        Style::default().fg(theme::MUTED),
    ));
    frame.render_widget(
        Paragraph::new(lines).block(panel(&format!("Access point on {}", editor.interface))),
        area,
    );
}

pub(crate) async fn handle_wifi_editor_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    let Some(editor) = app.wifi_editor.as_mut() else {
        app.screen = Screen::Wifi;
        return;
    };
    match key {
        KeyCode::Esc => {
            app.wifi_editor = None;
            app.screen = Screen::Wifi;
        }
        KeyCode::Up => editor.field = move_field(&WIFI_FIELDS, editor.field, false),
        KeyCode::Down => editor.field = move_field(&WIFI_FIELDS, editor.field, true),
        KeyCode::Enter if editor.field == WifiField::Security => {
            editor.security = cycle_ap_security(editor.security)
        }
        KeyCode::Char(' ') if editor.field == WifiField::Security => {
            editor.security = cycle_ap_security(editor.security)
        }
        KeyCode::Enter if editor.field == WifiField::Apply => apply_ap_editor(app, client).await,
        KeyCode::Enter => editor.field = move_field(&WIFI_FIELDS, editor.field, true),
        KeyCode::Backspace => {
            if let Some(value) = editor.active_value_mut() {
                value.pop();
            }
        }
        KeyCode::Char(character) => {
            if let Some(value) = editor.active_value_mut() {
                value.push(character);
            }
        }
        _ => {}
    }
}

fn ap_provision_request(editor: &WifiEditor) -> Request {
    Request::ProvisionWifiAccessPoint {
        interface: editor.interface.clone(),
        settings: WifiEditRequest {
            ssid: editor.ssid.clone(),
            country_code: editor.country_code(),
            band: DEFAULT_BAND,
            channel: DEFAULT_CHANNEL,
            channel_width: DEFAULT_CHANNEL_WIDTH,
            security: editor.security,
            hidden: false,
            client_isolation: false,
            max_stations: DEFAULT_MAX_STATIONS,
        },
        passphrase: (!editor.passphrase.is_empty()).then(|| editor.passphrase.clone()),
        configure_dhcp: editor.configure_dhcp,
    }
}

async fn apply_ap_editor(app: &mut TuiApp, client: &ApiClient) {
    let Some(editor) = app.wifi_editor.clone() else {
        return;
    };
    if editor.ssid.trim().is_empty() {
        app.push_message(LogLevel::Warn, "SSID cannot be empty");
        return;
    }
    if editor.security != WifiSecurity::Open && editor.passphrase.is_empty() && !editor.existing {
        app.push_message(LogLevel::Warn, "This security mode requires a passphrase");
        return;
    }
    match client.request(&ap_provision_request(&editor)).await {
        Ok(Response::WifiAccessPointProvisioned { dhcp, .. }) => {
            app.push_message(
                LogLevel::Info,
                if dhcp.is_some() {
                    "Access point and derived DHCP configured"
                } else {
                    "Access point configured"
                },
            );
            app.wifi_editor = None;
            app.screen = Screen::Wifi;
            load_wifi_data(app, client).await;
        }
        Ok(Response::WifiError { detail }) => {
            app.push_message(LogLevel::Error, format!("{detail:?}"))
        }
        Ok(response) => report_unexpected(app, response),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

async fn start_scan(app: &mut TuiApp, client: &ApiClient, interface: String) {
    match client
        .request(&Request::WifiClientScan {
            interface: interface.clone(),
        })
        .await
    {
        Ok(Response::WifiClientScanResults { mut results, .. }) => {
            sort_scan_results(&mut results);
            app.wifi_scan = Some(WifiScanPicker {
                interface,
                networks: results,
                selected: 0,
            });
            app.screen = Screen::WifiScan;
        }
        Ok(Response::WifiClientError { detail }) => {
            app.push_message(LogLevel::Error, format!("{detail:?}"))
        }
        Ok(response) => report_unexpected(app, response),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

pub(crate) fn render_wifi_scan(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let Some(scan) = &app.wifi_scan else { return };
    let lines = scan
        .networks
        .iter()
        .enumerate()
        .map(|(index, network)| {
            Line::styled(
                format!(
                    "{}{:>4} dBm  {:<32} {}",
                    if index == scan.selected { "▶ " } else { "  " },
                    network.signal_dbm,
                    if network.ssid.is_empty() {
                        "<hidden>"
                    } else {
                        &network.ssid
                    },
                    scan_security_label(network.security)
                ),
                selected_style(index == scan.selected),
            )
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(lines).block(panel(&format!("Scan results on {}", scan.interface))),
        area,
    );
}

pub(crate) fn handle_wifi_scan_key(app: &mut TuiApp, key: KeyCode) {
    let Some(scan) = app.wifi_scan.as_mut() else {
        app.screen = Screen::Wifi;
        return;
    };
    match key {
        KeyCode::Esc => {
            app.wifi_scan = None;
            app.screen = Screen::Wifi;
        }
        KeyCode::Up => scan.selected = scan.selected.saturating_sub(1),
        KeyCode::Down => {
            scan.selected = (scan.selected + 1).min(scan.networks.len().saturating_sub(1))
        }
        KeyCode::Enter => {
            let Some(network) = scan.networks.get(scan.selected) else {
                return;
            };
            match WifiProfileEditor::from_scan(scan.interface.clone(), network) {
                Ok(editor) => {
                    app.wifi_profile_editor = Some(editor);
                    app.screen = Screen::WifiProfileEditor;
                }
                Err(message) => app.push_message(LogLevel::Warn, message),
            }
        }
        _ => {}
    }
}

async fn open_profiles(app: &mut TuiApp, client: &ApiClient, interface: String) {
    match client.request(&Request::ListWifiClientProfiles).await {
        Ok(Response::WifiClientProfiles { mut profiles }) => {
            profiles.sort_by(|a, b| b.priority.cmp(&a.priority).then_with(|| a.id.cmp(&b.id)));
            app.wifi_profiles = Some(WifiProfilesView {
                interface,
                profiles,
                selected: 0,
                selected_profile: 0,
            });
            app.screen = Screen::WifiProfiles;
        }
        Ok(Response::WifiClientProfileError { detail }) => {
            app.push_message(LogLevel::Error, format!("{detail:?}"))
        }
        Ok(response) => report_unexpected(app, response),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

pub(crate) fn render_wifi_profiles(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut TuiApp) {
    let Some(view) = &app.wifi_profiles else {
        return;
    };
    let mut lines = view
        .profiles
        .iter()
        .enumerate()
        .map(|(index, profile)| {
            Line::styled(
                format!(
                    "{}{: <18} {: <28} {: <5} priority {}{}",
                    if index == view.selected { "▶ " } else { "  " },
                    profile.id,
                    profile.ssid,
                    client_security_label(profile.security),
                    profile.priority,
                    if profile.has_passphrase {
                        "  key: saved"
                    } else {
                        ""
                    }
                ),
                selected_style(index == view.selected),
            )
        })
        .collect::<Vec<_>>();
    let action_labels = [
        "Create profile",
        "Edit selected",
        "Activate selected",
        "Delete selected",
        "Deactivate client",
    ];
    for (slot, label) in action_labels.iter().enumerate() {
        let cursor = view.profiles.len() + slot;
        lines.push(Line::styled(
            format!(
                "{}{}",
                if view.selected == cursor {
                    "▶ "
                } else {
                    "  "
                },
                label
            ),
            selected_style(view.selected == cursor),
        ));
    }
    frame.render_widget(
        Paragraph::new(lines).block(panel("Saved Wi-Fi profiles")),
        area,
    );
}

pub(crate) async fn handle_wifi_profiles_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    let Some(view) = app.wifi_profiles.as_mut() else {
        app.screen = Screen::Wifi;
        return;
    };
    let limit = view.profiles.len() + 4;
    match key {
        KeyCode::Esc => {
            app.wifi_profiles = None;
            app.screen = Screen::Wifi;
        }
        KeyCode::Up => {
            view.selected = view.selected.saturating_sub(1);
            if view.selected < view.profiles.len() {
                view.selected_profile = view.selected;
            }
        }
        KeyCode::Down => {
            view.selected = (view.selected + 1).min(limit);
            if view.selected < view.profiles.len() {
                view.selected_profile = view.selected;
            }
        }
        KeyCode::Enter => activate_profile_row(app, client).await,
        _ => {}
    }
}

async fn activate_profile_row(app: &mut TuiApp, client: &ApiClient) {
    let Some(view) = app.wifi_profiles.clone() else {
        return;
    };
    if view.selected < view.profiles.len() {
        return;
    }
    let slot = view.selected - view.profiles.len();
    match slot {
        0 => {
            app.wifi_profile_editor = Some(WifiProfileEditor {
                interface: view.interface,
                original_id: None,
                field: ProfileField::Id,
                id: String::new(),
                ssid: String::new(),
                security: WifiClientSecurity::Wpa2,
                country: String::new(),
                priority: "0".into(),
                passphrase: String::new(),
                has_passphrase: false,
            });
            app.screen = Screen::WifiProfileEditor;
        }
        1 => {
            if let Some(profile) = view.profiles.get(view.selected_profile) {
                app.wifi_profile_editor =
                    Some(WifiProfileEditor::from_profile(view.interface, profile));
                app.screen = Screen::WifiProfileEditor;
            } else {
                app.push_message(LogLevel::Warn, "Select a profile first");
            }
        }
        2 => {
            let request = view
                .profiles
                .get(view.selected_profile)
                .map(|profile| Request::ActivateWifiClientProfile {
                    interface: view.interface.clone(),
                    profile_id: profile.id.clone(),
                })
                .ok_or("No saved profile selected");
            profile_request(app, client, request).await;
        }
        3 => {
            let request = view
                .profiles
                .get(view.selected_profile)
                .map(|profile| Request::DeleteWifiClientProfile {
                    id: profile.id.clone(),
                })
                .ok_or("No saved profile selected");
            profile_request(app, client, request).await;
        }
        4 => {
            profile_request(
                app,
                client,
                Ok(Request::DeactivateWifiClientProfile {
                    interface: view.interface,
                }),
            )
            .await
        }
        _ => {}
    }
}

async fn profile_request(
    app: &mut TuiApp,
    client: &ApiClient,
    request: Result<Request, &'static str>,
) {
    let request = match request {
        Ok(request) => request,
        Err(message) => {
            app.push_message(LogLevel::Warn, message);
            return;
        }
    };
    match client.request(&request).await {
        Ok(Response::WifiClientProfileActivated { .. })
        | Ok(Response::WifiClientProfileDeleted { .. })
        | Ok(Response::WifiClientDisabled { .. }) => {
            app.push_message(LogLevel::Info, "Wi-Fi profile action applied");
            let interface = app
                .wifi_profiles
                .as_ref()
                .map(|v| v.interface.clone())
                .unwrap_or_default();
            open_profiles(app, client, interface).await;
        }
        Ok(Response::WifiClientProfileError { detail }) => {
            app.push_message(LogLevel::Error, format!("{detail:?}"))
        }
        Ok(response) => report_unexpected(app, response),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

pub(crate) fn render_wifi_profile_editor(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    app: &mut TuiApp,
) {
    let Some(editor) = &app.wifi_profile_editor else {
        return;
    };
    let values = [
        (ProfileField::Id, "Id", editor.id.clone()),
        (ProfileField::Ssid, "SSID", editor.ssid.clone()),
        (
            ProfileField::Security,
            "Security",
            client_security_label(editor.security).into(),
        ),
        (ProfileField::Country, "Country", editor.country.clone()),
        (ProfileField::Priority, "Priority", editor.priority.clone()),
        (
            ProfileField::Passphrase,
            "Passphrase",
            masked(&editor.passphrase, editor.has_passphrase),
        ),
        (
            ProfileField::Save,
            "",
            if editor.original_id.is_some() {
                "Update profile".into()
            } else {
                "Create profile".into()
            },
        ),
    ];
    let lines = values
        .into_iter()
        .map(|(field, label, value)| {
            Line::styled(
                format!(
                    "{}{label:<14}{value}",
                    if editor.field == field { "▶ " } else { "  " }
                ),
                selected_style(editor.field == field),
            )
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(lines).block(panel("Wi-Fi profile editor")),
        area,
    );
}

pub(crate) async fn handle_wifi_profile_editor_key(
    app: &mut TuiApp,
    key: KeyCode,
    client: &ApiClient,
) {
    let Some(editor) = app.wifi_profile_editor.as_mut() else {
        app.screen = Screen::WifiProfiles;
        return;
    };
    match key {
        KeyCode::Esc => {
            app.wifi_profile_editor = None;
            app.screen = if app.wifi_profiles.is_some() {
                Screen::WifiProfiles
            } else {
                Screen::WifiScan
            };
        }
        KeyCode::Up => editor.field = move_field(&PROFILE_FIELDS, editor.field, false),
        KeyCode::Down => editor.field = move_field(&PROFILE_FIELDS, editor.field, true),
        KeyCode::Enter if editor.field == ProfileField::Security => {
            editor.security = cycle_client_security(editor.security)
        }
        KeyCode::Char(' ') if editor.field == ProfileField::Security => {
            editor.security = cycle_client_security(editor.security)
        }
        KeyCode::Enter if editor.field == ProfileField::Save => save_profile(app, client).await,
        KeyCode::Enter => editor.field = move_field(&PROFILE_FIELDS, editor.field, true),
        KeyCode::Backspace => {
            if let Some(value) = editor.active_value_mut() {
                value.pop();
            }
        }
        KeyCode::Char(character) => {
            if let Some(value) = editor.active_value_mut() {
                value.push(character);
            }
        }
        _ => {}
    }
}

async fn save_profile(app: &mut TuiApp, client: &ApiClient) {
    let Some(editor) = app.wifi_profile_editor.clone() else {
        return;
    };
    let profile = match editor.request() {
        Ok(profile) => profile,
        Err(message) => {
            app.push_message(LogLevel::Warn, message);
            return;
        }
    };
    let request = if let Some(id) = editor.original_id {
        Request::UpdateWifiClientProfile { id, profile }
    } else {
        Request::CreateWifiClientProfile { profile }
    };
    match client.request(&request).await {
        Ok(Response::WifiClientProfile { .. }) => {
            app.push_message(LogLevel::Info, "Wi-Fi profile saved");
            app.wifi_profile_editor = None;
            open_profiles(app, client, editor.interface).await;
        }
        Ok(Response::WifiClientProfileError { detail }) => {
            app.push_message(LogLevel::Error, format!("{detail:?}"))
        }
        Ok(response) => report_unexpected(app, response),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

pub(crate) async fn load_wifi_data(app: &mut TuiApp, client: &ApiClient) {
    app.wifi.error = None;
    let interfaces = match client.request(&Request::ListInterfaces).await {
        Ok(Response::Interfaces { interfaces }) => interfaces,
        Ok(response) => {
            report_unexpected(app, response);
            return;
        }
        Err(error) => {
            app.wifi.error = Some(error.to_string());
            return;
        }
    };
    let ap = match client.request(&Request::WifiStatus).await {
        Ok(Response::WifiStatus { interfaces }) => {
            app.wifi.ap_disabled = false;
            interfaces
        }
        Ok(Response::WifiError {
            detail: WifiErrorDetail::WifiDisabled,
        }) => {
            app.wifi.ap_disabled = true;
            Vec::new()
        }
        Ok(response) => {
            report_unexpected(app, response);
            Vec::new()
        }
        Err(error) => {
            app.wifi.error = Some(error.to_string());
            Vec::new()
        }
    };
    let clients = match client.request(&Request::WifiClientStatus).await {
        Ok(Response::WifiClientStatus { interfaces }) => {
            app.wifi.client_disabled = false;
            interfaces
        }
        Ok(Response::WifiClientError { .. }) => {
            app.wifi.client_disabled = true;
            Vec::new()
        }
        Ok(response) => {
            report_unexpected(app, response);
            Vec::new()
        }
        Err(error) => {
            app.wifi.error = Some(error.to_string());
            Vec::new()
        }
    };
    let mut rows = build_rows(&interfaces, &ap, &clients);
    for row in rows.iter_mut().filter(|row| row.role == WifiRole::Unknown) {
        if let Ok(Response::InterfaceConfig {
            config: Some(config),
            ..
        }) = client
            .request(&Request::GetInterfaceConfig {
                interface: row.interface.clone(),
            })
            .await
        {
            row.role = role_from_interface(config.role, config.managed);
        }
    }
    app.wifi.rows = rows;
    app.wifi.selected_radio = app
        .wifi
        .selected_radio
        .min(app.wifi.rows.len().saturating_sub(1));
    app.wifi.selected = app.wifi.selected.min(app.wifi.cursor_limit());
}

pub(crate) fn build_rows(
    interfaces: &[InterfaceStatus],
    ap: &[WifiApStatus],
    clients: &[WifiClientStatus],
) -> Vec<WifiRow> {
    interfaces
        .iter()
        .filter(|status| status.interface.is_wireless)
        .map(|status| {
            let interface = status.interface.name.clone();
            let ap_status = ap.iter().find(|item| item.interface == interface).cloned();
            let client = clients
                .iter()
                .find(|item| item.interface == interface)
                .cloned();
            let role = if ap_status.is_some() {
                WifiRole::AccessPoint
            } else if client.is_some() {
                WifiRole::Client
            } else {
                WifiRole::Unknown
            };
            WifiRow {
                interface,
                role,
                ap: ap_status,
                client,
            }
        })
        .collect()
}

fn role_from_interface(role: InterfaceRole, managed: bool) -> WifiRole {
    match (role, managed) {
        (InterfaceRole::Output, true) => WifiRole::AccessPoint,
        (InterfaceRole::Input, false) => WifiRole::Client,
        _ => WifiRole::Unknown,
    }
}

fn sort_scan_results(results: &mut [WpaSupplicantScanResult]) {
    results.sort_by(|a, b| {
        let hidden = a.ssid.is_empty().cmp(&b.ssid.is_empty());
        hidden
            .then_with(|| b.signal_dbm.cmp(&a.signal_dbm))
            .then_with(|| a.ssid.cmp(&b.ssid))
            .then_with(|| a.bssid.to_string().cmp(&b.bssid.to_string()))
    });
}

fn map_scan_security(
    security: WpaSupplicantScanSecurity,
) -> Result<WifiClientSecurity, &'static str> {
    match security {
        WpaSupplicantScanSecurity::Open => Ok(WifiClientSecurity::Open),
        WpaSupplicantScanSecurity::Wpa2Psk | WpaSupplicantScanSecurity::Wpa2Wpa3Transition => {
            Ok(WifiClientSecurity::Wpa2)
        }
        WpaSupplicantScanSecurity::Wpa3Sae => Ok(WifiClientSecurity::Wpa3),
        WpaSupplicantScanSecurity::EnterpriseOrUnsupported => {
            Err("Enterprise Wi-Fi is not supported by this client")
        }
        WpaSupplicantScanSecurity::Unknown => Err("Unknown Wi-Fi security cannot be saved safely"),
    }
}

fn normalized_country(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_uppercase())
}
fn profile_id_for_ssid(ssid: &str) -> String {
    let id = ssid
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    id.trim_matches('-').to_string()
}
fn masked(value: &str, existing: bool) -> String {
    if value.is_empty() {
        if existing {
            "•••••• (saved; leave blank to keep)".into()
        } else {
            "(not set)".into()
        }
    } else {
        "•".repeat(value.chars().count())
    }
}
fn cycle_ap_security(value: WifiSecurity) -> WifiSecurity {
    match value {
        WifiSecurity::Wpa2 => WifiSecurity::Wpa2Wpa3,
        WifiSecurity::Wpa2Wpa3 => WifiSecurity::Wpa3,
        WifiSecurity::Wpa3 => WifiSecurity::Open,
        WifiSecurity::Open => WifiSecurity::Wpa2,
    }
}
fn cycle_client_security(value: WifiClientSecurity) -> WifiClientSecurity {
    match value {
        WifiClientSecurity::Wpa2 => WifiClientSecurity::Wpa3,
        WifiClientSecurity::Wpa3 => WifiClientSecurity::Open,
        WifiClientSecurity::Open => WifiClientSecurity::Wpa2,
    }
}
fn describe_ap_security(value: WifiSecurity) -> &'static str {
    match value {
        WifiSecurity::Wpa2 => "wpa2",
        WifiSecurity::Wpa2Wpa3 => "wpa2/wpa3 transition",
        WifiSecurity::Wpa3 => "wpa3",
        WifiSecurity::Open => "open",
    }
}
fn client_security_label(value: WifiClientSecurity) -> &'static str {
    match value {
        WifiClientSecurity::Wpa2 => "wpa2",
        WifiClientSecurity::Wpa3 => "wpa3",
        WifiClientSecurity::Open => "open",
    }
}
fn scan_security_label(value: WpaSupplicantScanSecurity) -> &'static str {
    match map_scan_security(value) {
        Ok(v) => client_security_label(v),
        Err(_) => "unsupported",
    }
}
fn role_label(role: WifiRole) -> &'static str {
    match role {
        WifiRole::AccessPoint => "AP",
        WifiRole::Client => "client",
        WifiRole::Unknown => "unknown",
    }
}
fn describe_row_state(row: &WifiRow) -> String {
    if let Some(ap) = &row.ap {
        describe_health(&ap.health, &format!("serving {}", ap.spec.ssid))
    } else if let Some(client) = &row.client {
        describe_health(&client.health, &format!("joining {}", client.spec.ssid))
    } else {
        "not configured".into()
    }
}

/// Turns structured health into a short user-facing sentence.
fn describe_health(health: &WifiHealth, ok_description: &str) -> String {
    match health {
        WifiHealth::Healthy => ok_description.to_string(),
        WifiHealth::Starting => format!("{ok_description} — starting…"),
        WifiHealth::Retrying {
            error,
            attempts,
            retry_in_secs,
            competing_managers,
        } => {
            let mut message = format!(
                "✗ not working — {error} (attempt {attempts}{}",
                retry_in_secs
                    .map(|secs| format!(", retrying in {secs}s"))
                    .unwrap_or_default()
            );
            if !competing_managers.is_empty() {
                message.push_str(&format!(
                    "; {} may be controlling this interface",
                    competing_managers.join(" + ")
                ));
            }
            message.push(')');
            message
        }
    }
}
fn report_unexpected(app: &mut TuiApp, response: Response) {
    app.push_message(
        LogLevel::Error,
        format!("Unexpected response: {response:?}"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(
        ssid: &str,
        signal: i32,
        security: WpaSupplicantScanSecurity,
        mac: &str,
    ) -> WpaSupplicantScanResult {
        WpaSupplicantScanResult {
            bssid: mac.parse().unwrap(),
            frequency_mhz: 2412,
            signal_dbm: signal,
            ssid: ssid.into(),
            raw_flags: String::new(),
            security,
        }
    }

    #[test]
    fn scan_sort_is_strongest_first_hidden_last_and_stable_by_identity() {
        let mut rows = vec![
            scan(
                "",
                -20,
                WpaSupplicantScanSecurity::Open,
                "00:00:00:00:00:04",
            ),
            scan(
                "weak",
                -80,
                WpaSupplicantScanSecurity::Open,
                "00:00:00:00:00:03",
            ),
            scan(
                "same",
                -40,
                WpaSupplicantScanSecurity::Open,
                "00:00:00:00:00:02",
            ),
            scan(
                "same",
                -40,
                WpaSupplicantScanSecurity::Open,
                "00:00:00:00:00:01",
            ),
        ];
        sort_scan_results(&mut rows);
        assert_eq!(
            rows.iter().map(|r| r.ssid.as_str()).collect::<Vec<_>>(),
            vec!["same", "same", "weak", ""]
        );
        assert_eq!(rows[0].bssid.to_string(), "00:00:00:00:00:01");
    }

    #[test]
    fn scan_security_maps_supported_and_refuses_enterprise_and_unknown() {
        assert_eq!(
            map_scan_security(WpaSupplicantScanSecurity::Wpa2Psk),
            Ok(WifiClientSecurity::Wpa2)
        );
        assert_eq!(
            map_scan_security(WpaSupplicantScanSecurity::Wpa3Sae),
            Ok(WifiClientSecurity::Wpa3)
        );
        assert!(map_scan_security(WpaSupplicantScanSecurity::EnterpriseOrUnsupported).is_err());
        assert!(map_scan_security(WpaSupplicantScanSecurity::Unknown).is_err());
    }

    #[test]
    fn profile_editor_builds_create_and_update_payload_without_echoing_saved_secret() {
        let editor = WifiProfileEditor {
            interface: "wlan0".into(),
            original_id: Some("home".into()),
            field: ProfileField::Save,
            id: "home".into(),
            ssid: "Home".into(),
            security: WifiClientSecurity::Wpa2,
            country: " pl ".into(),
            priority: "10".into(),
            passphrase: String::new(),
            has_passphrase: true,
        };
        let request = editor.request().unwrap();
        assert_eq!(request.country_code.as_deref(), Some("PL"));
        assert_eq!(request.priority, 10);
        assert!(request.passphrase.is_none());
    }

    #[test]
    fn ap_request_is_atomic_and_enables_derived_dhcp_by_default() {
        let row = WifiRow {
            interface: "wlan0".into(),
            role: WifiRole::AccessPoint,
            ap: None,
            client: None,
        };
        let editor = WifiEditor::from_row(&row);
        assert!(editor.configure_dhcp);
        assert!(matches!(
            ap_provision_request(&editor),
            Request::ProvisionWifiAccessPoint {
                configure_dhcp: true,
                ..
            }
        ));
    }

    #[test]
    fn unconfigured_radio_never_defaults_to_ap_and_role_mapping_is_strict() {
        let status = InterfaceStatus {
            interface: crate::netlink::NetworkInterface {
                index: 1,
                name: "wlan0".into(),
                is_up: true,
                rx_bytes: 0,
                tx_bytes: 0,
                is_wireless: true,
            },
            ipv4_addresses: vec![],
            has_default_route: false,
        };
        assert_eq!(build_rows(&[status], &[], &[])[0].role, WifiRole::Unknown);
        assert_eq!(
            role_from_interface(InterfaceRole::Output, true),
            WifiRole::AccessPoint
        );
        assert_eq!(
            role_from_interface(InterfaceRole::Input, false),
            WifiRole::Client
        );
        assert_eq!(
            role_from_interface(InterfaceRole::Output, false),
            WifiRole::Unknown
        );
    }

    #[test]
    fn primary_navigation_moves_from_radios_into_role_actions() {
        let data = WifiData {
            rows: vec![
                WifiRow {
                    interface: "wlan0".into(),
                    role: WifiRole::Client,
                    ap: None,
                    client: None,
                },
                WifiRow {
                    interface: "wlan1".into(),
                    role: WifiRole::AccessPoint,
                    ap: None,
                    client: None,
                },
            ],
            selected: 2,
            selected_radio: 0,
            ..WifiData::default()
        };
        assert_eq!(data.focused_radio().unwrap().interface, "wlan0");
        assert_eq!(data.cursor_limit(), 6);
        assert_eq!(actions(WifiRole::Client)[0].1, "Scan networks");
    }
}
