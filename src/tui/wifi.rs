use crossterm::event::KeyCode;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use zeroize::Zeroize;

use crate::api::client::ApiClient;
use crate::api::model::{
    DhcpClientConfigRequest, InterfaceEditRequest, InterfaceStatus, Request, Response,
    WifiClientProfileWriteRequest, WifiEditRequest, WifiErrorDetail,
};
use crate::config::{InterfaceRole, WifiBand, WifiChannelWidth, WifiClientSecurity, WifiSecurity};
use crate::wifi::supervisor::WifiHealth;
use crate::wifi::{
    WifiApStatus, WifiClientProfileSummary, WifiClientStatus, WpaSupplicantScanResult,
    WpaSupplicantScanSecurity,
};

use super::layout::{panel, UiLayout};
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
    pub(crate) actions_open: bool,
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

    fn replace_rows(&mut self, rows: Vec<WifiRow>) {
        let previous = self
            .focused_radio()
            .map(|row| (row.interface.clone(), row.role));
        let action = self
            .actions_open
            .then(|| self.selected.saturating_sub(self.rows.len()));
        let retained = previous.as_ref().and_then(|(name, role)| {
            rows.iter()
                .position(|row| &row.interface == name && &row.role == role)
        });
        self.rows = rows;
        self.selected_radio = retained.unwrap_or(0);
        self.actions_open = self.actions_open && retained.is_some();
        self.selected = if self.actions_open {
            self.rows.len() + action.unwrap_or(0)
        } else {
            self.selected_radio
        }
        .min(self.cursor_limit());
    }

    fn cursor_limit(&self) -> usize {
        let Some(row) = self.focused_radio() else {
            return 0;
        };
        if self.actions_open {
            self.rows.len() + actions(row.role).len() - 1
        } else {
            self.rows.len().saturating_sub(1)
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WifiField {
    #[default]
    Ssid,
    Security,
    Passphrase,
    CountryCode,
    Band,
    Channel,
    ChannelWidth,
    Hidden,
    ClientIsolation,
    MaxStations,
    Dhcp,
    Apply,
}

const WIFI_FIELDS: [WifiField; 12] = [
    WifiField::Ssid,
    WifiField::Security,
    WifiField::Passphrase,
    WifiField::CountryCode,
    WifiField::Band,
    WifiField::Channel,
    WifiField::ChannelWidth,
    WifiField::Hidden,
    WifiField::ClientIsolation,
    WifiField::MaxStations,
    WifiField::Dhcp,
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

#[derive(Clone)]
pub(crate) struct WifiEditor {
    pub(crate) interface: String,
    pub(crate) field: WifiField,
    pub(crate) ssid: String,
    pub(crate) security: WifiSecurity,
    pub(crate) passphrase: String,
    pub(crate) country_code: String,
    pub(crate) existing: bool,
    pub(crate) configure_dhcp: bool,
    original_spec: Option<crate::wifi::WifiApSpec>,
    radio_settings: Option<WifiEditRequest>,
    pub(crate) cursor: usize,
}

impl Drop for WifiEditor {
    fn drop(&mut self) {
        self.passphrase.zeroize();
    }
}
impl std::fmt::Debug for WifiEditor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WifiEditor")
            .field("interface", &self.interface)
            .finish_non_exhaustive()
    }
}

impl WifiEditor {
    fn from_row(row: &WifiRow) -> Self {
        let (ssid, security, country_code) = row.ap.as_ref().map_or_else(
            || ("traffic-masq".into(), WifiSecurity::Wpa2, String::new()),
            |status| {
                (
                    status.spec.ssid.clone(),
                    status.spec.security,
                    status.spec.country_code.clone().unwrap_or_default(),
                )
            },
        );
        let cursor = ssid.chars().count();
        Self {
            interface: row.interface.clone(),
            field: WifiField::Ssid,
            ssid,
            security,
            passphrase: String::new(),
            country_code,
            existing: row.ap.is_some(),
            configure_dhcp: row.ap.is_none() && CONFIGURE_DHCP_BY_DEFAULT,
            original_spec: row.ap.as_ref().map(|status| status.spec.clone()),
            radio_settings: None,
            cursor,
        }
    }

    #[allow(dead_code)]
    fn active_value_mut(&mut self) -> Option<&mut String> {
        match self.field {
            WifiField::Ssid => Some(&mut self.ssid),
            WifiField::Passphrase => Some(&mut self.passphrase),
            WifiField::CountryCode => Some(&mut self.country_code),
            _ => None,
        }
    }

    pub(crate) fn active_value(&self) -> Option<&str> {
        match self.field {
            WifiField::Ssid => Some(&self.ssid),
            WifiField::Passphrase => Some(&self.passphrase),
            WifiField::CountryCode => Some(&self.country_code),
            _ => None,
        }
    }

    pub(crate) fn reset_cursor(&mut self) {
        self.cursor = self.active_value().map_or(0, |v| v.chars().count());
    }

    pub(crate) fn active_editor(&mut self) -> Option<super::input::TextEditor<'_>> {
        let cursor = &mut self.cursor;
        match self.field {
            WifiField::Ssid => Some(super::input::TextEditor::new(&mut self.ssid, cursor)),
            WifiField::Passphrase => {
                Some(super::input::TextEditor::new(&mut self.passphrase, cursor))
            }
            WifiField::CountryCode => Some(super::input::TextEditor::new(
                &mut self.country_code,
                cursor,
            )),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WifiProfilesMode {
    Menu,
    Management,
    ProfileActions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WifiProfilesMenuAction {
    Management,
    CreateNew,
}

impl WifiProfilesMenuAction {
    pub(crate) const ALL: [Self; 2] = [Self::Management, Self::CreateNew];

    pub(crate) fn from_index(index: usize) -> Option<Self> {
        Self::ALL.get(index).copied()
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Management => "Management",
            Self::CreateNew => "Create new",
        }
    }

    pub(crate) fn description(self, count_desc: &str) -> String {
        match self {
            Self::Management => format!("Manage existing saved profiles ({count_desc})"),
            Self::CreateNew => "Configure and add a new wireless profile".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WifiProfileAction {
    Activate,
    Edit,
    Delete,
    Deactivate,
    Back,
}

impl WifiProfileAction {
    pub(crate) const ALL: [Self; 5] = [
        Self::Activate,
        Self::Edit,
        Self::Delete,
        Self::Deactivate,
        Self::Back,
    ];

    pub(crate) fn from_index(index: usize) -> Option<Self> {
        Self::ALL.get(index).copied()
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Activate => "Activate / Connect",
            Self::Edit => "Edit profile",
            Self::Delete => "Delete profile",
            Self::Deactivate => "Deactivate client",
            Self::Back => "Back to profile list",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct WifiProfilesView {
    pub(crate) interface: String,
    pub(crate) profiles: Vec<WifiClientProfileSummary>,

    pub(crate) mode: WifiProfilesMode,
    pub(crate) selected: usize,

    pub(crate) selected_profile: usize,
    pub(crate) delete_confirmation: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProfileField {
    Id,
    Ssid,
    Security,
    Country,
    Priority,
    Autoconnect,
    Passphrase,
    Save,
}

const PROFILE_FIELDS: [ProfileField; 8] = [
    ProfileField::Id,
    ProfileField::Ssid,
    ProfileField::Security,
    ProfileField::Country,
    ProfileField::Priority,
    ProfileField::Autoconnect,
    ProfileField::Passphrase,
    ProfileField::Save,
];

#[derive(Clone)]
pub(crate) struct WifiProfileEditor {
    pub(crate) interface: String,
    pub(crate) original_id: Option<String>,
    pub(crate) field: ProfileField,
    pub(crate) id: String,
    pub(crate) ssid: String,
    pub(crate) security: WifiClientSecurity,
    pub(crate) country: String,
    pub(crate) priority: String,
    pub(crate) autoconnect: bool,
    pub(crate) passphrase: String,
    pub(crate) has_passphrase: bool,
    pub(crate) cursor: usize,
}

impl Drop for WifiProfileEditor {
    fn drop(&mut self) {
        self.passphrase.zeroize();
    }
}
impl std::fmt::Debug for WifiProfileEditor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WifiProfileEditor")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl WifiProfileEditor {
    fn from_scan(
        interface: String,
        network: &WpaSupplicantScanResult,
    ) -> Result<Self, &'static str> {
        let security = map_scan_security(network.security)?;
        let id = profile_id_for_ssid(&network.ssid);
        let cursor = id.chars().count();
        Ok(Self {
            interface,
            original_id: None,
            field: ProfileField::Id,
            id,
            ssid: network.ssid.clone(),
            security,
            country: String::new(),
            priority: "0".into(),
            autoconnect: false,
            passphrase: String::new(),
            has_passphrase: false,
            cursor,
        })
    }

    fn from_profile(interface: String, profile: &WifiClientProfileSummary) -> Self {
        let cursor = profile.id.chars().count();
        Self {
            interface,
            original_id: Some(profile.id.clone()),
            field: ProfileField::Id,
            id: profile.id.clone(),
            ssid: profile.ssid.clone(),
            security: profile.security,
            country: profile.country_code.clone().unwrap_or_default(),
            priority: profile.priority.to_string(),
            autoconnect: profile.autoconnect,
            passphrase: String::new(),
            has_passphrase: profile.has_passphrase,
            cursor,
        }
    }

    #[allow(dead_code)]
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

    pub(crate) fn active_value(&self) -> Option<&str> {
        match self.field {
            ProfileField::Id => Some(&self.id),
            ProfileField::Ssid => Some(&self.ssid),
            ProfileField::Country => Some(&self.country),
            ProfileField::Priority => Some(&self.priority),
            ProfileField::Passphrase => Some(&self.passphrase),
            _ => None,
        }
    }

    pub(crate) fn reset_cursor(&mut self) {
        self.cursor = self.active_value().map_or(0, |v| v.chars().count());
    }

    pub(crate) fn active_editor(&mut self) -> Option<super::input::TextEditor<'_>> {
        let cursor = &mut self.cursor;
        match self.field {
            ProfileField::Id => Some(super::input::TextEditor::new(&mut self.id, cursor)),
            ProfileField::Ssid => Some(super::input::TextEditor::new(&mut self.ssid, cursor)),
            ProfileField::Country => Some(super::input::TextEditor::new(&mut self.country, cursor)),
            ProfileField::Priority => {
                Some(super::input::TextEditor::new(&mut self.priority, cursor))
            }
            ProfileField::Passphrase => {
                Some(super::input::TextEditor::new(&mut self.passphrase, cursor))
            }
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
            autoconnect: self.autoconnect,
            passphrase: (!self.passphrase.is_empty()).then(|| self.passphrase.clone()),
            clear_passphrase: self.security == WifiClientSecurity::Open && self.has_passphrase,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WifiIpChoice {
    Dhcp,
    KeepStatic,
    NewStatic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WifiConnectField {
    Choice(WifiIpChoice),
    StaticCidr,
    Submit,
    Cancel,
}

#[derive(Debug, Clone)]
pub(crate) struct WifiConnectPrompt {
    pub(crate) interface: String,
    pub(crate) profile_id: String,
    pub(crate) ssid: String,
    pub(crate) current_static_ip: Option<String>,
    pub(crate) choice: WifiIpChoice,
    pub(crate) field: WifiConnectField,
    pub(crate) static_cidr: String,
    pub(crate) cursor: usize,
}

impl WifiConnectPrompt {
    pub(crate) fn new(
        interface: String,
        profile_id: String,
        ssid: String,
        current_static_ip: Option<String>,
    ) -> Self {
        let initial_cidr = current_static_ip.clone().unwrap_or_default();
        let cursor = initial_cidr.len();
        Self {
            interface,
            profile_id,
            ssid,
            current_static_ip,
            choice: WifiIpChoice::Dhcp,
            field: WifiConnectField::Choice(WifiIpChoice::Dhcp),
            static_cidr: initial_cidr,
            cursor,
        }
    }

    pub(crate) fn available_choices(&self) -> Vec<WifiIpChoice> {
        if self.current_static_ip.is_some() {
            vec![
                WifiIpChoice::Dhcp,
                WifiIpChoice::KeepStatic,
                WifiIpChoice::NewStatic,
            ]
        } else {
            vec![WifiIpChoice::Dhcp, WifiIpChoice::NewStatic]
        }
    }

    pub(crate) fn focusable_fields(&self) -> Vec<WifiConnectField> {
        let mut fields = Vec::new();
        for c in self.available_choices() {
            fields.push(WifiConnectField::Choice(c));
        }
        if self.choice == WifiIpChoice::NewStatic {
            fields.push(WifiConnectField::StaticCidr);
        }
        fields.push(WifiConnectField::Submit);
        fields.push(WifiConnectField::Cancel);
        fields
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
    let radio_start = usize::from(app.wifi.error.is_some());
    let mut button_rows = Vec::new();
    if app.wifi.actions_open {
        if let Some(row) = app.wifi.focused_radio() {
            lines.push(Line::from(format!("Actions for {}", row.interface)));
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
                button_rows.push((lines.len(), slot));
                lines.push(Line::styled(
                    text,
                    selected_style(app.wifi.selected == cursor),
                ));
            }
            if row.role == WifiRole::Unknown {
                lines.push(Line::styled("Role is unknown; configure the interface as managed output (AP) or managed input (client) first.", Style::default().fg(theme::WARN)));
            }
        }
    }
    if let Some(row) = app.wifi.focused_radio() {
        let (competing, advice_opt) = match (&row.ap, &row.client) {
            (Some(ap), _) => match &ap.health {
                WifiHealth::Retrying {
                    competing_managers,
                    advice,
                    ..
                } if !competing_managers.is_empty() => {
                    (Some(competing_managers), advice.as_deref())
                }
                _ => (None, None),
            },
            (_, Some(client)) => match &client.health {
                WifiHealth::Retrying {
                    competing_managers,
                    advice,
                    ..
                } if !competing_managers.is_empty() => {
                    (Some(competing_managers), advice.as_deref())
                }
                _ => (None, None),
            },
            _ => (None, None),
        };

        if let Some(competing) = competing {
            lines.push(Line::from(""));
            lines.push(Line::styled(
                format!(
                    "⚠ Conflict: {} may be controlling {}",
                    competing.join(" + "),
                    row.interface
                ),
                Style::default()
                    .fg(theme::WARN)
                    .add_modifier(Modifier::BOLD),
            ));
            lines.push(Line::styled(
                "How to release this interface:",
                Style::default().fg(theme::TEXT),
            ));
            let advice_text = advice_opt.map(|s| s.to_string()).unwrap_or_else(|| {
                crate::wifi::process::format_competing_manager_advice(competing, &row.interface)
            });
            for line in advice_text.lines() {
                lines.push(Line::styled(
                    format!("  {line}"),
                    Style::default().fg(theme::MUTED),
                ));
            }
        }
    }
    let selected_line = radio_start + app.wifi.selected + usize::from(app.wifi.actions_open);
    let offset = selected_line.saturating_sub(inner.height.saturating_sub(1) as usize);
    let visible_start = offset.max(radio_start);
    let visible_end = (offset + inner.height as usize).min(radio_start + app.wifi.rows.len());
    if visible_start < visible_end {
        app.ui.list_area = Some(Rect::new(
            inner.x,
            inner.y + (visible_start - offset) as u16,
            inner.width,
            (visible_end - visible_start) as u16,
        ));
        app.ui.list_scroll_offset = visible_start - radio_start;
    }
    app.ui.list_count = app.wifi.rows.len();
    app.ui.list_row_height = 1;
    for (line, slot) in button_rows {
        if line >= offset && line < offset + inner.height as usize {
            app.ui.buttons.push((
                Rect::new(inner.x, inner.y + (line - offset) as u16, inner.width, 1),
                slot,
            ));
        }
    }
    frame.render_widget(
        Paragraph::new(lines.into_iter().skip(offset).collect::<Vec<_>>()),
        inner,
    );
}

pub(crate) fn open_radio(app: &mut TuiApp, index: usize) {
    if index < app.wifi.rows.len() {
        app.wifi.selected_radio = index;
        app.wifi.actions_open = true;
        app.wifi.selected = app.wifi.rows.len();
    }
}

pub(crate) fn focus_action(app: &mut TuiApp, slot: usize) {
    app.wifi.selected = app.wifi.rows.len() + slot;
}

pub(crate) async fn handle_wifi_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    match key {
        KeyCode::Esc if app.wifi.actions_open => {
            app.wifi.actions_open = false;
            app.wifi.selected = app.wifi.selected_radio;
        }
        KeyCode::Esc => app.screen = Screen::Dashboard,
        KeyCode::Tab | KeyCode::BackTab => {
            if app.wifi.actions_open {
                app.wifi.actions_open = false;
                app.wifi.selected = app.wifi.selected_radio;
            } else {
                open_radio(app, app.wifi.selected_radio);
            }
        }
        KeyCode::Home => {
            app.wifi.selected = if app.wifi.actions_open {
                app.wifi.rows.len()
            } else {
                0
            };
            if !app.wifi.actions_open {
                app.wifi.selected_radio = 0;
            }
        }
        KeyCode::End => {
            app.wifi.selected = app.wifi.cursor_limit();
            if !app.wifi.actions_open {
                app.wifi.selected_radio = app.wifi.selected;
            }
        }
        KeyCode::Up | KeyCode::Left => {
            if app.wifi.actions_open && app.wifi.selected == app.wifi.rows.len() {
                app.wifi.actions_open = false;
                app.wifi.selected = app.wifi.selected_radio;
                return;
            }
            app.wifi.selected = app.wifi.selected.saturating_sub(1);
            if app.wifi.selected < app.wifi.rows.len() {
                app.wifi.selected_radio = app.wifi.selected;
                app.wifi.actions_open = false;
            }
        }
        KeyCode::Down | KeyCode::Right => {
            app.wifi.selected = (app.wifi.selected + 1).min(app.wifi.cursor_limit());
            if app.wifi.selected < app.wifi.rows.len() {
                app.wifi.selected_radio = app.wifi.selected;
                app.wifi.actions_open = false;
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
        open_radio(app, app.wifi.selected);

        return;
    }
    let slot = app.wifi.selected - app.wifi.rows.len();
    let Some((action, _)) = actions(row.role).get(slot).copied() else {
        return;
    };
    match action {
        PrimaryAction::ConfigureAp => {
            if !subsystem_disabled(app, row.role) {
                match client
                    .request(&Request::GetInterfaceConfig {
                        interface: row.interface.clone(),
                    })
                    .await
                {
                    Ok(Response::InterfaceConfig {
                        config: Some(config),
                        ..
                    }) => {
                        let spec = match crate::wifi::WifiApSpec::from_interface_config(
                            &row.interface,
                            &config,
                        ) {
                            Ok(spec) => spec,
                            Err(error) => {
                                app.push_message(LogLevel::Error, error.to_string());
                                return;
                            }
                        };
                        let mut editor = WifiEditor::from_row(&row);
                        editor.existing = spec.is_some();
                        editor.configure_dhcp = spec.is_none() && config.dhcp.is_none();
                        if let Some(spec) = &spec {
                            editor.ssid = spec.ssid.clone();
                            editor.security = spec.security;
                            editor.country_code = spec.country_code.clone().unwrap_or_default();
                        }
                        editor.original_spec = spec;
                        app.wifi_editor = Some(editor);
                        app.screen = Screen::WifiEditor;
                    }
                    Ok(response) => report_unexpected(app, response),
                    Err(error) => app.push_message(LogLevel::Error, error.to_string()),
                }
            }
        }
        PrimaryAction::Scan => start_scan(app, client, row.interface).await,
        PrimaryAction::Profiles => {
            open_profiles(app, client, row.interface, WifiProfilesMode::Menu).await
        }
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
    let settings = ap_settings(editor);
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
        (WifiField::Band, "Band", settings.band.to_string()),
        (
            WifiField::Channel,
            "Channel",
            if settings.channel == 0 {
                "Auto".into()
            } else {
                settings.channel.to_string()
            },
        ),
        (
            WifiField::ChannelWidth,
            "Width",
            format!("{:?}", settings.channel_width),
        ),
        (
            WifiField::Hidden,
            "Hidden SSID",
            settings.hidden.to_string(),
        ),
        (
            WifiField::ClientIsolation,
            "Isolation",
            settings.client_isolation.to_string(),
        ),
        (
            WifiField::MaxStations,
            "Max clients",
            settings.max_stations.to_string(),
        ),
        (
            WifiField::Dhcp,
            "Configure DHCP",
            editor.configure_dhcp.to_string(),
        ),
        (
            WifiField::Apply,
            "",
            if editor.configure_dhcp {
                "Apply AP + passphrase + DHCP"
            } else {
                "Apply AP; preserve DHCP"
            }
            .into(),
        ),
    ];
    for (field, label, value) in values {
        let active = editor.field == field;
        let style = selected_style(active);
        let prefix = format!("{}{label:<14}", if active { "▶ " } else { "  " });
        let mut spans = vec![Span::styled(prefix, style)];
        if active && matches!(field, WifiField::Ssid | WifiField::CountryCode) {
            spans.extend(super::input::render_value_with_cursor(
                &value,
                editor.cursor,
                true,
                style,
            ));
        } else if active && field == WifiField::Passphrase {
            if editor.passphrase.is_empty() && editor.existing {
                spans.push(Span::styled(
                    "•••••• (saved; leave blank to keep) ",
                    Style::default().fg(theme::MUTED),
                ));
                spans.extend(super::input::render_masked_with_cursor(
                    0, 0, true, '•', style,
                ));
            } else {
                spans.extend(super::input::render_masked_with_cursor(
                    editor.passphrase.chars().count(),
                    editor.cursor,
                    true,
                    '•',
                    style,
                ));
            }
        } else {
            spans.push(Span::styled(value, style));
        }
        lines.push(Line::from(spans));
    }
    lines.push(Line::from(""));
    lines.push(Line::styled(
        if editor.configure_dhcp {
            "Creates derived DHCP from output IPv4; DNS is not advertised."
        } else {
            "Existing DHCP is preserved. Enter/Space changes radio options; +/- adjusts client limit."
        },
        Style::default().fg(theme::WARN),
    ));
    lines.push(Line::styled(
        "Apply updates the AP immediately; no commit-confirm timer is provided by this API.",
        Style::default().fg(theme::MUTED),
    ));
    frame.render_widget(
        Paragraph::new(
            lines
                .clone()
                .into_iter()
                .skip(super::layout::focused_lines_offset(
                    &lines,
                    area.height.saturating_sub(2),
                ))
                .collect::<Vec<_>>(),
        )
        .block(panel(&format!("Access point on {}", editor.interface))),
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
        KeyCode::Up => {
            editor.field = move_field(&WIFI_FIELDS, editor.field, false);
            editor.reset_cursor();
        }
        KeyCode::Down => {
            editor.field = move_field(&WIFI_FIELDS, editor.field, true);
            editor.reset_cursor();
        }
        KeyCode::Enter if editor.field == WifiField::Security => {
            editor.security = cycle_ap_security(editor.security)
        }
        KeyCode::Char(' ') if editor.field == WifiField::Security => {
            editor.security = cycle_ap_security(editor.security)
        }
        KeyCode::Enter | KeyCode::Char(' ') | KeyCode::Char('+') | KeyCode::Char('-')
            if matches!(
                editor.field,
                WifiField::Band
                    | WifiField::Channel
                    | WifiField::ChannelWidth
                    | WifiField::Hidden
                    | WifiField::ClientIsolation
                    | WifiField::MaxStations
                    | WifiField::Dhcp
            ) =>
        {
            let mut settings = ap_settings(editor);
            match editor.field {
                WifiField::Band => {
                    settings.band = if settings.band == WifiBand::Ghz2 {
                        WifiBand::Ghz5
                    } else {
                        WifiBand::Ghz2
                    };
                    settings.channel = 0;
                    settings.channel_width = WifiChannelWidth::Ht20;
                }
                WifiField::Channel => {
                    settings.channel = settings
                        .band
                        .channels()
                        .iter()
                        .copied()
                        .find(|c| *c > settings.channel)
                        .unwrap_or(0);
                }
                WifiField::ChannelWidth => {
                    settings.channel_width = match settings.channel_width {
                        WifiChannelWidth::Ht20 => WifiChannelWidth::Ht40,
                        WifiChannelWidth::Ht40 if settings.band == WifiBand::Ghz5 => {
                            WifiChannelWidth::Vht80
                        }
                        _ => WifiChannelWidth::Ht20,
                    }
                }
                WifiField::Hidden => settings.hidden = !settings.hidden,
                WifiField::ClientIsolation => {
                    settings.client_isolation = !settings.client_isolation
                }
                WifiField::MaxStations => {
                    settings.max_stations = if key == KeyCode::Char('-') {
                        settings.max_stations.saturating_sub(1).max(1)
                    } else {
                        settings.max_stations.saturating_add(1)
                    }
                }
                WifiField::Dhcp => editor.configure_dhcp = !editor.configure_dhcp,
                _ => unreachable!(),
            }
            editor.radio_settings = Some(settings);
        }
        KeyCode::Enter if editor.field == WifiField::Apply => apply_ap_editor(app, client).await,
        KeyCode::Enter => {
            editor.field = move_field(&WIFI_FIELDS, editor.field, true);
            editor.reset_cursor();
        }
        other => {
            if let Some(mut text_editor) = editor.active_editor() {
                text_editor.handle_key(other);
            }
        }
    }
}

fn ap_provision_request(editor: &WifiEditor) -> Request {
    Request::ProvisionWifiAccessPoint {
        interface: editor.interface.clone(),
        settings: ap_settings(editor),
        passphrase: (!editor.passphrase.is_empty()).then(|| editor.passphrase.clone()),
        configure_dhcp: editor.configure_dhcp,
    }
}

fn ap_settings(editor: &WifiEditor) -> WifiEditRequest {
    let mut settings = editor
        .radio_settings
        .clone()
        .unwrap_or_else(|| WifiEditRequest {
            ssid: editor.ssid.clone(),
            country_code: editor.country_code(),
            band: editor
                .original_spec
                .as_ref()
                .map_or(DEFAULT_BAND, |s| s.band),
            channel: editor
                .original_spec
                .as_ref()
                .map_or(DEFAULT_CHANNEL, |s| s.channel),
            channel_width: editor
                .original_spec
                .as_ref()
                .map_or(DEFAULT_CHANNEL_WIDTH, |s| s.channel_width),
            security: editor.security,
            hidden: editor.original_spec.as_ref().is_some_and(|s| s.hidden),
            client_isolation: editor
                .original_spec
                .as_ref()
                .is_some_and(|s| s.client_isolation),
            max_stations: editor
                .original_spec
                .as_ref()
                .map_or(DEFAULT_MAX_STATIONS, |s| s.max_stations),
        });
    settings.ssid = editor.ssid.clone();
    settings.country_code = editor.country_code();
    settings.security = editor.security;
    settings
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
            app.wifi_profiles = None;
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
    let block = panel(&format!("Scan results on {}", scan.interface));
    let inner = block.inner(area);
    let offset = scan
        .selected
        .saturating_sub(inner.height.saturating_sub(1) as usize);
    app.ui.list_area = Some(inner);
    app.ui.list_count = scan.networks.len();
    app.ui.list_row_height = 1;
    app.ui.list_scroll_offset = offset;
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
        Paragraph::new(lines.into_iter().skip(offset).collect::<Vec<_>>()).block(block),
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
        KeyCode::Home => scan.selected = 0,
        KeyCode::End => scan.selected = scan.networks.len().saturating_sub(1),
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

fn open_create_profile(app: &mut TuiApp, interface: String) {
    app.wifi_profile_editor = Some(WifiProfileEditor {
        interface,
        original_id: None,
        field: ProfileField::Id,
        id: String::new(),
        ssid: String::new(),
        security: WifiClientSecurity::Wpa2,
        country: String::new(),
        priority: "0".into(),
        autoconnect: false,
        passphrase: String::new(),
        has_passphrase: false,
        cursor: 0,
    });
    app.screen = Screen::WifiProfileEditor;
}

async fn open_profiles(
    app: &mut TuiApp,
    client: &ApiClient,
    interface: String,
    mode: WifiProfilesMode,
) {
    match client.request(&Request::ListWifiClientProfiles).await {
        Ok(Response::WifiClientProfiles { mut profiles }) => {
            profiles.sort_by(|a, b| b.priority.cmp(&a.priority).then_with(|| a.id.cmp(&b.id)));
            let previous = app.wifi_profiles.as_ref();
            let previous_id = previous
                .and_then(|view| view.profiles.get(view.selected_profile))
                .map(|profile| &profile.id);
            let selected_profile = previous_id
                .and_then(|id| profiles.iter().position(|profile| &profile.id == id))
                .unwrap_or_else(|| {
                    previous
                        .map_or(0, |view| view.selected_profile)
                        .min(profiles.len().saturating_sub(1))
                });
            let mode = if profiles.is_empty() && mode == WifiProfilesMode::ProfileActions {
                WifiProfilesMode::Management
            } else {
                mode
            };
            let selected = match mode {
                WifiProfilesMode::Menu => 0,
                WifiProfilesMode::Management => selected_profile,
                WifiProfilesMode::ProfileActions => 0,
            };
            app.wifi_profiles = Some(WifiProfilesView {
                delete_confirmation: None,
                interface,
                profiles,
                mode,
                selected,
                selected_profile,
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
    match view.mode {
        WifiProfilesMode::Menu => render_profiles_menu(frame, area, &mut app.ui, view),
        WifiProfilesMode::Management => render_profiles_management(frame, area, &mut app.ui, view),
        WifiProfilesMode::ProfileActions => render_profile_actions(frame, area, &mut app.ui, view),
    }
}

fn render_profiles_menu(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    ui: &mut UiLayout,
    view: &WifiProfilesView,
) {
    let block = panel(&format!("Saved profiles — {}", view.interface));
    let inner = block.inner(area);

    ui.list_area = Some(inner);
    ui.list_count = WifiProfilesMenuAction::ALL.len();
    ui.list_row_height = 1;
    ui.list_scroll_offset = 0;

    let count = view.profiles.len();
    let count_desc = match count {
        0 => "no profiles saved".to_string(),
        1 => "1 profile saved".to_string(),
        n => format!("{n} profiles saved"),
    };

    let mut lines = Vec::new();
    for (idx, action) in WifiProfilesMenuAction::ALL.iter().enumerate() {
        let is_selected = view.selected == idx;
        lines.push(Line::styled(
            format!(
                "{}{:<16} {}",
                if is_selected { "▶ " } else { "  " },
                action.label(),
                action.description(&count_desc)
            ),
            selected_style(is_selected),
        ));
    }

    lines.push(Line::from(""));
    lines.push(Line::styled(
        "  ↑/↓: navigate │ Enter: select │ Esc: back",
        Style::default().fg(theme::MUTED),
    ));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_profiles_management(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    ui: &mut UiLayout,
    view: &WifiProfilesView,
) {
    let target = view
        .profiles
        .get(view.selected_profile)
        .map_or("none", |p| p.id.as_str());
    let title = if let Some(id) = &view.delete_confirmation {
        format!("Delete {id}? Y: confirm, any other key: cancel")
    } else {
        format!("Saved profiles — Management (selected: {target})")
    };
    let block = panel(&title);
    let inner = block.inner(area);

    if view.profiles.is_empty() {
        ui.list_area = Some(inner);
        ui.list_count = 0;
        ui.list_row_height = 1;
        ui.list_scroll_offset = 0;

        let lines = vec![
            Line::styled(
                "  No saved Wi-Fi profiles found.",
                Style::default().fg(theme::MUTED),
            ),
            Line::from(""),
            Line::styled(
                "  Press [Enter] to create a new profile, or [Esc] to return.",
                Style::default().fg(theme::ACCENT),
            ),
        ];
        frame.render_widget(Paragraph::new(lines).block(block), area);
        return;
    }

    let offset = view
        .selected
        .saturating_sub(inner.height.saturating_sub(1) as usize);
    ui.list_area = Some(inner);
    ui.list_count = view.profiles.len();
    ui.list_row_height = 1;
    ui.list_scroll_offset = offset;

    let lines = view
        .profiles
        .iter()
        .enumerate()
        .map(|(index, profile)| {
            let is_selected = index == view.selected;
            Line::styled(
                format!(
                    "{}{: <18} {: <28} {: <5} auto:{} priority {}{}",
                    if is_selected { "▶ " } else { "  " },
                    profile.id,
                    profile.ssid,
                    client_security_label(profile.security),
                    if profile.autoconnect { "on" } else { "off" },
                    profile.priority,
                    if profile.has_passphrase {
                        "  key: saved"
                    } else {
                        ""
                    }
                ),
                selected_style(is_selected),
            )
        })
        .collect::<Vec<_>>();

    frame.render_widget(
        Paragraph::new(lines.into_iter().skip(offset).collect::<Vec<_>>()).block(block),
        area,
    );
}

fn render_profile_actions(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    ui: &mut UiLayout,
    view: &WifiProfilesView,
) {
    let target = view
        .profiles
        .get(view.selected_profile)
        .map_or("none", |p| p.id.as_str());
    let title = if let Some(id) = &view.delete_confirmation {
        format!("Delete {id}? Y: confirm, any other key: cancel")
    } else {
        format!("Profile management — target: {target}")
    };
    let block = panel(&title);
    let inner = block.inner(area);

    let has_header = view.profiles.get(view.selected_profile).is_some();
    let header_lines = if has_header { 2 } else { 0 };

    let list_area = Rect::new(
        inner.x,
        inner.y + header_lines as u16,
        inner.width,
        inner.height.saturating_sub(header_lines as u16),
    );
    let offset = view
        .selected
        .saturating_sub(list_area.height.saturating_sub(1) as usize);

    ui.list_area = Some(list_area);
    ui.list_count = WifiProfileAction::ALL.len();
    ui.list_row_height = 1;
    ui.list_scroll_offset = offset;

    let mut lines = Vec::new();
    if let Some(profile) = view.profiles.get(view.selected_profile) {
        lines.push(Line::styled(
            format!(
                "  ID: {} │ SSID: {} │ Security: {} │ Priority: {} │ Auto: {}",
                profile.id,
                profile.ssid,
                client_security_label(profile.security),
                profile.priority,
                if profile.autoconnect { "on" } else { "off" }
            ),
            Style::default().fg(theme::ACCENT),
        ));
        lines.push(Line::from(""));
    }

    for (slot, action) in WifiProfileAction::ALL.iter().enumerate().skip(offset) {
        let is_selected = view.selected == slot;
        lines.push(Line::styled(
            format!(
                "{}{}",
                if is_selected { "▶ " } else { "  " },
                action.label()
            ),
            selected_style(is_selected),
        ));
    }

    lines.push(Line::from(""));
    lines.push(Line::styled(
        "  ↑/↓: choose action │ Enter: execute │ Esc: back",
        Style::default().fg(theme::MUTED),
    ));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

pub(crate) async fn handle_wifi_profiles_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    let Some(view) = app.wifi_profiles.as_mut() else {
        app.screen = Screen::Wifi;
        return;
    };
    if let Some(id) = view.delete_confirmation.take() {
        if key == KeyCode::Char('y') || key == KeyCode::Char('Y') {
            profile_request(app, client, Ok(Request::DeleteWifiClientProfile { id })).await;
        }
        return;
    }

    match view.mode {
        WifiProfilesMode::Menu => match key {
            KeyCode::Esc => {
                app.wifi_profiles = None;
                app.screen = Screen::Wifi;
            }
            KeyCode::Up => {
                view.selected = view.selected.saturating_sub(1);
            }
            KeyCode::Down => {
                let max_index = WifiProfilesMenuAction::ALL.len().saturating_sub(1);
                view.selected = (view.selected + 1).min(max_index);
            }
            KeyCode::Home => {
                view.selected = 0;
            }
            KeyCode::End => {
                view.selected = WifiProfilesMenuAction::ALL.len().saturating_sub(1);
            }
            KeyCode::Enter => activate_profile_row(app, client).await,
            _ => {}
        },
        WifiProfilesMode::Management => {
            if view.profiles.is_empty() {
                match key {
                    KeyCode::Esc => {
                        view.mode = WifiProfilesMode::Menu;
                        view.selected = 0;
                    }
                    KeyCode::Enter => {
                        let interface = view.interface.clone();
                        open_create_profile(app, interface);
                    }
                    _ => {}
                }
                return;
            }

            let count = view.profiles.len();
            match key {
                KeyCode::Esc => {
                    view.mode = WifiProfilesMode::Menu;
                    view.selected = 0;
                }
                KeyCode::Up => {
                    view.selected = view.selected.saturating_sub(1);
                    view.selected_profile = view.selected;
                }
                KeyCode::Down if view.selected + 1 < count => {
                    view.selected += 1;
                    view.selected_profile = view.selected;
                }
                KeyCode::Home => {
                    view.selected = 0;
                    view.selected_profile = 0;
                }
                KeyCode::End => {
                    view.selected = count.saturating_sub(1);
                    view.selected_profile = view.selected;
                }
                KeyCode::Enter => activate_profile_row(app, client).await,
                _ => {}
            }
        }
        WifiProfilesMode::ProfileActions => match key {
            KeyCode::Esc => {
                view.mode = WifiProfilesMode::Management;
                view.selected = view.selected_profile;
            }
            KeyCode::Up => {
                view.selected = view.selected.saturating_sub(1);
            }
            KeyCode::Down => {
                let max_index = WifiProfileAction::ALL.len().saturating_sub(1);
                view.selected = (view.selected + 1).min(max_index);
            }
            KeyCode::Home => {
                view.selected = 0;
            }
            KeyCode::End => {
                view.selected = WifiProfileAction::ALL.len().saturating_sub(1);
            }
            KeyCode::Enter => activate_profile_row(app, client).await,
            _ => {}
        },
    }
}

async fn activate_profile_action(app: &mut TuiApp, client: &ApiClient, action: WifiProfileAction) {
    match action {
        WifiProfileAction::Back => {
            if let Some(current) = app.wifi_profiles.as_mut() {
                current.mode = WifiProfilesMode::Management;
                current.selected = current.selected_profile;
            }
        }
        WifiProfileAction::Deactivate => {
            let interface = app
                .wifi_profiles
                .as_ref()
                .map(|v| v.interface.clone())
                .unwrap_or_default();
            profile_request(
                app,
                client,
                Ok(Request::DeactivateWifiClientProfile { interface }),
            )
            .await;
        }
        WifiProfileAction::Activate | WifiProfileAction::Edit | WifiProfileAction::Delete => {
            let Some((interface, profile)) = app.wifi_profiles.as_ref().and_then(|v| {
                v.profiles
                    .get(v.selected_profile)
                    .cloned()
                    .map(|p| (v.interface.clone(), p))
            }) else {
                app.push_message(LogLevel::Warn, "Select a profile first");
                return;
            };

            match action {
                WifiProfileAction::Activate => {
                    open_wifi_connect_prompt(app, client, interface, profile.id, profile.ssid)
                        .await;
                }
                WifiProfileAction::Edit => {
                    app.wifi_profile_editor =
                        Some(WifiProfileEditor::from_profile(interface, &profile));
                    app.screen = Screen::WifiProfileEditor;
                }
                WifiProfileAction::Delete => {
                    if let Some(current) = app.wifi_profiles.as_mut() {
                        current.delete_confirmation = Some(profile.id.clone());
                    }
                    app.push_message(
                        LogLevel::Warn,
                        format!(
                            "Delete profile {}? Y confirms; any other key cancels.",
                            profile.id
                        ),
                    );
                }
                WifiProfileAction::Deactivate | WifiProfileAction::Back => unreachable!(),
            }
        }
    }
}

async fn activate_profile_row(app: &mut TuiApp, client: &ApiClient) {
    let Some((mode, selected, is_empty, interface)) = app.wifi_profiles.as_ref().map(|v| {
        (
            v.mode,
            v.selected,
            v.profiles.is_empty(),
            v.interface.clone(),
        )
    }) else {
        return;
    };
    match mode {
        WifiProfilesMode::Menu => match WifiProfilesMenuAction::from_index(selected) {
            Some(WifiProfilesMenuAction::Management) => {
                if let Some(current) = app.wifi_profiles.as_mut() {
                    current.mode = WifiProfilesMode::Management;
                    current.selected = if current.profiles.is_empty() {
                        0
                    } else {
                        current.selected_profile.min(current.profiles.len() - 1)
                    };
                }
            }
            Some(WifiProfilesMenuAction::CreateNew) => {
                open_create_profile(app, interface);
            }
            None => {}
        },
        WifiProfilesMode::Management => {
            if is_empty {
                open_create_profile(app, interface);
            } else if let Some(current) = app.wifi_profiles.as_mut() {
                current.mode = WifiProfilesMode::ProfileActions;
                current.selected = 0;
            }
        }
        WifiProfilesMode::ProfileActions => {
            if let Some(action) = WifiProfileAction::from_index(selected) {
                activate_profile_action(app, client, action).await;
            }
        }
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
        | Ok(Response::WifiClientDisabled { .. }) => {
            app.push_message(LogLevel::Info, "Wi-Fi profile action applied");
            let interface = app
                .wifi_profiles
                .as_ref()
                .map(|v| v.interface.clone())
                .unwrap_or_default();
            let mode = app
                .wifi_profiles
                .as_ref()
                .map(|v| v.mode)
                .unwrap_or(WifiProfilesMode::Management);
            open_profiles(app, client, interface, mode).await;
        }
        Ok(Response::WifiClientProfileDeleted { .. }) => {
            app.push_message(LogLevel::Info, "Wi-Fi profile action applied");
            let interface = app
                .wifi_profiles
                .as_ref()
                .map(|v| v.interface.clone())
                .unwrap_or_default();
            open_profiles(app, client, interface, WifiProfilesMode::Management).await;
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
            ProfileField::Autoconnect,
            "Autoconnect",
            if editor.autoconnect {
                "[x] On"
            } else {
                "[ ] Off"
            }
            .into(),
        ),
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
            let active = editor.field == field;
            let style = selected_style(active);
            let prefix = format!("{}{label:<14}", if active { "▶ " } else { "  " });
            let mut spans = vec![Span::styled(prefix, style)];
            if active
                && matches!(
                    field,
                    ProfileField::Id
                        | ProfileField::Ssid
                        | ProfileField::Country
                        | ProfileField::Priority
                )
            {
                spans.extend(super::input::render_value_with_cursor(
                    &value,
                    editor.cursor,
                    true,
                    style,
                ));
            } else if active && field == ProfileField::Passphrase {
                if editor.passphrase.is_empty() && editor.has_passphrase {
                    spans.push(Span::styled(
                        "•••••• (saved; leave blank to keep) ",
                        Style::default().fg(theme::MUTED),
                    ));
                    spans.extend(super::input::render_masked_with_cursor(
                        0, 0, true, '•', style,
                    ));
                } else {
                    spans.extend(super::input::render_masked_with_cursor(
                        editor.passphrase.chars().count(),
                        editor.cursor,
                        true,
                        '•',
                        style,
                    ));
                }
            } else {
                spans.push(Span::styled(value, style));
            }
            Line::from(spans)
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(
            lines
                .clone()
                .into_iter()
                .skip(super::layout::focused_lines_offset(
                    &lines,
                    area.height.saturating_sub(2),
                ))
                .collect::<Vec<_>>(),
        )
        .block(panel("Wi-Fi profile editor")),
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
        KeyCode::Up => {
            editor.field = move_field(&PROFILE_FIELDS, editor.field, false);
            editor.reset_cursor();
        }
        KeyCode::Down => {
            editor.field = move_field(&PROFILE_FIELDS, editor.field, true);
            editor.reset_cursor();
        }
        KeyCode::Enter | KeyCode::Char(' ') if editor.field == ProfileField::Autoconnect => {
            editor.autoconnect = !editor.autoconnect;
        }
        KeyCode::Enter if editor.field == ProfileField::Security => {
            editor.security = cycle_client_security(editor.security)
        }
        KeyCode::Char(' ') if editor.field == ProfileField::Security => {
            editor.security = cycle_client_security(editor.security)
        }
        KeyCode::Enter if editor.field == ProfileField::Save => save_profile(app, client).await,
        KeyCode::Enter => {
            editor.field = move_field(&PROFILE_FIELDS, editor.field, true);
            editor.reset_cursor();
        }
        other => {
            if let Some(mut text_editor) = editor.active_editor() {
                text_editor.handle_key(other);
            }
        }
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
    let request = if let Some(id) = editor.original_id.clone() {
        Request::UpdateWifiClientProfile { id, profile }
    } else {
        Request::CreateWifiClientProfile { profile }
    };
    match client.request(&request).await {
        Ok(Response::WifiClientProfile {
            profile: saved_profile,
            ..
        }) => {
            app.push_message(LogLevel::Info, "Wi-Fi profile saved");
            let interface = editor.interface.clone();
            let is_new = editor.original_id.is_none();
            let profile_id = saved_profile.id.clone();
            let ssid = saved_profile.ssid.clone();
            app.wifi_profile_editor = None;
            app.screen = Screen::Wifi;
            if is_new {
                open_wifi_connect_prompt(app, client, interface, profile_id, ssid).await;
            } else {
                open_profiles(app, client, interface, WifiProfilesMode::Management).await;
            }
        }
        Ok(Response::WifiClientProfileError { detail }) => {
            app.push_message(LogLevel::Error, format!("{detail:?}"))
        }
        Ok(response) => report_unexpected(app, response),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

pub(crate) async fn open_wifi_connect_prompt(
    app: &mut TuiApp,
    client: &ApiClient,
    interface: String,
    profile_id: String,
    ssid: String,
) {
    let current_static_ip = match client
        .request(&Request::GetInterfaceConfig {
            interface: interface.clone(),
        })
        .await
    {
        Ok(Response::InterfaceConfig {
            config: Some(cfg), ..
        }) => cfg.ipv4.map(|ip| ip.to_string()),
        Ok(response) => {
            report_unexpected(app, response);
            None
        }
        Err(error) => {
            app.push_message(
                LogLevel::Warn,
                format!("Could not read current IP configuration: {error}"),
            );
            None
        }
    };

    app.wifi_connect = Some(WifiConnectPrompt::new(
        interface,
        profile_id,
        ssid,
        current_static_ip,
    ));
    app.screen = Screen::WifiConnectPrompt;
}

pub(crate) async fn handle_wifi_connect_prompt_key(
    app: &mut TuiApp,
    key: KeyCode,
    client: &ApiClient,
) {
    let Some(prompt) = app.wifi_connect.as_mut() else {
        app.screen = Screen::Wifi;
        return;
    };

    match key {
        KeyCode::Esc => {
            app.wifi_connect = None;
            app.screen = if app.wifi_profiles.is_some() {
                Screen::WifiProfiles
            } else {
                Screen::Wifi
            };
        }
        KeyCode::F(10) => {
            submit_wifi_connect(app, client).await;
        }
        KeyCode::Up => {
            let focusable = prompt.focusable_fields();
            if let Some(pos) = focusable.iter().position(|f| *f == prompt.field) {
                if pos > 0 {
                    prompt.field = focusable[pos - 1];
                    match prompt.field {
                        WifiConnectField::StaticCidr => {
                            prompt.cursor = prompt.static_cidr.len();
                        }
                        _ => {}
                    }
                }
            }
        }
        KeyCode::Down | KeyCode::Tab => {
            let focusable = prompt.focusable_fields();
            if let Some(pos) = focusable.iter().position(|f| *f == prompt.field) {
                if pos + 1 < focusable.len() {
                    prompt.field = focusable[pos + 1];
                    match prompt.field {
                        WifiConnectField::StaticCidr => {
                            prompt.cursor = prompt.static_cidr.len();
                        }
                        _ => {}
                    }
                }
            }
        }
        KeyCode::Left if prompt.field == WifiConnectField::Cancel => {
            prompt.field = WifiConnectField::Submit;
        }
        KeyCode::Right if prompt.field == WifiConnectField::Submit => {
            prompt.field = WifiConnectField::Cancel;
        }
        KeyCode::Char(' ') if matches!(prompt.field, WifiConnectField::Choice(_)) => {
            if let WifiConnectField::Choice(choice) = prompt.field {
                prompt.choice = choice;
            }
        }
        KeyCode::Enter => match prompt.field {
            WifiConnectField::Choice(c) => {
                prompt.choice = c;
                if c == WifiIpChoice::NewStatic {
                    prompt.field = WifiConnectField::StaticCidr;
                    prompt.cursor = prompt.static_cidr.len();
                } else {
                    prompt.field = WifiConnectField::Submit;
                }
            }
            WifiConnectField::StaticCidr => {
                prompt.field = WifiConnectField::Submit;
            }
            WifiConnectField::Submit => {
                submit_wifi_connect(app, client).await;
            }
            WifiConnectField::Cancel => {
                app.wifi_connect = None;
                app.screen = if app.wifi_profiles.is_some() {
                    Screen::WifiProfiles
                } else {
                    Screen::Wifi
                };
            }
        },
        other if prompt.field == WifiConnectField::StaticCidr => {
            let cursor = &mut prompt.cursor;
            super::input::TextEditor::new(&mut prompt.static_cidr, cursor)
                .handle_key_filtered(other, |c| c.is_ascii_digit() || c == '.' || c == '/');
        }
        _ => {}
    }
}

async fn disable_dhcp_for_static(app: &mut TuiApp, client: &ApiClient, interface: &str) -> bool {
    use crate::api::model::DhcpClientErrorDetail;
    match client
        .request(&Request::DisableDhcpClient {
            interface: interface.to_string(),
        })
        .await
    {
        Ok(Response::DhcpClientDisabled { .. })
        | Ok(Response::DhcpClientError {
            detail: DhcpClientErrorDetail::Disabled | DhcpClientErrorDetail::DhcpClientDisabled,
        }) => true,
        Ok(response) => {
            app.push_message(
                LogLevel::Warn,
                format!("Cannot configure static IP: DHCP client was not stopped: {response:?}"),
            );
            false
        }
        Err(error) => {
            app.push_message(
                LogLevel::Warn,
                format!("Cannot configure static IP: DHCP client was not stopped: {error}"),
            );
            false
        }
    }
}

async fn apply_wifi_static_ip(
    app: &mut TuiApp,
    client: &ApiClient,
    interface: &str,
    cidr: &str,
) -> bool {
    match client
        .request(&Request::ApplyInterfaceEdit {
            interface: interface.to_string(),
            edit: InterfaceEditRequest {
                cidr: cidr.to_string(),
                role: InterfaceRole::Input,
                managed: true,
                allow_management_change: true,
            },
        })
        .await
    {
        Ok(Response::NetworkChangePending { change }) => {
            match client
                .request(&Request::CommitNetworkChange {
                    token: change.token.clone(),
                })
                .await
            {
                Ok(Response::NetworkChangeCommitted { .. }) => true,
                result => {
                    // Retain the token and deadline so the user can inspect/roll back
                    // an ambiguous commit instead of losing the pending transaction.
                    app.pending = Some(change);
                    app.screen = Screen::PendingChange;
                    app.push_message(LogLevel::Warn, format!("Static IP commit was not confirmed: {result:?}. Inspect pending state before retrying."));
                    false
                }
            }
        }
        Ok(Response::NetworkChangeCommitted { .. }) => true,
        result => {
            app.push_message(
                LogLevel::Warn,
                format!("Static IP configuration failed: {result:?}"),
            );
            false
        }
    }
}

async fn submit_wifi_connect(app: &mut TuiApp, client: &ApiClient) {
    let Some(prompt) = app.wifi_connect.clone() else {
        return;
    };
    let static_cidr = match prompt.choice {
        WifiIpChoice::Dhcp => None,
        WifiIpChoice::KeepStatic => prompt.current_static_ip.as_deref(),
        WifiIpChoice::NewStatic => Some(prompt.static_cidr.trim()),
    };
    if prompt.choice != WifiIpChoice::Dhcp {
        let Some(cidr) = static_cidr.filter(|cidr| !cidr.is_empty()) else {
            app.push_message(LogLevel::Warn, "Static IP / CIDR is required");
            return;
        };
        if let Err(error) = cidr.parse::<ipnet::Ipv4Net>() {
            app.push_message(
                LogLevel::Warn,
                format!("Invalid CIDR format (e.g. 192.168.1.100/24): {error}"),
            );
            return;
        }
    }

    // Activation validates that an IP configuration already exists. Configure
    // it first, and stop immediately if any prerequisite fails.
    if let Some(cidr) = static_cidr {
        if !disable_dhcp_for_static(app, client, &prompt.interface).await
            || !apply_wifi_static_ip(app, client, &prompt.interface, cidr).await
        {
            return;
        }
    } else {
        match client
            .request(&Request::ConfigureDhcpClient {
                interface: prompt.interface.clone(),
                config: DhcpClientConfigRequest::default(),
            })
            .await
        {
            Ok(Response::DhcpClientInterface { .. }) => {}
            result => {
                app.push_message(
                    LogLevel::Warn,
                    format!("DHCP client configuration failed: {result:?}"),
                );
                return;
            }
        }
    }

    match client
        .request(&Request::ActivateWifiClientProfile {
            interface: prompt.interface.clone(),
            profile_id: prompt.profile_id.clone(),
        })
        .await
    {
        Ok(Response::WifiClientProfileActivated { .. }) => {
            app.push_message(
                LogLevel::Info,
                format!(
                    "Profile '{}' activated; waiting for Wi-Fi connection and IP readiness.",
                    prompt.ssid
                ),
            );
            app.wifi_connect = None;
            app.screen = Screen::Wifi;
            load_wifi_data(app, client).await;
        }
        result => {
            app.push_message(LogLevel::Warn, format!("IP configuration was updated, but profile activation was not confirmed: {result:?}. Inspect interface state before retrying."));
        }
    }
}

pub(crate) fn render_wifi_connect_prompt(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    app: &mut TuiApp,
) {
    let Some(prompt) = &app.wifi_connect else {
        return;
    };
    let block = panel(&format!(
        "Connect to '{}' on {}",
        prompt.ssid, prompt.interface
    ));
    let mut lines = Vec::new();

    lines.push(Line::from(
        "Select how IPv4 will be obtained for this connection:",
    ));
    lines.push(Line::from(""));

    // Option 1: DHCP
    let dhcp_active = prompt.field == WifiConnectField::Choice(WifiIpChoice::Dhcp);
    let dhcp_selected = prompt.choice == WifiIpChoice::Dhcp;
    let dhcp_radio = if dhcp_selected { "(•) " } else { "( ) " };
    let dhcp_prefix = if dhcp_active { "▶ " } else { "  " };
    lines.push(Line::styled(
        format!("{dhcp_prefix}{dhcp_radio}Obtain IP address automatically via DHCP (recommended)"),
        selected_style(dhcp_active),
    ));

    // Option 2 (conditional): Keep current static IP
    if let Some(ip) = &prompt.current_static_ip {
        let keep_active = prompt.field == WifiConnectField::Choice(WifiIpChoice::KeepStatic);
        let keep_selected = prompt.choice == WifiIpChoice::KeepStatic;
        let keep_radio = if keep_selected { "(•) " } else { "( ) " };
        let keep_prefix = if keep_active { "▶ " } else { "  " };
        lines.push(Line::styled(
            format!("{keep_prefix}{keep_radio}Keep current static IP ({ip})"),
            selected_style(keep_active),
        ));
    }

    // Option 3: Configure static IP
    let new_active = prompt.field == WifiConnectField::Choice(WifiIpChoice::NewStatic);
    let new_selected = prompt.choice == WifiIpChoice::NewStatic;
    let new_radio = if new_selected { "(•) " } else { "( ) " };
    let new_prefix = if new_active { "▶ " } else { "  " };
    lines.push(Line::styled(
        format!("{new_prefix}{new_radio}Configure static IP address"),
        selected_style(new_active),
    ));

    if prompt.choice == WifiIpChoice::NewStatic {
        lines.push(Line::from(""));

        // Static CIDR
        let cidr_active = prompt.field == WifiConnectField::StaticCidr;
        let cidr_style = selected_style(cidr_active);
        let cidr_prefix = format!(
            "{}{:<24}",
            if cidr_active { "▶ " } else { "  " },
            "IP / CIDR:"
        );
        let mut cidr_spans = vec![Span::styled(cidr_prefix, cidr_style)];
        if cidr_active {
            cidr_spans.extend(super::input::render_value_with_cursor(
                &prompt.static_cidr,
                prompt.cursor,
                true,
                cidr_style,
            ));
        } else {
            cidr_spans.push(Span::styled(
                if prompt.static_cidr.is_empty() {
                    "e.g. 192.168.1.100/24".to_string()
                } else {
                    prompt.static_cidr.clone()
                },
                if prompt.static_cidr.is_empty() {
                    Style::default().fg(theme::MUTED)
                } else {
                    cidr_style
                },
            ));
        }
        lines.push(Line::from(cidr_spans));
    }

    lines.push(Line::from(""));

    let buttons_line = lines.len();
    // Buttons
    let submit_active = prompt.field == WifiConnectField::Submit;
    let cancel_active = prompt.field == WifiConnectField::Cancel;
    lines.push(Line::from(vec![
        Span::styled(
            if submit_active {
                "▶ [ Connect (Enter) ] "
            } else {
                "  [ Connect ] "
            },
            selected_style(submit_active),
        ),
        Span::raw("    "),
        Span::styled(
            if cancel_active {
                "▶ [ Cancel (Esc) ]"
            } else {
                "  [ Cancel ]"
            },
            selected_style(cancel_active),
        ),
    ]));

    lines.push(Line::from(""));
    lines.push(Line::styled(
        "↑/↓: focus • Enter: select • F10: connect • Esc: cancel",
        Style::default().fg(theme::MUTED),
    ));

    let inner = block.inner(area);
    let offset = super::layout::focused_lines_offset(&lines, inner.height);
    if buttons_line >= offset && buttons_line < offset + inner.height as usize {
        let y = inner.y + (buttons_line - offset) as u16;
        let submit_width = if submit_active { 21 } else { 14 };
        let cancel_x = submit_width + 4;
        app.ui
            .buttons
            .push((Rect::new(inner.x, y, submit_width.min(inner.width), 1), 0));
        if cancel_x < inner.width {
            app.ui.buttons.push((
                Rect::new(inner.x + cancel_x, y, inner.width - cancel_x, 1),
                1,
            ));
        }
    }
    frame.render_widget(
        Paragraph::new(lines.into_iter().skip(offset).collect::<Vec<_>>()).block(block),
        area,
    );
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
        Ok(Response::WifiClientError {
            detail: crate::api::model::WifiClientErrorDetail::WifiClientDisabled,
        }) => {
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
    let mut managed = std::collections::HashMap::new();
    for row in rows.iter_mut() {
        let config = match client
            .request(&Request::GetInterfaceConfig {
                interface: row.interface.clone(),
            })
            .await
        {
            Ok(Response::InterfaceConfig {
                config: Some(config),
                ..
            }) => Some(config),
            Ok(Response::InterfaceConfig { config: None, .. }) => None,
            result => {
                app.wifi.error = Some(format!(
                    "Could not refresh {} configuration: {result:?}",
                    row.interface
                ));
                return;
            }
        };
        managed.insert(
            row.interface.clone(),
            config.as_ref().is_some_and(|c| c.managed),
        );
        if let Some(config) = &config {
            if config.role == InterfaceRole::Input && config.managed {
                row.role = WifiRole::Client;
            } else if config.role == InterfaceRole::Output && config.managed {
                row.role = WifiRole::AccessPoint;
            } else if row.role == WifiRole::Unknown {
                row.role = role_from_interface(config.role, config.managed);
            }
        }
    }
    rows.retain(|row| managed.get(&row.interface).copied().unwrap_or(false));
    app.wifi.replace_rows(rows);
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
        (InterfaceRole::Input, true) => WifiRole::Client,
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
            ..
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

    async fn mock_api(
        responses: Vec<Response>,
    ) -> (
        tempfile::TempDir,
        ApiClient,
        tokio::task::JoinHandle<Vec<String>>,
    ) {
        use http_body_util::{BodyExt, Full};
        use hyper::{body::Bytes, server::conn::http1, service::service_fn};
        use hyper_util::rt::TokioIo;
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("api.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let paths = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
            for response in responses {
                let (stream, _) =
                    tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                        .await
                        .unwrap()
                        .unwrap();
                let body = serde_json::to_vec(&response).unwrap();
                let paths = paths.clone();
                http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                            let paths = paths.clone();
                            let body = body.clone();
                            async move {
                                paths.lock().await.push(format!(
                                    "{} {}",
                                    request.method(),
                                    request.uri().path()
                                ));
                                request.into_body().collect().await.unwrap();
                                Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                                    Bytes::from(body),
                                )))
                            }
                        }),
                    )
                    .await
                    .unwrap();
            }
            let result = paths.lock().await.clone();
            result
        });
        (directory, ApiClient::new(socket), server)
    }

    fn radio(name: &str) -> WifiRow {
        WifiRow {
            interface: name.into(),
            role: WifiRole::Client,
            ap: None,
            client: None,
        }
    }

    #[test]
    fn refresh_preserves_radio_and_action_identity() {
        let mut app = TuiApp::default();
        app.wifi.rows = vec![radio("wlan0"), radio("wlan1")];
        open_radio(&mut app, 1);
        focus_action(&mut app, 2);
        app.wifi.replace_rows(vec![radio("wlan1")]);
        assert_eq!(app.wifi.selected_radio, 0);
        assert_eq!(app.wifi.selected, 3);
        assert!(app.wifi.actions_open);
        let mut changed_role = radio("wlan1");
        changed_role.role = WifiRole::AccessPoint;
        app.wifi.replace_rows(vec![changed_role]);
        assert!(!app.wifi.actions_open);
        assert_eq!(app.wifi.selected, 0);
        app.wifi.replace_rows(Vec::new());
        assert_eq!(app.wifi.selected, 0);
    }

    #[tokio::test]
    async fn radio_actions_scroll_and_return_to_the_original_radio() {
        let client = ApiClient::new("/nonexistent.sock");
        let mut app = TuiApp {
            screen: Screen::Wifi,
            ..Default::default()
        };
        app.wifi.rows = (0..20).map(|i| radio(&format!("wlan{i}"))).collect();
        app.wifi.selected = 19;
        app.wifi.selected_radio = 19;
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(60, 15)).unwrap();
        terminal
            .draw(|frame| super::super::render(frame, &mut app, false))
            .unwrap();
        assert!(app.ui.list_scroll_offset > 0);
        let area = app.ui.list_area.unwrap();
        assert!(area.bottom() <= 11);
        super::super::handle_key(&mut app, KeyCode::Tab, &client, false).await;
        assert!(app.wifi.actions_open);
        handle_wifi_key(&mut app, KeyCode::End, &client).await;
        terminal
            .draw(|frame| super::super::render(frame, &mut app, false))
            .unwrap();
        for (rect, _) in &app.ui.buttons {
            assert!(rect.bottom() <= 10);
        }
        assert!(app
            .ui
            .buttons
            .iter()
            .any(|(_, slot)| *slot == actions(WifiRole::Client).len() - 1));
        handle_wifi_key(&mut app, KeyCode::Esc, &client).await;
        app.wifi.selected = 2;
        app.wifi.selected_radio = 2;
        handle_wifi_key(&mut app, KeyCode::Tab, &client).await;
        handle_wifi_key(&mut app, KeyCode::Up, &client).await;
        assert_eq!(app.wifi.selected, 2);
        assert_eq!(app.wifi.selected_radio, 2);
    }

    #[tokio::test]
    async fn connect_navigation_does_not_change_choice_or_submit() {
        let mut app = TuiApp {
            screen: Screen::WifiConnectPrompt,
            wifi_connect: Some(WifiConnectPrompt::new(
                "wlan0".into(),
                "home".into(),
                "Home".into(),
                None,
            )),
            ..Default::default()
        };
        let client = ApiClient::new("/nonexistent.sock");
        handle_wifi_connect_prompt_key(&mut app, KeyCode::Down, &client).await;
        assert_eq!(
            app.wifi_connect.as_ref().unwrap().choice,
            WifiIpChoice::Dhcp
        );
        handle_wifi_connect_prompt_key(&mut app, KeyCode::Up, &client).await;
        handle_wifi_connect_prompt_key(&mut app, KeyCode::Enter, &client).await;
        assert_eq!(
            app.wifi_connect.as_ref().unwrap().field,
            WifiConnectField::Submit
        );
        assert!(app.message.is_none());
        let prompt = app.wifi_connect.as_mut().unwrap();
        prompt.choice = WifiIpChoice::NewStatic;
        prompt.current_static_ip = Some("192.168.1.5/24".into());
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(60, 15)).unwrap();
        terminal
            .draw(|frame| super::super::render(frame, &mut app, false))
            .unwrap();
        assert_eq!(app.ui.buttons.len(), 2);
        for (rect, _) in &app.ui.buttons {
            assert!(rect.bottom() <= 10);
        }
        let (rect, _) = app.ui.buttons[1];
        super::super::handle_mouse(
            &mut app,
            crossterm::event::MouseEvent {
                kind: crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
                column: rect.x,
                row: rect.y,
                modifiers: crossterm::event::KeyModifiers::NONE,
            },
            &client,
            false,
        )
        .await;
        assert!(app.wifi_connect.is_none());
    }

    #[tokio::test]
    async fn dhcp_is_configured_before_profile_activation() {
        use crate::api::model::{DhcpClientOperationalState, DhcpClientStatusView};
        let (_directory, client, server) = mock_api(vec![
            Response::DhcpClientInterface {
                status: DhcpClientStatusView {
                    interface: "wlan0".into(),
                    state: DhcpClientOperationalState::Waiting,
                    address: None,
                    prefix_length: None,
                    server: None,
                    expires_at_unix: None,
                    dns_servers: Vec::new(),
                    degraded_reason: None,
                    config: Default::default(),
                },
            },
            Response::Error {
                message: "activation failed".into(),
            },
        ])
        .await;
        let mut app = TuiApp {
            screen: Screen::WifiConnectPrompt,
            wifi_connect: Some(WifiConnectPrompt::new(
                "wlan0".into(),
                "home".into(),
                "Home".into(),
                None,
            )),
            ..Default::default()
        };
        submit_wifi_connect(&mut app, &client).await;
        let paths = server.await.unwrap();
        assert_eq!(paths[0], "PUT /api/v1/dhcp-client/wlan0");
        assert!(paths[1].ends_with("/active-profile"));
        assert!(app.wifi_connect.is_some());
        assert!(app
            .message
            .as_deref()
            .unwrap()
            .contains("IP configuration was updated"));
    }

    #[tokio::test]
    async fn failed_dhcp_stop_blocks_static_edit_and_activation() {
        let (_directory, client, server) = mock_api(vec![Response::DhcpClientError {
            detail: crate::api::model::DhcpClientErrorDetail::OwnershipConflict {
                message: "not owned".into(),
            },
        }])
        .await;
        let mut prompt = WifiConnectPrompt::new("wlan0".into(), "home".into(), "Home".into(), None);
        prompt.choice = WifiIpChoice::NewStatic;
        prompt.static_cidr = "192.168.1.5/24".into();
        let mut app = TuiApp {
            screen: Screen::WifiConnectPrompt,
            wifi_connect: Some(prompt),
            ..Default::default()
        };
        submit_wifi_connect(&mut app, &client).await;
        assert_eq!(
            server.await.unwrap(),
            vec!["DELETE /api/v1/dhcp-client/wlan0"]
        );
        assert_eq!(app.screen, Screen::WifiConnectPrompt);
        assert!(app.message.as_deref().unwrap().contains("not stopped"));
    }

    #[tokio::test]
    async fn static_ip_is_committed_before_profile_activation() {
        let change = crate::core::transaction::PendingNetworkChange {
            token: "static-token".into(),
            interface: "wlan0".into(),
            rollback_timeout_seconds: 60,
            expires_at_unix: super::super::current_unix_time() + 60,
        };
        let (_directory, client, server) = mock_api(vec![
            Response::DhcpClientDisabled {
                interface: "wlan0".into(),
            },
            Response::NetworkChangePending {
                change: change.clone(),
            },
            Response::NetworkChangeCommitted { change },
            Response::Error {
                message: "activation failed".into(),
            },
        ])
        .await;
        let mut prompt = WifiConnectPrompt::new("wlan0".into(), "home".into(), "Home".into(), None);
        prompt.choice = WifiIpChoice::NewStatic;
        prompt.static_cidr = "192.168.1.5/24".into();
        let mut app = TuiApp {
            screen: Screen::WifiConnectPrompt,
            wifi_connect: Some(prompt),
            ..Default::default()
        };
        submit_wifi_connect(&mut app, &client).await;
        let paths = server.await.unwrap();
        assert_eq!(paths.len(), 4);
        assert_eq!(paths[0], "DELETE /api/v1/dhcp-client/wlan0");
        assert_eq!(paths[1], "POST /api/v1/interfaces/wlan0/edit/apply");
        assert_eq!(paths[2], "POST /api/v1/network-transactions/commit");
        assert!(paths[3].ends_with("/active-profile"));
        assert!(app.wifi_connect.is_some());
    }

    #[tokio::test]
    async fn failed_static_commit_retains_pending_transaction() {
        let change = crate::core::transaction::PendingNetworkChange {
            token: "pending-token".into(),
            interface: "wlan0".into(),
            rollback_timeout_seconds: 60,
            expires_at_unix: super::super::current_unix_time() + 60,
        };
        let (_directory, client, server) = mock_api(vec![
            Response::NetworkChangePending { change },
            Response::Error {
                message: "commit rejected".into(),
            },
        ])
        .await;
        let mut app = TuiApp::default();
        assert!(!apply_wifi_static_ip(&mut app, &client, "wlan0", "192.168.1.5/24").await);
        assert_eq!(server.await.unwrap().len(), 2);
        assert_eq!(app.screen, Screen::PendingChange);
        assert_eq!(app.pending.as_ref().unwrap().token, "pending-token");
    }

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

    #[tokio::test]
    async fn ap_options_open_only_on_activation_and_radio_edits_reach_request() {
        let mut app = TuiApp::default();
        app.wifi.rows.push(WifiRow {
            interface: "wlan0".into(),
            role: WifiRole::AccessPoint,
            ap: None,
            client: None,
        });
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| render_wifi(frame, frame.area(), &mut app))
            .unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(!text.contains("Configure access point"));
        assert_eq!(app.wifi.selected, 0);
        let client = ApiClient::new("/nonexistent.sock");
        handle_wifi_key(&mut app, KeyCode::Down, &client).await;
        assert!(!app.wifi.actions_open);
        handle_wifi_key(&mut app, KeyCode::Enter, &client).await;
        terminal
            .draw(|frame| render_wifi(frame, frame.area(), &mut app))
            .unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(text.contains("Configure access point"));
        handle_wifi_key(&mut app, KeyCode::Esc, &client).await;
        assert!(!app.wifi.actions_open);
        app.wifi_editor = Some(WifiEditor::from_row(&app.wifi.rows[0]));
        let client = ApiClient::new("/nonexistent.sock");
        for field in [
            WifiField::Band,
            WifiField::Channel,
            WifiField::Hidden,
            WifiField::ClientIsolation,
            WifiField::MaxStations,
        ] {
            app.wifi_editor.as_mut().unwrap().field = field;
            handle_wifi_editor_key(&mut app, KeyCode::Enter, &client).await;
        }
        let editor = app.wifi_editor.as_mut().unwrap();
        editor.ssid = "Updated SSID".into();
        let Request::ProvisionWifiAccessPoint { settings, .. } = ap_provision_request(editor)
        else {
            panic!("wrong request")
        };
        assert_eq!(settings.band, WifiBand::Ghz5);
        assert_eq!(settings.channel, 32);
        assert!(settings.hidden && settings.client_isolation);
        assert_eq!(settings.max_stations, 33);
        assert_eq!(settings.ssid, "Updated SSID");
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
            autoconnect: false,
            passphrase: String::new(),
            has_passphrase: true,
            cursor: 0,
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
        let settings = ap_settings(&editor);
        assert_eq!(settings.ssid, "traffic-masq");
        assert_eq!(settings.band, WifiBand::Ghz2);
        assert_eq!(settings.channel, 0);
        assert_eq!(settings.channel_width, WifiChannelWidth::Ht20);
        assert_eq!(settings.security, WifiSecurity::Wpa2);
        assert_eq!(settings.max_stations, 32);
        assert!(!settings.hidden && !settings.client_isolation);
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
    fn existing_ap_request_preserves_unedited_radio_settings() {
        let row = WifiRow {
            interface: "wlan0".into(),
            role: WifiRole::AccessPoint,
            ap: None,
            client: None,
        };
        let mut editor = WifiEditor::from_row(&row);
        editor.original_spec = Some(crate::wifi::WifiApSpec {
            interface: "wlan0".into(),
            ssid: "old".into(),
            country_code: Some("US".into()),
            band: WifiBand::Ghz5,
            channel: 36,
            channel_width: WifiChannelWidth::Ht20,
            security: WifiSecurity::Wpa2,
            hidden: true,
            client_isolation: true,
            max_stations: 7,
            passphrase_file: None,
        });
        editor.existing = true;
        editor.configure_dhcp = false;
        editor.ssid = "new".into();
        if let Request::ProvisionWifiAccessPoint {
            settings,
            configure_dhcp,
            ..
        } = ap_provision_request(&editor)
        {
            assert_eq!(settings.ssid, "new");
            assert_eq!(settings.band, WifiBand::Ghz5);
            assert_eq!(settings.channel, 36);
            assert!(settings.hidden && settings.client_isolation);
            assert_eq!(settings.max_stations, 7);
            assert!(!configure_dhcp);
        } else {
            panic!("wrong request");
        }
        editor.passphrase = "never-print-this".into();
        assert!(!format!("{editor:?}").contains("never-print-this"));
    }

    #[test]
    fn scan_scrolls_selected_network_into_view() {
        let mut app = TuiApp {
            wifi_scan: Some(WifiScanPicker {
                interface: "wlan0".into(),
                networks: (0..40)
                    .map(|i| {
                        scan(
                            &format!("network-{i}"),
                            -40,
                            WpaSupplicantScanSecurity::Open,
                            "00:00:00:00:00:01",
                        )
                    })
                    .collect(),
                selected: 39,
            }),
            ..Default::default()
        };
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(60, 15)).unwrap();
        terminal
            .draw(|frame| render_wifi_scan(frame, frame.area(), &mut app))
            .unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(text.contains("network-39"));
        assert!(app.ui.list_scroll_offset > 0);
    }

    #[tokio::test]
    async fn long_profile_list_keeps_delete_visible_and_requires_confirmation() {
        let mut app = TuiApp {
            wifi_profiles: Some(WifiProfilesView {
                interface: "wlan0".into(),
                mode: WifiProfilesMode::Management,
                selected: 39,
                selected_profile: 39,
                delete_confirmation: None,
                profiles: (0..40)
                    .map(|i| WifiClientProfileSummary {
                        id: format!("p{i}"),
                        ssid: format!("network{i}"),
                        country_code: None,
                        security: WifiClientSecurity::Open,
                        priority: 0,
                        autoconnect: false,
                        created_at: 0,
                        modified_at: 0,
                        has_passphrase: false,
                    })
                    .collect(),
            }),
            ..Default::default()
        };
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(60, 15)).unwrap();
        terminal
            .draw(|frame| render_wifi_profiles(frame, frame.area(), &mut app))
            .unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(text.contains("p39"));
        assert!(!text.contains("Create profile"));
        let client = ApiClient::new("/nonexistent.sock");
        handle_wifi_profiles_key(&mut app, KeyCode::Enter, &client).await;
        assert_eq!(
            app.wifi_profiles.as_ref().unwrap().mode,
            WifiProfilesMode::ProfileActions
        );
        handle_wifi_profiles_key(&mut app, KeyCode::Down, &client).await;
        handle_wifi_profiles_key(&mut app, KeyCode::Down, &client).await;
        assert_eq!(
            WifiProfileAction::from_index(app.wifi_profiles.as_ref().unwrap().selected),
            Some(WifiProfileAction::Delete)
        );
        handle_wifi_profiles_key(&mut app, KeyCode::Enter, &client).await;
        assert_eq!(
            app.wifi_profiles
                .as_ref()
                .unwrap()
                .delete_confirmation
                .as_deref(),
            Some("p39")
        );
        handle_wifi_profiles_key(&mut app, KeyCode::Esc, &client).await;
        assert!(app
            .wifi_profiles
            .as_ref()
            .unwrap()
            .delete_confirmation
            .is_none());
    }

    #[tokio::test]
    async fn wifi_profiles_menu_shows_management_and_create_new() {
        let mut app = TuiApp {
            wifi_profiles: Some(WifiProfilesView {
                interface: "wlan0".into(),
                mode: WifiProfilesMode::Menu,
                selected: 0,
                selected_profile: 0,
                delete_confirmation: None,
                profiles: vec![WifiClientProfileSummary {
                    id: "home".into(),
                    ssid: "HomeNet".into(),
                    country_code: None,
                    security: WifiClientSecurity::Wpa2,
                    priority: 10,
                    autoconnect: false,
                    created_at: 0,
                    modified_at: 0,
                    has_passphrase: true,
                }],
            }),
            ..Default::default()
        };
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(60, 15)).unwrap();
        terminal
            .draw(|frame| render_wifi_profiles(frame, frame.area(), &mut app))
            .unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(text.contains("Management"));
        assert!(text.contains("Create new"));
        // Top menu does not mix in profile table
        assert!(!text.contains("HomeNet"));

        let client = ApiClient::new("/nonexistent.sock");
        // Down moves to Create new
        handle_wifi_profiles_key(&mut app, KeyCode::Down, &client).await;
        assert_eq!(
            WifiProfilesMenuAction::from_index(app.wifi_profiles.as_ref().unwrap().selected),
            Some(WifiProfilesMenuAction::CreateNew)
        );

        // Enter on Create new opens WifiProfileEditor
        handle_wifi_profiles_key(&mut app, KeyCode::Enter, &client).await;
        assert_eq!(app.screen, Screen::WifiProfileEditor);
        assert!(app.wifi_profile_editor.is_some());

        // Cancel editor returns to profiles
        handle_wifi_profile_editor_key(&mut app, KeyCode::Esc, &client).await;
        assert_eq!(app.screen, Screen::WifiProfiles);

        // Now select Management
        handle_wifi_profiles_key(&mut app, KeyCode::Up, &client).await;
        assert_eq!(
            WifiProfilesMenuAction::from_index(app.wifi_profiles.as_ref().unwrap().selected),
            Some(WifiProfilesMenuAction::Management)
        );
        handle_wifi_profiles_key(&mut app, KeyCode::Enter, &client).await;
        assert_eq!(
            app.wifi_profiles.as_ref().unwrap().mode,
            WifiProfilesMode::Management
        );

        // In Management, HomeNet is displayed cleanly
        terminal
            .draw(|frame| render_wifi_profiles(frame, frame.area(), &mut app))
            .unwrap();
        let mgmt_text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(mgmt_text.contains("HomeNet"));
        assert!(mgmt_text.contains("home"));

        // Enter in Management opens ProfileActions
        handle_wifi_profiles_key(&mut app, KeyCode::Enter, &client).await;
        assert_eq!(
            app.wifi_profiles.as_ref().unwrap().mode,
            WifiProfilesMode::ProfileActions
        );
        terminal
            .draw(|frame| render_wifi_profiles(frame, frame.area(), &mut app))
            .unwrap();
        let actions_text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(actions_text.contains("Activate / Connect"));
        assert!(actions_text.contains("Edit profile"));
        assert!(actions_text.contains("Delete profile"));
        assert!(actions_text.contains("Deactivate client"));
        assert!(actions_text.contains("Back to profile list"));

        // Esc in ProfileActions goes back to Management
        handle_wifi_profiles_key(&mut app, KeyCode::Esc, &client).await;
        assert_eq!(
            app.wifi_profiles.as_ref().unwrap().mode,
            WifiProfilesMode::Management
        );

        // Esc in Management goes back to Menu
        handle_wifi_profiles_key(&mut app, KeyCode::Esc, &client).await;
        assert_eq!(
            app.wifi_profiles.as_ref().unwrap().mode,
            WifiProfilesMode::Menu
        );

        // Esc in Menu exits to Wifi screen
        handle_wifi_profiles_key(&mut app, KeyCode::Esc, &client).await;
        assert_eq!(app.screen, Screen::Wifi);
    }

    #[test]
    fn unconfigured_radio_never_defaults_to_ap_and_role_mapping_is_strict() {
        let status = InterfaceStatus {
            owned_ipv4_addresses: None,
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
            WifiRole::Unknown
        );
        assert_eq!(
            role_from_interface(InterfaceRole::Input, true),
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
            actions_open: true,
            ..WifiData::default()
        };
        assert_eq!(data.focused_radio().unwrap().interface, "wlan0");
        assert_eq!(data.cursor_limit(), 6);
        assert_eq!(actions(WifiRole::Client)[0].1, "Scan networks");
    }

    #[tokio::test]
    async fn wifi_editor_cursor_navigation_and_editing() {
        let mut app = TuiApp::default();
        let row = WifiRow {
            interface: "wlan0".into(),
            role: WifiRole::AccessPoint,
            ap: None,
            client: None,
        };
        let mut editor = WifiEditor::from_row(&row);
        editor.field = WifiField::Ssid;
        editor.ssid = "MyNet".into();
        editor.cursor = editor.ssid.len();
        app.wifi_editor = Some(editor);
        app.screen = Screen::WifiEditor;
        let client = ApiClient::new("/nonexistent.sock");

        handle_wifi_editor_key(&mut app, KeyCode::Left, &client).await;
        assert_eq!(app.wifi_editor.as_ref().unwrap().cursor, 4);

        handle_wifi_editor_key(&mut app, KeyCode::Char('1'), &client).await;
        assert_eq!(app.wifi_editor.as_ref().unwrap().ssid, "MyNe1t");
        assert_eq!(app.wifi_editor.as_ref().unwrap().cursor, 5);

        handle_wifi_editor_key(&mut app, KeyCode::Backspace, &client).await;
        assert_eq!(app.wifi_editor.as_ref().unwrap().ssid, "MyNet");
        assert_eq!(app.wifi_editor.as_ref().unwrap().cursor, 4);
    }

    #[tokio::test]
    async fn wifi_profile_editor_cursor_navigation_and_editing() {
        let mut app = TuiApp::default();
        let mut editor = WifiProfileEditor {
            interface: "wlan0".into(),
            original_id: None,
            field: ProfileField::Ssid,
            id: "net-1".into(),
            ssid: "Office".into(),
            security: WifiClientSecurity::Wpa2,
            country: String::new(),
            priority: "0".into(),
            autoconnect: false,
            passphrase: String::new(),
            has_passphrase: false,
            cursor: 6,
        };
        editor.cursor = editor.ssid.len();
        app.wifi_profile_editor = Some(editor);
        app.screen = Screen::WifiProfileEditor;
        let client = ApiClient::new("/nonexistent.sock");

        handle_wifi_profile_editor_key(&mut app, KeyCode::Home, &client).await;
        assert_eq!(app.wifi_profile_editor.as_ref().unwrap().cursor, 0);

        handle_wifi_profile_editor_key(&mut app, KeyCode::Char('X'), &client).await;
        assert_eq!(app.wifi_profile_editor.as_ref().unwrap().ssid, "XOffice");
        assert_eq!(app.wifi_profile_editor.as_ref().unwrap().cursor, 1);

        handle_wifi_profile_editor_key(&mut app, KeyCode::Delete, &client).await;
        assert_eq!(app.wifi_profile_editor.as_ref().unwrap().ssid, "Xffice");
        assert_eq!(app.wifi_profile_editor.as_ref().unwrap().cursor, 1);
    }

    #[test]
    fn wifi_connect_prompt_choices_omits_keep_static_when_no_static_ip() {
        let prompt_no_static =
            WifiConnectPrompt::new("wlan0".into(), "prof1".into(), "HomeNet".into(), None);
        assert_eq!(
            prompt_no_static.available_choices(),
            vec![WifiIpChoice::Dhcp, WifiIpChoice::NewStatic]
        );
        let fields = prompt_no_static.focusable_fields();
        assert_eq!(
            fields,
            vec![
                WifiConnectField::Choice(WifiIpChoice::Dhcp),
                WifiConnectField::Choice(WifiIpChoice::NewStatic),
                WifiConnectField::Submit,
                WifiConnectField::Cancel,
            ]
        );

        let prompt_with_static = WifiConnectPrompt::new(
            "wlan0".into(),
            "prof1".into(),
            "HomeNet".into(),
            Some("192.168.1.50/24".into()),
        );
        assert_eq!(
            prompt_with_static.available_choices(),
            vec![
                WifiIpChoice::Dhcp,
                WifiIpChoice::KeepStatic,
                WifiIpChoice::NewStatic
            ]
        );
        let fields_with_static = prompt_with_static.focusable_fields();
        assert_eq!(
            fields_with_static,
            vec![
                WifiConnectField::Choice(WifiIpChoice::Dhcp),
                WifiConnectField::Choice(WifiIpChoice::KeepStatic),
                WifiConnectField::Choice(WifiIpChoice::NewStatic),
                WifiConnectField::Submit,
                WifiConnectField::Cancel,
            ]
        );
    }

    #[tokio::test]
    async fn wifi_connect_prompt_key_handling() {
        let prompt = WifiConnectPrompt::new(
            "wlan0".into(),
            "prof1".into(),
            "HomeNet".into(),
            Some("192.168.1.50/24".into()),
        );
        let mut app = TuiApp {
            screen: Screen::WifiConnectPrompt,
            wifi_connect: Some(prompt),
            ..Default::default()
        };
        let client = ApiClient::new("/nonexistent.sock");

        // Move down to KeepStatic
        handle_wifi_connect_prompt_key(&mut app, KeyCode::Down, &client).await;
        let p = app.wifi_connect.as_ref().unwrap();
        assert_eq!(p.field, WifiConnectField::Choice(WifiIpChoice::KeepStatic));
        assert_eq!(p.choice, WifiIpChoice::Dhcp);

        // Move down to NewStatic
        handle_wifi_connect_prompt_key(&mut app, KeyCode::Down, &client).await;
        let p = app.wifi_connect.as_ref().unwrap();
        assert_eq!(p.field, WifiConnectField::Choice(WifiIpChoice::NewStatic));
        assert_eq!(p.choice, WifiIpChoice::Dhcp);

        // Enter on NewStatic focuses StaticCidr
        handle_wifi_connect_prompt_key(&mut app, KeyCode::Enter, &client).await;
        let p = app.wifi_connect.as_ref().unwrap();
        assert_eq!(p.field, WifiConnectField::StaticCidr);

        // Backspace removes character from CIDR
        handle_wifi_connect_prompt_key(&mut app, KeyCode::Backspace, &client).await;
        let p = app.wifi_connect.as_ref().unwrap();
        assert_eq!(p.static_cidr, "192.168.1.50/2");

        // Type char
        handle_wifi_connect_prompt_key(&mut app, KeyCode::Char('5'), &client).await;
        let p = app.wifi_connect.as_ref().unwrap();
        assert_eq!(p.static_cidr, "192.168.1.50/25");

        // Home key moves cursor to 0
        handle_wifi_connect_prompt_key(&mut app, KeyCode::Home, &client).await;
        let p = app.wifi_connect.as_ref().unwrap();
        assert_eq!(p.cursor, 0);

        // Delete removes first character
        handle_wifi_connect_prompt_key(&mut app, KeyCode::Delete, &client).await;
        let p = app.wifi_connect.as_ref().unwrap();
        assert_eq!(p.static_cidr, "92.168.1.50/25");
        assert_eq!(p.cursor, 0);

        // Insert character at start
        handle_wifi_connect_prompt_key(&mut app, KeyCode::Char('1'), &client).await;
        let p = app.wifi_connect.as_ref().unwrap();
        assert_eq!(p.static_cidr, "192.168.1.50/25");
        assert_eq!(p.cursor, 1);

        // End key moves cursor to end
        handle_wifi_connect_prompt_key(&mut app, KeyCode::End, &client).await;
        let p = app.wifi_connect.as_ref().unwrap();
        assert_eq!(p.cursor, p.static_cidr.len());

        // Left key moves cursor left
        handle_wifi_connect_prompt_key(&mut app, KeyCode::Left, &client).await;
        let p = app.wifi_connect.as_ref().unwrap();
        assert_eq!(p.cursor, p.static_cidr.len() - 1);

        // Right key moves cursor right
        handle_wifi_connect_prompt_key(&mut app, KeyCode::Right, &client).await;
        let p = app.wifi_connect.as_ref().unwrap();
        assert_eq!(p.cursor, p.static_cidr.len());

        // Esc closes prompt
        handle_wifi_connect_prompt_key(&mut app, KeyCode::Esc, &client).await;
        assert!(app.wifi_connect.is_none());
        assert_eq!(app.screen, Screen::Wifi);
    }

    #[test]
    fn wifi_profile_actions_list_area_excludes_header_for_mouse_clicks() {
        let mut app = TuiApp {
            wifi_profiles: Some(WifiProfilesView {
                interface: "wlan0".into(),
                mode: WifiProfilesMode::ProfileActions,
                selected: 0,
                selected_profile: 0,
                delete_confirmation: None,
                profiles: vec![WifiClientProfileSummary {
                    id: "p0".into(),
                    ssid: "net0".into(),
                    country_code: None,
                    security: WifiClientSecurity::Open,
                    priority: 0,
                    autoconnect: false,
                    created_at: 0,
                    modified_at: 0,
                    has_passphrase: false,
                }],
            }),
            ..Default::default()
        };
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| render_wifi_profiles(frame, frame.area(), &mut app))
            .unwrap();

        let list_area = app.ui.list_area.expect("list_area must be populated");
        assert_eq!(app.ui.list_count, WifiProfileAction::ALL.len());
        assert_eq!(app.ui.list_scroll_offset, 0);
        // Header height is 2 lines, panel top border is 1 line, so list_area starts at y = 3
        assert_eq!(list_area.y, 3);
    }

    #[test]
    fn render_wifi_displays_conflict_advice_when_competing_managers_present() {
        use crate::wifi::{HostapdState, WifiApSpec};

        let mut app = TuiApp {
            wifi: WifiData {
                rows: vec![WifiRow {
                    interface: "wlp1s0".to_string(),
                    role: WifiRole::AccessPoint,
                    ap: Some(WifiApStatus {
                        interface: "wlp1s0".to_string(),
                        spec: WifiApSpec {
                            interface: "wlp1s0".to_string(),
                            ssid: "TestAP".to_string(),
                            country_code: Some("US".to_string()),
                            band: crate::config::WifiBand::Ghz2,
                            channel: 6,
                            channel_width: crate::config::WifiChannelWidth::Ht20,
                            security: crate::config::WifiSecurity::Open,
                            hidden: false,
                            client_isolation: false,
                            max_stations: 32,
                            passphrase_file: None,
                        },
                        pid: 0,
                        hostapd_state: HostapdState::Disabled,
                        num_stations: None,
                        health: WifiHealth::Retrying {
                            error: "ctrl socket timeout".to_string(),
                            attempts: 3,
                            retry_in_secs: Some(10),
                            competing_managers: vec!["iwd".to_string()],
                            advice: Some("Stop service: sudo sv down iwd".to_string()),
                        },
                    }),
                    client: None,
                }],
                selected: 0,
                selected_radio: 0,
                actions_open: false,
                ap_disabled: false,
                client_disabled: false,
                error: None,
            },
            ..Default::default()
        };

        let backend = ratatui::backend::TestBackend::new(100, 24);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render_wifi(frame, frame.area(), &mut app))
            .unwrap();

        let buffer = terminal.backend().buffer();
        let content = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(content.contains("Conflict"));
        assert!(content.contains("iwd"));
        assert!(content.contains("sudo sv down iwd"));
    }
}
