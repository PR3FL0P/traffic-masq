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

mod ap_editor;
mod connect;
mod profile_editor;
mod profiles;
mod scan;

pub(crate) use ap_editor::{handle_wifi_editor_key, render_wifi_editor};
pub(crate) use connect::{
    handle_wifi_connect_prompt_key, open_wifi_connect_prompt, render_wifi_connect_prompt,
};
pub(crate) use profile_editor::{handle_wifi_profile_editor_key, render_wifi_profile_editor};
pub(crate) use profiles::{handle_wifi_profiles_key, render_wifi_profiles};
pub(crate) use scan::{handle_wifi_scan_key, render_wifi_scan};

use profiles::open_profiles;

#[cfg(test)]
use ap_editor::{ap_provision_request, ap_settings};
#[cfg(test)]
use connect::{apply_wifi_static_ip, submit_wifi_connect};

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
    super::input::move_clamped(fields, field, forward)
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
        let cursor = super::input::grapheme_count(&ssid);
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


    pub(crate) fn active_value(&self) -> Option<&str> {
        match self.field {
            WifiField::Ssid => Some(&self.ssid),
            WifiField::Passphrase => Some(&self.passphrase),
            WifiField::CountryCode => Some(&self.country_code),
            _ => None,
        }
    }

    pub(crate) fn reset_cursor(&mut self) {
        self.cursor = self.active_value().map_or(0, super::input::grapheme_count);
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
        let cursor = super::input::grapheme_count(&id);
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
        let cursor = super::input::grapheme_count(&profile.id);
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
        self.cursor = self.active_value().map_or(0, super::input::grapheme_count);
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
        let health = match row.role {
            WifiRole::AccessPoint => row.ap.as_ref().map(|ap| &ap.health),
            WifiRole::Client => row.client.as_ref().map(|c| &c.health),
            WifiRole::Unknown => row
                .ap
                .as_ref()
                .map(|ap| &ap.health)
                .or_else(|| row.client.as_ref().map(|c| &c.health)),
        };
        let (competing, advice_opt) = match health {
            Some(WifiHealth::Retrying {
                competing_managers,
                advice,
                ..
            }) if !competing_managers.is_empty() => {
                (Some(competing_managers), advice.as_deref())
            }
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
        Ok(Response::WifiError { detail }) => {
            app.push_message(LogLevel::Error, format!("{detail:?}"));
        }
        Ok(Response::WifiClientError { detail }) => {
            app.push_message(LogLevel::Error, format!("{detail:?}"));
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
        "•".repeat(super::input::grapheme_count(value))
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
    match value {
        WpaSupplicantScanSecurity::Open => "open",
        WpaSupplicantScanSecurity::Wpa2Psk => "wpa2",
        WpaSupplicantScanSecurity::Wpa2Wpa3Transition => "wpa2/wpa3 transition",
        WpaSupplicantScanSecurity::Wpa3Sae => "wpa3",
        WpaSupplicantScanSecurity::EnterpriseOrUnsupported | WpaSupplicantScanSecurity::Unknown => {
            "unsupported"
        }
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
    match row.role {
        WifiRole::AccessPoint => {
            if let Some(ap) = &row.ap {
                describe_health(
                    &ap.health,
                    &format!("serving {}", ap.spec.ssid),
                    &format!("serving {} — starting…", ap.spec.ssid),
                )
            } else {
                "not configured".into()
            }
        }
        WifiRole::Client => {
            if let Some(client) = &row.client {
                describe_health(
                    &client.health,
                    &format!("connected to {}", client.spec.ssid),
                    &format!("joining {} — starting…", client.spec.ssid),
                )
            } else {
                "not configured".into()
            }
        }
        WifiRole::Unknown => {
            if let Some(ap) = &row.ap {
                describe_health(
                    &ap.health,
                    &format!("serving {}", ap.spec.ssid),
                    &format!("serving {} — starting…", ap.spec.ssid),
                )
            } else if let Some(client) = &row.client {
                describe_health(
                    &client.health,
                    &format!("connected to {}", client.spec.ssid),
                    &format!("joining {} — starting…", client.spec.ssid),
                )
            } else {
                "not configured".into()
            }
        }
    }
}

/// Turns structured health into a short user-facing sentence.
fn describe_health(
    health: &WifiHealth,
    ok_description: &str,
    starting_description: &str,
) -> String {
    match health {
        WifiHealth::Healthy => ok_description.to_string(),
        WifiHealth::Starting => starting_description.to_string(),
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
mod tests;
