use crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Gauge, Paragraph};
use zeroize::Zeroize;

use crate::api::client::ApiClient;
use crate::api::model::{
    ProvisioningOutputRequest, ProvisioningStage, ProvisioningUplinkRequest, ProvisioningWarning,
    Request, Response, RouterProvisioningApplyRequest, RouterProvisioningErrorDetail,
    RouterProvisioningPreviewRequest, RouterProvisioningPreviewView, RouterProvisioningRequest,
    RouterProvisioningStatusView,
};
use crate::config::{WifiBand, WifiChannelWidth, WifiClientSecurity, WifiSecurity};
use crate::core::router_provisioning::ProvisioningDownstreamOverrides;
use crate::wifi::{WifiClientProfileSummary, WpaSupplicantScanResult, WpaSupplicantScanSecurity};

use super::layout::panel;
use super::logs::LogLevel;
use super::theme;
use super::{current_unix_time, Screen, TuiApp};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    UplinkInterface,
    UplinkNetwork,
    UplinkPassphrase,
    OutputInterface,
    OutputSsid,
    OutputSecurity,
    OutputPassphrase,
    AllowManagement,
    Preview,
}

const FIELDS: [Field; 9] = [
    Field::UplinkInterface,
    Field::UplinkNetwork,
    Field::UplinkPassphrase,
    Field::OutputInterface,
    Field::OutputSsid,
    Field::OutputSecurity,
    Field::OutputPassphrase,
    Field::AllowManagement,
    Field::Preview,
];

#[derive(Debug, Clone)]
enum NetworkChoice {
    Scanned(WpaSupplicantScanResult),
    Saved(WifiClientProfileSummary),
}

impl NetworkChoice {
    fn ssid(&self) -> &str {
        match self {
            Self::Scanned(value) => &value.ssid,
            Self::Saved(value) => &value.ssid,
        }
    }

    fn security(&self) -> Option<WifiClientSecurity> {
        match self {
            Self::Saved(value) => Some(value.security),
            Self::Scanned(value) => match value.security {
                WpaSupplicantScanSecurity::Open => Some(WifiClientSecurity::Open),
                WpaSupplicantScanSecurity::Wpa2Psk
                | WpaSupplicantScanSecurity::Wpa2Wpa3Transition => Some(WifiClientSecurity::Wpa2),
                WpaSupplicantScanSecurity::Wpa3Sae => Some(WifiClientSecurity::Wpa3),
                WpaSupplicantScanSecurity::EnterpriseOrUnsupported
                | WpaSupplicantScanSecurity::Unknown => None,
            },
        }
    }

    fn country_code(&self) -> Option<String> {
        match self {
            Self::Saved(value) => value.country_code.clone(),
            Self::Scanned(_) => None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ProvisioningWizard {
    field: Field,
    interfaces: Vec<String>,
    uplink_index: usize,
    output_index: usize,
    uplink_ssid: String,
    uplink_country: Option<String>,
    uplink_security: WifiClientSecurity,
    uplink_passphrase: String,
    output_ssid: String,
    output_security: WifiSecurity,
    output_passphrase: String,
    allow_management_change: bool,
    choices: Vec<NetworkChoice>,
    choice_index: usize,
    preview: Option<RouterProvisioningPreviewView>,
    show_advanced: bool,
    pending: Option<PendingProvisioning>,
    error: Option<String>,
}

impl Drop for ProvisioningWizard {
    fn drop(&mut self) {
        self.uplink_passphrase.zeroize();
        self.output_passphrase.zeroize();
    }
}

#[derive(Debug)]
struct PendingProvisioning {
    token: String,
    applied_at_unix: u64,
    status: Option<RouterProvisioningStatusView>,
}

pub(crate) fn open(app: &mut TuiApp) {
    let interfaces = app
        .dashboard
        .interfaces
        .iter()
        .filter(|status| status.interface.is_wireless)
        .map(|status| status.interface.name.clone())
        .collect::<Vec<_>>();
    if interfaces.len() < 2 {
        app.push_message(
            LogLevel::Warn,
            "One-step setup requires at least two detected wireless interfaces",
        );
        return;
    }
    app.provisioning = Some(ProvisioningWizard {
        field: Field::UplinkInterface,
        interfaces,
        uplink_index: 0,
        output_index: 1,
        uplink_ssid: String::new(),
        uplink_country: None,
        uplink_security: WifiClientSecurity::Wpa2,
        uplink_passphrase: String::new(),
        output_ssid: "traffic-masq".into(),
        output_security: WifiSecurity::Wpa2,
        output_passphrase: String::new(),
        allow_management_change: false,
        choices: Vec::new(),
        choice_index: 0,
        preview: None,
        show_advanced: false,
        pending: None,
        error: None,
    });
    app.screen = Screen::RouterProvisioning;
}

fn selected_line(field: Field, active: Field, label: &str, value: String) -> Line<'static> {
    let selected = field == active;
    Line::styled(
        format!("{}{label:<22}{value}", if selected { "▶ " } else { "  " }),
        if selected {
            Style::default()
                .fg(theme::SELECTED_FG)
                .bg(theme::SELECTED_BG)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme::TEXT)
        },
    )
}

fn masked(value: &str) -> String {
    if value.is_empty() {
        "<use stored key if available>".into()
    } else {
        "•".repeat(value.chars().count())
    }
}

pub(crate) fn render_wizard(frame: &mut ratatui::Frame<'_>, area: Rect, app: &TuiApp) {
    let Some(wizard) = &app.provisioning else {
        return;
    };
    let uplink = &wizard.interfaces[wizard.uplink_index];
    let output = &wizard.interfaces[wizard.output_index];
    let mut lines = vec![
        Line::styled(
            "Guided setup: upstream Wi-Fi → local access point → derived LAN/DHCP",
            Style::default().fg(theme::MUTED),
        ),
        Line::from(""),
        selected_line(
            Field::UplinkInterface,
            wizard.field,
            "Uplink interface",
            uplink.clone(),
        ),
        selected_line(
            Field::UplinkNetwork,
            wizard.field,
            "Upstream network",
            if wizard.uplink_ssid.is_empty() {
                "Select scanned/saved network".into()
            } else {
                wizard.uplink_ssid.clone()
            },
        ),
        selected_line(
            Field::UplinkPassphrase,
            wizard.field,
            "Upstream passphrase",
            masked(&wizard.uplink_passphrase),
        ),
        selected_line(
            Field::OutputInterface,
            wizard.field,
            "Output interface",
            output.clone(),
        ),
        selected_line(
            Field::OutputSsid,
            wizard.field,
            "Access-point SSID",
            wizard.output_ssid.clone(),
        ),
        selected_line(
            Field::OutputSecurity,
            wizard.field,
            "AP security",
            format!("{:?}", wizard.output_security),
        ),
        selected_line(
            Field::OutputPassphrase,
            wizard.field,
            "AP passphrase",
            masked(&wizard.output_passphrase),
        ),
        selected_line(
            Field::AllowManagement,
            wizard.field,
            "Allow management change",
            wizard.allow_management_change.to_string(),
        ),
        selected_line(
            Field::Preview,
            wizard.field,
            "",
            "Preview and confirm".into(),
        ),
        Line::from(""),
        Line::styled(
            "↑/↓ move · Enter select/continue · Esc cancel",
            Style::default().fg(theme::MUTED),
        ),
    ];
    if let Some(error) = &wizard.error {
        lines.push(Line::styled(
            format!("Error: {error}"),
            Style::default().fg(theme::BAD),
        ));
    }
    frame.render_widget(Paragraph::new(lines).block(panel("Set up router")), area);
}

pub(crate) async fn handle_wizard_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    let Some(wizard) = app.provisioning.as_mut() else {
        app.screen = Screen::Router;
        return;
    };
    match key {
        KeyCode::Esc => cancel(app),
        KeyCode::Up | KeyCode::BackTab => move_field(wizard, false),
        KeyCode::Down | KeyCode::Tab => move_field(wizard, true),
        KeyCode::Left => cycle_value(wizard, false),
        KeyCode::Right => cycle_value(wizard, true),
        KeyCode::Enter => match wizard.field {
            Field::UplinkNetwork => load_networks(app, client).await,
            Field::Preview => preview(app, client).await,
            Field::UplinkInterface
            | Field::OutputInterface
            | Field::OutputSecurity
            | Field::AllowManagement => cycle_value(wizard, true),
            _ => move_field(wizard, true),
        },
        KeyCode::Backspace => {
            if let Some(value) = active_text(wizard) {
                value.pop();
            }
        }
        KeyCode::Char(character) => {
            if let Some(value) = active_text(wizard) {
                value.push(character);
            }
        }
        _ => {}
    }
}

fn move_field(wizard: &mut ProvisioningWizard, forward: bool) {
    let index = FIELDS
        .iter()
        .position(|field| *field == wizard.field)
        .unwrap_or(0);
    wizard.field = if forward {
        FIELDS[(index + 1).min(FIELDS.len() - 1)]
    } else {
        FIELDS[index.saturating_sub(1)]
    };
}

fn cycle_value(wizard: &mut ProvisioningWizard, forward: bool) {
    let next = |index: usize, len: usize| {
        if forward {
            (index + 1) % len
        } else {
            (index + len - 1) % len
        }
    };
    match wizard.field {
        Field::UplinkInterface => {
            wizard.uplink_index = next(wizard.uplink_index, wizard.interfaces.len())
        }
        Field::OutputInterface => {
            wizard.output_index = next(wizard.output_index, wizard.interfaces.len())
        }
        Field::OutputSecurity => {
            wizard.output_security = match (wizard.output_security, forward) {
                (WifiSecurity::Wpa2, true) | (WifiSecurity::Open, false) => WifiSecurity::Wpa2Wpa3,
                (WifiSecurity::Wpa2Wpa3, true) | (WifiSecurity::Wpa3, false) => WifiSecurity::Wpa3,
                (WifiSecurity::Wpa3, true) | (WifiSecurity::Wpa2Wpa3, false) => WifiSecurity::Open,
                (WifiSecurity::Open, true) | (WifiSecurity::Wpa2, false) => WifiSecurity::Wpa2,
            }
        }
        Field::AllowManagement => wizard.allow_management_change = !wizard.allow_management_change,
        _ => {}
    }
}

fn active_text(wizard: &mut ProvisioningWizard) -> Option<&mut String> {
    match wizard.field {
        Field::UplinkPassphrase => Some(&mut wizard.uplink_passphrase),
        Field::OutputSsid => Some(&mut wizard.output_ssid),
        Field::OutputPassphrase => Some(&mut wizard.output_passphrase),
        _ => None,
    }
}

async fn load_networks(app: &mut TuiApp, client: &ApiClient) {
    let Some(wizard) = app.provisioning.as_mut() else {
        return;
    };
    wizard.error = None;
    wizard.choices.clear();
    let interface = wizard.interfaces[wizard.uplink_index].clone();
    match client.request(&Request::WifiClientScan { interface }).await {
        Ok(Response::WifiClientScanResults { mut results, .. }) => {
            results.sort_by_key(|network| std::cmp::Reverse(network.signal_dbm));
            wizard.choices.extend(
                results
                    .into_iter()
                    .filter(|network| !network.ssid.is_empty())
                    .map(NetworkChoice::Scanned),
            );
        }
        Ok(Response::WifiClientError { detail }) => {
            wizard.error = Some(format_provisioning_source_error("scan", &detail))
        }
        Ok(_) => wizard.error = Some("Unexpected response while scanning networks".into()),
        Err(error) => wizard.error = Some(error.to_string()),
    }
    if let Ok(Response::WifiClientProfiles { mut profiles }) =
        client.request(&Request::ListWifiClientProfiles).await
    {
        profiles.sort_by_key(|profile| std::cmp::Reverse(profile.priority));
        wizard
            .choices
            .extend(profiles.into_iter().map(NetworkChoice::Saved));
    }
    if wizard.choices.is_empty() {
        wizard
            .error
            .get_or_insert_with(|| "No supported scanned or saved networks found".into());
    } else {
        wizard.choice_index = 0;
        app.screen = Screen::RouterProvisioningNetworks;
    }
}

fn format_provisioning_source_error<T: std::fmt::Debug>(source: &str, detail: &T) -> String {
    format!("Wi-Fi {source} failed: {detail:?}")
}

pub(crate) fn render_networks(frame: &mut ratatui::Frame<'_>, area: Rect, app: &TuiApp) {
    let Some(wizard) = &app.provisioning else {
        return;
    };
    let lines = wizard
        .choices
        .iter()
        .enumerate()
        .map(|(index, choice)| {
            let (source, detail) = match choice {
                NetworkChoice::Scanned(value) => ("scan", format!("{} dBm", value.signal_dbm)),
                NetworkChoice::Saved(value) => (
                    "saved",
                    if value.has_passphrase {
                        "key saved".into()
                    } else {
                        "no key".into()
                    },
                ),
            };
            Line::styled(
                format!(
                    "{}{: <32} {: <7} {detail}",
                    if index == wizard.choice_index {
                        "▶ "
                    } else {
                        "  "
                    },
                    choice.ssid(),
                    source
                ),
                if index == wizard.choice_index {
                    Style::default()
                        .fg(theme::SELECTED_FG)
                        .bg(theme::SELECTED_BG)
                } else {
                    Style::default().fg(theme::TEXT)
                },
            )
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(lines).block(panel("Choose upstream network")),
        area,
    );
}

pub(crate) async fn handle_network_key(app: &mut TuiApp, key: KeyCode) {
    let Some(wizard) = app.provisioning.as_mut() else {
        return;
    };
    match key {
        KeyCode::Esc => app.screen = Screen::RouterProvisioning,
        KeyCode::Up => wizard.choice_index = wizard.choice_index.saturating_sub(1),
        KeyCode::Down => {
            wizard.choice_index =
                (wizard.choice_index + 1).min(wizard.choices.len().saturating_sub(1))
        }
        KeyCode::Enter => {
            let Some(choice) = wizard.choices.get(wizard.choice_index) else {
                return;
            };
            let Some(security) = choice.security() else {
                wizard.error = Some("Enterprise or unknown Wi-Fi security is not supported".into());
                app.screen = Screen::RouterProvisioning;
                return;
            };
            wizard.uplink_ssid = choice.ssid().to_owned();
            wizard.uplink_country = choice.country_code();
            wizard.uplink_security = security;
            wizard.field = Field::UplinkPassphrase;
            app.screen = Screen::RouterProvisioning;
        }
        _ => {}
    }
}

fn request_from(wizard: &ProvisioningWizard) -> RouterProvisioningRequest {
    RouterProvisioningRequest {
        uplink: ProvisioningUplinkRequest {
            interface: wizard.interfaces[wizard.uplink_index].clone(),
            ssid: wizard.uplink_ssid.clone(),
            country_code: wizard.uplink_country.clone(),
            security: wizard.uplink_security,
        },
        output: ProvisioningOutputRequest {
            interface: wizard.interfaces[wizard.output_index].clone(),
            ssid: wizard.output_ssid.clone(),
            country_code: None,
            band: WifiBand::Ghz2,
            channel: 0,
            channel_width: WifiChannelWidth::Ht20,
            security: wizard.output_security,
            hidden: false,
            client_isolation: false,
            max_stations: 32,
        },
        downstream: ProvisioningDownstreamOverrides::default(),
        allow_management_change: wizard.allow_management_change,
    }
}

async fn preview(app: &mut TuiApp, client: &ApiClient) {
    let Some(wizard) = app.provisioning.as_mut() else {
        return;
    };
    wizard.error = None;
    if wizard.uplink_ssid.is_empty() || wizard.output_ssid.trim().is_empty() {
        wizard.error = Some("Select an upstream network and enter an AP SSID".into());
        return;
    }
    let request = RouterProvisioningPreviewRequest {
        provisioning: request_from(wizard),
        uplink_secret_pending: !wizard.uplink_passphrase.is_empty(),
        output_secret_pending: !wizard.output_passphrase.is_empty(),
    };
    match client
        .request(&Request::RouterProvisioningPreview { request })
        .await
    {
        Ok(Response::RouterProvisioningPreview { preview }) => {
            wizard.preview = Some(preview);
            app.screen = Screen::RouterProvisioningConfirm;
        }
        Ok(Response::RouterProvisioningError { detail }) => {
            wizard.error = Some(describe_error(&detail))
        }
        Ok(_) => wizard.error = Some("Unexpected provisioning preview response".into()),
        Err(error) => wizard.error = Some(error.to_string()),
    }
}

pub(crate) fn render_confirmation(frame: &mut ratatui::Frame<'_>, area: Rect, app: &TuiApp) {
    let Some(wizard) = &app.provisioning else {
        return;
    };
    let Some(preview) = &wizard.preview else {
        return;
    };
    let mut lines = vec![
        Line::from(format!(
            "Uplink: {} → {} ({:?})",
            preview.uplink.interface, preview.uplink.ssid, preview.uplink.security
        )),
        Line::from(format!(
            "Access point: {} → {} ({:?})",
            preview.output.interface, preview.output.ssid, preview.output.security
        )),
    ];
    for warning in &preview.warnings {
        lines.push(Line::styled(
            format!("WARNING: {}", describe_warning(warning)),
            Style::default().fg(theme::WARN),
        ));
    }
    if wizard.show_advanced {
        lines.extend([
            Line::from(""),
            Line::styled(
                "Derived LAN/DHCP (server preview)",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Line::from(format!(
                "Subnet/address: {} / {}",
                preview.downstream.subnet, preview.downstream.interface_ipv4
            )),
            Line::from(format!(
                "Pool: {}–{} · router {}",
                preview.downstream.pool_start,
                preview.downstream.pool_end,
                preview.downstream.router
            )),
            Line::from(format!(
                "DNS: {} · lease: {}s",
                if preview.downstream.dns_servers.is_empty() {
                    "not advertised".into()
                } else {
                    preview
                        .downstream
                        .dns_servers
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                },
                preview.downstream.lease_seconds
            )),
        ]);
    }
    lines.extend([
        Line::from(""),
        Line::styled(
            "Enter applies once; the daemon revalidates against fresh state.",
            Style::default()
                .fg(theme::WARN)
                .add_modifier(Modifier::BOLD),
        ),
        Line::styled(
            "Tab toggles advanced values · Esc returns without applying",
            Style::default().fg(theme::MUTED),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(lines).block(panel("Confirm router setup")),
        area,
    );
}

pub(crate) async fn handle_confirmation_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    match key {
        KeyCode::Esc => app.screen = Screen::RouterProvisioning,
        KeyCode::Tab | KeyCode::BackTab => {
            if let Some(wizard) = app.provisioning.as_mut() {
                wizard.show_advanced = !wizard.show_advanced;
            }
        }
        KeyCode::Enter => apply(app, client).await,
        _ => {}
    }
}

async fn apply(app: &mut TuiApp, client: &ApiClient) {
    let Some(wizard) = app.provisioning.as_mut() else {
        return;
    };
    let mut uplink_passphrase = std::mem::take(&mut wizard.uplink_passphrase);
    let mut output_passphrase = std::mem::take(&mut wizard.output_passphrase);
    let request = RouterProvisioningApplyRequest {
        provisioning: request_from(wizard),
        uplink_passphrase: (!uplink_passphrase.is_empty()).then(|| uplink_passphrase.clone()),
        output_passphrase: (!output_passphrase.is_empty()).then(|| output_passphrase.clone()),
    };
    let result = client
        .request(&Request::RouterProvisioningApply { request })
        .await;
    uplink_passphrase.zeroize();
    output_passphrase.zeroize();
    match result {
        Ok(Response::RouterProvisioningApplied { token, preview }) => {
            wizard.preview = Some(preview);
            wizard.pending = Some(PendingProvisioning {
                token,
                applied_at_unix: current_unix_time(),
                status: None,
            });
            app.screen = Screen::RouterProvisioningPending;
        }
        Ok(Response::RouterProvisioningError { detail }) => {
            wizard.error = Some(describe_error(&detail));
            app.screen = Screen::RouterProvisioning;
        }
        Ok(_) => {
            wizard.error = Some("Unexpected provisioning apply response".into());
            app.screen = Screen::RouterProvisioning;
        }
        Err(error) => {
            wizard.error = Some(error.to_string());
            app.screen = Screen::RouterProvisioning;
        }
    }
}

pub(crate) async fn refresh_pending(app: &mut TuiApp, client: &ApiClient) {
    let Some(pending) = app
        .provisioning
        .as_mut()
        .and_then(|wizard| wizard.pending.as_mut())
    else {
        return;
    };
    if let Ok(Response::RouterProvisioningStatus { status }) =
        client.request(&Request::RouterProvisioningStatus).await
    {
        pending.status = Some(status);
    }
}

pub(crate) fn render_pending(frame: &mut ratatui::Frame<'_>, area: Rect, app: &TuiApp) {
    let Some(wizard) = &app.provisioning else {
        return;
    };
    let Some(pending) = &wizard.pending else {
        return;
    };
    let remaining = app
        .router_rollback_timeout_seconds
        .saturating_sub(current_unix_time().saturating_sub(pending.applied_at_unix));
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(4)])
        .split(area);
    let ratio = if app.router_rollback_timeout_seconds == 0 {
        0.0
    } else {
        remaining as f64 / app.router_rollback_timeout_seconds as f64
    };
    frame.render_widget(
        Gauge::default()
            .block(panel("Automatic rollback countdown"))
            .ratio(ratio.clamp(0.0, 1.0))
            .label(format!("{remaining}s remaining")),
        chunks[0],
    );
    let mut lines = vec![Line::from(format!("Transaction: {}", pending.token))];
    if let Some(status) = &pending.status {
        lines.push(Line::styled(
            format!("Stage: {:?} · ready: {}", status.stage, status.ready),
            Style::default().fg(stage_color(status.stage)),
        ));
        for failure in &status.failures {
            lines.push(Line::styled(
                format!("  {failure}"),
                Style::default().fg(theme::BAD),
            ));
        }
    } else {
        lines.push(Line::styled(
            "Waiting for provisioning status…",
            Style::default().fg(theme::WARN),
        ));
    }
    lines.extend([
        Line::from(""),
        Line::styled(
            "Enter commits after connectivity verification",
            Style::default().fg(theme::GOOD),
        ),
        Line::styled(
            "Esc rolls back immediately",
            Style::default().fg(theme::WARN),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(lines).block(panel("Router setup applied")),
        chunks[1],
    );
}

fn stage_color(stage: ProvisioningStage) -> ratatui::style::Color {
    match stage {
        ProvisioningStage::Ready => theme::GOOD,
        ProvisioningStage::AwaitingConfirmation => theme::WARN,
        ProvisioningStage::Inactive
        | ProvisioningStage::Degraded
        | ProvisioningStage::RollbackFailed => theme::BAD,
    }
}

pub(crate) async fn handle_pending_key(app: &mut TuiApp, key: KeyCode, client: &ApiClient) {
    match key {
        KeyCode::Enter => finish(app, client, true).await,
        KeyCode::Esc => finish(app, client, false).await,
        _ => {}
    }
}

async fn finish(app: &mut TuiApp, client: &ApiClient, commit: bool) {
    let request = if commit {
        Request::RouterCommit
    } else {
        Request::RouterRollback
    };
    match client.request(&request).await {
        Ok(Response::RouterCommitted { revision }) if commit => {
            app.push_message(
                LogLevel::Info,
                format!("Router setup committed (revision {revision})"),
            );
            app.provisioning = None;
            app.screen = Screen::Router;
        }
        Ok(Response::RouterRolledBack) if !commit => {
            app.push_message(LogLevel::Info, "Router setup rolled back");
            app.provisioning = None;
            app.screen = Screen::Router;
        }
        Ok(Response::RouterError { detail }) => app.push_message(
            LogLevel::Error,
            format!("Router transaction failed: {detail:?}"),
        ),
        Ok(response) => app.push_message(
            LogLevel::Error,
            format!("Unexpected response: {response:?}"),
        ),
        Err(error) => app.push_message(LogLevel::Error, error.to_string()),
    }
}

fn cancel(app: &mut TuiApp) {
    app.provisioning = None;
    app.screen = Screen::Router;
}

fn describe_warning(warning: &ProvisioningWarning) -> String {
    match warning {
        ProvisioningWarning::ManagementInterfaceAffected { interface } => {
            format!("management interface {interface} may be disrupted")
        }
        ProvisioningWarning::DownstreamSubnetRelocated {
            preferred,
            selected,
        } => format!("LAN moved from {preferred} to conflict-free {selected}"),
        ProvisioningWarning::NoDownstreamDns => "downstream DHCP will not advertise DNS".into(),
        ProvisioningWarning::InterfaceConfigurationReplaced { interface } => {
            format!("existing configuration on {interface} will be replaced")
        }
        ProvisioningWarning::PendingSecret { interface } => {
            format!("a new write-only key will be supplied for {interface}")
        }
    }
}

fn describe_error(detail: &RouterProvisioningErrorDetail) -> String {
    match detail {
        RouterProvisioningErrorDetail::RouterDisabled => {
            "Enable [router] before running setup".into()
        }
        RouterProvisioningErrorDetail::GlobalServiceDisabled { service } => {
            format!("Enable the global {service} service and restart the daemon")
        }
        RouterProvisioningErrorDetail::InterfaceReused { interface } => {
            format!("Choose two different interfaces; {interface} is selected twice")
        }
        RouterProvisioningErrorDetail::InterfaceNotFound { interface } => {
            format!("Interface {interface} is no longer present; refresh and select again")
        }
        RouterProvisioningErrorDetail::RadioReused { phy, .. } => {
            format!("Both interfaces use radio {phy}; choose separate radios")
        }
        RouterProvisioningErrorDetail::ManagementConfirmationRequired { interface } => {
            format!("{interface} is management; explicitly enable the management-change option")
        }
        RouterProvisioningErrorDetail::UplinkSecretMissing { interface } => {
            format!("Enter or store the upstream passphrase for {interface}")
        }
        RouterProvisioningErrorDetail::OutputSecretMissing { interface } => {
            format!("Enter or store the AP passphrase for {interface}")
        }
        RouterProvisioningErrorDetail::InvalidSecret { message }
        | RouterProvisioningErrorDetail::InvalidPool { message }
        | RouterProvisioningErrorDetail::InvalidConfiguration { message }
        | RouterProvisioningErrorDetail::Other { message } => message.clone(),
        RouterProvisioningErrorDetail::SubnetConflict {
            requested,
            conflicting,
            conflict_source,
        } => format!("Subnet {requested} overlaps {conflicting} ({conflict_source})"),
        RouterProvisioningErrorDetail::NoAvailableSubnet => {
            "No conflict-free downstream /24 remains in 10.77.0.0/16".into()
        }
        RouterProvisioningErrorDetail::TransactionPending => {
            "Another router transaction is waiting for commit/rollback".into()
        }
        RouterProvisioningErrorDetail::RollbackRecoveryRequired => {
            "A previous rollback failed; retry rollback before provisioning".into()
        }
        RouterProvisioningErrorDetail::StaleCandidate { .. }
        | RouterProvisioningErrorDetail::StalePlan => "Network state changed; preview again".into(),
        RouterProvisioningErrorDetail::ReadinessTimeout { detail } => {
            format!("Readiness timed out and was rolled back: {detail}")
        }
        RouterProvisioningErrorDetail::ApplyFailed { detail } => {
            format!("Apply failed and was compensated: {detail}")
        }
        RouterProvisioningErrorDetail::RollbackFailed { failures } => {
            format!("Rollback needs recovery: {}", failures.join("; "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_typed_warning_has_concise_copy() {
        let warning = ProvisioningWarning::NoDownstreamDns;
        assert!(describe_warning(&warning).contains("not advertise DNS"));
    }

    #[test]
    fn secrets_are_masked_and_never_returned_by_the_form_renderer_helper() {
        assert_eq!(masked("correct horse"), "•••••••••••••");
        assert!(!masked("correct horse").contains("correct"));
    }

    #[test]
    fn stale_errors_tell_the_operator_to_preview_again() {
        assert_eq!(
            describe_error(&RouterProvisioningErrorDetail::StalePlan),
            "Network state changed; preview again"
        );
    }
}
