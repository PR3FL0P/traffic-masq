//! Wire DTOs that have no dependency on daemon internals.

mod dhcp_pool;
mod interface;
mod interface_plan;
mod network;
mod network_manager_advice;
mod recovery_action;
mod route;
mod router;
mod router_plan;
mod wifi_observation;
mod wifi_status;
pub use dhcp_pool::suggest_pool;
pub use interface::{
    DhcpClientInterfaceConfigView, DhcpInterfaceConfigView, InterfaceConfigView, WifiApConfigView,
    WifiClientConfigView, WifiClientSpecView, MAX_WIFI_STATIONS,
};
pub use interface_plan::{DhcpChangeActionView, InterfaceChangePlanView};
pub use network::{
    AddressOwnerView, InterfaceStatusView, Ipv4AddressInfoView, NetworkInterfaceView,
};
pub use network_manager_advice::{
    detect_init_system, format_competing_manager_advice, format_competing_manager_advice_for_init,
    InitSystem,
};
pub use recovery_action::RecoveryAction;
pub use route::{RouteOwnerView, RouteStatusView};
pub use router::{
    validate_forwarding, validate_interface_name, ForwardingConfigView, ForwardingRule,
    InterfaceOverrideRequestView, OwnedIpv4RouteConfigView, RouterConfigView,
    RouterProposalRequestView, UplinkConfigView, VpnHopConfigView,
};
pub use router_plan::{
    hop_interface_name, DhcpClientSpecView, DhcpPlanView, Ipv4RouteInfoView, Ipv4RouteSpecView,
    OutputNetworkView, OwnedFirewallIntegrityView, RoutePlanView, RouterDataplaneDesiredView,
    RouterDataplanePlanView, RouterDataplaneSnapshotView, RouterDataplaneTargetView,
    RouterDesiredView, RouterInterfaceDesiredView, RouterPlanView, RouterRiskView,
    VpnChainPlanView, VpnHopDesiredView, VpnHopKindView, VpnHopRoutingDesiredView,
    VpnPolicyDesiredView, VpnPolicyReservedIdsView, WifiPlanView,
};
pub use wifi_observation::{
    MacAddr, MacAddrParseError, Station, WpaSupplicantScanResult, WpaSupplicantScanSecurity,
};
pub use wifi_status::{
    HostapdStateView, WifiApStatusView, WifiClientStatusView, WifiHealthView, WpaStateView,
};

use std::fmt;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnProfileSummary {
    pub name: String,
    pub size_bytes: u64,
    pub modified_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifiClientProfileSummary {
    pub id: String,
    pub ssid: String,
    pub country_code: Option<String>,
    pub security: WifiClientSecurity,
    pub priority: i32,
    #[serde(default)]
    pub autoconnect: bool,
    pub created_at: i64,
    pub modified_at: i64,
    pub has_passphrase: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnActiveStatus {
    pub profile_name: String,
    pub interface: String,
    pub up: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnPolicyStatusView {
    pub mode: VpnPolicyMode,

    pub mode_override_active: bool,

    pub tunnel: Option<VpnActiveStatus>,

    pub tunnel_healthy: bool,

    pub policy_active: bool,

    pub kill_switch_active: bool,

    pub protected_subnets: Vec<Ipv4Net>,

    pub physical_uplink: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RouterHealthReport {
    pub interfaces: Option<String>,
    pub routes: Option<String>,
    pub dhcp: Option<String>,

    pub uplink_dhcp: Option<RouterDhcpHealthReason>,
    pub dataplane: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryFailureKind {
    Transient,
    DeviceMissing,
    Conflict,
    Incompatible,
    Storage,
    CommitIndeterminate,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryProgress {
    pub failure_kind: RecoveryFailureKind,
    pub attempts: u32,
    pub max_attempts: u32,
    pub deadline_unix: u64,
    pub automatic_recovery: bool,
    pub last_error: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterRecoveryNotice {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_progress: Option<RecoveryProgress>,
    pub recovery_code: String,
    pub invariant: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub blocked_operation: String,
    pub operator_action: String,
    pub operator_guidance: String,
    pub runbook: String,
    #[serde(default)]
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum RouterDhcpHealthReason {
    IntentMissing { interface: String },
    IntentMismatch { interface: String },
    Waiting { interface: String },
    Degraded { interface: String, detail: String },
    LeaseMissing { interface: String },
    LeaseNotBound { interface: String },
    LeaseExpired { interface: String },
    ObservationMismatch { interface: String, detail: String },
}

impl RouterHealthReport {
    pub fn ready(&self) -> bool {
        self.interfaces.is_none()
            && self.routes.is_none()
            && self.dhcp.is_none()
            && self.uplink_dhcp.is_none()
            && self.dataplane.is_none()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinatorStatus {
    CommitIndeterminate,
    Idle,
    Pending,
    RollbackFailed,
    /// Automatic recovery stopped; only an explicit rollback starts a new cycle.
    RecoveryRequired,
    RecoveredButJournalCleanupPending,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterProvisioningStatusView {
    pub stage: ProvisioningStage,
    pub enabled: bool,
    pub ready: bool,
    pub coordinator: CoordinatorStatus,

    pub readiness: RouterHealthReport,

    pub failures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingNetworkChange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_progress: Option<RecoveryProgress>,
    pub token: String,
    pub interface: String,
    pub rollback_timeout_seconds: u64,
    /// Advisory wall-clock display time; rollback waits for admitted operations.
    pub expires_at_unix: u64,
    #[serde(default)]
    pub phase: NetworkChangePhase,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkChangePhase {
    #[default]
    AwaitingCommit,
    RollbackRequired,
    RecoveryRequired,
    CommitIndeterminate,
}

impl PendingNetworkChange {
    pub fn can_commit(&self) -> bool {
        self.phase == NetworkChangePhase::AwaitingCommit
    }

    pub fn can_rollback(&self) -> bool {
        self.phase != NetworkChangePhase::CommitIndeterminate
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiHttpsSettings {
    pub enabled: bool,
    pub listen: String,
    #[serde(default)]
    pub certificate_path: Option<String>,
    #[serde(default)]
    pub private_key_path: Option<String>,
}

impl Default for ApiHttpsSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "127.0.0.1:8443".to_string(),
            certificate_path: None,
            private_key_path: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecuritySettings {
    pub rollback_timeout_seconds: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisioningDownstreamOverrides {
    pub interface_ipv4: Option<Ipv4Net>,
    pub pool_start: Option<Ipv4Addr>,
    pub pool_end: Option<Ipv4Addr>,

    #[serde(default)]
    pub dns_servers: Vec<Ipv4Addr>,
    pub lease_seconds: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceRole {
    /// Does not participate in the router. Legacy management roles retain protection.
    #[serde(alias = "management")]
    None,
    Input,
    Output,
    /// A slot naming one of the VPN hop chain's virtual `tm-wg-<hop_index>`
    /// interfaces. Unaddressed, WireGuard-only: never carries dhcp/wifi/ipv4.
    Middle,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UplinkMode {
    External,
    Dhcp,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WifiBand {
    #[default]
    #[serde(rename = "2g")]
    Ghz2,
    #[serde(rename = "5g")]
    Ghz5,
}

impl WifiBand {
    pub fn channels(self) -> &'static [u8] {
        const GHZ2: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        const GHZ5: &[u8] = &[
            32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 96, 100, 104, 108, 112, 116, 120, 124, 128,
            132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173, 177,
        ];
        match self {
            WifiBand::Ghz2 => GHZ2,
            WifiBand::Ghz5 => GHZ5,
        }
    }
}

impl std::fmt::Display for WifiBand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WifiBand::Ghz2 => write!(f, "2g"),
            WifiBand::Ghz5 => write!(f, "5g"),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WifiChannelWidth {
    #[default]
    Ht20,
    Ht40,
    Vht80,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WifiSecurity {
    #[default]
    Wpa2,
    Wpa2Wpa3,
    Wpa3,
    Open,
}

impl WifiSecurity {
    pub fn requires_passphrase(self) -> bool {
        !matches!(self, WifiSecurity::Open)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WifiClientSecurity {
    #[default]
    Wpa2,
    Wpa3,
    Wpa2Wpa3,
    Open,
}

impl WifiClientSecurity {
    pub fn requires_passphrase(self) -> bool {
        !matches!(self, WifiClientSecurity::Open)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VpnPolicyMode {
    #[default]
    Direct,
    Vpn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpEditRequest {
    pub pool_start: Ipv4Addr,
    pub pool_end: Ipv4Addr,
    pub router: Ipv4Addr,
    #[serde(default)]
    pub dns_servers: Vec<Ipv4Addr>,
    pub lease_seconds: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpServiceView {
    pub interface: String,
    pub server_ip: Ipv4Addr,
    pub prefix_len: u8,
    pub subnet_mask: Ipv4Addr,
    pub pool_start: Ipv4Addr,
    pub pool_end: Ipv4Addr,
    pub router: Ipv4Addr,
    pub dns_servers: Vec<Ipv4Addr>,
    pub lease_seconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifiApSpecView {
    pub interface: String,
    pub ssid: String,
    pub country_code: Option<String>,
    pub band: WifiBand,
    pub channel: u8,
    pub channel_width: WifiChannelWidth,
    pub security: WifiSecurity,
    pub hidden: bool,
    pub client_isolation: bool,
    pub max_stations: u16,
    pub passphrase_file: Option<std::path::PathBuf>,
}

impl WifiApSpecView {
    /// Derive the displayed AP spec from configuration already validated by the daemon.
    pub fn from_validated_interface_config(
        interface: &str,
        config: &InterfaceConfigView,
    ) -> Option<Self> {
        if !config.managed || config.role != InterfaceRole::Output {
            return None;
        }
        let wifi = config.wifi.as_ref()?;
        Some(Self {
            interface: interface.to_owned(),
            ssid: wifi.ssid.clone(),
            country_code: wifi.country_code.clone(),
            band: wifi.band,
            channel: wifi.channel,
            channel_width: wifi.channel_width,
            security: wifi.security,
            hidden: wifi.hidden,
            client_isolation: wifi.client_isolation,
            max_stations: wifi.max_stations,
            passphrase_file: wifi.passphrase_file.clone(),
        })
    }

    pub fn requires_passphrase(&self) -> bool {
        self.security.requires_passphrase()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpLeaseView {
    pub mac: [u8; 6],
    pub ip: Ipv4Addr,
    pub expires_at_unix: u64,
}

impl DhcpLeaseView {
    pub fn is_expired_at(&self, now_unix: u64) -> bool {
        self.expires_at_unix <= now_unix
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VpnErrorDetail {
    VpnDisabled,

    NotFound { name: String },

    InvalidProfile { message: String },

    AlreadyActive,

    NotActive,

    ProfileInUse { name: String },

    ForeignInterfaceConflict,

    Other { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RouterErrorDetail {
    RouterDisabled,

    TransactionPending,

    RollbackRecoveryRequired,

    StaleCandidate {
        candidate_revision: u64,
        current_revision: u64,
    },

    StalePlan,

    NoPendingTransaction,

    RollbackFailed {
        failures: Vec<String>,
    },

    Other {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VpnPolicyErrorDetail {
    VpnDisabled,

    NoProtectedSubnets,

    TunnelUnhealthy { message: String },

    ReservedNamespaceConflict { message: String },

    Other { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WifiErrorDetail {
    WifiDisabled,

    InterfaceNotFound,

    NotWireless,

    HostapdMissing,

    NotOwned,

    PassphraseMissing,

    InvalidSpec { message: String },

    HostapdFailed { message: String },

    CtrlTimeout,

    Other { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WifiClientIpPolicy {
    Preserve,
    Dhcp,
    Static { cidr: ipnet::Ipv4Net },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionWifiClientRequest {
    pub profile_id: String,
    pub ip_policy: WifiClientIpPolicy,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WifiClientActivationPhase {
    #[default]
    ActivationStarted,
    Associated,
    IpReady,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiClientProfileActivationRequest {
    pub profile_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WifiClientProfileErrorDetail {
    WifiClientDisabled,
    ProfileNotFound,
    ProfileAlreadyExists,
    ProfileActive { interfaces: Vec<String> },
    InvalidProfile { message: String },
    PassphraseMissing,
    InterfaceNotFound,
    ActivationFailed { message: String },
    PersistenceFailed { message: String },
    Other { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WifiClientErrorDetail {
    WifiClientDisabled,

    InterfaceNotFound,

    NotWireless,

    WpaSupplicantMissing,

    NotOwned,

    PassphraseMissing,

    AuthenticationFailed { reason: String },

    InvalidSpec { message: String },

    WpaSupplicantFailed { message: String },

    CtrlTimeout,

    ScanBusy,

    ScanTimeout,

    CtrlUnavailable,

    ProtocolFailure { message: String },

    Other { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpClientConfigRequest {
    #[serde(default = "default_route_metric")]
    pub route_metric: u32,
    #[serde(default = "default_true")]
    pub install_default_route: bool,
    #[serde(default = "default_true")]
    pub request_dns: bool,
    #[serde(default)]
    pub send_release_on_shutdown: bool,
}

impl Default for DhcpClientConfigRequest {
    fn default() -> Self {
        Self {
            route_metric: default_route_metric(),
            install_default_route: true,
            request_dns: true,
            send_release_on_shutdown: false,
        }
    }
}

const fn default_route_metric() -> u32 {
    100
}
const fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DhcpClientOperationalState {
    Waiting,
    Running,
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpClientStatusView {
    pub interface: String,
    pub state: DhcpClientOperationalState,
    pub address: Option<Ipv4Addr>,
    pub prefix_length: Option<u8>,
    pub server: Option<Ipv4Addr>,
    pub expires_at_unix: Option<u64>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub degraded_reason: Option<String>,
    pub config: DhcpClientConfigRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DhcpClientErrorDetail {
    DhcpClientDisabled,
    InterfaceNotFound,
    Disabled,
    InvalidConfig { message: String },
    OwnershipConflict { message: String },
    RuntimeFailure { message: String },
    PersistenceFailure { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProvisioningWarning {
    ManagementInterfaceAffected {
        interface: String,
    },

    DownstreamSubnetRelocated {
        preferred: Ipv4Net,
        selected: Ipv4Net,
    },

    NoDownstreamDns,

    InterfaceConfigurationReplaced {
        interface: String,
    },

    PendingSecret {
        interface: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvisioningStage {
    Unconfigured,

    Inactive,

    AwaitingConfirmation,

    Degraded,

    Ready,

    RollbackFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RouterProvisioningErrorDetail {
    RouterDisabled,

    GlobalServiceDisabled {
        service: String,
    },

    InterfaceReused {
        interface: String,
    },

    InterfaceNotFound {
        interface: String,
    },

    RadioReused {
        phy: String,
        uplink: String,
        output: String,
    },

    ManagementConfirmationRequired {
        interface: String,
    },

    UplinkSecretMissing {
        interface: String,
    },

    OutputSecretMissing {
        interface: String,
    },

    InvalidSecret {
        message: String,
    },

    SubnetConflict {
        requested: Ipv4Net,
        conflicting: Ipv4Net,
        conflict_source: String,
    },

    NoAvailableSubnet,

    InvalidPool {
        message: String,
    },

    InvalidConfiguration {
        message: String,
    },

    TransactionPending,

    RollbackRecoveryRequired,

    StaleCandidate {
        candidate_revision: u64,
        current_revision: u64,
    },

    StalePlan,

    ReadinessTimeout {
        detail: String,
    },

    ApplyFailed {
        detail: String,
    },

    RollbackFailed {
        failures: Vec<String>,
    },

    Other {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceEditRequest {
    #[serde(default)]
    pub cidr: String,
    pub role: InterfaceRole,
    pub managed: bool,
    #[serde(default)]
    pub allow_management_change: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiEditRequest {
    pub ssid: String,
    #[serde(default)]
    pub country_code: Option<String>,
    #[serde(default)]
    pub band: WifiBand,
    #[serde(default)]
    pub channel: u8,
    #[serde(default)]
    pub channel_width: WifiChannelWidth,
    #[serde(default)]
    pub security: WifiSecurity,
    #[serde(default)]
    pub hidden: bool,
    #[serde(default)]
    pub client_isolation: bool,
    pub max_stations: u16,
}
/// Reusable AP settings. Secrets are accepted on writes and never returned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiApProfileSummary {
    pub id: String,
    pub settings: WifiEditRequest,
    pub configure_dhcp: bool,
    #[serde(default)]
    pub subnet: Option<ipnet::Ipv4Net>,
    #[serde(default)]
    pub disable_dhcp: bool,
    pub has_passphrase: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct WifiApProfileWriteRequest {
    pub id: String,
    #[serde(flatten)]
    pub configuration: ProvisionWifiAccessPointRequest,
}

impl fmt::Debug for WifiApProfileWriteRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WifiApProfileWriteRequest")
            .field("id", &self.id)
            .field("configuration", &self.configuration)
            .finish()
    }
}
/// Apply AP, credential, and optional derived-DHCP changes tentatively.
/// A successful request returns `Response::NetworkChangePending`; callers must
/// commit the returned token before its rollback deadline.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProvisionWifiAccessPointRequest {
    pub settings: WifiEditRequest,
    #[serde(default)]
    pub passphrase: Option<String>,
    #[serde(default)]
    pub clear_passphrase: bool,
    #[serde(default)]
    pub configure_dhcp: bool,
    #[serde(default)]
    pub subnet: Option<ipnet::Ipv4Net>,
    #[serde(default)]
    pub disable_dhcp: bool,
}

impl fmt::Debug for ProvisionWifiAccessPointRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionWifiAccessPointRequest")
            .field("settings", &self.settings)
            .field("passphrase", &redacted(self.passphrase.is_some()))
            .field("clear_passphrase", &self.clear_passphrase)
            .field("configure_dhcp", &self.configure_dhcp)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiClientEditRequest {
    pub ssid: String,
    #[serde(default)]
    pub country_code: Option<String>,
    #[serde(default)]
    pub security: WifiClientSecurity,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct WifiClientProfileWriteRequest {
    pub id: String,
    pub ssid: String,
    #[serde(default)]
    pub country_code: Option<String>,
    #[serde(default)]
    pub security: WifiClientSecurity,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub autoconnect: bool,
    #[serde(default)]
    pub passphrase: Option<String>,
    #[serde(default)]
    pub clear_passphrase: bool,
}

impl fmt::Debug for WifiClientProfileWriteRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut value = serde_json::to_value(self).map_err(|_| fmt::Error)?;
        redact_debug_secrets(&mut value);
        write!(formatter, "{value}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisioningUplinkRequest {
    pub interface: String,
    pub ssid: String,
    #[serde(default)]
    pub country_code: Option<String>,
    #[serde(default)]
    pub security: WifiClientSecurity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisioningOutputRequest {
    pub interface: String,
    pub ssid: String,
    #[serde(default)]
    pub country_code: Option<String>,
    #[serde(default)]
    pub band: WifiBand,
    #[serde(default)]
    pub channel: u8,
    #[serde(default)]
    pub channel_width: WifiChannelWidth,
    #[serde(default)]
    pub security: WifiSecurity,
    #[serde(default)]
    pub hidden: bool,
    #[serde(default)]
    pub client_isolation: bool,
    #[serde(default = "default_provisioning_max_stations")]
    pub max_stations: u16,
}

fn default_provisioning_max_stations() -> u16 {
    32
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterProvisioningRequest {
    pub uplink: ProvisioningUplinkRequest,
    pub output: ProvisioningOutputRequest,
    #[serde(default)]
    pub downstream: ProvisioningDownstreamOverrides,
    #[serde(default)]
    pub allow_management_change: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterProvisioningPreviewRequest {
    pub provisioning: RouterProvisioningRequest,
    #[serde(default)]
    pub uplink_secret_pending: bool,
    #[serde(default)]
    pub output_secret_pending: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RouterProvisioningApplyRequest {
    pub provisioning: RouterProvisioningRequest,
    #[serde(default)]
    pub uplink_passphrase: Option<String>,
    #[serde(default)]
    pub output_passphrase: Option<String>,
}

impl fmt::Debug for RouterProvisioningApplyRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouterProvisioningApplyRequest")
            .field("provisioning", &self.provisioning)
            .field(
                "uplink_passphrase",
                &redacted(self.uplink_passphrase.is_some()),
            )
            .field(
                "output_passphrase",
                &redacted(self.output_passphrase.is_some()),
            )
            .finish()
    }
}

fn redacted(present: bool) -> &'static str {
    if present {
        "<redacted>"
    } else {
        "<absent>"
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisioningUplinkView {
    pub interface: String,
    pub ssid: String,
    pub country_code: Option<String>,
    pub security: WifiClientSecurity,

    pub mode: UplinkMode,

    pub secret_available: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisioningOutputView {
    pub interface: String,
    pub ssid: String,
    pub country_code: Option<String>,
    pub band: WifiBand,
    pub channel: u8,
    pub channel_width: WifiChannelWidth,
    pub security: WifiSecurity,
    pub hidden: bool,
    pub client_isolation: bool,
    pub max_stations: u16,

    pub secret_available: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisioningDownstreamView {
    pub subnet: Ipv4Net,
    pub interface_ipv4: Ipv4Net,
    pub router: Ipv4Addr,
    pub pool_start: Ipv4Addr,
    pub pool_end: Ipv4Addr,

    pub dns_servers: Vec<Ipv4Addr>,
    pub lease_seconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterProvisioningPreviewView {
    pub uplink: ProvisioningUplinkView,
    pub output: ProvisioningOutputView,
    pub downstream: ProvisioningDownstreamView,
    pub warnings: Vec<ProvisioningWarning>,
}

pub fn redact_debug_secrets(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(fields) => {
            for (name, value) in fields {
                if matches!(
                    name.as_str(),
                    "passphrase" | "uplink_passphrase" | "output_passphrase" | "password"
                ) {
                    *value = serde_json::Value::String(
                        if value.is_null() {
                            "<absent>"
                        } else {
                            "<redacted>"
                        }
                        .to_string(),
                    );
                } else {
                    redact_debug_secrets(value);
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                redact_debug_secrets(value);
            }
        }
        _ => {}
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfacePresence {
    Present,
    Missing,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceConfigSource {
    Base,
    Override,
    Derived,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceReadiness {
    Ready,
    Disabled,
    WaitingDevice,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InterfaceReadinessBlocker {
    MissingInterface { interface: String },
    ObservationFailed { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceInventoryEntry {
    pub name: String,
    pub observed: Option<InterfaceStatusView>,
    pub configured: Option<InterfaceConfigView>,
    pub config_source: InterfaceConfigSource,
    pub presence: InterfacePresence,
    pub observation_stale: bool,
    pub suppressed: bool,
    pub readiness: InterfaceReadiness,
    pub blockers: Vec<InterfaceReadinessBlocker>,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiInventoryEntry {
    pub interface: InterfaceInventoryEntry,
    pub ap_runtime: Option<WifiApStatusView>,
    pub client_runtime: Option<WifiClientStatusView>,
}

/// Control request envelope. Interface and router proposal payloads stay typed
/// while callers migrate those domain values to dedicated wire DTOs.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request<Interface, Proposal> {
    Ping,
    GetApiHttpsConfig,
    ConfigureApiHttpsSettings {
        settings: ApiHttpsSettings,
    },
    ResetApiHttpsSettings,
    GetSecurityConfig,
    ConfigureSecuritySettings {
        settings: SecuritySettings,
    },
    ResetSecuritySettings,
    ListInterfaces,
    ListInterfaceInventory,
    ListWifiInventory,
    SaveWifiInterface {
        interface: String,
        config: Interface,
        expected_revision: u64,
        #[serde(default)]
        passphrase: Option<String>,
    },
    SaveInterfaceConfig {
        interface: String,
        config: Interface,
        allow_management_change: bool,
        expected_revision: u64,
    },
    ForgetInterfaceConfig {
        interface: String,
        expected_revision: u64,
    },
    ResetInterfaceOverride {
        interface: String,
        expected_revision: u64,
    },
    GetInterfaceConfig {
        interface: String,
    },
    DhcpStatus,
    DhcpClientStatus,
    GetDhcpClient {
        interface: String,
    },
    ConfigureDhcpClient {
        interface: String,
        config: DhcpClientConfigRequest,
    },
    DisableDhcpClient {
        interface: String,
    },
    RenewDhcpClient {
        interface: String,
    },
    ReleaseDhcpClient {
        interface: String,
    },
    ConfigureDhcpSettings {
        interface: String,
        settings: DhcpEditRequest,
    },
    GetDhcpConfig {
        interface: String,
    },
    ConfigureDhcp {
        interface: String,
        config: DhcpEditRequest,
    },
    DisableDhcp {
        interface: String,
    },
    ListLeases {
        interface: String,
    },
    DryRunInterface {
        interface: String,
        config: Interface,
        allow_management_change: bool,
    },
    DryRunInterfaceEdit {
        interface: String,
        edit: InterfaceEditRequest,
    },
    ApplyInterface {
        interface: String,
        config: Interface,
        allow_management_change: bool,
    },
    ApplyInterfaceEdit {
        interface: String,
        edit: InterfaceEditRequest,
    },
    CommitNetworkChange {
        token: String,
    },
    RollbackNetworkChange {
        token: String,
    },
    PendingNetworkChanges,
    RouterStatus,
    RouterPlan {
        proposal: Proposal,
    },
    RouterApply {
        proposal: Proposal,
    },
    RouterCommit {
        token: String,
    },
    RouterRollback {
        token: String,
    },
    RouterPendingTransaction,
    ListRoutes {
        #[serde(default)]
        include_local_table: bool,
    },
    GetRouterConfig,
    RouterProvisioningPreview {
        request: RouterProvisioningPreviewRequest,
    },
    RouterProvisioningApply {
        request: RouterProvisioningApplyRequest,
    },
    RouterProvisioningStatus,
    RouterProvisioningRepair,
    VpnListProfiles,
    VpnImportProfile {
        name: String,
        contents: String,
    },
    VpnDeleteProfile {
        name: String,
    },
    GetVpnConfig,
    SetVpnEnabled {
        enabled: bool,
    },
    VpnStatus,
    VpnActivate {
        name: String,
    },
    VpnDeactivate,
    VpnPolicyStatus,
    VpnPolicySetMode {
        mode: VpnPolicyMode,
    },
    VpnPolicyClearMode,
    WifiStatus,
    GetWifiConfig {
        interface: String,
    },
    ConfigureWifi {
        interface: String,
        settings: WifiEditRequest,
    },
    ProvisionWifiAccessPoint {
        interface: String,
        settings: WifiEditRequest,
        passphrase: Option<String>,
        #[serde(default)]
        clear_passphrase: bool,
        configure_dhcp: bool,
        #[serde(default)]
        subnet: Option<ipnet::Ipv4Net>,
        #[serde(default)]
        disable_dhcp: bool,
    },
    DisableWifi {
        interface: String,
    },
    WifiSetPassphrase {
        interface: String,
        passphrase: String,
    },
    ListWifiStations {
        interface: String,
    },
    WifiDeauthStation {
        interface: String,
        mac: String,
    },
    WifiReload {
        interface: String,
    },
    WifiClientStatus,
    GetWifiClientConfig {
        interface: String,
    },
    ConfigureWifiClient {
        interface: String,
        settings: WifiClientEditRequest,
    },
    DisableWifiClient {
        interface: String,
    },
    WifiClientSetPassphrase {
        interface: String,
        passphrase: String,
    },
    WifiClientReconnect {
        interface: String,
    },
    WifiClientScan {
        interface: String,
    },
    ListWifiApProfiles,
    SaveWifiApProfile {
        profile: WifiApProfileWriteRequest,
    },
    DeleteWifiApProfile {
        id: String,
    },
    ActivateWifiApProfile {
        interface: String,
        profile_id: String,
    },
    ListWifiClientProfiles,
    GetWifiClientProfile {
        id: String,
    },
    CreateWifiClientProfile {
        profile: WifiClientProfileWriteRequest,
    },
    UpdateWifiClientProfile {
        id: String,
        profile: WifiClientProfileWriteRequest,
    },
    DeleteWifiClientProfile {
        id: String,
    },
    ProvisionWifiClient {
        interface: String,
        settings: ProvisionWifiClientRequest,
    },
    ActivateWifiClientProfile {
        interface: String,
        profile_id: String,
    },
    DeactivateWifiClientProfile {
        interface: String,
    },
}

/// The client-visible control request with protocol-owned payloads.
pub type ControlRequest = Request<InterfaceConfigView, RouterProposalRequestView>;

impl<Interface: Serialize, Proposal: Serialize> fmt::Debug for Request<Interface, Proposal> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut value = serde_json::to_value(self).map_err(|_| fmt::Error)?;
        redact_debug_secrets(&mut value);
        write!(formatter, "{value}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    bound(
        deserialize = "InterfaceStatus: Deserialize<'de>, InterfaceConfig: Deserialize<'de>, InterfaceChangePlan: Deserialize<'de>, RouterPlan: Deserialize<'de>, RouteStatus: Deserialize<'de>, RouterConfig: Deserialize<'de>, WifiApStatus: Deserialize<'de>, WifiClientStatus: Deserialize<'de>, WifiClientSpec: Deserialize<'de>"
    )
)]
pub enum Response<
    InterfaceStatus,
    InterfaceConfig,
    InterfaceChangePlan,
    RouterPlan,
    RouteStatus,
    RouterConfig,
    WifiApStatus,
    WifiClientStatus,
    WifiClientSpec,
> {
    Pong,
    ApiHttpsConfig {
        active: ApiHttpsSettings,
        desired: ApiHttpsSettings,
        override_active: bool,
        restart_required: bool,
    },
    SecurityConfig {
        active: SecuritySettings,
        desired: SecuritySettings,
        override_active: bool,
        restart_required: bool,
    },
    Interfaces {
        interfaces: Vec<InterfaceStatus>,
    },
    InterfaceInventory {
        revision: u64,
        interfaces: Vec<InterfaceInventoryEntry>,
        suppressed_interfaces: Vec<String>,
        observation_error: Option<String>,
    },
    WifiInventory {
        revision: u64,
        interfaces: Vec<WifiInventoryEntry>,
        observation_error: Option<String>,
    },
    InterfaceIntentSaved {
        interface: String,
        revision: u64,
        deferred: bool,
        missing_dependencies: Vec<String>,
    },
    InterfaceConfig {
        interface: String,
        config: Option<InterfaceConfig>,
        allow_management_change: bool,
    },
    DhcpStatus {
        running_interfaces: Vec<String>,
        unhealthy_interfaces: Vec<String>,
    },
    DhcpConfig {
        interface: String,
        spec: Option<DhcpServiceView>,
    },
    DhcpConfigured {
        spec: DhcpServiceView,
    },
    DhcpDisabled {
        interface: String,
    },
    DhcpClientStatus {
        interfaces: Vec<DhcpClientStatusView>,
    },
    DhcpClientInterface {
        status: DhcpClientStatusView,
    },
    DhcpClientDisabled {
        interface: String,
    },
    DhcpClientError {
        detail: DhcpClientErrorDetail,
    },
    Leases {
        interface: String,
        leases: Vec<DhcpLeaseView>,
    },
    InterfacePlan {
        plan: InterfaceChangePlan,
    },
    NetworkChangePending {
        change: PendingNetworkChange,
    },
    NetworkChangeCommitted {
        change: PendingNetworkChange,
    },
    NetworkChangeRolledBack {
        change: PendingNetworkChange,
    },
    PendingNetworkChanges {
        changes: Vec<PendingNetworkChange>,
    },
    Error {
        message: String,
    },
    RouterStatus {
        enabled: bool,
        ready: bool,
        coordinator_status: CoordinatorStatus,
        health: RouterHealthReport,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recovery: Option<RouterRecoveryNotice>,
    },
    RouterPlan {
        plan: RouterPlan,
    },
    RouterTransactionPending {
        token: String,
        plan: RouterPlan,
    },
    RouterCommitted {
        revision: u64,
    },
    RouterRolledBack,
    RouterPendingTransaction {
        token: Option<String>,
        status: CoordinatorStatus,
        rollback_failure: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recovery: Option<RouterRecoveryNotice>,
    },
    Routes {
        routes: Vec<RouteStatus>,
    },
    RouterConfig {
        config: RouterConfig,
    },
    RouterError {
        detail: RouterErrorDetail,
    },
    RouterProvisioningPreview {
        preview: RouterProvisioningPreviewView,
    },

    RouterProvisioningApplied {
        token: String,
        preview: RouterProvisioningPreviewView,
    },
    RouterProvisioningStatus {
        status: RouterProvisioningStatusView,
    },
    RouterProvisioningRepaired {
        status: RouterProvisioningStatusView,
    },
    RouterProvisioningError {
        detail: RouterProvisioningErrorDetail,
    },
    VpnProfiles {
        profiles: Vec<VpnProfileSummary>,
    },
    VpnProfileImported {
        name: String,
    },
    VpnProfileDeleted {
        name: String,
    },
    VpnConfig {
        enabled: bool,
    },
    VpnStatus {
        active: Option<VpnActiveStatus>,
    },
    VpnActivated {
        active: VpnActiveStatus,
    },
    VpnDeactivated,
    VpnError {
        detail: VpnErrorDetail,
    },
    VpnPolicyStatus {
        status: VpnPolicyStatusView,
    },
    VpnPolicyError {
        detail: VpnPolicyErrorDetail,
    },
    WifiStatus {
        interfaces: Vec<WifiApStatus>,
    },
    WifiConfig {
        interface: String,
        spec: Option<WifiApSpecView>,
    },
    WifiConfigured {
        spec: WifiApSpecView,
    },
    /// Legacy response retained for wire compatibility with older daemons that
    /// committed AP provisioning immediately. Current provisioning returns
    /// `NetworkChangePending` and requires an explicit commit.
    WifiAccessPointProvisioned {
        spec: WifiApSpecView,
        dhcp: Option<DhcpServiceView>,
    },
    WifiDisabled {
        interface: String,
    },
    WifiStations {
        interface: String,
        stations: Vec<Station>,
    },
    WifiError {
        detail: WifiErrorDetail,
    },
    WifiClientStatus {
        interfaces: Vec<WifiClientStatus>,
    },
    WifiClientConfig {
        interface: String,
        spec: Option<WifiClientSpec>,
    },
    WifiClientConfigured {
        spec: WifiClientSpec,
    },
    WifiClientDisabled {
        interface: String,
    },
    WifiClientScanResults {
        interface: String,
        results: Vec<WpaSupplicantScanResult>,
    },
    WifiApProfiles {
        profiles: Vec<WifiApProfileSummary>,
    },
    WifiApProfileSaved {
        profile: WifiApProfileSummary,
    },
    WifiApProfileDeleted {
        id: String,
    },
    WifiClientProfiles {
        profiles: Vec<WifiClientProfileSummary>,
    },
    WifiClientProfile {
        profile: WifiClientProfileSummary,
    },
    WifiClientProfileDeleted {
        id: String,
    },
    WifiClientProfileActivated {
        #[serde(default)]
        phase: WifiClientActivationPhase,
        interface: String,
        profile: WifiClientProfileSummary,
        status: WifiClientStatus,
    },
    WifiClientProfileError {
        detail: WifiClientProfileErrorDetail,
    },
    WifiClientError {
        detail: WifiClientErrorDetail,
    },
}

/// Complete control response decoded by a client without daemon model types.
pub type ControlResponse = Response<
    InterfaceStatusView,
    InterfaceConfigView,
    InterfaceChangePlanView,
    RouterPlanView,
    RouteStatusView,
    RouterConfigView,
    WifiApStatusView,
    WifiClientStatusView,
    WifiClientSpecView,
>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_details_keep_the_existing_wire_shape() {
        let detail = RouterErrorDetail::StaleCandidate {
            candidate_revision: 3,
            current_revision: 4,
        };
        assert_eq!(
            serde_json::to_value(detail).unwrap(),
            serde_json::json!({
                "kind": "stale_candidate",
                "candidate_revision": 3,
                "current_revision": 4
            })
        );
    }

    #[test]
    fn dhcp_client_defaults_keep_the_existing_wire_shape() {
        let config: DhcpClientConfigRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(config.route_metric, 100);
        assert!(config.install_default_route);
        assert!(config.request_dns);
        assert!(!config.send_release_on_shutdown);
    }

    #[test]
    fn shared_config_enums_keep_the_existing_wire_shape() {
        assert_eq!(serde_json::to_string(&WifiBand::Ghz5).unwrap(), "\"5g\"");
        assert_eq!(
            serde_json::from_str::<InterfaceRole>("\"management\"").unwrap(),
            InterfaceRole::None
        );
        assert_eq!(
            serde_json::to_string(&VpnPolicyMode::Direct).unwrap(),
            "\"direct\""
        );
    }

    #[test]
    fn wifi_client_profile_summary_preserves_wire_shape() {
        let json = serde_json::json!({
            "id": "home",
            "ssid": "Home",
            "country_code": null,
            "security": "wpa2",
            "priority": 5,
            "created_at": 10,
            "modified_at": 20,
            "has_passphrase": true
        });
        let summary: WifiClientProfileSummary = serde_json::from_value(json.clone()).unwrap();
        assert!(!summary.autoconnect);
        let mut expected = json;
        expected["autoconnect"] = serde_json::json!(false);
        assert_eq!(serde_json::to_value(summary).unwrap(), expected);
    }

    #[test]
    fn provisioning_debug_redacts_secrets() {
        let request = RouterProvisioningApplyRequest {
            provisioning: RouterProvisioningRequest {
                uplink: ProvisioningUplinkRequest {
                    interface: "wan0".into(),
                    ssid: "uplink".into(),
                    country_code: None,
                    security: WifiClientSecurity::Wpa2,
                },
                output: ProvisioningOutputRequest {
                    interface: "lan0".into(),
                    ssid: "local".into(),
                    country_code: None,
                    band: WifiBand::Ghz2,
                    channel: 1,
                    channel_width: WifiChannelWidth::Ht20,
                    security: WifiSecurity::Wpa2,
                    hidden: false,
                    client_isolation: false,
                    max_stations: 32,
                },
                downstream: ProvisioningDownstreamOverrides::default(),
                allow_management_change: false,
            },
            uplink_passphrase: Some("secret-uplink".into()),
            output_passphrase: Some("secret-output".into()),
        };
        let debug = format!("{request:?}");
        assert!(!debug.contains("secret-uplink"));
        assert!(!debug.contains("secret-output"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn request_envelope_preserves_wire_shape_and_redacts_payloads() {
        type TestRequest = Request<serde_json::Value, serde_json::Value>;
        let request = TestRequest::ApplyInterface {
            interface: "wan0".into(),
            config: serde_json::json!({"passphrase": "secret"}),
            allow_management_change: false,
        };
        let encoded = serde_json::to_value(&request).unwrap();
        assert_eq!(encoded["type"], "apply_interface");
        assert_eq!(encoded["config"]["passphrase"], "secret");
        let decoded: TestRequest = serde_json::from_value(encoded).unwrap();
        let debug = format!("{decoded:?}");
        assert!(!debug.contains("secret"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn offline_wifi_intent_preserves_revision_and_redacts_password() {
        type TestRequest = Request<serde_json::Value, serde_json::Value>;
        let request = TestRequest::SaveWifiInterface {
            interface: "wlan0".into(),
            config: serde_json::json!({"role": "output", "managed": true}),
            expected_revision: 7,
            passphrase: Some("private-offline-password".into()),
        };
        let encoded = serde_json::to_value(&request).unwrap();
        assert_eq!(encoded["type"], "save_wifi_interface");
        assert_eq!(encoded["expected_revision"], 7);
        let decoded: TestRequest = serde_json::from_value(encoded).unwrap();
        let debug = format!("{decoded:?}");
        assert!(!debug.contains("private-offline-password"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn https_defaults_match_the_wire_contract() {
        assert_eq!(
            serde_json::to_value(ApiHttpsSettings::default()).unwrap(),
            serde_json::json!({
                "enabled": false,
                "listen": "127.0.0.1:8443",
                "certificate_path": null,
                "private_key_path": null
            })
        );
    }

    #[test]
    fn pending_change_defaults_to_awaiting_commit() {
        let change: PendingNetworkChange = serde_json::from_value(serde_json::json!({
            "token": "abc",
            "interface": "lan0",
            "rollback_timeout_seconds": 30,
            "expires_at_unix": 100
        }))
        .unwrap();
        assert_eq!(change.phase, NetworkChangePhase::AwaitingCommit);
        assert!(change.can_commit());
        assert!(change.can_rollback());
    }

    #[test]
    fn dhcp_lease_view_keeps_the_existing_wire_shape() {
        let lease = DhcpLeaseView {
            mac: [0, 1, 2, 3, 4, 5],
            ip: Ipv4Addr::new(192, 0, 2, 10),
            expires_at_unix: 100,
        };
        assert_eq!(
            serde_json::to_value(&lease).unwrap(),
            serde_json::json!({
                "mac": [0, 1, 2, 3, 4, 5],
                "ip": "192.0.2.10",
                "expires_at_unix": 100
            })
        );
        assert!(!lease.is_expired_at(99));
        assert!(lease.is_expired_at(100));
    }
}
