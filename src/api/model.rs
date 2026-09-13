use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::time::SystemTime;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use crate::config::{
    DhcpInterfaceConfig, InterfaceConfig, InterfaceRole, RouterConfig, SecurityConfig,
    TcpApiConfig, UplinkMode, VpnPolicyMode, WifiBand, WifiChannelWidth, WifiClientSecurity,
    WifiSecurity,
};
use crate::core::interface::InterfaceChangePlan;
use crate::core::router::{RouterHealthReport, RouterPlan};
use crate::core::router_provisioning::ProvisioningDownstreamOverrides;
use crate::core::router_transaction::CoordinatorStatus;
use crate::core::transaction::PendingNetworkChange;
use crate::dhcp::lease::DhcpLease;
use crate::dhcp::supervisor::DhcpServiceSpec;
use crate::netlink::{Ipv4AddressInfo, NetworkInterface, RouteOwner};
use crate::wifi::{
    Station, WifiApSpec, WifiApStatus, WifiClientProfileSummary, WifiClientSpec, WifiClientStatus,
    WpaSupplicantScanResult,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceOverrideRequest {
    pub config: InterfaceConfig,
    #[serde(default)]
    pub allow_management_change: bool,
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
pub struct DhcpEditRequest {
    pub pool_start: Ipv4Addr,
    pub pool_end: Ipv4Addr,
    pub router: Ipv4Addr,
    #[serde(default)]
    pub dns_servers: Vec<Ipv4Addr>,
    pub lease_seconds: Option<u32>,
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
        Self::from(&TcpApiConfig::default())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecuritySettings {
    pub rollback_timeout_seconds: u64,
}

impl From<&SecurityConfig> for SecuritySettings {
    fn from(config: &SecurityConfig) -> Self {
        Self {
            rollback_timeout_seconds: config.rollback_timeout_seconds,
        }
    }
}

impl From<&TcpApiConfig> for ApiHttpsSettings {
    fn from(config: &TcpApiConfig) -> Self {
        Self {
            enabled: config.enabled,
            listen: config.listen.to_string(),
            certificate_path: config
                .certificate_path
                .as_ref()
                .map(|path| path.display().to_string()),
            private_key_path: config
                .private_key_path
                .as_ref()
                .map(|path| path.display().to_string()),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouterProposalRequest {
    #[serde(default)]
    pub set_router: Option<RouterConfig>,
    #[serde(default)]
    pub clear_router: bool,
    #[serde(default)]
    pub set_interfaces: BTreeMap<String, InterfaceOverrideRequest>,
    #[serde(default)]
    pub remove_interfaces: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnProfileSummary {
    pub name: String,
    pub size_bytes: u64,
    pub modified_unix: Option<u64>,
}

impl From<crate::vpn::WireGuardProfileSummary> for VpnProfileSummary {
    fn from(summary: crate::vpn::WireGuardProfileSummary) -> Self {
        Self {
            name: summary.name,
            size_bytes: summary.size_bytes,
            modified_unix: summary.modified.and_then(|modified| {
                modified
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .ok()
                    .map(|duration| duration.as_secs())
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnActiveStatus {
    pub profile_name: String,
    pub interface: String,
    pub up: bool,
}

impl From<crate::vpn::VpnActiveStatus> for VpnActiveStatus {
    fn from(status: crate::vpn::VpnActiveStatus) -> Self {
        Self {
            profile_name: status.profile_name,
            interface: status.interface,
            up: status.up,
        }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionWifiAccessPointRequest {
    pub settings: WifiEditRequest,
    #[serde(default)]
    pub passphrase: Option<String>,
    #[serde(default)]
    pub configure_dhcp: bool,
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
pub struct WifiClientEditRequest {
    pub ssid: String,
    #[serde(default)]
    pub country_code: Option<String>,
    #[serde(default)]
    pub security: WifiClientSecurity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub passphrase: Option<String>,
    #[serde(default)]
    pub clear_passphrase: bool,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterProvisioningPreviewView {
    pub uplink: ProvisioningUplinkView,
    pub output: ProvisioningOutputView,
    pub downstream: ProvisioningDownstreamView,
    pub warnings: Vec<ProvisioningWarning>,
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
pub struct RouterProvisioningStatusView {
    pub stage: ProvisioningStage,
    pub enabled: bool,
    pub ready: bool,
    pub coordinator: CoordinatorStatus,

    pub readiness: RouterHealthReport,

    pub failures: Vec<String>,
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
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
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
        config: DhcpInterfaceConfig,
    },
    DisableDhcp {
        interface: String,
    },
    ListLeases {
        interface: String,
    },
    DryRunInterface {
        interface: String,
        config: InterfaceConfig,
        allow_management_change: bool,
    },
    DryRunInterfaceEdit {
        interface: String,
        edit: InterfaceEditRequest,
    },
    ApplyInterface {
        interface: String,
        config: InterfaceConfig,
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
        proposal: RouterProposalRequest,
    },
    RouterApply {
        proposal: RouterProposalRequest,
    },
    RouterCommit,
    RouterRollback,
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
        configure_dhcp: bool,
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
    ActivateWifiClientProfile {
        interface: String,
        profile_id: String,
    },
    DeactivateWifiClientProfile {
        interface: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
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
        spec: Option<DhcpServiceSpec>,
    },
    DhcpConfigured {
        spec: DhcpServiceSpec,
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
        leases: Vec<DhcpLease>,
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
        status: CoordinatorStatus,
        rollback_failure: Option<Vec<String>>,
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
        spec: Option<WifiApSpec>,
    },
    WifiConfigured {
        spec: WifiApSpec,
    },
    WifiAccessPointProvisioned {
        spec: WifiApSpec,
        dhcp: Option<DhcpServiceSpec>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceStatus {
    /// Addresses installed by traffic-masq, verified using tags and its journal.
    /// None means the provider cannot supply authoritative ownership information.
    #[serde(default)]
    pub owned_ipv4_addresses: Option<Vec<Ipv4AddressInfo>>,
    pub interface: NetworkInterface,
    pub ipv4_addresses: Vec<Ipv4AddressInfo>,
    #[serde(default)]
    pub has_default_route: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteStatus {
    pub destination: Ipv4Net,
    pub gateway: Option<Ipv4Addr>,
    pub output_interface: Option<String>,
    pub output_interface_index: Option<u32>,
    pub table: u32,
    pub metric: Option<u32>,
    pub protocol: u8,
    pub scope: u8,
    pub owner: RouteOwner,
}

impl RouteStatus {
    pub fn from_info(
        info: &crate::netlink::Ipv4RouteInfo,
        output_interface: Option<String>,
    ) -> Self {
        Self {
            destination: info.destination,
            gateway: info.gateway,
            output_interface,
            output_interface_index: info.output_interface_index,
            table: info.table,
            metric: info.metric,
            protocol: info.protocol,
            scope: info.scope,
            owner: info.owner(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_status_serde_roundtrip() {
        let status = RouteStatus {
            destination: "192.168.1.0/24".parse().expect("dest"),
            gateway: Some(Ipv4Addr::new(10, 0, 0, 1)),
            output_interface: Some("eth0".to_string()),
            output_interface_index: Some(2),
            table: 254,
            metric: Some(100),
            protocol: 201,
            scope: 0,
            owner: RouteOwner::TrafficMasqStatic,
        };

        let json = serde_json::to_string(&status).expect("serialize");
        let parsed: RouteStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, status);
    }

    #[test]
    fn request_and_response_route_variants_roundtrip() {
        let req = Request::ListRoutes {
            include_local_table: true,
        };
        let json_req = serde_json::to_string(&req).expect("serialize request");
        let parsed_req: Request = serde_json::from_str(&json_req).expect("deserialize request");
        match parsed_req {
            Request::ListRoutes {
                include_local_table,
            } => assert!(include_local_table),
            _ => panic!("wrong variant"),
        }

        let resp = Response::Routes {
            routes: vec![RouteStatus {
                destination: "0.0.0.0/0".parse().expect("dest"),
                gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
                output_interface: Some("wan0".to_string()),
                output_interface_index: Some(3),
                table: 254,
                metric: None,
                protocol: 201,
                scope: 0,
                owner: RouteOwner::TrafficMasqStatic,
            }],
        };
        let json_resp = serde_json::to_string(&resp).expect("serialize response");
        let parsed_resp: Response =
            serde_json::from_str(&json_resp).expect("deserialize response");
        match parsed_resp {
            Response::Routes { routes } => {
                assert_eq!(routes.len(), 1);
                assert_eq!(routes[0].owner, RouteOwner::TrafficMasqStatic);
            }
            _ => panic!("wrong variant"),
        }
    }
}
