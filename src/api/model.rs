use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

pub use traffic_masq_protocol::{
    ApiHttpsSettings, CoordinatorStatus, InterfaceEditRequest, PendingNetworkChange,
    ProvisionWifiAccessPointRequest, ProvisioningDownstreamView, ProvisioningOutputRequest,
    ProvisioningOutputView, ProvisioningUplinkRequest, ProvisioningUplinkView, RouterHealthReport,
    RouterProvisioningApplyRequest, RouterProvisioningPreviewRequest,
    RouterProvisioningPreviewView, RouterProvisioningRequest, RouterProvisioningStatusView,
    RouterRecoveryNotice, SecuritySettings, VpnActiveStatus, VpnPolicyStatusView,
    VpnProfileSummary, WifiApProfileSummary, WifiApProfileWriteRequest, WifiApSpecView,
    WifiClientEditRequest, WifiClientProfileSummary, WifiClientProfileWriteRequest,
    WifiEditRequest,
};

pub use traffic_masq_protocol::{
    DhcpClientConfigRequest, DhcpClientErrorDetail, DhcpClientOperationalState,
    DhcpClientStatusView, DhcpEditRequest, DhcpServiceView, ProvisionWifiClientRequest,
    ProvisioningStage, ProvisioningWarning, RouterErrorDetail, RouterProvisioningErrorDetail,
    VpnErrorDetail, VpnPolicyErrorDetail, WifiClientActivationPhase, WifiClientErrorDetail,
    WifiClientIpPolicy, WifiClientProfileActivationRequest, WifiClientProfileErrorDetail,
    WifiErrorDetail,
};

use crate::config::{DhcpInterfaceConfig, InterfaceConfig, RouterConfig};
use crate::dhcp::supervisor::DhcpServiceSpec;
use crate::netlink::{Ipv4AddressInfo, NetworkInterface, RouteOwner};
use crate::wifi::WifiApSpec;

mod interface_config;
mod interface_plan;
mod network;
mod route;
mod router_config;
mod router_plan;
mod wifi_status;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceOverrideRequest {
    pub config: InterfaceConfig,
    #[serde(default)]
    pub allow_management_change: bool,
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

pub type Request = traffic_masq_protocol::ControlRequest;

impl From<DhcpServiceSpec> for DhcpServiceView {
    fn from(spec: DhcpServiceSpec) -> Self {
        Self {
            interface: spec.interface,
            server_ip: spec.server_ip,
            prefix_len: spec.prefix_len,
            subnet_mask: spec.subnet_mask,
            pool_start: spec.pool_start,
            pool_end: spec.pool_end,
            router: spec.router,
            dns_servers: spec.dns_servers,
            lease_seconds: spec.lease_seconds,
        }
    }
}

impl From<WifiApSpec> for WifiApSpecView {
    fn from(spec: WifiApSpec) -> Self {
        Self {
            interface: spec.interface,
            ssid: spec.ssid,
            country_code: spec.country_code,
            band: spec.band,
            channel: spec.channel,
            channel_width: spec.channel_width,
            security: spec.security,
            hidden: spec.hidden,
            client_isolation: spec.client_isolation,
            max_stations: spec.max_stations,
            passphrase_file: spec.passphrase_file,
        }
    }
}

impl From<DhcpEditRequest> for DhcpInterfaceConfig {
    fn from(request: DhcpEditRequest) -> Self {
        Self {
            pool_start: request.pool_start,
            pool_end: request.pool_end,
            router: request.router,
            dns_servers: request.dns_servers,
            lease_seconds: request.lease_seconds,
        }
    }
}

pub type Response = traffic_masq_protocol::ControlResponse;

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
mod tests;
