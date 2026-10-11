//! Interface configuration as it appears in control requests.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use crate::{InterfaceRole, WifiBand, WifiChannelWidth, WifiClientSecurity, WifiSecurity};

/// hostapd's maximum supported station count for an AP configuration.
pub const MAX_WIFI_STATIONS: u16 = 2007;

fn default_true() -> bool {
    true
}

fn default_max_stations() -> u16 {
    32
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceConfigView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<crate::MacAddr>,
    pub role: InterfaceRole,
    #[serde(default)]
    pub managed: bool,
    pub ipv4: Option<Ipv4Net>,
    pub dhcp: Option<DhcpInterfaceConfigView>,
    #[serde(default)]
    pub dhcp_client: Option<DhcpClientInterfaceConfigView>,
    #[serde(default)]
    pub wifi: Option<WifiApConfigView>,
    #[serde(default)]
    pub wifi_client: Option<WifiClientConfigView>,
    #[serde(default = "default_true")]
    pub nat: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpInterfaceConfigView {
    pub pool_start: Ipv4Addr,
    pub pool_end: Ipv4Addr,
    pub router: Ipv4Addr,
    #[serde(default)]
    pub dns_servers: Vec<Ipv4Addr>,
    pub lease_seconds: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DhcpClientInterfaceConfigView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    pub wifi_owned: bool,
    pub enabled: bool,
    pub route_metric: u32,
    pub install_default_route: bool,
    pub request_dns: bool,
    pub send_release_on_shutdown: bool,
}

impl Default for DhcpClientInterfaceConfigView {
    fn default() -> Self {
        Self {
            wifi_owned: false,
            enabled: true,
            hostname: None,
            route_metric: 100,
            install_default_route: true,
            request_dns: true,
            send_release_on_shutdown: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifiApConfigView {
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
    #[serde(default = "default_max_stations")]
    pub max_stations: u16,
    #[serde(default)]
    pub passphrase_file: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifiClientConfigView {
    pub ssid: String,
    #[serde(default)]
    pub country_code: Option<String>,
    #[serde(default)]
    pub security: WifiClientSecurity,
    #[serde(default)]
    pub passphrase_file: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifiClientSpecView {
    pub interface: String,
    pub ssid: String,
    pub country_code: Option<String>,
    pub security: WifiClientSecurity,
    pub passphrase_file: Option<PathBuf>,
}
