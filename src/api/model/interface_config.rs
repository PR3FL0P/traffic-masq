//! Conversion between wire configuration and validated daemon configuration.

use crate::config::{
    DhcpClientInterfaceConfig, DhcpInterfaceConfig, InterfaceConfig, WifiApConfig, WifiClientConfig,
};
use crate::wifi::WifiClientSpec;
use traffic_masq_protocol::{
    DhcpClientInterfaceConfigView, DhcpInterfaceConfigView, InterfaceConfigView, WifiApConfigView,
    WifiClientConfigView, WifiClientSpecView,
};

impl From<InterfaceConfigView> for InterfaceConfig {
    fn from(value: InterfaceConfigView) -> Self {
        Self {
            mac_address: value.mac_address,
            role: value.role,
            managed: value.managed,
            ipv4: value.ipv4,
            dhcp: value.dhcp.map(Into::into),
            dhcp_client: value.dhcp_client.map(Into::into),
            wifi: value.wifi.map(Into::into),
            wifi_client: value.wifi_client.map(Into::into),
            nat: value.nat,
        }
    }
}

impl From<InterfaceConfig> for InterfaceConfigView {
    fn from(value: InterfaceConfig) -> Self {
        Self {
            mac_address: value.mac_address,
            role: value.role,
            managed: value.managed,
            ipv4: value.ipv4,
            dhcp: value.dhcp.map(Into::into),
            dhcp_client: value.dhcp_client.map(Into::into),
            wifi: value.wifi.map(Into::into),
            wifi_client: value.wifi_client.map(Into::into),
            nat: value.nat,
        }
    }
}

impl From<DhcpInterfaceConfigView> for DhcpInterfaceConfig {
    fn from(value: DhcpInterfaceConfigView) -> Self {
        Self {
            pool_start: value.pool_start,
            pool_end: value.pool_end,
            router: value.router,
            dns_servers: value.dns_servers,
            lease_seconds: value.lease_seconds,
        }
    }
}

impl From<DhcpInterfaceConfig> for DhcpInterfaceConfigView {
    fn from(value: DhcpInterfaceConfig) -> Self {
        Self {
            pool_start: value.pool_start,
            pool_end: value.pool_end,
            router: value.router,
            dns_servers: value.dns_servers,
            lease_seconds: value.lease_seconds,
        }
    }
}

impl From<DhcpClientInterfaceConfigView> for DhcpClientInterfaceConfig {
    fn from(value: DhcpClientInterfaceConfigView) -> Self {
        Self {
            wifi_owned: value.wifi_owned,
            enabled: value.enabled,
            hostname: value.hostname,
            route_metric: value.route_metric,
            install_default_route: value.install_default_route,
            request_dns: value.request_dns,
            send_release_on_shutdown: value.send_release_on_shutdown,
        }
    }
}

impl From<DhcpClientInterfaceConfig> for DhcpClientInterfaceConfigView {
    fn from(value: DhcpClientInterfaceConfig) -> Self {
        Self {
            wifi_owned: value.wifi_owned,
            enabled: value.enabled,
            hostname: value.hostname,
            route_metric: value.route_metric,
            install_default_route: value.install_default_route,
            request_dns: value.request_dns,
            send_release_on_shutdown: value.send_release_on_shutdown,
        }
    }
}

impl From<WifiApConfigView> for WifiApConfig {
    fn from(value: WifiApConfigView) -> Self {
        Self {
            ssid: value.ssid,
            country_code: value.country_code,
            band: value.band,
            channel: value.channel,
            channel_width: value.channel_width,
            security: value.security,
            hidden: value.hidden,
            client_isolation: value.client_isolation,
            max_stations: value.max_stations,
            passphrase_file: value.passphrase_file,
        }
    }
}

impl From<WifiApConfig> for WifiApConfigView {
    fn from(value: WifiApConfig) -> Self {
        Self {
            ssid: value.ssid,
            country_code: value.country_code,
            band: value.band,
            channel: value.channel,
            channel_width: value.channel_width,
            security: value.security,
            hidden: value.hidden,
            client_isolation: value.client_isolation,
            max_stations: value.max_stations,
            passphrase_file: value.passphrase_file,
        }
    }
}

impl From<WifiClientConfigView> for WifiClientConfig {
    fn from(value: WifiClientConfigView) -> Self {
        Self {
            ssid: value.ssid,
            country_code: value.country_code,
            security: value.security,
            passphrase_file: value.passphrase_file,
        }
    }
}

impl From<WifiClientConfig> for WifiClientConfigView {
    fn from(value: WifiClientConfig) -> Self {
        Self {
            ssid: value.ssid,
            country_code: value.country_code,
            security: value.security,
            passphrase_file: value.passphrase_file,
        }
    }
}

impl From<WifiClientSpec> for WifiClientSpecView {
    fn from(value: WifiClientSpec) -> Self {
        Self {
            interface: value.interface,
            ssid: value.ssid,
            country_code: value.country_code,
            security: value.security,
            passphrase_file: value.passphrase_file,
        }
    }
}

impl From<WifiClientSpecView> for WifiClientSpec {
    fn from(value: WifiClientSpecView) -> Self {
        Self {
            interface: value.interface,
            ssid: value.ssid,
            country_code: value.country_code,
            security: value.security,
            passphrase_file: value.passphrase_file,
        }
    }
}
