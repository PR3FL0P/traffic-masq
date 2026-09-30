//! Loading, validation, and resolution of application configuration.
//!
//! Configuration describes runtime directories, network interfaces, DHCP,
//! Wi-Fi, VPN, firewall, API, and security settings. Values may come from a
//! TOML file and environment variables; [`ResolvedConfig`] records the source
//! of each resolved value.

use std::collections::BTreeMap;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

pub use traffic_masq_protocol::{
    InterfaceRole, UplinkMode, VpnPolicyMode, WifiBand, WifiChannelWidth, WifiClientSecurity,
    WifiSecurity,
};

mod resolver;
pub use resolver::{ConfigSource, ResolvedConfig, CONFIG_ENV, DEFAULT_CONFIG_PATH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub runtime: RuntimeConfig,
    pub network: NetworkConfig,
    #[serde(default)]
    pub router: RouterConfig,
    pub dhcp: DhcpConfig,

    #[serde(default)]
    pub wifi: WifiConfig,

    #[serde(default)]
    pub wifi_client: WifiClientGlobalConfig,
    pub vpn: VpnConfig,
    pub security: SecurityConfig,
    #[serde(default)]
    pub api: ApiConfig,
    #[serde(default)]
    pub auth: AuthConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub state_dir: PathBuf,
    pub log_dir: PathBuf,
    pub socket_path: PathBuf,
    pub pid_path: PathBuf,
    #[serde(default)]
    pub socket_group: Option<String>,
    #[serde(default)]
    pub shutdown_policy: ShutdownPolicy,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShutdownPolicy {
    #[default]
    PreserveInterfaces,
    RestoreInterfaces,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiConfig {
    pub tcp: Option<TcpApiConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TcpApiConfig {
    pub enabled: bool,
    pub listen: SocketAddr,
    pub certificate_path: Option<PathBuf>,
    pub private_key_path: Option<PathBuf>,
}

impl Default for TcpApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: SocketAddr::from(([127, 0, 0, 1], 8443)),
            certificate_path: None,
            private_key_path: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    pub database_path: PathBuf,
    pub session_idle_seconds: u64,
    pub session_absolute_seconds: u64,
    pub argon2_memory_kib: u32,
    pub argon2_iterations: u32,
    pub argon2_parallelism: u32,
    pub max_concurrent_logins: u32,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            database_path: PathBuf::from("/var/lib/traffic-masq/auth.sqlite3"),
            session_idle_seconds: 1_800,
            session_absolute_seconds: 28_800,
            argon2_memory_kib: 32_768,
            argon2_iterations: 3,
            argon2_parallelism: 1,
            max_concurrent_logins: 2,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(default)]
    pub interfaces: BTreeMap<String, InterfaceConfig>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceConfig {
    pub role: InterfaceRole,
    #[serde(default)]
    pub managed: bool,
    pub ipv4: Option<Ipv4Net>,
    pub dhcp: Option<DhcpInterfaceConfig>,

    #[serde(default)]
    pub dhcp_client: Option<DhcpClientInterfaceConfig>,

    #[serde(default)]
    pub wifi: Option<WifiApConfig>,

    #[serde(default)]
    pub wifi_client: Option<WifiClientConfig>,

    /// Whether a managed Output interface's traffic is masqueraded by the
    /// legacy router dataplane (ignored when router.forwarding is present).
    /// Defaults to `true` so upgrading a persisted config
    /// without this key preserves today's unconditional-NAT behavior.
    #[serde(default = "default_true")]
    pub nat: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RouterConfig {
    pub enabled: bool,
    pub uplink: Option<UplinkConfig>,
    /// Explicit ingress → egress rules. None preserves legacy uplink NAT;
    /// Some(empty) disables forwarding without restoring legacy rules.
    pub forwarding: Option<Vec<ForwardingConfig>>,
    pub owned_routes: Vec<OwnedIpv4RouteConfig>,
    pub allow_default_route_change: bool,
    /// Persisted, user-facing VPN hop chain: profile name per hop, ordered
    /// (index 0 = closest to the physical uplink). The derived `interface`/
    /// `reserved` fields of a hop are recomputed at runtime, not persisted.
    #[serde(default)]
    pub vpn_chain: Vec<VpnHopConfig>,
}

/// A directional permission to forward IPv4 traffic between existing interfaces.
/// Routing selects the egress; this rule does not create routes or VPN tunnels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardingConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_subnet: Option<Ipv4Net>,
    pub from: String,
    pub to: String,
    #[serde(default = "default_true")]
    pub masquerade: bool,
}

impl traffic_masq_protocol::ForwardingRule for ForwardingConfig {
    fn source_subnet(&self) -> Option<Ipv4Net> {
        self.source_subnet
    }

    fn from_interface(&self) -> &str {
        &self.from
    }

    fn to_interface(&self) -> &str {
        &self.to
    }
}

/// Reject invalid forwarding port ranges, addresses, protocols, and conflicting rules.
pub fn validate_forwarding(rules: &[ForwardingConfig]) -> Result<()> {
    traffic_masq_protocol::validate_forwarding(rules).map_err(anyhow::Error::msg)
}

/// The maximum number of hops a persisted VPN chain may contain, matching
/// [`crate::core::vpn_policy::MAX_VPN_HOP_INDEX`]'s bound on reserved-ID
/// allocation so the priority-band math can never overflow into an
/// unrelated reserved range.
pub const MAX_VPN_CHAIN_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnHopConfig {
    pub profile_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UplinkConfig {
    pub interface: String,
    pub mode: UplinkMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedIpv4RouteConfig {
    pub destination: Ipv4Net,
    pub gateway: Option<Ipv4Addr>,
    pub output_interface: Option<String>,
    pub table: u32,
    pub metric: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DhcpClientInterfaceConfig {
    /// True only when Wi-Fi activation enabled this previously disabled policy.
    pub wifi_owned: bool,
    pub enabled: bool,
    pub route_metric: u32,
    pub install_default_route: bool,
    pub request_dns: bool,
    pub send_release_on_shutdown: bool,
}

impl Default for DhcpClientInterfaceConfig {
    fn default() -> Self {
        Self {
            wifi_owned: false,
            enabled: true,
            route_metric: 100,
            install_default_route: true,
            request_dns: true,
            send_release_on_shutdown: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpInterfaceConfig {
    pub pool_start: Ipv4Addr,
    pub pool_end: Ipv4Addr,
    pub router: Ipv4Addr,
    #[serde(default)]
    pub dns_servers: Vec<Ipv4Addr>,
    pub lease_seconds: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpConfig {
    pub leases_dir: PathBuf,
    pub default_lease_seconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WifiConfig {
    pub enabled: bool,

    pub hostapd_binary: PathBuf,

    pub iw_binary: PathBuf,

    pub runtime_dir: PathBuf,

    pub restart_backoff_seconds: u64,
}

impl Default for WifiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            hostapd_binary: PathBuf::from("/usr/sbin/hostapd"),
            iw_binary: PathBuf::from("/usr/sbin/iw"),
            runtime_dir: PathBuf::from("/run/traffic-masq/hostapd"),
            restart_backoff_seconds: 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WifiClientGlobalConfig {
    pub enabled: bool,

    pub wpa_supplicant_binary: PathBuf,

    pub runtime_dir: PathBuf,

    pub restart_backoff_seconds: u64,
}

impl Default for WifiClientGlobalConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            wpa_supplicant_binary: PathBuf::from("/usr/sbin/wpa_supplicant"),
            runtime_dir: PathBuf::from("/run/traffic-masq/wpa_supplicant"),
            restart_backoff_seconds: 5,
        }
    }
}

pub fn vht80_center_channel(channel: u8) -> Option<u8> {
    const BLOCKS: &[([u8; 4], u8)] = &[
        ([36, 40, 44, 48], 42),
        ([52, 56, 60, 64], 58),
        ([100, 104, 108, 112], 106),
        ([116, 120, 124, 128], 122),
        ([132, 136, 140, 144], 138),
        ([149, 153, 157, 161], 155),
        ([165, 169, 173, 177], 171),
    ];

    BLOCKS
        .iter()
        .find(|(members, _)| members.contains(&channel))
        .map(|(_, center)| *center)
}

pub use traffic_masq_protocol::MAX_WIFI_STATIONS;

pub const MAX_SSID_BYTES: usize = 32;

pub const MIN_WIFI_PASSPHRASE_LEN: usize = 8;
pub const MAX_WIFI_PASSPHRASE_LEN: usize = 63;

fn default_max_stations() -> u16 {
    32
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifiApConfig {
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
pub struct WifiClientConfig {
    pub ssid: String,

    #[serde(default)]
    pub country_code: Option<String>,
    #[serde(default)]
    pub security: WifiClientSecurity,

    #[serde(default)]
    pub passphrase_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnConfig {
    #[serde(default)]
    pub enabled: bool,
    pub wireguard_config_dir: PathBuf,

    #[serde(default)]
    pub policy: VpnTrafficPolicyConfig,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VpnProtectedSubnets {
    #[default]
    AllManagedOutputSubnets,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct VpnTrafficPolicyConfig {
    pub default_mode: VpnPolicyMode,

    pub protected_subnets: VpnProtectedSubnets,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub rollback_timeout_seconds: u64,
}

impl AppConfig {
    /// Read and deserialize a TOML configuration file without admitting it for normal runtime use.
    ///
    /// Startup recovery needs durable paths and router state even when an unrelated API/auth
    /// setting is semantically invalid. Call [`Self::validate`] before normal startup or mutation.
    pub fn load_unvalidated(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        toml::from_str(&content)
            .with_context(|| format!("failed to parse config file {}", path.display()))
    }

    /// Read, deserialize, and fully validate a TOML configuration file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let config = Self::load_unvalidated(path)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate only state required to reconstruct router recovery intent.
    ///
    /// API/auth/security admission is deliberately excluded: those subsystems are not needed to
    /// prove or roll back a durable router transaction. Full validation remains mandatory before
    /// listeners, authentication, or normal convergence start.
    pub(crate) fn validate_router_recovery(&self) -> Result<()> {
        self.network.validate()?;
        self.router.validate(&self.network)?;
        if self.dhcp.default_lease_seconds == 0 {
            bail!("dhcp.default_lease_seconds must be greater than zero");
        }
        Ok(())
    }

    /// Check configuration invariants and reject incompatible or unsafe settings before application.
    pub fn validate(&self) -> Result<()> {
        self.network.validate()?;
        self.router.validate(&self.network)?;
        if self.router.forwarding.is_some() && self.vpn.policy.default_mode == VpnPolicyMode::Vpn {
            bail!("explicit forwarding requires direct global VPN policy; configure routes for each VPN interface separately");
        }
        self.vpn.validate(&self.router)?;
        self.wifi.validate(&self.network)?;
        self.wifi_client.validate()?;
        self.api.validate()?;
        self.auth.validate()?;

        if self.dhcp.default_lease_seconds == 0 {
            bail!("dhcp.default_lease_seconds must be greater than zero");
        }

        if self.security.rollback_timeout_seconds == 0 {
            bail!("security.rollback_timeout_seconds must be greater than zero");
        }

        if self
            .runtime
            .socket_group
            .as_deref()
            .is_some_and(|group| group.trim().is_empty())
        {
            bail!("runtime.socket_group must not be empty");
        }

        if self.runtime.socket_path == self.runtime.pid_path {
            bail!("runtime.socket_path and runtime.pid_path must be different");
        }
        if self.runtime.socket_path == process_lock_path(&self.runtime.pid_path) {
            bail!("runtime.socket_path conflicts with the derived process lock path");
        }
        Ok(())
    }
}

impl ApiConfig {
    /// Check configuration invariants and reject incompatible or unsafe settings before application.
    fn validate(&self) -> Result<()> {
        let Some(tcp) = &self.tcp else {
            return Ok(());
        };
        if !tcp.enabled {
            return Ok(());
        }

        let certificate = tcp
            .certificate_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("api.tcp.certificate_path is required when enabled"))?;
        let private_key = tcp
            .private_key_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("api.tcp.private_key_path is required when enabled"))?;
        if certificate == private_key {
            bail!("api.tcp.certificate_path and api.tcp.private_key_path must be different");
        }

        Ok(())
    }
}

impl VpnConfig {
    /// Check configuration invariants and reject incompatible or unsafe settings before application.
    fn validate(&self, router: &RouterConfig) -> Result<()> {
        self.policy.validate(self.enabled, router)
    }
}

impl VpnTrafficPolicyConfig {
    /// Check configuration invariants and reject incompatible or unsafe settings before application.
    fn validate(&self, vpn_enabled: bool, router: &RouterConfig) -> Result<()> {
        if self.default_mode == VpnPolicyMode::Vpn && !vpn_enabled {
            bail!("vpn.policy.default_mode = \"vpn\" requires vpn.enabled = true");
        }
        if self.default_mode == VpnPolicyMode::Vpn && !router.enabled {
            bail!("vpn.policy.default_mode = \"vpn\" requires router.enabled = true");
        }
        Ok(())
    }
}

impl AuthConfig {
    /// Check configuration invariants and reject incompatible or unsafe settings before application.
    fn validate(&self) -> Result<()> {
        if self.session_idle_seconds == 0 {
            bail!("auth.session_idle_seconds must be greater than zero");
        }
        if self.session_absolute_seconds == 0 {
            bail!("auth.session_absolute_seconds must be greater than zero");
        }
        if self.argon2_memory_kib == 0 {
            bail!("auth.argon2_memory_kib must be greater than zero");
        }
        if self.argon2_iterations == 0 {
            bail!("auth.argon2_iterations must be greater than zero");
        }
        if self.argon2_parallelism == 0 {
            bail!("auth.argon2_parallelism must be greater than zero");
        }
        if self.max_concurrent_logins == 0 {
            bail!("auth.max_concurrent_logins must be greater than zero");
        }
        if self.session_idle_seconds > self.session_absolute_seconds {
            bail!("auth.session_idle_seconds must not exceed auth.session_absolute_seconds");
        }

        Ok(())
    }
}

impl NetworkConfig {
    /// Check configuration invariants and reject incompatible or unsafe settings before application.
    pub fn validate(&self) -> Result<()> {
        for (name, interface) in &self.interfaces {
            validate_interface_name(name)?;
            interface
                .validate(name)
                .map_err(|error| anyhow::anyhow!("interface {name}: {error}"))?;
        }

        let configured: Vec<(&str, Ipv4Net)> = self
            .interfaces
            .iter()
            .filter(|(_, config)| config.managed)
            .filter_map(|(name, config)| config.ipv4.map(|network| (name.as_str(), network)))
            .collect();

        for (index, (left_name, left)) in configured.iter().enumerate() {
            for (right_name, right) in configured.iter().skip(index + 1) {
                if networks_overlap(*left, *right) {
                    bail!(
                        "managed interface networks overlap: {left_name} ({left}) and {right_name} ({right})"
                    );
                }
            }
        }

        Ok(())
    }

    pub fn management_interfaces(&self) -> impl Iterator<Item = (&str, &InterfaceConfig)> {
        self.interfaces
            .iter()
            .filter(|(_, config)| config.role == InterfaceRole::None)
            .map(|(name, config)| (name.as_str(), config))
    }
}

impl RouterConfig {
    /// Check configuration invariants and reject incompatible or unsafe settings before application.
    fn validate(&self, network: &NetworkConfig) -> Result<()> {
        if let Some(rules) = &self.forwarding {
            validate_forwarding(rules)?;
            if !self.vpn_chain.is_empty() {
                bail!("explicit forwarding cannot be combined with the legacy global vpn_chain; configure tunnel routing separately");
            }
        }
        if self.enabled {
            if let Some(uplink) = self.uplink.as_ref() {
                validate_interface_name(&uplink.interface)
                    .map_err(|error| anyhow::anyhow!("router uplink: {error}"))?;
                let interface = network.interfaces.get(&uplink.interface).ok_or_else(|| {
                    anyhow::anyhow!(
                        "router uplink interface {} is not configured",
                        uplink.interface
                    )
                })?;
                if interface.role != InterfaceRole::Input {
                    bail!("router uplink interface must have the input role");
                }
                match uplink.mode {
                    UplinkMode::External if interface.managed => {
                        bail!("external router uplink must be unmanaged");
                    }
                    UplinkMode::Dhcp
                        if !interface.managed
                            || !interface
                                .dhcp_client
                                .as_ref()
                                .is_some_and(|config| config.enabled) =>
                    {
                        bail!(
                            "DHCP router uplink must be a managed input interface with an enabled dhcp_client block"
                        );
                    }
                    UplinkMode::External | UplinkMode::Dhcp => {}
                }

                let outputs = network
                    .interfaces
                    .iter()
                    .filter(|(_, interface)| {
                        self.forwarding.is_none()
                            && interface.role == InterfaceRole::Output
                            && interface.managed
                    })
                    .collect::<Vec<_>>();
                if outputs.is_empty() && self.forwarding.is_none() {
                    bail!("enabled router mode requires at least one managed output interface");
                }
                for (name, interface) in outputs {
                    if interface.ipv4.is_none() {
                        bail!("router output interface {name} requires a static IPv4 subnet");
                    }
                }
            } else {
                let outputs = network
                    .interfaces
                    .iter()
                    .filter(|(_, interface)| {
                        self.forwarding.is_none()
                            && interface.role == InterfaceRole::Output
                            && interface.managed
                    })
                    .collect::<Vec<_>>();
                for (name, interface) in outputs {
                    if interface.ipv4.is_none() {
                        bail!("router output interface {name} requires a static IPv4 subnet");
                    }
                }
            }
        }

        if self.vpn_chain.len() > MAX_VPN_CHAIN_LEN {
            bail!(
                "vpn_chain length {} exceeds the maximum supported chain length of {}",
                self.vpn_chain.len(),
                MAX_VPN_CHAIN_LEN
            );
        }

        for (index, route) in self.owned_routes.iter().enumerate() {
            route
                .validate(network, self.uplink.as_ref())
                .map_err(|error| anyhow::anyhow!("router owned route {index}: {error}"))?;
            if route.destination.prefix_len() == 0 && !self.allow_default_route_change {
                bail!(
                    "router owned default route requires router.allow_default_route_change = true"
                );
            }
            if self.owned_routes[..index].iter().any(|prior| {
                prior.table == route.table
                    && prior.destination.trunc() == route.destination.trunc()
                    && prior.metric.unwrap_or(0) == route.metric.unwrap_or(0)
            }) {
                bail!(
                    "duplicate router owned IPv4 route: {} in table {} with metric {}",
                    route.destination,
                    route.table,
                    route.metric.unwrap_or(0)
                );
            }
        }

        Ok(())
    }
}

impl OwnedIpv4RouteConfig {
    /// Check configuration invariants and reject incompatible or unsafe settings before application.
    fn validate(&self, network: &NetworkConfig, _uplink: Option<&UplinkConfig>) -> Result<()> {
        if self.table == 0 {
            bail!("IPv4 route table must not be RT_TABLE_UNSPEC (0)");
        }
        if self.table == 255 {
            bail!("IPv4 route table must not be RT_TABLE_LOCAL (255)");
        }
        if self.destination.prefix_len() > 32 {
            bail!(
                "invalid IPv4 prefix length {}",
                self.destination.prefix_len()
            );
        }
        if self.destination.addr() != self.destination.network() {
            bail!(
                "destination prefix {} has host bits set (did you mean {}?)",
                self.destination,
                self.destination.trunc()
            );
        }
        if self.gateway.is_none() && self.output_interface.is_none() {
            bail!("IPv4 route requires a gateway or output interface");
        }
        if let Some(gateway) = self.gateway {
            if gateway.is_unspecified() || gateway.is_broadcast() || gateway.is_multicast() {
                bail!(
                    "IPv4 route gateway must not be unspecified, multicast, or broadcast: {gateway}"
                );
            }
        }

        let Some(name) = self.output_interface.as_deref() else {
            return Ok(());
        };
        validate_interface_name(name)?;
        if let Some(interface) = network.interfaces.get(name) {
            if interface.role == InterfaceRole::Disabled {
                bail!("disabled interface {name} cannot own a router route");
            }
        }
        Ok(())
    }
}

impl InterfaceConfig {
    /// Check configuration invariants and reject incompatible or unsafe settings before application.
    pub fn validate(&self, name: &str) -> Result<()> {
        if self.role == InterfaceRole::Disabled && self.managed {
            bail!("disabled interface cannot be managed");
        }

        if self.dhcp.is_some() && !self.managed {
            bail!("DHCP cannot be enabled on an unmanaged interface");
        }

        if self.dhcp.is_some() && self.role != InterfaceRole::Output {
            bail!("DHCP server can only be enabled on an output interface");
        }

        if self.role == InterfaceRole::Middle
            && (self.dhcp.is_some()
                || self.wifi.is_some()
                || self.wifi_client.is_some()
                || self.ipv4.is_some())
        {
            bail!(
                "a Middle (VPN hop) interface is unaddressed and WireGuard-only; it cannot carry \
                 dhcp, wifi, or an ipv4 address"
            );
        }

        if self.wifi.is_some() && self.wifi_client.is_some() {
            bail!("an interface cannot be both a Wi-Fi access point and a Wi-Fi client (non-goal: concurrent AP+STA)");
        }

        if self.dhcp_client.is_some() && self.role != InterfaceRole::Input {
            bail!("a DHCP client can only be configured on an input interface");
        }

        if self
            .dhcp_client
            .as_ref()
            .is_some_and(|dhcp_client| dhcp_client.enabled)
            && !self.managed
        {
            bail!("an enabled DHCP client requires a managed input interface");
        }

        if self.ipv4.is_some()
            && self
                .dhcp_client
                .as_ref()
                .is_some_and(|dhcp_client| dhcp_client.enabled)
        {
            bail!("an interface cannot have both a static IPv4 address and an enabled DHCP client");
        }

        if self.wifi.is_some() && !self.managed {
            bail!("a Wi-Fi access point cannot be enabled on an unmanaged interface");
        }

        if self.wifi.is_some() && self.role != InterfaceRole::Output {
            bail!("a Wi-Fi access point can only be enabled on an output interface");
        }

        if let Some(wifi) = &self.wifi {
            wifi.validate(name)?;
        }

        if self.wifi_client.is_some() && !self.managed {
            bail!("a Wi-Fi client cannot be enabled on an unmanaged interface; traffic-masq does not modify unmanaged interfaces. Enable 'managed' first.");
        }

        if self.wifi_client.is_some() && self.role != InterfaceRole::Input {
            bail!(
                "a Wi-Fi client can only be enabled on an input interface (current role: {:?})",
                self.role
            );
        }

        if let Some(wifi_client) = &self.wifi_client {
            wifi_client.validate(name)?;
        }

        let Some(dhcp) = &self.dhcp else {
            return Ok(());
        };
        let network = self
            .ipv4
            .ok_or_else(|| anyhow::anyhow!("DHCP requires an IPv4 interface address"))?;

        dhcp.validate(name, network)
    }
}

pub const MAX_DHCP_DNS_SERVERS: usize = 63;

impl DhcpInterfaceConfig {
    /// Check configuration invariants and reject incompatible or unsafe settings before application.
    fn validate(&self, _interface_name: &str, network: Ipv4Net) -> Result<()> {
        if self.dns_servers.len() > MAX_DHCP_DNS_SERVERS {
            bail!(
                "DHCP dns_servers has {} entries, but DHCP option 6 holds at most {MAX_DHCP_DNS_SERVERS}",
                self.dns_servers.len()
            );
        }

        if u32::from(self.pool_start) > u32::from(self.pool_end) {
            bail!("DHCP pool start is greater than pool end");
        }

        if !network.contains(&self.pool_start) || !network.contains(&self.pool_end) {
            bail!("DHCP pool must be contained in interface network {network}");
        }

        if !network.contains(&self.router) {
            bail!("DHCP router must be contained in interface network {network}");
        }

        if self.router != network.addr() {
            bail!(
                "DHCP router must match the output interface IPv4 address {}",
                network.addr()
            );
        }

        if ip_in_range(self.router, self.pool_start, self.pool_end) {
            bail!("DHCP router must not be inside the lease pool");
        }

        if ip_in_range(network.addr(), self.pool_start, self.pool_end) {
            bail!("interface IPv4 address must not be inside the DHCP lease pool");
        }

        if self.pool_start == network.network() || self.pool_end == network.broadcast() {
            bail!("DHCP pool must not include network or broadcast address");
        }

        if self.lease_seconds == Some(0) {
            bail!("DHCP lease_seconds must be greater than zero");
        }

        Ok(())
    }
}

impl WifiConfig {
    /// Check configuration invariants and reject incompatible or unsafe settings before application.
    fn validate(&self, network: &NetworkConfig) -> Result<()> {
        if self.hostapd_binary.as_os_str().is_empty() {
            bail!("wifi.hostapd_binary must not be empty");
        }
        if !self.hostapd_binary.is_absolute() {
            bail!(
                "wifi.hostapd_binary must be an absolute path, got {}",
                self.hostapd_binary.display()
            );
        }
        if self.iw_binary.as_os_str().is_empty() {
            bail!("wifi.iw_binary must not be empty");
        }
        if !self.iw_binary.is_absolute() {
            bail!(
                "wifi.iw_binary must be an absolute path, got {}",
                self.iw_binary.display()
            );
        }
        if self.runtime_dir.as_os_str().is_empty() {
            bail!("wifi.runtime_dir must not be empty");
        }
        if !self.runtime_dir.is_absolute() {
            bail!(
                "wifi.runtime_dir must be an absolute path, got {}",
                self.runtime_dir.display()
            );
        }
        if self.restart_backoff_seconds == 0 {
            bail!("wifi.restart_backoff_seconds must be greater than zero");
        }

        let mut seen: BTreeMap<(&str, WifiBand), &str> = BTreeMap::new();
        for (name, interface) in &network.interfaces {
            let Some(wifi) = &interface.wifi else {
                continue;
            };
            if let Some(previous) = seen.insert((wifi.ssid.as_str(), wifi.band), name.as_str()) {
                bail!(
                    "interfaces {previous} and {name} both advertise SSID {:?} on the {} band",
                    wifi.ssid,
                    wifi.band
                );
            }
        }

        Ok(())
    }
}

impl WifiApConfig {
    /// Check configuration invariants and reject incompatible or unsafe settings before application.
    fn validate(&self, interface_name: &str) -> Result<()> {
        let ssid_bytes = self.ssid.len();
        if ssid_bytes == 0 {
            bail!("Wi-Fi ssid must not be empty");
        }
        if ssid_bytes > MAX_SSID_BYTES {
            bail!("Wi-Fi ssid is {ssid_bytes} bytes, but at most {MAX_SSID_BYTES} fit in an SSID element");
        }
        if self.ssid.chars().any(|character| character.is_control()) {
            bail!("Wi-Fi ssid must not contain control characters");
        }

        if let Some(country) = &self.country_code {
            if country.len() != 2 || !country.bytes().all(|byte| byte.is_ascii_uppercase()) {
                bail!(
                    "Wi-Fi country_code must be two uppercase ASCII letters (ISO 3166-1 alpha-2), got {country:?}"
                );
            }
        } else if self.band == WifiBand::Ghz5 {
            bail!("Wi-Fi country_code is required on the 5 GHz band");
        }

        if self.channel != 0 && !self.band.channels().contains(&self.channel) {
            bail!(
                "Wi-Fi channel {} is not a {} channel (use 0 to let hostapd select one)",
                self.channel,
                self.band
            );
        }

        if self.channel_width == WifiChannelWidth::Vht80 {
            if self.band != WifiBand::Ghz5 {
                bail!("Wi-Fi channel_width \"vht80\" requires band \"5g\"");
            }

            if self.channel != 0 && vht80_center_channel(self.channel).is_none() {
                bail!(
                    "Wi-Fi channel {} carries no 80 MHz block, so it cannot be used with channel_width \"vht80\"",
                    self.channel
                );
            }
        }

        if self.max_stations == 0 {
            bail!("Wi-Fi max_stations must be greater than zero");
        }
        if self.max_stations > MAX_WIFI_STATIONS {
            bail!(
                "Wi-Fi max_stations is {}, but hostapd accepts at most {MAX_WIFI_STATIONS}",
                self.max_stations
            );
        }

        if let Some(path) = &self.passphrase_file {
            if self.security == WifiSecurity::Open {
                bail!(
                    "Wi-Fi passphrase_file is set on {interface_name}, but security is \"open\" — \
                     remove one of the two rather than leaving it ambiguous"
                );
            }
            if path.as_os_str().is_empty() {
                bail!("Wi-Fi passphrase_file must not be empty");
            }
            if !path.is_absolute() {
                bail!(
                    "Wi-Fi passphrase_file must be an absolute path, got {}",
                    path.display()
                );
            }
        }

        Ok(())
    }
}

impl WifiClientGlobalConfig {
    /// Check configuration invariants and reject incompatible or unsafe settings before application.
    fn validate(&self) -> Result<()> {
        if self.wpa_supplicant_binary.as_os_str().is_empty() {
            bail!("wifi_client.wpa_supplicant_binary must not be empty");
        }
        if !self.wpa_supplicant_binary.is_absolute() {
            bail!(
                "wifi_client.wpa_supplicant_binary must be an absolute path, got {}",
                self.wpa_supplicant_binary.display()
            );
        }
        if self.runtime_dir.as_os_str().is_empty() {
            bail!("wifi_client.runtime_dir must not be empty");
        }
        if !self.runtime_dir.is_absolute() {
            bail!(
                "wifi_client.runtime_dir must be an absolute path, got {}",
                self.runtime_dir.display()
            );
        }
        if self.restart_backoff_seconds == 0 {
            bail!("wifi_client.restart_backoff_seconds must be greater than zero");
        }
        Ok(())
    }
}

impl WifiClientConfig {
    /// Check configuration invariants and reject incompatible or unsafe settings before application.
    fn validate(&self, interface_name: &str) -> Result<()> {
        let ssid_bytes = self.ssid.len();
        if ssid_bytes == 0 {
            bail!("Wi-Fi client ssid must not be empty");
        }
        if ssid_bytes > MAX_SSID_BYTES {
            bail!(
                "Wi-Fi client ssid is {ssid_bytes} bytes, but at most {MAX_SSID_BYTES} fit in an SSID element"
            );
        }
        if self.ssid.chars().any(|character| character.is_control()) {
            bail!("Wi-Fi client ssid must not contain control characters");
        }

        if let Some(country) = &self.country_code {
            if country.len() != 2 || !country.bytes().all(|byte| byte.is_ascii_uppercase()) {
                bail!(
                    "Wi-Fi client country_code must be two uppercase ASCII letters (ISO 3166-1 alpha-2), got {country:?}"
                );
            }
        }

        if let Some(path) = &self.passphrase_file {
            if self.security == WifiClientSecurity::Open {
                bail!(
                    "Wi-Fi client passphrase_file is set on {interface_name}, but security is \"open\" — \
                     remove one of the two rather than leaving it ambiguous"
                );
            }
            if path.as_os_str().is_empty() {
                bail!("Wi-Fi client passphrase_file must not be empty");
            }
            if !path.is_absolute() {
                bail!(
                    "Wi-Fi client passphrase_file must be an absolute path, got {}",
                    path.display()
                );
            }
        }

        Ok(())
    }
}

/// Reject names that exceed Linux interface limits or contain unsupported characters.
pub(crate) fn validate_interface_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("interface name cannot be empty");
    }

    if name.len() > 15 {
        bail!("interface name exceeds Linux IFNAMSIZ limit");
    }

    if !name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.'))
    {
        bail!("interface name contains unsupported characters");
    }

    Ok(())
}

pub(crate) fn networks_overlap(left: Ipv4Net, right: Ipv4Net) -> bool {
    left.contains(&right.network()) || right.contains(&left.network())
}

fn process_lock_path(pid_path: &Path) -> PathBuf {
    let file_name = pid_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("traffic-masqd.pid");
    pid_path.with_file_name(format!("{file_name}.lock"))
}

fn ip_in_range(ip: Ipv4Addr, start: Ipv4Addr, end: Ipv4Addr) -> bool {
    let ip = u32::from(ip);
    u32::from(start) <= ip && ip <= u32::from(end)
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            runtime: RuntimeConfig {
                state_dir: PathBuf::from("/var/lib/traffic-masq"),
                log_dir: PathBuf::from("/var/log/traffic-masq"),
                socket_path: PathBuf::from("/run/traffic-masq/traffic-masqd.sock"),
                pid_path: PathBuf::from("/run/traffic-masq/traffic-masqd.pid"),
                socket_group: None,
                shutdown_policy: ShutdownPolicy::PreserveInterfaces,
            },
            network: NetworkConfig::default(),
            router: RouterConfig::default(),
            dhcp: DhcpConfig {
                leases_dir: PathBuf::from("/var/lib/traffic-masq/dhcp/leases"),
                default_lease_seconds: 86_400,
            },
            wifi: WifiConfig::default(),
            wifi_client: WifiClientGlobalConfig::default(),
            vpn: VpnConfig {
                enabled: false,
                wireguard_config_dir: PathBuf::from("/var/lib/traffic-masq/vpn/wireguard"),
                policy: VpnTrafficPolicyConfig::default(),
            },
            security: SecurityConfig {
                rollback_timeout_seconds: 60,
            },
            api: ApiConfig::default(),
            auth: AuthConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests;
