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
    /// router dataplane. Defaults to `true` so upgrading a persisted config
    /// without this key preserves today's unconditional-NAT behavior.
    #[serde(default = "default_true")]
    pub nat: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RouterConfig {
    pub enabled: bool,
    pub uplink: Option<UplinkConfig>,
    pub owned_routes: Vec<OwnedIpv4RouteConfig>,
    pub allow_default_route_change: bool,
    /// Persisted, user-facing VPN hop chain: profile name per hop, ordered
    /// (index 0 = closest to the physical uplink). The derived `interface`/
    /// `reserved` fields of a hop are recomputed at runtime, not persisted.
    #[serde(default)]
    pub vpn_chain: Vec<VpnHopConfig>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UplinkMode {
    External,
    Dhcp,
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
    pub enabled: bool,
    pub route_metric: u32,
    pub install_default_route: bool,
    pub request_dns: bool,
    pub send_release_on_shutdown: bool,
}

impl Default for DhcpClientInterfaceConfig {
    fn default() -> Self {
        Self {
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

    pub runtime_dir: PathBuf,

    pub restart_backoff_seconds: u64,
}

impl Default for WifiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            hostapd_binary: PathBuf::from("/usr/sbin/hostapd"),
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

pub const MAX_WIFI_STATIONS: u16 = 2007;

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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WifiClientSecurity {
    #[default]
    Wpa2,
    Wpa3,
    Open,
}

impl WifiClientSecurity {
    pub fn requires_passphrase(self) -> bool {
        !matches!(self, WifiClientSecurity::Open)
    }
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
pub enum VpnPolicyMode {
    #[default]
    Direct,
    Vpn,
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
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        let config: Self = toml::from_str(&content)
            .with_context(|| format!("failed to parse config file {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        self.network.validate()?;
        self.router.validate(&self.network)?;
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
    fn validate(&self, router: &RouterConfig) -> Result<()> {
        self.policy.validate(self.enabled, router)
    }
}

impl VpnTrafficPolicyConfig {
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
    fn validate(&self, network: &NetworkConfig) -> Result<()> {
        if self.enabled {
            // An enabled router without an uplink is a valid control-plane state:
            // the daemon can start and the user can complete setup through the
            // provisioning API.  A complete uplink remains mandatory before a
            // router candidate can be activated.
            let Some(uplink) = self.uplink.as_ref() else {
                return Ok(());
            };
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
                    interface.role == InterfaceRole::Output && interface.managed
                })
                .collect::<Vec<_>>();
            if outputs.is_empty() {
                bail!("enabled router mode requires at least one managed output interface");
            }
            for (name, interface) in outputs {
                if interface.ipv4.is_none() {
                    bail!("router output interface {name} requires a static IPv4 subnet");
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
            if self.owned_routes[..index].contains(route) {
                bail!("duplicate router owned IPv4 route: {}", route.destination);
            }
        }

        Ok(())
    }
}

impl OwnedIpv4RouteConfig {
    fn validate(&self, network: &NetworkConfig, uplink: Option<&UplinkConfig>) -> Result<()> {
        if self.table == 0 {
            bail!("IPv4 route table must not be RT_TABLE_UNSPEC (0)");
        }
        if self.gateway.is_none() && self.output_interface.is_none() {
            bail!("IPv4 route requires a gateway or output interface");
        }

        let Some(name) = self.output_interface.as_deref() else {
            return Ok(());
        };
        validate_interface_name(name)?;
        let interface = network
            .interfaces
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("output interface {name} is not configured"))?;
        match interface.role {
            InterfaceRole::Input if uplink.is_some_and(|uplink| uplink.interface == name) => Ok(()),
            InterfaceRole::Output if interface.managed => Ok(()),
            InterfaceRole::None | InterfaceRole::Disabled | InterfaceRole::Middle => {
                bail!("outside-router, disabled, or VPN-hop interface {name} cannot own a router route")
            }
            InterfaceRole::Input => {
                bail!("route input interface {name} is not the selected uplink")
            }
            InterfaceRole::Output => bail!("route output interface {name} must be managed"),
        }
    }
}

impl InterfaceConfig {
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

        if self.wifi.is_some() && self.wifi_client.is_some() {
            bail!("an interface cannot be both a Wi-Fi access point and a Wi-Fi client (non-goal: concurrent AP+STA)");
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

        if self.wifi_client.is_some() && self.role != InterfaceRole::Input {
            bail!("a Wi-Fi client can only be enabled on an input interface");
        }

        if self.wifi_client.is_some()
            && self.managed
            && !self
                .dhcp_client
                .as_ref()
                .is_some_and(|dhcp_client| dhcp_client.enabled)
        {
            bail!(
                "a managed Wi-Fi client requires an enabled dhcp_client block; otherwise leave it unmanaged for external L3 ownership"
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
mod tests {

    #[test]
    fn legacy_management_role_reads_as_none_and_serializes_canonically() {
        let config: InterfaceConfig =
            toml::from_str("role = \"management\"\nmanaged = false\n").unwrap();
        assert_eq!(config.role, InterfaceRole::None);
        let encoded = toml::to_string(&config).unwrap();
        assert!(encoded.contains("role = \"none\""));
        assert!(!encoded.contains("management"));
    }

    use super::*;

    fn input_interface() -> InterfaceConfig {
        InterfaceConfig {
            nat: true,
            role: InterfaceRole::Input,
            managed: false,
            ipv4: None,
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        }
    }

    fn output_interface(ipv4: &str, pool_start: Ipv4Addr, pool_end: Ipv4Addr) -> InterfaceConfig {
        InterfaceConfig {
            nat: true,
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some(ipv4.parse().expect("valid network")),
            dhcp: Some(DhcpInterfaceConfig {
                pool_start,
                pool_end,
                router: ipv4
                    .split('/')
                    .next()
                    .expect("address")
                    .parse()
                    .expect("router"),
                dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
                lease_seconds: Some(3600),
            }),
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        }
    }

    fn valid_router_config() -> AppConfig {
        let mut config = AppConfig::default();
        config
            .network
            .interfaces
            .insert("wan0".to_string(), input_interface());
        config.network.interfaces.insert(
            "lan0".to_string(),
            output_interface(
                "192.168.10.1/24",
                Ipv4Addr::new(192, 168, 10, 100),
                Ipv4Addr::new(192, 168, 10, 200),
            ),
        );
        config.network.interfaces.insert(
            "lan1".to_string(),
            output_interface(
                "192.168.20.1/24",
                Ipv4Addr::new(192, 168, 20, 100),
                Ipv4Addr::new(192, 168, 20, 200),
            ),
        );
        config.router = RouterConfig {
            vpn_chain: Vec::new(),
            enabled: true,
            uplink: Some(UplinkConfig {
                interface: "wan0".to_string(),
                mode: UplinkMode::External,
            }),
            owned_routes: vec![OwnedIpv4RouteConfig {
                destination: "203.0.113.0/24".parse().expect("route destination"),
                gateway: None,
                output_interface: Some("wan0".to_string()),
                table: 254,
                metric: Some(100),
            }],
            allow_default_route_change: false,
        };
        config
    }

    #[test]
    fn rejects_dhcp_router_that_differs_from_output_interface_address() {
        let interface = output_interface(
            "192.168.10.1/24",
            Ipv4Addr::new(192, 168, 10, 100),
            Ipv4Addr::new(192, 168, 10, 200),
        );
        let mut interface = interface;
        interface.dhcp.as_mut().expect("DHCP config").router = Ipv4Addr::new(192, 168, 10, 254);

        let error = interface
            .validate("lan0")
            .expect_err("external DHCP gateway is not supported");
        assert!(error
            .to_string()
            .contains("must match the output interface IPv4 address"));
    }

    #[test]
    fn example_config_parses_and_validates() {
        let config: AppConfig = toml::from_str(include_str!("../../examples/config.toml"))
            .expect("example config should parse");
        config.validate().expect("example config should validate");
    }

    #[test]
    fn example_config_documents_both_wifi_sections_disabled() {
        let raw = include_str!("../../examples/config.toml");
        let config: AppConfig = toml::from_str(raw).expect("example config should parse");

        assert!(
            raw.contains("[wifi]"),
            "the AP section should be documented"
        );
        assert!(
            raw.contains("[wifi_client]"),
            "the client section should be documented"
        );
        assert!(!config.wifi.enabled, "the example must not start an AP");
        assert!(
            !config.wifi_client.enabled,
            "the example must not join a network"
        );

        // The warning is a wrapped comment. Match the sentence as it reads,
        // not as it happens to be broken across lines: rewrapping the example
        // must not look like deleting the warning.
        let unwrapped = raw
            .lines()
            .map(|line| line.trim_start_matches('#').trim())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            unwrapped.contains("does NOT give this interface an IP address"),
            "the external-address-acquisition warning must stay in the example"
        );
    }

    #[test]
    fn example_config_describes_a_complete_working_router() {
        let config: AppConfig = toml::from_str(include_str!("../../examples/config.toml"))
            .expect("example config should parse");

        assert!(config.router.enabled, "example should demonstrate routing");
        let uplink = config
            .router
            .uplink
            .as_ref()
            .expect("example has an uplink");
        assert_eq!(uplink.interface, "wan0");
        assert_eq!(uplink.mode, UplinkMode::External);
        assert!(
            !config.router.allow_default_route_change,
            "example must not ship with default-route replacement pre-authorized"
        );

        let uplink_interface = config
            .network
            .interfaces
            .get("wan0")
            .expect("uplink is declared");
        assert_eq!(uplink_interface.role, InterfaceRole::Input);
        assert!(
            !uplink_interface.managed,
            "an external uplink must stay unmanaged"
        );

        let management = config
            .network
            .interfaces
            .get("eth0")
            .expect("example shows an outside-router interface");
        assert_eq!(management.role, InterfaceRole::None);
        assert!(!management.managed);

        let lan = config
            .network
            .interfaces
            .get("wlan0")
            .expect("example shows a managed LAN");
        assert_eq!(lan.role, InterfaceRole::Output);
        assert!(lan.managed);
        assert!(lan.ipv4.is_some());
        assert!(lan.dhcp.is_some());

        assert!(!config.vpn.enabled);
        assert_eq!(config.vpn.policy.default_mode, VpnPolicyMode::Direct);
        assert!(config.api.tcp.as_ref().is_some_and(|tcp| !tcp.enabled));
    }

    #[test]
    fn default_config_does_not_manage_any_interface() {
        let config = AppConfig::default();
        assert!(config.network.interfaces.is_empty());
        assert_eq!(config.router, RouterConfig::default());
        assert!(!config.router.enabled);
        assert_eq!(config.vpn.policy.default_mode, VpnPolicyMode::Direct);
        assert_eq!(
            config.vpn.policy.protected_subnets,
            VpnProtectedSubnets::AllManagedOutputSubnets
        );
        config.validate().expect("default config should be valid");
    }

    #[test]
    fn legacy_vpn_config_without_policy_uses_stage_06_defaults() {
        let mut legacy = toml::Value::try_from(AppConfig::default()).expect("serialize config");
        let root = legacy.as_table_mut().expect("root table");
        let vpn = root
            .get_mut("vpn")
            .and_then(toml::Value::as_table_mut)
            .expect("vpn table");
        vpn.remove("policy");
        vpn.insert("enabled".into(), toml::Value::Boolean(true));

        let config: AppConfig = legacy.try_into().expect("legacy config should parse");
        assert_eq!(config.vpn.policy.default_mode, VpnPolicyMode::Direct);
        assert_eq!(
            config.vpn.policy.protected_subnets,
            VpnProtectedSubnets::AllManagedOutputSubnets
        );
        config.validate().expect("legacy config should validate");
    }

    #[test]
    fn vpn_policy_vpn_mode_requires_vpn_manager_to_be_enabled() {
        let mut config = valid_router_config();
        config.vpn.policy.default_mode = VpnPolicyMode::Vpn;

        let error = config
            .validate()
            .expect_err("VPN mode requires vpn.enabled");
        assert!(error
            .to_string()
            .contains("vpn.policy.default_mode = \"vpn\" requires vpn.enabled = true"));
    }

    #[test]
    fn vpn_policy_vpn_mode_requires_router_baseline() {
        let mut config = AppConfig::default();
        config.vpn.enabled = true;
        config.vpn.policy.default_mode = VpnPolicyMode::Vpn;

        let error = config
            .validate()
            .expect_err("VPN mode requires router baseline");
        assert!(error
            .to_string()
            .contains("vpn.policy.default_mode = \"vpn\" requires router.enabled = true"));
    }

    #[test]
    fn vpn_policy_vpn_mode_accepts_valid_router_baseline() {
        let mut config = valid_router_config();
        config.vpn.enabled = true;
        config.vpn.policy.default_mode = VpnPolicyMode::Vpn;

        config
            .validate()
            .expect("vpn mode should validate on top of a valid router baseline");
    }

    #[test]
    fn valid_single_uplink_multi_output_router_passes_validation() {
        valid_router_config()
            .validate()
            .expect("single uplink and multiple outputs should be valid");
    }

    #[test]
    fn enabled_router_without_uplink_is_valid_but_unconfigured() {
        let mut config = valid_router_config();
        config.router.uplink = None;
        config
            .validate()
            .expect("an enabled router may await interactive provisioning");
    }

    #[test]
    fn enabled_router_rejects_uplink_with_wrong_interface_role() {
        let mut config = valid_router_config();
        config
            .network
            .interfaces
            .get_mut("wan0")
            .expect("uplink")
            .role = InterfaceRole::None;
        assert!(config
            .validate()
            .expect_err("outside-router interface cannot be uplink")
            .to_string()
            .contains("must have the input role"));
    }

    #[test]
    fn enabled_router_rejects_missing_outputs() {
        let mut config = valid_router_config();
        config
            .network
            .interfaces
            .retain(|_, interface| interface.role != InterfaceRole::Output);
        assert!(config
            .validate()
            .expect_err("output is required")
            .to_string()
            .contains("at least one managed output"));
    }

    #[test]
    fn owned_default_route_requires_explicit_permission() {
        let mut config = valid_router_config();
        config.router.owned_routes[0].destination = "0.0.0.0/0".parse().expect("default route");
        assert!(config
            .validate()
            .expect_err("default route needs permission")
            .to_string()
            .contains("allow_default_route_change"));

        config.router.allow_default_route_change = true;
        config
            .validate()
            .expect("explicitly permitted default route should be valid");
    }

    #[test]
    fn rejects_route_ownership_violations() {
        for role in [InterfaceRole::None, InterfaceRole::Disabled] {
            let mut config = valid_router_config();
            config.network.interfaces.insert(
                "foreign0".to_string(),
                InterfaceConfig {
                    nat: true,
                    role,
                    managed: false,
                    ipv4: None,
                    dhcp: None,
                    dhcp_client: None,
                    wifi: None,
                    wifi_client: None,
                },
            );
            config.router.owned_routes[0].output_interface = Some("foreign0".to_string());
            assert!(config
                .validate()
                .expect_err("protected role cannot own route")
                .to_string()
                .contains("cannot own a router route"));
        }

        let mut config = valid_router_config();
        config
            .network
            .interfaces
            .insert("other-wan".to_string(), input_interface());
        config.router.owned_routes[0].output_interface = Some("other-wan".to_string());
        assert!(config
            .validate()
            .expect_err("unselected input cannot own route")
            .to_string()
            .contains("not the selected uplink"));
    }

    #[test]
    fn legacy_config_uses_api_auth_and_runtime_defaults() {
        let mut legacy = toml::Value::try_from(AppConfig::default()).expect("serialize config");
        let root = legacy.as_table_mut().expect("root table");
        root.remove("api");
        root.remove("auth");
        root.remove("router");
        let runtime = root
            .get_mut("runtime")
            .and_then(toml::Value::as_table_mut)
            .expect("runtime table");
        runtime.remove("socket_group");
        runtime.remove("shutdown_policy");

        let config: AppConfig = legacy.try_into().expect("legacy config should parse");
        assert_eq!(config.api, ApiConfig::default());
        assert_eq!(config.auth, AuthConfig::default());
        assert_eq!(config.router, RouterConfig::default());
        assert_eq!(config.runtime.socket_group, None);
        assert_eq!(
            config.runtime.shutdown_policy,
            ShutdownPolicy::PreserveInterfaces
        );
    }

    #[test]
    fn tcp_api_is_disabled_by_default_and_requires_distinct_tls_paths() {
        let mut config = AppConfig::default();
        assert_eq!(config.api, ApiConfig::default());

        config.api.tcp = Some(TcpApiConfig::default());
        config
            .validate()
            .expect("disabled TCP listener should not require TLS paths");

        let tcp = config.api.tcp.as_mut().expect("TCP config");
        tcp.enabled = true;
        assert!(config.validate().is_err());

        let tcp = config.api.tcp.as_mut().expect("TCP config");
        tcp.certificate_path = Some(PathBuf::from("/etc/traffic-masq/server.pem"));
        tcp.private_key_path = Some(PathBuf::from("/etc/traffic-masq/server.pem"));
        assert!(config.validate().is_err());

        config
            .api
            .tcp
            .as_mut()
            .expect("TCP config")
            .private_key_path = Some(PathBuf::from("/etc/traffic-masq/server-key.pem"));
        config
            .validate()
            .expect("enabled TCP listener should accept distinct TLS paths");
    }

    #[test]
    fn tcp_api_uses_loopback_default_listen_address() {
        let tcp: TcpApiConfig = toml::from_str("enabled = false").expect("TCP config");
        assert_eq!(
            tcp.listen,
            "127.0.0.1:8443".parse().expect("socket address")
        );
    }

    #[test]
    fn auth_defaults_match_approved_limits() {
        let auth = AuthConfig::default();
        assert_eq!(
            auth.database_path,
            PathBuf::from("/var/lib/traffic-masq/auth.sqlite3")
        );
        assert_eq!(auth.session_idle_seconds, 1_800);
        assert_eq!(auth.session_absolute_seconds, 28_800);
        assert_eq!(auth.argon2_memory_kib, 32_768);
        assert_eq!(auth.argon2_iterations, 3);
        assert_eq!(auth.argon2_parallelism, 1);
        assert_eq!(auth.max_concurrent_logins, 2);
        auth.validate().expect("auth defaults should validate");
    }

    #[test]
    fn auth_rejects_zero_limits_and_idle_longer_than_absolute() {
        let invalid = [
            AuthConfig {
                session_idle_seconds: 0,
                ..AuthConfig::default()
            },
            AuthConfig {
                session_absolute_seconds: 0,
                ..AuthConfig::default()
            },
            AuthConfig {
                argon2_memory_kib: 0,
                ..AuthConfig::default()
            },
            AuthConfig {
                argon2_iterations: 0,
                ..AuthConfig::default()
            },
            AuthConfig {
                argon2_parallelism: 0,
                ..AuthConfig::default()
            },
            AuthConfig {
                max_concurrent_logins: 0,
                ..AuthConfig::default()
            },
            AuthConfig {
                session_idle_seconds: 28_801,
                ..AuthConfig::default()
            },
        ];

        for auth in invalid {
            assert!(auth.validate().is_err());
        }
    }

    #[test]
    fn runtime_rejects_empty_socket_group_and_path_conflicts() {
        let mut config = AppConfig::default();
        config.runtime.socket_group = Some("   ".to_string());
        assert!(config.validate().is_err());

        config.runtime.socket_group = None;
        config.runtime.socket_path = config.runtime.pid_path.clone();
        assert!(config.validate().is_err());

        config.runtime.socket_path = process_lock_path(&config.runtime.pid_path);
        assert!(config.validate().is_err());
    }

    #[test]
    fn valid_output_dhcp_config_passes_validation() {
        let mut config = AppConfig::default();
        config.network.interfaces.insert(
            "wlan0".to_string(),
            output_interface(
                "192.168.10.1/24",
                Ipv4Addr::new(192, 168, 10, 100),
                Ipv4Addr::new(192, 168, 10, 200),
            ),
        );

        config.validate().expect("config should be valid");
    }

    #[test]
    fn rejects_pool_outside_interface_network() {
        let mut config = AppConfig::default();
        config.network.interfaces.insert(
            "wlan0".to_string(),
            output_interface(
                "192.168.10.1/24",
                Ipv4Addr::new(192, 168, 11, 100),
                Ipv4Addr::new(192, 168, 11, 200),
            ),
        );

        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_interface_address_inside_pool() {
        let mut config = AppConfig::default();
        config.network.interfaces.insert(
            "wlan0".to_string(),
            output_interface(
                "192.168.10.100/24",
                Ipv4Addr::new(192, 168, 10, 100),
                Ipv4Addr::new(192, 168, 10, 200),
            ),
        );

        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_overlapping_managed_networks() {
        let mut config = AppConfig::default();
        config.network.interfaces.insert(
            "wlan0".to_string(),
            output_interface(
                "192.168.10.1/24",
                Ipv4Addr::new(192, 168, 10, 100),
                Ipv4Addr::new(192, 168, 10, 150),
            ),
        );
        config.network.interfaces.insert(
            "usb0".to_string(),
            output_interface(
                "192.168.10.2/25",
                Ipv4Addr::new(192, 168, 10, 10),
                Ipv4Addr::new(192, 168, 10, 20),
            ),
        );

        assert!(config.validate().is_err());
    }

    fn access_point() -> WifiApConfig {
        WifiApConfig {
            ssid: "traffic-masq".to_string(),
            country_code: Some("PL".to_string()),
            band: WifiBand::Ghz2,
            channel: 6,
            channel_width: WifiChannelWidth::Ht20,
            security: WifiSecurity::Wpa2,
            hidden: false,
            client_isolation: false,
            max_stations: 32,
            passphrase_file: None,
        }
    }

    fn wifi_interface(wifi: WifiApConfig) -> InterfaceConfig {
        let mut config = output_interface(
            "192.168.30.1/24",
            Ipv4Addr::new(192, 168, 30, 100),
            Ipv4Addr::new(192, 168, 30, 200),
        );
        config.wifi = Some(wifi);
        config
    }

    fn config_with_access_point(wifi: WifiApConfig) -> AppConfig {
        let mut config = AppConfig::default();
        config
            .network
            .interfaces
            .insert("wlan0".to_string(), wifi_interface(wifi));
        config
    }

    #[test]
    fn accepts_an_access_point_on_a_managed_output_interface() {
        config_with_access_point(access_point())
            .validate()
            .expect("valid access point");
    }

    #[test]
    fn rejects_an_access_point_on_an_unmanaged_or_non_output_interface() {
        let mut config = config_with_access_point(access_point());
        config
            .network
            .interfaces
            .get_mut("wlan0")
            .expect("interface")
            .managed = false;
        assert!(config.validate().is_err());

        let mut config = config_with_access_point(access_point());
        let interface = config
            .network
            .interfaces
            .get_mut("wlan0")
            .expect("interface");
        interface.role = InterfaceRole::None;
        interface.dhcp = None;
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_an_ssid_that_cannot_fit_or_cannot_be_advertised() {
        let mut empty = access_point();
        empty.ssid = String::new();
        assert!(config_with_access_point(empty).validate().is_err());

        let mut overlong = access_point();
        overlong.ssid = "a".repeat(MAX_SSID_BYTES + 1);
        assert!(config_with_access_point(overlong).validate().is_err());

        let mut multibyte = access_point();
        multibyte.ssid = "ы".repeat(17);
        assert!(config_with_access_point(multibyte).validate().is_err());

        let mut control = access_point();
        control.ssid = "traffic\nmasq".to_string();
        assert!(config_with_access_point(control).validate().is_err());
    }

    #[test]
    fn rejects_a_channel_that_does_not_belong_to_the_band() {
        let mut wrong_band = access_point();
        wrong_band.channel = 36;
        assert!(config_with_access_point(wrong_band).validate().is_err());

        let mut nonexistent = access_point();
        nonexistent.channel = 15;
        assert!(config_with_access_point(nonexistent).validate().is_err());

        let mut acs = access_point();
        acs.channel = 0;
        config_with_access_point(acs).validate().expect("acs");
    }

    #[test]
    fn requires_a_country_code_on_5_ghz_and_rejects_a_malformed_one() {
        let mut missing = access_point();
        missing.band = WifiBand::Ghz5;
        missing.channel = 36;
        missing.country_code = None;
        assert!(config_with_access_point(missing).validate().is_err());

        let mut lowercase = access_point();
        lowercase.country_code = Some("pl".to_string());
        assert!(config_with_access_point(lowercase).validate().is_err());

        let mut too_long = access_point();
        too_long.country_code = Some("POL".to_string());
        assert!(config_with_access_point(too_long).validate().is_err());

        let mut band_2g = access_point();
        band_2g.country_code = None;
        config_with_access_point(band_2g)
            .validate()
            .expect("2.4ghz");
    }

    #[test]
    fn rejects_vht80_outside_5_ghz() {
        let mut wide = access_point();
        wide.channel_width = WifiChannelWidth::Vht80;
        assert!(config_with_access_point(wide).validate().is_err());

        let mut wide_5g = access_point();
        wide_5g.channel_width = WifiChannelWidth::Vht80;
        wide_5g.band = WifiBand::Ghz5;
        wide_5g.channel = 36;
        config_with_access_point(wide_5g).validate().expect("5ghz");
    }

    #[test]
    fn rejects_an_unusable_station_limit() {
        let mut zero = access_point();
        zero.max_stations = 0;
        assert!(config_with_access_point(zero).validate().is_err());

        let mut too_many = access_point();
        too_many.max_stations = MAX_WIFI_STATIONS + 1;
        assert!(config_with_access_point(too_many).validate().is_err());
    }

    #[test]
    fn rejects_a_passphrase_file_that_is_relative_or_contradicts_open_security() {
        let mut relative = access_point();
        relative.passphrase_file = Some(PathBuf::from("secrets/wlan0.psk"));
        assert!(config_with_access_point(relative).validate().is_err());

        let mut open = access_point();
        open.security = WifiSecurity::Open;
        open.passphrase_file = Some(PathBuf::from("/etc/traffic-masq/wlan0.psk"));
        assert!(config_with_access_point(open).validate().is_err());

        let mut absolute = access_point();
        absolute.passphrase_file = Some(PathBuf::from("/etc/traffic-masq/wlan0.psk"));
        config_with_access_point(absolute)
            .validate()
            .expect("absolute passphrase file");
    }

    #[test]
    fn rejects_two_interfaces_advertising_one_ssid_on_one_band() {
        let mut config = config_with_access_point(access_point());
        let mut second = output_interface(
            "192.168.40.1/24",
            Ipv4Addr::new(192, 168, 40, 100),
            Ipv4Addr::new(192, 168, 40, 200),
        );
        second.wifi = Some(access_point());
        config
            .network
            .interfaces
            .insert("wlan1".to_string(), second);
        assert!(config.validate().is_err());

        let mut other_band = access_point();
        other_band.band = WifiBand::Ghz5;
        other_band.channel = 36;
        config
            .network
            .interfaces
            .get_mut("wlan1")
            .expect("interface")
            .wifi = Some(other_band);
        config.validate().expect("dual band");
    }

    #[test]
    fn rejects_a_global_wifi_section_that_cannot_work() {
        let mut relative_binary = AppConfig::default();
        relative_binary.wifi.hostapd_binary = PathBuf::from("hostapd");
        assert!(relative_binary.validate().is_err());

        let mut relative_runtime = AppConfig::default();
        relative_runtime.wifi.runtime_dir = PathBuf::from("hostapd");
        assert!(relative_runtime.validate().is_err());

        let mut no_backoff = AppConfig::default();
        no_backoff.wifi.restart_backoff_seconds = 0;
        assert!(no_backoff.validate().is_err());
    }

    #[test]
    fn a_config_without_a_wifi_section_still_loads_with_wifi_disabled() {
        let config: AppConfig = toml::from_str(
            r#"
            [runtime]
            state_dir = "/var/lib/traffic-masq"
            log_dir = "/var/log/traffic-masq"
            socket_path = "/run/traffic-masq/traffic-masqd.sock"
            pid_path = "/run/traffic-masq/traffic-masqd.pid"

            [network]

            [dhcp]
            leases_dir = "/var/lib/traffic-masq/dhcp/leases"
            default_lease_seconds = 86400

            [vpn]
            wireguard_config_dir = "/var/lib/traffic-masq/vpn/wireguard"

            [security]
            rollback_timeout_seconds = 60
            "#,
        )
        .expect("config without a [wifi] section parses");

        assert!(!config.wifi.enabled);
        config.validate().expect("valid");
    }

    fn client_association(ssid: &str) -> WifiClientConfig {
        WifiClientConfig {
            ssid: ssid.to_string(),
            country_code: Some("PL".to_string()),
            security: WifiClientSecurity::Wpa2,
            passphrase_file: None,
        }
    }

    fn client_interface(wifi_client: WifiClientConfig) -> InterfaceConfig {
        InterfaceConfig {
            nat: true,
            role: InterfaceRole::Input,
            managed: false,
            ipv4: None,
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: Some(wifi_client),
        }
    }

    fn config_with_wifi_client(wifi_client: WifiClientConfig) -> AppConfig {
        let mut config = AppConfig::default();
        config
            .network
            .interfaces
            .insert("wan_wifi".to_string(), client_interface(wifi_client));
        config
    }

    #[test]
    fn accepts_a_wifi_client_on_an_unmanaged_input_interface() {
        config_with_wifi_client(client_association("upstream"))
            .validate()
            .expect("valid wifi client");
    }

    #[test]
    fn rejects_a_wifi_client_on_a_managed_or_non_input_interface() {
        let mut config = config_with_wifi_client(client_association("upstream"));
        config
            .network
            .interfaces
            .get_mut("wan_wifi")
            .expect("interface")
            .managed = true;
        assert!(config.validate().is_err());

        let mut config = config_with_wifi_client(client_association("upstream"));
        config
            .network
            .interfaces
            .get_mut("wan_wifi")
            .expect("interface")
            .role = InterfaceRole::Output;
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_a_wifi_client_ssid_that_cannot_fit_or_cannot_be_advertised() {
        let mut empty = client_association("upstream");
        empty.ssid = String::new();
        assert!(config_with_wifi_client(empty).validate().is_err());

        let mut overlong = client_association("upstream");
        overlong.ssid = "a".repeat(MAX_SSID_BYTES + 1);
        assert!(config_with_wifi_client(overlong).validate().is_err());

        let mut control = client_association("upstream");
        control.ssid = "wan\nwifi".to_string();
        assert!(config_with_wifi_client(control).validate().is_err());
    }

    #[test]
    fn rejects_a_malformed_wifi_client_country_code() {
        let mut lowercase = client_association("upstream");
        lowercase.country_code = Some("pl".to_string());
        assert!(config_with_wifi_client(lowercase).validate().is_err());

        let mut too_long = client_association("upstream");
        too_long.country_code = Some("POL".to_string());
        assert!(config_with_wifi_client(too_long).validate().is_err());

        let mut none = client_association("upstream");
        none.country_code = None;
        config_with_wifi_client(none)
            .validate()
            .expect("no country code");
    }

    #[test]
    fn rejects_a_wifi_client_passphrase_file_that_is_relative_or_contradicts_open_security() {
        let mut relative = client_association("upstream");
        relative.passphrase_file = Some(PathBuf::from("secrets/wan.psk"));
        assert!(config_with_wifi_client(relative).validate().is_err());

        let mut open = client_association("upstream");
        open.security = WifiClientSecurity::Open;
        open.passphrase_file = Some(PathBuf::from("/etc/traffic-masq/wan.psk"));
        assert!(config_with_wifi_client(open).validate().is_err());

        let mut absolute = client_association("upstream");
        absolute.passphrase_file = Some(PathBuf::from("/etc/traffic-masq/wan.psk"));
        config_with_wifi_client(absolute)
            .validate()
            .expect("absolute passphrase file");
    }

    #[test]
    fn rejects_a_global_wifi_client_section_that_cannot_work() {
        let mut relative_binary = AppConfig::default();
        relative_binary.wifi_client.wpa_supplicant_binary = PathBuf::from("wpa_supplicant");
        assert!(relative_binary.validate().is_err());

        let mut relative_runtime = AppConfig::default();
        relative_runtime.wifi_client.runtime_dir = PathBuf::from("wpa_supplicant");
        assert!(relative_runtime.validate().is_err());

        let mut no_backoff = AppConfig::default();
        no_backoff.wifi_client.restart_backoff_seconds = 0;
        assert!(no_backoff.validate().is_err());
    }

    #[test]
    fn a_config_without_a_wifi_client_section_still_loads_with_it_disabled() {
        let config: AppConfig = toml::from_str(
            r#"
            [runtime]
            state_dir = "/var/lib/traffic-masq"
            log_dir = "/var/log/traffic-masq"
            socket_path = "/run/traffic-masq/traffic-masqd.sock"
            pid_path = "/run/traffic-masq/traffic-masqd.pid"

            [network]

            [dhcp]
            leases_dir = "/var/lib/traffic-masq/dhcp/leases"
            default_lease_seconds = 86400

            [vpn]
            wireguard_config_dir = "/var/lib/traffic-masq/vpn/wireguard"

            [security]
            rollback_timeout_seconds = 60
            "#,
        )
        .expect("config without a [wifi_client] section parses");

        assert!(!config.wifi_client.enabled);
        config.validate().expect("valid");
    }

    fn dhcp_client() -> DhcpClientInterfaceConfig {
        DhcpClientInterfaceConfig::default()
    }

    #[test]
    fn dhcp_client_defaults_and_legacy_absence_are_backward_compatible() {
        let interface: InterfaceConfig =
            toml::from_str("role = \"input\"").expect("legacy interface");
        assert!(interface.dhcp_client.is_none());

        let interface: InterfaceConfig =
            toml::from_str("role = \"input\"\nmanaged = true\n[dhcp_client]\n")
                .expect("DHCP client interface");
        assert_eq!(interface.dhcp_client, Some(dhcp_client()));
    }

    #[test]
    fn accepts_external_and_managed_dhcp_input_matrix() {
        let external_wifi = client_interface(client_association("upstream"));
        external_wifi.validate("wlan0").expect("legacy external L3");

        let mut managed_wifi = external_wifi;
        managed_wifi.managed = true;
        managed_wifi.dhcp_client = Some(dhcp_client());
        managed_wifi
            .validate("wlan0")
            .expect("managed Wi-Fi DHCP input");

        let mut managed_wired = input_interface();
        managed_wired.managed = true;
        managed_wired.dhcp_client = Some(dhcp_client());
        managed_wired
            .validate("wan0")
            .expect("managed wired DHCP input");

        let mut existing_static_owner = input_interface();
        existing_static_owner.managed = true;
        existing_static_owner.ipv4 = Some("192.0.2.2/24".parse().unwrap());
        existing_static_owner
            .validate("wan0")
            .expect("existing managed static input semantics remain valid");
    }

    #[test]
    fn rejects_invalid_dhcp_client_ownership_combinations() {
        for role in [
            InterfaceRole::Output,
            InterfaceRole::None,
            InterfaceRole::Disabled,
        ] {
            let mut interface = input_interface();
            interface.role = role;
            interface.dhcp_client = Some(DhcpClientInterfaceConfig {
                enabled: false,
                ..dhcp_client()
            });
            assert!(interface.validate("bad0").is_err(), "role {role:?}");
        }

        let mut unmanaged = input_interface();
        unmanaged.dhcp_client = Some(dhcp_client());
        let error = unmanaged.validate("wan0").expect_err("ownership conflict");
        assert!(error.to_string().contains("requires a managed input"));
    }

    #[test]
    fn router_uplink_modes_preserve_explicit_ownership() {
        let mut config = valid_router_config();
        let wan = config.network.interfaces.get_mut("wan0").unwrap();
        wan.managed = true;
        wan.dhcp_client = Some(dhcp_client());
        config.router.uplink.as_mut().unwrap().mode = UplinkMode::Dhcp;
        config.validate().expect("DHCP-owned uplink");

        config.router.uplink.as_mut().unwrap().mode = UplinkMode::External;
        assert!(config
            .validate()
            .expect_err("external may not claim ownership")
            .to_string()
            .contains("external router uplink must be unmanaged"));

        config.router.uplink.as_mut().unwrap().mode = UplinkMode::Dhcp;
        config
            .network
            .interfaces
            .get_mut("wan0")
            .unwrap()
            .dhcp_client = None;
        assert!(config
            .validate()
            .expect_err("DHCP mode requires DHCP client")
            .to_string()
            .contains("enabled dhcp_client block"));
    }

    #[test]
    fn an_ap_and_a_client_block_are_mutually_exclusive() {
        let mut config = client_interface(client_association("upstream"));
        config.role = InterfaceRole::Output;
        config.managed = true;
        config.wifi = Some(access_point());

        let error = config.validate("wlan0").expect_err("must be rejected");
        assert!(
            error.to_string().contains("cannot be both"),
            "expected the mutual-exclusion error specifically, got: {error}"
        );
    }

    /// A pre-`nat`-field `InterfaceConfig` (an upgrade from before this
    /// field existed) must deserialize with NAT still on for every output —
    /// today's behavior — not silently turn NAT off because the key is
    /// missing.
    #[test]
    fn interface_config_without_a_nat_key_defaults_nat_to_true() {
        let toml = r#"
            role = "output"
            managed = true
            ipv4 = "192.168.10.1/24"
        "#;
        let interface: InterfaceConfig = toml::from_str(toml).expect("pre-nat fixture parses");
        assert!(
            interface.nat,
            "a config predating InterfaceConfig.nat must still get NAT on upgrade"
        );
    }

    /// A pre-`vpn_chain`-field `RouterConfig` (an upgrade from before the
    /// hop chain existed) must deserialize with an empty chain, not fail to
    /// parse or silently synthesize one at the `RouterConfig` level (that is
    /// `migrate_vpn_policy_mode_to_chain`'s job, exercised separately).
    #[test]
    fn router_config_without_a_vpn_chain_key_defaults_to_an_empty_chain() {
        let toml = r#"
            enabled = true
            allow_default_route_change = false

            [uplink]
            interface = "wan0"
            mode = "external"
        "#;
        let router: RouterConfig = toml::from_str(toml).expect("pre-vpn_chain fixture parses");
        assert!(
            router.vpn_chain.is_empty(),
            "a config predating RouterConfig.vpn_chain must load with an empty chain"
        );
    }

    #[test]
    fn vpn_chain_longer_than_the_cap_is_rejected() {
        let mut config = valid_router_config();
        config.router.vpn_chain = (0..=MAX_VPN_CHAIN_LEN)
            .map(|i| VpnHopConfig {
                profile_name: format!("hop{i}.conf"),
            })
            .collect();

        let error = config.validate().expect_err("chain longer than the cap");
        assert!(error.to_string().contains("exceeds the maximum"));
    }
}
