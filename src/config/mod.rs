//! Loading, validation, and resolution of application configuration.
//!
//! Configuration describes runtime directories, network interfaces, DHCP,
//! Wi-Fi, VPN, firewall, API, and security settings. Configuration comes from
//! one TOML file or built-in defaults. The command line and `TRAFFIC_MASQ_CONFIG`
//! environment variable select the file; [`ResolvedConfig`] records the source
//! of the configuration as a whole.

use std::collections::BTreeMap;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

pub use traffic_masq_dataplane::ForwardingConfig;
pub use traffic_masq_protocol::{
    InterfaceRole, UplinkMode, VpnPolicyMode, WifiBand, WifiChannelWidth, WifiClientSecurity,
    WifiSecurity,
};
pub use traffic_masq_protocol::{PortForwardConfig, PortForwardProtocol};

mod resolver;
pub use resolver::{ConfigSource, ResolvedConfig, CONFIG_ENV, DEFAULT_CONFIG_PATH};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    pub tcp: Option<TcpApiConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    #[serde(default)]
    pub interfaces: BTreeMap<String, InterfaceConfig>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<traffic_masq_protocol::MacAddr>,
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
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct RouterConfig {
    pub uplink: Option<UplinkConfig>,
    /// Explicit ingress → egress permissions; omission disables forwarding.
    pub forwarding: Option<Vec<ForwardingConfig>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_forwards: Vec<PortForwardConfig>,
    pub owned_routes: Vec<OwnedIpv4RouteConfig>,
    pub allow_default_route_change: bool,
    /// Persisted, user-facing VPN hop chain: profile name per hop, ordered
    /// (index 0 = closest to the physical uplink). The derived `interface`/
    /// `reserved` fields of a hop are recomputed at runtime, not persisted.
    #[serde(default)]
    pub vpn_chain: Vec<VpnHopConfig>,
    /// Also send the router's own locally generated traffic through the VPN
    /// chain, with a kill switch and an IPv6 egress block. Requires `vpn_chain`.
    #[serde(default)]
    pub route_host_traffic: bool,
}

/// Validate interface names, distinct ingress/egress, network CIDRs without host
/// bits, and overlapping source subnets for rules with the same interface pair.
pub fn validate_forwarding(rules: &[ForwardingConfig]) -> Result<()> {
    traffic_masq_protocol::validate_forwarding(rules).map_err(anyhow::Error::msg)
}

/// The maximum number of hops a persisted VPN chain may contain, matching
/// [`crate::core::vpn_policy::MAX_VPN_HOP_INDEX`]'s bound on reserved-ID
/// allocation so the priority-band math can never overflow into an
/// unrelated reserved range.
pub const MAX_VPN_CHAIN_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VpnHopConfig {
    pub profile_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UplinkConfig {
    pub interface: String,
    pub mode: UplinkMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedIpv4RouteConfig {
    pub destination: Ipv4Net,
    pub gateway: Option<Ipv4Addr>,
    pub output_interface: Option<String>,
    pub table: u32,
    pub metric: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct DhcpClientInterfaceConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
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
            hostname: None,
            route_metric: 100,
            install_default_route: true,
            request_dns: true,
            send_release_on_shutdown: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DhcpInterfaceConfig {
    pub pool_start: Ipv4Addr,
    pub pool_end: Ipv4Addr,
    pub router: Ipv4Addr,
    #[serde(default)]
    pub dns_servers: Vec<Ipv4Addr>,
    pub lease_seconds: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DhcpConfig {
    pub leases_dir: PathBuf,
    pub default_lease_seconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct VpnConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standalone: Option<StandaloneVpnIntent>,
    #[serde(default)]
    pub enabled: bool,
    pub wireguard_config_dir: PathBuf,
    #[serde(default = "default_wireguard_import_dir")]
    pub wireguard_import_dir: PathBuf,

    #[serde(default)]
    pub policy: VpnTrafficPolicyConfig,
}

/// Confirmed standalone tunnel selection; `profile: None` explicitly means disconnected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandaloneVpnIntent {
    pub profile: Option<String>,
}

fn default_wireguard_import_dir() -> PathBuf {
    PathBuf::from("/etc/wireguard")
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VpnProtectedSubnets {
    #[default]
    AllManagedOutputSubnets,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct VpnTrafficPolicyConfig {
    pub default_mode: VpnPolicyMode,

    pub protected_subnets: VpnProtectedSubnets,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

    /// Validate all configuration sections, positive timers and runtime socket/lock conflicts.
    /// Structural checks do not establish tool availability, PHY capability or connectivity.
    pub fn validate(&self) -> Result<()> {
        self.network.validate()?;
        self.router.validate(&self.network)?;
        if (self.router.forwarding.is_some() || !self.router.port_forwards.is_empty())
            && self.vpn.policy.default_mode == VpnPolicyMode::Vpn
        {
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
    /// Require distinct certificate/key paths when HTTPS is enabled; does not read certificates.
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
    /// Reject overlapping import/managed profile directories and invalid VPN policy.
    fn validate(&self, router: &RouterConfig) -> Result<()> {
        let same_directory = resolve_directory_path(&self.wireguard_import_dir)?
            == resolve_directory_path(&self.wireguard_config_dir)?;
        if same_directory {
            bail!("vpn.wireguard_import_dir must differ from vpn.wireguard_config_dir");
        }
        self.policy.validate(self.enabled, router)
    }
}

/// Resolve existing symlinks and normalize paths even before their final
/// directories are created. Normalizing `..` after resolving each component
/// preserves its filesystem meaning when an ancestor is a symlink.
fn resolve_directory_path(path: &std::path::Path) -> Result<PathBuf> {
    use std::path::Component;

    let absolute = std::path::absolute(path)?;
    let mut resolved = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => continue,
            Component::ParentDir => {
                resolved.pop();
            }
            _ => resolved.push(component.as_os_str()),
        }
        // Configuration can be inspected without access to the daemon's
        // private directories. Resolve readable ancestors, but do not make
        // validation depend on permissions to inspect the complete path.
        if let Ok(canonical) = resolved.canonicalize() {
            resolved = canonical;
        }
    }
    Ok(resolved)
}

impl VpnTrafficPolicyConfig {
    /// Require enabled VPN and configured router intent for global VPN mode.
    fn validate(&self, vpn_enabled: bool, router: &RouterConfig) -> Result<()> {
        if self.default_mode == VpnPolicyMode::Vpn && !vpn_enabled {
            bail!("vpn.policy.default_mode = \"vpn\" requires vpn.enabled = true");
        }
        if self.default_mode == VpnPolicyMode::Vpn && !router.is_active() {
            bail!("vpn.policy.default_mode = \"vpn\" requires router intent");
        }
        Ok(())
    }
}

impl AuthConfig {
    /// Validate positive session and Argon2/concurrency limits and idle <= absolute expiry.
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
    /// Validate each named interface and reject overlapping managed IPv4 networks.
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
    /// Router intent is active when there is something to apply; no global enable switch.
    pub fn is_active(&self) -> bool {
        self.uplink.is_some()
            || self
                .forwarding
                .as_ref()
                .is_some_and(|rules| !rules.is_empty())
            || !self.port_forwards.is_empty()
            || !self.owned_routes.is_empty()
            || !self.vpn_chain.is_empty()
    }

    /// Validate forwarding/uplink roles, output addressing, route consent/conflicts and VPN chain length.
    fn validate(&self, network: &NetworkConfig) -> Result<()> {
        traffic_masq_protocol::validate_port_forwards(&self.port_forwards)
            .map_err(anyhow::Error::msg)?;
        if !self.port_forwards.is_empty() && !self.vpn_chain.is_empty() {
            bail!("port forwarding cannot be combined with a global vpn_chain; configure tunnel routing separately");
        }
        for rule in &self.port_forwards {
            if network
                .interfaces
                .values()
                .filter_map(|interface| interface.ipv4)
                .any(|ip| ip.addr() == rule.target_address)
            {
                bail!("port forwarding target must be a remote host, not a router address");
            }
            if network
                .interfaces
                .get(&rule.to)
                .and_then(|interface| interface.ipv4)
                .is_some_and(|net| {
                    net.prefix_len() < 31
                        && (rule.target_address == net.network()
                            || rule.target_address == net.broadcast())
                })
            {
                bail!("port forwarding target must not be a subnet network or broadcast address");
            }
        }
        if let Some(rules) = &self.forwarding {
            validate_forwarding(rules)?;
        }
        if self.is_active() {
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
            }
        }
        if !self.vpn_chain.is_empty() && self.uplink.is_none() {
            bail!("router.uplink is required when router.vpn_chain is configured");
        }

        if self.route_host_traffic && self.vpn_chain.is_empty() {
            bail!("router.route_host_traffic requires a configured vpn_chain");
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
                .validate()
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
    /// Validate the route table, network prefix, gateway and output interface name.
    fn validate(&self) -> Result<()> {
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
        Ok(())
    }
}

impl InterfaceConfig {
    /// Validate role/management, IPv4 and role-specific DHCP/AP/STA compatibility; no device probing.
    pub fn validate(&self, name: &str) -> Result<()> {
        if let Some(mac) = self.mac_address {
            anyhow::ensure!(self.managed, "MAC address requires a managed interface");
            anyhow::ensure!(
                self.role != InterfaceRole::Middle,
                "MAC address cannot be configured on a WireGuard interface"
            );
            anyhow::ensure!(
                mac.octets() != [0; 6] && mac.octets()[0] & 1 == 0,
                "MAC address must be a nonzero unicast address"
            );
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

        if let Some(hostname) = self
            .dhcp_client
            .as_ref()
            .and_then(|client| client.hostname.as_deref())
        {
            traffic_masq_protocol::validate_dhcp_hostname(hostname).map_err(anyhow::Error::msg)?;
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
    /// Validate DHCP pool order/subnet, router identity/exclusion, DNS count and positive lease time.
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
    /// Validate absolute AP tool/runtime paths, positive backoff and duplicate SSID/band assignments; no tool probing.
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
    /// Validate AP SSID, country, band/channel/width, station limits and secret-file policy; no PHY probing.
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
    /// Validate absolute supplicant/runtime paths and positive backoff; does not check executables exist.
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
    /// Validate STA SSID/country and secret-file/security policy; does not inspect the radio or connect.
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
    traffic_masq_protocol::validate_interface_name(name).map_err(anyhow::Error::msg)
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
                standalone: None,
                enabled: false,
                wireguard_config_dir: PathBuf::from("/var/lib/traffic-masq/vpn/wireguard"),
                wireguard_import_dir: "/etc/wireguard".into(),
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
