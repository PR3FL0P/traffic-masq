//! Linux netlink adapter for interfaces, addresses, routes, and rules.
//!
//! This module isolates the system netlink API from the core and provides
//! state inspection, safe IPv4 object installation, and drift events.

pub mod events;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use futures_util::TryStreamExt;
use netlink_packet_route::{
    address::{AddressAttribute, AddressMessage},
    link::{LinkAttribute, LinkFlag},
    route::{RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteScope, RouteType},
    rule::{RuleAction, RuleAttribute, RuleMessage},
    AddressFamily,
};
use netlink_packet_utils::nla::{DefaultNla, Nla};
use rtnetlink::{new_connection, Handle, IpVersion};
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub index: u32,
    pub name: String,
    pub is_up: bool,

    #[serde(default)]
    pub rx_bytes: u64,

    #[serde(default)]
    pub tx_bytes: u64,

    #[serde(default)]
    pub is_wireless: bool,
}

#[cfg(target_os = "linux")]
pub fn interface_is_wireless(interface: &str) -> bool {
    std::path::Path::new("/sys/class/net")
        .join(interface)
        .join("phy80211")
        .exists()
}

#[cfg(not(target_os = "linux"))]
pub fn interface_is_wireless(_interface: &str) -> bool {
    false
}

#[cfg(target_os = "linux")]
pub fn wireless_phy(interface: &str) -> Option<String> {
    let attachment = std::path::Path::new("/sys/class/net")
        .join(interface)
        .join("phy80211");
    let target = std::fs::read_link(attachment).ok()?;
    Some(target.file_name()?.to_string_lossy().into_owned())
}

#[cfg(not(target_os = "linux"))]
pub fn wireless_phy(_interface: &str) -> Option<String> {
    None
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv4AddressInfo {
    pub interface_index: u32,
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    #[serde(default)]
    pub protocol: Option<u8>,
}

impl Ipv4AddressInfo {
    pub fn owner(&self) -> AddressOwner {
        AddressOwner::from_protocol(self.protocol)
    }
}

pub const TRAFFIC_MASQ_ADDRESS_PROTOCOL: u8 = 201;
pub const TRAFFIC_MASQ_DHCP_ADDRESS_PROTOCOL: u8 = 202;
const IFA_PROTO: u16 = 11;
const IFA_FLAGS: u16 = 8;
const IFA_F_NOPREFIXROUTE: u32 = 0x200;

pub const TRAFFIC_MASQ_ROUTE_PROTOCOL: u8 = 201;

pub const TRAFFIC_MASQ_DHCP_ROUTE_PROTOCOL: u8 = 202;

/// The ownership traffic-masq claims for an address it is about to install.
///
/// Every write path has to name one, so an address can never be created
/// without a deliberate decision about who owns it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressOwnership {
    /// A statically configured traffic-masq address.
    Static,
    /// An address held by the traffic-masq DHCP client on behalf of a lease.
    DhcpClient,
    /// An address traffic-masq installs but does not claim, e.g. when
    /// restoring state that belonged to something else.
    Untagged,
}

impl AddressOwnership {
    pub fn protocol(self) -> Option<u8> {
        match self {
            Self::Static => Some(TRAFFIC_MASQ_ADDRESS_PROTOCOL),
            Self::DhcpClient => Some(TRAFFIC_MASQ_DHCP_ADDRESS_PROTOCOL),
            Self::Untagged => None,
        }
    }
}

/// What the kernel reports about an address that already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressOwner {
    TrafficMasqStatic,
    TrafficMasqDhcp,
    /// No `IFA_PROTO` at all: either predates ownership tagging or belongs to
    /// a daemon that does not tag. Indistinguishable, deliberately.
    Untagged,
    /// Tagged by something that is not us.
    Foreign(u8),
}

impl AddressOwner {
    pub fn from_protocol(protocol: Option<u8>) -> Self {
        match protocol {
            None | Some(0) => Self::Untagged,
            Some(TRAFFIC_MASQ_ADDRESS_PROTOCOL) => Self::TrafficMasqStatic,
            Some(TRAFFIC_MASQ_DHCP_ADDRESS_PROTOCOL) => Self::TrafficMasqDhcp,
            Some(other) => Self::Foreign(other),
        }
    }

    /// The ownership to restore this address with. A foreign tag is never
    /// replayed: userspace claiming e.g. `IFAPROT_KERNEL_RA` would lie to
    /// every other daemon that filters on it.
    pub fn restore_as(self) -> AddressOwnership {
        match self {
            Self::TrafficMasqStatic => AddressOwnership::Static,
            Self::TrafficMasqDhcp => AddressOwnership::DhcpClient,
            Self::Untagged | Self::Foreign(_) => AddressOwnership::Untagged,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv4RouteSpec {
    pub destination: ipnet::Ipv4Net,
    pub gateway: Option<Ipv4Addr>,
    pub output_interface_index: Option<u32>,
    pub table: u32,
    pub metric: Option<u32>,
    pub protocol: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteOwner {
    TrafficMasqStatic, // proto 201 (TRAFFIC_MASQ_ROUTE_PROTOCOL)
    TrafficMasqDhcp,   // proto 202 (TRAFFIC_MASQ_DHCP_ROUTE_PROTOCOL)
    Kernel,            // proto 2 (RTPROT_KERNEL)
    Boot,              // proto 3 (RTPROT_BOOT)
    Static,            // proto 4 (RTPROT_STATIC)
    Dhcp,              // proto 16 (RTPROT_DHCP)
    Foreign(u8),       // other rt_proto
    Untagged,          // RTPROT_UNSPEC (0)
}

impl RouteOwner {
    pub fn from_protocol(protocol: u8) -> Self {
        match protocol {
            0 => Self::Untagged,
            2 => Self::Kernel,
            3 => Self::Boot,
            4 => Self::Static,
            16 => Self::Dhcp,
            TRAFFIC_MASQ_ROUTE_PROTOCOL => Self::TrafficMasqStatic,
            TRAFFIC_MASQ_DHCP_ROUTE_PROTOCOL => Self::TrafficMasqDhcp,
            other => Self::Foreign(other),
        }
    }

    pub fn is_owned(self) -> bool {
        matches!(self, Self::TrafficMasqStatic | Self::TrafficMasqDhcp)
    }

    pub fn is_editable(self) -> bool {
        matches!(self, Self::TrafficMasqStatic)
    }
}

impl std::fmt::Display for RouteOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TrafficMasqStatic => write!(f, "traffic-masq"),
            Self::TrafficMasqDhcp => write!(f, "traffic-masq (dhcp)"),
            Self::Kernel => write!(f, "[ext:kernel]"),
            Self::Boot => write!(f, "[ext:boot]"),
            Self::Static => write!(f, "[ext:static]"),
            Self::Dhcp => write!(f, "[ext:dhcp]"),
            Self::Foreign(proto) => write!(f, "[ext:proto {proto}]"),
            Self::Untagged => write!(f, "[?]"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv4RouteInfo {
    pub destination: ipnet::Ipv4Net,
    pub gateway: Option<Ipv4Addr>,
    pub output_interface_index: Option<u32>,
    pub table: u32,
    pub metric: Option<u32>,
    pub protocol: u8,
    pub scope: u8,
}

impl Ipv4RouteInfo {
    pub fn owner(&self) -> RouteOwner {
        RouteOwner::from_protocol(self.protocol)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv4RuleSpec {
    pub source: Option<ipnet::Ipv4Net>,
    pub destination: Option<ipnet::Ipv4Net>,
    pub table: u32,
    pub priority: Option<u32>,
    pub fw_mark: Option<u32>,
    pub fw_mask: Option<u32>,
    pub input_interface: Option<String>,
    pub output_interface: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv4RuleInfo {
    pub source: Option<ipnet::Ipv4Net>,
    pub destination: Option<ipnet::Ipv4Net>,
    pub table: u32,
    pub priority: Option<u32>,
    pub fw_mark: Option<u32>,
    pub fw_mask: Option<u32>,
    pub input_interface: Option<String>,
    pub output_interface: Option<String>,
}

impl Ipv4RouteSpec {
    pub fn validate(&self) -> Result<()> {
        if self.table == 0 {
            anyhow::bail!("IPv4 route table must not be RT_TABLE_UNSPEC (0)");
        }
        if self.table == 255 {
            anyhow::bail!("IPv4 route table must not be RT_TABLE_LOCAL (255)");
        }
        if self.destination.addr() != self.destination.network() {
            anyhow::bail!(
                "IPv4 route destination prefix {} has host bits set",
                self.destination
            );
        }
        if self.gateway.is_none() && self.output_interface_index.is_none() {
            anyhow::bail!("IPv4 route requires a gateway or output interface");
        }
        if let Some(gateway) = self.gateway {
            if gateway.is_unspecified() || gateway.is_broadcast() || gateway.is_multicast() {
                anyhow::bail!(
                    "IPv4 route gateway must not be unspecified, multicast, or broadcast: {gateway}"
                );
            }
        }
        if self.protocol == 0 {
            anyhow::bail!("IPv4 route protocol must not be RTPROT_UNSPEC (0)");
        }
        Ok(())
    }
}

impl Ipv4RuleSpec {
    pub fn validate(&self) -> Result<()> {
        if self.table == 0 {
            anyhow::bail!("IPv4 rule table must not be RT_TABLE_UNSPEC (0)");
        }
        if self.fw_mask.is_some() && self.fw_mark.is_none() {
            anyhow::bail!("IPv4 rule fw_mask requires fw_mark");
        }
        let has_selector = self.source.is_some()
            || self.destination.is_some()
            || self.fw_mark.is_some()
            || self.input_interface.is_some()
            || self.output_interface.is_some();
        if !has_selector {
            anyhow::bail!(
                "IPv4 rule must define at least one selector (source, destination, fw_mark, input_interface or output_interface)"
            );
        }
        if self
            .input_interface
            .as_deref()
            .is_some_and(|name| name.trim().is_empty())
        {
            anyhow::bail!("IPv4 rule input interface must not be empty");
        }
        if self
            .output_interface
            .as_deref()
            .is_some_and(|name| name.trim().is_empty())
        {
            anyhow::bail!("IPv4 rule output interface must not be empty");
        }
        Ok(())
    }
}

#[async_trait]
pub trait NetworkProvider: Send + Sync {
    /// Physical radio identity used by common Wi-Fi admission.
    fn wireless_phy(&self, interface: &str) -> Option<String> {
        wireless_phy(interface)
    }

    /// Whether address ownership tags can be trusted on this provider.
    ///
    /// Implementations must report observed truth, not intent: a provider that
    /// has seen the kernel drop `IFA_PROTO` is expected to start returning
    /// `false` so the planner and the ownership guards agree with reality.
    fn supports_ipv4_address_protocol(&self) -> bool {
        false
    }

    async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>>;

    async fn hardware_address(&self, _interface: &str) -> Result<Vec<u8>> {
        anyhow::bail!("hardware-address observation is not supported by this network provider")
    }

    async fn list_ipv4_addresses(&self, interface: &str) -> Result<Vec<Ipv4AddressInfo>>;
    async fn set_link_up(&self, name: &str) -> Result<()>;
    async fn set_link_down(&self, name: &str) -> Result<()>;
    /// Install an address. There is deliberately no default implementation and
    /// no untagged variant of this method: a provider that cannot honour
    /// `ownership` must say so by failing, never by silently dropping the tag.
    async fn add_ipv4_address(
        &self,
        interface: &str,
        address: Ipv4Addr,
        prefix_len: u8,
        ownership: AddressOwnership,
    ) -> Result<()>;

    /// Re-tag an address that already exists, without taking it off the link.
    async fn set_ipv4_address_ownership(
        &self,
        _interface: &str,
        _address: Ipv4Addr,
        _prefix_len: u8,
        _ownership: AddressOwnership,
    ) -> Result<()> {
        anyhow::bail!("IPv4 address ownership tagging is not supported by this network provider")
    }

    async fn delete_ipv4_address(
        &self,
        interface: &str,
        address: Ipv4Addr,
        prefix_len: u8,
    ) -> Result<()>;

    async fn list_ipv4_routes(&self) -> Result<Vec<Ipv4RouteInfo>> {
        anyhow::bail!("IPv4 route observation is not supported by this network provider")
    }

    async fn list_ipv4_routes_in_table(&self, table: u32) -> Result<Vec<Ipv4RouteInfo>> {
        let mut routes = self.list_ipv4_routes().await?;
        routes.retain(|route| route.table == table);
        routes.sort_by_key(|route| {
            (
                route.table,
                u32::from(route.destination.network()),
                route.destination.prefix_len(),
                route.gateway,
                route.output_interface_index,
                route.metric,
                route.protocol,
                route.scope,
            )
        });
        Ok(routes)
    }

    async fn add_ipv4_route(&self, _route: &Ipv4RouteSpec) -> Result<()> {
        anyhow::bail!("IPv4 route creation is not supported by this network provider")
    }

    async fn delete_ipv4_route(&self, _route: &Ipv4RouteInfo) -> Result<()> {
        anyhow::bail!("IPv4 route deletion is not supported by this network provider")
    }

    async fn list_ipv4_rules(&self) -> Result<Vec<Ipv4RuleInfo>> {
        anyhow::bail!("IPv4 rule observation is not supported by this network provider")
    }

    async fn add_ipv4_rule(&self, _rule: &Ipv4RuleSpec) -> Result<()> {
        anyhow::bail!("IPv4 rule creation is not supported by this network provider")
    }

    async fn delete_ipv4_rule(&self, _rule: &Ipv4RuleInfo) -> Result<()> {
        anyhow::bail!("IPv4 rule deletion is not supported by this network provider")
    }
}

#[async_trait]
impl<T> NetworkProvider for Arc<T>
where
    T: NetworkProvider + ?Sized,
{
    fn wireless_phy(&self, interface: &str) -> Option<String> {
        (**self).wireless_phy(interface)
    }

    fn supports_ipv4_address_protocol(&self) -> bool {
        (**self).supports_ipv4_address_protocol()
    }

    async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        (**self).list_interfaces().await
    }

    async fn hardware_address(&self, interface: &str) -> Result<Vec<u8>> {
        (**self).hardware_address(interface).await
    }

    async fn list_ipv4_addresses(&self, interface: &str) -> Result<Vec<Ipv4AddressInfo>> {
        (**self).list_ipv4_addresses(interface).await
    }

    async fn set_link_up(&self, name: &str) -> Result<()> {
        (**self).set_link_up(name).await
    }

    async fn set_link_down(&self, name: &str) -> Result<()> {
        (**self).set_link_down(name).await
    }

    async fn add_ipv4_address(
        &self,
        interface: &str,
        address: Ipv4Addr,
        prefix_len: u8,
        ownership: AddressOwnership,
    ) -> Result<()> {
        (**self)
            .add_ipv4_address(interface, address, prefix_len, ownership)
            .await
    }

    async fn set_ipv4_address_ownership(
        &self,
        interface: &str,
        address: Ipv4Addr,
        prefix_len: u8,
        ownership: AddressOwnership,
    ) -> Result<()> {
        (**self)
            .set_ipv4_address_ownership(interface, address, prefix_len, ownership)
            .await
    }

    async fn delete_ipv4_address(
        &self,
        interface: &str,
        address: Ipv4Addr,
        prefix_len: u8,
    ) -> Result<()> {
        (**self)
            .delete_ipv4_address(interface, address, prefix_len)
            .await
    }

    async fn list_ipv4_routes(&self) -> Result<Vec<Ipv4RouteInfo>> {
        (**self).list_ipv4_routes().await
    }

    async fn list_ipv4_routes_in_table(&self, table: u32) -> Result<Vec<Ipv4RouteInfo>> {
        (**self).list_ipv4_routes_in_table(table).await
    }

    async fn add_ipv4_route(&self, route: &Ipv4RouteSpec) -> Result<()> {
        (**self).add_ipv4_route(route).await
    }

    async fn delete_ipv4_route(&self, route: &Ipv4RouteInfo) -> Result<()> {
        (**self).delete_ipv4_route(route).await
    }

    async fn list_ipv4_rules(&self) -> Result<Vec<Ipv4RuleInfo>> {
        (**self).list_ipv4_rules().await
    }

    async fn add_ipv4_rule(&self, rule: &Ipv4RuleSpec) -> Result<()> {
        (**self).add_ipv4_rule(rule).await
    }

    async fn delete_ipv4_rule(&self, rule: &Ipv4RuleInfo) -> Result<()> {
        (**self).delete_ipv4_rule(rule).await
    }
}

/// `IFA_PROTO` support has not been observed yet; assume it works and let the
/// first tagged write settle the question.
const ADDRESS_PROTOCOL_UNKNOWN: u8 = 0;
const ADDRESS_PROTOCOL_SUPPORTED: u8 = 1;
const ADDRESS_PROTOCOL_UNSUPPORTED: u8 = 2;

#[derive(Debug)]
pub struct RtnetlinkNetworkProvider {
    handle: Handle,
    _connection_task: JoinHandle<()>,
    /// Observed `IFA_PROTO` support, resolved by reading back the first
    /// address we tag. `IFA_PROTO` needs Linux 5.18; older kernels parse
    /// `RTM_NEWADDR` liberally and ignore the attribute without an error, so
    /// asking the kernel is the only way to know.
    address_protocol_support: AtomicU8,
}

impl RtnetlinkNetworkProvider {
    pub fn connect() -> Result<Self> {
        let (connection, handle, _) = new_connection()?;
        let connection_task = tokio::spawn(connection);
        Ok(Self {
            handle,
            _connection_task: connection_task,
            address_protocol_support: AtomicU8::new(ADDRESS_PROTOCOL_UNKNOWN),
        })
    }

    /// Confirm that a tag we just wrote actually landed, once per process.
    ///
    /// A dropped tag does not fail the operation: the address itself is on the
    /// link and healthy, only ownership tracking is degraded. Recording that
    /// keeps `supports_ipv4_address_protocol` honest, which is what the
    /// unmanage guard relies on.
    async fn confirm_address_protocol(
        &self,
        interface: &str,
        address: Ipv4Addr,
        prefix_len: u8,
        expected: u8,
    ) -> Result<()> {
        if self.address_protocol_support.load(Ordering::Relaxed) != ADDRESS_PROTOCOL_UNKNOWN {
            return Ok(());
        }

        let observed = self
            .list_ipv4_addresses(interface)
            .await?
            .into_iter()
            .find(|item| item.address == address && item.prefix_len == prefix_len)
            .and_then(|item| item.protocol);

        if observed == Some(expected) {
            self.address_protocol_support
                .store(ADDRESS_PROTOCOL_SUPPORTED, Ordering::Relaxed);
        } else {
            self.address_protocol_support
                .store(ADDRESS_PROTOCOL_UNSUPPORTED, Ordering::Relaxed);
            tracing::warn!(
                interface = %interface,
                address = %address,
                prefix_len,
                expected,
                ?observed,
                "kernel did not store the IPv4 address ownership tag (IFA_PROTO needs Linux 5.18); \
                 traffic-masq cannot verify address ownership and will refuse to stop managing \
                 interfaces it cannot prove it configured"
            );
        }
        Ok(())
    }

    /// Build the `IFA_PROTO` attribute, or nothing for an untagged address.
    fn ownership_attribute(ownership: AddressOwnership) -> Option<AddressAttribute> {
        ownership
            .protocol()
            .map(|protocol| AddressAttribute::Other(DefaultNla::new(IFA_PROTO, vec![protocol])))
    }

    async fn link_index(&self, name: &str) -> Result<u32> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute();
        let link = links
            .try_next()
            .await?
            .ok_or_else(|| anyhow::anyhow!("interface not found: {name}"))?;
        Ok(link.header.index)
    }

    async fn address_message(
        &self,
        interface: &str,
        address: Ipv4Addr,
        prefix_len: u8,
    ) -> Result<AddressMessage> {
        let index = self.link_index(interface).await?;
        let mut addresses = self
            .handle
            .address()
            .get()
            .set_link_index_filter(index)
            .set_address_filter(IpAddr::V4(address))
            .set_prefix_length_filter(prefix_len)
            .execute();

        addresses.try_next().await?.ok_or_else(|| {
            anyhow::anyhow!("address {address}/{prefix_len} not found on {interface}")
        })
    }
}

fn ipv4_net_sort_key(network: Option<ipnet::Ipv4Net>) -> Option<(u32, u8)> {
    network.map(|network| (u32::from(network.network()), network.prefix_len()))
}

fn parse_ipv4_route(message: &RouteMessage) -> Result<Option<Ipv4RouteInfo>> {
    if message.header.kind != RouteType::Unicast {
        return Ok(None);
    }

    let mut destination = Ipv4Addr::UNSPECIFIED;
    let mut gateway = None;
    let mut output_interface_index = None;
    let mut table = u32::from(message.header.table);
    let mut metric = None;
    let mut unsupported = false;

    for attribute in &message.attributes {
        match attribute {
            RouteAttribute::Destination(RouteAddress::Inet(address)) => destination = *address,
            RouteAttribute::Gateway(RouteAddress::Inet(address)) => gateway = Some(*address),
            RouteAttribute::Oif(index) => output_interface_index = Some(*index),
            RouteAttribute::Table(value) => table = *value,
            RouteAttribute::Priority(value) => metric = Some(*value),
            RouteAttribute::Source(_) | RouteAttribute::MultiPath(_) | RouteAttribute::Via(_) => {
                unsupported = true
            }
            _ => {}
        }
    }
    if unsupported {
        return Ok(None);
    }

    let destination = ipnet::Ipv4Net::new(destination, message.header.destination_prefix_length)?;
    Ok(Some(Ipv4RouteInfo {
        destination,
        gateway,
        output_interface_index,
        table,
        metric,
        protocol: u8::from(message.header.protocol),
        scope: u8::from(message.header.scope),
    }))
}

fn parse_ipv4_rule(message: &RuleMessage) -> Result<Option<Ipv4RuleInfo>> {
    if message.header.family != AddressFamily::Inet {
        return Ok(None);
    }
    match message.header.action {
        RuleAction::ToTable | RuleAction::Unspec => {}
        _ => return Ok(None),
    }

    let mut source = None;
    let mut destination = None;
    let mut table = u32::from(message.header.table);
    let mut priority = None;
    let mut fw_mark = None;
    let mut fw_mask = None;
    let mut input_interface = None;
    let mut output_interface = None;
    let mut unsupported = false;

    for attribute in &message.attributes {
        match attribute {
            RuleAttribute::Source(IpAddr::V4(address)) => {
                source = Some(ipnet::Ipv4Net::new(*address, message.header.src_len)?);
            }
            RuleAttribute::Destination(IpAddr::V4(address)) => {
                destination = Some(ipnet::Ipv4Net::new(*address, message.header.dst_len)?);
            }
            RuleAttribute::Priority(value) => priority = Some(*value),
            RuleAttribute::FwMark(value) => fw_mark = Some(*value),
            RuleAttribute::FwMask(value) => fw_mask = Some(*value),
            RuleAttribute::Table(value) => table = *value,
            RuleAttribute::Iifname(name) => input_interface = Some(name.clone()),
            RuleAttribute::Oifname(name) => output_interface = Some(name.clone()),

            RuleAttribute::Protocol(_) => {}
            RuleAttribute::SuppressPrefixLen(u32::MAX) => {}

            RuleAttribute::SuppressPrefixLen(_)
            | RuleAttribute::Source(IpAddr::V6(_))
            | RuleAttribute::Destination(IpAddr::V6(_))
            | RuleAttribute::Goto(_)
            | RuleAttribute::Realm(_)
            | RuleAttribute::TunId(_)
            | RuleAttribute::SuppressIfGroup(_)
            | RuleAttribute::L3MDev(_)
            | RuleAttribute::UidRange(_)
            | RuleAttribute::IpProtocol(_)
            | RuleAttribute::SourcePortRange(_)
            | RuleAttribute::DestinationPortRange(_)
            | RuleAttribute::Other(_)
            | _ => unsupported = true,
        }
    }

    if unsupported {
        return Ok(None);
    }
    if message.header.src_len > 0 && source.is_none() {
        return Ok(None);
    }
    if message.header.dst_len > 0 && destination.is_none() {
        return Ok(None);
    }

    let info = Ipv4RuleInfo {
        source,
        destination,
        table,
        priority,
        fw_mark,
        fw_mask,
        input_interface,
        output_interface,
    };
    if info.fw_mask.is_some() && info.fw_mark.is_none() {
        return Ok(None);
    }
    Ok(Some(info))
}

#[async_trait]
impl NetworkProvider for RtnetlinkNetworkProvider {
    fn supports_ipv4_address_protocol(&self) -> bool {
        // Optimistic until proven otherwise: the first tagged write reads the
        // address back and flips this to `false` if the kernel dropped the tag.
        self.address_protocol_support.load(Ordering::Relaxed) != ADDRESS_PROTOCOL_UNSUPPORTED
    }

    async fn hardware_address(&self, interface: &str) -> Result<Vec<u8>> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(interface.to_string())
            .execute();
        let link = links
            .try_next()
            .await?
            .ok_or_else(|| anyhow::anyhow!("interface not found: {interface}"))?;
        link.attributes
            .into_iter()
            .find_map(|attribute| match attribute {
                LinkAttribute::Address(address) => Some(address),
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("interface has no hardware address: {interface}"))
    }

    async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        let mut links = self.handle.link().get().execute();
        let mut interfaces = Vec::new();

        while let Some(link) = links.try_next().await? {
            let mut name = None;
            let mut rx_bytes = 0u64;
            let mut tx_bytes = 0u64;
            for attr in link.attributes {
                match attr {
                    LinkAttribute::IfName(if_name) => name = Some(if_name),
                    LinkAttribute::Stats64(stats) => {
                        rx_bytes = stats.rx_bytes;
                        tx_bytes = stats.tx_bytes;
                    }

                    LinkAttribute::Stats(stats) if rx_bytes == 0 && tx_bytes == 0 => {
                        rx_bytes = u64::from(stats.rx_bytes);
                        tx_bytes = u64::from(stats.tx_bytes);
                    }
                    LinkAttribute::Stats(_) => {}
                    _ => {}
                }
            }

            if let Some(name) = name {
                interfaces.push(NetworkInterface {
                    index: link.header.index,
                    is_up: link.header.flags.contains(&LinkFlag::Up),
                    is_wireless: interface_is_wireless(&name),
                    name,
                    rx_bytes,
                    tx_bytes,
                });
            }
        }

        Ok(interfaces)
    }

    async fn list_ipv4_addresses(&self, interface: &str) -> Result<Vec<Ipv4AddressInfo>> {
        let index = self.link_index(interface).await?;
        let mut addresses = self
            .handle
            .address()
            .get()
            .set_link_index_filter(index)
            .execute();

        let mut result = Vec::new();

        while let Some(message) = addresses.try_next().await? {
            let mut ipv4 = None;
            let mut protocol = None;
            for attr in &message.attributes {
                match attr {
                    AddressAttribute::Local(IpAddr::V4(address))
                    | AddressAttribute::Address(IpAddr::V4(address)) => {
                        ipv4.get_or_insert(*address);
                    }
                    AddressAttribute::Other(other)
                        if other.kind() == IFA_PROTO && other.value_len() == 1 =>
                    {
                        let mut value = [0u8; 1];
                        other.emit_value(&mut value);
                        protocol = Some(value[0]);
                    }
                    _ => {}
                }
            }

            if let Some(address) = ipv4 {
                result.push(Ipv4AddressInfo {
                    interface_index: message.header.index,
                    address,
                    prefix_len: message.header.prefix_len,
                    protocol,
                });
            }
        }

        Ok(result)
    }

    async fn set_link_up(&self, name: &str) -> Result<()> {
        let index = self.link_index(name).await?;
        self.handle.link().set(index).up().execute().await?;
        Ok(())
    }

    async fn set_link_down(&self, name: &str) -> Result<()> {
        let index = self.link_index(name).await?;
        self.handle.link().set(index).down().execute().await?;
        Ok(())
    }

    async fn add_ipv4_address(
        &self,
        interface: &str,
        address: Ipv4Addr,
        prefix_len: u8,
        ownership: AddressOwnership,
    ) -> Result<()> {
        let index = self.link_index(interface).await?;
        let mut request = self
            .handle
            .address()
            .add(index, IpAddr::V4(address), prefix_len);
        if ownership == AddressOwnership::DhcpClient {
            request
                .message_mut()
                .attributes
                .push(AddressAttribute::Other(DefaultNla::new(
                    IFA_FLAGS,
                    IFA_F_NOPREFIXROUTE.to_ne_bytes().to_vec(),
                )));
        }
        if let Some(attribute) = Self::ownership_attribute(ownership) {
            request.message_mut().attributes.push(attribute);
        }
        request.execute().await?;

        if let Some(protocol) = ownership.protocol() {
            self.confirm_address_protocol(interface, address, prefix_len, protocol)
                .await?;
        }
        Ok(())
    }

    async fn set_ipv4_address_ownership(
        &self,
        interface: &str,
        address: Ipv4Addr,
        prefix_len: u8,
        ownership: AddressOwnership,
    ) -> Result<()> {
        let existing = self.address_message(interface, address, prefix_len).await?;
        let mut request = self
            .handle
            .address()
            .add(existing.header.index, IpAddr::V4(address), prefix_len)
            .replace();

        {
            let message = request.message_mut();
            // Keep the flags and scope the address already carries; dropping
            // e.g. IFA_F_NOPREFIXROUTE while re-tagging would change routing.
            message.header = existing.header.clone();
            // IFA_CACHEINFO is deliberately not replayed: resending stale
            // lifetimes would age the address. Everything else the request
            // needs (Address/Local/Broadcast) is already built by `add`.
            message
                .attributes
                .extend(
                    existing
                        .attributes
                        .iter()
                        .filter_map(|attribute| match attribute {
                            AddressAttribute::Label(_) | AddressAttribute::Flags(_) => {
                                Some(attribute.clone())
                            }
                            _ => None,
                        }),
                );
            if let Some(attribute) = Self::ownership_attribute(ownership) {
                message.attributes.push(attribute);
            }
        }

        request.execute().await?;

        if let Some(protocol) = ownership.protocol() {
            self.confirm_address_protocol(interface, address, prefix_len, protocol)
                .await?;
        }
        Ok(())
    }

    async fn delete_ipv4_address(
        &self,
        interface: &str,
        address: Ipv4Addr,
        prefix_len: u8,
    ) -> Result<()> {
        let message = self.address_message(interface, address, prefix_len).await?;
        self.handle.address().del(message).execute().await?;
        Ok(())
    }

    async fn list_ipv4_routes(&self) -> Result<Vec<Ipv4RouteInfo>> {
        let mut messages = self.handle.route().get(IpVersion::V4).execute();
        let mut routes = Vec::new();
        while let Some(message) = messages.try_next().await? {
            if let Some(route) = parse_ipv4_route(&message)? {
                routes.push(route);
            }
        }
        routes.sort_by_key(|route| {
            (
                route.table,
                u32::from(route.destination.network()),
                route.destination.prefix_len(),
                route.gateway,
                route.output_interface_index,
                route.metric,
                route.protocol,
                route.scope,
            )
        });
        Ok(routes)
    }

    async fn add_ipv4_route(&self, route: &Ipv4RouteSpec) -> Result<()> {
        route.validate()?;
        let mut request = self
            .handle
            .route()
            .add()
            .v4()
            .destination_prefix(route.destination.network(), route.destination.prefix_len())
            .table_id(route.table)
            .protocol(RouteProtocol::Other(route.protocol));
        if let Some(gateway) = route.gateway {
            request = request.gateway(gateway);
        } else {
            request = request.scope(RouteScope::Link);
        }
        if let Some(index) = route.output_interface_index {
            request = request.output_interface(index);
        }
        if let Some(metric) = route.metric {
            request = request.priority(metric);
        }
        request.execute().await?;
        Ok(())
    }

    async fn delete_ipv4_route(&self, route: &Ipv4RouteInfo) -> Result<()> {
        let mut messages = self.handle.route().get(IpVersion::V4).execute();
        while let Some(message) = messages.try_next().await? {
            if parse_ipv4_route(&message)?.as_ref() == Some(route) {
                self.handle.route().del(message).execute().await?;
                return Ok(());
            }
        }
        anyhow::bail!(
            "IPv4 route {}/{} in table {} was not found",
            route.destination.network(),
            route.destination.prefix_len(),
            route.table
        )
    }

    async fn list_ipv4_rules(&self) -> Result<Vec<Ipv4RuleInfo>> {
        let mut messages = self.handle.rule().get(IpVersion::V4).execute();
        let mut rules = Vec::new();
        while let Some(message) = messages.try_next().await? {
            if let Some(rule) = parse_ipv4_rule(&message)? {
                rules.push(rule);
            }
        }
        rules.sort_by_key(|rule| {
            (
                rule.priority,
                rule.table,
                rule.fw_mark,
                rule.fw_mask,
                ipv4_net_sort_key(rule.source),
                ipv4_net_sort_key(rule.destination),
                rule.input_interface.clone(),
                rule.output_interface.clone(),
            )
        });
        Ok(rules)
    }

    async fn add_ipv4_rule(&self, rule: &Ipv4RuleSpec) -> Result<()> {
        rule.validate()?;
        let mut request = self
            .handle
            .rule()
            .add()
            .v4()
            .action(RuleAction::ToTable)
            .table_id(rule.table);
        if let Some(source) = rule.source {
            request = request.source_prefix(source.network(), source.prefix_len());
        }
        if let Some(destination) = rule.destination {
            request = request.destination_prefix(destination.network(), destination.prefix_len());
        }
        if let Some(priority) = rule.priority {
            request = request.priority(priority);
        }
        if let Some(fw_mark) = rule.fw_mark {
            request = request.fw_mark(fw_mark);
        }
        if let Some(input_interface) = &rule.input_interface {
            request = request.input_interface(input_interface.clone());
        }
        if let Some(output_interface) = &rule.output_interface {
            request = request.output_interface(output_interface.clone());
        }
        if let Some(fw_mask) = rule.fw_mask {
            request
                .message_mut()
                .attributes
                .push(RuleAttribute::FwMask(fw_mask));
        }
        request.execute().await?;
        Ok(())
    }

    async fn delete_ipv4_rule(&self, rule: &Ipv4RuleInfo) -> Result<()> {
        let mut messages = self.handle.rule().get(IpVersion::V4).execute();
        while let Some(message) = messages.try_next().await? {
            if parse_ipv4_rule(&message)?.as_ref() == Some(rule) {
                self.handle.rule().del(message).execute().await?;
                return Ok(());
            }
        }
        anyhow::bail!("IPv4 rule for table {} was not found", rule.table)
    }
}

#[cfg(test)]
mod tests;
