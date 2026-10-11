use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::path::PathBuf;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::{
    AppConfig, DhcpClientInterfaceConfig, DhcpInterfaceConfig, ForwardingConfig, InterfaceConfig,
    InterfaceRole, RouterConfig, UplinkConfig, UplinkMode, WifiApConfig, WifiBand,
    WifiChannelWidth, WifiClientConfig, WifiClientSecurity, WifiSecurity,
};
use crate::core::router_candidate::RouterIntentProposal;

pub use traffic_masq_protocol::ProvisioningDownstreamOverrides;

pub const DEFAULT_DOWNSTREAM_PREFIX: u8 = 24;
pub const DEFAULT_DOWNSTREAM_THIRD_OCTET: u8 = 0;
pub const DEFAULT_DHCP_LEASE_SECONDS: u32 = 3600;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterProvisioningDesired {
    pub uplink: ProvisioningUplink,
    pub output: ProvisioningOutput,
    #[serde(default)]
    pub downstream: ProvisioningDownstreamOverrides,
    #[serde(default)]
    pub allow_management_change: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisioningUplink {
    pub interface: String,
    pub ssid: String,
    #[serde(default)]
    pub country_code: Option<String>,
    #[serde(default)]
    pub security: WifiClientSecurity,
    #[serde(default)]
    pub passphrase_file: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisioningOutput {
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
    #[serde(default = "default_max_stations")]
    pub max_stations: u16,
    #[serde(default)]
    pub passphrase_file: Option<PathBuf>,
}

fn default_max_stations() -> u16 {
    32
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisioningInterfaceObservation {
    pub role: Option<InterfaceRole>,
    pub wireless_phy: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisioningKnownNetwork {
    pub network: Ipv4Net,
    pub source: String,
}

#[derive(Debug, Clone)]
pub struct RouterProvisioningContext {
    pub effective_config: AppConfig,
    /// Whether an access-point runtime is available to carry out the intent.
    /// Replaces reading `wifi.enabled`, which is a startup hint rather than a
    /// statement about what the daemon can currently do.
    pub wifi_runtime_available: bool,
    /// Whether a station runtime is available. See `wifi_runtime_available`.
    pub wifi_client_runtime_available: bool,
    pub interfaces: BTreeMap<String, ProvisioningInterfaceObservation>,
    pub known_networks: Vec<ProvisioningKnownNetwork>,

    pub runtime_ap_secrets: BTreeSet<String>,
    pub runtime_sta_secrets: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterProvisioningEffective {
    pub router: RouterConfig,
    pub uplink_interface: InterfaceConfig,
    pub output_interface: InterfaceConfig,
    pub downstream_subnet: Ipv4Net,
    pub dns_servers: Vec<Ipv4Addr>,
    allow_management_change: bool,
    uplink_name: String,
    output_name: String,
}

impl RouterProvisioningEffective {
    pub fn into_router_intent_proposal(self) -> RouterIntentProposal {
        RouterIntentProposal::new()
            .set_interface(
                self.uplink_name,
                self.uplink_interface,
                self.allow_management_change,
            )
            .set_interface(
                self.output_name,
                self.output_interface,
                self.allow_management_change,
            )
            .set_router(self.router)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RouterProvisioningError {
    #[error("uplink and output must use different interfaces; both selected {interface}")]
    InterfaceReused { interface: String },
    #[error("selected interface does not exist: {interface}")]
    InterfaceNotFound { interface: String },
    #[error("uplink {uplink} and output {output} belong to the same wireless PHY {phy}")]
    RadioReused {
        phy: String,
        uplink: String,
        output: String,
    },
    #[error("changing outside-router interface {interface} requires explicit confirmation")]
    ManagementConfirmationRequired { interface: String },
    #[error("global service {service} must be enabled before router provisioning")]
    GlobalServiceDisabled { service: &'static str },
    #[error("WPA-protected uplink has no available passphrase for {interface}")]
    MissingUplinkSecret { interface: String },
    #[error("WPA-protected access point has no available passphrase for {interface}")]
    MissingOutputSecret { interface: String },
    #[error("downstream network {requested} overlaps {conflicting} from {conflict_source}")]
    SubnetConflict {
        requested: Ipv4Net,
        conflicting: Ipv4Net,
        conflict_source: String,
    },
    #[error("no conflict-free downstream /24 remains in 10.77.0.0/16")]
    NoAvailableDownstreamSubnet,
    #[error("pool_start and pool_end must either both be supplied or both be omitted")]
    PartialDhcpPool,
    #[error("explicit DHCP pool requires an explicit downstream interface_ipv4")]
    PoolWithoutExplicitNetwork,
    #[error("derived router configuration is invalid: {0}")]
    InvalidEffectiveConfig(String),
}

pub fn derive_router_provisioning(
    desired: &RouterProvisioningDesired,
    context: &RouterProvisioningContext,
) -> Result<RouterProvisioningEffective, RouterProvisioningError> {
    if desired.uplink.interface == desired.output.interface {
        return Err(RouterProvisioningError::InterfaceReused {
            interface: desired.uplink.interface.clone(),
        });
    }

    let uplink_observation = require_interface(&desired.uplink.interface, context)?;
    let output_observation = require_interface(&desired.output.interface, context)?;

    crate::wifi::policy::WifiRadioPolicy::validate_roles(
        [
            (
                desired.uplink.interface.as_str(),
                crate::wifi::policy::WifiRadioRole::Client,
            ),
            (
                desired.output.interface.as_str(),
                crate::wifi::policy::WifiRadioRole::Ap,
            ),
        ],
        |name| {
            context
                .interfaces
                .get(name)
                .and_then(|interface| interface.wireless_phy.clone())
        },
    )
    .map_err(radio_conflict)?;

    for (name, observation) in [
        (&desired.uplink.interface, uplink_observation),
        (&desired.output.interface, output_observation),
    ] {
        if observation.role == Some(InterfaceRole::None) && !desired.allow_management_change {
            return Err(RouterProvisioningError::ManagementConfirmationRequired {
                interface: name.clone(),
            });
        }
    }

    // Availability of the runtime, not the `enabled` flag in the file. The flag
    // is a startup hint; refusing to provision because of it made Wi-Fi a
    // boot-time decision, which is exactly what this check should not be.
    if !context.wifi_runtime_available {
        return Err(RouterProvisioningError::GlobalServiceDisabled { service: "wifi" });
    }
    if !context.wifi_client_runtime_available {
        return Err(RouterProvisioningError::GlobalServiceDisabled {
            service: "wifi_client",
        });
    }

    if desired.uplink.security.requires_passphrase()
        && desired.uplink.passphrase_file.is_none()
        && !context
            .runtime_sta_secrets
            .contains(&desired.uplink.interface)
    {
        return Err(RouterProvisioningError::MissingUplinkSecret {
            interface: desired.uplink.interface.clone(),
        });
    }
    if desired.output.security.requires_passphrase()
        && desired.output.passphrase_file.is_none()
        && !context
            .runtime_ap_secrets
            .contains(&desired.output.interface)
    {
        return Err(RouterProvisioningError::MissingOutputSecret {
            interface: desired.output.interface.clone(),
        });
    }

    let downstream_interface = select_downstream_interface(desired, context)?;
    let downstream_subnet = Ipv4Net::new(
        downstream_interface.network(),
        downstream_interface.prefix_len(),
    )
    .expect("an existing IPv4 network always has a valid prefix");

    let (pool_start, pool_end) = match (desired.downstream.pool_start, desired.downstream.pool_end)
    {
        (Some(start), Some(end)) => (start, end),
        (None, None) if desired.downstream.interface_ipv4.is_none() => {
            let octets = downstream_subnet.network().octets();
            (
                Ipv4Addr::new(octets[0], octets[1], octets[2], 100),
                Ipv4Addr::new(octets[0], octets[1], octets[2], 200),
            )
        }
        (None, None) => {
            let octets = downstream_subnet.network().octets();
            (
                Ipv4Addr::new(octets[0], octets[1], octets[2], 100),
                Ipv4Addr::new(octets[0], octets[1], octets[2], 200),
            )
        }
        _ => return Err(RouterProvisioningError::PartialDhcpPool),
    };

    if desired.downstream.interface_ipv4.is_none()
        && (desired.downstream.pool_start.is_some() || desired.downstream.pool_end.is_some())
    {
        return Err(RouterProvisioningError::PoolWithoutExplicitNetwork);
    }

    let uplink_interface = InterfaceConfig {
        mac_address: None,
        role: InterfaceRole::Input,
        managed: true,
        ipv4: None,
        dhcp: None,
        dhcp_client: Some(DhcpClientInterfaceConfig::default()),
        wifi: None,
        wifi_client: Some(WifiClientConfig {
            ssid: desired.uplink.ssid.clone(),
            country_code: desired.uplink.country_code.clone(),
            security: desired.uplink.security,
            passphrase_file: desired.uplink.passphrase_file.clone(),
        }),
        nat: true,
    };

    let output_interface = InterfaceConfig {
        mac_address: None,
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some(downstream_interface),
        dhcp: Some(DhcpInterfaceConfig {
            pool_start,
            pool_end,
            router: downstream_interface.addr(),
            dns_servers: desired.downstream.dns_servers.clone(),
            lease_seconds: Some(
                desired
                    .downstream
                    .lease_seconds
                    .unwrap_or(DEFAULT_DHCP_LEASE_SECONDS),
            ),
        }),
        dhcp_client: None,
        wifi: Some(WifiApConfig {
            ssid: desired.output.ssid.clone(),
            country_code: desired.output.country_code.clone(),
            band: desired.output.band,
            channel: desired.output.channel,
            channel_width: desired.output.channel_width,
            security: desired.output.security,
            hidden: desired.output.hidden,
            client_isolation: desired.output.client_isolation,
            max_stations: desired.output.max_stations,
            passphrase_file: desired.output.passphrase_file.clone(),
        }),
        wifi_client: None,
        nat: true,
    };

    let router = RouterConfig {
        uplink: Some(UplinkConfig {
            interface: desired.uplink.interface.clone(),
            mode: UplinkMode::Dhcp,
        }),
        owned_routes: Vec::new(),
        allow_default_route_change: true,
        forwarding: Some(vec![ForwardingConfig {
            source_subnet: None,
            from: desired.output.interface.clone(),
            to: desired.uplink.interface.clone(),
            masquerade: true,
        }]),
        vpn_chain: Vec::new(),
        route_host_traffic: false,
    };

    let mut effective_config = context.effective_config.clone();
    effective_config
        .network
        .interfaces
        .insert(desired.uplink.interface.clone(), uplink_interface.clone());
    effective_config
        .network
        .interfaces
        .insert(desired.output.interface.clone(), output_interface.clone());
    effective_config.router = router.clone();
    crate::wifi::policy::WifiRadioPolicy::validate(&effective_config.network, |name| {
        context
            .interfaces
            .get(name)
            .and_then(|interface| interface.wireless_phy.clone())
    })
    .map_err(radio_conflict)?;

    effective_config
        .validate()
        .map_err(|error| RouterProvisioningError::InvalidEffectiveConfig(error.to_string()))?;

    Ok(RouterProvisioningEffective {
        router,
        uplink_interface,
        output_interface,
        downstream_subnet,
        dns_servers: desired.downstream.dns_servers.clone(),
        allow_management_change: desired.allow_management_change,
        uplink_name: desired.uplink.interface.clone(),
        output_name: desired.output.interface.clone(),
    })
}

fn radio_conflict(error: crate::wifi::policy::WifiRadioConflict) -> RouterProvisioningError {
    RouterProvisioningError::RadioReused {
        phy: error.phy,
        uplink: error.client_interface,
        output: error.ap_interface,
    }
}

fn require_interface<'a>(
    interface: &str,
    context: &'a RouterProvisioningContext,
) -> Result<&'a ProvisioningInterfaceObservation, RouterProvisioningError> {
    context
        .interfaces
        .get(interface)
        .ok_or_else(|| RouterProvisioningError::InterfaceNotFound {
            interface: interface.to_owned(),
        })
}

fn select_downstream_interface(
    desired: &RouterProvisioningDesired,
    context: &RouterProvisioningContext,
) -> Result<Ipv4Net, RouterProvisioningError> {
    if let Some(interface) = desired.downstream.interface_ipv4 {
        let subnet = Ipv4Net::new(interface.network(), interface.prefix_len())
            .expect("an existing IPv4 network always has a valid prefix");
        reject_conflict(subnet, context)?;
        return Ok(interface);
    }

    for third_octet_offset in 0..=u8::MAX {
        let third_octet = DEFAULT_DOWNSTREAM_THIRD_OCTET.wrapping_add(third_octet_offset);
        let subnet = Ipv4Net::new(
            Ipv4Addr::new(10, 77, third_octet, 0),
            DEFAULT_DOWNSTREAM_PREFIX,
        )
        .expect("fixed /24 candidate is valid");
        if find_conflict(subnet, context).is_none() {
            return Ok(Ipv4Net::new(
                Ipv4Addr::new(10, 77, third_octet, 1),
                DEFAULT_DOWNSTREAM_PREFIX,
            )
            .expect("fixed /24 interface address is valid"));
        }
    }

    Err(RouterProvisioningError::NoAvailableDownstreamSubnet)
}

fn reject_conflict(
    requested: Ipv4Net,
    context: &RouterProvisioningContext,
) -> Result<(), RouterProvisioningError> {
    if let Some(conflict) = find_conflict(requested, context) {
        return Err(RouterProvisioningError::SubnetConflict {
            requested,
            conflicting: conflict.network,
            conflict_source: conflict.source.clone(),
        });
    }
    Ok(())
}

fn find_conflict(
    requested: Ipv4Net,
    context: &RouterProvisioningContext,
) -> Option<&ProvisioningKnownNetwork> {
    context
        .known_networks
        .iter()
        .find(|known| networks_overlap(requested, known.network))
}

fn networks_overlap(left: Ipv4Net, right: Ipv4Net) -> bool {
    left.contains(&right.network()) || right.contains(&left.network())
}

#[cfg(test)]
mod tests;
