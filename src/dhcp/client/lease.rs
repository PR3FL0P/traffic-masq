use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use crate::netlink::TRAFFIC_MASQ_DHCP_ROUTE_PROTOCOL;

pub const DHCP_CLIENT_LEASE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DhcpClientLeaseState {
    PendingApply,
    Bound,
    Suspended,
    CleanupNeeded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpClientOwnedRoute {
    pub destination: Ipv4Net,
    pub gateway: Option<Ipv4Addr>,
    pub output_interface_index: Option<u32>,
    pub table: u32,
    pub metric: Option<u32>,
    pub protocol: u8,
    pub scope: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpClientLeasePolicy {
    pub route_metric: u32,
    pub install_default_route: bool,
    pub request_dns: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpClientLease {
    pub schema_version: u32,
    pub state: DhcpClientLeaseState,
    pub interface: String,
    pub interface_index: u32,
    pub hardware_address: Vec<u8>,
    pub client_identifier: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<DhcpClientLeasePolicy>,
    pub server_identifier: Ipv4Addr,
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub routers: Vec<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub lease_seconds: u32,
    pub renewal_seconds: u32,
    pub rebinding_seconds: u32,
    pub expires_at_unix: u64,
    pub owned_routes: Vec<DhcpClientOwnedRoute>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LeaseValidationError {
    #[error("unsupported DHCP lease schema version {0}")]
    UnsupportedSchema(u32),
    #[error("invalid interface name")]
    InvalidInterface,
    #[error("interface index must be nonzero")]
    InvalidInterfaceIndex,
    #[error("hardware address must not be empty")]
    MissingHardwareAddress,
    #[error("client identifier must not be empty")]
    MissingClientIdentifier,
    #[error("invalid IPv4 address or prefix")]
    InvalidAddress,
    #[error("lease timers must satisfy 0 < T1 < T2 < lease")]
    InvalidTimers,
    #[error("expiry timestamp must be nonzero")]
    InvalidExpiry,
    #[error("owned route {0} is invalid")]
    InvalidRoute(usize),
}

impl DhcpClientLease {
    /// Validate the current schema, interface/index and identifiers, IPv4/prefix,
    /// nonzero expiry, 0 < T1 < T2 < lease and recorded DHCP route protocol/table/
    /// nexthop shape. This is structural validation, not proof that the current
    /// device, addresses or routes still belong to this lease; recovery must observe them.
    pub fn validate(&self) -> Result<(), LeaseValidationError> {
        if self.schema_version != DHCP_CLIENT_LEASE_SCHEMA_VERSION {
            return Err(LeaseValidationError::UnsupportedSchema(self.schema_version));
        }
        if !valid_interface_name(&self.interface) {
            return Err(LeaseValidationError::InvalidInterface);
        }
        if self.interface_index == 0 {
            return Err(LeaseValidationError::InvalidInterfaceIndex);
        }
        if self.hardware_address.is_empty() {
            return Err(LeaseValidationError::MissingHardwareAddress);
        }
        if self.client_identifier.is_empty() {
            return Err(LeaseValidationError::MissingClientIdentifier);
        }
        if self.prefix_len > 32 || self.address.is_unspecified() || self.address.is_broadcast() {
            return Err(LeaseValidationError::InvalidAddress);
        }
        if self.renewal_seconds == 0
            || self.renewal_seconds >= self.rebinding_seconds
            || self.rebinding_seconds >= self.lease_seconds
        {
            return Err(LeaseValidationError::InvalidTimers);
        }
        if self.expires_at_unix == 0 {
            return Err(LeaseValidationError::InvalidExpiry);
        }
        for (index, route) in self.owned_routes.iter().enumerate() {
            if route.protocol != TRAFFIC_MASQ_DHCP_ROUTE_PROTOCOL
                || route.table == 0
                || (route.gateway.is_none() && route.output_interface_index.is_none())
            {
                return Err(LeaseValidationError::InvalidRoute(index));
            }
        }
        Ok(())
    }
}

/// The same rule the private store applies to document names, because a lease
/// is stored under its interface name and the two must not be able to drift.
pub(crate) fn valid_interface_name(name: &str) -> bool {
    crate::state::private_store::valid_document_key(name)
}
