//! Route status returned by the control API.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteOwnerView {
    TrafficMasqStatic,
    TrafficMasqDhcp,
    Kernel,
    Boot,
    Static,
    Dhcp,
    Foreign(u8),
    Untagged,
}

impl RouteOwnerView {
    pub fn from_protocol(protocol: u8) -> Self {
        match protocol {
            0 => Self::Untagged,
            2 => Self::Kernel,
            3 => Self::Boot,
            4 => Self::Static,
            16 => Self::Dhcp,
            201 => Self::TrafficMasqStatic,
            202 => Self::TrafficMasqDhcp,
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

impl std::fmt::Display for RouteOwnerView {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TrafficMasqStatic => write!(formatter, "traffic-masq"),
            Self::TrafficMasqDhcp => write!(formatter, "traffic-masq (dhcp)"),
            Self::Kernel => write!(formatter, "[ext:kernel]"),
            Self::Boot => write!(formatter, "[ext:boot]"),
            Self::Static => write!(formatter, "[ext:static]"),
            Self::Dhcp => write!(formatter, "[ext:dhcp]"),
            Self::Foreign(protocol) => write!(formatter, "[ext:proto {protocol}]"),
            Self::Untagged => write!(formatter, "[?]"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteStatusView {
    pub destination: Ipv4Net,
    pub gateway: Option<Ipv4Addr>,
    pub output_interface: Option<String>,
    pub output_interface_index: Option<u32>,
    pub table: u32,
    pub metric: Option<u32>,
    pub protocol: u8,
    pub scope: u8,
    pub owner: RouteOwnerView,
}
