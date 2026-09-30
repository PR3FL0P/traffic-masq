//! Observed interface data returned by the control API.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInterfaceView {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv4AddressInfoView {
    pub interface_index: u32,
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    #[serde(default)]
    pub protocol: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressOwnerView {
    TrafficMasqStatic,
    TrafficMasqDhcp,
    Untagged,
    Foreign(u8),
}

impl AddressOwnerView {
    pub fn from_protocol(protocol: Option<u8>) -> Self {
        match protocol {
            None | Some(0) => Self::Untagged,
            Some(201) => Self::TrafficMasqStatic,
            Some(202) => Self::TrafficMasqDhcp,
            Some(other) => Self::Foreign(other),
        }
    }
}

impl Ipv4AddressInfoView {
    pub fn owner(&self) -> AddressOwnerView {
        AddressOwnerView::from_protocol(self.protocol)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceStatusView {
    #[serde(default)]
    pub owned_ipv4_addresses: Option<Vec<Ipv4AddressInfoView>>,
    pub interface: NetworkInterfaceView,
    pub ipv4_addresses: Vec<Ipv4AddressInfoView>,
    #[serde(default)]
    pub has_default_route: bool,
}
