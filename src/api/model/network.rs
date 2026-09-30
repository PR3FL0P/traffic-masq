//! Observed interface conversion at the API boundary.

use super::InterfaceStatus;
use crate::netlink::{Ipv4AddressInfo, NetworkInterface};
use traffic_masq_protocol::{InterfaceStatusView, Ipv4AddressInfoView, NetworkInterfaceView};

fn network_interface_to_view(value: NetworkInterface) -> NetworkInterfaceView {
    NetworkInterfaceView {
        index: value.index,
        name: value.name,
        is_up: value.is_up,
        rx_bytes: value.rx_bytes,
        tx_bytes: value.tx_bytes,
        is_wireless: value.is_wireless,
    }
}

fn network_interface_from_view(value: NetworkInterfaceView) -> NetworkInterface {
    NetworkInterface {
        index: value.index,
        name: value.name,
        is_up: value.is_up,
        rx_bytes: value.rx_bytes,
        tx_bytes: value.tx_bytes,
        is_wireless: value.is_wireless,
    }
}

pub(super) fn address_to_view(value: Ipv4AddressInfo) -> Ipv4AddressInfoView {
    Ipv4AddressInfoView {
        interface_index: value.interface_index,
        address: value.address,
        prefix_len: value.prefix_len,
        protocol: value.protocol,
    }
}

pub(super) fn address_from_view(value: Ipv4AddressInfoView) -> Ipv4AddressInfo {
    Ipv4AddressInfo {
        interface_index: value.interface_index,
        address: value.address,
        prefix_len: value.prefix_len,
        protocol: value.protocol,
    }
}

impl From<InterfaceStatus> for InterfaceStatusView {
    fn from(value: InterfaceStatus) -> Self {
        Self {
            owned_ipv4_addresses: value
                .owned_ipv4_addresses
                .map(|items| items.into_iter().map(address_to_view).collect()),
            interface: network_interface_to_view(value.interface),
            ipv4_addresses: value
                .ipv4_addresses
                .into_iter()
                .map(address_to_view)
                .collect(),
            has_default_route: value.has_default_route,
        }
    }
}

impl From<InterfaceStatusView> for InterfaceStatus {
    fn from(value: InterfaceStatusView) -> Self {
        Self {
            owned_ipv4_addresses: value
                .owned_ipv4_addresses
                .map(|items| items.into_iter().map(address_from_view).collect()),
            interface: network_interface_from_view(value.interface),
            ipv4_addresses: value
                .ipv4_addresses
                .into_iter()
                .map(address_from_view)
                .collect(),
            has_default_route: value.has_default_route,
        }
    }
}
