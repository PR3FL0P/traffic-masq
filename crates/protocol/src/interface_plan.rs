//! Proposed interface changes returned by the control API.

use serde::{Deserialize, Serialize};

use crate::Ipv4AddressInfoView;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DhcpChangeActionView {
    Unchanged,
    Start,
    Reconfigure,
    Stop,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceChangePlanView {
    pub interface: String,
    pub delete_ipv4: Vec<Ipv4AddressInfoView>,
    #[serde(default)]
    pub retag_ipv4: Option<Ipv4AddressInfoView>,
    pub add_ipv4: Option<Ipv4AddressInfoView>,
    pub set_link_up: bool,
    pub management_change: bool,
    pub dhcp_action: DhcpChangeActionView,
    #[serde(default)]
    pub releasing_management: bool,
}
