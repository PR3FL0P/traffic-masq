//! Interface plan conversion at the API boundary.

use super::network::{address_from_view, address_to_view};
use crate::core::interface::{DhcpChangeAction, InterfaceChangePlan};
use traffic_masq_protocol::{DhcpChangeActionView, InterfaceChangePlanView};

impl From<DhcpChangeAction> for DhcpChangeActionView {
    fn from(value: DhcpChangeAction) -> Self {
        match value {
            DhcpChangeAction::Unchanged => Self::Unchanged,
            DhcpChangeAction::Start => Self::Start,
            DhcpChangeAction::Reconfigure => Self::Reconfigure,
            DhcpChangeAction::Stop => Self::Stop,
        }
    }
}

impl From<DhcpChangeActionView> for DhcpChangeAction {
    fn from(value: DhcpChangeActionView) -> Self {
        match value {
            DhcpChangeActionView::Unchanged => Self::Unchanged,
            DhcpChangeActionView::Start => Self::Start,
            DhcpChangeActionView::Reconfigure => Self::Reconfigure,
            DhcpChangeActionView::Stop => Self::Stop,
        }
    }
}

impl From<InterfaceChangePlan> for InterfaceChangePlanView {
    fn from(value: InterfaceChangePlan) -> Self {
        Self {
            interface: value.interface,
            delete_ipv4: value.delete_ipv4.into_iter().map(address_to_view).collect(),
            retag_ipv4: value.retag_ipv4.map(address_to_view),
            add_ipv4: value.add_ipv4.map(address_to_view),
            set_link_up: value.set_link_up,
            management_change: value.management_change,
            dhcp_action: value.dhcp_action.into(),
            releasing_management: value.releasing_management,
        }
    }
}

impl From<InterfaceChangePlanView> for InterfaceChangePlan {
    fn from(value: InterfaceChangePlanView) -> Self {
        Self {
            interface: value.interface,
            delete_ipv4: value
                .delete_ipv4
                .into_iter()
                .map(address_from_view)
                .collect(),
            retag_ipv4: value.retag_ipv4.map(address_from_view),
            add_ipv4: value.add_ipv4.map(address_from_view),
            set_link_up: value.set_link_up,
            management_change: value.management_change,
            dhcp_action: value.dhcp_action.into(),
            releasing_management: value.releasing_management,
        }
    }
}
