//! Route status conversion at the API boundary.

use super::RouteStatus;
use crate::netlink::RouteOwner;
use traffic_masq_protocol::{RouteOwnerView, RouteStatusView};

pub(super) fn route_owner_to_view(value: RouteOwner) -> RouteOwnerView {
    match value {
        RouteOwner::TrafficMasqStatic => RouteOwnerView::TrafficMasqStatic,
        RouteOwner::TrafficMasqDhcp => RouteOwnerView::TrafficMasqDhcp,
        RouteOwner::Kernel => RouteOwnerView::Kernel,
        RouteOwner::Boot => RouteOwnerView::Boot,
        RouteOwner::Static => RouteOwnerView::Static,
        RouteOwner::Dhcp => RouteOwnerView::Dhcp,
        RouteOwner::Foreign(protocol) => RouteOwnerView::Foreign(protocol),
        RouteOwner::Untagged => RouteOwnerView::Untagged,
    }
}

pub(super) fn route_owner_from_view(value: RouteOwnerView) -> RouteOwner {
    match value {
        RouteOwnerView::TrafficMasqStatic => RouteOwner::TrafficMasqStatic,
        RouteOwnerView::TrafficMasqDhcp => RouteOwner::TrafficMasqDhcp,
        RouteOwnerView::Kernel => RouteOwner::Kernel,
        RouteOwnerView::Boot => RouteOwner::Boot,
        RouteOwnerView::Static => RouteOwner::Static,
        RouteOwnerView::Dhcp => RouteOwner::Dhcp,
        RouteOwnerView::Foreign(protocol) => RouteOwner::Foreign(protocol),
        RouteOwnerView::Untagged => RouteOwner::Untagged,
    }
}

impl From<RouteStatus> for RouteStatusView {
    fn from(value: RouteStatus) -> Self {
        Self {
            destination: value.destination,
            gateway: value.gateway,
            output_interface: value.output_interface,
            output_interface_index: value.output_interface_index,
            table: value.table,
            metric: value.metric,
            protocol: value.protocol,
            scope: value.scope,
            owner: route_owner_to_view(value.owner),
        }
    }
}

impl From<RouteStatusView> for RouteStatus {
    fn from(value: RouteStatusView) -> Self {
        Self {
            destination: value.destination,
            gateway: value.gateway,
            output_interface: value.output_interface,
            output_interface_index: value.output_interface_index,
            table: value.table,
            metric: value.metric,
            protocol: value.protocol,
            scope: value.scope,
            owner: route_owner_from_view(value.owner),
        }
    }
}
