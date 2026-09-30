//! Router proposal conversion at the daemon boundary.

use super::{InterfaceOverrideRequest, RouterProposalRequest};
use crate::config::{OwnedIpv4RouteConfig, RouterConfig, UplinkConfig, VpnHopConfig};
use traffic_masq_protocol::{
    InterfaceOverrideRequestView, OwnedIpv4RouteConfigView, RouterConfigView,
    RouterProposalRequestView, UplinkConfigView, VpnHopConfigView,
};

macro_rules! copy_fields {
    ($domain:ty, $view:ty, $($field:ident),+ $(,)?) => {
        impl From<$view> for $domain {
            fn from(value: $view) -> Self {
                Self { $($field: value.$field),+ }
            }
        }
        impl From<$domain> for $view {
            fn from(value: $domain) -> Self {
                Self { $($field: value.$field),+ }
            }
        }
    };
}

copy_fields!(UplinkConfig, UplinkConfigView, interface, mode);
copy_fields!(
    OwnedIpv4RouteConfig,
    OwnedIpv4RouteConfigView,
    destination,
    gateway,
    output_interface,
    table,
    metric
);
copy_fields!(VpnHopConfig, VpnHopConfigView, profile_name);

impl From<RouterConfigView> for RouterConfig {
    fn from(value: RouterConfigView) -> Self {
        Self {
            enabled: value.enabled,
            uplink: value.uplink.map(Into::into),
            forwarding: value
                .forwarding
                .map(|rules| rules.into_iter().map(Into::into).collect()),
            owned_routes: value.owned_routes.into_iter().map(Into::into).collect(),
            allow_default_route_change: value.allow_default_route_change,
            vpn_chain: value.vpn_chain.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<RouterConfig> for RouterConfigView {
    fn from(value: RouterConfig) -> Self {
        Self {
            enabled: value.enabled,
            uplink: value.uplink.map(Into::into),
            forwarding: value
                .forwarding
                .map(|rules| rules.into_iter().map(Into::into).collect()),
            owned_routes: value.owned_routes.into_iter().map(Into::into).collect(),
            allow_default_route_change: value.allow_default_route_change,
            vpn_chain: value.vpn_chain.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<InterfaceOverrideRequestView> for InterfaceOverrideRequest {
    fn from(value: InterfaceOverrideRequestView) -> Self {
        Self {
            config: value.config.into(),
            allow_management_change: value.allow_management_change,
        }
    }
}

impl From<InterfaceOverrideRequest> for InterfaceOverrideRequestView {
    fn from(value: InterfaceOverrideRequest) -> Self {
        Self {
            config: value.config.into(),
            allow_management_change: value.allow_management_change,
        }
    }
}

impl From<RouterProposalRequestView> for RouterProposalRequest {
    fn from(value: RouterProposalRequestView) -> Self {
        Self {
            set_router: value.set_router.map(Into::into),
            clear_router: value.clear_router,
            set_interfaces: value
                .set_interfaces
                .into_iter()
                .map(|(name, value)| (name, value.into()))
                .collect(),
            remove_interfaces: value.remove_interfaces,
        }
    }
}

impl From<RouterProposalRequest> for RouterProposalRequestView {
    fn from(value: RouterProposalRequest) -> Self {
        Self {
            set_router: value.set_router.map(Into::into),
            clear_router: value.clear_router,
            set_interfaces: value
                .set_interfaces
                .into_iter()
                .map(|(name, value)| (name, value.into()))
                .collect(),
            remove_interfaces: value.remove_interfaces,
        }
    }
}
