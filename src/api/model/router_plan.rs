use crate::core::route::RoutePlan;
use crate::core::router::{
    DhcpPlan, RouterDesired, RouterInterfaceDesired, RouterPlan, RouterRisk, VpnChainPlan, WifiPlan,
};
use crate::core::vpn_chain::{VpnHopDesired, VpnHopKind, VpnHopRoutingDesired};
use crate::core::vpn_policy::VpnPolicyReservedIds;
use crate::core::vpn_policy_manager::VpnPolicyDesired;
use crate::dhcp::client::DhcpClientSpec;
use crate::netlink::{Ipv4RouteInfo, Ipv4RouteSpec};
use traffic_masq_protocol::{
    DhcpClientSpecView, DhcpPlanView, Ipv4RouteInfoView, Ipv4RouteSpecView,
    OwnedIpv4RouteConfigView, RoutePlanView, RouterDesiredView, RouterInterfaceDesiredView,
    RouterPlanView, RouterRiskView, VpnChainPlanView, VpnHopDesiredView, VpnHopKindView,
    VpnHopRoutingDesiredView, VpnPolicyDesiredView, VpnPolicyReservedIdsView, WifiPlanView,
};

fn route_spec_view(route: Ipv4RouteSpec) -> Ipv4RouteSpecView {
    Ipv4RouteSpecView {
        destination: route.destination,
        gateway: route.gateway,
        output_interface_index: route.output_interface_index,
        table: route.table,
        metric: route.metric,
        protocol: route.protocol,
    }
}

fn route_info_view(route: Ipv4RouteInfo) -> Ipv4RouteInfoView {
    Ipv4RouteInfoView {
        destination: route.destination,
        gateway: route.gateway,
        output_interface_index: route.output_interface_index,
        table: route.table,
        metric: route.metric,
        protocol: route.protocol,
        scope: route.scope,
    }
}

impl From<RoutePlan> for RoutePlanView {
    fn from(plan: RoutePlan) -> Self {
        Self {
            add: plan.add.into_iter().map(route_spec_view).collect(),
            delete: plan.delete.into_iter().map(route_info_view).collect(),
        }
    }
}

impl From<RouterRisk> for RouterRiskView {
    fn from(risk: RouterRisk) -> Self {
        Self {
            changes_default_route: risk.changes_default_route,
            requires_management_confirmation: risk.requires_management_confirmation,
        }
    }
}

impl From<DhcpPlan> for DhcpPlanView {
    fn from(plan: DhcpPlan) -> Self {
        match plan {
            DhcpPlan::Start { desired } => Self::Start {
                desired: desired.into(),
            },
            DhcpPlan::Stop { current } => Self::Stop {
                current: current.into(),
            },
            DhcpPlan::Reconfigure { current, desired } => Self::Reconfigure {
                current: current.into(),
                desired: desired.into(),
            },
            DhcpPlan::Unchanged { current } => Self::Unchanged {
                current: current.into(),
            },
        }
    }
}

pub(super) fn wifi_plan_view<T, U>(plan: WifiPlan<T>) -> WifiPlanView<U>
where
    T: Into<U>,
{
    match plan {
        WifiPlan::Start { desired } => WifiPlanView::Start {
            desired: desired.into(),
        },
        WifiPlan::Stop { current } => WifiPlanView::Stop {
            current: current.into(),
        },
        WifiPlan::Reconfigure { current, desired } => WifiPlanView::Reconfigure {
            current: current.into(),
            desired: desired.into(),
        },
        WifiPlan::Unchanged { current } => WifiPlanView::Unchanged {
            current: current.into(),
        },
    }
}

impl From<RouterInterfaceDesired> for RouterInterfaceDesiredView {
    fn from(value: RouterInterfaceDesired) -> Self {
        Self {
            name: value.name,
            config: value.config.into(),
        }
    }
}

impl From<DhcpClientSpec> for DhcpClientSpecView {
    fn from(value: DhcpClientSpec) -> Self {
        Self {
            interface: value.interface,
            hostname: value.hostname,
            route_metric: value.route_metric,
            install_default_route: value.install_default_route,
            request_dns: value.request_dns,
            send_release_on_shutdown: value.send_release_on_shutdown,
        }
    }
}

impl From<VpnPolicyReservedIds> for VpnPolicyReservedIdsView {
    fn from(value: VpnPolicyReservedIds) -> Self {
        Self {
            route_table: value.route_table.get(),
            rule_priority_start: value.rule_priority_start.get(),
            rule_priority_end: value.rule_priority_end.get(),
            fw_mark: value.fw_mark.get(),
            fw_mask: value.fw_mask.get(),
        }
    }
}

impl From<VpnHopRoutingDesired> for VpnHopRoutingDesiredView {
    fn from(value: VpnHopRoutingDesired) -> Self {
        Self {
            hop_interface: value.hop_interface,
            upstream_interface: value.upstream_interface,
        }
    }
}

impl From<VpnPolicyDesired> for VpnPolicyDesiredView {
    fn from(value: VpnPolicyDesired) -> Self {
        Self {
            masquerade_forwarded: value.masquerade_forwarded,
            protected_subnets: value.protected_subnets,
            vpn_interface: value.vpn_interface,
            physical_uplink: value.physical_uplink,
            route_host_traffic: value.route_host_traffic,
        }
    }
}

impl From<VpnHopKind> for VpnHopKindView {
    fn from(value: VpnHopKind) -> Self {
        match value {
            VpnHopKind::Relay { own_route } => Self::Relay {
                own_route: own_route.into(),
            },
            VpnHopKind::Exit { policy } => Self::Exit {
                policy: policy.into(),
            },
        }
    }
}

impl From<VpnHopDesired> for VpnHopDesiredView {
    fn from(value: VpnHopDesired) -> Self {
        Self {
            hop_index: value.hop_index,
            profile_name: value.profile_name,
            interface: value.interface,
            upstream: value.upstream,
            reserved: value.reserved.into(),
            kind: value.kind.into(),
        }
    }
}

impl From<VpnChainPlan> for VpnChainPlanView {
    fn from(value: VpnChainPlan) -> Self {
        Self {
            standalone: value.standalone.map(|desired| {
                traffic_masq_protocol::StandaloneVpnPlanView {
                    profile: desired.profile,
                    protected_traffic: desired.policy.is_some(),
                }
            }),
            hops: value.hops.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<RouterDesired> for RouterDesiredView {
    fn from(value: RouterDesired) -> Self {
        Self {
            enabled: value.enabled,
            uplink_wifi: value.uplink_wifi.map(Into::into),
            uplink_dhcp: value.uplink_dhcp.map(Into::into),
            output_wifi: value.output_wifi.into_iter().map(Into::into).collect(),
            dhcp: value.dhcp.into_iter().map(Into::into).collect(),
            routes: value
                .routes
                .into_iter()
                .map(|route| OwnedIpv4RouteConfigView {
                    destination: route.destination,
                    gateway: route.gateway,
                    output_interface: route.output_interface,
                    table: route.table,
                    metric: route.metric,
                })
                .collect(),
            allow_default_route_change: value.allow_default_route_change,
            vpn_chain: value.vpn_chain.into_iter().map(Into::into).collect(),
            dataplane: value.dataplane.into(),
            interfaces: value.interfaces.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<RouterPlan> for RouterPlanView {
    fn from(value: RouterPlan) -> Self {
        Self {
            base_revision: None,
            observation_fingerprint: None,
            desired: value.desired.into(),
            interfaces: value.interfaces.into_iter().map(Into::into).collect(),
            uplink_wifi: value.uplink_wifi.into_iter().map(wifi_plan_view).collect(),
            output_wifi: value.output_wifi.into_iter().map(wifi_plan_view).collect(),
            dhcp: value.dhcp.into_iter().map(Into::into).collect(),
            routes: value.routes.into(),
            vpn_chain: value.vpn_chain.into(),
            dataplane: value.dataplane.into(),
            risk: value.risk.into(),
        }
    }
}
