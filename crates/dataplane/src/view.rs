//! Conversion between dataplane state and API views.

use crate::{
    ForwardingConfig, OutputNetwork, OwnedFirewallIntegrity, RouterDataplaneDesired,
    RouterDataplanePlan, RouterDataplaneSnapshot, RouterDataplaneTarget,
};
use traffic_masq_protocol::{
    ForwardingConfigView, OutputNetworkView, OwnedFirewallIntegrityView,
    RouterDataplaneDesiredView, RouterDataplanePlanView, RouterDataplaneSnapshotView,
    RouterDataplaneTargetView,
};

impl From<ForwardingConfigView> for ForwardingConfig {
    fn from(value: ForwardingConfigView) -> Self {
        Self {
            source_subnet: value.source_subnet,
            from: value.from,
            to: value.to,
            masquerade: value.masquerade,
        }
    }
}

impl From<ForwardingConfig> for ForwardingConfigView {
    fn from(value: ForwardingConfig) -> Self {
        Self {
            source_subnet: value.source_subnet,
            from: value.from,
            to: value.to,
            masquerade: value.masquerade,
        }
    }
}

impl From<OutputNetwork> for OutputNetworkView {
    fn from(value: OutputNetwork) -> Self {
        Self {
            interface: value.interface,
            subnet: value.subnet,
        }
    }
}

impl From<RouterDataplaneDesired> for RouterDataplaneDesiredView {
    fn from(value: RouterDataplaneDesired) -> Self {
        Self {
            forwarding: value
                .forwarding
                .map(|rules| rules.into_iter().map(Into::into).collect()),
            uplink: value.uplink,
            outputs: value.outputs.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<OwnedFirewallIntegrity> for OwnedFirewallIntegrityView {
    fn from(value: OwnedFirewallIntegrity) -> Self {
        match value {
            OwnedFirewallIntegrity::Intact => Self::Intact,
            OwnedFirewallIntegrity::Drifted => Self::Drifted,
        }
    }
}

impl From<RouterDataplaneSnapshot> for RouterDataplaneSnapshotView {
    fn from(value: RouterDataplaneSnapshot) -> Self {
        Self {
            ipv4_forwarding: value.ipv4_forwarding,
            owned: value.owned.map(Into::into),
            owned_firewall_integrity: value.owned_firewall_integrity.into(),
        }
    }
}

impl From<RouterDataplaneTarget> for RouterDataplaneTargetView {
    fn from(value: RouterDataplaneTarget) -> Self {
        match value {
            RouterDataplaneTarget::Enabled(desired) => Self::Enabled(desired.into()),
            RouterDataplaneTarget::Disabled => Self::Disabled,
        }
    }
}

impl From<RouterDataplanePlan> for RouterDataplanePlanView {
    fn from(value: RouterDataplanePlan) -> Self {
        Self {
            snapshot: value.snapshot.into(),
            target: value.target.into(),
            requires_apply: value.requires_apply,
        }
    }
}
