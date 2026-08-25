use std::collections::BTreeMap;
use std::fmt;

use anyhow::{bail, Context, Result};
use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::{AppConfig, InterfaceConfig, InterfaceRole, RouterConfig};
use crate::core::interface::is_management_change;
use crate::core::router::RouterDesired;
use crate::state::overrides::{InterfaceOverride, RuntimeOverrides};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum RouterOverrideChange {
    #[default]
    Keep,

    Set(RouterConfig),

    Clear,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouterIntentProposal {
    router: RouterOverrideChange,
    interfaces: BTreeMap<String, Option<InterfaceOverride>>,
}

impl RouterIntentProposal {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_router(mut self, router: RouterConfig) -> Self {
        self.router = RouterOverrideChange::Set(router);
        self
    }

    pub fn clear_router(mut self) -> Self {
        self.router = RouterOverrideChange::Clear;
        self
    }

    pub fn set_interface(
        mut self,
        interface: impl Into<String>,
        config: InterfaceConfig,
        allow_management_change: bool,
    ) -> Self {
        self.interfaces.insert(
            interface.into(),
            Some(InterfaceOverride {
                config,
                allow_management_change,
            }),
        );
        self
    }

    pub fn remove_interface(mut self, interface: impl Into<String>) -> Self {
        self.interfaces.insert(interface.into(), None);
        self
    }

    fn apply_to(&self, document: &mut RuntimeOverrides) {
        match &self.router {
            RouterOverrideChange::Keep => {}
            RouterOverrideChange::Set(router) => document.router = Some(router.clone()),
            RouterOverrideChange::Clear => document.router = None,
        }

        for (interface, change) in &self.interfaces {
            match change {
                Some(value) => {
                    document.interfaces.insert(interface.clone(), value.clone());
                }
                None => {
                    document.interfaces.remove(interface);
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CandidateDigest([u8; 32]);

impl CandidateDigest {
    fn of_intent(document: &RuntimeOverrides) -> Result<Self> {
        #[derive(Serialize)]
        struct CanonicalIntent<'a> {
            schema_version: u32,
            router: Option<&'a RouterConfig>,
            interfaces: &'a BTreeMap<String, InterfaceOverride>,
        }

        let canonical = serde_json::to_vec(&CanonicalIntent {
            schema_version: document.schema_version,
            router: document.router.as_ref(),
            interfaces: &document.interfaces,
        })
        .context("failed to serialize canonical router candidate intent")?;
        Ok(Self(Sha256::digest(canonical).into()))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for CandidateDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for CandidateDigest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

fn reject_unconfirmed_management_change(
    committed_effective: &AppConfig,
    proposal: &RouterIntentProposal,
) -> Result<()> {
    for (name, change) in &proposal.interfaces {
        let current_role = committed_effective
            .network
            .interfaces
            .get(name)
            .map(|config| config.role);
        let confirmed = change
            .as_ref()
            .is_some_and(|value| value.allow_management_change);
        let target_role = change.as_ref().map(|value| value.config.role);

        let touches_management = match target_role {
            Some(target) => is_management_change(target, current_role),

            None => current_role == Some(InterfaceRole::Management),
        };

        if touches_management && !confirmed {
            bail!(
                "refusing to change management interface {name} without explicit confirmation \
                 (set allow_management_change on its override)"
            );
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error(
    "router candidate is stale: it was built from committed revision {candidate}, \
     but the current committed revision is {current}"
)]
pub struct StaleCandidateError {
    pub candidate: u64,
    pub current: u64,
}

#[derive(Debug, Clone)]
pub struct RouterCandidate {
    base_revision: u64,
    digest: CandidateDigest,
    document: RuntimeOverrides,
    effective: AppConfig,
    desired: RouterDesired,
}

impl RouterCandidate {
    pub fn build(
        base: &AppConfig,
        committed: &RuntimeOverrides,
        proposal: &RouterIntentProposal,
    ) -> Result<Self> {
        if let RouterOverrideChange::Set(router) = &proposal.router {
            if router.enabled && router.uplink.is_none() {
                bail!(
                    "router.uplink is required before an enabled router candidate can be activated"
                );
            }
        }
        let committed_effective = committed.effective_config(base)?;
        reject_unconfirmed_management_change(&committed_effective, proposal)?;

        let mut document = committed.clone();
        proposal.apply_to(&mut document);

        let document = document.normalized()?;
        let effective = document.effective_config(base)?;
        let desired = RouterDesired::from_effective_config(&effective)?;
        let digest = CandidateDigest::of_intent(&document)?;

        Ok(Self {
            base_revision: committed.revision,
            digest,
            document,
            effective,
            desired,
        })
    }

    pub fn base_revision(&self) -> u64 {
        self.base_revision
    }

    pub fn digest(&self) -> CandidateDigest {
        self.digest
    }

    pub fn document(&self) -> &RuntimeOverrides {
        &self.document
    }

    pub fn effective_config(&self) -> &AppConfig {
        &self.effective
    }

    pub fn desired(&self) -> &RouterDesired {
        &self.desired
    }

    pub fn ensure_base_revision(&self, current_revision: u64) -> Result<(), StaleCandidateError> {
        if self.base_revision == current_revision {
            return Ok(());
        }
        Err(StaleCandidateError {
            candidate: self.base_revision,
            current: current_revision,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::config::{
        DhcpInterfaceConfig, InterfaceRole, OwnedIpv4RouteConfig, UplinkConfig, UplinkMode,
    };

    use super::*;

    fn input_interface() -> InterfaceConfig {
        InterfaceConfig {
            role: InterfaceRole::Input,
            managed: false,
            ipv4: None,
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        }
    }

    fn output_interface(address: &str, pool_start: u8, pool_end: u8) -> InterfaceConfig {
        let ipv4: ipnet::Ipv4Net = address.parse().expect("IPv4 network");
        let octet = ipv4.addr().octets()[2];
        InterfaceConfig {
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some(ipv4),
            dhcp: Some(DhcpInterfaceConfig {
                pool_start: Ipv4Addr::new(192, 168, octet, pool_start),
                pool_end: Ipv4Addr::new(192, 168, octet, pool_end),
                router: ipv4.addr(),
                dns_servers: Vec::new(),
                lease_seconds: None,
            }),
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        }
    }

    fn base_config() -> AppConfig {
        let mut config = AppConfig::default();
        config
            .network
            .interfaces
            .insert("wan0".to_string(), input_interface());
        config.network.interfaces.insert(
            "lan0".to_string(),
            output_interface("192.168.10.1/24", 100, 150),
        );
        config
    }

    fn enabled_router() -> RouterConfig {
        RouterConfig {
            enabled: true,
            uplink: Some(UplinkConfig {
                interface: "wan0".to_string(),
                mode: UplinkMode::External,
            }),
            owned_routes: Vec::new(),
            allow_default_route_change: false,
        }
    }

    fn committed() -> RuntimeOverrides {
        RuntimeOverrides::default()
    }

    fn management_interface() -> InterfaceConfig {
        InterfaceConfig {
            role: InterfaceRole::Management,
            managed: false,
            ipv4: Some("192.168.1.20/24".parse().expect("IPv4 network")),
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        }
    }

    fn base_config_with_management() -> AppConfig {
        let mut config = base_config();
        config
            .network
            .interfaces
            .insert("mgmt0".to_string(), management_interface());
        config
    }

    #[test]
    fn rejects_relabelling_a_management_interface_without_confirmation() {
        let base = base_config_with_management();
        let relabelled = InterfaceConfig {
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some("10.9.0.1/24".parse().expect("IPv4 network")),
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        };

        let error = RouterCandidate::build(
            &base,
            &committed(),
            &RouterIntentProposal::new().set_interface("mgmt0", relabelled.clone(), false),
        )
        .expect_err("relabelling a management interface should be rejected");
        assert!(error.to_string().contains("management interface mgmt0"));

        RouterCandidate::build(
            &base,
            &committed(),
            &RouterIntentProposal::new().set_interface("mgmt0", relabelled, true),
        )
        .expect("explicit confirmation should allow the change");
    }

    #[test]
    fn rejects_removing_a_management_override_without_confirmation() {
        let error = RouterCandidate::build(
            &base_config_with_management(),
            &committed(),
            &RouterIntentProposal::new().remove_interface("mgmt0"),
        )
        .expect_err("dropping a management override should be rejected");
        assert!(error.to_string().contains("management interface mgmt0"));
    }

    #[test]
    fn allows_non_management_interface_changes_without_confirmation() {
        RouterCandidate::build(
            &base_config_with_management(),
            &committed(),
            &RouterIntentProposal::new().set_interface(
                "lan1",
                output_interface("192.168.20.1/24", 100, 150),
                false,
            ),
        )
        .expect("non-management change needs no confirmation");
    }

    #[test]
    fn builds_validated_candidate_bound_to_committed_revision() {
        let mut committed = committed();
        committed.revision = 4;

        let candidate = RouterCandidate::build(
            &base_config(),
            &committed,
            &RouterIntentProposal::new()
                .set_router(enabled_router())
                .set_interface("lan1", output_interface("192.168.20.1/24", 100, 150), false),
        )
        .expect("valid candidate");

        assert_eq!(candidate.base_revision(), 4);
        assert!(candidate.desired().enabled);
        assert_eq!(candidate.desired().dhcp.len(), 2);
        assert!(candidate.effective_config().router.enabled);
        assert_eq!(candidate.document().revision, 4);
    }

    #[test]
    fn rejects_activating_an_unconfigured_router_candidate() {
        let mut router = enabled_router();
        router.uplink = None;

        let error = RouterCandidate::build(
            &base_config(),
            &committed(),
            &RouterIntentProposal::new().set_router(router),
        )
        .expect_err("activation must require a complete router intent");

        assert!(error.to_string().contains("router.uplink is required"));
    }

    #[test]
    fn rejects_candidate_that_is_invalid_across_sections() {
        let error = RouterCandidate::build(
            &base_config(),
            &committed(),
            &RouterIntentProposal::new()
                .set_router(enabled_router())
                .set_interface("wan0", output_interface("192.168.30.1/24", 100, 150), false),
        )
        .expect_err("uplink turned into an output must be rejected");

        assert!(format!("{error:#}").contains("router uplink interface must have the input role"));
    }

    #[test]
    fn rejects_candidate_whose_owned_route_leaves_the_router_contract() {
        let mut router = enabled_router();
        router.owned_routes = vec![OwnedIpv4RouteConfig {
            destination: "0.0.0.0/0".parse().expect("route"),
            gateway: None,
            output_interface: Some("wan0".to_string()),
            table: 254,
            metric: None,
        }];

        let error = RouterCandidate::build(
            &base_config(),
            &committed(),
            &RouterIntentProposal::new().set_router(router),
        )
        .expect_err("default route without permission must be rejected");

        assert!(format!("{error:#}").contains("allow_default_route_change"));
    }

    #[test]
    fn equal_intent_has_the_same_digest_regardless_of_declaration_order() {
        let base = base_config();
        let first = RouterCandidate::build(
            &base,
            &committed(),
            &RouterIntentProposal::new()
                .set_router(enabled_router())
                .set_interface("lan1", output_interface("192.168.20.1/24", 100, 150), false)
                .set_interface("lan2", output_interface("192.168.30.1/24", 100, 150), false),
        )
        .expect("first candidate");
        let second = RouterCandidate::build(
            &base,
            &committed(),
            &RouterIntentProposal::new()
                .set_interface("lan2", output_interface("192.168.30.1/24", 100, 150), false)
                .set_interface("lan1", output_interface("192.168.20.1/24", 100, 150), false)
                .set_router(enabled_router()),
        )
        .expect("second candidate");

        assert_eq!(first.digest(), second.digest());
        assert_eq!(first.digest().to_string(), second.digest().to_string());
        assert_eq!(first.digest().to_string().len(), 64);
    }

    #[test]
    fn digest_ignores_the_committed_revision() {
        let base = base_config();
        let proposal = RouterIntentProposal::new().set_router(enabled_router());
        let mut later = committed();
        later.revision = 97;

        let first = RouterCandidate::build(&base, &committed(), &proposal).expect("first");
        let second = RouterCandidate::build(&base, &later, &proposal).expect("second");

        assert_ne!(first.base_revision(), second.base_revision());
        assert_eq!(first.digest(), second.digest());
    }

    #[test]
    fn semantic_intent_changes_change_the_digest() {
        let base = base_config();
        let router = RouterIntentProposal::new().set_router(enabled_router());
        let baseline = RouterCandidate::build(&base, &committed(), &router).expect("baseline");

        let mut allowed_default_route = enabled_router();
        allowed_default_route.allow_default_route_change = true;
        let changed_router = RouterCandidate::build(
            &base,
            &committed(),
            &RouterIntentProposal::new().set_router(allowed_default_route),
        )
        .expect("changed router");
        assert_ne!(baseline.digest(), changed_router.digest());

        let changed_interface = RouterCandidate::build(
            &base,
            &committed(),
            &router.clone().set_interface(
                "lan1",
                output_interface("192.168.20.1/24", 100, 150),
                false,
            ),
        )
        .expect("changed interface");
        assert_ne!(baseline.digest(), changed_interface.digest());

        let changed_dhcp = RouterCandidate::build(
            &base,
            &committed(),
            &router.clone().set_interface(
                "lan1",
                output_interface("192.168.20.1/24", 100, 149),
                false,
            ),
        )
        .expect("changed DHCP pool");
        assert_ne!(changed_interface.digest(), changed_dhcp.digest());
    }

    #[test]
    fn stale_candidate_is_detected_by_the_revision_guard() {
        let mut committed = committed();
        committed.revision = 7;
        let candidate = RouterCandidate::build(
            &base_config(),
            &committed,
            &RouterIntentProposal::new().set_router(enabled_router()),
        )
        .expect("candidate");

        candidate
            .ensure_base_revision(7)
            .expect("current candidate");
        let error = candidate
            .ensure_base_revision(8)
            .expect_err("stale candidate");
        assert_eq!(
            error,
            StaleCandidateError {
                candidate: 7,
                current: 8,
            }
        );
        assert!(error.to_string().contains("stale"));
    }

    #[test]
    fn validated_candidate_is_not_mutable_through_its_accessors() {
        let candidate = RouterCandidate::build(
            &base_config(),
            &committed(),
            &RouterIntentProposal::new()
                .set_router(enabled_router())
                .set_interface("lan1", output_interface("192.168.20.1/24", 100, 150), false),
        )
        .expect("candidate");
        let digest = candidate.digest();

        let mut document = candidate.document().clone();
        document.interfaces.clear();
        document.router = None;
        let mut desired = candidate.desired().clone();
        desired.dhcp.clear();

        assert_eq!(candidate.document().interfaces.len(), 1);
        assert!(candidate.document().router.is_some());
        assert_eq!(candidate.desired().dhcp.len(), 2);
        assert_eq!(candidate.digest(), digest);
    }
}
