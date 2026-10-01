use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use anyhow::{bail, Context, Result};
use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::{AppConfig, InterfaceConfig, InterfaceRole, RouterConfig, UplinkMode};
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
    forgotten_interfaces: BTreeSet<String>,
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
        let interface = interface.into();
        self.forgotten_interfaces.remove(&interface);
        self.interfaces.insert(
            interface,
            Some(InterfaceOverride {
                config,
                allow_management_change,
                dhcp_client_only: false,
            }),
        );
        self
    }

    pub fn remove_interface(mut self, interface: impl Into<String>) -> Self {
        let interface = interface.into();
        self.forgotten_interfaces.remove(&interface);
        self.interfaces.insert(interface, None);
        self
    }

    pub fn forget_interface(mut self, interface: impl Into<String>) -> Self {
        let interface = interface.into();
        self.interfaces.remove(&interface);
        self.forgotten_interfaces.insert(interface);
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
                    document.suppressed_interfaces.remove(interface);
                    document.interfaces.insert(interface.clone(), value.clone());
                }
                None => {
                    document.reset_interface_override(interface);
                }
            }
        }
        for interface in &self.forgotten_interfaces {
            document.forget_interface(interface);
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
            suppressed_interfaces: &'a BTreeSet<String>,
        }

        let canonical = serde_json::to_vec(&CanonicalIntent {
            schema_version: document.schema_version,
            router: document.router.as_ref(),
            interfaces: &document.interfaces,
            suppressed_interfaces: &document.suppressed_interfaces,
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

fn apply_derived_router_requirements(
    base: &AppConfig,
    proposal: &RouterIntentProposal,
    document: &mut RuntimeOverrides,
) -> Result<()> {
    let RouterOverrideChange::Set(router) = &proposal.router else {
        return Ok(());
    };
    if !router.enabled {
        return Ok(());
    }
    let Some(uplink) = router
        .uplink
        .as_ref()
        .filter(|uplink| uplink.mode == UplinkMode::Dhcp)
    else {
        return Ok(());
    };

    if document.suppressed_interfaces.contains(&uplink.interface) {
        bail!("router uplink interface {} is suppressed; explicitly configure it before enabling DHCP", uplink.interface);
    }

    if matches!(proposal.interfaces.get(&uplink.interface), Some(None)) {
        bail!(
            "cannot remove router uplink interface {} while configuring it as a DHCP uplink",
            uplink.interface
        );
    }

    if let Some(existing) = document.interfaces.get_mut(&uplink.interface) {
        existing
            .config
            .dhcp_client
            .get_or_insert_with(Default::default)
            .enabled = true;
        return Ok(());
    }

    let Some(base_config) = base.network.interfaces.get(&uplink.interface) else {
        bail!(
            "router uplink interface {} is not configured",
            uplink.interface
        );
    };
    if base_config
        .dhcp_client
        .as_ref()
        .is_some_and(|policy| policy.enabled)
    {
        return Ok(());
    }

    let mut config = base_config.clone();
    config
        .dhcp_client
        .get_or_insert_with(Default::default)
        .enabled = true;
    document.interfaces.insert(
        uplink.interface.clone(),
        InterfaceOverride {
            config,
            allow_management_change: false,
            dhcp_client_only: true,
        },
    );
    Ok(())
}

fn reject_unconfirmed_management_change(
    committed_effective: &AppConfig,
    proposal: &RouterIntentProposal,
) -> Result<()> {
    for name in &proposal.forgotten_interfaces {
        if committed_effective
            .network
            .interfaces
            .get(name)
            .is_some_and(|config| config.role == InterfaceRole::None)
        {
            bail!(
                "refusing to forget outside-router interface {name} without explicit confirmation"
            );
        }
    }
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

            None => current_role == Some(InterfaceRole::None),
        };

        if touches_management && !confirmed {
            bail!(
                "refusing to change outside-router interface {name} without explicit confirmation \
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
        Self::build_inner(base, committed, proposal, false)
    }

    /// Recovery-only candidate construction that ignores unrelated API/auth/security admission.
    pub(crate) fn build_for_recovery(
        base: &AppConfig,
        committed: &RuntimeOverrides,
        proposal: &RouterIntentProposal,
    ) -> Result<Self> {
        Self::build_inner(base, committed, proposal, true)
    }

    fn build_inner(
        base: &AppConfig,
        committed: &RuntimeOverrides,
        proposal: &RouterIntentProposal,
        recovery: bool,
    ) -> Result<Self> {
        if let RouterOverrideChange::Set(router) = &proposal.router {
            if router.enabled
                && router.uplink.is_none()
                && router.owned_routes.is_empty()
                && router.forwarding.is_none()
            {
                bail!(
                    "router.uplink is required before an enabled router candidate can be activated"
                );
            }
        }
        let committed_effective = if recovery {
            committed.effective_router_recovery_config(base)?
        } else {
            committed.effective_config(base)?
        };
        reject_unconfirmed_management_change(&committed_effective, proposal)?;

        let mut document = committed.clone();
        proposal.apply_to(&mut document);
        apply_derived_router_requirements(base, proposal, &mut document)?;

        let document = document.normalized()?;
        let effective = if recovery {
            document.effective_router_recovery_config(base)?
        } else {
            document.effective_config(base)?
        };
        let desired = if recovery {
            RouterDesired::from_router_recovery_config(&effective)?
        } else {
            RouterDesired::from_effective_config(&effective)?
        };
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
mod tests;
