use std::collections::BTreeSet;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::{InterfaceConfig, InterfaceRole, NetworkConfig};
use crate::core::mutation::InterfaceMutationLocks;
use crate::core::ownership::AddressOwnershipJournal;
use crate::netlink::{AddressOwner, AddressOwnership, Ipv4AddressInfo, NetworkProvider};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceSnapshot {
    pub name: String,
    pub was_up: bool,
    pub ipv4_addresses: Vec<Ipv4AddressInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DhcpChangeAction {
    Unchanged,
    Start,
    Reconfigure,
    Stop,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceChangePlan {
    pub interface: String,
    pub delete_ipv4: Vec<Ipv4AddressInfo>,
    /// The desired address is already on the link but carries no ownership
    /// tag: claim it in place rather than dropping and re-adding it.
    #[serde(default)]
    pub retag_ipv4: Option<Ipv4AddressInfo>,
    pub add_ipv4: Option<Ipv4AddressInfo>,
    pub set_link_up: bool,
    pub management_change: bool,
    pub dhcp_action: DhcpChangeAction,
    #[serde(default)]
    pub releasing_management: bool,
}

/// Render an address the way the action log needs it: the ownership tag is the
/// whole point, so it is never omitted.
fn describe_address(address: &Ipv4AddressInfo) -> String {
    match address.protocol {
        Some(protocol) => format!(
            "{}/{} proto={protocol}",
            address.address, address.prefix_len
        ),
        None => format!("{}/{} untagged", address.address, address.prefix_len),
    }
}

fn describe_optional_address(address: Option<&Ipv4AddressInfo>) -> String {
    address.map_or_else(|| "none".to_string(), describe_address)
}

fn describe_addresses(addresses: &[Ipv4AddressInfo]) -> String {
    if addresses.is_empty() {
        return "none".to_string();
    }
    addresses
        .iter()
        .map(describe_address)
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn is_management_change(
    target_role: InterfaceRole,
    current_role: Option<InterfaceRole>,
) -> bool {
    target_role == InterfaceRole::None || current_role == Some(InterfaceRole::None)
}

pub fn owns_dynamic_ipv4(config: &InterfaceConfig) -> bool {
    config.managed
        && config.role == InterfaceRole::Input
        && config
            .dhcp_client
            .as_ref()
            .is_some_and(|dhcp_client| dhcp_client.enabled)
}

#[derive(Clone)]
pub struct InterfaceManager {
    provider: Arc<dyn NetworkProvider>,
    journal: AddressOwnershipJournal,
    mutation_locks: InterfaceMutationLocks,
}

impl InterfaceManager {
    /// The journal is not optional and not a detail of construction: every
    /// manager that writes addresses has to record them where every manager
    /// that asks "is this mine" will look, or the answer depends on which
    /// object you happened to ask.
    pub fn new(provider: Arc<dyn NetworkProvider>, journal: AddressOwnershipJournal) -> Self {
        Self::new_with_mutation_locks(provider, journal, InterfaceMutationLocks::global())
    }

    pub fn new_with_mutation_locks(
        provider: Arc<dyn NetworkProvider>,
        journal: AddressOwnershipJournal,
        mutation_locks: InterfaceMutationLocks,
    ) -> Self {
        Self {
            provider,
            journal,
            mutation_locks,
        }
    }

    /// Whether traffic-masq installed this address.
    ///
    /// Two sources, one answer. The journal is what the daemon wrote down
    /// before touching the machine; the `IFA_PROTO` tag is the kernel
    /// confirming it. Either alone is enough, which is the point: the journal
    /// survives a kernel that cannot hold tags, and the tag survives losing the
    /// journal.
    pub async fn owns_address(&self, interface: &str, address: &Ipv4AddressInfo) -> bool {
        address.owner() == AddressOwner::TrafficMasqStatic
            || self
                .journal
                .owns(interface, address.address, address.prefix_len)
                .await
    }

    /// Whether any of these addresses is ours.
    pub async fn owns_any_address(&self, interface: &str, addresses: &[Ipv4AddressInfo]) -> bool {
        for address in addresses {
            if self.owns_address(interface, address).await {
                return true;
            }
        }
        false
    }

    /// Observe an interface and retain its current link and IPv4 state for rollback.
    pub async fn snapshot(&self, name: &str) -> Result<InterfaceSnapshot> {
        self.snapshot_if_present(name)
            .await?
            .ok_or_else(|| anyhow::anyhow!("interface not found: {name}"))
    }

    /// Snapshot an interface, or report that it is simply not there.
    ///
    /// Callers that snapshot a *set* of interfaces need to tell "this one is
    /// gone" apart from "the snapshot failed": a removable interface
    /// disappearing is ordinary and must not take the whole operation down,
    /// while a netlink failure still has to surface.
    pub async fn snapshot_if_present(&self, name: &str) -> Result<Option<InterfaceSnapshot>> {
        let interfaces = self.provider.list_interfaces().await?;
        let Some(interface) = interfaces
            .into_iter()
            .find(|interface| interface.name == name)
        else {
            return Ok(None);
        };
        let ipv4_addresses = self
            .provider
            .list_ipv4_addresses(name)
            .await?
            .into_iter()
            // DHCP leases are live protocol state, not configuration state.
            // Replaying them from a transaction snapshot can overwrite a
            // newer renewal/rebind during rollback, so DHCP owns their
            // lifecycle exclusively.
            .filter(|address| address.owner() != AddressOwner::TrafficMasqDhcp)
            .collect();

        Ok(Some(InterfaceSnapshot {
            name: name.to_string(),
            was_up: interface.is_up,
            ipv4_addresses,
        }))
    }

    /// Apply managed interface settings and retain snapshots for restoration.
    pub async fn apply_network(
        &self,
        config: &NetworkConfig,
        allow_management_changes: bool,
    ) -> Result<Vec<InterfaceSnapshot>> {
        self.apply_network_internal(config, allow_management_changes, None)
            .await
    }

    /// Apply managed settings while allowing explicit changes to listed management interfaces.
    pub async fn apply_network_with_management_allowlist(
        &self,
        config: &NetworkConfig,
        management_allowlist: &BTreeSet<String>,
    ) -> Result<Vec<InterfaceSnapshot>> {
        self.apply_network_internal(config, false, Some(management_allowlist))
            .await
    }

    async fn apply_network_internal(
        &self,
        config: &NetworkConfig,
        allow_all_management_changes: bool,
        management_allowlist: Option<&BTreeSet<String>>,
    ) -> Result<Vec<InterfaceSnapshot>> {
        config.validate()?;
        let mut snapshots = Vec::new();

        let observed = self.provider.list_interfaces().await?;

        for (name, interface) in &config.interfaces {
            if !interface.managed {
                continue;
            }

            if !observed.iter().any(|candidate| &candidate.name == name) {
                tracing::warn!(
                    interface = %name,
                    "managed interface is absent at startup; skipping its configuration — \
                     the runtime reconcile loop will configure it if it reappears"
                );
                continue;
            }

            let allow_management_change = allow_all_management_changes
                || management_allowlist.is_some_and(|allowed| allowed.contains(name));
            let applied = async {
                let snapshot = self.snapshot(name).await?;
                self.apply_interface(
                    name,
                    interface,
                    Some(interface.role),
                    allow_management_change,
                )
                .await?;
                Ok::<_, anyhow::Error>(snapshot)
            }
            .await;
            let snapshot = match applied {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    let mut rollback_failures = Vec::new();
                    for snapshot in snapshots.iter().rev() {
                        if let Err(rollback_error) = self.rollback(snapshot).await {
                            tracing::error!(
                                interface = %snapshot.name,
                                %rollback_error,
                                "failed to rollback interface after apply error"
                            );
                            rollback_failures
                                .push(format!("{}: {rollback_error:#}", snapshot.name));
                        }
                    }
                    if !rollback_failures.is_empty() {
                        return Err(error).context(format!(
                            "failed to apply interface {name}; rollback incomplete: {}",
                            rollback_failures.join("; ")
                        ));
                    }
                    return Err(error).with_context(|| format!("failed to apply interface {name}"));
                }
            };
            snapshots.push(snapshot);
        }

        Ok(snapshots)
    }

    /// Validate and preview an interface configuration without changing kernel state.
    pub async fn plan_interface(
        &self,
        name: &str,
        config: &InterfaceConfig,
        current_role: Option<InterfaceRole>,
        allow_management_change: bool,
    ) -> Result<InterfaceChangePlan> {
        self.plan_interface_transition(name, config, None, current_role, allow_management_change)
            .await
    }

    /// Plan a change and record the decision.
    ///
    /// Every outcome is logged, including refusals, because "nothing happened"
    /// and "the plan was empty" and "planning was rejected" look identical from
    /// the outside and have completely different causes.
    pub async fn plan_interface_transition(
        &self,
        name: &str,
        config: &InterfaceConfig,
        previous_config: Option<&InterfaceConfig>,
        current_role: Option<InterfaceRole>,
        allow_management_change: bool,
    ) -> Result<InterfaceChangePlan> {
        let previous_managed = previous_config.map(|previous| previous.managed);
        let result = self
            .plan_interface_transition_inner(
                name,
                config,
                previous_config,
                current_role,
                allow_management_change,
            )
            .await;

        match &result {
            Ok(plan) => tracing::info!(
                interface = %name,
                managed = config.managed,
                ?previous_managed,
                role = ?config.role,
                ?current_role,
                allow_management_change,
                releasing_management = plan.releasing_management,
                delete = %describe_addresses(&plan.delete_ipv4),
                retag = %describe_optional_address(plan.retag_ipv4.as_ref()),
                add = %describe_optional_address(plan.add_ipv4.as_ref()),
                set_link_up = plan.set_link_up,
                "planned interface change"
            ),
            Err(error) => tracing::warn!(
                interface = %name,
                managed = config.managed,
                ?previous_managed,
                role = ?config.role,
                ?current_role,
                allow_management_change,
                %error,
                "interface change refused while planning"
            ),
        }

        result
    }

    async fn plan_interface_transition_inner(
        &self,
        name: &str,
        config: &InterfaceConfig,
        previous_config: Option<&InterfaceConfig>,
        current_role: Option<InterfaceRole>,
        allow_management_change: bool,
    ) -> Result<InterfaceChangePlan> {
        if !config.managed
            && (config.ipv4.is_some()
                || config.dhcp.is_some()
                || config.dhcp_client.is_some()
                || config.wifi.is_some()
                || config.wifi_client.is_some())
        {
            bail!(
                "unmanaged interface {name} cannot contain traffic-masq settings; enable Managed to edit them"
            );
        }
        config.validate(name)?;

        let management_change = is_management_change(config.role, current_role);
        if management_change && !allow_management_change {
            bail!(
                "refusing to modify outside-router interface {name} without explicit confirmation"
            );
        }

        if !config.managed {
            let releasing_management = previous_config.is_some_and(|previous| previous.managed);
            let delete_ipv4 = {
                let previous_ipv4 = previous_config.and_then(|previous| previous.ipv4);
                let observed = self.provider.list_ipv4_addresses(name).await?;
                tracing::info!(
                    interface = %name,
                    observed = %describe_addresses(&observed),
                    ?previous_ipv4,
                    releasing_management,
                    "observed IPv4 addresses while planning an unmanaged interface"
                );
                // The configured address is still on the link and nothing —
                // neither the journal nor a tag — says we put it there. Deleting
                // it would take away an address that belongs to someone else.
                if let Some(previous_ipv4) = previous_ipv4 {
                    let unproven = {
                        let mut unproven = None;
                        for address in &observed {
                            if ipnet::Ipv4Net::new(address.address, address.prefix_len).ok()
                                == Some(previous_ipv4)
                                && !self.owns_address(name, address).await
                            {
                                unproven = Some(address.clone());
                                break;
                            }
                        }
                        unproven
                    };
                    if let Some(address) = unproven {
                        bail!(
                            "cannot safely stop managing {name}: configured address {}/{} is not recorded as installed by traffic-masq and carries no ownership tag (observed protocol {:?}); re-apply the managed configuration before trying again",
                            address.address,
                            address.prefix_len,
                            address.protocol
                        );
                    }
                }
                // Cleanup is a state, not an edge. An address of ours has no
                // business sitting on an interface we do not manage, however
                // many apply cycles ago we stopped managing it — otherwise a
                // leftover becomes unremovable once the managed -> unmanaged
                // transition has been spent.
                //
                // Only our own static addresses: DHCP-owned ones are torn down
                // by the DHCP client supervisor's disable path, and deleting
                // them here as well would race with it.
                let mut ours = Vec::new();
                for address in observed {
                    if address.owner() != AddressOwner::TrafficMasqDhcp
                        && self.owns_address(name, &address).await
                    {
                        ours.push(address);
                    }
                }
                ours
            };
            return Ok(InterfaceChangePlan {
                interface: name.to_string(),
                delete_ipv4,
                retag_ipv4: None,
                add_ipv4: None,
                set_link_up: false,
                management_change,
                dhcp_action: DhcpChangeAction::Unchanged,
                releasing_management,
            });
        }

        if owns_dynamic_ipv4(config) {
            return Ok(InterfaceChangePlan {
                interface: name.to_string(),
                delete_ipv4: Vec::new(),
                retag_ipv4: None,
                add_ipv4: None,
                set_link_up: true,
                management_change,
                dhcp_action: DhcpChangeAction::Unchanged,
                releasing_management: false,
            });
        }

        let current = self.provider.list_ipv4_addresses(name).await?;
        let desired = config
            .ipv4
            .map(|network| (network.addr(), network.prefix_len()));
        let can_tag = self.provider.supports_ipv4_address_protocol();
        tracing::info!(
            interface = %name,
            observed = %describe_addresses(&current),
            ?desired,
            ownership_tagging_available = can_tag,
            "observed IPv4 addresses while planning a managed interface"
        );
        let ownership = if can_tag {
            AddressOwnership::Static
        } else {
            AddressOwnership::Untagged
        };

        let mut delete_ipv4 = Vec::new();
        for address in &current {
            if desired != Some((address.address, address.prefix_len))
                && address.owner() != AddressOwner::TrafficMasqDhcp
                && self.owns_address(name, address).await
            {
                delete_ipv4.push(address.clone());
            }
        }

        let existing_desired = desired.and_then(|(address, prefix_len)| {
            current
                .iter()
                .find(|item| item.address == address && item.prefix_len == prefix_len)
        });

        // An address that predates us belongs to its existing owner. Never
        // retag it merely because it happens to match our desired address.
        let retag_ipv4 = None;

        let add_ipv4 =
            desired
                .filter(|_| existing_desired.is_none())
                .map(|(address, prefix_len)| Ipv4AddressInfo {
                    interface_index: current.first().map_or(0, |address| address.interface_index),
                    address,
                    prefix_len,
                    protocol: ownership.protocol(),
                });

        Ok(InterfaceChangePlan {
            interface: name.to_string(),
            delete_ipv4,
            retag_ipv4,
            add_ipv4,
            set_link_up: true,
            management_change,
            dhcp_action: DhcpChangeAction::Unchanged,
            releasing_management: false,
        })
    }

    pub async fn verify_configured_ipv4(&self, name: &str, config: &InterfaceConfig) -> Result<()> {
        let Some(network) = config.ipv4 else {
            return Ok(());
        };
        let addresses = self.provider.list_ipv4_addresses(name).await?;
        if addresses.iter().any(|address| {
            address.address == network.addr() && address.prefix_len == network.prefix_len()
        }) {
            Ok(())
        } else {
            bail!("configured IPv4 address {network} is not present on interface {name}")
        }
    }

    /// Best-effort daemon bootstrap. Transactions retain all-or-nothing apply.
    pub async fn apply_network_degraded(
        &self,
        config: &NetworkConfig,
        allowlist: &BTreeSet<String>,
    ) -> Result<Vec<InterfaceSnapshot>> {
        config.validate()?;
        let observed = self.provider.list_interfaces().await?;
        let mut snapshots = Vec::new();
        for (name, interface) in &config.interfaces {
            if !interface.managed || !observed.iter().any(|entry| &entry.name == name) {
                continue;
            }
            let result: Result<()> = async {
                snapshots.push(self.snapshot(name).await?);
                self.apply_interface(
                    name,
                    interface,
                    Some(interface.role),
                    allowlist.contains(name),
                )
                .await
            }
            .await;
            if let Err(error) = result {
                tracing::error!(interface = %name, operation = "startup_apply_interface",
                    error = %format!("{error:#}"), "interface degraded; remaining interfaces will still start");
            }
        }
        Ok(snapshots)
    }

    /// Plan and apply one interface configuration, returning its original state for rollback.
    pub async fn apply_interface(
        &self,
        name: &str,
        config: &InterfaceConfig,
        current_role: Option<InterfaceRole>,
        allow_management_change: bool,
    ) -> Result<()> {
        self.apply_interface_transition(name, config, None, current_role, allow_management_change)
            .await
    }

    /// Apply a validated transition under the per-interface mutation lock.
    pub async fn apply_interface_transition(
        &self,
        name: &str,
        config: &InterfaceConfig,
        previous_config: Option<&InterfaceConfig>,
        current_role: Option<InterfaceRole>,
        allow_management_change: bool,
    ) -> Result<()> {
        let snapshot = self.snapshot(name).await?;
        if let Err(error) = self
            .apply_interface_unchecked(
                name,
                config,
                previous_config,
                current_role,
                allow_management_change,
            )
            .await
        {
            return match self.rollback(&snapshot).await {
                Ok(()) => Err(anyhow::anyhow!(
                    "interface apply failed; previous state was restored: {error}"
                )),
                Err(rollback_error) => Err(anyhow::anyhow!(
                    "interface apply failed: {error}; rollback also failed: {rollback_error}"
                )),
            };
        }
        Ok(())
    }

    async fn apply_interface_unchecked(
        &self,
        name: &str,
        config: &InterfaceConfig,
        previous_config: Option<&InterfaceConfig>,
        current_role: Option<InterfaceRole>,
        allow_management_change: bool,
    ) -> Result<()> {
        let plan = self
            .plan_interface_transition(
                name,
                config,
                previous_config,
                current_role,
                allow_management_change,
            )
            .await?;
        self.apply_plan(&plan).await
    }

    /// Revalidate and execute planned link/address changes while journaling daemon ownership.
    pub async fn apply_plan(&self, plan: &InterfaceChangePlan) -> Result<()> {
        let _mutation = self.mutation_locks.lock(&plan.interface).await;
        if plan.delete_ipv4.is_empty() && plan.retag_ipv4.is_none() && plan.add_ipv4.is_none() {
            tracing::info!(
                interface = %plan.interface,
                releasing_management = plan.releasing_management,
                "applying interface plan: no IPv4 address changes to make"
            );
        }

        for address in &plan.delete_ipv4 {
            tracing::info!(
                interface = %plan.interface,
                address = %describe_address(address),
                "applying interface plan: deleting IPv4 address"
            );
            self.record_release(&plan.interface, address).await?;
            self.provider
                .delete_ipv4_address(&plan.interface, address.address, address.prefix_len)
                .await?;
            self.record_released(&plan.interface, address).await?;
        }

        if let Some(address) = &plan.retag_ipv4 {
            tracing::info!(
                interface = %plan.interface,
                address = %describe_address(address),
                "applying interface plan: claiming existing IPv4 address in place"
            );
            self.record_claim(&plan.interface, address).await?;
            self.provider
                .set_ipv4_address_ownership(
                    &plan.interface,
                    address.address,
                    address.prefix_len,
                    address.owner().restore_as(),
                )
                .await?;
            self.record_claimed(&plan.interface, address).await?;
        }

        if let Some(address) = &plan.add_ipv4 {
            tracing::info!(
                interface = %plan.interface,
                address = %describe_address(address),
                "applying interface plan: adding IPv4 address"
            );
            self.record_claim(&plan.interface, address).await?;
            self.provider
                .add_ipv4_address(
                    &plan.interface,
                    address.address,
                    address.prefix_len,
                    address.owner().restore_as(),
                )
                .await?;
            self.record_claimed(&plan.interface, address).await?;
        }

        if plan.set_link_up {
            self.provider.set_link_up(&plan.interface).await?;
        }
        Ok(())
    }

    /// Write down that an address is about to become ours.
    ///
    /// Before the mutation, always. The other order leaves the crash window on
    /// the wrong side: an address on the machine that nothing remembers
    /// installing is an address nobody will ever take off.
    ///
    /// Callers decide what counts as ours — installing the configured address
    /// does, restoring one that was on the link before us does not — because
    /// the tag cannot decide it: on a kernel that drops `IFA_PROTO` our own
    /// address goes on untagged, and that is exactly when the journal is the
    /// only record there is.
    ///
    /// Ownership bookkeeping is part of the mutation protocol, not optional
    /// telemetry. If it cannot be written, fail before touching the kernel so
    /// crash recovery never loses the authority record for an address.
    async fn record_claim(&self, interface: &str, address: &Ipv4AddressInfo) -> Result<()> {
        self.journal
            .claim(interface, address.address, address.prefix_len)
            .await
            .with_context(|| {
                format!(
                    "failed to record IPv4 address ownership before installing {} on {interface}",
                    describe_address(address)
                )
            })
    }

    async fn record_claimed(&self, interface: &str, address: &Ipv4AddressInfo) -> Result<()> {
        self.journal
            .confirm(interface, address.address, address.prefix_len)
            .await
            .with_context(|| {
                format!(
                    "failed to confirm IPv4 address ownership after installing {} on {interface}",
                    describe_address(address)
                )
            })
    }

    async fn record_release(&self, interface: &str, address: &Ipv4AddressInfo) -> Result<()> {
        self.journal
            .releasing(interface, address.address, address.prefix_len)
            .await
            .with_context(|| {
                format!(
                    "failed to record IPv4 address release before removing {} from {interface}",
                    describe_address(address)
                )
            })
    }

    async fn record_released(&self, interface: &str, address: &Ipv4AddressInfo) -> Result<()> {
        self.journal
            .release(interface, address.address, address.prefix_len)
            .await
            .with_context(|| {
                format!(
                    "failed to drop IPv4 address ownership after removing {} from {interface}",
                    describe_address(address)
                )
            })
    }

    /// Restore captured link/address state while respecting current ownership and external addresses.
    pub async fn rollback(&self, snapshot: &InterfaceSnapshot) -> Result<()> {
        let _mutation = self.mutation_locks.lock(&snapshot.name).await;
        let current = self.provider.list_ipv4_addresses(&snapshot.name).await?;
        let can_tag = self.provider.supports_ipv4_address_protocol();
        let same_address = |left: &Ipv4AddressInfo, right: &Ipv4AddressInfo| {
            left.address == right.address && left.prefix_len == right.prefix_len
        };

        tracing::info!(
            interface = %snapshot.name,
            observed = %describe_addresses(&current),
            snapshot = %describe_addresses(&snapshot.ipv4_addresses),
            was_up = snapshot.was_up,
            "rolling back interface to its snapshot"
        );

        for address in &current {
            let existed_before = snapshot
                .ipv4_addresses
                .iter()
                .any(|previous| same_address(previous, address));
            if !existed_before && self.owns_address(&snapshot.name, address).await {
                tracing::info!(
                    interface = %snapshot.name,
                    address = %describe_address(address),
                    "rollback: deleting IPv4 address that was not in the snapshot"
                );
                self.record_release(&snapshot.name, address).await?;
                self.provider
                    .delete_ipv4_address(&snapshot.name, address.address, address.prefix_len)
                    .await?;
                self.record_released(&snapshot.name, address).await?;
            }
        }

        for address in &snapshot.ipv4_addresses {
            // Older durable transaction journals may still contain DHCP-owned
            // addresses. Never replay those: DHCP lease state advances
            // independently of the transaction and may already be newer.
            if address.owner() == AddressOwner::TrafficMasqDhcp {
                continue;
            }
            // Ownership is restored as it was, except that a foreign tag is
            // never replayed: see `AddressOwner::restore_as`.
            let ownership = address.owner().restore_as();
            // Whether putting this back makes it ours again. An address that
            // was on the link before traffic-masq touched it is restored, not
            // claimed — recording it would authorise deleting it later.
            let ours = self.owns_address(&snapshot.name, address).await;
            match current.iter().find(|item| same_address(item, address)) {
                Some(present) if present.protocol != address.protocol && can_tag => {
                    tracing::info!(
                        interface = %snapshot.name,
                        address = %describe_address(address),
                        observed = %describe_address(present),
                        "rollback: restoring the ownership tag of an existing IPv4 address"
                    );
                    if ours {
                        self.record_claim(&snapshot.name, address).await?;
                    }
                    self.provider
                        .set_ipv4_address_ownership(
                            &snapshot.name,
                            address.address,
                            address.prefix_len,
                            ownership,
                        )
                        .await?;
                    if ours {
                        self.record_claimed(&snapshot.name, address).await?;
                    }
                }
                Some(_) => {}
                None => {
                    tracing::info!(
                        interface = %snapshot.name,
                        address = %describe_address(address),
                        "rollback: re-adding an IPv4 address from the snapshot"
                    );
                    if ours {
                        self.record_claim(&snapshot.name, address).await?;
                    }
                    self.provider
                        .add_ipv4_address(
                            &snapshot.name,
                            address.address,
                            address.prefix_len,
                            ownership,
                        )
                        .await?;
                    if ours {
                        self.record_claimed(&snapshot.name, address).await?;
                    }
                }
            }
        }

        if snapshot.was_up {
            self.provider.set_link_up(&snapshot.name).await?;
        } else {
            self.provider.set_link_down(&snapshot.name).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests;
