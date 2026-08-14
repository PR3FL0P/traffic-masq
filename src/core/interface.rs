use std::collections::BTreeSet;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::{InterfaceConfig, InterfaceRole, NetworkConfig};
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
    target_role == InterfaceRole::Management || current_role == Some(InterfaceRole::Management)
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
}

impl InterfaceManager {
    pub fn new(provider: Arc<dyn NetworkProvider>) -> Self {
        Self { provider }
    }

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
        let ipv4_addresses = self.provider.list_ipv4_addresses(name).await?;

        Ok(Some(InterfaceSnapshot {
            name: name.to_string(),
            was_up: interface.is_up,
            ipv4_addresses,
        }))
    }

    pub async fn apply_network(
        &self,
        config: &NetworkConfig,
        allow_management_changes: bool,
    ) -> Result<Vec<InterfaceSnapshot>> {
        self.apply_network_internal(config, allow_management_changes, None)
            .await
    }

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
            let snapshot = self.snapshot(name).await?;

            if let Err(error) = self
                .apply_interface(
                    name,
                    interface,
                    Some(interface.role),
                    allow_management_change,
                )
                .await
            {
                for snapshot in snapshots.iter().rev() {
                    if let Err(rollback_error) = self.rollback(snapshot).await {
                        tracing::error!(
                            interface = %snapshot.name,
                            %rollback_error,
                            "failed to rollback interface after apply error"
                        );
                    }
                }
                return Err(error).with_context(|| format!("failed to apply interface {name}"));
            }
            snapshots.push(snapshot);
        }

        Ok(snapshots)
    }

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
            bail!("refusing to modify management interface {name} without explicit confirmation");
        }

        if !config.managed {
            let releasing_management = previous_config.is_some_and(|previous| previous.managed);
            let delete_ipv4 = {
                let previous_ipv4 = previous_config.and_then(|previous| previous.ipv4);
                if previous_ipv4.is_some() && !self.provider.supports_ipv4_address_protocol() {
                    bail!(
                        "cannot safely stop managing {name}: this network provider cannot verify IPv4 address ownership"
                    );
                }
                let observed = self.provider.list_ipv4_addresses(name).await?;
                tracing::info!(
                    interface = %name,
                    observed = %describe_addresses(&observed),
                    ?previous_ipv4,
                    releasing_management,
                    "observed IPv4 addresses while planning an unmanaged interface"
                );
                if let Some(previous_ipv4) = previous_ipv4 {
                    if let Some(address) = observed.iter().find(|address| {
                        ipnet::Ipv4Net::new(address.address, address.prefix_len).ok()
                            == Some(previous_ipv4)
                            && address.owner() != AddressOwner::TrafficMasqStatic
                    }) {
                        bail!(
                            "cannot safely stop managing {name}: configured address {}/{} has no traffic-masq ownership tag (observed protocol {:?}); re-apply the managed configuration before trying again",
                            address.address,
                            address.prefix_len,
                            address.protocol
                        );
                    }
                }
                // Cleanup is a state, not an edge. An address tagged as ours has
                // no business sitting on an interface we do not manage, however
                // many apply cycles ago we stopped managing it — otherwise a
                // leftover becomes unremovable once the managed -> unmanaged
                // transition has been spent.
                //
                // Only our own static addresses: DHCP-owned ones are torn down
                // by the DHCP client supervisor's disable path, and deleting
                // them here as well would race with it.
                observed
                    .into_iter()
                    .filter(|address| address.owner() == AddressOwner::TrafficMasqStatic)
                    .collect()
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

        let delete_ipv4 = current
            .iter()
            .filter(|address| desired != Some((address.address, address.prefix_len)))
            .cloned()
            .collect();

        let existing_desired = desired.and_then(|(address, prefix_len)| {
            current
                .iter()
                .find(|item| item.address == address && item.prefix_len == prefix_len)
        });

        // The desired address is already on the link but is not ours yet:
        // claim it in place. Deleting and re-adding it would drop the address
        // on every unrelated edit, which on a management interface is a blip
        // the user never asked for.
        let retag_ipv4 = existing_desired
            .filter(|address| can_tag && address.owner() != AddressOwner::TrafficMasqStatic)
            .map(|address| Ipv4AddressInfo {
                protocol: ownership.protocol(),
                ..address.clone()
            });

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

    pub async fn apply_plan(&self, plan: &InterfaceChangePlan) -> Result<()> {
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
            self.provider
                .delete_ipv4_address(&plan.interface, address.address, address.prefix_len)
                .await?;
        }

        if let Some(address) = &plan.retag_ipv4 {
            tracing::info!(
                interface = %plan.interface,
                address = %describe_address(address),
                "applying interface plan: claiming existing IPv4 address in place"
            );
            self.provider
                .set_ipv4_address_ownership(
                    &plan.interface,
                    address.address,
                    address.prefix_len,
                    address.owner().restore_as(),
                )
                .await?;
        }

        if let Some(address) = &plan.add_ipv4 {
            tracing::info!(
                interface = %plan.interface,
                address = %describe_address(address),
                "applying interface plan: adding IPv4 address"
            );
            self.provider
                .add_ipv4_address(
                    &plan.interface,
                    address.address,
                    address.prefix_len,
                    address.owner().restore_as(),
                )
                .await?;
        }

        if plan.set_link_up {
            self.provider.set_link_up(&plan.interface).await?;
        }
        Ok(())
    }

    pub async fn rollback(&self, snapshot: &InterfaceSnapshot) -> Result<()> {
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
            if !existed_before {
                tracing::info!(
                    interface = %snapshot.name,
                    address = %describe_address(address),
                    "rollback: deleting IPv4 address that was not in the snapshot"
                );
                self.provider
                    .delete_ipv4_address(&snapshot.name, address.address, address.prefix_len)
                    .await?;
            }
        }

        for address in &snapshot.ipv4_addresses {
            // Ownership is restored as it was, except that a foreign tag is
            // never replayed: see `AddressOwner::restore_as`.
            let ownership = address.owner().restore_as();
            match current.iter().find(|item| same_address(item, address)) {
                Some(present) if present.protocol != address.protocol && can_tag => {
                    tracing::info!(
                        interface = %snapshot.name,
                        address = %describe_address(address),
                        observed = %describe_address(present),
                        "rollback: restoring the ownership tag of an existing IPv4 address"
                    );
                    self.provider
                        .set_ipv4_address_ownership(
                            &snapshot.name,
                            address.address,
                            address.prefix_len,
                            ownership,
                        )
                        .await?;
                }
                Some(_) => {}
                None => {
                    tracing::info!(
                        interface = %snapshot.name,
                        address = %describe_address(address),
                        "rollback: re-adding an IPv4 address from the snapshot"
                    );
                    self.provider
                        .add_ipv4_address(
                            &snapshot.name,
                            address.address,
                            address.prefix_len,
                            ownership,
                        )
                        .await?;
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
mod tests {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    use async_trait::async_trait;
    use ipnet::Ipv4Net;
    use tokio::sync::Mutex;

    use crate::config::InterfaceConfig;
    use crate::netlink::{
        NetworkInterface, TRAFFIC_MASQ_ADDRESS_PROTOCOL, TRAFFIC_MASQ_DHCP_ADDRESS_PROTOCOL,
    };

    use super::*;

    #[derive(Debug, Default)]
    struct FakeNetworkProvider {
        interfaces: Mutex<HashMap<String, NetworkInterface>>,
        addresses: Mutex<HashMap<String, Vec<Ipv4AddressInfo>>>,
    }

    impl FakeNetworkProvider {
        async fn add_interface(&self, name: &str, is_up: bool, addresses: Vec<Ipv4AddressInfo>) {
            self.interfaces.lock().await.insert(
                name.to_string(),
                NetworkInterface {
                    is_wireless: false,
                    index: 1,
                    name: name.to_string(),
                    is_up,
                    rx_bytes: 0,
                    tx_bytes: 0,
                },
            );
            self.addresses
                .lock()
                .await
                .insert(name.to_string(), addresses);
        }
    }

    #[async_trait]
    impl NetworkProvider for FakeNetworkProvider {
        fn supports_ipv4_address_protocol(&self) -> bool {
            true
        }

        async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
            Ok(self.interfaces.lock().await.values().cloned().collect())
        }

        async fn list_ipv4_addresses(&self, interface: &str) -> Result<Vec<Ipv4AddressInfo>> {
            Ok(self
                .addresses
                .lock()
                .await
                .get(interface)
                .cloned()
                .unwrap_or_default())
        }

        async fn set_link_up(&self, name: &str) -> Result<()> {
            self.interfaces
                .lock()
                .await
                .get_mut(name)
                .expect("interface")
                .is_up = true;
            Ok(())
        }

        async fn set_link_down(&self, name: &str) -> Result<()> {
            self.interfaces
                .lock()
                .await
                .get_mut(name)
                .expect("interface")
                .is_up = false;
            Ok(())
        }

        async fn add_ipv4_address(
            &self,
            interface: &str,
            address: Ipv4Addr,
            prefix_len: u8,
            ownership: AddressOwnership,
        ) -> Result<()> {
            self.addresses
                .lock()
                .await
                .entry(interface.to_string())
                .or_default()
                .push(Ipv4AddressInfo {
                    interface_index: 1,
                    address,
                    prefix_len,
                    protocol: ownership.protocol(),
                });
            Ok(())
        }

        async fn set_ipv4_address_ownership(
            &self,
            interface: &str,
            address: Ipv4Addr,
            prefix_len: u8,
            ownership: AddressOwnership,
        ) -> Result<()> {
            let mut addresses = self.addresses.lock().await;
            let entry = addresses.entry(interface.to_string()).or_default();
            let existing = entry
                .iter_mut()
                .find(|item| item.address == address && item.prefix_len == prefix_len)
                .ok_or_else(|| {
                    anyhow::anyhow!("address {address}/{prefix_len} not found on {interface}")
                })?;
            existing.protocol = ownership.protocol();
            Ok(())
        }

        async fn delete_ipv4_address(
            &self,
            interface: &str,
            address: Ipv4Addr,
            prefix_len: u8,
        ) -> Result<()> {
            self.addresses
                .lock()
                .await
                .entry(interface.to_string())
                .or_default()
                .retain(|current| current.address != address || current.prefix_len != prefix_len);
            Ok(())
        }
    }

    fn config(role: InterfaceRole, address: &str) -> InterfaceConfig {
        InterfaceConfig {
            role,
            managed: true,
            ipv4: Some(address.parse::<Ipv4Net>().expect("network")),
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        }
    }

    fn address_with_protocol(address: &str, protocol: Option<u8>) -> Ipv4AddressInfo {
        let network = address.parse::<Ipv4Net>().expect("network");
        Ipv4AddressInfo {
            interface_index: 1,
            address: network.addr(),
            prefix_len: network.prefix_len(),
            protocol,
        }
    }

    #[tokio::test]
    async fn releasing_management_deletes_only_tagged_addresses() {
        let provider = Arc::new(FakeNetworkProvider::default());
        let owned = address_with_protocol("192.168.50.1/24", Some(TRAFFIC_MASQ_ADDRESS_PROTOCOL));
        let foreign = address_with_protocol("192.168.1.20/24", None);
        provider
            .add_interface("eth0", true, vec![owned.clone(), foreign])
            .await;
        let manager = InterfaceManager::new(provider);
        let previous = config(InterfaceRole::Output, "192.168.50.1/24");
        let mut target = previous.clone();
        target.managed = false;
        target.ipv4 = None;

        let plan = manager
            .plan_interface_transition(
                "eth0",
                &target,
                Some(&previous),
                Some(InterfaceRole::Output),
                false,
            )
            .await
            .expect("release plan");

        assert!(plan.releasing_management);
        assert_eq!(plan.delete_ipv4, vec![owned]);
        assert!(plan.add_ipv4.is_none());
        assert!(!plan.set_link_up);
    }

    #[tokio::test]
    async fn releasing_management_refuses_an_untagged_legacy_address() {
        let provider = Arc::new(FakeNetworkProvider::default());
        provider
            .add_interface(
                "eth0",
                true,
                vec![address_with_protocol("192.168.50.1/24", None)],
            )
            .await;
        let manager = InterfaceManager::new(provider);
        let previous = config(InterfaceRole::Output, "192.168.50.1/24");
        let mut target = previous.clone();
        target.managed = false;
        target.ipv4 = None;

        let error = manager
            .plan_interface_transition(
                "eth0",
                &target,
                Some(&previous),
                Some(InterfaceRole::Output),
                false,
            )
            .await
            .expect_err("untagged address must not be claimed");
        assert!(error.to_string().contains("ownership tag"));
    }

    #[tokio::test]
    async fn snapshotting_reports_a_missing_interface_instead_of_failing() {
        let provider = Arc::new(FakeNetworkProvider::default());
        provider.add_interface("eth0", true, Vec::new()).await;
        let manager = InterfaceManager::new(provider);

        assert!(manager
            .snapshot_if_present("eth0")
            .await
            .expect("present interface")
            .is_some());
        assert!(manager
            .snapshot_if_present("usb0")
            .await
            .expect("a missing interface is not an error")
            .is_none());
        // The strict variant keeps its contract for callers that need one.
        assert!(manager.snapshot("usb0").await.is_err());
    }

    #[tokio::test]
    async fn a_leftover_owned_address_is_cleaned_up_after_the_release_transition() {
        let provider = Arc::new(FakeNetworkProvider::default());
        let owned = address_with_protocol("192.168.50.1/24", Some(TRAFFIC_MASQ_ADDRESS_PROTOCOL));
        let foreign = address_with_protocol("192.168.1.20/24", None);
        provider
            .add_interface("eth0", true, vec![owned.clone(), foreign])
            .await;
        let manager = InterfaceManager::new(provider);

        // Both sides already unmanaged: the managed -> unmanaged edge is long
        // gone, but our address is still sitting on the link.
        let unmanaged = InterfaceConfig {
            role: InterfaceRole::Output,
            managed: false,
            ipv4: None,
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        };

        let plan = manager
            .plan_interface_transition(
                "eth0",
                &unmanaged,
                Some(&unmanaged),
                Some(InterfaceRole::Output),
                false,
            )
            .await
            .expect("plan");

        assert!(!plan.releasing_management);
        assert_eq!(
            plan.delete_ipv4,
            vec![owned],
            "a leftover traffic-masq address must stay removable, and a foreign one untouched"
        );
    }

    #[tokio::test]
    async fn applying_a_retag_honours_the_ownership_the_plan_carries() {
        let provider = Arc::new(FakeNetworkProvider::default());
        provider
            .add_interface(
                "eth0",
                true,
                vec![address_with_protocol("192.168.50.1/24", None)],
            )
            .await;
        let manager = InterfaceManager::new(provider.clone());

        // Not a plan the planner currently produces, which is the point: apply
        // must read the tag out of the plan instead of assuming Static.
        let plan = InterfaceChangePlan {
            interface: "eth0".to_string(),
            delete_ipv4: Vec::new(),
            retag_ipv4: Some(address_with_protocol(
                "192.168.50.1/24",
                Some(TRAFFIC_MASQ_DHCP_ADDRESS_PROTOCOL),
            )),
            add_ipv4: None,
            set_link_up: false,
            management_change: false,
            dhcp_action: DhcpChangeAction::Unchanged,
            releasing_management: false,
        };
        manager.apply_plan(&plan).await.expect("apply plan");

        let addresses = provider
            .list_ipv4_addresses("eth0")
            .await
            .expect("addresses");
        assert_eq!(
            addresses,
            vec![address_with_protocol(
                "192.168.50.1/24",
                Some(TRAFFIC_MASQ_DHCP_ADDRESS_PROTOCOL)
            )]
        );
    }

    #[tokio::test]
    async fn legacy_address_is_claimed_in_place_on_every_path() {
        let provider = Arc::new(FakeNetworkProvider::default());
        provider
            .add_interface(
                "eth0",
                true,
                vec![address_with_protocol("192.168.50.1/24", None)],
            )
            .await;
        let manager = InterfaceManager::new(provider);
        let desired = config(InterfaceRole::Output, "192.168.50.1/24");

        // The startup/reconcile path and the transactional path must agree:
        // both claim the untagged address rather than one of them adopting it
        // silently and the other tearing it down.
        let startup = manager
            .plan_interface("eth0", &desired, Some(InterfaceRole::Output), false)
            .await
            .expect("startup plan");
        let explicit = manager
            .plan_interface_transition(
                "eth0",
                &desired,
                Some(&desired),
                Some(InterfaceRole::Output),
                false,
            )
            .await
            .expect("explicit plan");

        for plan in [&startup, &explicit] {
            assert!(
                plan.delete_ipv4.is_empty(),
                "claiming an address must not take it off the link"
            );
            assert!(plan.add_ipv4.is_none());
            assert_eq!(
                plan.retag_ipv4
                    .as_ref()
                    .and_then(|address| address.protocol),
                Some(TRAFFIC_MASQ_ADDRESS_PROTOCOL)
            );
        }
    }

    #[tokio::test]
    async fn claiming_a_legacy_address_keeps_it_on_the_link() {
        let provider = Arc::new(FakeNetworkProvider::default());
        provider
            .add_interface(
                "eth0",
                true,
                vec![address_with_protocol("192.168.50.1/24", None)],
            )
            .await;
        let manager = InterfaceManager::new(provider.clone());
        let desired = config(InterfaceRole::Output, "192.168.50.1/24");

        manager
            .apply_interface_transition(
                "eth0",
                &desired,
                Some(&desired),
                Some(InterfaceRole::Output),
                false,
            )
            .await
            .expect("apply");

        let addresses = provider
            .list_ipv4_addresses("eth0")
            .await
            .expect("addresses");
        assert_eq!(
            addresses,
            vec![address_with_protocol(
                "192.168.50.1/24",
                Some(TRAFFIC_MASQ_ADDRESS_PROTOCOL)
            )],
            "the address must be the same one, now tagged — not a replacement"
        );
    }

    #[tokio::test]
    async fn an_unrelated_edit_leaves_an_owned_address_untouched() {
        let provider = Arc::new(FakeNetworkProvider::default());
        provider
            .add_interface(
                "eth0",
                true,
                vec![address_with_protocol(
                    "192.168.50.1/24",
                    Some(TRAFFIC_MASQ_ADDRESS_PROTOCOL),
                )],
            )
            .await;
        let manager = InterfaceManager::new(provider);
        let desired = config(InterfaceRole::Output, "192.168.50.1/24");

        let plan = manager
            .plan_interface_transition(
                "eth0",
                &desired,
                Some(&desired),
                Some(InterfaceRole::Output),
                false,
            )
            .await
            .expect("plan");

        assert!(plan.delete_ipv4.is_empty());
        assert!(plan.add_ipv4.is_none());
        assert!(plan.retag_ipv4.is_none());
    }

    #[tokio::test]
    async fn refuses_management_change_without_confirmation() {
        let provider = Arc::new(FakeNetworkProvider::default());
        provider.add_interface("eth0", true, Vec::new()).await;
        let manager = InterfaceManager::new(provider);

        let error = manager
            .apply_interface(
                "eth0",
                &config(InterfaceRole::Management, "192.168.1.20/24"),
                Some(InterfaceRole::Management),
                false,
            )
            .await
            .expect_err("management change should be rejected");

        assert!(error.to_string().contains("management interface"));
    }

    #[tokio::test]
    async fn refuses_relabelling_a_management_interface_without_confirmation() {
        let provider = Arc::new(FakeNetworkProvider::default());
        provider.add_interface("eth0", true, Vec::new()).await;
        let manager = InterfaceManager::new(provider);

        let error = manager
            .apply_interface(
                "eth0",
                &config(InterfaceRole::Output, "10.0.0.1/24"),
                Some(InterfaceRole::Management),
                false,
            )
            .await
            .expect_err("relabelling a management interface should be rejected");

        assert!(error.to_string().contains("management interface"));

        manager
            .apply_interface(
                "eth0",
                &config(InterfaceRole::Output, "10.0.0.1/24"),
                Some(InterfaceRole::Management),
                true,
            )
            .await
            .expect("explicit confirmation should allow the change");
    }

    #[test]
    fn management_change_is_symmetric_in_current_and_target_role() {
        assert!(is_management_change(
            InterfaceRole::Output,
            Some(InterfaceRole::Management)
        ));
        assert!(is_management_change(InterfaceRole::Management, None));
        assert!(is_management_change(
            InterfaceRole::Management,
            Some(InterfaceRole::Output)
        ));
        assert!(!is_management_change(
            InterfaceRole::Output,
            Some(InterfaceRole::Output)
        ));
        assert!(!is_management_change(InterfaceRole::Output, None));
    }

    #[tokio::test]
    async fn a_dhcp_client_interface_plans_no_address_change_and_never_oscillates() {
        let provider = Arc::new(FakeNetworkProvider::default());
        let dynamic = Ipv4AddressInfo {
            interface_index: 1,
            address: Ipv4Addr::new(192, 0, 2, 42),
            prefix_len: 24,
            protocol: None,
        };
        provider
            .add_interface("wan0", false, vec![dynamic.clone()])
            .await;
        let manager = InterfaceManager::new(provider.clone());

        let mut config = config(InterfaceRole::Input, "192.0.2.42/24");

        config.ipv4 = None;
        config.dhcp_client = Some(crate::config::DhcpClientInterfaceConfig::default());
        assert!(owns_dynamic_ipv4(&config));

        let plan = manager
            .plan_interface("wan0", &config, Some(InterfaceRole::Input), false)
            .await
            .expect("plan");
        assert!(plan.delete_ipv4.is_empty());
        assert!(plan.add_ipv4.is_none());
        assert!(plan.set_link_up);

        for _ in 0..5 {
            manager
                .apply_interface("wan0", &config, Some(InterfaceRole::Input), false)
                .await
                .expect("apply");
        }
        assert_eq!(
            provider
                .list_ipv4_addresses("wan0")
                .await
                .expect("addresses"),
            vec![dynamic]
        );
    }

    #[tokio::test]
    async fn a_disabled_dhcp_client_block_keeps_static_planning() {
        let provider = Arc::new(FakeNetworkProvider::default());
        provider
            .add_interface(
                "wan0",
                true,
                vec![Ipv4AddressInfo {
                    interface_index: 1,
                    address: Ipv4Addr::new(198, 51, 100, 9),
                    prefix_len: 24,
                    protocol: None,
                }],
            )
            .await;
        let manager = InterfaceManager::new(provider);

        let mut config = config(InterfaceRole::Input, "192.0.2.10/24");
        config.dhcp_client = Some(crate::config::DhcpClientInterfaceConfig {
            enabled: false,
            ..crate::config::DhcpClientInterfaceConfig::default()
        });
        assert!(!owns_dynamic_ipv4(&config));

        let plan = manager
            .plan_interface("wan0", &config, Some(InterfaceRole::Input), false)
            .await
            .expect("plan");
        assert_eq!(plan.delete_ipv4.len(), 1);
        assert!(plan.add_ipv4.is_some());
    }

    #[tokio::test]
    async fn apply_and_rollback_restore_interface_state() {
        let provider = Arc::new(FakeNetworkProvider::default());
        let original = Ipv4AddressInfo {
            interface_index: 1,
            address: Ipv4Addr::new(192, 168, 1, 10),
            prefix_len: 24,
            protocol: None,
        };
        provider
            .add_interface("usb0", false, vec![original.clone()])
            .await;
        let manager = InterfaceManager::new(provider.clone());
        let snapshot = manager.snapshot("usb0").await.expect("snapshot");

        manager
            .apply_interface(
                "usb0",
                &config(InterfaceRole::Output, "192.168.50.1/24"),
                Some(InterfaceRole::Output),
                false,
            )
            .await
            .expect("apply");
        let applied = provider
            .list_ipv4_addresses("usb0")
            .await
            .expect("addresses");
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].address, Ipv4Addr::new(192, 168, 50, 1));

        manager.rollback(&snapshot).await.expect("rollback");
        let restored = provider
            .list_ipv4_addresses("usb0")
            .await
            .expect("addresses");
        assert_eq!(restored, vec![original]);
        let interface = provider
            .list_interfaces()
            .await
            .expect("interfaces")
            .into_iter()
            .find(|interface| interface.name == "usb0")
            .expect("usb0");
        assert!(!interface.is_up);
    }

    #[tokio::test]
    async fn apply_network_skips_absent_managed_interface_and_applies_the_rest() {
        let provider = Arc::new(FakeNetworkProvider::default());
        provider.add_interface("eth0", false, Vec::new()).await;

        let manager = InterfaceManager::new(provider.clone());

        let mut network = NetworkConfig::default();
        network.interfaces.insert(
            "eth0".to_string(),
            config(InterfaceRole::Output, "192.168.50.1/24"),
        );
        network.interfaces.insert(
            "usb0".to_string(),
            config(InterfaceRole::Output, "192.168.60.1/24"),
        );

        let snapshots = manager
            .apply_network(&network, true)
            .await
            .expect("startup must succeed despite the absent managed interface");

        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].name, "eth0");
        let applied = provider
            .list_ipv4_addresses("eth0")
            .await
            .expect("addresses");
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].address, Ipv4Addr::new(192, 168, 50, 1));
    }

    #[tokio::test]
    async fn apply_network_still_rolls_back_on_a_real_failure_after_success() {
        let provider = Arc::new(FakeNetworkProvider::default());
        provider.add_interface("eth0", false, Vec::new()).await;
        provider.add_interface("mgmt0", true, Vec::new()).await;
        let manager = InterfaceManager::new(provider.clone());

        let mut network = NetworkConfig::default();
        network.interfaces.insert(
            "eth0".to_string(),
            config(InterfaceRole::Output, "192.168.50.1/24"),
        );

        network.interfaces.insert(
            "mgmt0".to_string(),
            config(InterfaceRole::Management, "192.168.70.1/24"),
        );

        let error = manager
            .apply_network(&network, false)
            .await
            .expect_err("management change without confirmation must fail");
        assert!(error.to_string().contains("failed to apply interface"));

        let restored = provider
            .list_ipv4_addresses("eth0")
            .await
            .expect("addresses");
        assert!(restored.is_empty());
    }
}
