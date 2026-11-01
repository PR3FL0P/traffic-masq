use std::sync::Arc;

use crate::{
    core::mutation::InterfaceMutationLocks,
    dhcp::client::{
        lease::{
            DhcpClientLease, DhcpClientLeaseState, DhcpClientOwnedRoute, LeaseValidationError,
        },
        store::{DhcpClientLeaseStore, LeaseStoreError},
    },
    netlink::{
        AddressOwnership, Ipv4RouteInfo, Ipv4RouteSpec, NetworkProvider,
        TRAFFIC_MASQ_DHCP_ADDRESS_PROTOCOL, TRAFFIC_MASQ_DHCP_ROUTE_PROTOCOL,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OwnershipConflict {
    #[error("interface {interface} was not found")]
    InterfaceMissing { interface: String },
    #[error("interface identity changed for {interface}: expected ifindex={expected_index} mac={expected_mac:02x?}, observed ifindex={observed_index} mac={observed_mac:02x?}")]
    InterfaceIdentity {
        interface: String,
        expected_index: u32,
        expected_mac: Vec<u8>,
        observed_index: u32,
        observed_mac: Vec<u8>,
    },
    #[error("address {address} already exists without exact ownership proof; inspect `ip -4 -details address show` and reconfigure the DHCP client or service managing that address manually; traffic-masq will not adopt or delete it")]
    ForeignAddress { address: std::net::Ipv4Addr },
    #[error(
        "address {address} exists with prefix /{observed_prefix}, requested /{requested_prefix}"
    )]
    AddressPrefix {
        address: std::net::Ipv4Addr,
        observed_prefix: u8,
        requested_prefix: u8,
    },
    #[error("route conflicts with foreign or unrecorded kernel state: {diagnostics}")]
    ForeignRoute { diagnostics: String },
    #[error("persisted lease has expired")]
    Expired,
    #[error("persisted and observed kernel state do not match exactly")]
    ObservationMismatch,
}

#[derive(Debug, thiserror::Error)]
pub enum OwnershipError {
    #[error(transparent)]
    InvalidLease(#[from] LeaseValidationError),
    #[error(transparent)]
    Store(#[from] LeaseStoreError),
    #[error(transparent)]
    Conflict(#[from] OwnershipConflict),
    #[error("network operation failed: {0:#}")]
    Network(#[source] anyhow::Error),
    #[error("apply failed and cleanup remains necessary: {0}")]
    CleanupNeeded(String),
}

pub struct DhcpClientOwnershipApplier {
    network: Arc<dyn NetworkProvider>,
    store: DhcpClientLeaseStore,
    mutation_locks: InterfaceMutationLocks,
}

impl DhcpClientOwnershipApplier {
    /// Construct an isolated writer. Writers sharing kernel resources must
    /// supply the same locks through `new_with_mutation_locks`.
    pub fn new(network: Arc<dyn NetworkProvider>, store: DhcpClientLeaseStore) -> Self {
        Self::new_with_mutation_locks(network, store, InterfaceMutationLocks::default())
    }

    pub fn new_with_mutation_locks(
        network: Arc<dyn NetworkProvider>,
        store: DhcpClientLeaseStore,
        mutation_locks: InterfaceMutationLocks,
    ) -> Self {
        Self {
            network,
            store,
            mutation_locks,
        }
    }

    pub(crate) fn state_dir(&self) -> &std::path::Path {
        self.store
            .directory()
            .parent()
            .expect("DHCP store has a state directory")
    }

    pub(crate) fn persisted_interfaces(&self) -> Result<Vec<String>, OwnershipError> {
        Ok(self.store.interfaces()?)
    }

    pub(crate) fn persisted_lease(
        &self,
        interface: &str,
    ) -> Result<Option<DhcpClientLease>, OwnershipError> {
        Ok(self.store.load(interface)?)
    }

    pub async fn apply(
        &self,
        mut lease: DhcpClientLease,
    ) -> Result<DhcpClientLease, OwnershipError> {
        lease.validate()?;
        let _mutation = self.mutation_locks.lock(&lease.interface).await;
        self.verify_identity(&lease).await?;
        let prior = self.store.load(&lease.interface)?;
        let addresses = self
            .network
            .list_ipv4_addresses(&lease.interface)
            .await
            .map_err(OwnershipError::Network)?;
        let exact_recorded = prior.as_ref().is_some_and(|record| {
            same_identity(record, &lease)
                && record.address == lease.address
                && record.prefix_len == lease.prefix_len
        });
        let mut address_present = false;
        for address in addresses
            .iter()
            .filter(|item| item.address == lease.address)
        {
            if address.prefix_len != lease.prefix_len {
                return Err(OwnershipConflict::AddressPrefix {
                    address: lease.address,
                    observed_prefix: address.prefix_len,
                    requested_prefix: lease.prefix_len,
                }
                .into());
            }
            if !exact_recorded || address.protocol != Some(TRAFFIC_MASQ_DHCP_ADDRESS_PROTOCOL) {
                return Err(OwnershipConflict::ForeignAddress {
                    address: lease.address,
                }
                .into());
            }
            address_present = true;
        }

        let routes = self
            .network
            .list_ipv4_routes()
            .await
            .map_err(OwnershipError::Network)?;
        // Keep the effective metric stable across renewals, while retaining the
        // requested metric in policy so explicit configuration changes take effect.
        for desired in &mut lease.owned_routes {
            let requested_metric = desired.metric.unwrap_or(0);
            if let Some(previous) = prior
                .as_ref()
                .filter(|record| {
                    record.interface == lease.interface
                        && record.interface_index == lease.interface_index
                        && record.hardware_address == lease.hardware_address
                        && record.client_identifier == lease.client_identifier
                        && record.policy == lease.policy
                })
                .and_then(|record| {
                    record.owned_routes.iter().find(|route| {
                        route.destination == desired.destination
                            && route.gateway == desired.gateway
                            && route.table == desired.table
                            && route.output_interface_index == desired.output_interface_index
                            && route.metric.unwrap_or(0) >= requested_metric
                    })
                })
            {
                desired.metric = previous.metric;
            }
            loop {
                let collision = routes.iter().find(|observed| {
                    route_collision_matches(observed, desired)
                        && !(route_complete_matches(observed, desired)
                            && prior.as_ref().is_some_and(|record| {
                                record.interface == lease.interface
                                    && record.interface_index == lease.interface_index
                                    && record.hardware_address == lease.hardware_address
                                    && record.client_identifier == lease.client_identifier
                                    && record.owned_routes.contains(desired)
                            }))
                });
                if collision.is_none() {
                    break;
                }
                let Some(metric) = desired.metric.unwrap_or(0).checked_add(1) else {
                    return Err(OwnershipConflict::ForeignRoute {
                        diagnostics: format!("no lower-priority metric is available for DHCP route on {} in table {}; requested metric {}. Open Router to inspect routes, then DHCP Client > {} > e (edit) > Route metric > Apply DHCP client settings now", lease.interface, desired.table, requested_metric, lease.interface),
                    }.into());
                };
                desired.metric = Some(metric);
            }
            if desired.metric.unwrap_or(0) != requested_metric {
                tracing::warn!(
                    interface = %lease.interface,
                    requested_metric,
                    effective_metric = desired.metric.unwrap_or(0),
                    table = desired.table,
                    destination = %desired.destination,
                    "DHCP route metric adjusted to preserve existing routes. Set DHCP client route_metric to an unused value to choose priority; higher metrics have lower priority. The effective metric is stored with the lease."
                );
            }
        }
        for desired in &lease.owned_routes {
            let same_key = routes
                .iter()
                .filter(|route| route_collision_matches(route, desired));
            for observed in same_key {
                if !route_complete_matches(observed, desired)
                    || !prior.as_ref().is_some_and(|record| {
                        same_identity(record, &lease) && record.owned_routes.contains(desired)
                    })
                {
                    return Err(self.route_conflict(&lease, desired, observed).await);
                }
            }
        }

        lease.state = DhcpClientLeaseState::PendingApply;
        self.store.save(&lease)?;
        let mut added_address = false;
        let mut added_routes = Vec::new();
        let mutation = async {
            if !address_present {
                self.network
                    .add_ipv4_address(
                        &lease.interface,
                        lease.address,
                        lease.prefix_len,
                        AddressOwnership::DhcpClient,
                    )
                    .await
                    .map_err(OwnershipError::Network)?;
                added_address = true;
            }
            for route in &lease.owned_routes {
                if !routes
                    .iter()
                    .any(|observed| route_complete_matches(observed, route))
                {
                    if let Err(error) = self.network.add_ipv4_route(&route_spec(route)).await {
                        // Another manager may have installed a route since the preflight.
                        // Observe again for useful diagnostics; never adopt or replace it.
                        if let Ok(current) = self.network.list_ipv4_routes().await {
                            if let Some(observed) = current
                                .iter()
                                .find(|observed| route_collision_matches(observed, route))
                            {
                                return Err(self.route_conflict(&lease, route, observed).await);
                            }
                        }
                        return Err(OwnershipError::Network(error));
                    }
                    added_routes.push(route.clone());
                }
            }
            self.observe_exact(&lease).await
        }
        .await;

        if let Err(error) = mutation {
            lease.state = DhcpClientLeaseState::CleanupNeeded;
            self.store.save(&lease)?;
            let cleaned = self
                .rollback_added(&lease, added_address, &added_routes)
                .await;
            tracing::warn!(
                interface = %lease.interface,
                ifindex = lease.interface_index,
                address = %lease.address,
                prefix_len = lease.prefix_len,
                server = %lease.server_identifier,
                error = %error,
                rollback_succeeded = cleaned.is_ok(),
                rollback_error = ?cleaned.as_ref().err(),
                "Failed to apply DHCP lease; attempted rollback"
            );
            if cleaned.is_ok() {
                // Compensation removes only this attempt's additions. A
                // renewal may have reused the prior address/routes, whose
                // durable ownership proof must survive the failed update.
                match &prior {
                    Some(prior) => self.store.save(prior)?,
                    None => {
                        self.store.remove(&lease.interface)?;
                    }
                }
                return Err(error);
            }
            return Err(OwnershipError::CleanupNeeded(error.to_string()));
        }
        lease.state = DhcpClientLeaseState::Bound;
        self.store.save(&lease)?;
        Ok(lease)
    }

    async fn route_conflict(
        &self,
        lease: &DhcpClientLease,
        desired: &DhcpClientOwnedRoute,
        observed: &Ipv4RouteInfo,
    ) -> OwnershipError {
        let interfaces = self.network.list_interfaces().await.unwrap_or_default();
        let output = observed
            .output_interface_index
            .and_then(|index| interfaces.iter().find(|item| item.index == index))
            .map(|item| item.name.clone())
            .unwrap_or_else(|| format!("ifindex={:?}", observed.output_interface_index));
        OwnershipConflict::ForeignRoute {
                        diagnostics: format!(
                            "requested {} via {:?} dev {} metric {} table {}; existing {} via {:?} dev {} metric {} protocol {} ({}) table {}. The route protocol is not proof of its creating process. To keep the existing route, change DHCP route_metric on {} to an unused value (higher means lower preference), then retry. To remove the conflict, inspect `ip -4 -details route show table {}` and change the configuration of the manager that installed the existing route. traffic-masq will not replace or delete it",
                            desired.destination, desired.gateway, lease.interface,
                            desired.metric.unwrap_or(0), desired.table,
                            observed.destination, observed.gateway, output,
                            observed.metric.unwrap_or(0), observed.protocol, observed.owner(), observed.table,
                            lease.interface, observed.table,
                        ),
                    }.into()
    }

    pub async fn adopt(
        &self,
        interface: &str,
        now_unix: u64,
    ) -> Result<Option<DhcpClientLease>, OwnershipError> {
        let _mutation = self.mutation_locks.lock(interface).await;
        let Some(lease) = self.store.load(interface)? else {
            return Ok(None);
        };
        if self.retire_replaced_interface(&lease).await? {
            return Ok(None);
        }
        self.verify_identity(&lease).await?;
        if lease.expires_at_unix <= now_unix {
            self.cleanup_locked(interface).await?;
            return Err(OwnershipConflict::Expired.into());
        }
        match lease.state {
            DhcpClientLeaseState::Bound => self.observe_exact(&lease).await?,
            DhcpClientLeaseState::Suspended => self.verify_absent(&lease).await?,
            DhcpClientLeaseState::PendingApply | DhcpClientLeaseState::CleanupNeeded => {
                return Err(OwnershipConflict::ObservationMismatch.into())
            }
        }
        Ok(Some(lease))
    }

    pub async fn suspend(
        &self,
        interface: &str,
        now_unix: u64,
    ) -> Result<Option<DhcpClientLease>, OwnershipError> {
        let _mutation = self.mutation_locks.lock(interface).await;
        let Some(mut lease) = self.store.load(interface)? else {
            return Ok(None);
        };
        if self.retire_replaced_interface(&lease).await? {
            return Ok(None);
        }
        match self.verify_identity(&lease).await {
            Ok(()) => {}
            Err(OwnershipError::Conflict(OwnershipConflict::InterfaceMissing { .. })) => {
                self.retire_missing_interface(&lease).await?;
                return Ok(None);
            }
            Err(error) => return Err(error),
        }
        if lease.expires_at_unix <= now_unix {
            self.cleanup_locked(interface).await?;
            return Ok(None);
        }

        lease.state = DhcpClientLeaseState::CleanupNeeded;
        self.store.save(&lease)?;
        self.remove_owned_kernel_state(&lease).await?;
        self.verify_absent(&lease).await?;
        lease.state = DhcpClientLeaseState::Suspended;
        self.store.save(&lease)?;
        Ok(Some(lease))
    }

    pub async fn cleanup(&self, interface: &str) -> Result<(), OwnershipError> {
        let _mutation = self.mutation_locks.lock(interface).await;
        self.cleanup_locked(interface).await
    }

    /// An old actor must never clean ownership established by a replacement actor.
    /// Returns false when the callback was superseded and must leave shared status alone.
    pub(crate) async fn cleanup_for_identity(
        &self,
        interface: &str,
        index: u32,
        hardware_address: &[u8],
    ) -> Result<bool, OwnershipError> {
        let _mutation = self.mutation_locks.lock(interface).await;
        if let Some(record) = self.store.load(interface)? {
            if record.interface_index != index || record.hardware_address != hardware_address {
                tracing::debug!(%interface, index, "skipping DHCP cleanup from a superseded actor");
                return Ok(false);
            }
        }
        self.cleanup_locked(interface).await?;
        Ok(true)
    }

    /// Called only under the interface mutation lock. This retires a journal,
    /// never transfers its ownership proof or DHCP memory to the replacement.
    async fn retire_replaced_interface(
        &self,
        lease: &DhcpClientLease,
    ) -> Result<bool, OwnershipError> {
        let interfaces = self
            .network
            .list_interfaces()
            .await
            .map_err(OwnershipError::Network)?;
        let Some(current) = interfaces.iter().find(|item| item.name == lease.interface) else {
            return Ok(false);
        };
        if current.index == lease.interface_index
            || interfaces
                .iter()
                .any(|item| item.index == lease.interface_index)
        {
            // The old netdev may have been renamed, or its index reused. Keep
            // the journal for explicit recovery rather than orphaning its state.
            return Ok(false);
        }
        // Do not discard evidence if a provider still reports exact old state.
        self.verify_absent(lease).await?;
        let confirmed = self
            .network
            .list_interfaces()
            .await
            .map_err(OwnershipError::Network)?;
        if confirmed
            .iter()
            .any(|item| item.index == lease.interface_index)
            || !confirmed
                .iter()
                .any(|item| item.name == lease.interface && item.index == current.index)
        {
            return Err(OwnershipError::CleanupNeeded(
                "interface observation changed while retiring DHCP ownership; proof retained"
                    .into(),
            ));
        }
        self.store.remove(&lease.interface)?;
        tracing::info!(interface = %lease.interface, previous_index = lease.interface_index,
            current_index = current.index, "retired DHCP ownership for a vanished interface; fresh acquisition required");
        Ok(true)
    }

    /// An absent name alone is not evidence that its old kernel state vanished.
    /// A renamed netdev, reused ifindex, stale routes or failed observation must
    /// preserve the lease proof for recovery without deleting kernel state.
    async fn retire_missing_interface(
        &self,
        lease: &DhcpClientLease,
    ) -> Result<(), OwnershipError> {
        let verify_missing = |interfaces: &[crate::netlink::NetworkInterface]| {
            if interfaces
                .iter()
                .any(|item| item.name == lease.interface || item.index == lease.interface_index)
            {
                return Err(OwnershipError::CleanupNeeded(
                    "missing interface identity is still present or observation changed; ownership proof retained".into(),
                ));
            }
            Ok(())
        };
        let interfaces = self
            .network
            .list_interfaces()
            .await
            .map_err(OwnershipError::Network)?;
        verify_missing(&interfaces)?;
        let routes = self
            .network
            .list_ipv4_routes()
            .await
            .map_err(OwnershipError::Network)?;
        if lease.owned_routes.iter().any(|owned| {
            routes
                .iter()
                .any(|route| route_complete_matches(route, owned))
        }) {
            return Err(OwnershipError::CleanupNeeded(
                "owned routes remain for a missing interface; ownership proof retained".into(),
            ));
        }
        let interfaces = self
            .network
            .list_interfaces()
            .await
            .map_err(OwnershipError::Network)?;
        verify_missing(&interfaces)?;
        self.store.remove(&lease.interface)?;
        Ok(())
    }

    async fn cleanup_locked(&self, interface: &str) -> Result<(), OwnershipError> {
        let Some(mut lease) = self.store.load(interface)? else {
            return Ok(());
        };
        if self.retire_replaced_interface(&lease).await? {
            return Ok(());
        }
        match self.verify_identity(&lease).await {
            Ok(()) => {}
            Err(OwnershipError::Conflict(OwnershipConflict::InterfaceMissing { .. })) => {
                self.retire_missing_interface(&lease).await?;
                return Ok(());
            }
            Err(error) => return Err(error),
        }
        lease.state = DhcpClientLeaseState::CleanupNeeded;
        self.store.save(&lease)?;
        self.remove_owned_kernel_state(&lease).await?;
        self.verify_absent(&lease).await?;
        self.store.remove(interface)?;
        Ok(())
    }

    async fn remove_owned_kernel_state(
        &self,
        lease: &DhcpClientLease,
    ) -> Result<(), OwnershipError> {
        let routes = self
            .network
            .list_ipv4_routes()
            .await
            .map_err(OwnershipError::Network)?;
        for owned in lease.owned_routes.iter().rev() {
            if let Some(route) = routes
                .iter()
                .find(|route| route_complete_matches(route, owned))
            {
                self.network
                    .delete_ipv4_route(route)
                    .await
                    .map_err(OwnershipError::Network)?;
            }
        }
        let addresses = self
            .network
            .list_ipv4_addresses(&lease.interface)
            .await
            .map_err(OwnershipError::Network)?;
        if addresses
            .iter()
            .any(|item| address_complete_matches(item, lease))
        {
            self.network
                .delete_ipv4_address(&lease.interface, lease.address, lease.prefix_len)
                .await
                .map_err(OwnershipError::Network)?;
        }
        Ok(())
    }

    async fn verify_identity(&self, lease: &DhcpClientLease) -> Result<(), OwnershipError> {
        let interfaces = self
            .network
            .list_interfaces()
            .await
            .map_err(OwnershipError::Network)?;
        let interface = interfaces
            .iter()
            .find(|item| item.name == lease.interface)
            .ok_or_else(|| OwnershipConflict::InterfaceMissing {
                interface: lease.interface.clone(),
            })?;
        let hardware = self
            .network
            .hardware_address(&lease.interface)
            .await
            .map_err(OwnershipError::Network)?;
        if interface.index != lease.interface_index || hardware != lease.hardware_address {
            return Err(OwnershipConflict::InterfaceIdentity {
                interface: lease.interface.clone(),
                expected_index: lease.interface_index,
                expected_mac: lease.hardware_address.clone(),
                observed_index: interface.index,
                observed_mac: hardware,
            }
            .into());
        }
        Ok(())
    }

    pub(crate) async fn observe_exact(
        &self,
        lease: &DhcpClientLease,
    ) -> Result<(), OwnershipError> {
        let addresses = self
            .network
            .list_ipv4_addresses(&lease.interface)
            .await
            .map_err(OwnershipError::Network)?;
        if !addresses
            .iter()
            .any(|item| address_complete_matches(item, lease))
        {
            return Err(OwnershipConflict::ObservationMismatch.into());
        }
        let routes = self
            .network
            .list_ipv4_routes()
            .await
            .map_err(OwnershipError::Network)?;
        if !lease.owned_routes.iter().all(|owned| {
            routes
                .iter()
                .any(|route| route_complete_matches(route, owned))
        }) {
            return Err(OwnershipConflict::ObservationMismatch.into());
        }
        Ok(())
    }

    async fn verify_absent(&self, lease: &DhcpClientLease) -> Result<(), OwnershipError> {
        let addresses = self
            .network
            .list_ipv4_addresses(&lease.interface)
            .await
            .map_err(OwnershipError::Network)?;
        let routes = self
            .network
            .list_ipv4_routes()
            .await
            .map_err(OwnershipError::Network)?;
        if addresses
            .iter()
            .any(|item| address_complete_matches(item, lease))
            || lease.owned_routes.iter().any(|owned| {
                routes
                    .iter()
                    .any(|route| route_complete_matches(route, owned))
            })
        {
            return Err(OwnershipError::CleanupNeeded(
                "exact owned kernel state remains after cleanup".into(),
            ));
        }
        Ok(())
    }

    async fn rollback_added(
        &self,
        lease: &DhcpClientLease,
        address: bool,
        routes: &[DhcpClientOwnedRoute],
    ) -> Result<(), OwnershipError> {
        let observed = self
            .network
            .list_ipv4_routes()
            .await
            .map_err(OwnershipError::Network)?;
        for owned in routes.iter().rev() {
            if let Some(route) = observed
                .iter()
                .find(|route| route_complete_matches(route, owned))
            {
                self.network
                    .delete_ipv4_route(route)
                    .await
                    .map_err(OwnershipError::Network)?;
            }
        }
        if address {
            let observed = self
                .network
                .list_ipv4_addresses(&lease.interface)
                .await
                .map_err(OwnershipError::Network)?;
            if observed
                .iter()
                .any(|item| address_complete_matches(item, lease))
            {
                self.network
                    .delete_ipv4_address(&lease.interface, lease.address, lease.prefix_len)
                    .await
                    .map_err(OwnershipError::Network)?;
            }
        }
        let observed_addresses = self
            .network
            .list_ipv4_addresses(&lease.interface)
            .await
            .map_err(OwnershipError::Network)?;
        let observed_routes = self
            .network
            .list_ipv4_routes()
            .await
            .map_err(OwnershipError::Network)?;
        if (address
            && observed_addresses
                .iter()
                .any(|item| address_complete_matches(item, lease)))
            || routes.iter().any(|owned| {
                observed_routes
                    .iter()
                    .any(|route| route_complete_matches(route, owned))
            })
        {
            return Err(OwnershipError::CleanupNeeded(
                "partial apply rollback remains incomplete".into(),
            ));
        }
        Ok(())
    }
}

fn address_complete_matches(
    address: &crate::netlink::Ipv4AddressInfo,
    lease: &DhcpClientLease,
) -> bool {
    address.interface_index == lease.interface_index
        && address.address == lease.address
        && address.prefix_len == lease.prefix_len
        && address.protocol == Some(TRAFFIC_MASQ_DHCP_ADDRESS_PROTOCOL)
}

fn same_identity(left: &DhcpClientLease, right: &DhcpClientLease) -> bool {
    left.interface == right.interface
        && left.interface_index == right.interface_index
        && left.hardware_address == right.hardware_address
        && left.client_identifier == right.client_identifier
}

// Linux exclusive route creation collides on prefix/table/priority even
// when the nexthop points at another interface or gateway.
fn route_collision_matches(route: &Ipv4RouteInfo, owned: &DhcpClientOwnedRoute) -> bool {
    route.destination == owned.destination
        && route.table == owned.table
        && route.metric.unwrap_or(0) == owned.metric.unwrap_or(0)
}

fn route_key_matches(route: &Ipv4RouteInfo, owned: &DhcpClientOwnedRoute) -> bool {
    route.destination == owned.destination
        && route.gateway == owned.gateway
        && route.output_interface_index == owned.output_interface_index
        && route.table == owned.table
        && route.metric == owned.metric
}

fn route_complete_matches(route: &Ipv4RouteInfo, owned: &DhcpClientOwnedRoute) -> bool {
    route_key_matches(route, owned)
        && route.protocol == TRAFFIC_MASQ_DHCP_ROUTE_PROTOCOL
        && route.protocol == owned.protocol
        && route.scope == owned.scope
}

fn route_spec(route: &DhcpClientOwnedRoute) -> Ipv4RouteSpec {
    Ipv4RouteSpec {
        destination: route.destination,
        gateway: route.gateway,
        output_interface_index: route.output_interface_index,
        table: route.table,
        metric: route.metric,
        protocol: route.protocol,
    }
}

#[cfg(test)]
mod tests;
