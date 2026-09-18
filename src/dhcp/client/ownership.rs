use std::sync::Arc;

use crate::{
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
    #[error("interface identity changed for {interface}")]
    InterfaceIdentity { interface: String },
    #[error("address {address} already exists without exact ownership proof")]
    ForeignAddress { address: std::net::Ipv4Addr },
    #[error(
        "address {address} exists with prefix /{observed_prefix}, requested /{requested_prefix}"
    )]
    AddressPrefix {
        address: std::net::Ipv4Addr,
        observed_prefix: u8,
        requested_prefix: u8,
    },
    #[error("route conflicts with foreign or unrecorded kernel state")]
    ForeignRoute,
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
    #[error("network operation failed: {0}")]
    Network(#[source] anyhow::Error),
    #[error("apply failed and cleanup remains necessary: {0}")]
    CleanupNeeded(String),
}

pub struct DhcpClientOwnershipApplier {
    network: Arc<dyn NetworkProvider>,
    store: DhcpClientLeaseStore,
}

impl DhcpClientOwnershipApplier {
    pub fn new(network: Arc<dyn NetworkProvider>, store: DhcpClientLeaseStore) -> Self {
        Self { network, store }
    }

    pub async fn apply(
        &self,
        mut lease: DhcpClientLease,
    ) -> Result<DhcpClientLease, OwnershipError> {
        lease.validate()?;
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
        for desired in &lease.owned_routes {
            let same_key = routes
                .iter()
                .filter(|route| route_key_matches(route, desired));
            for observed in same_key {
                if !route_complete_matches(observed, desired)
                    || !prior.as_ref().is_some_and(|record| {
                        same_identity(record, &lease) && record.owned_routes.contains(desired)
                    })
                {
                    return Err(OwnershipConflict::ForeignRoute.into());
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
                    self.network
                        .add_ipv4_route(&route_spec(route))
                        .await
                        .map_err(OwnershipError::Network)?;
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
            if cleaned.is_ok() {
                self.store.remove(&lease.interface)?;
                return Err(error);
            }
            return Err(OwnershipError::CleanupNeeded(error.to_string()));
        }
        lease.state = DhcpClientLeaseState::Bound;
        self.store.save(&lease)?;
        Ok(lease)
    }

    pub async fn adopt(
        &self,
        interface: &str,
        now_unix: u64,
    ) -> Result<Option<DhcpClientLease>, OwnershipError> {
        let Some(lease) = self.store.load(interface)? else {
            return Ok(None);
        };
        self.verify_identity(&lease).await?;
        if lease.expires_at_unix <= now_unix {
            self.cleanup(interface).await?;
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
        let Some(mut lease) = self.store.load(interface)? else {
            return Ok(None);
        };
        match self.verify_identity(&lease).await {
            Ok(()) => {}
            Err(OwnershipError::Conflict(OwnershipConflict::InterfaceMissing { .. })) => {
                self.store.remove(interface)?;
                return Ok(None);
            }
            Err(error) => return Err(error),
        }
        if lease.expires_at_unix <= now_unix {
            self.cleanup(interface).await?;
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
        let Some(mut lease) = self.store.load(interface)? else {
            return Ok(());
        };
        match self.verify_identity(&lease).await {
            Ok(()) => {}
            Err(OwnershipError::Conflict(OwnershipConflict::InterfaceMissing { .. })) => {
                self.store.remove(interface)?;
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
        if !addresses.iter().any(|item| address_complete_matches(item, lease)) {
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
        if addresses.iter().any(|item| address_complete_matches(item, lease)) || lease.owned_routes.iter().any(|owned| {
            routes
                .iter()
                .any(|route| route_complete_matches(route, owned))
        }) {
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
            if observed.iter().any(|item| address_complete_matches(item, lease)) {
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
            && observed_addresses.iter().any(|item| address_complete_matches(item, lease)))
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

fn address_complete_matches(address: &crate::netlink::Ipv4AddressInfo, lease: &DhcpClientLease) -> bool {
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
mod tests {
    use std::{net::Ipv4Addr, sync::Mutex};

    use anyhow::{bail, Result};
    use async_trait::async_trait;
    use ipnet::Ipv4Net;
    use tempfile::tempdir;

    use super::*;
    use crate::{
        dhcp::client::lease::DHCP_CLIENT_LEASE_SCHEMA_VERSION,
        netlink::{
            Ipv4AddressInfo, NetworkInterface, TRAFFIC_MASQ_ADDRESS_PROTOCOL,
            TRAFFIC_MASQ_ROUTE_PROTOCOL,
        },
    };

    #[derive(Default)]
    struct FakeNetwork {
        index: Mutex<u32>,
        mac: Mutex<Vec<u8>>,
        addresses: Mutex<Vec<Ipv4AddressInfo>>,
        routes: Mutex<Vec<Ipv4RouteInfo>>,
        route_adds: Mutex<usize>,
        fail_route_add: Mutex<Option<usize>>,
        hide_interface: Mutex<bool>,
    }

    impl FakeNetwork {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                index: Mutex::new(2),
                mac: Mutex::new(vec![2, 0, 0, 0, 0, 1]),
                ..Self::default()
            })
        }
    }

    #[async_trait]
    impl NetworkProvider for FakeNetwork {
        async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
            if *self.hide_interface.lock().unwrap() {
                return Ok(Vec::new());
            }
            Ok(vec![NetworkInterface {
                index: *self.index.lock().unwrap(),
                name: "eth0".into(),
                is_up: true,
                rx_bytes: 0,
                tx_bytes: 0,
                is_wireless: false,
            }])
        }
        async fn hardware_address(&self, _interface: &str) -> Result<Vec<u8>> {
            Ok(self.mac.lock().unwrap().clone())
        }
        async fn list_ipv4_addresses(&self, _interface: &str) -> Result<Vec<Ipv4AddressInfo>> {
            Ok(self.addresses.lock().unwrap().clone())
        }
        async fn set_link_up(&self, _name: &str) -> Result<()> {
            Ok(())
        }
        async fn set_link_down(&self, _name: &str) -> Result<()> {
            Ok(())
        }
        async fn add_ipv4_address(
            &self,
            _interface: &str,
            address: Ipv4Addr,
            prefix_len: u8,
            ownership: AddressOwnership,
        ) -> Result<()> {
            self.addresses.lock().unwrap().push(Ipv4AddressInfo {
                interface_index: *self.index.lock().unwrap(),
                address,
                prefix_len,
                protocol: ownership.protocol(),
            });
            Ok(())
        }
        async fn delete_ipv4_address(
            &self,
            _interface: &str,
            address: Ipv4Addr,
            prefix_len: u8,
        ) -> Result<()> {
            self.addresses
                .lock()
                .unwrap()
                .retain(|item| item.address != address || item.prefix_len != prefix_len);
            Ok(())
        }
        async fn list_ipv4_routes(&self) -> Result<Vec<Ipv4RouteInfo>> {
            Ok(self.routes.lock().unwrap().clone())
        }
        async fn add_ipv4_route(&self, route: &Ipv4RouteSpec) -> Result<()> {
            let mut count = self.route_adds.lock().unwrap();
            *count += 1;
            if *self.fail_route_add.lock().unwrap() == Some(*count) {
                bail!("injected route failure")
            }
            self.routes.lock().unwrap().push(Ipv4RouteInfo {
                destination: route.destination,
                gateway: route.gateway,
                output_interface_index: route.output_interface_index,
                table: route.table,
                metric: route.metric,
                protocol: route.protocol,
                scope: 0,
            });
            Ok(())
        }
        async fn delete_ipv4_route(&self, route: &Ipv4RouteInfo) -> Result<()> {
            self.routes.lock().unwrap().retain(|item| item != route);
            Ok(())
        }
    }

    fn route(destination: &str) -> DhcpClientOwnedRoute {
        DhcpClientOwnedRoute {
            destination: destination.parse::<Ipv4Net>().unwrap(),
            gateway: Some(Ipv4Addr::new(192, 0, 2, 1)),
            output_interface_index: Some(2),
            table: 254,
            metric: Some(100),
            protocol: TRAFFIC_MASQ_DHCP_ROUTE_PROTOCOL,
            scope: 0,
        }
    }

    fn lease() -> DhcpClientLease {
        DhcpClientLease {
            schema_version: DHCP_CLIENT_LEASE_SCHEMA_VERSION,
            state: DhcpClientLeaseState::PendingApply,
            interface: "eth0".into(),
            interface_index: 2,
            hardware_address: vec![2, 0, 0, 0, 0, 1],
            client_identifier: vec![1, 2, 0, 0, 0, 0, 1],
            server_identifier: Ipv4Addr::new(192, 0, 2, 1),
            address: Ipv4Addr::new(192, 0, 2, 20),
            prefix_len: 24,
            routers: vec![Ipv4Addr::new(192, 0, 2, 1)],
            dns_servers: vec![Ipv4Addr::new(192, 0, 2, 53)],
            lease_seconds: 3600,
            renewal_seconds: 1800,
            rebinding_seconds: 3150,
            expires_at_unix: 10_000,
            owned_routes: vec![route("0.0.0.0/0")],
        }
    }

    fn fixture(
        network: Arc<FakeNetwork>,
    ) -> (
        tempfile::TempDir,
        DhcpClientLeaseStore,
        DhcpClientOwnershipApplier,
    ) {
        let directory = tempdir().unwrap();
        let store = DhcpClientLeaseStore::new(directory.path()).unwrap();
        let applier = DhcpClientOwnershipApplier::new(network, store.clone());
        (directory, store, applier)
    }

    #[tokio::test]
    async fn successful_apply_adopt_and_cleanup_preserves_unrelated_state() {
        let network = FakeNetwork::new();
        network.addresses.lock().unwrap().push(Ipv4AddressInfo {
            interface_index: 2,
            address: Ipv4Addr::new(198, 51, 100, 9),
            prefix_len: 27,
            protocol: None,
        });
        let (_dir, store, applier) = fixture(network.clone());
        let bound = applier.apply(lease()).await.unwrap();
        assert_eq!(bound.state, DhcpClientLeaseState::Bound);
        assert_eq!(applier.adopt("eth0", 5_000).await.unwrap(), Some(bound));
        applier.cleanup("eth0").await.unwrap();
        assert!(store.load("eth0").unwrap().is_none());
        assert_eq!(
            network.addresses.lock().unwrap().as_slice(),
            &[Ipv4AddressInfo {
                interface_index: 2,
                address: Ipv4Addr::new(198, 51, 100, 9),
                prefix_len: 27,
                protocol: None,
            }]
        );
        assert!(network.routes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn suspend_removes_kernel_state_but_keeps_lease_for_revalidation() {
        let network = FakeNetwork::new();
        let (_dir, store, applier) = fixture(network.clone());
        let bound = applier.apply(lease()).await.unwrap();

        let suspended = applier
            .suspend("eth0", 5_000)
            .await
            .unwrap()
            .expect("suspended lease");
        assert_eq!(suspended.state, DhcpClientLeaseState::Suspended);
        assert!(network.addresses.lock().unwrap().is_empty());
        assert!(network.routes.lock().unwrap().is_empty());
        assert_eq!(applier.adopt("eth0", 5_000).await.unwrap(), Some(suspended));
        assert!(store.load("eth0").unwrap().is_some());
        assert_eq!(bound.address, lease().address);
    }

    #[tokio::test]
    async fn unrecorded_identical_and_different_prefix_addresses_are_refused() {
        for prefix_len in [24, 25] {
            let network = FakeNetwork::new();
            network.addresses.lock().unwrap().push(Ipv4AddressInfo {
                interface_index: 2,
                address: lease().address,
                prefix_len,
                protocol: None,
            });
            let (_dir, _store, applier) = fixture(network.clone());
            let error = applier.apply(lease()).await.unwrap_err();
            assert!(matches!(
                error,
                OwnershipError::Conflict(OwnershipConflict::ForeignAddress { .. })
                    | OwnershipError::Conflict(OwnershipConflict::AddressPrefix { .. })
            ));
            assert_eq!(network.addresses.lock().unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn foreign_route_blocks_apply_and_is_not_deleted() {
        let network = FakeNetwork::new();
        let owned = route("0.0.0.0/0");
        network.routes.lock().unwrap().push(Ipv4RouteInfo {
            destination: owned.destination,
            gateway: owned.gateway,
            output_interface_index: owned.output_interface_index,
            table: owned.table,
            metric: owned.metric,
            protocol: TRAFFIC_MASQ_ROUTE_PROTOCOL,
            scope: owned.scope,
        });
        let (_dir, _store, applier) = fixture(network.clone());
        assert!(matches!(
            applier.apply(lease()).await,
            Err(OwnershipError::Conflict(OwnershipConflict::ForeignRoute))
        ));
        assert_eq!(
            network.routes.lock().unwrap()[0].protocol,
            TRAFFIC_MASQ_ROUTE_PROTOCOL
        );
        assert!(network.addresses.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn cleanup_never_removes_foreign_address_or_route_state() {
        let network = FakeNetwork::new();
        let (_dir, store, applier) = fixture(network.clone());
        let mut record = lease();
        record.state = DhcpClientLeaseState::CleanupNeeded;
        store.save(&record).unwrap();
        network.addresses.lock().unwrap().extend([
            Ipv4AddressInfo {
                interface_index: 2,
                address: record.address,
                prefix_len: 24,
                protocol: Some(TRAFFIC_MASQ_ADDRESS_PROTOCOL),
            },
            Ipv4AddressInfo {
                interface_index: 2,
                address: record.address,
                prefix_len: 25,
                protocol: None,
            },
        ]);
        let owned = &record.owned_routes[0];
        network.routes.lock().unwrap().extend([
            Ipv4RouteInfo {
                destination: owned.destination,
                gateway: owned.gateway,
                output_interface_index: owned.output_interface_index,
                table: owned.table,
                metric: owned.metric,
                protocol: TRAFFIC_MASQ_DHCP_ROUTE_PROTOCOL,
                scope: owned.scope,
            },
            Ipv4RouteInfo {
                destination: owned.destination,
                gateway: owned.gateway,
                output_interface_index: owned.output_interface_index,
                table: owned.table,
                metric: owned.metric,
                protocol: TRAFFIC_MASQ_ROUTE_PROTOCOL,
                scope: owned.scope,
            },
        ]);
        applier.cleanup("eth0").await.unwrap();
        assert_eq!(network.addresses.lock().unwrap().len(), 2);
        assert_eq!(
            network.addresses.lock().unwrap()[0].protocol,
            Some(TRAFFIC_MASQ_ADDRESS_PROTOCOL)
        );
        assert_eq!(
            network.routes.lock().unwrap()[0].protocol,
            TRAFFIC_MASQ_ROUTE_PROTOCOL
        );
    }

    #[tokio::test]
    async fn recorded_address_retagged_away_from_dhcp_ownership_is_refused() {
        let network = FakeNetwork::new();
        let (_dir, store, applier) = fixture(network.clone());
        let mut record = lease();
        record.state = DhcpClientLeaseState::Bound;
        store.save(&record).unwrap();
        network.addresses.lock().unwrap().push(Ipv4AddressInfo {
            interface_index: 2,
            address: record.address,
            prefix_len: record.prefix_len,
            protocol: Some(TRAFFIC_MASQ_ADDRESS_PROTOCOL),
        });

        assert!(matches!(
            applier.apply(lease()).await,
            Err(OwnershipError::Conflict(OwnershipConflict::ForeignAddress { .. }))
        ));
        assert_eq!(network.addresses.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn partial_route_failure_rolls_back_only_successful_mutations() {
        let network = FakeNetwork::new();
        *network.fail_route_add.lock().unwrap() = Some(2);
        let (_dir, store, applier) = fixture(network.clone());
        let mut desired = lease();
        desired.owned_routes.push(route("203.0.113.0/24"));
        assert!(applier.apply(desired).await.is_err());
        assert!(network.addresses.lock().unwrap().is_empty());
        assert!(network.routes.lock().unwrap().is_empty());
        assert!(store.load("eth0").unwrap().is_none());
    }

    #[tokio::test]
    async fn pending_crash_state_is_not_adopted_but_cleanup_state_recovers() {
        let network = FakeNetwork::new();
        let (_dir, store, applier) = fixture(network.clone());
        let pending = lease();
        store.save(&pending).unwrap();
        assert!(matches!(
            applier.adopt("eth0", 1).await,
            Err(OwnershipError::Conflict(
                OwnershipConflict::ObservationMismatch
            ))
        ));
        let mut cleanup = pending;
        cleanup.state = DhcpClientLeaseState::CleanupNeeded;
        store.save(&cleanup).unwrap();
        applier.cleanup("eth0").await.unwrap();
        assert!(store.load("eth0").unwrap().is_none());
    }

    #[tokio::test]
    async fn identity_mismatch_prevents_adopt_and_cleanup() {
        for mismatch_mac in [false, true] {
            let network = FakeNetwork::new();
            let (_dir, store, applier) = fixture(network.clone());
            let mut record = lease();
            record.state = DhcpClientLeaseState::Bound;
            store.save(&record).unwrap();
            if mismatch_mac {
                *network.mac.lock().unwrap() = vec![9; 6]
            } else {
                *network.index.lock().unwrap() = 9
            }
            assert!(matches!(
                applier.adopt("eth0", 1).await,
                Err(OwnershipError::Conflict(
                    OwnershipConflict::InterfaceIdentity { .. }
                ))
            ));
            assert!(matches!(
                applier.cleanup("eth0").await,
                Err(OwnershipError::Conflict(
                    OwnershipConflict::InterfaceIdentity { .. }
                ))
            ));
            assert!(store.load("eth0").unwrap().is_some());
        }
    }

    #[tokio::test]
    async fn expired_record_is_cleaned_exactly() {
        let network = FakeNetwork::new();
        let (_dir, store, applier) = fixture(network.clone());
        let bound = applier.apply(lease()).await.unwrap();
        assert!(matches!(
            applier.adopt("eth0", bound.expires_at_unix).await,
            Err(OwnershipError::Conflict(OwnershipConflict::Expired))
        ));
        assert!(store.load("eth0").unwrap().is_none());
        assert!(network.addresses.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn missing_interface_cleanup_removes_record_cleanly() {
        let network = FakeNetwork::new();
        let (_dir, store, applier) = fixture(network.clone());
        let _bound = applier.apply(lease()).await.unwrap();
        assert!(store.load("eth0").unwrap().is_some());

        *network.hide_interface.lock().unwrap() = true;
        applier
            .cleanup("eth0")
            .await
            .expect("missing interface cleanup must succeed");
        assert!(store.load("eth0").unwrap().is_none());
    }
}
