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
    extra_interfaces: Mutex<Vec<NetworkInterface>>,
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
        let mut interfaces = vec![NetworkInterface {
            index: *self.index.lock().unwrap(),
            name: "eth0".into(),
            is_up: true,
            rx_bytes: 0,
            tx_bytes: 0,
            is_wireless: false,
        }];
        interfaces.extend(self.extra_interfaces.lock().unwrap().clone());
        Ok(interfaces)
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
        policy: None,
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
        Err(OwnershipError::Conflict(
            OwnershipConflict::ForeignAddress { .. }
        ))
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
async fn failed_lease_update_preserves_prior_ownership_for_cleanup() {
    let network = FakeNetwork::new();
    let (_dir, store, applier) = fixture(network.clone());
    let prior = applier.apply(lease()).await.unwrap();
    *network.fail_route_add.lock().unwrap() = Some(2);
    let mut updated = lease();
    updated.owned_routes.push(route("203.0.113.0/24"));
    assert!(applier.apply(updated).await.is_err());
    assert_eq!(store.load("eth0").unwrap(), Some(prior));
    assert_eq!(network.addresses.lock().unwrap().len(), 1);
    assert_eq!(network.routes.lock().unwrap().len(), 1);
    applier.cleanup("eth0").await.unwrap();
    assert!(network.addresses.lock().unwrap().is_empty());
    assert!(network.routes.lock().unwrap().is_empty());
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
async fn mac_mismatch_prevents_adopt_and_cleanup() {
    for changed_index in [false, true] {
        let network = FakeNetwork::new();
        let (_dir, store, applier) = fixture(network.clone());
        let mut record = lease();
        record.state = DhcpClientLeaseState::Bound;
        store.save(&record).unwrap();
        *network.mac.lock().unwrap() = vec![9; 6];
        if changed_index {
            *network.index.lock().unwrap() = 9;
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

#[tokio::test]
async fn replaced_interface_retires_journal_without_touching_replacement_state() {
    for operation in ["adopt", "cleanup", "suspend"] {
        let network = FakeNetwork::new();
        let (_dir, store, applier) = fixture(network.clone());
        store.save(&lease()).unwrap();
        *network.index.lock().unwrap() = 9;
        let address = Ipv4AddressInfo {
            interface_index: 9,
            address: lease().address,
            prefix_len: 24,
            protocol: Some(TRAFFIC_MASQ_DHCP_ADDRESS_PROTOCOL),
        };
        network.addresses.lock().unwrap().push(address.clone());
        match operation {
            "adopt" => assert!(applier.adopt("eth0", 1).await.unwrap().is_none()),
            "suspend" => assert!(applier.suspend("eth0", 1).await.unwrap().is_none()),
            _ => applier.cleanup("eth0").await.unwrap(),
        }
        assert!(store.load("eth0").unwrap().is_none());
        assert_eq!(*network.addresses.lock().unwrap(), vec![address]);
        // A retired record is not proof of ownership on the new interface.
        let mut fresh = lease();
        fresh.interface_index = 9;
        fresh.owned_routes[0].output_interface_index = Some(9);
        assert!(matches!(
            applier.apply(fresh).await,
            Err(OwnershipError::Conflict(
                OwnershipConflict::ForeignAddress { .. }
            ))
        ));
    }
}

#[tokio::test]
async fn replaced_interface_with_observed_old_state_keeps_journal() {
    let network = FakeNetwork::new();
    let (_dir, store, applier) = fixture(network.clone());
    applier.apply(lease()).await.unwrap();
    *network.index.lock().unwrap() = 9;
    assert!(applier.cleanup("eth0").await.is_err());
    assert!(store.load("eth0").unwrap().is_some());
    assert_eq!(network.routes.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn stale_ack_is_rejected_before_mutation_with_identity_details() {
    let network = FakeNetwork::new();
    let (_dir, store, applier) = fixture(network.clone());
    *network.index.lock().unwrap() = 9;
    let error = applier.apply(lease()).await.unwrap_err();
    assert!(error.to_string().contains("expected ifindex=2"));
    assert!(error.to_string().contains("observed ifindex=9"));
    assert!(store.load("eth0").unwrap().is_none());
    assert!(network.addresses.lock().unwrap().is_empty());
    assert!(network.routes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn old_index_still_present_under_another_name_blocks_retirement() {
    let network = FakeNetwork::new();
    let (_dir, store, applier) = fixture(network.clone());
    store.save(&lease()).unwrap();
    *network.index.lock().unwrap() = 9;
    network
        .extra_interfaces
        .lock()
        .unwrap()
        .push(NetworkInterface {
            index: 2,
            name: "renamed0".into(),
            is_up: true,
            rx_bytes: 0,
            tx_bytes: 0,
            is_wireless: false,
        });
    assert!(matches!(
        applier.adopt("eth0", 1).await,
        Err(OwnershipError::Conflict(
            OwnershipConflict::InterfaceIdentity { .. }
        ))
    ));
    assert!(applier.cleanup("eth0").await.is_err());
    assert!(store.load("eth0").unwrap().is_some());
}
