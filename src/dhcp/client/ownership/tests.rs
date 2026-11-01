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

#[test]
fn network_error_preserves_underlying_failure_in_status_text() {
    let error = OwnershipError::Network(
        anyhow::anyhow!("Network is unreachable (os error 101)")
            .context("RTM_NEWROUTE while adding 0.0.0.0/0 in table 254"),
    );
    let text = error.to_string();
    assert!(text.contains("RTM_NEWROUTE"));
    assert!(text.contains("Network is unreachable (os error 101)"));
}

#[derive(Default)]
struct FakeNetwork {
    index: Mutex<u32>,
    mac: Mutex<Vec<u8>>,
    addresses: Mutex<Vec<Ipv4AddressInfo>>,
    routes: Mutex<Vec<Ipv4RouteInfo>>,
    route_adds: Mutex<usize>,
    fail_route_add: Mutex<Option<usize>>,
    hide_interface: Mutex<bool>,
    fail_observation: Mutex<bool>,
    fail_route_observation: Mutex<bool>,
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
        if *self.fail_observation.lock().unwrap() {
            bail!("injected device observation failure");
        }
        if *self.hide_interface.lock().unwrap() {
            return Ok(self.extra_interfaces.lock().unwrap().clone());
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
        if *self.fail_route_observation.lock().unwrap() {
            bail!("injected route observation failure");
        }
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
            scope: if route.gateway.is_some() { 0 } else { 253 },
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
async fn foreign_default_route_adjusts_metric_and_is_not_deleted() {
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
    let applied = applier.apply(lease()).await.unwrap();
    assert_eq!(applied.owned_routes[0].metric, Some(101));
    applier.cleanup("eth0").await.unwrap();
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
async fn mac_mismatch_on_a_present_index_prevents_adopt_and_cleanup() {
    let network = FakeNetwork::new();
    let (_dir, store, applier) = fixture(network.clone());
    let mut record = lease();
    record.state = DhcpClientLeaseState::Bound;
    store.save(&record).unwrap();
    *network.mac.lock().unwrap() = vec![9; 6];
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

    network.addresses.lock().unwrap().clear();
    network.routes.lock().unwrap().clear();
    *network.hide_interface.lock().unwrap() = true;
    applier
        .cleanup("eth0")
        .await
        .expect("missing interface cleanup must succeed");
    assert!(store.load("eth0").unwrap().is_none());
}

#[tokio::test]
async fn replaced_interface_retires_journal_without_touching_replacement_state() {
    for changed_mac in [false, true] {
        for operation in ["adopt", "cleanup", "suspend"] {
            let network = FakeNetwork::new();
            let (_dir, store, applier) = fixture(network.clone());
            store.save(&lease()).unwrap();
            *network.index.lock().unwrap() = 9;
            if changed_mac {
                *network.mac.lock().unwrap() = vec![2, 0, 0, 0, 0, 9];
            }
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
            fresh.hardware_address = network.mac.lock().unwrap().clone();
            fresh.owned_routes[0].output_interface_index = Some(9);
            assert!(matches!(
                applier.apply(fresh).await,
                Err(OwnershipError::Conflict(
                    OwnershipConflict::ForeignAddress { .. }
                ))
            ));
        }
    }
}

#[tokio::test]
async fn replaced_interface_with_observed_old_state_keeps_journal() {
    for changed_mac in [false, true] {
        let network = FakeNetwork::new();
        let (_dir, store, applier) = fixture(network.clone());
        applier.apply(lease()).await.unwrap();
        *network.index.lock().unwrap() = 9;
        if changed_mac {
            *network.mac.lock().unwrap() = vec![9; 6];
        }
        assert!(applier.cleanup("eth0").await.is_err());
        assert!(store.load("eth0").unwrap().is_some());
        assert_eq!(network.routes.lock().unwrap().len(), 1);
    }
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

#[tokio::test]
async fn missing_name_does_not_retire_renamed_identity_or_remaining_routes() {
    for renamed in [false, true] {
        for operation in ["cleanup", "suspend"] {
            let network = FakeNetwork::new();
            let (_dir, store, applier) = fixture(network.clone());
            let bound = applier.apply(lease()).await.unwrap();
            *network.hide_interface.lock().unwrap() = true;
            if renamed {
                network
                    .extra_interfaces
                    .lock()
                    .unwrap()
                    .push(NetworkInterface {
                        index: bound.interface_index,
                        name: "renamed0".into(),
                        is_up: true,
                        rx_bytes: 0,
                        tx_bytes: 0,
                        is_wireless: false,
                    });
            }
            let addresses = network.addresses.lock().unwrap().clone();
            let routes = network.routes.lock().unwrap().clone();
            let result = if operation == "cleanup" {
                applier.cleanup("eth0").await
            } else {
                applier
                    .suspend("eth0", bound.expires_at_unix - 1)
                    .await
                    .map(|_| ())
            };
            assert!(result.is_err(), "{operation}, renamed={renamed}");
            assert_eq!(store.load("eth0").unwrap(), Some(bound));
            assert_eq!(*network.addresses.lock().unwrap(), addresses);
            assert_eq!(*network.routes.lock().unwrap(), routes);
            network.extra_interfaces.lock().unwrap().clear();
            network.addresses.lock().unwrap().clear();
            network.routes.lock().unwrap().clear();
            applier.cleanup("eth0").await.unwrap();
            assert!(store.load("eth0").unwrap().is_none());
        }
    }
}

#[tokio::test]
async fn missing_cleanup_preserves_proof_when_device_or_route_observation_fails() {
    for routes_fail in [false, true] {
        let network = FakeNetwork::new();
        let (_dir, store, applier) = fixture(network.clone());
        let bound = applier.apply(lease()).await.unwrap();
        *network.hide_interface.lock().unwrap() = true;
        *network.fail_observation.lock().unwrap() = !routes_fail;
        *network.fail_route_observation.lock().unwrap() = routes_fail;
        assert!(applier.cleanup("eth0").await.is_err());
        assert_eq!(store.load("eth0").unwrap(), Some(bound));
    }
}

#[tokio::test]
async fn same_metric_default_selects_free_metric_and_preserves_it_on_renewal() {
    let network = FakeNetwork::new();
    network
        .extra_interfaces
        .lock()
        .unwrap()
        .push(NetworkInterface {
            index: 9,
            name: "other0".into(),
            is_up: true,
            rx_bytes: 0,
            tx_bytes: 0,
            is_wireless: false,
        });
    let desired = route("0.0.0.0/0");
    let foreign = Ipv4RouteInfo {
        destination: desired.destination,
        gateway: Some(Ipv4Addr::new(192, 168, 112, 1)),
        output_interface_index: Some(9),
        table: 254,
        metric: Some(100),
        protocol: 16,
        scope: 0,
    };
    network.routes.lock().unwrap().push(foreign.clone());
    let (_dir, store, applier) = fixture(network.clone());
    let mut occupied = foreign.clone();
    occupied.metric = Some(101);
    network.routes.lock().unwrap().push(occupied.clone());
    let applied = applier.apply(lease()).await.unwrap();
    assert_eq!(applied.owned_routes[0].metric, Some(102));
    assert_eq!(store.load("eth0").unwrap(), Some(applied.clone()));
    assert_eq!(
        applier.apply(lease()).await.unwrap().owned_routes,
        applied.owned_routes
    );
    assert_eq!(network.routes.lock().unwrap().len(), 3);
    assert_eq!(applier.adopt("eth0", 1).await.unwrap(), Some(applied));
    applier.cleanup("eth0").await.unwrap();
    assert_eq!(
        network.routes.lock().unwrap().as_slice(),
        &[foreign, occupied]
    );
    assert!(network.addresses.lock().unwrap().is_empty());
    assert!(store.load("eth0").unwrap().is_none());
}

#[tokio::test]
async fn different_metric_default_coexists_without_replacing_foreign_route() {
    let network = FakeNetwork::new();
    let foreign = Ipv4RouteInfo {
        destination: "0.0.0.0/0".parse().unwrap(),
        gateway: Some(Ipv4Addr::new(192, 168, 112, 1)),
        output_interface_index: Some(9),
        table: 254,
        metric: Some(100),
        protocol: 16,
        scope: 0,
    };
    network.routes.lock().unwrap().push(foreign.clone());
    let (_dir, _store, applier) = fixture(network.clone());
    let mut requested = lease();
    requested.owned_routes[0].metric = Some(200);
    applier.apply(requested).await.unwrap();
    applier.cleanup("eth0").await.unwrap();
    assert_eq!(network.routes.lock().unwrap().as_slice(), &[foreign]);
}

#[tokio::test]
async fn exhausted_default_metric_fails_without_mutation() {
    let network = FakeNetwork::new();
    let mut requested = lease();
    requested.owned_routes[0].metric = Some(u32::MAX);
    let owned = &requested.owned_routes[0];
    network.routes.lock().unwrap().push(Ipv4RouteInfo {
        destination: owned.destination,
        gateway: owned.gateway,
        output_interface_index: Some(9),
        table: owned.table,
        metric: owned.metric,
        protocol: 16,
        scope: owned.scope,
    });
    let (_dir, store, applier) = fixture(network.clone());
    assert!(applier
        .apply(requested)
        .await
        .unwrap_err()
        .to_string()
        .contains("no lower-priority metric"));
    assert!(network.addresses.lock().unwrap().is_empty());
    assert!(store.load("eth0").unwrap().is_none());
    assert_eq!(network.routes.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn subnet_route_collision_preserves_both_interfaces_through_renewal_and_cleanup() {
    let network = FakeNetwork::new();
    let mut candidate = lease();
    let mut subnet = route("192.0.2.0/24");
    subnet.gateway = None;
    subnet.metric = None;
    subnet.scope = 253;
    candidate.owned_routes.insert(0, subnet.clone());
    let existing = Ipv4RouteInfo {
        destination: subnet.destination,
        gateway: None,
        output_interface_index: Some(9),
        table: 254,
        metric: None,
        protocol: TRAFFIC_MASQ_DHCP_ROUTE_PROTOCOL,
        scope: 253,
    };
    network.routes.lock().unwrap().push(existing.clone());
    let (_directory, store, applier) = fixture(network.clone());
    let applied = applier.apply(candidate.clone()).await.unwrap();
    assert_eq!(applied.owned_routes[0].metric, Some(1));
    assert!(network.routes.lock().unwrap().contains(&existing));
    assert_eq!(
        applier.apply(candidate).await.unwrap().owned_routes,
        applied.owned_routes
    );
    assert_eq!(
        store.load("eth0").unwrap().unwrap().owned_routes,
        applied.owned_routes
    );
    applier.cleanup("eth0").await.unwrap();
    assert_eq!(*network.routes.lock().unwrap(), vec![existing]);
}
