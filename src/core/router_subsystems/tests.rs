use crate::netlink::AddressOwnership;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::config::{
    AppConfig, DhcpInterfaceConfig, InterfaceConfig, InterfaceRole, RouterConfig, UplinkConfig,
    UplinkMode,
};
use crate::core::ownership::AddressOwnershipJournal;
use crate::core::router::RouterDesired;
use crate::firewall::{OwnedFirewallIntegrity, RouterDataplaneDesired};
use crate::netlink::{
    Ipv4AddressInfo, Ipv4RouteInfo, Ipv4RouteSpec, NetworkInterface, NetworkProvider,
};

use super::*;
use crate::test_support::FakeNetworkProvider;

struct FakeDataplaneProvider {
    state: Mutex<RouterDataplaneSnapshot>,
}

impl Default for FakeDataplaneProvider {
    fn default() -> Self {
        Self {
            state: Mutex::new(RouterDataplaneSnapshot {
                ipv4_forwarding: false,
                owned: None,
                owned_firewall_integrity: OwnedFirewallIntegrity::Intact,
            }),
        }
    }
}

#[async_trait]
impl RouterDataplaneProvider for FakeDataplaneProvider {
    async fn observe(&self) -> Result<RouterDataplaneSnapshot> {
        Ok(self.state.lock().await.clone())
    }

    async fn apply_owned(&self, desired: &RouterDataplaneDesired) -> Result<()> {
        let mut state = self.state.lock().await;
        state.ipv4_forwarding = true;
        state.owned = Some(desired.clone());
        Ok(())
    }

    async fn disable_owned(&self) -> Result<()> {
        self.state.lock().await.owned = None;
        Ok(())
    }

    async fn restore_owned(&self, snapshot: &RouterDataplaneSnapshot) -> Result<()> {
        *self.state.lock().await = snapshot.clone();
        Ok(())
    }
}

fn output_interface(address: &str, pool_start: u8, pool_end: u8) -> InterfaceConfig {
    let ipv4: ipnet::Ipv4Net = address.parse().expect("IPv4 network");
    let octet = ipv4.addr().octets()[2];
    InterfaceConfig {
        mac_address: None,
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

fn enabled_config() -> AppConfig {
    let mut config = AppConfig::default();
    config.network.interfaces.insert(
        "wan0".to_string(),
        InterfaceConfig {
            mac_address: None,
            role: InterfaceRole::Input,
            managed: false,
            ipv4: None,
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        },
    );
    config.network.interfaces.insert(
        "lan0".to_string(),
        output_interface("192.168.10.1/24", 100, 150),
    );
    config.router = RouterConfig {
        port_forwards: Vec::new(),
        forwarding: Some(vec![traffic_masq_dataplane::ForwardingConfig {
            from: "lan0".into(),
            to: "wan0".into(),
            source_subnet: Some("192.168.10.0/24".parse().unwrap()),
            masquerade: true,
        }]),
        vpn_chain: Vec::new(),
        uplink: Some(UplinkConfig {
            interface: "wan0".to_string(),
            mode: UplinkMode::External,
        }),
        owned_routes: Vec::new(),
        allow_default_route_change: false,
        route_host_traffic: false,
    };
    config
}

fn dhcp_less_output_interface(address: &str) -> InterfaceConfig {
    InterfaceConfig {
        mac_address: None,
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some(address.parse().expect("IPv4 network")),
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    }
}

async fn subsystems_for(
    network_config: &AppConfig,
) -> (
    ProductionRouterSubsystems<FakeDataplaneProvider>,
    Arc<FakeNetworkProvider>,
) {
    let provider = Arc::new(FakeNetworkProvider::permissive_addresses());
    provider
        .add_interface_with_state("wan0", 1, true, Vec::new())
        .await;
    provider
        .add_interface_with_state("lan0", 2, false, Vec::new())
        .await;

    let interfaces = InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory());
    let routes = RouteManager::new(provider.clone());
    let dhcp = DhcpSupervisor::start(&AppConfig::default())
        .await
        .expect("dhcp supervisor without any configured interfaces never binds a socket");
    let dataplane = RouterDataplaneManager::new(FakeDataplaneProvider::default());
    let subsystems = ProductionRouterSubsystems::new(
        interfaces,
        routes,
        dhcp,
        dataplane,
        vec!["wan0".to_string(), "lan0".to_string()],
    );
    let _ = network_config;
    (subsystems, provider)
}

#[tokio::test]
async fn planning_rejects_missing_dhcp_client_before_changing_runtime() {
    let mut config = enabled_config();
    let uplink = config.network.interfaces.get_mut("wan0").unwrap();
    uplink.managed = true;
    uplink.dhcp_client = Some(crate::config::DhcpClientInterfaceConfig::default());
    config.router.uplink.as_mut().unwrap().mode = UplinkMode::Dhcp;
    let desired = RouterDesired::from_effective_config(&config).unwrap();
    assert!(desired.uplink_dhcp.is_some());

    let (subsystems, provider) = subsystems_for(&config).await;
    let manager = crate::core::router::RouterManager::new(Arc::new(subsystems));
    let error = manager.plan(desired).await.unwrap_err();
    assert!(error
        .to_string()
        .contains("DHCP client runtime is unavailable"));
    assert!(provider
        .list_ipv4_addresses("lan0")
        .await
        .unwrap()
        .is_empty());
    assert!(provider
        .list_interfaces()
        .await
        .unwrap()
        .iter()
        .any(|interface| { interface.name == "lan0" && !interface.is_up }));
}

#[tokio::test]
async fn wired_router_snapshot_rolls_back_without_wifi_runtimes() {
    let mut config = enabled_config();
    config.network.interfaces.insert(
        "lan0".to_string(),
        dhcp_less_output_interface("192.168.10.1/24"),
    );
    let (subsystems, _) = subsystems_for(&config).await;
    let desired = RouterDesired::from_effective_config(&config).unwrap();
    let manager = crate::core::router::RouterManager::new(Arc::new(subsystems));
    let snapshot = manager.snapshot_for(&desired).await.unwrap();
    assert!(!snapshot.uplink_wifi.is_empty());
    assert!(!snapshot.output_wifi.is_empty());
    let failures = manager.rollback_to(&snapshot).await;
    assert!(failures.is_empty(), "{failures:?}");
}

#[tokio::test]
async fn wifi_rollback_releases_the_conflicting_radio_role() {
    #[derive(Default)]
    struct Radio {
        ap: Mutex<Option<WifiApSpec>>,
        station: Mutex<Option<WifiClientSpec>>,
    }
    #[async_trait]
    impl RouterApRuntime for Radio {
        async fn status(&self, _: &str) -> Option<(WifiApSpec, bool)> {
            self.ap.lock().await.clone().map(|spec| (spec, true))
        }
        async fn configure(&self, spec: WifiApSpec) -> Result<()> {
            anyhow::ensure!(self.station.lock().await.is_none(), "station owns radio");
            *self.ap.lock().await = Some(spec);
            Ok(())
        }
        async fn disable(&self, _: &str) -> Result<()> {
            *self.ap.lock().await = None;
            Ok(())
        }
    }
    #[async_trait]
    impl RouterStaRuntime for Radio {
        async fn status(&self, _: &str) -> Option<(WifiClientSpec, bool)> {
            self.station.lock().await.clone().map(|spec| (spec, true))
        }
        async fn configure(&self, spec: WifiClientSpec) -> Result<()> {
            anyhow::ensure!(self.ap.lock().await.is_none(), "AP owns radio");
            *self.station.lock().await = Some(spec);
            Ok(())
        }
        async fn disable(&self, _: &str) -> Result<()> {
            *self.station.lock().await = None;
            Ok(())
        }
    }
    let radio = Arc::new(Radio::default());
    let (subsystems, _) = subsystems_for(&enabled_config()).await;
    let subsystems = subsystems.with_wifi_runtimes(radio.clone(), radio.clone());
    let ap = WifiApSpec {
        interface: "wan0".into(),
        ssid: "old-ap".into(),
        country_code: None,
        band: crate::config::WifiBand::Ghz2,
        channel: 1,
        channel_width: crate::config::WifiChannelWidth::Ht20,
        security: crate::config::WifiSecurity::Open,
        hidden: false,
        client_isolation: false,
        max_stations: 32,
        passphrase_file: None,
    };
    let station = WifiClientSpec {
        interface: "wan0".into(),
        ssid: "upstream".into(),
        country_code: None,
        security: crate::config::WifiClientSecurity::Open,
        passphrase_file: None,
    };
    *radio.station.lock().await = Some(station.clone());
    subsystems
        .rollback_output_wifi(&[WifiSnapshot {
            interface: "wan0".into(),
            spec: Some(ap.clone()),
        }])
        .await
        .unwrap();
    assert_eq!(*radio.ap.lock().await, Some(ap));
    assert!(radio.station.lock().await.is_none());

    subsystems
        .rollback_uplink_wifi(&[WifiSnapshot {
            interface: "wan0".into(),
            spec: Some(station.clone()),
        }])
        .await
        .unwrap();
    assert_eq!(*radio.station.lock().await, Some(station));
    assert!(radio.ap.lock().await.is_none());
}

#[tokio::test]
async fn planning_a_runtime_router_is_observational_and_apply_adopts_interfaces() {
    let mut config = enabled_config();
    config.network.interfaces.insert(
        "lan0".to_string(),
        dhcp_less_output_interface("192.168.10.1/24"),
    );
    let (mut subsystems, provider) = subsystems_for(&config).await;
    // Start from "router disabled at boot": nothing is owned yet.
    subsystems.router_interfaces = RwLock::new(Vec::new());
    let _ = &provider;
    assert!(subsystems.owned_interfaces().await.is_empty());

    let desired = RouterDesired::from_effective_config(&config).expect("desired");
    let snapshot = subsystems.snapshot_for(&desired).await.expect("snapshot");

    assert!(
        !snapshot.interfaces.is_empty(),
        "a runtime-provisioned router must capture the interfaces it is about to touch"
    );
    assert!(
        subsystems.owned_interfaces().await.is_empty(),
        "snapshotting for a plan preview must not mutate router ownership"
    );

    subsystems.adopt_router_interfaces(&desired).await;
    let owned = subsystems.owned_interfaces().await;
    for entry in &desired.interfaces {
        assert!(
            owned.contains(&entry.name),
            "interface {} should be owned once execution begins",
            entry.name
        );
    }
}

/// Ownership widens when an intent is applied and narrows when it settles,
/// so it tracks the intent in force rather than every intent that ever was.
#[tokio::test]
async fn ownership_narrows_to_the_intent_that_settled() {
    let mut config = enabled_config();
    config.network.interfaces.insert(
        "lan0".to_string(),
        dhcp_less_output_interface("192.168.10.1/24"),
    );
    let (mut subsystems, _provider) = subsystems_for(&config).await;
    subsystems.router_interfaces = RwLock::new(vec!["old0".to_string(), "wan0".to_string()]);

    let desired = RouterDesired::from_effective_config(&config).expect("desired");
    subsystems.snapshot_for(&desired).await.expect("snapshot");

    // While the transaction is in flight the old interface is still owned,
    // because a rollback may still need to restore it.
    assert!(subsystems
        .owned_interfaces()
        .await
        .contains(&"old0".to_string()));

    let settled: Vec<String> = desired
        .interfaces
        .iter()
        .map(|entry| entry.name.clone())
        .collect();
    subsystems.retain_router_interfaces(&settled).await;

    // Ownership is kept sorted, so compare as sets rather than sequences.
    let owned = subsystems.owned_interfaces().await;
    let mut expected = settled.clone();
    expected.sort();
    assert_eq!(owned, expected);
    assert!(
        !owned.contains(&"old0".to_string()),
        "an interface the settled intent does not cover must be released"
    );
}

/// A removable adapter can vanish at any moment. When it does, it must not
/// take every router transaction down with it — including the one that
/// would drop it from the intent.
#[tokio::test]
async fn a_vanished_interface_does_not_block_router_transactions() {
    let mut config = enabled_config();
    config.network.interfaces.insert(
        "lan0".to_string(),
        dhcp_less_output_interface("192.168.10.1/24"),
    );
    let (mut subsystems, _provider) = subsystems_for(&config).await;
    // usb0 was part of a previous intent and has since been unplugged: it
    // is still owned, but the kernel knows nothing about it.
    subsystems.router_interfaces = RwLock::new(vec![
        "lan0".to_string(),
        "usb0".to_string(),
        "wan0".to_string(),
    ]);

    let desired = RouterDesired::from_effective_config(&config).expect("desired");

    let snapshot = subsystems
        .snapshot_for(&desired)
        .await
        .expect("a missing interface must not fail the snapshot");
    assert!(
        snapshot.interfaces.iter().any(|entry| entry.name == "wan0"),
        "interfaces that are present must still be captured"
    );
    assert!(
        snapshot.interfaces.iter().all(|entry| entry.name != "usb0"),
        "an absent interface has nothing to restore and must be skipped"
    );
}

#[tokio::test]
async fn full_round_trip_applies_interfaces_routes_and_dataplane() {
    let mut config = enabled_config();
    config.network.interfaces.insert(
        "lan0".to_string(),
        dhcp_less_output_interface("192.168.10.1/24"),
    );
    let (subsystems, provider) = subsystems_for(&config).await;
    let desired = RouterDesired::from_effective_config(&config).expect("desired");

    let plan = subsystems.plan_for(&desired).await.expect("router plan");
    assert_eq!(plan.interfaces.len(), 2);
    assert!(plan.uplink_wifi.is_empty());
    assert!(plan.output_wifi.is_empty());
    assert!(plan.dhcp.is_empty());
    assert!(plan.vpn_chain.hops.is_empty());

    subsystems
        .apply_interfaces(&plan.interfaces)
        .await
        .expect("apply interfaces");
    subsystems
        .apply_routes(&plan.routes)
        .await
        .expect("apply routes");
    subsystems
        .apply_dhcp(&plan.dhcp)
        .await
        .expect("apply dhcp (no-op)");
    subsystems
        .apply_dataplane(&plan.dataplane)
        .await
        .expect("apply dataplane");

    let addresses = provider
        .list_ipv4_addresses("lan0")
        .await
        .expect("addresses");
    assert_eq!(addresses.len(), 1);
    assert_eq!(addresses[0].address, Ipv4Addr::new(192, 168, 10, 1));

    subsystems
        .health_interfaces(&desired)
        .await
        .expect("interfaces healthy");
    subsystems
        .health_routes(&desired)
        .await
        .expect("routes healthy");
    subsystems
        .health_dhcp(&desired)
        .await
        .expect("dhcp healthy");
    subsystems
        .health_dataplane(&desired)
        .await
        .expect("dataplane healthy");
}

#[tokio::test]
async fn plan_dhcp_reports_start_for_a_newly_desired_interface_without_binding_a_socket() {
    let config = enabled_config();
    let (subsystems, _provider) = subsystems_for(&config).await;
    let desired = RouterDesired::from_effective_config(&config).expect("desired");

    let dhcp_plan = subsystems.plan_dhcp(&desired).await.expect("dhcp plan");
    assert_eq!(dhcp_plan.len(), 1);
    assert!(matches!(
        &dhcp_plan[0],
        DhcpPlan::Start { desired } if desired.interface == "lan0"
    ));
}

#[tokio::test]
async fn apply_interfaces_only_touches_router_scoped_interfaces() {
    let config = enabled_config();
    let (subsystems, provider) = subsystems_for(&config).await;
    provider
        .add_interface_with_state("mgmt0", 3, true, Vec::new())
        .await;
    provider.addresses.lock().await.insert(
        "mgmt0".to_string(),
        vec![Ipv4AddressInfo {
            interface_index: 3,
            address: Ipv4Addr::new(10, 0, 0, 1),
            prefix_len: 24,
            protocol: None,
        }],
    );
    let desired = RouterDesired::from_effective_config(&config).expect("desired");

    let plan = subsystems
        .plan_interfaces(&desired)
        .await
        .expect("interface plan");
    assert!(plan.iter().all(|item| item.interface != "mgmt0"));
    subsystems
        .apply_interfaces(&plan)
        .await
        .expect("apply interfaces");

    let mgmt_addresses = provider
        .list_ipv4_addresses("mgmt0")
        .await
        .expect("addresses");
    assert_eq!(mgmt_addresses.len(), 1);
    assert_eq!(mgmt_addresses[0].address, Ipv4Addr::new(10, 0, 0, 1));
}

#[tokio::test]
async fn a_subsystem_failure_is_not_absorbed_by_a_nested_rollback() {
    let config = enabled_config();
    let (subsystems, provider) = subsystems_for(&config).await;
    *provider.fail_next_add_route.lock().await = true;
    let plan = RoutePlan {
        add: vec![Ipv4RouteSpec {
            destination: "198.51.100.0/24".parse().expect("destination"),
            gateway: None,
            output_interface_index: Some(1),
            table: 254,
            metric: Some(100),
            protocol: crate::netlink::TRAFFIC_MASQ_ROUTE_PROTOCOL,
        }],
        delete: Vec::new(),
    };

    let error = subsystems
        .apply_routes(&plan)
        .await
        .expect_err("provider failure must propagate, not be retried by the adapter");
    assert!(format!("{error:#}").contains("injected route add failure"));
    assert!(provider.routes.lock().await.is_empty());
}

#[tokio::test]
async fn rollback_interfaces_is_best_effort_and_reports_every_failure() {
    let config = enabled_config();
    let (subsystems, _provider) = subsystems_for(&config).await;
    let snapshot = vec![
        InterfaceSnapshot {
            mac_address: None,
            name: "wan0".to_string(),
            was_up: true,
            ipv4_addresses: Vec::new(),
        },
        InterfaceSnapshot {
            mac_address: None,
            name: "missing0".to_string(),
            was_up: true,
            ipv4_addresses: Vec::new(),
        },
    ];

    let error = subsystems
        .rollback_interfaces(&snapshot)
        .await
        .expect_err("unknown interface must fail rollback");
    assert!(error.to_string().contains("missing0"));
    assert!(error.to_string().contains("incomplete"));
}

// --- VPN hop chain: `apply_vpn_chain`/`rollback_vpn_chain` -------------
//
// These use only `Relay` hops (route-only, no nftables mark/killswitch)
// rather than mixing in a real `Exit` hop, to avoid needing to also mock
// the nft nftables nftables round-trip (`FakeNftExecutor`'s exact
// request/response sequencing) for what is fundamentally a test about
// hop-activation *ordering*, not about the exit hop's firewall
// mechanics (which `vpn_policy_manager.rs`'s own tests already cover in
// detail).

use crate::core::vpn_chain::{VpnHopDesired, VpnHopKind, VpnHopRoutingDesired};
use crate::core::vpn_policy::VpnPolicyReservedIds;
use crate::firewall::vpn::test_support::FakeNftExecutor;
use crate::netlink::{Ipv4RuleInfo, Ipv4RuleSpec as NetIpv4RuleSpec};
use crate::vpn::active_profile::ActiveProfileStore;
use crate::vpn::store::WireGuardProfileStore;
use crate::vpn::wireguard::{WireGuardKey, WireGuardPeerConfig};
use crate::vpn::{ProviderError, VpnProvider};
use std::path::Path;
use std::sync::Mutex as StdMutex;

const VALID_PRIVATE_KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
const VALID_PUBLIC_KEY: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

fn valid_wg_config() -> String {
    format!(
        "[Interface]\n\
         PrivateKey = {VALID_PRIVATE_KEY}\n\
         Address = 10.0.0.2/24\n\
         \n\
         [Peer]\n\
         PublicKey = {VALID_PUBLIC_KEY}\n\
         AllowedIPs = 0.0.0.0/0\n\
         Endpoint = 203.0.113.1:51820\n"
    )
}

#[derive(Default)]
struct FakeChainVpnProvider {
    links: StdMutex<HashMap<String, bool>>,
    launch_markers: StdMutex<HashMap<String, String>>,
    endpoints: StdMutex<HashMap<String, Vec<std::net::SocketAddr>>>,
    fail_create: StdMutex<Option<String>>,
    fail_set_peers: StdMutex<Option<String>>,
    fail_delete: StdMutex<Option<String>>,
}

impl FakeChainVpnProvider {
    fn fail_create_link_for(&self, name: &str) {
        *self.fail_create.lock().unwrap() = Some(name.to_string());
    }

    fn fail_set_peers_for(&self, name: &str) {
        *self.fail_set_peers.lock().unwrap() = Some(name.to_string());
    }

    fn fail_delete_link_for(&self, name: &str) {
        *self.fail_delete.lock().unwrap() = Some(name.to_string());
    }
}

#[async_trait]
impl VpnProvider for FakeChainVpnProvider {
    async fn link_exists(&self, name: &str) -> Result<bool, ProviderError> {
        Ok(self.links.lock().unwrap().contains_key(name))
    }

    async fn create_link(
        &self,
        name: &str,
        _private_key: &WireGuardKey,
        _listen_port: Option<u16>,
        launch_marker: &str,
    ) -> Result<(), ProviderError> {
        if self.fail_create.lock().unwrap().as_deref() == Some(name) {
            return Err(ProviderError::CommandFailed {
                command: "create_link",
                status: "1".to_string(),
                stderr: format!("injected create_link failure for {name}"),
            });
        }
        self.links.lock().unwrap().insert(name.to_string(), false);
        self.launch_markers
            .lock()
            .unwrap()
            .insert(name.to_string(), launch_marker.to_string());
        Ok(())
    }

    async fn delete_link_if_launch_marker(
        &self,
        name: &str,
        launch_marker: &str,
    ) -> Result<bool, ProviderError> {
        let matches = self
            .launch_markers
            .lock()
            .unwrap()
            .get(name)
            .is_some_and(|marker| marker == launch_marker);
        if !matches {
            return Ok(false);
        }
        self.delete_link(name).await?;
        Ok(true)
    }

    async fn set_mtu(&self, _name: &str, _mtu: u32) -> Result<(), ProviderError> {
        Ok(())
    }

    async fn set_addresses(
        &self,
        name: &str,
        _addresses: &[ipnet::IpNet],
    ) -> Result<(), ProviderError> {
        self.require(name)
    }

    async fn set_peers(
        &self,
        name: &str,
        peers: &[WireGuardPeerConfig],
    ) -> Result<(), ProviderError> {
        if self.fail_set_peers.lock().unwrap().as_deref() == Some(name) {
            return Err(ProviderError::CommandFailed {
                command: "set_peers",
                status: "1".to_string(),
                stderr: format!("injected set_peers failure for {name}"),
            });
        }
        self.endpoints.lock().unwrap().insert(
            name.into(),
            peers
                .iter()
                .filter_map(|peer| match &peer.endpoint {
                    Some(crate::vpn::wireguard::WireGuardEndpoint::Address(address)) => {
                        Some(*address)
                    }
                    _ => None,
                })
                .collect(),
        );
        self.require(name)
    }

    async fn set_link_up(&self, name: &str) -> Result<(), ProviderError> {
        let mut links = self.links.lock().unwrap();
        let up = links
            .get_mut(name)
            .ok_or_else(|| ProviderError::NotFound(name.to_string()))?;
        *up = true;
        Ok(())
    }

    async fn set_link_down(&self, name: &str) -> Result<(), ProviderError> {
        let mut links = self.links.lock().unwrap();
        let up = links
            .get_mut(name)
            .ok_or_else(|| ProviderError::NotFound(name.to_string()))?;
        *up = false;
        Ok(())
    }

    async fn delete_link(&self, name: &str) -> Result<(), ProviderError> {
        if self.fail_delete.lock().unwrap().as_deref() == Some(name) {
            return Err(ProviderError::CommandFailed {
                command: "delete_link",
                status: "1".to_string(),
                stderr: format!("injected delete_link failure for {name}"),
            });
        }
        let removed = self.links.lock().unwrap().remove(name);
        self.launch_markers.lock().unwrap().remove(name);
        removed
            .map(|_| ())
            .ok_or_else(|| ProviderError::NotFound(name.to_string()))
    }

    async fn public_key(&self, name: &str) -> Result<Option<WireGuardKey>, ProviderError> {
        Ok(self
            .links
            .lock()
            .unwrap()
            .get(name)
            .map(|_| WireGuardKey::parse(VALID_PUBLIC_KEY, "test").unwrap()))
    }

    async fn peer_endpoints(&self, name: &str) -> Result<Vec<std::net::SocketAddr>, ProviderError> {
        self.require(name)?;
        Ok(self
            .endpoints
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .unwrap_or_default())
    }

    async fn is_up(&self, name: &str) -> Result<bool, ProviderError> {
        Ok(*self.links.lock().unwrap().get(name).unwrap_or(&false))
    }
}

impl FakeChainVpnProvider {
    fn require(&self, name: &str) -> Result<(), ProviderError> {
        if self.links.lock().unwrap().contains_key(name) {
            Ok(())
        } else {
            Err(ProviderError::NotFound(name.to_string()))
        }
    }
}

#[derive(Default)]
struct FakeChainNetworkProvider {
    interfaces: Mutex<HashMap<String, NetworkInterface>>,
    rules: Mutex<Vec<Ipv4RuleInfo>>,
    routes: Mutex<Vec<Ipv4RouteInfo>>,
}

impl FakeChainNetworkProvider {
    async fn add_interface(&self, name: &str, index: u32) {
        self.interfaces.lock().await.insert(
            name.to_string(),
            NetworkInterface {
                is_wireless: false,
                index,
                name: name.to_string(),
                is_up: true,
                rx_bytes: 0,
                tx_bytes: 0,
            },
        );
    }
}

#[async_trait]
impl NetworkProvider for FakeChainNetworkProvider {
    async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        Ok(self.interfaces.lock().await.values().cloned().collect())
    }

    async fn list_ipv4_addresses(&self, _interface: &str) -> Result<Vec<Ipv4AddressInfo>> {
        Ok(Vec::new())
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
        _address: Ipv4Addr,
        _prefix_len: u8,
        _ownership: AddressOwnership,
    ) -> Result<()> {
        Ok(())
    }

    async fn delete_ipv4_address(
        &self,
        _interface: &str,
        _address: Ipv4Addr,
        _prefix_len: u8,
    ) -> Result<()> {
        Ok(())
    }

    async fn list_ipv4_routes(&self) -> Result<Vec<Ipv4RouteInfo>> {
        Ok(self.routes.lock().await.clone())
    }

    async fn add_ipv4_route(&self, route: &Ipv4RouteSpec) -> Result<()> {
        self.routes.lock().await.push(Ipv4RouteInfo {
            destination: route.destination,
            gateway: route.gateway,
            output_interface_index: route.output_interface_index,
            table: route.table,
            metric: route.metric,
            protocol: route.protocol,
            scope: 253,
        });
        Ok(())
    }

    async fn delete_ipv4_route(&self, route: &Ipv4RouteInfo) -> Result<()> {
        self.routes.lock().await.retain(|current| current != route);
        Ok(())
    }

    async fn list_ipv4_rules(&self) -> Result<Vec<Ipv4RuleInfo>> {
        Ok(self.rules.lock().await.clone())
    }

    async fn add_ipv4_rule(&self, rule: &NetIpv4RuleSpec) -> Result<()> {
        self.rules.lock().await.push(Ipv4RuleInfo {
            source: rule.source,
            destination: rule.destination,
            table: rule.table,
            priority: rule.priority,
            fw_mark: rule.fw_mark,
            fw_mask: rule.fw_mask,
            input_interface: rule.input_interface.clone(),
            output_interface: rule.output_interface.clone(),
        });
        Ok(())
    }

    async fn delete_ipv4_rule(&self, rule: &Ipv4RuleInfo) -> Result<()> {
        self.rules.lock().await.retain(|current| current != rule);
        Ok(())
    }
}

fn relay_hop(hop_index: u32, interface: &str, upstream: &str) -> VpnHopDesired {
    VpnHopDesired {
        hop_index,
        profile_name: "chain.conf".to_string(),
        interface: interface.to_string(),
        upstream: upstream.to_string(),
        reserved: VpnPolicyReservedIds::for_hop(hop_index).expect("reserved ids"),
        kind: VpnHopKind::Relay {
            own_route: VpnHopRoutingDesired {
                hop_interface: interface.to_string(),
                upstream_interface: upstream.to_string(),
            },
        },
    }
}

async fn build_chain_subsystems(
    dir: &Path,
    vpn_provider: Arc<FakeChainVpnProvider>,
    net_provider: Arc<FakeChainNetworkProvider>,
) -> ProductionRouterSubsystems<FakeDataplaneProvider> {
    let interfaces = InterfaceManager::new(
        Arc::new(FakeNetworkProvider::permissive_addresses()),
        AddressOwnershipJournal::in_memory(),
    );
    let routes = RouteManager::new(Arc::new(FakeNetworkProvider::permissive_addresses()));
    let dhcp = DhcpSupervisor::start(&AppConfig::default())
        .await
        .expect("dhcp supervisor without any configured interfaces never binds a socket");
    let dataplane = RouterDataplaneManager::new(FakeDataplaneProvider::default());

    let wireguard_store = WireGuardProfileStore::new(dir.join("wireguard"));
    let vpn_provider_erased: Arc<dyn VpnProvider> = vpn_provider;
    ProductionRouterSubsystems::new(interfaces, routes, dhcp, dataplane, Vec::new()).with_vpn_chain(
        VpnChainDeps {
            standalone: Some(Arc::new(crate::vpn::VpnManager::new(
                crate::vpn::WireGuardVpnDriver::new(
                    vpn_provider_erased.clone(),
                    wireguard_store.clone(),
                ),
                crate::vpn::ActiveProfileStore::new(dir.join("vpn-active-profile.json")),
            ))),
            vpn_provider: vpn_provider_erased,
            wireguard_store,
            state_dir: dir.to_path_buf(),
            network: net_provider,
            nft_executor: Arc::new(FakeNftExecutor::default()),
        },
    )
}

async fn chain_subsystems() -> (
    ProductionRouterSubsystems<FakeDataplaneProvider>,
    Arc<FakeChainVpnProvider>,
    Arc<FakeChainNetworkProvider>,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let net_provider = Arc::new(FakeChainNetworkProvider::default());
    net_provider.add_interface("wan0", 1).await;

    let vpn_provider = Arc::new(FakeChainVpnProvider::default());
    let wireguard_store = WireGuardProfileStore::new(dir.path().join("wireguard"));
    wireguard_store
        .import(
            &crate::vpn::wireguard::WireGuardDriver,
            "chain.conf",
            valid_wg_config().as_bytes(),
        )
        .expect("import chain profile");
    let subsystems =
        build_chain_subsystems(dir.path(), vpn_provider.clone(), net_provider.clone()).await;
    (subsystems, vpn_provider, net_provider, dir)
}

async fn chain_snapshot(
    subsystems: &ProductionRouterSubsystems<FakeDataplaneProvider>,
) -> VpnChainSnapshot {
    let desired = RouterDesired::from_effective_config(&AppConfig::default()).unwrap();
    subsystems
        .snapshot_for(&desired)
        .await
        .expect("snapshot")
        .vpn_chain
}

#[tokio::test]
async fn apply_vpn_chain_activates_hops_in_order() {
    let (subsystems, vpn_provider, net, _dir) = chain_subsystems().await;
    net.add_interface("tm-wg-0", 2).await;
    net.add_interface("tm-wg-1", 3).await;
    let plan = VpnChainPlan {
        standalone: None,
        hops: vec![
            relay_hop(0, "tm-wg-0", "wan0"),
            relay_hop(1, "tm-wg-1", "tm-wg-0"),
            relay_hop(2, "tm-wg-2", "tm-wg-1"),
        ],
    };

    subsystems
        .apply_vpn_chain(&plan)
        .await
        .expect("3-hop chain activates");

    for name in ["tm-wg-0", "tm-wg-1", "tm-wg-2"] {
        assert!(
            vpn_provider.link_exists(name).await.expect("link_exists"),
            "{name} should be active after apply_vpn_chain"
        );
    }
}

/// If a mid-chain hop fails to activate, every hop this call already
/// activated must be rolled back — in reverse order — entirely inside
/// `apply_vpn_chain`, before it returns `Err`.
#[tokio::test]
async fn apply_vpn_chain_rolls_back_already_applied_hops_on_mid_chain_failure() {
    let (subsystems, vpn_provider, net, _dir) = chain_subsystems().await;
    net.add_interface("tm-wg-0", 2).await;
    net.add_interface("tm-wg-1", 3).await;
    vpn_provider.fail_create_link_for("tm-wg-2");

    let plan = VpnChainPlan {
        standalone: None,
        hops: vec![
            relay_hop(0, "tm-wg-0", "wan0"),
            relay_hop(1, "tm-wg-1", "tm-wg-0"),
            relay_hop(2, "tm-wg-2", "tm-wg-1"),
        ],
    };

    let error = subsystems
        .apply_vpn_chain(&plan)
        .await
        .expect_err("hop 2's activation failure must propagate");
    assert!(error.to_string().contains("tm-wg-2") || error.to_string().contains("hop"));

    for name in ["tm-wg-0", "tm-wg-1", "tm-wg-2"] {
        assert!(
            !vpn_provider.link_exists(name).await.expect("link_exists"),
            "{name} must have been rolled back after the mid-chain failure"
        );
    }
}

#[tokio::test]
async fn partial_wireguard_activation_removes_the_created_link() {
    let (subsystems, vpn_provider, _net, _dir) = chain_subsystems().await;
    vpn_provider.fail_set_peers_for("tm-wg-0");
    let plan = VpnChainPlan {
        standalone: None,
        hops: vec![relay_hop(0, "tm-wg-0", "wan0")],
    };

    subsystems
        .apply_vpn_chain(&plan)
        .await
        .expect_err("set_peers failure must propagate");

    assert!(
        !vpn_provider.link_exists("tm-wg-0").await.expect("link"),
        "driver-level compensation must delete a partially-created link"
    );
}

#[tokio::test]
async fn failed_wireguard_cleanup_remains_visible_to_outer_rollback() {
    let (subsystems, vpn_provider, _net, _dir) = chain_subsystems().await;
    vpn_provider.fail_set_peers_for("tm-wg-0");
    vpn_provider.fail_delete_link_for("tm-wg-0");
    let hop = relay_hop(0, "tm-wg-0", "wan0");
    let plan = VpnChainPlan {
        standalone: None,
        hops: vec![hop.clone()],
    };

    subsystems
        .apply_vpn_chain(&plan)
        .await
        .expect_err("activation cleanup failure must propagate");
    assert!(vpn_provider.link_exists("tm-wg-0").await.expect("link"));

    let recovery = chain_snapshot(&subsystems).await;
    assert!(recovery.previous_hops.contains(&hop));
    assert!(
        subsystems
            .rollback_vpn_chain(&VpnChainSnapshot::default())
            .await
            .is_err(),
        "foreign/unproven surviving link must keep rollback in failed state"
    );
}

#[tokio::test]
async fn vpn_chain_health_detects_and_repair_reinstalls_relay_rule() {
    let (subsystems, _vpn_provider, net, _dir) = chain_subsystems().await;
    net.add_interface("tm-wg-0", 2).await;
    let hop = relay_hop(0, "tm-wg-0", "wan0");
    let plan = VpnChainPlan {
        standalone: None,
        hops: vec![hop.clone()],
    };
    subsystems
        .apply_vpn_chain(&plan)
        .await
        .expect("initial apply");
    let mut desired = RouterDesired::from_effective_config(&AppConfig::default()).unwrap();
    desired.vpn_chain = vec![hop];
    net.rules.lock().await.clear();

    assert!(subsystems.health_vpn_chain(&desired).await.is_err());
    subsystems
        .apply_vpn_chain(&plan)
        .await
        .expect("repair apply");
    subsystems
        .health_vpn_chain(&desired)
        .await
        .expect("healthy after repair");
}

#[tokio::test]
async fn vpn_repair_keeps_obsolete_hops_until_teardown() {
    let (subsystems, vpn_provider, net, _dir) = chain_subsystems().await;
    net.add_interface("tm-wg-0", 2).await;
    let hop = relay_hop(0, "tm-wg-0", "wan0");
    subsystems
        .apply_vpn_chain(&VpnChainPlan {
            standalone: None,
            hops: vec![hop.clone()],
        })
        .await
        .unwrap();
    let desired = RouterDesired::from_effective_config(&AppConfig::default()).unwrap();
    assert!(subsystems.health_vpn_chain(&desired).await.is_err());
    subsystems.prepare_recovery(&desired).await.unwrap();
    assert_eq!(chain_snapshot(&subsystems).await.previous_hops, vec![hop]);
    subsystems
        .apply_vpn_chain(&VpnChainPlan {
            standalone: None,
            hops: vec![],
        })
        .await
        .unwrap();
    assert!(!vpn_provider.link_exists("tm-wg-0").await.unwrap());
    assert!(net.rules.lock().await.is_empty());
    assert!(net.routes.lock().await.is_empty());
    subsystems.health_vpn_chain(&desired).await.unwrap();
}

#[tokio::test]
async fn vpn_repair_keeps_hops_outside_the_recovered_desired_chain() {
    let (subsystems, _vpn_provider, net, _dir) = chain_subsystems().await;
    net.add_interface("tm-wg-0", 2).await;
    let first = relay_hop(0, "tm-wg-0", "wan0");
    let second = relay_hop(1, "tm-wg-1", "tm-wg-0");
    let hops = vec![first.clone(), second];
    subsystems
        .apply_vpn_chain(&VpnChainPlan {
            standalone: None,
            hops: hops.clone(),
        })
        .await
        .unwrap();
    let mut desired = RouterDesired::from_effective_config(&AppConfig::default()).unwrap();
    desired.vpn_chain = vec![first];
    subsystems.prepare_recovery(&desired).await.unwrap();
    assert_eq!(chain_snapshot(&subsystems).await.previous_hops, hops);
}

#[tokio::test]
async fn vpn_chain_restart_readopts_owned_hops_and_apply_is_idempotent() {
    let (subsystems, vpn_provider, net, dir) = chain_subsystems().await;
    net.add_interface("tm-wg-0", 2).await;
    let plan = VpnChainPlan {
        standalone: None,
        hops: vec![relay_hop(0, "tm-wg-0", "wan0")],
    };
    subsystems
        .apply_vpn_chain(&plan)
        .await
        .expect("initial apply");
    drop(subsystems);

    let restarted = build_chain_subsystems(dir.path(), vpn_provider.clone(), net.clone()).await;
    let mut desired =
        RouterDesired::from_effective_config(&AppConfig::default()).expect("disabled desired");
    desired.vpn_chain = plan.hops.clone();

    restarted
        .prepare_recovery(&desired)
        .await
        .expect("re-adopt persisted ownership");
    assert_eq!(chain_snapshot(&restarted).await.previous_hops, plan.hops);
    restarted
        .apply_vpn_chain(&plan)
        .await
        .expect("idempotent repair apply");

    assert!(vpn_provider.link_exists("tm-wg-0").await.expect("link"));
    assert_eq!(
        net.rules.lock().await.len(),
        1,
        "relay rule must not duplicate"
    );
    assert_eq!(
        net.routes.lock().await.len(),
        1,
        "relay route must not duplicate"
    );
}

#[tokio::test]
async fn vpn_chain_crash_recovery_rolls_candidate_back_to_snapshot() {
    let (subsystems, vpn_provider, net, dir) = chain_subsystems().await;
    net.add_interface("tm-wg-0", 2).await;
    let old_plan = VpnChainPlan {
        standalone: None,
        hops: vec![relay_hop(0, "tm-wg-0", "wan0")],
    };
    subsystems
        .apply_vpn_chain(&old_plan)
        .await
        .expect("old apply");
    let old_snapshot = chain_snapshot(&subsystems).await;

    let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
    store
        .import(
            &crate::vpn::wireguard::WireGuardDriver,
            "new.conf",
            valid_wg_config().as_bytes(),
        )
        .expect("import replacement profile");
    let mut replacement = relay_hop(0, "tm-wg-0", "wan0");
    replacement.profile_name = "new.conf".to_string();
    let candidate = VpnChainPlan {
        standalone: None,
        hops: vec![replacement.clone()],
    };
    subsystems
        .apply_vpn_chain(&candidate)
        .await
        .expect("candidate apply");
    drop(subsystems);

    let restarted = build_chain_subsystems(dir.path(), vpn_provider.clone(), net).await;
    let mut candidate_desired =
        RouterDesired::from_effective_config(&AppConfig::default()).expect("disabled desired");
    candidate_desired.vpn_chain = candidate.hops;
    restarted
        .prepare_recovery(&candidate_desired)
        .await
        .expect("recover candidate ownership");
    restarted
        .rollback_vpn_chain(&old_snapshot)
        .await
        .expect("rollback old snapshot");

    let persisted = ActiveProfileStore::for_hop(dir.path(), 0)
        .load()
        .await
        .expect("load active profile")
        .expect("active profile restored");
    assert_eq!(persisted.profile_name, "chain.conf");
    assert!(vpn_provider.link_exists("tm-wg-0").await.expect("link"));
}

#[tokio::test]
async fn host_policy_uses_live_kernel_endpoints_instead_of_resolving_profiles_again() {
    let (subsystems, provider, _, dir) = chain_subsystems().await;
    let plan = VpnChainPlan {
        standalone: None,
        hops: vec![relay_hop(0, "tm-wg-0", "wan0")],
    };
    subsystems.apply_vpn_chain(&plan).await.unwrap();
    let mut policy = crate::core::vpn_policy_manager::VpnPolicyDesired {
        masquerade_forwarded: true,
        route_host_traffic: true,
        chain_profiles: vec!["chain.conf".into()],
        protected_subnets: vec!["192.0.2.0/24".parse().unwrap()],
        vpn_interface: "tm-wg-0".into(),
        physical_uplink: "wan0".into(),
        host_endpoints: Vec::new(),
    };
    let first: std::net::SocketAddr = "203.0.113.45:51820".parse().unwrap();
    provider
        .endpoints
        .lock()
        .unwrap()
        .insert("tm-wg-0".into(), vec![first]);
    // Even an unavailable profile must not trigger a second resolution after
    // WireGuard has already been configured and its actual endpoint is known.
    std::fs::remove_file(dir.path().join("wireguard/chain.conf")).unwrap();
    let observed = subsystems
        .vpn_chain
        .with_host_endpoints(&policy)
        .await
        .unwrap();
    assert_eq!(
        observed.host_endpoints,
        vec!["203.0.113.45".parse::<Ipv4Addr>().unwrap()]
    );
    let roaming: std::net::SocketAddr = "198.51.100.27:51820".parse().unwrap();
    provider
        .endpoints
        .lock()
        .unwrap()
        .insert("tm-wg-0".into(), vec![roaming]);
    policy.host_endpoints = observed.host_endpoints;
    assert_eq!(
        subsystems
            .vpn_chain
            .with_host_endpoints(&policy)
            .await
            .unwrap()
            .host_endpoints,
        vec!["198.51.100.27".parse::<Ipv4Addr>().unwrap()]
    );
}

#[tokio::test]
async fn router_mac_change_pauses_station_and_restarts_it_with_the_new_identity() {
    struct StationRuntime {
        provider: Arc<FakeNetworkProvider>,
        spec: WifiClientSpec,
        calls: Mutex<Vec<(&'static str, [u8; 6])>>,
    }
    #[async_trait]
    impl RouterStaRuntime for StationRuntime {
        async fn status(&self, _: &str) -> Option<(WifiClientSpec, bool)> {
            Some((self.spec.clone(), true))
        }
        async fn configure(&self, _: WifiClientSpec) -> Result<()> {
            let mac = self.provider.mac_address("wan0").await?.unwrap();
            self.calls.lock().await.push(("start", mac));
            Ok(())
        }
        async fn disable(&self, _: &str) -> Result<()> {
            let mac = self.provider.mac_address("wan0").await?.unwrap();
            self.calls.lock().await.push(("stop", mac));
            Ok(())
        }
    }
    let (subsystems, provider) = subsystems_for(&enabled_config()).await;
    let previous = [0, 1, 2, 3, 4, 5];
    let next = [2, 6, 7, 8, 9, 10];
    provider.macs.lock().await.insert("wan0".into(), previous);
    let runtime = Arc::new(StationRuntime {
        provider: provider.clone(),
        spec: WifiClientSpec {
            interface: "wan0".into(),
            ssid: "upstream".into(),
            country_code: None,
            security: crate::config::WifiClientSecurity::Open,
            passphrase_file: None,
        },
        calls: Mutex::new(Vec::new()),
    });
    let subsystems = subsystems.with_station_runtime(runtime.clone());
    let mac = traffic_masq_protocol::MacAddr::new(next);
    subsystems
        .change_mac_with_consumers("wan0", mac)
        .await
        .unwrap();
    subsystems
        .change_mac_with_consumers("wan0", mac)
        .await
        .unwrap();
    assert_eq!(
        *runtime.calls.lock().await,
        vec![("stop", previous), ("start", next)]
    );
}

/// Real coordinator and VPN adapters shared by API contract tests; only OS I/O is simulated.
pub(crate) async fn standalone_coordinator(
    config: &AppConfig,
    overrides: crate::core::override_manager::RuntimeOverrideManager,
    tunnel: Arc<crate::vpn::ProductionVpnManager>,
    provider: Arc<dyn VpnProvider>,
    network: Arc<dyn NetworkProvider>,
    executor: Arc<dyn crate::firewall::NftExecutor>,
) -> crate::core::router_transaction::RouterTransactionCoordinator {
    let interfaces = Arc::new(FakeNetworkProvider::default());
    for (index, (name, config)) in config.network.interfaces.iter().enumerate() {
        interfaces.add_interface(name, index as u32 + 1).await;
        if let Some(address) = config.ipv4 {
            interfaces
                .add_ipv4_address(
                    name,
                    address.addr(),
                    address.prefix_len(),
                    AddressOwnership::Static,
                )
                .await
                .unwrap();
        }
    }
    let subsystems = ProductionRouterSubsystems::new(
        InterfaceManager::new(interfaces, AddressOwnershipJournal::in_memory()),
        RouteManager::new(network.clone()),
        DhcpSupervisor::start(config).await.unwrap(),
        RouterDataplaneManager::new(FakeDataplaneProvider::default()),
        vec![],
    )
    .with_vpn_chain(VpnChainDeps {
        standalone: Some(tunnel),
        vpn_provider: provider,
        wireguard_store: WireGuardProfileStore::new(config.vpn.wireguard_config_dir.clone()),
        state_dir: config.runtime.state_dir.clone(),
        network,
        nft_executor: executor,
    });
    crate::core::router_transaction::RouterTransactionCoordinator::new(
        crate::core::router::RouterManager::new(Arc::new(subsystems)),
        overrides,
        std::time::Duration::from_secs(config.security.rollback_timeout_seconds),
    )
}
