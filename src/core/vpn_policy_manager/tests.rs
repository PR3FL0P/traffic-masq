use crate::netlink::AddressOwnership;
use std::sync::Mutex as StdMutex;

use async_trait::async_trait;

use super::*;
use crate::firewall::vpn::test_support::{nft_ruleset, FakeNftExecutor};
use crate::netlink::{Ipv4AddressInfo, NetworkInterface};
use crate::vpn::active_profile::ActiveProfileStore;
use crate::vpn::manager::OWNED_INTERFACE_NAME;
use crate::vpn::store::WireGuardProfileStore;
use crate::vpn::wireguard::WireGuardVpnDriver;

/// A router with one managed output subnet and an uplink — the minimum
/// shape `vpn_policy_desired` needs to produce a policy.
fn config_with_managed_output_and_uplink() -> AppConfig {
    use crate::config::{InterfaceConfig, RouterConfig, UplinkConfig, UplinkMode};

    let mut config = AppConfig::default();
    config.network.interfaces.insert(
        "wan0".to_string(),
        InterfaceConfig {
            role: InterfaceRole::Input,
            managed: false,
            ipv4: None,
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
            nat: true,
        },
    );
    config.network.interfaces.insert(
        "lan0".to_string(),
        InterfaceConfig {
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some("192.168.10.1/24".parse().expect("network")),
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
            nat: true,
        },
    );
    config.router = RouterConfig {
        enabled: true,
        uplink: Some(UplinkConfig {
            interface: "wan0".to_string(),
            mode: UplinkMode::External,
        }),
        owned_routes: Vec::new(),
        allow_default_route_change: false,
        forwarding: None,
        vpn_chain: Vec::new(),
    };
    config
}

#[test]
fn vpn_policy_desired_builds_from_managed_output_subnets_and_router_uplink() {
    let config = config_with_managed_output_and_uplink();

    let desired = vpn_policy_desired(&config).expect("desired");

    assert_eq!(desired.vpn_interface, OWNED_INTERFACE_NAME);
    assert_eq!(desired.physical_uplink, "wan0");
    assert_eq!(
        desired.protected_subnets,
        vec!["192.168.10.1/24".parse::<Ipv4Net>().unwrap()]
    );
}

#[test]
fn vpn_policy_desired_is_none_without_router_uplink() {
    let config = AppConfig::default();

    assert!(vpn_policy_desired(&config).is_none());
}

use crate::test_support::StaticKeyVpnProvider;
use crate::vpn::VpnProvider;

const VALID_PRIVATE_KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
const VALID_PUBLIC_KEY: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

fn valid_config() -> String {
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
struct FakeNetwork {
    interfaces: StdMutex<Vec<NetworkInterface>>,
    rules: StdMutex<Vec<Ipv4RuleInfo>>,
    routes: StdMutex<Vec<Ipv4RouteInfo>>,
    fail_next_add_route: StdMutex<bool>,
    fail_next_delete_rule: StdMutex<bool>,
}

impl FakeNetwork {
    fn with_interface(name: &str, index: u32) -> Arc<Self> {
        let network = Self::default();
        network.interfaces.lock().unwrap().push(NetworkInterface {
            is_wireless: false,
            index,
            name: name.to_string(),
            is_up: true,
            rx_bytes: 0,
            tx_bytes: 0,
        });
        Arc::new(network)
    }
}

#[async_trait]
impl NetworkProvider for FakeNetwork {
    async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        Ok(self.interfaces.lock().unwrap().clone())
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
        _address: std::net::Ipv4Addr,
        _prefix_len: u8,
        _ownership: AddressOwnership,
    ) -> Result<()> {
        Ok(())
    }

    async fn delete_ipv4_address(
        &self,
        _interface: &str,
        _address: std::net::Ipv4Addr,
        _prefix_len: u8,
    ) -> Result<()> {
        Ok(())
    }

    async fn list_ipv4_rules(&self) -> Result<Vec<Ipv4RuleInfo>> {
        Ok(self.rules.lock().unwrap().clone())
    }

    async fn add_ipv4_rule(&self, rule: &Ipv4RuleSpec) -> Result<()> {
        self.rules.lock().unwrap().push(Ipv4RuleInfo {
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
        if std::mem::take(&mut *self.fail_next_delete_rule.lock().unwrap()) {
            bail!("injected delete-rule failure");
        }
        self.rules.lock().unwrap().retain(|current| current != rule);
        Ok(())
    }

    async fn list_ipv4_routes(&self) -> Result<Vec<Ipv4RouteInfo>> {
        Ok(self.routes.lock().unwrap().clone())
    }

    async fn add_ipv4_route(&self, route: &Ipv4RouteSpec) -> Result<()> {
        let mut fail = self.fail_next_add_route.lock().unwrap();
        if *fail {
            *fail = false;
            bail!("injected add-route failure");
        }
        self.routes.lock().unwrap().push(Ipv4RouteInfo {
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
        self.routes
            .lock()
            .unwrap()
            .retain(|current| current != route);
        Ok(())
    }
}

fn desired() -> VpnPolicyDesired {
    VpnPolicyDesired {
        protected_subnets: vec!["192.168.10.0/24".parse().expect("subnet")],
        vpn_interface: OWNED_INTERFACE_NAME.to_string(),
        physical_uplink: "eth0".to_string(),
    }
}

type TestManager = VpnPolicyManager<WireGuardVpnDriver, FakeNftExecutor>;

fn manager_with(
    network: Arc<FakeNetwork>,
    firewall_executor: FakeNftExecutor,
) -> (TestManager, Arc<StaticKeyVpnProvider>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
    let active_profile_store = ActiveProfileStore::new(dir.path().join("active-profile.json"));
    let fake_provider = Arc::new(StaticKeyVpnProvider::default());
    let erased: Arc<dyn VpnProvider> = fake_provider.clone();
    let driver = WireGuardVpnDriver::new(erased, store);
    let tunnel = Arc::new(VpnManager::new(driver, active_profile_store));
    let firewall = VpnPolicyFirewallBackend::new(firewall_executor);
    let manager = VpnPolicyManager::new(network, firewall, tunnel);
    (manager, fake_provider, dir)
}

async fn activate_tunnel(manager: &TestManager) {
    manager
        .tunnel
        .import_profile("home.conf", valid_config().as_bytes())
        .expect("import");
    manager
        .tunnel
        .activate("home.conf")
        .await
        .expect("tunnel activate");
}

#[tokio::test]
async fn activate_installs_rules_routes_and_firewall_when_tunnel_is_healthy() {
    let network = FakeNetwork::with_interface(OWNED_INTERFACE_NAME, 42);

    let executor = FakeNftExecutor::with_responses(vec![
        Ok(nft_ruleset(None)),
        Ok(nft_ruleset(None)),
        Ok(Vec::new()),
    ]);
    let (manager, _provider, _dir) = manager_with(network.clone(), executor);
    activate_tunnel(&manager).await;

    let snapshot = manager.activate(&desired()).await.expect("activate policy");
    assert!(snapshot.rules.is_empty());
    assert!(snapshot.routes.is_empty());
    assert!(snapshot.firewall.is_none());

    let rules = network.list_ipv4_rules().await.expect("rules");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].fw_mark, Some(0x5400_0000));

    let routes = network.list_ipv4_routes().await.expect("routes");
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].output_interface_index, Some(42));
    assert_eq!(routes[0].table, 30_100);

    let calls = manager.firewall.executor.calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[2].0, ["-f", "-"]);
}

#[tokio::test]
async fn health_inactive_accepts_empty_policy_state() {
    let network = FakeNetwork::with_interface(OWNED_INTERFACE_NAME, 42);
    let executor = FakeNftExecutor::with_responses(vec![Ok(nft_ruleset(None))]);
    let (manager, _provider, _dir) = manager_with(network, executor);

    manager.health_inactive().await.expect("inactive policy");
}

#[tokio::test]
async fn health_accepts_fully_applied_policy() {
    let network = FakeNetwork::with_interface(OWNED_INTERFACE_NAME, 42);
    let firewall_desired = desired().firewall();
    let executor = FakeNftExecutor::with_responses(vec![
        Ok(nft_ruleset(None)),
        Ok(nft_ruleset(None)),
        Ok(Vec::new()),
        Ok(nft_ruleset(Some(&firewall_desired))),
    ]);
    let (manager, _provider, _dir) = manager_with(network, executor);
    activate_tunnel(&manager).await;
    manager.activate(&desired()).await.expect("activate");

    manager.health(&desired()).await.expect("healthy policy");
}

#[tokio::test]
async fn health_rejects_missing_routing_state() {
    let network = FakeNetwork::with_interface(OWNED_INTERFACE_NAME, 42);
    let executor = FakeNftExecutor::with_responses(vec![
        Ok(nft_ruleset(None)),
        Ok(nft_ruleset(None)),
        Ok(Vec::new()),
    ]);
    let (manager, _provider, _dir) = manager_with(network.clone(), executor);
    activate_tunnel(&manager).await;
    manager.activate(&desired()).await.expect("activate");
    network.rules.lock().unwrap().clear();

    assert!(manager.health(&desired()).await.is_err());
}

#[tokio::test]
async fn health_rejects_missing_firewall_state() {
    let network = FakeNetwork::with_interface(OWNED_INTERFACE_NAME, 42);
    let executor = FakeNftExecutor::with_responses(vec![
        Ok(nft_ruleset(None)),
        Ok(nft_ruleset(None)),
        Ok(Vec::new()),
        Ok(nft_ruleset(None)),
    ]);
    let (manager, _provider, _dir) = manager_with(network, executor);
    activate_tunnel(&manager).await;
    manager.activate(&desired()).await.expect("activate");

    assert!(manager.health(&desired()).await.is_err());
}

#[tokio::test]
async fn activate_with_explicit_reserved_ids_uses_the_same_conflict_namespace() {
    let network = FakeNetwork::with_interface(OWNED_INTERFACE_NAME, 42);
    let executor = FakeNftExecutor::with_responses(vec![
        Ok(nft_ruleset(None)),
        Ok(nft_ruleset(None)),
        Ok(Vec::new()),
    ]);
    let dir = tempfile::tempdir().expect("tempdir");
    let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
    let active_profile_store = ActiveProfileStore::new(dir.path().join("active-profile.json"));
    let provider = Arc::new(StaticKeyVpnProvider::default());
    let erased: Arc<dyn VpnProvider> = provider;
    let tunnel = Arc::new(VpnManager::new(
        WireGuardVpnDriver::new(erased, store),
        active_profile_store,
    ));
    let reserved = VpnPolicyReservedIds::for_hop(1).expect("hop ids");
    let manager = VpnPolicyManager::new_with_reserved(
        network.clone(),
        VpnPolicyFirewallBackend::new(executor),
        tunnel,
        reserved,
    );
    activate_tunnel(&manager).await;

    manager
        .activate(&desired())
        .await
        .expect("activate hop policy");

    let rules = network.list_ipv4_rules().await.expect("rules");
    assert_eq!(rules[0].table, reserved.route_table.get());
    assert_eq!(rules[0].priority, Some(reserved.rule_priority_start.get()));
}

#[tokio::test]
async fn activate_fails_closed_when_no_tunnel_is_active() {
    let network = FakeNetwork::with_interface(OWNED_INTERFACE_NAME, 42);
    let executor = FakeNftExecutor::with_responses(vec![]);
    let (manager, _provider, _dir) = manager_with(network.clone(), executor);

    let error = manager.activate(&desired()).await.unwrap_err();
    assert!(error.to_string().contains("no active VPN tunnel"));
    assert!(network.list_ipv4_rules().await.unwrap().is_empty());
    assert!(network.list_ipv4_routes().await.unwrap().is_empty());
}

#[tokio::test]
async fn activate_fails_closed_when_active_interface_does_not_match_desired() {
    let network = FakeNetwork::with_interface(OWNED_INTERFACE_NAME, 42);
    let executor = FakeNftExecutor::with_responses(vec![]);
    let (manager, _provider, _dir) = manager_with(network.clone(), executor);
    activate_tunnel(&manager).await;

    let mut mismatched = desired();
    mismatched.vpn_interface = "some-other-wg".to_string();

    let error = manager.activate(&mismatched).await.unwrap_err();
    assert!(error
        .to_string()
        .contains("does not match the expected VPN policy interface"));
    assert!(network.list_ipv4_rules().await.unwrap().is_empty());
}

#[tokio::test]
async fn activate_refuses_when_foreign_rule_occupies_reserved_space() {
    let network = FakeNetwork::with_interface(OWNED_INTERFACE_NAME, 42);
    network.rules.lock().unwrap().push(Ipv4RuleInfo {
        source: None,
        destination: None,
        table: 254,
        priority: Some(10_100),
        fw_mark: Some(0x5400_0000),
        fw_mask: Some(0xff00_0000),
        input_interface: None,
        output_interface: None,
    });
    let executor = FakeNftExecutor::with_responses(vec![]);
    let (manager, _provider, _dir) = manager_with(network.clone(), executor);
    activate_tunnel(&manager).await;

    let error = manager.activate(&desired()).await.unwrap_err();
    assert!(error
        .to_string()
        .contains("foreign objects occupy the reserved namespace"));

    assert_eq!(network.list_ipv4_rules().await.unwrap().len(), 1);
    assert!(manager.firewall.executor.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn activate_is_idempotent_when_already_applied() {
    let network = FakeNetwork::with_interface(OWNED_INTERFACE_NAME, 42);
    let firewall_desired = desired().firewall();
    let executor = FakeNftExecutor::with_responses(vec![
        Ok(nft_ruleset(None)),
        Ok(nft_ruleset(None)),
        Ok(Vec::new()),
        Ok(nft_ruleset(Some(&firewall_desired))),
        Ok(nft_ruleset(Some(&firewall_desired))),
    ]);
    let (manager, _provider, _dir) = manager_with(network.clone(), executor);
    activate_tunnel(&manager).await;

    manager.activate(&desired()).await.expect("first activate");
    manager
        .activate(&desired())
        .await
        .expect("second activate is idempotent");

    assert_eq!(network.list_ipv4_rules().await.unwrap().len(), 1);
    assert_eq!(network.list_ipv4_routes().await.unwrap().len(), 1);
}

#[tokio::test]
async fn activate_rolls_back_rule_when_route_installation_fails() {
    let network = FakeNetwork::with_interface(OWNED_INTERFACE_NAME, 42);
    *network.fail_next_add_route.lock().unwrap() = true;

    let executor =
        FakeNftExecutor::with_responses(vec![Ok(nft_ruleset(None)), Ok(nft_ruleset(None))]);
    let (manager, _provider, _dir) = manager_with(network.clone(), executor);
    activate_tunnel(&manager).await;

    let error = manager.activate(&desired()).await.unwrap_err();
    assert!(error
        .to_string()
        .contains("failed to install VPN policy IPv4 route"));

    assert!(network.list_ipv4_rules().await.unwrap().is_empty());
    assert!(network.list_ipv4_routes().await.unwrap().is_empty());

    assert_eq!(manager.firewall.executor.calls.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn activate_rolls_back_rule_and_route_when_firewall_apply_fails() {
    let network = FakeNetwork::with_interface(OWNED_INTERFACE_NAME, 42);

    let executor = FakeNftExecutor::with_responses(vec![
        Ok(nft_ruleset(None)),
        Ok(nft_ruleset(None)),
        Err(anyhow::anyhow!("injected nft apply failure")),
        Ok(nft_ruleset(None)),
    ]);
    let (manager, _provider, _dir) = manager_with(network.clone(), executor);
    activate_tunnel(&manager).await;

    let error = manager.activate(&desired()).await.unwrap_err();
    assert!(error
        .to_string()
        .contains("failed to apply VPN policy firewall"));

    assert!(network.list_ipv4_rules().await.unwrap().is_empty());
    assert!(network.list_ipv4_routes().await.unwrap().is_empty());
}

#[tokio::test]
async fn deactivate_removes_rules_and_routes_before_firewall() {
    let network = FakeNetwork::with_interface(OWNED_INTERFACE_NAME, 42);
    let firewall_desired = desired().firewall();
    let executor = FakeNftExecutor::with_responses(vec![
        Ok(nft_ruleset(None)),
        Ok(nft_ruleset(None)),
        Ok(Vec::new()),
        Ok(nft_ruleset(Some(&firewall_desired))),
        Ok(nft_ruleset(Some(&firewall_desired))),
        Ok(Vec::new()),
    ]);
    let (manager, _provider, _dir) = manager_with(network.clone(), executor);
    activate_tunnel(&manager).await;
    manager.activate(&desired()).await.expect("activate");

    manager.deactivate(&desired()).await.expect("deactivate");

    assert!(network.list_ipv4_rules().await.unwrap().is_empty());
    assert!(network.list_ipv4_routes().await.unwrap().is_empty());
    let calls = manager.firewall.executor.calls.lock().unwrap();

    assert_eq!(calls.len(), 6);
    assert_eq!(calls[5].0, ["-f", "-"]);
    let removal_batch = String::from_utf8(calls[5].1.clone()).unwrap();
    assert_eq!(removal_batch, "delete table inet traffic_masq_vpn\n");
}

#[tokio::test]
async fn failed_deactivation_restores_routes_and_rules() {
    for firewall_failure in [false, true] {
        let network = FakeNetwork::with_interface(OWNED_INTERFACE_NAME, 42);
        let firewall_desired = desired().firewall();
        let mut responses = vec![
            Ok(nft_ruleset(None)),
            Ok(nft_ruleset(None)),
            Ok(Vec::new()),
            Ok(nft_ruleset(Some(&firewall_desired))),
        ];
        if firewall_failure {
            responses.push(Ok(nft_ruleset(Some(&firewall_desired))));
            responses.push(Err(anyhow::anyhow!("injected firewall removal failure")));
        }
        responses.push(Ok(nft_ruleset(Some(&firewall_desired))));
        let executor = FakeNftExecutor::with_responses(responses);
        let (manager, _provider, _dir) = manager_with(network.clone(), executor);
        activate_tunnel(&manager).await;
        manager.activate(&desired()).await.unwrap();
        let routes = network.list_ipv4_routes().await.unwrap();
        let rules = network.list_ipv4_rules().await.unwrap();
        *network.fail_next_delete_rule.lock().unwrap() = !firewall_failure;

        assert!(manager.deactivate(&desired()).await.is_err());

        assert_eq!(network.list_ipv4_routes().await.unwrap(), routes);
        assert_eq!(network.list_ipv4_rules().await.unwrap(), rules);
    }
}

#[tokio::test]
async fn deactivate_is_robust_when_tunnel_interface_is_already_gone() {
    let network = Arc::new(FakeNetwork::default());
    network.rules.lock().unwrap().push(Ipv4RuleInfo {
        source: None,
        destination: None,
        table: 30_100,
        priority: Some(10_100),
        fw_mark: Some(0x5400_0000),
        fw_mask: Some(0xff00_0000),
        input_interface: None,
        output_interface: None,
    });
    network.routes.lock().unwrap().push(Ipv4RouteInfo {
        destination: "0.0.0.0/0".parse().unwrap(),
        gateway: None,
        output_interface_index: Some(999),
        table: 30_100,
        metric: Some(50),
        protocol: TRAFFIC_MASQ_ROUTE_PROTOCOL,
        scope: 253,
    });
    let executor =
        FakeNftExecutor::with_responses(vec![Ok(nft_ruleset(None)), Ok(nft_ruleset(None))]);
    let (manager, _provider, _dir) = manager_with(network.clone(), executor);

    manager
        .deactivate(&desired())
        .await
        .expect("deactivate despite missing interface");

    assert!(network.list_ipv4_rules().await.unwrap().is_empty());
    assert!(network.list_ipv4_routes().await.unwrap().is_empty());
}
