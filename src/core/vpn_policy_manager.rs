use std::sync::Arc;

use anyhow::{bail, Context, Result};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use crate::config::{AppConfig, InterfaceRole};
use crate::core::vpn_policy::{
    VpnPolicyDesiredState, VpnPolicyReservedIds, VpnPolicyResourceConflictDetector,
};
use crate::firewall::vpn::{VpnPolicyFirewallBackend, VpnPolicyFirewallDesired};
use crate::firewall::NftExecutor;
use crate::netlink::{
    Ipv4RouteInfo, Ipv4RouteSpec, Ipv4RuleInfo, Ipv4RuleSpec, NetworkProvider,
    TRAFFIC_MASQ_ROUTE_PROTOCOL,
};
use crate::vpn::manager::OWNED_INTERFACE_NAME;
use crate::vpn::{VpnDriver, VpnManager};

const VPN_POLICY_ROUTE_METRIC: u32 = 50;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnPolicyDesired {
    pub protected_subnets: Vec<Ipv4Net>,
    pub vpn_interface: String,
    pub physical_uplink: String,
}

/// The VPN policy this configuration calls for, or `None` if there is nothing
/// to protect.
///
/// Lives beside [`VpnPolicyDesired`] rather than in `app`, where it used to sit:
/// deciding what the policy should be given a configuration is a domain rule,
/// not part of wiring the daemon together. Having it in `app` meant `api` had
/// to reach into `app` to ask the question, which closed a cycle between the
/// two.
pub fn vpn_policy_desired(config: &AppConfig) -> Option<VpnPolicyDesired> {
    if config.router.forwarding.is_some() { return None; }
    let uplink = config.router.uplink.as_ref()?;
    let protected_subnets: Vec<Ipv4Net> = config
        .network
        .interfaces
        .values()
        .filter(|interface| interface.role == InterfaceRole::Output && interface.managed)
        .filter_map(|interface| interface.ipv4)
        .collect();
    if protected_subnets.is_empty() {
        return None;
    }
    Some(VpnPolicyDesired {
        protected_subnets,
        vpn_interface: OWNED_INTERFACE_NAME.to_string(),
        physical_uplink: uplink.interface.clone(),
    })
}

/// The desired state that means "own nothing": used to find and remove whatever
/// a previous run installed.
pub fn vpn_policy_teardown_target() -> VpnPolicyDesired {
    VpnPolicyDesired {
        protected_subnets: Vec::new(),
        vpn_interface: OWNED_INTERFACE_NAME.to_string(),
        physical_uplink: String::new(),
    }
}

impl VpnPolicyDesired {
    fn firewall(&self) -> VpnPolicyFirewallDesired {
        VpnPolicyFirewallDesired {
            protected_subnets: self.protected_subnets.clone(),
            vpn_interface: self.vpn_interface.clone(),
            physical_uplink: self.physical_uplink.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VpnPolicySnapshot {
    rules: Vec<Ipv4RuleInfo>,
    routes: Vec<Ipv4RouteInfo>,
    firewall: Option<VpnPolicyFirewallDesired>,
}

impl VpnPolicySnapshot {
    pub fn is_active(&self) -> bool {
        !self.rules.is_empty()
    }
}

pub struct VpnPolicyManager<D: VpnDriver, E: NftExecutor> {
    network: Arc<dyn NetworkProvider>,
    conflicts: VpnPolicyResourceConflictDetector,
    firewall: VpnPolicyFirewallBackend<E>,
    tunnel: Arc<VpnManager<D>>,
    reserved: VpnPolicyReservedIds,
}

impl<D: VpnDriver, E: NftExecutor> VpnPolicyManager<D, E> {
    pub fn new(
        network: Arc<dyn NetworkProvider>,
        firewall: VpnPolicyFirewallBackend<E>,
        tunnel: Arc<VpnManager<D>>,
    ) -> Self {
        Self::new_with_reserved(network, firewall, tunnel, VpnPolicyReservedIds::default())
    }

    /// Like [`Self::new`], but with an explicit reserved-ID allocation
    /// instead of the legacy single-hop default. Used by the VPN hop chain
    /// (`ProductionRouterSubsystems::apply_vpn_chain`) to run one
    /// `VpnPolicyManager` per exit hop, each scoped to
    /// `VpnPolicyReservedIds::for_hop(hop_index)` instead of colliding on
    /// the same reserved band.
    pub fn new_with_reserved(
        network: Arc<dyn NetworkProvider>,
        firewall: VpnPolicyFirewallBackend<E>,
        tunnel: Arc<VpnManager<D>>,
        reserved: VpnPolicyReservedIds,
    ) -> Self {
        Self {
            conflicts: VpnPolicyResourceConflictDetector::new(network.clone()),
            network,
            firewall,
            tunnel,
            reserved,
        }
    }

    pub async fn snapshot(&self, desired: &VpnPolicyDesired) -> Result<VpnPolicySnapshot> {
        let expected = self.desired_state_best_effort(desired).await;
        let observation = self.conflicts.observe(&expected).await?;
        if !observation.is_conflict_free() {
            bail!(
                "refusing to observe VPN policy state: foreign objects occupy the reserved \
                 namespace: {:?}",
                observation.conflicts
            );
        }
        let firewall = self
            .firewall
            .observe()
            .context("failed to observe VPN policy firewall state")?;

        let mut routes = observation.owned_routes;
        routes.extend(observation.unexpected_owned_routes);
        Ok(VpnPolicySnapshot {
            rules: observation.owned_rules,
            routes,
            firewall: firewall.desired,
        })
    }

    pub async fn activate(&self, desired: &VpnPolicyDesired) -> Result<VpnPolicySnapshot> {
        desired.firewall().validate()?;
        self.ensure_tunnel_healthy(&desired.vpn_interface).await?;

        let expected = self.desired_state_strict(desired).await?;
        let observation = self.conflicts.observe(&expected).await?;
        if !observation.is_conflict_free() {
            bail!(
                "refusing to activate VPN policy: foreign objects occupy the reserved \
                 namespace: {:?}",
                observation.conflicts
            );
        }

        let firewall_before = self
            .firewall
            .observe()
            .context("failed to observe VPN policy firewall state before activation")?;
        let mut snapshot_routes = observation.owned_routes.clone();
        snapshot_routes.extend(observation.unexpected_owned_routes.clone());
        let snapshot = VpnPolicySnapshot {
            rules: observation.owned_rules.clone(),
            routes: snapshot_routes,
            firewall: firewall_before.desired,
        };

        if let Err(error) = self.install_missing_rules_and_routes(&observation).await {
            let _ = self.rollback(desired, &snapshot).await;
            return Err(error);
        }

        if let Err(error) = self
            .firewall
            .apply(&desired.firewall())
            .context("failed to apply VPN policy firewall marking/NAT/kill switch")
        {
            let _ = self.rollback(desired, &snapshot).await;
            return Err(error);
        }

        Ok(snapshot)
    }

    pub async fn deactivate(&self, desired: &VpnPolicyDesired) -> Result<()> {
        let mut errors = Vec::new();

        if let Err(error) = self.firewall.restore(None) {
            errors.push(format!(
                "failed to remove VPN policy firewall state: {error:#}"
            ));
        }

        let expected = self.desired_state_best_effort(desired).await;
        match self.conflicts.observe(&expected).await {
            Ok(observation) => {
                for route in observation
                    .owned_routes
                    .into_iter()
                    .chain(observation.unexpected_owned_routes)
                {
                    if let Err(error) = self.network.delete_ipv4_route(&route).await {
                        errors.push(format!("failed to remove VPN policy route: {error:#}"));
                    }
                }
                for rule in observation.owned_rules {
                    if let Err(error) = self.network.delete_ipv4_rule(&rule).await {
                        errors.push(format!("failed to remove VPN policy rule: {error:#}"));
                    }
                }
            }
            Err(error) => {
                errors.push(format!(
                    "failed to observe VPN policy IPv4 state: {error:#}"
                ));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            bail!(
                "VPN policy deactivation was incomplete: {}",
                errors.join("; ")
            )
        }
    }

    pub async fn rollback(
        &self,
        desired: &VpnPolicyDesired,
        snapshot: &VpnPolicySnapshot,
    ) -> Result<()> {
        let mut errors = Vec::new();

        if let Err(error) = self.firewall.restore(snapshot.firewall.as_ref()) {
            errors.push(format!("firewall rollback failed: {error:#}"));
        }

        let expected = self.desired_state_best_effort(desired).await;
        match self.conflicts.observe(&expected).await {
            Ok(observation) => {
                let mut current_routes = observation.owned_routes;
                current_routes.extend(observation.unexpected_owned_routes);

                for route in current_routes
                    .iter()
                    .filter(|route| !snapshot.routes.contains(route))
                {
                    if let Err(error) = self.network.delete_ipv4_route(route).await {
                        errors.push(format!("failed to remove route during rollback: {error:#}"));
                    }
                }
                for route in snapshot
                    .routes
                    .iter()
                    .filter(|route| !current_routes.contains(route))
                {
                    if let Err(error) = self
                        .network
                        .add_ipv4_route(&route_spec_from_info(route))
                        .await
                    {
                        errors.push(format!(
                            "failed to restore route during rollback: {error:#}"
                        ));
                    }
                }

                for rule in observation
                    .owned_rules
                    .iter()
                    .filter(|rule| !snapshot.rules.contains(rule))
                {
                    if let Err(error) = self.network.delete_ipv4_rule(rule).await {
                        errors.push(format!("failed to remove rule during rollback: {error:#}"));
                    }
                }
                for rule in snapshot
                    .rules
                    .iter()
                    .filter(|rule| !observation.owned_rules.contains(rule))
                {
                    if let Err(error) = self.network.add_ipv4_rule(&rule_spec_from_info(rule)).await
                    {
                        errors.push(format!("failed to restore rule during rollback: {error:#}"));
                    }
                }
            }
            Err(error) => {
                errors.push(format!(
                    "failed to observe VPN policy IPv4 state during rollback: {error:#}"
                ));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            bail!("VPN policy rollback was incomplete: {}", errors.join("; "))
        }
    }

    async fn install_missing_rules_and_routes(
        &self,
        observation: &crate::core::vpn_policy::VpnPolicyResourceObservation,
    ) -> Result<()> {
        for route in &observation.unexpected_owned_routes {
            self.network
                .delete_ipv4_route(route)
                .await
                .context("failed to remove drifted owned VPN policy route")?;
        }
        for rule in &observation.missing_rules {
            self.network
                .add_ipv4_rule(rule)
                .await
                .context("failed to install VPN policy IPv4 rule")?;
        }
        for route in &observation.missing_routes {
            self.network
                .add_ipv4_route(route)
                .await
                .context("failed to install VPN policy IPv4 route")?;
        }
        Ok(())
    }

    async fn ensure_tunnel_healthy(&self, vpn_interface: &str) -> Result<()> {
        let status = self
            .tunnel
            .status()
            .await
            .context("failed to read VPN tunnel status")?;
        match status {
            Some(status) if status.up && status.interface == vpn_interface => Ok(()),
            Some(status) => bail!(
                "refusing to activate VPN policy: active tunnel interface '{}' (up={}) does not \
                 match the expected VPN policy interface '{vpn_interface}' — fail closed, not \
                 falling back to direct uplink",
                status.interface,
                status.up
            ),
            None => bail!(
                "refusing to activate VPN policy: no active VPN tunnel — fail closed, not \
                 falling back to direct uplink"
            ),
        }
    }

    fn desired_rule(&self) -> Ipv4RuleSpec {
        Ipv4RuleSpec {
            source: None,
            destination: None,
            table: self.reserved.route_table.get(),
            priority: Some(self.reserved.rule_priority_start.get()),
            fw_mark: Some(self.reserved.fw_mark.get()),
            fw_mask: Some(self.reserved.fw_mask.get()),
            input_interface: None,
            output_interface: None,
        }
    }

    async fn desired_route(&self, vpn_interface: &str) -> Result<Ipv4RouteSpec> {
        let index = self.resolve_interface_index(vpn_interface).await?;
        Ok(Ipv4RouteSpec {
            destination: default_ipv4_route(),
            gateway: None,
            output_interface_index: Some(index),
            table: self.reserved.route_table.get(),
            metric: Some(VPN_POLICY_ROUTE_METRIC),
            protocol: TRAFFIC_MASQ_ROUTE_PROTOCOL,
        })
    }

    async fn desired_state_strict(
        &self,
        desired: &VpnPolicyDesired,
    ) -> Result<VpnPolicyDesiredState> {
        Ok(VpnPolicyDesiredState {
            rules: vec![self.desired_rule()],
            routes: vec![self.desired_route(&desired.vpn_interface).await?],
        })
    }

    async fn desired_state_best_effort(&self, desired: &VpnPolicyDesired) -> VpnPolicyDesiredState {
        let routes = match self.desired_route(&desired.vpn_interface).await {
            Ok(route) => vec![route],
            Err(_) => Vec::new(),
        };
        VpnPolicyDesiredState {
            rules: vec![self.desired_rule()],
            routes,
        }
    }

    async fn resolve_interface_index(&self, name: &str) -> Result<u32> {
        self.network
            .list_interfaces()
            .await
            .context("failed to list interfaces while resolving VPN policy interface")?
            .into_iter()
            .find(|interface| interface.name == name)
            .map(|interface| interface.index)
            .ok_or_else(|| anyhow::anyhow!("VPN policy interface not found: {name}"))
    }
}

fn default_ipv4_route() -> Ipv4Net {
    Ipv4Net::new(std::net::Ipv4Addr::UNSPECIFIED, 0).expect("0.0.0.0/0 is always a valid network")
}

fn route_spec_from_info(info: &Ipv4RouteInfo) -> Ipv4RouteSpec {
    Ipv4RouteSpec {
        destination: info.destination,
        gateway: info.gateway,
        output_interface_index: info.output_interface_index,
        table: info.table,
        metric: info.metric,
        protocol: info.protocol,
    }
}

fn rule_spec_from_info(info: &Ipv4RuleInfo) -> Ipv4RuleSpec {
    Ipv4RuleSpec {
        source: info.source,
        destination: info.destination,
        table: info.table,
        priority: info.priority,
        fw_mark: info.fw_mark,
        fw_mask: info.fw_mask,
        input_interface: info.input_interface.clone(),
        output_interface: info.output_interface.clone(),
    }
}

#[cfg(test)]
mod tests {
    use crate::netlink::AddressOwnership;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    use async_trait::async_trait;

    use super::*;
    use crate::firewall::vpn::test_support::{nft_ruleset, FakeNftExecutor};
    use crate::netlink::{Ipv4AddressInfo, NetworkInterface};
    use crate::vpn::active_profile::ActiveProfileStore;
    use crate::vpn::manager::OWNED_INTERFACE_NAME;
    use crate::vpn::store::WireGuardProfileStore;
    use crate::vpn::wireguard::{WireGuardKey, WireGuardPeerConfig, WireGuardVpnDriver};

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

    use crate::vpn::{ProviderError, VpnProvider};

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

    #[derive(Debug, Clone)]
    struct FakeLink {
        up: bool,
    }

    #[derive(Default)]
    struct FakeVpnProvider {
        links: StdMutex<HashMap<String, FakeLink>>,
    }

    #[async_trait]
    impl VpnProvider for FakeVpnProvider {
        async fn link_exists(&self, name: &str) -> Result<bool, ProviderError> {
            Ok(self.links.lock().unwrap().contains_key(name))
        }

        async fn create_link(
            &self,
            name: &str,
            _private_key: &WireGuardKey,
            _listen_port: Option<u16>,
        ) -> Result<(), ProviderError> {
            self.links
                .lock()
                .unwrap()
                .insert(name.to_string(), FakeLink { up: false });
            Ok(())
        }

        async fn set_addresses(
            &self,
            name: &str,
            _addresses: &[ipnet::IpNet],
        ) -> Result<(), ProviderError> {
            self.require_link(name)
        }

        async fn set_peers(
            &self,
            name: &str,
            _peers: &[WireGuardPeerConfig],
        ) -> Result<(), ProviderError> {
            self.require_link(name)
        }

        async fn set_link_up(&self, name: &str) -> Result<(), ProviderError> {
            let mut links = self.links.lock().unwrap();
            let link = links
                .get_mut(name)
                .ok_or_else(|| ProviderError::NotFound(name.to_string()))?;
            link.up = true;
            Ok(())
        }

        async fn set_link_down(&self, name: &str) -> Result<(), ProviderError> {
            let mut links = self.links.lock().unwrap();
            let link = links
                .get_mut(name)
                .ok_or_else(|| ProviderError::NotFound(name.to_string()))?;
            link.up = false;
            Ok(())
        }

        async fn delete_link(&self, name: &str) -> Result<(), ProviderError> {
            self.links
                .lock()
                .unwrap()
                .remove(name)
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

        async fn is_up(&self, name: &str) -> Result<bool, ProviderError> {
            Ok(self
                .links
                .lock()
                .unwrap()
                .get(name)
                .map(|link| link.up)
                .unwrap_or(false))
        }
    }

    impl FakeVpnProvider {
        fn require_link(&self, name: &str) -> Result<(), ProviderError> {
            if self.links.lock().unwrap().contains_key(name) {
                Ok(())
            } else {
                Err(ProviderError::NotFound(name.to_string()))
            }
        }
    }

    #[derive(Default)]
    struct FakeNetwork {
        interfaces: StdMutex<Vec<NetworkInterface>>,
        rules: StdMutex<Vec<Ipv4RuleInfo>>,
        routes: StdMutex<Vec<Ipv4RouteInfo>>,
        fail_next_add_route: StdMutex<bool>,
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
    ) -> (TestManager, Arc<FakeVpnProvider>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
        let active_profile_store = ActiveProfileStore::new(dir.path().join("active-profile.json"));
        let fake_provider = Arc::new(FakeVpnProvider::default());
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
    async fn deactivate_removes_firewall_before_rules_and_routes() {
        let network = FakeNetwork::with_interface(OWNED_INTERFACE_NAME, 42);
        let firewall_desired = desired().firewall();
        let executor = FakeNftExecutor::with_responses(vec![
            Ok(nft_ruleset(None)),
            Ok(nft_ruleset(None)),
            Ok(Vec::new()),
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

        assert_eq!(calls.len(), 5);
        assert_eq!(calls[4].0, ["-f", "-"]);
        let removal_batch = String::from_utf8(calls[4].1.clone()).unwrap();
        assert_eq!(removal_batch, "delete table inet traffic_masq_vpn\n");
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
        let executor = FakeNftExecutor::with_responses(vec![Ok(nft_ruleset(None)), Ok(Vec::new())]);
        let (manager, _provider, _dir) = manager_with(network.clone(), executor);

        manager
            .deactivate(&desired())
            .await
            .expect("deactivate despite missing interface");

        assert!(network.list_ipv4_rules().await.unwrap().is_empty());
        assert!(network.list_ipv4_routes().await.unwrap().is_empty());
    }
}
