use super::super::*;

pub(in crate::api::control::tests) fn valid_vpn_profile_contents() -> String {
    format!(
        "[Interface]\n\
         PrivateKey = {VALID_VPN_PRIVATE_KEY}\n\
         Address = 10.0.0.2/24\n\
         \n\
         [Peer]\n\
         PublicKey = {VALID_VPN_PUBLIC_KEY}\n\
         AllowedIPs = 0.0.0.0/0\n\
         Endpoint = 203.0.113.1:51820\n"
    )
}

pub(in crate::api::control::tests) async fn vpn_enabled_service(
) -> (ControlService, tempfile::TempDir) {
    vpn_enabled_service_with_provider(FakeVpnProvider::default()).await
}

pub(in crate::api::control::tests) async fn vpn_enabled_service_with_provider(
    provider: FakeVpnProvider,
) -> (ControlService, tempfile::TempDir) {
    let directory = tempdir().expect("tempdir");
    let mut config = router_base_config();
    config.vpn.enabled = true;
    config.runtime.state_dir = directory.path().into();
    config.vpn.wireguard_config_dir = directory.path().join("wireguard");
    config.vpn.wireguard_import_dir = directory.path().join("sources");
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = FakePolicyNetwork::with_owned_interface();
    let vpn_store = crate::vpn::WireGuardProfileStore::new(directory.path().join("wireguard"));
    let active_profile_store =
        crate::vpn::ActiveProfileStore::new(directory.path().join("active-profile.json"));
    let provider: Arc<dyn crate::vpn::VpnProvider> = Arc::new(provider);
    let driver = crate::vpn::WireGuardVpnDriver::new(provider.clone(), vpn_store);
    let vpn_manager = Arc::new(crate::vpn::VpnManager::new(driver, active_profile_store));
    let coordinator = crate::core::router_subsystems::tests::standalone_coordinator(
        &config,
        overrides.clone(),
        vpn_manager.clone(),
        provider,
        network.clone(),
        Arc::new(StatefulFakeNftExecutor::default()),
    )
    .await;
    let service = ControlService::new_detached(config, network, dhcp, overrides)
        .with_vpn_manager(vpn_manager)
        .with_router_coordinator(coordinator);
    (service, directory)
}

pub(in crate::api::control::tests) fn vpn_policy_firewall_desired() -> VpnPolicyFirewallDesired {
    VpnPolicyFirewallDesired {
        masquerade_forwarded: true,
        protected_subnets: vec!["192.168.10.0/24".parse().unwrap()],
        vpn_interface: OWNED_INTERFACE_NAME.to_string(),
        physical_uplink: "wan0".to_string(),
        host_traffic: None,
    }
}

#[derive(Default)]
pub(in crate::api::control::tests) struct StatefulFakeNftExecutor {
    pub(in crate::api::control::tests) installed: StdMutex<Option<VpnPolicyFirewallDesired>>,
}

impl NftExecutor for StatefulFakeNftExecutor {
    fn execute(&self, arguments: &[&str], input: &[u8]) -> Result<Vec<u8>> {
        match arguments {
            ["--json", "list", "ruleset"] => {
                Ok(nft_ruleset(self.installed.lock().unwrap().as_ref()))
            }
            ["-f", "-"] => {
                let batch = String::from_utf8_lossy(input);
                let mut installed = self.installed.lock().unwrap();
                *installed = if batch.contains("table inet traffic_masq_vpn {") {
                    Some(vpn_policy_firewall_desired())
                } else {
                    None
                };
                Ok(Vec::new())
            }
            other => anyhow::bail!("unexpected nft invocation: {other:?}"),
        }
    }
}

#[derive(Default)]
pub(in crate::api::control::tests) struct FakePolicyNetwork {
    pub(in crate::api::control::tests) interfaces: StdMutex<Vec<NetworkInterface>>,
    pub(in crate::api::control::tests) rules: StdMutex<Vec<crate::netlink::Ipv4RuleInfo>>,
    pub(in crate::api::control::tests) routes: StdMutex<Vec<crate::netlink::Ipv4RouteInfo>>,
}

impl FakePolicyNetwork {
    pub(in crate::api::control::tests) fn with_owned_interface() -> Arc<Self> {
        let network = Self::default();
        network.interfaces.lock().unwrap().push(NetworkInterface {
            is_wireless: false,
            index: 42,
            name: OWNED_INTERFACE_NAME.to_string(),
            is_up: true,
            rx_bytes: 0,
            tx_bytes: 0,
        });
        Arc::new(network)
    }
}

#[async_trait]
impl NetworkProvider for FakePolicyNetwork {
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

    async fn list_ipv4_rules(&self) -> Result<Vec<crate::netlink::Ipv4RuleInfo>> {
        Ok(self.rules.lock().unwrap().clone())
    }

    async fn add_ipv4_rule(&self, rule: &crate::netlink::Ipv4RuleSpec) -> Result<()> {
        self.rules
            .lock()
            .unwrap()
            .push(crate::netlink::Ipv4RuleInfo {
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

    async fn delete_ipv4_rule(&self, rule: &crate::netlink::Ipv4RuleInfo) -> Result<()> {
        self.rules.lock().unwrap().retain(|current| current != rule);
        Ok(())
    }

    async fn list_ipv4_routes(&self) -> Result<Vec<crate::netlink::Ipv4RouteInfo>> {
        Ok(self.routes.lock().unwrap().clone())
    }

    async fn add_ipv4_route(&self, route: &crate::netlink::Ipv4RouteSpec) -> Result<()> {
        self.routes
            .lock()
            .unwrap()
            .push(crate::netlink::Ipv4RouteInfo {
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

    async fn delete_ipv4_route(&self, route: &crate::netlink::Ipv4RouteInfo) -> Result<()> {
        self.routes
            .lock()
            .unwrap()
            .retain(|current| current != route);
        Ok(())
    }
}

pub(in crate::api::control::tests) fn router_and_vpn_base_config(
    wireguard_dir: std::path::PathBuf,
) -> AppConfig {
    let mut config = router_base_config_with_router_enabled();
    config.router.forwarding = None;
    config.vpn.enabled = true;
    config.vpn.wireguard_config_dir = wireguard_dir;
    config
}

pub(in crate::api::control::tests) struct VpnPolicyFixture {
    pub(in crate::api::control::tests) service: ControlService,
    pub(in crate::api::control::tests) overrides: RuntimeOverrideManager,
    pub(in crate::api::control::tests) network: Arc<FakePolicyNetwork>,
    pub(in crate::api::control::tests) provider: Arc<dyn crate::vpn::VpnProvider>,
    pub(in crate::api::control::tests) executor: Arc<dyn NftExecutor>,
    pub(in crate::api::control::tests) _directory: tempfile::TempDir,
}

pub(in crate::api::control::tests) async fn vpn_policy_fixture(
    activate_tunnel: bool,
) -> VpnPolicyFixture {
    vpn_policy_fixture_with_router_chain(activate_tunnel, false).await
}

pub(in crate::api::control::tests) async fn vpn_policy_fixture_with_router_chain(
    activate_tunnel: bool,
    router_chain: bool,
) -> VpnPolicyFixture {
    let directory = tempdir().expect("tempdir");
    let mut config = router_and_vpn_base_config(directory.path().join("wireguard"));
    if router_chain {
        config.router.vpn_chain = vec![crate::config::VpnHopConfig {
            profile_name: "chain.conf".to_string(),
        }];
    }
    config.runtime.state_dir = directory.path().into();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network = FakePolicyNetwork::with_owned_interface();

    let vpn_store = crate::vpn::WireGuardProfileStore::new(config.vpn.wireguard_config_dir.clone());
    let active_profile_store =
        crate::vpn::ActiveProfileStore::new(directory.path().join("active-profile.json"));
    let provider: Arc<dyn crate::vpn::VpnProvider> = Arc::new(FakeVpnProvider::default());
    let driver = crate::vpn::WireGuardVpnDriver::new(provider.clone(), vpn_store);
    let tunnel = Arc::new(crate::vpn::VpnManager::new(driver, active_profile_store));

    if activate_tunnel {
        tunnel
            .import_profile("home.conf", valid_vpn_profile_contents().as_bytes())
            .expect("import profile");
        tunnel.activate("home.conf").await.expect("activate tunnel");
    }

    let executor: Arc<dyn NftExecutor> = Arc::new(StatefulFakeNftExecutor::default());
    let firewall = VpnPolicyFirewallBackend::new(executor.clone());
    let policy = Arc::new(VpnPolicyManager::new(
        network.clone(),
        firewall,
        tunnel.clone(),
    ));

    let coordinator = crate::core::router_subsystems::tests::standalone_coordinator(
        &config,
        overrides.clone(),
        tunnel.clone(),
        provider.clone(),
        network.clone(),
        executor.clone(),
    )
    .await;
    let service = ControlService::new_detached(config, network.clone(), dhcp, overrides.clone())
        .with_vpn_manager(tunnel)
        .with_vpn_policy_manager(policy)
        .with_router_coordinator(coordinator);

    VpnPolicyFixture {
        service,
        overrides,
        network,
        provider,
        executor,
        _directory: directory,
    }
}

pub(in crate::api::control::tests) fn network_pending_token(response: Response) -> String {
    match response {
        Response::NetworkChangePending { change } => {
            assert_eq!(
                change.phase,
                traffic_masq_protocol::NetworkChangePhase::AwaitingCommit
            );
            change.token
        }
        other => panic!("expected tentative network change: {other:?}"),
    }
}

pub(in crate::api::control::tests) async fn commit_vpn_request(
    service: &ControlService,
    request: Request,
) {
    let response = service.dispatch(request).await;
    let token = match response {
        Response::RouterTransactionPending { token, .. } => token,
        other => panic!("expected tentative router change: {other:?}"),
    };
    let response = service.dispatch(Request::RouterCommit { token }).await;
    assert!(
        matches!(response, Response::RouterCommitted { .. }),
        "{response:?}"
    );
}

pub(in crate::api::control::tests) async fn commit_policy_request(
    service: &ControlService,
    request: Request,
) -> Response {
    commit_vpn_request(service, request).await;
    service.dispatch(Request::VpnPolicyStatus).await
}

pub(in crate::api::control::tests) const VALID_VPN_PRIVATE_KEY: &str =
    "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
pub(in crate::api::control::tests) const VALID_VPN_PUBLIC_KEY: &str =
    "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
pub(in crate::api::control::tests) const OTHER_VPN_PRIVATE_KEY: &str =
    "SBmoW+ojuoJZeh6P/2sh8aetgAy4dTZTAO8UzHzKtGY=";
