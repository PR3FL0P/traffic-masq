use super::super::*;

pub(in crate::api::control::tests) struct DhcpClientControlFixture {
    pub(in crate::api::control::tests) service: ControlService,
    pub(in crate::api::control::tests) overrides: RuntimeOverrideManager,
    pub(in crate::api::control::tests) supervisor: DhcpClientSupervisor,
    pub(in crate::api::control::tests) directory: tempfile::TempDir,
}

pub(in crate::api::control::tests) async fn dhcp_client_control_fixture(
    enabled: bool,
) -> DhcpClientControlFixture {
    dhcp_client_control_fixture_with_router(enabled, false).await
}

pub(in crate::api::control::tests) async fn dhcp_client_control_fixture_with_router(
    enabled: bool,
    router_uplink: bool,
) -> DhcpClientControlFixture {
    let directory = tempdir().expect("tempdir");
    let mut config = AppConfig::default();
    config.runtime.state_dir = directory.path().to_path_buf();
    config.dhcp.leases_dir = directory.path().join("leases");
    if router_uplink {
        config.router.uplink = Some(UplinkConfig {
            interface: "wan0".to_string(),
            mode: UplinkMode::Dhcp,
        });
        config.network.interfaces.insert(
            "lan0".to_string(),
            InterfaceConfig {
                wifi_concurrent: false,
                randomize_mac: false,
                mac_address: None,
                role: InterfaceRole::Output,
                managed: true,
                ipv4: Some("10.9.0.1/24".parse().expect("output subnet")),
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
            },
        );
    }
    config.network.interfaces.insert(
        "wan0".to_string(),
        InterfaceConfig {
            wifi_concurrent: false,
            randomize_mac: false,
            mac_address: None,
            role: InterfaceRole::Input,
            managed: true,
            ipv4: None,
            dhcp: None,
            dhcp_client: enabled.then(DhcpClientInterfaceConfig::default),
            wifi: None,
            wifi_client: Some(WifiClientConfig {
                ssid: "upstream".to_string(),
                country_code: Some("PL".to_string()),
                security: WifiClientSecurity::Open,
                passphrase_file: None,
            }),
        },
    );
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("server supervisor");
    let supervisor = DhcpClientSupervisor::start(&config, network.clone())
        .await
        .expect("client supervisor");
    let service = ControlService::new_detached(config, network, dhcp, overrides.clone())
        .with_dhcp_client_supervisor(supervisor.clone());
    DhcpClientControlFixture {
        service,
        overrides,
        supervisor,
        directory,
    }
}

// Exercise real admission/execution gates, interface journals and the DHCP
// supervisor. DHCP sees a detached device so these tests never open raw sockets;
// the transaction observer sees the device to allow a confirmed policy edit.
pub(in crate::api::control::tests) async fn dhcp_route_policy_fixture(
    timeout_seconds: u64,
) -> (DhcpClientControlFixture, tokio::task::JoinHandle<()>) {
    dhcp_confirm_fixture(true, timeout_seconds).await
}

pub(in crate::api::control::tests) async fn dhcp_confirm_fixture(
    enabled: bool,
    timeout_seconds: u64,
) -> (DhcpClientControlFixture, tokio::task::JoinHandle<()>) {
    let mut fixture = dhcp_client_control_fixture(enabled).await;
    let mut config = fixture.service.base_config.clone();
    config.security.rollback_timeout_seconds = timeout_seconds;
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    network.add_interface("wan0", 1).await;
    let desired = DesiredNetworkState::new(config.clone(), fixture.overrides.clone());
    desired.attach_converger();
    fixture.service = ControlService::from_runtime(
        ControlRuntime {
            active_config: config.clone(),
            base_config: config,
            network,
            dhcp: fixture.service.dhcp.clone(),
            overrides: fixture.overrides.clone(),
            baselines: Vec::new(),
            ownership_journal: AddressOwnershipJournal::in_memory(),
            desired_state: desired.clone(),
            mutation_gate: Arc::new(NetworkMutationGate::default()),
        },
        ControlSubsystems {
            dhcp_client: Some(fixture.supervisor.clone()),
            ..ControlSubsystems::default()
        },
    );
    let gate = fixture.service.network_mutations.clone();
    let supervisor = fixture.supervisor.clone();
    let worker = tokio::spawn(async move {
        loop {
            let version = desired.version();
            {
                let _execution = gate.read().await;
                let config = desired.effective().await.unwrap();
                let spec = DhcpClientSpec::from_interface_config(
                    "wan0",
                    &config.network.interfaces["wan0"],
                )
                .unwrap();
                match spec {
                    Some(spec) => supervisor.configure(spec).await,
                    None => {
                        supervisor.disable("wan0").await.unwrap();
                    }
                }
                desired.report_result(version, Ok(BTreeMap::new()));
            }
            desired.changed().await;
        }
    });
    (fixture, worker)
}
