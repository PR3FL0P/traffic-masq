//! Use the API admission path and the real reconciliation pass. Only kernel and
//! Wi-Fi process I/O are replaced; transaction timers and gates are production.
use super::*;
use crate::api::control::{ControlRuntime, ControlService, ControlSubsystems};
use crate::api::model::{Request, Response};
use crate::core::mutation::NetworkMutationGate;
use std::collections::HashSet;

mod failure_scenarios;

struct StartingWifi {
    delay: Duration,
    started: Mutex<HashSet<String>>,
    live: Mutex<HashSet<String>>,
    entered: mpsc::UnboundedSender<String>,
}

#[async_trait]
impl WifiRuntimeReconciler for StartingWifi {
    async fn ensure_alive(&self) -> Result<bool> {
        Ok(false)
    }

    async fn reconcile_interface(&self, name: &str, config: &InterfaceConfig) -> Result<()> {
        if config.wifi_client.is_some() && self.started.lock().await.insert(name.into()) {
            self.entered.send(name.into()).unwrap();
            // A supplicant may take up to STARTUP_READY_TIMEOUT to become ready.
            // Successful starts here stay strictly inside that per-device budget.
            tokio::time::sleep(self.delay).await;
        }
        if config.wifi_client.is_some() {
            self.live.lock().await.insert(name.into());
        } else {
            self.live.lock().await.remove(name);
        }
        Ok(())
    }

    async fn association_ready(&self, _: &str) -> Option<bool> {
        Some(true)
    }
}

fn ethernet(cidr: &str) -> InterfaceConfig {
    InterfaceConfig {
        mac_address: None,
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some(cidr.parse().unwrap()),
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    }
}

fn station() -> InterfaceConfig {
    InterfaceConfig {
        role: InterfaceRole::Input,
        ipv4: None,
        wifi_client: Some(crate::config::WifiClientConfig {
            ssid: "reachable-network".into(),
            country_code: None,
            security: crate::config::WifiClientSecurity::Open,
            passphrase_file: None,
        }),
        ..ethernet("192.0.2.1/24")
    }
}

struct Fixture {
    service: ControlService,
    desired: DesiredNetworkState,
    wifi: Arc<StartingWifi>,
    gate: Arc<NetworkMutationGate>,
    network: Arc<FakeNetworkProvider>,
    worker: Option<JoinHandle<()>>,
    overrides: RuntimeOverrideManager,
    ownership: AddressOwnershipJournal,
    entered: mpsc::UnboundedReceiver<String>,
    _directory: tempfile::TempDir,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(worker) = &self.worker {
            worker.abort();
        }
    }
}

impl Fixture {
    async fn start(wifi_count: usize, delay: Duration, window_seconds: u64) -> Self {
        Self::start_with_converger(wifi_count, delay, window_seconds, true).await
    }

    async fn start_with_converger(
        wifi_count: usize,
        delay: Duration,
        window_seconds: u64,
        attach_converger: bool,
    ) -> Self {
        let directory = tempdir().unwrap();
        let mut config = AppConfig::default();
        config.runtime.state_dir = directory.path().into();
        config.dhcp.leases_dir = directory.path().join("leases");
        config.wifi_client.enabled = true;
        config.wifi_client.runtime_dir = directory.path().join("wpa_supplicant");
        config.security.rollback_timeout_seconds = window_seconds;
        config
            .network
            .interfaces
            .insert("eth0".into(), ethernet("192.0.2.1/24"));
        let network = Arc::new(FakeNetworkProvider::default());
        network
            .add_interface_with_state(
                "eth0",
                1,
                true,
                vec![Ipv4AddressInfo {
                    interface_index: 1,
                    address: Ipv4Addr::new(192, 0, 2, 1),
                    prefix_len: 24,
                    protocol: AddressOwnership::Static.protocol(),
                }],
            )
            .await;
        for index in 0..wifi_count.max(1) {
            let name = format!("wlan{index}");
            network.add_interface(&name, index as u32 + 2).await;
            network
                .wireless_phys
                .lock()
                .unwrap()
                .insert(name.clone(), format!("phy{index}"));
            network
                .interfaces
                .lock()
                .await
                .get_mut(&name)
                .unwrap()
                .is_wireless = true;
            if index < wifi_count {
                config.network.interfaces.insert(name, station());
            }
        }
        config.validate().expect("realistic daemon configuration");
        let overrides = RuntimeOverrideManager::load(directory.path(), &config)
            .await
            .unwrap();
        let desired = DesiredNetworkState::new(config.clone(), overrides.clone());
        let journal = AddressOwnershipJournal::in_memory();
        let gate = Arc::new(NetworkMutationGate::default());
        let dhcp = DhcpSupervisor::start(&config).await.unwrap();
        let service = ControlService::from_runtime(
            ControlRuntime {
                active_config: config.clone(),
                base_config: config,
                network: network.clone(),
                dhcp,
                overrides: overrides.clone(),
                baselines: Vec::new(),
                ownership_journal: journal.clone(),
                desired_state: desired.clone(),
                mutation_gate: gate.clone(),
            },
            ControlSubsystems::default(),
        );
        let (entered_tx, entered) = mpsc::unbounded_channel();
        let wifi = Arc::new(StartingWifi {
            delay,
            started: Mutex::new(HashSet::new()),
            live: Mutex::new(HashSet::new()),
            entered: entered_tx,
        });
        if attach_converger {
            desired.attach_converger();
        }
        let ownership = journal.clone();
        let runtime_network = network.clone();
        let fixture_desired = desired.clone();
        let fixture_wifi = wifi.clone();
        let fixture_gate = gate.clone();
        let worker = attach_converger.then(|| {
            tokio::spawn(async move {
                // Start on the first API proposal, as after a kernel/config event.
                loop {
                    desired.changed().await;
                    let version = desired.version();
                    let _runtime = gate.converge().await;
                    let result = reconcile_network_runtime_once(
                        &desired,
                        &journal,
                        runtime_network.clone(),
                        &FakeDhcpReconciler::default(),
                        None::<&FakeWifiReconciler>,
                        Some(wifi.as_ref()),
                        Some(&FakeDhcpClientReconciler::default()),
                    )
                    .await;
                    desired.report_result(version, result);
                }
            })
        });
        Self {
            overrides,
            ownership,
            service,
            desired: fixture_desired,
            wifi: fixture_wifi,
            gate: fixture_gate,
            network,
            worker,
            entered,
            _directory: directory,
        }
    }
}

fn apply(name: &str, config: InterfaceConfig) -> Request {
    Request::ApplyInterface {
        interface: name.into(),
        config: config.into(),
        allow_management_change: true,
    }
}

#[tokio::test]
async fn regression_expired_interface_restores_while_another_interface_starts() {
    let mut fixture = Fixture::start(0, Duration::from_secs(4), 1).await;
    let first = fixture
        .service
        .dispatch(apply("eth0", ethernet("192.0.2.99/24")))
        .await;
    assert!(
        matches!(first, Response::NetworkChangePending { .. }),
        "{first:?}"
    );
    let second = {
        let service = fixture.service.clone();
        tokio::spawn(async move { service.dispatch(apply("wlan0", station())).await })
    };
    tokio::time::timeout(Duration::from_secs(2), fixture.entered.recv())
        .await
        .unwrap()
        .unwrap();
    let writer = tokio::spawn({
        let gate = fixture.gate.clone();
        async move {
            let _exclusive = gate.execute().await;
        }
    });
    // Allow a whole extra second beyond eth0's confirmation deadline. wlan0's
    // ordinary four-second startup must not extend eth0's unsafe configuration.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let addresses = fixture.network.list_ipv4_addresses("eth0").await.unwrap();
    let restored_on_time = addresses
        .iter()
        .any(|a| a.address == Ipv4Addr::new(192, 0, 2, 1))
        && !addresses
            .iter()
            .any(|a| a.address == Ipv4Addr::new(192, 0, 2, 99));
    let second_result = second.await.unwrap();
    assert!(
        matches!(second_result, Response::NetworkChangePending { .. }),
        "{second_result:?}"
    );
    // Show that this is delayed compensation, rather than a broken fake.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if fixture
                .network
                .list_ipv4_addresses("eth0")
                .await
                .unwrap()
                .iter()
                .any(|a| a.address == Ipv4Addr::new(192, 0, 2, 1))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("eth0 eventually restores once the unrelated apply finishes");
    writer.await.unwrap();
    assert!(
        restored_on_time,
        "expired eth0 retained the candidate address while unrelated wlan0 was starting"
    );
}

#[tokio::test]
async fn regression_healthy_interface_apply_survives_sequential_wifi_startups() {
    // Four independent radios recovering after a device/process event; each
    // successful startup takes 12s (<15s), but the full pass takes 48s.
    let fixture = Fixture::start(4, Duration::from_secs(12), 120).await;
    let result = tokio::time::timeout(
        Duration::from_secs(70),
        fixture
            .service
            .dispatch(apply("eth0", ethernet("192.0.2.99/24"))),
    )
    .await
    .expect("apply/compensation must terminate");
    assert!(matches!(result, Response::NetworkChangePending { .. }),
        "healthy eth0 must not be rolled back because other radios consume the shared convergence-pass budget: {result:?}");
}

#[tokio::test]
async fn late_wifi_start_cannot_acknowledge_or_replay_superseded_intent() {
    let mut fixture = Fixture::start(0, Duration::from_millis(200), 60).await;
    let interfaces = InterfaceManager::new(
        fixture.network.clone(),
        AddressOwnershipJournal::in_memory(),
    );
    let snapshot = interfaces.snapshot("wlan0").await.unwrap();
    let mut candidate = station();
    candidate.ipv4 = Some("198.51.100.9/24".parse().unwrap());
    fixture
        .desired
        .propose("cancelled", "wlan0", candidate, true)
        .await;
    tokio::time::timeout(Duration::from_secs(1), fixture.entered.recv())
        .await
        .unwrap()
        .unwrap();
    // Publish restoration while the old runtime call is in flight. Its future
    // must be drained, not aborted, and its completion cannot certify rollback.
    fixture.desired.restore("cancelled", snapshot, None).await;
    let version = fixture.desired.interface_revision("wlan0");
    assert!(tokio::time::timeout(
        Duration::from_millis(30),
        fixture.desired.interface_pass_covering("wlan0", version)
    )
    .await
    .is_err());
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        fixture.desired.interface_pass_covering("wlan0", version),
    )
    .await
    .unwrap();
    assert!(
        result.error.is_none() && result.failures.is_empty(),
        "{result:?}"
    );
    assert!(
        fixture.wifi.started.lock().await.contains("wlan0"),
        "old launch actually ran"
    );
    assert!(
        !fixture.wifi.live.lock().await.contains("wlan0"),
        "the late process must be stopped by restoration"
    );
    assert!(
        fixture
            .network
            .list_ipv4_addresses("wlan0")
            .await
            .unwrap()
            .is_empty(),
        "the obsolete candidate address must not survive restoration"
    );
}
