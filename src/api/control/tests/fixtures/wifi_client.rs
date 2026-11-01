use super::super::*;

pub(in crate::api::control::tests) struct FakeSupplicantProcess {
    pub(in crate::api::control::tests) fail_spawn: std::sync::atomic::AtomicBool,
    pub(in crate::api::control::tests) responders: StdMutex<HashMap<u32, FakeSupplicant>>,
    pub(in crate::api::control::tests) configs: StdMutex<HashMap<u32, std::path::PathBuf>>,
    pub(in crate::api::control::tests) next_pid: AtomicU32,
    pub(in crate::api::control::tests) wpa_state: Arc<StdMutex<String>>,
}

impl Default for FakeSupplicantProcess {
    fn default() -> Self {
        Self {
            fail_spawn: std::sync::atomic::AtomicBool::new(false),
            responders: StdMutex::new(HashMap::new()),
            configs: StdMutex::new(HashMap::new()),
            next_pid: AtomicU32::new(3000),
            wpa_state: Arc::new(StdMutex::new("COMPLETED".to_string())),
        }
    }
}

impl FakeSupplicantProcess {
    pub(in crate::api::control::tests) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub(in crate::api::control::tests) fn set_wpa_state(&self, state: &str) {
        *self.wpa_state.lock().unwrap() = state.to_string();
    }
}

#[async_trait]
impl SupervisedProcess for FakeSupplicantProcess {
    async fn spawn(
        &self,
        binary: &std::path::Path,
        config_path: &std::path::Path,
    ) -> Result<u32, WifiProcessError> {
        let interface = config_path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("wlan0");
        self.spawn_wifi_client(binary, interface, config_path).await
    }

    async fn spawn_wifi_client(
        &self,
        _binary: &std::path::Path,
        interface: &str,
        config_path: &std::path::Path,
    ) -> Result<u32, WifiProcessError> {
        if self.fail_spawn.load(WifiOrdering::SeqCst) {
            return Err(WifiProcessError::Spawn {
                binary: _binary.to_path_buf(),
                source: std::io::Error::other("injected restoration spawn failure"),
            });
        }
        let pid = self.next_pid.fetch_add(1, WifiOrdering::Relaxed);
        let ctrl_path = config_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new(""))
            .join(interface);
        let responder =
            FakeSupplicant::spawn(ctrl_path, config_path.to_path_buf(), self.wpa_state.clone());
        self.responders.lock().unwrap().insert(pid, responder);
        self.configs
            .lock()
            .unwrap()
            .insert(pid, config_path.to_path_buf());
        Ok(pid)
    }

    async fn is_alive(&self, pid: u32) -> Result<bool, WifiProcessError> {
        Ok(self.responders.lock().unwrap().contains_key(&pid))
    }

    async fn identity_matches(
        &self,
        pid: u32,
        _kind: crate::wifi::record::WifiProcessKind,
        _binary_path: &std::path::Path,
        config_path: &std::path::Path,
        _started_at_unix: u64,
    ) -> Result<bool, WifiProcessError> {
        Ok(self
            .configs
            .lock()
            .unwrap()
            .get(&pid)
            .is_some_and(|recorded| recorded == config_path))
    }

    async fn process_start_ticks(&self, pid: u32) -> Result<Option<u64>, WifiProcessError> {
        Ok(self
            .configs
            .lock()
            .unwrap()
            .contains_key(&pid)
            .then_some(u64::from(pid)))
    }

    async fn boot_id(&self) -> Result<Option<String>, WifiProcessError> {
        Ok(Some("test-boot".to_string()))
    }

    async fn pids_matching_identity(
        &self,
        _kind: crate::wifi::record::WifiProcessKind,
        _binary_path: &std::path::Path,
        config_path: &std::path::Path,
        _started_at_unix: u64,
    ) -> Result<Vec<u32>, WifiProcessError> {
        let mut pids: Vec<u32> = self
            .configs
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(pid, recorded)| (recorded == config_path).then_some(*pid))
            .collect();
        pids.sort_unstable();
        Ok(pids)
    }

    async fn owns_unix_socket(
        &self,
        pid: u32,
        socket_path: &std::path::Path,
    ) -> Result<bool, WifiProcessError> {
        Ok(self
            .responders
            .lock()
            .unwrap()
            .get(&pid)
            .is_some_and(|responder| responder.ctrl_path.as_path() == socket_path))
    }

    async fn terminate(&self, pid: u32) -> Result<(), WifiProcessError> {
        self.responders.lock().unwrap().remove(&pid);
        self.configs.lock().unwrap().remove(&pid);
        Ok(())
    }

    async fn kill(&self, pid: u32) -> Result<(), WifiProcessError> {
        self.responders.lock().unwrap().remove(&pid);
        self.configs.lock().unwrap().remove(&pid);
        Ok(())
    }
}

pub(in crate::api::control::tests) fn wifi_client_base_config(
    directory: &std::path::Path,
) -> AppConfig {
    let mut config = AppConfig::default();
    config.runtime.state_dir = directory.to_path_buf();
    config.wifi_client = WifiClientGlobalConfig {
        enabled: true,
        wpa_supplicant_binary: PathBuf::from("/usr/sbin/wpa_supplicant"),
        runtime_dir: directory.join("wpa_supplicant"),
        restart_backoff_seconds: 1,
    };
    config.network.interfaces.insert(
        "wlan1".to_string(),
        InterfaceConfig {
            wifi_concurrent: false,
            mac_address: None,
            role: InterfaceRole::Input,
            managed: true,
            ipv4: None,
            dhcp: None,
            dhcp_client: Some(DhcpClientInterfaceConfig::default()),
            wifi: None,
            wifi_client: Some(crate::config::WifiClientConfig {
                ssid: "upstream".to_string(),
                country_code: Some("PL".to_string()),
                security: WifiClientSecurity::Open,
                passphrase_file: None,
            }),
        },
    );
    config
}

pub(in crate::api::control::tests) struct WifiClientFixture {
    pub(in crate::api::control::tests) network: Arc<FakeWirelessNetwork>,
    pub(in crate::api::control::tests) process: Arc<FakeSupplicantProcess>,
    pub(in crate::api::control::tests) service: ControlService,
    pub(in crate::api::control::tests) _directory: tempfile::TempDir,
}

pub(in crate::api::control::tests) struct FakeWirelessNetwork {
    pub(in crate::api::control::tests) missing: std::sync::atomic::AtomicBool,
    pub(in crate::api::control::tests) interfaces: Vec<NetworkInterface>,
}

#[async_trait]
impl NetworkProvider for FakeWirelessNetwork {
    async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        if self.missing.load(WifiOrdering::SeqCst) {
            return Ok(Vec::new());
        }
        Ok(self.interfaces.clone())
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
}

pub(in crate::api::control::tests) async fn wifi_client_enabled_fixture() -> WifiClientFixture {
    wifi_client_fixture_with_security(WifiClientSecurity::Open).await
}

pub(in crate::api::control::tests) async fn wifi_client_fixture_with_security(
    security: WifiClientSecurity,
) -> WifiClientFixture {
    let directory = tempdir().expect("tempdir");
    let mut config = wifi_client_base_config(directory.path());
    config
        .network
        .interfaces
        .get_mut("wlan1")
        .unwrap()
        .wifi_client
        .as_mut()
        .unwrap()
        .security = security;
    if security.requires_passphrase() {
        crate::wifi::PassphraseStore::for_role(
            directory.path(),
            crate::wifi::store::WifiCredentialRole::Client,
        )
        .set(
            "wlan1",
            &crate::wifi::WifiPassphrase::new("first client secret").unwrap(),
        )
        .unwrap();
    }
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network = Arc::new(FakeWirelessNetwork {
        missing: Default::default(),
        interfaces: vec![
            NetworkInterface {
                name: "wlan1".to_string(),
                index: 1,
                is_up: true,
                rx_bytes: 0,
                tx_bytes: 0,
                is_wireless: true,
            },
            NetworkInterface {
                name: "wlan2".to_string(),
                index: 2,
                is_up: true,
                rx_bytes: 0,
                tx_bytes: 0,
                is_wireless: true,
            },
        ],
    });
    let process = FakeSupplicantProcess::new();
    let wifi_client = ClientSupervisor::start_with_process(&config, process.clone())
        .await
        .expect("wifi client supervisor");

    let interface_config = config
        .network
        .interfaces
        .get("wlan1")
        .expect("wlan1 declared");
    let spec = WifiClientSpec::from_interface_config("wlan1", interface_config)
        .expect("valid")
        .expect("wifi_client declared on wlan1");
    wifi_client.configure(spec).await.expect("configure wlan1");

    let dhcp_client = DhcpClientSupervisor::start(&config, network.clone())
        .await
        .expect("DHCP client supervisor");
    let service = ControlService::new_detached(config, network.clone(), dhcp, overrides)
        .with_wifi_client_supervisor(wifi_client)
        .with_dhcp_client_supervisor(dhcp_client);
    WifiClientFixture {
        network,
        process,
        service,
        _directory: directory,
    }
}

pub(in crate::api::control::tests) async fn shared_phy_wifi_service(
) -> (ControlService, tempfile::TempDir) {
    let directory = tempdir().unwrap();
    let mut config = wifi_client_base_config(directory.path());
    let ap_config = wifi_base_config(directory.path());
    config.wifi = ap_config.wifi;
    config.wifi.hostapd_binary = PathBuf::from("/bin/true");
    config.wifi_client.wpa_supplicant_binary = PathBuf::from("/bin/true");
    config.network.interfaces.insert(
        "wlan0".into(),
        ap_config.network.interfaces["wlan0"].clone(),
    );
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    for (name, index) in [("wlan0", 1), ("wlan1", 2)] {
        network.add_interface(name, index).await;
        network
            .interfaces
            .lock()
            .await
            .get_mut(name)
            .unwrap()
            .is_wireless = true;
        network
            .wireless_phys
            .lock()
            .unwrap()
            .insert(name.into(), "shared-radio".into());
    }
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&config).await.unwrap();
    let wifi = WifiSupervisor::start_with_process_and_radio(
        &config,
        FakeWifiProcess::new(),
        Arc::new(crate::wifi::radio::AllowAllRadioValidator),
    )
    .await
    .unwrap();
    let client = ClientSupervisor::start_with_process(&config, FakeSupplicantProcess::new())
        .await
        .unwrap();
    let service = ControlService::new_detached(config, network, dhcp, overrides)
        .with_wifi_supervisor(wifi)
        .with_wifi_client_supervisor(client);
    let response = service
        .dispatch(Request::CreateWifiClientProfile {
            profile: WifiClientProfileWriteRequest {
                id: "radio-test".into(),
                ssid: "upstream".into(),
                country_code: Some("PL".into()),
                security: WifiClientSecurity::Open,
                priority: 0,
                autoconnect: true,
                passphrase: None,
                clear_passphrase: false,
            },
        })
        .await;
    assert!(
        matches!(response, Response::WifiClientProfile { .. }),
        "{response:?}"
    );
    (service, directory)
}

pub(in crate::api::control::tests) async fn saved_wifi_without_runtime(
) -> (ControlService, tempfile::TempDir) {
    let directory = tempdir().unwrap();
    let mut base = wifi_base_config(directory.path());
    base.network
        .interfaces
        .get_mut("wlan0")
        .unwrap()
        .wifi
        .as_mut()
        .unwrap()
        .security = WifiSecurity::Wpa2;
    let store = crate::wifi::store::PassphraseStore::for_role(
        directory.path(),
        crate::wifi::store::WifiCredentialRole::Ap,
    );
    store
        .set("wlan0", &WifiPassphrase::new("previous-password").unwrap())
        .unwrap();
    base.network
        .interfaces
        .get_mut("wlan0")
        .unwrap()
        .wifi
        .as_mut()
        .unwrap()
        .passphrase_file = Some(store.directory().join("wlan0"));
    let overrides = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&base).await.unwrap();
    let service = ControlService::new_detached(
        base,
        Arc::new(crate::test_support::FakeNetworkProvider::default()),
        dhcp,
        overrides,
    );
    (service, directory)
}

pub(in crate::api::control::tests) async fn offline_client_profile_fixture(
) -> (ControlService, tempfile::TempDir) {
    let directory = tempdir().unwrap();
    let mut base = wifi_client_base_config(directory.path());
    let config = base.network.interfaces.get_mut("wlan1").unwrap();
    config.ipv4 = Some("192.0.2.10/24".parse().unwrap());
    config.dhcp_client.as_mut().unwrap().enabled = false;
    let overrides = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&base).await.unwrap();
    let service = ControlService::new_detached(
        base,
        Arc::new(crate::test_support::FakeNetworkProvider::default()),
        dhcp,
        overrides,
    );
    let response = service
        .dispatch(Request::CreateWifiClientProfile {
            profile: WifiClientProfileWriteRequest {
                id: "saved-uplink".into(),
                ssid: "Offline uplink".into(),
                country_code: Some("UA".into()),
                security: WifiClientSecurity::Wpa2,
                priority: 0,
                autoconnect: false,
                passphrase: Some("profile-original-password".into()),
                clear_passphrase: false,
            },
        })
        .await;
    assert!(
        matches!(response, Response::WifiClientProfile { .. }),
        "{response:?}"
    );
    (service, directory)
}

pub(in crate::api::control::tests) async fn client_convergence_service(
    fixture: &WifiClientFixture,
) -> (ControlService, tokio::task::JoinHandle<()>) {
    let desired = DesiredNetworkState::new(
        fixture.service.base_config.clone(),
        fixture.service.overrides.clone(),
    );
    desired.attach_converger();
    let service = ControlService::from_runtime(
        ControlRuntime {
            active_config: fixture.service.config.clone(),
            base_config: fixture.service.base_config.clone(),
            network: fixture.service.network.clone(),
            dhcp: fixture.service.dhcp.clone(),
            overrides: fixture.service.overrides.clone(),
            baselines: Vec::new(),
            ownership_journal: AddressOwnershipJournal::in_memory(),
            desired_state: desired.clone(),
            mutation_gate: Arc::new(NetworkMutationGate::default()),
        },
        ControlSubsystems {
            wifi_client: fixture.service.wifi_client.clone(),
            ..ControlSubsystems::default()
        },
    );
    let runtime = service.wifi_client.as_ref().unwrap().clone();
    let gate = service.network_mutations.clone();
    let worker_desired = desired.clone();
    let worker_runtime = runtime.clone();
    let worker = tokio::spawn(async move {
        loop {
            let version = worker_desired.version();
            {
                // Same gate as the daemon's convergence pass: dispatch must
                // release exclusive execution while retaining API admission.
                let _execution = gate.read().await;
                let config = worker_desired.effective().await.unwrap();
                let spec = WifiClientSpec::from_interface_config(
                    "wlan1",
                    &config.network.interfaces["wlan1"],
                )
                .unwrap()
                .unwrap();
                let result = worker_runtime
                    .configure(spec)
                    .await
                    .map_err(anyhow::Error::from);
                worker_desired.report_result(version, result.map(|_| BTreeMap::new()));
            }
            worker_desired.changed().await;
        }
    });
    (service, worker)
}
