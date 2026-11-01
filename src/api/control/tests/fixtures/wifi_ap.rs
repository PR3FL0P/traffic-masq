use super::super::*;

pub(in crate::api::control::tests) struct FakeWifiHostapd {
    pub(in crate::api::control::tests) shutdown: Arc<std::sync::atomic::AtomicBool>,
    pub(in crate::api::control::tests) join: Option<std::thread::JoinHandle<()>>,
    pub(in crate::api::control::tests) ctrl_path: std::path::PathBuf,
}

impl FakeWifiHostapd {
    pub(in crate::api::control::tests) fn spawn(
        ctrl_path: std::path::PathBuf,
        config_path: std::path::PathBuf,
    ) -> Self {
        let socket =
            std::os::unix::net::UnixDatagram::bind(&ctrl_path).expect("bind fake ctrl socket");
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("set read timeout");
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shutdown_for_thread = shutdown.clone();

        let join = std::thread::spawn(move || {
            let read_ssid = |path: &std::path::Path| -> String {
                let content = std::fs::read_to_string(path).expect("read fake config");
                let hex = content
                    .lines()
                    .find_map(|line| line.strip_prefix("ssid2="))
                    .expect("ssid2 present");
                let bytes: Vec<u8> = (0..hex.len())
                    .step_by(2)
                    .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
                    .collect();
                String::from_utf8(bytes).expect("utf8 ssid")
            };
            let mut ssid = read_ssid(&config_path);
            let mut buffer = [0u8; 4096];
            while !shutdown_for_thread.load(WifiOrdering::Relaxed) {
                let (read, from) = match socket.recv_from(&mut buffer) {
                    Ok(result) => result,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(_) => break,
                };
                let command = String::from_utf8_lossy(&buffer[..read]).into_owned();
                let reply = if command == "PING" {
                    "PONG\n".to_string()
                } else if command == "STATUS" {
                    format!(
                        "state=ENABLED\nssid[0]={ssid}\nbssid[0]=02:00:00:00:00:00\nnum_sta[0]=0\n"
                    )
                } else if command == "RELOAD" {
                    ssid = read_ssid(&config_path);
                    "OK\n".to_string()
                } else if command == "STA-FIRST" {
                    "FAIL\n".to_string()
                } else if command.starts_with("DEAUTHENTICATE ") {
                    "OK\n".to_string()
                } else {
                    "UNKNOWN COMMAND\n".to_string()
                };
                let _ = socket.send_to_addr(reply.as_bytes(), &from);
            }
        });

        Self {
            shutdown,
            join: Some(join),
            ctrl_path,
        }
    }
}

impl Drop for FakeWifiHostapd {
    fn drop(&mut self) {
        self.shutdown.store(true, WifiOrdering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        let _ = std::fs::remove_file(&self.ctrl_path);
    }
}

#[derive(Default)]
pub(in crate::api::control::tests) struct FakeWifiProcess {
    pub(in crate::api::control::tests) after_stop: StdMutex<Option<Box<dyn Fn() + Send + Sync>>>,
    pub(in crate::api::control::tests) fail_stop: std::sync::atomic::AtomicBool,
    pub(in crate::api::control::tests) fail_spawn: std::sync::atomic::AtomicBool,
    pub(in crate::api::control::tests) responders: StdMutex<HashMap<u32, FakeWifiHostapd>>,
    pub(in crate::api::control::tests) configs: StdMutex<HashMap<u32, std::path::PathBuf>>,
    pub(in crate::api::control::tests) next_pid: AtomicU32,
}

impl FakeWifiProcess {
    pub(in crate::api::control::tests) fn new() -> Arc<Self> {
        Arc::new(Self {
            next_pid: AtomicU32::new(2000),
            ..Default::default()
        })
    }
}

#[async_trait]
impl SupervisedProcess for FakeWifiProcess {
    async fn spawn(
        &self,
        _binary: &std::path::Path,
        config_path: &std::path::Path,
    ) -> Result<u32, WifiProcessError> {
        if self.fail_spawn.load(WifiOrdering::SeqCst) {
            return Err(WifiProcessError::Spawn {
                binary: _binary.to_path_buf(),
                source: std::io::Error::other("injected restoration spawn failure"),
            });
        }
        let pid = self.next_pid.fetch_add(1, WifiOrdering::Relaxed);
        let ctrl_path = config_path.with_extension("");
        let responder = FakeWifiHostapd::spawn(ctrl_path, config_path.to_path_buf());
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
        if self.fail_stop.load(WifiOrdering::SeqCst) {
            return Err(WifiProcessError::Signal {
                pid,
                source: nix::errno::Errno::EPERM,
            });
        }
        self.responders.lock().unwrap().remove(&pid);
        self.configs.lock().unwrap().remove(&pid);
        if let Some(hook) = self.after_stop.lock().unwrap().take() {
            hook();
        }
        Ok(())
    }

    async fn kill(&self, pid: u32) -> Result<(), WifiProcessError> {
        self.responders.lock().unwrap().remove(&pid);
        self.configs.lock().unwrap().remove(&pid);
        Ok(())
    }
}

pub(in crate::api::control::tests) fn wifi_ap_config(
    ssid: &str,
    security: WifiSecurity,
) -> crate::config::WifiApConfig {
    crate::config::WifiApConfig {
        ssid: ssid.to_string(),
        country_code: Some("PL".to_string()),
        band: WifiBand::Ghz2,
        channel: 6,
        channel_width: WifiChannelWidth::Ht20,
        security,
        hidden: false,
        client_isolation: false,
        max_stations: 32,
        passphrase_file: None,
    }
}

pub(in crate::api::control::tests) fn wifi_base_config(directory: &std::path::Path) -> AppConfig {
    let mut config = AppConfig::default();
    config.runtime.state_dir = directory.to_path_buf();
    config.wifi = WifiConfig {
        enabled: true,
        hostapd_binary: PathBuf::from("/usr/sbin/hostapd"),
        runtime_dir: directory.join("hostapd"),
        restart_backoff_seconds: 1,
    };
    config.network.interfaces.insert(
        "wlan0".to_string(),
        InterfaceConfig {
            wifi_concurrent: false,
            randomize_mac: false,
            mac_address: None,
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some("192.168.101.1/24".parse().unwrap()),
            dhcp: None,
            dhcp_client: None,
            wifi: Some(wifi_ap_config("net-a", WifiSecurity::Open)),
            wifi_client: None,
        },
    );
    config
}

pub(in crate::api::control::tests) struct WifiFixture {
    pub(in crate::api::control::tests) network: Arc<crate::test_support::FakeNetworkProvider>,
    pub(in crate::api::control::tests) service: ControlService,
    pub(in crate::api::control::tests) process: Arc<FakeWifiProcess>,
    pub(in crate::api::control::tests) _directory: tempfile::TempDir,
}

pub(in crate::api::control::tests) async fn configure_wlan0(
    wifi: &WifiSupervisor,
    config: &AppConfig,
) {
    let interface_config = config
        .network
        .interfaces
        .get("wlan0")
        .expect("wlan0 declared");
    let spec = WifiApSpec::from_interface_config("wlan0", interface_config)
        .expect("valid")
        .expect("wifi declared on wlan0");
    wifi.configure(spec).await.expect("configure wlan0");
}

pub(in crate::api::control::tests) async fn wifi_enabled_fixture() -> WifiFixture {
    let directory = tempdir().expect("tempdir");
    let config = wifi_base_config(directory.path());
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    network.add_interface("wlan0", 1).await;
    let process = FakeWifiProcess::new();
    let wifi = WifiSupervisor::start_with_process_and_radio(
        &config,
        process.clone(),
        Arc::new(crate::wifi::radio::AllowAllRadioValidator),
    )
    .await
    .expect("wifi supervisor");
    configure_wlan0(&wifi, &config).await;
    let service = ControlService::new_detached(config, network.clone(), dhcp, overrides)
        .with_wifi_supervisor(wifi);
    WifiFixture {
        network,
        service,
        process,
        _directory: directory,
    }
}

pub(in crate::api::control::tests) struct FakeSupplicant {
    pub(in crate::api::control::tests) shutdown: Arc<std::sync::atomic::AtomicBool>,
    pub(in crate::api::control::tests) join: Option<std::thread::JoinHandle<()>>,
    pub(in crate::api::control::tests) ctrl_path: std::path::PathBuf,
}

impl FakeSupplicant {
    pub(in crate::api::control::tests) fn spawn(
        ctrl_path: std::path::PathBuf,
        config_path: std::path::PathBuf,
        wpa_state: Arc<StdMutex<String>>,
    ) -> Self {
        let socket =
            std::os::unix::net::UnixDatagram::bind(&ctrl_path).expect("bind fake ctrl socket");
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("set read timeout");
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shutdown_for_thread = shutdown.clone();

        let join = std::thread::spawn(move || {
            let content = std::fs::read_to_string(&config_path).unwrap_or_default();
            let ssid = content
                .lines()
                .map(str::trim)
                .find_map(|line| line.strip_prefix("ssid="))
                .and_then(|hex| {
                    let bytes: Vec<u8> = (0..hex.len())
                        .step_by(2)
                        .filter_map(|index| {
                            if index + 2 <= hex.len() {
                                u8::from_str_radix(&hex[index..index + 2], 16).ok()
                            } else {
                                None
                            }
                        })
                        .collect();
                    String::from_utf8(bytes).ok()
                });

            let mut buffer = [0u8; 4096];
            let mut attached: Vec<std::os::unix::net::SocketAddr> = Vec::new();
            while !shutdown_for_thread.load(WifiOrdering::Relaxed) {
                let (read, from) = match socket.recv_from(&mut buffer) {
                    Ok(result) => result,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(_) => break,
                };
                let command = String::from_utf8_lossy(&buffer[..read]).into_owned();
                let reply = match command.as_str() {
                    "PING" => "PONG\n".to_string(),
                    "STATUS" => {
                        let state = wpa_state.lock().unwrap().clone();
                        let mut reply = format!("wpa_state={state}\n");
                        if let Some(ssid) = &ssid {
                            reply.push_str(&format!("ssid={ssid}\n"));
                        }
                        reply.push_str("bssid=02:00:00:00:00:01\nfreq=2437\n");
                        reply
                    }
                    "ATTACH" => {
                        attached.push(from.clone());
                        "OK\n".to_string()
                    }
                    "DETACH" => {
                        #[cfg(target_os = "linux")]
                        {
                            use std::os::linux::net::SocketAddrExt;
                            if let Some(name) = from.as_abstract_name() {
                                attached.retain(|address| address.as_abstract_name() != Some(name));
                            }
                        }
                        "OK\n".to_string()
                    }
                    "SCAN" => {
                        for addr in &attached {
                            let _ = socket.send_to_addr(b"<3>CTRL-EVENT-SCAN-RESULTS\n", addr);
                        }
                        "OK\n".to_string()
                    }
                    "BSS FIRST" => "id=0\nbssid=02:00:00:00:00:01\nfreq=2412\nlevel=-42\nflags=[WPA2-PSK-CCMP][SAE][ESS]\nssid=upstream\n".to_string(),
                    "BSS NEXT-0" => String::new(),
                    "RECONNECT" | "DISCONNECT" | "REASSOCIATE" => "OK\n".to_string(),
                    _ => "UNKNOWN COMMAND\n".to_string(),
                };
                let _ = socket.send_to_addr(reply.as_bytes(), &from);
            }
        });

        Self {
            shutdown,
            join: Some(join),
            ctrl_path,
        }
    }
}

impl Drop for FakeSupplicant {
    fn drop(&mut self) {
        self.shutdown.store(true, WifiOrdering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        let _ = std::fs::remove_file(&self.ctrl_path);
    }
}
