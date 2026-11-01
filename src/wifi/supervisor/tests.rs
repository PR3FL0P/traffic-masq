use std::os::unix::net::UnixDatagram as StdUnixDatagram;
use std::sync::atomic::{AtomicBool, Ordering};

use tempfile::tempdir;

use super::*;
use crate::config::{
    DhcpConfig, InterfaceConfig, InterfaceRole, NetworkConfig, RouterConfig, RuntimeConfig,
    SecurityConfig, ShutdownPolicy as ConfigShutdownPolicy, VpnConfig, WifiApConfig, WifiBand,
    WifiChannelWidth, WifiConfig, WifiSecurity,
};
use crate::test_support::{FakeProcessCall as FakeCall, FakeSupervisedProcess};
use crate::wifi::render::WifiDigest;

enum SsidSource {
    Fixed(String),
    ConfigFile(PathBuf),
}

impl SsidSource {
    fn current(&self) -> String {
        match self {
            SsidSource::Fixed(ssid) => ssid.clone(),
            SsidSource::ConfigFile(path) => read_ssid_from_config(path),
        }
    }
}

fn read_ssid_from_config(path: &Path) -> String {
    let content = std::fs::read_to_string(path).expect("read fake hostapd config");
    let hex = content
        .lines()
        .find_map(|line| line.strip_prefix("ssid2="))
        .expect("ssid2 line present");
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("valid hex"))
        .collect();
    String::from_utf8(bytes).expect("ssid2 decodes as UTF-8 in these tests")
}

struct FakeHostapdCtrl {
    shutdown: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
    ctrl_path: PathBuf,
}

impl FakeHostapdCtrl {
    fn spawn(ctrl_path: PathBuf, source: SsidSource) -> Self {
        Self::spawn_with_state(ctrl_path, source, "ENABLED")
    }

    fn spawn_with_state(ctrl_path: PathBuf, source: SsidSource, state: &str) -> Self {
        let state = state.to_string();
        let socket = StdUnixDatagram::bind(&ctrl_path).expect("bind fake ctrl socket");
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("set read timeout");
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_for_thread = shutdown.clone();

        let join = std::thread::spawn(move || {
            let mut ssid = source.current();
            let mut buffer = [0u8; 4096];
            while !shutdown_for_thread.load(Ordering::Relaxed) {
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
                        "state={state}\nssid[0]={ssid}\nbssid[0]=02:00:00:00:00:00\nnum_sta[0]=0\n"
                    )
                } else if command == "RELOAD" {
                    ssid = source.current();
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

    fn spawn_fixed(ctrl_path: PathBuf, ssid: &str) -> Self {
        Self::spawn(ctrl_path, SsidSource::Fixed(ssid.to_string()))
    }

    fn spawn_for_config(ctrl_path: PathBuf, config_path: PathBuf) -> Self {
        Self::spawn(ctrl_path, SsidSource::ConfigFile(config_path))
    }

    fn spawn_silent(ctrl_path: PathBuf) -> Self {
        let socket = StdUnixDatagram::bind(&ctrl_path).expect("bind silent fake ctrl socket");
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("set read timeout");
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_for_thread = shutdown.clone();
        let join = std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            while !shutdown_for_thread.load(Ordering::Relaxed) {
                match socket.recv_from(&mut buffer) {
                    Ok(_) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) => {}
                    Err(_) => break,
                }
            }
        });
        Self {
            shutdown,
            join: Some(join),
            ctrl_path,
        }
    }
}

impl Drop for FakeHostapdCtrl {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        let _ = std::fs::remove_file(&self.ctrl_path);
    }
}

type FakeProcess = FakeSupervisedProcess<FakeHostapdCtrl>;

fn fake_process() -> Arc<FakeProcess> {
    FakeProcess::new("hostapd", 1000, "", |_interface, config_path, _profile| {
        let ctrl_path = config_path.with_extension("");
        FakeHostapdCtrl::spawn_for_config(ctrl_path, config_path.to_path_buf())
    })
}

fn seed_process(process: &FakeProcess, pid: u32, config_path: PathBuf, ssid: &str) {
    let ctrl_path = config_path.with_extension("");
    let responder = FakeHostapdCtrl::spawn_fixed(ctrl_path, ssid);
    process.seed(pid, config_path, responder);
}

fn ap_config(ssid: &str) -> WifiApConfig {
    WifiApConfig {
        ssid: ssid.to_string(),
        country_code: Some("PL".to_string()),
        band: WifiBand::Ghz2,
        channel: 6,
        channel_width: WifiChannelWidth::Ht20,

        security: WifiSecurity::Open,
        hidden: false,
        client_isolation: false,
        max_stations: 32,
        passphrase_file: None,
    }
}

fn spec(interface: &str, ssid: &str) -> WifiApSpec {
    let config = InterfaceConfig {
        wifi_concurrent: false,
        mac_address: None,
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some("192.168.101.1/24".parse().expect("network")),
        dhcp: None,
        dhcp_client: None,
        wifi: Some(ap_config(ssid)),
        wifi_client: None,
    };
    WifiApSpec::from_interface_config(interface, &config)
        .expect("valid")
        .expect("spec")
}

fn app_config(state_dir: &Path, runtime_dir: &Path) -> AppConfig {
    AppConfig {
        runtime: RuntimeConfig {
            state_dir: state_dir.to_path_buf(),
            log_dir: state_dir.join("log"),
            socket_path: state_dir.join("daemon.sock"),
            pid_path: state_dir.join("daemon.pid"),
            socket_group: None,
            shutdown_policy: ConfigShutdownPolicy::PreserveInterfaces,
        },
        network: NetworkConfig::default(),
        router: RouterConfig::default(),
        dhcp: DhcpConfig {
            default_dns_servers: traffic_masq_protocol::DhcpDnsDefaults::default().servers,
            leases_dir: state_dir.join("dhcp/leases"),
            default_lease_seconds: 86_400,
        },
        wifi: WifiConfig {
            enabled: true,
            hostapd_binary: PathBuf::from("/usr/sbin/hostapd"),
            runtime_dir: runtime_dir.to_path_buf(),
            restart_backoff_seconds: 1,
        },
        wifi_client: Default::default(),
        vpn: VpnConfig {
            standalone: None,
            enabled: false,
            wireguard_config_dir: state_dir.join("vpn/wireguard"),
            wireguard_import_dir: "/etc/wireguard".into(),
            policy: Default::default(),
        },
        security: SecurityConfig {
            rollback_timeout_seconds: 60,
        },
        api: Default::default(),
        auth: Default::default(),
    }
}

async fn test_supervisor(
    state_dir: &Path,
    runtime_dir: &Path,
    process: Arc<FakeProcess>,
) -> HostapdSupervisor {
    tokio::fs::create_dir_all(runtime_dir)
        .await
        .expect("create runtime dir");
    let inner = Inner {
        recovery: Default::default(),
        client_runtime_dir: runtime_dir.join("client"),
        hostapd_binary: PathBuf::from("/usr/sbin/hostapd"),
        runtime_dir: runtime_dir.to_path_buf(),
        passphrase_store: PassphraseStore::new(state_dir.join("wifi/psk-ap")),
        records_dir: state_dir.join("wifi"),
        restart_backoff_seconds: 1,
        ctrl_timeout: Duration::from_millis(500),
        process,
        radio: Arc::new(crate::wifi::radio::AllowAllRadioValidator),
        tasks: Mutex::new(HashMap::new()),
        operation_lock: RwLock::new(()),
        interface_operations: Default::default(),
    };
    HostapdSupervisor {
        inner: Arc::new(inner),
    }
}

#[tokio::test]
async fn effective_specs_derives_one_spec_per_access_point_interface() {
    let temp = tempdir().expect("tempdir");
    let mut config = app_config(temp.path(), &temp.path().join("hostapd"));
    config.network.interfaces.insert(
        "wlan0".to_string(),
        InterfaceConfig {
            wifi_concurrent: false,
            mac_address: None,
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some("192.168.101.1/24".parse().unwrap()),
            dhcp: None,
            dhcp_client: None,
            wifi: Some(ap_config("net-a")),
            wifi_client: None,
        },
    );
    config.network.interfaces.insert(
        "wan0".to_string(),
        InterfaceConfig {
            wifi_concurrent: false,
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

    let specs = HostapdSupervisor::effective_specs(&config).expect("effective specs");
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].interface, "wlan0");
    assert_eq!(specs[0].ssid, "net-a");
}

#[tokio::test]
async fn configure_spawns_hostapd_and_persists_a_record() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;

    supervisor
        .configure(spec("wlan0", "net-a"))
        .await
        .expect("configure");

    assert_eq!(
        process.calls(),
        vec![FakeCall::Spawn(render::config_path(&runtime_dir, "wlan0"))]
    );
    let status = supervisor.status("wlan0").await.expect("status");
    assert_eq!(status.hostapd_state, HostapdState::Enabled);

    let record = WifiRecordStore::for_access_point(temp.path().join("wifi"), &runtime_dir, "wlan0")
        .load()
        .await
        .expect("load")
        .expect("present");
    assert_eq!(record.ssid, "net-a");
    assert_eq!(record.pid, 1000);
}

#[tokio::test]
async fn ap_waits_for_a_socket_created_during_ownership_observation() {
    let temp = tempdir().unwrap();
    let runtime = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime, process.clone()).await;
    process
        .suppress_spawn_responder
        .store(true, Ordering::Relaxed);
    let weak = Arc::downgrade(&process);
    let config = render::config_path(&runtime, "wlan0");
    let bound = AtomicBool::new(false);
    process.set_after_socket_proof_hook(move |pid| {
        if !bound.swap(true, Ordering::SeqCst) {
            seed_process(&weak.upgrade().unwrap(), pid, config.clone(), "net-a");
        }
    });

    supervisor.configure(spec("wlan0", "net-a")).await.unwrap();
    let record = supervisor
        .record_store("wlan0")
        .load()
        .await
        .unwrap()
        .unwrap();
    assert!(record.ctrl_dev.is_some() && record.ctrl_ino.is_some());
    assert_eq!(process.spawn_count(), 1);
    assert!(!process
        .calls()
        .iter()
        .any(|call| matches!(call, FakeCall::Terminate(_))));
}

#[tokio::test]
async fn readiness_failure_stops_the_spawned_hostapd_without_recording_it() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    process
        .suppress_spawn_responder
        .store(true, Ordering::Relaxed);
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;

    let error = supervisor
        .configure(spec("wlan0", "net-a"))
        .await
        .expect_err("readiness must time out");

    assert!(matches!(error, SupervisorError::StartupTimeout { .. }));
    assert_eq!(
        process.calls(),
        vec![
            FakeCall::Spawn(render::config_path(&runtime_dir, "wlan0")),
            FakeCall::Terminate(1000),
        ]
    );
    assert!(supervisor
        .record_store("wlan0")
        .load()
        .await
        .expect("load")
        .is_none());
    assert!(supervisor.status("wlan0").await.is_none());
}

#[tokio::test]
async fn configuring_the_same_spec_twice_is_a_no_op() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;

    supervisor
        .configure(spec("wlan0", "net-a"))
        .await
        .expect("configure once");
    supervisor
        .configure(spec("wlan0", "net-a"))
        .await
        .expect("configure again");

    assert_eq!(
        process.calls().len(),
        1,
        "second configure must not respawn"
    );
}

#[tokio::test]
async fn configure_after_a_failed_startup_spawns_instead_of_reloading() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;
    let spec = spec("wlan0", "net-a");

    supervisor
        .record_failed_startup(&spec, "interface busy with a foreign manager")
        .await;

    supervisor
        .configure(spec.clone())
        .await
        .expect("recovering from a failed startup must spawn hostapd, not reload it");

    assert_eq!(
        process.calls().len(),
        1,
        "the placeholder task has no real process to reload; configure must spawn fresh"
    );
}

#[tokio::test]
async fn an_ssid_only_change_reloads_instead_of_restarting() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;

    supervisor
        .configure(spec("wlan0", "net-a"))
        .await
        .expect("configure once");
    supervisor
        .configure(spec("wlan0", "net-b"))
        .await
        .expect("configure with new ssid");

    assert_eq!(
        process.calls().len(),
        1,
        "an SSID change must reload, not restart"
    );
    let status = supervisor.status("wlan0").await.expect("status");
    assert_eq!(status.spec.ssid, "net-b");

    assert_eq!(status.hostapd_state, HostapdState::Enabled);
}

#[tokio::test]
async fn a_channel_change_restarts_hostapd() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;

    supervisor
        .configure(spec("wlan0", "net-a"))
        .await
        .expect("configure once");

    let mut changed = spec("wlan0", "net-a");
    changed.channel = 11;
    supervisor
        .configure(changed)
        .await
        .expect("configure with new channel");

    assert_eq!(
        process.calls(),
        vec![
            FakeCall::Spawn(render::config_path(&runtime_dir, "wlan0")),
            FakeCall::Terminate(1000),
            FakeCall::Spawn(render::config_path(&runtime_dir, "wlan0")),
        ],
        "a channel change must terminate the old process, then spawn a new one"
    );
}

#[tokio::test]
async fn unchanged_ap_with_unresponsive_ctrl_socket_is_restarted() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;
    let original = spec("wlan0", "net-a");

    supervisor
        .configure(original.clone())
        .await
        .expect("configure original");
    let config_path = render::config_path(&runtime_dir, "wlan0");
    process.kill_externally(1000);
    process.seed(
        1000,
        config_path.clone(),
        FakeHostapdCtrl::spawn_silent(supervisor.ctrl_path("wlan0")),
    );

    supervisor
        .configure(original)
        .await
        .expect("unresponsive control socket must trigger restart");

    assert_eq!(process.spawn_count(), 2);
    assert!(process
        .calls()
        .iter()
        .any(|call| matches!(call, FakeCall::Terminate(1000))));
}

#[tokio::test]
async fn failed_restart_can_be_rolled_back_to_the_previous_ap() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;
    let original = spec("wlan0", "net-a");

    supervisor
        .configure(original.clone())
        .await
        .expect("configure original");

    process.fail_spawn.store(true, Ordering::Relaxed);
    let mut changed = original.clone();
    changed.channel = 11;
    supervisor
        .configure(changed)
        .await
        .expect_err("replacement spawn must fail");

    process.fail_spawn.store(false, Ordering::Relaxed);
    supervisor
        .configure(original.clone())
        .await
        .expect("rollback must respawn original");

    assert_eq!(
        supervisor.status("wlan0").await.expect("status").spec,
        original
    );
    assert_eq!(process.spawn_count(), 3);
}

#[tokio::test]
async fn recovers_a_process_spawned_after_a_durable_launch_intent() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;

    let target = spec("wlan0", "net-a");
    let rendered = supervisor.render_for(&target).await.expect("render");
    seed_process(&process, 4242, rendered.path.clone(), "net-a");
    supervisor
        .record_store("wlan0")
        .save(&PersistedWifiRecord {
            pid: 0,
            started_at_unix: 1,
            process_start_ticks: None,
            boot_id: Some("test-boot".to_string()),
            binary_path: Some(std::path::PathBuf::from("/usr/sbin/hostapd")),
            ctrl_path: supervisor.ctrl_path("wlan0"),
            ctrl_dev: None,
            ctrl_ino: None,
            config_path: rendered.path.clone(),
            config_digest: rendered.config_digest,
            key_digest: rendered.key_digest,
            ssid: "net-a".to_string(),
        })
        .await
        .expect("seed launch intent");

    supervisor
        .configure(target)
        .await
        .expect("recover and adopt");

    assert_eq!(
        process.spawn_count(),
        0,
        "recovery must not spawn a duplicate"
    );
    assert_eq!(supervisor.status("wlan0").await.expect("status").pid, 4242);
    assert_eq!(
        supervisor
            .record_store("wlan0")
            .load()
            .await
            .expect("load")
            .expect("record")
            .pid,
        4242,
        "the launch intent must be upgraded to the recovered PID"
    );
}

#[tokio::test]
async fn interrupted_reload_is_restarted_from_committed_state() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;

    let committed = spec("wlan0", "net-a");
    let rendered = supervisor.render_for(&committed).await.expect("render");
    // Model a crash after hostapd accepted a new SSID but before the
    // mutation completed and before desired state was persisted.
    seed_process(&process, 4243, rendered.path.clone(), "uncommitted-net");
    let store = supervisor.record_store("wlan0");
    store
        .save(&PersistedWifiRecord {
            pid: 4243,
            started_at_unix: 1,
            process_start_ticks: Some(4243),
            boot_id: Some("test-boot".into()),
            binary_path: Some(std::path::PathBuf::from("/usr/sbin/hostapd")),
            ctrl_path: supervisor.ctrl_path("wlan0"),
            ctrl_dev: None,
            ctrl_ino: None,
            config_path: rendered.path.clone(),
            config_digest: rendered.config_digest,
            key_digest: rendered.key_digest,
            ssid: "net-a".to_string(),
        })
        .await
        .expect("seed record");
    store
        .mark_transition()
        .await
        .expect("mark interrupted reload");

    supervisor
        .configure(committed)
        .await
        .expect("restart committed state");

    assert!(process
        .calls()
        .iter()
        .any(|call| matches!(call, FakeCall::Terminate(4243))));
    assert_eq!(process.spawn_count(), 1);
    assert!(!store.transition_pending().await.expect("transition state"));
}

#[tokio::test]
async fn startup_stops_owned_ap_absent_from_committed_configuration() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    tokio::fs::create_dir_all(&runtime_dir)
        .await
        .expect("create runtime dir");
    let process = fake_process();
    let config = app_config(temp.path(), &runtime_dir);
    let config_path = render::config_path(&runtime_dir, "wlan0");
    seed_process(&process, 4244, config_path.clone(), "uncommitted-net");
    let store = WifiRecordStore::for_access_point(temp.path().join("wifi"), &runtime_dir, "wlan0");
    store
        .save(&PersistedWifiRecord {
            pid: 0,
            started_at_unix: 1,
            process_start_ticks: None,
            boot_id: Some("test-boot".to_string()),
            binary_path: Some(std::path::PathBuf::from("/usr/sbin/hostapd")),
            ctrl_path: runtime_dir.join("wlan0"),
            ctrl_dev: None,
            ctrl_ino: None,
            config_path,
            config_digest: WifiDigest::from_bytes([1; 32]),
            key_digest: WifiDigest::from_bytes([2; 32]),
            ssid: "uncommitted-net".to_string(),
        })
        .await
        .expect("seed record");

    HostapdSupervisor::start_with_process(&config, process.clone())
        .await
        .expect("startup recovery");

    assert!(process
        .calls()
        .iter()
        .any(|call| matches!(call, FakeCall::Terminate(4244))));
    assert!(store.load().await.expect("load").is_none());
}

#[tokio::test]
async fn refuses_a_live_ctrl_socket_with_no_matching_record() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;

    let _foreign = FakeHostapdCtrl::spawn_fixed(supervisor.ctrl_path("wlan0"), "unrelated-network");

    let error = supervisor
        .configure(spec("wlan0", "net-a"))
        .await
        .expect_err("must refuse a foreign occupant");
    assert!(matches!(error, SupervisorError::NotOwned { .. }));
    assert!(
        process.calls().is_empty(),
        "a refusal must never spawn or signal anything"
    );
}

#[tokio::test]
async fn adoption_refuses_a_rebound_ctrl_socket_even_when_the_recorded_pid_still_matches() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;

    let target = spec("wlan0", "net-a");
    let rendered = supervisor.render_for(&target).await.expect("render");
    seed_process(&process, 4242, rendered.path.clone(), "net-a");
    supervisor
        .record_store("wlan0")
        .save(&PersistedWifiRecord {
            pid: 4242,
            started_at_unix: 1,
            process_start_ticks: Some(4242),
            boot_id: Some("test-boot".into()),
            binary_path: Some(PathBuf::from("/usr/sbin/hostapd")),
            ctrl_path: supervisor.ctrl_path("wlan0"),
            ctrl_dev: None,
            ctrl_ino: None,
            config_path: rendered.path.clone(),
            config_digest: rendered.config_digest,
            key_digest: rendered.key_digest,
            ssid: "net-a".to_string(),
        })
        .await
        .expect("seed record");

    process.detach_ctrl_socket(4242);
    let _foreign = FakeHostapdCtrl::spawn_fixed(supervisor.ctrl_path("wlan0"), "net-a");

    let error = supervisor
        .configure(target)
        .await
        .expect_err("matching PID is insufficient when the ctrl socket was rebound");
    assert!(matches!(error, SupervisorError::NotOwned { .. }));
    assert!(
        process.calls().is_empty(),
        "foreign ctrl ownership must not trigger a signal or replacement spawn"
    );
}

#[tokio::test]
async fn a_digest_mismatch_restarts_with_the_new_config() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;

    let target = spec("wlan0", "net-a");
    let rendered = supervisor.render_for(&target).await.expect("render");

    seed_process(&process, 4242, rendered.path.clone(), "net-a");
    supervisor
        .record_store("wlan0")
        .save(&PersistedWifiRecord {
            pid: 4242,
            started_at_unix: crate::wifi::lifecycle::unix_now(),
            process_start_ticks: Some(4242),
            boot_id: Some("test-boot".into()),
            binary_path: Some(std::path::PathBuf::from("/usr/sbin/hostapd")),
            ctrl_path: supervisor.ctrl_path("wlan0"),
            ctrl_dev: None,
            ctrl_ino: None,
            config_path: rendered.path.clone(),
            config_digest: WifiDigest::from_bytes([9; 32]),
            key_digest: rendered.key_digest,
            ssid: "net-a".to_string(),
        })
        .await
        .expect("seed stale record");

    supervisor.configure(target).await.expect("configure");

    assert_eq!(
        process.calls(),
        vec![
            FakeCall::Terminate(4242),
            FakeCall::Spawn(render::config_path(&runtime_dir, "wlan0")),
        ]
    );
}

#[tokio::test]
async fn absent_ctrl_socket_clears_any_stale_record_and_spawns_fresh() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;

    supervisor
        .record_store("wlan0")
        .save(&PersistedWifiRecord {
            pid: 9999,
            started_at_unix: crate::wifi::lifecycle::unix_now(),
            process_start_ticks: Some(9999),
            boot_id: Some("test-boot".into()),
            binary_path: Some(std::path::PathBuf::from("/usr/sbin/hostapd")),
            ctrl_path: supervisor.ctrl_path("wlan0"),
            ctrl_dev: None,
            ctrl_ino: None,
            config_path: render::config_path(&runtime_dir, "wlan0"),
            config_digest: WifiDigest::from_bytes([1; 32]),
            key_digest: WifiDigest::from_bytes([2; 32]),
            ssid: "net-a".to_string(),
        })
        .await
        .expect("seed stale record");

    supervisor
        .configure(spec("wlan0", "net-a"))
        .await
        .expect("configure");

    assert_eq!(
        process.calls(),
        vec![FakeCall::Spawn(render::config_path(&runtime_dir, "wlan0"))]
    );
    assert_eq!(
        WifiRecordStore::for_access_point(temp.path().join("wifi"), &runtime_dir, "wlan0")
            .load()
            .await
            .expect("load")
            .expect("present")
            .pid,
        1000
    );
}

#[tokio::test]
async fn disable_stops_hostapd_and_forgets_the_interface() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;
    supervisor
        .configure(spec("wlan0", "net-a"))
        .await
        .expect("configure");

    let disabled = supervisor.disable("wlan0").await.expect("disable");
    assert_eq!(disabled.map(|spec| spec.ssid), Some("net-a".to_string()));
    assert!(supervisor.status("wlan0").await.is_none());
    assert_eq!(process.calls().last(), Some(&FakeCall::Terminate(1000)));
    assert_eq!(
        WifiRecordStore::for_access_point(temp.path().join("wifi"), &runtime_dir, "wlan0")
            .load()
            .await
            .expect("load"),
        None
    );
}

#[tokio::test]
async fn disable_on_an_unconfigured_interface_is_none_not_an_error() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process).await;
    assert_eq!(supervisor.disable("wlan0").await.expect("disable"), None);
}

#[tokio::test]
async fn ensure_alive_respawns_a_dead_hostapd_and_backs_off_on_repeated_failure() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;
    supervisor
        .configure(spec("wlan0", "net-a"))
        .await
        .expect("configure");

    process.kill_externally(1000);
    process.fail_spawn.store(true, Ordering::Relaxed);

    let restarted = supervisor.ensure_alive().await.expect("ensure_alive");
    assert!(restarted, "a dead hostapd must trigger a respawn attempt");
    assert_eq!(
        process.calls().last(),
        Some(&FakeCall::Spawn(render::config_path(&runtime_dir, "wlan0")))
    );

    let calls_before = process.calls().len();
    let restarted_again = supervisor.ensure_alive().await.expect("ensure_alive again");
    assert!(!restarted_again, "backoff must suppress an immediate retry");
    assert_eq!(
        process.calls().len(),
        calls_before,
        "a suppressed retry must not call spawn again"
    );
}

#[tokio::test]
async fn ensure_alive_refuses_respawn_when_the_old_ctrl_socket_still_answers() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;
    supervisor
        .configure(spec("wlan0", "net-a"))
        .await
        .expect("configure");
    let original_record = supervisor
        .record_store("wlan0")
        .load()
        .await
        .expect("load")
        .expect("record");
    process.persistent_responder.store(true, Ordering::Relaxed);

    let error = supervisor
        .ensure_alive()
        .await
        .expect_err("persistent ctrl responder must be refused");

    assert!(matches!(error, SupervisorError::NotOwned { .. }));
    assert_eq!(
        process.calls(),
        vec![FakeCall::Spawn(render::config_path(&runtime_dir, "wlan0"))],
        "ownership refusal must not signal an already-dead PID or spawn a replacement"
    );
    assert_eq!(
        supervisor
            .record_store("wlan0")
            .load()
            .await
            .expect("load")
            .expect("record"),
        original_record,
        "ownership refusal must not overwrite the existing record"
    );
}

#[tokio::test]
async fn ensure_alive_leaves_a_healthy_access_point_untouched() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;
    supervisor
        .configure(spec("wlan0", "net-a"))
        .await
        .expect("configure");

    let restarted = supervisor.ensure_alive().await.expect("ensure_alive");
    assert!(!restarted, "a healthy hostapd must not be touched");
    assert_eq!(process.calls().len(), 1, "only the original spawn call");
}

#[tokio::test]
async fn set_passphrase_then_reconfigure_takes_the_reload_path() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;
    let mut secured = spec("wlan0", "net-a");
    secured.security = WifiSecurity::Wpa2;

    let first_passphrase =
        crate::wifi::secret::WifiPassphrase::new("first passphrase").expect("valid");
    supervisor
        .set_passphrase("wlan0", &first_passphrase)
        .await
        .expect("set_passphrase");
    supervisor
        .configure(secured.clone())
        .await
        .expect("configure");
    assert_eq!(process.calls().len(), 1);

    let second_passphrase =
        crate::wifi::secret::WifiPassphrase::new("second passphrase").expect("valid");
    supervisor
        .set_passphrase("wlan0", &second_passphrase)
        .await
        .expect("set_passphrase");
    assert_eq!(
        process.calls().len(),
        1,
        "storing a passphrase must not restart hostapd"
    );

    supervisor
        .configure(secured)
        .await
        .expect("configure again");
    assert_eq!(
        process.calls().len(),
        1,
        "a passphrase-only change must reload rather than restart"
    );
}

#[tokio::test]
async fn reload_sends_reload_even_when_nothing_changed() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;
    supervisor
        .configure(spec("wlan0", "net-a"))
        .await
        .expect("configure");

    let spec = supervisor.reload("wlan0").await.expect("reload");
    assert_eq!(spec.ssid, "net-a");
}

#[tokio::test]
async fn ctrl_operations_wait_for_the_supervisor_mutation_lock() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process).await;
    supervisor
        .configure(spec("wlan0", "net-a"))
        .await
        .expect("configure");

    let guard = supervisor.inner.interface_operations.lock("wlan0").await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), supervisor.status("wlan1"))
            .await
            .expect("another interface's launch must not block status")
            .is_none()
    );
    let concurrent = supervisor.clone();
    let mut reload = tokio::spawn(async move { concurrent.reload("wlan0").await });
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut reload)
            .await
            .is_err(),
        "RELOAD must wait while configure/restart owns operation_lock"
    );
    drop(guard);
    reload.await.expect("join").expect("reload after unlock");
}

#[tokio::test]
async fn ctrl_operations_reject_a_socket_not_owned_by_the_recorded_hostapd() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;
    supervisor
        .configure(spec("wlan0", "net-a"))
        .await
        .expect("configure");

    process.detach_ctrl_socket(1000);
    let ctrl_path = runtime_dir.join("wlan0");
    let _foreign = FakeHostapdCtrl::spawn_fixed(ctrl_path, "foreign-net");

    let reload = supervisor.reload("wlan0").await.unwrap_err();
    assert!(matches!(reload, SupervisorError::NotOwned { .. }));

    let stations = supervisor.stations("wlan0").await.unwrap_err();
    assert!(matches!(stations, SupervisorError::NotOwned { .. }));

    let mac = MacAddr::new([0x02, 0, 0, 0, 0, 1]);
    let deauth = supervisor.deauthenticate("wlan0", mac).await.unwrap_err();
    assert!(matches!(deauth, SupervisorError::NotOwned { .. }));

    let status = supervisor.status("wlan0").await.expect("configured status");
    assert_eq!(
        status.hostapd_state,
        HostapdState::Other("unreachable".to_string()),
        "STATUS must not be read from the foreign ctrl socket"
    );
    let WifiHealth::Retrying { error, .. } = status.health else {
        panic!("an unreachable owned control interface must be reported as an error");
    };
    assert!(
        error.contains("ownership") || error.contains("control"),
        "health should retain the concrete control/ownership failure: {error}"
    );

    let configure = supervisor
        .configure(spec("wlan0", "net-b"))
        .await
        .unwrap_err();
    assert!(matches!(configure, SupervisorError::NotOwned { .. }));
    assert_eq!(
        read_ssid_from_config(&render::config_path(&runtime_dir, "wlan0")),
        "net-a",
        "reload path must prove ctrl ownership before rewriting hostapd config"
    );
}

#[tokio::test]
async fn unexpected_hostapd_state_is_reported_as_an_error() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = FakeProcess::new("hostapd", 1000, "FAILED", |_, path, state| {
        FakeHostapdCtrl::spawn_with_state(
            path.with_extension(""),
            SsidSource::ConfigFile(path.to_path_buf()),
            state,
        )
    });
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process).await;
    supervisor
        .configure(spec("wlan0", "net-a"))
        .await
        .expect("PING-ready hostapd is accepted during startup");

    let status = supervisor.status("wlan0").await.expect("configured status");
    assert_eq!(
        status.hostapd_state,
        HostapdState::Other("FAILED".to_string())
    );
    let WifiHealth::Retrying { error, .. } = status.health else {
        panic!("an unknown hostapd state must not be reported as Starting");
    };
    assert!(error.contains("FAILED"));
}

#[tokio::test]
async fn reload_on_an_unconfigured_interface_is_not_configured() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process).await;

    let error = supervisor.reload("wlan0").await.unwrap_err();
    assert!(matches!(error, SupervisorError::NotConfigured { .. }));
}

#[tokio::test]
async fn deauthenticate_reaches_the_running_hostapd() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process).await;
    supervisor
        .configure(spec("wlan0", "net-a"))
        .await
        .expect("configure");

    let mac = MacAddr::new([0x02, 0, 0, 0, 0, 1]);
    supervisor
        .deauthenticate("wlan0", mac)
        .await
        .expect("deauthenticate");
}

#[tokio::test]
async fn deauthenticate_on_an_unconfigured_interface_is_not_configured() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process).await;

    let mac = MacAddr::new([0x02, 0, 0, 0, 0, 1]);
    let error = supervisor.deauthenticate("wlan0", mac).await.unwrap_err();
    assert!(matches!(error, SupervisorError::NotConfigured { .. }));
}

#[tokio::test]
async fn shutdown_with_preserve_interfaces_leaves_hostapd_and_its_record_alone() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;
    supervisor
        .configure(spec("wlan0", "net-a"))
        .await
        .expect("configure");

    supervisor
        .shutdown(ShutdownPolicy::PreserveInterfaces)
        .await;

    assert!(
        process
            .calls()
            .iter()
            .all(|call| !matches!(call, FakeCall::Terminate(_) | FakeCall::Kill(_))),
        "PreserveInterfaces must never signal hostapd"
    );
    assert!(
        WifiRecordStore::for_access_point(temp.path().join("wifi"), &runtime_dir, "wlan0")
            .load()
            .await
            .expect("load")
            .is_some(),
        "the record must survive so the next start can adopt it"
    );
}

#[tokio::test]
async fn shutdown_with_restore_interfaces_stops_hostapd_and_clears_its_record() {
    let temp = tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime_dir, process.clone()).await;
    supervisor
        .configure(spec("wlan0", "net-a"))
        .await
        .expect("configure");

    supervisor.shutdown(ShutdownPolicy::RestoreInterfaces).await;

    assert_eq!(process.calls().last(), Some(&FakeCall::Terminate(1000)));
    assert_eq!(
        WifiRecordStore::for_access_point(temp.path().join("wifi"), &runtime_dir, "wlan0")
            .load()
            .await
            .expect("load"),
        None
    );
}

#[test]
fn backoff_doubles_up_to_the_five_minute_ceiling() {
    assert_eq!(
        crate::wifi::retry::backoff_duration(5, 1),
        Duration::from_secs(5)
    );
    assert_eq!(
        crate::wifi::retry::backoff_duration(5, 2),
        Duration::from_secs(10)
    );
    assert_eq!(
        crate::wifi::retry::backoff_duration(5, 3),
        Duration::from_secs(20)
    );
    assert_eq!(
        crate::wifi::retry::backoff_duration(5, 20),
        crate::wifi::retry::BACKOFF_CEILING
    );
}

#[test]
fn restart_classification_matches_the_documented_reload_safe_set() {
    let base = spec("wlan0", "net-a");

    let mut ssid_only = base.clone();
    ssid_only.ssid = "net-b".to_string();
    assert!(!requires_restart(&base, &ssid_only));

    let mut hidden_only = base.clone();
    hidden_only.hidden = true;
    assert!(!requires_restart(&base, &hidden_only));

    let mut isolation_only = base.clone();
    isolation_only.client_isolation = true;
    assert!(!requires_restart(&base, &isolation_only));

    let mut channel_only = base.clone();
    channel_only.channel = 11;
    assert!(requires_restart(&base, &channel_only));

    let mut band_only = base.clone();
    band_only.band = WifiBand::Ghz5;
    assert!(requires_restart(&base, &band_only));

    let mut width_only = base.clone();
    width_only.channel_width = WifiChannelWidth::Ht40;
    assert!(requires_restart(&base, &width_only));

    let mut country_only = base.clone();
    country_only.country_code = Some("DE".to_string());
    assert!(requires_restart(&base, &country_only));

    let mut security_only = base.clone();
    security_only.security = WifiSecurity::Wpa2;
    assert!(requires_restart(&base, &security_only));
}

#[tokio::test]
async fn disabling_ap_never_signals_a_pid_with_mismatched_identity() {
    let temp = tempdir().unwrap();
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime, process.clone()).await;
    supervisor.configure(spec("wlan0", "test")).await.unwrap();
    supervisor
        .inner
        .tasks
        .lock()
        .await
        .get_mut("wlan0")
        .unwrap()
        .record
        .config_path = runtime.join("different.conf");
    assert!(matches!(
        supervisor.disable("wlan0").await,
        Err(SupervisorError::NotOwned { .. })
    ));
    assert!(!process
        .calls()
        .iter()
        .any(|c| matches!(c, FakeCall::Terminate(_) | FakeCall::Kill(_))));
}

#[tokio::test]
async fn disabled_acs_ap_keeps_backoff_after_a_successful_spawn() {
    let temp = tempdir().unwrap();
    let runtime = temp.path().join("hostapd");
    let process = FakeProcess::new("hostapd", 1000, "DISABLED", |_, path, state| {
        FakeHostapdCtrl::spawn_with_state(
            path.with_extension(""),
            SsidSource::ConfigFile(path.to_path_buf()),
            state,
        )
    });
    let supervisor = test_supervisor(temp.path(), &runtime, process.clone()).await;
    let mut ap = spec("wlan0", "acs-test");
    ap.channel = 0;
    supervisor.configure(ap.clone()).await.unwrap();

    for attempt in 1..=3 {
        assert!(supervisor.ensure_alive().await.unwrap());
        let count = process.spawn_count();
        assert!(!supervisor.ensure_alive().await.unwrap());
        assert_eq!(process.spawn_count(), count);
        supervisor.configure(ap.clone()).await.unwrap();
        assert_eq!(
            process.spawn_count(),
            count,
            "convergence must respect backoff"
        );
        let status = supervisor.status("wlan0").await.unwrap();
        let WifiHealth::Retrying { error, .. } = status.health else {
            panic!("a disabled AP must report failure");
        };
        assert!(error.contains("fixed channel"));
        let mut tasks = supervisor.inner.tasks.lock().await;
        let task = tasks.get_mut("wlan0").unwrap();
        assert_eq!(task.retry.attempts(), attempt);
        assert!(task.retry.next_restart().unwrap() > Instant::now());
        // Advance the supervisor's retry deadline without a wall-clock sleep.
        task.retry.retry_now();
    }
    let pid = supervisor.status("wlan0").await.unwrap().pid;
    process.kill_externally(pid);
    supervisor
        .inner
        .tasks
        .lock()
        .await
        .get_mut("wlan0")
        .unwrap()
        .retry
        .await_health(60);
    let count = process.spawn_count();
    supervisor.configure(ap).await.unwrap();
    assert_eq!(
        process.spawn_count(),
        count,
        "unchanged intent must not restart a dead process during backoff"
    );
    supervisor
        .inner
        .tasks
        .lock()
        .await
        .get_mut("wlan0")
        .unwrap()
        .retry
        .retry_now();
    process.set_spawn_profile("ENABLED");
    assert!(supervisor.ensure_alive().await.unwrap());
    supervisor
        .inner
        .tasks
        .lock()
        .await
        .get_mut("wlan0")
        .unwrap()
        .retry
        .retry_now();
    assert!(!supervisor.ensure_alive().await.unwrap());
    assert_eq!(
        supervisor.inner.tasks.lock().await["wlan0"]
            .retry
            .attempts(),
        0
    );
    assert!(matches!(
        supervisor.status("wlan0").await.unwrap().health,
        WifiHealth::Healthy
    ));
}

#[tokio::test]
async fn deterministic_acs_failure_suspends_retry_until_config_changes() {
    let temp = tempdir().unwrap();
    let runtime = temp.path().join("hostapd");
    let process = FakeProcess::new("hostapd", 1000, "DISABLED", |_, path, state| {
        FakeHostapdCtrl::spawn_with_state(
            path.with_extension(""),
            SsidSource::ConfigFile(path.to_path_buf()),
            state,
        )
    });
    let supervisor = test_supervisor(temp.path(), &runtime, process.clone()).await;
    let mut ap = spec("wlan0", "acs-test");
    ap.channel = 0;
    supervisor.configure(ap.clone()).await.unwrap();

    let pid = supervisor.status("wlan0").await.unwrap().pid;
    process.set_diagnostics(
        pid,
        &[
            "ACS: Unable to collect survey data",
            "ACS: All study options have failed",
            "Interface initialization failed",
            "ACS: Failed to start",
        ],
    );

    assert!(!supervisor.ensure_alive().await.unwrap());
    assert_eq!(
        process.spawn_count(),
        1,
        "fatal ACS failure must not respawn"
    );
    assert!(!supervisor.ensure_alive().await.unwrap());
    assert_eq!(process.spawn_count(), 1, "suspended retry must stay quiet");

    let status = supervisor.status("wlan0").await.unwrap();
    let WifiHealth::Retrying {
        error,
        retry_in_secs,
        advice,
        ..
    } = status.health
    else {
        panic!("suspended AP must expose its failure");
    };
    assert!(error.contains("Unable to collect survey data"));
    assert!(error.contains("automatic retry suspended"));
    assert_eq!(retry_in_secs, None);
    assert!(advice.unwrap().contains("suspended"));

    process.set_spawn_profile("ENABLED");
    let mut changed = ap;
    changed.ssid = "changed-after-failure".to_string();
    supervisor.configure(changed).await.unwrap();
    assert_eq!(
        process.spawn_count(),
        2,
        "changing config must restart even though the previous hostapd is dead"
    );
    assert!(!supervisor.inner.tasks.lock().await["wlan0"]
        .retry
        .is_suspended());
}

#[tokio::test]
async fn deterministic_startup_failure_is_suspended_immediately() {
    let temp = tempdir().unwrap();
    let runtime = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime, process.clone()).await;
    let ap = spec("wlan0", "broken-startup");

    supervisor
        .record_failed_startup(
            &ap,
            "hostapd startup failed: ACS: All study options have failed",
        )
        .await;

    assert!(!supervisor.ensure_alive().await.unwrap());
    assert_eq!(process.spawn_count(), 0);
    supervisor.configure(ap.clone()).await.unwrap();
    assert_eq!(
        process.spawn_count(),
        0,
        "reapplying unchanged desired state must not bypass suspension"
    );
    let task = supervisor.inner.tasks.lock().await["wlan0"].clone();
    assert!(task.retry.is_suspended());
    assert!(task
        .retry
        .failure()
        .unwrap()
        .contains("automatic retry suspended"));
}

#[tokio::test]
async fn interface_identity_change_resumes_a_suspended_retry() {
    let temp = tempdir().unwrap();
    let runtime = temp.path().join("hostapd");
    let process = FakeProcess::new("hostapd", 1000, "DISABLED", |_, path, state| {
        FakeHostapdCtrl::spawn_with_state(
            path.with_extension(""),
            SsidSource::ConfigFile(path.to_path_buf()),
            state,
        )
    });
    let supervisor = test_supervisor(temp.path(), &runtime, process.clone()).await;
    let mut ap = spec("lo", "acs-test");
    ap.channel = 0;
    supervisor.configure(ap).await.unwrap();

    let pid = supervisor.status("lo").await.unwrap().pid;
    process.set_diagnostics(pid, &["ACS: All study options have failed"]);
    assert!(!supervisor.ensure_alive().await.unwrap());
    assert!(supervisor.inner.tasks.lock().await["lo"]
        .retry
        .is_suspended());

    // Model the observation that the old interface disappeared. When the same
    // configured name now resolves again, it is a new interface identity and
    // the supervisor should permit one fresh attempt.
    supervisor
        .inner
        .tasks
        .lock()
        .await
        .get_mut("lo")
        .unwrap()
        .retry
        .resume_for_interface(None);
    process.set_spawn_profile("ENABLED");
    assert!(supervisor.ensure_alive().await.unwrap());
    assert_eq!(process.spawn_count(), 2);
    assert!(!supervisor.inner.tasks.lock().await["lo"]
        .retry
        .is_suspended());
}

#[test]
fn diagnostic_summary_prefers_root_cause_over_shutdown_noise() {
    let lines = vec![
        "ACS: Automatic channel selection started, this may take a bit".to_string(),
        "ACS: Unable to collect survey data".to_string(),
        "ACS: All study options have failed".to_string(),
        "Interface initialization failed".to_string(),
        "wlan0: AP-DISABLED".to_string(),
        "hostapd_free_hapd_data: Interface wlan0 wasn't started".to_string(),
        "nl80211: deinit ifname=wlan0 disabled_11b_rates=0".to_string(),
        "wlan0: CTRL-EVENT-TERMINATING".to_string(),
        "process exited with exit status: 0".to_string(),
    ];

    let summary = diagnostic_summary(&lines).expect("summary");
    assert!(summary.contains("Unable to collect survey data"));
    assert!(summary.contains("study options have failed"));
    assert!(summary.contains("initialization failed"));
    assert!(summary.contains("exit status: 0"));
}

#[test]
fn deterministic_hostapd_failures_are_classified_for_suspension() {
    for line in [
        "ACS: Unable to collect survey data",
        "ACS: All study options have failed",
        "Line 12: unknown configuration item 'foo'",
        "Hardware does not support configured mode",
        "Could not select hw_mode and channel. (-3)",
        "nl80211: Failed to set channel (freq=5180): -22 (Invalid argument)",
    ] {
        assert!(
            hostapd_failure_should_suspend_retry(&[line.to_string()]),
            "expected deterministic classification for: {line}"
        );
    }

    assert!(!hostapd_failure_should_suspend_retry(&[
        "nl80211: kernel reports: Device or resource busy".to_string(),
        "CTRL-EVENT-TERMINATING".to_string(),
    ]));
}

#[tokio::test]
async fn deterministic_background_startup_failure_suspends_without_losing_its_cause() {
    let temp = tempdir().unwrap();
    let runtime = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime, process.clone()).await;
    let ap = spec("wlan0", "test");
    supervisor.configure(ap.clone()).await.unwrap();
    process.kill_externally(1000);
    process
        .suppress_spawn_responder
        .store(true, Ordering::Relaxed);
    process.set_diagnostics(1001, &["Line 12: unknown configuration item 'foo'"]);

    assert!(supervisor.ensure_alive().await.unwrap());
    assert!(!supervisor.ensure_alive().await.unwrap());
    supervisor.configure(ap).await.unwrap();
    assert_eq!(process.spawn_count(), 2);
    let status = supervisor.status("wlan0").await.unwrap();
    let WifiHealth::Retrying {
        error,
        retry_in_secs,
        ..
    } = status.health
    else {
        panic!("failed background startup must retain its error");
    };
    assert!(error.contains("unknown configuration item"));
    assert!(error.contains("automatic retry suspended"));
    assert_eq!(retry_in_secs, None);
}

#[tokio::test]
async fn transient_channel_failure_keeps_retrying() {
    let temp = tempdir().unwrap();
    let runtime = temp.path().join("hostapd");
    let process = FakeProcess::new("hostapd", 1000, "DISABLED", |_, path, state| {
        FakeHostapdCtrl::spawn_with_state(
            path.with_extension(""),
            SsidSource::ConfigFile(path.to_path_buf()),
            state,
        )
    });
    let supervisor = test_supervisor(temp.path(), &runtime, process.clone()).await;
    supervisor.configure(spec("wlan0", "test")).await.unwrap();
    process.set_diagnostics(
        1000,
        &["nl80211: Failed to set channel (freq=5180): -16 (Device or resource busy)"],
    );
    process.set_spawn_profile("ENABLED");
    assert!(supervisor.ensure_alive().await.unwrap());
    assert_eq!(process.spawn_count(), 2);
    let task = supervisor.inner.tasks.lock().await["wlan0"].clone();
    assert!(!task.retry.is_suspended());
    assert!(task.retry.next_restart().is_some());
}

#[test]
fn driver_failure_classification_requires_a_permanent_cause_on_the_same_line() {
    for line in [
        "nl80211: Failed to set channel: -16 (Device or resource busy)",
        "Failed to set beacon parameters",
        "nl80211: Failed to set channel: -1 (Operation not permitted)",
        "nl80211: Failed to set channel: -16 (Device or resource busy)\nother operation failed: Invalid argument",
        "nl80211: Failed to set channel: -16 (Device or resource busy) | other operation failed: Invalid argument",
    ] {
        assert!(!hostapd_failure_text_should_suspend_retry(line), "{line}");
    }
    assert!(hostapd_failure_text_should_suspend_retry(
        "Failed to set beacon parameters: -95 (Operation not supported)"
    ));
}

#[tokio::test]
async fn changing_credentials_resumes_a_suspended_startup_with_the_same_spec() {
    let temp = tempdir().unwrap();
    let runtime = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime, process.clone()).await;
    let mut ap = spec("wlan0", "test");
    ap.security = WifiSecurity::Wpa2;
    supervisor
        .set_passphrase("wlan0", &WifiPassphrase::new("old-password").unwrap())
        .await
        .unwrap();
    supervisor
        .record_failed_startup(&ap, "unknown configuration item 'foo'")
        .await;
    supervisor.configure(ap.clone()).await.unwrap();
    assert_eq!(process.spawn_count(), 0);
    supervisor
        .set_passphrase("wlan0", &WifiPassphrase::new("new-password").unwrap())
        .await
        .unwrap();
    supervisor.configure(ap).await.unwrap();
    assert_eq!(process.spawn_count(), 1);
    assert!(!supervisor.inner.tasks.lock().await["wlan0"]
        .retry
        .is_suspended());
}

#[tokio::test]
async fn background_render_failure_is_recorded_and_backs_off() {
    let temp = tempdir().unwrap();
    let runtime = temp.path().join("hostapd");
    let process = fake_process();
    let supervisor = test_supervisor(temp.path(), &runtime, process.clone()).await;
    let mut ap = spec("wlan0", "test");
    ap.security = WifiSecurity::Wpa2;
    supervisor
        .set_passphrase("wlan0", &WifiPassphrase::new("test-password").unwrap())
        .await
        .unwrap();
    supervisor.configure(ap).await.unwrap();
    process.kill_externally(1000);
    supervisor.clear_passphrase("wlan0").await.unwrap();
    assert!(supervisor.ensure_alive().await.unwrap());
    assert!(!supervisor.ensure_alive().await.unwrap());
    let task = supervisor.inner.tasks.lock().await["wlan0"].clone();
    assert!(task.retry.failure().unwrap().contains("passphrase"));
    assert!(task.retry.next_restart().unwrap() > Instant::now());
    assert_eq!(process.spawn_count(), 1);
}

#[tokio::test]
async fn resumed_retry_does_not_reuse_diagnostics_from_the_old_process() {
    let temp = tempdir().unwrap();
    let runtime = temp.path().join("hostapd");
    let process = FakeProcess::new("hostapd", 1000, "DISABLED", |_, path, state| {
        FakeHostapdCtrl::spawn_with_state(
            path.with_extension(""),
            SsidSource::ConfigFile(path.to_path_buf()),
            state,
        )
    });
    let supervisor = test_supervisor(temp.path(), &runtime, process.clone()).await;
    supervisor.configure(spec("lo", "test")).await.unwrap();
    process.set_diagnostics(1000, &["ACS: All study options have failed"]);
    assert!(!supervisor.ensure_alive().await.unwrap());
    supervisor
        .inner
        .tasks
        .lock()
        .await
        .get_mut("lo")
        .unwrap()
        .retry
        .resume_for_interface(None);
    process.fail_spawn.store(true, Ordering::Relaxed);
    assert!(supervisor.ensure_alive().await.unwrap());
    let status = supervisor.status("lo").await.unwrap();
    let WifiHealth::Retrying { error, .. } = status.health else {
        panic!("spawn failure");
    };
    assert!(error.contains("fake spawn failure"));
    supervisor
        .inner
        .tasks
        .lock()
        .await
        .get_mut("lo")
        .unwrap()
        .retry
        .retry_now();
    assert!(supervisor.ensure_alive().await.unwrap());
    assert_eq!(process.spawn_count(), 3);
    assert!(!supervisor.inner.tasks.lock().await["lo"]
        .retry
        .is_suspended());
}

#[test]
fn compact_diagnostic_summary_preserves_a_permanent_cause_in_the_middle() {
    let mut lines: Vec<_> = (0..12)
        .map(|index| format!("setup failed at step {index}"))
        .collect();
    lines[6] = "Configured channel is not found".to_string();
    let summary = diagnostic_summary(&lines).unwrap();
    assert!(summary.contains("Configured channel is not found"));
    assert!(hostapd_failure_text_should_suspend_retry(&summary));
    assert_eq!(summary.split(" | ").count(), 8);
}

#[test]
fn configuration_error_preserves_underlying_failure() {
    let error = SupervisorError::Configuration(
        anyhow::anyhow!("Permission denied (os error 13)")
            .context("failed to inspect control socket"),
    );
    assert_eq!(
        error.to_string(),
        "failed to inspect control socket: Permission denied (os error 13)"
    );
}

#[test]
fn binary_preflight_error_preserves_underlying_failure() {
    let error = SupervisorError::BinaryPreflight(
        crate::wifi::lifecycle::BinaryPreflightError::ProbeFailed {
            binary: PathBuf::from("/usr/sbin/hostapd"),
            source: anyhow::anyhow!("Permission denied (os error 13)")
                .context("failed to start /usr/sbin/hostapd"),
        },
    );
    let message = error.to_string();
    assert!(message.contains("failed to start /usr/sbin/hostapd"));
    assert!(message.contains("Permission denied (os error 13)"));
}
