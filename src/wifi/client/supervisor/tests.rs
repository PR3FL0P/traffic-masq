use crate::wifi::client::render::scan_config_path;
use std::os::unix::net::UnixDatagram as StdUnixDatagram;
use std::sync::atomic::{AtomicBool, Ordering};

use tempfile::tempdir;

use super::*;
use crate::config::{
    DhcpConfig, InterfaceConfig, InterfaceRole, NetworkConfig, RouterConfig, RuntimeConfig,
    SecurityConfig, ShutdownPolicy as ConfigShutdownPolicy, VpnConfig, WifiClientConfig,
    WifiClientGlobalConfig, WifiClientSecurity, WifiConfig,
};
use crate::test_support::{FakeProcessCall as FakeCall, FakeSupervisedProcess};
use crate::wifi::render::WifiDigest;

fn read_ssid_from_config(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let hex = content
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("ssid="))?;
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
}

struct FakeSupplicantCtrl {
    shutdown: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
    ctrl_path: PathBuf,
}

impl FakeSupplicantCtrl {
    fn spawn(ctrl_path: PathBuf, state: &str, config: &Path) -> Self {
        let socket = StdUnixDatagram::bind(&ctrl_path).expect("bind fake ctrl socket");
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("set read timeout");
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_for_thread = shutdown.clone();
        let state = state.to_string();
        let config = config.to_path_buf();

        let join = std::thread::spawn(move || {
            let ssid = read_ssid_from_config(&config);
            let mut buffer = [0u8; 4096];
            let mut attached: Vec<std::os::unix::net::SocketAddr> = Vec::new();
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
                let reply = match command.as_str() {
                    "PING" => "PONG\n".to_string(),
                    "STATUS" => {
                        let mut reply = format!("wpa_state={state}\n");

                        if state == "COMPLETED" {
                            if let Some(ssid) = &ssid {
                                reply.push_str(&format!("ssid={ssid}\n"));
                            }
                            reply.push_str("bssid=02:00:00:00:00:01\nfreq=2437\n");
                        }
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
                    "RECONNECT" => {
                        for addr in &attached {
                            let _ = socket.send_to_addr(b"<3>CTRL-EVENT-CONNECTED - Connection to 02:00:00:00:00:01 completed\n", addr);
                        }
                        "OK\n".to_string()
                    }
                    "DISCONNECT" | "REASSOCIATE" => "OK\n".to_string(),
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

impl Drop for FakeSupplicantCtrl {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        let _ = std::fs::remove_file(&self.ctrl_path);
    }
}

type FakeProcess = FakeSupervisedProcess<FakeSupplicantCtrl>;

fn fake_process() -> Arc<FakeProcess> {
    FakeProcess::new(
        "wpa_supplicant",
        2000,
        "COMPLETED",
        |interface, config_path, state| {
            let ctrl_path = config_path
                .parent()
                .unwrap_or_else(|| Path::new(""))
                .join(interface);
            FakeSupplicantCtrl::spawn(ctrl_path, state, config_path)
        },
    )
}

fn seed_process(process: &FakeProcess, pid: u32, config_path: PathBuf, state: &str) {
    let ctrl_path = config_path.with_extension("");
    let responder = FakeSupplicantCtrl::spawn(ctrl_path, state, &config_path);
    process.seed(pid, config_path, responder);
}

fn client_config(ssid: &str) -> WifiClientConfig {
    WifiClientConfig {
        ssid: ssid.to_string(),
        country_code: Some("PL".to_string()),

        security: WifiClientSecurity::Open,
        passphrase_file: None,
    }
}

fn spec(interface: &str, ssid: &str) -> WifiClientSpec {
    let config = InterfaceConfig {
        role: InterfaceRole::Input,
        managed: true,
        ipv4: None,
        dhcp: None,
        dhcp_client: Some(crate::config::DhcpClientInterfaceConfig {
            enabled: true,
            ..Default::default()
        }),
        wifi: None,
        wifi_client: Some(client_config(ssid)),
        nat: true,
    };
    WifiClientSpec::from_interface_config(interface, &config)
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
            leases_dir: state_dir.join("dhcp/leases"),
            default_lease_seconds: 86_400,
        },
        wifi: WifiConfig::default(),
        wifi_client: WifiClientGlobalConfig {
            enabled: true,
            wpa_supplicant_binary: PathBuf::from("/usr/sbin/wpa_supplicant"),
            runtime_dir: runtime_dir.to_path_buf(),
            restart_backoff_seconds: 1,
        },
        vpn: VpnConfig {
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

async fn supervisor(
    state_dir: &Path,
    runtime_dir: &Path,
    process: Arc<FakeProcess>,
) -> WifiClientSupervisor {
    WifiClientSupervisor::start_with_process(&app_config(state_dir, runtime_dir), process)
        .await
        .expect("start")
}

#[tokio::test]
async fn configure_spawns_and_records_ownership() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .expect("configure");

    assert_eq!(process.spawn_count(), 1);
    let record = WifiRecordStore::for_client(temp.path().join("wifi"), &runtime, "wlan0")
        .load()
        .await
        .expect("load")
        .expect("record present");
    assert_eq!(record.ssid, "upstream");
    assert_eq!(record.pid, 2000);
}

#[tokio::test]
async fn readiness_failure_stops_the_spawned_supplicant_without_recording_it() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let process = fake_process();
    process
        .suppress_spawn_responder
        .store(true, Ordering::Relaxed);
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

    let error = supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .expect_err("readiness must time out");

    assert!(matches!(
        error,
        ClientSupervisorError::StartupTimeout { .. }
    ));
    assert_eq!(
        process.calls(),
        vec![
            FakeCall::Spawn(config_path(&runtime, "wlan0")),
            FakeCall::Terminate(2000),
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
async fn the_client_record_does_not_collide_with_an_access_point_one() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .expect("configure");

    let records = temp.path().join("wifi");
    assert!(WifiRecordStore::for_client(&records, &runtime, "wlan0")
        .load()
        .await
        .expect("load client")
        .is_some());
    assert!(
        WifiRecordStore::for_access_point(&records, &runtime, "wlan0")
            .load()
            .await
            .expect("load ap")
            .is_none(),
        "a client record must not be readable as an access point record"
    );
}

#[tokio::test]
async fn reconfiguring_with_an_identical_spec_is_a_no_op() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .expect("first");
    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .expect("second");

    assert_eq!(process.spawn_count(), 1);
    assert!(
        !process
            .calls()
            .iter()
            .any(|call| matches!(call, FakeCall::Terminate(_))),
        "an unchanged configure must not stop the running supplicant"
    );
}

#[tokio::test]
async fn changing_the_network_restarts_rather_than_reloading() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .expect("first");
    supervisor
        .configure(spec("wlan0", "somewhere-else"))
        .await
        .expect("second");

    assert_eq!(process.spawn_count(), 2);
    assert!(process
        .calls()
        .iter()
        .any(|call| matches!(call, FakeCall::Terminate(2000))));

    let record = WifiRecordStore::for_client(temp.path().join("wifi"), &runtime, "wlan0")
        .load()
        .await
        .expect("load")
        .expect("record");
    assert_eq!(record.ssid, "somewhere-else");
    assert_eq!(record.pid, 2001);
}

#[tokio::test]
async fn unchanged_client_with_unresponsive_ctrl_socket_is_restarted() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;
    let original = spec("wlan0", "upstream");

    supervisor
        .configure(original.clone())
        .await
        .expect("configure original");
    let config = config_path(&runtime, "wlan0");
    process.kill_externally(2000);
    process.seed(
        2000,
        config,
        FakeSupplicantCtrl::spawn_silent(runtime.join("wlan0")),
    );

    supervisor
        .configure(original)
        .await
        .expect("unresponsive control socket must trigger restart");

    assert_eq!(process.spawn_count(), 2);
    assert!(process
        .calls()
        .iter()
        .any(|call| matches!(call, FakeCall::Terminate(2000))));
}

#[tokio::test]
async fn failed_restart_can_be_rolled_back_to_the_previous_network() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;
    let original = spec("wlan0", "upstream");

    supervisor
        .configure(original.clone())
        .await
        .expect("configure original");

    process.fail_spawn.store(true, Ordering::Relaxed);
    supervisor
        .configure(spec("wlan0", "somewhere-else"))
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
async fn a_passphrase_only_change_still_restarts() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

    let mut secured = spec("wlan0", "upstream");
    secured.security = WifiClientSecurity::Wpa2;
    supervisor
        .set_passphrase(
            "wlan0",
            &WifiPassphrase::new("first-secret").expect("valid"),
        )
        .await
        .expect("set first");
    supervisor
        .configure(secured.clone())
        .await
        .expect("configure");
    assert_eq!(process.spawn_count(), 1);

    supervisor
        .set_passphrase(
            "wlan0",
            &WifiPassphrase::new("second-secret").expect("valid"),
        )
        .await
        .expect("set second");
    supervisor.configure(secured).await.expect("reconfigure");

    assert_eq!(
        process.spawn_count(),
        2,
        "a key-material-only change must be detected via key_digest"
    );
}

#[tokio::test]
async fn an_unchanged_supplicant_from_a_previous_daemon_is_adopted() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let records = temp.path().join("wifi");
    let process = fake_process();

    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;
    let target = spec("wlan0", "upstream");
    let rendered = supervisor.render_for(&target).await.expect("render");
    write_config_file(&rendered).await.expect("write config");
    seed_process(&process, 4242, rendered.path.clone(), "COMPLETED");
    WifiRecordStore::for_client(&records, &runtime, "wlan0")
        .save(&PersistedWifiRecord {
            pid: 4242,
            started_at_unix: 1,
            process_start_ticks: None,
            boot_id: None,
            binary_path: Some(std::path::PathBuf::from("/usr/sbin/wpa_supplicant")),
            ctrl_path: runtime.join("wlan0"),
            ctrl_dev: None,
            ctrl_ino: None,
            config_path: rendered.path.clone(),
            config_digest: rendered.config_digest,
            key_digest: rendered.key_digest,
            ssid: "upstream".to_string(),
        })
        .await
        .expect("seed record");

    supervisor.configure(target).await.expect("configure");

    assert_eq!(
        process.spawn_count(),
        0,
        "an adopted supplicant must not be respawned"
    );
    assert_eq!(
        supervisor.status("wlan0").await.expect("status").pid,
        4242,
        "the adopted pid must be the one now tracked"
    );
}

#[tokio::test]
async fn recovers_supplicant_spawned_after_a_durable_launch_intent() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let records = temp.path().join("wifi");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

    let target = spec("wlan0", "upstream");
    let rendered = supervisor.render_for(&target).await.expect("render");
    write_config_file(&rendered).await.expect("write config");
    seed_process(&process, 4242, rendered.path.clone(), "COMPLETED");
    WifiRecordStore::for_client(&records, &runtime, "wlan0")
        .save(&PersistedWifiRecord {
            pid: 0,
            started_at_unix: 1,
            process_start_ticks: None,
            boot_id: Some("test-boot".to_string()),
            binary_path: Some(std::path::PathBuf::from("/usr/sbin/wpa_supplicant")),
            ctrl_path: runtime.join("wlan0"),
            ctrl_dev: None,
            ctrl_ino: None,
            config_path: rendered.path.clone(),
            config_digest: rendered.config_digest,
            key_digest: rendered.key_digest,
            ssid: "upstream".to_string(),
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
}

#[tokio::test]
async fn startup_stops_pending_client_absent_from_committed_configuration() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    tokio::fs::create_dir_all(&runtime)
        .await
        .expect("create runtime dir");
    let process = fake_process();
    let config = app_config(temp.path(), &runtime);
    let process_config = config_path(&runtime, "wlan0");
    seed_process(&process, 4248, process_config.clone(), "COMPLETED");
    let store = WifiRecordStore::for_client(temp.path().join("wifi"), &runtime, "wlan0");
    store
        .save(&PersistedWifiRecord {
            pid: 0,
            started_at_unix: 1,
            process_start_ticks: None,
            boot_id: Some("test-boot".to_string()),
            binary_path: Some(std::path::PathBuf::from("/usr/sbin/wpa_supplicant")),
            ctrl_path: runtime.join("wlan0"),
            ctrl_dev: None,
            ctrl_ino: None,
            config_path: process_config,
            config_digest: WifiDigest::from_bytes([1; 32]),
            key_digest: WifiDigest::from_bytes([2; 32]),
            ssid: "uncommitted-network".to_string(),
        })
        .await
        .expect("seed launch intent");

    WifiClientSupervisor::start_with_process(&config, process.clone())
        .await
        .expect("startup recovery");

    assert!(process
        .calls()
        .iter()
        .any(|call| matches!(call, FakeCall::Terminate(4248))));
    assert!(store.load().await.expect("load").is_none());
}

#[tokio::test]
async fn a_still_associating_supplicant_is_adopted_not_refused() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let records = temp.path().join("wifi");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

    let target = spec("wlan0", "upstream");
    let rendered = supervisor.render_for(&target).await.expect("render");
    write_config_file(&rendered).await.expect("write config");

    seed_process(&process, 4243, rendered.path.clone(), "SCANNING");
    WifiRecordStore::for_client(&records, &runtime, "wlan0")
        .save(&PersistedWifiRecord {
            pid: 4243,
            started_at_unix: 1,
            process_start_ticks: None,
            boot_id: None,
            binary_path: Some(std::path::PathBuf::from("/usr/sbin/wpa_supplicant")),
            ctrl_path: runtime.join("wlan0"),
            ctrl_dev: None,
            ctrl_ino: None,
            config_path: rendered.path.clone(),
            config_digest: rendered.config_digest,
            key_digest: rendered.key_digest,
            ssid: "upstream".to_string(),
        })
        .await
        .expect("seed record");

    supervisor.configure(target).await.expect("configure");

    assert_eq!(process.spawn_count(), 0);
    assert_eq!(supervisor.status("wlan0").await.expect("status").pid, 4243);
}

#[tokio::test]
async fn a_supplicant_answering_for_a_different_network_is_refused() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let records = temp.path().join("wifi");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

    let target = spec("wlan0", "upstream");
    let rendered = supervisor.render_for(&target).await.expect("render");
    write_config_file(&rendered).await.expect("write config");
    seed_process(&process, 4244, rendered.path.clone(), "COMPLETED");

    WifiRecordStore::for_client(&records, &runtime, "wlan0")
        .save(&PersistedWifiRecord {
            pid: 4244,
            started_at_unix: 1,
            process_start_ticks: None,
            boot_id: None,
            binary_path: Some(std::path::PathBuf::from("/usr/sbin/wpa_supplicant")),
            ctrl_path: runtime.join("wlan0"),
            ctrl_dev: None,
            ctrl_ino: None,
            config_path: rendered.path.clone(),
            config_digest: rendered.config_digest,
            key_digest: rendered.key_digest,
            ssid: "someone-elses-network".to_string(),
        })
        .await
        .expect("seed record");

    let error = supervisor.configure(target).await.expect_err("must refuse");
    assert!(
        matches!(error, ClientSupervisorError::NotOwned { .. }),
        "{error:?}"
    );
    assert_eq!(process.spawn_count(), 0);
}

#[tokio::test]
async fn a_live_supplicant_with_no_record_is_refused_never_taken_over() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

    let target = spec("wlan0", "upstream");
    let rendered = supervisor.render_for(&target).await.expect("render");
    write_config_file(&rendered).await.expect("write config");
    seed_process(&process, 4245, rendered.path.clone(), "COMPLETED");

    let error = supervisor.configure(target).await.expect_err("must refuse");
    assert!(
        matches!(error, ClientSupervisorError::NotOwned { .. }),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_stale_record_with_nothing_behind_it_is_a_fresh_start() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let records = temp.path().join("wifi");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

    WifiRecordStore::for_client(&records, &runtime, "wlan0")
        .save(&PersistedWifiRecord {
            pid: 9999,
            started_at_unix: 1,
            process_start_ticks: None,
            boot_id: None,
            binary_path: Some(std::path::PathBuf::from("/usr/sbin/wpa_supplicant")),
            ctrl_path: runtime.join("wlan0"),
            ctrl_dev: None,
            ctrl_ino: None,
            config_path: runtime.join("wlan0.conf"),
            config_digest: WifiDigest::from_bytes([7; 32]),
            key_digest: WifiDigest::from_bytes([8; 32]),
            ssid: "upstream".to_string(),
        })
        .await
        .expect("seed record");

    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .expect("configure");
    assert_eq!(process.spawn_count(), 1);
}

#[tokio::test]
async fn a_config_changed_while_the_daemon_was_stopped_restarts_the_supplicant() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let records = temp.path().join("wifi");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

    let target = spec("wlan0", "upstream");
    let rendered = supervisor.render_for(&target).await.expect("render");
    write_config_file(&rendered).await.expect("write config");
    seed_process(&process, 4246, rendered.path.clone(), "COMPLETED");

    WifiRecordStore::for_client(&records, &runtime, "wlan0")
        .save(&PersistedWifiRecord {
            pid: 4246,
            started_at_unix: 1,
            process_start_ticks: None,
            boot_id: None,
            binary_path: Some(std::path::PathBuf::from("/usr/sbin/wpa_supplicant")),
            ctrl_path: runtime.join("wlan0"),
            ctrl_dev: None,
            ctrl_ino: None,
            config_path: rendered.path.clone(),
            config_digest: WifiDigest::from_bytes([1; 32]),
            key_digest: WifiDigest::from_bytes([2; 32]),
            ssid: "upstream".to_string(),
        })
        .await
        .expect("seed record");

    supervisor.configure(target).await.expect("configure");

    assert_eq!(process.spawn_count(), 1);
    assert!(process
        .calls()
        .iter()
        .any(|call| matches!(call, FakeCall::Terminate(4246))));
}

#[tokio::test]
async fn ensure_alive_respawns_a_supplicant_that_died() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .expect("configure");
    process.kill_externally(2000);

    assert!(supervisor.ensure_alive().await.expect("ensure_alive"));
    assert_eq!(process.spawn_count(), 2);
}

#[tokio::test]
async fn ensure_alive_refuses_respawn_when_the_old_ctrl_socket_still_answers() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;
    supervisor
        .configure(spec("wlan0", "upstream"))
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

    assert!(matches!(error, ClientSupervisorError::NotOwned { .. }));
    assert_eq!(
        process.calls(),
        vec![FakeCall::Spawn(config_path(&runtime, "wlan0"))],
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
async fn ensure_alive_leaves_a_healthy_supplicant_alone() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .expect("configure");

    assert!(!supervisor.ensure_alive().await.expect("ensure_alive"));
    assert_eq!(process.spawn_count(), 1);
}

#[tokio::test]
async fn ensure_alive_tolerates_a_supplicant_that_is_still_associating() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let process = fake_process();
    process.set_spawn_profile("4WAY_HANDSHAKE");
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .expect("configure");

    assert!(
        !supervisor.ensure_alive().await.expect("ensure_alive"),
        "a supplicant inside the association grace period must be left alone"
    );
    assert_eq!(process.spawn_count(), 1);
}

#[tokio::test]
async fn ensure_alive_restarts_a_supplicant_wedged_past_the_grace_period() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let process = fake_process();
    process.set_spawn_profile("4WAY_HANDSHAKE");
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .expect("configure");

    {
        let mut tasks = supervisor.inner.tasks.lock().await;
        let task = tasks.get_mut("wlan0").expect("task");
        task.associated_or_started_at = Instant::now() - ASSOCIATION_GRACE - Duration::from_secs(1);
    }

    assert!(
        supervisor.ensure_alive().await.expect("ensure_alive"),
        "a supplicant stuck out of COMPLETED past the grace period must be restarted"
    );
    assert_eq!(process.spawn_count(), 2);
}

#[tokio::test]
async fn ensure_alive_does_not_restart_a_normally_disconnected_supplicant() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let process = fake_process();
    process.set_spawn_profile("DISCONNECTED");
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .expect("configure");
    {
        let mut tasks = supervisor.inner.tasks.lock().await;
        tasks
            .get_mut("wlan0")
            .expect("task")
            .associated_or_started_at = Instant::now() - ASSOCIATION_GRACE - Duration::from_secs(1);
    }

    assert!(!supervisor.ensure_alive().await.expect("ensure_alive"));
    assert_eq!(process.spawn_count(), 1);
}

#[tokio::test]
async fn reaching_completed_resets_the_association_clock() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .expect("configure");
    {
        let mut tasks = supervisor.inner.tasks.lock().await;
        let task = tasks.get_mut("wlan0").expect("task");
        task.associated_or_started_at = Instant::now() - ASSOCIATION_GRACE - Duration::from_secs(1);
    }

    assert!(!supervisor.ensure_alive().await.expect("ensure_alive"));
    let refreshed = {
        let tasks = supervisor.inner.tasks.lock().await;
        tasks.get("wlan0").expect("task").associated_or_started_at
    };
    assert!(refreshed.elapsed() < ASSOCIATION_GRACE);
}

#[tokio::test]
async fn a_failed_respawn_backs_off_before_trying_again() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .expect("configure");
    process.kill_externally(2000);
    process.fail_spawn.store(true, Ordering::Relaxed);

    assert!(supervisor.ensure_alive().await.expect("first"));
    let after_first = process.spawn_count();

    assert!(!supervisor.ensure_alive().await.expect("second"));
    assert_eq!(process.spawn_count(), after_first);
}

#[tokio::test]
async fn disable_stops_the_supplicant_and_clears_its_record() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .expect("configure");
    let removed = supervisor.disable("wlan0").await.expect("disable");

    assert_eq!(removed.map(|spec| spec.ssid), Some("upstream".to_string()));
    assert!(process
        .calls()
        .iter()
        .any(|call| matches!(call, FakeCall::Terminate(2000))));
    assert!(
        WifiRecordStore::for_client(temp.path().join("wifi"), &runtime, "wlan0")
            .load()
            .await
            .expect("load")
            .is_none()
    );
    assert!(supervisor.status("wlan0").await.is_none());
    assert!(!config_path(&runtime, "wlan0").exists());
}

#[tokio::test]
async fn disabling_an_unconfigured_interface_is_not_an_error() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let supervisor = supervisor(temp.path(), &runtime, fake_process()).await;
    assert!(supervisor
        .disable("wlan9")
        .await
        .expect("disable")
        .is_none());
}

#[tokio::test]
async fn status_reports_the_live_association() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let supervisor = supervisor(temp.path(), &runtime, fake_process()).await;

    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .expect("configure");
    let status = supervisor.status("wlan0").await.expect("status");

    assert_eq!(status.interface, "wlan0");
    assert_eq!(status.wpa_state, WpaState::Completed);
    assert_eq!(status.freq, Some(2437));
    assert_eq!(status.spec.ssid, "upstream");
}

#[tokio::test]
async fn status_of_a_managed_but_unreachable_supplicant_says_so() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .expect("configure");
    process.kill_externally(2000);

    let status = supervisor.status("wlan0").await.expect("still managed");
    assert_eq!(status.wpa_state, WpaState::Other("unreachable".to_string()));
}

#[tokio::test]
async fn reconnect_requires_a_configured_interface() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let supervisor = supervisor(temp.path(), &runtime, fake_process()).await;

    let error = supervisor
        .reconnect("wlan9")
        .await
        .expect_err("not managed");
    assert!(
        matches!(error, ClientSupervisorError::NotConfigured { .. }),
        "{error:?}"
    );

    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .expect("configure");
    supervisor.reconnect("wlan0").await.expect("reconnect");
}

#[tokio::test]
async fn shutdown_with_preserve_interfaces_leaves_the_supplicant_running() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .expect("configure");
    supervisor
        .shutdown(ShutdownPolicy::PreserveInterfaces)
        .await;

    assert!(!process
        .calls()
        .iter()
        .any(|call| matches!(call, FakeCall::Terminate(_) | FakeCall::Kill(_))));
    assert!(
        WifiRecordStore::for_client(temp.path().join("wifi"), &runtime, "wlan0")
            .load()
            .await
            .expect("load")
            .is_some()
    );
}

#[tokio::test]
async fn shutdown_with_restore_interfaces_stops_it_and_clears_the_record() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .expect("configure");
    supervisor.shutdown(ShutdownPolicy::RestoreInterfaces).await;

    assert!(process
        .calls()
        .iter()
        .any(|call| matches!(call, FakeCall::Terminate(2000))));
    assert!(
        WifiRecordStore::for_client(temp.path().join("wifi"), &runtime, "wlan0")
            .load()
            .await
            .expect("load")
            .is_none()
    );
}

#[tokio::test]
async fn scan_on_unconfigured_interface_performs_ephemeral_scan_and_cleans_up() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

    let results = supervisor.scan("wlan0").await.expect("scan succeeds");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ssid, "upstream");
    assert_eq!(results[0].frequency_mhz, 2412);

    // Ephemeral process was spawned and terminated:
    assert_eq!(process.spawn_count(), 1);
    let calls = process.calls();
    assert!(calls.iter().any(|c| matches!(c, FakeCall::Terminate(_))));

    // Ephemeral config, socket, and durable ownership were removed:
    assert!(!runtime.join("wlan0-scan.conf").exists());
    assert!(!runtime.join("wlan0").exists());
    assert!(
        WifiRecordStore::for_scan(temp.path().join("wifi"), &runtime, "wlan0")
            .load()
            .await
            .expect("load scan record")
            .is_none()
    );
}

#[tokio::test]
async fn ephemeral_scan_cleanup_preserves_rebound_foreign_socket() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;
    let foreign = Arc::new(std::sync::Mutex::new(None));
    let foreign_for_hook = foreign.clone();
    let ctrl_path = runtime.join("wlan0");
    let scan_config = scan_config_path(&runtime, "wlan0");

    process.set_after_terminate_hook(move |_| {
        let responder = FakeSupplicantCtrl::spawn(ctrl_path.clone(), "COMPLETED", &scan_config);
        *foreign_for_hook.lock().expect("foreign responder lock") = Some(responder);
    });

    assert!(matches!(
        supervisor.scan("wlan0").await,
        Err(ClientSupervisorError::NotOwned { .. })
    ));

    assert!(runtime.join("wlan0").exists());
    assert!(!runtime.join("wlan0-scan.conf").exists());
    assert!(
        WifiRecordStore::for_scan(temp.path().join("wifi"), &runtime, "wlan0")
            .load()
            .await
            .expect("load scan record")
            .is_none()
    );

    drop(foreign.lock().expect("foreign responder lock").take());
}

#[tokio::test]
async fn startup_recovers_an_interrupted_ephemeral_scan() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    tokio::fs::create_dir_all(&runtime)
        .await
        .expect("create runtime dir");
    let process = fake_process();
    let config = app_config(temp.path(), &runtime);
    let scan_path = scan_config_path(&runtime, "wlan0");
    seed_process(&process, 4249, scan_path.clone(), "SCANNING");
    let store = WifiRecordStore::for_scan(temp.path().join("wifi"), &runtime, "wlan0");
    store
        .save(&PersistedWifiRecord {
            pid: 0,
            started_at_unix: 1,
            process_start_ticks: None,
            boot_id: Some("test-boot".to_string()),
            binary_path: Some(std::path::PathBuf::from("/usr/sbin/wpa_supplicant")),
            ctrl_path: runtime.join("wlan0"),
            ctrl_dev: None,
            ctrl_ino: None,
            config_path: scan_path,
            config_digest: WifiDigest::from_bytes([3; 32]),
            key_digest: WifiDigest::from_bytes([4; 32]),
            ssid: String::new(),
        })
        .await
        .expect("seed scan launch intent");

    WifiClientSupervisor::start_with_process(&config, process.clone())
        .await
        .expect("startup recovery");

    assert!(process
        .calls()
        .iter()
        .any(|call| matches!(call, FakeCall::Terminate(4249))));
    assert!(store.load().await.expect("load").is_none());
}

#[tokio::test]
async fn scan_on_configured_interface_reuses_running_supplicant() {
    let temp = tempdir().expect("tempdir");
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .expect("configure");
    assert_eq!(process.spawn_count(), 1);

    let results = supervisor.scan("wlan0").await.expect("scan succeeds");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ssid, "upstream");

    // No new process was spawned, and the running process was NOT terminated:
    assert_eq!(process.spawn_count(), 1);
    let terminate_count = process
        .calls()
        .iter()
        .filter(|c| matches!(c, FakeCall::Terminate(_)))
        .count();
    assert_eq!(terminate_count, 0);
}

#[tokio::test]
async fn reconnect_rechecks_socket_ownership_after_connect() {
    let temp = tempdir().unwrap();
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;
    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .unwrap();

    // First proof succeeds, post-connect proof fails.
    process.fail_ownership_after_checks(2);
    assert!(matches!(
        supervisor.reconnect("wlan0").await,
        Err(ClientSupervisorError::NotOwned { .. })
    ));
}

#[tokio::test]
async fn configured_scan_rechecks_ownership_before_attach() {
    let temp = tempdir().unwrap();
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;
    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .unwrap();

    // Command session pre/post proofs succeed; event-session post-connect
    // proof fails, so ATTACH/SCAN must not proceed through an unbound path.
    process.fail_ownership_after_checks(4);
    assert!(matches!(
        supervisor.scan("wlan0").await,
        Err(ClientSupervisorError::NotOwned { .. })
    ));
}

#[tokio::test]
async fn association_monitor_rechecks_ownership_before_attach() {
    let temp = tempdir().unwrap();
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;
    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .unwrap();

    supervisor.inner.association_monitors.lock().await.clear();
    process.fail_ownership_after_checks(4);
    supervisor.monitor_association("wlan0", 2000).await;

    assert!(!supervisor
        .inner
        .association_monitors
        .lock()
        .await
        .contains_key("wlan0"));
}

#[tokio::test]
async fn silent_foreign_ctrl_path_is_not_treated_as_absent() {
    let temp = tempdir().unwrap();
    let runtime = temp.path().join("run");
    std::fs::create_dir_all(&runtime).unwrap();
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;
    let _foreign = FakeSupplicantCtrl::spawn_silent(runtime.join("wlan0"));

    assert!(matches!(
        supervisor.configure(spec("wlan0", "upstream")).await,
        Err(ClientSupervisorError::NotOwned { .. })
    ));
    assert_eq!(process.spawn_count(), 0);
}

#[tokio::test]
async fn startup_readiness_refuses_a_foreign_responder() {
    let temp = tempdir().unwrap();
    let runtime = temp.path().join("run");
    std::fs::create_dir_all(&runtime).unwrap();
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;
    let config = config_path(&runtime, "wlan0");

    seed_process(&process, 4242, config.clone(), "COMPLETED");
    process.detach_ctrl_socket(4242);
    let _foreign = FakeSupplicantCtrl::spawn(runtime.join("wlan0"), "COMPLETED", &config);

    let record = PersistedWifiRecord {
        pid: 4242,
        started_at_unix: 1,
        process_start_ticks: None,
        boot_id: None,
        binary_path: Some(PathBuf::from("/usr/sbin/wpa_supplicant")),
        ctrl_path: runtime.join("wlan0"),
        ctrl_dev: None,
        ctrl_ino: None,
        config_path: config,
        config_digest: WifiDigest::from_bytes([1; 32]),
        key_digest: WifiDigest::from_bytes([2; 32]),
        ssid: "upstream".to_string(),
    };
    WifiRecordStore::for_client(temp.path().join("wifi"), &runtime, "wlan0")
        .save(&record)
        .await
        .unwrap();

    assert!(matches!(
        supervisor
            .wait_for_ready(
                OwnedWpaCtrlIdentity {
                    interface: "wlan0".to_string(),
                    kind: WifiProcessKind::Client,
                    record,
                    require_current_record: true,
                },
                Duration::from_millis(20),
            )
            .await,
        Err(ClientSupervisorError::NotOwned { .. })
    ));
}

#[tokio::test]
async fn client_ctrl_operations_refuse_a_replaced_control_socket() {
    let temp = tempdir().unwrap();
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;
    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .unwrap();
    process.detach_ctrl_socket(2000);
    let _foreign = FakeSupplicantCtrl::spawn(
        runtime.join("wlan0"),
        "COMPLETED",
        &config_path(&runtime, "wlan0"),
    );
    assert!(matches!(
        supervisor.reconnect("wlan0").await,
        Err(ClientSupervisorError::NotOwned { .. })
    ));
    assert!(matches!(
        supervisor.scan("wlan0").await,
        Err(ClientSupervisorError::NotOwned { .. })
    ));
    assert!(!supervisor
        .status("wlan0")
        .await
        .unwrap()
        .wpa_state
        .is_connected());
    assert_eq!(process.spawn_count(), 1);
}

#[tokio::test]
async fn ephemeral_scan_refuses_unowned_nodes_and_symlinked_configuration() {
    use std::os::unix::fs::symlink;
    let temp = tempdir().unwrap();
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::write(runtime.join("wlan0"), "unowned").unwrap();
    assert!(matches!(
        supervisor.scan("wlan0").await,
        Err(ClientSupervisorError::NotOwned { .. })
    ));
    assert_eq!(
        std::fs::read_to_string(runtime.join("wlan0")).unwrap(),
        "unowned"
    );
    std::fs::remove_file(runtime.join("wlan0")).unwrap();
    let outside = temp.path().join("outside");
    std::fs::write(&outside, "untouched").unwrap();
    symlink(&outside, scan_config_path(&runtime, "wlan0")).unwrap();
    assert!(supervisor.scan("wlan0").await.is_err());
    assert_eq!(std::fs::read_to_string(outside).unwrap(), "untouched");
    assert_eq!(process.spawn_count(), 0);
}

#[tokio::test]
async fn disabling_client_never_signals_a_pid_with_mismatched_identity() {
    let temp = tempdir().unwrap();
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;
    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .unwrap();
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
        Err(ClientSupervisorError::NotOwned { .. })
    ));
    assert!(!process
        .calls()
        .iter()
        .any(|c| matches!(c, FakeCall::Terminate(_) | FakeCall::Kill(_))));
}

#[tokio::test]
async fn association_events_identify_the_current_supplicant_and_stop_on_disable() {
    let temp = tempdir().unwrap();
    let runtime = temp.path().join("run");
    let supervisor = supervisor(temp.path(), &runtime, fake_process()).await;
    let mut changes = supervisor.subscribe_association_changes();
    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .unwrap();
    supervisor.reconnect("wlan0").await.unwrap();
    let (interface, pid) = tokio::time::timeout(Duration::from_secs(2), changes.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(interface, "wlan0");
    assert_eq!(pid, supervisor.status("wlan0").await.unwrap().pid);
    supervisor.disable("wlan0").await.unwrap();
    assert!(supervisor
        .inner
        .association_monitors
        .lock()
        .await
        .is_empty());
}

#[tokio::test]
async fn reconfigure_preserves_silent_foreign_socket_rebound_after_stop() {
    let temp = tempdir().unwrap();
    let runtime = temp.path().join("run");
    let process = fake_process();
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;
    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .unwrap();
    let foreign = Arc::new(std::sync::Mutex::new(None));
    let foreign_for_hook = foreign.clone();
    let ctrl_path = runtime.join("wlan0");
    process.set_after_terminate_hook(move |_| {
        *foreign_for_hook.lock().unwrap() =
            Some(FakeSupplicantCtrl::spawn_silent(ctrl_path.clone()));
    });

    assert!(matches!(
        supervisor.configure(spec("wlan0", "another-network")).await,
        Err(ClientSupervisorError::NotOwned { .. })
    ));
    assert_eq!(process.spawn_count(), 1);
    assert!(runtime.join("wlan0").exists());
}

#[tokio::test]
async fn status_waits_for_the_operation_lock() {
    let temp = tempdir().unwrap();
    let runtime = temp.path().join("run");
    let supervisor = supervisor(temp.path(), &runtime, fake_process()).await;
    supervisor
        .configure(spec("wlan0", "upstream"))
        .await
        .unwrap();
    let operation = supervisor.inner.interface_operations.lock("wlan0").await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), supervisor.status("wlan1"))
            .await
            .expect("another interface's launch must not block status")
            .is_none()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), supervisor.status("wlan0"))
            .await
            .is_err()
    );
    drop(operation);
    assert!(supervisor
        .status("wlan0")
        .await
        .unwrap()
        .wpa_state
        .is_connected());
}

#[tokio::test]
async fn socket_replacement_before_connect_sends_no_commands_to_foreign_endpoint() {
    for operation in ["reconnect", "scan", "monitor"] {
        let temp = tempdir().unwrap();
        let runtime = temp.path().join("run");
        let process = fake_process();
        let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;
        supervisor
            .configure(spec("wlan0", "upstream"))
            .await
            .unwrap();
        supervisor.inner.association_monitors.lock().await.clear();
        let foreign = Arc::new(std::sync::Mutex::new(None));
        let foreign_for_hook = foreign.clone();
        let weak_process = Arc::downgrade(&process);
        let ctrl_path = runtime.join("wlan0");
        let checks = std::sync::atomic::AtomicU32::new(0);
        let replace_after = if operation == "reconnect" { 1 } else { 3 };
        process.set_after_socket_proof_hook(move |pid| {
            if checks.fetch_add(1, Ordering::Relaxed) + 1 == replace_after {
                weak_process.upgrade().unwrap().detach_ctrl_socket(pid);
                let socket = StdUnixDatagram::bind(&ctrl_path).unwrap();
                socket.set_nonblocking(true).unwrap();
                *foreign_for_hook.lock().unwrap() = Some(socket);
            }
        });

        match operation {
            "reconnect" => assert!(matches!(
                supervisor.reconnect("wlan0").await,
                Err(ClientSupervisorError::NotOwned { .. })
            )),
            "scan" => assert!(matches!(
                supervisor.scan("wlan0").await,
                Err(ClientSupervisorError::NotOwned { .. })
            )),
            _ => {
                supervisor.monitor_association("wlan0", 2000).await;
                assert!(supervisor
                    .inner
                    .association_monitors
                    .lock()
                    .await
                    .is_empty());
            }
        }
        let guard = foreign.lock().unwrap();
        let mut buffer = [0; 128];
        assert_eq!(
            guard
                .as_ref()
                .unwrap()
                .recv(&mut buffer)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WouldBlock,
            "unexpected command during {operation}"
        );
    }
}

#[tokio::test]
async fn ap_and_client_supervisors_keep_interface_credentials_separate() {
    let temp = tempdir().unwrap();
    let runtime = temp.path().join("run");
    let config = app_config(temp.path(), &runtime);
    let client = WifiClientSupervisor::open_with_process_for_recovery(&config, fake_process());
    let ap = crate::wifi::HostapdSupervisor::open_for_recovery(&config);
    client
        .set_passphrase("wlan0", &WifiPassphrase::new("station-password").unwrap())
        .await
        .unwrap();
    assert!(ap.stored_passphrase("wlan0").await.unwrap().is_none());
    ap.set_passphrase("wlan0", &WifiPassphrase::new("ap-password").unwrap())
        .await
        .unwrap();
    assert_eq!(
        client
            .stored_passphrase("wlan0")
            .await
            .unwrap()
            .unwrap()
            .expose(),
        "station-password"
    );
    client.clear_passphrase("wlan0").await.unwrap();
    assert_eq!(
        ap.stored_passphrase("wlan0")
            .await
            .unwrap()
            .unwrap()
            .expose(),
        "ap-password"
    );
}

#[tokio::test]
async fn ephemeral_scan_cleans_up_when_start_identity_is_unavailable() {
    let temp = tempdir().unwrap();
    let runtime = temp.path().join("run");
    let process = fake_process();
    process.missing_start_ticks.store(true, Ordering::SeqCst);
    let supervisor = supervisor(temp.path(), &runtime, process.clone()).await;

    assert!(matches!(
        supervisor.scan("wlan0").await,
        Err(ClientSupervisorError::Process(
            ProcessError::IdentityChanged { .. }
        ))
    ));
    assert_eq!(process.spawn_count(), 1);
    assert!(process
        .calls()
        .iter()
        .any(|call| matches!(call, FakeCall::Terminate(_))));
    assert!(!runtime.join("wlan0-scan.conf").exists());
    assert!(!runtime.join("wlan0").exists());
    assert!(
        WifiRecordStore::for_scan(temp.path().join("wifi"), &runtime, "wlan0")
            .load()
            .await
            .unwrap()
            .is_none()
    );
}
