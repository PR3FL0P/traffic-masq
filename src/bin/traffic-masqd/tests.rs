#[test]
fn reset_cli_accepts_preview_and_non_interactive_confirmation() {
    use clap::Parser;
    let args = super::Args::try_parse_from([
        "traffic-masqd",
        "--config",
        "/tmp/config.toml",
        "reset",
        "--dry-run",
        "--yes",
        "--timeout-seconds",
        "12",
        "--force-offline",
    ])
    .unwrap();
    let Some(super::Command::Reset(options)) = args.command else {
        panic!("wrong command")
    };
    assert!(options.dry_run && options.yes && options.force_offline);
    assert_eq!(options.timeout_seconds, 12);
}

#[test]
fn uninstall_cli_accepts_custom_paths_and_preview() {
    use clap::Parser;
    let args = super::Args::try_parse_from([
        "traffic-masqd",
        "--config",
        "/tmp/config.toml",
        "uninstall",
        "--prefix",
        "/opt/traffic-masq",
        "--dry-run",
        "--yes",
    ])
    .unwrap();
    let Some(super::Command::Uninstall(options)) = args.command else {
        panic!("wrong command")
    };
    assert!(options.dry_run && options.yes);
    assert_eq!(
        options.prefix,
        std::path::PathBuf::from("/opt/traffic-masq")
    );
}

use std::os::unix::fs::PermissionsExt;

use tempfile::tempdir;

use super::*;

#[test]
fn init_creates_a_private_valid_safe_config_and_refuses_overwrite() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("config.toml");
    init_config(&path, false).expect("initialize");

    assert_eq!(
        fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
        0o640
    );
    let config = AppConfig::load(&path).expect("load initialized config");
    config.validate().expect("valid initialized config");
    assert!(config.network.interfaces.is_empty());
    assert!(init_config(&path, false).is_err());
    init_config(&path, true).expect("explicit overwrite");
}

#[test]
fn stop_and_restart_accept_force_and_timeout() {
    for command in ["stop", "restart"] {
        let args = Args::try_parse_from([
            "traffic-masqd",
            command,
            "--force",
            "--direct",
            "--timeout-seconds",
            "12",
        ])
        .unwrap();
        match args.command.unwrap() {
            Command::Stop {
                force,
                direct,
                timeout_seconds,
            }
            | Command::Restart {
                force,
                direct,
                timeout_seconds,
            } => {
                assert!(force && direct);
                assert_eq!(timeout_seconds, 12);
            }
            _ => panic!("wrong command"),
        }
    }
}

#[tokio::test]
async fn force_stop_of_already_stopped_daemon_is_a_noop() {
    let directory = tempdir().unwrap();
    let mut config = AppConfig::default();
    config.runtime.pid_path = directory.path().join("daemon.pid");
    let resolved = ResolvedConfig {
        config,
        source: traffic_masq::config::ConfigSource::BuiltIn,
    };
    assert!(!stop_daemon(&resolved, true, true, Duration::from_secs(1))
        .await
        .unwrap());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
}

/// A separate process implements the shutdown IPC boundary without touching networking.
/// Invoked by `ShutdownPeer`; an ordinary test run has no peer environment and returns.
#[tokio::test]
async fn shutdown_peer_process() {
    use fs2::FileExt;
    use tokio::signal::unix::{signal, SignalKind};

    let Some(root) = std::env::var_os("TRAFFIC_MASQ_TEST_SHUTDOWN_PEER") else {
        return;
    };
    let root = PathBuf::from(root);
    let mut terminate = signal(SignalKind::terminate()).unwrap();
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(root.join("daemon.pid.lock"))
        .unwrap();
    lock.try_lock_exclusive().unwrap();
    fs::write(root.join("daemon.pid"), std::process::id().to_string()).unwrap();
    fs::write(root.join("ready"), b"").unwrap();
    tokio::time::timeout(Duration::from_secs(10), terminate.recv())
        .await
        .expect("parent must send SIGTERM")
        .expect("signal stream");

    // The request must already exist when the stop signal is delivered.
    let request: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("daemon.pid.shutdown-request.json")).unwrap())
            .unwrap();
    assert_eq!(request["mode"], "cancel_pending");
    assert_eq!(request["pid"], std::process::id());
    assert_eq!(request["schema_version"], 1);
    assert!(
        request["expires_at_unix_seconds"].as_u64().unwrap()
            >= std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
    );
    match std::env::var("TRAFFIC_MASQ_TEST_SHUTDOWN_ACK")
        .unwrap()
        .as_str()
    {
        "matching" => {
            fs::write(root.join("cleaned"), b"").unwrap();
            fs::write(
                root.join("daemon.pid.shutdown-complete"),
                request["token"].as_str().unwrap(),
            )
            .unwrap();
        }
        "mismatched" => {
            fs::write(
                root.join("daemon.pid.shutdown-complete"),
                b"another-attempt",
            )
            .unwrap();
        }
        "missing" => {}
        mode => panic!("unknown acknowledgement mode: {mode}"),
    }
    fs::remove_file(root.join("daemon.pid")).unwrap();
    FileExt::unlock(&lock).unwrap();
}

struct ShutdownPeer {
    child: tokio::process::Child,
    resolved: ResolvedConfig,
    directory: tempfile::TempDir,
}

impl ShutdownPeer {
    async fn spawn(acknowledgement: &str) -> Self {
        let directory = tempdir().unwrap();
        let mut config = AppConfig::default();
        config.runtime.pid_path = directory.path().join("daemon.pid");
        config.runtime.socket_path = directory.path().join("daemon.sock");
        config.runtime.log_dir = directory.path().join("logs");
        let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::shutdown_peer_process", "--nocapture"])
            .env("TRAFFIC_MASQ_TEST_SHUTDOWN_PEER", directory.path())
            .env("TRAFFIC_MASQ_TEST_SHUTDOWN_ACK", acknowledgement)
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !directory.path().join("ready").exists() {
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "shutdown peer exited before readiness"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("shutdown peer readiness");
        Self {
            child,
            resolved: ResolvedConfig {
                config,
                source: traffic_masq::config::ConfigSource::BuiltIn,
            },
            directory,
        }
    }

    async fn wait(&mut self) {
        let exit = tokio::time::timeout(Duration::from_secs(5), self.child.wait())
            .await
            .expect("shutdown peer exit")
            .unwrap();
        assert!(exit.success(), "shutdown peer failed: {exit}");
    }
}

#[tokio::test]
async fn force_stop_waits_for_process_exit_and_verifies_cleanup() {
    let mut peer = ShutdownPeer::spawn("matching").await;
    assert!(
        stop_daemon(&peer.resolved, true, true, Duration::from_secs(5))
            .await
            .unwrap()
    );
    peer.wait().await;
    let root = peer.directory.path();
    assert!(root.join("cleaned").exists());
    assert!(!root.join("daemon.pid.shutdown-request.json").exists());
    assert!(!root.join("daemon.pid.shutdown-complete").exists());
}

#[tokio::test]
async fn force_stop_and_restart_reject_unproved_cleanup_before_starting() {
    for restart in [false, true] {
        for acknowledgement in ["missing", "mismatched"] {
            let mut peer = ShutdownPeer::spawn(acknowledgement).await;
            let timeout = Duration::from_secs(5);
            let error = if restart {
                restart_daemon(&peer.resolved, true, true, timeout)
                    .await
                    .unwrap_err()
            } else {
                stop_daemon(&peer.resolved, true, true, timeout)
                    .await
                    .unwrap_err()
            };
            peer.wait().await;
            let message = format!("{error:#}");
            assert!(
                message.contains(if acknowledgement == "missing" {
                    "without acknowledging"
                } else {
                    "does not match"
                }),
                "{message}"
            );
            let root = peer.directory.path();
            assert!(root.join("daemon.pid.shutdown-request.json").exists());
            // start_daemon acquires this lock before preparing diagnostics or spawning.
            assert!(!root.join("daemon.pid.start.lock").exists());
            assert!(!peer.resolved.config.runtime.log_dir.exists());
        }
    }
}

// Run a real process so an accidentally unbounded Runtime::drop cannot hang the suite.
#[test]
fn shutdown_deadline_peer_exits_with_blocking_work_still_running() {
    let Some(root) = std::env::var_os("TRAFFIC_MASQ_TEST_BLOCKED_SHUTDOWN") else {
        return;
    };
    let root = PathBuf::from(root);
    let result = run_with_runtime(async {
        let (started, ready) = tokio::sync::oneshot::channel();
        tokio::task::spawn_blocking(move || {
            let _ = started.send(());
            loop {
                std::thread::park();
            }
        });
        ready.await.unwrap();
        fs::write(root.join("recovery.json"), b"interrupted mutation proof").unwrap();
        Err(ShutdownDeadlineExceeded.into())
    });
    assert!(result.unwrap_err().is::<ShutdownDeadlineExceeded>());
}

#[tokio::test]
async fn shutdown_deadline_does_not_wait_for_blocking_workers_or_remove_recovery_proof() {
    let root = tempdir().unwrap();
    let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::shutdown_deadline_peer_exits_with_blocking_work_still_running",
        ])
        .env("TRAFFIC_MASQ_TEST_BLOCKED_SHUTDOWN", root.path())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .expect("process must exit without waiting for its blocked worker")
        .unwrap();
    assert!(status.success());
    assert_eq!(
        fs::read(root.path().join("recovery.json")).unwrap(),
        b"interrupted mutation proof"
    );
}
