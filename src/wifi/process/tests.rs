use std::io::Write;
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

use tempfile::NamedTempFile;

use super::*;

async fn wait_for_exit(process: &TokioSupervisedProcess, pid: u32) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while process.is_alive(pid).await.expect("process state") {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("process must exit");
}

async fn wait_for_cmdline(pid: u32, argument: &Path) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !proc_cmdline_contains(pid, argument).await {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("spawned process must expose its command line");
}

#[tokio::test]
async fn stdout_and_stderr_diagnostics_are_retained_for_supervisor_health() {
    let mut script = NamedTempFile::new().expect("script");
    writeln!(script, "echo 'ACS: Unable to collect survey data'").expect("write script");
    writeln!(script, "echo 'nl80211: setup failed' >&2").expect("write script");
    writeln!(script, "exit 7").expect("write script");
    script.flush().expect("flush script");

    let process = TokioSupervisedProcess::new();
    let pid = process
        .spawn(Path::new("/bin/sh"), script.path())
        .await
        .expect("spawn");

    wait_for_exit(&process, pid).await;
    let diagnostics = process
        .recent_diagnostics(pid)
        .await
        .expect("read exit diagnostics");
    assert!(
        diagnostics
            .iter()
            .any(|line| line.contains("Unable to collect survey data")),
        "stdout must retain hostapd diagnostics"
    );
    assert!(
        diagnostics.iter().any(|line| line.contains("setup failed")),
        "stderr must retain hostapd diagnostics"
    );
    assert!(
        diagnostics
            .iter()
            .any(|line| line.contains("exit status: 7")),
        "process exit status must be retained"
    );
}

async fn proc_cmdline_contains(pid: u32, argument: &Path) -> bool {
    tokio::fs::read(format!("/proc/{pid}/cmdline"))
        .await
        .ok()
        .is_some_and(|raw| {
            raw.split(|byte| *byte == 0)
                .any(|candidate| candidate == argument.as_os_str().as_encoded_bytes())
        })
}

#[tokio::test]
async fn unix_socket_ownership_is_tied_to_the_pid_holding_the_kernel_socket() {
    let temp = tempfile::tempdir().expect("tempdir");
    let socket_path = temp.path().join("hostapd.ctrl");
    let socket = UnixDatagram::bind(&socket_path).expect("bind ctrl socket");
    let process = TokioSupervisedProcess::new();

    assert!(process
        .owns_unix_socket(std::process::id(), &socket_path)
        .await
        .expect("owned socket"));
    let foreign_pid = process
        .spawn(Path::new("/bin/sleep"), Path::new("300"))
        .await
        .expect("spawn foreign process");
    assert!(!process
        .owns_unix_socket(foreign_pid, &socket_path)
        .await
        .expect("foreign pid"));

    process
        .kill(foreign_pid)
        .await
        .expect("cleanup foreign process");
    drop(socket);
}

#[tokio::test]
async fn unix_socket_ownership_fails_closed_during_unlink_rebind_ambiguity() {
    let temp = tempfile::tempdir().expect("tempdir");
    let socket_path = temp.path().join("hostapd.ctrl");
    let first = UnixDatagram::bind(&socket_path).expect("bind first socket");
    std::fs::remove_file(&socket_path).expect("unlink first socket path");
    let second = UnixDatagram::bind(&socket_path).expect("bind replacement socket");
    let process = TokioSupervisedProcess::new();

    assert!(!process
        .owns_unix_socket(std::process::id(), &socket_path)
        .await
        .expect("ambiguous socket ownership"));

    drop(first);
    drop(second);
}

#[test]
fn wifi_process_kind_matching_distinguishes_hostapd_from_supplicant() {
    let config = Path::new("/run/traffic-masq/wlan0.conf");
    let scan_config = Path::new("/run/traffic-masq/wlan0-scan.conf");
    let hostapd = b"/usr/sbin/hostapd\0/run/traffic-masq/wlan0.conf\0";
    let supplicant = b"/usr/sbin/wpa_supplicant\0-i\0wlan0\0-c\0/run/traffic-masq/wlan0.conf\0";
    let scan = b"/usr/sbin/wpa_supplicant\0-i\0wlan0\0-c\0/run/traffic-masq/wlan0-scan.conf\0";

    assert!(argv_matches_kind(
        hostapd,
        WifiProcessKind::AccessPoint,
        config
    ));
    assert!(!argv_matches_kind(hostapd, WifiProcessKind::Client, config));
    assert!(argv_matches_kind(
        supplicant,
        WifiProcessKind::Client,
        config
    ));
    assert!(argv_matches_kind(scan, WifiProcessKind::Scan, scan_config));
    assert!(!argv_matches_kind(
        supplicant,
        WifiProcessKind::AccessPoint,
        config
    ));
    assert!(!argv_matches_kind(
        b"/usr/sbin/hostapd\0-d\0/run/traffic-masq/wlan0.conf\0",
        WifiProcessKind::AccessPoint,
        config
    ));
}

#[tokio::test]
async fn process_identity_requires_the_expected_executable_not_just_config_argv() {
    let process = TokioSupervisedProcess::new();
    let config = Path::new("300");
    let pid = process
        .spawn(Path::new("/bin/sleep"), config)
        .await
        .expect("spawn");
    wait_for_cmdline(pid, config).await;
    let started_at_unix = crate::wifi::lifecycle::unix_now();

    assert!(process
        .identity_matches(
            pid,
            WifiProcessKind::AccessPoint,
            Path::new("/bin/sleep"),
            config,
            started_at_unix,
        )
        .await
        .expect("matching executable"));
    assert!(!process
        .identity_matches(
            pid,
            WifiProcessKind::AccessPoint,
            Path::new("/bin/true"),
            config,
            started_at_unix,
        )
        .await
        .expect("foreign executable"));
    assert!(!process
        .identity_matches(
            pid,
            WifiProcessKind::AccessPoint,
            Path::new("/bin/sleep"),
            config,
            1,
        )
        .await
        .expect("stale process identity"));

    process.kill(pid).await.expect("cleanup");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn adopted_stop_never_signals_a_process_after_the_recorded_lifetime_exits() {
    let mut original = tokio::process::Command::new("/bin/sleep")
        .arg("300")
        .spawn()
        .expect("original");
    let pid = original.id().expect("pid");
    let inspector = TokioSupervisedProcess::new();
    let start_ticks = inspector
        .process_start_ticks(pid)
        .await
        .expect("inspect starttime")
        .expect("live process has starttime");
    let boot_id = inspector
        .boot_id()
        .await
        .expect("read boot id")
        .expect("Linux boot id");
    let record = crate::wifi::record::PersistedWifiRecord {
        pid,
        started_at_unix: crate::wifi::lifecycle::unix_now(),
        process_start_ticks: Some(start_ticks),
        boot_id: Some(boot_id),
        binary_path: Some(PathBuf::from("/bin/sleep")),
        ctrl_path: PathBuf::from("/tmp/unused-wifi-control"),
        ctrl_dev: None,
        ctrl_ino: None,
        config_path: PathBuf::from("300"),
        config_digest: crate::wifi::render::WifiDigest::of(&[]),
        key_digest: crate::wifi::render::WifiDigest::of(&[]),
        ssid: String::new(),
    };
    original.kill().await.expect("kill original");
    original.wait().await.expect("reap original");
    let mut other = tokio::process::Command::new("/bin/sleep")
        .arg("300")
        .spawn()
        .expect("other");
    let process = TokioSupervisedProcess::new();
    process
        .stop_recorded(&record, WifiProcessKind::AccessPoint, "test")
        .await
        .expect("stale lifetime");
    assert!(other.try_wait().expect("other state").is_none());
    other.kill().await.expect("cleanup other");
}

#[tokio::test]
async fn a_freshly_spawned_process_is_alive_and_visible_in_proc() {
    let process = TokioSupervisedProcess::new();

    let pid = process
        .spawn(Path::new("/bin/sleep"), Path::new("300"))
        .await
        .expect("spawn");

    assert!(process.is_alive(pid).await.expect("is_alive"));
    wait_for_cmdline(pid, Path::new("300")).await;

    process.kill(pid).await.expect("kill");
    wait_for_exit(&process, pid).await;
    assert!(!process.is_alive(pid).await.expect("is_alive after kill"));
}

#[tokio::test]
async fn cmdline_contains_is_false_for_a_config_path_not_in_argv() {
    let process = TokioSupervisedProcess::new();
    let pid = process
        .spawn(Path::new("/bin/sleep"), Path::new("300"))
        .await
        .expect("spawn");

    wait_for_cmdline(pid, Path::new("300")).await;

    assert!(!proc_cmdline_contains(pid, Path::new("600")).await);

    process.kill(pid).await.expect("cleanup");
}

#[tokio::test]
async fn terminate_and_kill_on_a_pid_that_already_exited_are_not_errors() {
    let config = NamedTempFile::new().expect("tempfile");
    let process = TokioSupervisedProcess::new();
    let pid = process
        .spawn(Path::new("/bin/true"), config.path())
        .await
        .expect("spawn");

    wait_for_exit(&process, pid).await;
    process.terminate(pid).await.expect("terminate a dead pid");
    process.kill(pid).await.expect("kill a dead pid");
}

#[tokio::test]
async fn is_alive_and_cmdline_contains_are_false_for_a_pid_never_spawned_here() {
    let config = NamedTempFile::new().expect("tempfile");
    let process = TokioSupervisedProcess::new();

    assert!(process.is_alive(1).await.expect("pid 1 exists"));
    assert!(!proc_cmdline_contains(1, config.path()).await);

    assert!(!process.is_alive(u32::MAX / 2).await.expect("is_alive"));
}

#[tokio::test]
async fn competing_manager_scan_returns_a_list_without_errors() {
    // On any Linux system /proc is readable; the result may legitimately be
    // empty, but the scan itself must never fail or panic.
    let _ = super::find_competing_network_managers().await;
}

#[test]
fn competing_daemons_excludes_our_own_supervised_processes() {
    // hostapd and wpa_supplicant are what THIS daemon supervises; treating
    // them as competitors would make the scan report itself as the
    // interloper on almost every restart.
    assert!(!super::COMPETING_DAEMONS.contains(&"hostapd"));
    assert!(!super::COMPETING_DAEMONS.contains(&"wpa_supplicant"));
}

#[test]
fn advice_formatting_contains_relevant_commands_for_managers() {
    let managers = vec![
        "iwd".to_string(),
        "NetworkManager".to_string(),
        "systemd-networkd".to_string(),
        "connman".to_string(),
        "dhcpcd".to_string(),
    ];
    let advice = super::format_competing_manager_advice(&managers, "wlp1s0");
    assert!(advice.contains("iwd"));
    assert!(advice.contains("NetworkManager"));
    assert!(advice.contains("systemd-networkd"));
    assert!(advice.contains("connman"));
    assert!(advice.contains("dhcpcd"));
    assert!(advice.contains("denyinterfaces wlp1s0"));
    assert!(advice.contains("wlp1s0"));
}

#[test]
fn advice_formatting_respects_init_systems() {
    let managers = vec!["iwd".to_string(), "NetworkManager".to_string()];

    let runit_advice = super::format_competing_manager_advice_for_init(
        &managers,
        "wlan0",
        super::InitSystem::Runit,
    );
    assert!(runit_advice.contains("sv down iwd"));
    assert!(runit_advice.contains("/etc/sv/iwd/down"));

    let systemd_advice = super::format_competing_manager_advice_for_init(
        &managers,
        "wlan0",
        super::InitSystem::Systemd,
    );
    assert!(systemd_advice.contains("systemctl stop iwd"));
    assert!(systemd_advice.contains("systemctl disable --now iwd"));

    let openrc_advice = super::format_competing_manager_advice_for_init(
        &managers,
        "wlan0",
        super::InitSystem::OpenRc,
    );
    assert!(openrc_advice.contains("rc-service iwd stop"));
    assert!(openrc_advice.contains("rc-update del iwd default"));
}

#[test]
fn proc_stat_starttime_parser_handles_spaces_and_closing_parens_in_comm() {
    let raw =
        b"123 (odd ) process name) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242 0 0\n";
    assert_eq!(parse_proc_stat_start_ticks(raw), Some(424_242));
}

#[tokio::test]
async fn persisted_process_identity_uses_exact_kernel_starttime() {
    let process = TokioSupervisedProcess::new();
    let config = Path::new("300");
    let pid = process
        .spawn(Path::new("/bin/sleep"), config)
        .await
        .expect("spawn");
    wait_for_cmdline(pid, config).await;
    let start_ticks = process
        .process_start_ticks(pid)
        .await
        .expect("read starttime")
        .expect("live process has starttime");
    let boot_id = process
        .boot_id()
        .await
        .expect("read boot id")
        .expect("Linux boot id");
    let mut record = crate::wifi::record::PersistedWifiRecord {
        pid,
        started_at_unix: crate::wifi::lifecycle::unix_now(),
        process_start_ticks: Some(start_ticks),
        boot_id: Some(boot_id.clone()),
        binary_path: Some(PathBuf::from("/bin/sleep")),
        ctrl_path: PathBuf::from("/tmp/unused-wifi-control"),
        ctrl_dev: None,
        ctrl_ino: None,
        config_path: config.to_path_buf(),
        config_digest: crate::wifi::render::WifiDigest::of(&[]),
        key_digest: crate::wifi::render::WifiDigest::of(&[]),
        ssid: String::new(),
    };

    assert!(process
        .identity_matches_record(
            &record,
            WifiProcessKind::AccessPoint,
            Path::new("/bin/sleep")
        )
        .await
        .expect("exact identity"));

    record.boot_id = Some("00000000-0000-0000-0000-000000000000".to_string());
    assert!(!process
        .identity_matches_record(
            &record,
            WifiProcessKind::AccessPoint,
            Path::new("/bin/sleep")
        )
        .await
        .expect("mismatched boot"));
    record.boot_id = Some(boot_id);

    record.process_start_ticks = Some(start_ticks.saturating_add(1));
    assert!(!process
        .identity_matches_record(
            &record,
            WifiProcessKind::AccessPoint,
            Path::new("/bin/sleep")
        )
        .await
        .expect("mismatched lifetime"));

    process.kill(pid).await.expect("cleanup");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn pidfd_stop_refuses_a_record_with_the_wrong_starttime() {
    let process = TokioSupervisedProcess::new();
    let config = Path::new("300");
    let pid = process
        .spawn(Path::new("/bin/sleep"), config)
        .await
        .expect("spawn");
    wait_for_cmdline(pid, config).await;
    let start_ticks = process
        .process_start_ticks(pid)
        .await
        .expect("read starttime")
        .expect("live process has starttime");
    let boot_id = process
        .boot_id()
        .await
        .expect("read boot id")
        .expect("Linux boot id");
    let record = crate::wifi::record::PersistedWifiRecord {
        pid,
        started_at_unix: crate::wifi::lifecycle::unix_now(),
        process_start_ticks: Some(start_ticks.saturating_add(1)),
        boot_id: Some(boot_id),
        binary_path: Some(PathBuf::from("/bin/sleep")),
        ctrl_path: PathBuf::from("/tmp/unused-wifi-control"),
        ctrl_dev: None,
        ctrl_ino: None,
        config_path: config.to_path_buf(),
        config_digest: crate::wifi::render::WifiDigest::of(&[]),
        key_digest: crate::wifi::render::WifiDigest::of(&[]),
        ssid: String::new(),
    };

    // Prove that the altered record field is the reason for rejection.
    let mut valid = record.clone();
    valid.process_start_ticks = Some(start_ticks);
    assert!(process
        .identity_matches_record(
            &valid,
            WifiProcessKind::AccessPoint,
            Path::new("/bin/sleep")
        )
        .await
        .expect("valid identity before corrupting proof"));

    assert!(matches!(
        process
            .stop_recorded(&record, WifiProcessKind::AccessPoint, "test")
            .await,
        Err(ProcessError::IdentityChanged { pid: rejected }) if rejected == pid
    ));
    assert!(process
        .is_alive(pid)
        .await
        .expect("process survives rejected stop"));
    process.kill(pid).await.expect("cleanup");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn pidfd_stop_refuses_a_record_from_another_boot() {
    let process = TokioSupervisedProcess::new();
    let config = Path::new("300");
    let pid = process
        .spawn(Path::new("/bin/sleep"), config)
        .await
        .expect("spawn");
    wait_for_cmdline(pid, config).await;
    let start_ticks = process
        .process_start_ticks(pid)
        .await
        .expect("read starttime")
        .expect("live process has starttime");
    let record = crate::wifi::record::PersistedWifiRecord {
        pid,
        started_at_unix: crate::wifi::lifecycle::unix_now(),
        process_start_ticks: Some(start_ticks),
        boot_id: Some("00000000-0000-0000-0000-000000000000".to_string()),
        binary_path: Some(PathBuf::from("/bin/sleep")),
        ctrl_path: PathBuf::from("/tmp/unused-wifi-control"),
        ctrl_dev: None,
        ctrl_ino: None,
        config_path: config.to_path_buf(),
        config_digest: crate::wifi::render::WifiDigest::of(&[]),
        key_digest: crate::wifi::render::WifiDigest::of(&[]),
        ssid: String::new(),
    };

    // Prove that the altered record field is the reason for rejection.
    let mut valid = record.clone();
    valid.boot_id = process.boot_id().await.unwrap();
    assert!(process
        .identity_matches_record(
            &valid,
            WifiProcessKind::AccessPoint,
            Path::new("/bin/sleep")
        )
        .await
        .expect("valid identity before corrupting proof"));

    assert!(matches!(
        process
            .stop_recorded(&record, WifiProcessKind::AccessPoint, "test")
            .await,
        Err(ProcessError::IdentityChanged { pid: rejected }) if rejected == pid
    ));
    assert!(process
        .is_alive(pid)
        .await
        .expect("process survives rejected stop"));
    process.kill(pid).await.expect("cleanup");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn pidfd_stop_accepts_the_exact_recorded_starttime() {
    let process = TokioSupervisedProcess::new();
    let config = Path::new("300");
    let pid = process
        .spawn(Path::new("/bin/sleep"), config)
        .await
        .expect("spawn");
    wait_for_cmdline(pid, config).await;
    let start_ticks = process
        .process_start_ticks(pid)
        .await
        .expect("read starttime")
        .expect("live process has starttime");
    let boot_id = process
        .boot_id()
        .await
        .expect("read boot id")
        .expect("Linux boot id");
    let record = crate::wifi::record::PersistedWifiRecord {
        pid,
        started_at_unix: crate::wifi::lifecycle::unix_now(),
        process_start_ticks: Some(start_ticks),
        boot_id: Some(boot_id),
        binary_path: Some(PathBuf::from("/bin/sleep")),
        ctrl_path: PathBuf::from("/tmp/unused-wifi-control"),
        ctrl_dev: None,
        ctrl_ino: None,
        config_path: config.to_path_buf(),
        config_digest: crate::wifi::render::WifiDigest::of(&[]),
        key_digest: crate::wifi::render::WifiDigest::of(&[]),
        ssid: String::new(),
    };

    process
        .stop_recorded(&record, WifiProcessKind::AccessPoint, "test")
        .await
        .expect("exact lifetime is safe to signal");
    assert!(
        !process.children.lock().await.contains_key(&pid),
        "stop must reap the child"
    );
    assert!(
        !process.output_tasks.lock().await.contains_key(&pid),
        "stop must finish output tasks"
    );
    assert!(process
        .recent_diagnostics(pid)
        .await
        .unwrap()
        .iter()
        .any(|line| line.starts_with("process exited with ")));
    assert!(!process.is_alive(pid).await.expect("process stopped"));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn pidfd_stop_refuses_legacy_record_without_exact_starttime() {
    let process = TokioSupervisedProcess::new();
    let config = Path::new("300");
    let pid = process
        .spawn(Path::new("/bin/sleep"), config)
        .await
        .expect("spawn");
    wait_for_cmdline(pid, config).await;
    let record = crate::wifi::record::PersistedWifiRecord {
        pid,
        started_at_unix: crate::wifi::lifecycle::unix_now(),
        process_start_ticks: None,
        boot_id: None,
        binary_path: Some(PathBuf::from("/bin/sleep")),
        ctrl_path: PathBuf::from("/tmp/unused-wifi-control"),
        ctrl_dev: None,
        ctrl_ino: None,
        config_path: config.to_path_buf(),
        config_digest: crate::wifi::render::WifiDigest::of(&[]),
        key_digest: crate::wifi::render::WifiDigest::of(&[]),
        ssid: String::new(),
    };

    // Prove that the altered record field is the reason for rejection.
    let mut valid = record.clone();
    valid.process_start_ticks = process.process_start_ticks(pid).await.unwrap();
    valid.boot_id = process.boot_id().await.unwrap();
    assert!(process
        .identity_matches_record(
            &valid,
            WifiProcessKind::AccessPoint,
            Path::new("/bin/sleep")
        )
        .await
        .expect("valid identity before corrupting proof"));

    assert!(matches!(
        process
            .stop_recorded(&record, WifiProcessKind::AccessPoint, "test")
            .await,
        Err(ProcessError::IdentityChanged { pid: rejected }) if rejected == pid
    ));
    assert!(process
        .is_alive(pid)
        .await
        .expect("legacy record cannot signal process"));
    process.kill(pid).await.expect("cleanup");
}

#[test]
fn diagnostic_history_is_bounded_across_launches_and_pid_reuse() {
    let mut diagnostics = WifiDiagnostics::default();
    diagnostics.start(0);
    diagnostics.push(0, "old launch".to_string());
    for pid in 1..=MAX_WIFI_DIAGNOSTIC_PROCESSES as u32 {
        diagnostics.start(pid);
        diagnostics.push(pid, format!("launch {pid}"));
    }
    diagnostics.push(0, "late output from evicted launch".to_string());
    assert!(!diagnostics.lines.contains_key(&0));
    assert_eq!(diagnostics.lines.len(), MAX_WIFI_DIAGNOSTIC_PROCESSES);
    let newest = MAX_WIFI_DIAGNOSTIC_PROCESSES as u32;
    assert_eq!(diagnostics.lines[&newest][0], format!("launch {newest}"));
    diagnostics.start(newest);
    assert!(diagnostics.lines[&newest].is_empty());
    assert_eq!(diagnostics.launches.len(), MAX_WIFI_DIAGNOSTIC_PROCESSES);
    for _ in 0..MAX_WIFI_DIAGNOSTIC_LINES + 1 {
        diagnostics.push(newest, "界".repeat(MAX_WIFI_DIAGNOSTIC_BYTES));
    }
    assert_eq!(diagnostics.lines[&newest].len(), MAX_WIFI_DIAGNOSTIC_LINES);
    assert!(diagnostics.lines[&newest]
        .iter()
        .all(|line| line.len() <= MAX_WIFI_DIAGNOSTIC_BYTES));
}

#[tokio::test]
async fn inherited_output_pipe_does_not_block_exit_observation() {
    let mut script = NamedTempFile::new().unwrap();
    writeln!(script, "sleep 30 >&1 2>/dev/null &\necho $!\nexit 7").unwrap();
    script.flush().unwrap();
    let process = TokioSupervisedProcess::new();
    let pid = process
        .spawn(Path::new("/bin/sh"), script.path())
        .await
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        while process.is_alive(pid).await.unwrap() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let diagnostics = process.recent_diagnostics(pid).await.unwrap();
    // Clean up the descendant even if the liveness timeout failed.
    for line in &diagnostics {
        if let Ok(descendant) = line.parse::<u32>() {
            send_signal(descendant, Signal::SIGKILL).unwrap();
        }
    }
    assert!(
        result.is_ok(),
        "an inherited pipe must not hang the supervisor"
    );
    assert!(diagnostics
        .iter()
        .any(|line| line.contains("exit status: 7")));
}

#[tokio::test]
async fn sensitive_output_is_redacted_in_retained_diagnostics() {
    let mut script = NamedTempFile::new().unwrap();
    writeln!(
        script,
        "echo 'password=do-not-retain'\necho 'wpa_psk=do-not-retain' >&2"
    )
    .unwrap();
    script.flush().unwrap();
    let process = TokioSupervisedProcess::new();
    let pid = process
        .spawn(Path::new("/bin/sh"), script.path())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while process.is_alive(pid).await.unwrap() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let diagnostics = process.recent_diagnostics(pid).await.unwrap();
    assert_eq!(
        diagnostics
            .iter()
            .filter(|line| line.contains("redacted"))
            .count(),
        2
    );
    assert!(!diagnostics
        .iter()
        .any(|line| line.contains("do-not-retain")));
}
