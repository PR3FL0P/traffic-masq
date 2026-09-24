use std::os::unix::net::UnixDatagram;
use std::time::Duration;

use tempfile::NamedTempFile;

use super::*;

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

    process.kill(foreign_pid).await.expect("cleanup foreign process");
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
    assert!(!argv_matches_kind(
        hostapd,
        WifiProcessKind::Client,
        config
    ));
    assert!(argv_matches_kind(
        supplicant,
        WifiProcessKind::Client,
        config
    ));
    assert!(argv_matches_kind(
        scan,
        WifiProcessKind::Scan,
        scan_config
    ));
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

#[tokio::test]
async fn a_freshly_spawned_process_is_alive_and_visible_in_proc() {
    let process = TokioSupervisedProcess::new();

    let pid = process
        .spawn(Path::new("/bin/sleep"), Path::new("300"))
        .await
        .expect("spawn");

    assert!(process.is_alive(pid).await.expect("is_alive"));
    let mut found = false;
    for _ in 0..50 {
        if proc_cmdline_contains(pid, Path::new("300")).await {
            found = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(found, "cmdline should contain '300'");

    process.kill(pid).await.expect("kill");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!process.is_alive(pid).await.expect("is_alive after kill"));
}

#[tokio::test]
async fn cmdline_contains_is_false_for_a_config_path_not_in_argv() {
    let process = TokioSupervisedProcess::new();
    let pid = process
        .spawn(Path::new("/bin/sleep"), Path::new("300"))
        .await
        .expect("spawn");

    let mut ready = false;
    for _ in 0..50 {
        if proc_cmdline_contains(pid, Path::new("300")).await {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(ready, "spawned process should be visible in proc cmdline");

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

    tokio::time::sleep(Duration::from_millis(100)).await;
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
