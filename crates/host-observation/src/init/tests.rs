use super::*;

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
    assert!(runit_advice.contains("sv status SERVICE"));
    let systemd_advice = super::format_competing_manager_advice_for_init(
        &managers,
        "wlan0",
        super::InitSystem::Systemd,
    );
    assert!(systemd_advice.contains("systemctl status UNIT"));
    let openrc_advice = super::format_competing_manager_advice_for_init(
        &managers,
        "wlan0",
        super::InitSystem::OpenRc,
    );
    assert!(openrc_advice.contains("rc-service SERVICE status"));
    for advice in [runit_advice, systemd_advice, openrc_advice] {
        assert!(!advice.contains("disable --now"));
        assert!(!advice.contains("[Blacklist]\n"));
        assert!(advice.contains("--nointerfaces 'wlan0'"));
    }
}

#[test]
fn pid_one_takes_precedence_over_stale_service_directories() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("proc/1")).unwrap();
    std::fs::create_dir_all(root.path().join("run/systemd/system")).unwrap();
    std::fs::write(root.path().join("proc/1/comm"), "runit\n").unwrap();
    assert_eq!(detect_init_system_at(root.path()), InitSystem::Runit);
}

#[test]
fn missing_pid_one_uses_runtime_markers_and_unknown_is_safe() {
    let root = tempfile::tempdir().unwrap();
    assert_eq!(detect_init_system_at(root.path()), InitSystem::Unknown);
    std::fs::create_dir_all(root.path().join("run/openrc")).unwrap();
    assert_eq!(detect_init_system_at(root.path()), InitSystem::OpenRc);
    std::fs::create_dir_all(root.path().join("run/systemd/system")).unwrap();
    assert_eq!(detect_init_system_at(root.path()), InitSystem::Systemd);
}

#[test]
fn networkd_advice_respects_first_match_and_quotes_interface_commands() {
    let advice = format_competing_manager_advice_for_init(
        &["systemd-networkd".into(), "NetworkManager".into()],
        "odd'iface",
        InitSystem::Systemd,
    );
    assert!(advice.contains("00-traffic-masq-unmanaged.network"));
    assert!(advice.contains("FIRST matching"));
    assert!(advice.contains("'odd'\"'\"'iface'"));
    assert!(!advice.contains("systemctl stop NetworkManager"));
}
