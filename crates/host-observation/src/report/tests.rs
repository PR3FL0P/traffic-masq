use super::*;
use std::os::unix::fs::symlink;

fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    for dir in [
        "proc/self/ns",
        "proc/net",
        "sys/class/net/wlan0",
        "run/systemd/netif/links",
    ] {
        std::fs::create_dir_all(root.path().join(dir)).unwrap();
    }
    symlink("net:[42]", root.path().join("proc/self/ns/net")).unwrap();
    std::fs::write(root.path().join("sys/class/net/wlan0/ifindex"), "3\n").unwrap();
    for name in ["unix", "udp", "udp6"] {
        std::fs::write(root.path().join("proc/net").join(name), "header\n").unwrap();
    }
    root
}

fn process(root: &Path, pid: u32, comm: &str, namespace: u32) {
    let path = root.join(format!("proc/{pid}"));
    std::fs::create_dir_all(path.join("ns")).unwrap();
    std::fs::create_dir_all(path.join("fd")).unwrap();
    std::fs::write(path.join("comm"), comm).unwrap();
    std::fs::write(
        path.join("cgroup"),
        "0::/system.slice/custom-wifi.service\n",
    )
    .unwrap();
    symlink(format!("net:[{namespace}]"), path.join("ns/net")).unwrap();
}

#[test]
fn missing_proc_is_incomplete_not_clean() {
    let root = tempfile::tempdir().unwrap();
    let report = scan_at(root.path(), &[]);
    assert_eq!(report.exit_code(), 2);
    assert!(report.render().contains("INCOMPLETE"));
    assert!(!report.render().contains("No candidates found"));
}

#[test]
fn clean_scope_and_unknown_selected_interface_have_distinct_results() {
    let root = fixture();
    assert_eq!(scan_at(root.path(), &[]).exit_code(), 0);
    let missing = scan_at(root.path(), &["missing0".into()]);
    assert_eq!(missing.exit_code(), 2);
    assert!(missing.interfaces.is_empty());
}

#[test]
fn foreign_namespace_is_ignored_and_workers_are_not_hidden() {
    let root = fixture();
    process(root.path(), 10, "NetworkManager", 43);
    process(root.path(), 11, "wpa_supplicant", 42);
    let report = scan_at(root.path(), &["wlan0".into()]);
    assert_eq!(report.exit_code(), 1);
    assert_eq!(report.processes.len(), 1);
    assert_eq!(report.processes[0].name, "wpa_supplicant");
    assert_eq!(
        report.processes[0].service.as_deref(),
        Some("custom-wifi.service")
    );
    assert!(report.render().contains("may be traffic-masq's own worker"));
}

#[test]
fn actual_socket_holder_is_correlated_without_claiming_foreign_ownership() {
    let root = fixture();
    process(root.path(), 12, "hostapd", 42);
    symlink("socket:[123]", root.path().join("proc/12/fd/5")).unwrap();
    std::fs::write(
        root.path().join("proc/net/unix"),
        "header\n0: 2 0 0 2 1 123 /run/hostapd/wlan0\n0: 2 0 0 2 1 124 /run/hostapd/wlan1\n",
    )
    .unwrap();
    let report = scan_at(root.path(), &["wlan0".into()]);
    assert_eq!(report.resources.len(), 1);
    assert_eq!(report.resources[0].holder_pids, vec![12]);
    assert!(report.resources[0].ownership.contains("not established"));
    assert_eq!(report.exit_code(), 1);
}

#[test]
fn stale_networkd_state_is_not_reported_as_live_management() {
    let root = fixture();
    std::fs::write(
        root.path().join("run/systemd/netif/links/3"),
        "ADMIN_STATE=configured\nNETWORK_FILE=/run/systemd/network/10-netplan.network\n",
    )
    .unwrap();
    let report = scan_at(root.path(), &[]);
    assert!(report.interfaces[0].networkd_state.is_none());
    assert_eq!(report.exit_code(), 2);
    process(root.path(), 13, "systemd-network", 42);
    let report = scan_at(root.path(), &[]);
    assert_eq!(
        report.interfaces[0].networkd_state.as_deref(),
        Some("configured")
    );
    assert_eq!(report.exit_code(), 1);
}

#[test]
fn unknown_nm_output_is_not_treated_as_unmanaged() {
    assert_eq!(parse_nm_managed("yes\n"), Ok(true));
    assert_eq!(parse_nm_managed("no\n"), Ok(false));
    assert!(parse_nm_managed("unavailable").is_err());
    assert!(parse_nm_managed("").is_err());
}

#[test]
fn dhcp_port_filter_includes_ipv6_and_ignores_dns() {
    let mut sockets = BTreeMap::new();
    collect_sockets("net/udp", "header\n0: 00000000:0043 00000000:0000 07 0 0 0 0 0 222\n0: 00000000:0035 00000000:0000 07 0 0 0 0 0 333\n", &[], &mut sockets);
    collect_sockets(
        "net/udp6",
        "header\n0: 00000000000000000000000000000000:0043 0 07 0 0 0 0 0 444\n",
        &[],
        &mut sockets,
    );
    assert_eq!(sockets.len(), 2);
    assert!(sockets.contains_key("socket:[222]"));
    assert!(sockets.contains_key("socket:[444]"));
}

#[test]
fn socket_addresses_are_readable_and_use_kernel_native_byte_order() {
    let hex = format!("{:08X}", u32::from_ne_bytes([192, 168, 1, 1]));
    assert_eq!(decode_address(&hex).as_deref(), Some("192.168.1.1"));
    assert_eq!(
        decode_address("00000000000000000000000000000000").as_deref(),
        Some("[::]")
    );
    assert!(decode_address("invalid").is_none());
}
