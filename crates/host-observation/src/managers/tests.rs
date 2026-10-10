use super::*;

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

#[tokio::test]
async fn scan_canonicalizes_aliases_and_ignores_unavailable_or_supervised_processes() {
    let root = tempfile::tempdir().unwrap();
    for (pid, comm) in [
        ("1", "systemd-network"),
        ("2", "systemd-networkd"),
        ("3", "connmand"),
        ("4", "connman"),
        ("5", "hostapd"),
        ("6", "wpa_supplicant"),
        ("7", "NetworkManager"),
        ("non-pid", "iwd"),
    ] {
        let path = root.path().join(pid);
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("comm"), format!("{comm}\n")).unwrap();
    }
    // A process can disappear after readdir but before its comm is read.
    std::fs::create_dir(root.path().join("8")).unwrap();
    assert_eq!(
        find_competing_network_managers_at(root.path()).await,
        ["NetworkManager", "connman", "systemd-networkd"],
    );
}
