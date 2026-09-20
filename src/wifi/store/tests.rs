use std::os::unix::fs::symlink;

use tempfile::tempdir;

use super::*;

fn passphrase(value: &str) -> WifiPassphrase {
    WifiPassphrase::new(value).expect("valid passphrase")
}

#[test]
fn set_creates_a_0600_file_in_a_0700_directory() {
    let dir = tempdir().expect("tempdir");
    let store_dir = dir.path().join("psk");
    let store = PassphraseStore::new(&store_dir);

    store
        .set("wlan0", &passphrase("correct horse battery"))
        .expect("set");

    let file_path = store_dir.join("wlan0");
    assert!(file_path.exists());
    let file_mode = fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(file_mode, 0o600);
    let dir_mode = fs::metadata(&store_dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700);
}

#[test]
fn set_then_get_round_trips_exactly() {
    let dir = tempdir().expect("tempdir");
    let store = PassphraseStore::new(dir.path().join("psk"));

    store
        .set("wlan0", &passphrase(" correct horse battery "))
        .expect("set");

    let read_back = store.get("wlan0").expect("get").expect("present");
    assert_eq!(read_back.expose(), " correct horse battery ");
}

#[test]
fn get_on_an_interface_never_set_is_none_not_an_error() {
    let dir = tempdir().expect("tempdir");
    let store = PassphraseStore::new(dir.path().join("psk"));
    assert_eq!(store.get("wlan0").expect("get"), None);
}

#[test]
fn set_replaces_a_previous_value_atomically() {
    let dir = tempdir().expect("tempdir");
    let store = PassphraseStore::new(dir.path().join("psk"));

    store.set("wlan0", &passphrase("first password")).unwrap();
    store.set("wlan0", &passphrase("second password")).unwrap();

    let read_back = store.get("wlan0").expect("get").expect("present");
    assert_eq!(read_back.expose(), "second password");

    let entries: Vec<_> = fs::read_dir(store.directory())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries, vec![std::ffi::OsString::from("wlan0")]);
}

#[test]
fn clear_is_idempotent() {
    let dir = tempdir().expect("tempdir");
    let store = PassphraseStore::new(dir.path().join("psk"));

    store.clear("wlan0").expect("clearing nothing is fine");
    store
        .set("wlan0", &passphrase("correct horse battery"))
        .unwrap();
    store.clear("wlan0").expect("clear");
    assert_eq!(store.get("wlan0").expect("get"), None);
    store.clear("wlan0").expect("clearing twice is fine");
}

#[test]
fn a_dot_or_dot_dot_interface_name_is_rejected_by_the_component_check() {
    let dir = tempdir().expect("tempdir");
    let store = PassphraseStore::new(dir.path().join("psk"));
    let secret = passphrase("correct horse battery");

    for hostile in [".", ".."] {
        let error = store.set(hostile, &secret).unwrap_err();
        assert!(
            matches!(error, PassphraseStoreError::PathEscape),
            "{hostile:?} should have been rejected, got {error:?}"
        );
    }
}

#[test]
fn a_path_separator_in_an_interface_name_is_rejected_before_touching_the_filesystem() {
    let dir = tempdir().expect("tempdir");
    let store = PassphraseStore::new(dir.path().join("psk"));
    let secret = passphrase("correct horse battery");

    for hostile in ["../escape", "a/../../escape", "a/b"] {
        let error = store.set(hostile, &secret).unwrap_err();
        assert!(
            matches!(error, PassphraseStoreError::InvalidInterfaceName(_)),
            "{hostile:?} should have been rejected, got {error:?}"
        );
    }
    assert!(!dir.path().join("escape").exists());
}

#[test]
fn rejects_a_symlinked_store_directory() {
    let dir = tempdir().expect("tempdir");
    let real_dir = dir.path().join("real");
    fs::create_dir_all(&real_dir).unwrap();
    let link_dir = dir.path().join("link");
    symlink(&real_dir, &link_dir).unwrap();

    let store = PassphraseStore::new(&link_dir);
    let error = store
        .set("wlan0", &passphrase("correct horse battery"))
        .unwrap_err();
    assert!(matches!(error, PassphraseStoreError::SymlinkRejected(_)));
}

#[test]
fn refuses_to_follow_a_preexisting_symlink_at_the_target() {
    let dir = tempdir().expect("tempdir");
    let store_dir = dir.path().join("psk");
    fs::create_dir_all(&store_dir).unwrap();
    fs::set_permissions(&store_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let outside = dir.path().join("outside-secret");
    symlink(&outside, store_dir.join("wlan0")).unwrap();

    let store = PassphraseStore::new(&store_dir);

    let error = store.get("wlan0").unwrap_err();
    assert!(matches!(error, PassphraseStoreError::SymlinkRejected(_)));
    assert!(!outside.exists());
}

fn spec_with(interface: &str, passphrase_file: Option<PathBuf>) -> WifiApSpec {
    use crate::config::{
        InterfaceConfig, InterfaceRole, WifiApConfig, WifiBand, WifiChannelWidth, WifiSecurity,
    };

    let config = InterfaceConfig {
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some("192.168.101.1/24".parse().expect("network")),
        dhcp: None,
        dhcp_client: None,
        wifi: Some(WifiApConfig {
            ssid: "traffic-masq".to_string(),
            country_code: Some("PL".to_string()),
            band: WifiBand::Ghz2,
            channel: 6,
            channel_width: WifiChannelWidth::Ht20,
            security: WifiSecurity::Wpa2,
            hidden: false,
            client_isolation: false,
            max_stations: 32,
            passphrase_file,
        }),
        wifi_client: None,
        nat: true,
    };
    WifiApSpec::from_interface_config(interface, &config)
        .expect("valid")
        .expect("spec")
}

#[test]
fn resolve_prefers_the_store_over_the_passphrase_file() {
    let dir = tempdir().expect("tempdir");
    let store = PassphraseStore::new(dir.path().join("psk"));
    store.set("wlan0", &passphrase("from the store")).unwrap();

    let file_path = dir.path().join("wlan0.psk");
    fs::write(&file_path, "from the file\n").unwrap();
    fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600)).unwrap();

    let spec = spec_with("wlan0", Some(file_path));
    let resolved = resolve_passphrase(&spec, &store)
        .expect("resolve")
        .expect("present");
    assert_eq!(resolved.expose(), "from the store");
}

#[test]
fn resolve_falls_back_to_the_passphrase_file_when_the_store_is_empty() {
    let dir = tempdir().expect("tempdir");
    let store = PassphraseStore::new(dir.path().join("psk"));

    let file_path = dir.path().join("wlan0.psk");
    fs::write(&file_path, "from the file\n").unwrap();
    fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600)).unwrap();

    let spec = spec_with("wlan0", Some(file_path));
    let resolved = resolve_passphrase(&spec, &store)
        .expect("resolve")
        .expect("present");
    assert_eq!(resolved.expose(), "from the file");
}

#[test]
fn resolve_strips_exactly_the_trailing_line_ending_crlf_included() {
    let dir = tempdir().expect("tempdir");
    let store = PassphraseStore::new(dir.path().join("psk"));

    let file_path = dir.path().join("wlan0.psk");
    fs::write(&file_path, "correct horse\r\nignored second line\n").unwrap();
    fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600)).unwrap();

    let spec = spec_with("wlan0", Some(file_path));
    let resolved = resolve_passphrase(&spec, &store)
        .expect("resolve")
        .expect("present");
    assert_eq!(resolved.expose(), "correct horse");
}

#[test]
fn resolve_is_none_with_neither_a_stored_nor_a_file_passphrase() {
    let dir = tempdir().expect("tempdir");
    let store = PassphraseStore::new(dir.path().join("psk"));
    let spec = spec_with("wlan0", None);
    assert_eq!(resolve_passphrase(&spec, &store).expect("resolve"), None);
}

#[test]
fn resolve_refuses_a_world_readable_passphrase_file() {
    let dir = tempdir().expect("tempdir");
    let store = PassphraseStore::new(dir.path().join("psk"));

    let file_path = dir.path().join("wlan0.psk");
    fs::write(&file_path, "correct horse battery\n").unwrap();
    fs::set_permissions(&file_path, fs::Permissions::from_mode(0o644)).unwrap();

    let spec = spec_with("wlan0", Some(file_path));
    let error = resolve_passphrase(&spec, &store).unwrap_err();
    assert!(matches!(
        error,
        ResolvePassphraseError::InsecurePermissions(_)
    ));
}

#[test]
fn resolve_refuses_a_symlinked_passphrase_file() {
    let dir = tempdir().expect("tempdir");
    let store = PassphraseStore::new(dir.path().join("psk"));

    let outside = dir.path().join("outside-secret");
    fs::write(&outside, "correct horse battery\n").unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
    let link_path = dir.path().join("wlan0.psk");
    symlink(&outside, &link_path).unwrap();

    let spec = spec_with("wlan0", Some(link_path));
    let error = resolve_passphrase(&spec, &store).unwrap_err();
    assert!(matches!(error, ResolvePassphraseError::SymlinkRejected(_)));
}

#[test]
fn resolve_rejects_an_empty_passphrase_file() {
    let dir = tempdir().expect("tempdir");
    let store = PassphraseStore::new(dir.path().join("psk"));

    let file_path = dir.path().join("wlan0.psk");
    fs::write(&file_path, "").unwrap();
    fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600)).unwrap();

    let spec = spec_with("wlan0", Some(file_path));
    let error = resolve_passphrase(&spec, &store).unwrap_err();
    assert!(matches!(error, ResolvePassphraseError::Empty(_)));
}

#[test]
fn resolve_rejects_a_passphrase_file_whose_first_line_fails_wpa_validation() {
    let dir = tempdir().expect("tempdir");
    let store = PassphraseStore::new(dir.path().join("psk"));

    let file_path = dir.path().join("wlan0.psk");
    fs::write(&file_path, "short\n").unwrap();
    fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600)).unwrap();

    let spec = spec_with("wlan0", Some(file_path));
    let error = resolve_passphrase(&spec, &store).unwrap_err();
    assert!(matches!(error, ResolvePassphraseError::Passphrase(_)));
}
