use std::os::unix::fs::symlink;

use tempfile::tempdir;

use crate::config::WifiSecurity;

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
    assert!(matches!(
        store.get("wlan0"),
        Err(PassphraseStoreError::SymlinkRejected(_))
    ));
}

#[test]
fn reading_repairs_loose_directory_permissions() {
    let root = tempdir().unwrap();
    let directory = root.path().join("secrets");
    let store = PassphraseStore::new(&directory);
    store
        .set("wlan0", &passphrase("correct horse battery"))
        .unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(store.get("wlan0").unwrap().is_some());
    assert_eq!(
        fs::metadata(directory).unwrap().permissions().mode() & 0o7777,
        0o700
    );
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

fn spec_with_security(
    interface: &str,
    passphrase_file: Option<PathBuf>,
    security: WifiSecurity,
) -> WifiApSpec {
    use crate::config::{InterfaceConfig, InterfaceRole, WifiApConfig, WifiBand, WifiChannelWidth};

    let config = InterfaceConfig {
        wifi_concurrent: false,
        mac_address: None,
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
            security,
            hidden: false,
            client_isolation: false,
            max_stations: 32,
            passphrase_file,
        }),
        wifi_client: None,
    };
    WifiApSpec::from_interface_config(interface, &config)
        .expect("valid")
        .expect("spec")
}

fn spec_with(interface: &str, passphrase_file: Option<PathBuf>) -> WifiApSpec {
    spec_with_security(interface, passphrase_file, WifiSecurity::Wpa2)
}

#[test]
fn open_ap_ignores_a_stale_stored_passphrase() {
    let dir = tempdir().expect("tempdir");
    let store = PassphraseStore::new(dir.path().join("psk"));
    store
        .set("wlan0", &passphrase("stale protected secret"))
        .expect("set stale secret");

    let spec = spec_with_security("wlan0", None, WifiSecurity::Open);
    assert_eq!(resolve_passphrase(&spec, &store).expect("resolve"), None);
    assert!(store.get("wlan0").expect("get").is_some());
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

#[test]
fn role_stores_never_resolve_or_clear_another_roles_secret() {
    let dir = tempdir().unwrap();
    let ap = PassphraseStore::for_role(dir.path(), WifiCredentialRole::Ap);
    let client = PassphraseStore::for_role(dir.path(), WifiCredentialRole::Client);
    let legacy = PassphraseStore::new(dir.path().join("wifi/psk"));
    legacy.set("wlan0", &passphrase("legacy-password")).unwrap();
    assert!(ap.get("wlan0").unwrap().is_none());
    assert!(client.get("wlan0").unwrap().is_none());
    ap.set("wlan0", &passphrase("ap-password")).unwrap();
    assert!(client.get("wlan0").unwrap().is_none());
    client.set("wlan0", &passphrase("client-password")).unwrap();
    ap.clear("wlan0").unwrap();
    assert_eq!(
        client.get("wlan0").unwrap().unwrap().expose(),
        "client-password"
    );
    assert_eq!(
        legacy.get("wlan0").unwrap().unwrap().expose(),
        "legacy-password"
    );
}

#[test]
fn oversized_passphrase_files_are_rejected_without_replacing_them() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wlan0");
    File::create(&path)
        .unwrap()
        .set_len(MAX_SECRET_FILE_BYTES + 1)
        .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        matches!(read_passphrase_file(&path), Err(ResolvePassphraseError::Io { source, .. }) if source.kind() == std::io::ErrorKind::InvalidData)
    );
    let store = PassphraseStore::new(dir.path());
    assert!(store.get("wlan0").is_err());
    assert!(store
        .set("wlan0", &passphrase("replacement password"))
        .is_err());
    assert_eq!(fs::metadata(path).unwrap().len(), MAX_SECRET_FILE_BYTES + 1);
}

#[test]
fn external_fifo_is_rejected_without_waiting_for_a_writer() {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = tempdir().unwrap();
    let path = dir.path().join("secret");
    nix::unistd::mkfifo(&path, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
    let mut writer = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(&path)
        .unwrap();
    writer.write_all(b"valid password").unwrap();
    let release = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(100));
        drop(writer);
    });
    let result = read_passphrase_file(&path);
    release.join().unwrap();
    assert!(
        matches!(result, Err(ResolvePassphraseError::Io { source, .. }) if source.kind() == std::io::ErrorKind::InvalidData)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn blocking_store_keeps_the_async_worker_available() {
    let (release, wait) = std::sync::mpsc::channel();
    let (entered, started) = tokio::sync::oneshot::channel();
    let operation = tokio::spawn(blocking_store(move || {
        entered.send(()).unwrap();
        wait.recv_timeout(std::time::Duration::from_secs(5))
            .map_err(std::io::Error::other)
    }));
    started.await.unwrap();
    // This task must run while the synchronous store operation is still waiting.
    release.send(()).unwrap();
    operation.await.unwrap().unwrap();
}

#[tokio::test]
async fn async_secret_store_preserves_read_write_and_clear_behavior() {
    let root = tempfile::tempdir().unwrap();
    let store = PassphraseStore::new(root.path().join("secrets"));
    let secret = WifiPassphrase::new("test-passphrase").unwrap();
    store.set_async("wlan0", &secret).await.unwrap();
    assert_eq!(
        store.get_async("wlan0").await.unwrap().unwrap().expose(),
        secret.expose()
    );
    store.clear_async("wlan0").await.unwrap();
    assert!(store.get_async("wlan0").await.unwrap().is_none());
}
