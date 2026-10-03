use std::os::unix::fs::{symlink, PermissionsExt};

use tempfile::tempdir;

use super::*;

const VALID_PRIVATE_KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
const VALID_PUBLIC_KEY: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

fn valid_config() -> String {
    format!(
        "[Interface]\n\
         PrivateKey = {VALID_PRIVATE_KEY}\n\
         Address = 10.0.0.2/24\n\
         \n\
         [Peer]\n\
         PublicKey = {VALID_PUBLIC_KEY}\n\
         AllowedIPs = 0.0.0.0/0\n\
         Endpoint = 203.0.113.1:51820\n"
    )
}

#[test]
fn import_creates_file_with_expected_mode_and_contents() {
    let dir = tempdir().expect("tempdir");
    let store_dir = dir.path().join("wireguard");
    let store = WireGuardProfileStore::new(&store_dir);
    let driver = WireGuardDriver;

    let raw = valid_config();
    let profile = store
        .import(&driver, "home.conf", raw.as_bytes())
        .expect("import should succeed");
    assert_eq!(profile.name, "home.conf");

    let file_path = store_dir.join("home.conf");
    assert!(file_path.exists());

    let contents = fs::read(&file_path).expect("read imported file");
    assert_eq!(contents, raw.as_bytes());

    let file_mode = fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(file_mode, 0o600);

    let dir_mode = fs::metadata(&store_dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700);
}

#[test]
fn import_rejects_path_traversal_in_name() {
    let dir = tempdir().expect("tempdir");
    let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
    let driver = WireGuardDriver;

    let err = store
        .import(&driver, "../escape.conf", valid_config().as_bytes())
        .unwrap_err();
    assert!(matches!(err, StoreError::Profile(_)));

    assert!(!dir.path().join("escape.conf").exists());
}

#[test]
fn import_refuses_to_follow_preexisting_symlink_at_target() {
    let dir = tempdir().expect("tempdir");
    let store_dir = dir.path().join("wireguard");
    fs::create_dir_all(&store_dir).unwrap();
    fs::set_permissions(&store_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let outside_target = dir.path().join("outside-secret.conf");

    let link_path = store_dir.join("evil.conf");
    symlink(&outside_target, &link_path).expect("create symlink");

    let store = WireGuardProfileStore::new(&store_dir);
    let driver = WireGuardDriver;

    let err = store
        .import(&driver, "evil.conf", valid_config().as_bytes())
        .unwrap_err();
    assert!(matches!(err, StoreError::SymlinkRejected(_)));

    assert!(!outside_target.exists());

    assert!(fs::symlink_metadata(&link_path)
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn import_rejects_symlinked_store_directory() {
    let dir = tempdir().expect("tempdir");
    let real_dir = dir.path().join("real");
    fs::create_dir_all(&real_dir).unwrap();
    let link_dir = dir.path().join("link");
    symlink(&real_dir, &link_dir).expect("create dir symlink");

    let store = WireGuardProfileStore::new(&link_dir);
    let driver = WireGuardDriver;
    let err = store
        .import(&driver, "home.conf", valid_config().as_bytes())
        .unwrap_err();
    assert!(matches!(err, StoreError::SymlinkRejected(_)));
}

#[test]
fn list_returns_safe_metadata_without_secrets() {
    let dir = tempdir().expect("tempdir");
    let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
    let driver = WireGuardDriver;

    store
        .import(&driver, "a.conf", valid_config().as_bytes())
        .unwrap();
    store
        .import(&driver, "b.conf", valid_config().as_bytes())
        .unwrap();

    let summaries = store.list().expect("list");
    assert_eq!(summaries.len(), 2);
    assert_eq!(summaries[0].name, "a.conf");
    assert_eq!(summaries[1].name, "b.conf");
    assert!(summaries[0].size_bytes > 0);

    for summary in &summaries {
        let debug = format!("{summary:?}");
        assert!(!debug.contains(VALID_PRIVATE_KEY));
    }
}

#[test]
fn list_ignores_symlinks_inside_store_directory() {
    let dir = tempdir().expect("tempdir");
    let store_dir = dir.path().join("wireguard");
    let store = WireGuardProfileStore::new(&store_dir);
    let driver = WireGuardDriver;

    store
        .import(&driver, "real.conf", valid_config().as_bytes())
        .unwrap();

    let outside = dir.path().join("outside.conf");
    fs::write(&outside, valid_config()).unwrap();
    symlink(&outside, store_dir.join("linked.conf")).unwrap();

    let summaries = store.list().expect("list");
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].name, "real.conf");
}

#[test]
fn delete_removes_only_files_inside_store() {
    let dir = tempdir().expect("tempdir");
    let store_dir = dir.path().join("wireguard");
    let store = WireGuardProfileStore::new(&store_dir);
    let driver = WireGuardDriver;

    store
        .import(&driver, "home.conf", valid_config().as_bytes())
        .unwrap();
    assert!(store_dir.join("home.conf").exists());

    store.delete("home.conf").expect("delete");
    assert!(!store_dir.join("home.conf").exists());

    let err = store.delete("home.conf").unwrap_err();
    assert!(matches!(err, StoreError::NotFound(_)));
}

#[test]
fn delete_rejects_path_traversal_and_leaves_outside_file_untouched() {
    let dir = tempdir().expect("tempdir");
    let store_dir = dir.path().join("wireguard");
    fs::create_dir_all(&store_dir).unwrap();

    let outside = dir.path().join("victim.conf");
    fs::write(&outside, "do-not-delete-me").unwrap();

    let store = WireGuardProfileStore::new(&store_dir);
    let err = store.delete("../victim.conf").unwrap_err();
    assert!(matches!(err, StoreError::Profile(_)));
    assert!(outside.exists());
}

#[test]
fn delete_refuses_to_remove_symlink_even_if_target_name_matches() {
    let dir = tempdir().expect("tempdir");
    let store_dir = dir.path().join("wireguard");
    fs::create_dir_all(&store_dir).unwrap();

    let outside = dir.path().join("outside.conf");
    fs::write(&outside, "sensitive").unwrap();
    symlink(&outside, store_dir.join("linked.conf")).unwrap();

    let store = WireGuardProfileStore::new(&store_dir);
    let err = store.delete("linked.conf").unwrap_err();
    assert!(matches!(err, StoreError::SymlinkRejected(_)));
    assert!(outside.exists());
    assert!(fs::symlink_metadata(store_dir.join("linked.conf"))
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn read_round_trips_imported_profile() {
    let dir = tempdir().expect("tempdir");
    let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
    let driver = WireGuardDriver;

    store
        .import(&driver, "home.conf", valid_config().as_bytes())
        .unwrap();

    let profile = store.read(&driver, "home.conf").expect("read");
    assert_eq!(profile.name, "home.conf");
    assert_eq!(profile.peers.len(), 1);
}

#[test]
fn read_missing_profile_is_not_found() {
    let dir = tempdir().expect("tempdir");
    let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
    let driver = WireGuardDriver;
    let err = store.read(&driver, "missing.conf").unwrap_err();
    assert!(matches!(err, StoreError::NotFound(_)));
}

#[test]
fn ensure_directory_rejects_symlinked_directory_on_list() {
    let dir = tempdir().expect("tempdir");
    let real_dir = dir.path().join("real");
    fs::create_dir_all(&real_dir).unwrap();
    let link_dir = dir.path().join("link");
    symlink(&real_dir, &link_dir).unwrap();

    let store = WireGuardProfileStore::new(&link_dir);
    let err = store.list().unwrap_err();
    assert!(matches!(err, StoreError::SymlinkRejected(_)));
}

#[test]
fn source_browser_lists_only_regular_configs_and_preserves_permissions() {
    let directory = tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750)).unwrap();
    fs::write(directory.path().join("wg0.conf"), valid_config()).unwrap();
    fs::write(directory.path().join("notes.txt"), "notes").unwrap();
    symlink("wg0.conf", directory.path().join("alias.conf")).unwrap();
    fs::create_dir(directory.path().join("folder.conf")).unwrap();
    let profiles = list_source_profiles(directory.path()).unwrap();
    assert_eq!(
        profiles.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
        vec!["wg0.conf"]
    );
    let contents = read_source_profile(directory.path(), "wg0.conf").unwrap();
    assert_eq!(&*contents, valid_config().as_bytes());
    assert_eq!(
        fs::metadata(directory.path()).unwrap().permissions().mode() & 0o777,
        0o750
    );
    assert!(read_source_profile(directory.path(), "alias.conf").is_err());
    assert!(read_source_profile(directory.path(), "../wg0.conf").is_err());
    assert!(read_source_profile(directory.path(), "folder.conf").is_err());
}

#[test]
fn source_import_rejects_oversized_files_and_fifos_without_blocking() {
    let directory = tempdir().unwrap();
    fs::write(
        directory.path().join("large.conf"),
        vec![b'x'; 1024 * 1024 + 1],
    )
    .unwrap();
    assert!(read_source_profile(directory.path(), "large.conf").is_err());
    let fifo = directory.path().join("fifo.conf");
    nix::unistd::mkfifo(&fifo, Mode::from_bits_truncate(0o600)).unwrap();
    assert!(read_source_profile(directory.path(), "fifo.conf").is_err());
}

#[test]
fn missing_source_directory_is_empty_without_being_created() {
    let directory = tempdir().unwrap();
    let missing = directory.path().join("missing");
    assert!(list_source_profiles(&missing).unwrap().is_empty());
    assert!(!missing.exists());
}
