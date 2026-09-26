use std::os::unix::fs::{symlink, MetadataExt};

use tempfile::tempdir;

use super::*;

fn input(id: &str) -> WifiClientProfileInput {
    WifiClientProfileInput {
        id: id.to_string(),
        ssid: "home network".to_string(),
        country_code: Some("PL".to_string()),
        security: WifiClientSecurity::Wpa2,
        priority: 10,
        autoconnect: false,
    }
}

fn secret() -> WifiPassphrase {
    WifiPassphrase::new("correct horse battery").expect("passphrase")
}

#[test]
fn rejects_traversal_and_non_ascii_ids() {
    let dir = tempdir().unwrap();
    let store = WifiClientProfileStore::new(dir.path().join("profiles"));
    for id in ["", "..", "a/b", "a.b", "é", &"a".repeat(65)] {
        assert!(matches!(
            store.create(input(id), None),
            Err(WifiClientProfileError::InvalidId)
        ));
    }
}

#[test]
fn crud_and_secret_update_semantics_work() {
    let dir = tempdir().unwrap();
    let store = WifiClientProfileStore::new(dir.path().join("profiles"));
    let created = store.create(input("home"), Some(secret())).unwrap();
    assert!(created.has_passphrase);
    assert_eq!(
        store.get_passphrase("home").unwrap().unwrap().expose(),
        "correct horse battery"
    );

    let mut changed = input("home");
    changed.ssid = "new ssid".into();
    let updated = store
        .update(changed.clone(), WifiClientProfileSecretUpdate::Unchanged)
        .unwrap();
    assert_eq!(updated.created_at, created.created_at);
    assert!(updated.has_passphrase);
    let cleared = store
        .update(changed.clone(), WifiClientProfileSecretUpdate::Clear)
        .unwrap();
    assert!(!cleared.has_passphrase);
    let replaced = store
        .update(changed, WifiClientProfileSecretUpdate::Replace(secret()))
        .unwrap();
    assert!(replaced.has_passphrase);
    assert_eq!(store.list().unwrap(), vec![replaced]);

    store.delete("home").unwrap();
    assert!(matches!(
        store.get("home"),
        Err(WifiClientProfileError::NotFound)
    ));
    assert!(matches!(
        store.delete("home"),
        Err(WifiClientProfileError::NotFound)
    ));
}

#[test]
fn creates_restricted_directories_and_files() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("profiles");
    let store = WifiClientProfileStore::new(&root);
    store.create(input("home"), Some(secret())).unwrap();
    assert_eq!(fs::metadata(&root).unwrap().mode() & 0o777, 0o700);
    assert_eq!(
        fs::metadata(root.join("metadata")).unwrap().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(root.join("secrets")).unwrap().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(root.join("metadata/home.json"))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(root.join("secrets/home.psk")).unwrap().mode() & 0o777,
        0o600
    );
}

#[test]
fn rejects_symlinked_root_directories_and_targets() {
    let dir = tempdir().unwrap();
    let actual = dir.path().join("actual");
    fs::create_dir(&actual).unwrap();
    let linked = dir.path().join("linked");
    symlink(&actual, &linked).unwrap();
    let store = WifiClientProfileStore::new(&linked);
    assert!(matches!(
        store.list(),
        Err(WifiClientProfileError::SymlinkRejected(_))
    ));

    let root = dir.path().join("profiles");
    let store = WifiClientProfileStore::new(&root);
    store.list().unwrap();
    symlink(dir.path().join("outside"), root.join("metadata/evil.json")).unwrap();
    assert!(matches!(
        store.get("evil"),
        Err(WifiClientProfileError::SymlinkRejected(_))
    ));
    symlink(
        dir.path().join("outside-secret"),
        root.join("secrets/secret.psk"),
    )
    .unwrap();
    assert!(matches!(
        store.create(input("secret"), None),
        Err(WifiClientProfileError::SymlinkRejected(_))
    ));
}

#[test]
fn metadata_summary_debug_and_errors_never_leak_the_secret() {
    let dir = tempdir().unwrap();
    let store = WifiClientProfileStore::new(dir.path().join("profiles"));
    let value = "unique-secret-value";
    let update = WifiClientProfileSecretUpdate::Replace(WifiPassphrase::new(value).unwrap());
    assert!(!format!("{update:?}").contains(value));
    store
        .create(input("home"), Some(WifiPassphrase::new(value).unwrap()))
        .unwrap();
    let summary = store.get("home").unwrap();
    assert!(!format!("{summary:?}").contains(value));
    assert!(!serde_json::to_string(&summary).unwrap().contains(value));
    assert!(!fs::read_to_string(store.root().join("metadata/home.json"))
        .unwrap()
        .contains(value));
}

#[test]
fn profile_validation_matches_wifi_client_config() {
    let dir = tempdir().unwrap();
    let store = WifiClientProfileStore::new(dir.path().join("profiles"));
    let mut invalid = input("bad");
    invalid.ssid.clear();
    assert!(matches!(
        store.create(invalid, None),
        Err(WifiClientProfileError::InvalidProfile(_))
    ));
    let mut invalid = input("bad-country");
    invalid.country_code = Some("pl".into());
    assert!(matches!(
        store.create(invalid, None),
        Err(WifiClientProfileError::InvalidProfile(_))
    ));
    let mut open = input("open");
    open.security = WifiClientSecurity::Open;
    assert!(matches!(
        store.create(open, Some(secret())),
        Err(WifiClientProfileError::InvalidProfile(_))
    ));
}

#[test]
fn list_rejects_symlink_entries_instead_of_following_them() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("profiles");
    let store = WifiClientProfileStore::new(&root);
    store.list().unwrap();
    symlink("elsewhere", root.join("metadata/planted.json")).unwrap();
    assert!(matches!(
        store.list(),
        Err(WifiClientProfileError::SymlinkRejected(_))
    ));
}

#[test]
fn every_profile_operation_rejects_metadata_with_a_different_id() {
    let dir = tempdir().unwrap();
    let store = WifiClientProfileStore::new(dir.path().join("profiles"));
    store.create(input("home"), Some(secret())).unwrap();
    let target = store.root().join("metadata/home.json");
    let mut metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(&target).unwrap()).unwrap();
    metadata["id"] = "other".into();
    fs::write(&target, serde_json::to_vec(&metadata).unwrap()).unwrap();
    assert!(store.list().is_err());
    assert!(store.get("home").is_err());
    assert!(store.get_passphrase("home").is_err());
    assert!(store
        .update(input("home"), WifiClientProfileSecretUpdate::Clear)
        .is_err());
    assert!(store.delete("home").is_err());
    assert!(store.root().join("secrets/home.psk").exists());
}
