use tempfile::tempdir;

use super::*;

fn digest(seed: u8) -> WifiDigest {
    WifiDigest::from_bytes([seed; 32])
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn ap_runtime() -> PathBuf {
    PathBuf::from("/run/traffic-masq/hostapd")
}

fn client_runtime() -> PathBuf {
    PathBuf::from("/run/traffic-masq/wpa")
}

fn record(pid: u32) -> PersistedWifiRecord {
    PersistedWifiRecord {
        pid,
        started_at_unix: 1_700_000_000,
        process_start_ticks: Some(42_424_242),
        boot_id: Some("test-boot".to_string()),
        binary_path: Some(std::path::PathBuf::from("/usr/sbin/hostapd")),
        ctrl_path: PathBuf::from("/run/traffic-masq/hostapd/wlan0"),
        ctrl_dev: None,
        ctrl_ino: None,
        config_path: PathBuf::from("/run/traffic-masq/hostapd/wlan0.conf"),
        config_digest: digest(1),
        key_digest: digest(2),
        ssid: "traffic-masq".to_string(),
    }
}

async fn write_legacy_document(path: &Path, record: &PersistedWifiRecord) {
    let document = PersistedWifiRecordDocument {
        schema_version: LEGACY_WIFI_RECORD_SCHEMA,
        kind: None,
        interface: None,
        pid: record.pid,
        started_at_unix: record.started_at_unix,
        process_start_ticks: record.process_start_ticks,
        boot_id: record.boot_id.clone(),
        binary_path: record.binary_path.clone(),
        ctrl_path: record.ctrl_path.clone(),
        ctrl_dev: record.ctrl_dev,
        ctrl_ino: record.ctrl_ino,
        config_path: record.config_path.clone(),
        config_digest: record.config_digest,
        key_digest: record.key_digest,
        ssid: record.ssid.clone(),
    };
    tokio::fs::write(path, serde_json::to_vec_pretty(&document).unwrap())
        .await
        .expect("write legacy record");
}

#[tokio::test]
async fn missing_file_loads_as_none() {
    let directory = tempdir().expect("tempdir");
    let store = WifiRecordStore::for_access_point(directory.path(), ap_runtime(), "wlan0");
    assert_eq!(store.load().await.expect("load"), None);
}

#[tokio::test]
async fn save_then_load_round_trips() {
    let directory = tempdir().expect("tempdir");
    let store = WifiRecordStore::for_access_point(directory.path(), ap_runtime(), "wlan0");
    let saved = record(1234);

    store.save(&saved).await.expect("save");
    let loaded = store.load().await.expect("load").expect("present");
    assert_eq!(loaded, saved);
}

#[tokio::test]
async fn two_interfaces_get_independent_files() {
    let directory = tempdir().expect("tempdir");
    let wlan0 = WifiRecordStore::for_access_point(directory.path(), ap_runtime(), "wlan0");
    let wlan1 = WifiRecordStore::for_access_point(directory.path(), ap_runtime(), "wlan1");

    wlan0.save(&record(1)).await.expect("save wlan0");
    let mut wlan1_record = record(2);
    wlan1_record.ctrl_path = PathBuf::from("/run/traffic-masq/hostapd/wlan1");
    wlan1_record.config_path = PathBuf::from("/run/traffic-masq/hostapd/wlan1.conf");
    wlan1.save(&wlan1_record).await.expect("save wlan1");

    assert_ne!(wlan0.path(), wlan1.path());
    assert_eq!(wlan0.load().await.expect("load").unwrap().pid, 1);
    assert_eq!(wlan1.load().await.expect("load").unwrap().pid, 2);
}

#[tokio::test]
async fn save_overwrites_previous_record() {
    let directory = tempdir().expect("tempdir");
    let store = WifiRecordStore::for_access_point(directory.path(), ap_runtime(), "wlan0");
    store.save(&record(1)).await.expect("save first");
    store.save(&record(2)).await.expect("save second");

    let loaded = store.load().await.expect("load").expect("present");
    assert_eq!(loaded.pid, 2);
}

#[tokio::test]
async fn clear_removes_record_and_is_idempotent() {
    let directory = tempdir().expect("tempdir");
    let store = WifiRecordStore::for_access_point(directory.path(), ap_runtime(), "wlan0");
    store.save(&record(1)).await.expect("save");

    store.clear().await.expect("clear");
    assert_eq!(store.load().await.expect("load"), None);
    store.clear().await.expect("clear again");
}

#[tokio::test]
async fn transition_marker_round_trips_and_clear_removes_it() {
    let directory = tempdir().expect("tempdir");
    let store = WifiRecordStore::for_access_point(directory.path(), ap_runtime(), "wlan0");

    assert!(!store.transition_pending().await.expect("initial state"));
    store.mark_transition().await.expect("mark");
    assert!(store.transition_pending().await.expect("marked"));
    store.save(&record(1)).await.expect("save");
    store.clear().await.expect("clear");
    assert!(!store.transition_pending().await.expect("cleared"));
}

#[tokio::test]
async fn ap_and_client_namespaces_cannot_collide() {
    let directory = tempdir().expect("tempdir");
    let ap = WifiRecordStore::for_access_point(directory.path(), ap_runtime(), "client-wlan0");
    let client = WifiRecordStore::for_client(directory.path(), client_runtime(), "wlan0");
    let mut ap_record = record(7);
    ap_record.ctrl_path = PathBuf::from("/run/traffic-masq/hostapd/client-wlan0");
    ap_record.config_path = PathBuf::from("/run/traffic-masq/hostapd/client-wlan0.conf");
    let mut client_record = record(8);
    client_record.ctrl_path = PathBuf::from("/run/traffic-masq/wpa/wlan0");
    client_record.config_path = PathBuf::from("/run/traffic-masq/wpa/wlan0.conf");

    ap.save(&ap_record).await.expect("save AP");
    client.save(&client_record).await.expect("save client");

    assert_ne!(ap.path(), client.path());
    assert_eq!(ap.load().await.expect("load AP").unwrap().pid, 7);
    assert_eq!(client.load().await.expect("load client").unwrap().pid, 8);
}

#[tokio::test]
async fn legacy_ap_record_is_migrated_into_ap_namespace() {
    let directory = tempdir().expect("tempdir");
    let legacy = directory.path().join("active-client-wlan0.json");
    let legacy_transition = legacy.with_extension("transition");
    let mut saved = record(7);
    saved.ctrl_path = PathBuf::from("/run/traffic-masq/hostapd/client-wlan0");
    saved.config_path = PathBuf::from("/run/traffic-masq/hostapd/client-wlan0.conf");
    write_legacy_document(&legacy, &saved).await;
    tokio::fs::write(&legacy_transition, b"pending\n")
        .await
        .expect("legacy transition");

    let store = WifiRecordStore::for_access_point(directory.path(), ap_runtime(), "client-wlan0");
    assert_eq!(store.load().await.expect("load").unwrap().pid, 7);
    assert!(store.path().exists());
    assert!(!legacy.exists());
    assert!(store
        .transition_pending()
        .await
        .expect("transition migrated"));
    assert!(!legacy_transition.exists());
}

#[tokio::test]
async fn discovery_migrates_legacy_record_into_namespaced_store() {
    let directory = tempdir().expect("tempdir");
    let legacy = directory.path().join("active-client-wlan0.json");
    let mut saved = record(10);
    saved.ctrl_path = PathBuf::from("/run/traffic-masq/wpa/wlan0");
    saved.config_path = PathBuf::from("/run/traffic-masq/wpa/wlan0.conf");
    write_legacy_document(&legacy, &saved).await;

    let records =
        WifiRecordStore::discover(WifiProcessKind::Client, directory.path(), client_runtime())
            .await
            .expect("discover client");

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].0, "wlan0");
    assert_eq!(records[0].2.pid, 10);
    assert!(records[0]
        .1
        .path()
        .starts_with(directory.path().join("client")));
    assert!(!legacy.exists());
}

#[tokio::test]
async fn legacy_collision_is_migrated_only_by_matching_kind() {
    let directory = tempdir().expect("tempdir");
    let legacy = directory.path().join("active-client-wlan0.json");
    let mut saved = record(9);
    saved.ctrl_path = PathBuf::from("/run/traffic-masq/wpa/wlan0");
    saved.config_path = PathBuf::from("/run/traffic-masq/wpa/wlan0.conf");
    write_legacy_document(&legacy, &saved).await;

    let ap = WifiRecordStore::for_access_point(directory.path(), ap_runtime(), "client-wlan0");
    assert!(ap.load().await.expect("AP load").is_none());
    assert!(
        legacy.exists(),
        "AP lookup must not consume a client record"
    );

    let client = WifiRecordStore::for_client(directory.path(), client_runtime(), "wlan0");
    assert_eq!(client.load().await.expect("client load").unwrap().pid, 9);
    assert!(client.path().exists());
    assert!(!legacy.exists());
}

#[tokio::test]
async fn rejects_unsupported_schema_version() {
    let directory = tempdir().expect("tempdir");
    let store = WifiRecordStore::for_access_point(directory.path(), ap_runtime(), "wlan0");
    tokio::fs::create_dir_all(store.path().parent().unwrap())
        .await
        .unwrap();
    let path = store.path().to_path_buf();
    tokio::fs::write(
        &path,
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 99,
            "pid": 1,
            "started_at_unix": 0,
            "ctrl_path": "/run/x",
            "config_path": "/run/x.conf",
            "config_digest": hex_of(&[1; 32]),
            "key_digest": hex_of(&[2; 32]),
            "ssid": "traffic-masq",
        }))
        .unwrap(),
    )
    .await
    .unwrap();

    let error = store.load().await.expect_err("unsupported schema");
    assert!(matches!(error, WifiRecordError::UnsupportedSchema(_, 99)));
}

#[tokio::test]
async fn legacy_record_without_executable_identity_loads_unproven() {
    let directory = tempdir().expect("tempdir");
    let store = WifiRecordStore::for_access_point(directory.path(), ap_runtime(), "wlan0");
    tokio::fs::create_dir_all(store.path().parent().unwrap())
        .await
        .unwrap();
    tokio::fs::write(
        store.path(),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "pid": 4242,
            "started_at_unix": 1_700_000_000u64,
            "ctrl_path": "/run/traffic-masq/hostapd/wlan0",
            "config_path": "/run/traffic-masq/hostapd/wlan0.conf",
            "config_digest": hex_of(&[1; 32]),
            "key_digest": hex_of(&[2; 32]),
            "ssid": "traffic-masq",
        }))
        .unwrap(),
    )
    .await
    .unwrap();

    let record = store
        .load()
        .await
        .expect("legacy record loads")
        .expect("record");
    assert_eq!(record.pid, 4242);
    assert_eq!(record.process_start_ticks, None);
    assert_eq!(record.boot_id, None);
    assert_eq!(record.binary_path, None);

    let migrated: serde_json::Value = serde_json::from_slice(
        &tokio::fs::read(store.path())
            .await
            .expect("read migrated record"),
    )
    .expect("parse migrated record");
    assert_eq!(
        migrated["schema_version"],
        serde_json::json!(CURRENT_WIFI_RECORD_SCHEMA)
    );
    assert_eq!(migrated["kind"], serde_json::json!("access_point"));
    assert_eq!(migrated["interface"], serde_json::json!("wlan0"));
}

#[tokio::test]
async fn schema_v2_requires_explicit_kind_and_interface() {
    let directory = tempdir().expect("tempdir");
    let store = WifiRecordStore::for_access_point(directory.path(), ap_runtime(), "wlan0");
    tokio::fs::create_dir_all(store.path().parent().unwrap())
        .await
        .unwrap();

    for missing in ["kind", "interface"] {
        let mut document = serde_json::json!({
            "schema_version": CURRENT_WIFI_RECORD_SCHEMA,
            "kind": "access_point",
            "interface": "wlan0",
            "pid": 42,
            "started_at_unix": 1_700_000_000u64,
            "ctrl_path": "/run/traffic-masq/hostapd/wlan0",
            "config_path": "/run/traffic-masq/hostapd/wlan0.conf",
            "config_digest": hex_of(&[1; 32]),
            "key_digest": hex_of(&[2; 32]),
            "ssid": "traffic-masq",
        });
        document.as_object_mut().unwrap().remove(missing);
        tokio::fs::write(store.path(), serde_json::to_vec(&document).unwrap())
            .await
            .unwrap();
        assert!(matches!(
            store.load().await,
            Err(WifiRecordError::MismatchedContext(_))
        ));
    }
}

#[tokio::test]
async fn legacy_schema_record_outside_configured_runtime_root_is_rejected() {
    let directory = tempdir().expect("tempdir");
    let store = WifiRecordStore::for_access_point(directory.path(), ap_runtime(), "wlan0");
    tokio::fs::create_dir_all(store.path().parent().unwrap())
        .await
        .unwrap();
    tokio::fs::write(
        store.path(),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": LEGACY_WIFI_RECORD_SCHEMA,
            "pid": 42,
            "started_at_unix": 1_700_000_000u64,
            "ctrl_path": "/tmp/foreign-runtime/wlan0",
            "config_path": "/tmp/foreign-runtime/wlan0.conf",
            "config_digest": hex_of(&[1; 32]),
            "key_digest": hex_of(&[2; 32]),
            "ssid": "traffic-masq",
        }))
        .unwrap(),
    )
    .await
    .unwrap();

    assert!(matches!(
        store.load().await,
        Err(WifiRecordError::MismatchedContext(_))
    ));
}

#[tokio::test]
async fn rejects_self_consistent_paths_outside_configured_runtime_root() {
    let directory = tempdir().expect("tempdir");
    let store = WifiRecordStore::for_access_point(directory.path(), ap_runtime(), "wlan0");
    let mut foreign = record(42);
    foreign.ctrl_path = PathBuf::from("/tmp/foreign-runtime/wlan0");
    foreign.config_path = PathBuf::from("/tmp/foreign-runtime/wlan0.conf");

    assert!(matches!(
        store.save(&foreign).await,
        Err(WifiRecordError::MismatchedContext(_))
    ));

    tokio::fs::create_dir_all(store.path().parent().unwrap())
        .await
        .unwrap();
    let document = PersistedWifiRecordDocument {
        schema_version: CURRENT_WIFI_RECORD_SCHEMA,
        kind: Some(WifiProcessKind::AccessPoint),
        interface: Some("wlan0".into()),
        pid: foreign.pid,
        started_at_unix: foreign.started_at_unix,
        process_start_ticks: foreign.process_start_ticks,
        boot_id: foreign.boot_id.clone(),
        binary_path: foreign.binary_path.clone(),
        ctrl_path: foreign.ctrl_path.clone(),
        ctrl_dev: foreign.ctrl_dev,
        ctrl_ino: foreign.ctrl_ino,
        config_path: foreign.config_path.clone(),
        config_digest: foreign.config_digest,
        key_digest: foreign.key_digest,
        ssid: foreign.ssid.clone(),
    };
    tokio::fs::write(store.path(), serde_json::to_vec(&document).unwrap())
        .await
        .unwrap();
    assert!(matches!(
        store.load().await,
        Err(WifiRecordError::MismatchedContext(_))
    ));
}

#[tokio::test]
async fn primary_record_rejects_wrong_namespace_fields_before_recovery() {
    let directory = tempdir().expect("tempdir");
    let store = WifiRecordStore::for_access_point(directory.path(), ap_runtime(), "wlan0");
    store.save(&record(42)).await.expect("save");
    for (field, value) in [
        ("interface", serde_json::json!("wlan1")),
        ("kind", serde_json::json!("client")),
        (
            "config_path",
            serde_json::json!("/run/traffic-masq/hostapd/wlan1.conf"),
        ),
        (
            "ctrl_path",
            serde_json::json!("/run/traffic-masq/hostapd/wlan1"),
        ),
    ] {
        let original = serde_json::to_value(PersistedWifiRecordDocument {
            schema_version: CURRENT_WIFI_RECORD_SCHEMA,
            kind: Some(WifiProcessKind::AccessPoint),
            interface: Some("wlan0".into()),
            pid: 42,
            started_at_unix: 1_700_000_000,
            process_start_ticks: None,
            boot_id: None,
            binary_path: Some(PathBuf::from("/usr/sbin/hostapd")),
            ctrl_path: PathBuf::from("/run/traffic-masq/hostapd/wlan0"),
            ctrl_dev: None,
            ctrl_ino: None,
            config_path: PathBuf::from("/run/traffic-masq/hostapd/wlan0.conf"),
            config_digest: digest(1),
            key_digest: digest(2),
            ssid: "traffic-masq".into(),
        })
        .unwrap();
        let mut corrupted = original;
        corrupted[field] = value;
        tokio::fs::write(store.path(), serde_json::to_vec(&corrupted).unwrap())
            .await
            .unwrap();
        assert!(
            matches!(
                store.load().await,
                Err(WifiRecordError::MismatchedContext(_))
            ),
            "field {field}"
        );
    }
}
