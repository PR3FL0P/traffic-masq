use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use tempfile::tempdir;

use super::*;

fn proof(seed: u8) -> String {
    BASE64.encode([seed; 32])
}

#[tokio::test]
async fn missing_file_loads_as_none() {
    let directory = tempdir().expect("tempdir");
    let store = ActiveProfileStore::new(directory.path().join("active-profile.json"));

    assert_eq!(store.load().await.expect("load"), None);
}

#[tokio::test]
async fn save_then_load_round_trips() {
    let directory = tempdir().expect("tempdir");
    let store = ActiveProfileStore::new(directory.path().join("active-profile.json"));
    let record = PersistedActiveProfile {
        profile_name: "home.conf".to_string(),
        interface: "tm-wg0".to_string(),
        ownership_proof_base64: proof(7),
    };

    store.save(&record).await.expect("save");
    let loaded = store.load().await.expect("load").expect("record present");

    assert_eq!(loaded, record);
}

#[tokio::test]
async fn save_overwrites_previous_record() {
    let directory = tempdir().expect("tempdir");
    let store = ActiveProfileStore::new(directory.path().join("active-profile.json"));
    store
        .save(&PersistedActiveProfile {
            profile_name: "home.conf".to_string(),
            interface: "tm-wg0".to_string(),
            ownership_proof_base64: proof(1),
        })
        .await
        .expect("save first");
    store
        .save(&PersistedActiveProfile {
            profile_name: "office.conf".to_string(),
            interface: "tm-wg0".to_string(),
            ownership_proof_base64: proof(2),
        })
        .await
        .expect("save second");

    let loaded = store.load().await.expect("load").expect("record present");
    assert_eq!(loaded.profile_name, "office.conf");
    assert_eq!(loaded.ownership_proof_base64, proof(2));
}

#[tokio::test]
async fn clear_removes_record_and_is_idempotent() {
    let directory = tempdir().expect("tempdir");
    let store = ActiveProfileStore::new(directory.path().join("active-profile.json"));
    store
        .save(&PersistedActiveProfile {
            profile_name: "home.conf".to_string(),
            interface: "tm-wg0".to_string(),
            ownership_proof_base64: proof(3),
        })
        .await
        .expect("save");

    store.clear().await.expect("clear");
    assert_eq!(store.load().await.expect("load"), None);

    store.clear().await.expect("clear again");
}

#[tokio::test]
async fn rejects_unsupported_schema_version() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("active-profile.json");
    tokio::fs::write(
        &path,
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 99,
            "profile_name": "home.conf",
            "interface": "tm-wg0",
            "ownership_proof_base64": proof(4),
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    let store = ActiveProfileStore::new(path);

    let error = store.load().await.expect_err("unsupported schema");
    assert!(matches!(
        error,
        ActiveProfileError::UnsupportedSchema(_, 99)
    ));
}

#[tokio::test]
async fn activation_intent_round_trips_and_uses_separate_file() {
    let directory = tempdir().expect("tempdir");
    let active = ActiveProfileStore::new(directory.path().join("active-profile.json"));
    let store = ActivationIntentStore::for_active_profile(&active);
    let intent = PersistedActivationIntent {
        profile_name: "home.conf".to_string(),
        interface: "tm-wg0".to_string(),
        launch_marker: "traffic-masq:vpn:test".to_string(),
    };

    assert_eq!(
        store.path(),
        directory.path().join("active-profile.intent.json")
    );
    store.save(&intent).await.expect("save intent");
    assert_eq!(store.load().await.expect("load intent"), Some(intent));
    assert_eq!(active.load().await.expect("load active"), None);

    store.clear().await.expect("clear intent");
    assert_eq!(store.load().await.expect("load cleared intent"), None);
}
