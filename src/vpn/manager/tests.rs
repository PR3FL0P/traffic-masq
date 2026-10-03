use tempfile::tempdir;

use super::*;
use crate::test_support::{fake_vpn_public_key, FakeVpnProvider};
use crate::vpn::store::WireGuardProfileStore;
use crate::vpn::wireguard::{WireGuardKey, WireGuardVpnDriver};
use crate::vpn::VpnProvider;

const VALID_PRIVATE_KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
const VALID_PUBLIC_KEY: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
const OTHER_PRIVATE_KEY: &str = "SBmoW+ojuoJZeh6P/2sh8aetgAy4dTZTAO8UzHzKtGY=";

fn valid_config(private_key: &str) -> String {
    format!(
        "[Interface]\n\
         PrivateKey = {private_key}\n\
         Address = 10.0.0.2/24\n\
         \n\
         [Peer]\n\
         PublicKey = {VALID_PUBLIC_KEY}\n\
         AllowedIPs = 0.0.0.0/0\n\
         Endpoint = 203.0.113.1:51820\n"
    )
}

type TestManager = VpnManager<WireGuardVpnDriver>;

fn encode_proof(key: &WireGuardKey) -> String {
    BASE64.encode(key.0)
}

fn fake_provider() -> (
    std::sync::Arc<dyn VpnProvider>,
    std::sync::Arc<FakeVpnProvider>,
) {
    let fake = std::sync::Arc::new(FakeVpnProvider::default());
    let erased: std::sync::Arc<dyn VpnProvider> = fake.clone();
    (erased, fake)
}

fn manager_with_store() -> (
    TestManager,
    std::sync::Arc<FakeVpnProvider>,
    tempfile::TempDir,
) {
    let dir = tempdir().expect("tempdir");
    let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
    let active_profile_store = ActiveProfileStore::new(dir.path().join("active-profile.json"));
    let (provider, fake) = fake_provider();
    let driver = WireGuardVpnDriver::new(provider, store);
    let manager = VpnManager::new(driver, active_profile_store);
    (manager, fake, dir)
}

#[tokio::test]
async fn activate_deactivate_round_trip_succeeds() {
    let (manager, fake, _dir) = manager_with_store();
    manager
        .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
        .expect("import");

    manager.activate("home.conf").await.expect("activate");
    assert_eq!(
        manager
            .activation_intent_store
            .load()
            .await
            .expect("load activation intent"),
        None,
        "successful activation must clean its write-ahead intent"
    );

    let active = manager.active().expect("should be active");
    assert_eq!(active.interface, OWNED_INTERFACE_NAME);
    assert_eq!(active.profile_name, "home.conf");

    assert!(fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
    assert!(fake.is_up(OWNED_INTERFACE_NAME).await.unwrap());

    manager.deactivate().await.expect("deactivate");
    assert!(manager.active().is_none());
    assert!(!fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
}

#[tokio::test]
async fn delete_refuses_profile_used_by_an_active_owned_interface() {
    let (manager, _fake, _dir) = manager_with_store();
    manager
        .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
        .expect("import");
    manager.activate("home.conf").await.expect("activate");

    let error = manager
        .delete_profile("home.conf")
        .expect_err("active profile must not be deleted");
    assert!(matches!(error, ManagerError::ProfileInUse(name) if name == "home.conf"));
    assert_eq!(manager.list_profiles().expect("profiles").len(), 1);
}

#[tokio::test]
async fn import_refuses_to_overwrite_profile_used_by_an_active_owned_interface() {
    let (manager, _fake, _dir) = manager_with_store();
    manager
        .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
        .expect("import");
    manager.activate("home.conf").await.expect("activate");

    let error = manager
        .import_profile("home.conf", valid_config(OTHER_PRIVATE_KEY).as_bytes())
        .expect_err("active profile must not be overwritten");
    assert!(matches!(error, ManagerError::ProfileInUse(name) if name == "home.conf"));
}

#[tokio::test]
async fn activation_rejects_conflict_with_existing_foreign_interface() {
    let (manager, fake, _dir) = manager_with_store();
    manager
        .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
        .expect("import");

    fake.seed_foreign_link(OWNED_INTERFACE_NAME, OTHER_PRIVATE_KEY);

    let error = manager.activate("home.conf").await.unwrap_err();
    assert!(matches!(error, ManagerError::ForeignInterfaceConflict(_)));

    assert!(fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
    assert!(manager.active().is_none());
}

#[tokio::test]
async fn activation_rejects_conflict_when_already_active() {
    let (manager, _fake, _dir) = manager_with_store();
    manager
        .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
        .expect("import");
    manager.activate("home.conf").await.expect("activate");

    let error = manager.activate("home.conf").await.unwrap_err();
    assert!(matches!(error, ManagerError::AlreadyActive));
}

#[tokio::test]
async fn two_different_hop_interfaces_can_be_activated_concurrently() {
    let (manager, fake, _dir) = manager_with_store();
    manager
        .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
        .expect("import");

    let hop0 = hop_interface_name(0);
    let hop1 = hop_interface_name(1);
    assert_ne!(hop0, hop1);

    manager
        .activate_on(&hop0, "home.conf")
        .await
        .expect("hop 0 activates");
    manager
        .activate_on(&hop1, "home.conf")
        .await
        .expect("a second, differently-named hop activates while hop 0 is still active");

    assert!(manager.active_on(&hop0).is_some());
    assert!(manager.active_on(&hop1).is_some());
    assert_eq!(manager.active_interfaces().len(), 2);
    assert!(fake.link_exists(&hop0).await.unwrap());
    assert!(fake.link_exists(&hop1).await.unwrap());

    // Re-activating an already-active hop by name is still rejected.
    let error = manager.activate_on(&hop0, "home.conf").await.unwrap_err();
    assert!(matches!(error, ManagerError::AlreadyActive));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_activate_calls_never_race_into_a_foreign_interface_conflict() {
    let (manager, fake, _dir) = manager_with_store();
    let manager = std::sync::Arc::new(manager);
    manager
        .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
        .expect("import");

    let manager_a = manager.clone();
    let manager_b = manager.clone();
    let (result_a, result_b) = tokio::join!(
        tokio::spawn(async move { manager_a.activate("home.conf").await }),
        tokio::spawn(async move { manager_b.activate("home.conf").await }),
    );
    let result_a = result_a.expect("task a panicked");
    let result_b = result_b.expect("task b panicked");

    let outcomes = [&result_a, &result_b];
    let successes = outcomes.iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        successes, 1,
        "exactly one of two concurrent activate calls must succeed, got {result_a:?} / {result_b:?}"
    );
    let loser = outcomes
        .into_iter()
        .find(|r| r.is_err())
        .expect("one call must have failed");
    assert!(
        matches!(loser, Err(ManagerError::AlreadyActive)),
        "the losing concurrent activate call must see AlreadyActive, not a spurious \
         ForeignInterfaceConflict for an interface this manager itself is creating: {loser:?}"
    );

    let active = manager.active().expect("manager should be active");
    assert_eq!(active.interface, OWNED_INTERFACE_NAME);
    assert!(fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconcile_waits_for_in_flight_activation_before_rolling_back_intent() {
    use tokio::time::{timeout, Duration};

    let (manager, fake, _dir) = manager_with_store();
    let manager = std::sync::Arc::new(manager);
    let marker = "traffic-masq:vpn:in-flight";

    // Model the exact crash-journal state visible after create_link but
    // before the active-profile commit, while an activation still owns the
    // mutation lock. Reconcile must not treat this as abandoned state until
    // that activation is no longer in flight.
    let guard = manager.activation_lock.lock().await;
    manager
        .activation_intent_store
        .save(&PersistedActivationIntent {
            profile_name: "home.conf".to_string(),
            interface: OWNED_INTERFACE_NAME.to_string(),
            launch_marker: marker.to_string(),
        })
        .await
        .expect("save intent");
    fake.create_link(
        OWNED_INTERFACE_NAME,
        &WireGuardKey::parse(VALID_PRIVATE_KEY, "test").unwrap(),
        None,
        marker,
    )
    .await
    .expect("create pending link");

    let reconcile_manager = manager.clone();
    let mut reconcile = tokio::spawn(async move { reconcile_manager.reconcile().await });

    assert!(
        timeout(Duration::from_millis(50), &mut reconcile)
            .await
            .is_err(),
        "reconcile must wait while activation owns the mutation lock"
    );
    assert!(
        fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap(),
        "reconcile must not delete an interface belonging to an in-flight activation"
    );

    drop(guard);
    let outcome = reconcile.await.expect("reconcile task").expect("reconcile");
    assert_eq!(outcome, ReconcileOutcome::Absent);
    assert!(!fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
}

#[tokio::test]
async fn deactivate_refuses_to_touch_foreign_interface_that_replaced_owned_one() {
    let (manager, fake, _dir) = manager_with_store();
    manager
        .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
        .expect("import");
    manager.activate("home.conf").await.expect("activate");

    fake.delete_link(OWNED_INTERFACE_NAME).await.unwrap();
    fake.seed_foreign_link(OWNED_INTERFACE_NAME, OTHER_PRIVATE_KEY);

    let error = manager.deactivate().await.unwrap_err();
    assert!(matches!(error, ManagerError::OwnershipProofFailed(_)));

    assert!(fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
}

#[tokio::test]
async fn rollback_after_failed_activation_removes_only_owned_interface() {
    let (manager, fake, _dir) = manager_with_store();

    manager
        .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
        .expect("import");

    let snapshot = manager.snapshot().await.expect("snapshot");
    assert!(!snapshot.existed_before);

    fake.create_link(
        OWNED_INTERFACE_NAME,
        &WireGuardKey::parse(VALID_PRIVATE_KEY, "test").unwrap(),
        None,
        "test-launch-marker",
    )
    .await
    .unwrap();
    let ownership_proof = fake
        .public_key(OWNED_INTERFACE_NAME)
        .await
        .unwrap()
        .unwrap();
    manager.owned.lock().unwrap().insert(
        OWNED_INTERFACE_NAME.to_string(),
        OwnedInterfaceRecord {
            interface: OWNED_INTERFACE_NAME.to_string(),
            ownership_proof,
            profile_name: "home.conf".to_string(),
        },
    );

    manager.rollback(&snapshot).await.expect("rollback");

    assert!(manager.active().is_none());
    assert!(!fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
}

#[tokio::test]
async fn rollback_never_removes_a_preexisting_foreign_interface() {
    let (manager, fake, _dir) = manager_with_store();

    fake.seed_foreign_link(OWNED_INTERFACE_NAME, OTHER_PRIVATE_KEY);

    let snapshot = VpnInterfaceSnapshot {
        interface: OWNED_INTERFACE_NAME.to_string(),
        existed_before: true,
        ownership_proof: fake.public_key(OWNED_INTERFACE_NAME).await.unwrap(),
        was_up: true,
    };

    manager.rollback(&snapshot).await.expect("rollback no-op");

    assert!(fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
}

#[tokio::test]
async fn reconcile_is_noop_when_no_interface_exists() {
    let (manager, _fake, _dir) = manager_with_store();

    let outcome = manager.reconcile().await.expect("reconcile");

    assert_eq!(outcome, ReconcileOutcome::Absent);
    assert!(manager.active().is_none());
}

#[tokio::test]
async fn reconcile_clears_intent_when_crash_preceded_link_creation() {
    let dir = tempdir().expect("tempdir");
    let active_profile_store = ActiveProfileStore::new(dir.path().join("active-profile.json"));
    let intent_store = ActivationIntentStore::for_active_profile(&active_profile_store);
    intent_store
        .save(&PersistedActivationIntent {
            profile_name: "home.conf".to_string(),
            interface: OWNED_INTERFACE_NAME.to_string(),
            launch_marker: "traffic-masq:vpn:pre-create".to_string(),
        })
        .await
        .expect("persist activation intent");

    let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
    let (provider, fake) = fake_provider();
    let driver = WireGuardVpnDriver::new(provider, store);
    let manager = VpnManager::new(driver, active_profile_store);

    let outcome = manager.reconcile().await.expect("reconcile");

    assert_eq!(outcome, ReconcileOutcome::Absent);
    assert!(!fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
    assert_eq!(intent_store.load().await.expect("load intent"), None);
}

#[tokio::test]
async fn reconcile_rolls_back_matching_uncommitted_activation_intent() {
    let dir = tempdir().expect("tempdir");
    let active_profile_store = ActiveProfileStore::new(dir.path().join("active-profile.json"));
    let intent_store = ActivationIntentStore::for_active_profile(&active_profile_store);
    let marker = "traffic-masq:vpn:pending-test";
    intent_store
        .save(&PersistedActivationIntent {
            profile_name: "home.conf".to_string(),
            interface: OWNED_INTERFACE_NAME.to_string(),
            launch_marker: marker.to_string(),
        })
        .await
        .expect("persist activation intent");

    let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
    let (provider, fake) = fake_provider();
    fake.create_link(
        OWNED_INTERFACE_NAME,
        &WireGuardKey::parse(VALID_PRIVATE_KEY, "test").unwrap(),
        None,
        marker,
    )
    .await
    .expect("seed interrupted activation");
    let driver = WireGuardVpnDriver::new(provider, store);
    let manager = VpnManager::new(driver, active_profile_store);

    let outcome = manager.reconcile().await.expect("reconcile");

    assert_eq!(outcome, ReconcileOutcome::Absent);
    assert!(!fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
    assert_eq!(intent_store.load().await.expect("load intent"), None);
}

#[tokio::test]
async fn reconcile_never_deletes_interface_when_activation_marker_mismatches() {
    let dir = tempdir().expect("tempdir");
    let active_profile_store = ActiveProfileStore::new(dir.path().join("active-profile.json"));
    let intent_store = ActivationIntentStore::for_active_profile(&active_profile_store);
    intent_store
        .save(&PersistedActivationIntent {
            profile_name: "home.conf".to_string(),
            interface: OWNED_INTERFACE_NAME.to_string(),
            launch_marker: "traffic-masq:vpn:ours".to_string(),
        })
        .await
        .expect("persist activation intent");

    let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
    let (provider, fake) = fake_provider();
    fake.seed_foreign_link(OWNED_INTERFACE_NAME, OTHER_PRIVATE_KEY);
    let driver = WireGuardVpnDriver::new(provider, store);
    let manager = VpnManager::new(driver, active_profile_store);

    let outcome = manager.reconcile().await.expect("reconcile");

    assert_eq!(outcome, ReconcileOutcome::ForeignInterfacePresent);
    assert!(fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
    assert!(intent_store.load().await.expect("load intent").is_some());
}

#[tokio::test]
async fn reconcile_prefers_committed_active_record_over_stale_activation_intent() {
    let dir = tempdir().expect("tempdir");
    let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
    let active_profile_store = ActiveProfileStore::new(dir.path().join("active-profile.json"));
    let intent_store = ActivationIntentStore::for_active_profile(&active_profile_store);
    let (provider, fake) = fake_provider();
    let driver = WireGuardVpnDriver::new(provider, store);
    let manager = VpnManager::new(driver, active_profile_store.clone());
    manager
        .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
        .expect("import");
    manager.activate("home.conf").await.expect("activate");
    let original = manager.active().expect("active");
    let marker = fake
        .launch_marker_for(OWNED_INTERFACE_NAME)
        .expect("marker");
    intent_store
        .save(&PersistedActivationIntent {
            profile_name: "home.conf".to_string(),
            interface: OWNED_INTERFACE_NAME.to_string(),
            launch_marker: marker,
        })
        .await
        .expect("recreate stale intent");

    let restarted_store = WireGuardProfileStore::new(dir.path().join("wireguard"));
    let same_provider: std::sync::Arc<dyn VpnProvider> = fake.clone();
    let restarted_driver = WireGuardVpnDriver::new(same_provider, restarted_store);
    let restarted = VpnManager::new(restarted_driver, active_profile_store);

    let outcome = restarted.reconcile().await.expect("reconcile");

    assert_eq!(outcome, ReconcileOutcome::Adopted(original));
    assert!(fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
    assert_eq!(intent_store.load().await.expect("load intent"), None);
}

#[tokio::test]
async fn reconcile_reports_foreign_interface_under_owned_name_without_adopting_it() {
    let (manager, fake, _dir) = manager_with_store();
    fake.seed_foreign_link(OWNED_INTERFACE_NAME, OTHER_PRIVATE_KEY);

    let outcome = manager.reconcile().await.expect("reconcile");

    assert_eq!(outcome, ReconcileOutcome::ForeignInterfacePresent);

    assert!(manager.active().is_none());
    assert!(fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
}

#[tokio::test]
async fn reconcile_after_restart_still_refuses_to_adopt_own_previous_interface() {
    let (manager, fake, _dir) = manager_with_store();
    manager
        .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
        .expect("import");
    manager.activate("home.conf").await.expect("activate");

    let dir2 = tempdir().expect("tempdir");

    let fresh_store = WireGuardProfileStore::new(dir2.path().join("wireguard"));
    let fresh_active_profile_store =
        ActiveProfileStore::new(dir2.path().join("active-profile.json"));
    let same_provider: std::sync::Arc<dyn VpnProvider> = fake.clone();
    let fresh_driver = WireGuardVpnDriver::new(same_provider, fresh_store);
    let fresh_manager = VpnManager::new(fresh_driver, fresh_active_profile_store);

    let outcome = fresh_manager.reconcile().await.expect("reconcile");

    assert_eq!(outcome, ReconcileOutcome::ForeignInterfacePresent);
    assert!(fresh_manager.active().is_none());
}

#[tokio::test]
async fn reconcile_adopts_after_restart_when_persisted_record_matches_kernel_state() {
    let dir = tempdir().expect("tempdir");
    let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
    let active_profile_store = ActiveProfileStore::new(dir.path().join("active-profile.json"));
    let (provider, fake) = fake_provider();
    let driver = WireGuardVpnDriver::new(provider, store);
    let manager = VpnManager::new(driver, active_profile_store.clone());
    manager
        .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
        .expect("import");
    manager.activate("home.conf").await.expect("activate");
    let original_record = manager.active().expect("active after activate");

    let restarted_store = WireGuardProfileStore::new(dir.path().join("wireguard"));
    let same_provider: std::sync::Arc<dyn VpnProvider> = fake.clone();
    let restarted_driver = WireGuardVpnDriver::new(same_provider, restarted_store);
    let restarted = VpnManager::new(restarted_driver, active_profile_store);
    assert!(restarted.active().is_none());

    let outcome = restarted.reconcile().await.expect("reconcile");

    assert_eq!(outcome, ReconcileOutcome::Adopted(original_record.clone()));
    assert_eq!(restarted.active(), Some(original_record));
}

#[tokio::test]
async fn reconcile_refuses_to_adopt_when_persisted_key_mismatches_kernel_state() {
    let dir = tempdir().expect("tempdir");
    let active_profile_store = ActiveProfileStore::new(dir.path().join("active-profile.json"));
    active_profile_store
        .save(&PersistedActiveProfile {
            profile_name: "home.conf".to_string(),
            interface: OWNED_INTERFACE_NAME.to_string(),
            ownership_proof_base64: encode_proof(
                &WireGuardKey::parse(VALID_PUBLIC_KEY, "test").unwrap(),
            ),
        })
        .await
        .expect("save persisted record");

    let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
    let (provider, fake) = fake_provider();
    let driver = WireGuardVpnDriver::new(provider, store);
    let manager = VpnManager::new(driver, active_profile_store);
    fake.seed_foreign_link(OWNED_INTERFACE_NAME, OTHER_PRIVATE_KEY);

    let outcome = manager.reconcile().await.expect("reconcile");

    assert_eq!(outcome, ReconcileOutcome::ForeignInterfacePresent);
    assert!(manager.active().is_none());
    assert!(fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
}

#[tokio::test]
async fn deactivate_clears_persisted_active_profile_record() {
    let dir = tempdir().expect("tempdir");
    let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
    let active_profile_store = ActiveProfileStore::new(dir.path().join("active-profile.json"));
    let (provider, _fake) = fake_provider();
    let driver = WireGuardVpnDriver::new(provider, store);
    let manager = VpnManager::new(driver, active_profile_store.clone());
    manager
        .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
        .expect("import");
    manager.activate("home.conf").await.expect("activate");
    assert!(active_profile_store.load().await.expect("load").is_some());

    manager.deactivate().await.expect("deactivate");

    assert_eq!(
        active_profile_store.load().await.expect("load"),
        None,
        "persisted record must be cleared once the owned interface is torn down"
    );
}

#[tokio::test]
async fn shutdown_preserve_policy_leaves_owned_interface_running() {
    let (manager, fake, _dir) = manager_with_store();
    manager
        .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
        .expect("import");
    manager.activate("home.conf").await.expect("activate");

    manager
        .shutdown(ShutdownPolicy::PreserveInterfaces)
        .await
        .expect("shutdown");

    assert!(manager.active().is_some());
    assert!(fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
}

#[tokio::test]
async fn shutdown_restore_policy_tears_down_owned_interface() {
    let (manager, fake, _dir) = manager_with_store();
    manager
        .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
        .expect("import");
    manager.activate("home.conf").await.expect("activate");

    manager
        .shutdown(ShutdownPolicy::RestoreInterfaces)
        .await
        .expect("shutdown");

    assert!(manager.active().is_none());
    assert!(!fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
}

#[tokio::test]
async fn shutdown_is_noop_when_nothing_is_active() {
    let (manager, _fake, _dir) = manager_with_store();

    manager
        .shutdown(ShutdownPolicy::RestoreInterfaces)
        .await
        .expect("shutdown");
    manager
        .shutdown(ShutdownPolicy::PreserveInterfaces)
        .await
        .expect("shutdown");

    assert!(manager.active().is_none());
}

#[test]
fn ownership_record_round_trip_matches_kernel_reported_key() {
    let private_key = WireGuardKey::parse(VALID_PRIVATE_KEY, "test").unwrap();
    let expected_public = fake_vpn_public_key(&private_key);

    let record = OwnedInterfaceRecord {
        interface: OWNED_INTERFACE_NAME.to_string(),
        ownership_proof: expected_public.clone(),
        profile_name: "home.conf".to_string(),
    };

    assert_eq!(record.ownership_proof, expected_public);
    assert_eq!(record.interface, OWNED_INTERFACE_NAME);
}

#[tokio::test]
async fn hostname_profile_activation_applies_mtu_and_remains_cancellable() {
    let (manager, fake, _directory) = manager_with_store();
    let contents = valid_config(VALID_PRIVATE_KEY)
        .replace(
            "Address = 10.0.0.2/24",
            "Address = 10.13.37.172/24\nDNS = 95.215.19.53\nMTU = 1280",
        )
        .replace("203.0.113.1:51820", "localhost:51820");
    manager
        .import_profile("wg0.conf", contents.as_bytes())
        .unwrap();
    manager.activate("wg0.conf").await.unwrap();
    assert_eq!(
        fake.mtus.lock().unwrap().get(OWNED_INTERFACE_NAME).copied(),
        Some(1280)
    );
    manager.deactivate().await.unwrap();
    assert!(!fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
}
