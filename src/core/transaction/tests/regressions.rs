//! Regression coverage for confirmation deadlines and recovery ownership.
//! Cancellation tests target the manager directly: ControlService already shields
//! accepted mutations from HTTP caller cancellation.

use super::*;

const WINDOW: Duration = Duration::from_millis(100);
const WATCHDOG: Duration = Duration::from_secs(2);

async fn apply_candidate(manager: &NetworkTransactionManager) -> PendingNetworkChange {
    manager
        .apply(
            "test0",
            InterfaceChange {
                config: &interface_config(PROPOSED),
                previous: None,
                current_role: Some(InterfaceRole::Output),
                passphrase: WifiPassphraseUpdate::Keep,
                allow_management_change: false,
            },
        )
        .await
        .expect("candidate must apply before exercising the failure")
}

async fn wait_for_proposal(desired: &DesiredNetworkState) {
    tokio::time::timeout(WATCHDOG, async {
        while !desired.is_tentative("test0").await {
            desired.changed().await;
        }
    })
    .await
    .expect("apply must publish its proposal");
}

fn manager_for(
    desired: &DesiredNetworkState,
    provider: Arc<FakeNetwork>,
) -> NetworkTransactionManager {
    NetworkTransactionManager::new(
        InterfaceManager::new(provider, AddressOwnershipJournal::in_memory()),
        WINDOW,
        desired.clone(),
    )
}

#[tokio::test]
async fn regression_expired_rollback_must_not_wait_for_unrelated_admission() {
    let directory = tempdir().unwrap();
    let desired = desired_state(directory.path()).await;
    let provider = fake_network();
    let manager = manager_for(&desired, provider.clone());
    let gate = Arc::new(NetworkMutationGate::default());
    manager.set_runtime_gate(gate.clone());
    let converger = spawn_converger(desired.clone(), provider.clone());
    let pending = apply_candidate(&manager).await;
    assert!(addresses(&provider)
        .await
        .contains(&Ipv4Addr::new(192, 168, 50, 1)));

    // Another request is waiting for convergence. It holds admission, but the
    // runtime execution lock is free, so compensation could safely progress.
    let admission = gate.admit().await;
    let recovered = tokio::time::timeout(WATCHDOG, async {
        while manager
            .inner
            .pending
            .lock()
            .await
            .contains_key(&pending.token)
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let remaining_addresses = addresses(&provider).await;
    drop(admission);
    converger.abort();

    assert!(recovered.is_ok(), "expired candidate stayed active for 2s because an unrelated operation held admission (confirmation window: 100ms)");
    assert!(!remaining_addresses.contains(&Ipv4Addr::new(192, 168, 50, 1)));
}

#[tokio::test]
async fn regression_commit_queued_before_expiry_must_recheck_deadline_at_execution() {
    let directory = tempdir().unwrap();
    let desired = desired_state(directory.path()).await;
    let provider = fake_network();
    let manager = manager_for(&desired, provider.clone());
    let gate = Arc::new(NetworkMutationGate::default());
    manager.set_runtime_gate(gate.clone());
    let converger = spawn_converger(desired.clone(), provider);
    let pending = apply_candidate(&manager).await;
    let admission = gate.admit().await;

    // Poll explicitly to establish FIFO ordering without a scheduling sleep:
    // commit queues on admission before the rollback timer does.
    let mut commit = Box::pin(async {
        let _admission = gate.admit().await;
        manager.commit(&pending.token).await
    });
    std::future::poll_fn(|cx| {
        use std::future::Future;
        assert!(commit.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    tokio::time::sleep(WINDOW * 3).await;
    drop(admission);
    let result = tokio::time::timeout(WATCHDOG, commit).await.unwrap();
    let committed = desired.committed_interface("test0").await.unwrap();
    converger.abort();

    assert!(result.is_err(), "commit queued before expiry persisted the candidate after the confirmation deadline: {result:?}");
    assert_eq!(committed, Some(interface_config(COMMITTED)));
}

#[tokio::test]
async fn regression_cancel_between_apply_guard_and_pending_must_keep_recovery_visible() {
    let directory = tempdir().unwrap();
    let desired = desired_state(directory.path()).await;
    desired.attach_converger();
    let provider = fake_network();
    let manager = manager_for(&desired, provider.clone());
    let worker = manager.clone();
    let applying = tokio::spawn(async move { apply_candidate(&worker).await });
    wait_for_proposal(&desired).await;

    // Block precisely the handoff into pending, then acknowledge convergence.
    // No production hooks or changes to the implementation are necessary.
    let pending_lock = manager.inner.pending.lock().await;
    InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory())
        .apply_interface(
            "test0",
            &interface_config(PROPOSED),
            Some(InterfaceRole::Output),
            false,
        )
        .await
        .unwrap();
    desired.report_pass(desired.version(), BTreeMap::new());
    let path = manager.journal_path("test0");
    tokio::time::timeout(WATCHDOG, async {
        while recovery_control::progress(&path).is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("apply guard must finish before the blocked pending insertion");
    assert!(!applying.is_finished());
    applying.abort();
    assert!(applying.await.unwrap_err().is_cancelled());
    drop(pending_lock);

    assert!(path.exists(), "original snapshot still needs recovery");
    assert!(desired.is_tentative("test0").await);
    assert!(addresses(&provider)
        .await
        .contains(&Ipv4Addr::new(192, 168, 50, 1)));
    let visible = manager.pending().await;
    assert_eq!(visible.len(), 1, "cancelled apply left a journal and tentative intent, but status exposes no token and no rollback timer owns it");
    assert!(!visible[0].can_commit());
}

#[tokio::test]
async fn regression_cancel_during_apply_must_eventually_compensate_without_operator() {
    let directory = tempdir().unwrap();
    let desired = desired_state(directory.path()).await;
    desired.attach_converger();
    let provider = fake_network();
    let manager = manager_for(&desired, provider.clone());
    let worker = manager.clone();
    let applying = tokio::spawn(async move { apply_candidate(&worker).await });
    wait_for_proposal(&desired).await;

    // Execute the requested network mutation, but interrupt before its success
    // is reported. This models loss of the operation task, not an HTTP client.
    // Keep the same ownership journal when the worker resumes, as the daemon
    // does; another empty journal cannot authorize removing these addresses.
    let interfaces = InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory());
    interfaces
        .apply_interface(
            "test0",
            &interface_config(PROPOSED),
            Some(InterfaceRole::Output),
            false,
        )
        .await
        .unwrap();
    applying.abort();
    assert!(applying.await.unwrap_err().is_cancelled());
    assert!(addresses(&provider)
        .await
        .contains(&Ipv4Addr::new(192, 168, 50, 1)));
    let converger = spawn_converger_with_interfaces(desired.clone(), interfaces);

    let recovered = tokio::time::timeout(WATCHDOG, async {
        // Publishing restoration removes the proposal but is not completion.
        // Wait for the restoration to be verified and withdrawn as well.
        while desired.has_pending().await {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let visible = manager.pending().await;
    converger.abort();
    assert!(recovered.is_ok(), "an interrupted unconfirmed network mutation requires an operator indefinitely despite a healthy converger: {visible:?}");
    assert!(!addresses(&provider)
        .await
        .contains(&Ipv4Addr::new(192, 168, 50, 1)));
}

#[tokio::test]
async fn regression_uncertain_security_write_must_not_disable_network_compensation() {
    let directory = tempdir().unwrap();
    let mut base = AppConfig::default();
    base.network
        .interfaces
        .insert("test0".into(), interface_config(COMMITTED));
    let overrides = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    // Ensure compensation replaces an existing document, exercising both faults.
    overrides
        .set_security_config(base.security.clone())
        .await
        .unwrap();
    let desired = DesiredNetworkState::new(base.clone(), overrides.clone());
    let provider = fake_network();
    let manager = manager_for(&desired, provider.clone());
    let converger = spawn_converger(desired.clone(), provider);
    let pending = apply_candidate(&manager).await;
    let network_before = overrides.snapshot().await;

    crate::atomic_file::fail_replacement_and_compensation(overrides.path());
    let error = overrides.clear_security_config().await.unwrap_err();
    assert!(crate::atomic_file::is_indeterminate_write(&error));
    let published: crate::state::overrides::RuntimeOverrides =
        serde_json::from_slice(&tokio::fs::read(overrides.path()).await.unwrap()).unwrap();
    assert!(network_before.security.is_some());
    assert!(published.security.is_none());
    assert_eq!(published.interfaces, network_before.interfaces);
    assert_eq!(
        published.committed_interface_transactions,
        network_before.committed_interface_transactions
    );
    assert!(crate::core::recovery::check_persistence(directory.path()).is_err());
    assert!(crate::core::recovery::check_commit(directory.path()).is_ok());
    let document = tokio::fs::read(overrides.path()).await.unwrap();
    assert!(overrides.clear_security_config().await.is_err());
    assert_eq!(tokio::fs::read(overrides.path()).await.unwrap(), document);
    // Neither possible outcome of this settings-only write commits the network
    // candidate. A future fix must establish that proof, not ignore the fence.
    let rollback = manager.rollback(&pending.token).await;
    converger.abort();
    assert!(rollback.is_ok(), "settings-only persistence uncertainty disabled compensation of an independently uncommitted network change: {rollback:?}");
    assert!(!desired.is_tentative("test0").await);
}

#[tokio::test]
async fn commit_started_before_deadline_may_finish_persistence_after_it() {
    let directory = tempdir().unwrap();
    let desired = desired_state(directory.path()).await;
    let manager = manager_for(&desired, fake_network());
    let pending = apply_candidate(&manager).await;
    manager
        .commit_with(&pending.token, |interface, config, allow| {
            let desired = desired.clone();
            let token = pending.token.clone();
            async move {
                tokio::time::sleep(WINDOW * 3).await;
                desired
                    .commit_interface(&token, interface, config, allow)
                    .await
            }
        })
        .await
        .unwrap();
    assert_eq!(
        desired.committed_interface("test0").await.unwrap(),
        Some(interface_config(PROPOSED))
    );
    assert!(manager.pending().await.is_empty());
}

#[tokio::test]
async fn cancelled_credential_write_retains_lane_until_compensation_can_restore_secret() {
    let directory = tempdir().unwrap();
    let desired = desired_state(directory.path()).await;
    let manager = manager_for(&desired, fake_network());
    let store = PassphraseStore::for_role(directory.path(), WifiCredentialRole::Ap);
    store
        .set("test0", &WifiPassphrase::new("original-password").unwrap())
        .unwrap();
    let path = directory.path().join("wifi/psk-ap/test0");
    let (entered, release) = crate::atomic_file::pause_next_replacement(&path);
    let worker = manager.clone();
    let applying = tokio::spawn(async move {
        worker
            .apply(
                "test0",
                InterfaceChange {
                    config: &credential_config(WifiCredentialRole::Ap),
                    previous: Some(&interface_config(COMMITTED)),
                    current_role: Some(InterfaceRole::Output),
                    passphrase: WifiPassphraseUpdate::Set(
                        WifiPassphrase::new("replacement-password").unwrap(),
                    ),
                    allow_management_change: false,
                },
            )
            .await
    });
    tokio::task::spawn_blocking(move || entered.recv_timeout(WATCHDOG).unwrap())
        .await
        .unwrap();
    applying.abort();
    assert!(applying.await.unwrap_err().is_cancelled());
    assert!(
        desired.runtime_locks.try_lock("test0").await.is_none(),
        "cancelled await must not release the lane while storage is writing"
    );
    release.send(()).unwrap();
    tokio::time::timeout(WATCHDOG, async {
        while !manager.pending().await.is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        store.get("test0").unwrap().unwrap().expose(),
        "original-password"
    );
    assert!(!desired.has_pending().await);
    assert!(!manager.journal_path("test0").exists());
}
