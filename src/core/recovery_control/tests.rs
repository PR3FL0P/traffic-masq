use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

async fn journal() -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("router-transaction.json");
    tokio::fs::write(&path, br#"{"token":"one","snapshot":{}}"#)
        .await
        .unwrap();
    (root, path)
}

/// Model a forward wall-clock correction by aging only the civil deadline.
/// The live monotonic budget and attempt count remain unchanged. This avoids
/// changing the host clock or adding a production clock-injection hook.
#[tokio::test]
async fn regression_wall_clock_jump_must_not_exhaust_live_monotonic_recovery_budget() {
    let state = crate::core::recovery::RecoveryState::default();
    let (_root, path) = journal().await;
    state
        .run::<(), _>(&path, false, async {
            Err(failure(FailureKind::Transient, "temporary netlink failure"))
        })
        .await
        .unwrap_err();
    let monotonic_deadline = state.inner.control.deadlines.lock().unwrap()[&path];
    assert!(monotonic_deadline > tokio::time::Instant::now() + Duration::from_secs(60));

    let mut control = state.inner.control.controls.lock().unwrap()[&path].clone();
    assert_eq!(control.phase, Phase::Ready);
    assert_eq!(control.attempts, 1);
    control.deadline_unix = now().saturating_sub(1);
    state.save(&path, &control).await.unwrap();

    let mutations = AtomicUsize::new(0);
    let result = state
        .run(&path, false, async {
            mutations.fetch_add(1, Ordering::SeqCst);
            state.retire(&path).await
        })
        .await;
    assert!(result.is_ok(), "wall time exhausted a still-live monotonic recovery budget before compensation could execute: {result:?}");
    assert_eq!(mutations.load(Ordering::SeqCst), 1);
    assert!(!path.exists());
}

#[tokio::test]
async fn cancelled_apply_handoff_cannot_clear_storage_or_recovery_failures() {
    let state = crate::core::recovery::RecoveryState::default();
    for kind in [FailureKind::Storage, FailureKind::Unknown] {
        let (_root, path) = journal().await;
        state
            .run::<(), _>(&path, false, async {
                Err(failure(kind, "injected recovery failure"))
            })
            .await
            .unwrap_err();
        let before = tokio::fs::read(control_path(&path)).await.unwrap();
        assert!(state.compensate_cancelled_apply(&path).await.is_err());
        assert_eq!(tokio::fs::read(control_path(&path)).await.unwrap(), before);
        assert_eq!(state.progress(&path).unwrap().attempts, 1);
    }
    let (_root, path) = journal().await;
    state
        .stop(&path, FailureKind::Storage, "failed before first attempt")
        .await
        .unwrap();
    assert!(state.compensate_cancelled_apply(&path).await.is_err());
    assert!(state.stopped(&path));
}

#[test]
fn classification_uses_types_instead_of_error_text() {
    assert_eq!(
        classify(&anyhow::anyhow!("interface not found: fake")),
        FailureKind::Unknown
    );
    assert_eq!(
        classify(
            &anyhow::Error::new(crate::netlink::MissingInterface {
                interface: "wan0".into()
            })
            .context("snapshot failed")
        ),
        FailureKind::DeviceMissing
    );
    assert_eq!(
        classify(&std::io::Error::from(std::io::ErrorKind::Interrupted).into()),
        FailureKind::Transient
    );
    assert_eq!(
        classify(&std::io::Error::from(std::io::ErrorKind::PermissionDenied).into()),
        FailureKind::Storage
    );
    assert_eq!(
        classify(
            &crate::core::route::ForeignRouteConflict {
                destination: "192.0.2.0/24".parse().unwrap(),
                table: 254,
                metric: 0,
                owner: "foreign".into(),
            }
            .into()
        ),
        FailureKind::Conflict
    );
}

#[tokio::test]
async fn missing_device_stops_and_late_arrival_requires_explicit_retry() {
    let state = crate::core::recovery::RecoveryState::default();
    let (_root, path) = journal().await;
    let original = tokio::fs::read(&path).await.unwrap();
    let mutations = AtomicUsize::new(0);
    for attempt in 1..=MAX_ATTEMPTS {
        assert!(state
            .run(&path, false, async {
                mutations.fetch_add(1, Ordering::SeqCst);
                Err::<(), _>(failure(FailureKind::DeviceMissing, "adapter absent"))
            })
            .await
            .is_err());
        assert_eq!(state.progress(&path).unwrap().attempts, attempt);
    }
    assert!(state.stopped(&path));
    assert!(!state.progress(&path).unwrap().automatic_recovery);
    assert!(state
        .run(&path, false, async {
            mutations.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .await
        .is_err());
    assert_eq!(mutations.load(Ordering::SeqCst), MAX_ATTEMPTS as usize);
    assert_eq!(tokio::fs::read(&path).await.unwrap(), original);
    state.forget(&path); // simulate a new process
    assert!(state.restore_stop(&path).await.unwrap());
    state
        .run(&path, true, async {
            mutations.fetch_add(1, Ordering::SeqCst);
            state.retire(&path).await
        })
        .await
        .unwrap();
    assert!(!path.exists());
    assert!(!control_path(&path).exists());
    assert!(!state.stopped(&path));
}

#[tokio::test]
async fn permanent_failure_stops_immediately_and_preserves_snapshot() {
    let state = crate::core::recovery::RecoveryState::default();
    for kind in [
        FailureKind::Conflict,
        FailureKind::Incompatible,
        FailureKind::Storage,
        FailureKind::CommitIndeterminate,
    ] {
        let (_root, path) = journal().await;
        state
            .run::<(), _>(&path, false, async {
                Err(failure(kind, "requires repair"))
            })
            .await
            .unwrap_err();
        assert!(state.stopped(&path));
        assert_eq!(state.progress(&path).unwrap().attempts, 1);
        assert_eq!(state.progress(&path).unwrap().failure_kind, kind);
        state.forget(&path);
        assert!(state.restore_stop(&path).await.unwrap());
        assert!(path.exists());
    }
}

#[tokio::test]
async fn interrupted_attempt_is_fenced_in_process_and_after_restart() {
    let state = crate::core::recovery::RecoveryState::default();
    let (_root, path) = journal().await;
    let worker_path = path.clone();
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let worker_entered = entered.clone();
    let worker_state = state.clone();
    let task = tokio::spawn(async move {
        worker_state
            .run::<(), _>(&worker_path, false, async {
                worker_entered.notify_one();
                std::future::pending().await
            })
            .await
    });
    entered.notified().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(state.stopped(&path));
    state.forget(&path);
    assert!(state.restore_stop(&path).await.unwrap());
    assert!(state
        .run(&path, false, async {
            panic!("interrupted attempt cannot resume automatically");
            #[allow(unreachable_code)]
            Ok(())
        })
        .await
        .is_err());
}

#[tokio::test]
async fn application_cancellation_is_durable_before_a_timer_exists() {
    let state = crate::core::recovery::RecoveryState::default();
    let (_root, path) = journal().await;
    let guard = state.begin_apply(&path).await.unwrap();
    drop(guard);
    assert!(state.stopped(&path));
    state.forget(&path);
    assert!(state.restore_stop(&path).await.unwrap());
    assert_eq!(state.progress(&path).unwrap().attempts, 0);
}

#[tokio::test]
async fn corrupt_control_never_authorizes_even_manual_mutations() {
    let state = crate::core::recovery::RecoveryState::default();
    let (_root, path) = journal().await;
    tokio::fs::write(control_path(&path), b"corrupt")
        .await
        .unwrap();
    for manual in [false, true] {
        assert!(state
            .run(&path, manual, async {
                panic!("untrusted metadata must fence mutations");
                #[allow(unreachable_code)]
                Ok(())
            })
            .await
            .is_err());
        assert!(state.stopped(&path));
    }
}

#[tokio::test]
async fn failed_control_write_is_visible_and_blocks_runtime() {
    let state = crate::core::recovery::RecoveryState::default();
    let (root, path) = journal().await;
    tokio::fs::create_dir(control_path(&path)).await.unwrap();
    let error = state
        .begin_apply(&path)
        .await
        .err()
        .expect("write-ahead control persistence must fail");
    assert!(format!("{error:#}").contains("persistence is unconfirmed"));
    assert!(state.stopped(&path));
    assert!(state.check_runtime(root.path(), Some("wan0")).is_err());
}

#[tokio::test]
async fn scope_retry_cannot_bypass_ownership_or_other_stops() {
    let state = crate::core::recovery::RecoveryState::default();
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("interface-transactions");
    tokio::fs::create_dir(&directory).await.unwrap();
    let path = directory.join("lan0.json");
    tokio::fs::write(&path, b"snapshot").await.unwrap();
    state
        .run::<(), _>(&path, false, async {
            Err(failure(FailureKind::Conflict, "conflict"))
        })
        .await
        .unwrap_err();
    state.block_interface(root.path(), "lan0", "transaction failed".into());
    assert!(state.check_scope(root.path(), Some("lan0")).is_err());
    assert!(state.check_scope(root.path(), Some("lan1")).is_ok());
    assert!(state
        .check_rollback_scope(root.path(), Some("lan0"), &path)
        .is_ok());
    state.block_interface_nonretryable(
        root.path(),
        "lan0",
        &root.path().join("ownership"),
        "ownership untrusted".into(),
    );
    assert!(state
        .check_rollback_scope(root.path(), Some("lan0"), &path)
        .is_err());
}

#[tokio::test]
async fn stale_control_has_no_authority_over_a_different_snapshot() {
    let state = crate::core::recovery::RecoveryState::default();
    let (_root, path) = journal().await;
    state
        .run::<(), _>(&path, false, async {
            Err(failure(FailureKind::Storage, "disk"))
        })
        .await
        .unwrap_err();
    state.forget(&path);
    tokio::fs::write(&path, br#"{"token":"two","snapshot":{}}"#)
        .await
        .unwrap();
    assert!(!state.restore_stop(&path).await.unwrap());
}

#[tokio::test(start_paused = true)]
async fn elapsed_budget_cannot_be_reset_by_a_different_failure_or_clock() {
    let state = crate::core::recovery::RecoveryState::default();
    let (_root, path) = journal().await;
    state
        .run::<(), _>(&path, false, async {
            Err(failure(FailureKind::Transient, "busy"))
        })
        .await
        .unwrap_err();
    tokio::time::advance(RECOVERY_TIMEOUT).await;
    assert!(state
        .run(&path, false, async {
            panic!("expired cycle must not perform another operation");
            #[allow(unreachable_code)]
            Ok(())
        })
        .await
        .is_err());
    assert!(state.stopped(&path));
    assert_eq!(state.progress(&path).unwrap().attempts, 1);
}

#[tokio::test(start_paused = true)]
async fn individual_attempt_has_a_deadline_and_retains_unknown_outcome() {
    let state = crate::core::recovery::RecoveryState::default();
    let (_root, path) = journal().await;
    let worker_path = path.clone();
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let worker_entered = entered.clone();
    let worker_state = state.clone();
    let task = tokio::spawn(async move {
        worker_state
            .run::<(), _>(&worker_path, false, async {
                worker_entered.notify_one();
                std::future::pending().await
            })
            .await
    });
    entered.notified().await;
    tokio::time::advance(ATTEMPT_TIMEOUT).await;
    assert!(task.await.unwrap().is_err());
    assert!(path.exists());
    assert_eq!(state.progress(&path).unwrap().attempts, 1);
}

#[tokio::test]
async fn stopped_shutdown_policy_preserves_resources_even_for_requested_restore() {
    let state = crate::core::recovery::RecoveryState::default();
    let (root, path) = journal().await;
    state
        .stop(&path, FailureKind::Conflict, "changed externally")
        .await
        .unwrap();
    assert!(state.preservation_required(root.path()));
    assert!(state.check_scope(root.path(), None).is_err());
    assert!(state.check_rollback_scope(root.path(), None, &path).is_ok());
    state.fence_commit(root.path(), "commit unknown".into());
    assert_eq!(
        state.progress(&path).unwrap().failure_kind,
        FailureKind::CommitIndeterminate
    );
    assert!(!state.progress(&path).unwrap().automatic_recovery);
    assert!(state
        .check_rollback_scope(root.path(), None, &path)
        .is_err());
}

#[tokio::test]
async fn independent_session_loads_durable_stop_without_inheriting_cached_budget() {
    let first = RecoveryState::default();
    let second = RecoveryState::default();
    let (root, path) = journal().await;
    first
        .run::<(), _>(&path, false, async {
            Err(failure(FailureKind::Conflict, "foreign resource"))
        })
        .await
        .unwrap_err();
    assert!(first.clone().stopped(&path));
    assert!(first.clone().check_runtime(root.path(), None).is_err());
    assert!(second.progress(&path).is_none());
    assert!(!second.stopped(&path));
    assert!(second.restore_stop(&path).await.unwrap());
    assert!(second.stopped(&path));
    assert_eq!(second.progress(&path).unwrap().attempts, 1);

    // Clearing this session's cache cannot erase another session's stop.
    second.forget(&path);
    assert!(second.progress(&path).is_none());
    assert!(first.stopped(&path));
}
