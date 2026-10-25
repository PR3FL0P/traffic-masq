//! Exercise the durable coordinator across a failure in every restoration hook.
//! OS adapters are simulated; journals, secrets, fences and restart admission are real.
use super::*;

const RESTORATION: &[&str] = &[
    "rollback_dataplane",
    "rollback_routes",
    "rollback_dhcp",
    "rollback_output_wifi",
    "rollback_vpn_chain",
    "rollback_candidate_uplink_dhcp",
    "rollback_uplink_wifi",
    "rollback_interfaces",
    "rollback_uplink_dhcp",
];

fn rollback_events(fake: &FakeSubsystems) -> Vec<String> {
    fake.events()
        .into_iter()
        .filter(|event| event.starts_with("rollback_"))
        .collect()
}

#[tokio::test]
async fn every_recovery_stage_preserves_proof_across_restart_then_accepts_a_new_change() {
    for failed_stage in RESTORATION {
        let fake = FakeSubsystems::new();
        let (coordinator, overrides, directory) = coordinator_with(fake.clone()).await;
        let secrets = stage_test_secret(directory.path()).await;
        *fake.rollback_secret.lock().unwrap() = Some(directory.path().into());
        let plan = coordinator
            .plan(build_candidate(&overrides).await)
            .await
            .unwrap();
        let token = coordinator.apply(plan).await.unwrap();
        secrets.bind_token(&token).await.unwrap();
        // Disable the old confirmation callback to simulate process exit later.
        coordinator.inner.timer_epoch.fetch_add(1, Ordering::SeqCst);
        let journal = coordinator.inner.journal.clone();
        let original_journal = std::fs::read(&journal).unwrap();
        fake.fail_rollback(failed_stage);
        *fake.rollback_failure_kind.lock().unwrap() = Some(recovery_control::FailureKind::Conflict);

        assert!(
            coordinator.rollback_with_token(&token).await.is_err(),
            "{failed_stage}"
        );
        assert_eq!(
            rollback_events(&fake),
            RESTORATION,
            "remaining restoration hooks must run after {failed_stage}"
        );
        assert_eq!(std::fs::read(&journal).unwrap(), original_journal);
        assert!(secrets
            .unresolved_after_committed_cleanup(None)
            .await
            .unwrap());
        assert!(coordinator.commit(&token).await.is_err());
        let plan = coordinator
            .plan(build_candidate(&overrides).await)
            .await
            .unwrap();
        assert!(coordinator.apply(plan).await.is_err());
        assert_eq!(overrides.committed_revision().await, 0);

        // Reopen durable storage and discard the volatile recovery budget, just
        // as a new daemon does. A stopped conflict must survive this boundary.
        recovery_control::forget(&journal);
        let reloaded = RuntimeOverrideManager::load(directory.path(), &base_config())
            .await
            .unwrap();
        let restarted = RouterTransactionCoordinator::new(
            RouterManager::new(fake.clone()),
            reloaded.clone(),
            Duration::from_secs(60),
        );
        let before = fake.events();
        assert!(restarted.recover().await.is_err());
        assert_eq!(
            fake.events(),
            before,
            "startup must preserve the stop at {failed_stage}"
        );
        assert_eq!(
            restarted.status().await,
            CoordinatorStatus::RecoveryRequired
        );
        assert_eq!(
            restarted.pending_token().await.as_deref(),
            Some(token.as_str())
        );
        assert_eq!(std::fs::read(&journal).unwrap(), original_journal);

        *fake.rollback_fail.lock().unwrap() = None;
        fake.events.lock().unwrap().clear();
        restarted.rollback_with_token(&token).await.unwrap();
        assert_eq!(
            rollback_events(&fake),
            RESTORATION,
            "complete retry after {failed_stage}"
        );
        assert_eq!(
            *fake.rollback_credentials_restored.lock().unwrap(),
            vec![true; 6],
            "both Wi-Fi hooks and interfaces must see restored credentials on both attempts"
        );
        assert_eq!(restarted.status().await, CoordinatorStatus::Idle);
        assert!(!journal.exists());
        assert!(!recovery_control::control_path(&journal).exists());
        assert!(!secrets
            .unresolved_after_committed_cleanup(None)
            .await
            .unwrap());
        assert_eq!(reloaded.committed_revision().await, 0);

        let candidate = build_candidate(&reloaded).await;
        let expected_intent = candidate.desired().clone();
        let plan = restarted.plan(candidate).await.unwrap();
        let next_token = restarted.apply(plan).await.unwrap();
        restarted.commit(&next_token).await.unwrap();
        assert_eq!(restarted.status().await, CoordinatorStatus::Idle);
        let disk = RuntimeOverrideManager::load(directory.path(), &base_config())
            .await
            .unwrap();
        assert_eq!(disk.committed_revision().await, 1);
        let saved = disk.snapshot().await;
        let actual_intent =
            RouterDesired::from_effective_config(&saved.effective_config(&base_config()).unwrap())
                .unwrap();
        assert_eq!(actual_intent, expected_intent, "{failed_stage}");
        assert_eq!(
            saved.committed_router_transaction.as_deref(),
            Some(next_token.as_str())
        );
    }
}
