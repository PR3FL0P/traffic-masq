use tempfile::tempdir;

use crate::app::process::ProcessGuard;

use super::*;

#[tokio::test]
async fn status_distinguishes_stopped_from_locked_but_unready() {
    let directory = tempdir().expect("tempdir");
    let mut config = AppConfig::default();
    config.runtime.pid_path = directory.path().join("traffic-masqd.pid");
    config.runtime.socket_path = directory.path().join("traffic-masqd.sock");

    assert_eq!(
        status(&config).await.expect("stopped status"),
        ServiceStatus::Stopped
    );
    let guard = ProcessGuard::acquire(&config.runtime.pid_path).expect("process guard");
    assert_eq!(
        status(&config).await.expect("unready status"),
        ServiceStatus::StartingOrUnhealthy {
            pid: Some(std::process::id())
        }
    );
    drop(guard);
    assert_eq!(
        status(&config).await.expect("stopped status"),
        ServiceStatus::Stopped
    );
}

#[test]
fn prints_and_selects_latest_rolling_log() {
    let directory = tempdir().expect("tempdir");
    let older = directory.path().join("traffic-masqd.log.2026-01-01");
    let latest = directory.path().join("traffic-masqd.log.2026-01-02");
    fs::write(&older, "old\n").expect("older log");
    std::thread::sleep(Duration::from_millis(10));
    fs::write(&latest, "one\ntwo\nthree\n").expect("latest log");
    assert_eq!(latest_log_path(directory.path()).expect("latest"), latest);
}

#[tokio::test]
async fn startup_recovery_report_round_trips_typed_diagnostic() {
    let directory = tempdir().expect("tempdir");
    let mut config = AppConfig::default();
    config.runtime.log_dir = directory.path().join("logs");

    let diagnostic = crate::core::recovery::RecoveryDiagnostic::fatal(
        crate::core::recovery::StartupRecoveryCode::RevisionOrder,
        "validate",
        crate::core::recovery::RecoveryAction::RestoreCoherentBackup,
    )
    .journal("/state/router-transaction.json")
    .object("router")
    .detail("journal_base_revision", 15)
    .detail("committed_revision", 14);
    let daemon_error = anyhow::Error::msg("transaction journal is newer").context(diagnostic);

    assert!(persist_startup_recovery_report(&config, &daemon_error)
        .await
        .expect("persist report"));
    let report = read_startup_recovery_report(&config)
        .expect("read report")
        .expect("recovery report");
    assert_eq!(report.recovery_code, "TM-REC-206");
    assert_eq!(report.runbook, "docs/recovery.md#tm-rec-206");
    assert_eq!(report.invariant, "revision_order");
    assert_eq!(report.operator_action, "restore_coherent_backup");

    let error = augment_start_error(&config, anyhow::anyhow!("daemon exited"), None);
    let rendered = format!("{error:#}");
    assert!(rendered.contains("startup is blocked by persisted recovery state"));
    assert!(rendered.contains("recovery_code: TM-REC-206"));
    assert!(rendered.contains("invariant: revision_order"));
    assert!(rendered.contains("journal_base_revision: 15"));
    assert!(rendered.contains("committed_revision: 14"));
    assert!(rendered.contains("restore_coherent_backup"));
    assert!(rendered.contains("Runbook: docs/recovery.md#tm-rec-206"));
    assert!(rendered.contains("Recovery metadata must be preserved"));
}

#[tokio::test]
async fn startup_recovery_report_rejects_code_invariant_mismatch() {
    let directory = tempdir().expect("tempdir");
    let mut config = AppConfig::default();
    config.runtime.log_dir = directory.path().join("logs");

    let diagnostic = crate::core::recovery::RecoveryDiagnostic::fatal(
        crate::core::recovery::StartupRecoveryCode::RevisionOrder,
        "validate",
        crate::core::recovery::RecoveryAction::RestoreCoherentBackup,
    );
    let daemon_error = anyhow::Error::msg("revision mismatch").context(diagnostic);
    persist_startup_recovery_report(&config, &daemon_error)
        .await
        .expect("persist report");

    let path = startup_recovery_report_path(&config);
    let bytes = fs::read(&path).expect("report bytes");
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("report json");
    value["invariant"] = serde_json::Value::String("supported_schema".to_string());
    fs::write(
        &path,
        serde_json::to_vec_pretty(&value).expect("serialize report"),
    )
    .expect("rewrite report");

    let error = read_startup_recovery_report(&config)
        .expect_err("mismatched recovery code/invariant must be rejected");
    assert!(format!("{error:#}").contains("code/invariant mismatch"));
}

#[tokio::test]
async fn startup_recovery_report_rejects_code_runbook_mismatch() {
    let directory = tempdir().expect("tempdir");
    let mut config = AppConfig::default();
    config.runtime.log_dir = directory.path().join("logs");

    let diagnostic = crate::core::recovery::RecoveryDiagnostic::fatal(
        crate::core::recovery::StartupRecoveryCode::RevisionOrder,
        "validate",
        crate::core::recovery::RecoveryAction::RestoreCoherentBackup,
    );
    let daemon_error = anyhow::Error::msg("revision mismatch").context(diagnostic);
    persist_startup_recovery_report(&config, &daemon_error)
        .await
        .expect("persist report");

    let path = startup_recovery_report_path(&config);
    let bytes = fs::read(&path).expect("report bytes");
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("report json");
    value["runbook"] = serde_json::Value::String("docs/recovery.md#tm-rec-205".to_string());
    fs::write(
        &path,
        serde_json::to_vec_pretty(&value).expect("serialize report"),
    )
    .expect("rewrite report");

    let error = read_startup_recovery_report(&config)
        .expect_err("mismatched recovery code/runbook must be rejected");
    assert!(format!("{error:#}").contains("code/runbook mismatch"));
}

#[tokio::test]
async fn startup_recovery_report_rejects_degraded_status_code() {
    let directory = tempdir().expect("tempdir");
    let mut config = AppConfig::default();
    config.runtime.log_dir = directory.path().join("logs");
    fs::create_dir_all(&config.runtime.log_dir).expect("log dir");

    let report = crate::core::recovery::RecoveryDiagnosticRecord {
        version: crate::core::recovery::RECOVERY_DIAGNOSTIC_RECORD_VERSION,
        recovery_code: "TM-REC-207".to_owned(),
        runbook: "docs/recovery.md#tm-rec-207".to_owned(),
        invariant: "router_rollback_failed".to_owned(),
        object: Some("router".to_owned()),
        journal: None,
        path: None,
        operation: "startup_recovery".to_owned(),
        metadata_safe_to_remove: false,
        details: Default::default(),
        operator_action: "retry_rollback".to_owned(),
        operator_guidance: "retry rollback".to_owned(),
    };
    fs::write(
        startup_recovery_report_path(&config),
        serde_json::to_vec_pretty(&report).expect("serialize report"),
    )
    .expect("write report");

    let error = read_startup_recovery_report(&config)
        .expect_err("degraded status must not masquerade as startup blocker");
    assert!(format!("{error:#}").contains("non-blocking recovery code TM-REC-207"));
}

#[tokio::test]
async fn version_one_startup_recovery_report_is_rejected_as_old_format() {
    let directory = tempdir().expect("tempdir");
    let mut config = AppConfig::default();
    config.runtime.log_dir = directory.path().join("logs");

    let diagnostic = crate::core::recovery::RecoveryDiagnostic::fatal(
        crate::core::recovery::StartupRecoveryCode::RevisionOrder,
        "validate",
        crate::core::recovery::RecoveryAction::RestoreCoherentBackup,
    );
    let daemon_error = anyhow::Error::msg("revision mismatch").context(diagnostic);
    persist_startup_recovery_report(&config, &daemon_error)
        .await
        .expect("persist report");

    let path = startup_recovery_report_path(&config);
    let bytes = fs::read(&path).expect("report bytes");
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("report json");
    value["version"] = serde_json::Value::from(1);
    value
        .as_object_mut()
        .expect("report object")
        .remove("recovery_code");
    value
        .as_object_mut()
        .expect("report object")
        .remove("runbook");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&value).expect("serialize report"),
    )
    .expect("rewrite report");

    let error = read_startup_recovery_report(&config)
        .expect_err("version one receipt must not be accepted as current");
    assert!(format!("{error:#}").contains("unsupported startup recovery report version 1"));
}

#[tokio::test]
async fn non_recovery_failure_does_not_publish_or_claim_recovery() {
    let directory = tempdir().expect("tempdir");
    let mut config = AppConfig::default();
    config.runtime.log_dir = directory.path().join("logs");
    let daemon_error = anyhow::anyhow!("address already in use");

    assert!(!persist_startup_recovery_report(&config, &daemon_error)
        .await
        .expect("skip non-recovery report"));
    let error = augment_start_error(&config, daemon_error, None);
    let rendered = format!("{error:#}");
    assert!(!rendered.contains("blocked by persisted recovery state"));
    assert!(rendered.contains("did not publish a recovery diagnostic"));
}

#[tokio::test]
async fn clearing_report_prevents_stale_recovery_advice() {
    let directory = tempdir().expect("tempdir");
    let mut config = AppConfig::default();
    config.runtime.log_dir = directory.path().join("logs");
    let diagnostic = crate::core::recovery::RecoveryDiagnostic::fatal(
        crate::core::recovery::StartupRecoveryCode::SupportedSchema,
        "decode",
        crate::core::recovery::RecoveryAction::UseCompatibleDaemon,
    );
    let daemon_error = anyhow::Error::msg("unsupported schema").context(diagnostic);
    persist_startup_recovery_report(&config, &daemon_error)
        .await
        .expect("persist report");

    clear_startup_recovery_report(&config).expect("clear report");
    assert!(read_startup_recovery_report(&config)
        .expect("read after clear")
        .is_none());
    let rendered = format!(
        "{:#}",
        augment_start_error(&config, anyhow::anyhow!("unrelated startup failure"), None)
    );
    assert!(!rendered.contains("supported_schema"));
    assert!(!rendered.contains("blocked by persisted recovery state"));
}

#[test]
fn startup_attempt_lock_serializes_start_commands() {
    let directory = tempdir().expect("tempdir");
    let mut config = AppConfig::default();
    config.runtime.pid_path = directory.path().join("run/traffic-masqd.pid");

    let first = acquire_startup_attempt(&config).expect("first startup attempt");
    let second = acquire_startup_attempt(&config).expect_err("second attempt must be rejected");
    assert!(format!("{second:#}").contains("another traffic-masqd start attempt"));
    drop(first);
    acquire_startup_attempt(&config).expect("lock released after first attempt");
}

#[test]
fn unsafe_previous_report_never_becomes_recovery_advice() {
    let directory = tempdir().expect("tempdir");
    let mut config = AppConfig::default();
    config.runtime.log_dir = directory.path().join("logs");

    let rendered = format!(
        "{:#}",
        augment_start_error(
            &config,
            anyhow::anyhow!("unrelated startup failure"),
            Some("unsafe symlink at startup report"),
        )
    );
    assert!(rendered.contains("startup recovery diagnostic is unavailable"));
    assert!(!rendered.contains("blocked by persisted recovery state"));
}
