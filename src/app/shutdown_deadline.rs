//! Bound final cleanup without discarding proof of interrupted mutations.
use std::future::Future;
use std::time::Duration;

use anyhow::Result;
use tokio::task::AbortHandle;

use crate::core::desired::DesiredNetworkState;

// API admission has its own 30-second drain. This bounds all subsequent worker
// joins, transaction compensation, and final subsystem cleanup together.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(90);

/// Fatal cleanup deadline: callers must terminate the process, since blocking
/// filesystem operations may still own runtime reservations and recovery proof.
#[derive(Debug, thiserror::Error)]
#[error("daemon shutdown deadline reached; runtime cleanup is incomplete; recovery journals retained for next startup")]
pub struct ShutdownDeadlineExceeded;

pub(super) async fn finish(
    desired: &DesiredNetworkState,
    tasks: &[AbortHandle],
    cleanup: impl Future<Output = Result<()>>,
) -> Result<()> {
    // Install the fence before dropping cleanup: its cancellation guards may
    // spawn compensation tasks as they are dropped.
    tokio::pin!(cleanup);
    tokio::select! {
        biased;
        result = &mut cleanup => result,
        _ = tokio::time::sleep(SHUTDOWN_TIMEOUT) => {
            let reason = "daemon shutdown deadline reached; runtime cleanup is incomplete; recovery journals retained for next startup";
            // A late cancellation guard must not start more compensation after
            // the shutdown budget expired. Durable journals remain authoritative.
            desired
                .recovery()
                .fence_commit(desired.state_dir(), reason.into());
            desired.fail_converger(reason);
            for task in tasks {
                task.abort();
            }
            tracing::error!(timeout_seconds = SHUTDOWN_TIMEOUT.as_secs(), "{reason}");
            Err(ShutdownDeadlineExceeded.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::core::override_manager::RuntimeOverrideManager;

    #[tokio::test(start_paused = true)]
    async fn stalled_cleanup_aborts_workers_and_keeps_recovery_proof() {
        let directory = tempfile::tempdir().unwrap();
        let config = AppConfig::default();
        let overrides = RuntimeOverrideManager::load(directory.path(), &config)
            .await
            .unwrap();
        let desired = DesiredNetworkState::new(config, overrides);
        desired.attach_converger();
        let journal = directory.path().join("interface-transactions");
        std::fs::create_dir_all(&journal).unwrap();
        let journal = journal.join("wlan0.json");
        std::fs::write(&journal, b"recovery proof").unwrap();
        let worker = tokio::spawn(std::future::pending::<()>());
        struct CheckFenceOnCancel(DesiredNetworkState);
        impl Drop for CheckFenceOnCancel {
            fn drop(&mut self) {
                assert!(
                    self.0.recovery().check_commit(self.0.state_dir()).is_err(),
                    "cancellation guards must observe the shutdown fence"
                );
            }
        }
        let cleanup = async {
            let _guard = CheckFenceOnCancel(desired.clone());
            std::future::pending().await
        };
        let error = finish(&desired, &[worker.abort_handle()], cleanup)
            .await
            .unwrap_err();
        assert!(error.is::<ShutdownDeadlineExceeded>());
        assert!(error.to_string().contains("shutdown deadline"));
        assert!(worker.await.unwrap_err().is_cancelled());
        assert!(desired.recovery().check_commit(directory.path()).is_err());
        assert_eq!(std::fs::read(journal).unwrap(), b"recovery proof");
        assert!(!desired.has_converger());
    }

    #[tokio::test]
    async fn completed_cleanup_keeps_its_result_and_does_not_abort_workers() {
        let directory = tempfile::tempdir().unwrap();
        let config = AppConfig::default();
        let overrides = RuntimeOverrideManager::load(directory.path(), &config)
            .await
            .unwrap();
        let desired = DesiredNetworkState::new(config, overrides);
        let worker = tokio::spawn(std::future::pending::<()>());
        let result = finish(&desired, &[worker.abort_handle()], async {
            anyhow::bail!("cleanup failed")
        })
        .await;
        assert_eq!(result.unwrap_err().to_string(), "cleanup failed");
        assert!(!worker.is_finished());
        assert!(desired.recovery().check_commit(directory.path()).is_ok());
        worker.abort();
    }
}
