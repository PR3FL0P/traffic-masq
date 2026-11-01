//! Durable interface snapshot schema and journal storage policy.

use super::credentials::SecretSnapshot;
use crate::core::interface::InterfaceSnapshot;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Deserialize)]
pub(super) struct InterfaceJournalHeader {
    pub(super) token: String,
}

#[derive(Serialize, Deserialize)]
pub(super) struct InterfaceJournal {
    pub(super) version: u32,
    pub(super) token: String,
    pub(super) snapshot: InterfaceSnapshot,
    #[serde(default)]
    pub(super) secret: Option<SecretSnapshot>,
}

const INTERFACE_RECOVERY_STORE_ATTEMPTS: usize = 3;
const INTERFACE_RECOVERY_RETRY_DELAY: Duration = Duration::from_millis(100);

pub(super) fn retryable_interface_store_error(
    error: &crate::state::private_store::PrivateStoreError,
) -> bool {
    matches!(
        error,
        crate::state::private_store::PrivateStoreError::Io(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::TimedOut
            )
    )
}

pub(super) fn interface_recovery_store_error(
    state_dir: &std::path::Path,
    operation: &'static str,
    error: crate::state::private_store::PrivateStoreError,
) -> anyhow::Error {
    anyhow::Error::new(error).context(
        crate::core::recovery::RecoveryDiagnostic::fatal(
            crate::core::recovery::StartupRecoveryCode::AccessibleInterfaceRecoveryStore,
            operation,
            crate::core::recovery::RecoveryAction::RepairStorageAccess,
        )
        .path(state_dir.join("interface-transactions"))
        .object("interface-transactions")
        .detail("expected_type", "directory")
        .detail(
            "expected_mode",
            format!("{:04o}", crate::atomic_file::PRIVATE_DIR_MODE),
        )
        .detail("symlink_allowed", false),
    )
}

pub(super) async fn open_interface_recovery_store(
    state_dir: &std::path::Path,
) -> Result<crate::state::private_store::PrivateJsonDirectory> {
    for attempt in 1..=INTERFACE_RECOVERY_STORE_ATTEMPTS {
        let root = state_dir.to_path_buf();
        let opened = tokio::task::spawn_blocking(move || {
            crate::state::private_store::PrivateJsonDirectory::open(root, "interface-transactions")
        })
        .await?;

        match opened {
            Ok(store) => return Ok(store),
            Err(error)
                if attempt < INTERFACE_RECOVERY_STORE_ATTEMPTS
                    && retryable_interface_store_error(&error) =>
            {
                tracing::warn!(
                    attempt,
                    max_attempts = INTERFACE_RECOVERY_STORE_ATTEMPTS,
                    operation = "open_interface_recovery_store",
                    error = %error,
                    "transient interface recovery store error; retrying"
                );
                tokio::time::sleep(INTERFACE_RECOVERY_RETRY_DELAY).await;
            }
            Err(error) => return Err(interface_recovery_store_error(state_dir, "open", error)),
        }
    }
    unreachable!("interface recovery retry loop always returns on its final attempt")
}

pub(super) async fn enumerate_interface_recovery_journals(
    state_dir: &std::path::Path,
    store: &crate::state::private_store::PrivateJsonDirectory,
) -> Result<Vec<String>> {
    for attempt in 1..=INTERFACE_RECOVERY_STORE_ATTEMPTS {
        let store = store.clone();
        let names = tokio::task::spawn_blocking(move || store.keys()).await?;
        match names {
            Ok(names) => return Ok(names),
            Err(error)
                if attempt < INTERFACE_RECOVERY_STORE_ATTEMPTS
                    && retryable_interface_store_error(&error) =>
            {
                tracing::warn!(
                    attempt,
                    max_attempts = INTERFACE_RECOVERY_STORE_ATTEMPTS,
                    operation = "enumerate_interface_recovery_journals",
                    error = %error,
                    "transient interface recovery store error; retrying"
                );
                tokio::time::sleep(INTERFACE_RECOVERY_RETRY_DELAY).await;
            }
            Err(error) => {
                return Err(interface_recovery_store_error(
                    state_dir,
                    "enumerate",
                    error,
                ));
            }
        }
    }
    unreachable!("interface recovery retry loop always returns on its final attempt")
}

pub(super) struct InterfaceJournalStore {
    recovery: crate::core::recovery::RecoveryState,
    root: std::path::PathBuf,
}

impl InterfaceJournalStore {
    pub(super) fn new(
        state_dir: &std::path::Path,
        recovery: crate::core::recovery::RecoveryState,
    ) -> Self {
        Self {
            recovery,
            root: state_dir.to_path_buf(),
        }
    }

    pub(super) fn path(&self, interface: &str) -> std::path::PathBuf {
        self.root
            .join("interface-transactions")
            .join(format!("{interface}.json"))
    }

    pub(super) async fn write(
        &self,
        token: &str,
        snapshot: InterfaceSnapshot,
        secret: Option<SecretSnapshot>,
    ) -> Result<()> {
        self.recovery
            .before_write(&self.path(&snapshot.name))
            .await?;
        let root = self.root.clone();
        let record = InterfaceJournal {
            version: 3,
            token: token.to_owned(),
            snapshot,
            secret,
        };
        tokio::task::spawn_blocking(move || -> Result<()> {
            let store = crate::state::private_store::PrivateJsonDirectory::open(
                root,
                "interface-transactions",
            )?;
            anyhow::ensure!(
                store.read(&record.snapshot.name)?.is_none(),
                "interface has an unresolved recovery journal; restart the daemon to recover it"
            );
            store.write(&record.snapshot.name, &serde_json::to_vec(&record)?)?;
            Ok(())
        })
        .await??;
        Ok(())
    }

    pub(super) async fn retire(&self, interface: &str) -> Result<()> {
        self.recovery.retire(&self.path(interface)).await
    }
}
