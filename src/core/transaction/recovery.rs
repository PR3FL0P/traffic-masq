//! Startup and background recovery of interrupted interface transactions.

use super::journal::{
    enumerate_interface_recovery_journals, open_interface_recovery_store, InterfaceJournal,
    InterfaceJournalHeader,
};
use crate::core::{interface::InterfaceManager, recovery_control};
use anyhow::Result;

/// Restore unconfirmed interface snapshots before applying startup configuration.
/// In particular, startup otherwise skips interfaces that were previously unmanaged.
pub async fn recover_interface_transactions(
    state_dir: &std::path::Path,
    manager: &InterfaceManager,
    committed: &crate::state::overrides::RuntimeOverrides,
    wifi_runtime_dirs: &crate::wifi::WifiRuntimeDirs,
) -> Result<()> {
    recover_interface_transactions_with_tokens(
        state_dir,
        manager,
        &committed.committed_interface_transactions,
        &std::collections::BTreeSet::new(),
        wifi_runtime_dirs,
    )
    .await
}

/// Early-startup recovery variant that consumes only independently parsed
/// commit tokens, before the full override document is semantically validated.
pub async fn recover_interface_transactions_with_commit_tokens(
    state_dir: &std::path::Path,
    manager: &InterfaceManager,
    committed: &std::collections::BTreeMap<String, String>,
    wifi_runtime_dirs: &crate::wifi::WifiRuntimeDirs,
) -> Result<()> {
    recover_interface_transactions_with_commit_tokens_excluding(
        state_dir,
        manager,
        committed,
        &std::collections::BTreeSet::new(),
        wifi_runtime_dirs,
    )
    .await
}

/// Recover interface transactions except scopes already fenced by independent recovery metadata.
pub async fn recover_interface_transactions_with_commit_tokens_excluding(
    state_dir: &std::path::Path,
    manager: &InterfaceManager,
    committed: &std::collections::BTreeMap<String, String>,
    excluded: &std::collections::BTreeSet<String>,
    wifi_runtime_dirs: &crate::wifi::WifiRuntimeDirs,
) -> Result<()> {
    recover_interface_transactions_with_tokens(
        state_dir,
        manager,
        committed,
        excluded,
        wifi_runtime_dirs,
    )
    .await
}

/// Preserve every pending interface journal when its independent commit proof is untrusted.
///
/// Enumeration itself remains a global invariant: if the directory cannot be listed, startup
/// cannot know which interfaces must be fenced. Once names are known, each scope is blocked and
/// unrelated router recovery may continue without guessing whether rollback would destroy a
/// committed interface change.
pub async fn block_interface_transactions_without_commit_proof(
    state_dir: &std::path::Path,
    reason: &str,
) -> Result<()> {
    let store = open_interface_recovery_store(state_dir).await?;
    let names = enumerate_interface_recovery_journals(state_dir, &store).await?;
    for name in names {
        let path = store.directory().join(format!("{name}.json"));
        crate::core::recovery::block_interface(
            state_dir,
            &name,
            format!(
                "journal={}; commit_proof=untrusted; {reason}",
                path.display()
            ),
        );
    }
    Ok(())
}

async fn recover_interface_transactions_with_tokens(
    state_dir: &std::path::Path,
    manager: &InterfaceManager,
    committed: &std::collections::BTreeMap<String, String>,
    excluded: &std::collections::BTreeSet<String>,
    wifi_runtime_dirs: &crate::wifi::WifiRuntimeDirs,
) -> Result<()> {
    crate::core::recovery::check_commit(state_dir)?;
    let store = open_interface_recovery_store(state_dir).await?;
    let names = enumerate_interface_recovery_journals(state_dir, &store)
        .await?
        .into_iter()
        .filter(|name| {
            if !excluded.contains(name) {
                return true;
            }
            tracing::error!(
                interface = %name,
                invariant = "restore_before_mutation",
                operation = "recover_interface",
                metadata_safe_to_remove = false,
                "interface transaction recovery deferred because another recovery record for this interface is untrusted"
            );
            false
        })
        .collect();
    recover_interface_journals(
        state_dir,
        manager,
        committed,
        &store,
        names,
        wifi_runtime_dirs,
        true,
    )
    .await;
    Ok(())
}

/// Retry only failed startup journals, never live unconfirmed transactions.
pub(crate) async fn retry_interface_recovery(
    state_dir: &std::path::Path,
    manager: &InterfaceManager,
    committed: &crate::state::overrides::RuntimeOverrides,
    wifi_runtime_dirs: &crate::wifi::WifiRuntimeDirs,
) -> Result<()> {
    crate::core::recovery::check_commit(state_dir)?;
    let names = crate::core::recovery::retryable_blocked_interfaces(state_dir);
    if names.is_empty() {
        return Ok(());
    }
    let store = open_interface_recovery_store(state_dir).await?;
    recover_interface_journals(
        state_dir,
        manager,
        &committed.committed_interface_transactions,
        &store,
        names,
        wifi_runtime_dirs,
        false,
    )
    .await;
    Ok(())
}

async fn recover_interface_journals(
    state_dir: &std::path::Path,
    manager: &InterfaceManager,
    committed: &std::collections::BTreeMap<String, String>,
    store: &crate::state::private_store::PrivateJsonDirectory,
    names: Vec<String>,
    wifi_runtime_dirs: &crate::wifi::WifiRuntimeDirs,
    new_session: bool,
) {
    for name in names {
        let recovery_path = state_dir
            .join("interface-transactions")
            .join(format!("{name}.json"));
        if !new_session && recovery_control::stopped(&recovery_path) {
            continue;
        }
        let path = store.directory().join(format!("{name}.json"));
        let result: Result<()> =
            async {
                let bytes = store.read(&name)?.ok_or_else(|| {
                    anyhow::anyhow!("recovery journal disappeared before restoration")
                })?;
                if crate::core::recovery::completed(&path, &bytes).await? {
                    return crate::core::recovery::retire(&path).await;
                }
                let committed_token = committed.get(&name);
                let committed_proof = serde_json::from_slice::<InterfaceJournalHeader>(&bytes)
                    .ok()
                    .is_some_and(|header| Some(&header.token) == committed_token);
                if committed_proof {
                    tracing::warn!(
                        interface = %name,
                        journal = %path.display(),
                        operation = "retire_committed_interface_journal",
                        invariant = "committed_token_proof",
                        metadata_safe_to_remove = true,
                        "retiring interface recovery metadata proven obsolete by committed token"
                    );
                    return crate::core::recovery::retire(&path).await;
                }
                // A daemon restart starts a new bounded restoration attempt.
                // Historical failures are evidence, not proof that the current
                // environment still prevents cancellation. Background retries
                // retain the existing attempt budget.
                recovery_control::run(&path, new_session, async {
                let record: InterfaceJournal = serde_json::from_slice(&bytes)?;
                anyhow::ensure!(
                matches!(record.version, 1..=3) && record.snapshot.name == name,
                recovery_control::failure(recovery_control::FailureKind::Incompatible,
                    "invariant=valid_interface_snapshot: unsupported schema or interface mismatch")
            );
                anyhow::ensure!(
                    record.version < 3
                        || record
                            .secret
                            .as_ref()
                            .is_none_or(|secret| secret.role.is_some()),
                    recovery_control::failure(
                        recovery_control::FailureKind::Incompatible,
                        "role missing from Wi-Fi secret snapshot"
                    )
                );
                if committed.get(&name) != Some(&record.token) {
                    if let Some(secret) = &record.secret {
                        secret.restore(state_dir, &name)?;
                    }
                    crate::wifi::lifecycle::stop_recorded_interface(
                        state_dir,
                        wifi_runtime_dirs,
                        &name,
                    )
                    .await?;
                    manager.rollback_transaction_snapshot(&record.snapshot).await?;
                    tracing::warn!(interface = %name, "restored interrupted interface transaction");
                }
                crate::core::recovery::retire(&path).await
            })
            .await
            }
            .await;
        match result {
            Ok(()) => crate::core::recovery::unblock_interface(state_dir, &name),
            Err(error) => crate::core::recovery::block_interface(
                state_dir,
                &name,
                format!("journal={}; {error:#}", path.display()),
            ),
        }
    }
}
