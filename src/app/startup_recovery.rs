//! Validate independent recovery proofs and prepare startup network state.

use std::collections::BTreeSet;
use std::sync::Arc;

use anyhow::{Context, Result};

use crate::config::AppConfig;
use crate::core::interface::InterfaceManager;
use crate::core::override_manager::RuntimeOverrideManager;
use crate::core::ownership::AddressOwnershipJournal;
use crate::netlink::{NetworkProvider, RtnetlinkNetworkProvider};
use crate::state::overrides::RuntimeOverrides;

pub(super) struct StartupRecovery {
    pub(super) network_provider: Arc<dyn NetworkProvider>,
    pub(super) ownership_journal: AddressOwnershipJournal,
    pub(super) interface_manager: InterfaceManager,
    pub(super) overrides: RuntimeOverrideManager,
    pub(super) effective_config: AppConfig,
    pub(super) strict_admitted: bool,
    pub(super) router_recovery_pending: bool,
    pub(super) management_allowlist: BTreeSet<String>,
}

/// Before listeners or normal convergence start, load independent commit proofs,
/// recover interface journals and reconcile owned addresses. Isolate damaged
/// interface scopes; global storage/proof errors fail startup. Return effective
/// intent and strict-admission/router-recovery status so callers can fence normal
/// writes. Recovery must precede unrelated configuration admission.
pub(super) async fn prepare(config: &AppConfig) -> Result<StartupRecovery> {
    // Decode the durable proof envelope without admitting unrelated runtime settings. Individual
    // proof fields are handled independently below so one recovery scope cannot suppress another.
    let recovery_store =
        crate::state::overrides::RuntimeOverrideStore::in_state_dir(&config.runtime.state_dir);
    let recovery_proof = recovery_store.load_recovery_commit_proof().await?;
    let committed_router_transaction = recovery_proof.committed_router_transaction();
    let committed_interface_transactions = recovery_proof.committed_interface_transactions();

    let network_provider: Arc<dyn NetworkProvider> = Arc::new(RtnetlinkNetworkProvider::connect()?);
    // The directory itself is still a global invariant: if it cannot be enumerated, ownership is
    // unknowable. Damage to one named document is isolated to that interface and fenced below.
    let ownership_open = AddressOwnershipJournal::open_isolated(&config.runtime.state_dir)
        .context("failed to open the IPv4 address ownership journal")?;
    let ownership_blocked_interfaces = ownership_open
        .blocked_interfaces
        .iter()
        .map(|(interface, _)| interface.clone())
        .collect::<BTreeSet<_>>();
    for (interface, reason) in &ownership_open.blocked_interfaces {
        let ownership_path = config
            .runtime
            .state_dir
            .join("address-ownership")
            .join(format!("{interface}.json"));
        crate::core::recovery::block_interface_nonretryable(
            &config.runtime.state_dir,
            interface,
            &ownership_path,
            format!("address_ownership={}; {reason}", ownership_path.display()),
        );
    }
    let ownership_journal = ownership_open.journal;
    reconcile_address_ownership(&ownership_journal, network_provider.as_ref()).await;

    let interface_manager =
        InterfaceManager::new(network_provider.clone(), ownership_journal.clone());
    match committed_interface_transactions {
        Ok(committed) => {
            let wifi_runtime_dirs = crate::wifi::WifiRuntimeDirs::new(
                &config.wifi.runtime_dir,
                &config.wifi_client.runtime_dir,
            );
            crate::core::transaction::recover_interface_transactions_with_commit_tokens_excluding(
                &config.runtime.state_dir,
                &interface_manager,
                &committed,
                &ownership_blocked_interfaces,
                &wifi_runtime_dirs,
            )
            .await?;
        }
        Err(error) => {
            // Never guess that a journal is uncommitted when the independent proof field is
            // malformed. Fence only the interfaces that actually have pending journals and keep
            // unrelated router recovery available.
            crate::core::transaction::block_interface_transactions_without_commit_proof(
                &config.runtime.state_dir,
                &format!("runtime override interface commit proof is invalid: {error:#}"),
            )
            .await?;
            tracing::error!(
                operation = "recover_interface_transactions",
                invariant = "independent_commit_proof",
                error = %format!("{error:#}"),
                "interface commit proof is untrusted; pending interface scopes were fenced"
            );
        }
    }

    let router_journal = config.runtime.state_dir.join("router-transaction.json");
    let router_recovery_pending = crate::atomic_file::regular_file_exists(&router_journal)
        .context(
            crate::core::recovery::RecoveryDiagnostic::fatal(
                crate::core::recovery::StartupRecoveryCode::AccessibleRouterRecoveryJournal,
                "inspect",
                crate::core::recovery::RecoveryAction::RepairStorageAccess,
            )
            .journal(router_journal.clone())
            .object("router")
            .detail("expected_type", "regular_file_when_present")
            .detail(
                "expected_mode",
                format!("{:04o}", crate::atomic_file::PRIVATE_FILE_MODE),
            )
            .detail("symlink_allowed", false),
        )?;
    let provisioning_journal = config
        .runtime
        .state_dir
        .join("wifi")
        .join("router-provisioning-secrets.json");
    let provisioning_recovery_pending =
        crate::atomic_file::regular_file_exists(&provisioning_journal).context(
            crate::core::recovery::RecoveryDiagnostic::fatal(
                crate::core::recovery::StartupRecoveryCode::RestoreProvisioningSecrets,
                "inspect",
                crate::core::recovery::RecoveryAction::RepairStorageAccess,
            )
            .journal(provisioning_journal.clone())
            .object("router-provisioning-secrets")
            .detail("expected_type", "regular_file_when_present")
            .detail(
                "expected_mode",
                format!("{:04o}", crate::atomic_file::PRIVATE_FILE_MODE),
            )
            .detail("symlink_allowed", false),
        )?;

    let committed_router_transaction = match committed_router_transaction {
        Ok(token) => token,
        Err(error) if router_recovery_pending || provisioning_recovery_pending => {
            return Err(crate::core::recovery::context_if_missing(
                error,
                crate::core::recovery::RecoveryDiagnostic::fatal(
                    crate::core::recovery::StartupRecoveryCode::ProvableRouterRecovery,
                    "startup_recovery",
                    crate::core::recovery::RecoveryAction::InspectRecoveryState,
                )
                .journal(router_journal.clone())
                .object("router")
                .detail("required_proof", "independent_committed_transaction_token"),
            ));
        }
        Err(error) => {
            // There is no router recovery metadata to act on. Preserve the field error for strict
            // admission later, but do not let it suppress already-completed interface recovery.
            tracing::warn!(
                error = %format!("{error:#}"),
                "router commit proof is invalid but no router recovery journal is pending"
            );
            None
        }
    };

    // Provisioning secrets belong to the router recovery scope. Run this only after independent
    // interface recovery, so a router-secret problem cannot suppress interface rollback.
    let secrets = crate::core::provisioning_secret_transaction::ProvisioningSecretTransactionStore::in_state_dir(
        &config.runtime.state_dir,
    );
    // A router journal owns both runtime and secret compensation. Its bounded
    // coordinator must decide whether recovery may run before restoring secrets.
    let provisioning_recovery = if router_recovery_pending {
        secrets
            .unresolved_after_committed_cleanup(committed_router_transaction.as_deref())
            .await
    } else {
        secrets
            .recover(committed_router_transaction.as_deref())
            .await
    };
    if let Err(error) = provisioning_recovery {
        return Err(crate::core::recovery::context_if_missing(
            error,
            crate::core::recovery::RecoveryDiagnostic::fatal(
                crate::core::recovery::StartupRecoveryCode::RestoreProvisioningSecrets,
                "startup_recovery",
                crate::core::recovery::RecoveryAction::InspectRecoveryState,
            )
            .journal(provisioning_journal)
            .object("router-provisioning-secrets")
            .detail(
                "next_step",
                "inspect_nested_recovery_diagnostic_before_restoring_state",
            ),
        ));
    }

    // Build only router-relevant state first. When no router journal is pending, recovery is already
    // complete and normal startup must pass strict admission before it mutates the network. With a
    // pending router journal, strict admission remains deferred until rollback has finished.
    let overrides = RuntimeOverrideManager::from_router_recovery_proof(
        recovery_store,
        config,
        &recovery_proof,
        committed_router_transaction,
    )?;
    let (effective_config, strict_admitted) = if router_recovery_pending {
        let snapshot = overrides.snapshot().await;
        (snapshot.effective_router_recovery_config(config)?, false)
    } else {
        config.validate()?;
        (overrides.hydrate_strict().await?, true)
    };
    let override_snapshot = overrides.snapshot().await;
    let management_allowlist = management_allowlist(&override_snapshot);

    Ok(StartupRecovery {
        network_provider,
        ownership_journal,
        interface_manager,
        overrides,
        effective_config,
        strict_admitted,
        router_recovery_pending,
        management_allowlist,
    })
}

/// Compare the address ownership journal with the machine, once, at startup.
///
/// The journal is written before the kernel is touched, so after a crash it can
/// claim an address that never made it onto a link, or one that has since been
/// replaced by somebody else's. Both are dropped here. Everything that survives
/// is an address this daemon may take off again, which is exactly the authority
/// that must not be granted on the strength of an unchecked file.
async fn reconcile_address_ownership(
    journal: &AddressOwnershipJournal,
    network: &dyn NetworkProvider,
) {
    for interface in journal.interfaces().await {
        let observed = match network.list_ipv4_addresses(&interface).await {
            Ok(observed) => observed,
            Err(error) => {
                // The interface is not there right now — unplugged, or renamed.
                // The claims stay: convergence will look again, and dropping
                // them here would disown addresses that come back with it.
                tracing::info!(
                    %interface,
                    %error,
                    "keeping recorded IPv4 address ownership: the interface cannot be read right now"
                );
                continue;
            }
        };
        match journal.reconcile(&interface, &observed).await {
            Ok(outcome) => {
                for (claim, reason) in &outcome.dropped {
                    tracing::info!(
                        %interface,
                        address = %format!("{}/{}", claim.address, claim.prefix_len),
                        reason = %reason,
                        "dropping a recorded IPv4 address claim: the machine disagrees"
                    );
                }
                if !outcome.kept.is_empty() {
                    tracing::info!(
                        %interface,
                        addresses = %outcome
                            .kept
                            .iter()
                            .map(|claim| format!("{}/{}", claim.address, claim.prefix_len))
                            .collect::<Vec<_>>()
                            .join(", "),
                        "adopted IPv4 addresses recorded by a previous run"
                    );
                }
            }
            Err(error) => tracing::warn!(
                %interface,
                %error,
                "failed to reconcile recorded IPv4 address ownership"
            ),
        }
    }
}

fn management_allowlist(snapshot: &RuntimeOverrides) -> BTreeSet<String> {
    snapshot
        .interfaces
        .iter()
        .filter(|(_, value)| value.allow_management_change)
        .map(|(interface, _)| interface.clone())
        .collect()
}
