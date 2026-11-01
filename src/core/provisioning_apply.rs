//! Staging and compensation for the secret half of router provisioning.
use crate::core::{
    override_manager::RuntimeOverrideManager,
    provisioning_secret_transaction::ProvisioningSecretTransactionStore,
    router_candidate::RouterIntentProposal, router_transaction::RouterTransactionCoordinator,
};
use crate::wifi::{HostapdSupervisor, WifiClientSupervisor, WifiPassphrase};
use anyhow::Result;
use std::collections::BTreeMap;

pub(crate) enum ProvisioningApplyError {
    Secret(anyhow::Error),
    Other(anyhow::Error),
    Transaction(anyhow::Error),
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn apply(
    router: &RouterTransactionCoordinator,
    overrides: &RuntimeOverrideManager,
    state_dir: &std::path::Path,
    output_supervisor: Option<&HostapdSupervisor>,
    uplink_supervisor: Option<&WifiClientSupervisor>,
    output_interface: String,
    uplink_interface: String,
    output_passphrase: Option<WifiPassphrase>,
    uplink_passphrase: Option<WifiPassphrase>,
    proposal: RouterIntentProposal,
) -> Result<String, ProvisioningApplyError> {
    let mut previous = BTreeMap::new();
    if let Some(supervisor) = output_supervisor {
        match supervisor.stored_passphrase(&output_interface).await {
            Ok(secret) => {
                previous.insert(
                    output_interface.clone(),
                    (crate::wifi::store::WifiCredentialRole::Ap, secret),
                );
            }
            Err(error) => return Err(ProvisioningApplyError::Other(error.into())),
        }
    }
    if let Some(supervisor) = uplink_supervisor {
        match supervisor.stored_passphrase(&uplink_interface).await {
            Ok(secret) => {
                previous.insert(
                    uplink_interface.clone(),
                    (crate::wifi::store::WifiCredentialRole::Client, secret),
                );
            }
            Err(error) => return Err(ProvisioningApplyError::Other(error.into())),
        }
    }

    let secret_tx =
        ProvisioningSecretTransactionStore::in_state_dir(state_dir, overrides.recovery().clone());
    secret_tx.stage(previous).await.map_err(|e| {
        ProvisioningApplyError::Other(e.context("failed to open provisioning secret transaction"))
    })?;
    let prepared = async {
        if let (Some(supervisor), Some(passphrase)) =
            (output_supervisor, output_passphrase.as_ref())
        {
            supervisor
                .set_passphrase(&output_interface, passphrase)
                .await
                .map_err(|e| ProvisioningApplyError::Secret(e.into()))?;
        }
        if let (Some(supervisor), Some(passphrase)) =
            (uplink_supervisor, uplink_passphrase.as_ref())
        {
            supervisor
                .set_passphrase(&uplink_interface, passphrase)
                .await
                .map_err(|e| ProvisioningApplyError::Secret(e.into()))?;
        }
        let candidate = overrides
            .build_candidate(&proposal)
            .await
            .map_err(ProvisioningApplyError::Transaction)?;
        router
            .plan(candidate)
            .await
            .map_err(ProvisioningApplyError::Transaction)
    }
    .await;
    let plan = match prepared {
        Ok(plan) => plan,
        Err(error) => {
            let restore = router.restore_staged_provisioning_secrets().await;
            return Err(match (error, restore) {
                (error, Ok(_)) => error,
                (ProvisioningApplyError::Secret(error), Err(restore)) => {
                    ProvisioningApplyError::Secret(anyhow::anyhow!(
                        "{error}; restoring prior provisioning secrets also failed: {restore:#}"
                    ))
                }
                (
                    ProvisioningApplyError::Other(error)
                    | ProvisioningApplyError::Transaction(error),
                    Err(restore),
                ) => ProvisioningApplyError::Other(anyhow::anyhow!(
                    "{error:#}; restoring prior provisioning secrets also failed: {restore:#}"
                )),
            });
        }
    };
    // Once apply starts, the coordinator owns journal recovery.
    router
        .apply(plan)
        .await
        .map_err(ProvisioningApplyError::Transaction)
}
