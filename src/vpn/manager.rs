use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;

use crate::config::ShutdownPolicy;
use crate::vpn::active_profile::{
    ActivationIntentStore, ActiveProfileError, ActiveProfileStore, PersistedActivationIntent,
    PersistedActiveProfile,
};
use crate::vpn::store::WireGuardProfileSummary;
use crate::vpn::{VpnDriver, VpnDriverError};

/// The legacy single-tunnel interface name, kept for the `VpnPolicyMode`
/// coexistence window (Landing 1): `vpn_policy_set_mode`/`VpnPolicyManager`'s
/// non-chain callers still activate exactly this interface through
/// [`VpnManager::activate`]/[`VpnManager::status`] etc. Landing 2 removes it
/// once those callers are repointed onto the chain exclusively.
pub const OWNED_INTERFACE_NAME: &str = "tm-wg0";

/// Distinct from [`OWNED_INTERFACE_NAME`] during the coexistence window.
pub use traffic_masq_protocol::hop_interface_name;

fn new_launch_marker() -> String {
    let mut token = [0u8; 16];
    OsRng.fill_bytes(&mut token);
    let mut marker = String::with_capacity(17 + token.len() * 2);
    marker.push_str("traffic-masq:vpn:");
    for byte in token {
        write!(&mut marker, "{byte:02x}").expect("writing to a String cannot fail");
    }
    marker
}

#[derive(Debug, Error)]
pub enum ManagerError {
    #[error(transparent)]
    Driver(#[from] VpnDriverError),

    #[error(transparent)]
    ActiveProfile(#[from] ActiveProfileError),

    #[error(
        "cannot activate: interface '{0}' already exists and is not owned by this daemon \
         (refusing to touch a possibly-foreign interface); inspect `ip -details link show dev {0}` and `sudo wg show {0}`; identify and reconfigure its owning service manually before retrying; traffic-masq will not delete or take over the interface"
    )]
    ForeignInterfaceConflict(String),

    #[error("cannot activate: an owned interface is already active")]
    AlreadyActive,

    #[error("no owned interface is currently active")]
    NotActive,

    #[error("profile '{0}' is still used by an active owned VPN interface")]
    ProfileInUse(String),

    #[error(
        "refusing to modify interface '{0}': it no longer matches the recorded ownership proof \
         (observed value differs from what this daemon created it with, or the interface is \
         missing) — treating it as foreign; inspect `ip -details link show dev {0}` and `sudo wg show {0}` and reconcile the owning service/configuration manually"
    )]
    OwnershipProofFailed(String),

    #[error("operation failed: {operation}; rollback also failed: {rollback}")]
    RollbackFailed { operation: String, rollback: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedInterfaceRecord<K> {
    pub interface: String,
    pub ownership_proof: K,
    pub profile_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnInterfaceSnapshot<K> {
    pub interface: String,
    pub existed_before: bool,
    pub ownership_proof: Option<K>,
    pub was_up: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileOutcome<K> {
    Absent,

    ForeignInterfacePresent,

    Adopted(OwnedInterfaceRecord<K>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnActiveStatus {
    pub interface: String,
    pub profile_name: String,
    pub up: bool,
}

pub struct VpnManager<D: VpnDriver> {
    driver: D,
    /// Every interface this manager currently owns, keyed by interface name.
    /// A `BTreeMap` rather than a single `Option` slot so multiple chain
    /// hops (each its own named `tm-wg-<hop_index>` interface) can be active
    /// concurrently; "already active" now means "this specific interface key
    /// is present", not "the map is non-empty".
    owned: Mutex<BTreeMap<String, OwnedInterfaceRecord<D::OwnershipProof>>>,
    active_profile_store: ActiveProfileStore,
    activation_intent_store: ActivationIntentStore,

    activation_lock: AsyncMutex<()>,
}

impl<D: VpnDriver> VpnManager<D> {
    pub fn new(driver: D, active_profile_store: ActiveProfileStore) -> Self {
        let activation_intent_store =
            ActivationIntentStore::for_active_profile(&active_profile_store);
        Self {
            driver,
            owned: Mutex::new(BTreeMap::new()),
            active_profile_store,
            activation_intent_store,
            activation_lock: AsyncMutex::new(()),
        }
    }

    /// List stored profile summaries without exposing private key material.
    pub fn list_profiles(&self) -> Result<Vec<WireGuardProfileSummary>, ManagerError> {
        Ok(self.driver.list_profiles()?)
    }

    /// Validate and import a profile, rejecting replacement of a profile currently in use.
    pub fn import_profile(&self, name: &str, raw: &[u8]) -> Result<String, ManagerError> {
        self.ensure_profile_not_active(name)?;
        self.driver.import_profile(name, raw)?;
        Ok(name.to_string())
    }

    /// Delete a stored profile only when no owned interface uses it.
    pub fn delete_profile(&self, name: &str) -> Result<(), ManagerError> {
        self.ensure_profile_not_active(name)?;
        Ok(self.driver.delete_profile(name)?)
    }

    fn ensure_profile_not_active(&self, name: &str) -> Result<(), ManagerError> {
        if self
            .owned
            .lock()
            .expect("owned mutex poisoned")
            .values()
            .any(|record| record.profile_name == name)
        {
            return Err(ManagerError::ProfileInUse(name.to_string()));
        }
        Ok(())
    }

    /// The legacy single-tunnel record, if `OWNED_INTERFACE_NAME` is active.
    /// Kept for the `VpnPolicyMode` coexistence window; chain callers should
    /// use [`Self::active_on`].
    pub fn active(&self) -> Option<OwnedInterfaceRecord<D::OwnershipProof>> {
        self.active_on(OWNED_INTERFACE_NAME)
    }

    pub fn active_on(&self, interface: &str) -> Option<OwnedInterfaceRecord<D::OwnershipProof>> {
        self.owned
            .lock()
            .expect("owned mutex poisoned")
            .get(interface)
            .cloned()
    }

    /// Every interface this manager currently owns.
    pub fn active_interfaces(&self) -> Vec<OwnedInterfaceRecord<D::OwnershipProof>> {
        self.owned
            .lock()
            .expect("owned mutex poisoned")
            .values()
            .cloned()
            .collect()
    }

    pub async fn status(&self) -> Result<Option<VpnActiveStatus>, ManagerError> {
        self.status_on(OWNED_INTERFACE_NAME).await
    }

    pub async fn status_on(
        &self,
        interface: &str,
    ) -> Result<Option<VpnActiveStatus>, ManagerError> {
        let Some(record) = self.active_on(interface) else {
            return Ok(None);
        };
        let up = self.driver.is_up(&record.interface).await?;
        Ok(Some(VpnActiveStatus {
            interface: record.interface,
            profile_name: record.profile_name,
            up,
        }))
    }

    /// Validate activation on the default owned VPN interface without creating a link.
    pub async fn plan_activation(&self, name: &str) -> Result<D::Profile, ManagerError> {
        self.plan_activation_on(OWNED_INTERFACE_NAME, name).await
    }

    /// Read the profile and reject an occupied or foreign target interface before activation.
    pub async fn plan_activation_on(
        &self,
        interface: &str,
        name: &str,
    ) -> Result<D::Profile, ManagerError> {
        let profile = self.driver.read_profile(name)?;

        if self
            .owned
            .lock()
            .expect("owned mutex poisoned")
            .contains_key(interface)
        {
            return Err(ManagerError::AlreadyActive);
        }

        if self.driver.link_exists(interface).await? {
            return Err(ManagerError::ForeignInterfaceConflict(
                interface.to_string(),
            ));
        }

        Ok(profile)
    }

    /// Read-only transaction observation: never adopt, clear evidence or clean a launch here.
    pub(crate) async fn snapshot_profile(&self) -> Result<Option<String>, ManagerError> {
        let _guard = self.activation_lock.lock().await;
        let interface = OWNED_INTERFACE_NAME;
        if !self.driver.link_exists(interface).await? {
            return Ok(None);
        }
        let persisted = self.active_profile_store.load().await?;
        if let Some(persisted) = persisted.filter(|record| record.interface == interface) {
            let proof = BASE64
                .decode(&persisted.ownership_proof_base64)
                .ok()
                .and_then(|bytes| self.driver.decode_ownership_proof(&bytes).ok());
            if let Some(proof) = proof {
                if self.driver.read_ownership_proof(interface).await?.as_ref() == Some(&proof) {
                    return Ok(Some(persisted.profile_name));
                }
            }
        }
        Err(ManagerError::ForeignInterfaceConflict(interface.into()))
    }

    pub async fn snapshot(&self) -> Result<VpnInterfaceSnapshot<D::OwnershipProof>, ManagerError> {
        self.snapshot_on(OWNED_INTERFACE_NAME).await
    }

    pub async fn snapshot_on(
        &self,
        interface: &str,
    ) -> Result<VpnInterfaceSnapshot<D::OwnershipProof>, ManagerError> {
        let existed_before = self.driver.link_exists(interface).await?;
        let (ownership_proof, was_up) = if existed_before {
            (
                self.driver.read_ownership_proof(interface).await?,
                self.driver.is_up(interface).await?,
            )
        } else {
            (None, false)
        };
        Ok(VpnInterfaceSnapshot {
            interface: interface.to_string(),
            existed_before,
            ownership_proof,
            was_up,
        })
    }

    /// Activate a profile on the default owned VPN interface and persist its ownership proof.
    pub async fn activate(&self, name: &str) -> Result<(), ManagerError> {
        self.activate_on(OWNED_INTERFACE_NAME, name).await
    }

    /// Serialize activation, journal ownership intent before link creation, and persist the active proof.
    /// Attempt rollback on failure; report both operation and rollback errors when recovery fails.
    pub async fn activate_on(&self, interface: &str, name: &str) -> Result<(), ManagerError> {
        let _activation_guard = self.activation_lock.lock().await;

        let profile = self.plan_activation_on(interface, name).await?;
        let snapshot = self.snapshot_on(interface).await?;
        let intent = PersistedActivationIntent {
            profile_name: name.to_string(),
            interface: interface.to_string(),
            launch_marker: new_launch_marker(),
        };

        // Write-ahead ownership: this must be durable before RTM_NEWLINK. The
        // driver places the same marker into IFLA_IFALIAS atomically with link
        // creation, so recovery can prove ownership even if we die before the
        // WireGuard private/public key exists.
        self.activation_intent_store.save(&intent).await?;

        if let Err(error) = self
            .activate_inner(interface, name, &profile, &intent.launch_marker)
            .await
        {
            return match self.rollback_activation_intent(&intent).await {
                Ok(()) => Err(error),
                Err(rollback) => Err(ManagerError::RollbackFailed {
                    operation: error.to_string(),
                    rollback: rollback.to_string(),
                }),
            };
        }

        let record = self
            .active_on(interface)
            .expect("activate_inner set the owned record");
        let persisted = PersistedActiveProfile {
            profile_name: record.profile_name.clone(),
            interface: record.interface.clone(),
            ownership_proof_base64: BASE64
                .encode(self.driver.encode_ownership_proof(&record.ownership_proof)),
        };
        if let Err(error) = self.active_profile_store.save(&persisted).await {
            let operation = ManagerError::ActiveProfile(error);
            return match self.rollback(&snapshot).await {
                Ok(()) => match self.clear_activation_intent_for(interface).await {
                    Ok(()) => Err(operation),
                    Err(cleanup) => Err(ManagerError::RollbackFailed {
                        operation: operation.to_string(),
                        rollback: format!(
                            "runtime rollback succeeded but activation-intent cleanup failed: {cleanup}"
                        ),
                    }),
                },
                Err(rollback) => {
                    // Preserve the existing stronger recovery proof if runtime
                    // rollback fails. The activation intent remains alongside
                    // it, so startup can prefer the committed/public-key proof
                    // when this write succeeds and otherwise still retry the
                    // marker-verified rollback.
                    let recovery_marker = self.active_profile_store.save(&persisted).await.err();
                    Err(ManagerError::RollbackFailed {
                        operation: operation.to_string(),
                        rollback: match recovery_marker {
                            Some(marker) => format!(
                                "{rollback}; durable ownership recovery marker also failed: {marker}"
                            ),
                            None => rollback.to_string(),
                        },
                    })
                }
            };
        }

        // The active-profile record is the commit point. A stale intent is
        // harmless after this point: startup verifies the stronger public-key
        // proof first and then removes the intent. Do not turn a successful
        // committed activation into a reported failure merely because journal
        // cleanup hit a transient filesystem error.
        if let Err(error) = self.clear_activation_intent_for(interface).await {
            tracing::warn!(
                interface,
                error = %error,
                "VPN activation committed but activation-intent cleanup failed; startup recovery will retry"
            );
        }

        Ok(())
    }

    async fn activate_inner(
        &self,
        interface: &str,
        name: &str,
        profile: &D::Profile,
        launch_marker: &str,
    ) -> Result<(), ManagerError> {
        let ownership_proof = self
            .driver
            .activate(interface, profile, launch_marker)
            .await?;

        self.owned.lock().expect("owned mutex poisoned").insert(
            interface.to_string(),
            OwnedInterfaceRecord {
                interface: interface.to_string(),
                ownership_proof,
                profile_name: name.to_string(),
            },
        );

        Ok(())
    }

    async fn clear_activation_intent_for(&self, interface: &str) -> Result<(), ManagerError> {
        if self
            .activation_intent_store
            .load()
            .await?
            .as_ref()
            .is_some_and(|intent| intent.interface == interface)
        {
            self.activation_intent_store.clear().await?;
        }
        Ok(())
    }

    async fn rollback_activation_intent(
        &self,
        intent: &PersistedActivationIntent,
    ) -> Result<(), ManagerError> {
        if !self.driver.link_exists(&intent.interface).await? {
            self.clear_activation_intent_for(&intent.interface).await?;
            self.owned
                .lock()
                .expect("owned mutex poisoned")
                .remove(&intent.interface);
            return Ok(());
        }

        if !self
            .driver
            .delete_if_launch_marker(&intent.interface, &intent.launch_marker)
            .await?
        {
            // The interface may have disappeared between the existence check
            // and the marker-verified delete. That is safe: there is no
            // runtime state left to own, so only the stale intent remains.
            if !self.driver.link_exists(&intent.interface).await? {
                self.clear_activation_intent_for(&intent.interface).await?;
                self.owned
                    .lock()
                    .expect("owned mutex poisoned")
                    .remove(&intent.interface);
                return Ok(());
            }
            return Err(ManagerError::OwnershipProofFailed(intent.interface.clone()));
        }

        self.clear_activation_intent_for(&intent.interface).await?;
        self.owned
            .lock()
            .expect("owned mutex poisoned")
            .remove(&intent.interface);
        Ok(())
    }

    /// Remove the default owned VPN interface and clear its durable ownership state.
    pub async fn deactivate(&self) -> Result<(), ManagerError> {
        self.deactivate_on(OWNED_INTERFACE_NAME).await
    }

    /// Verify ownership before deleting a VPN link and clearing its recovery records.
    /// Keep in-memory ownership on persistence failure so cleanup can be retried.
    pub async fn deactivate_on(&self, interface: &str) -> Result<(), ManagerError> {
        let _activation_guard = self.activation_lock.lock().await;

        let record = self
            .owned
            .lock()
            .expect("owned mutex poisoned")
            .get(interface)
            .cloned();

        let Some(record) = record else {
            if !self.driver.link_exists(interface).await? {
                let persisted_matches = self
                    .active_profile_store
                    .load()
                    .await?
                    .as_ref()
                    .is_some_and(|persisted| persisted.interface == interface);
                let intent_matches = self
                    .activation_intent_store
                    .load()
                    .await?
                    .as_ref()
                    .is_some_and(|intent| intent.interface == interface);

                if persisted_matches {
                    self.active_profile_store.clear().await?;
                }
                if intent_matches {
                    self.activation_intent_store.clear().await?;
                }
                if persisted_matches || intent_matches {
                    return Ok(());
                }
            }
            return Err(ManagerError::NotActive);
        };

        if self.driver.link_exists(interface).await? {
            self.assert_still_owned(&record).await?;
            self.driver.deactivate(&record.interface).await?;
        }

        // Keep the in-memory ownership proof until the durable marker is gone.
        // If this clear fails, a retry sees the missing link and can finish the
        // persistence cleanup without reporting a false-success deactivation.
        self.active_profile_store.clear().await?;
        self.clear_activation_intent_for(interface).await?;
        self.owned
            .lock()
            .expect("owned mutex poisoned")
            .remove(interface);
        Ok(())
    }

    /// Remove a newly created owned interface; leave interfaces present in the snapshot untouched.
    /// Refuse deletion when the current link no longer matches the ownership proof.
    pub async fn rollback(
        &self,
        snapshot: &VpnInterfaceSnapshot<D::OwnershipProof>,
    ) -> Result<(), ManagerError> {
        if snapshot.existed_before {
            return Ok(());
        }

        let currently_exists = self.driver.link_exists(&snapshot.interface).await?;
        if !currently_exists {
            self.active_profile_store.clear().await?;
            self.clear_activation_intent_for(&snapshot.interface)
                .await?;
            self.owned
                .lock()
                .expect("owned mutex poisoned")
                .remove(&snapshot.interface);
            return Ok(());
        }

        let record = self
            .owned
            .lock()
            .expect("owned mutex poisoned")
            .get(&snapshot.interface)
            .cloned();
        let record = match record {
            Some(record) if record.interface == snapshot.interface => record,
            _ => {
                return Err(ManagerError::OwnershipProofFailed(
                    snapshot.interface.clone(),
                ));
            }
        };

        self.assert_still_owned(&record).await?;

        self.driver.deactivate(&record.interface).await?;
        self.active_profile_store.clear().await?;
        self.clear_activation_intent_for(&snapshot.interface)
            .await?;
        self.owned
            .lock()
            .expect("owned mutex poisoned")
            .remove(&snapshot.interface);
        Ok(())
    }

    /// Recover or classify the default VPN interface using persisted ownership evidence.
    pub async fn reconcile(&self) -> Result<ReconcileOutcome<D::OwnershipProof>, ManagerError> {
        self.reconcile_on(OWNED_INTERFACE_NAME).await
    }

    /// Serialize recovery with activation and deactivation; adopt a proven committed link,
    /// clean interrupted activation, or classify unmatched surviving links as foreign.
    pub async fn reconcile_on(
        &self,
        interface: &str,
    ) -> Result<ReconcileOutcome<D::OwnershipProof>, ManagerError> {
        // Reconciliation mutates the same runtime/ownership state as activation
        // and deactivation. In particular, a persisted activation intent is a
        // rollback journal only after an in-flight activation has stopped. If
        // reconcile races the live activation between RTM_NEWLINK and the
        // active-profile commit, it can otherwise delete the interface that
        // activate() is still configuring. Serialize all three paths through
        // the same lock so a launch intent cannot be mistaken for crash residue.
        let _activation_guard = self.activation_lock.lock().await;

        let persisted = self.active_profile_store.load().await?;
        let intent = self.activation_intent_store.load().await?;

        if !self.driver.link_exists(interface).await? {
            if persisted
                .as_ref()
                .is_some_and(|persisted| persisted.interface == interface)
            {
                self.active_profile_store.clear().await?;
            }
            if intent
                .as_ref()
                .is_some_and(|intent| intent.interface == interface)
            {
                self.activation_intent_store.clear().await?;
            }
            self.owned
                .lock()
                .expect("owned mutex poisoned")
                .remove(interface);
            return Ok(ReconcileOutcome::Absent);
        }

        // A durable active-profile record is the commit point. Prefer its
        // public-key proof over any leftover activation intent. If it matches,
        // the activation committed before the crash and the intent is merely a
        // stale journal entry.
        if let Some(persisted) = persisted.as_ref() {
            if persisted.interface == interface {
                let decoded = BASE64
                    .decode(&persisted.ownership_proof_base64)
                    .ok()
                    .and_then(|bytes| self.driver.decode_ownership_proof(&bytes).ok());
                if let Some(persisted_proof) = decoded {
                    let observed_proof = self.driver.read_ownership_proof(interface).await?;
                    if observed_proof.as_ref() == Some(&persisted_proof) {
                        let record = OwnedInterfaceRecord {
                            interface: interface.to_string(),
                            ownership_proof: persisted_proof,
                            profile_name: persisted.profile_name.clone(),
                        };
                        self.owned
                            .lock()
                            .expect("owned mutex poisoned")
                            .insert(interface.to_string(), record.clone());
                        if intent
                            .as_ref()
                            .is_some_and(|intent| intent.interface == interface)
                        {
                            self.activation_intent_store.clear().await?;
                        }
                        return Ok(ReconcileOutcome::Adopted(record));
                    }
                } else {
                    tracing::warn!(
                        interface,
                        "persisted active-profile ownership proof could not be decoded; \
                         treating the surviving interface as foreign rather than adopting it"
                    );
                }

                // Once the active record exists, a proof mismatch is treated as
                // foreign/tampered state even if a stale launch marker happens
                // to remain. Never let the weaker journal marker override the
                // committed ownership proof.
                return Ok(ReconcileOutcome::ForeignInterfacePresent);
            }
        }

        // No committed record exists for this interface. A matching launch
        // marker means the process died during activation, so roll back only
        // the interface whose alias proves it was created by this intent.
        if let Some(intent) = intent.as_ref() {
            if intent.interface == interface
                && self
                    .driver
                    .delete_if_launch_marker(interface, &intent.launch_marker)
                    .await?
            {
                self.activation_intent_store.clear().await?;
                self.owned
                    .lock()
                    .expect("owned mutex poisoned")
                    .remove(interface);
                return Ok(ReconcileOutcome::Absent);
            }
        }

        Ok(ReconcileOutcome::ForeignInterfacePresent)
    }

    /// Apply the shutdown policy to owned VPN interfaces, retaining links under keep policy.
    pub async fn shutdown(&self, policy: ShutdownPolicy) -> Result<(), ManagerError> {
        let interfaces: Vec<String> = self
            .owned
            .lock()
            .expect("owned mutex poisoned")
            .keys()
            .cloned()
            .collect();
        if interfaces.is_empty() {
            return Ok(());
        }
        match policy {
            ShutdownPolicy::PreserveInterfaces => Ok(()),
            ShutdownPolicy::RestoreInterfaces => {
                for interface in interfaces {
                    self.deactivate_on(&interface).await?;
                }
                Ok(())
            }
        }
    }

    /// Reject a missing or changed ownership proof before a destructive VPN operation.
    async fn assert_still_owned(
        &self,
        record: &OwnedInterfaceRecord<D::OwnershipProof>,
    ) -> Result<(), ManagerError> {
        let observed_proof = self.driver.read_ownership_proof(&record.interface).await?;
        if observed_proof.as_ref() != Some(&record.ownership_proof) {
            return Err(ManagerError::OwnershipProofFailed(record.interface.clone()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
