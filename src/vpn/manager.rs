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
    ActiveProfileError, ActiveProfileStore, ActivationIntentStore, PersistedActivationIntent,
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

/// The interface name for a given chain hop: `tm-wg-<hop_index>`. Deliberately
/// namespaced apart from [`OWNED_INTERFACE_NAME`] (`tm-wg0` vs. `tm-wg-0`) so
/// the two activation paths can never collide on the same kernel interface
/// during the coexistence window.
pub fn hop_interface_name(hop_index: u32) -> String {
    format!("tm-wg-{hop_index}")
}

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
         (refusing to touch a possibly-foreign interface)"
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
         missing) — treating it as foreign"
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
        let activation_intent_store = ActivationIntentStore::for_active_profile(&active_profile_store);
        Self {
            driver,
            owned: Mutex::new(BTreeMap::new()),
            active_profile_store,
            activation_intent_store,
            activation_lock: AsyncMutex::new(()),
        }
    }

    pub fn list_profiles(&self) -> Result<Vec<WireGuardProfileSummary>, ManagerError> {
        Ok(self.driver.list_profiles()?)
    }

    pub fn import_profile(&self, name: &str, raw: &[u8]) -> Result<String, ManagerError> {
        self.ensure_profile_not_active(name)?;
        self.driver.import_profile(name, raw)?;
        Ok(name.to_string())
    }

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

    pub async fn plan_activation(&self, name: &str) -> Result<D::Profile, ManagerError> {
        self.plan_activation_on(OWNED_INTERFACE_NAME, name).await
    }

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

    pub async fn activate(&self, name: &str) -> Result<(), ManagerError> {
        self.activate_on(OWNED_INTERFACE_NAME, name).await
    }

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

    pub async fn deactivate(&self) -> Result<(), ManagerError> {
        self.deactivate_on(OWNED_INTERFACE_NAME).await
    }

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
            self.clear_activation_intent_for(&snapshot.interface).await?;
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
        self.clear_activation_intent_for(&snapshot.interface).await?;
        self.owned
            .lock()
            .expect("owned mutex poisoned")
            .remove(&snapshot.interface);
        Ok(())
    }

    pub async fn reconcile(&self) -> Result<ReconcileOutcome<D::OwnershipProof>, ManagerError> {
        self.reconcile_on(OWNED_INTERFACE_NAME).await
    }

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
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::test_support::{fake_vpn_public_key, FakeVpnProvider};
    use crate::vpn::store::WireGuardProfileStore;
    use crate::vpn::wireguard::{WireGuardKey, WireGuardVpnDriver};
    use crate::vpn::VpnProvider;

    const VALID_PRIVATE_KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const VALID_PUBLIC_KEY: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    const OTHER_PRIVATE_KEY: &str = "SBmoW+ojuoJZeh6P/2sh8aetgAy4dTZTAO8UzHzKtGY=";

    fn valid_config(private_key: &str) -> String {
        format!(
            "[Interface]\n\
             PrivateKey = {private_key}\n\
             Address = 10.0.0.2/24\n\
             \n\
             [Peer]\n\
             PublicKey = {VALID_PUBLIC_KEY}\n\
             AllowedIPs = 0.0.0.0/0\n\
             Endpoint = 203.0.113.1:51820\n"
        )
    }

    type TestManager = VpnManager<WireGuardVpnDriver>;

    fn encode_proof(key: &WireGuardKey) -> String {
        BASE64.encode(key.0)
    }

    fn fake_provider() -> (
        std::sync::Arc<dyn VpnProvider>,
        std::sync::Arc<FakeVpnProvider>,
    ) {
        let fake = std::sync::Arc::new(FakeVpnProvider::default());
        let erased: std::sync::Arc<dyn VpnProvider> = fake.clone();
        (erased, fake)
    }

    fn manager_with_store() -> (
        TestManager,
        std::sync::Arc<FakeVpnProvider>,
        tempfile::TempDir,
    ) {
        let dir = tempdir().expect("tempdir");
        let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
        let active_profile_store = ActiveProfileStore::new(dir.path().join("active-profile.json"));
        let (provider, fake) = fake_provider();
        let driver = WireGuardVpnDriver::new(provider, store);
        let manager = VpnManager::new(driver, active_profile_store);
        (manager, fake, dir)
    }

    #[tokio::test]
    async fn activate_deactivate_round_trip_succeeds() {
        let (manager, fake, _dir) = manager_with_store();
        manager
            .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
            .expect("import");

        manager.activate("home.conf").await.expect("activate");
        assert_eq!(
            manager
                .activation_intent_store
                .load()
                .await
                .expect("load activation intent"),
            None,
            "successful activation must clean its write-ahead intent"
        );

        let active = manager.active().expect("should be active");
        assert_eq!(active.interface, OWNED_INTERFACE_NAME);
        assert_eq!(active.profile_name, "home.conf");

        assert!(fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
        assert!(fake.is_up(OWNED_INTERFACE_NAME).await.unwrap());

        manager.deactivate().await.expect("deactivate");
        assert!(manager.active().is_none());
        assert!(!fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
    }

    #[tokio::test]
    async fn delete_refuses_profile_used_by_an_active_owned_interface() {
        let (manager, _fake, _dir) = manager_with_store();
        manager
            .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
            .expect("import");
        manager.activate("home.conf").await.expect("activate");

        let error = manager
            .delete_profile("home.conf")
            .expect_err("active profile must not be deleted");
        assert!(matches!(error, ManagerError::ProfileInUse(name) if name == "home.conf"));
        assert_eq!(manager.list_profiles().expect("profiles").len(), 1);
    }

    #[tokio::test]
    async fn import_refuses_to_overwrite_profile_used_by_an_active_owned_interface() {
        let (manager, _fake, _dir) = manager_with_store();
        manager
            .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
            .expect("import");
        manager.activate("home.conf").await.expect("activate");

        let error = manager
            .import_profile("home.conf", valid_config(OTHER_PRIVATE_KEY).as_bytes())
            .expect_err("active profile must not be overwritten");
        assert!(matches!(error, ManagerError::ProfileInUse(name) if name == "home.conf"));
    }

    #[tokio::test]
    async fn activation_rejects_conflict_with_existing_foreign_interface() {
        let (manager, fake, _dir) = manager_with_store();
        manager
            .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
            .expect("import");

        fake.seed_foreign_link(OWNED_INTERFACE_NAME, OTHER_PRIVATE_KEY);

        let error = manager.activate("home.conf").await.unwrap_err();
        assert!(matches!(error, ManagerError::ForeignInterfaceConflict(_)));

        assert!(fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
        assert!(manager.active().is_none());
    }

    #[tokio::test]
    async fn activation_rejects_conflict_when_already_active() {
        let (manager, _fake, _dir) = manager_with_store();
        manager
            .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
            .expect("import");
        manager.activate("home.conf").await.expect("activate");

        let error = manager.activate("home.conf").await.unwrap_err();
        assert!(matches!(error, ManagerError::AlreadyActive));
    }

    #[tokio::test]
    async fn two_different_hop_interfaces_can_be_activated_concurrently() {
        let (manager, fake, _dir) = manager_with_store();
        manager
            .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
            .expect("import");

        let hop0 = hop_interface_name(0);
        let hop1 = hop_interface_name(1);
        assert_ne!(hop0, hop1);

        manager
            .activate_on(&hop0, "home.conf")
            .await
            .expect("hop 0 activates");
        manager
            .activate_on(&hop1, "home.conf")
            .await
            .expect("a second, differently-named hop activates while hop 0 is still active");

        assert!(manager.active_on(&hop0).is_some());
        assert!(manager.active_on(&hop1).is_some());
        assert_eq!(manager.active_interfaces().len(), 2);
        assert!(fake.link_exists(&hop0).await.unwrap());
        assert!(fake.link_exists(&hop1).await.unwrap());

        // Re-activating an already-active hop by name is still rejected.
        let error = manager.activate_on(&hop0, "home.conf").await.unwrap_err();
        assert!(matches!(error, ManagerError::AlreadyActive));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_activate_calls_never_race_into_a_foreign_interface_conflict() {
        let (manager, fake, _dir) = manager_with_store();
        let manager = std::sync::Arc::new(manager);
        manager
            .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
            .expect("import");

        let manager_a = manager.clone();
        let manager_b = manager.clone();
        let (result_a, result_b) = tokio::join!(
            tokio::spawn(async move { manager_a.activate("home.conf").await }),
            tokio::spawn(async move { manager_b.activate("home.conf").await }),
        );
        let result_a = result_a.expect("task a panicked");
        let result_b = result_b.expect("task b panicked");

        let outcomes = [&result_a, &result_b];
        let successes = outcomes.iter().filter(|r| r.is_ok()).count();
        assert_eq!(
            successes, 1,
            "exactly one of two concurrent activate calls must succeed, got {result_a:?} / {result_b:?}"
        );
        let loser = outcomes
            .into_iter()
            .find(|r| r.is_err())
            .expect("one call must have failed");
        assert!(
            matches!(loser, Err(ManagerError::AlreadyActive)),
            "the losing concurrent activate call must see AlreadyActive, not a spurious \
             ForeignInterfaceConflict for an interface this manager itself is creating: {loser:?}"
        );

        let active = manager.active().expect("manager should be active");
        assert_eq!(active.interface, OWNED_INTERFACE_NAME);
        assert!(fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconcile_waits_for_in_flight_activation_before_rolling_back_intent() {
        use tokio::time::{timeout, Duration};

        let (manager, fake, _dir) = manager_with_store();
        let manager = std::sync::Arc::new(manager);
        let marker = "traffic-masq:vpn:in-flight";

        // Model the exact crash-journal state visible after create_link but
        // before the active-profile commit, while an activation still owns the
        // mutation lock. Reconcile must not treat this as abandoned state until
        // that activation is no longer in flight.
        let guard = manager.activation_lock.lock().await;
        manager
            .activation_intent_store
            .save(&PersistedActivationIntent {
                profile_name: "home.conf".to_string(),
                interface: OWNED_INTERFACE_NAME.to_string(),
                launch_marker: marker.to_string(),
            })
            .await
            .expect("save intent");
        fake.create_link(
            OWNED_INTERFACE_NAME,
            &WireGuardKey::parse(VALID_PRIVATE_KEY, "test").unwrap(),
            None,
            marker,
        )
        .await
        .expect("create pending link");

        let reconcile_manager = manager.clone();
        let mut reconcile = tokio::spawn(async move { reconcile_manager.reconcile().await });

        assert!(
            timeout(Duration::from_millis(50), &mut reconcile).await.is_err(),
            "reconcile must wait while activation owns the mutation lock"
        );
        assert!(
            fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap(),
            "reconcile must not delete an interface belonging to an in-flight activation"
        );

        drop(guard);
        let outcome = reconcile.await.expect("reconcile task").expect("reconcile");
        assert_eq!(outcome, ReconcileOutcome::Absent);
        assert!(!fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
    }

    #[tokio::test]
    async fn deactivate_refuses_to_touch_foreign_interface_that_replaced_owned_one() {
        let (manager, fake, _dir) = manager_with_store();
        manager
            .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
            .expect("import");
        manager.activate("home.conf").await.expect("activate");

        fake.delete_link(OWNED_INTERFACE_NAME).await.unwrap();
        fake.seed_foreign_link(OWNED_INTERFACE_NAME, OTHER_PRIVATE_KEY);

        let error = manager.deactivate().await.unwrap_err();
        assert!(matches!(error, ManagerError::OwnershipProofFailed(_)));

        assert!(fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
    }

    #[tokio::test]
    async fn rollback_after_failed_activation_removes_only_owned_interface() {
        let (manager, fake, _dir) = manager_with_store();

        manager
            .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
            .expect("import");

        let snapshot = manager.snapshot().await.expect("snapshot");
        assert!(!snapshot.existed_before);

        fake.create_link(
            OWNED_INTERFACE_NAME,
            &WireGuardKey::parse(VALID_PRIVATE_KEY, "test").unwrap(),
            None,
            "test-launch-marker",
        )
        .await
        .unwrap();
        let ownership_proof = fake
            .public_key(OWNED_INTERFACE_NAME)
            .await
            .unwrap()
            .unwrap();
        manager.owned.lock().unwrap().insert(
            OWNED_INTERFACE_NAME.to_string(),
            OwnedInterfaceRecord {
                interface: OWNED_INTERFACE_NAME.to_string(),
                ownership_proof,
                profile_name: "home.conf".to_string(),
            },
        );

        manager.rollback(&snapshot).await.expect("rollback");

        assert!(manager.active().is_none());
        assert!(!fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
    }

    #[tokio::test]
    async fn rollback_never_removes_a_preexisting_foreign_interface() {
        let (manager, fake, _dir) = manager_with_store();

        fake.seed_foreign_link(OWNED_INTERFACE_NAME, OTHER_PRIVATE_KEY);

        let snapshot = VpnInterfaceSnapshot {
            interface: OWNED_INTERFACE_NAME.to_string(),
            existed_before: true,
            ownership_proof: fake.public_key(OWNED_INTERFACE_NAME).await.unwrap(),
            was_up: true,
        };

        manager.rollback(&snapshot).await.expect("rollback no-op");

        assert!(fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
    }

    #[tokio::test]
    async fn reconcile_is_noop_when_no_interface_exists() {
        let (manager, _fake, _dir) = manager_with_store();

        let outcome = manager.reconcile().await.expect("reconcile");

        assert_eq!(outcome, ReconcileOutcome::Absent);
        assert!(manager.active().is_none());
    }

    #[tokio::test]
    async fn reconcile_clears_intent_when_crash_preceded_link_creation() {
        let dir = tempdir().expect("tempdir");
        let active_profile_store = ActiveProfileStore::new(dir.path().join("active-profile.json"));
        let intent_store = ActivationIntentStore::for_active_profile(&active_profile_store);
        intent_store
            .save(&PersistedActivationIntent {
                profile_name: "home.conf".to_string(),
                interface: OWNED_INTERFACE_NAME.to_string(),
                launch_marker: "traffic-masq:vpn:pre-create".to_string(),
            })
            .await
            .expect("persist activation intent");

        let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
        let (provider, fake) = fake_provider();
        let driver = WireGuardVpnDriver::new(provider, store);
        let manager = VpnManager::new(driver, active_profile_store);

        let outcome = manager.reconcile().await.expect("reconcile");

        assert_eq!(outcome, ReconcileOutcome::Absent);
        assert!(!fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
        assert_eq!(intent_store.load().await.expect("load intent"), None);
    }

    #[tokio::test]
    async fn reconcile_rolls_back_matching_uncommitted_activation_intent() {
        let dir = tempdir().expect("tempdir");
        let active_profile_store = ActiveProfileStore::new(dir.path().join("active-profile.json"));
        let intent_store = ActivationIntentStore::for_active_profile(&active_profile_store);
        let marker = "traffic-masq:vpn:pending-test";
        intent_store
            .save(&PersistedActivationIntent {
                profile_name: "home.conf".to_string(),
                interface: OWNED_INTERFACE_NAME.to_string(),
                launch_marker: marker.to_string(),
            })
            .await
            .expect("persist activation intent");

        let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
        let (provider, fake) = fake_provider();
        fake.create_link(
            OWNED_INTERFACE_NAME,
            &WireGuardKey::parse(VALID_PRIVATE_KEY, "test").unwrap(),
            None,
            marker,
        )
        .await
        .expect("seed interrupted activation");
        let driver = WireGuardVpnDriver::new(provider, store);
        let manager = VpnManager::new(driver, active_profile_store);

        let outcome = manager.reconcile().await.expect("reconcile");

        assert_eq!(outcome, ReconcileOutcome::Absent);
        assert!(!fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
        assert_eq!(intent_store.load().await.expect("load intent"), None);
    }

    #[tokio::test]
    async fn reconcile_never_deletes_interface_when_activation_marker_mismatches() {
        let dir = tempdir().expect("tempdir");
        let active_profile_store = ActiveProfileStore::new(dir.path().join("active-profile.json"));
        let intent_store = ActivationIntentStore::for_active_profile(&active_profile_store);
        intent_store
            .save(&PersistedActivationIntent {
                profile_name: "home.conf".to_string(),
                interface: OWNED_INTERFACE_NAME.to_string(),
                launch_marker: "traffic-masq:vpn:ours".to_string(),
            })
            .await
            .expect("persist activation intent");

        let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
        let (provider, fake) = fake_provider();
        fake.seed_foreign_link(OWNED_INTERFACE_NAME, OTHER_PRIVATE_KEY);
        let driver = WireGuardVpnDriver::new(provider, store);
        let manager = VpnManager::new(driver, active_profile_store);

        let outcome = manager.reconcile().await.expect("reconcile");

        assert_eq!(outcome, ReconcileOutcome::ForeignInterfacePresent);
        assert!(fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
        assert!(intent_store.load().await.expect("load intent").is_some());
    }

    #[tokio::test]
    async fn reconcile_prefers_committed_active_record_over_stale_activation_intent() {
        let dir = tempdir().expect("tempdir");
        let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
        let active_profile_store = ActiveProfileStore::new(dir.path().join("active-profile.json"));
        let intent_store = ActivationIntentStore::for_active_profile(&active_profile_store);
        let (provider, fake) = fake_provider();
        let driver = WireGuardVpnDriver::new(provider, store);
        let manager = VpnManager::new(driver, active_profile_store.clone());
        manager
            .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
            .expect("import");
        manager.activate("home.conf").await.expect("activate");
        let original = manager.active().expect("active");
        let marker = fake
            .launch_marker_for(OWNED_INTERFACE_NAME)
            .expect("marker");
        intent_store
            .save(&PersistedActivationIntent {
                profile_name: "home.conf".to_string(),
                interface: OWNED_INTERFACE_NAME.to_string(),
                launch_marker: marker,
            })
            .await
            .expect("recreate stale intent");

        let restarted_store = WireGuardProfileStore::new(dir.path().join("wireguard"));
        let same_provider: std::sync::Arc<dyn VpnProvider> = fake.clone();
        let restarted_driver = WireGuardVpnDriver::new(same_provider, restarted_store);
        let restarted = VpnManager::new(restarted_driver, active_profile_store);

        let outcome = restarted.reconcile().await.expect("reconcile");

        assert_eq!(outcome, ReconcileOutcome::Adopted(original));
        assert!(fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
        assert_eq!(intent_store.load().await.expect("load intent"), None);
    }

    #[tokio::test]
    async fn reconcile_reports_foreign_interface_under_owned_name_without_adopting_it() {
        let (manager, fake, _dir) = manager_with_store();
        fake.seed_foreign_link(OWNED_INTERFACE_NAME, OTHER_PRIVATE_KEY);

        let outcome = manager.reconcile().await.expect("reconcile");

        assert_eq!(outcome, ReconcileOutcome::ForeignInterfacePresent);

        assert!(manager.active().is_none());
        assert!(fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
    }

    #[tokio::test]
    async fn reconcile_after_restart_still_refuses_to_adopt_own_previous_interface() {
        let (manager, fake, _dir) = manager_with_store();
        manager
            .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
            .expect("import");
        manager.activate("home.conf").await.expect("activate");

        let dir2 = tempdir().expect("tempdir");

        let fresh_store = WireGuardProfileStore::new(dir2.path().join("wireguard"));
        let fresh_active_profile_store =
            ActiveProfileStore::new(dir2.path().join("active-profile.json"));
        let same_provider: std::sync::Arc<dyn VpnProvider> = fake.clone();
        let fresh_driver = WireGuardVpnDriver::new(same_provider, fresh_store);
        let fresh_manager = VpnManager::new(fresh_driver, fresh_active_profile_store);

        let outcome = fresh_manager.reconcile().await.expect("reconcile");

        assert_eq!(outcome, ReconcileOutcome::ForeignInterfacePresent);
        assert!(fresh_manager.active().is_none());
    }

    #[tokio::test]
    async fn reconcile_adopts_after_restart_when_persisted_record_matches_kernel_state() {
        let dir = tempdir().expect("tempdir");
        let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
        let active_profile_store = ActiveProfileStore::new(dir.path().join("active-profile.json"));
        let (provider, fake) = fake_provider();
        let driver = WireGuardVpnDriver::new(provider, store);
        let manager = VpnManager::new(driver, active_profile_store.clone());
        manager
            .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
            .expect("import");
        manager.activate("home.conf").await.expect("activate");
        let original_record = manager.active().expect("active after activate");

        let restarted_store = WireGuardProfileStore::new(dir.path().join("wireguard"));
        let same_provider: std::sync::Arc<dyn VpnProvider> = fake.clone();
        let restarted_driver = WireGuardVpnDriver::new(same_provider, restarted_store);
        let restarted = VpnManager::new(restarted_driver, active_profile_store);
        assert!(restarted.active().is_none());

        let outcome = restarted.reconcile().await.expect("reconcile");

        assert_eq!(outcome, ReconcileOutcome::Adopted(original_record.clone()));
        assert_eq!(restarted.active(), Some(original_record));
    }

    #[tokio::test]
    async fn reconcile_refuses_to_adopt_when_persisted_key_mismatches_kernel_state() {
        let dir = tempdir().expect("tempdir");
        let active_profile_store = ActiveProfileStore::new(dir.path().join("active-profile.json"));
        active_profile_store
            .save(&PersistedActiveProfile {
                profile_name: "home.conf".to_string(),
                interface: OWNED_INTERFACE_NAME.to_string(),
                ownership_proof_base64: encode_proof(
                    &WireGuardKey::parse(VALID_PUBLIC_KEY, "test").unwrap(),
                ),
            })
            .await
            .expect("save persisted record");

        let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
        let (provider, fake) = fake_provider();
        let driver = WireGuardVpnDriver::new(provider, store);
        let manager = VpnManager::new(driver, active_profile_store);
        fake.seed_foreign_link(OWNED_INTERFACE_NAME, OTHER_PRIVATE_KEY);

        let outcome = manager.reconcile().await.expect("reconcile");

        assert_eq!(outcome, ReconcileOutcome::ForeignInterfacePresent);
        assert!(manager.active().is_none());
        assert!(fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
    }

    #[tokio::test]
    async fn deactivate_clears_persisted_active_profile_record() {
        let dir = tempdir().expect("tempdir");
        let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
        let active_profile_store = ActiveProfileStore::new(dir.path().join("active-profile.json"));
        let (provider, _fake) = fake_provider();
        let driver = WireGuardVpnDriver::new(provider, store);
        let manager = VpnManager::new(driver, active_profile_store.clone());
        manager
            .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
            .expect("import");
        manager.activate("home.conf").await.expect("activate");
        assert!(active_profile_store.load().await.expect("load").is_some());

        manager.deactivate().await.expect("deactivate");

        assert_eq!(
            active_profile_store.load().await.expect("load"),
            None,
            "persisted record must be cleared once the owned interface is torn down"
        );
    }

    #[tokio::test]
    async fn shutdown_preserve_policy_leaves_owned_interface_running() {
        let (manager, fake, _dir) = manager_with_store();
        manager
            .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
            .expect("import");
        manager.activate("home.conf").await.expect("activate");

        manager
            .shutdown(ShutdownPolicy::PreserveInterfaces)
            .await
            .expect("shutdown");

        assert!(manager.active().is_some());
        assert!(fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
    }

    #[tokio::test]
    async fn shutdown_restore_policy_tears_down_owned_interface() {
        let (manager, fake, _dir) = manager_with_store();
        manager
            .import_profile("home.conf", valid_config(VALID_PRIVATE_KEY).as_bytes())
            .expect("import");
        manager.activate("home.conf").await.expect("activate");

        manager
            .shutdown(ShutdownPolicy::RestoreInterfaces)
            .await
            .expect("shutdown");

        assert!(manager.active().is_none());
        assert!(!fake.link_exists(OWNED_INTERFACE_NAME).await.unwrap());
    }

    #[tokio::test]
    async fn shutdown_is_noop_when_nothing_is_active() {
        let (manager, _fake, _dir) = manager_with_store();

        manager
            .shutdown(ShutdownPolicy::RestoreInterfaces)
            .await
            .expect("shutdown");
        manager
            .shutdown(ShutdownPolicy::PreserveInterfaces)
            .await
            .expect("shutdown");

        assert!(manager.active().is_none());
    }

    #[test]
    fn ownership_record_round_trip_matches_kernel_reported_key() {
        let private_key = WireGuardKey::parse(VALID_PRIVATE_KEY, "test").unwrap();
        let expected_public = fake_vpn_public_key(&private_key);

        let record = OwnedInterfaceRecord {
            interface: OWNED_INTERFACE_NAME.to_string(),
            ownership_proof: expected_public.clone(),
            profile_name: "home.conf".to_string(),
        };

        assert_eq!(record.ownership_proof, expected_public);
        assert_eq!(record.interface, OWNED_INTERFACE_NAME);
    }
}
