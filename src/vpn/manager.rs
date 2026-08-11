use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;

use crate::config::ShutdownPolicy;
use crate::vpn::active_profile::{ActiveProfileError, ActiveProfileStore, PersistedActiveProfile};
use crate::vpn::store::WireGuardProfileSummary;
use crate::vpn::{VpnDriver, VpnDriverError};

pub const OWNED_INTERFACE_NAME: &str = "tm-wg0";

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

    #[error(
        "refusing to modify interface '{0}': it no longer matches the recorded ownership proof \
         (observed value differs from what this daemon created it with, or the interface is \
         missing) — treating it as foreign"
    )]
    OwnershipProofFailed(String),
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
    owned: Mutex<Option<OwnedInterfaceRecord<D::OwnershipProof>>>,
    active_profile_store: ActiveProfileStore,

    activation_lock: AsyncMutex<()>,
}

impl<D: VpnDriver> VpnManager<D> {
    pub fn new(driver: D, active_profile_store: ActiveProfileStore) -> Self {
        Self {
            driver,
            owned: Mutex::new(None),
            active_profile_store,
            activation_lock: AsyncMutex::new(()),
        }
    }

    pub fn list_profiles(&self) -> Result<Vec<WireGuardProfileSummary>, ManagerError> {
        Ok(self.driver.list_profiles()?)
    }

    pub fn import_profile(&self, name: &str, raw: &[u8]) -> Result<String, ManagerError> {
        self.driver.import_profile(name, raw)?;
        Ok(name.to_string())
    }

    pub fn delete_profile(&self, name: &str) -> Result<(), ManagerError> {
        Ok(self.driver.delete_profile(name)?)
    }

    pub fn active(&self) -> Option<OwnedInterfaceRecord<D::OwnershipProof>> {
        self.owned.lock().expect("owned mutex poisoned").clone()
    }

    pub async fn status(&self) -> Result<Option<VpnActiveStatus>, ManagerError> {
        let Some(record) = self.active() else {
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
        let profile = self.driver.read_profile(name)?;

        if self.owned.lock().expect("owned mutex poisoned").is_some() {
            return Err(ManagerError::AlreadyActive);
        }

        if self.driver.link_exists(OWNED_INTERFACE_NAME).await? {
            return Err(ManagerError::ForeignInterfaceConflict(
                OWNED_INTERFACE_NAME.to_string(),
            ));
        }

        Ok(profile)
    }

    pub async fn snapshot(&self) -> Result<VpnInterfaceSnapshot<D::OwnershipProof>, ManagerError> {
        let existed_before = self.driver.link_exists(OWNED_INTERFACE_NAME).await?;
        let (ownership_proof, was_up) = if existed_before {
            (
                self.driver
                    .read_ownership_proof(OWNED_INTERFACE_NAME)
                    .await?,
                self.driver.is_up(OWNED_INTERFACE_NAME).await?,
            )
        } else {
            (None, false)
        };
        Ok(VpnInterfaceSnapshot {
            interface: OWNED_INTERFACE_NAME.to_string(),
            existed_before,
            ownership_proof,
            was_up,
        })
    }

    pub async fn activate(&self, name: &str) -> Result<(), ManagerError> {
        let _activation_guard = self.activation_lock.lock().await;

        let profile = self.plan_activation(name).await?;
        let snapshot = self.snapshot().await?;

        if let Err(error) = self.activate_inner(name, &profile).await {
            let _ = self.rollback(&snapshot).await;
            return Err(error);
        }

        let record = self.active().expect("activate_inner set the owned record");
        let encoded = BASE64.encode(self.driver.encode_ownership_proof(&record.ownership_proof));
        if let Err(error) = self
            .active_profile_store
            .save(&PersistedActiveProfile {
                profile_name: record.profile_name.clone(),
                interface: record.interface.clone(),
                ownership_proof_base64: encoded,
            })
            .await
        {
            let _ = self.rollback(&snapshot).await;
            return Err(ManagerError::ActiveProfile(error));
        }

        Ok(())
    }

    async fn activate_inner(&self, name: &str, profile: &D::Profile) -> Result<(), ManagerError> {
        let ownership_proof = self.driver.activate(OWNED_INTERFACE_NAME, profile).await?;

        *self.owned.lock().expect("owned mutex poisoned") = Some(OwnedInterfaceRecord {
            interface: OWNED_INTERFACE_NAME.to_string(),
            ownership_proof,
            profile_name: name.to_string(),
        });

        Ok(())
    }

    pub async fn deactivate(&self) -> Result<(), ManagerError> {
        let _activation_guard = self.activation_lock.lock().await;

        let record = self
            .owned
            .lock()
            .expect("owned mutex poisoned")
            .clone()
            .ok_or(ManagerError::NotActive)?;

        self.assert_still_owned(&record).await?;

        self.driver.deactivate(&record.interface).await?;

        *self.owned.lock().expect("owned mutex poisoned") = None;

        let _ = self.active_profile_store.clear().await;
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
            *self.owned.lock().expect("owned mutex poisoned") = None;
            return Ok(());
        }

        let record = self.owned.lock().expect("owned mutex poisoned").clone();
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
        *self.owned.lock().expect("owned mutex poisoned") = None;
        Ok(())
    }

    pub async fn reconcile(&self) -> Result<ReconcileOutcome<D::OwnershipProof>, ManagerError> {
        if !self.driver.link_exists(OWNED_INTERFACE_NAME).await? {
            return Ok(ReconcileOutcome::Absent);
        }

        let persisted = self.active_profile_store.load().await?;
        if let Some(persisted) = persisted {
            if persisted.interface == OWNED_INTERFACE_NAME {
                let decoded = BASE64
                    .decode(&persisted.ownership_proof_base64)
                    .ok()
                    .and_then(|bytes| self.driver.decode_ownership_proof(&bytes).ok());
                if let Some(persisted_proof) = decoded {
                    let observed_proof = self
                        .driver
                        .read_ownership_proof(OWNED_INTERFACE_NAME)
                        .await?;
                    if observed_proof.as_ref() == Some(&persisted_proof) {
                        let record = OwnedInterfaceRecord {
                            interface: OWNED_INTERFACE_NAME.to_string(),
                            ownership_proof: persisted_proof,
                            profile_name: persisted.profile_name,
                        };
                        *self.owned.lock().expect("owned mutex poisoned") = Some(record.clone());
                        return Ok(ReconcileOutcome::Adopted(record));
                    }
                } else {
                    tracing::warn!(
                        interface = OWNED_INTERFACE_NAME,
                        "persisted active-profile ownership proof could not be decoded; \
                         treating the surviving interface as foreign rather than adopting it"
                    );
                }
            }
        }

        Ok(ReconcileOutcome::ForeignInterfacePresent)
    }

    pub async fn shutdown(&self, policy: ShutdownPolicy) -> Result<(), ManagerError> {
        if self.active().is_none() {
            return Ok(());
        }
        match policy {
            ShutdownPolicy::PreserveInterfaces => Ok(()),
            ShutdownPolicy::RestoreInterfaces => self.deactivate().await,
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
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    use async_trait::async_trait;
    use ipnet::IpNet;
    use sha2::{Digest, Sha256};
    use tempfile::tempdir;

    use super::*;
    use crate::vpn::store::WireGuardProfileStore;
    use crate::vpn::wireguard::{WireGuardKey, WireGuardPeerConfig, WireGuardVpnDriver};
    use crate::vpn::{ProviderError, VpnProvider};

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

    fn fake_public_key(private_key: &WireGuardKey) -> WireGuardKey {
        let digest = Sha256::digest(private_key.0);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest[..32]);
        WireGuardKey(bytes)
    }

    #[derive(Debug, Clone)]
    struct FakeLink {
        private_key: WireGuardKey,
        up: bool,
    }

    #[derive(Default)]
    struct FakeVpnProvider {
        links: StdMutex<HashMap<String, FakeLink>>,
    }

    impl FakeVpnProvider {
        fn seed_foreign_link(&self, name: &str, private_key: &str) {
            let key = WireGuardKey::parse(private_key, "test").unwrap();
            self.links.lock().unwrap().insert(
                name.to_string(),
                FakeLink {
                    private_key: key,
                    up: true,
                },
            );
        }
    }

    #[async_trait]
    impl VpnProvider for FakeVpnProvider {
        async fn link_exists(&self, name: &str) -> Result<bool, ProviderError> {
            Ok(self.links.lock().unwrap().contains_key(name))
        }

        async fn create_link(
            &self,
            name: &str,
            private_key: &WireGuardKey,
            _listen_port: Option<u16>,
        ) -> Result<(), ProviderError> {
            let mut links = self.links.lock().unwrap();
            if links.contains_key(name) {
                return Err(ProviderError::CommandFailed {
                    command: "ip",
                    status: "exit code: 1".to_string(),
                    stderr: "link already exists".to_string(),
                });
            }
            links.insert(
                name.to_string(),
                FakeLink {
                    private_key: private_key.clone(),
                    up: false,
                },
            );
            Ok(())
        }

        async fn set_addresses(
            &self,
            name: &str,
            _addresses: &[IpNet],
        ) -> Result<(), ProviderError> {
            self.require_link(name)
        }

        async fn set_peers(
            &self,
            name: &str,
            _peers: &[WireGuardPeerConfig],
        ) -> Result<(), ProviderError> {
            self.require_link(name)
        }

        async fn set_link_up(&self, name: &str) -> Result<(), ProviderError> {
            let mut links = self.links.lock().unwrap();
            let link = links
                .get_mut(name)
                .ok_or_else(|| ProviderError::NotFound(name.to_string()))?;
            link.up = true;
            Ok(())
        }

        async fn set_link_down(&self, name: &str) -> Result<(), ProviderError> {
            let mut links = self.links.lock().unwrap();
            let link = links
                .get_mut(name)
                .ok_or_else(|| ProviderError::NotFound(name.to_string()))?;
            link.up = false;
            Ok(())
        }

        async fn delete_link(&self, name: &str) -> Result<(), ProviderError> {
            self.links
                .lock()
                .unwrap()
                .remove(name)
                .map(|_| ())
                .ok_or_else(|| ProviderError::NotFound(name.to_string()))
        }

        async fn public_key(&self, name: &str) -> Result<Option<WireGuardKey>, ProviderError> {
            Ok(self
                .links
                .lock()
                .unwrap()
                .get(name)
                .map(|link| fake_public_key(&link.private_key)))
        }

        async fn is_up(&self, name: &str) -> Result<bool, ProviderError> {
            Ok(self
                .links
                .lock()
                .unwrap()
                .get(name)
                .map(|link| link.up)
                .unwrap_or(false))
        }
    }

    impl FakeVpnProvider {
        fn require_link(&self, name: &str) -> Result<(), ProviderError> {
            if self.links.lock().unwrap().contains_key(name) {
                Ok(())
            } else {
                Err(ProviderError::NotFound(name.to_string()))
            }
        }
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
        )
        .await
        .unwrap();
        let ownership_proof = fake
            .public_key(OWNED_INTERFACE_NAME)
            .await
            .unwrap()
            .unwrap();
        *manager.owned.lock().unwrap() = Some(OwnedInterfaceRecord {
            interface: OWNED_INTERFACE_NAME.to_string(),
            ownership_proof,
            profile_name: "home.conf".to_string(),
        });

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
        let expected_public = fake_public_key(&private_key);

        let record = OwnedInterfaceRecord {
            interface: OWNED_INTERFACE_NAME.to_string(),
            ownership_proof: expected_public.clone(),
            profile_name: "home.conf".to_string(),
        };

        assert_eq!(record.ownership_proof, expected_public);
        assert_eq!(record.interface, OWNED_INTERFACE_NAME);
    }
}
