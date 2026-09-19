use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::config::{InterfaceConfig, InterfaceRole};
use crate::core::desired::DesiredNetworkState;
use crate::core::mutation::NetworkMutationGate;
use crate::wifi::{secret::WifiPassphrase, store::PassphraseStore};
use crate::core::interface::{
    DhcpChangeAction, InterfaceChangePlan, InterfaceManager, InterfaceSnapshot,
};
use crate::dhcp::supervisor::{DhcpServiceSpec, DhcpSupervisor};

/// How long an apply waits for convergence to reach what it proposed.
///
/// A deadline, not a poll: nothing here wakes up to ask whether anything has
/// changed. It exists so that a converger which has stopped — a bug, or a
/// daemon on its way down — turns into an error the operator can see instead of
/// a request that never answers.
const CONVERGENCE_DEADLINE: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingNetworkChange {
    pub token: String,
    pub interface: String,
    pub rollback_timeout_seconds: u64,
    pub expires_at_unix: u64,
}

#[derive(Serialize, Deserialize)]
struct InterfaceJournal {
    version: u32,
    token: String,
    snapshot: InterfaceSnapshot,
    #[serde(default)]
    secret: Option<SecretSnapshot>,
}

#[derive(Clone, Serialize, Deserialize)]
struct SecretSnapshot {
    previous: Option<zeroize::Zeroizing<String>>,
}

impl SecretSnapshot {
    fn restore(&self, store: &PassphraseStore, interface: &str) -> Result<()> {
        match &self.previous {
            Some(secret) => store.set(interface, &WifiPassphrase::new(secret.to_string())?)?,
            None => store.clear(interface)?,
        }
        Ok(())
    }
}

/// Restore unconfirmed interface snapshots before applying startup configuration.
/// In particular, startup otherwise skips interfaces that were previously unmanaged.
pub async fn recover_interface_transactions(
    state_dir: &std::path::Path,
    manager: &InterfaceManager,
    committed: &crate::state::overrides::RuntimeOverrides,
) -> Result<()> {
    let root = state_dir.to_path_buf();
    let (store, records) = tokio::task::spawn_blocking(move || -> Result<_> {
        let store = crate::state::private_store::PrivateJsonDirectory::open(
            root,
            "interface-transactions",
        )?;
        let mut records = Vec::new();
        for name in store.keys()? {
            let bytes = store
                .read(&name)?
                .ok_or_else(|| anyhow::anyhow!("interface journal disappeared"))?;
            let record: InterfaceJournal = serde_json::from_slice(&bytes)?;
            anyhow::ensure!(
                matches!(record.version, 1 | 2) && record.snapshot.name == name,
                "invalid interface transaction journal"
            );
            records.push((name, record));
        }
        Ok((store, records))
    })
    .await??;
    for (name, record) in records {
        if committed.committed_interface_transactions.get(&name) != Some(&record.token) {
            if let Some(secret) = &record.secret {
                secret.restore(&PassphraseStore::new(state_dir.join("wifi/psk")), &name)?;
            }
            crate::wifi::lifecycle::stop_recorded_interface(state_dir, &name).await?;
            manager.rollback(&record.snapshot).await?;
            tracing::warn!(interface = %name, "restored interrupted interface transaction");
        }
        let store = store.clone();
        tokio::task::spawn_blocking(move || store.remove(&name)).await??;
    }
    Ok(())
}

/// Applies interface changes by proposing them as desired state.
///
/// The manager does not write to the kernel. It puts a change into the
/// tentative layer of [`DesiredNetworkState`], waits for the converger to
/// report a pass that had already seen it, and keeps the bookkeeping —
/// token, expiry, rollback timer — that turns "the machine now looks like
/// this" into "and it stays that way only if you confirm".
#[derive(Clone)]
pub struct NetworkTransactionManager {
    inner: Arc<Inner>,
}

struct Inner {
    interface_manager: InterfaceManager,
    rollback_timeout: Duration,
    pending: Mutex<HashMap<String, PendingTransaction>>,
    /// What the interfaces looked like before the daemon touched anything,
    /// restored on shutdown. Nothing to do with transactions: by then the
    /// converger is gone, so this is the one path that still writes directly.
    baselines: Mutex<HashMap<String, InterfaceSnapshot>>,
    operation_lock: Mutex<()>,
    runtime_gate: std::sync::Mutex<Option<Arc<NetworkMutationGate>>>,
    token_counter: AtomicU64,
    dhcp: Option<DhcpSupervisor>,
    default_lease_seconds: u32,
    /// Where proposals go. Replaceable because the daemon builds the service
    /// before it builds the converger, and the two have to share one state —
    /// see [`NetworkTransactionManager::set_desired_state`].
    desired: std::sync::Mutex<DesiredNetworkState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingPhase {
    AwaitingCommit,
    RollbackRequired,
}

#[derive(Clone)]
struct PendingTransaction {
    info: PendingNetworkChange,
    target: InterfaceConfig,
    allow_management_change: bool,
    phase: PendingPhase,
    snapshot: InterfaceSnapshot,
    previous_config: Option<InterfaceConfig>,
    secret: Option<SecretSnapshot>,
}

impl NetworkTransactionManager {
    pub(crate) fn set_runtime_gate(&self, gate: Arc<NetworkMutationGate>) {
        *self.inner.runtime_gate.lock().expect("runtime gate lock") = Some(gate);
    }

    fn runtime_gate(&self) -> Option<Arc<NetworkMutationGate>> {
        self.inner.runtime_gate.lock().expect("runtime gate lock").clone()
    }

    pub(crate) async fn owns_address(
        &self,
        interface: &str,
        address: &crate::netlink::Ipv4AddressInfo,
    ) -> bool {
        self.inner
            .interface_manager
            .owns_address(interface, address)
            .await
            || address.owner() == crate::netlink::AddressOwner::TrafficMasqDhcp
    }

    pub fn new(
        interface_manager: InterfaceManager,
        rollback_timeout: Duration,
        desired: DesiredNetworkState,
    ) -> Self {
        Self::new_with_baselines(interface_manager, rollback_timeout, Vec::new(), desired)
    }

    pub fn new_with_baselines(
        interface_manager: InterfaceManager,
        rollback_timeout: Duration,
        baselines: Vec<InterfaceSnapshot>,
        desired: DesiredNetworkState,
    ) -> Self {
        Self::build(
            interface_manager,
            rollback_timeout,
            baselines,
            None,
            1,
            desired,
        )
    }

    pub fn new_with_services(
        interface_manager: InterfaceManager,
        rollback_timeout: Duration,
        baselines: Vec<InterfaceSnapshot>,
        dhcp: DhcpSupervisor,
        default_lease_seconds: u32,
        desired: DesiredNetworkState,
    ) -> Self {
        Self::build(
            interface_manager,
            rollback_timeout,
            baselines,
            Some(dhcp),
            default_lease_seconds,
            desired,
        )
    }

    fn build(
        interface_manager: InterfaceManager,
        rollback_timeout: Duration,
        baselines: Vec<InterfaceSnapshot>,
        dhcp: Option<DhcpSupervisor>,
        default_lease_seconds: u32,
        desired: DesiredNetworkState,
    ) -> Self {
        let baselines = baselines
            .into_iter()
            .map(|snapshot| (snapshot.name.clone(), snapshot))
            .collect();
        Self {
            inner: Arc::new(Inner {
                interface_manager,
                rollback_timeout,
                pending: Mutex::new(HashMap::new()),
                baselines: Mutex::new(baselines),
                operation_lock: Mutex::new(()),
                runtime_gate: std::sync::Mutex::new(None),
                token_counter: AtomicU64::new(0),
                dhcp,
                default_lease_seconds,
                desired: std::sync::Mutex::new(desired),
            }),
        }
    }

    /// Point the manager at the desired state the converger is driving.
    ///
    /// Proposing into a state nobody converges would report success without
    /// anything having happened, so the daemon has to call this once both
    /// halves exist.
    pub fn set_desired_state(&self, desired: DesiredNetworkState) {
        *self
            .inner
            .desired
            .lock()
            .expect("desired state lock is never held across a panic") = desired;
    }

    fn desired(&self) -> DesiredNetworkState {
        self.inner
            .desired
            .lock()
            .expect("desired state lock is never held across a panic")
            .clone()
    }

    pub async fn dry_run(
        &self,
        interface: &str,
        config: &InterfaceConfig,
        current_role: Option<InterfaceRole>,
        allow_management_change: bool,
    ) -> Result<InterfaceChangePlan> {
        self.dry_run_transition(
            interface,
            config,
            None,
            current_role,
            allow_management_change,
        )
        .await
    }

    pub async fn dry_run_transition(
        &self,
        interface: &str,
        config: &InterfaceConfig,
        previous_config: Option<&InterfaceConfig>,
        current_role: Option<InterfaceRole>,
        allow_management_change: bool,
    ) -> Result<InterfaceChangePlan> {
        let mut plan = self
            .inner
            .interface_manager
            .plan_interface_transition(
                interface,
                config,
                previous_config,
                current_role,
                allow_management_change,
            )
            .await?;
        if let Some(dhcp) = &self.inner.dhcp {
            let current = dhcp.spec(interface).await;
            let target = DhcpServiceSpec::from_interface_config(
                interface,
                config,
                self.inner.default_lease_seconds,
            )?;
            plan.dhcp_action = match (current, target) {
                (None, None) => DhcpChangeAction::Unchanged,
                (None, Some(_)) => DhcpChangeAction::Start,
                (Some(_), None) => DhcpChangeAction::Stop,
                (Some(current), Some(target)) if current == target => DhcpChangeAction::Unchanged,
                (Some(_), Some(_)) => DhcpChangeAction::Reconfigure,
            };
        }
        Ok(plan)
    }

    pub async fn apply(
        &self,
        interface: &str,
        config: &InterfaceConfig,
        current_role: Option<InterfaceRole>,
        allow_management_change: bool,
    ) -> Result<PendingNetworkChange> {
        self.apply_transition(
            interface,
            config,
            None,
            current_role,
            allow_management_change,
        )
        .await
    }

    pub async fn apply_transition(
        &self,
        interface: &str,
        config: &InterfaceConfig,
        previous_config: Option<&InterfaceConfig>,
        current_role: Option<InterfaceRole>,
        allow_management_change: bool,
    ) -> Result<PendingNetworkChange> {
        self.apply_with_passphrase(interface, config, previous_config, current_role,
            allow_management_change, None).await
    }

    pub async fn apply_with_passphrase(
        &self, interface: &str, config: &InterfaceConfig,
        previous_config: Option<&InterfaceConfig>, current_role: Option<InterfaceRole>,
        allow_management_change: bool, passphrase: Option<WifiPassphrase>,
    ) -> Result<PendingNetworkChange> {
        let _operation = self.inner.operation_lock.lock().await;
        let gate = self.runtime_gate();
        let execution = match &gate { Some(gate) => Some(gate.execute().await), None => None };

        if self
            .inner
            .pending
            .lock()
            .await
            .values()
            .any(|pending| pending.info.interface == interface)
        {
            bail!("interface {interface} already has a pending network change");
        }

        // Planned before it is proposed. A change the planner refuses is the
        // operator's mistake and has to come back as one, immediately and with
        // the planner's own wording — not as a convergence failure a second
        // later, and never as a proposal the converger would keep retrying.
        self.dry_run_transition(
            interface,
            config,
            previous_config,
            current_role,
            allow_management_change,
        )
        .await?;

        // Reading, not writing: the first time a transaction touches an
        // interface, record what it looked like beforehand so shutdown can put
        // it back. Interfaces configured at startup are already in here.
        //
        // Also the one check that the interface exists at all. Convergence
        // skips what is not plugged in — correctly, it may come back — but a
        // person asking for a change to a missing interface has made a mistake
        // and needs to hear about it now.
        let snapshot = self.inner.interface_manager.snapshot(interface).await?;
        self.inner
            .baselines
            .lock()
            .await
            .entry(interface.to_string())
            .or_insert(snapshot.clone());

        let token = self.next_token();
        let desired = self.desired();
        let previous_config = desired.committed_interface(interface).await?;
        let store = PassphraseStore::new(desired.state_dir().join("wifi/psk"));
        let secret = if passphrase.is_some() {
            Some(SecretSnapshot { previous: store.get(interface)?.map(|value|
                zeroize::Zeroizing::new(value.expose().to_owned())) })
        } else { None };
        self.write_journal_record(&token, snapshot.clone(), secret.clone()).await?;
        let staged = match passphrase {
            Some(passphrase) => store.set(interface, &passphrase).map_err(anyhow::Error::from),
            None => Ok(()),
        };
        if staged.is_ok() {
            desired.propose(&token, interface, config.clone(), allow_management_change).await;
        }
        drop(execution);
        let applied = match staged {
            Ok(()) => self.await_convergence(&desired, interface).await,
            Err(error) => Err(error),
        };
        if let Err(error) = applied {
            let execution = match &gate { Some(gate) => Some(gate.execute().await), None => None };
            let secret_restored = match &secret {
                Some(secret) => secret.restore(&store, interface),
                None => Ok(()),
            };
            desired.restore(&token, snapshot.clone(), previous_config.clone()).await;
            drop(execution);
            let restoration = match secret_restored {
                Ok(()) => self.await_convergence(&desired, interface).await,
                Err(error) => Err(error),
            };
            let rollback = match restoration {
                Ok(()) => self.clear_journal(interface).await,
                Err(error) => Err(error),
            };
            if let Err(rollback_error) = rollback {
                // The requested state is no longer desired, but until a fresh
                // convergence pass proves the committed state was restored the
                // transaction must stay visible and block overlapping network
                // mutations. The token is rollback-only: a failed candidate
                // must never become committable merely because compensation
                // also failed.
                let rollback_timeout_seconds = self.inner.rollback_timeout.as_secs();
                let info = PendingNetworkChange {
                    token: token.clone(),
                    interface: interface.to_string(),
                    rollback_timeout_seconds,
                    expires_at_unix: current_unix_time()
                        .saturating_add(rollback_timeout_seconds),
                };
                self.inner.pending.lock().await.insert(
                    token.clone(),
                    PendingTransaction {
                        info,
                        target: config.clone(),
                        allow_management_change,
                        phase: PendingPhase::RollbackRequired,
                        snapshot: snapshot.clone(),
                        previous_config: previous_config.clone(),
                        secret: secret.clone(),
                    },
                );
                self.spawn_rollback_timer(token.clone());
                bail!(
                    "network change failed to converge: {error}; rollback also failed: {rollback_error}; recovery remains pending as token {token}"
                );
            }
            desired.withdraw(&token).await;
            return Err(error);
        }

        // Dated from here, not from the proposal: the confirmation window is
        // the time the operator has to look at a machine that already changed,
        // and it starts when the machine changed.
        let rollback_timeout_seconds = self.inner.rollback_timeout.as_secs();
        let info = PendingNetworkChange {
            token,
            interface: interface.to_string(),
            rollback_timeout_seconds,
            expires_at_unix: current_unix_time().saturating_add(rollback_timeout_seconds),
        };

        self.inner.pending.lock().await.insert(
            info.token.clone(),
            PendingTransaction {
                info: info.clone(),
                target: config.clone(),
                allow_management_change,
                phase: PendingPhase::AwaitingCommit,
                snapshot,
                previous_config,
                secret,
            },
        );

        tracing::info!(
            interface = %interface,
            token = %info.token,
            rollback_timeout_seconds,
            managed = config.managed,
            "network change converged; awaiting commit before the rollback timer fires"
        );

        self.spawn_rollback_timer(info.token.clone());
        Ok(info)
    }

    /// Wait for the converger to reach what was just proposed.
    ///
    /// The version is read after the proposal, so only a pass that had already
    /// seen it can answer — an older pass knows nothing about this change and
    /// must not be mistaken for a success.
    async fn await_convergence(
        &self,
        desired: &DesiredNetworkState,
        interface: &str,
    ) -> Result<()> {
        if !desired.has_converger() {
            return Ok(());
        }

        let version = desired.version();
        let pass = match tokio::time::timeout(CONVERGENCE_DEADLINE, desired.pass_covering(version))
            .await
        {
            Ok(pass) => pass,
            Err(_) => bail!(
                "timed out waiting for interface {interface} to be converged to the requested configuration"
            ),
        };

        if let Some(error) = pass.error {
            bail!("convergence failed: {error}");
        }
        match pass.failures.get(interface) {
            Some(error) => bail!("{error}"),
            None => Ok(()),
        }
    }

    pub async fn commit(&self, token: &str) -> Result<PendingNetworkChange> {
        self.commit_with(token, |_, _, _| async { Ok(()) }).await
    }

    pub async fn commit_with<F, Fut>(&self, token: &str, persist: F) -> Result<PendingNetworkChange>
    where
        F: FnOnce(String, InterfaceConfig, bool) -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        let _operation = self.inner.operation_lock.lock().await;
        let (interface, target, allow_management_change) = {
            let pending = self.inner.pending.lock().await;
            let pending = pending
                .get(token)
                .ok_or_else(|| anyhow::anyhow!("pending network change not found: {token}"))?;
            anyhow::ensure!(
                pending.phase == PendingPhase::AwaitingCommit,
                "network change {token} failed during apply and is rollback-only"
            );
            (
                pending.info.interface.clone(),
                pending.target.clone(),
                pending.allow_management_change,
            )
        };

        persist(interface.clone(), target, allow_management_change).await?;

        // Only once the override carries the change: withdrawing the tentative
        // layer first would make the desired state briefly describe the old
        // configuration, and the converger would take the machine back to it.
        self.desired().withdraw(token).await;

        let pending = self
            .inner
            .pending
            .lock()
            .await
            .remove(token)
            .expect("pending transaction cannot change while operation lock is held");

        if let Err(error) = self.clear_journal(&interface).await {
            tracing::warn!(%error, "failed to remove committed interface journal");
        }
        tracing::info!(
            interface = %interface,
            %token,
            "network change committed; the new configuration is now persisted"
        );
        Ok(pending.info)
    }

    /// Restore the pre-apply snapshot through convergence. A failed restoration
    /// is rollback-only and remains journaled and visible until a retry succeeds.
    pub async fn rollback(&self, token: &str) -> Result<PendingNetworkChange> {
        let _operation = self.inner.operation_lock.lock().await;
        let pending = {
            let mut pending = self.inner.pending.lock().await;
            let entry = pending.get_mut(token)
                .ok_or_else(|| anyhow::anyhow!("pending network change not found: {token}"))?;
            entry.phase = PendingPhase::RollbackRequired;
            entry.clone()
        };
        tracing::info!(
            interface = %pending.info.interface,
            %token,
            "network change is being rolled back; the committed configuration will be converged to"
        );
        let desired = self.desired();
        let gate = self.runtime_gate();
        let execution = match &gate { Some(gate) => Some(gate.execute().await), None => None };
        if let Some(secret) = &pending.secret {
            secret.restore(&PassphraseStore::new(desired.state_dir().join("wifi/psk")), &pending.info.interface)?;
        }
        desired.restore(token, pending.snapshot.clone(), pending.previous_config.clone()).await;
        drop(execution);
        if let Err(error) = self
            .await_convergence(&desired, &pending.info.interface)
            .await
        {
            // Keep both the pending record and recovery journal. The desired
            // state already points back at the committed configuration, so a
            // later retry only needs to verify convergence; reporting success
            // here would falsely claim the runtime had been restored.
            bail!(
                "failed to confirm rollback convergence for interface {}: {error}",
                pending.info.interface
            );
        }

        self.clear_journal(&pending.info.interface).await?;
        desired.withdraw(token).await;
        self.inner.pending.lock().await.remove(token);
        Ok(pending.info)
    }

    pub async fn rollback_all_pending(&self) -> Result<()> {
        let tokens: Vec<_> = self.inner.pending.lock().await.keys().cloned().collect();
        let mut errors = Vec::new();
        for token in tokens {
            if let Err(error) = self.rollback(&token).await {
                errors.push(format!("{token}: {error}"));
            }
        }
        anyhow::ensure!(errors.is_empty(), "failed to roll back pending network changes: {}", errors.join("; "));
        Ok(())
    }

    pub async fn restore_baselines(&self) -> Result<()> {
        let rollback_error = self.rollback_all_pending().await.err();
        let _operation = self.inner.operation_lock.lock().await;
        let mut baselines: Vec<_> = self
            .inner
            .baselines
            .lock()
            .await
            .values()
            .cloned()
            .collect();
        baselines.sort_by(|left, right| left.name.cmp(&right.name));
        let mut errors: Vec<String> = rollback_error.into_iter().map(|error| error.to_string()).collect();
        for snapshot in baselines.into_iter().rev() {
            if let Err(error) = self.inner.interface_manager.rollback(&snapshot).await {
                errors.push(format!("{}: {error}", snapshot.name));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            bail!(
                "failed to restore interface baselines: {}",
                errors.join("; ")
            )
        }
    }

    pub async fn pending(&self) -> Vec<PendingNetworkChange> {
        let mut pending: Vec<_> = self
            .inner
            .pending
            .lock()
            .await
            .values()
            .map(|pending| pending.info.clone())
            .collect();
        pending.sort_by(|left, right| left.token.cmp(&right.token));
        pending
    }

    #[cfg(test)]
    async fn write_journal(&self, token: &str, snapshot: InterfaceSnapshot) -> Result<()> {
        self.write_journal_record(token, snapshot, None).await
    }

    async fn write_journal_record(&self, token: &str, snapshot: InterfaceSnapshot, secret: Option<SecretSnapshot>) -> Result<()> {
        let root = self.desired().state_dir().to_path_buf();
        let record = InterfaceJournal {
            version: 2,
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

    async fn clear_journal(&self, interface: &str) -> Result<()> {
        let root = self.desired().state_dir().to_path_buf();
        let interface = interface.to_owned();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let store = crate::state::private_store::PrivateJsonDirectory::open(
                root,
                "interface-transactions",
            )?;
            store.remove(&interface)?;
            Ok(())
        })
        .await??;
        Ok(())
    }

    fn spawn_rollback_timer(&self, token: String) {
        let manager = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(manager.inner.rollback_timeout).await;
            if let Err(error) = manager.rollback(&token).await {
                if !error.to_string().contains("not found") {
                    tracing::error!(%token, %error, "automatic network rollback failed");
                }
            } else {
                tracing::warn!(%token, "network change automatically rolled back after timeout");
            }
        });
    }

    fn next_token(&self) -> String {
        let counter = self.inner.token_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("{}-{counter}-{nanos}", std::process::id())
    }
}

fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use crate::netlink::AddressOwnership;
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;

    use anyhow::Result;
    use async_trait::async_trait;
    use tempfile::tempdir;
    use tokio::sync::Mutex;

    use crate::config::{AppConfig, InterfaceConfig, InterfaceRole};
    use crate::core::override_manager::RuntimeOverrideManager;
    use crate::core::ownership::AddressOwnershipJournal;
    use crate::netlink::{Ipv4AddressInfo, NetworkInterface, NetworkProvider};

    use super::*;

    #[derive(Debug)]
    struct FakeNetwork {
        interface: Mutex<NetworkInterface>,
        addresses: Mutex<Vec<Ipv4AddressInfo>>,
    }

    #[async_trait]
    impl NetworkProvider for FakeNetwork {
        async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
            Ok(vec![self.interface.lock().await.clone()])
        }

        async fn list_ipv4_addresses(&self, _interface: &str) -> Result<Vec<Ipv4AddressInfo>> {
            Ok(self.addresses.lock().await.clone())
        }

        async fn set_link_up(&self, _name: &str) -> Result<()> {
            self.interface.lock().await.is_up = true;
            Ok(())
        }

        async fn set_link_down(&self, _name: &str) -> Result<()> {
            self.interface.lock().await.is_up = false;
            Ok(())
        }

        async fn add_ipv4_address(
            &self,
            _interface: &str,
            address: Ipv4Addr,
            prefix_len: u8,
            ownership: AddressOwnership,
        ) -> Result<()> {
            self.addresses.lock().await.push(Ipv4AddressInfo {
                interface_index: 1,
                address,
                prefix_len,
                protocol: ownership.protocol(),
            });
            Ok(())
        }

        async fn delete_ipv4_address(
            &self,
            _interface: &str,
            address: Ipv4Addr,
            prefix_len: u8,
        ) -> Result<()> {
            self.addresses
                .lock()
                .await
                .retain(|current| current.address != address || current.prefix_len != prefix_len);
            Ok(())
        }
    }

    const COMMITTED: &str = "192.168.1.10/24";
    const PROPOSED: &str = "192.168.50.1/24";

    fn interface_config(cidr: &str) -> InterfaceConfig {
        InterfaceConfig {
            nat: true,
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some(cidr.parse().expect("network")),
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        }
    }

    fn fake_network() -> Arc<FakeNetwork> {
        Arc::new(FakeNetwork {
            interface: Mutex::new(NetworkInterface {
                is_wireless: false,
                index: 1,
                name: "test0".to_string(),
                is_up: false,
                rx_bytes: 0,
                tx_bytes: 0,
            }),
            addresses: Mutex::new(vec![Ipv4AddressInfo {
                interface_index: 1,
                address: Ipv4Addr::new(192, 168, 1, 10),
                prefix_len: 24,
                protocol: None,
            }]),
        })
    }

    async fn desired_state(directory: &std::path::Path) -> DesiredNetworkState {
        let mut base = AppConfig::default();
        base.network
            .interfaces
            .insert("test0".to_string(), interface_config(COMMITTED));
        let overrides = RuntimeOverrideManager::load(directory, &base)
            .await
            .expect("overrides");
        DesiredNetworkState::new(base, overrides)
    }

    /// A stand-in for the daemon's convergence loop.
    ///
    /// Small on purpose, but it keeps the one ordering rule the real loop
    /// depends on: the version is read before the pass and published after, so
    /// a pass only ever answers for changes it could have seen.
    fn spawn_converger(
        desired: DesiredNetworkState,
        provider: Arc<FakeNetwork>,
    ) -> tokio::task::JoinHandle<()> {
        desired.attach_converger();
        tokio::spawn(async move {
            let interfaces = InterfaceManager::new(provider, AddressOwnershipJournal::in_memory());
            loop {
                let version = desired.version();
                let mut failures = BTreeMap::new();
                let effective = desired.effective().await.expect("effective config");
                let allowed = desired.management_allowlist().await;
                for (name, config) in &effective.network.interfaces {
                    if let Err(error) = interfaces
                        .apply_interface(name, config, Some(config.role), allowed.contains(name))
                        .await
                    {
                        failures.insert(name.clone(), error.to_string());
                    }
                }
                desired.report_pass(version, failures);
                desired.changed().await;
            }
        })
    }

    async fn addresses(provider: &FakeNetwork) -> Vec<Ipv4Addr> {
        provider
            .addresses
            .lock()
            .await
            .iter()
            .map(|address| address.address)
            .collect()
    }

    #[tokio::test]
    async fn a_global_convergence_failure_is_not_success_for_an_interface() {
        let directory = tempdir().unwrap();
        let desired = desired_state(directory.path()).await;
        desired.attach_converger();
        desired
            .propose("pending", "test0", interface_config(PROPOSED), false)
            .await;
        desired.report_result(
            desired.version(),
            Err(anyhow::anyhow!("failed to list interfaces")),
        );
        let manager = NetworkTransactionManager::new(
            InterfaceManager::new(fake_network(), AddressOwnershipJournal::in_memory()),
            Duration::from_secs(60),
            desired.clone(),
        );
        let error = manager
            .await_convergence(&desired, "test0")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("failed to list interfaces"));
    }

    #[tokio::test]
    async fn restart_removes_unconfirmed_address_on_previously_unmanaged_interface() {
        let directory = tempdir().unwrap();
        let provider = fake_network();
        let interfaces =
            InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory());
        let desired = desired_state(directory.path()).await;
        let transactions =
            NetworkTransactionManager::new(interfaces.clone(), Duration::from_secs(60), desired);
        let snapshot = interfaces.snapshot("test0").await.unwrap();
        transactions
            .write_journal("interrupted", snapshot)
            .await
            .unwrap();
        interfaces
            .apply_interface(
                "test0",
                &interface_config(PROPOSED),
                Some(InterfaceRole::Output),
                true,
            )
            .await
            .unwrap();
        assert!(addresses(&provider)
            .await
            .contains(&interface_config(PROPOSED).ipv4.unwrap().addr()));
        recover_interface_transactions(directory.path(), &interfaces, &Default::default())
            .await
            .unwrap();
        assert_eq!(
            addresses(&provider).await,
            vec![Ipv4Addr::new(192, 168, 1, 10)]
        );
    }

    #[tokio::test]
    async fn restart_keeps_address_whose_commit_token_was_persisted() {
        let directory = tempdir().unwrap();
        let provider = fake_network();
        let interfaces =
            InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory());
        let desired = desired_state(directory.path()).await;
        let transactions =
            NetworkTransactionManager::new(interfaces.clone(), Duration::from_secs(60), desired);
        transactions
            .write_journal("confirmed", interfaces.snapshot("test0").await.unwrap())
            .await
            .unwrap();
        interfaces
            .apply_interface(
                "test0",
                &interface_config(PROPOSED),
                Some(InterfaceRole::Output),
                true,
            )
            .await
            .unwrap();
        let before = addresses(&provider).await;
        let mut committed = crate::state::overrides::RuntimeOverrides::default();
        committed
            .committed_interface_transactions
            .insert("test0".into(), "confirmed".into());
        recover_interface_transactions(directory.path(), &interfaces, &committed)
            .await
            .unwrap();
        assert_eq!(addresses(&provider).await, before);
    }

    #[tokio::test]
    async fn failed_commit_persistence_keeps_change_pending_for_rollback() {
        let directory = tempdir().expect("tempdir");
        let provider = fake_network();
        let desired = desired_state(directory.path()).await;
        let converger = spawn_converger(desired.clone(), provider.clone());
        let manager = NetworkTransactionManager::new(
            InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory()),
            Duration::from_secs(60),
            desired,
        );

        let change = manager
            .apply(
                "test0",
                &interface_config(PROPOSED),
                Some(InterfaceRole::Output),
                false,
            )
            .await
            .expect("apply");
        assert_eq!(
            addresses(&provider).await,
            vec![
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(192, 168, 50, 1)
            ],
            "apply must not return before the change has reached the machine"
        );

        let error = manager
            .commit_with(&change.token, |_, _, _| async {
                Err(anyhow::anyhow!("persistence failed"))
            })
            .await
            .expect_err("commit must fail");

        assert!(error.to_string().contains("persistence failed"));
        assert_eq!(manager.pending().await, vec![change.clone()]);
        manager
            .rollback(&change.token)
            .await
            .expect("manual rollback");
        assert_eq!(
            addresses(&provider).await,
            vec![Ipv4Addr::new(192, 168, 1, 10)],
            "withdrawing the proposal returns the machine to the committed state"
        );
        converger.abort();
    }

    #[tokio::test]
    async fn uncommitted_change_is_automatically_rolled_back() {
        let directory = tempdir().expect("tempdir");
        let provider = fake_network();
        let desired = desired_state(directory.path()).await;
        let converger = spawn_converger(desired.clone(), provider.clone());
        let manager = NetworkTransactionManager::new(
            InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory()),
            Duration::from_millis(20),
            desired,
        );

        manager
            .apply(
                "test0",
                &interface_config(PROPOSED),
                Some(InterfaceRole::Output),
                false,
            )
            .await
            .expect("apply");
        assert_eq!(
            addresses(&provider).await,
            vec![
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(192, 168, 50, 1)
            ]
        );

        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(manager.pending().await.is_empty());
        assert_eq!(
            addresses(&provider).await,
            vec![Ipv4Addr::new(192, 168, 1, 10)]
        );
        converger.abort();
    }

    /// The manager is not a writer any more, and this is the assertion that
    /// says so: with nothing converging, an apply changes the desired state and
    /// the machine stays exactly as it was.
    #[tokio::test]
    async fn an_apply_writes_desired_state_rather_than_the_kernel() {
        let directory = tempdir().expect("tempdir");
        let provider = fake_network();
        let desired = desired_state(directory.path()).await;
        let manager = NetworkTransactionManager::new(
            InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory()),
            Duration::from_secs(60),
            desired.clone(),
        );

        manager
            .apply(
                "test0",
                &interface_config(PROPOSED),
                Some(InterfaceRole::Output),
                false,
            )
            .await
            .expect("apply");

        assert_eq!(
            addresses(&provider).await,
            vec![Ipv4Addr::new(192, 168, 1, 10)],
            "nothing but convergence may write to the machine"
        );
        assert!(desired.is_tentative("test0").await);
        assert_eq!(
            desired
                .effective()
                .await
                .expect("effective")
                .network
                .interfaces["test0"]
                .ipv4,
            Some(PROPOSED.parse().expect("network"))
        );
    }

    #[tokio::test]
    async fn failed_apply_with_failed_compensation_stays_pending_and_rollback_only() {
        let directory = tempdir().expect("tempdir");
        let desired = desired_state(directory.path()).await;
        desired.attach_converger();
        let manager = NetworkTransactionManager::new(
            InterfaceManager::new(fake_network(), AddressOwnershipJournal::in_memory()),
            Duration::from_secs(60),
            desired.clone(),
        );

        let apply_manager = manager.clone();
        let apply = tokio::spawn(async move {
            apply_manager
                .apply(
                    "test0",
                    &interface_config(PROPOSED),
                    Some(InterfaceRole::Output),
                    false,
                )
                .await
        });

        while desired.version() < 1 {
            tokio::task::yield_now().await;
        }
        desired.report_result(1, Err(anyhow::anyhow!("candidate failed")));
        while desired.version() < 2 {
            tokio::task::yield_now().await;
        }
        desired.report_result(2, Err(anyhow::anyhow!("rollback failed")));

        let error = apply.await.expect("apply task").expect_err("apply must fail");
        assert!(error.to_string().contains("candidate failed"));
        assert!(error.to_string().contains("rollback failed"));
        assert!(!desired.is_tentative("test0").await);

        let pending = manager.pending().await;
        assert_eq!(pending.len(), 1, "failed compensation must remain recoverable");
        let token = pending[0].token.clone();
        let commit_error = manager
            .commit(&token)
            .await
            .expect_err("a candidate that never converged cannot be committed");
        assert!(commit_error.to_string().contains("rollback-only"));

        let rollback_manager = manager.clone();
        let rollback_token = token.clone();
        let rollback = tokio::spawn(async move { rollback_manager.rollback(&rollback_token).await });
        while desired.version() < 3 {
            tokio::task::yield_now().await;
        }
        desired.report_pass(3, BTreeMap::new());
        rollback
            .await
            .expect("rollback task")
            .expect("retry rollback");
        assert!(manager.pending().await.is_empty());
    }

    /// A change the planner refuses never becomes a proposal: the converger
    /// would only refuse it again, once a second, with nobody listening.
    #[tokio::test]
    async fn a_refused_change_is_reported_to_the_caller_and_not_proposed() {
        let directory = tempdir().expect("tempdir");
        let provider = fake_network();
        let desired = desired_state(directory.path()).await;
        let manager = NetworkTransactionManager::new(
            InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory()),
            Duration::from_secs(60),
            desired.clone(),
        );

        let error = manager
            .apply(
                "test0",
                &interface_config(PROPOSED),
                Some(InterfaceRole::None),
                false,
            )
            .await
            .expect_err("a management change without confirmation must be refused");

        assert!(error.to_string().contains("outside-router interface"));
        assert!(!desired.is_tentative("test0").await);
        assert!(manager.pending().await.is_empty());
    }
}
