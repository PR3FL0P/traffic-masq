use crate::core::mutation::NetworkMutationGate;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::{watch, Mutex, MutexGuard};

use crate::core::override_manager::RuntimeOverrideManager;
use crate::core::router::{RouterDesired, RouterManager, RouterPlan, RouterSnapshot};
use crate::core::router_candidate::RouterCandidate;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ObservationFingerprint([u8; 32]);

impl ObservationFingerprint {
    fn of(snapshot: &RouterSnapshot) -> Result<Self> {
        let canonical = serde_json::to_vec(snapshot)
            .context("failed to serialize router snapshot for plan fingerprinting")?;
        Ok(Self(Sha256::digest(canonical).into()))
    }
}

pub struct TransactionPlan {
    candidate: RouterCandidate,
    plan: RouterPlan,
    fingerprint: ObservationFingerprint,
}

impl TransactionPlan {
    pub fn candidate(&self) -> &RouterCandidate {
        &self.candidate
    }

    pub fn plan(&self) -> &RouterPlan {
        &self.plan
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CoordinatorConflict {
    #[error(
        "a router transaction is already pending; commit or roll it back before starting a new one"
    )]
    TransactionPending,
    #[error(
        "a previous router rollback failed and left the coordinator in recovery state; \
         resolve it before starting a new transaction"
    )]
    RollbackRecoveryRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("router plan is stale: the observed system state changed since the plan was built")]
pub struct StalePlanError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("no router transaction is pending")]
pub struct NoPendingTransactionError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinatorStatus {
    Idle,
    Pending,
    RollbackFailed,
}

#[derive(Debug, Clone)]
pub struct RollbackFailure {
    pub token: String,
    pub candidate: RouterCandidate,
    pub snapshot: RouterSnapshot,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone)]
struct PendingTransaction {
    token: String,
    candidate: RouterCandidate,
    snapshot: RouterSnapshot,
}

enum CoordinatorState {
    Idle,
    Pending(PendingTransaction),
    RollbackFailed(RollbackFailure),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RollbackTrigger {
    Manual,
    Timeout,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct TransactionJournal {
    version: u32,
    base_revision: u64,
    token: String,
    snapshot: RouterSnapshot,
    /// The state that may have been partially applied when the process died.
    /// Version-1 journals do not have this field; recovery for those keeps the
    /// historical snapshot-only behaviour.
    #[serde(default)]
    current_desired: Option<RouterDesired>,
}

struct Inner {
    manager: RouterManager,
    overrides: RuntimeOverrideManager,
    rollback_timeout: Duration,
    state: Mutex<CoordinatorState>,
    journal: std::path::PathBuf,
    token_counter: AtomicU64,
    timeout_mutation_gate: StdRwLock<Option<Arc<NetworkMutationGate>>>,
    idle_epoch: watch::Sender<u64>,
}

#[derive(Clone)]
pub struct RouterTransactionCoordinator {
    inner: Arc<Inner>,
}

impl RouterTransactionCoordinator {
    pub fn new(
        manager: RouterManager,
        overrides: RuntimeOverrideManager,
        rollback_timeout: Duration,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                journal: overrides.path().with_file_name("router-transaction.json"),
                manager,
                overrides,
                rollback_timeout,
                state: Mutex::new(CoordinatorState::Idle),
                token_counter: AtomicU64::new(0),
                timeout_mutation_gate: StdRwLock::new(None),
                idle_epoch: watch::channel(0).0,
            }),
        }
    }

    /// Gate used by the automatic timeout rollback. API-driven router
    /// operations are already serialized by ControlService; the timer is the
    /// one mutation path that otherwise has no request-level guard.
    pub fn set_timeout_mutation_gate(&self, gate: Arc<NetworkMutationGate>) {
        *self
            .inner
            .timeout_mutation_gate
            .write()
            .expect("router timeout mutation-gate lock poisoned") = Some(gate);
    }

    pub async fn plan(&self, candidate: RouterCandidate) -> Result<TransactionPlan> {
        let snapshot = self.inner.manager.snapshot_for(candidate.desired()).await?;
        let fingerprint = ObservationFingerprint::of(&snapshot)?;
        let plan = self.inner.manager.plan(candidate.desired().clone()).await?;
        Ok(TransactionPlan {
            candidate,
            plan,
            fingerprint,
        })
    }

    pub fn manager(&self) -> RouterManager {
        self.inner.manager.clone()
    }

    pub async fn apply(&self, plan: TransactionPlan) -> Result<String> {
        let mut state = self.inner.state.lock().await;
        match &*state {
            CoordinatorState::Idle => {}
            CoordinatorState::Pending(_) => {
                return Err(CoordinatorConflict::TransactionPending.into())
            }
            CoordinatorState::RollbackFailed(_) => {
                return Err(CoordinatorConflict::RollbackRecoveryRequired.into())
            }
        }

        let committed_revision = self.inner.overrides.committed_revision().await;
        plan.candidate.ensure_base_revision(committed_revision)?;

        let current_snapshot = self
            .inner
            .manager
            .snapshot_for(plan.candidate.desired())
            .await?;
        if ObservationFingerprint::of(&current_snapshot)? != plan.fingerprint {
            return Err(StalePlanError.into());
        }

        let token = self.next_token();
        self.write_journal(
            plan.candidate.base_revision(),
            &token,
            &current_snapshot,
            plan.candidate.desired(),
        )
            .await?;
        if let Err(error) = self.inner.manager.apply(&plan.plan).await {
            // Retry the complete snapshot: a failed apply may also have failed
            // its compensation. Keep the journal until restoration succeeds.
            let mut failures = self.rollback_snapshot(&token, &current_snapshot).await;
            if failures.is_empty() {
                if let Err(ownership_error) = self.retain_committed_router_interfaces().await {
                    failures.push(format!(
                        "failed to restore committed router ownership: {ownership_error:#}"
                    ));
                }
            }
            if failures.is_empty() {
                if let Err(cleanup_error) = self.clear_journal().await {
                    *state = CoordinatorState::RollbackFailed(RollbackFailure {
                        token: token.clone(),
                        candidate: plan.candidate,
                        snapshot: current_snapshot,
                        failures: vec![format!(
                            "failed to clear rollback journal: {cleanup_error:#}"
                        )],
                    });
                    return Err(error.context(format!(
                        "rollback journal cleanup failed: {cleanup_error:#}"
                    )));
                }
            } else {
                let recovery = failures.join("; ");
                *state = CoordinatorState::RollbackFailed(RollbackFailure {
                    token: token.clone(),
                    candidate: plan.candidate,
                    snapshot: current_snapshot,
                    failures,
                });
                return Err(error.context(format!(
                    "router rollback recovery remains required: {recovery}"
                )));
            }
            return Err(error);
        }

        *state = CoordinatorState::Pending(PendingTransaction {
            token: token.clone(),
            candidate: plan.candidate,
            snapshot: current_snapshot,
        });
        drop(state);
        self.spawn_rollback_timer(token.clone());
        Ok(token)
    }

    pub async fn repair(&self, desired: RouterDesired) -> Result<()> {
        self.repair_inner(desired, false).await
    }

    pub async fn reconcile_dataplane(&self, desired: RouterDesired) -> Result<()> {
        self.repair_inner(desired, true).await
    }

    async fn repair_inner(&self, desired: RouterDesired, dataplane_only: bool) -> Result<()> {
        let mut state = self.inner.state.lock().await;
        match &*state {
            CoordinatorState::Idle => {}
            CoordinatorState::Pending(_) => return Err(CoordinatorConflict::TransactionPending.into()),
            CoordinatorState::RollbackFailed(_) => return Err(CoordinatorConflict::RollbackRecoveryRequired.into()),
        }
        if dataplane_only && !self.inner.manager.dataplane_needs_reconcile(&desired).await {
            return Ok(());
        }
        self.inner.manager.prepare_recovery(&desired).await?;
        let candidate = self.inner.overrides.build_candidate(
            &crate::core::router_candidate::RouterIntentProposal::new()).await?;
        let snapshot = self.inner.manager.snapshot_for(&desired).await?;
        let token = self.next_token();
        self.write_journal(candidate.base_revision(), &token, &snapshot, &desired).await?;
        let result = if dataplane_only {
            self.inner.manager.reconcile_dataplane(&desired).await
        } else {
            match self.inner.manager.plan(desired).await {
                Ok(plan) => self.inner.manager.apply(&plan).await,
                Err(error) => Err(error),
            }
        };
        if let Err(error) = result {
            let mut failures = self.inner.manager.rollback_to(&snapshot).await;
            if failures.is_empty() {
                if let Err(ownership_error) = self.retain_committed_router_interfaces().await {
                    failures.push(format!(
                        "failed to restore committed router ownership: {ownership_error:#}"
                    ));
                }
            }
            if failures.is_empty() {
                if let Err(cleanup) = self.clear_journal().await {
                    failures.push(cleanup.to_string());
                }
            }
            if !failures.is_empty() {
                *state = CoordinatorState::RollbackFailed(RollbackFailure {
                    token, candidate, snapshot, failures,
                });
            }
            return Err(error);
        }
        if let Err(error) = self.retain_committed_router_interfaces().await {
            *state = CoordinatorState::RollbackFailed(RollbackFailure {
                token,
                candidate,
                snapshot,
                failures: vec![format!(
                    "failed to settle committed router ownership: {error:#}"
                )],
            });
            return Err(error.context("router repair applied but ownership settlement failed"));
        }
        if let Err(error) = self.clear_journal().await {
            // Keep recovery ownership until the durable journal is resolved.
            *state = CoordinatorState::RollbackFailed(RollbackFailure {
                token, candidate, snapshot, failures: vec![error.to_string()],
            });
            return Err(error);
        }
        Ok(())
    }

    pub async fn commit(&self, token: &str) -> Result<u64> {
        let mut state = self.inner.state.lock().await;
        let pending = match &*state {
            CoordinatorState::Pending(pending) => pending.clone(),
            CoordinatorState::Idle => return Err(NoPendingTransactionError.into()),
            CoordinatorState::RollbackFailed(_) => {
                return Err(CoordinatorConflict::RollbackRecoveryRequired.into())
            }
        };

        anyhow::ensure!(
            pending.token == token,
            "router transaction token does not match pending transaction"
        );
        let revision = self
            .inner
            .overrides
            .commit_candidate_with_token(&pending.candidate, Some(&pending.token))
            .await?;

        // Ownership now matches the intent that is in force. Interfaces this
        // intent dropped were torn down as part of the apply, so holding onto
        // them would only make the set grow with every provisioning that ever
        // happened. Narrowing after the commit succeeds, never before.
        let owned: Vec<String> = pending
            .candidate
            .desired()
            .interfaces
            .iter()
            .map(|entry| entry.name.clone())
            .collect();
        self.inner.manager.retain_router_interfaces(&owned).await;

        *state = CoordinatorState::Idle;
        self.notify_idle();
        // The persisted revision is authoritative if removal fails or the
        // process dies here. Recovery must never undo a committed revision.
        if let Err(error) = self.clear_journal().await {
            tracing::warn!(%error, "failed to remove committed transaction journal");
        }
        Ok(revision)
    }

    pub async fn rollback(&self) -> Result<()> {
        let mut state = self.inner.state.lock().await;
        self.rollback_locked(&mut state, RollbackTrigger::Manual)
            .await
    }

    pub async fn pending_token(&self) -> Option<String> {
        match &*self.inner.state.lock().await {
            CoordinatorState::Pending(pending) => Some(pending.token.clone()),
            CoordinatorState::RollbackFailed(failure) => Some(failure.token.clone()),
            CoordinatorState::Idle => None,
        }
    }

    pub async fn rollback_with_token(&self, token: &str) -> Result<()> {
        let mut state = self.inner.state.lock().await;
        let expected = match &*state {
            CoordinatorState::Pending(pending) => &pending.token,
            CoordinatorState::RollbackFailed(failure) => &failure.token,
            CoordinatorState::Idle => return Err(NoPendingTransactionError.into()),
        };
        anyhow::ensure!(
            expected == token,
            "router transaction token does not match pending transaction"
        );
        self.rollback_locked(&mut state, RollbackTrigger::Manual)
            .await
    }

    pub async fn status(&self) -> CoordinatorStatus {
        match &*self.inner.state.lock().await {
            CoordinatorState::Idle => CoordinatorStatus::Idle,
            CoordinatorState::Pending(_) => CoordinatorStatus::Pending,
            CoordinatorState::RollbackFailed(_) => CoordinatorStatus::RollbackFailed,
        }
    }

    /// Wait until a pending/recovery transaction has returned to idle.
    ///
    /// The epoch watch closes the race between checking `status()` and
    /// registering the wakeup: an idle transition that happens in between is
    /// retained as a changed watch value.
    pub async fn wait_until_idle(&self) {
        let mut idle = self.inner.idle_epoch.subscribe();
        loop {
            if self.status().await == CoordinatorStatus::Idle {
                return;
            }
            if idle.changed().await.is_err() {
                return;
            }
        }
    }

    fn notify_idle(&self) {
        self.inner
            .idle_epoch
            .send_modify(|epoch| *epoch = epoch.wrapping_add(1));
    }

    pub async fn rollback_failure(&self) -> Option<RollbackFailure> {
        match &*self.inner.state.lock().await {
            CoordinatorState::RollbackFailed(failure) => Some(failure.clone()),
            _ => None,
        }
    }

    async fn rollback_locked(
        &self,
        state: &mut MutexGuard<'_, CoordinatorState>,
        trigger: RollbackTrigger,
    ) -> Result<()> {
        let (token, candidate, snapshot) = match &**state {
            CoordinatorState::Pending(pending) => (
                pending.token.clone(),
                pending.candidate.clone(),
                pending.snapshot.clone(),
            ),
            CoordinatorState::RollbackFailed(failure) => (
                failure.token.clone(),
                failure.candidate.clone(),
                failure.snapshot.clone(),
            ),
            CoordinatorState::Idle => return Err(NoPendingTransactionError.into()),
        };

        let mut failures = self.rollback_snapshot(&token, &snapshot).await;
        if failures.is_empty() {
            // Applying a candidate widens the volatile ownership scope before
            // its apply-time snapshot. The snapshot therefore contains both
            // committed and candidate-only interfaces and cannot be used to
            // decide what remains owned after an abort. Restore ownership from
            // the durable committed intent instead.
            if let Err(error) = self.retain_committed_router_interfaces().await {
                failures.push(format!(
                    "failed to restore committed router ownership: {error:#}"
                ));
            }
        }
        if failures.is_empty() {
            if let Err(error) = self.clear_journal().await {
                **state = CoordinatorState::RollbackFailed(RollbackFailure {
                    token,
                    candidate,
                    snapshot,
                    failures: vec![format!("failed to clear rollback journal: {error:#}")],
                });
                return Err(error.context("network restored but rollback journal cleanup failed"));
            }
            **state = CoordinatorState::Idle;
            self.notify_idle();
            if trigger == RollbackTrigger::Timeout {
                tracing::warn!("router transaction automatically rolled back after timeout");
            }
            Ok(())
        } else {
            let message = failures.join("; ");
            **state = CoordinatorState::RollbackFailed(RollbackFailure {
                token,
                candidate,
                snapshot,
                failures,
            });
            Err(anyhow::anyhow!("router rollback failed: {message}"))
        }
    }

    async fn rollback_snapshot(&self, token: &str, snapshot: &RouterSnapshot) -> Vec<String> {
        let secrets = crate::core::provisioning_secret_transaction::ProvisioningSecretTransactionStore::in_state_dir(
            self.inner.overrides.path().parent().expect("override store has a parent"),
        );
        // Runtime restoration can need the old credentials to start a station
        // or AP. Restore them before the snapshot, including apply compensation
        // where the provisioning journal has not been bound to a token yet.
        let restored = secrets
            .restore_for_token_or_unbound_for_reconvergence(token)
            .await;
        let mut failures = self.inner.manager.rollback_to(snapshot).await;
        match restored {
            Err(error) => {
                failures.push(format!("failed to restore provisioning secrets: {error:#}"))
            }
            Ok(true) if failures.is_empty() => {
                if let Err(error) = secrets.complete_reconvergence().await {
                    failures.push(format!(
                        "failed to clear provisioning secret journal: {error:#}"
                    ));
                }
            }
            _ => {}
        }
        failures
    }

    async fn retain_committed_router_interfaces(&self) -> Result<()> {
        let committed = self
            .inner
            .overrides
            .build_candidate(&crate::core::router_candidate::RouterIntentProposal::new())
            .await?;
        let owned = committed
            .desired()
            .interfaces
            .iter()
            .map(|entry| entry.name.clone())
            .collect::<Vec<_>>();
        self.inner.manager.retain_router_interfaces(&owned).await;
        Ok(())
    }

    async fn rollback_timeout_fired(&self, token: &str) {
        let gate = self
            .inner
            .timeout_mutation_gate
            .read()
            .expect("router timeout mutation-gate lock poisoned")
            .clone();
        let _network_mutation = match &gate {
            Some(gate) => Some(gate.write().await),
            None => None,
        };
        let mut state = self.inner.state.lock().await;
        match &*state {
            CoordinatorState::Pending(pending) if pending.token == token => {}

            _ => return,
        }
        if let Err(error) = self
            .rollback_locked(&mut state, RollbackTrigger::Timeout)
            .await
        {
            tracing::error!(%error, "automatic router rollback failed");
        }
    }

    fn spawn_rollback_timer(&self, token: String) {
        let coordinator = self.clone();
        let timeout = self.inner.rollback_timeout;
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            coordinator.rollback_timeout_fired(&token).await;
        });
    }

    async fn write_journal(
        &self,
        base_revision: u64,
        token: &str,
        snapshot: &RouterSnapshot,
        current_desired: &RouterDesired,
    ) -> Result<()> {
        let journal = TransactionJournal {
            version: 2,
            base_revision,
            token: token.to_owned(),
            snapshot: snapshot.clone(),
            current_desired: Some(current_desired.clone()),
        };
        let bytes = serde_json::to_vec(&journal)?;
        if let Some(parent) = self.inner.journal.parent() {
            let parent = parent.to_path_buf();
            tokio::task::spawn_blocking(move || {
                crate::atomic_file::ensure_private_dir(
                    &parent,
                    crate::atomic_file::PRIVATE_DIR_MODE,
                )
            })
            .await??;
        }
        crate::atomic_file::replace_preserving_on_error_async(&self.inner.journal, &bytes, 0o600)
            .await?;
        Ok(())
    }

    async fn clear_journal(&self) -> Result<()> {
        crate::atomic_file::remove_preserving_on_error_async(&self.inner.journal, 0o600)
            .await?;
        Ok(())
    }

    /// Restore an interrupted transaction before accepting control requests.
    pub async fn recover(&self) -> Result<bool> {
        let _state = self.inner.state.lock().await;
        crate::atomic_file::reject_symlink(&self.inner.journal)?;
        let bytes = match tokio::fs::read(&self.inner.journal).await {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        let journal: TransactionJournal =
            serde_json::from_slice(&bytes).context("invalid router transaction journal")?;
        anyhow::ensure!(
            matches!(journal.version, 1 | 2),
            "unsupported router transaction journal version"
        );
        let revision = self.inner.overrides.committed_revision().await;
        anyhow::ensure!(
            revision >= journal.base_revision,
            "transaction journal is newer than committed configuration"
        );
        let committed = self
            .inner
            .overrides
            .snapshot()
            .await
            .committed_router_transaction
            .as_deref()
            == Some(journal.token.as_str());
        if !committed {
            if let Some(current_desired) = journal.current_desired.as_ref() {
                self.inner
                    .manager
                    .prepare_recovery(current_desired)
                    .await
                    .context("failed to reconstruct partially-applied router state")?;
            }
            let failures = self.inner.manager.rollback_to(&journal.snapshot).await;
            anyhow::ensure!(
                failures.is_empty(),
                "interrupted router transaction recovery failed: {}",
                failures.join("; ")
            );
            tracing::warn!("restored interrupted router transaction");
        }
        // Rebuild volatile ownership from the durable committed intent for both
        // aborted and already-committed journals. This keeps recovery correct
        // even if the manager was constructed with a wider transient scope.
        self.retain_committed_router_interfaces()
            .await
            .context("failed to restore committed router ownership during recovery")?;
        self.clear_journal().await?;
        Ok(!committed)
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Mutex as StdMutex;

    use async_trait::async_trait;
    use tempfile::tempdir;

    use crate::config::{
        AppConfig, DhcpInterfaceConfig, InterfaceConfig, InterfaceRole, RouterConfig, UplinkConfig,
        UplinkMode,
    };
    use crate::core::interface::{DhcpChangeAction, InterfaceChangePlan, InterfaceSnapshot};
    use crate::core::route::{RoutePlan, RouteSnapshot};
    use crate::core::router::{DhcpPlan, RouterSubsystems};
    use crate::core::router_candidate::RouterIntentProposal;
    use crate::dhcp::supervisor::DhcpServiceSpec;
    use crate::firewall::{RouterDataplanePlan, RouterDataplaneSnapshot};

    use super::*;

    fn output_interface(address: &str, pool_start: u8, pool_end: u8) -> InterfaceConfig {
        let ipv4: ipnet::Ipv4Net = address.parse().expect("IPv4 network");
        let octet = ipv4.addr().octets()[2];
        InterfaceConfig {
            nat: true,
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some(ipv4),
            dhcp: Some(DhcpInterfaceConfig {
                pool_start: Ipv4Addr::new(192, 168, octet, pool_start),
                pool_end: Ipv4Addr::new(192, 168, octet, pool_end),
                router: ipv4.addr(),
                dns_servers: Vec::new(),
                lease_seconds: None,
            }),
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        }
    }

    fn base_config() -> AppConfig {
        let mut config = AppConfig::default();
        config.network.interfaces.insert(
            "wan0".to_string(),
            InterfaceConfig {
                nat: true,
                role: InterfaceRole::Input,
                managed: false,
                ipv4: None,
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
            },
        );
        config.network.interfaces.insert(
            "lan0".to_string(),
            output_interface("192.168.10.1/24", 100, 150),
        );
        config
    }

    fn enabled_router() -> RouterConfig {
        RouterConfig {
            forwarding: None,
            vpn_chain: Vec::new(),
            enabled: true,
            uplink: Some(UplinkConfig {
                interface: "wan0".to_string(),
                mode: UplinkMode::External,
            }),
            owned_routes: Vec::new(),
            allow_default_route_change: false,
        }
    }

    struct FakeSubsystems {
        events: StdMutex<Vec<String>>,
        apply_fail: StdMutex<Option<&'static str>>,
        rollback_fail: StdMutex<Option<&'static str>>,
        drifted: StdMutex<bool>,
        retained: StdMutex<Vec<Vec<String>>>,
        rollback_secret: StdMutex<Option<std::path::PathBuf>>,
    }

    impl FakeSubsystems {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                events: StdMutex::new(Vec::new()),
                apply_fail: StdMutex::new(None),
                rollback_fail: StdMutex::new(None),
                drifted: StdMutex::new(false),
                retained: StdMutex::new(Vec::new()),
                rollback_secret: StdMutex::new(None),
            })
        }

        fn fail_apply(&self, stage: &'static str) {
            *self.apply_fail.lock().unwrap() = Some(stage);
        }

        fn fail_rollback(&self, stage: &'static str) {
            *self.rollback_fail.lock().unwrap() = Some(stage);
        }

        fn drift(&self) {
            *self.drifted.lock().unwrap() = true;
        }

        fn events(&self) -> Vec<String> {
            self.events.lock().unwrap().clone()
        }

        fn retained(&self) -> Vec<Vec<String>> {
            self.retained.lock().unwrap().clone()
        }

        fn record(&self, event: &str) -> Result<()> {
            self.events.lock().unwrap().push(event.to_string());
            Ok(())
        }

        fn dataplane_snapshot(&self) -> RouterDataplaneSnapshot {
            RouterDataplaneSnapshot {
                ipv4_forwarding: *self.drifted.lock().unwrap(),
                owned: None,
                owned_firewall_integrity: crate::firewall::OwnedFirewallIntegrity::Intact,
            }
        }
    }

    #[async_trait]
    impl RouterSubsystems for FakeSubsystems {
        async fn plan_interfaces(
            &self,
            _: &crate::core::router::RouterDesired,
        ) -> Result<Vec<InterfaceChangePlan>> {
            self.record("plan_interfaces")?;
            Ok(vec![InterfaceChangePlan {
                interface: "lan0".into(),
                delete_ipv4: Vec::new(),
                retag_ipv4: None,
                add_ipv4: None,
                set_link_up: false,
                management_change: false,
                dhcp_action: DhcpChangeAction::Unchanged,
                releasing_management: false,
            }])
        }
        async fn plan_routes(&self, _: &crate::core::router::RouterDesired) -> Result<RoutePlan> {
            self.record("plan_routes")?;
            Ok(RoutePlan {
                add: Vec::new(),
                delete: Vec::new(),
            })
        }
        async fn plan_dhcp(&self, _: &crate::core::router::RouterDesired) -> Result<Vec<DhcpPlan>> {
            self.record("plan_dhcp")?;
            Ok(Vec::new())
        }
        async fn plan_dataplane(
            &self,
            desired: &crate::core::router::RouterDesired,
        ) -> Result<RouterDataplanePlan> {
            self.record("plan_dataplane")?;
            Ok(RouterDataplanePlan {
                snapshot: self.dataplane_snapshot(),
                target: desired.dataplane.clone(),
                requires_apply: true,
            })
        }
        async fn snapshot_interfaces(&self) -> Result<Vec<InterfaceSnapshot>> {
            self.record("snapshot_interfaces")?;
            Ok(Vec::new())
        }
        async fn retain_router_interfaces(&self, interfaces: &[String]) {
            self.retained.lock().unwrap().push(interfaces.to_vec());
        }
        async fn snapshot_routes(&self) -> Result<RouteSnapshot> {
            self.record("snapshot_routes")?;
            Ok(RouteSnapshot::empty())
        }
        async fn snapshot_dhcp(&self) -> Result<Vec<DhcpServiceSpec>> {
            self.record("snapshot_dhcp")?;
            Ok(Vec::new())
        }
        async fn snapshot_dataplane(&self) -> Result<RouterDataplaneSnapshot> {
            self.record("snapshot_dataplane")?;
            Ok(self.dataplane_snapshot())
        }
        async fn apply_interfaces(&self, _: &[InterfaceChangePlan]) -> Result<()> {
            self.fail_if_matched("apply_interfaces", &self.apply_fail)
        }
        async fn apply_routes(&self, _: &RoutePlan) -> Result<()> {
            self.fail_if_matched("apply_routes", &self.apply_fail)
        }
        async fn apply_dhcp(&self, _: &[DhcpPlan]) -> Result<()> {
            self.fail_if_matched("apply_dhcp", &self.apply_fail)
        }
        async fn apply_dataplane(&self, _: &RouterDataplanePlan) -> Result<()> {
            self.fail_if_matched("apply_dataplane", &self.apply_fail)
        }
        async fn rollback_interfaces(&self, _: &[InterfaceSnapshot]) -> Result<()> {
            if let Some(root) = self.rollback_secret.lock().unwrap().as_ref() {
                let store = crate::wifi::store::PassphraseStore::new(root.join("wifi/psk"));
                anyhow::ensure!(
                    store.get("wlan0")?.is_some_and(|secret| secret.expose() == "old-password"),
                    "runtime rollback needs the original Wi-Fi credential"
                );
            }
            self.fail_if_matched("rollback_interfaces", &self.rollback_fail)
        }
        async fn rollback_routes(&self, _: &RouteSnapshot) -> Result<()> {
            self.fail_if_matched("rollback_routes", &self.rollback_fail)
        }
        async fn rollback_dhcp(&self, _: &[DhcpServiceSpec]) -> Result<()> {
            self.fail_if_matched("rollback_dhcp", &self.rollback_fail)
        }
        async fn rollback_dataplane(&self, _: &RouterDataplaneSnapshot) -> Result<()> {
            self.fail_if_matched("rollback_dataplane", &self.rollback_fail)
        }
        async fn health_interfaces(&self, _: &crate::core::router::RouterDesired) -> Result<()> {
            self.record("health_interfaces")
        }
        async fn health_routes(&self, _: &crate::core::router::RouterDesired) -> Result<()> {
            self.record("health_routes")
        }
        async fn health_dhcp(&self, _: &crate::core::router::RouterDesired) -> Result<()> {
            self.record("health_dhcp")
        }
        async fn health_dataplane(&self, _: &crate::core::router::RouterDesired) -> Result<()> {
            self.record("health_dataplane")
        }
    }

    impl FakeSubsystems {
        fn fail_if_matched(
            &self,
            event: &'static str,
            switch: &StdMutex<Option<&'static str>>,
        ) -> Result<()> {
            self.record(event)?;
            if *switch.lock().unwrap() == Some(event) {
                anyhow::bail!("injected {event} failure");
            }
            Ok(())
        }
    }

    async fn coordinator_with(
        fake: Arc<FakeSubsystems>,
    ) -> (
        RouterTransactionCoordinator,
        RuntimeOverrideManager,
        tempfile::TempDir,
    ) {
        let directory = tempdir().expect("tempdir");
        let overrides = RuntimeOverrideManager::load(directory.path(), &base_config())
            .await
            .expect("overrides manager");
        let manager = RouterManager::new(fake);
        let coordinator = RouterTransactionCoordinator::new(
            manager,
            overrides.clone(),
            Duration::from_millis(30),
        );
        (coordinator, overrides, directory)
    }

    async fn build_candidate(overrides: &RuntimeOverrideManager) -> RouterCandidate {
        overrides
            .build_candidate(&RouterIntentProposal::new().set_router(enabled_router()))
            .await
            .expect("candidate")
    }

    #[tokio::test]
    async fn recovery_restores_a_snapshot_left_before_apply() {
        let fake = FakeSubsystems::new();
        let (coordinator, overrides, _directory) = coordinator_with(fake.clone()).await;
        let candidate = build_candidate(&overrides).await;
        let snapshot = coordinator
            .manager()
            .snapshot_for(candidate.desired())
            .await
            .unwrap();
        coordinator
            .write_journal(candidate.base_revision(), "test-transaction", &snapshot, candidate.desired())
            .await
            .unwrap();
        let expected = overrides
            .build_candidate(&RouterIntentProposal::new())
            .await
            .expect("committed candidate")
            .desired()
            .interfaces
            .iter()
            .map(|entry| entry.name.clone())
            .collect::<Vec<_>>();
        let restored = RouterTransactionCoordinator::new(
            coordinator.manager(),
            overrides,
            Duration::from_secs(60),
        );
        restored.recover().await.unwrap();
        assert!(fake
            .events()
            .iter()
            .any(|event| event == "rollback_interfaces"));
        assert_eq!(fake.retained().last(), Some(&expected));
        assert!(!restored.inner.journal.exists());
    }

    #[tokio::test]
    async fn recovery_does_not_undo_a_persisted_commit() {
        let fake = FakeSubsystems::new();
        let (coordinator, overrides, _directory) = coordinator_with(fake.clone()).await;
        let candidate = build_candidate(&overrides).await;
        let snapshot = coordinator
            .manager()
            .snapshot_for(candidate.desired())
            .await
            .unwrap();
        coordinator
            .write_journal(candidate.base_revision(), "test-transaction", &snapshot, candidate.desired())
            .await
            .unwrap();
        overrides
            .commit_candidate_with_token(&candidate, Some("test-transaction"))
            .await
            .unwrap();
        let expected = overrides
            .build_candidate(&RouterIntentProposal::new())
            .await
            .expect("committed candidate")
            .desired()
            .interfaces
            .iter()
            .map(|entry| entry.name.clone())
            .collect::<Vec<_>>();
        let restored = RouterTransactionCoordinator::new(
            coordinator.manager(),
            overrides,
            Duration::from_secs(60),
        );
        restored.recover().await.unwrap();
        assert!(!fake
            .events()
            .iter()
            .any(|event| event.starts_with("rollback_")));
        assert_eq!(fake.retained().last(), Some(&expected));
        assert!(!restored.inner.journal.exists());
    }

    #[tokio::test]
    async fn failed_recovery_preserves_the_journal_for_retry() {
        let fake = FakeSubsystems::new();
        let (coordinator, overrides, _directory) = coordinator_with(fake.clone()).await;
        let candidate = build_candidate(&overrides).await;
        let snapshot = coordinator
            .manager()
            .snapshot_for(candidate.desired())
            .await
            .unwrap();
        coordinator
            .write_journal(candidate.base_revision(), "test-transaction", &snapshot, candidate.desired())
            .await
            .unwrap();
        fake.fail_rollback("rollback_routes");
        assert!(coordinator.recover().await.is_err());
        assert!(coordinator.inner.journal.exists());
        *fake.rollback_fail.lock().unwrap() = None;
        coordinator.recover().await.unwrap();
        assert!(!coordinator.inner.journal.exists());
    }

    #[tokio::test]
    async fn unrelated_saved_settings_do_not_confirm_router_transaction() {
        let fake = FakeSubsystems::new();
        let (coordinator, overrides, _directory) = coordinator_with(fake.clone()).await;
        let candidate = build_candidate(&overrides).await;
        let snapshot = coordinator
            .manager()
            .snapshot_for(candidate.desired())
            .await
            .unwrap();
        coordinator
            .write_journal(candidate.base_revision(), "unconfirmed", &snapshot, candidate.desired())
            .await
            .unwrap();
        overrides
            .set_vpn_mode(crate::config::VpnPolicyMode::Direct)
            .await
            .unwrap();
        assert!(coordinator.recover().await.unwrap());
        assert!(fake
            .events()
            .iter()
            .any(|event| event == "rollback_interfaces"));
    }

    #[tokio::test]
    async fn invalid_recovery_record_is_not_discarded() {
        let (coordinator, _, _directory) = coordinator_with(FakeSubsystems::new()).await;
        tokio::fs::write(&coordinator.inner.journal, b"invalid")
            .await
            .unwrap();
        assert!(coordinator.recover().await.is_err());
        assert!(coordinator.inner.journal.exists());
    }

    #[tokio::test]
    async fn write_journal_creates_missing_parent_directory() {
        let fake = FakeSubsystems::new();
        let (coordinator, overrides, directory) = coordinator_with(fake.clone()).await;
        let nested_dir = directory.path().join("nested_missing_state_dir");
        let non_existent_journal = nested_dir.join("router-transaction.json");
        assert!(!nested_dir.exists());

        let candidate = build_candidate(&overrides).await;
        let snapshot = coordinator
            .manager()
            .snapshot_for(candidate.desired())
            .await
            .unwrap();

        let isolated_coordinator = RouterTransactionCoordinator {
            inner: Arc::new(Inner {
                journal: non_existent_journal.clone(),
                manager: coordinator.manager(),
                overrides,
                rollback_timeout: Duration::from_secs(60),
                state: Mutex::new(CoordinatorState::Idle),
                token_counter: AtomicU64::new(0),
                timeout_mutation_gate: StdRwLock::new(None),
                idle_epoch: watch::channel(0).0,
            }),
        };

        isolated_coordinator
            .write_journal(candidate.base_revision(), "token-1", &snapshot, candidate.desired())
            .await
            .unwrap();

        assert!(non_existent_journal.exists());
    }

    #[tokio::test]
    async fn full_lifecycle_applies_and_commits() {
        let fake = FakeSubsystems::new();
        let (coordinator, overrides, _directory) = coordinator_with(fake.clone()).await;
        let candidate = build_candidate(&overrides).await;

        let plan = coordinator.plan(candidate).await.expect("plan");
        coordinator.apply(plan).await.expect("apply");
        assert_eq!(coordinator.status().await, CoordinatorStatus::Pending);

        let revision = coordinator
            .commit(&coordinator.pending_token().await.unwrap_or_default())
            .await
            .expect("commit");
        assert_eq!(revision, 1);
        assert_eq!(coordinator.status().await, CoordinatorStatus::Idle);
        assert_eq!(overrides.committed_revision().await, 1);
        assert!(overrides.snapshot().await.router.is_some());

        let events = fake.events();
        assert!(events.contains(&"apply_interfaces".to_string()));
        assert!(events.contains(&"health_dataplane".to_string()));
        assert!(!events.iter().any(|event| event.starts_with("rollback_")));
    }

    #[tokio::test]
    async fn second_concurrent_transaction_is_rejected() {
        let fake = FakeSubsystems::new();
        let (coordinator, overrides, _directory) = coordinator_with(fake.clone()).await;
        let candidate = build_candidate(&overrides).await;
        let plan = coordinator.plan(candidate).await.expect("plan");
        coordinator.apply(plan).await.expect("first apply");

        let second_candidate = overrides
            .build_candidate(&RouterIntentProposal::new().set_interface(
                "lan1",
                output_interface("192.168.20.1/24", 100, 150),
                false,
            ))
            .await
            .expect("second candidate");
        let second_plan = coordinator
            .plan(second_candidate)
            .await
            .expect("second plan");
        let error = coordinator
            .apply(second_plan)
            .await
            .expect_err("second concurrent apply must be rejected");
        assert!(error.to_string().contains("already pending"));
        assert_eq!(coordinator.status().await, CoordinatorStatus::Pending);
    }

    #[tokio::test]
    async fn repair_reapplies_committed_intent_without_creating_a_revision() {
        let fake = FakeSubsystems::new();
        let (coordinator, overrides, _directory) = coordinator_with(fake.clone()).await;
        let candidate = build_candidate(&overrides).await;
        overrides
            .commit_candidate(&candidate)
            .await
            .expect("seed committed intent");
        let desired = RouterDesired::from_effective_config(
            &overrides
                .snapshot()
                .await
                .effective_config(&base_config())
                .expect("effective config"),
        )
        .expect("desired");

        coordinator.repair(desired).await.expect("repair");

        assert_eq!(overrides.committed_revision().await, 1);
        assert_eq!(coordinator.status().await, CoordinatorStatus::Idle);
        let events = fake.events();
        assert!(events.contains(&"plan_interfaces".to_string()));
        assert!(events.contains(&"apply_dataplane".to_string()));
        assert!(!events.iter().any(|event| event.starts_with("rollback_")));
    }

    #[tokio::test]
    async fn repair_respects_pending_transaction_ownership() {
        let fake = FakeSubsystems::new();
        let (coordinator, overrides, _directory) = coordinator_with(fake).await;
        let candidate = build_candidate(&overrides).await;
        let desired = candidate.desired().clone();
        let plan = coordinator.plan(candidate).await.expect("plan");
        coordinator.apply(plan).await.expect("apply");

        let error = coordinator
            .repair(desired)
            .await
            .expect_err("pending transaction must keep ownership");

        assert!(error.to_string().contains("already pending"));
        assert_eq!(coordinator.status().await, CoordinatorStatus::Pending);
    }

    #[tokio::test]
    async fn stale_candidate_is_rejected_before_mutation() {
        let fake = FakeSubsystems::new();
        let (coordinator, overrides, _directory) = coordinator_with(fake.clone()).await;
        let candidate = build_candidate(&overrides).await;
        let plan = coordinator.plan(candidate).await.expect("plan");

        let unrelated = overrides
            .build_candidate(&RouterIntentProposal::new().set_interface(
                "lan1",
                output_interface("192.168.20.1/24", 100, 150),
                false,
            ))
            .await
            .expect("unrelated candidate");
        overrides
            .commit_candidate(&unrelated)
            .await
            .expect("unrelated commit");

        let error = coordinator
            .apply(plan)
            .await
            .expect_err("stale candidate must be rejected");
        assert!(error.to_string().contains("stale"));
        assert_eq!(coordinator.status().await, CoordinatorStatus::Idle);
        assert!(!fake
            .events()
            .iter()
            .any(|event| event.starts_with("apply_")));
    }

    #[tokio::test]
    async fn stale_plan_fingerprint_is_rejected_before_mutation() {
        let fake = FakeSubsystems::new();
        let (coordinator, overrides, _directory) = coordinator_with(fake.clone()).await;
        let candidate = build_candidate(&overrides).await;
        let plan = coordinator.plan(candidate).await.expect("plan");

        fake.drift();

        let error = coordinator
            .apply(plan)
            .await
            .expect_err("drifted observation must be rejected");
        assert!(error.to_string().contains("stale"));
        assert_eq!(coordinator.status().await, CoordinatorStatus::Idle);
        assert!(!fake
            .events()
            .iter()
            .any(|event| event.starts_with("apply_")));
    }

    #[tokio::test]
    async fn commit_persistence_failure_leaves_transaction_pending() {
        let fake = FakeSubsystems::new();
        let (coordinator, overrides, directory) = coordinator_with(fake.clone()).await;
        let candidate = build_candidate(&overrides).await;
        let plan = coordinator.plan(candidate).await.expect("plan");
        coordinator.apply(plan).await.expect("apply");

        tokio::fs::create_dir(overrides.path())
            .await
            .expect("conflicting target directory");

        let error = coordinator
            .commit(&coordinator.pending_token().await.unwrap_or_default())
            .await
            .expect_err("commit persistence must fail");
        assert!(!error.to_string().is_empty());
        assert_eq!(coordinator.status().await, CoordinatorStatus::Pending);
        assert_eq!(overrides.committed_revision().await, 0);

        tokio::fs::remove_dir(overrides.path())
            .await
            .expect("cleanup");
        let revision = coordinator
            .commit(&coordinator.pending_token().await.unwrap_or_default())
            .await
            .expect("retry commit");
        assert_eq!(revision, 1);
        let _ = directory;
    }

    #[tokio::test]
    async fn stale_confirmation_cannot_commit_or_rollback_a_new_transaction() {
        let (coordinator, overrides, _directory) = coordinator_with(FakeSubsystems::new()).await;
        let plan = coordinator
            .plan(build_candidate(&overrides).await)
            .await
            .unwrap();
        let old = coordinator.apply(plan).await.unwrap();
        coordinator.rollback_with_token(&old).await.unwrap();
        let plan = coordinator
            .plan(build_candidate(&overrides).await)
            .await
            .unwrap();
        let current = coordinator.apply(plan).await.unwrap();
        assert_ne!(old, current);
        assert!(coordinator.commit(&old).await.is_err());
        assert!(coordinator.rollback_with_token(&old).await.is_err());
        assert_eq!(coordinator.status().await, CoordinatorStatus::Pending);
        assert_eq!(overrides.committed_revision().await, 0);
        coordinator.commit(&current).await.unwrap();
        assert_eq!(overrides.committed_revision().await, 1);
    }

    #[tokio::test]
    async fn rollback_journal_cleanup_failure_cannot_be_committed() {
        let (coordinator, overrides, _directory) = coordinator_with(FakeSubsystems::new()).await;
        let plan = coordinator
            .plan(build_candidate(&overrides).await)
            .await
            .unwrap();
        coordinator.apply(plan).await.unwrap();
        let journal = &coordinator.inner.journal;
        tokio::fs::remove_file(journal).await.unwrap();
        tokio::fs::create_dir(journal).await.unwrap();
        assert!(coordinator.rollback().await.is_err());
        assert_eq!(
            coordinator.status().await,
            CoordinatorStatus::RollbackFailed
        );
        assert!(coordinator
            .commit(&coordinator.pending_token().await.unwrap_or_default())
            .await
            .is_err());
        assert_eq!(overrides.committed_revision().await, 0);
        tokio::fs::remove_dir(journal).await.unwrap();
        coordinator.rollback().await.unwrap();
        assert_eq!(coordinator.status().await, CoordinatorStatus::Idle);
    }

    #[tokio::test]
    async fn manual_rollback_restores_idle_state() {
        let fake = FakeSubsystems::new();
        let (coordinator, overrides, _directory) = coordinator_with(fake.clone()).await;
        let candidate = build_candidate(&overrides).await;
        let plan = coordinator.plan(candidate).await.expect("plan");
        coordinator.apply(plan).await.expect("apply");

        coordinator.rollback().await.expect("manual rollback");
        assert_eq!(coordinator.status().await, CoordinatorStatus::Idle);
        assert_eq!(overrides.committed_revision().await, 0);
        assert!(fake
            .events()
            .iter()
            .any(|event| event == "rollback_dataplane"));

        let error = coordinator
            .rollback()
            .await
            .expect_err("nothing left to roll back");
        assert!(error.to_string().contains("no router transaction"));
    }

    #[tokio::test]
    async fn wait_until_idle_wakes_after_rollback() {
        let fake = FakeSubsystems::new();
        let (coordinator, overrides, _directory) = coordinator_with(fake).await;
        let candidate = build_candidate(&overrides).await;
        let plan = coordinator.plan(candidate).await.expect("plan");
        coordinator.apply(plan).await.expect("apply");

        let waiter = tokio::spawn({
            let coordinator = coordinator.clone();
            async move { coordinator.wait_until_idle().await }
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        coordinator.rollback().await.expect("rollback");
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("idle waiter wake")
            .expect("waiter task");
    }

    async fn stage_test_secret(
        directory: &std::path::Path,
    ) -> crate::core::provisioning_secret_transaction::ProvisioningSecretTransactionStore {
        use crate::wifi::{secret::WifiPassphrase, store::PassphraseStore};
        let secrets = crate::core::provisioning_secret_transaction::ProvisioningSecretTransactionStore::in_state_dir(directory);
        secrets
            .stage(std::collections::BTreeMap::from([(
                "wlan0".into(),
                Some(WifiPassphrase::new("old-password").unwrap()),
            )]))
            .await
            .unwrap();
        PassphraseStore::new(directory.join("wifi/psk"))
            .set("wlan0", &WifiPassphrase::new("new-password").unwrap())
            .unwrap();
        secrets
    }

    #[tokio::test]
    async fn provisioning_timeout_restores_secrets_before_runtime_rollback() {
        let fake = FakeSubsystems::new();
        let (_, overrides, directory) = coordinator_with(fake.clone()).await;
        let coordinator = RouterTransactionCoordinator::new(
            RouterManager::new(fake.clone()),
            overrides.clone(),
            Duration::from_secs(60),
        );
        let secrets = stage_test_secret(directory.path()).await;
        *fake.rollback_secret.lock().unwrap() = Some(directory.path().to_path_buf());
        let plan = coordinator
            .plan(build_candidate(&overrides).await)
            .await
            .unwrap();
        let token = coordinator.apply(plan).await.unwrap();
        secrets.bind_token(&token).await.unwrap();

        coordinator.rollback_timeout_fired(&token).await;

        assert_eq!(coordinator.status().await, CoordinatorStatus::Idle);
        assert!(!secrets
            .unresolved_after_committed_cleanup(None)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn provisioning_rollback_failure_retains_secret_journal_for_retry() {
        let fake = FakeSubsystems::new();
        let (_, overrides, directory) = coordinator_with(fake.clone()).await;
        let coordinator = RouterTransactionCoordinator::new(
            RouterManager::new(fake.clone()),
            overrides.clone(),
            Duration::from_secs(60),
        );
        let secrets = stage_test_secret(directory.path()).await;
        *fake.rollback_secret.lock().unwrap() = Some(directory.path().to_path_buf());
        let plan = coordinator
            .plan(build_candidate(&overrides).await)
            .await
            .unwrap();
        let token = coordinator.apply(plan).await.unwrap();
        secrets.bind_token(&token).await.unwrap();
        fake.fail_rollback("rollback_dhcp");

        assert!(coordinator.rollback_with_token(&token).await.is_err());
        assert_eq!(
            coordinator.status().await,
            CoordinatorStatus::RollbackFailed
        );
        assert!(secrets
            .unresolved_after_committed_cleanup(None)
            .await
            .unwrap());
        assert!(coordinator.commit(&token).await.is_err());

        *fake.rollback_fail.lock().unwrap() = None;
        coordinator.rollback_with_token(&token).await.unwrap();
        assert!(!secrets
            .unresolved_after_committed_cleanup(None)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn provisioning_secret_restore_failure_blocks_commit_and_can_be_retried() {
        let fake = FakeSubsystems::new();
        let (_, overrides, directory) = coordinator_with(fake.clone()).await;
        let coordinator = RouterTransactionCoordinator::new(
            RouterManager::new(fake),
            overrides.clone(),
            Duration::from_secs(60),
        );
        let secrets = stage_test_secret(directory.path()).await;
        let plan = coordinator
            .plan(build_candidate(&overrides).await)
            .await
            .unwrap();
        let token = coordinator.apply(plan).await.unwrap();
        secrets.bind_token(&token).await.unwrap();
        let secret_path = directory.path().join("wifi/psk/wlan0");
        std::fs::remove_file(&secret_path).unwrap();
        std::fs::create_dir(&secret_path).unwrap();

        assert!(coordinator.rollback_with_token(&token).await.is_err());
        assert_eq!(
            coordinator.status().await,
            CoordinatorStatus::RollbackFailed
        );
        assert!(coordinator.commit(&token).await.is_err());
        assert!(secrets
            .unresolved_after_committed_cleanup(None)
            .await
            .unwrap());

        std::fs::remove_dir(&secret_path).unwrap();
        coordinator.rollback_with_token(&token).await.unwrap();
        assert_eq!(coordinator.status().await, CoordinatorStatus::Idle);
        assert!(!secrets
            .unresolved_after_committed_cleanup(None)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn provisioning_apply_failure_restores_unbound_secret_before_compensation() {
        let fake = FakeSubsystems::new();
        let (coordinator, overrides, directory) = coordinator_with(fake.clone()).await;
        let secrets = stage_test_secret(directory.path()).await;
        *fake.rollback_secret.lock().unwrap() = Some(directory.path().to_path_buf());
        fake.fail_apply("apply_routes");
        let plan = coordinator
            .plan(build_candidate(&overrides).await)
            .await
            .unwrap();

        assert!(coordinator.apply(plan).await.is_err());
        assert_eq!(coordinator.status().await, CoordinatorStatus::Idle);
        assert!(!secrets
            .unresolved_after_committed_cleanup(None)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn timeout_rolls_back_uncommitted_transaction() {
        let fake = FakeSubsystems::new();
        let (coordinator, overrides, _directory) = coordinator_with(fake.clone()).await;
        let candidate = build_candidate(&overrides).await;
        let plan = coordinator.plan(candidate).await.expect("plan");
        coordinator.apply(plan).await.expect("apply");
        assert_eq!(coordinator.status().await, CoordinatorStatus::Pending);

        tokio::time::sleep(Duration::from_millis(150)).await;

        assert_eq!(coordinator.status().await, CoordinatorStatus::Idle);
        assert_eq!(overrides.committed_revision().await, 0);
    }

    #[tokio::test]
    async fn timeout_does_not_roll_back_an_already_committed_transaction() {
        let fake = FakeSubsystems::new();
        let (coordinator, overrides, _directory) = coordinator_with(fake.clone()).await;
        let candidate = build_candidate(&overrides).await;
        let plan = coordinator.plan(candidate).await.expect("plan");
        coordinator.apply(plan).await.expect("apply");
        coordinator
            .commit(&coordinator.pending_token().await.unwrap_or_default())
            .await
            .expect("commit before timeout");

        tokio::time::sleep(Duration::from_millis(150)).await;

        assert_eq!(coordinator.status().await, CoordinatorStatus::Idle);
        assert_eq!(overrides.committed_revision().await, 1);
        assert!(!fake
            .events()
            .iter()
            .any(|event| event.starts_with("rollback_")));
    }

    #[tokio::test]
    async fn rollback_restores_router_ownership_from_committed_intent() {
        let fake = FakeSubsystems::new();
        let (coordinator, overrides, _directory) = coordinator_with(fake.clone()).await;

        let initial = build_candidate(&overrides).await;
        let initial_plan = coordinator.plan(initial).await.expect("initial plan");
        let initial_token = coordinator.apply(initial_plan).await.expect("initial apply");
        coordinator.commit(&initial_token).await.expect("initial commit");

        let expected = overrides
            .build_candidate(&RouterIntentProposal::new())
            .await
            .expect("committed candidate")
            .desired()
            .interfaces
            .iter()
            .map(|entry| entry.name.clone())
            .collect::<Vec<_>>();

        let candidate = overrides
            .build_candidate(&RouterIntentProposal::new().set_interface(
                "lan1",
                output_interface("192.168.20.1/24", 100, 150),
                false,
            ))
            .await
            .expect("candidate with extra interface");
        let plan = coordinator.plan(candidate).await.expect("plan");
        coordinator.apply(plan).await.expect("apply");
        coordinator.rollback().await.expect("rollback");

        assert_eq!(fake.retained().last(), Some(&expected));
    }

    #[tokio::test]
    async fn apply_failure_restores_router_ownership_from_committed_intent() {
        let fake = FakeSubsystems::new();
        let (coordinator, overrides, _directory) = coordinator_with(fake.clone()).await;

        let initial = build_candidate(&overrides).await;
        let initial_plan = coordinator.plan(initial).await.expect("initial plan");
        let initial_token = coordinator.apply(initial_plan).await.expect("initial apply");
        coordinator.commit(&initial_token).await.expect("initial commit");

        let expected = overrides
            .build_candidate(&RouterIntentProposal::new())
            .await
            .expect("committed candidate")
            .desired()
            .interfaces
            .iter()
            .map(|entry| entry.name.clone())
            .collect::<Vec<_>>();

        let candidate = overrides
            .build_candidate(&RouterIntentProposal::new().set_interface(
                "lan1",
                output_interface("192.168.20.1/24", 100, 150),
                false,
            ))
            .await
            .expect("candidate with extra interface");
        let plan = coordinator.plan(candidate).await.expect("plan");
        fake.fail_apply("apply_dhcp");
        coordinator.apply(plan).await.expect_err("apply must fail");

        assert_eq!(coordinator.status().await, CoordinatorStatus::Idle);
        assert_eq!(fake.retained().last(), Some(&expected));
    }

    #[tokio::test]
    async fn incomplete_rollback_enters_recovery_state_and_can_be_retried() {
        let fake = FakeSubsystems::new();
        let (coordinator, overrides, _directory) = coordinator_with(fake.clone()).await;
        let candidate = build_candidate(&overrides).await;
        let plan = coordinator.plan(candidate).await.expect("plan");
        coordinator.apply(plan).await.expect("apply");

        fake.fail_rollback("rollback_dhcp");
        let error = coordinator
            .rollback()
            .await
            .expect_err("partial rollback failure");
        assert!(error.to_string().contains("rollback_dhcp"));
        assert_eq!(
            coordinator.status().await,
            CoordinatorStatus::RollbackFailed
        );
        let failure = coordinator
            .rollback_failure()
            .await
            .expect("recorded failure");
        assert!(failure.failures.iter().any(|f| f.contains("rollback_dhcp")));

        let blocked_candidate = build_candidate(&overrides).await;
        let blocked_plan = coordinator
            .plan(blocked_candidate)
            .await
            .expect("plan during recovery");
        let apply_error = coordinator
            .apply(blocked_plan)
            .await
            .expect_err("apply must be blocked during recovery");
        assert!(apply_error.to_string().contains("recovery state"));

        *fake.rollback_fail.lock().unwrap() = None;
        coordinator.rollback().await.expect("retry rollback");
        assert_eq!(coordinator.status().await, CoordinatorStatus::Idle);
    }

    #[tokio::test]
    async fn apply_failure_leaves_coordinator_idle() {
        let fake = FakeSubsystems::new();
        let (coordinator, overrides, _directory) = coordinator_with(fake.clone()).await;
        let candidate = build_candidate(&overrides).await;
        let plan = coordinator.plan(candidate).await.expect("plan");

        fake.fail_apply("apply_dhcp");
        let error = coordinator.apply(plan).await.expect_err("apply must fail");
        assert!(error.to_string().contains("injected apply_dhcp failure"));
        assert_eq!(coordinator.status().await, CoordinatorStatus::Idle);
    }
}
