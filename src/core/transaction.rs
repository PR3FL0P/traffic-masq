use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};
use tokio::sync::{Mutex, RwLock};

use crate::config::{InterfaceConfig, InterfaceRole};

use crate::core::desired::{ConvergerState, DesiredNetworkState};
use crate::core::interface::{
    DhcpChangeAction, InterfaceChangePlan, InterfaceManager, InterfaceSnapshot,
};
use crate::core::mutation::NetworkMutationGate;
use crate::core::recovery_control;
use crate::dhcp::supervisor::{DhcpServiceSpec, DhcpSupervisor};
use crate::wifi::secret::WifiPassphraseUpdate;

mod credentials;
mod journal;
mod recovery;
use credentials::{PreparedCredentialChange, SecretSnapshot};
use journal::{InterfaceJournal, InterfaceJournalStore};
pub(crate) use recovery::retry_interface_recovery;
pub use recovery::{
    block_interface_transactions_without_commit_proof, recover_interface_transactions,
    recover_interface_transactions_with_commit_tokens,
    recover_interface_transactions_with_commit_tokens_excluding,
};
pub use traffic_masq_protocol::{NetworkChangePhase, PendingNetworkChange};

/// How long an apply waits for convergence to reach what it proposed.
///
/// A deadline, not a poll: nothing here wakes up to ask whether anything has
/// changed. It exists so that a converger which has stopped — a bug, or a
/// daemon on its way down — turns into an error the operator can see instead of
/// a request that never answers.
// Wi-Fi association and DHCP readiness run sequentially. Cover both startup
// budgets and leave headroom for the other convergence work.
const CONVERGENCE_DEADLINE: Duration = crate::wifi::lifecycle::STARTUP_READY_TIMEOUT
    .saturating_add(crate::dhcp::client::supervisor::LEASE_READY_TIMEOUT)
    .saturating_add(Duration::from_secs(5));

/// Applies interface changes by proposing them as desired state.
///
/// The manager does not write to the kernel. It puts a change into the
/// tentative layer of [`DesiredNetworkState`], waits for the converger to
/// report a pass that had already seen it, and keeps the bookkeeping —
/// token, expiry, rollback timer — that turns "the machine now looks like
/// this" into "and it stays that way only if you confirm".
///
/// Dropping an in-flight apply transfers compensation to a background task.
/// Restoration must still be verified by convergence; storage/conflict stops
/// leave a visible recovery token requiring explicit rollback.
///
/// Commit always persists configuration and its recovery token through the
/// shared desired state's override manager. Custom persistence callbacks are
/// not part of the public transaction contract.
/// The desired state is supplied at construction and remains shared for the
/// entire lifetime of the manager and its pending transactions.
///
/// ```compile_fail
/// use traffic_masq::core::transaction::NetworkTransactionManager;
/// async fn bypass_persistence(manager: &NetworkTransactionManager) {
///     manager.commit_with("token", |_, _, _| async { Ok(()) }).await.unwrap();
/// }
/// ```
///
/// ```compile_fail
/// use traffic_masq::core::{desired::DesiredNetworkState, transaction::NetworkTransactionManager};
/// fn replace_state(manager: &NetworkTransactionManager, desired: DesiredNetworkState) {
///     manager.set_desired_state(desired);
/// }
/// ```
#[derive(Clone)]
pub struct NetworkTransactionManager {
    inner: Arc<Inner>,
}

/// One tentative interface change, including the previous configuration used
/// to plan transitions and the explicit credential operation.
pub struct InterfaceChange<'a> {
    pub config: &'a InterfaceConfig,
    pub previous: Option<&'a InterfaceConfig>,
    pub current_role: Option<InterfaceRole>,
    pub passphrase: WifiPassphraseUpdate,
    pub allow_management_change: bool,
}

struct Inner {
    interface_manager: InterfaceManager,
    rollback_timeout: Duration,
    pending: Mutex<HashMap<String, PendingTransaction>>,
    /// What the interfaces looked like before the daemon touched anything,
    /// restored on shutdown. Nothing to do with transactions: by then the
    /// converger is gone, so this is the one path that still writes directly.
    baselines: Mutex<HashMap<String, InterfaceSnapshot>>,
    operation_lock: Arc<RwLock<()>>,
    runtime_gate: std::sync::Mutex<Option<Arc<NetworkMutationGate>>>,
    require_converger: std::sync::atomic::AtomicBool,
    token_counter: AtomicU64,
    timer_epochs: std::sync::Mutex<HashMap<String, u64>>,
    dhcp: Option<DhcpSupervisor>,
    default_lease_seconds: u32,
    desired: DesiredNetworkState,
}

#[derive(Clone)]
struct PendingTransaction {
    info: PendingNetworkChange,
    confirmation_deadline: Option<tokio::time::Instant>,
    target: InterfaceConfig,
    allow_management_change: bool,
    snapshot: InterfaceSnapshot,
    previous_config: Option<InterfaceConfig>,
    secret: Option<SecretSnapshot>,
}

/// Keep compensation owned across every await between the first proposal and
/// the confirmation timer. The pending snapshot is registered before mutation.
struct ApplyRecoveryGuard {
    manager: NetworkTransactionManager,
    token: String,
    armed: bool,
}

impl Drop for ApplyRecoveryGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let manager = self.manager.clone();
        let token = self.token.clone();
        tokio::spawn(async move {
            let _operation = manager.inner.operation_lock.read().await;
            let interface = manager
                .inner
                .pending
                .lock()
                .await
                .get(&token)
                .map(|pending| pending.info.interface.clone());
            let Some(interface) = interface else {
                return;
            };
            let _interface_operation = manager.desired().transaction_locks.lock(&interface).await;
            if !manager.inner.pending.lock().await.contains_key(&token) {
                return;
            }
            let path = manager.journal_path(&interface);
            let prepared = async {
                manager.recovery().check_rollback_scope(
                    manager.desired().state_dir(),
                    Some(&interface),
                    &path,
                )?;
                manager.recovery().compensate_cancelled_apply(&path).await
            }
            .await;
            if let Err(error) = prepared {
                tracing::error!(%token, error = %format!("{error:#}"), "cancelled apply requires explicit recovery");
                if let Some(pending) = manager.inner.pending.lock().await.get_mut(&token) {
                    pending.info.phase = NetworkChangePhase::RecoveryRequired;
                    pending.info.last_error = Some(format!("{error:#}"));
                }
                return;
            }
            if let Err(error) = manager.rollback_locked(&token, false).await {
                tracing::error!(%token, error = %format!("{error:#}"), "cancelled apply compensation failed");
                if !manager.recovery().stopped(&path) {
                    manager.spawn_timer(token, false);
                }
            }
        });
    }
}

impl NetworkTransactionManager {
    /// Attach the shared gate used to serialize transaction state with runtime mutations.
    pub(crate) fn set_runtime_gate(&self, gate: Arc<NetworkMutationGate>) {
        *self.inner.runtime_gate.lock().expect("runtime gate lock") = Some(gate);
    }

    #[cfg(test)]
    pub(crate) fn require_converger(&self, required: bool) {
        self.inner
            .require_converger
            .store(required, Ordering::SeqCst);
    }

    fn runtime_gate(&self) -> Option<Arc<NetworkMutationGate>> {
        self.inner
            .runtime_gate
            .lock()
            .expect("runtime gate lock")
            .clone()
    }

    /// Recognize addresses owned by the interface manager or tagged as daemon DHCP addresses.
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

    /// Create a transaction manager requiring a running converger.
    /// No startup baselines or DHCP supervisor are installed.
    pub fn new(
        interface_manager: InterfaceManager,
        rollback_timeout: Duration,
        desired: DesiredNetworkState,
    ) -> Self {
        Self::new_with_baselines(interface_manager, rollback_timeout, Vec::new(), desired)
    }

    /// Create a manager permitting apply without a converger for tests and tooling.
    /// Detached apply reports acceptance of intent, not runtime convergence.
    /// Failed or stopped convergers still cause apply to fail.
    pub fn new_detached(
        interface_manager: InterfaceManager,
        rollback_timeout: Duration,
        desired: DesiredNetworkState,
    ) -> Self {
        Self::build(
            interface_manager,
            rollback_timeout,
            Vec::new(),
            None,
            1,
            desired,
            false,
        )
    }

    /// Create a manager requiring a running converger, with startup snapshots to restore.
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
            true,
        )
    }

    /// Create a manager requiring a running converger, with startup snapshots and DHCP-aware previews.
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
            true,
        )
    }

    pub(crate) fn new_detached_with_services(
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
            false,
        )
    }

    fn build(
        interface_manager: InterfaceManager,
        rollback_timeout: Duration,
        baselines: Vec<InterfaceSnapshot>,
        dhcp: Option<DhcpSupervisor>,
        default_lease_seconds: u32,
        desired: DesiredNetworkState,
        require_converger: bool,
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
                operation_lock: Arc::new(RwLock::new(())),
                runtime_gate: std::sync::Mutex::new(None),
                require_converger: std::sync::atomic::AtomicBool::new(require_converger),
                token_counter: AtomicU64::new(0),
                timer_epochs: std::sync::Mutex::new(HashMap::new()),
                dhcp,
                default_lease_seconds,
                desired,
            }),
        }
    }

    pub fn recovery(&self) -> &crate::core::recovery::RecoveryState {
        self.inner.desired.recovery()
    }

    fn desired(&self) -> DesiredNetworkState {
        self.inner.desired.clone()
    }

    /// Preview an interface change without modifying desired state or kernel configuration.
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

    /// Preview an interface transition, including DHCP start, stop, or reconfiguration.
    pub async fn dry_run_transition(
        &self,
        interface: &str,
        config: &InterfaceConfig,
        previous_config: Option<&InterfaceConfig>,
        current_role: Option<InterfaceRole>,
        allow_management_change: bool,
    ) -> Result<InterfaceChangePlan> {
        let mut network = self.desired().effective().await?.network;
        network
            .interfaces
            .insert(interface.to_owned(), config.clone());
        self.inner
            .interface_manager
            .validate_wifi_radio_policy(&network)?;
        if config.wifi_concurrent {
            crate::wifi::concurrent::validate(interface).await?;
        }
        if previous_config.is_some_and(|previous| previous.wifi_concurrent)
            && !config.wifi_concurrent
        {
            let ap = crate::wifi::concurrent::ap_name(interface);
            anyhow::ensure!(
                !network
                    .interfaces
                    .get(&ap)
                    .is_some_and(|c| c.managed || c.wifi.is_some() || c.dhcp.is_some()),
                "disable and unmanage virtual AP {ap} before leaving Input + Output"
            );
        }
        if let Some(parent) = crate::wifi::concurrent::parent_for(&network, interface) {
            anyhow::ensure!(
                !self.desired().is_tentative(parent).await,
                "Commit Input + Output on {parent} before configuring its virtual AP"
            );
            anyhow::ensure!(
                config.mac_address.is_none(),
                "virtual AP MAC is managed by Input + Output"
            );
        }
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

    /// Journal the original interface and explicit secret operation before proposing a change.
    /// Wait for convergence and require confirmation before the deadline; failed rollback
    /// remains visible and journaled so recovery can be retried.
    pub async fn apply(
        &self,
        interface: &str,
        change: InterfaceChange<'_>,
    ) -> Result<PendingNetworkChange> {
        let InterfaceChange {
            config,
            previous: previous_config,
            current_role,
            passphrase: passphrase_update,
            allow_management_change,
        } = change;
        let _operation = self.inner.operation_lock.clone().read_owned().await;
        let _interface_operation = self.desired().transaction_locks.lock(interface).await;
        let desired = self.desired();
        let gate = self.runtime_gate();
        let execution = match &gate {
            Some(gate) => Some(gate.participate().await),
            None => None,
        };

        let lane = desired.runtime_locks.lock(interface).await;
        self.recovery()
            .check_scope(desired.state_dir(), Some(interface))?;
        if self.inner.require_converger.load(Ordering::SeqCst) {
            anyhow::ensure!(
                matches!(desired.converger_state(), ConvergerState::Running),
                "network converger unavailable: runtime worker is not running"
            );
        }
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
        // Retain _interface_operation while holding the lane and waiting here:
        // recovery holds the credential writer and skips transaction-owned lanes.
        // See docs/architecture.md, "Interface lock ordering".
        let credential_update = desired.credential_updates.clone().read_owned().await;
        let root = desired.state_dir().to_path_buf();
        let name = interface.to_owned();
        let target = config.clone();
        let previous = previous_config.clone();
        let credentials = tokio::task::spawn_blocking(move || {
            PreparedCredentialChange::prepare(
                &root,
                &name,
                &target,
                previous.as_ref(),
                passphrase_update,
            )
        })
        .await??;
        let secret = credentials.snapshot.clone();
        let pending = PendingTransaction {
            info: PendingNetworkChange {
                recovery_progress: None,
                token: token.clone(),
                interface: interface.to_owned(),
                rollback_timeout_seconds: self.inner.rollback_timeout.as_secs(),
                expires_at_unix: 0,
                phase: NetworkChangePhase::RollbackRequired,
                last_error: None,
            },
            confirmation_deadline: None,
            target: config.clone(),
            allow_management_change,
            snapshot: snapshot.clone(),
            previous_config: previous_config.clone(),
            secret: secret.clone(),
        };
        let manager = self.clone();
        // Registration owns the reservations until durable and volatile state
        // agree. Cancelling the caller detaches this short task; its returned
        // recovery guard then hands the registered transaction to compensation.
        let (
            _operation,
            _interface_operation,
            lane,
            credential_update,
            execution,
            mut cancellation,
        ) = tokio::spawn(async move {
            manager
                .write_journal_record(
                    &pending.info.token,
                    pending.snapshot.clone(),
                    pending.secret.clone(),
                )
                .await?;
            let token = pending.info.token.clone();
            manager
                .inner
                .pending
                .lock()
                .await
                .insert(token.clone(), pending);
            let cancellation = ApplyRecoveryGuard {
                manager,
                token,
                armed: true,
            };
            Ok::<_, anyhow::Error>((
                _operation,
                _interface_operation,
                lane,
                credential_update,
                execution,
                cancellation,
            ))
        })
        .await??;
        let (apply_guard, stage_error) = match self
            .recovery()
            .begin_apply(&self.journal_path(interface))
            .await
        {
            Ok(guard) => (Some(guard), None),
            Err(error) => (None, Some(error)),
        };
        // Blocking storage retains its reservations even if shutdown cancels
        // the awaiting task. Compensation cannot race a late credential write.
        let name = interface.to_owned();
        let (lane, credential_update, execution, staged) = tokio::task::spawn_blocking(move || {
            let result = match stage_error {
                Some(error) => Err(error),
                None => credentials.apply(&name),
            };
            (lane, credential_update, execution, result)
        })
        .await?;
        if staged.is_ok() {
            desired
                .propose(&token, interface, config.clone(), allow_management_change)
                .await;
        }
        drop(credential_update);
        drop(lane);
        drop(execution);
        let mut applied = match staged {
            Ok(()) => self.await_convergence(&desired, interface).await,
            Err(error) => Err(error),
        };
        if let Some(guard) = apply_guard {
            if let Err(error) = guard.finish().await {
                applied = Err(error);
            }
        }
        if let Err(error) = applied {
            let running_network_managers = if config.wifi_client.is_some() {
                crate::wifi::process::find_competing_network_managers().await
            } else {
                Vec::new()
            };
            tracing::warn!(%interface, %token, error = %format!("{error:#}"), ?running_network_managers, "interface change failed; restoring previous configuration");
            let path = self.journal_path(interface);
            let rollback = self
                .recovery()
                .run(&path, false, async {
                    self.recovery().check_rollback_scope(
                        desired.state_dir(),
                        Some(interface),
                        &path,
                    )?;
                    let execution = match &gate {
                        Some(gate) => Some(gate.participate().await),
                        None => None,
                    };
                    let lane = desired.runtime_locks.lock(interface).await;
                    // Persistence in another scope may have become uncertain
                    // while compensation waited for its runtime reservation/lane.
                    self.recovery().check_commit(desired.state_dir())?;
                    let credential_update = desired.credential_updates.clone().read_owned().await;
                    let secret = secret.clone();
                    let root = desired.state_dir().to_path_buf();
                    let name = interface.to_owned();
                    let (lane, credential_update, execution, secret_restored) =
                        tokio::task::spawn_blocking(move || {
                            let result = match secret {
                                Some(secret) => secret.restore(&root, &name),
                                None => Ok(()),
                            };
                            (lane, credential_update, execution, result)
                        })
                        .await?;
                    desired
                        .restore(&token, snapshot.clone(), previous_config.clone())
                        .await;
                    drop(credential_update);
                    drop(lane);
                    drop(execution);
                    let restoration = match secret_restored {
                        Ok(()) => self.await_convergence(&desired, interface).await,
                        Err(error) => Err(error),
                    };
                    match restoration {
                        Ok(()) => self.clear_journal(interface).await,
                        Err(error) => Err(error),
                    }
                })
                .await;
            if let Err(rollback_error) = rollback {
                // The requested state is no longer desired, but until a fresh
                // convergence pass proves the committed state was restored the
                // transaction must stay visible and block overlapping network
                // mutations. The token is rollback-only: a failed candidate
                // must never become committable merely because compensation
                // also failed.
                let rollback_timeout_seconds = self.inner.rollback_timeout.as_secs();
                let info = PendingNetworkChange {
                    recovery_progress: None,
                    token: token.clone(),
                    interface: interface.to_string(),
                    rollback_timeout_seconds,
                    expires_at_unix: current_unix_time().saturating_add(rollback_timeout_seconds),
                    phase: if self.recovery().stopped(&path) {
                        NetworkChangePhase::RecoveryRequired
                    } else {
                        NetworkChangePhase::RollbackRequired
                    },
                    last_error: Some(format!("apply: {error:#}; rollback: {rollback_error:#}")),
                };
                self.inner.pending.lock().await.insert(
                    token.clone(),
                    PendingTransaction {
                        info,
                        confirmation_deadline: None,
                        target: config.clone(),
                        allow_management_change,
                        snapshot: snapshot.clone(),
                        previous_config: previous_config.clone(),
                        secret: secret.clone(),
                    },
                );
                self.spawn_timer(token.clone(), false);
                cancellation.armed = false;
                bail!(
                    "network change failed to converge: {error}; rollback also failed: {rollback_error}; recovery remains pending as token {token}"
                );
            }
            desired.withdraw(&token).await;
            self.inner.pending.lock().await.remove(&token);
            cancellation.armed = false;
            return Err(error);
        }

        // Dated from here, not from the proposal: the confirmation window is
        // the time the operator has to look at a machine that already changed,
        // and it starts when the machine changed.
        let rollback_timeout_seconds = self.inner.rollback_timeout.as_secs();
        let info = PendingNetworkChange {
            recovery_progress: None,
            token,
            interface: interface.to_string(),
            rollback_timeout_seconds,
            expires_at_unix: current_unix_time().saturating_add(rollback_timeout_seconds),
            phase: NetworkChangePhase::AwaitingCommit,
            last_error: None,
        };

        self.inner.pending.lock().await.insert(
            info.token.clone(),
            PendingTransaction {
                info: info.clone(),
                confirmation_deadline: Some(
                    tokio::time::Instant::now() + self.inner.rollback_timeout,
                ),
                target: config.clone(),
                allow_management_change,
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
        cancellation.armed = false;
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
        match desired.converger_state() {
            ConvergerState::Detached if !self.inner.require_converger.load(Ordering::SeqCst) => {
                return Ok(())
            }
            ConvergerState::Detached => {
                bail!("network converger unavailable: runtime worker is not running")
            }
            ConvergerState::Running => {}
            ConvergerState::Failed(error) => {
                bail!("network converger unavailable: {error}")
            }
            ConvergerState::Stopped => bail!("network converger unavailable: stopped"),
        }

        let version = desired.interface_revision(interface);
        let pass = match tokio::time::timeout(CONVERGENCE_DEADLINE, desired.interface_pass_covering(interface, version))
            .await
        {
            Ok(pass) => pass,
            Err(_) => return Err(recovery_control::failure(recovery_control::FailureKind::Transient,
                format!("timed out waiting for interface {interface} to be converged to the requested configuration"))),
        };

        anyhow::ensure!(
            desired.interface_revision(interface) == version,
            "interface {interface} intent was superseded while awaiting convergence"
        );
        if let Some(error) = pass.error {
            return Err(recovery_control::failure(
                pass.error_kind
                    .unwrap_or(recovery_control::FailureKind::Unknown),
                format!("convergence failed: {error}"),
            ));
        }
        match pass.failures.get(interface) {
            Some(error) => Err(recovery_control::failure(
                pass.failure_kinds
                    .get(interface)
                    .copied()
                    .unwrap_or(recovery_control::FailureKind::Unknown),
                error.clone(),
            )),
            None => Ok(()),
        }
    }

    /// Persist the pending interface change and retire its tentative state after persistence succeeds.
    pub async fn commit(&self, token: &str) -> Result<PendingNetworkChange> {
        let desired = self.desired();
        self.commit_with(token, |interface, config, allow| async move {
            desired
                .commit_interface(token, interface, config, allow)
                .await
        })
        .await
    }

    /// Confirm a pending change through the supplied persistence callback.
    /// A failed callback leaves the transaction pending; rollback-only changes cannot be committed.
    async fn commit_with<F, Fut>(&self, token: &str, persist: F) -> Result<PendingNetworkChange>
    where
        F: FnOnce(String, InterfaceConfig, bool) -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        let _operation = self.inner.operation_lock.read().await;
        let interface = self.interface_for_token(token).await?;
        let _interface_operation = self.desired().transaction_locks.lock(&interface).await;
        // Publish the committed layer and remove the proposal as one runtime
        // operation. Otherwise a pass can read the old overrides followed by
        // the newly empty tentative layer and briefly undo a confirmed change.
        let gate = self.runtime_gate();
        let _execution = match &gate {
            Some(gate) => Some(gate.participate().await),
            None => None,
        };
        let desired = self.desired();
        let _lane = desired.runtime_locks.lock(&interface).await;
        self.recovery().check_commit(desired.state_dir())?;
        let (interface, target, allow_management_change) = {
            let pending = self.inner.pending.lock().await;
            let pending = pending
                .get(token)
                .ok_or_else(|| anyhow::anyhow!("pending network change not found: {token}"))?;
            anyhow::ensure!(
                pending.info.can_commit(),
                "network change {token} failed during apply and is rollback-only"
            );
            anyhow::ensure!(
                pending
                    .confirmation_deadline
                    .is_some_and(|deadline| tokio::time::Instant::now() < deadline),
                "network change {token} confirmation deadline expired"
            );
            (
                pending.info.interface.clone(),
                pending.target.clone(),
                pending.allow_management_change,
            )
        };

        if let Err(error) = persist(interface.clone(), target, allow_management_change).await {
            let mut pending = self.inner.pending.lock().await;
            let entry = pending.get_mut(token).expect("operation lock held");
            entry.info.last_error = Some(format!("{error:#}"));
            if crate::atomic_file::is_indeterminate_write(&error) {
                self.recovery()
                    .fence_commit(self.desired().state_dir(), format!("{error:#}"));
                entry.info.phase = NetworkChangePhase::CommitIndeterminate;
            }
            return Err(error);
        }

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

        self.inner
            .timer_epochs
            .lock()
            .expect("interface timer epoch lock")
            .remove(token);
        if let Err(error) = self.clear_journal(&interface).await {
            // Durable commit tokens prove this journal is obsolete. Let the
            // normal recovery sweep retry retirement after storage recovers.
            self.recovery().block_interface(
                desired.state_dir(),
                &interface,
                format!("committed journal cleanup pending: {error:#}"),
            );
            tracing::warn!(error = %format!("{error:#}"), "failed to remove committed interface journal");
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
        self.rollback_inner(token, true).await
    }

    async fn rollback_inner(&self, token: &str, manual: bool) -> Result<PendingNetworkChange> {
        let _operation = self.inner.operation_lock.read().await;
        let interface = self.interface_for_token(token).await?;
        let _interface_operation = self.desired().transaction_locks.lock(&interface).await;
        self.rollback_locked(token, manual).await
    }

    async fn interface_for_token(&self, token: &str) -> Result<String> {
        self.import_stopped_journals().await?;
        self.inner
            .pending
            .lock()
            .await
            .get(token)
            .map(|pending| pending.info.interface.clone())
            .ok_or_else(|| anyhow::anyhow!("pending network change not found: {token}"))
    }

    async fn rollback_for_epoch(
        &self,
        token: &str,
        epoch: u64,
    ) -> Result<Option<PendingNetworkChange>> {
        let _operation = self.inner.operation_lock.read().await;
        let Ok(interface) = self.interface_for_token(token).await else {
            return Ok(None);
        };
        let _interface_operation = self.desired().transaction_locks.lock(&interface).await;
        // An explicit retry may replace this timer while it waits for the
        // operation lock. Only the current timer may start another attempt.
        if self
            .inner
            .timer_epochs
            .lock()
            .expect("interface timer epoch lock")
            .get(token)
            != Some(&epoch)
        {
            return Ok(None);
        }
        self.rollback_locked(token, false).await.map(Some)
    }

    // The caller holds this interface's operation lock throughout restoration and bookkeeping.
    async fn rollback_locked(&self, token: &str, manual: bool) -> Result<PendingNetworkChange> {
        self.import_stopped_journals().await?;
        self.recovery().check_commit(self.desired().state_dir())?;
        let pending = {
            let mut pending = self.inner.pending.lock().await;
            let entry = pending
                .get_mut(token)
                .ok_or_else(|| anyhow::anyhow!("pending network change not found: {token}"))?;
            entry.info.phase = NetworkChangePhase::RollbackRequired;
            entry.clone()
        };
        tracing::info!(
            interface = %pending.info.interface,
            %token,
            "network change is being rolled back; the committed configuration will be converged to"
        );
        let path = self.journal_path(&pending.info.interface);
        if self
            .desired()
            .committed_overrides()
            .await
            .committed_interface_transactions
            .get(&pending.info.interface)
            .map(String::as_str)
            == Some(token)
        {
            let desired = self.desired();
            let _lane = desired.runtime_locks.lock(&pending.info.interface).await;
            desired.withdraw(token).await;
            self.clear_journal(&pending.info.interface).await?;
            self.inner.pending.lock().await.remove(token);
            self.inner
                .timer_epochs
                .lock()
                .expect("interface timer epoch lock")
                .remove(token);
            if manual {
                bail!("network change {token} was already committed; rollback is unavailable");
            }
            return Ok(pending.info);
        }
        self.recovery().check_rollback_scope(
            self.desired().state_dir(),
            Some(&pending.info.interface),
            &path,
        )?;
        let restoration = self
            .recovery()
            .run(&path, manual, async {
                // Startup transaction blocks are retryable. Ownership blocks remain fenced.
                if self
                    .recovery()
                    .retryable_blocked_interfaces(self.desired().state_dir())
                    .contains(&pending.info.interface)
                {
                    self.recovery()
                        .unblock_interface(self.desired().state_dir(), &pending.info.interface);
                }
                let desired = self.desired();
                let gate = self.runtime_gate();
                let execution = match &gate {
                    Some(gate) => Some(gate.participate().await),
                    None => None,
                };
                let lane = desired.runtime_locks.lock(&pending.info.interface).await;
                // A different persistence operation may have fenced the network
                // while compensation was waiting for exclusive runtime access.
                self.recovery().check_commit(desired.state_dir())?;
                let credential_update = desired.credential_updates.clone().read_owned().await;
                let secret = pending.secret.clone();
                let root = desired.state_dir().to_path_buf();
                let name = pending.info.interface.clone();
                let (lane, credential_update, execution, secret_restored) =
                    tokio::task::spawn_blocking(move || {
                        let result = match secret {
                            Some(secret) => secret.restore(&root, &name),
                            None => Ok(()),
                        };
                        (lane, credential_update, execution, result)
                    })
                    .await?;
                // Publishing rollback intent must not depend on secret-store I/O. If
                // restoring the passphrase fails, keep the transaction rollback-only
                // and journaled, but still stop converging toward the failed candidate.
                desired
                    .restore(
                        token,
                        pending.snapshot.clone(),
                        pending.previous_config.clone(),
                    )
                    .await;
                drop(credential_update);
                drop(lane);
                drop(execution);
                match secret_restored {
                    Ok(()) => {
                        self.await_convergence(&desired, &pending.info.interface)
                            .await
                    }
                    Err(error) => Err(error),
                }?;
                self.clear_journal(&pending.info.interface).await
            })
            .await;
        if let Err(error) = restoration {
            self.inner
                .pending
                .lock()
                .await
                .get_mut(token)
                .expect("operation lock held")
                .info
                .last_error = Some(format!("{error:#}"));
            if self.recovery().stopped(&path) {
                self.inner
                    .pending
                    .lock()
                    .await
                    .get_mut(token)
                    .expect("operation lock held")
                    .info
                    .phase = NetworkChangePhase::RecoveryRequired;
            } else if manual {
                self.spawn_timer(token.to_owned(), false);
            }
            // Keep both the pending record and recovery journal. The desired
            // state already points back at the committed configuration, so a
            // later retry only needs to verify convergence; reporting success
            // here would falsely claim the runtime had been restored.
            bail!(
                "failed to complete rollback for interface {}: {error:#}",
                pending.info.interface
            );
        }

        let desired = self.desired();
        let _lane = desired.runtime_locks.lock(&pending.info.interface).await;
        desired.withdraw(token).await;
        self.inner.pending.lock().await.remove(token);
        self.inner
            .timer_epochs
            .lock()
            .expect("interface timer epoch lock")
            .remove(token);
        Ok(pending.info)
    }

    /// Attempt every pending rollback and return all restoration failures together.
    pub async fn rollback_all_pending(&self) -> Result<()> {
        // Registration and cancellation compensation must settle before the
        // sweep captures its tokens. Keep ownership throughout the sweep so
        // compensation cannot retire a token between collection and rollback.
        let _operation = self.inner.operation_lock.write().await;
        let tokens: Vec<_> = {
            // Cancelled applies and stopped startup recovery may exist only
            // in the journal; shutdown must not depend on a prior status query.
            self.import_stopped_journals().await?;
            self.inner.pending.lock().await.keys().cloned().collect()
        };
        let mut errors = Vec::new();
        for token in tokens {
            let result = async {
                let interface = self.interface_for_token(&token).await?;
                let _interface_operation = self.desired().transaction_locks.lock(&interface).await;
                self.rollback_locked(&token, false).await
            }
            .await;
            if let Err(error) = result {
                errors.push(format!("{token}: {error:#}"));
            }
        }
        anyhow::ensure!(
            errors.is_empty(),
            "failed to roll back pending network changes: {}",
            errors.join("; ")
        );
        Ok(())
    }

    /// Roll back pending changes, then restore startup interface snapshots in reverse name order.
    /// Continue after individual failures and return their combined errors.
    pub async fn restore_baselines(&self) -> Result<()> {
        self.recovery().check_commit(self.desired().state_dir())?;
        let rollback_error = self.rollback_all_pending().await.err();
        let _operation = self.inner.operation_lock.write().await;
        self.recovery().check_commit(self.desired().state_dir())?;
        let mut baselines: Vec<_> = self
            .inner
            .baselines
            .lock()
            .await
            .values()
            .cloned()
            .collect();
        baselines.sort_by(|left, right| left.name.cmp(&right.name));
        let mut errors: Vec<String> = rollback_error
            .into_iter()
            .map(|error| format!("{error:#}"))
            .collect();
        for snapshot in baselines.into_iter().rev() {
            if self
                .recovery()
                .check_scope(self.desired().state_dir(), Some(&snapshot.name))
                .is_err()
                || self
                    .inner
                    .pending
                    .lock()
                    .await
                    .values()
                    .any(|pending| pending.info.interface == snapshot.name)
            {
                errors.push(format!(
                    "{}: baseline preserved because recovery is unresolved",
                    snapshot.name
                ));
                continue;
            }
            if let Err(error) = self.inner.interface_manager.rollback(&snapshot).await {
                errors.push(format!("{}: {error:#}", snapshot.name));
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

    fn journal_store(&self) -> InterfaceJournalStore {
        InterfaceJournalStore::new(self.desired().state_dir(), self.recovery().clone())
    }

    fn journal_path(&self, interface: &str) -> std::path::PathBuf {
        self.journal_store().path(interface)
    }

    /// Reconstruct tokens for stopped startup journals so the existing rollback API
    /// remains usable. Never import malformed snapshots or unrelated ownership blocks.
    async fn import_stopped_journals(&self) -> Result<()> {
        let desired = self.desired();
        for path in self.recovery().stopped_journals(desired.state_dir()) {
            if path.parent() != Some(desired.state_dir().join("interface-transactions").as_path()) {
                continue;
            }
            let name = path
                .file_stem()
                .and_then(|name| name.to_str())
                .ok_or_else(|| anyhow::anyhow!("invalid recovery scope"))?;
            let bytes = zeroize::Zeroizing::new(tokio::fs::read(&path).await?);
            let Ok(record) = serde_json::from_slice::<InterfaceJournal>(&bytes) else {
                continue;
            };
            if record.version != 3 || record.snapshot.name != name {
                continue;
            }
            let previous_config = desired.committed_interface(name).await?;
            let target = previous_config.clone().unwrap_or(InterfaceConfig {
                wifi_concurrent: false,
                mac_address: None,
                role: InterfaceRole::Output,
                managed: false,
                ipv4: None,
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
            });
            let mut pending = self.inner.pending.lock().await;
            // A concurrent explicit retry may have retired this snapshot while
            // it was being read. Never resurrect its pending token afterwards.
            if !self.recovery().stopped(&path) {
                continue;
            }
            pending
                .entry(record.token.clone())
                .or_insert(PendingTransaction {
                    confirmation_deadline: None,
                    info: PendingNetworkChange {
                        recovery_progress: None,
                        token: record.token,
                        interface: name.to_owned(),
                        rollback_timeout_seconds: self.inner.rollback_timeout.as_secs(),
                        expires_at_unix: 0,
                        phase: NetworkChangePhase::RecoveryRequired,
                        last_error: Some(
                            "automatic recovery stopped; explicit rollback retry required".into(),
                        ),
                    },
                    target,
                    allow_management_change: false,
                    snapshot: record.snapshot,
                    previous_config,
                    secret: record.secret,
                });
        }
        Ok(())
    }

    /// Return pending changes, including rollback-only entries, sorted by token.
    pub async fn pending(&self) -> Vec<PendingNetworkChange> {
        // Read failures remain fenced; listing must not mutate the network.
        if let Err(error) = self.import_stopped_journals().await {
            tracing::error!(error = %format!("{error:#}"), "failed to expose stopped interface recovery");
        }
        let mut pending: Vec<_> = self
            .inner
            .pending
            .lock()
            .await
            .values()
            .map(|pending| pending.info.clone())
            .collect();
        if let Some(error) = self
            .recovery()
            .commit_uncertainty(self.desired().state_dir())
        {
            for change in &mut pending {
                change.phase = NetworkChangePhase::CommitIndeterminate;
                change.last_error = Some(error.clone());
            }
        }
        for change in &mut pending {
            change.recovery_progress = self
                .recovery()
                .progress(&self.journal_path(&change.interface));
            if change.phase != NetworkChangePhase::CommitIndeterminate
                && self
                    .recovery()
                    .stopped(&self.journal_path(&change.interface))
            {
                change.phase = NetworkChangePhase::RecoveryRequired;
            }
        }
        pending.sort_by(|left, right| left.token.cmp(&right.token));
        pending
    }

    #[cfg(test)]
    async fn write_journal(&self, token: &str, snapshot: InterfaceSnapshot) -> Result<()> {
        self.write_journal_record(token, snapshot, None).await
    }

    /// Persist the original interface and secret before changing runtime state.
    async fn write_journal_record(
        &self,
        token: &str,
        snapshot: InterfaceSnapshot,
        secret: Option<SecretSnapshot>,
    ) -> Result<()> {
        self.journal_store().write(token, snapshot, secret).await
    }

    async fn clear_journal(&self, interface: &str) -> Result<()> {
        self.journal_store().retire(interface).await
    }

    fn spawn_rollback_timer(&self, token: String) {
        self.spawn_timer(token, true);
    }

    fn spawn_timer(&self, token: String, confirmation: bool) {
        let manager = self.clone();
        let epoch = {
            let mut epochs = self
                .inner
                .timer_epochs
                .lock()
                .expect("interface timer epoch lock");
            let epoch = epochs.entry(token.clone()).or_default();
            *epoch += 1;
            *epoch
        };
        tokio::spawn(async move {
            let deadline = if confirmation {
                let pending = manager.inner.pending.lock().await;
                let Some(deadline) = pending
                    .get(&token)
                    .and_then(|entry| entry.confirmation_deadline)
                else {
                    return;
                };
                deadline
            } else {
                let interface = manager
                    .inner
                    .pending
                    .lock()
                    .await
                    .get(&token)
                    .map(|entry| entry.info.interface.clone());
                tokio::time::Instant::now()
                    + interface.map_or(Duration::from_secs(1), |interface| {
                        manager
                            .recovery()
                            .retry_delay(&manager.journal_path(&interface))
                    })
            };
            tokio::time::sleep_until(deadline).await;
            loop {
                if manager
                    .inner
                    .timer_epochs
                    .lock()
                    .expect("interface timer epoch lock")
                    .get(&token)
                    != Some(&epoch)
                {
                    return;
                }
                // Compensation is autonomous runtime work. It serializes on
                // operation_lock and execution, but must not queue behind an
                // unrelated request holding admission while awaiting convergence.
                if manager
                    .recovery()
                    .check_commit(manager.desired().state_dir())
                    .is_err()
                {
                    return;
                }
                if !manager.inner.pending.lock().await.contains_key(&token) {
                    return;
                }
                match manager.rollback_for_epoch(&token, epoch).await {
                    Ok(Some(_)) => {
                        tracing::warn!(%token, "network change automatically rolled back after timeout");
                        return;
                    }
                    Ok(None) => return,
                    Err(error) => {
                        tracing::error!(%token, error = %format!("{error:#}"), "automatic network rollback failed; will retry");
                    }
                }
                let interface = manager
                    .inner
                    .pending
                    .lock()
                    .await
                    .get(&token)
                    .map(|entry| entry.info.interface.clone());
                let Some(interface) = interface else {
                    return;
                };
                let path = manager.journal_path(&interface);
                if manager.recovery().stopped(&path) {
                    return;
                }
                tokio::time::sleep(manager.recovery().retry_delay(&path)).await;
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
mod tests;
