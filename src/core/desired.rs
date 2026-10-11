//! The configuration the machine is being converged towards.
//!
//! Two layers. The committed one is what has been persisted to the runtime
//! overrides. The tentative one is a change that has been applied but not yet
//! confirmed by whoever asked for it.
//!
//! Both proposals and restoration snapshots remain in the desired layer until
//! a convergence pass verifies them. This includes interfaces with no committed
//! configuration: removing an entry alone cannot undo their runtime state.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::{watch, Mutex, Notify};

use crate::config::{AppConfig, InterfaceConfig};
use crate::core::interface::InterfaceSnapshot;
use crate::core::override_manager::RuntimeOverrideManager;

/// An applied-but-unconfirmed interface configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TentativeInterface {
    /// The transaction that proposed it, so only its owner can withdraw it.
    token: String,
    config: InterfaceConfig,
    /// Carried alongside the config because the converger has to be able to
    /// realise the proposal, and a role change it is not allowed to make is
    /// one it would refuse. The committed layer keeps the same permission in
    /// the override; this is where it lives until the change is committed.
    allow_management_change: bool,
    restore: Option<InterfaceSnapshot>,
}

/// What one convergence pass achieved.
///
/// Published by the converger so that whoever asked for a change can find out
/// how it went. Without this the only writer would also be the only one who
/// knows whether the write worked, and every caller would have to either guess
/// or poll.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConvergencePass {
    /// The desired-state version this pass was working towards. A pass only
    /// tells you about changes proposed before it started.
    pub version: u64,
    /// Interfaces the pass could not bring to the desired state, and why.
    pub failures: BTreeMap<String, String>,
    pub failure_kinds: BTreeMap<String, crate::core::recovery_control::FailureKind>,
    pub error_kind: Option<crate::core::recovery_control::FailureKind>,
    /// Failure before individual interfaces could be reconciled.
    pub error: Option<String>,
}

/// Lifecycle of the daemon task that drives convergence.
///
/// `Detached` is intentional for one-shot tooling and unit tests that use the
/// desired-state model without a runtime reconciler. `Failed` and `Stopped`
/// are terminal for a daemon-attached state: callers must not mistake either
/// for the detached/tooling case and silently skip convergence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConvergerState {
    Detached,
    Running,
    Failed(String),
    Stopped,
}

/// Committed configuration with any unconfirmed changes layered on top.
#[derive(Clone)]
pub struct DesiredNetworkState {
    overrides: RuntimeOverrideManager,
    base: AppConfig,
    tentative: Arc<Mutex<BTreeMap<String, TentativeInterface>>>,
    tentative_changed: Arc<Notify>,
    missing_interfaces: Arc<std::sync::Mutex<BTreeSet<String>>>,
    /// Bumped by every proposal or withdrawal, so a caller can tell whether a
    /// convergence pass had already seen its change when it ran.
    version: Arc<AtomicU64>,
    passes: watch::Sender<ConvergencePass>,
    interface_passes: watch::Sender<BTreeMap<String, ConvergencePass>>,
    intent_changes: watch::Sender<u64>,
    interface_revisions: Arc<std::sync::Mutex<BTreeMap<String, u64>>>,
    /// Runtime work and credential/snapshot publication share one interface lane.
    pub(crate) credential_updates: Arc<tokio::sync::RwLock<()>>,
    pub(crate) transaction_locks: crate::core::mutation::InterfaceMutationLocks,
    pub(crate) runtime_locks: crate::core::mutation::InterfaceMutationLocks,
    pub(crate) radio_locks: crate::core::mutation::InterfaceMutationLocks,
    failure_kinds:
        Arc<std::sync::Mutex<BTreeMap<(u64, String), crate::core::recovery_control::FailureKind>>>,
    /// Lifecycle of the convergence loop driving this state.
    ///
    /// Waiting for a pass only means something while the converger is alive.
    /// Keeping terminal states distinct from `Detached` prevents an unexpected
    /// reconciler exit from being mistaken for one-shot/tooling mode.
    converger: watch::Sender<ConvergerState>,
}

impl DesiredNetworkState {
    pub fn new(base: AppConfig, overrides: RuntimeOverrideManager) -> Self {
        Self {
            overrides,
            base,
            tentative: Arc::new(Mutex::new(BTreeMap::new())),
            tentative_changed: Arc::new(Notify::new()),
            missing_interfaces: Default::default(),
            version: Arc::new(AtomicU64::new(0)),
            passes: watch::Sender::new(ConvergencePass::default()),
            interface_passes: watch::Sender::new(BTreeMap::new()),
            intent_changes: watch::Sender::new(0),
            interface_revisions: Default::default(),
            credential_updates: Default::default(),
            transaction_locks: Default::default(),
            runtime_locks: Default::default(),
            radio_locks: Default::default(),
            failure_kinds: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
            converger: watch::Sender::new(ConvergerState::Detached),
        }
    }

    /// Record successful device observation. Failed observations must not call this.
    pub(crate) fn record_interface_presence(
        &self,
        configured: impl Iterator<Item = String>,
        observed: &BTreeSet<String>,
    ) {
        let missing: BTreeSet<String> =
            configured.filter(|name| !observed.contains(name)).collect();
        let mut previous = self
            .missing_interfaces
            .lock()
            .expect("device observation state");
        for name in missing.difference(&previous) {
            tracing::info!(interface = %name, "saved interface configuration is waiting for its device");
        }
        for name in previous
            .difference(&missing)
            .filter(|name| observed.contains(*name))
        {
            tracing::info!(interface = %name, "configured interface appeared; resuming convergence");
        }
        *previous = missing;
    }

    /// The current desired-state version.
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::SeqCst)
    }

    /// Announce that a convergence loop is driving this state.
    pub fn attach_converger(&self) {
        self.converger.send_replace(ConvergerState::Running);
    }

    /// Whether anyone is converging the machine towards this state.
    pub fn has_converger(&self) -> bool {
        matches!(&*self.converger.borrow(), ConvergerState::Running)
    }

    pub(crate) fn converger_state(&self) -> ConvergerState {
        self.converger.borrow().clone()
    }

    /// Mark the attached converger unusable and wake anyone waiting for it.
    pub(crate) fn fail_converger(&self, error: impl Into<String>) {
        if !matches!(&*self.converger.borrow(), ConvergerState::Failed(_)) {
            self.converger
                .send_replace(ConvergerState::Failed(error.into()));
        }
    }

    /// Mark a normally terminating converger as stopped.
    ///
    /// A prior failure is sticky: shutdown after a failure must not erase the
    /// reason transactions were unable to converge.
    pub(crate) fn stop_converger(&self) {
        if matches!(&*self.converger.borrow(), ConvergerState::Running) {
            self.converger.send_replace(ConvergerState::Stopped);
        }
    }

    /// Record the outcome of a convergence pass.
    ///
    /// `version` is the desired-state version the pass read when it started —
    /// not the current one, which may have moved while it ran.
    pub fn report_pass(&self, version: u64, failures: BTreeMap<String, String>) {
        self.report_result(version, Ok(failures));
    }

    pub fn record_failure_kind(&self, version: u64, interface: &str, error: &anyhow::Error) {
        self.failure_kinds
            .lock()
            .expect("convergence failure kind lock")
            .insert(
                (version, interface.to_owned()),
                crate::core::recovery_control::classify(error),
            );
    }

    pub fn report_result(&self, version: u64, result: Result<BTreeMap<String, String>>) {
        let error_kind = result
            .as_ref()
            .err()
            .map(crate::core::recovery_control::classify);
        let mut kinds = self
            .failure_kinds
            .lock()
            .expect("convergence failure kind lock");
        let failure_kinds = kinds
            .iter()
            .filter(|((pass, _), _)| *pass == version)
            .map(|((_, interface), kind)| (interface.clone(), *kind))
            .collect();
        kinds.retain(|(pass, _), _| *pass > version);
        drop(kinds);
        let (failures, error) = match result {
            Ok(failures) => (failures, None),
            Err(error) => (BTreeMap::new(), Some(format!("{error:#}"))),
        };
        // Keep the latest result even if the caller has not subscribed yet.
        self.passes.send_replace(ConvergencePass {
            version,
            failures,
            failure_kinds,
            error_kind,
            error,
        });
    }

    /// Wait for a convergence pass that had already seen version `version`.
    ///
    /// A pass that started before the caller's change cannot say anything about
    /// it, so those are skipped rather than mistaken for success.
    pub async fn pass_covering(&self, version: u64) -> ConvergencePass {
        let mut passes = self.passes.subscribe();
        let mut converger = self.converger.subscribe();
        loop {
            match &*converger.borrow_and_update() {
                ConvergerState::Failed(error) => {
                    return ConvergencePass {
                        version,
                        failure_kinds: BTreeMap::new(),
                        error_kind: None,
                        failures: BTreeMap::new(),
                        error: Some(format!("network converger failed: {error}")),
                    };
                }
                ConvergerState::Stopped => {
                    return ConvergencePass {
                        version,
                        failure_kinds: BTreeMap::new(),
                        error_kind: None,
                        failures: BTreeMap::new(),
                        error: Some("network converger stopped".into()),
                    };
                }
                ConvergerState::Detached | ConvergerState::Running => {}
            }
            {
                let pass = passes.borrow_and_update();
                if pass.version >= version {
                    return pass.clone();
                }
            }
            tokio::select! {
                changed = passes.changed() => {
                    if changed.is_err() {
                        return ConvergencePass {
                            version,
                            failure_kinds: BTreeMap::new(),
                        error_kind: None,
                        failures: BTreeMap::new(),
                            error: Some("convergence result channel stopped".into()),
                        };
                    }
                }
                changed = converger.changed() => {
                    if changed.is_err() {
                        return ConvergencePass {
                            version,
                            failure_kinds: BTreeMap::new(),
                        error_kind: None,
                        failures: BTreeMap::new(),
                            error: Some("network converger state channel stopped".into()),
                        };
                    }
                }
            }
        }
    }

    /// Independent notification stream: workers must not consume the main
    /// converger's retained wakeup while a previous pass is still running.
    pub(crate) fn intent_changes(&self) -> watch::Receiver<u64> {
        self.intent_changes.subscribe()
    }

    pub(crate) fn interface_revision(&self, interface: &str) -> u64 {
        self.interface_revisions
            .lock()
            .expect("interface revisions")
            .get(interface)
            .copied()
            .unwrap_or(0)
    }

    pub(crate) fn report_interface_result(
        &self,
        interface: &str,
        version: u64,
        result: &Result<()>,
    ) {
        let mut pass = ConvergencePass {
            version,
            ..Default::default()
        };
        if let Err(error) = result {
            pass.failures
                .insert(interface.to_owned(), format!("{error:#}"));
            pass.failure_kinds.insert(
                interface.to_owned(),
                crate::core::recovery_control::classify(error),
            );
        }
        self.interface_passes.send_modify(|passes| {
            if passes
                .get(interface)
                .is_none_or(|previous| previous.version <= version)
            {
                passes.insert(interface.to_owned(), pass);
            }
        });
    }

    /// A completed interface can answer without waiting for unrelated radios.
    /// Full-pass reports remain supported for global errors and simple consumers.
    pub(crate) async fn interface_pass_covering(
        &self,
        interface: &str,
        version: u64,
    ) -> ConvergencePass {
        let mut interfaces = self.interface_passes.subscribe();
        loop {
            if let Some(pass) = interfaces
                .borrow_and_update()
                .get(interface)
                .filter(|pass| pass.version >= version)
                .cloned()
            {
                if matches!(
                    self.converger_state(),
                    ConvergerState::Running | ConvergerState::Detached
                ) {
                    return pass;
                }
            }
            tokio::select! {
                biased;
                result = self.pass_covering(version) => return result,
                _ = interfaces.changed() => {}
            }
        }
    }

    fn interface_changed(&self, interface: &str) {
        let version = self.version.fetch_add(1, Ordering::SeqCst) + 1;
        self.interface_revisions
            .lock()
            .expect("interface revisions")
            .insert(interface.to_owned(), version);
        self.intent_changes.send_replace(version);
        self.tentative_changed.notify_one();
    }

    /// Return the directory containing durable override and recovery records.
    pub(crate) fn state_dir(&self) -> &std::path::Path {
        self.overrides
            .path()
            .parent()
            .expect("override store has a parent")
    }

    pub(crate) async fn committed_overrides(&self) -> crate::state::overrides::RuntimeOverrides {
        self.overrides.snapshot().await
    }

    pub(crate) async fn committed_config(&self) -> Result<AppConfig> {
        let mut config = self
            .overrides
            .snapshot()
            .await
            .effective_config(&self.base)?;
        config.runtime.state_dir = self.state_dir().to_path_buf();
        Ok(config)
    }

    /// Merge base configuration, committed overrides, and tentative interface changes.
    /// Tentative entries take precedence; invalid committed configuration is an error.
    pub async fn effective(&self) -> Result<AppConfig> {
        // Read the tentative layer before committed state and retain it while
        // reading overrides. Commit persists first, then withdraws: this order
        // cannot combine old overrides with an already withdrawn proposal.
        let tentative = self.tentative.lock().await;
        let mut effective = self
            .overrides
            .snapshot()
            .await
            .effective_config(&self.base)?;
        for (interface, pending) in tentative.iter() {
            effective
                .network
                .interfaces
                .insert(interface.clone(), pending.config.clone());
        }
        Ok(effective)
    }

    /// Interfaces whose management role the operator has explicitly confirmed.
    ///
    /// Part of the desired state rather than a separate lookup: "what should
    /// this machine look like" and "which management interfaces am I allowed to
    /// touch while getting there" are answered from the same place, so they
    /// cannot be read from two versions of the truth.
    ///
    /// An unconfirmed change carries its own permission: the operator gave it
    /// when they asked for the change, and until the change is committed there
    /// is no override to read it from.
    pub async fn management_allowlist(&self) -> BTreeSet<String> {
        let tentative = self.tentative.lock().await;
        let mut allowed: BTreeSet<String> = self
            .overrides
            .snapshot()
            .await
            .interfaces
            .iter()
            .filter(|(_, value)| value.allow_management_change)
            .map(|(interface, _)| interface.clone())
            .collect();
        allowed.extend(
            tentative
                .iter()
                .filter(|(_, pending)| pending.allow_management_change)
                .map(|(interface, _)| interface.clone()),
        );
        allowed
    }

    /// Whether this interface currently carries an unconfirmed change.
    pub async fn is_tentative(&self, interface: &str) -> bool {
        self.tentative
            .lock()
            .await
            .get(interface)
            .is_some_and(|entry| entry.restore.is_none())
    }

    /// Propose a change: convergence will start moving the machine towards it.
    ///
    /// Deliberately does not touch the kernel. Nothing here writes to the
    /// machine — that is the converger's job, and its alone.
    pub async fn propose(
        &self,
        token: &str,
        interface: &str,
        config: InterfaceConfig,
        allow_management_change: bool,
    ) {
        self.tentative.lock().await.insert(
            interface.to_string(),
            TentativeInterface {
                token: token.to_string(),
                config,
                allow_management_change,
                restore: None,
            },
        );
        // Bumped after the layer is in place, never before: a converger that
        // reads this version has to be able to see what it stands for.
        self.interface_changed(interface);
    }

    /// Report whether any proposal or restoration still awaits completion.
    pub async fn has_pending(&self) -> bool {
        !self.tentative.lock().await.is_empty()
    }

    /// Return the effective committed interface configuration, excluding tentative changes.
    pub async fn committed_interface(&self, interface: &str) -> Result<Option<InterfaceConfig>> {
        Ok(self
            .overrides
            .snapshot()
            .await
            .effective_config(&self.base)?
            .network
            .interfaces
            .get(interface)
            .cloned())
    }

    /// Persist the interface configuration and transaction token through the override manager.
    pub(crate) async fn commit_interface(
        &self,
        token: &str,
        interface: String,
        config: InterfaceConfig,
        allow_management_change: bool,
    ) -> Result<()> {
        self.overrides
            .commit_interface(interface, config, allow_management_change, token)
            .await
    }

    /// Clone the interface snapshots that convergence must restore.
    pub async fn restorations(&self) -> BTreeMap<String, InterfaceSnapshot> {
        self.tentative
            .lock()
            .await
            .iter()
            .filter_map(|(name, entry)| {
                entry
                    .restore
                    .clone()
                    .map(|snapshot| (name.clone(), snapshot))
            })
            .collect()
    }

    /// Replace a proposal with a restoration, including an explicit service
    /// tombstone when the interface was not configured before the transaction.
    pub async fn restore(
        &self,
        token: &str,
        snapshot: InterfaceSnapshot,
        config: Option<InterfaceConfig>,
    ) {
        let interface = snapshot.name.clone();
        let config = config.unwrap_or(InterfaceConfig {
            role: crate::config::InterfaceRole::Output,
            managed: false,
            ipv4: None,
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
            nat: false,
        });
        self.tentative.lock().await.insert(
            interface.clone(),
            TentativeInterface {
                token: token.to_owned(),
                config,
                allow_management_change: true,
                restore: Some(snapshot),
            },
        );
        self.interface_changed(&interface);
    }

    /// Drop everything a transaction proposed.
    ///
    /// Called after persistence succeeds or restoration has been verified.
    ///
    /// Returns the interfaces that were released.
    pub async fn withdraw(&self, token: &str) -> Vec<String> {
        let mut tentative = self.tentative.lock().await;
        let released: Vec<String> = tentative
            .iter()
            .filter(|(_, pending)| pending.token == token)
            .map(|(interface, _)| interface.clone())
            .collect();
        for interface in &released {
            tentative.remove(interface);
        }
        drop(tentative);

        for interface in &released {
            self.interface_changed(interface);
        }
        released
    }

    /// Ask the converger to make and report a fresh pass even though the
    /// desired configuration itself did not change. This is used when a
    /// rollback is retried after its tentative layer was already withdrawn:
    /// waiting on the old version would otherwise immediately replay the
    /// previous failed convergence result.
    pub fn request_convergence(&self) {
        let version = self.version.fetch_add(1, Ordering::SeqCst) + 1;
        self.intent_changes.send_replace(version);
        self.tentative_changed.notify_one();
    }

    /// Wait until the desired state moves, from either layer.
    ///
    /// There is one convergence consumer. Each layer retains one notification
    /// while a pass runs, so changes between reading state and waiting are not lost.
    pub async fn changed(&self) {
        tokio::select! {
            () = self.overrides.changed() => {}
            () = self.tentative_changed.notified() => {}
        }
    }
}

#[cfg(test)]
mod tests;
