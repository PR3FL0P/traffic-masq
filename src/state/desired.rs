//! The configuration the machine is being converged towards.
//!
//! Two layers. The committed one is what has been persisted to the runtime
//! overrides. The tentative one is a change that has been applied but not yet
//! confirmed by whoever asked for it.
//!
//! The point of expressing an unconfirmed change as a *layer of desired state*
//! rather than as a direct write to the kernel is that there is then only one
//! writer. Convergence reaches a tentative change exactly the way it reaches a
//! committed one, and abandoning it is dropping the layer — no separate undo
//! path, nothing to snapshot, and nothing that can disagree with the converger
//! about what the machine is supposed to look like.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::{watch, Mutex, Notify};

use crate::config::{AppConfig, InterfaceConfig};
use crate::state::overrides::RuntimeOverrideManager;

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
}

/// Committed configuration with any unconfirmed changes layered on top.
#[derive(Clone)]
pub struct DesiredNetworkState {
    overrides: RuntimeOverrideManager,
    base: AppConfig,
    tentative: Arc<Mutex<BTreeMap<String, TentativeInterface>>>,
    tentative_changed: Arc<Notify>,
    /// Bumped by every proposal or withdrawal, so a caller can tell whether a
    /// convergence pass had already seen its change when it ran.
    version: Arc<AtomicU64>,
    passes: watch::Sender<ConvergencePass>,
    /// Whether a convergence loop is running against this state.
    ///
    /// Waiting for a pass only means something if something is passing. In the
    /// daemon the converger attaches before its first pass; a state nobody
    /// converges — unit tests, one-shot tooling — answers questions about the
    /// desired configuration and nothing more, so callers must not block on it.
    converger: Arc<AtomicBool>,
}

impl DesiredNetworkState {
    pub fn new(base: AppConfig, overrides: RuntimeOverrideManager) -> Self {
        Self {
            overrides,
            base,
            tentative: Arc::new(Mutex::new(BTreeMap::new())),
            tentative_changed: Arc::new(Notify::new()),
            version: Arc::new(AtomicU64::new(0)),
            passes: watch::Sender::new(ConvergencePass::default()),
            converger: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The current desired-state version.
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::SeqCst)
    }

    /// Announce that a convergence loop is driving this state.
    pub fn attach_converger(&self) {
        self.converger.store(true, Ordering::SeqCst);
    }

    /// Whether anyone is converging the machine towards this state.
    pub fn has_converger(&self) -> bool {
        self.converger.load(Ordering::SeqCst)
    }

    /// Record the outcome of a convergence pass.
    ///
    /// `version` is the desired-state version the pass read when it started —
    /// not the current one, which may have moved while it ran.
    pub fn report_pass(&self, version: u64, failures: BTreeMap<String, String>) {
        let _ = self.passes.send(ConvergencePass { version, failures });
    }

    /// Wait for a convergence pass that had already seen version `version`.
    ///
    /// A pass that started before the caller's change cannot say anything about
    /// it, so those are skipped rather than mistaken for success.
    pub async fn pass_covering(&self, version: u64) -> ConvergencePass {
        let mut passes = self.passes.subscribe();
        loop {
            {
                let pass = passes.borrow_and_update();
                if pass.version >= version {
                    return pass.clone();
                }
            }
            if passes.changed().await.is_err() {
                return ConvergencePass {
                    version,
                    failures: BTreeMap::new(),
                };
            }
        }
    }

    /// The configuration to converge towards right now.
    pub async fn effective(&self) -> Result<AppConfig> {
        let mut effective = self
            .overrides
            .snapshot()
            .await
            .effective_config(&self.base)?;
        for (interface, pending) in self.tentative.lock().await.iter() {
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
            self.tentative
                .lock()
                .await
                .iter()
                .filter(|(_, pending)| pending.allow_management_change)
                .map(|(interface, _)| interface.clone()),
        );
        allowed
    }

    /// Whether this interface currently carries an unconfirmed change.
    pub async fn is_tentative(&self, interface: &str) -> bool {
        self.tentative.lock().await.contains_key(interface)
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
            },
        );
        // Bumped after the layer is in place, never before: a converger that
        // reads this version has to be able to see what it stands for.
        self.version.fetch_add(1, Ordering::SeqCst);
        self.tentative_changed.notify_waiters();
    }

    /// Drop everything a transaction proposed.
    ///
    /// Used both when a change is confirmed — at which point the committed
    /// layer already carries it — and when it is abandoned, where dropping the
    /// layer is the whole of the rollback: convergence takes the machine back
    /// to the committed state on its own.
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

        if !released.is_empty() {
            self.version.fetch_add(1, Ordering::SeqCst);
            self.tentative_changed.notify_waiters();
        }
        released
    }

    /// Wait until the desired state moves, from either layer.
    ///
    /// One place to wait, because "the desired state changed" is one fact
    /// regardless of which layer it came from.
    pub async fn changed(&self) {
        tokio::select! {
            () = self.overrides.changed() => {}
            () = self.tentative_changed.notified() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tempfile::tempdir;

    use crate::config::InterfaceRole;

    use super::*;

    fn interface(address: &str) -> InterfaceConfig {
        InterfaceConfig {
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some(address.parse().expect("network")),
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        }
    }

    async fn desired_state() -> (DesiredNetworkState, tempfile::TempDir) {
        let directory = tempdir().expect("tempdir");
        let mut base = AppConfig::default();
        base.network
            .interfaces
            .insert("lan0".to_string(), interface("192.168.10.1/24"));
        let overrides = RuntimeOverrideManager::load(directory.path(), &base)
            .await
            .expect("overrides");
        (DesiredNetworkState::new(base, overrides), directory)
    }

    async fn lan0_address(state: &DesiredNetworkState) -> String {
        state
            .effective()
            .await
            .expect("effective")
            .network
            .interfaces["lan0"]
            .ipv4
            .expect("ipv4")
            .to_string()
    }

    #[tokio::test]
    async fn without_a_proposal_the_committed_configuration_is_what_counts() {
        let (state, _dir) = desired_state().await;
        assert_eq!(lan0_address(&state).await, "192.168.10.1/24");
    }

    #[tokio::test]
    async fn a_proposal_becomes_what_the_machine_is_converged_towards() {
        let (state, _dir) = desired_state().await;

        state
            .propose("token-1", "lan0", interface("10.1.1.1/24"), false)
            .await;

        assert_eq!(lan0_address(&state).await, "10.1.1.1/24");
        assert!(state.is_tentative("lan0").await);
    }

    /// Abandoning a change is dropping the layer. There is no undo step,
    /// because the committed layer never stopped describing the old state.
    #[tokio::test]
    async fn withdrawing_a_proposal_restores_the_committed_configuration() {
        let (state, _dir) = desired_state().await;
        state
            .propose("token-1", "lan0", interface("10.1.1.1/24"), false)
            .await;

        let released = state.withdraw("token-1").await;

        assert_eq!(released, vec!["lan0".to_string()]);
        assert_eq!(lan0_address(&state).await, "192.168.10.1/24");
        assert!(!state.is_tentative("lan0").await);
    }

    #[tokio::test]
    async fn a_transaction_cannot_withdraw_what_another_one_proposed() {
        let (state, _dir) = desired_state().await;
        state
            .propose("token-1", "lan0", interface("10.1.1.1/24"), false)
            .await;

        assert!(state.withdraw("token-2").await.is_empty());
        assert_eq!(lan0_address(&state).await, "10.1.1.1/24");
    }

    #[tokio::test]
    async fn proposing_wakes_whoever_is_converging() {
        let (state, _dir) = desired_state().await;
        let waiter = {
            let state = state.clone();
            tokio::spawn(async move { state.changed().await })
        };
        tokio::task::yield_now().await;

        state
            .propose("token-1", "lan0", interface("10.1.1.1/24"), false)
            .await;

        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("a proposal must wake the converger")
            .expect("waiter task");
    }

    /// Both layers feed one wait, so a committed change is not missed just
    /// because the converger happened to be waiting for a tentative one.
    #[tokio::test]
    async fn a_committed_change_wakes_the_same_wait() {
        let (state, _dir) = desired_state().await;
        let waiter = {
            let state = state.clone();
            tokio::spawn(async move { state.changed().await })
        };
        tokio::task::yield_now().await;

        state
            .overrides
            .set_interface("lan0".to_string(), interface("172.16.0.1/24"), false)
            .await
            .expect("commit");

        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("a committed change must wake the converger")
            .expect("waiter task");
        assert_eq!(lan0_address(&state).await, "172.16.0.1/24");
    }

    /// The layer on top wins while it exists: a transaction that has been
    /// applied but not confirmed is what the machine should currently look like.
    #[tokio::test]
    async fn a_proposal_outranks_the_committed_configuration() {
        let (state, _dir) = desired_state().await;
        state
            .overrides
            .set_interface("lan0".to_string(), interface("172.16.0.1/24"), false)
            .await
            .expect("commit");
        state
            .propose("token-1", "lan0", interface("10.1.1.1/24"), false)
            .await;

        assert_eq!(lan0_address(&state).await, "10.1.1.1/24");

        state.withdraw("token-1").await;
        assert_eq!(lan0_address(&state).await, "172.16.0.1/24");
    }
}
