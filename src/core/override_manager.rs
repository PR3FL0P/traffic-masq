//! The runtime override manager: the single writer of persisted intent.
//!
//! Lives in `core` rather than beside the document it writes, because every
//! write path here is gated on a domain question — "can this configuration
//! actually be realised as a router intent?" — answered by
//! [`RouterDesired::from_effective_config`]. Keeping the manager in `state`
//! meant the storage module had to import the domain to validate, and the
//! domain had to import storage to use it: a cycle at the bottom of the stack.
//!
//! `state` now holds only the document and its store; deciding what may be
//! written is this module's job.

use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::sync::{Mutex, Notify};

use crate::config::{ApiConfig, AppConfig, InterfaceConfig, SecurityConfig, VpnPolicyMode};
use crate::core::router::RouterDesired;
use crate::core::router_candidate::{RouterCandidate, RouterIntentProposal};
use crate::state::overrides::{InterfaceOverride, RuntimeOverrideStore, RuntimeOverrides};

/// Cancellation while storage is writing has the same uncertain outcome as a
/// failed write with failed compensation. Never let a timer guess it aborted.
struct CommitPersistenceGuard<'a> {
    root: &'a std::path::Path,
    armed: bool,
}

impl Drop for CommitPersistenceGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            crate::core::recovery::fence_commit(
                self.root,
                "commit persistence was interrupted; durable outcome is unknown".into(),
            );
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeOverrideManager {
    store: RuntimeOverrideStore,
    base: AppConfig,
    state: Arc<Mutex<RuntimeOverrides>>,
    /// Fires whenever the overrides change.
    ///
    /// The desired state just moved, so whoever converges the machine towards
    /// it has to look again. Without this the only way to notice would be to
    /// ask on a timer, which is the latency this daemon is trying not to have.
    changed: Arc<Notify>,
}

impl RuntimeOverrideManager {
    /// Load persisted overrides and reject configurations that cannot form valid router intent.
    pub async fn load(state_dir: impl AsRef<Path>, base: &AppConfig) -> Result<Self> {
        let store = RuntimeOverrideStore::in_state_dir(state_dir);
        let state = store.load().await?;
        validate_candidate(&state, base).with_context(|| {
            format!(
                "runtime overrides in {} are invalid",
                store.path().display()
            )
        })?;
        Ok(Self {
            store,
            base: base.clone(),
            state: Arc::new(Mutex::new(state)),
            changed: Arc::new(Notify::new()),
        })
    }

    /// Build a manager from only router-relevant recovery state.
    ///
    /// This is used before the full override document is admitted for normal
    /// startup, so unrelated API/security corruption cannot suppress router
    /// journal recovery. The same manager is hydrated with the strict document
    /// once recovery has completed.
    #[cfg(test)]
    pub(crate) async fn load_for_router_recovery(
        state_dir: impl AsRef<Path>,
        base: &AppConfig,
    ) -> Result<Self> {
        let store = RuntimeOverrideStore::in_state_dir(state_dir);
        let proof = store.load_recovery_commit_proof().await?;
        let committed_router_transaction = proof.committed_router_transaction()?;
        Self::from_router_recovery_proof(store, base, &proof, committed_router_transaction)
    }

    /// Build a recovery manager from an already-inspected proof envelope.
    ///
    /// The router commit token is supplied separately so another proof field can fail without
    /// forcing startup to reparse or conflate recovery scopes.
    pub(crate) fn from_router_recovery_proof(
        store: RuntimeOverrideStore,
        base: &AppConfig,
        proof: &crate::state::overrides::RecoveryCommitProof,
        committed_router_transaction: Option<String>,
    ) -> Result<Self> {
        let state =
            proof.router_recovery_overrides_with_commit_token(committed_router_transaction)?;
        Ok(Self {
            store,
            base: base.clone(),
            state: Arc::new(Mutex::new(state)),
            changed: Arc::new(Notify::new()),
        })
    }

    /// Replace recovery-only state with the strict persisted document after
    /// router recovery, preserving manager identity held by the coordinator.
    pub(crate) async fn hydrate_strict(&self) -> Result<AppConfig> {
        let state = self.store.load().await?;
        validate_candidate(&state, &self.base).with_context(|| {
            format!(
                "runtime overrides in {} are invalid",
                self.store.path().display()
            )
        })?;
        let effective = state.effective_config(&self.base)?;
        *self.state.lock().await = state;
        Ok(effective)
    }

    /// Clone the committed override document under its state lock.
    pub async fn snapshot(&self) -> RuntimeOverrides {
        self.state.lock().await.clone()
    }

    /// Merge overrides with the base configuration and return the named interface.
    pub async fn effective_interface(&self, interface: &str) -> Result<Option<InterfaceConfig>> {
        Ok(self
            .state
            .lock()
            .await
            .effective_config(&self.base)?
            .network
            .interfaces
            .get(interface)
            .cloned())
    }

    /// Return the revision used to reject stale router candidates.
    pub async fn committed_revision(&self) -> u64 {
        self.state.lock().await.revision
    }

    /// Return API settings after applying committed overrides to the base configuration.
    pub async fn effective_api_config(&self) -> Result<ApiConfig> {
        Ok(self.state.lock().await.effective_config(&self.base)?.api)
    }

    /// Return security settings after applying committed overrides.
    pub async fn effective_security_config(&self) -> Result<SecurityConfig> {
        Ok(self
            .state
            .lock()
            .await
            .effective_config(&self.base)?
            .security)
    }

    /// Return the persisted VPN policy mode, falling back to the configured default.
    pub async fn effective_vpn_mode(&self) -> VpnPolicyMode {
        self.state
            .lock()
            .await
            .vpn_mode
            .unwrap_or(self.base.vpn.policy.default_mode)
    }

    /// Validate a router proposal against the current committed revision without saving it.
    pub async fn build_candidate(
        &self,
        proposal: &RouterIntentProposal,
    ) -> Result<RouterCandidate> {
        let state = self.state.lock().await;
        RouterCandidate::build(&self.base, &state, proposal)
    }

    /// Build a router candidate using recovery-scoped validation only.
    pub(crate) async fn build_recovery_candidate(
        &self,
        proposal: &RouterIntentProposal,
    ) -> Result<RouterCandidate> {
        let state = self.state.lock().await;
        RouterCandidate::build_for_recovery(&self.base, &state, proposal)
    }

    /// Persist a validated candidate only if its base revision is still current.
    pub async fn commit_candidate(&self, candidate: &RouterCandidate) -> Result<u64> {
        self.commit_candidate_with_token(candidate, None).await
    }

    /// Reject stale candidates and persist the new intent with an optional recovery token.
    pub async fn commit_candidate_with_token(
        &self,
        candidate: &RouterCandidate,
        token: Option<&str>,
    ) -> Result<u64> {
        let mut state = self.state.lock().await;
        candidate.ensure_base_revision(state.revision)?;
        let mut document = candidate.document().clone();
        if let Some(token) = token {
            document.committed_router_transaction = Some(token.to_owned());
        }
        self.save_locked(&mut state, document).await?;
        Ok(state.revision)
    }

    /// Validate and durably save a replacement override document under the mutation lock.
    pub async fn save_committed(&self, candidate: RuntimeOverrides) -> Result<()> {
        let mut state = self.state.lock().await;
        self.save_locked(&mut state, candidate).await
    }

    /// Normalize and validate a candidate, increment its revision, and save before publishing it.
    /// Notify convergence only after persistence succeeds; errors leave in-memory state unchanged.
    async fn save_locked(
        &self,
        state: &mut RuntimeOverrides,
        candidate: RuntimeOverrides,
    ) -> Result<()> {
        let root = self
            .store
            .path()
            .parent()
            .expect("override state directory");
        crate::core::recovery::check_commit(root)?;
        let mut candidate = candidate.normalized()?;
        validate_candidate(&candidate, &self.base)?;
        candidate.revision = state
            .revision
            .checked_add(1)
            .context("runtime override revision overflow")?;
        let mut guard = CommitPersistenceGuard { root, armed: true };
        let persisted = self.store.save(&candidate).await;
        guard.armed = false; // A returned result is known; errors below carry their own proof.
        if let Err(error) = persisted {
            if crate::atomic_file::is_indeterminate_write(&error) {
                crate::core::recovery::fence_commit(root, format!("{error:#}"));
                return Err(error.context("commit_indeterminate: repair storage access and restart the daemon; confirmation and rollback are blocked"));
            }
            return Err(error);
        }
        *state = candidate;
        // Every mutation funnels through here, so this is the one place that
        // has to announce that the desired state moved.
        self.changed.notify_one();
        Ok(())
    }

    /// Wait until the overrides change.
    ///
    /// One convergence consumer waits here. Retain a notification if it is
    /// still applying the previous snapshot; multiple changes coalesce.
    pub async fn changed(&self) {
        self.changed.notified().await;
    }

    /// Persist replacement API settings and notify the desired-state consumer.
    pub async fn set_api_config(&self, api: ApiConfig) -> Result<()> {
        let mut state = self.state.lock().await;
        let mut candidate = state.clone();
        candidate.api = Some(api);
        self.save_locked(&mut state, candidate).await
    }

    /// Remove the API override so the base configuration supplies API settings.
    pub async fn clear_api_config(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        let mut candidate = state.clone();
        candidate.api = None;
        self.save_locked(&mut state, candidate).await
    }

    /// Validate and persist replacement security settings.
    pub async fn set_security_config(&self, security: SecurityConfig) -> Result<()> {
        let mut state = self.state.lock().await;
        let mut candidate = state.clone();
        candidate.security = Some(security);
        self.save_locked(&mut state, candidate).await
    }

    /// Remove the security override so base settings take effect.
    pub async fn clear_security_config(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        let mut candidate = state.clone();
        candidate.security = None;
        self.save_locked(&mut state, candidate).await
    }

    /// Persist the VPN enabled flag after validating the resulting router configuration.
    pub async fn set_vpn_enabled(&self, enabled: bool) -> Result<()> {
        let mut state = self.state.lock().await;
        let mut candidate = state.clone();
        candidate.vpn_enabled = Some(enabled);
        self.save_locked(&mut state, candidate).await
    }

    /// Persist a VPN policy mode only if the effective configuration supports it.
    pub async fn set_vpn_mode(&self, mode: VpnPolicyMode) -> Result<()> {
        let mut state = self.state.lock().await;
        let mut candidate = state.clone();
        candidate.vpn_mode = Some(mode);
        self.save_locked(&mut state, candidate).await
    }

    /// Remove the policy override to restore the configured default VPN mode.
    pub async fn clear_vpn_mode(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        let mut candidate = state.clone();
        candidate.vpn_mode = None;
        self.save_locked(&mut state, candidate).await
    }

    /// Restore a prior interface override, or remove it when no prior override existed.
    pub async fn restore_interface_override(
        &self,
        interface: &str,
        previous: Option<InterfaceOverride>,
    ) -> Result<()> {
        let mut state = self.state.lock().await;
        let mut candidate = state.clone();
        match previous {
            Some(previous) => {
                candidate.suppressed_interfaces.remove(interface);
                candidate.interfaces.insert(interface.to_string(), previous);
            }
            None => {
                candidate.interfaces.remove(interface);
            }
        }
        self.save_locked(&mut state, candidate).await
    }

    /// Validate and persist an interface override with its management-change permission.
    pub async fn set_interface(
        &self,
        interface: String,
        config: InterfaceConfig,
        allow_management_change: bool,
    ) -> Result<()> {
        config.validate(&interface)?;
        let mut state = self.state.lock().await;
        let mut candidate = state.clone();
        candidate.suppressed_interfaces.remove(&interface);
        candidate.interfaces.insert(
            interface,
            InterfaceOverride {
                config,
                allow_management_change,
                dhcp_client_only: false,
            },
        );
        self.save_locked(&mut state, candidate).await
    }

    /// Persist an interface override and its confirmation token in the same document.
    pub async fn commit_interface(
        &self,
        interface: String,
        config: InterfaceConfig,
        allow_management_change: bool,
        token: &str,
    ) -> Result<()> {
        let mut state = self.state.lock().await;
        let mut candidate = state.clone();
        candidate
            .committed_interface_transactions
            .insert(interface.clone(), token.to_owned());
        candidate.suppressed_interfaces.remove(&interface);
        candidate.interfaces.insert(
            interface,
            InterfaceOverride {
                config,
                allow_management_change,
                dhcp_client_only: false,
            },
        );
        self.save_locked(&mut state, candidate).await
    }

    /// Validate a proposed interface override against full router intent without persisting it.
    pub async fn check_interface(
        &self,
        interface: &str,
        config: &InterfaceConfig,
        allow_management_change: bool,
    ) -> Result<()> {
        config.validate(interface)?;
        let state = self.state.lock().await;
        let mut candidate = state.clone();
        candidate.suppressed_interfaces.remove(interface);
        candidate.interfaces.insert(
            interface.to_owned(),
            InterfaceOverride {
                config: config.clone(),
                allow_management_change,
                dhcp_client_only: false,
            },
        );
        let candidate = candidate.normalized()?;
        validate_candidate(&candidate, &self.base)
    }

    pub fn path(&self) -> &Path {
        self.store.path()
    }
}

/// Reject overrides whose effective router intent or VPN policy dependencies are invalid.
fn validate_candidate(candidate: &RuntimeOverrides, base: &AppConfig) -> Result<()> {
    let effective = candidate.effective_config(base)?;
    RouterDesired::from_effective_config(&effective)?;
    if candidate.vpn_mode == Some(VpnPolicyMode::Vpn) {
        if !effective.vpn.enabled {
            bail!("persisted vpn traffic policy mode \"vpn\" requires vpn.enabled = true");
        }
        if !effective.router.enabled {
            bail!("persisted vpn traffic policy mode \"vpn\" requires router.enabled = true");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
