use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::{Mutex, MutexGuard};

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

struct Inner {
    manager: RouterManager,
    overrides: RuntimeOverrideManager,
    rollback_timeout: Duration,
    state: Mutex<CoordinatorState>,
    token_counter: AtomicU64,
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
                manager,
                overrides,
                rollback_timeout,
                state: Mutex::new(CoordinatorState::Idle),
                token_counter: AtomicU64::new(0),
            }),
        }
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

        self.inner.manager.apply(&plan.plan).await?;

        let token = self.next_token();
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
        let state = self.inner.state.lock().await;
        match &*state {
            CoordinatorState::Idle => {}
            CoordinatorState::Pending(_) => {
                return Err(CoordinatorConflict::TransactionPending.into())
            }
            CoordinatorState::RollbackFailed(_) => {
                return Err(CoordinatorConflict::RollbackRecoveryRequired.into())
            }
        }

        let plan = self.inner.manager.plan(desired).await?;
        self.inner.manager.apply(&plan).await
    }

    pub async fn commit(&self) -> Result<u64> {
        let mut state = self.inner.state.lock().await;
        let pending = match &*state {
            CoordinatorState::Pending(pending) => pending.clone(),
            CoordinatorState::Idle => return Err(NoPendingTransactionError.into()),
            CoordinatorState::RollbackFailed(_) => {
                return Err(CoordinatorConflict::RollbackRecoveryRequired.into())
            }
        };

        let revision = self
            .inner
            .overrides
            .commit_candidate(&pending.candidate)
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
        Ok(revision)
    }

    pub async fn rollback(&self) -> Result<()> {
        let mut state = self.inner.state.lock().await;
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
        let (candidate, snapshot) = match &**state {
            CoordinatorState::Pending(pending) => {
                (pending.candidate.clone(), pending.snapshot.clone())
            }
            CoordinatorState::RollbackFailed(failure) => {
                (failure.candidate.clone(), failure.snapshot.clone())
            }
            CoordinatorState::Idle => return Err(NoPendingTransactionError.into()),
        };

        let failures = self.inner.manager.rollback_to(&snapshot).await;
        if failures.is_empty() {
            // The snapshot names what was actually on the machine when the
            // transaction started, so this at least drops hardware that has
            // since vanished. It is not an exact revert of ownership: the
            // aborted intent's interfaces stay owned until the next commit
            // narrows them, which is the harmless direction to err in.
            let owned: Vec<String> = snapshot
                .interfaces
                .iter()
                .map(|entry| entry.name.clone())
                .collect();
            self.inner.manager.retain_router_interfaces(&owned).await;

            **state = CoordinatorState::Idle;
            if trigger == RollbackTrigger::Timeout {
                tracing::warn!("router transaction automatically rolled back after timeout");
            }
            Ok(())
        } else {
            let message = failures.join("; ");
            **state = CoordinatorState::RollbackFailed(RollbackFailure {
                candidate,
                snapshot,
                failures,
            });
            Err(anyhow::anyhow!("router rollback failed: {message}"))
        }
    }

    async fn rollback_timeout_fired(&self, token: &str) {
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
    }

    impl FakeSubsystems {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                events: StdMutex::new(Vec::new()),
                apply_fail: StdMutex::new(None),
                rollback_fail: StdMutex::new(None),
                drifted: StdMutex::new(false),
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
    async fn full_lifecycle_applies_and_commits() {
        let fake = FakeSubsystems::new();
        let (coordinator, overrides, _directory) = coordinator_with(fake.clone()).await;
        let candidate = build_candidate(&overrides).await;

        let plan = coordinator.plan(candidate).await.expect("plan");
        coordinator.apply(plan).await.expect("apply");
        assert_eq!(coordinator.status().await, CoordinatorStatus::Pending);

        let revision = coordinator.commit().await.expect("commit");
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
            .commit()
            .await
            .expect_err("commit persistence must fail");
        assert!(!error.to_string().is_empty());
        assert_eq!(coordinator.status().await, CoordinatorStatus::Pending);
        assert_eq!(overrides.committed_revision().await, 0);

        tokio::fs::remove_dir(overrides.path())
            .await
            .expect("cleanup");
        let revision = coordinator.commit().await.expect("retry commit");
        assert_eq!(revision, 1);
        let _ = directory;
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
        coordinator.commit().await.expect("commit before timeout");

        tokio::time::sleep(Duration::from_millis(150)).await;

        assert_eq!(coordinator.status().await, CoordinatorStatus::Idle);
        assert_eq!(overrides.committed_revision().await, 1);
        assert!(!fake
            .events()
            .iter()
            .any(|event| event.starts_with("rollback_")));
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
