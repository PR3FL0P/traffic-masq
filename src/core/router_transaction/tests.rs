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
use crate::core::router::{DhcpPlan, RouterSnapshot, RouterSubsystems, VpnChainSnapshot};
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
        uplink: Some(UplinkConfig {
            interface: "wan0".to_string(),
            mode: UplinkMode::External,
        }),
        owned_routes: Vec::new(),
        allow_default_route_change: false,
        route_host_traffic: false,
    }
}

struct FakeSubsystems {
    events: StdMutex<Vec<String>>,
    apply_fail: StdMutex<Option<&'static str>>,
    rollback_fail: StdMutex<Option<&'static str>>,
    pause_apply: std::sync::atomic::AtomicBool,
    apply_entered: tokio::sync::Notify,
    prepare_fail: std::sync::atomic::AtomicBool,
    prepare_attempts: std::sync::atomic::AtomicUsize,
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
            pause_apply: std::sync::atomic::AtomicBool::new(false),
            apply_entered: tokio::sync::Notify::new(),
            prepare_fail: std::sync::atomic::AtomicBool::new(false),
            prepare_attempts: std::sync::atomic::AtomicUsize::new(0),
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
    async fn prepare_recovery(&self, _: &RouterDesired) -> Result<()> {
        self.prepare_attempts.fetch_add(1, Ordering::SeqCst);
        anyhow::ensure!(
            !self.prepare_fail.load(Ordering::SeqCst),
            "ownership unavailable"
        );
        Ok(())
    }

    async fn plan_for(
        &self,
        desired: &RouterDesired,
    ) -> Result<crate::core::router::RouterSubsystemPlan> {
        self.record("plan_interfaces")?;
        let interfaces = vec![InterfaceChangePlan {
            interface: "lan0".into(),
            delete_ipv4: Vec::new(),
            retag_ipv4: None,
            add_ipv4: None,
            set_link_up: false,
            management_change: false,
            dhcp_action: DhcpChangeAction::Unchanged,
            releasing_management: false,
        }];
        if desired.uplink_wifi.is_some() {
            anyhow::bail!("uplink Wi-Fi runtime is unavailable");
        }
        if !desired.output_wifi.is_empty() {
            anyhow::bail!("output Wi-Fi runtime is unavailable");
        }
        let routes = self.plan_routes(desired).await?;
        self.record("plan_dhcp")?;
        let vpn_chain = self.plan_vpn_chain(desired).await?;
        let dataplane = self.plan_dataplane(desired).await?;
        Ok(crate::core::router::RouterSubsystemPlan {
            interfaces,
            uplink_wifi: Vec::new(),
            output_wifi: Vec::new(),
            routes,
            dhcp: Vec::new(),
            vpn_chain,
            dataplane,
        })
    }
    async fn plan_routes(&self, _: &crate::core::router::RouterDesired) -> Result<RoutePlan> {
        self.record("plan_routes")?;
        Ok(RoutePlan {
            add: Vec::new(),
            delete: Vec::new(),
        })
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
    async fn retain_router_interfaces(&self, interfaces: &[String]) {
        self.retained.lock().unwrap().push(interfaces.to_vec());
    }
    async fn snapshot_for(&self, _: &RouterDesired) -> Result<RouterSnapshot> {
        self.record("snapshot_for")?;
        Ok(RouterSnapshot {
            interfaces: Vec::new(),
            uplink_wifi: Vec::new(),
            uplink_dhcp: None,
            dhcp_clients: Vec::new(),
            output_wifi: Vec::new(),
            dhcp: Vec::new(),
            dhcp_absent_interfaces: Vec::new(),
            routes: RouteSnapshot::empty(),
            vpn_chain: VpnChainSnapshot::empty(),
            dataplane: self.dataplane_snapshot(),
        })
    }
    async fn apply_interfaces(&self, _: &[InterfaceChangePlan]) -> Result<()> {
        if self.pause_apply.load(Ordering::SeqCst) {
            self.apply_entered.notify_one();
            std::future::pending::<()>().await;
        }
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
            let store = crate::wifi::store::PassphraseStore::new(root.join("wifi/psk-ap"));
            anyhow::ensure!(
                store
                    .get("wlan0")?
                    .is_some_and(|secret| secret.expose() == "old-password"),
                "runtime rollback needs the original Wi-Fi credential"
            );
        }
        self.fail_if_matched("rollback_interfaces", &self.rollback_fail)
    }
    async fn rollback_routes(&self, _: &RouteSnapshot) -> Result<()> {
        self.fail_if_matched("rollback_routes", &self.rollback_fail)
    }
    async fn rollback_dhcp_scoped(&self, _: &[DhcpServiceSpec], _: &[String]) -> Result<()> {
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
    async fn quiesce_uplink_dhcp(
        &self,
        desired: Option<&crate::dhcp::client::DhcpClientSpec>,
    ) -> Result<()> {
        anyhow::ensure!(
            desired.is_none(),
            "embedded DHCP client runtime is unavailable"
        );
        Ok(())
    }
    async fn apply_uplink_dhcp_candidate(
        &self,
        desired: Option<&crate::dhcp::client::DhcpClientSpec>,
    ) -> Result<bool> {
        anyhow::ensure!(
            desired.is_none(),
            "embedded DHCP client runtime is unavailable"
        );
        Ok(false)
    }
    async fn rollback_candidate_uplink_dhcp(&self) -> Result<()> {
        Ok(())
    }
    async fn rollback_dhcp_clients(
        &self,
        snapshots: &[crate::core::router::DhcpClientSnapshot],
        legacy: Option<&crate::dhcp::client::DhcpClientSpec>,
    ) -> Result<()> {
        anyhow::ensure!(
            snapshots.is_empty() && legacy.is_none(),
            "DHCP client restoration is unavailable"
        );
        Ok(())
    }
    async fn health_uplink_dhcp(
        &self,
        desired: &RouterDesired,
    ) -> Option<crate::core::router::RouterDhcpHealthReason> {
        desired.uplink_dhcp.as_ref().map(|spec| {
            crate::core::router::RouterDhcpHealthReason::IntentMissing {
                interface: spec.interface.clone(),
            }
        })
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
    coordinator_with_timeout(fake, Duration::from_secs(60)).await
}

async fn coordinator_with_timeout(
    fake: Arc<FakeSubsystems>,
    timeout: Duration,
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
    let coordinator = RouterTransactionCoordinator::new(manager, overrides.clone(), timeout);
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
        .write_journal(
            candidate.base_revision(),
            "test-transaction",
            &snapshot,
            candidate.desired(),
        )
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
        .write_journal(
            candidate.base_revision(),
            "test-transaction",
            &snapshot,
            candidate.desired(),
        )
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
        .write_journal(
            candidate.base_revision(),
            "test-transaction",
            &snapshot,
            candidate.desired(),
        )
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
        .write_journal(
            candidate.base_revision(),
            "unconfirmed",
            &snapshot,
            candidate.desired(),
        )
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
    let error = coordinator
        .recover()
        .await
        .expect_err("invalid recovery record must remain operator-blocking");
    let diagnostic = error.to_string();
    assert!(diagnostic.contains("recovery_code=TM-REC-203"));
    assert!(diagnostic.contains("invariant=decodable_recovery_snapshot"));
    assert!(diagnostic.contains(&format!("journal={}", coordinator.inner.journal.display())));
    assert!(diagnostic.contains("required_proof=independent_committed_transaction_token"));
    assert!(diagnostic.contains("backup_scope=complete_state_directory"));
    assert!(diagnostic.contains("operator_action=restore_coherent_backup"));
    assert!(coordinator.inner.journal.exists());
}

#[tokio::test]
async fn unsupported_uncommitted_router_schema_reports_versions_and_action() {
    let fake = FakeSubsystems::new();
    let (coordinator, overrides, _directory) = coordinator_with(fake).await;
    let candidate = build_candidate(&overrides).await;
    let snapshot = coordinator
        .manager()
        .snapshot_for(candidate.desired())
        .await
        .unwrap();
    let journal = TransactionJournal {
        version: 999,
        base_revision: candidate.base_revision(),
        token: "uncommitted".to_string(),
        snapshot,
        current_desired: Some(candidate.desired().clone()),
    };
    tokio::fs::write(
        &coordinator.inner.journal,
        serde_json::to_vec(&journal).unwrap(),
    )
    .await
    .unwrap();

    let error = coordinator
        .recover()
        .await
        .expect_err("unsupported schema must block");
    let diagnostic = format!("{error:#}");
    assert!(diagnostic.contains("recovery_code=TM-REC-205"));
    assert!(diagnostic.contains("invariant=supported_schema"));
    assert!(diagnostic.contains("journal_schema=999"));
    assert!(diagnostic.contains("supported_schemas=1,2"));
    assert!(diagnostic.contains("operator_action=use_compatible_daemon"));
}

#[tokio::test]
async fn newer_router_journal_reports_both_revisions() {
    let fake = FakeSubsystems::new();
    let (coordinator, overrides, _directory) = coordinator_with(fake).await;
    let candidate = build_candidate(&overrides).await;
    let snapshot = coordinator
        .manager()
        .snapshot_for(candidate.desired())
        .await
        .unwrap();
    coordinator
        .write_journal(1, "uncommitted", &snapshot, candidate.desired())
        .await
        .unwrap();

    let error = coordinator
        .recover()
        .await
        .expect_err("newer journal must block");
    let diagnostic = format!("{error:#}");
    assert!(diagnostic.contains("recovery_code=TM-REC-206"));
    assert!(diagnostic.contains("invariant=revision_order"));
    assert!(diagnostic.contains("journal_base_revision=1"));
    assert!(diagnostic.contains("committed_revision=0"));
    assert!(diagnostic.contains("backup_scope=complete_state_directory"));
    assert!(diagnostic.contains("operator_action=restore_coherent_backup"));
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
            timer_epoch: AtomicU64::new(0),
            timeout_mutation_gate: StdRwLock::new(None),
            idle_epoch: watch::channel(0).0,
            last_applied_revision: StdRwLock::new(None),
        }),
    };

    isolated_coordinator
        .write_journal(
            candidate.base_revision(),
            "token-1",
            &snapshot,
            candidate.desired(),
        )
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
    assert!(coordinator.last_applied_revision().is_none());
    let pending = coordinator.view().await;
    assert_eq!(pending.phase, RouterPhase::Pending);
    assert!(pending.commit_uncertainty.is_none());
    assert!(!pending.cleanup_pending);

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
    assert_eq!(coordinator.last_applied_revision(), Some(1));

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
        CoordinatorStatus::RecoveryRequired
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
            (
                crate::wifi::store::WifiCredentialRole::Ap,
                Some(WifiPassphrase::new("old-password").unwrap()),
            ),
        )]))
        .await
        .unwrap();
    PassphraseStore::new(directory.join("wifi/psk-ap"))
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
    let secret_path = directory.path().join("wifi/psk-ap/wlan0");
    std::fs::remove_file(&secret_path).unwrap();
    std::fs::create_dir(&secret_path).unwrap();

    assert!(coordinator.rollback_with_token(&token).await.is_err());
    assert_eq!(
        coordinator.status().await,
        CoordinatorStatus::RecoveryRequired
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

#[tokio::test(start_paused = true)]
async fn timeout_rolls_back_uncommitted_transaction() {
    let fake = FakeSubsystems::new();
    let (coordinator, overrides, _directory) =
        coordinator_with_timeout(fake.clone(), Duration::from_millis(30)).await;
    let candidate = build_candidate(&overrides).await;
    let plan = coordinator.plan(candidate).await.expect("plan");
    coordinator.apply(plan).await.expect("apply");
    assert_eq!(coordinator.status().await, CoordinatorStatus::Pending);

    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(150)).await;
    // Filesystem work runs outside the virtual clock. Bound its completion
    // with real time so an idle executor cannot skip past the I/O.
    tokio::time::resume();
    tokio::time::timeout(Duration::from_secs(5), coordinator.wait_until_idle())
        .await
        .expect("rollback completion");

    assert_eq!(coordinator.status().await, CoordinatorStatus::Idle);
    assert_eq!(overrides.committed_revision().await, 0);
}

#[tokio::test]
async fn router_timeout_does_not_wait_for_unrelated_admission() {
    let fake = FakeSubsystems::new();
    let (coordinator, overrides, _directory) =
        coordinator_with_timeout(fake, Duration::from_millis(100)).await;
    let gate = Arc::new(NetworkMutationGate::default());
    coordinator.set_timeout_mutation_gate(gate.clone());
    let plan = coordinator
        .plan(build_candidate(&overrides).await)
        .await
        .unwrap();
    coordinator.apply(plan).await.unwrap();
    let _admission = gate.admit().await;
    tokio::time::timeout(Duration::from_secs(2), coordinator.wait_until_idle())
        .await
        .unwrap();
    assert_eq!(overrides.committed_revision().await, 0);
}

#[tokio::test(start_paused = true)]
async fn router_commit_checks_deadline_even_before_timer_gets_state_lock() {
    let fake = FakeSubsystems::new();
    let (coordinator, overrides, _directory) =
        coordinator_with_timeout(fake, Duration::from_secs(60)).await;
    let plan = coordinator
        .plan(build_candidate(&overrides).await)
        .await
        .unwrap();
    let token = coordinator.apply(plan).await.unwrap();
    // Expire the transaction's monotonic deadline without relying on the timer
    // being scheduled; the commit path itself must refuse stale confirmation.
    if let CoordinatorState::Pending(pending) = &mut *coordinator.inner.state.lock().await {
        pending.confirmation_deadline = Some(tokio::time::Instant::now());
    } else {
        panic!("expected pending transaction");
    }
    assert!(coordinator
        .commit(&token)
        .await
        .unwrap_err()
        .to_string()
        .contains("deadline expired"));
    assert_eq!(overrides.committed_revision().await, 0);
    assert!(coordinator.inner.journal.exists());
}

#[tokio::test(start_paused = true)]
async fn timeout_does_not_roll_back_an_already_committed_transaction() {
    let fake = FakeSubsystems::new();
    let (coordinator, overrides, _directory) =
        coordinator_with_timeout(fake.clone(), Duration::from_millis(30)).await;
    let candidate = build_candidate(&overrides).await;
    let plan = coordinator.plan(candidate).await.expect("plan");
    coordinator.apply(plan).await.expect("apply");
    coordinator
        .commit(&coordinator.pending_token().await.unwrap_or_default())
        .await
        .expect("commit before timeout");

    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(150)).await;
    // Filesystem work runs outside the virtual clock. Bound its completion
    // with real time so an idle executor cannot skip past the I/O.
    tokio::time::resume();
    tokio::time::timeout(Duration::from_secs(5), coordinator.wait_until_idle())
        .await
        .expect("rollback completion");

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
    let initial_token = coordinator
        .apply(initial_plan)
        .await
        .expect("initial apply");
    coordinator
        .commit(&initial_token)
        .await
        .expect("initial commit");

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
    let initial_token = coordinator
        .apply(initial_plan)
        .await
        .expect("initial apply");
    coordinator
        .commit(&initial_token)
        .await
        .expect("initial commit");

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

    let view = coordinator.view().await;
    assert_eq!(view.phase, RouterPhase::RollbackRequired);
    assert!(view.commit_uncertainty.is_none());
    assert_eq!(view.status(), CoordinatorStatus::RollbackFailed);
    assert_eq!(view.token.as_deref(), Some(failure.token.as_str()));
    assert_eq!(view.rollback_failures, failure.failures);

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

#[tokio::test]
async fn completed_receipt_skips_destructive_recovery_after_restart() {
    use sha2::Digest;
    let fake = FakeSubsystems::new();
    let (coordinator, overrides, _directory) = coordinator_with(fake.clone()).await;
    let candidate = build_candidate(&overrides).await;
    let snapshot = coordinator
        .manager()
        .snapshot_for(candidate.desired())
        .await
        .unwrap();
    coordinator
        .write_journal(
            candidate.base_revision(),
            "recovered",
            &snapshot,
            candidate.desired(),
        )
        .await
        .unwrap();
    let bytes = tokio::fs::read(&coordinator.inner.journal).await.unwrap();
    tokio::fs::write(
        coordinator.inner.journal.with_extension("json.recovered"),
        sha2::Sha256::digest(&bytes).as_slice(),
    )
    .await
    .unwrap();
    assert!(!coordinator.recover().await.unwrap());
    assert!(!fake
        .events()
        .iter()
        .any(|event| event.starts_with("rollback_")));
    assert_eq!(coordinator.status().await, CoordinatorStatus::Idle);
}

#[tokio::test]
async fn unsupported_committed_journal_is_quarantined_without_rollback() {
    let fake = FakeSubsystems::new();
    let (coordinator, overrides, directory) = coordinator_with(fake.clone()).await;
    let candidate = build_candidate(&overrides).await;
    overrides
        .commit_candidate_with_token(&candidate, Some("committed"))
        .await
        .unwrap();
    tokio::fs::write(
        &coordinator.inner.journal,
        br#"{"version":999,"token":"committed"}"#,
    )
    .await
    .unwrap();
    assert!(!coordinator.recover().await.unwrap());
    assert!(!coordinator.inner.journal.exists());
    assert!(std::fs::read_dir(directory.path())
        .unwrap()
        .any(|entry| entry
            .unwrap()
            .path()
            .to_string_lossy()
            .ends_with(".corrupt")));
    assert!(!fake
        .events()
        .iter()
        .any(|event| event.starts_with("rollback_")));
}

#[tokio::test]
async fn restored_router_reports_cleanup_pending_and_never_rolls_back_twice() {
    let fake = FakeSubsystems::new();
    let (coordinator, overrides, _directory) = coordinator_with(fake.clone()).await;
    let candidate = build_candidate(&overrides).await;
    let plan = coordinator.plan(candidate).await.unwrap();
    coordinator.apply(plan).await.unwrap();
    let receipt = coordinator.inner.journal.with_extension("json.recovered");
    tokio::fs::create_dir(&receipt).await.unwrap();
    coordinator.rollback().await.unwrap();
    let view = coordinator.view().await;
    assert_eq!(view.phase, RouterPhase::Idle);
    assert!(view.commit_uncertainty.is_none());
    assert!(view.cleanup_pending);
    assert_eq!(
        view.status(),
        CoordinatorStatus::RecoveredButJournalCleanupPending
    );
    let after = fake.events();
    tokio::fs::remove_dir(receipt).await.unwrap();
    crate::core::recovery::before_write(&coordinator.inner.journal)
        .await
        .unwrap();
    assert_eq!(coordinator.status().await, CoordinatorStatus::Idle);
    assert!(!coordinator.view().await.cleanup_pending);
    assert_eq!(fake.events(), after);
}

#[tokio::test]
async fn manual_rollback_retries_failed_startup_preparation_before_restoring() {
    let fake = FakeSubsystems::new();
    let (coordinator, overrides, _directory) = coordinator_with(fake.clone()).await;
    let candidate = build_candidate(&overrides).await;
    let snapshot = coordinator
        .manager()
        .snapshot_for(candidate.desired())
        .await
        .unwrap();
    coordinator
        .write_journal(
            candidate.base_revision(),
            "interrupted",
            &snapshot,
            candidate.desired(),
        )
        .await
        .unwrap();
    fake.prepare_fail.store(true, Ordering::SeqCst);

    assert!(coordinator.recover().await.is_err());
    assert!(coordinator
        .rollback_with_token("interrupted")
        .await
        .is_err());
    assert_eq!(fake.prepare_attempts.load(Ordering::SeqCst), 2);
    assert!(!fake
        .events()
        .iter()
        .any(|event| event.starts_with("rollback_")));
    assert!(coordinator.inner.journal.exists());
    assert_eq!(
        coordinator.status().await,
        CoordinatorStatus::RollbackFailed
    );

    fake.prepare_fail.store(false, Ordering::SeqCst);
    coordinator
        .rollback_with_token("interrupted")
        .await
        .unwrap();
    assert_eq!(fake.prepare_attempts.load(Ordering::SeqCst), 3);
    assert!(fake
        .events()
        .iter()
        .any(|event| event.starts_with("rollback_")));
    assert!(!coordinator.inner.journal.exists());
    assert_eq!(coordinator.status().await, CoordinatorStatus::Idle);
}

#[tokio::test]
async fn dangling_router_journal_symlink_is_not_treated_as_missing() {
    let fake = FakeSubsystems::new();
    let (coordinator, _, directory) = coordinator_with(fake.clone()).await;
    std::os::unix::fs::symlink(
        directory.path().join("missing-router-journal-target"),
        &coordinator.inner.journal,
    )
    .expect("dangling journal symlink");

    let error = coordinator
        .recover()
        .await
        .expect_err("dangling journal symlink must block recovery");
    let diagnostic = format!("{error:#}");
    assert!(diagnostic.contains("recovery_code=TM-REC-202"));
    assert!(diagnostic.contains("invariant=accessible_router_recovery_journal"));
    assert!(
        fake.events().is_empty(),
        "recovery must not mutate the network"
    );
}

#[tokio::test]
async fn automatic_rollback_retries_after_transient_failure() {
    let fake = FakeSubsystems::new();
    let (coordinator, overrides, _directory) =
        coordinator_with_timeout(fake.clone(), Duration::from_millis(30)).await;
    let gate = Arc::new(NetworkMutationGate::default());
    coordinator.set_timeout_mutation_gate(gate.clone());
    let plan = coordinator
        .plan(build_candidate(&overrides).await)
        .await
        .unwrap();
    let token = coordinator.apply(plan).await.unwrap();
    fake.fail_rollback("rollback_routes");
    tokio::time::timeout(Duration::from_secs(2), async {
        while coordinator.status().await != CoordinatorStatus::RollbackFailed {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(coordinator.inner.journal.exists());
    assert!(coordinator.commit(&token).await.is_err());
    let admission = tokio::time::timeout(Duration::from_millis(500), gate.admit())
        .await
        .unwrap();
    *fake.rollback_fail.lock().unwrap() = None;
    drop(admission);
    tokio::time::timeout(Duration::from_secs(3), coordinator.wait_until_idle())
        .await
        .expect("automatic retry must finish recovery");
    assert!(!coordinator.inner.journal.exists());
    assert_eq!(overrides.committed_revision().await, 0);
}

#[tokio::test]
async fn failed_apply_compensation_is_retried_automatically() {
    let fake = FakeSubsystems::new();
    let (coordinator, overrides, _directory) = coordinator_with(fake.clone()).await;
    let plan = coordinator
        .plan(build_candidate(&overrides).await)
        .await
        .unwrap();
    fake.fail_apply("apply_routes");
    fake.fail_rollback("rollback_routes");
    assert!(coordinator.apply(plan).await.is_err());
    assert_eq!(
        coordinator.status().await,
        CoordinatorStatus::RollbackFailed
    );
    *fake.rollback_fail.lock().unwrap() = None;
    tokio::time::timeout(Duration::from_secs(3), coordinator.wait_until_idle())
        .await
        .expect("failed apply must also schedule recovery");
    assert!(!coordinator.inner.journal.exists());
    assert_eq!(overrides.committed_revision().await, 0);
}

#[tokio::test]
async fn indeterminate_commit_fences_router_and_retains_recovery_evidence() {
    let fake = FakeSubsystems::new();
    let (original, overrides, directory) = coordinator_with(fake.clone()).await;
    // Seed an existing document so compensation must replace it.
    overrides
        .save_committed(overrides.snapshot().await)
        .await
        .unwrap();
    let coordinator = RouterTransactionCoordinator::new(
        original.manager(),
        overrides.clone(),
        Duration::from_secs(60),
    );
    let plan = coordinator
        .plan(build_candidate(&overrides).await)
        .await
        .unwrap();
    let token = coordinator.apply(plan).await.unwrap();
    let revision = overrides.committed_revision().await;
    crate::atomic_file::fail_replacement_and_compensation(overrides.path());
    assert!(crate::atomic_file::is_indeterminate_write(
        &coordinator.commit(&token).await.unwrap_err()
    ));
    assert_eq!(
        coordinator.status().await,
        CoordinatorStatus::CommitIndeterminate
    );
    let view = coordinator.view().await;
    assert_eq!(view.phase, RouterPhase::Pending);
    assert!(view.commit_uncertainty.is_some());
    assert_eq!(view.token.as_deref(), Some(token.as_str()));
    assert!(view.rollback_failures.is_empty());
    assert!(!view.failures().is_empty());
    assert!(coordinator.commit(&token).await.is_err());
    assert!(coordinator.rollback_with_token(&token).await.is_err());
    assert!(coordinator.rollback().await.is_err());
    assert!(!coordinator.rollback_timeout_fired(&token).await);
    assert!(overrides
        .save_committed(overrides.snapshot().await)
        .await
        .is_err());
    assert_eq!(overrides.committed_revision().await, revision);
    let disk = crate::state::overrides::RuntimeOverrideStore::in_state_dir(directory.path())
        .load()
        .await
        .unwrap();
    assert_eq!(
        disk.committed_router_transaction.as_deref(),
        Some(token.as_str())
    );
    assert_eq!(disk.revision, revision + 1);
    assert!(coordinator.inner.journal.exists());
    let restarted_dir = tempdir().unwrap();
    let restarted_store =
        crate::state::overrides::RuntimeOverrideStore::in_state_dir(restarted_dir.path());
    std::fs::copy(overrides.path(), restarted_store.path()).unwrap();
    std::fs::copy(
        &coordinator.inner.journal,
        restarted_dir.path().join("router-transaction.json"),
    )
    .unwrap();
    let reloaded = RuntimeOverrideManager::load(restarted_dir.path(), &base_config())
        .await
        .unwrap();
    let restarted =
        RouterTransactionCoordinator::new(coordinator.manager(), reloaded, Duration::from_secs(60));
    assert!(
        !restarted.recover().await.unwrap(),
        "persisted commit proof must prevent rollback after restart"
    );
    assert_eq!(restarted.status().await, CoordinatorStatus::Idle);
    assert!(coordinator.recover().await.is_err());
    assert!(!fake
        .events()
        .iter()
        .any(|event| event.starts_with("rollback_")));
}

#[tokio::test]
async fn exhausted_router_recovery_survives_restart_and_shutdown_without_mutations() {
    let fake = FakeSubsystems::new();
    let (original, overrides, _root) = coordinator_with(fake.clone()).await;
    let coordinator = RouterTransactionCoordinator::new(
        original.manager(),
        overrides.clone(),
        Duration::from_secs(3600),
    );
    let plan = coordinator
        .plan(build_candidate(&overrides).await)
        .await
        .unwrap();
    let token = coordinator.apply(plan).await.unwrap();
    coordinator.inner.timer_epoch.fetch_add(1, Ordering::SeqCst);
    fake.fail_rollback("rollback_routes");
    for _ in 0..recovery_control::MAX_ATTEMPTS {
        coordinator.rollback_timeout_fired(&token).await;
    }
    assert_eq!(
        coordinator.status().await,
        CoordinatorStatus::RecoveryRequired
    );
    assert_eq!(
        recovery_control::progress(&coordinator.inner.journal)
            .unwrap()
            .attempts,
        recovery_control::MAX_ATTEMPTS
    );
    let before = fake.events();
    assert!(!coordinator.rollback_timeout_fired(&token).await);
    assert!(coordinator.rollback_for_shutdown().await.is_err());
    assert_eq!(fake.events(), before);
    recovery_control::forget(&coordinator.inner.journal);
    let restarted = RouterTransactionCoordinator::new(
        coordinator.manager(),
        overrides.clone(),
        Duration::from_secs(3600),
    );
    assert!(restarted.recover().await.is_err());
    assert_eq!(
        restarted.status().await,
        CoordinatorStatus::RecoveryRequired
    );
    assert_eq!(fake.events(), before);
    *fake.rollback_fail.lock().unwrap() = None;
    assert!(!restarted.rollback_timeout_fired(&token).await);
    assert_eq!(
        fake.events(),
        before,
        "late repair cannot resume automatically"
    );
    restarted.rollback_with_token(&token).await.unwrap();
    assert_eq!(restarted.status().await, CoordinatorStatus::Idle);
    assert!(!restarted.inner.journal.exists());
    assert_eq!(overrides.committed_revision().await, 0);
}

#[tokio::test]
async fn persisted_commit_proof_prevents_rollback_of_stale_volatile_pending_state() {
    let fake = FakeSubsystems::new();
    let (original, overrides, _directory) = coordinator_with(fake.clone()).await;
    let coordinator = RouterTransactionCoordinator::new(
        original.manager(),
        overrides.clone(),
        Duration::from_secs(3600),
    );
    let plan = coordinator
        .plan(build_candidate(&overrides).await)
        .await
        .unwrap();
    let token = coordinator.apply(plan).await.unwrap();
    let candidate = match &*coordinator.inner.state.lock().await {
        CoordinatorState::Pending(pending) => pending.candidate.clone(),
        _ => panic!("transaction must be pending"),
    };
    // Model cancellation after persistence, before coordinator bookkeeping.
    overrides
        .commit_candidate_with_token(&candidate, Some(&token))
        .await
        .unwrap();
    let before = fake.events();
    assert!(!coordinator.rollback_timeout_fired(&token).await);
    assert_eq!(fake.events(), before);
    assert_eq!(coordinator.status().await, CoordinatorStatus::Idle);
    assert_eq!(overrides.committed_revision().await, 1);
    assert!(!coordinator.inner.journal.exists());
}

#[tokio::test]
async fn cancelled_router_apply_keeps_a_recovery_token_and_cannot_be_confirmed() {
    let fake = FakeSubsystems::new();
    let (original, overrides, _directory) = coordinator_with(fake.clone()).await;
    let coordinator = RouterTransactionCoordinator::new(
        original.manager(),
        overrides.clone(),
        Duration::from_secs(3600),
    );
    let plan = coordinator
        .plan(build_candidate(&overrides).await)
        .await
        .unwrap();
    fake.pause_apply.store(true, Ordering::SeqCst);
    let worker = coordinator.clone();
    let applying = tokio::spawn(async move { worker.apply(plan).await });
    fake.apply_entered.notified().await;
    applying.abort();
    assert!(applying.await.unwrap_err().is_cancelled());
    assert_eq!(
        coordinator.status().await,
        CoordinatorStatus::RecoveryRequired
    );
    let token = coordinator
        .pending_token()
        .await
        .expect("cancelled apply must remain inspectable");
    assert!(coordinator.commit(&token).await.is_err());
    assert!(coordinator.inner.journal.exists());
    let before = fake.events();
    assert!(coordinator.rollback_for_shutdown().await.is_err());
    assert_eq!(fake.events(), before);
    coordinator.rollback_with_token(&token).await.unwrap();
    assert_eq!(coordinator.status().await, CoordinatorStatus::Idle);
    assert!(!coordinator.inner.journal.exists());
    assert_eq!(overrides.committed_revision().await, 0);
}
