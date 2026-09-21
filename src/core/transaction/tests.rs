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
async fn a_failed_converger_is_rejected_without_waiting_for_the_deadline() {
    let directory = tempdir().unwrap();
    let desired = desired_state(directory.path()).await;
    desired.attach_converger();
    desired.fail_converger("rtnetlink notification stream closed");
    let manager = NetworkTransactionManager::new(
        InterfaceManager::new(fake_network(), AddressOwnershipJournal::in_memory()),
        Duration::from_secs(60),
        desired.clone(),
    );

    let error = tokio::time::timeout(
        Duration::from_secs(1),
        manager.await_convergence(&desired, "test0"),
    )
    .await
    .expect("failed converger should be rejected immediately")
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("network converger unavailable: rtnetlink notification stream closed"));
}

#[tokio::test]
async fn restart_removes_unconfirmed_address_on_previously_unmanaged_interface() {
    let directory = tempdir().unwrap();
    let provider = fake_network();
    let interfaces = InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory());
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
    let interfaces = InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory());
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
async fn direct_commit_persists_the_configuration_and_recovery_token() {
    let directory = tempdir().unwrap();
    let desired = desired_state(directory.path()).await;
    let manager = NetworkTransactionManager::new(
        InterfaceManager::new(fake_network(), AddressOwnershipJournal::in_memory()),
        Duration::from_secs(60),
        desired.clone(),
    );
    let pending = manager
        .apply("test0", &interface_config(PROPOSED), None, false)
        .await
        .unwrap();
    manager.commit(&pending.token).await.unwrap();
    assert!(!desired.has_pending().await);
    let reloaded = desired_state(directory.path()).await;
    assert_eq!(
        reloaded.committed_interface("test0").await.unwrap(),
        Some(interface_config(PROPOSED))
    );
    let overrides = RuntimeOverrideManager::load(directory.path(), &AppConfig::default())
        .await
        .unwrap();
    assert_eq!(
        overrides
            .snapshot()
            .await
            .committed_interface_transactions
            .get("test0"),
        Some(&pending.token)
    );
}

#[tokio::test]
async fn confirmation_waits_for_an_active_convergence_pass() {
    let directory = tempdir().unwrap();
    let desired = desired_state(directory.path()).await;
    let manager = NetworkTransactionManager::new(
        InterfaceManager::new(fake_network(), AddressOwnershipJournal::in_memory()),
        Duration::from_secs(60),
        desired.clone(),
    );
    let gate = Arc::new(NetworkMutationGate::default());
    manager.set_runtime_gate(gate.clone());
    let pending = manager
        .apply("test0", &interface_config(PROPOSED), None, false)
        .await
        .unwrap();
    let pass = gate.read().await;
    let (persisted_tx, mut persisted_rx) = tokio::sync::oneshot::channel();
    let commit = tokio::spawn(async move {
        manager
            .commit_with(&pending.token, |_, _, _| async move {
                persisted_tx.send(()).unwrap();
                Ok(())
            })
            .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut persisted_rx)
            .await
            .is_err()
    );
    assert!(desired.is_tentative("test0").await);
    drop(pass);
    tokio::time::timeout(Duration::from_secs(1), commit)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    persisted_rx.await.unwrap();
    assert!(!desired.has_pending().await);
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
async fn timeout_waits_for_admitted_confirmation() {
    let directory = tempdir().unwrap();
    let desired = desired_state(directory.path()).await;
    let manager = NetworkTransactionManager::new(
        InterfaceManager::new(fake_network(), AddressOwnershipJournal::in_memory()),
        Duration::from_millis(20),
        desired.clone(),
    );
    let gate = Arc::new(NetworkMutationGate::default());
    manager.set_runtime_gate(gate.clone());
    let pending = manager
        .apply("test0", &interface_config(PROPOSED), None, false)
        .await
        .unwrap();

    // A confirmation already admitted must not be overtaken by the timer
    // while it performs validation before acquiring the operation lock.
    let admission = gate.admit().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(manager.pending().await, vec![pending.clone()]);
    assert!(desired.is_tentative("test0").await);
    manager.commit(&pending.token).await.unwrap();
    drop(admission);
    assert_eq!(
        desired.committed_interface("test0").await.unwrap(),
        Some(interface_config(PROPOSED))
    );
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

    let error = apply
        .await
        .expect("apply task")
        .expect_err("apply must fail");
    assert!(error.to_string().contains("candidate failed"));
    assert!(error.to_string().contains("rollback failed"));
    assert!(!desired.is_tentative("test0").await);

    let pending = manager.pending().await;
    assert_eq!(
        pending.len(),
        1,
        "failed compensation must remain recoverable"
    );
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

#[tokio::test]
async fn rollback_publishes_restore_intent_even_when_secret_restore_fails() {
    let directory = tempdir().expect("tempdir");
    let desired = desired_state(directory.path()).await;
    let manager = NetworkTransactionManager::new(
        InterfaceManager::new(fake_network(), AddressOwnershipJournal::in_memory()),
        Duration::from_secs(60),
        desired.clone(),
    );
    let proposed = interface_config(PROPOSED);
    let pending = manager
        .apply_with_passphrase(
            "test0",
            &proposed,
            None,
            Some(InterfaceRole::Output),
            false,
            Some(WifiPassphrase::new("new-password").expect("passphrase")),
        )
        .await
        .expect("apply");
    assert!(desired.is_tentative("test0").await);

    let psk_dir = directory.path().join("wifi/psk");
    std::fs::remove_dir_all(&psk_dir).expect("remove passphrase directory");
    std::os::unix::fs::symlink(directory.path(), &psk_dir)
        .expect("replace passphrase directory with a rejected symlink");

    let error = manager
        .rollback(&pending.token)
        .await
        .expect_err("secret restoration must fail");
    assert!(error.to_string().contains("failed to complete rollback"));
    assert!(
        !desired.is_tentative("test0").await,
        "the failed candidate must stop being desired even when secret compensation fails"
    );
    assert!(desired.restorations().await.contains_key("test0"));
    assert_eq!(
        desired
            .effective()
            .await
            .expect("effective config")
            .network
            .interfaces["test0"]
            .ipv4,
        Some(COMMITTED.parse().expect("network"))
    );
    assert_eq!(manager.pending().await, vec![pending.clone()]);
    let commit_error = manager
        .commit(&pending.token)
        .await
        .expect_err("failed rollback must remain rollback-only");
    assert!(commit_error.to_string().contains("rollback-only"));
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

#[tokio::test]
async fn corrupt_interface_journal_does_not_prevent_another_recovery() {
    let directory = tempdir().unwrap();
    let provider = fake_network();
    let interfaces = InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory());
    let transactions = NetworkTransactionManager::new(
        interfaces.clone(),
        Duration::from_secs(60),
        desired_state(directory.path()).await,
    );
    transactions
        .write_journal("interrupted", interfaces.snapshot("test0").await.unwrap())
        .await
        .unwrap();
    tokio::fs::write(
        directory.path().join("interface-transactions/bad0.json"),
        b"invalid",
    )
    .await
    .unwrap();
    recover_interface_transactions(directory.path(), &interfaces, &Default::default())
        .await
        .unwrap();
    assert!(crate::core::recovery::check_scope(directory.path(), Some("bad0")).is_err());
    assert!(crate::core::recovery::check_scope(directory.path(), Some("test0")).is_ok());
    assert!(!directory
        .path()
        .join("interface-transactions/test0.json")
        .exists());
    assert!(directory
        .path()
        .join("interface-transactions/bad0.json")
        .exists());
    recover_interface_transactions(directory.path(), &interfaces, &Default::default())
        .await
        .unwrap();
}
