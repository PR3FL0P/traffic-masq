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
use crate::wifi::{PassphraseStore, WifiPassphrase, WifiPassphraseUpdate, WifiRuntimeDirs};

use super::journal::{interface_recovery_store_error, retryable_interface_store_error};
use super::*;
use crate::wifi::store::WifiCredentialRole;

mod regressions;

#[tokio::test]
async fn runtime_constructors_reject_detached_apply_before_staging_changes() {
    let directory = tempdir().unwrap();
    let desired = desired_state(directory.path()).await;
    let provider = fake_network();
    let interfaces = InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory());
    let dhcp = DhcpSupervisor::start(&AppConfig::default()).await.unwrap();
    let managers = [
        NetworkTransactionManager::new(
            interfaces.clone(),
            Duration::from_secs(60),
            desired.clone(),
        ),
        NetworkTransactionManager::new_with_baselines(
            interfaces.clone(),
            Duration::from_secs(60),
            Vec::new(),
            desired.clone(),
        ),
        NetworkTransactionManager::new_with_services(
            interfaces,
            Duration::from_secs(60),
            Vec::new(),
            dhcp,
            60,
            desired.clone(),
        ),
    ];
    let before = addresses(&provider).await;
    for manager in managers {
        let error = manager
            .apply(
                "test0",
                InterfaceChange {
                    config: &interface_config(PROPOSED),
                    previous: None,
                    current_role: None,
                    passphrase: WifiPassphraseUpdate::Keep,
                    allow_management_change: false,
                },
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("converger unavailable"));
        assert!(manager.pending().await.is_empty());
        assert!(!desired.has_pending().await);
        assert!(!manager.journal_path("test0").exists());
        assert_eq!(addresses(&provider).await, before);
    }
}

#[tokio::test]
async fn detached_mode_only_skips_convergence_for_an_unattached_worker() {
    let directory = tempdir().unwrap();
    let desired = desired_state(directory.path()).await;
    let manager = NetworkTransactionManager::new_detached(
        InterfaceManager::new(fake_network(), AddressOwnershipJournal::in_memory()),
        Duration::from_secs(60),
        desired.clone(),
    );
    manager.await_convergence(&desired, "test0").await.unwrap();
    desired.fail_converger("worker failed");
    assert!(manager
        .await_convergence(&desired, "test0")
        .await
        .unwrap_err()
        .to_string()
        .contains("worker failed"));
    desired.attach_converger();
    desired.stop_converger();
    assert!(manager
        .await_convergence(&desired, "test0")
        .await
        .unwrap_err()
        .to_string()
        .contains("stopped"));
    assert!(manager.pending().await.is_empty());
}

fn wifi_runtime_dirs() -> WifiRuntimeDirs {
    WifiRuntimeDirs::new(
        "/run/traffic-masq/hostapd",
        "/run/traffic-masq/wpa_supplicant",
    )
}

#[test]
fn convergence_deadline_exceeds_sequential_wifi_and_dhcp_startup_budgets() {
    assert!(
        CONVERGENCE_DEADLINE
            > crate::wifi::lifecycle::STARTUP_READY_TIMEOUT
                + crate::dhcp::client::supervisor::LEASE_READY_TIMEOUT
    );
}

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
        wifi_concurrent: false,
        randomize_mac: false,
        mac_address: None,
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
    spawn_converger_with_interfaces(
        desired,
        InterfaceManager::new(provider, AddressOwnershipJournal::in_memory()),
    )
}

fn spawn_converger_with_interfaces(
    desired: DesiredNetworkState,
    interfaces: InterfaceManager,
) -> tokio::task::JoinHandle<()> {
    desired.attach_converger();
    tokio::spawn(async move {
        loop {
            let version = desired.version();
            let mut failures = BTreeMap::new();
            let effective = desired.effective().await.expect("effective config");
            let allowed = desired.management_allowlist().await;
            let restorations = desired.restorations().await;
            for (name, config) in &effective.network.interfaces {
                let result = match restorations.get(name) {
                    Some(snapshot) => interfaces.rollback_transaction_snapshot(snapshot).await,
                    None => {
                        interfaces
                            .apply_interface(
                                name,
                                config,
                                Some(config.role),
                                allowed.contains(name),
                            )
                            .await
                    }
                };
                if let Err(error) = result {
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
async fn shutdown_preserves_cancelled_apply_when_converger_cannot_restore_it() {
    for restore_baselines in [false, true] {
        let directory = tempdir().unwrap();
        let desired = desired_state(directory.path()).await;
        desired.attach_converger();
        let provider = fake_network();
        let manager = NetworkTransactionManager::new(
            InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory()),
            Duration::from_secs(60),
            desired.clone(),
        );
        let worker = manager.clone();
        let applying = tokio::spawn(async move {
            worker
                .apply(
                    "test0",
                    InterfaceChange {
                        config: &interface_config(PROPOSED),
                        previous: None,
                        current_role: None,
                        allow_management_change: false,
                        passphrase: WifiPassphraseUpdate::Keep,
                    },
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while !desired.is_tentative("test0").await {
                desired.changed().await;
            }
        })
        .await
        .unwrap();
        // Model a partially applied runtime change before cancellation.
        provider.interface.lock().await.is_up = true;
        desired.fail_converger("injected failure prevents compensation");
        applying.abort();
        assert!(applying.await.unwrap_err().is_cancelled());

        // No prior status request is needed to make shutdown aware of recovery.
        let result = if restore_baselines {
            manager.restore_baselines().await
        } else {
            manager.rollback_all_pending().await
        };
        assert!(result.is_err(), "shutdown must report unresolved recovery");
        assert!(provider.interface.lock().await.is_up);
        assert!(manager.journal_path("test0").exists());
        assert!(desired.has_pending().await);
        let pending = manager.pending().await;
        assert_eq!(pending.len(), 1);
        assert!(!pending[0].can_commit());
    }
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
    let transactions = NetworkTransactionManager::new_detached(
        interfaces.clone(),
        Duration::from_secs(60),
        desired,
    );
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
    recover_interface_transactions(
        transactions.recovery(),
        directory.path(),
        &interfaces,
        &Default::default(),
        &wifi_runtime_dirs(),
    )
    .await
    .unwrap();
    assert_eq!(
        addresses(&provider).await,
        vec![Ipv4Addr::new(192, 168, 1, 10)]
    );
}

#[tokio::test]
async fn independently_blocked_interface_is_not_rolled_back_by_transaction_recovery() {
    let directory = tempdir().unwrap();
    let provider = fake_network();
    let interfaces = InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory());
    let desired = desired_state(directory.path()).await;
    let transactions = NetworkTransactionManager::new_detached(
        interfaces.clone(),
        Duration::from_secs(60),
        desired,
    );
    transactions
        .write_journal("interrupted", interfaces.snapshot("test0").await.unwrap())
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
    let excluded = std::collections::BTreeSet::from(["test0".to_string()]);

    recover_interface_transactions_with_commit_tokens_excluding(
        transactions.recovery(),
        directory.path(),
        &interfaces,
        &Default::default(),
        &excluded,
        &wifi_runtime_dirs(),
    )
    .await
    .unwrap();

    assert_eq!(addresses(&provider).await, before);
    assert!(directory
        .path()
        .join("interface-transactions/test0.json")
        .exists());
}

#[tokio::test]
async fn restart_keeps_address_whose_commit_token_was_persisted() {
    let directory = tempdir().unwrap();
    let provider = fake_network();
    let interfaces = InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory());
    let desired = desired_state(directory.path()).await;
    let transactions = NetworkTransactionManager::new_detached(
        interfaces.clone(),
        Duration::from_secs(60),
        desired,
    );
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
    recover_interface_transactions(
        transactions.recovery(),
        directory.path(),
        &interfaces,
        &committed,
        &wifi_runtime_dirs(),
    )
    .await
    .unwrap();
    assert_eq!(addresses(&provider).await, before);
}

#[tokio::test]
async fn committed_invalid_interface_schema_is_retired_without_rollback() {
    let recovery = crate::core::recovery::RecoveryState::default();
    let directory = tempdir().unwrap();
    let provider = fake_network();
    let interfaces = InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory());
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
    let journal_dir = directory.path().join("interface-transactions");
    tokio::fs::create_dir_all(&journal_dir).await.unwrap();
    let journal = journal_dir.join("test0.json");
    tokio::fs::write(
        &journal,
        br#"{"version":999,"token":"confirmed","future_field":true}"#,
    )
    .await
    .unwrap();
    let mut committed = crate::state::overrides::RuntimeOverrides::default();
    committed
        .committed_interface_transactions
        .insert("test0".into(), "confirmed".into());

    recover_interface_transactions(
        &recovery,
        directory.path(),
        &interfaces,
        &committed,
        &wifi_runtime_dirs(),
    )
    .await
    .unwrap();

    assert_eq!(addresses(&provider).await, before);
    assert!(!journal.exists());
    assert!(recovery
        .check_scope(directory.path(), Some("test0"))
        .is_ok());
}

#[tokio::test]
async fn direct_commit_persists_the_configuration_and_recovery_token() {
    let directory = tempdir().unwrap();
    let desired = desired_state(directory.path()).await;
    let manager = NetworkTransactionManager::new_detached(
        InterfaceManager::new(fake_network(), AddressOwnershipJournal::in_memory()),
        Duration::from_secs(60),
        desired.clone(),
    );
    let pending = manager
        .apply(
            "test0",
            InterfaceChange {
                config: &interface_config(PROPOSED),
                previous: None,
                current_role: None,
                allow_management_change: false,
                passphrase: WifiPassphraseUpdate::Keep,
            },
        )
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
    let manager = NetworkTransactionManager::new_detached(
        InterfaceManager::new(fake_network(), AddressOwnershipJournal::in_memory()),
        Duration::from_secs(60),
        desired.clone(),
    );
    let gate = Arc::new(NetworkMutationGate::default());
    manager.set_runtime_gate(gate.clone());
    let pending = manager
        .apply(
            "test0",
            InterfaceChange {
                config: &interface_config(PROPOSED),
                previous: None,
                current_role: None,
                allow_management_change: false,
                passphrase: WifiPassphraseUpdate::Keep,
            },
        )
        .await
        .unwrap();
    let pass = desired.runtime_locks.lock("test0").await;
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
            InterfaceChange {
                config: &interface_config(PROPOSED),
                previous: None,
                current_role: Some(InterfaceRole::Output),
                allow_management_change: false,
                passphrase: WifiPassphraseUpdate::Keep,
            },
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
    let status = manager.pending().await;
    assert_eq!(status[0].phase, NetworkChangePhase::AwaitingCommit);
    assert!(status[0]
        .last_error
        .as_deref()
        .unwrap()
        .contains("persistence failed"));
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

#[tokio::test(start_paused = true)]
async fn admission_does_not_extend_confirmation_deadline() {
    let directory = tempdir().unwrap();
    let desired = desired_state(directory.path()).await;
    let manager = NetworkTransactionManager::new_detached(
        InterfaceManager::new(fake_network(), AddressOwnershipJournal::in_memory()),
        Duration::from_millis(20),
        desired.clone(),
    );
    let gate = Arc::new(NetworkMutationGate::default());
    manager.set_runtime_gate(gate.clone());
    let pending = manager
        .apply(
            "test0",
            InterfaceChange {
                config: &interface_config(PROPOSED),
                previous: None,
                current_role: None,
                allow_management_change: false,
                passphrase: WifiPassphraseUpdate::Keep,
            },
        )
        .await
        .unwrap();

    // Admission is not commit ownership. Only a commit that actually started
    // under operation_lock before the deadline may finish after it.
    let admission = gate.admit().await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(100)).await;
    assert!(manager.commit(&pending.token).await.is_err());
    drop(admission);
    assert_eq!(
        desired.committed_interface("test0").await.unwrap(),
        Some(interface_config(COMMITTED))
    );
}

#[tokio::test]
async fn replaced_timer_cannot_rollback_after_waiting_for_operation_lock() {
    let directory = tempdir().unwrap();
    let desired = desired_state(directory.path()).await;
    let manager = NetworkTransactionManager::new_detached(
        InterfaceManager::new(fake_network(), AddressOwnershipJournal::in_memory()),
        Duration::from_secs(3600),
        desired.clone(),
    );
    let pending = manager
        .apply(
            "test0",
            InterfaceChange {
                config: &interface_config(PROPOSED),
                previous: None,
                current_role: None,
                allow_management_change: false,
                passphrase: WifiPassphraseUpdate::Keep,
            },
        )
        .await
        .unwrap();
    let epoch = manager.inner.timer_epochs.lock().unwrap()[&pending.token];
    let operation = desired.transaction_locks.lock("test0").await;
    let rollback = manager.rollback_for_epoch(&pending.token, epoch);
    tokio::pin!(rollback);
    // Poll the timer until it is queued behind a manual operation.
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut rollback)
            .await
            .is_err()
    );
    manager
        .inner
        .timer_epochs
        .lock()
        .unwrap()
        .insert(pending.token.clone(), epoch + 1);
    drop(operation);

    assert!(rollback.await.unwrap().is_none());
    assert!(desired.is_tentative("test0").await);
    assert_eq!(manager.pending().await, vec![pending.clone()]);
    manager.rollback(&pending.token).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn uncommitted_change_is_automatically_rolled_back() {
    let directory = tempdir().expect("tempdir");
    let provider = fake_network();
    let desired = desired_state(directory.path()).await;
    let converger = spawn_converger(desired.clone(), provider.clone());
    let manager = NetworkTransactionManager::new_detached(
        InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory()),
        Duration::from_millis(20),
        desired,
    );

    manager
        .apply(
            "test0",
            InterfaceChange {
                config: &interface_config(PROPOSED),
                previous: None,
                current_role: Some(InterfaceRole::Output),
                allow_management_change: false,
                passphrase: WifiPassphraseUpdate::Keep,
            },
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

    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(200)).await;
    tokio::time::resume();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !manager.pending().await.is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("automatic rollback must finish");

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
    let manager = NetworkTransactionManager::new_detached(
        InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory()),
        Duration::from_secs(60),
        desired.clone(),
    );

    manager
        .apply(
            "test0",
            InterfaceChange {
                config: &interface_config(PROPOSED),
                previous: None,
                current_role: Some(InterfaceRole::Output),
                allow_management_change: false,
                passphrase: WifiPassphraseUpdate::Keep,
            },
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
    async fn wait_for_version<T>(
        desired: &DesiredNetworkState,
        version: u64,
        task: &tokio::task::JoinHandle<T>,
    ) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while desired.version() < version {
                assert!(
                    !task.is_finished(),
                    "operation ended before publishing desired-state version {version}"
                );
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("operation must publish the expected desired-state version");
    }

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
                InterfaceChange {
                    config: &interface_config(PROPOSED),
                    previous: None,
                    current_role: Some(InterfaceRole::Output),
                    allow_management_change: false,
                    passphrase: WifiPassphraseUpdate::Keep,
                },
            )
            .await
    });

    wait_for_version(&desired, 1, &apply).await;
    desired.report_result(1, Err(anyhow::anyhow!("candidate failed")));
    wait_for_version(&desired, 2, &apply).await;
    desired.report_result(2, Err(anyhow::anyhow!("rollback failed")));

    let error = tokio::time::timeout(Duration::from_secs(5), apply)
        .await
        .expect("failed apply and compensation must finish")
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
    wait_for_version(&desired, 3, &rollback).await;
    desired.report_pass(3, BTreeMap::new());
    tokio::time::timeout(Duration::from_secs(5), rollback)
        .await
        .expect("rollback retry must finish")
        .expect("rollback task")
        .expect("retry rollback");
    assert!(manager.pending().await.is_empty());
}

#[tokio::test]
async fn clear_passphrase_is_journaled_and_restored_on_rollback() {
    let directory = tempdir().expect("tempdir");
    let desired = desired_state(directory.path()).await;
    let manager = NetworkTransactionManager::new_detached(
        InterfaceManager::new(fake_network(), AddressOwnershipJournal::in_memory()),
        Duration::from_secs(60),
        desired,
    );
    let store = PassphraseStore::new(directory.path().join("wifi/psk-ap"));
    store
        .set(
            "test0",
            &WifiPassphrase::new("original-password").expect("passphrase"),
        )
        .expect("seed passphrase");

    let previous = interface_config(COMMITTED);
    let proposed = credential_config(WifiCredentialRole::Ap);
    let pending = manager
        .apply(
            "test0",
            InterfaceChange {
                config: &proposed,
                previous: Some(&previous),
                current_role: Some(InterfaceRole::Output),
                allow_management_change: false,
                passphrase: WifiPassphraseUpdate::Clear,
            },
        )
        .await
        .expect("apply clear");
    assert!(store.get("test0").expect("read cleared secret").is_none());

    manager
        .rollback(&pending.token)
        .await
        .expect("rollback clear");
    assert_eq!(
        store
            .get("test0")
            .expect("read restored secret")
            .expect("secret restored")
            .expose(),
        "original-password"
    );
}

#[tokio::test]
async fn clearing_a_removed_wifi_role_uses_the_previous_role_store_and_rolls_back() {
    let directory = tempdir().expect("tempdir");
    let previous = credential_config(WifiCredentialRole::Ap);
    let mut base = AppConfig::default();
    base.runtime.state_dir = directory.path().to_path_buf();
    base.network
        .interfaces
        .insert("test0".to_string(), previous.clone());
    let overrides = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .expect("overrides");
    let desired = DesiredNetworkState::new(base, overrides);
    let manager = NetworkTransactionManager::new_detached(
        InterfaceManager::new(fake_network(), AddressOwnershipJournal::in_memory()),
        Duration::from_secs(60),
        desired,
    );
    let store = PassphraseStore::new(directory.path().join("wifi/psk-ap"));
    store
        .set(
            "test0",
            &WifiPassphrase::new("original-password").expect("passphrase"),
        )
        .expect("seed passphrase");

    let mut target = previous.clone();
    target.wifi = None;
    let pending = manager
        .apply(
            "test0",
            InterfaceChange {
                config: &target,
                previous: Some(&previous),
                current_role: Some(InterfaceRole::Output),
                allow_management_change: true,
                passphrase: WifiPassphraseUpdate::Clear,
            },
        )
        .await
        .expect("apply AP removal");
    assert!(store.get("test0").expect("read cleared secret").is_none());

    manager
        .rollback(&pending.token)
        .await
        .expect("rollback AP removal");
    assert_eq!(
        store
            .get("test0")
            .expect("read restored secret")
            .expect("secret restored")
            .expose(),
        "original-password"
    );
}

#[tokio::test]
async fn rollback_publishes_restore_intent_even_when_secret_restore_fails() {
    let directory = tempdir().expect("tempdir");
    let desired = desired_state(directory.path()).await;
    let manager = NetworkTransactionManager::new_detached(
        InterfaceManager::new(fake_network(), AddressOwnershipJournal::in_memory()),
        Duration::from_secs(60),
        desired.clone(),
    );
    let proposed = credential_config(WifiCredentialRole::Ap);
    let pending = manager
        .apply(
            "test0",
            InterfaceChange {
                config: &proposed,
                previous: None,
                current_role: Some(InterfaceRole::Output),
                allow_management_change: false,
                passphrase: WifiPassphraseUpdate::Set(
                    WifiPassphrase::new("new-password").expect("passphrase"),
                ),
            },
        )
        .await
        .expect("apply");
    assert!(desired.is_tentative("test0").await);

    let psk_dir = directory.path().join("wifi/psk-ap");
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
    let status = manager.pending().await;
    assert_eq!(status[0].token, pending.token);
    assert_eq!(status[0].phase, NetworkChangePhase::RecoveryRequired);
    assert!(status[0].last_error.is_some());
    assert!(!status[0].can_commit());
    assert!(status[0].can_rollback());
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
    let manager = NetworkTransactionManager::new_detached(
        InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory()),
        Duration::from_secs(60),
        desired.clone(),
    );

    let error = manager
        .apply(
            "test0",
            InterfaceChange {
                config: &interface_config(PROPOSED),
                previous: None,
                current_role: Some(InterfaceRole::None),
                allow_management_change: false,
                passphrase: WifiPassphraseUpdate::Keep,
            },
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
    let transactions = NetworkTransactionManager::new_detached(
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
    recover_interface_transactions(
        transactions.recovery(),
        directory.path(),
        &interfaces,
        &Default::default(),
        &wifi_runtime_dirs(),
    )
    .await
    .unwrap();
    assert!(transactions
        .recovery()
        .check_scope(directory.path(), Some("bad0"))
        .is_err());
    assert!(transactions
        .recovery()
        .check_scope(directory.path(), Some("test0"))
        .is_ok());
    assert!(!directory
        .path()
        .join("interface-transactions/test0.json")
        .exists());
    assert!(directory
        .path()
        .join("interface-transactions/bad0.json")
        .exists());
    recover_interface_transactions(
        transactions.recovery(),
        directory.path(),
        &interfaces,
        &Default::default(),
        &wifi_runtime_dirs(),
    )
    .await
    .unwrap();
}

#[test]
fn interface_recovery_store_retries_only_explicitly_transient_io_errors() {
    use crate::state::private_store::PrivateStoreError;
    use std::io::{Error, ErrorKind};

    for kind in [
        ErrorKind::Interrupted,
        ErrorKind::WouldBlock,
        ErrorKind::TimedOut,
    ] {
        assert!(retryable_interface_store_error(&PrivateStoreError::Io(
            Error::new(kind, "retry")
        )));
    }
    for kind in [
        ErrorKind::NotFound,
        ErrorKind::PermissionDenied,
        ErrorKind::NotADirectory,
        ErrorKind::InvalidInput,
        ErrorKind::InvalidData,
        ErrorKind::Other,
    ] {
        assert!(!retryable_interface_store_error(&PrivateStoreError::Io(
            Error::new(kind, "operator action")
        )));
    }
    assert!(!retryable_interface_store_error(
        &PrivateStoreError::Symlink(std::path::PathBuf::from("interface-transactions"))
    ));
}

#[test]
fn interface_recovery_store_error_uses_resource_path_not_journal() {
    let state_dir = std::path::Path::new("/state");
    let error = interface_recovery_store_error(
        state_dir,
        "open",
        crate::state::private_store::PrivateStoreError::Symlink(
            state_dir.join("interface-transactions"),
        ),
    );
    let diagnostic = error.to_string();
    assert!(diagnostic.contains("recovery_code=TM-REC-101"));
    assert!(diagnostic.contains("invariant=accessible_interface_recovery_store"));
    assert!(diagnostic.contains("path=/state/interface-transactions"));
    assert!(diagnostic.contains("expected_type=directory"));
    assert!(diagnostic.contains("expected_mode=0700"));
    assert!(diagnostic.contains("symlink_allowed=false"));
    assert!(diagnostic.contains("operator_action=repair_storage_access"));
    assert!(!diagnostic.contains("journal="));
}

#[tokio::test]
async fn rejected_wifi_candidate_restores_credentials_and_both_ip_policy_transitions() {
    for was_dhcp in [true, false] {
        let directory = tempdir().unwrap();
        let mut previous = interface_config(COMMITTED);
        previous.role = InterfaceRole::Input;
        previous.dhcp = None;
        previous.ipv4 = (!was_dhcp).then(|| COMMITTED.parse().unwrap());
        previous.dhcp_client = Some(crate::config::DhcpClientInterfaceConfig {
            enabled: was_dhcp,
            route_metric: 777,
            install_default_route: false,
            request_dns: false,
            ..Default::default()
        });
        previous.wifi_client = Some(crate::config::WifiClientConfig {
            ssid: "original".into(),
            country_code: None,
            security: crate::config::WifiClientSecurity::Wpa2,
            passphrase_file: None,
        });
        let mut base = AppConfig::default();
        base.network
            .interfaces
            .insert("test0".into(), previous.clone());
        let overrides = RuntimeOverrideManager::load(directory.path(), &base)
            .await
            .unwrap();
        let desired = DesiredNetworkState::new(base, overrides.clone());
        desired.attach_converger();
        let manager = NetworkTransactionManager::new(
            InterfaceManager::new(fake_network(), AddressOwnershipJournal::in_memory()),
            Duration::from_secs(60),
            desired.clone(),
        );
        let store = PassphraseStore::new(directory.path().join("wifi/psk-client"));
        store
            .set("test0", &WifiPassphrase::new("original-password").unwrap())
            .unwrap();
        let mut candidate = previous.clone();
        candidate.ipv4 = was_dhcp.then(|| PROPOSED.parse().unwrap());
        candidate.dhcp_client.as_mut().unwrap().enabled = !was_dhcp;
        candidate.wifi_client.as_mut().unwrap().ssid = "wrong-credentials".into();
        let apply_manager = manager.clone();
        let old = previous.clone();
        let apply = tokio::spawn(async move {
            apply_manager
                .apply(
                    "test0",
                    InterfaceChange {
                        config: &candidate,
                        previous: Some(&old),
                        current_role: Some(InterfaceRole::Input),
                        allow_management_change: true,
                        passphrase: WifiPassphraseUpdate::Set(
                            WifiPassphrase::new("wrong-password").unwrap(),
                        ),
                    },
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while desired.version() < 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        desired.report_result(1, Err(anyhow::anyhow!("Wi-Fi authentication failed")));
        tokio::time::timeout(Duration::from_secs(2), async {
            while desired.version() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        desired.report_pass(2, BTreeMap::new());
        assert!(apply.await.unwrap().is_err());
        assert_eq!(
            desired.effective().await.unwrap().network.interfaces["test0"],
            previous
        );
        assert_eq!(
            overrides
                .effective_interface("test0")
                .await
                .unwrap()
                .unwrap(),
            previous
        );
        assert_eq!(
            store.get("test0").unwrap().unwrap().expose(),
            "original-password"
        );
        assert!(manager.pending().await.is_empty());
    }
}

#[tokio::test]
async fn automatic_rollback_retries_after_converger_recovers() {
    let directory = tempdir().unwrap();
    let desired = desired_state(directory.path()).await;
    let manager = NetworkTransactionManager::new_detached(
        InterfaceManager::new(fake_network(), AddressOwnershipJournal::in_memory()),
        Duration::from_millis(20),
        desired.clone(),
    );
    let gate = Arc::new(NetworkMutationGate::default());
    manager.set_runtime_gate(gate.clone());
    let pending = manager
        .apply(
            "test0",
            InterfaceChange {
                config: &interface_config(PROPOSED),
                previous: None,
                current_role: None,
                allow_management_change: false,
                passphrase: WifiPassphraseUpdate::Keep,
            },
        )
        .await
        .unwrap();
    desired.fail_converger("temporary failure");
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if manager.inner.pending.lock().await[&pending.token]
                .info
                .phase
                == NetworkChangePhase::RollbackRequired
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // A failed attempt must retain recovery proof but release admission.
    let admission = tokio::time::timeout(Duration::from_millis(500), gate.admit())
        .await
        .unwrap();
    assert!(directory
        .path()
        .join("interface-transactions/test0.json")
        .exists());
    assert!(manager.commit(&pending.token).await.is_err());
    let converger = spawn_converger(desired.clone(), fake_network());
    drop(admission);
    tokio::time::timeout(Duration::from_secs(3), async {
        while !manager.pending().await.is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("automatic retry must finish recovery");
    assert!(!desired.is_tentative("test0").await);
    assert!(!directory
        .path()
        .join("interface-transactions/test0.json")
        .exists());
    converger.abort();
}

#[tokio::test]
async fn indeterminate_commit_blocks_manual_timer_and_shutdown_rollback() {
    let directory = tempdir().unwrap();
    let store = crate::state::overrides::RuntimeOverrideStore::in_state_dir(directory.path());
    store.save(&Default::default()).await.unwrap();
    let desired = desired_state(directory.path()).await;
    let provider = fake_network();
    let converger = spawn_converger(desired.clone(), provider.clone());
    let manager = NetworkTransactionManager::new(
        InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory()),
        Duration::from_secs(60),
        desired.clone(),
    );
    let pending = manager
        .apply(
            "test0",
            InterfaceChange {
                config: &interface_config(PROPOSED),
                previous: None,
                current_role: None,
                allow_management_change: false,
                passphrase: WifiPassphraseUpdate::Keep,
            },
        )
        .await
        .unwrap();
    let applied = addresses(&provider).await;
    crate::atomic_file::fail_replacement_and_compensation(store.path());
    let error = manager.commit(&pending.token).await.unwrap_err();
    assert!(crate::atomic_file::is_indeterminate_write(&error));
    assert_eq!(
        store
            .load()
            .await
            .unwrap()
            .committed_interface_transactions
            .get("test0"),
        Some(&pending.token)
    );
    assert!(!desired
        .committed_overrides()
        .await
        .committed_interface_transactions
        .contains_key("test0"));
    assert!(manager.commit(&pending.token).await.is_err());
    assert!(manager.rollback(&pending.token).await.is_err());
    assert!(manager.restore_baselines().await.is_err());
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::task::yield_now().await;
    let status = manager.pending().await;
    assert_eq!(status[0].phase, NetworkChangePhase::CommitIndeterminate);
    assert!(status[0].last_error.is_some());
    assert!(!status[0].can_commit());
    assert!(!status[0].can_rollback());
    assert_eq!(addresses(&provider).await, applied);
    assert!(directory
        .path()
        .join("interface-transactions/test0.json")
        .exists());
    assert!(manager
        .recovery()
        .check_scope(directory.path(), Some("other0"))
        .is_err());
    converger.abort();
}

#[test]
fn old_pending_response_defaults_to_awaiting_confirmation() {
    let info: PendingNetworkChange = serde_json::from_str(
        r#"{
        "token":"old", "interface":"test0", "rollback_timeout_seconds":60,
        "expires_at_unix":123
    }"#,
    )
    .unwrap();
    assert!(info.can_commit());
    assert!(info.can_rollback());
    assert_eq!(info.last_error, None);
}

fn credential_config(role: WifiCredentialRole) -> InterfaceConfig {
    let mut config = interface_config(PROPOSED);
    match role {
        WifiCredentialRole::Ap => {
            config.wifi = Some(
                serde_json::from_value(serde_json::json!({
                    "ssid": "test-ap", "channel": 6, "security": "wpa2"
                }))
                .unwrap(),
            );
        }
        WifiCredentialRole::Client => {
            config.role = InterfaceRole::Input;
            config.wifi_client = Some(
                serde_json::from_value(serde_json::json!({
                    "ssid": "test-sta", "security": "wpa2"
                }))
                .unwrap(),
            );
        }
    }
    config
}

#[tokio::test]
async fn keep_cannot_reuse_credentials_across_wifi_roles_in_either_direction() {
    for (old_role, new_role) in [
        (WifiCredentialRole::Client, WifiCredentialRole::Ap),
        (WifiCredentialRole::Ap, WifiCredentialRole::Client),
    ] {
        let directory = tempdir().unwrap();
        let previous = credential_config(old_role);
        let candidate = credential_config(new_role);
        let mut base = AppConfig::default();
        base.network
            .interfaces
            .insert("test0".into(), previous.clone());
        let overrides = RuntimeOverrideManager::load(directory.path(), &base)
            .await
            .unwrap();
        let desired = DesiredNetworkState::new(base, overrides);
        let manager = NetworkTransactionManager::new_detached(
            InterfaceManager::new(fake_network(), AddressOwnershipJournal::in_memory()),
            Duration::from_secs(60),
            desired.clone(),
        );
        let old = PassphraseStore::for_role(directory.path(), old_role);
        let target = PassphraseStore::for_role(directory.path(), new_role);
        old.set("test0", &WifiPassphrase::new("source-password").unwrap())
            .unwrap();
        // Even a stale credential from an earlier use of the target role is
        // not authorization to reuse it on this transition.
        target
            .set(
                "test0",
                &WifiPassphrase::new("stale-target-password").unwrap(),
            )
            .unwrap();
        let error = manager
            .apply(
                "test0",
                InterfaceChange {
                    config: &candidate,
                    previous: Some(&previous),
                    current_role: Some(previous.role),
                    allow_management_change: true,
                    passphrase: WifiPassphraseUpdate::Keep,
                },
            )
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("explicit passphrase"),
            "{error:#}"
        );
        assert_eq!(desired.version(), 0);
        assert!(manager.pending().await.is_empty());
        assert_eq!(
            old.get("test0").unwrap().unwrap().expose(),
            "source-password"
        );
        assert_eq!(
            target.get("test0").unwrap().unwrap().expose(),
            "stale-target-password"
        );
    }
}

#[tokio::test]
async fn role_switch_rollback_and_crash_recovery_restore_only_the_target_namespace() {
    for (old_role, new_role) in [
        (WifiCredentialRole::Client, WifiCredentialRole::Ap),
        (WifiCredentialRole::Ap, WifiCredentialRole::Client),
    ] {
        for crash in [false, true] {
            let directory = tempdir().unwrap();
            let previous = credential_config(old_role);
            let candidate = credential_config(new_role);
            let mut base = AppConfig::default();
            base.network
                .interfaces
                .insert("test0".into(), previous.clone());
            let overrides = RuntimeOverrideManager::load(directory.path(), &base)
                .await
                .unwrap();
            let desired = DesiredNetworkState::new(base, overrides);
            let interfaces =
                InterfaceManager::new(fake_network(), AddressOwnershipJournal::in_memory());
            let manager = NetworkTransactionManager::new_detached(
                interfaces.clone(),
                Duration::from_secs(60),
                desired,
            );
            let source = PassphraseStore::for_role(directory.path(), old_role);
            let target = PassphraseStore::for_role(directory.path(), new_role);
            source
                .set("test0", &WifiPassphrase::new("source-password").unwrap())
                .unwrap();
            target
                .set(
                    "test0",
                    &WifiPassphrase::new("previous-target-password").unwrap(),
                )
                .unwrap();
            let pending = manager
                .apply(
                    "test0",
                    InterfaceChange {
                        config: &candidate,
                        previous: Some(&previous),
                        current_role: Some(previous.role),
                        allow_management_change: true,
                        passphrase: WifiPassphraseUpdate::Set(
                            WifiPassphrase::new("new-target-password").unwrap(),
                        ),
                    },
                )
                .await
                .unwrap();
            assert_eq!(
                target.get("test0").unwrap().unwrap().expose(),
                "new-target-password"
            );
            if crash {
                recover_interface_transactions(
                    manager.recovery(),
                    directory.path(),
                    &interfaces,
                    &Default::default(),
                    &wifi_runtime_dirs(),
                )
                .await
                .unwrap();
            } else {
                manager.rollback(&pending.token).await.unwrap();
            }
            assert_eq!(
                source.get("test0").unwrap().unwrap().expose(),
                "source-password"
            );
            assert_eq!(
                target.get("test0").unwrap().unwrap().expose(),
                "previous-target-password"
            );
            assert!(!directory
                .path()
                .join("interface-transactions/test0.json")
                .exists());
        }
    }
}

#[tokio::test]
async fn explicit_file_on_role_switch_cannot_be_shadowed_by_stale_target_secret() {
    let directory = tempdir().unwrap();
    let previous = credential_config(WifiCredentialRole::Client);
    let mut candidate = credential_config(WifiCredentialRole::Ap);
    candidate.wifi.as_mut().unwrap().passphrase_file =
        Some(directory.path().join("explicit-secret"));
    let mut base = AppConfig::default();
    base.network
        .interfaces
        .insert("test0".into(), previous.clone());
    let overrides = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    let desired = DesiredNetworkState::new(base, overrides);
    let manager = NetworkTransactionManager::new_detached(
        InterfaceManager::new(fake_network(), AddressOwnershipJournal::in_memory()),
        Duration::from_secs(60),
        desired,
    );
    let target = PassphraseStore::for_role(directory.path(), WifiCredentialRole::Ap);
    target
        .set("test0", &WifiPassphrase::new("stale-password").unwrap())
        .unwrap();
    let pending = manager
        .apply(
            "test0",
            InterfaceChange {
                config: &candidate,
                previous: Some(&previous),
                current_role: Some(previous.role),
                allow_management_change: true,
                passphrase: WifiPassphraseUpdate::Keep,
            },
        )
        .await
        .unwrap();
    assert!(target.get("test0").unwrap().is_none());
    manager.rollback(&pending.token).await.unwrap();
    assert_eq!(
        target.get("test0").unwrap().unwrap().expose(),
        "stale-password"
    );
}

#[tokio::test]
async fn stopped_interface_recovery_is_rechecked_and_completed_on_restart() {
    let directory = tempdir().unwrap();
    let desired = desired_state(directory.path()).await;
    let provider = fake_network();
    let interfaces = InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory());
    let manager = NetworkTransactionManager::new_detached(
        interfaces.clone(),
        Duration::from_secs(3600),
        desired.clone(),
    );
    let snapshot = interfaces.snapshot("test0").await.unwrap();
    manager
        .write_journal("stopped-token", snapshot)
        .await
        .unwrap();
    let path = manager.journal_path("test0");
    manager
        .recovery()
        .run::<(), _>(&path, false, async {
            Err(recovery_control::failure(
                recovery_control::FailureKind::Conflict,
                "external change",
            ))
        })
        .await
        .unwrap_err();
    manager.recovery().forget(&path);
    recover_interface_transactions(
        manager.recovery(),
        directory.path(),
        &interfaces,
        &crate::state::overrides::RuntimeOverrides::default(),
        &wifi_runtime_dirs(),
    )
    .await
    .unwrap();
    assert!(!manager.recovery().stopped(&path));
    let restarted =
        NetworkTransactionManager::new_detached(interfaces, Duration::from_secs(3600), desired);
    assert!(!path.exists());
    assert!(restarted.pending().await.is_empty());
    assert!(manager
        .recovery()
        .check_scope(directory.path(), Some("test0"))
        .is_ok());
}
