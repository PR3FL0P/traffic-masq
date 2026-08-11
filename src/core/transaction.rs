use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::config::{InterfaceConfig, InterfaceRole};
use crate::core::interface::{
    DhcpChangeAction, InterfaceChangePlan, InterfaceManager, InterfaceSnapshot,
};
use crate::dhcp::supervisor::{DhcpServiceSpec, DhcpSupervisor};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingNetworkChange {
    pub token: String,
    pub interface: String,
    pub rollback_timeout_seconds: u64,
    pub expires_at_unix: u64,
}

#[derive(Clone)]
pub struct NetworkTransactionManager {
    inner: Arc<Inner>,
}

struct Inner {
    interface_manager: InterfaceManager,
    rollback_timeout: Duration,
    pending: Mutex<HashMap<String, PendingTransaction>>,
    baselines: Mutex<HashMap<String, InterfaceSnapshot>>,
    operation_lock: Mutex<()>,
    token_counter: AtomicU64,
    dhcp: Option<DhcpSupervisor>,
    default_lease_seconds: u32,
}

#[derive(Debug, Clone)]
struct PendingTransaction {
    info: PendingNetworkChange,
    snapshot: InterfaceSnapshot,
    target: InterfaceConfig,
    allow_management_change: bool,
    previous_dhcp: Option<DhcpServiceSpec>,
}

impl NetworkTransactionManager {
    pub fn new(interface_manager: InterfaceManager, rollback_timeout: Duration) -> Self {
        Self::new_with_baselines(interface_manager, rollback_timeout, Vec::new())
    }

    pub fn new_with_baselines(
        interface_manager: InterfaceManager,
        rollback_timeout: Duration,
        baselines: Vec<InterfaceSnapshot>,
    ) -> Self {
        Self::build(interface_manager, rollback_timeout, baselines, None, 1)
    }

    pub fn new_with_services(
        interface_manager: InterfaceManager,
        rollback_timeout: Duration,
        baselines: Vec<InterfaceSnapshot>,
        dhcp: DhcpSupervisor,
        default_lease_seconds: u32,
    ) -> Self {
        Self::build(
            interface_manager,
            rollback_timeout,
            baselines,
            Some(dhcp),
            default_lease_seconds,
        )
    }

    fn build(
        interface_manager: InterfaceManager,
        rollback_timeout: Duration,
        baselines: Vec<InterfaceSnapshot>,
        dhcp: Option<DhcpSupervisor>,
        default_lease_seconds: u32,
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
                token_counter: AtomicU64::new(0),
                dhcp,
                default_lease_seconds,
            }),
        }
    }

    pub async fn dry_run(
        &self,
        interface: &str,
        config: &InterfaceConfig,
        current_role: Option<InterfaceRole>,
        allow_management_change: bool,
    ) -> Result<InterfaceChangePlan> {
        let mut plan = self
            .inner
            .interface_manager
            .plan_interface(interface, config, current_role, allow_management_change)
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
        let _operation = self.inner.operation_lock.lock().await;

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

        let target_dhcp = DhcpServiceSpec::from_interface_config(
            interface,
            config,
            self.inner.default_lease_seconds,
        )?;
        let snapshot = self.inner.interface_manager.snapshot(interface).await?;
        let previous_dhcp = match &self.inner.dhcp {
            Some(dhcp) => dhcp.spec(interface).await,
            None => None,
        };

        if let Some(dhcp) = &self.inner.dhcp {
            dhcp.disable(interface).await?;
        }
        if let Err(error) = self
            .inner
            .interface_manager
            .apply_interface(interface, config, current_role, allow_management_change)
            .await
        {
            self.restore_dhcp(previous_dhcp.clone()).await?;
            return Err(error);
        }
        if target_dhcp.is_some() {
            if let Err(error) = self
                .inner
                .interface_manager
                .verify_configured_ipv4(interface, config)
                .await
            {
                self.rollback_applied_service(&snapshot, previous_dhcp.clone())
                    .await?;
                return Err(error);
            }
        }
        if let (Some(dhcp), Some(spec)) = (&self.inner.dhcp, target_dhcp) {
            if let Err(error) = dhcp.configure(spec).await {
                self.rollback_applied_service(&snapshot, previous_dhcp.clone())
                    .await?;
                return Err(error);
            }
        }
        self.inner
            .baselines
            .lock()
            .await
            .entry(interface.to_string())
            .or_insert_with(|| snapshot.clone());

        let rollback_timeout_seconds = self.inner.rollback_timeout.as_secs();
        let info = PendingNetworkChange {
            token: self.next_token(),
            interface: interface.to_string(),
            rollback_timeout_seconds,
            expires_at_unix: current_unix_time().saturating_add(rollback_timeout_seconds),
        };
        self.inner.pending.lock().await.insert(
            info.token.clone(),
            PendingTransaction {
                info: info.clone(),
                snapshot,
                target: config.clone(),
                allow_management_change,
                previous_dhcp,
            },
        );

        self.spawn_rollback_timer(info.token.clone());
        Ok(info)
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
            (
                pending.info.interface.clone(),
                pending.target.clone(),
                pending.allow_management_change,
            )
        };

        persist(interface, target, allow_management_change).await?;

        let pending = self
            .inner
            .pending
            .lock()
            .await
            .remove(token)
            .expect("pending transaction cannot change while operation lock is held");
        Ok(pending.info)
    }

    pub async fn rollback(&self, token: &str) -> Result<PendingNetworkChange> {
        let _operation = self.inner.operation_lock.lock().await;
        let pending = self
            .inner
            .pending
            .lock()
            .await
            .get(token)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("pending network change not found: {token}"))?;
        self.rollback_applied_service(&pending.snapshot, pending.previous_dhcp.clone())
            .await?;
        self.inner.pending.lock().await.remove(token);
        Ok(pending.info)
    }

    pub async fn rollback_all_pending(&self) -> Result<()> {
        let _operation = self.inner.operation_lock.lock().await;
        let pending: Vec<_> = self.inner.pending.lock().await.values().cloned().collect();
        let mut errors = Vec::new();

        for transaction in pending {
            match self
                .rollback_applied_service(&transaction.snapshot, transaction.previous_dhcp.clone())
                .await
            {
                Ok(()) => {
                    self.inner
                        .pending
                        .lock()
                        .await
                        .remove(&transaction.info.token);
                }
                Err(error) => errors.push(format!("{}: {error}", transaction.info.interface)),
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            bail!(
                "failed to roll back pending network changes: {}",
                errors.join("; ")
            )
        }
    }

    pub async fn restore_baselines(&self) -> Result<()> {
        self.rollback_all_pending().await?;
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
        let mut errors = Vec::new();
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

    async fn rollback_applied_service(
        &self,
        snapshot: &InterfaceSnapshot,
        previous_dhcp: Option<DhcpServiceSpec>,
    ) -> Result<()> {
        if let Some(dhcp) = &self.inner.dhcp {
            dhcp.disable(&snapshot.name).await?;
        }
        self.inner.interface_manager.rollback(snapshot).await?;
        self.restore_dhcp(previous_dhcp).await
    }

    async fn restore_dhcp(&self, previous: Option<DhcpServiceSpec>) -> Result<()> {
        if let (Some(dhcp), Some(spec)) = (&self.inner.dhcp, previous) {
            dhcp.configure(spec).await?;
        }
        Ok(())
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
    use std::net::Ipv4Addr;

    use anyhow::Result;
    use async_trait::async_trait;
    use tokio::sync::Mutex;

    use crate::config::{InterfaceConfig, InterfaceRole};
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
        ) -> Result<()> {
            self.addresses.lock().await.push(Ipv4AddressInfo {
                interface_index: 1,
                address,
                prefix_len,
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

    #[tokio::test]
    async fn failed_commit_persistence_keeps_change_pending_for_rollback() {
        let original = Ipv4AddressInfo {
            interface_index: 1,
            address: Ipv4Addr::new(192, 168, 1, 10),
            prefix_len: 24,
        };
        let provider = Arc::new(FakeNetwork {
            interface: Mutex::new(NetworkInterface {
                is_wireless: false,
                index: 1,
                name: "test0".to_string(),
                is_up: false,
                rx_bytes: 0,
                tx_bytes: 0,
            }),
            addresses: Mutex::new(vec![original.clone()]),
        });
        let manager = NetworkTransactionManager::new(
            InterfaceManager::new(provider.clone()),
            Duration::from_secs(60),
        );
        let config = InterfaceConfig {
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some("192.168.50.1/24".parse().expect("network")),
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        };
        let change = manager
            .apply("test0", &config, Some(InterfaceRole::Output), false)
            .await
            .expect("apply");

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
        assert_eq!(*provider.addresses.lock().await, vec![original]);
    }

    #[tokio::test]
    async fn uncommitted_change_is_automatically_rolled_back() {
        let original = Ipv4AddressInfo {
            interface_index: 1,
            address: Ipv4Addr::new(192, 168, 1, 10),
            prefix_len: 24,
        };
        let provider = Arc::new(FakeNetwork {
            interface: Mutex::new(NetworkInterface {
                is_wireless: false,
                index: 1,
                name: "test0".to_string(),
                is_up: false,
                rx_bytes: 0,
                tx_bytes: 0,
            }),
            addresses: Mutex::new(vec![original.clone()]),
        });
        let manager = NetworkTransactionManager::new(
            InterfaceManager::new(provider.clone()),
            Duration::from_millis(20),
        );
        let config = InterfaceConfig {
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some("192.168.50.1/24".parse().expect("network")),
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        };

        manager
            .apply("test0", &config, Some(InterfaceRole::Output), false)
            .await
            .expect("apply");
        assert_eq!(
            provider.addresses.lock().await[0].address,
            Ipv4Addr::new(192, 168, 50, 1)
        );

        tokio::time::sleep(Duration::from_millis(80)).await;

        assert!(manager.pending().await.is_empty());
        assert_eq!(*provider.addresses.lock().await, vec![original]);
        assert!(!provider.interface.lock().await.is_up);
    }
}
