use std::collections::BTreeSet;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::{InterfaceConfig, InterfaceRole, NetworkConfig};
use crate::netlink::{Ipv4AddressInfo, NetworkProvider};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceSnapshot {
    pub name: String,
    pub was_up: bool,
    pub ipv4_addresses: Vec<Ipv4AddressInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DhcpChangeAction {
    Unchanged,
    Start,
    Reconfigure,
    Stop,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceChangePlan {
    pub interface: String,
    pub delete_ipv4: Vec<Ipv4AddressInfo>,
    pub add_ipv4: Option<Ipv4AddressInfo>,
    pub set_link_up: bool,
    pub management_change: bool,
    pub dhcp_action: DhcpChangeAction,
}

pub fn is_management_change(
    target_role: InterfaceRole,
    current_role: Option<InterfaceRole>,
) -> bool {
    target_role == InterfaceRole::Management || current_role == Some(InterfaceRole::Management)
}

pub fn owns_dynamic_ipv4(config: &InterfaceConfig) -> bool {
    config.managed
        && config.role == InterfaceRole::Input
        && config
            .dhcp_client
            .as_ref()
            .is_some_and(|dhcp_client| dhcp_client.enabled)
}

#[derive(Clone)]
pub struct InterfaceManager {
    provider: Arc<dyn NetworkProvider>,
}

impl InterfaceManager {
    pub fn new(provider: Arc<dyn NetworkProvider>) -> Self {
        Self { provider }
    }

    pub async fn snapshot(&self, name: &str) -> Result<InterfaceSnapshot> {
        let interfaces = self.provider.list_interfaces().await?;
        let interface = interfaces
            .into_iter()
            .find(|interface| interface.name == name)
            .ok_or_else(|| anyhow::anyhow!("interface not found: {name}"))?;
        let ipv4_addresses = self.provider.list_ipv4_addresses(name).await?;

        Ok(InterfaceSnapshot {
            name: name.to_string(),
            was_up: interface.is_up,
            ipv4_addresses,
        })
    }

    pub async fn apply_network(
        &self,
        config: &NetworkConfig,
        allow_management_changes: bool,
    ) -> Result<Vec<InterfaceSnapshot>> {
        self.apply_network_internal(config, allow_management_changes, None)
            .await
    }

    pub async fn apply_network_with_management_allowlist(
        &self,
        config: &NetworkConfig,
        management_allowlist: &BTreeSet<String>,
    ) -> Result<Vec<InterfaceSnapshot>> {
        self.apply_network_internal(config, false, Some(management_allowlist))
            .await
    }

    async fn apply_network_internal(
        &self,
        config: &NetworkConfig,
        allow_all_management_changes: bool,
        management_allowlist: Option<&BTreeSet<String>>,
    ) -> Result<Vec<InterfaceSnapshot>> {
        config.validate()?;
        let mut snapshots = Vec::new();

        let observed = self.provider.list_interfaces().await?;

        for (name, interface) in &config.interfaces {
            if !interface.managed {
                continue;
            }

            if !observed.iter().any(|candidate| &candidate.name == name) {
                tracing::warn!(
                    interface = %name,
                    "managed interface is absent at startup; skipping its configuration — \
                     the runtime reconcile loop will configure it if it reappears"
                );
                continue;
            }

            let allow_management_change = allow_all_management_changes
                || management_allowlist.is_some_and(|allowed| allowed.contains(name));
            let snapshot = self.snapshot(name).await?;

            if let Err(error) = self
                .apply_interface(
                    name,
                    interface,
                    Some(interface.role),
                    allow_management_change,
                )
                .await
            {
                for snapshot in snapshots.iter().rev() {
                    if let Err(rollback_error) = self.rollback(snapshot).await {
                        tracing::error!(
                            interface = %snapshot.name,
                            %rollback_error,
                            "failed to rollback interface after apply error"
                        );
                    }
                }
                return Err(error).with_context(|| format!("failed to apply interface {name}"));
            }
            snapshots.push(snapshot);
        }

        Ok(snapshots)
    }

    pub async fn plan_interface(
        &self,
        name: &str,
        config: &InterfaceConfig,
        current_role: Option<InterfaceRole>,
        allow_management_change: bool,
    ) -> Result<InterfaceChangePlan> {
        config.validate(name)?;

        let management_change = is_management_change(config.role, current_role);
        if management_change && !allow_management_change {
            bail!("refusing to modify management interface {name} without explicit confirmation");
        }

        if !config.managed {
            return Ok(InterfaceChangePlan {
                interface: name.to_string(),
                delete_ipv4: Vec::new(),
                add_ipv4: None,
                set_link_up: false,
                management_change,
                dhcp_action: DhcpChangeAction::Unchanged,
            });
        }

        if owns_dynamic_ipv4(config) {
            return Ok(InterfaceChangePlan {
                interface: name.to_string(),
                delete_ipv4: Vec::new(),
                add_ipv4: None,
                set_link_up: true,
                management_change,
                dhcp_action: DhcpChangeAction::Unchanged,
            });
        }

        let current = self.provider.list_ipv4_addresses(name).await?;
        let desired = config
            .ipv4
            .map(|network| (network.addr(), network.prefix_len()));
        let delete_ipv4 = current
            .iter()
            .filter(|address| desired != Some((address.address, address.prefix_len)))
            .cloned()
            .collect();
        let add_ipv4 = desired.and_then(|(address, prefix_len)| {
            let already_present = current
                .iter()
                .any(|current| current.address == address && current.prefix_len == prefix_len);
            (!already_present).then_some(Ipv4AddressInfo {
                interface_index: current.first().map_or(0, |address| address.interface_index),
                address,
                prefix_len,
            })
        });

        Ok(InterfaceChangePlan {
            interface: name.to_string(),
            delete_ipv4,
            add_ipv4,
            set_link_up: true,
            management_change,
            dhcp_action: DhcpChangeAction::Unchanged,
        })
    }

    pub async fn verify_configured_ipv4(&self, name: &str, config: &InterfaceConfig) -> Result<()> {
        let Some(network) = config.ipv4 else {
            return Ok(());
        };
        let addresses = self.provider.list_ipv4_addresses(name).await?;
        if addresses.iter().any(|address| {
            address.address == network.addr() && address.prefix_len == network.prefix_len()
        }) {
            Ok(())
        } else {
            bail!("configured IPv4 address {network} is not present on interface {name}")
        }
    }

    pub async fn apply_interface(
        &self,
        name: &str,
        config: &InterfaceConfig,
        current_role: Option<InterfaceRole>,
        allow_management_change: bool,
    ) -> Result<()> {
        let snapshot = self.snapshot(name).await?;
        if let Err(error) = self
            .apply_interface_unchecked(name, config, current_role, allow_management_change)
            .await
        {
            return match self.rollback(&snapshot).await {
                Ok(()) => Err(anyhow::anyhow!(
                    "interface apply failed; previous state was restored: {error}"
                )),
                Err(rollback_error) => Err(anyhow::anyhow!(
                    "interface apply failed: {error}; rollback also failed: {rollback_error}"
                )),
            };
        }
        Ok(())
    }

    async fn apply_interface_unchecked(
        &self,
        name: &str,
        config: &InterfaceConfig,
        current_role: Option<InterfaceRole>,
        allow_management_change: bool,
    ) -> Result<()> {
        let plan = self
            .plan_interface(name, config, current_role, allow_management_change)
            .await?;
        self.apply_plan(&plan).await
    }

    pub async fn apply_plan(&self, plan: &InterfaceChangePlan) -> Result<()> {
        for address in &plan.delete_ipv4 {
            self.provider
                .delete_ipv4_address(&plan.interface, address.address, address.prefix_len)
                .await?;
        }

        if let Some(address) = &plan.add_ipv4 {
            self.provider
                .add_ipv4_address(&plan.interface, address.address, address.prefix_len)
                .await?;
        }

        if plan.set_link_up {
            self.provider.set_link_up(&plan.interface).await?;
        }
        Ok(())
    }

    pub async fn rollback(&self, snapshot: &InterfaceSnapshot) -> Result<()> {
        let current = self.provider.list_ipv4_addresses(&snapshot.name).await?;

        for address in &current {
            let existed_before = snapshot.ipv4_addresses.iter().any(|previous| {
                previous.address == address.address && previous.prefix_len == address.prefix_len
            });
            if !existed_before {
                self.provider
                    .delete_ipv4_address(&snapshot.name, address.address, address.prefix_len)
                    .await?;
            }
        }

        for address in &snapshot.ipv4_addresses {
            let still_present = current.iter().any(|current| {
                current.address == address.address && current.prefix_len == address.prefix_len
            });
            if !still_present {
                self.provider
                    .add_ipv4_address(&snapshot.name, address.address, address.prefix_len)
                    .await?;
            }
        }

        if snapshot.was_up {
            self.provider.set_link_up(&snapshot.name).await?;
        } else {
            self.provider.set_link_down(&snapshot.name).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    use async_trait::async_trait;
    use ipnet::Ipv4Net;
    use tokio::sync::Mutex;

    use crate::config::InterfaceConfig;
    use crate::netlink::NetworkInterface;

    use super::*;

    #[derive(Debug, Default)]
    struct FakeNetworkProvider {
        interfaces: Mutex<HashMap<String, NetworkInterface>>,
        addresses: Mutex<HashMap<String, Vec<Ipv4AddressInfo>>>,
    }

    impl FakeNetworkProvider {
        async fn add_interface(&self, name: &str, is_up: bool, addresses: Vec<Ipv4AddressInfo>) {
            self.interfaces.lock().await.insert(
                name.to_string(),
                NetworkInterface {
                    is_wireless: false,
                    index: 1,
                    name: name.to_string(),
                    is_up,
                    rx_bytes: 0,
                    tx_bytes: 0,
                },
            );
            self.addresses
                .lock()
                .await
                .insert(name.to_string(), addresses);
        }
    }

    #[async_trait]
    impl NetworkProvider for FakeNetworkProvider {
        async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
            Ok(self.interfaces.lock().await.values().cloned().collect())
        }

        async fn list_ipv4_addresses(&self, interface: &str) -> Result<Vec<Ipv4AddressInfo>> {
            Ok(self
                .addresses
                .lock()
                .await
                .get(interface)
                .cloned()
                .unwrap_or_default())
        }

        async fn set_link_up(&self, name: &str) -> Result<()> {
            self.interfaces
                .lock()
                .await
                .get_mut(name)
                .expect("interface")
                .is_up = true;
            Ok(())
        }

        async fn set_link_down(&self, name: &str) -> Result<()> {
            self.interfaces
                .lock()
                .await
                .get_mut(name)
                .expect("interface")
                .is_up = false;
            Ok(())
        }

        async fn add_ipv4_address(
            &self,
            interface: &str,
            address: Ipv4Addr,
            prefix_len: u8,
        ) -> Result<()> {
            self.addresses
                .lock()
                .await
                .entry(interface.to_string())
                .or_default()
                .push(Ipv4AddressInfo {
                    interface_index: 1,
                    address,
                    prefix_len,
                });
            Ok(())
        }

        async fn delete_ipv4_address(
            &self,
            interface: &str,
            address: Ipv4Addr,
            prefix_len: u8,
        ) -> Result<()> {
            self.addresses
                .lock()
                .await
                .entry(interface.to_string())
                .or_default()
                .retain(|current| current.address != address || current.prefix_len != prefix_len);
            Ok(())
        }
    }

    fn config(role: InterfaceRole, address: &str) -> InterfaceConfig {
        InterfaceConfig {
            role,
            managed: true,
            ipv4: Some(address.parse::<Ipv4Net>().expect("network")),
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        }
    }

    #[tokio::test]
    async fn refuses_management_change_without_confirmation() {
        let provider = Arc::new(FakeNetworkProvider::default());
        provider.add_interface("eth0", true, Vec::new()).await;
        let manager = InterfaceManager::new(provider);

        let error = manager
            .apply_interface(
                "eth0",
                &config(InterfaceRole::Management, "192.168.1.20/24"),
                Some(InterfaceRole::Management),
                false,
            )
            .await
            .expect_err("management change should be rejected");

        assert!(error.to_string().contains("management interface"));
    }

    #[tokio::test]
    async fn refuses_relabelling_a_management_interface_without_confirmation() {
        let provider = Arc::new(FakeNetworkProvider::default());
        provider.add_interface("eth0", true, Vec::new()).await;
        let manager = InterfaceManager::new(provider);

        let error = manager
            .apply_interface(
                "eth0",
                &config(InterfaceRole::Output, "10.0.0.1/24"),
                Some(InterfaceRole::Management),
                false,
            )
            .await
            .expect_err("relabelling a management interface should be rejected");

        assert!(error.to_string().contains("management interface"));

        manager
            .apply_interface(
                "eth0",
                &config(InterfaceRole::Output, "10.0.0.1/24"),
                Some(InterfaceRole::Management),
                true,
            )
            .await
            .expect("explicit confirmation should allow the change");
    }

    #[test]
    fn management_change_is_symmetric_in_current_and_target_role() {
        assert!(is_management_change(
            InterfaceRole::Output,
            Some(InterfaceRole::Management)
        ));
        assert!(is_management_change(InterfaceRole::Management, None));
        assert!(is_management_change(
            InterfaceRole::Management,
            Some(InterfaceRole::Output)
        ));
        assert!(!is_management_change(
            InterfaceRole::Output,
            Some(InterfaceRole::Output)
        ));
        assert!(!is_management_change(InterfaceRole::Output, None));
    }

    #[tokio::test]
    async fn a_dhcp_client_interface_plans_no_address_change_and_never_oscillates() {
        let provider = Arc::new(FakeNetworkProvider::default());
        let dynamic = Ipv4AddressInfo {
            interface_index: 1,
            address: Ipv4Addr::new(192, 0, 2, 42),
            prefix_len: 24,
        };
        provider
            .add_interface("wan0", false, vec![dynamic.clone()])
            .await;
        let manager = InterfaceManager::new(provider.clone());

        let mut config = config(InterfaceRole::Input, "192.0.2.42/24");

        config.ipv4 = None;
        config.dhcp_client = Some(crate::config::DhcpClientInterfaceConfig::default());
        assert!(owns_dynamic_ipv4(&config));

        let plan = manager
            .plan_interface("wan0", &config, Some(InterfaceRole::Input), false)
            .await
            .expect("plan");
        assert!(plan.delete_ipv4.is_empty());
        assert!(plan.add_ipv4.is_none());
        assert!(plan.set_link_up);

        for _ in 0..5 {
            manager
                .apply_interface("wan0", &config, Some(InterfaceRole::Input), false)
                .await
                .expect("apply");
        }
        assert_eq!(
            provider
                .list_ipv4_addresses("wan0")
                .await
                .expect("addresses"),
            vec![dynamic]
        );
    }

    #[tokio::test]
    async fn a_disabled_dhcp_client_block_keeps_static_planning() {
        let provider = Arc::new(FakeNetworkProvider::default());
        provider
            .add_interface(
                "wan0",
                true,
                vec![Ipv4AddressInfo {
                    interface_index: 1,
                    address: Ipv4Addr::new(198, 51, 100, 9),
                    prefix_len: 24,
                }],
            )
            .await;
        let manager = InterfaceManager::new(provider);

        let mut config = config(InterfaceRole::Input, "192.0.2.10/24");
        config.dhcp_client = Some(crate::config::DhcpClientInterfaceConfig {
            enabled: false,
            ..crate::config::DhcpClientInterfaceConfig::default()
        });
        assert!(!owns_dynamic_ipv4(&config));

        let plan = manager
            .plan_interface("wan0", &config, Some(InterfaceRole::Input), false)
            .await
            .expect("plan");
        assert_eq!(plan.delete_ipv4.len(), 1);
        assert!(plan.add_ipv4.is_some());
    }

    #[tokio::test]
    async fn apply_and_rollback_restore_interface_state() {
        let provider = Arc::new(FakeNetworkProvider::default());
        let original = Ipv4AddressInfo {
            interface_index: 1,
            address: Ipv4Addr::new(192, 168, 1, 10),
            prefix_len: 24,
        };
        provider
            .add_interface("usb0", false, vec![original.clone()])
            .await;
        let manager = InterfaceManager::new(provider.clone());
        let snapshot = manager.snapshot("usb0").await.expect("snapshot");

        manager
            .apply_interface(
                "usb0",
                &config(InterfaceRole::Output, "192.168.50.1/24"),
                Some(InterfaceRole::Output),
                false,
            )
            .await
            .expect("apply");
        let applied = provider
            .list_ipv4_addresses("usb0")
            .await
            .expect("addresses");
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].address, Ipv4Addr::new(192, 168, 50, 1));

        manager.rollback(&snapshot).await.expect("rollback");
        let restored = provider
            .list_ipv4_addresses("usb0")
            .await
            .expect("addresses");
        assert_eq!(restored, vec![original]);
        let interface = provider
            .list_interfaces()
            .await
            .expect("interfaces")
            .into_iter()
            .find(|interface| interface.name == "usb0")
            .expect("usb0");
        assert!(!interface.is_up);
    }

    #[tokio::test]
    async fn apply_network_skips_absent_managed_interface_and_applies_the_rest() {
        let provider = Arc::new(FakeNetworkProvider::default());
        provider.add_interface("eth0", false, Vec::new()).await;

        let manager = InterfaceManager::new(provider.clone());

        let mut network = NetworkConfig::default();
        network.interfaces.insert(
            "eth0".to_string(),
            config(InterfaceRole::Output, "192.168.50.1/24"),
        );
        network.interfaces.insert(
            "usb0".to_string(),
            config(InterfaceRole::Output, "192.168.60.1/24"),
        );

        let snapshots = manager
            .apply_network(&network, true)
            .await
            .expect("startup must succeed despite the absent managed interface");

        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].name, "eth0");
        let applied = provider
            .list_ipv4_addresses("eth0")
            .await
            .expect("addresses");
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].address, Ipv4Addr::new(192, 168, 50, 1));
    }

    #[tokio::test]
    async fn apply_network_still_rolls_back_on_a_real_failure_after_success() {
        let provider = Arc::new(FakeNetworkProvider::default());
        provider.add_interface("eth0", false, Vec::new()).await;
        provider.add_interface("mgmt0", true, Vec::new()).await;
        let manager = InterfaceManager::new(provider.clone());

        let mut network = NetworkConfig::default();
        network.interfaces.insert(
            "eth0".to_string(),
            config(InterfaceRole::Output, "192.168.50.1/24"),
        );

        network.interfaces.insert(
            "mgmt0".to_string(),
            config(InterfaceRole::Management, "192.168.70.1/24"),
        );

        let error = manager
            .apply_network(&network, false)
            .await
            .expect_err("management change without confirmation must fail");
        assert!(error.to_string().contains("failed to apply interface"));

        let restored = provider
            .list_ipv4_addresses("eth0")
            .await
            .expect("addresses");
        assert!(restored.is_empty());
    }
}
