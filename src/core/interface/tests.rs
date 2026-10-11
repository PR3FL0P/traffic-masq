use std::collections::HashMap;
use std::net::Ipv4Addr;

use async_trait::async_trait;
use ipnet::Ipv4Net;
use tokio::sync::Mutex;

use crate::config::InterfaceConfig;
use crate::netlink::{
    NetworkInterface, TRAFFIC_MASQ_ADDRESS_PROTOCOL, TRAFFIC_MASQ_DHCP_ADDRESS_PROTOCOL,
};

use super::*;

#[tokio::test]
async fn owned_addresses_remain_editable_after_restart_without_saved_interface_settings() {
    for tagged in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let provider = Arc::new(UntaggedNetworkProvider::default());
        let external = address_with_protocol("192.168.1.20/24", None);
        provider
            .0
            .add_interface("eth0", true, vec![external.clone()])
            .await;
        let journal = AddressOwnershipJournal::open(directory.path()).unwrap();
        let manager = InterfaceManager::new(provider.clone(), journal);
        manager
            .apply_interface(
                "eth0",
                &config(InterfaceRole::Output, "192.168.50.1/24"),
                Some(InterfaceRole::Output),
                false,
            )
            .await
            .unwrap();
        drop(manager);
        if tagged {
            // A reset may remove both intent and its journal. A surviving
            // kernel tag remains independent ownership proof.
            provider.0.addresses.lock().await.get_mut("eth0").unwrap()[1].protocol =
                Some(TRAFFIC_MASQ_ADDRESS_PROTOCOL);
            std::fs::remove_dir_all(directory.path().join("address-ownership")).unwrap();
        }
        let reopened = AddressOwnershipJournal::open(directory.path()).unwrap();
        let observed = provider.list_ipv4_addresses("eth0").await.unwrap();
        reopened.reconcile("eth0", &observed).await.unwrap();
        let manager = InterfaceManager::new(provider.clone(), reopened);
        assert!(manager.owns_address("eth0", &observed[1]).await);
        assert!(!manager.owns_address("eth0", &external).await);
        let target = InterfaceConfig {
            mac_address: None,
            managed: true,
            role: InterfaceRole::None,
            ipv4: None,
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
            nat: true,
        };
        // No previous configuration or role: same plan used after settings reset.
        let plan = manager
            .plan_interface_transition("eth0", &target, None, None, true)
            .await
            .unwrap();
        assert_eq!(plan.delete_ipv4, vec![observed[1].clone()]);
        manager.apply_plan(&plan).await.unwrap();
        assert_eq!(
            provider.list_ipv4_addresses("eth0").await.unwrap(),
            vec![external]
        );
    }
}

#[tokio::test]
async fn current_foreign_or_dhcp_tag_overrides_an_old_static_claim() {
    let journal = AddressOwnershipJournal::in_memory();
    journal
        .claim("eth0", "192.168.50.1".parse().unwrap(), 24)
        .await
        .unwrap();
    let manager = InterfaceManager::new(Arc::new(FakeNetworkProvider::default()), journal);
    for protocol in [Some(16), Some(TRAFFIC_MASQ_DHCP_ADDRESS_PROTOCOL)] {
        let address = address_with_protocol("192.168.50.1/24", protocol);
        assert!(!manager.owns_address("eth0", &address).await);
    }
}

#[derive(Debug, Default)]
struct FakeNetworkProvider {
    interfaces: Mutex<HashMap<String, NetworkInterface>>,
    addresses: Mutex<HashMap<String, Vec<Ipv4AddressInfo>>>,
    fail_address_read: Mutex<Option<String>>,
    macs: Mutex<HashMap<String, [u8; 6]>>,
    fail_mac_write: Mutex<bool>,
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
    async fn mac_address(&self, name: &str) -> Result<Option<[u8; 6]>> {
        Ok(self.macs.lock().await.get(name).copied())
    }

    async fn set_mac_address(&self, name: &str, mac: [u8; 6]) -> Result<()> {
        anyhow::ensure!(
            !self.interfaces.lock().await[name].is_up,
            "MAC must be changed while down"
        );
        let mut fail = self.fail_mac_write.lock().await;
        if *fail {
            *fail = false;
            anyhow::bail!("injected MAC write failure");
        }
        self.macs.lock().await.insert(name.into(), mac);
        Ok(())
    }

    fn supports_ipv4_address_protocol(&self) -> bool {
        true
    }

    async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        Ok(self.interfaces.lock().await.values().cloned().collect())
    }

    async fn list_ipv4_addresses(&self, interface: &str) -> Result<Vec<Ipv4AddressInfo>> {
        anyhow::ensure!(
            self.fail_address_read.lock().await.as_deref() != Some(interface),
            "injected address observation failure"
        );
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
        ownership: AddressOwnership,
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
                protocol: ownership.protocol(),
            });
        Ok(())
    }

    async fn set_ipv4_address_ownership(
        &self,
        interface: &str,
        address: Ipv4Addr,
        prefix_len: u8,
        ownership: AddressOwnership,
    ) -> Result<()> {
        let mut addresses = self.addresses.lock().await;
        let entry = addresses.entry(interface.to_string()).or_default();
        let existing = entry
            .iter_mut()
            .find(|item| item.address == address && item.prefix_len == prefix_len)
            .ok_or_else(|| {
                anyhow::anyhow!("address {address}/{prefix_len} not found on {interface}")
            })?;
        existing.protocol = ownership.protocol();
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
        mac_address: None,
        nat: true,
        role,
        managed: true,
        ipv4: Some(address.parse::<Ipv4Net>().expect("network")),
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    }
}

fn address_with_protocol(address: &str, protocol: Option<u8>) -> Ipv4AddressInfo {
    let network = address.parse::<Ipv4Net>().expect("network");
    Ipv4AddressInfo {
        interface_index: 1,
        address: network.addr(),
        prefix_len: network.prefix_len(),
        protocol,
    }
}

/// Removing the address is a configuration in its own right: a managed
/// interface with no configured IPv4 is one that must end up carrying none,
/// whether the address was ours or was already on the link when we arrived.
#[tokio::test]
async fn a_managed_interface_without_a_configured_address_has_its_addresses_removed() {
    let provider = Arc::new(FakeNetworkProvider::default());
    let ours = address_with_protocol("192.168.50.1/24", Some(TRAFFIC_MASQ_ADDRESS_PROTOCOL));
    let pre_existing = address_with_protocol("192.168.1.20/24", None);
    provider
        .add_interface("eth0", true, vec![ours.clone(), pre_existing.clone()])
        .await;
    let manager = InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory());
    let previous = config(InterfaceRole::Output, "192.168.50.1/24");
    let mut target = previous.clone();
    target.ipv4 = None;

    let plan = manager
        .plan_interface_transition(
            "eth0",
            &target,
            Some(&previous),
            Some(InterfaceRole::Output),
            false,
        )
        .await
        .expect("removal plan");

    assert_eq!(plan.delete_ipv4, vec![ours]);
    assert!(plan.add_ipv4.is_none());
    assert!(plan.retag_ipv4.is_none());
    assert!(
        !plan.releasing_management,
        "the interface stays managed; only the address goes"
    );

    manager.apply_plan(&plan).await.expect("apply the removal");
    assert_eq!(
        provider
            .list_ipv4_addresses("eth0")
            .await
            .expect("addresses")
            .as_slice(),
        &[pre_existing]
    );
}

/// The removal has to be reached by convergence too, not only by the
/// operator's apply: an address that comes back — a rollback, a reboot, a
/// second daemon — is removed again on the next pass.
#[tokio::test]
async fn convergence_keeps_removing_an_address_that_is_no_longer_configured() {
    let provider = Arc::new(FakeNetworkProvider::default());
    provider
        .add_interface(
            "eth0",
            true,
            vec![address_with_protocol("192.168.50.1/24", None)],
        )
        .await;
    let manager = InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory());
    let mut target = config(InterfaceRole::Output, "192.168.50.1/24");
    target.ipv4 = None;

    manager
        .apply_interface("eth0", &target, Some(InterfaceRole::Output), false)
        .await
        .expect("first pass removes the address");
    provider
        .add_ipv4_address(
            "eth0",
            Ipv4Addr::new(192, 168, 50, 1),
            24,
            AddressOwnership::Untagged,
        )
        .await
        .expect("the address reappears");
    manager
        .apply_interface("eth0", &target, Some(InterfaceRole::Output), false)
        .await
        .expect("second pass removes it again");

    assert_eq!(
        provider
            .list_ipv4_addresses("eth0")
            .await
            .expect("addresses")
            .len(),
        2
    );
}

#[tokio::test]
async fn releasing_management_deletes_only_tagged_addresses() {
    let provider = Arc::new(FakeNetworkProvider::default());
    let owned = address_with_protocol("192.168.50.1/24", Some(TRAFFIC_MASQ_ADDRESS_PROTOCOL));
    let foreign = address_with_protocol("192.168.1.20/24", None);
    provider
        .add_interface("eth0", true, vec![owned.clone(), foreign])
        .await;
    let manager = InterfaceManager::new(provider, AddressOwnershipJournal::in_memory());
    let previous = config(InterfaceRole::Output, "192.168.50.1/24");
    let mut target = previous.clone();
    target.managed = false;
    target.ipv4 = None;

    let plan = manager
        .plan_interface_transition(
            "eth0",
            &target,
            Some(&previous),
            Some(InterfaceRole::Output),
            false,
        )
        .await
        .expect("release plan");

    assert!(plan.releasing_management);
    assert_eq!(plan.delete_ipv4, vec![owned]);
    assert!(plan.add_ipv4.is_none());
    assert!(!plan.set_link_up);
}

#[tokio::test]
async fn releasing_management_refuses_an_untagged_legacy_address() {
    let provider = Arc::new(FakeNetworkProvider::default());
    provider
        .add_interface(
            "eth0",
            true,
            vec![address_with_protocol("192.168.50.1/24", None)],
        )
        .await;
    let manager = InterfaceManager::new(provider, AddressOwnershipJournal::in_memory());
    let previous = config(InterfaceRole::Output, "192.168.50.1/24");
    let mut target = previous.clone();
    target.managed = false;
    target.ipv4 = None;

    let error = manager
        .plan_interface_transition(
            "eth0",
            &target,
            Some(&previous),
            Some(InterfaceRole::Output),
            false,
        )
        .await
        .expect_err("untagged address must not be claimed");
    assert!(error.to_string().contains("ownership tag"));
}

/// A provider that installs addresses but cannot hold an ownership tag —
/// which is every Linux older than 5.18.
#[derive(Debug, Default)]
struct UntaggedNetworkProvider(FakeNetworkProvider);

#[async_trait]
impl NetworkProvider for UntaggedNetworkProvider {
    fn supports_ipv4_address_protocol(&self) -> bool {
        false
    }

    async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        self.0.list_interfaces().await
    }

    async fn list_ipv4_addresses(&self, interface: &str) -> Result<Vec<Ipv4AddressInfo>> {
        self.0.list_ipv4_addresses(interface).await
    }

    async fn set_link_up(&self, name: &str) -> Result<()> {
        self.0.set_link_up(name).await
    }

    async fn set_link_down(&self, name: &str) -> Result<()> {
        self.0.set_link_down(name).await
    }

    async fn add_ipv4_address(
        &self,
        interface: &str,
        address: Ipv4Addr,
        prefix_len: u8,
        _ownership: AddressOwnership,
    ) -> Result<()> {
        // The tag is dropped, silently, exactly as the kernel does.
        self.0
            .add_ipv4_address(interface, address, prefix_len, AddressOwnership::Untagged)
            .await
    }

    async fn delete_ipv4_address(
        &self,
        interface: &str,
        address: Ipv4Addr,
        prefix_len: u8,
    ) -> Result<()> {
        self.0
            .delete_ipv4_address(interface, address, prefix_len)
            .await
    }
}

/// The dead end this stage exists to remove.
///
/// On a kernel that cannot hold `IFA_PROTO`, traffic-masq used to install an
/// address it could never prove was its own, and refuse to release the
/// interface for ever after. The journal is that proof, so the same
/// sequence now completes.
#[tokio::test]
async fn an_interface_can_be_released_on_a_kernel_without_ownership_tags() {
    let provider = Arc::new(UntaggedNetworkProvider::default());
    provider.0.add_interface("eth0", true, Vec::new()).await;
    let manager = InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory());
    let managed = config(InterfaceRole::Output, "192.168.50.1/24");

    manager
        .apply_interface("eth0", &managed, Some(InterfaceRole::Output), false)
        .await
        .expect("apply the managed configuration");

    let installed = provider
        .list_ipv4_addresses("eth0")
        .await
        .expect("addresses");
    assert_eq!(
        installed[0].owner(),
        AddressOwner::Untagged,
        "this kernel cannot hold the tag; the journal has to be what remembers"
    );

    let mut released = managed.clone();
    released.managed = false;
    released.ipv4 = None;

    let plan = manager
        .plan_interface_transition(
            "eth0",
            &released,
            Some(&managed),
            Some(InterfaceRole::Output),
            false,
        )
        .await
        .expect("releasing management must not be a dead end");

    assert_eq!(plan.delete_ipv4, installed);
    assert!(plan.releasing_management);

    manager.apply_plan(&plan).await.expect("apply the release");
    assert!(provider
        .list_ipv4_addresses("eth0")
        .await
        .expect("addresses")
        .is_empty());
}

/// The other half of the same rule: without a record and without a tag, the
/// address is not ours and is not touched. The journal must not be a licence
/// to delete whatever happens to match the configuration.
#[tokio::test]
async fn an_untagged_address_nobody_recorded_is_still_refused() {
    let provider = Arc::new(UntaggedNetworkProvider::default());
    provider
        .0
        .add_interface(
            "eth0",
            true,
            vec![address_with_protocol("192.168.50.1/24", None)],
        )
        .await;
    let manager = InterfaceManager::new(provider, AddressOwnershipJournal::in_memory());
    let previous = config(InterfaceRole::Output, "192.168.50.1/24");
    let mut target = previous.clone();
    target.managed = false;
    target.ipv4 = None;

    let error = manager
        .plan_interface_transition(
            "eth0",
            &target,
            Some(&previous),
            Some(InterfaceRole::Output),
            false,
        )
        .await
        .expect_err("an address we cannot prove is ours must not be deleted");
    assert!(error.to_string().contains("not recorded as installed"));
}

/// Installing an address writes it down before the kernel is touched, and
/// removing it gives the record up. Without the second half the journal
/// would grow claims on addresses that are long gone.
#[tokio::test]
async fn installing_and_removing_an_address_keeps_the_journal_in_step() {
    let provider = Arc::new(FakeNetworkProvider::default());
    provider.add_interface("eth0", true, Vec::new()).await;
    let journal = AddressOwnershipJournal::in_memory();
    let manager = InterfaceManager::new(provider.clone(), journal.clone());

    manager
        .apply_interface(
            "eth0",
            &config(InterfaceRole::Output, "192.168.50.1/24"),
            Some(InterfaceRole::Output),
            false,
        )
        .await
        .expect("apply");

    assert!(
        journal
            .owns("eth0", Ipv4Addr::new(192, 168, 50, 1), 24)
            .await
    );

    manager
        .apply_interface(
            "eth0",
            &config(InterfaceRole::Output, "192.168.60.1/24"),
            Some(InterfaceRole::Output),
            false,
        )
        .await
        .expect("apply a different address");

    assert!(
        !journal
            .owns("eth0", Ipv4Addr::new(192, 168, 50, 1), 24)
            .await,
        "an address that has been removed is no longer ours"
    );
    assert!(
        journal
            .owns("eth0", Ipv4Addr::new(192, 168, 60, 1), 24)
            .await
    );
}

#[tokio::test]
async fn snapshotting_reports_a_missing_interface_instead_of_failing() {
    let provider = Arc::new(FakeNetworkProvider::default());
    provider.add_interface("eth0", true, Vec::new()).await;
    let manager = InterfaceManager::new(provider, AddressOwnershipJournal::in_memory());

    assert!(manager
        .snapshot_if_present("eth0")
        .await
        .expect("present interface")
        .is_some());
    assert!(manager
        .snapshot_if_present("usb0")
        .await
        .expect("a missing interface is not an error")
        .is_none());
    // The strict variant keeps its contract for callers that need one.
    assert!(manager.snapshot("usb0").await.is_err());
}

#[tokio::test]
async fn a_leftover_owned_address_is_cleaned_up_after_the_release_transition() {
    let provider = Arc::new(FakeNetworkProvider::default());
    let owned = address_with_protocol("192.168.50.1/24", Some(TRAFFIC_MASQ_ADDRESS_PROTOCOL));
    let foreign = address_with_protocol("192.168.1.20/24", None);
    provider
        .add_interface("eth0", true, vec![owned.clone(), foreign])
        .await;
    let manager = InterfaceManager::new(provider, AddressOwnershipJournal::in_memory());

    // Both sides already unmanaged: the managed -> unmanaged edge is long
    // gone, but our address is still sitting on the link.
    let unmanaged = InterfaceConfig {
        mac_address: None,
        nat: true,
        role: InterfaceRole::Output,
        managed: false,
        ipv4: None,
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    };

    let plan = manager
        .plan_interface_transition(
            "eth0",
            &unmanaged,
            Some(&unmanaged),
            Some(InterfaceRole::Output),
            false,
        )
        .await
        .expect("plan");

    assert!(!plan.releasing_management);
    assert_eq!(
        plan.delete_ipv4,
        vec![owned],
        "a leftover traffic-masq address must stay removable, and a foreign one untouched"
    );
}

#[tokio::test]
async fn applying_a_retag_honours_the_ownership_the_plan_carries() {
    let provider = Arc::new(FakeNetworkProvider::default());
    provider
        .add_interface(
            "eth0",
            true,
            vec![address_with_protocol("192.168.50.1/24", None)],
        )
        .await;
    let manager = InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory());

    // Not a plan the planner currently produces, which is the point: apply
    // must read the tag out of the plan instead of assuming Static.
    let plan = InterfaceChangePlan {
        mac_address: None,
        interface: "eth0".to_string(),
        delete_ipv4: Vec::new(),
        retag_ipv4: Some(address_with_protocol(
            "192.168.50.1/24",
            Some(TRAFFIC_MASQ_DHCP_ADDRESS_PROTOCOL),
        )),
        add_ipv4: None,
        set_link_up: false,
        management_change: false,
        dhcp_action: DhcpChangeAction::Unchanged,
        releasing_management: false,
    };
    manager.apply_plan(&plan).await.expect("apply plan");

    let addresses = provider
        .list_ipv4_addresses("eth0")
        .await
        .expect("addresses");
    assert_eq!(
        addresses,
        vec![address_with_protocol(
            "192.168.50.1/24",
            Some(TRAFFIC_MASQ_DHCP_ADDRESS_PROTOCOL)
        )]
    );
}

#[tokio::test]
async fn legacy_address_is_claimed_in_place_on_every_path() {
    let provider = Arc::new(FakeNetworkProvider::default());
    provider
        .add_interface(
            "eth0",
            true,
            vec![address_with_protocol("192.168.50.1/24", None)],
        )
        .await;
    let manager = InterfaceManager::new(provider, AddressOwnershipJournal::in_memory());
    let desired = config(InterfaceRole::Output, "192.168.50.1/24");

    // The startup/reconcile path and the transactional path must agree:
    // both claim the untagged address rather than one of them adopting it
    // silently and the other tearing it down.
    let startup = manager
        .plan_interface("eth0", &desired, Some(InterfaceRole::Output), false)
        .await
        .expect("startup plan");
    let explicit = manager
        .plan_interface_transition(
            "eth0",
            &desired,
            Some(&desired),
            Some(InterfaceRole::Output),
            false,
        )
        .await
        .expect("explicit plan");

    for plan in [&startup, &explicit] {
        assert!(
            plan.delete_ipv4.is_empty(),
            "claiming an address must not take it off the link"
        );
        assert!(plan.add_ipv4.is_none());
        assert!(plan.retag_ipv4.is_none());
    }
}

#[tokio::test]
async fn claiming_a_legacy_address_keeps_it_on_the_link() {
    let provider = Arc::new(FakeNetworkProvider::default());
    provider
        .add_interface(
            "eth0",
            true,
            vec![address_with_protocol("192.168.50.1/24", None)],
        )
        .await;
    let manager = InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory());
    let desired = config(InterfaceRole::Output, "192.168.50.1/24");

    manager
        .apply_interface_transition(
            "eth0",
            &desired,
            Some(&desired),
            Some(InterfaceRole::Output),
            false,
        )
        .await
        .expect("apply");

    let addresses = provider
        .list_ipv4_addresses("eth0")
        .await
        .expect("addresses");
    assert_eq!(
        addresses,
        vec![address_with_protocol("192.168.50.1/24", None)]
    );
}

#[tokio::test]
async fn an_unrelated_edit_leaves_an_owned_address_untouched() {
    let provider = Arc::new(FakeNetworkProvider::default());
    provider
        .add_interface(
            "eth0",
            true,
            vec![address_with_protocol(
                "192.168.50.1/24",
                Some(TRAFFIC_MASQ_ADDRESS_PROTOCOL),
            )],
        )
        .await;
    let manager = InterfaceManager::new(provider, AddressOwnershipJournal::in_memory());
    let desired = config(InterfaceRole::Output, "192.168.50.1/24");

    let plan = manager
        .plan_interface_transition(
            "eth0",
            &desired,
            Some(&desired),
            Some(InterfaceRole::Output),
            false,
        )
        .await
        .expect("plan");

    assert!(plan.delete_ipv4.is_empty());
    assert!(plan.add_ipv4.is_none());
    assert!(plan.retag_ipv4.is_none());
}

#[tokio::test]
async fn refuses_management_change_without_confirmation() {
    let provider = Arc::new(FakeNetworkProvider::default());
    provider.add_interface("eth0", true, Vec::new()).await;
    let manager = InterfaceManager::new(provider, AddressOwnershipJournal::in_memory());

    let error = manager
        .apply_interface(
            "eth0",
            &config(InterfaceRole::None, "192.168.1.20/24"),
            Some(InterfaceRole::None),
            false,
        )
        .await
        .expect_err("management change should be rejected");

    assert!(error.to_string().contains("outside-router interface"));
}

#[tokio::test]
async fn refuses_relabelling_a_management_interface_without_confirmation() {
    let provider = Arc::new(FakeNetworkProvider::default());
    provider.add_interface("eth0", true, Vec::new()).await;
    let manager = InterfaceManager::new(provider, AddressOwnershipJournal::in_memory());

    let error = manager
        .apply_interface(
            "eth0",
            &config(InterfaceRole::Output, "10.0.0.1/24"),
            Some(InterfaceRole::None),
            false,
        )
        .await
        .expect_err("relabelling an outside-router interface should be rejected");

    assert!(error.to_string().contains("outside-router interface"));

    manager
        .apply_interface(
            "eth0",
            &config(InterfaceRole::Output, "10.0.0.1/24"),
            Some(InterfaceRole::None),
            true,
        )
        .await
        .expect("explicit confirmation should allow the change");
}

#[test]
fn management_change_is_symmetric_in_current_and_target_role() {
    assert!(is_management_change(
        InterfaceRole::Output,
        Some(InterfaceRole::None)
    ));
    assert!(is_management_change(InterfaceRole::None, None));
    assert!(is_management_change(
        InterfaceRole::None,
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
        protocol: None,
    };
    provider
        .add_interface("wan0", false, vec![dynamic.clone()])
        .await;
    let manager = InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory());

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
                protocol: None,
            }],
        )
        .await;
    let manager = InterfaceManager::new(provider, AddressOwnershipJournal::in_memory());

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
    assert_eq!(plan.delete_ipv4.len(), 0);
    assert!(plan.add_ipv4.is_some());
}

#[tokio::test]
async fn snapshot_excludes_dhcp_owned_addresses() {
    let provider = Arc::new(FakeNetworkProvider::default());
    let static_address = Ipv4AddressInfo {
        interface_index: 1,
        address: Ipv4Addr::new(192, 0, 2, 10),
        prefix_len: 24,
        protocol: Some(TRAFFIC_MASQ_ADDRESS_PROTOCOL),
    };
    let dhcp_address = Ipv4AddressInfo {
        interface_index: 1,
        address: Ipv4Addr::new(198, 51, 100, 20),
        prefix_len: 24,
        protocol: Some(TRAFFIC_MASQ_DHCP_ADDRESS_PROTOCOL),
    };
    provider
        .add_interface("wan0", true, vec![static_address.clone(), dhcp_address])
        .await;
    let manager = InterfaceManager::new(provider, AddressOwnershipJournal::in_memory());

    let snapshot = manager.snapshot("wan0").await.expect("snapshot");
    assert_eq!(snapshot.ipv4_addresses, vec![static_address]);
}

#[tokio::test]
async fn rollback_never_replays_dhcp_addresses_from_legacy_snapshots() {
    let provider = Arc::new(FakeNetworkProvider::default());
    let newer_lease = Ipv4AddressInfo {
        interface_index: 1,
        address: Ipv4Addr::new(198, 51, 100, 30),
        prefix_len: 24,
        protocol: Some(TRAFFIC_MASQ_DHCP_ADDRESS_PROTOCOL),
    };
    provider
        .add_interface("wan0", true, vec![newer_lease.clone()])
        .await;
    let manager = InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory());
    let legacy_snapshot = InterfaceSnapshot {
        mac_address: None,
        name: "wan0".into(),
        was_up: true,
        ipv4_addresses: vec![Ipv4AddressInfo {
            interface_index: 1,
            address: Ipv4Addr::new(198, 51, 100, 20),
            prefix_len: 24,
            protocol: Some(TRAFFIC_MASQ_DHCP_ADDRESS_PROTOCOL),
        }],
    };

    manager.rollback(&legacy_snapshot).await.expect("rollback");
    assert_eq!(
        provider
            .list_ipv4_addresses("wan0")
            .await
            .expect("addresses"),
        vec![newer_lease]
    );
}

#[tokio::test]
async fn apply_and_rollback_restore_interface_state() {
    let provider = Arc::new(FakeNetworkProvider::default());
    let original = Ipv4AddressInfo {
        interface_index: 1,
        address: Ipv4Addr::new(192, 168, 1, 10),
        prefix_len: 24,
        protocol: None,
    };
    provider
        .add_interface("usb0", false, vec![original.clone()])
        .await;
    let manager = InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory());
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
    assert_eq!(applied.len(), 2);
    assert!(applied
        .iter()
        .any(|address| address.address == Ipv4Addr::new(192, 168, 50, 1)));
    assert!(applied.iter().any(|address| address == &original));

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

    let manager = InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory());

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
async fn apply_network_rolls_back_when_a_later_snapshot_fails() {
    let provider = Arc::new(FakeNetworkProvider::default());
    provider.add_interface("eth0", false, Vec::new()).await;
    provider.add_interface("eth1", false, Vec::new()).await;
    *provider.fail_address_read.lock().await = Some("eth1".to_string());
    let manager = InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory());
    let mut network = NetworkConfig::default();
    network.interfaces.insert(
        "eth0".into(),
        config(InterfaceRole::Output, "192.168.50.1/24"),
    );
    network.interfaces.insert(
        "eth1".into(),
        config(InterfaceRole::Output, "192.168.60.1/24"),
    );
    let error = manager.apply_network(&network, false).await.unwrap_err();
    assert!(format!("{error:#}").contains("injected address observation failure"));
    assert!(provider
        .list_ipv4_addresses("eth0")
        .await
        .unwrap()
        .is_empty());
    assert!(!provider.interfaces.lock().await["eth0"].is_up);
}

#[tokio::test]
async fn apply_network_still_rolls_back_on_a_real_failure_after_success() {
    let provider = Arc::new(FakeNetworkProvider::default());
    provider.add_interface("eth0", false, Vec::new()).await;
    provider.add_interface("mgmt0", true, Vec::new()).await;
    let manager = InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory());

    let mut network = NetworkConfig::default();
    network.interfaces.insert(
        "eth0".to_string(),
        config(InterfaceRole::Output, "192.168.50.1/24"),
    );

    network.interfaces.insert(
        "mgmt0".to_string(),
        config(InterfaceRole::None, "192.168.70.1/24"),
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

#[tokio::test]
async fn mac_change_is_previewed_idempotent_and_rolled_back() {
    let provider = Arc::new(FakeNetworkProvider::default());
    provider.add_interface("eth0", true, vec![]).await;
    let original = [0x00, 1, 2, 3, 4, 5];
    provider.macs.lock().await.insert("eth0".into(), original);
    let manager = InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory());
    let snapshot = manager.snapshot("eth0").await.unwrap();
    let mut target = config(InterfaceRole::Output, "192.168.50.1/24");
    let generated = traffic_masq_protocol::MacAddr::new([0x02, 6, 7, 8, 9, 10]);
    target.mac_address = Some(generated);
    let plan = manager
        .plan_interface("eth0", &target, Some(target.role), false)
        .await
        .unwrap();
    assert_eq!(plan.mac_address, Some(generated));
    assert_eq!(provider.mac_address("eth0").await.unwrap(), Some(original));
    manager.apply_plan(&plan).await.unwrap();
    assert_eq!(
        provider.mac_address("eth0").await.unwrap(),
        Some(generated.octets())
    );
    assert!(provider.interfaces.lock().await["eth0"].is_up);
    assert_eq!(
        manager
            .plan_interface("eth0", &target, Some(target.role), false)
            .await
            .unwrap()
            .mac_address,
        None
    );
    manager.rollback(&snapshot).await.unwrap();
    assert_eq!(provider.mac_address("eth0").await.unwrap(), Some(original));
    assert!(provider.interfaces.lock().await["eth0"].is_up);
}

#[tokio::test]
async fn rejected_mac_change_restores_identity_and_link_state() {
    let provider = Arc::new(FakeNetworkProvider::default());
    provider.add_interface("eth0", true, vec![]).await;
    let original = [0x00, 1, 2, 3, 4, 5];
    provider.macs.lock().await.insert("eth0".into(), original);
    *provider.fail_mac_write.lock().await = true;
    let manager = InterfaceManager::new(provider.clone(), AddressOwnershipJournal::in_memory());
    let mut target = config(InterfaceRole::Output, "192.168.50.1/24");
    target.mac_address = Some(traffic_masq_protocol::MacAddr::new([0x02, 6, 7, 8, 9, 10]));
    manager
        .apply_interface("eth0", &target, Some(target.role), false)
        .await
        .unwrap_err();
    assert_eq!(provider.mac_address("eth0").await.unwrap(), Some(original));
    assert!(provider.interfaces.lock().await["eth0"].is_up);
    assert!(provider
        .list_ipv4_addresses("eth0")
        .await
        .unwrap()
        .is_empty());
}

#[test]
fn invalid_mac_configuration_is_rejected() {
    let mut target = config(InterfaceRole::Output, "192.168.50.1/24");
    for bytes in [[0; 6], [0xff; 6], [1, 2, 3, 4, 5, 6]] {
        target.mac_address = Some(traffic_masq_protocol::MacAddr::new(bytes));
        assert!(target.validate("eth0").is_err());
    }
    target.mac_address = Some(traffic_masq_protocol::MacAddr::new([2, 1, 2, 3, 4, 5]));
    assert!(target.validate("eth0").is_ok());
    target.managed = false;
    assert!(target.validate("eth0").is_err());
}
