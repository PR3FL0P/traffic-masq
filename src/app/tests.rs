use crate::netlink::AddressOwnership;
use std::collections::HashMap;
use std::net::Ipv4Addr;

use async_trait::async_trait;
use tempfile::tempdir;
use tokio::sync::Mutex;

use crate::config::{
    DhcpInterfaceConfig, InterfaceConfig, InterfaceRole, RouterConfig, UplinkConfig, UplinkMode,
    VpnConfig, VpnPolicyMode,
};
#[cfg(target_os = "linux")]
use crate::dhcp::client::supervisor::LinuxDhcpClientLauncher;
use crate::firewall::vpn::test_support::{nft_ruleset, FakeNftExecutor};
use crate::firewall::{
    OwnedFirewallIntegrity, RouterDataplaneDesired, RouterDataplaneInterfaceMissing,
};
use crate::netlink::{Ipv4AddressInfo, Ipv4RouteInfo, Ipv4RuleInfo};
use crate::vpn::active_profile::ActiveProfileStore;
use crate::vpn::manager::OWNED_INTERFACE_NAME;
use crate::vpn::store::WireGuardProfileStore;
use crate::vpn::wireguard::WireGuardVpnDriver;
use crate::vpn::{VpnManager, VpnProvider};

use super::*;
use crate::test_support::{FakeNetworkProvider, StaticKeyVpnProvider};

#[cfg(target_os = "linux")]
#[tokio::test]
async fn closed_kernel_event_stream_fails_the_runtime_converger() {
    let directory = tempdir().expect("tempdir");
    let mut config = AppConfig::default();
    config.runtime.state_dir = directory.path().join("state");
    config.dhcp.leases_dir = directory.path().join("leases");
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let desired = DesiredNetworkState::new(config.clone(), overrides);
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetworkProvider::default());
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("DHCP supervisor");
    let dhcp_client = DhcpClientSupervisor::start_with_launcher(
        &config,
        network.clone(),
        Arc::new(LinuxDhcpClientLauncher),
    )
    .await
    .expect("DHCP client supervisor");
    let (kernel_events_tx, kernel_events) = mpsc::unbounded_channel();
    drop(kernel_events_tx);
    let (_shutdown_tx, shutdown) = watch::channel(false);

    let task = spawn_runtime_network_reconcile(
        desired.clone(),
        AddressOwnershipJournal::in_memory(),
        network,
        dhcp,
        None,
        None,
        dhcp_client,
        Arc::new(NetworkMutationGate::default()),
        None,
        kernel_events,
        shutdown,
    );

    let error = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("closed event stream should stop the reconciler")
        .expect("reconciler task")
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("kernel change notifications stopped"));
    assert!(matches!(
        desired.converger_state(),
        crate::core::desired::ConvergerState::Failed(reason)
            if reason.contains("kernel change notifications stopped")
    ));
}

#[tokio::test]
async fn startup_rollback_unwind_runs_pushed_steps_in_lifo_order() {
    let order = std::sync::Arc::new(Mutex::new(Vec::new()));
    let mut stack = StartupRollback::new();
    for n in [1, 2, 3] {
        let order = order.clone();
        stack.push(async move { order.lock().await.push(n) });
    }
    stack.unwind().await;
    assert_eq!(*order.lock().await, vec![3, 2, 1]);
}

#[tokio::test]
async fn startup_rollback_unwind_on_empty_stack_is_a_noop() {
    StartupRollback::new().unwind().await;
}

#[tokio::test]
async fn startup_rollback_dropping_without_unwind_runs_nothing() {
    let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let mut stack = StartupRollback::new();
        let flag = ran.clone();
        stack.push(async move { flag.store(true, std::sync::atomic::Ordering::SeqCst) });
    }
    assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
}

#[tokio::test]
async fn startup_rollback_unwind_only_runs_what_was_actually_pushed() {
    let order = std::sync::Arc::new(Mutex::new(Vec::new()));
    let mut stack = StartupRollback::new();
    let pushed = order.clone();
    stack.push(async move { pushed.lock().await.push("interfaces") });
    stack.unwind().await;
    assert_eq!(*order.lock().await, vec!["interfaces"]);
}

#[derive(Debug, Default)]
struct FakeDhcpReconciler {
    specs: Mutex<HashMap<String, DhcpServiceSpec>>,
    stale_bindings: Mutex<HashMap<String, bool>>,
    configure_calls: Mutex<Vec<DhcpServiceSpec>>,
    disable_calls: Mutex<Vec<String>>,
    runtime_liveness_checks: Mutex<usize>,
}

#[async_trait]
impl DhcpRuntimeReconciler for FakeDhcpReconciler {
    async fn spec(&self, interface: &str) -> Option<DhcpServiceSpec> {
        self.specs.lock().await.get(interface).cloned()
    }

    async fn disable(&self, interface: &str) -> Result<Option<DhcpServiceSpec>> {
        self.disable_calls.lock().await.push(interface.to_string());
        Ok(self.specs.lock().await.remove(interface))
    }

    async fn binding_stale(&self, interface: &str) -> Result<bool> {
        Ok(*self
            .stale_bindings
            .lock()
            .await
            .get(interface)
            .unwrap_or(&false))
    }

    async fn reconcile(&self, spec: DhcpServiceSpec) -> Result<()> {
        self.configure_calls.lock().await.push(spec.clone());
        self.stale_bindings
            .lock()
            .await
            .insert(spec.interface.clone(), false);
        self.specs.lock().await.insert(spec.interface.clone(), spec);
        Ok(())
    }

    async fn ensure_runtime_alive(&self) -> Result<bool> {
        *self.runtime_liveness_checks.lock().await += 1;
        Ok(false)
    }
}

#[derive(Debug, Default)]
struct FakeDhcpClientReconciler {
    specs: Mutex<HashMap<String, DhcpClientSpec>>,
    reconcile_calls: Mutex<Vec<DhcpClientSpec>>,
    readiness: Mutex<Vec<(String, bool)>>,
    disable_calls: Mutex<Vec<String>>,
    liveness_checks: Mutex<usize>,
}

#[async_trait]
impl DhcpClientRuntimeReconciler for FakeDhcpClientReconciler {
    async fn specs(&self) -> Vec<DhcpClientSpec> {
        self.specs.lock().await.values().cloned().collect()
    }

    async fn disable(&self, interface: &str) -> Result<Option<DhcpClientSpec>> {
        self.disable_calls.lock().await.push(interface.to_string());
        Ok(self.specs.lock().await.remove(interface))
    }

    async fn reconcile(&self, spec: DhcpClientSpec, link_ready: bool) -> Result<()> {
        self.readiness
            .lock()
            .await
            .push((spec.interface.clone(), link_ready));
        let changed = self.specs.lock().await.get(&spec.interface) != Some(&spec);
        if changed {
            self.reconcile_calls.lock().await.push(spec.clone());
            self.specs.lock().await.insert(spec.interface.clone(), spec);
        }
        Ok(())
    }

    async fn ensure_alive(&self) -> Result<bool> {
        *self.liveness_checks.lock().await += 1;
        Ok(false)
    }
}

#[derive(Debug, Default)]
struct FakeWifiReconciler {
    liveness_checks: Mutex<usize>,
    associations: Mutex<HashMap<String, bool>>,
}

#[async_trait]
impl WifiRuntimeReconciler for FakeWifiReconciler {
    async fn ensure_alive(&self) -> Result<bool> {
        *self.liveness_checks.lock().await += 1;
        Ok(false)
    }

    async fn association_ready(&self, interface: &str) -> Option<bool> {
        self.associations.lock().await.get(interface).copied()
    }
}

struct FakeDataplaneProvider {
    state: Mutex<RouterDataplaneSnapshot>,
    fail_next_apply: Mutex<bool>,
    missing_next_apply: Mutex<Option<(String, String)>>,
}

impl Default for FakeDataplaneProvider {
    fn default() -> Self {
        Self {
            state: Mutex::new(RouterDataplaneSnapshot {
                ipv4_forwarding: false,
                owned: None,
                owned_firewall_integrity: OwnedFirewallIntegrity::Intact,
            }),
            fail_next_apply: Mutex::new(false),
            missing_next_apply: Mutex::new(None),
        }
    }
}

#[async_trait]
impl RouterDataplaneProvider for FakeDataplaneProvider {
    async fn observe(&self) -> Result<RouterDataplaneSnapshot> {
        Ok(self.state.lock().await.clone())
    }

    async fn apply_owned(&self, desired: &RouterDataplaneDesired) -> Result<()> {
        if let Some((role, interface)) = self.missing_next_apply.lock().await.take() {
            return Err(RouterDataplaneInterfaceMissing { role, interface }.into());
        }
        let mut fail = self.fail_next_apply.lock().await;
        if *fail {
            *fail = false;
            anyhow::bail!("injected dataplane apply failure");
        }
        drop(fail);
        let mut state = self.state.lock().await;
        state.ipv4_forwarding = true;
        state.owned = Some(desired.clone());
        Ok(())
    }

    async fn disable_owned(&self) -> Result<()> {
        self.state.lock().await.owned = None;
        Ok(())
    }

    async fn restore_owned(&self, snapshot: &RouterDataplaneSnapshot) -> Result<()> {
        *self.state.lock().await = snapshot.clone();
        Ok(())
    }
}

const VALID_VPN_PRIVATE_KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
const VALID_VPN_PUBLIC_KEY: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

fn valid_vpn_profile() -> String {
    format!(
        "[Interface]\n\
         PrivateKey = {VALID_VPN_PRIVATE_KEY}\n\
         Address = 10.0.0.2/24\n\
         \n\
         [Peer]\n\
         PublicKey = {VALID_VPN_PUBLIC_KEY}\n\
         AllowedIPs = 0.0.0.0/0\n\
         Endpoint = 203.0.113.1:51820\n"
    )
}

fn fake_vpn_manager() -> (Arc<ProductionVpnManager>, tempfile::TempDir) {
    let dir = tempdir().expect("tempdir");
    let store = WireGuardProfileStore::new(dir.path().join("wireguard"));
    let active_profile_store = ActiveProfileStore::new(dir.path().join("active-profile.json"));
    let provider: Arc<dyn VpnProvider> = Arc::new(StaticKeyVpnProvider::default());
    let driver = WireGuardVpnDriver::new(provider, store);
    (Arc::new(VpnManager::new(driver, active_profile_store)), dir)
}

fn vpn_policy_startup_config() -> AppConfig {
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
        InterfaceConfig {
            nat: true,
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some("192.168.10.1/24".parse().expect("network")),
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        },
    );
    config.router = RouterConfig {
        enabled: true,
        uplink: Some(UplinkConfig {
            interface: "wan0".to_string(),
            mode: UplinkMode::External,
        }),
        ..RouterConfig::default()
    };
    config.vpn = VpnConfig {
        enabled: true,
        wireguard_config_dir: std::path::PathBuf::from("/var/lib/traffic-masq/vpn/wireguard"),
        policy: Default::default(),
    };
    config
}

/// `default_mode: Vpn` with an active legacy profile and an empty
/// `vpn_chain` must migrate into a length-1 chain carrying that
/// profile's name — the one true migration in Landing 1.
#[tokio::test]
async fn migrates_default_mode_vpn_with_an_active_profile_into_a_length_one_chain() {
    let state_dir = tempdir().expect("tempdir");
    let mut config = vpn_policy_startup_config();
    config.runtime.state_dir = state_dir.path().to_path_buf();
    config.vpn.policy.default_mode = VpnPolicyMode::Vpn;
    assert!(config.router.vpn_chain.is_empty());

    let legacy_store = ActiveProfileStore::new(state_dir.path().join("vpn-active-profile.json"));
    legacy_store
        .save(&crate::vpn::active_profile::PersistedActiveProfile {
            profile_name: "home.conf".to_string(),
            interface: "tm-wg0".to_string(),
            ownership_proof_base64: "irrelevant".to_string(),
        })
        .await
        .expect("persist legacy active profile");

    migrate_vpn_policy_mode_to_chain(&mut config).await;

    assert_eq!(config.router.vpn_chain.len(), 1);
    assert_eq!(config.router.vpn_chain[0].profile_name, "home.conf");
}

/// Without a legacy active profile to synthesize from, the migration
/// must leave `vpn_chain` empty rather than fabricate a hop with no real
/// profile behind it.
#[tokio::test]
async fn does_not_synthesize_a_chain_without_a_legacy_active_profile() {
    let state_dir = tempdir().expect("tempdir");
    let mut config = vpn_policy_startup_config();
    config.runtime.state_dir = state_dir.path().to_path_buf();
    config.vpn.policy.default_mode = VpnPolicyMode::Vpn;

    migrate_vpn_policy_mode_to_chain(&mut config).await;

    assert!(config.router.vpn_chain.is_empty());
}

/// `default_mode: Direct` never triggers the migration, regardless of
/// whether a legacy active profile happens to be lying around.
#[tokio::test]
async fn direct_mode_never_triggers_the_migration() {
    let state_dir = tempdir().expect("tempdir");
    let mut config = vpn_policy_startup_config();
    config.runtime.state_dir = state_dir.path().to_path_buf();
    config.vpn.policy.default_mode = VpnPolicyMode::Direct;

    let legacy_store = ActiveProfileStore::new(state_dir.path().join("vpn-active-profile.json"));
    legacy_store
        .save(&crate::vpn::active_profile::PersistedActiveProfile {
            profile_name: "home.conf".to_string(),
            interface: "tm-wg0".to_string(),
            ownership_proof_base64: "irrelevant".to_string(),
        })
        .await
        .expect("persist legacy active profile");

    migrate_vpn_policy_mode_to_chain(&mut config).await;

    assert!(config.router.vpn_chain.is_empty());
}

fn hotplug_reconcile_config() -> AppConfig {
    let mut config = AppConfig::default();
    config.network.interfaces.insert(
        "lan0".to_string(),
        InterfaceConfig {
            nat: true,
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some("192.168.77.1/24".parse().expect("network")),
            dhcp: Some(DhcpInterfaceConfig {
                pool_start: Ipv4Addr::new(192, 168, 77, 100),
                pool_end: Ipv4Addr::new(192, 168, 77, 120),
                router: Ipv4Addr::new(192, 168, 77, 1),
                dns_servers: vec![Ipv4Addr::new(1, 1, 1, 1)],
                lease_seconds: Some(300),
            }),
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        },
    );
    config
}

#[test]
fn interface_reapply_detects_link_or_address_drift() {
    let config = hotplug_reconcile_config();
    let desired = config.network.interfaces.get("lan0").expect("lan0 config");
    let interface = crate::netlink::NetworkInterface {
        is_wireless: false,
        index: 7,
        name: "lan0".to_string(),
        is_up: true,
        rx_bytes: 0,
        tx_bytes: 0,
    };

    let configured = |protocol| {
        [Ipv4AddressInfo {
            interface_index: 7,
            address: Ipv4Addr::new(192, 168, 77, 1),
            prefix_len: 24,
            protocol,
        }]
    };
    let ours = AddressOwnership::Static.protocol();

    assert!(!interface_needs_reapply(
        &interface,
        &configured(ours),
        desired,
        true,
    ));

    assert!(!interface_needs_reapply(
        &interface,
        &configured(None),
        desired,
        false,
    ));

    // The address is right but carries no ownership tag on a kernel that
    // can hold one: claiming it is work, and it is the only thing that
    // keeps "did we put this here" answerable later.
    assert!(interface_needs_reapply(
        &interface,
        &configured(None),
        desired,
        true,
    ));

    assert!(interface_needs_reapply(
        &crate::netlink::NetworkInterface {
            is_up: false,
            ..interface.clone()
        },
        &configured(ours),
        desired,
        true,
    ));

    assert!(interface_needs_reapply(
        &interface,
        &[Ipv4AddressInfo {
            interface_index: 7,
            address: Ipv4Addr::new(192, 168, 88, 1),
            prefix_len: 24,
            protocol: ours,
        }],
        desired,
        true,
    ));
}

#[test]
fn dhcp_reconcile_disables_missing_interface_and_reconfigures_stale_binding() {
    let config = hotplug_reconcile_config();
    let spec = DhcpServiceSpec::from_interface_config(
        "lan0",
        config.network.interfaces.get("lan0").expect("lan0 config"),
        config.dhcp.default_lease_seconds,
    )
    .expect("spec")
    .expect("dhcp enabled");

    assert_eq!(
        plan_dhcp_reconcile(Some(spec.clone()), Some(spec.clone()), false, false, false),
        DhcpReconcileAction::Disable
    );
    assert_eq!(
        plan_dhcp_reconcile(Some(spec.clone()), Some(spec.clone()), true, true, true),
        DhcpReconcileAction::Configure(spec.clone())
    );
    assert_eq!(
        plan_dhcp_reconcile(Some(spec.clone()), Some(spec.clone()), true, true, false),
        DhcpReconcileAction::Keep
    );
}

#[tokio::test]
async fn runtime_reconcile_reapplies_output_interface_and_restores_dhcp_after_replug() {
    let config = hotplug_reconcile_config();
    let state_dir = tempdir().expect("state dir");
    let overrides = RuntimeOverrideManager::load(state_dir.path(), &config)
        .await
        .expect("overrides");
    let network = Arc::new(FakeNetworkProvider::default());
    network
        .add_interface_with_state("lan0", 7, false, Vec::new())
        .await;
    let dhcp = FakeDhcpReconciler::default();
    let wifi = FakeWifiReconciler::default();

    reconcile_network_runtime_once(
        &DesiredNetworkState::new(config.clone(), overrides.clone()),
        &AddressOwnershipJournal::in_memory(),
        network.clone(),
        &dhcp,
        Some(&wifi),
        None::<&FakeWifiReconciler>,
        None::<&FakeDhcpClientReconciler>,
    )
    .await
    .expect("reconcile");

    let interfaces = network.list_interfaces().await.expect("interfaces");
    let lan0 = interfaces
        .into_iter()
        .find(|interface| interface.name == "lan0")
        .expect("lan0 present");
    assert!(lan0.is_up);
    assert_eq!(
        network
            .list_ipv4_addresses("lan0")
            .await
            .expect("addresses"),
        vec![Ipv4AddressInfo {
            interface_index: 7,
            address: Ipv4Addr::new(192, 168, 77, 1),
            prefix_len: 24,
            protocol: None,
        }]
    );
    assert_eq!(dhcp.configure_calls.lock().await.len(), 1);
    assert!(dhcp.disable_calls.lock().await.is_empty());
    assert_eq!(
        *dhcp.runtime_liveness_checks.lock().await,
        0,
        "convergence must not poll for process liveness; that is a separate concern"
    );
    assert_eq!(*wifi.liveness_checks.lock().await, 0);
}

/// The tentative layer is not something convergence works around — it is
/// what convergence works towards. An unconfirmed change reaches the
/// machine the same way a committed one does, and withdrawing it takes the
/// machine back without anything having to remember how to undo it.
#[tokio::test]
async fn an_unconfirmed_change_is_converged_to_and_then_back_again() {
    let config = hotplug_reconcile_config();
    let state_dir = tempdir().expect("state dir");
    let overrides = RuntimeOverrideManager::load(state_dir.path(), &config)
        .await
        .expect("overrides");
    let network = Arc::new(FakeNetworkProvider::default());
    network
        .add_interface_with_state("lan0", 7, true, Vec::new())
        .await;
    let dhcp = FakeDhcpReconciler::default();
    let desired = DesiredNetworkState::new(config.clone(), overrides.clone());
    let journal = AddressOwnershipJournal::in_memory();

    let proposed = InterfaceConfig {
        ipv4: Some("10.9.9.1/24".parse().expect("network")),
        dhcp: None,
        ..config.network.interfaces["lan0"].clone()
    };
    desired.propose("token-1", "lan0", proposed, false).await;

    reconcile_network_runtime_once(
        &desired,
        &journal,
        network.clone(),
        &dhcp,
        None::<&FakeWifiReconciler>,
        None::<&FakeWifiReconciler>,
        None::<&FakeDhcpClientReconciler>,
    )
    .await
    .expect("reconcile");

    assert_eq!(
        network
            .list_ipv4_addresses("lan0")
            .await
            .expect("addresses")
            .first()
            .map(|address| address.address),
        Some(Ipv4Addr::new(10, 9, 9, 1)),
        "an unconfirmed change must reach the machine through convergence"
    );

    desired.withdraw("token-1").await;

    reconcile_network_runtime_once(
        &desired,
        &journal,
        network.clone(),
        &dhcp,
        None::<&FakeWifiReconciler>,
        None::<&FakeWifiReconciler>,
        None::<&FakeDhcpClientReconciler>,
    )
    .await
    .expect("reconcile");

    assert_eq!(
        network
            .list_ipv4_addresses("lan0")
            .await
            .expect("addresses")
            .first()
            .map(|address| address.address),
        Some(Ipv4Addr::new(192, 168, 77, 1)),
        "dropping the tentative layer is the whole of the rollback"
    );
}

/// A management-role change the operator confirmed has to survive the trip
/// through the desired state: the permission lives in the override only
/// after the change is committed, so until then the proposal carries it.
#[tokio::test]
async fn a_proposal_carries_its_own_permission_to_touch_a_management_interface() {
    let mut config = AppConfig::default();
    config.network.interfaces.insert(
        "mgmt0".to_string(),
        InterfaceConfig {
            nat: true,
            role: InterfaceRole::None,
            managed: true,
            ipv4: Some("192.168.1.10/24".parse().expect("network")),
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        },
    );
    let state_dir = tempdir().expect("state dir");
    let overrides = RuntimeOverrideManager::load(state_dir.path(), &config)
        .await
        .expect("overrides");
    let network = Arc::new(FakeNetworkProvider::default());
    network
        .add_interface_with_state("mgmt0", 3, true, Vec::new())
        .await;
    let dhcp = FakeDhcpReconciler::default();
    let desired = DesiredNetworkState::new(config.clone(), overrides.clone());
    let journal = AddressOwnershipJournal::in_memory();

    let proposed = InterfaceConfig {
        ipv4: Some("192.168.1.11/24".parse().expect("network")),
        ..config.network.interfaces["mgmt0"].clone()
    };
    desired
        .propose("token-1", "mgmt0", proposed.clone(), true)
        .await;

    let failures = reconcile_network_runtime_once(
        &desired,
        &journal,
        network.clone(),
        &dhcp,
        None::<&FakeWifiReconciler>,
        None::<&FakeWifiReconciler>,
        None::<&FakeDhcpClientReconciler>,
    )
    .await
    .expect("reconcile");

    assert!(failures.is_empty(), "unexpected failures: {failures:?}");
    assert_eq!(
        network
            .list_ipv4_addresses("mgmt0")
            .await
            .expect("addresses")
            .first()
            .map(|address| address.address),
        Some(Ipv4Addr::new(192, 168, 1, 11))
    );

    // Without the permission the next change to the same interface is
    // refused, which is what makes carrying it meaningful rather than
    // decorative.
    desired.withdraw("token-1").await;
    let unconfirmed = InterfaceConfig {
        ipv4: Some("192.168.1.12/24".parse().expect("network")),
        ..proposed
    };
    desired
        .propose("token-2", "mgmt0", unconfirmed, false)
        .await;
    let failures = reconcile_network_runtime_once(
        &desired,
        &journal,
        network.clone(),
        &dhcp,
        None::<&FakeWifiReconciler>,
        None::<&FakeWifiReconciler>,
        None::<&FakeDhcpClientReconciler>,
    )
    .await
    .expect("reconcile");
    assert!(failures.contains_key("mgmt0"));
}

/// Cleanup is a state, not an edge: an address tagged as ours on an
/// interface we are not asked to manage is removed whenever convergence
/// notices it, not only on the apply that stopped managing it.
#[tokio::test]
async fn convergence_takes_our_addresses_off_an_unmanaged_interface() {
    let mut config = AppConfig::default();
    config.network.interfaces.insert(
        "lan0".to_string(),
        InterfaceConfig {
            nat: true,
            role: InterfaceRole::Output,
            managed: false,
            ipv4: None,
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        },
    );
    let state_dir = tempdir().expect("state dir");
    let overrides = RuntimeOverrideManager::load(state_dir.path(), &config)
        .await
        .expect("overrides");
    let network = Arc::new(FakeNetworkProvider::default());
    network
        .add_interface_with_state(
            "lan0",
            7,
            true,
            vec![
                Ipv4AddressInfo {
                    interface_index: 7,
                    address: Ipv4Addr::new(192, 168, 77, 1),
                    prefix_len: 24,
                    protocol: AddressOwnership::Static.protocol(),
                },
                Ipv4AddressInfo {
                    interface_index: 7,
                    address: Ipv4Addr::new(10, 0, 0, 5),
                    prefix_len: 24,
                    protocol: None,
                },
            ],
        )
        .await;
    let dhcp = FakeDhcpReconciler::default();

    reconcile_network_runtime_once(
        &DesiredNetworkState::new(config.clone(), overrides.clone()),
        &AddressOwnershipJournal::in_memory(),
        network.clone(),
        &dhcp,
        None::<&FakeWifiReconciler>,
        None::<&FakeWifiReconciler>,
        None::<&FakeDhcpClientReconciler>,
    )
    .await
    .expect("reconcile");

    let addresses = network
        .list_ipv4_addresses("lan0")
        .await
        .expect("addresses");
    assert_eq!(
        addresses
            .iter()
            .map(|address| address.address)
            .collect::<Vec<_>>(),
        vec![Ipv4Addr::new(10, 0, 0, 5)],
        "only addresses we tagged as ours may be removed"
    );
}

#[tokio::test]
async fn reconcile_skips_wifi_liveness_when_wifi_is_disabled() {
    let config = hotplug_reconcile_config();
    let state_dir = tempdir().expect("state dir");
    let overrides = RuntimeOverrideManager::load(state_dir.path(), &config)
        .await
        .expect("overrides");
    let network = Arc::new(FakeNetworkProvider::default());
    let dhcp = FakeDhcpReconciler::default();

    reconcile_network_runtime_once(
        &DesiredNetworkState::new(config.clone(), overrides.clone()),
        &AddressOwnershipJournal::in_memory(),
        network,
        &dhcp,
        None::<&FakeWifiReconciler>,
        None::<&FakeWifiReconciler>,
        None::<&FakeDhcpClientReconciler>,
    )
    .await
    .expect("reconcile");
}

#[tokio::test]
async fn liveness_checks_the_wifi_client_independently_of_the_access_point() {
    let dhcp = FakeDhcpReconciler::default();
    let wifi_client = FakeWifiReconciler::default();

    check_process_liveness(
        &dhcp,
        None::<&FakeWifiReconciler>,
        Some(&wifi_client),
        None::<&FakeDhcpClientReconciler>,
    )
    .await;

    assert_eq!(*wifi_client.liveness_checks.lock().await, 1);
    assert_eq!(*dhcp.runtime_liveness_checks.lock().await, 1);
}

#[tokio::test]
async fn liveness_covers_every_supervised_runtime() {
    let dhcp = FakeDhcpReconciler::default();
    let wifi = FakeWifiReconciler::default();
    let wifi_client = FakeWifiReconciler::default();
    let dhcp_client = FakeDhcpClientReconciler::default();

    check_process_liveness(&dhcp, Some(&wifi), Some(&wifi_client), Some(&dhcp_client)).await;

    assert_eq!(*dhcp.runtime_liveness_checks.lock().await, 1);
    assert_eq!(*wifi.liveness_checks.lock().await, 1);
    assert_eq!(*wifi_client.liveness_checks.lock().await, 1);
    assert_eq!(
        *dhcp_client.liveness_checks.lock().await,
        1,
        "every supervised runtime means every one: the DHCP client was the \
         one left behind in the convergence pass"
    );
}

#[tokio::test]
async fn liveness_resynchronizes_wifi_association_into_dhcp_link_ready() {
    let dhcp = FakeDhcpReconciler::default();
    let wifi_client = FakeWifiReconciler::default();
    let dhcp_client = FakeDhcpClientReconciler::default();
    let spec = DhcpClientSpec {
        interface: "wlan0".into(),
        route_metric: 100,
        install_default_route: true,
        request_dns: true,
        send_release_on_shutdown: false,
    };
    dhcp_client
        .specs
        .lock()
        .await
        .insert(spec.interface.clone(), spec.clone());
    wifi_client
        .associations
        .lock()
        .await
        .insert(spec.interface.clone(), true);

    check_process_liveness(
        &dhcp,
        None::<&FakeWifiReconciler>,
        Some(&wifi_client),
        Some(&dhcp_client),
    )
    .await;

    assert_eq!(
        dhcp_client.readiness.lock().await.as_slice(),
        &[("wlan0".to_string(), true)]
    );
}

fn dhcp_client_reconcile_config() -> AppConfig {
    let mut config = hotplug_reconcile_config();
    config.network.interfaces.insert(
        "wan0".to_string(),
        InterfaceConfig {
            nat: true,
            role: InterfaceRole::Input,
            managed: true,
            ipv4: None,
            dhcp: None,
            dhcp_client: Some(crate::config::DhcpClientInterfaceConfig::default()),
            wifi: None,
            wifi_client: None,
        },
    );
    config
}

#[tokio::test]
async fn runtime_reconcile_declares_a_dhcp_client_once_and_stays_stable() {
    let config = dhcp_client_reconcile_config();
    let state_dir = tempdir().expect("state dir");
    let overrides = RuntimeOverrideManager::load(state_dir.path(), &config)
        .await
        .expect("overrides");
    let network = Arc::new(FakeNetworkProvider::default());
    let dynamic = Ipv4AddressInfo {
        interface_index: 9,
        address: Ipv4Addr::new(192, 0, 2, 42),
        prefix_len: 24,
        protocol: None,
    };
    network
        .add_interface_with_state("wan0", 9, true, vec![dynamic.clone()])
        .await;
    let dhcp = FakeDhcpReconciler::default();
    let dhcp_client = FakeDhcpClientReconciler::default();

    for _ in 0..3 {
        reconcile_network_runtime_once(
            &DesiredNetworkState::new(config.clone(), overrides.clone()),
            &AddressOwnershipJournal::in_memory(),
            network.clone(),
            &dhcp,
            None::<&FakeWifiReconciler>,
            None::<&FakeWifiReconciler>,
            Some(&dhcp_client),
        )
        .await
        .expect("reconcile");
    }

    assert_eq!(dhcp_client.reconcile_calls.lock().await.len(), 1);
    assert!(dhcp_client.disable_calls.lock().await.is_empty());
    assert_eq!(
        *dhcp_client.liveness_checks.lock().await,
        0,
        "convergence must not poll for process liveness; that is a separate concern"
    );

    assert_eq!(
        network
            .list_ipv4_addresses("wan0")
            .await
            .expect("addresses"),
        vec![dynamic]
    );

    assert!(dhcp
        .configure_calls
        .lock()
        .await
        .iter()
        .all(|spec| spec.interface != "wan0"));
}

#[tokio::test]
async fn convergence_releases_access_point_before_starting_station() {
    struct RadioRuntime {
        ap: bool,
        ap_running: Arc<Mutex<bool>>,
    }
    #[async_trait]
    impl WifiRuntimeReconciler for RadioRuntime {
        async fn ensure_alive(&self) -> Result<bool> {
            Ok(false)
        }
        async fn reconcile_interface(&self, _: &str, config: &InterfaceConfig) -> Result<()> {
            let mut running = self.ap_running.lock().await;
            if self.ap {
                *running = config.wifi.is_some();
            } else if config.wifi_client.is_some() {
                anyhow::ensure!(!*running, "radio is still owned by hostapd");
            }
            Ok(())
        }
        async fn association_ready(&self, _: &str) -> Option<bool> {
            Some(true)
        }
    }
    let mut config = dhcp_client_reconcile_config();
    config.network.interfaces.remove("lan0");
    config
        .network
        .interfaces
        .get_mut("wan0")
        .unwrap()
        .wifi_client = Some(crate::config::WifiClientConfig {
        ssid: "upstream".into(),
        country_code: None,
        security: crate::config::WifiClientSecurity::Open,
        passphrase_file: None,
    });
    let directory = tempdir().unwrap();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let desired = DesiredNetworkState::new(config.clone(), overrides);
    desired
        .propose(
            "switch",
            "wan0",
            config.network.interfaces["wan0"].clone(),
            true,
        )
        .await;
    let network = Arc::new(FakeNetworkProvider::default());
    network.add_interface("wan0", 9).await;
    let running = Arc::new(Mutex::new(true));
    let ap = RadioRuntime {
        ap: true,
        ap_running: running.clone(),
    };
    let station = RadioRuntime {
        ap: false,
        ap_running: running.clone(),
    };
    let failures = reconcile_network_runtime_once(
        &desired,
        &AddressOwnershipJournal::in_memory(),
        network,
        &FakeDhcpReconciler::default(),
        Some(&ap),
        Some(&station),
        Some(&FakeDhcpClientReconciler::default()),
    )
    .await
    .unwrap();
    assert!(failures.is_empty(), "{failures:?}");
    assert!(!*running.lock().await);
}

#[tokio::test]
async fn managed_wifi_dhcp_tracks_completed_while_wired_stays_ready() {
    let mut config = dhcp_client_reconcile_config();
    let wifi = config.network.interfaces.get_mut("wan0").expect("wan0");
    wifi.wifi_client = Some(crate::config::WifiClientConfig {
        ssid: "upstream".to_string(),
        country_code: None,
        security: crate::config::WifiClientSecurity::Open,
        passphrase_file: None,
    });
    config.network.interfaces.insert(
        "eth0".to_string(),
        InterfaceConfig {
            nat: true,
            role: InterfaceRole::Input,
            managed: true,
            ipv4: None,
            dhcp: None,
            dhcp_client: Some(crate::config::DhcpClientInterfaceConfig::default()),
            wifi: None,
            wifi_client: None,
        },
    );
    let state_dir = tempdir().expect("state dir");
    let overrides = RuntimeOverrideManager::load(state_dir.path(), &config)
        .await
        .expect("overrides");
    let network = Arc::new(FakeNetworkProvider::default());
    network.add_interface("wan0", 9).await;
    network.add_interface("eth0", 10).await;
    let dhcp = FakeDhcpReconciler::default();
    let wifi_client = FakeWifiReconciler::default();
    wifi_client
        .associations
        .lock()
        .await
        .insert("wan0".to_string(), false);
    let dhcp_client = FakeDhcpClientReconciler::default();

    reconcile_network_runtime_once(
        &DesiredNetworkState::new(config.clone(), overrides.clone()),
        &AddressOwnershipJournal::in_memory(),
        network.clone(),
        &dhcp,
        None::<&FakeWifiReconciler>,
        Some(&wifi_client),
        Some(&dhcp_client),
    )
    .await
    .expect("disconnected reconcile");
    assert!(dhcp_client
        .readiness
        .lock()
        .await
        .contains(&("wan0".to_string(), false)));
    assert!(dhcp_client
        .readiness
        .lock()
        .await
        .contains(&("eth0".to_string(), true)));

    wifi_client
        .associations
        .lock()
        .await
        .insert("wan0".to_string(), true);
    reconcile_network_runtime_once(
        &DesiredNetworkState::new(config.clone(), overrides.clone()),
        &AddressOwnershipJournal::in_memory(),
        network,
        &dhcp,
        None::<&FakeWifiReconciler>,
        Some(&wifi_client),
        Some(&dhcp_client),
    )
    .await
    .expect("completed reconcile");
    assert_eq!(
        dhcp_client
            .readiness
            .lock()
            .await
            .iter()
            .filter(|(interface, ready)| interface == "wan0" && *ready)
            .count(),
        1
    );
}

#[tokio::test]
async fn runtime_reconcile_disables_a_dhcp_client_whose_intent_was_removed() {
    let config = hotplug_reconcile_config();
    let state_dir = tempdir().expect("state dir");
    let overrides = RuntimeOverrideManager::load(state_dir.path(), &config)
        .await
        .expect("overrides");
    let network = Arc::new(FakeNetworkProvider::default());
    network.add_interface("wan0", 9).await;
    let dhcp = FakeDhcpReconciler::default();
    let dhcp_client = FakeDhcpClientReconciler::default();

    let spec = DhcpClientSpec::from_interface_config(
        "wan0",
        dhcp_client_reconcile_config()
            .network
            .interfaces
            .get("wan0")
            .expect("wan0 config"),
    )
    .expect("spec")
    .expect("dhcp client enabled");
    dhcp_client
        .specs
        .lock()
        .await
        .insert("wan0".to_string(), spec);

    let mut config = config;
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

    reconcile_network_runtime_once(
        &DesiredNetworkState::new(config.clone(), overrides.clone()),
        &AddressOwnershipJournal::in_memory(),
        network,
        &dhcp,
        None::<&FakeWifiReconciler>,
        None::<&FakeWifiReconciler>,
        Some(&dhcp_client),
    )
    .await
    .expect("reconcile");

    assert_eq!(
        dhcp_client.disable_calls.lock().await.as_slice(),
        &["wan0".to_string()]
    );
    assert!(dhcp_client.specs.lock().await.is_empty());
}

#[tokio::test]
async fn runtime_reconcile_disables_stale_dhcp_when_interface_disappears() {
    let config = hotplug_reconcile_config();
    let state_dir = tempdir().expect("state dir");
    let overrides = RuntimeOverrideManager::load(state_dir.path(), &config)
        .await
        .expect("overrides");
    let dhcp = FakeDhcpReconciler::default();
    let spec = DhcpServiceSpec::from_interface_config(
        "lan0",
        config.network.interfaces.get("lan0").expect("lan0 config"),
        config.dhcp.default_lease_seconds,
    )
    .expect("spec")
    .expect("dhcp enabled");
    dhcp.specs.lock().await.insert("lan0".to_string(), spec);
    let network = Arc::new(FakeNetworkProvider::default());

    reconcile_network_runtime_once(
        &DesiredNetworkState::new(config.clone(), overrides.clone()),
        &AddressOwnershipJournal::in_memory(),
        network,
        &dhcp,
        None::<&HostapdSupervisor>,
        None::<&WifiClientSupervisor>,
        None::<&FakeDhcpClientReconciler>,
    )
    .await
    .expect("reconcile");

    assert_eq!(
        dhcp.disable_calls.lock().await.as_slice(),
        &["lan0".to_string()]
    );
    assert!(dhcp.specs.lock().await.is_empty());
}

fn desired_with_route_and_dataplane() -> RouterDesired {
    let mut config = AppConfig::default();
    config.network.interfaces.insert(
        "wan0".to_string(),
        crate::config::InterfaceConfig {
            nat: true,
            role: crate::config::InterfaceRole::Input,
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
        crate::config::InterfaceConfig {
            nat: true,
            role: crate::config::InterfaceRole::Output,
            managed: true,
            ipv4: Some("192.168.10.1/24".parse().expect("network")),
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        },
    );
    config.router = RouterConfig {
        forwarding: None,
        vpn_chain: Vec::new(),
        enabled: true,
        uplink: Some(UplinkConfig {
            interface: "wan0".to_string(),
            mode: UplinkMode::External,
        }),
        owned_routes: vec![crate::config::OwnedIpv4RouteConfig {
            destination: "203.0.113.0/24".parse().expect("route"),
            gateway: None,
            output_interface: Some("wan0".to_string()),
            table: 254,
            metric: Some(100),
        }],
        allow_default_route_change: false,
    };
    RouterDesired::from_effective_config(&config).expect("desired")
}

#[tokio::test]
async fn apply_router_dataplane_applies_routes_then_dataplane() {
    let network = Arc::new(FakeNetworkProvider::default());
    network.add_interface("wan0", 1).await;
    network.add_interface("lan0", 2).await;
    let desired = desired_with_route_and_dataplane();

    let state = apply_router_dataplane(&desired, network.clone(), FakeDataplaneProvider::default())
        .await
        .expect("apply");

    assert_eq!(network.routes.lock().await.len(), 1);
    assert!(state
        .dataplane
        .snapshot()
        .await
        .expect("snapshot")
        .owned
        .is_some());

    assert!(state.dataplane_snapshot.owned.is_none());
}

#[tokio::test]
async fn dataplane_apply_failure_rolls_back_routes_without_leaving_partial_state() {
    let network = Arc::new(FakeNetworkProvider::default());
    network.add_interface("wan0", 1).await;
    network.add_interface("lan0", 2).await;
    let desired = desired_with_route_and_dataplane();
    let dataplane_provider = FakeDataplaneProvider::default();
    *dataplane_provider.fail_next_apply.lock().await = true;

    let error = apply_router_dataplane(&desired, network.clone(), dataplane_provider)
        .await
        .map(|_| ())
        .expect_err("dataplane apply must fail");
    assert!(format!("{error:#}").contains("injected dataplane apply failure"));
    assert!(network.routes.lock().await.is_empty());
}

#[tokio::test]
async fn missing_dataplane_interface_defers_startup_without_leaving_partial_state() {
    let network = Arc::new(FakeNetworkProvider::default());
    network.add_interface("wan0", 1).await;
    network.add_interface("lan0", 2).await;
    let desired = desired_with_route_and_dataplane();
    let dataplane_provider = FakeDataplaneProvider::default();
    *dataplane_provider.missing_next_apply.lock().await =
        Some(("egress".to_string(), "wlan0".to_string()));

    let state = apply_router_dataplane(&desired, network.clone(), dataplane_provider)
        .await
        .expect("missing interface must defer startup");

    assert!(network.routes.lock().await.is_empty());
    assert!(state
        .dataplane
        .snapshot()
        .await
        .expect("snapshot")
        .owned
        .is_none());
    assert!(state.dataplane_snapshot.owned.is_none());

    // Once the adapter returns, the deferred target can be applied without
    // restarting the daemon, and shutdown still restores the original baseline.
    let plan = state
        .dataplane
        .plan_target(desired.dataplane.clone())
        .await
        .unwrap();
    state.dataplane.apply(&plan).await.unwrap();
    assert!(state.dataplane.snapshot().await.unwrap().owned.is_some());
    restore_router_dataplane(&state).await.unwrap();
    assert!(state.dataplane.snapshot().await.unwrap().owned.is_none());
}

#[tokio::test]
async fn rollback_router_dataplane_restores_pre_apply_baseline() {
    let network = Arc::new(FakeNetworkProvider::default());
    network.add_interface("wan0", 1).await;
    network.add_interface("lan0", 2).await;
    let desired = desired_with_route_and_dataplane();

    let state = apply_router_dataplane(&desired, network.clone(), FakeDataplaneProvider::default())
        .await
        .expect("apply");
    assert_eq!(network.routes.lock().await.len(), 1);

    rollback_router_dataplane(&state).await;

    assert!(network.routes.lock().await.is_empty());
    assert!(state
        .dataplane
        .snapshot()
        .await
        .expect("snapshot")
        .owned
        .is_none());
}

#[tokio::test]
async fn apply_vpn_policy_startup_is_noop_when_vpn_is_disabled() {
    let config = vpn_policy_startup_config();
    let state_dir = tempdir().expect("state dir");
    let overrides = RuntimeOverrideManager::load(state_dir.path(), &config)
        .await
        .expect("overrides");
    let network = Arc::new(FakeNetworkProvider::default());

    let firewall_executor = FakeNftExecutor::with_responses(vec![]);

    apply_vpn_policy_startup(
        &config,
        &overrides,
        network.clone(),
        firewall_executor,
        &None,
    )
    .await;

    assert!(network.rules.lock().await.is_empty());
    assert!(network.routes.lock().await.is_empty());
}

#[tokio::test]
async fn apply_vpn_policy_startup_does_not_touch_legacy_policy_when_router_chain_exists() {
    let mut config = vpn_policy_startup_config();
    config.router.vpn_chain = vec![crate::config::VpnHopConfig {
        profile_name: "chain.conf".to_string(),
    }];
    let state_dir = tempdir().expect("state dir");
    let overrides = RuntimeOverrideManager::load(state_dir.path(), &config)
        .await
        .expect("overrides");
    overrides
        .set_vpn_mode(crate::config::VpnPolicyMode::Vpn)
        .await
        .expect("persist vpn mode");

    let network = Arc::new(FakeNetworkProvider::default());
    network.add_interface(OWNED_INTERFACE_NAME, 42).await;
    let firewall_executor = FakeNftExecutor::with_responses(vec![
        Ok(nft_ruleset(None)),
        Ok(nft_ruleset(None)),
        Ok(Vec::new()),
    ]);
    let (tunnel, _dir) = fake_vpn_manager();
    tunnel
        .import_profile("home.conf", valid_vpn_profile().as_bytes())
        .expect("import");
    tunnel.activate("home.conf").await.expect("tunnel activate");
    let vpn_manager = Some(tunnel);

    apply_vpn_policy_startup(
        &config,
        &overrides,
        network.clone(),
        firewall_executor,
        &vpn_manager,
    )
    .await;

    assert!(network.rules.lock().await.is_empty());
    assert!(network.routes.lock().await.is_empty());
}

#[tokio::test]
async fn apply_vpn_policy_startup_activates_policy_in_vpn_mode_when_tunnel_is_healthy() {
    let config = vpn_policy_startup_config();
    let state_dir = tempdir().expect("state dir");
    let overrides = RuntimeOverrideManager::load(state_dir.path(), &config)
        .await
        .expect("overrides");
    overrides
        .set_vpn_mode(crate::config::VpnPolicyMode::Vpn)
        .await
        .expect("persist vpn mode");

    let network = Arc::new(FakeNetworkProvider::default());
    network.add_interface(OWNED_INTERFACE_NAME, 42).await;

    let firewall_executor = FakeNftExecutor::with_responses(vec![
        Ok(nft_ruleset(None)),
        Ok(nft_ruleset(None)),
        Ok(Vec::new()),
    ]);
    let (tunnel, _dir) = fake_vpn_manager();
    tunnel
        .import_profile("home.conf", valid_vpn_profile().as_bytes())
        .expect("import");
    tunnel.activate("home.conf").await.expect("tunnel activate");
    let vpn_manager = Some(tunnel);

    apply_vpn_policy_startup(
        &config,
        &overrides,
        network.clone(),
        firewall_executor,
        &vpn_manager,
    )
    .await;

    let rules = network.rules.lock().await;
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].fw_mark, Some(0x5400_0000));
    let routes = network.routes.lock().await;
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].output_interface_index, Some(42));
}

#[tokio::test]
async fn apply_vpn_policy_startup_fails_closed_when_tunnel_is_not_active() {
    let config = vpn_policy_startup_config();
    let state_dir = tempdir().expect("state dir");
    let overrides = RuntimeOverrideManager::load(state_dir.path(), &config)
        .await
        .expect("overrides");
    overrides
        .set_vpn_mode(crate::config::VpnPolicyMode::Vpn)
        .await
        .expect("persist vpn mode");

    let network = Arc::new(FakeNetworkProvider::default());
    network.add_interface(OWNED_INTERFACE_NAME, 42).await;

    let firewall_executor = FakeNftExecutor::with_responses(vec![]);
    let (tunnel, _dir) = fake_vpn_manager();

    let vpn_manager = Some(tunnel);

    apply_vpn_policy_startup(
        &config,
        &overrides,
        network.clone(),
        firewall_executor,
        &vpn_manager,
    )
    .await;

    assert!(network.rules.lock().await.is_empty());
    assert!(network.routes.lock().await.is_empty());
}

#[tokio::test]
async fn apply_vpn_policy_startup_deactivates_leftover_policy_in_direct_mode() {
    let config = vpn_policy_startup_config();
    let state_dir = tempdir().expect("state dir");
    let overrides = RuntimeOverrideManager::load(state_dir.path(), &config)
        .await
        .expect("overrides");

    let network = Arc::new(FakeNetworkProvider::default());
    network.rules.lock().await.push(Ipv4RuleInfo {
        source: None,
        destination: None,
        table: 30_100,
        priority: Some(10_100),
        fw_mark: Some(0x5400_0000),
        fw_mask: Some(0xff00_0000),
        input_interface: None,
        output_interface: None,
    });
    network.routes.lock().await.push(Ipv4RouteInfo {
        destination: "0.0.0.0/0".parse().unwrap(),
        gateway: None,
        output_interface_index: Some(999),
        table: 30_100,
        metric: Some(50),
        protocol: crate::netlink::TRAFFIC_MASQ_ROUTE_PROTOCOL,
        scope: 253,
    });
    let leftover_firewall = crate::firewall::vpn::VpnPolicyFirewallDesired {
        protected_subnets: vec!["192.168.10.0/24".parse().unwrap()],
        vpn_interface: OWNED_INTERFACE_NAME.to_string(),
        physical_uplink: "wan0".to_string(),
    };

    let firewall_executor = FakeNftExecutor::with_responses(vec![
        Ok(nft_ruleset(Some(&leftover_firewall))),
        Ok(nft_ruleset(Some(&leftover_firewall))),
        Ok(Vec::new()),
    ]);
    let (tunnel, _dir) = fake_vpn_manager();
    let vpn_manager = Some(tunnel);

    apply_vpn_policy_startup(
        &config,
        &overrides,
        network.clone(),
        firewall_executor,
        &vpn_manager,
    )
    .await;

    assert!(network.rules.lock().await.is_empty());
    assert!(network.routes.lock().await.is_empty());
}

#[tokio::test]
async fn preflight_accepts_a_runnable_binary() {
    let binary = if std::path::Path::new("/bin/true").exists() {
        "/bin/true"
    } else {
        "/bin/sh"
    };
    preflight_hostapd_binary(Path::new(binary))
        .await
        .expect("a real, executable binary must pass preflight");
}

#[tokio::test]
async fn preflight_reports_a_missing_binary_clearly() {
    let error = preflight_hostapd_binary(Path::new("/definitely/not/a/real/hostapd"))
        .await
        .expect_err("a nonexistent binary must fail preflight");
    let message = format!("{error:#}");
    assert!(message.contains("hostapd"), "{message}");
    assert!(
        message.contains("/definitely/not/a/real/hostapd"),
        "{message}"
    );
}

/// `wifi.enabled = false` must not decide, for the lifetime of the process,
/// that Wi-Fi can never be turned on. The supervisor is built anyway; the
/// flag only decides whether a missing binary is reported at startup.
#[tokio::test]
async fn wifi_supervisor_is_built_even_when_wifi_is_disabled_at_startup() {
    let directory = tempdir().expect("tempdir");
    let mut config = AppConfig::default();
    config.runtime.state_dir = directory.path().join("state");
    config.wifi.enabled = false;
    config.wifi.hostapd_binary = std::path::PathBuf::from("/definitely/not/a/real/hostapd");

    let supervisor = build_wifi_supervisor(&config)
        .await
        .expect("a missing binary must not fail startup while Wi-Fi is off")
        .expect("the supervisor must exist so Wi-Fi can be enabled at runtime");

    // The check the flag used to gate now happens where the intent is real.
    assert!(
        supervisor.preflight_binary().await.is_err(),
        "a missing hostapd must still be diagnosed, just later"
    );
}

/// The startup hint half of the same rule: a box that declares it uses
/// Wi-Fi still finds out about a missing binary immediately.
#[tokio::test]
async fn a_missing_hostapd_still_fails_startup_when_wifi_is_enabled() {
    let mut config = AppConfig::default();
    config.wifi.enabled = true;
    config.wifi.hostapd_binary = std::path::PathBuf::from("/definitely/not/a/real/hostapd");

    assert!(build_wifi_supervisor(&config).await.is_err());
}

#[tokio::test]
async fn wifi_client_supervisor_is_built_even_when_disabled_at_startup() {
    let directory = tempdir().expect("tempdir");
    let mut config = AppConfig::default();
    config.runtime.state_dir = directory.path().join("state");
    config.wifi_client.enabled = false;
    config.wifi_client.wpa_supplicant_binary =
        std::path::PathBuf::from("/definitely/not/a/real/wpa_supplicant");

    let supervisor = build_wifi_client_supervisor(&config)
        .await
        .expect("a missing binary must not fail startup while the client is off")
        .expect("the supervisor must exist so the client can be enabled at runtime");

    assert!(supervisor.preflight_binary().await.is_err());
}

#[tokio::test]
async fn router_startup_repair_waits_for_missing_lan_and_uplink() {
    let network = FakeNetworkProvider::default();
    let desired = desired_with_route_and_dataplane();
    assert_eq!(
        missing_router_repair_interfaces(&desired, &network)
            .await
            .unwrap(),
        vec!["lan0", "wan0"]
    );
    network.add_interface("wan0", 1).await;
    assert_eq!(
        missing_router_repair_interfaces(&desired, &network)
            .await
            .unwrap(),
        vec!["lan0"]
    );
    network.add_interface("lan0", 2).await;
    assert!(missing_router_repair_interfaces(&desired, &network)
        .await
        .unwrap()
        .is_empty());
    // Presence, not link readiness: a down interface can be raised by repair.
    assert!(network.routes.lock().await.is_empty());
}

#[tokio::test]
async fn runtime_retries_startup_recovery_after_replug_without_replaying_live_journals() {
    let directory = tempdir().unwrap();
    let mut config = AppConfig::default();
    config.runtime.state_dir = directory.path().to_path_buf();
    config.network.interfaces.insert(
        "eth0".into(),
        InterfaceConfig {
            role: InterfaceRole::None,
            managed: false,
            ipv4: None,
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
            nat: false,
        },
    );
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let desired = DesiredNetworkState::new(config, overrides.clone());
    let network = Arc::new(FakeNetworkProvider::default());
    let ownership = AddressOwnershipJournal::in_memory();
    let manager = InterfaceManager::new(network.clone(), ownership.clone());
    let store = crate::state::private_store::PrivateJsonDirectory::open(
        directory.path(),
        "interface-transactions",
    )
    .unwrap();
    let snapshot = crate::core::interface::InterfaceSnapshot {
        name: "eth0".into(),
        was_up: true,
        ipv4_addresses: Vec::new(),
    };
    store
        .write(
            "eth0",
            &serde_json::to_vec(&serde_json::json!({
                "version": 2, "token": "interrupted", "snapshot": snapshot,
            }))
            .unwrap(),
        )
        .unwrap();
    let wifi_runtime_dirs = crate::wifi::WifiRuntimeDirs::new(
        "/run/traffic-masq/hostapd",
        "/run/traffic-masq/wpa_supplicant",
    );
    crate::core::transaction::recover_interface_transactions(
        directory.path(),
        &manager,
        &overrides.snapshot().await,
        &wifi_runtime_dirs,
    )
    .await
    .unwrap();
    assert!(crate::core::recovery::check_scope(directory.path(), Some("eth0")).is_err());
    // This appeared after startup and belongs to a live transaction. A retry
    // must neither parse it nor retire it, even while another interface recovers.
    store.write("live0", b"live transaction journal").unwrap();
    let dhcp = FakeDhcpReconciler::default();
    for present in [false, true] {
        if present {
            network
                .add_interface_with_state("eth0", 1, false, Vec::new())
                .await;
        }
        let failures = reconcile_network_runtime_once(
            &desired,
            &ownership,
            network.clone(),
            &dhcp,
            None::<&FakeWifiReconciler>,
            None::<&FakeWifiReconciler>,
            None::<&FakeDhcpClientReconciler>,
        )
        .await
        .unwrap();
        assert_eq!(failures.is_empty(), present, "{failures:?}");
        assert_eq!(
            crate::core::recovery::check_scope(directory.path(), Some("eth0")).is_ok(),
            present
        );
        assert_eq!(store.read("eth0").unwrap().is_none(), present);
        assert_eq!(
            store.read("live0").unwrap().unwrap(),
            b"live transaction journal"
        );
        assert!(crate::core::recovery::check_scope(directory.path(), Some("live0")).is_ok());
    }
    assert!(network.list_interfaces().await.unwrap()[0].is_up);
}

#[test]
fn unrelated_interface_recovery_never_downgrades_fatal_router_recovery() {
    let dir = tempdir().expect("tempdir");
    crate::core::recovery::block_interface(dir.path(), "wlan0", "invalid snapshot".into());
    assert!(crate::core::recovery::check_scope(dir.path(), None).is_err());
    assert!(!router_recovery_allows_degraded_startup(
        crate::core::router_transaction::CoordinatorStatus::Idle,
        false,
    ));
    crate::core::recovery::unblock_interface(dir.path(), "wlan0");
}

#[test]
fn explicit_router_recovery_states_may_keep_control_plane_available() {
    use crate::core::router_transaction::CoordinatorStatus;

    assert!(router_recovery_allows_degraded_startup(
        CoordinatorStatus::RollbackFailed,
        false,
    ));
    assert!(router_recovery_allows_degraded_startup(
        CoordinatorStatus::Idle,
        true,
    ));
    assert!(router_recovery_allows_degraded_startup(
        CoordinatorStatus::RecoveredButJournalCleanupPending,
        false,
    ));
}

#[tokio::test]
async fn hotplug_phy_conflict_blocks_reconciliation_before_interface_mutation() {
    let mut config = hotplug_reconcile_config();
    config.network.interfaces.get_mut("lan0").unwrap().wifi = Some(
        serde_json::from_value(serde_json::json!({
            "ssid": "ap", "channel": 6, "security": "open"
        }))
        .unwrap(),
    );
    let mut client = config.network.interfaces["lan0"].clone();
    client.role = InterfaceRole::Input;
    client.wifi = None;
    client.wifi_client = Some(crate::config::WifiClientConfig {
        ssid: "sta".into(),
        country_code: None,
        security: crate::config::WifiClientSecurity::Open,
        passphrase_file: None,
    });
    client.dhcp = None;
    client.ipv4 = Some("192.168.78.1/24".parse().unwrap());
    config.network.interfaces.insert("wan0".into(), client);
    let directory = tempdir().unwrap();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let network = Arc::new(FakeNetworkProvider::default());
    network
        .add_interface_with_state("lan0", 7, false, Vec::new())
        .await;
    network
        .add_interface_with_state("wan0", 8, false, Vec::new())
        .await;
    {
        let mut phys = network.wireless_phys.lock().unwrap();
        phys.insert("lan0".into(), "hotplug-radio".into());
        phys.insert("wan0".into(), "hotplug-radio".into());
    }
    let error = reconcile_network_runtime_once(
        &DesiredNetworkState::new(config, overrides),
        &AddressOwnershipJournal::in_memory(),
        network.clone(),
        &FakeDhcpReconciler::default(),
        None::<&FakeWifiReconciler>,
        None::<&FakeWifiReconciler>,
        None::<&FakeDhcpClientReconciler>,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("hotplug-radio"));
    assert!(network
        .list_interfaces()
        .await
        .unwrap()
        .iter()
        .all(|interface| !interface.is_up));
}
