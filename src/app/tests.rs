use crate::netlink::AddressOwnership;
use std::collections::HashMap;
use std::net::Ipv4Addr;

use async_trait::async_trait;
use tempfile::tempdir;
use tokio::sync::Mutex;

use crate::config::{
    DhcpInterfaceConfig, InterfaceConfig, InterfaceRole, RouterConfig, UplinkConfig, UplinkMode,
    VpnConfig,
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

struct ReconcileReadNetwork {
    failures_remaining: std::sync::atomic::AtomicUsize,
    reads: mpsc::UnboundedSender<()>,
}

#[async_trait]
impl NetworkProvider for ReconcileReadNetwork {
    async fn list_interfaces(&self) -> Result<Vec<crate::netlink::NetworkInterface>> {
        self.reads.send(()).unwrap();
        if self
            .failures_remaining
            .fetch_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |remaining| remaining.checked_sub(1),
            )
            .is_ok()
        {
            anyhow::bail!("injected transient network read failure");
        }
        Ok(Vec::new())
    }

    async fn list_ipv4_addresses(&self, _: &str) -> Result<Vec<Ipv4AddressInfo>> {
        Ok(Vec::new())
    }

    async fn set_link_up(&self, _: &str) -> Result<()> {
        unreachable!("test has no observed interfaces")
    }

    async fn set_link_down(&self, _: &str) -> Result<()> {
        unreachable!("test has no observed interfaces")
    }

    async fn add_ipv4_address(
        &self,
        _: &str,
        _: Ipv4Addr,
        _: u8,
        _: AddressOwnership,
    ) -> Result<()> {
        unreachable!("test has no observed interfaces")
    }

    async fn delete_ipv4_address(&self, _: &str, _: Ipv4Addr, _: u8) -> Result<()> {
        unreachable!("test has no observed interfaces")
    }
}

#[cfg(target_os = "linux")]
struct ReconcileRetryFixture {
    // Isolate recovery notifications from other tests in the same process.
    _kernel_events: mpsc::UnboundedSender<crate::netlink::events::KernelEvent>,
    _recovery_events: watch::Sender<u64>,
    desired: DesiredNetworkState,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<Result<()>>,
    network: Arc<ReconcileReadNetwork>,
    reads: mpsc::UnboundedReceiver<()>,
    _directory: tempfile::TempDir,
}

#[cfg(target_os = "linux")]
impl ReconcileRetryFixture {
    async fn start(failures: usize, missing_interface: bool) -> Self {
        let directory = tempdir().unwrap();
        let mut config = AppConfig::default();
        config.runtime.state_dir = directory.path().to_path_buf();
        config.dhcp.leases_dir = directory.path().join("leases");
        if missing_interface {
            config.network.interfaces.insert(
                "wan0".into(),
                InterfaceConfig {
                    wifi_concurrent: false,
                    mac_address: None,
                    role: InterfaceRole::Input,
                    managed: true,
                    ipv4: None,
                    dhcp: None,
                    dhcp_client: None,
                    wifi: None,
                    wifi_client: None,
                },
            );
        }
        let overrides = RuntimeOverrideManager::load(directory.path(), &config)
            .await
            .unwrap();
        let desired = DesiredNetworkState::new(config.clone(), overrides);
        let (reads_tx, reads) = mpsc::unbounded_channel();
        let network = Arc::new(ReconcileReadNetwork {
            failures_remaining: std::sync::atomic::AtomicUsize::new(failures),
            reads: reads_tx,
        });
        let dhcp = DhcpSupervisor::start(&config).await.unwrap();
        let dhcp_client = DhcpClientSupervisor::start_with_launcher(
            &config,
            network.clone(),
            Arc::new(LinuxDhcpClientLauncher),
        )
        .await
        .unwrap();
        let (kernel_events_tx, kernel_events) = mpsc::unbounded_channel();
        let (recovery_events_tx, recovery_events) = watch::channel(0);
        let (shutdown_tx, shutdown) = watch::channel(false);
        let task = super::reconcile::spawn_runtime_network_reconcile_with_recovery_events(
            desired.clone(),
            AddressOwnershipJournal::in_memory(),
            network.clone(),
            dhcp,
            None,
            None,
            dhcp_client,
            Arc::new(NetworkMutationGate::default()),
            None,
            kernel_events,
            recovery_events,
            shutdown,
        );
        Self {
            _kernel_events: kernel_events_tx,
            _recovery_events: recovery_events_tx,
            desired,
            shutdown: shutdown_tx,
            task,
            network,
            reads,
            _directory: directory,
        }
    }

    async fn wait_for_pass(&mut self) {
        tokio::time::timeout(Duration::from_secs(5), self.reads.recv())
            .await
            .expect("convergence pass should run")
            .expect("network observer stays open");
    }

    async fn advance_to_retry(&mut self, delay: Duration) {
        tokio::time::pause();
        tokio::time::advance(delay / 2).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(matches!(
            self.reads.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        tokio::time::advance(delay / 2 + Duration::from_millis(2)).await;
        // Filesystem work uses the blocking pool; let it finish without the
        // paused clock automatically skipping ahead to the next retry.
        tokio::time::resume();
        self.wait_for_pass().await;
    }

    async fn stop(self) {
        self.shutdown.send(true).unwrap();
        self.task.await.unwrap().unwrap();
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn runtime_reconcile_retries_transient_errors_then_waits_for_events() {
    let mut fixture = ReconcileRetryFixture::start(1, false).await;
    fixture.wait_for_pass().await;
    fixture.advance_to_retry(Duration::from_secs(1)).await;

    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(120)).await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert!(matches!(
        fixture.reads.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    tokio::time::resume();

    // Success resets backoff, and new events still trigger immediate passes.
    fixture
        .network
        .failures_remaining
        .store(1, std::sync::atomic::Ordering::SeqCst);
    fixture
        ._kernel_events
        .send(crate::netlink::events::KernelEvent::Changed)
        .unwrap();
    fixture.wait_for_pass().await;
    fixture.advance_to_retry(Duration::from_secs(1)).await;
    fixture.stop().await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn runtime_reconcile_retries_interface_failures_with_capped_backoff() {
    let mut fixture = ReconcileRetryFixture::start(0, true).await;
    fixture.wait_for_pass().await;
    for seconds in [1, 2, 4, 8, 16, 30, 30] {
        fixture.advance_to_retry(Duration::from_secs(seconds)).await;
    }
    fixture.stop().await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn kernel_notifications_do_not_bypass_failed_reconcile_backoff() {
    let mut fixture = ReconcileRetryFixture::start(0, true).await;
    fixture.wait_for_pass().await;
    for seconds in [1, 2, 4] {
        for _ in 0..100 {
            fixture
                ._kernel_events
                .send(crate::netlink::events::KernelEvent::Changed)
                .unwrap();
        }
        fixture.advance_to_retry(Duration::from_secs(seconds)).await;
    }
    // Operator recovery remains responsive even during a failed-pass backoff.
    fixture._recovery_events.send(1).unwrap();
    fixture.wait_for_pass().await;
    fixture.desired.request_convergence();
    fixture.wait_for_pass().await;
    fixture.advance_to_retry(Duration::from_secs(1)).await;
    fixture.stop().await;
}

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
    reject_readiness: bool,
    readiness_checks: Mutex<usize>,
    specs: Mutex<HashMap<String, DhcpClientSpec>>,
    reconcile_calls: Mutex<Vec<DhcpClientSpec>>,
    readiness: Mutex<Vec<(String, bool)>>,
    disable_calls: Mutex<Vec<String>>,
    liveness_checks: Mutex<usize>,
}

#[async_trait]
impl DhcpClientRuntimeReconciler for FakeDhcpClientReconciler {
    async fn verify_ready(&self, _interface: &str) -> Result<()> {
        *self.readiness_checks.lock().await += 1;
        anyhow::ensure!(!self.reject_readiness, "DHCP server unavailable");
        Ok(())
    }
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

#[derive(Clone)]
struct FakeDataplaneProvider {
    state: Arc<Mutex<RouterDataplaneSnapshot>>,
    fail_next_apply: Arc<Mutex<bool>>,
    missing_next_apply: Arc<Mutex<Option<(String, String)>>>,
    apply_calls: Arc<std::sync::atomic::AtomicUsize>,
    restore_calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl Default for FakeDataplaneProvider {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(RouterDataplaneSnapshot {
                ipv4_forwarding: false,
                owned: None,
                owned_firewall_integrity: OwnedFirewallIntegrity::Intact,
            })),
            fail_next_apply: Arc::new(Mutex::new(false)),
            missing_next_apply: Arc::new(Mutex::new(None)),
            apply_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            restore_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }
}

#[async_trait]
impl RouterDataplaneProvider for FakeDataplaneProvider {
    async fn observe(&self) -> Result<RouterDataplaneSnapshot> {
        Ok(self.state.lock().await.clone())
    }

    async fn apply_owned(&self, desired: &RouterDataplaneDesired) -> Result<()> {
        self.apply_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
        self.restore_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
            wifi_concurrent: false,
            mac_address: None,
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
            wifi_concurrent: false,
            mac_address: None,
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
        uplink: Some(UplinkConfig {
            interface: "wan0".to_string(),
            mode: UplinkMode::External,
        }),
        ..RouterConfig::default()
    };
    config.vpn = VpnConfig {
        standalone: None,
        enabled: true,
        wireguard_config_dir: std::path::PathBuf::from("/var/lib/traffic-masq/vpn/wireguard"),
        wireguard_import_dir: "/etc/wireguard".into(),
        policy: Default::default(),
    };
    config
}

fn hotplug_reconcile_config() -> AppConfig {
    let mut config = AppConfig::default();
    config.network.interfaces.insert(
        "lan0".to_string(),
        InterfaceConfig {
            wifi_concurrent: false,
            mac_address: None,
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
            wifi_concurrent: false,
            mac_address: None,
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
            wifi_concurrent: false,
            mac_address: None,
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
        None,
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

    check_process_liveness(
        None,
        &dhcp,
        Some(&wifi),
        Some(&wifi_client),
        Some(&dhcp_client),
    )
    .await;

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
        hostname: None,
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
        None,
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
            wifi_concurrent: false,
            mac_address: None,
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
            wifi_concurrent: false,
            mac_address: None,
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
            wifi_concurrent: false,
            mac_address: None,
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
            wifi_concurrent: false,
            mac_address: None,
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
            wifi_concurrent: false,
            mac_address: None,
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
        port_forwards: Vec::new(),
        forwarding: Some(vec![traffic_masq_dataplane::ForwardingConfig {
            from: "lan0".into(),
            to: "wan0".into(),
            source_subnet: Some("192.168.10.0/24".parse().unwrap()),
            masquerade: true,
        }]),
        vpn_chain: Vec::new(),
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
        route_host_traffic: false,
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
async fn apply_vpn_policy_startup_does_not_touch_legacy_policy_when_standalone_intent_is_coordinator_owned(
) {
    let mut config = vpn_policy_startup_config();
    config.vpn.standalone = Some(crate::config::StandaloneVpnIntent {
        profile: Some("home.conf".into()),
    });
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
        masquerade_forwarded: true,
        protected_subnets: vec!["192.168.10.0/24".parse().unwrap()],
        vpn_interface: OWNED_INTERFACE_NAME.to_string(),
        physical_uplink: "wan0".to_string(),
        host_traffic: None,
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

    let mut desired = desired;
    desired.routes[0].output_interface = Some("route0".into());
    assert_eq!(
        missing_router_repair_interfaces(&desired, &network)
            .await
            .unwrap(),
        vec!["route0"]
    );
}

fn sharing_config() -> AppConfig {
    let mut config = AppConfig::default();
    for (name, role, ipv4) in [
        ("lan0", InterfaceRole::Output, Some("192.168.88.1/24")),
        ("lan1", InterfaceRole::Output, Some("192.168.111.1/24")),
        ("wan0", InterfaceRole::Input, None),
    ] {
        config.network.interfaces.insert(
            name.into(),
            InterfaceConfig {
                wifi_concurrent: false,
                mac_address: None,
                role,
                managed: true,
                ipv4: ipv4.map(|ip| ip.parse().unwrap()),
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
            },
        );
    }
    config.router.forwarding = Some(
        ["lan0", "lan1"]
            .into_iter()
            .map(|from| crate::config::ForwardingConfig {
                from: from.into(),
                to: "wan0".into(),
                source_subnet: None,
                masquerade: true,
            })
            .collect(),
    );
    config
}

#[tokio::test]
async fn sharing_repair_checks_all_forwarding_interfaces_without_legacy_uplink() {
    let config = sharing_config();
    let desired = RouterDesired::from_effective_config(&config).unwrap();
    assert!(!desired.interfaces.iter().any(|entry| entry.name == "wan0"));
    let network = FakeNetworkProvider::default();
    network.add_interface("lan0", 1).await;
    network.add_interface("lan1", 2).await;
    assert_eq!(
        missing_router_repair_interfaces(&desired, &network)
            .await
            .unwrap(),
        vec!["wan0"]
    );
    network.add_interface("wan0", 3).await;
    assert!(missing_router_repair_interfaces(&desired, &network)
        .await
        .unwrap()
        .is_empty());

    // Explicit rules may also reference interfaces with no managed config,
    // including externally created tunnels. Both endpoints must be observed.
    let mut config = config;
    config.router.forwarding.as_mut().unwrap()[1].from = "external0".into();
    config.router.forwarding.as_mut().unwrap()[1].to = "tun0".into();
    let desired = RouterDesired::from_effective_config(&config).unwrap();
    assert_eq!(
        missing_router_repair_interfaces(&desired, &network)
            .await
            .unwrap(),
        vec!["external0", "tun0"]
    );
    network.add_interface("external0", 4).await;
    network.add_interface("tun0", 5).await;
    assert!(missing_router_repair_interfaces(&desired, &network)
        .await
        .unwrap()
        .is_empty());

    // An empty forwarding list must still permit removal of old firewall rules.
    config.router.forwarding = Some(vec![]);
    let desired = RouterDesired::from_effective_config(&config).unwrap();
    assert!(
        missing_router_repair_interfaces(&desired, &FakeNetworkProvider::default())
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn sharing_repair_defers_before_mutations_and_resumes_after_replug() {
    use crate::core::route::RouteManager;
    use crate::core::router::RouterManager;
    use crate::core::router_subsystems::ProductionRouterSubsystems;
    use crate::core::router_transaction::{CoordinatorStatus, RouterTransactionCoordinator};
    use crate::firewall::RouterDataplaneManager;
    use std::sync::atomic::Ordering;

    let directory = tempdir().unwrap();
    let mut config = sharing_config();
    config.runtime.state_dir = directory.path().to_path_buf();
    config.dhcp.leases_dir = directory.path().join("leases");
    let desired = RouterDesired::from_effective_config(&config).unwrap();
    let network = Arc::new(FakeNetworkProvider::default());
    network.add_interface("lan0", 1).await;
    network.add_interface("lan1", 2).await;
    let provider = FakeDataplaneProvider::default();
    *provider.missing_next_apply.lock().await = Some(("egress".into(), "wan0".into()));
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&config).await.unwrap();
    let subsystems = ProductionRouterSubsystems::new(
        InterfaceManager::new(network.clone(), AddressOwnershipJournal::in_memory()),
        RouteManager::new(network.clone()),
        dhcp,
        RouterDataplaneManager::new(provider.clone()),
        desired
            .interfaces
            .iter()
            .map(|entry| entry.name.clone())
            .collect(),
    );
    let router = RouterTransactionCoordinator::new(
        RouterManager::new(Arc::new(subsystems)),
        overrides.clone(),
        Duration::from_secs(30),
    );
    for _ in 0..3 {
        let error = super::reconcile::reconcile_router_dataplane(
            &router,
            desired.clone(),
            network.as_ref(),
        )
        .await
        .expect_err("missing egress must defer repair before opening a journal");
        assert_eq!(
            crate::firewall::missing_router_dataplane_interface(&error)
                .unwrap()
                .interface,
            "wan0"
        );
        assert_eq!(router.status().await, CoordinatorStatus::Idle);
        assert!(!directory.path().join("router-transaction.json").exists());
    }
    assert_eq!(provider.apply_calls.load(Ordering::SeqCst), 0);
    assert_eq!(provider.restore_calls.load(Ordering::SeqCst), 0);
    assert!(network.routes.lock().await.is_empty());

    // API-driven full repair and narrow repair must reject the missing
    // dependency too, before a journal makes compensation necessary.
    for error in [
        router.repair(desired.clone()).await.unwrap_err(),
        router
            .reconcile_dataplane(desired.clone())
            .await
            .unwrap_err(),
        router.manager().plan(desired.clone()).await.unwrap_err(),
    ] {
        assert_eq!(
            crate::firewall::missing_router_dataplane_interface(&error)
                .unwrap()
                .interface,
            "wan0"
        );
    }
    assert_eq!(provider.apply_calls.load(Ordering::SeqCst), 0);
    assert_eq!(provider.restore_calls.load(Ordering::SeqCst), 0);
    assert!(!directory.path().join("router-transaction.json").exists());

    network.add_interface("wan0", 3).await;
    provider.missing_next_apply.lock().await.take();
    for _ in 0..2 {
        super::reconcile::reconcile_router_dataplane(&router, desired.clone(), network.as_ref())
            .await
            .unwrap();
    }
    assert_eq!(provider.apply_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.restore_calls.load(Ordering::SeqCst), 0);

    // The adapter can disappear between a plan preview and execution. The
    // executor must check again before journaling or touching healthy LANs.
    let candidate = overrides
        .build_candidate(&crate::core::router_candidate::RouterIntentProposal::new())
        .await
        .unwrap();
    let plan = router.plan(candidate).await.unwrap();
    network.interfaces.lock().await.remove("wan0");
    let addresses_before = network.addresses.lock().await.clone();
    let error = router.apply(plan).await.unwrap_err();
    assert_eq!(
        crate::firewall::missing_router_dataplane_interface(&error)
            .unwrap()
            .interface,
        "wan0"
    );
    assert_eq!(*network.addresses.lock().await, addresses_before);
    assert_eq!(provider.apply_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.restore_calls.load(Ordering::SeqCst), 0);
    assert!(!directory.path().join("router-transaction.json").exists());

    // Removing the rules remains possible with the old egress unplugged.
    // Its snapshot can still be restored on rollback: recovery is independent
    // of whether the committed forwarding endpoints are currently present.
    let mut disabled = config.router.clone();
    disabled.forwarding = Some(Vec::new());
    let candidate = overrides
        .build_candidate(
            &crate::core::router_candidate::RouterIntentProposal::new().set_router(disabled),
        )
        .await
        .unwrap();
    let plan = router.plan(candidate).await.unwrap();
    let token = router.apply(plan).await.unwrap();
    assert!(provider.state.lock().await.owned.is_none());
    router.rollback_with_token(&token).await.unwrap();
    assert_eq!(
        provider.state.lock().await.owned,
        match desired.dataplane {
            crate::firewall::RouterDataplaneTarget::Enabled(wanted) => Some(wanted),
            crate::firewall::RouterDataplaneTarget::Disabled => panic!("sharing should be enabled"),
        }
    );
    assert_eq!(router.status().await, CoordinatorStatus::Idle);
}

#[tokio::test]
async fn sharing_ignores_unplugged_unrelated_lan_but_retains_its_dhcp_and_ap_intent() {
    use crate::core::route::RouteManager;
    use crate::core::router::RouterManager;
    use crate::core::router_candidate::RouterIntentProposal;
    use crate::core::router_subsystems::ProductionRouterSubsystems;
    use crate::core::router_transaction::RouterTransactionCoordinator;
    use crate::firewall::{RouterDataplaneManager, RouterDataplaneTarget};

    for with_ap in [false, true] {
        let directory = tempdir().unwrap();
        let mut config = sharing_config();
        config.runtime.state_dir = directory.path().to_path_buf();
        config.dhcp.leases_dir = directory.path().join("leases");
        config
            .router
            .forwarding
            .as_mut()
            .unwrap()
            .retain(|rule| rule.from == "lan0");
        let offline = config.network.interfaces.get_mut("lan1").unwrap();
        offline.dhcp = Some(DhcpInterfaceConfig {
            pool_start: "192.168.111.100".parse().unwrap(),
            pool_end: "192.168.111.150".parse().unwrap(),
            router: "192.168.111.1".parse().unwrap(),
            dns_servers: vec!["1.1.1.1".parse().unwrap()],
            lease_seconds: Some(600),
        });
        if with_ap {
            offline.wifi = Some(serde_json::from_value(serde_json::json!({"ssid": "saved-offline-ap", "security": "open", "channel": 1})).unwrap());
            config.wifi.enabled = true;
        }
        let saved_offline = config.network.interfaces["lan1"].clone();
        let desired = RouterDesired::from_effective_config(&config).unwrap();
        let network = Arc::new(FakeNetworkProvider::default());
        network.add_interface("lan0", 1).await;
        network.add_interface("wan0", 2).await;
        assert!(missing_router_repair_interfaces(&desired, network.as_ref())
            .await
            .unwrap()
            .is_empty());
        let provider = FakeDataplaneProvider::default();
        let overrides = RuntimeOverrideManager::load(directory.path(), &config)
            .await
            .unwrap();
        let dhcp = DhcpSupervisor::start(&config).await.unwrap();
        let subsystems = ProductionRouterSubsystems::new(
            InterfaceManager::new(network.clone(), AddressOwnershipJournal::in_memory()),
            RouteManager::new(network.clone()),
            dhcp,
            RouterDataplaneManager::new(provider.clone()),
            desired
                .interfaces
                .iter()
                .map(|entry| entry.name.clone())
                .collect(),
        );
        let router = RouterTransactionCoordinator::new(
            RouterManager::new(Arc::new(subsystems)),
            overrides.clone(),
            Duration::from_secs(60),
        );

        // Full live Apply/rollback/Commit must work too, not just background repair.
        for commit in [false, true] {
            let candidate = overrides
                .build_candidate(&RouterIntentProposal::new())
                .await
                .unwrap();
            let plan = router.plan(candidate).await.unwrap();
            assert!(plan
                .plan()
                .interfaces
                .iter()
                .all(|entry| entry.interface != "lan1"));
            assert!(plan.plan().dhcp.is_empty());
            assert!(plan.plan().output_wifi.is_empty());
            assert!(router
                .manager()
                .snapshot_for(&desired)
                .await
                .unwrap()
                .interfaces
                .iter()
                .all(|entry| entry.name != "lan1"));
            let token = router.apply(plan).await.unwrap();
            assert!(provider.state.lock().await.ipv4_forwarding);
            assert_eq!(
                provider.state.lock().await.owned.as_ref(),
                match &desired.dataplane {
                    RouterDataplaneTarget::Enabled(value) => Some(value),
                    _ => None,
                }
            );
            if commit {
                router.commit(&token).await.unwrap();
            } else {
                router.rollback_with_token(&token).await.unwrap();
            }
        }
        router.repair(desired.clone()).await.unwrap();
        provider.state.lock().await.owned = None;
        super::reconcile::reconcile_router_dataplane(&router, desired.clone(), network.as_ref())
            .await
            .unwrap();
        assert_eq!(
            overrides.effective_interface("lan1").await.unwrap(),
            Some(saved_offline)
        );
        assert!(router.manager().health(&desired).await.ready());
        assert!(!directory.path().join("router-transaction.json").exists());

        // Removing the last sharing rule must not try to start the saved DHCP
        // service on the missing LAN either; its settings remain independent.
        for enabled in [false, true] {
            let mut sharing = config.router.clone();
            if !enabled {
                sharing.forwarding = Some(Vec::new());
            }
            let candidate = overrides
                .build_candidate(&RouterIntentProposal::new().set_router(sharing))
                .await
                .unwrap();
            let plan = router.plan(candidate).await.unwrap();
            assert!(plan.plan().dhcp.is_empty());
            let token = router.apply(plan).await.unwrap();
            router.commit(&token).await.unwrap();
            assert_eq!(provider.state.lock().await.owned.is_some(), enabled);
        }
        assert_eq!(
            overrides.effective_interface("lan1").await.unwrap(),
            Some(config.network.interfaces["lan1"].clone())
        );

        if !with_ap {
            network.add_interface("lan1", 3).await;
            let plan = router.manager().plan(desired).await.unwrap();
            assert!(plan
                .interfaces
                .iter()
                .any(|entry| entry.interface == "lan1"));
            assert!(plan.dhcp.iter().any(|entry| matches!(entry, crate::core::router::DhcpPlan::Start { desired } if desired.interface == "lan1")));
        }
    }
}

#[tokio::test]
async fn startup_cancels_removed_device_transaction_without_replaying_it_after_replug() {
    let directory = tempdir().unwrap();
    let mut config = AppConfig::default();
    config.runtime.state_dir = directory.path().to_path_buf();
    config.network.interfaces.insert(
        "eth0".into(),
        InterfaceConfig {
            wifi_concurrent: false,
            mac_address: None,
            role: InterfaceRole::None,
            managed: false,
            ipv4: None,
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        },
    );
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let recovery = overrides.recovery().clone();
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
        mac_address: None,
        name: "eth0".into(),
        was_up: true,
        ipv4_addresses: Vec::new(),
    };
    store
        .write(
            "eth0",
            &serde_json::to_vec(&serde_json::json!({
                "version": 3, "token": "interrupted", "snapshot": snapshot,
            }))
            .unwrap(),
        )
        .unwrap();
    let wifi_runtime_dirs = crate::wifi::WifiRuntimeDirs::new(
        "/run/traffic-masq/hostapd",
        "/run/traffic-masq/wpa_supplicant",
    );
    crate::core::transaction::recover_interface_transactions(
        &recovery,
        directory.path(),
        &manager,
        &overrides.snapshot().await,
        &wifi_runtime_dirs,
    )
    .await
    .unwrap();
    assert!(recovery.check_scope(directory.path(), Some("eth0")).is_ok());
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
        assert!(recovery.check_scope(directory.path(), Some("eth0")).is_ok());
        assert!(store.read("eth0").unwrap().is_none());
        assert_eq!(
            store.read("live0").unwrap().unwrap(),
            b"live transaction journal"
        );
        assert!(recovery
            .check_scope(directory.path(), Some("live0"))
            .is_ok());
    }
    // A returned device follows committed unmanaged policy, not a retired
    // snapshot belonging to an earlier incarnation of the link.
    assert!(!network.list_interfaces().await.unwrap()[0].is_up);
}

#[test]
fn unrelated_interface_recovery_never_downgrades_fatal_router_recovery() {
    let recovery = crate::core::recovery::RecoveryState::default();
    let dir = tempdir().expect("tempdir");
    recovery.block_interface(dir.path(), "wlan0", "invalid snapshot".into());
    assert!(recovery.check_scope(dir.path(), None).is_err());
    assert!(!router_recovery_allows_degraded_startup(
        crate::core::router_transaction::CoordinatorStatus::Idle,
        false,
    ));
    recovery.unblock_interface(dir.path(), "wlan0");
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

#[tokio::test]
async fn liveness_does_not_replay_dhcp_association_from_withdrawn_desired_policy() {
    let dhcp = FakeDhcpReconciler::default();
    let wifi = FakeWifiReconciler::default();
    let client = FakeDhcpClientReconciler::default();
    let spec = DhcpClientSpec {
        hostname: None,
        interface: "wlan0".into(),
        route_metric: 100,
        install_default_route: true,
        request_dns: true,
        send_release_on_shutdown: false,
    };
    client.specs.lock().await.insert("wlan0".into(), spec);
    wifi.associations.lock().await.insert("wlan0".into(), true);
    check_process_liveness(
        Some(&AppConfig::default()),
        &dhcp,
        None::<&FakeWifiReconciler>,
        Some(&wifi),
        Some(&client),
    )
    .await;
    assert!(client.readiness.lock().await.is_empty());
}

async fn rollback_without_external_connectivity(device_present: bool) {
    use crate::core::transaction::{InterfaceChange, NetworkTransactionManager};
    let directory = tempdir().unwrap();
    let mut config = AppConfig::default();
    config.runtime.state_dir = directory.path().to_path_buf();
    let previous = InterfaceConfig {
        wifi_concurrent: false,
        mac_address: None,
        role: InterfaceRole::Input,
        managed: true,
        ipv4: None,
        dhcp: None,
        dhcp_client: Some(Default::default()),
        wifi: None,
        wifi_client: Some(crate::config::WifiClientConfig {
            ssid: "unavailable-network".into(),
            country_code: None,
            security: crate::config::WifiClientSecurity::Open,
            passphrase_file: None,
        }),
    };
    config
        .network
        .interfaces
        .insert("wan0".into(), previous.clone());
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let desired = DesiredNetworkState::new(config, overrides);
    let network = Arc::new(FakeNetworkProvider::default());
    network
        .add_interface_with_state("wan0", 7, true, Vec::new())
        .await;
    let journal = AddressOwnershipJournal::in_memory();
    let manager = NetworkTransactionManager::new_detached(
        crate::core::interface::InterfaceManager::new(network.clone(), journal.clone()),
        Duration::from_secs(3600),
        desired.clone(),
    );
    let mut candidate = previous.clone();
    candidate.dhcp_client = None;
    candidate.wifi_client = None;
    let pending = manager
        .apply(
            "wan0",
            InterfaceChange {
                config: &candidate,
                previous: Some(&previous),
                current_role: Some(previous.role),
                allow_management_change: true,
                passphrase: crate::wifi::WifiPassphraseUpdate::Keep,
            },
        )
        .await
        .unwrap();
    if !device_present {
        network.interfaces.lock().await.remove("wan0");
        network.addresses.lock().await.remove("wan0");
    }
    desired.attach_converger();
    let dhcp = Arc::new(FakeDhcpReconciler::default());
    let wifi = Arc::new(FakeWifiReconciler::default()); // no association
    let client = Arc::new(FakeDhcpClientReconciler {
        reject_readiness: true,
        ..Default::default()
    });
    let worker = {
        let desired = desired.clone();
        let network = network.clone();
        let dhcp = dhcp.clone();
        let wifi = wifi.clone();
        let client = client.clone();
        tokio::spawn(async move {
            loop {
                desired.changed().await;
                let version = desired.version();
                let result = reconcile_network_runtime_once(
                    &desired,
                    &journal,
                    network.clone(),
                    dhcp.as_ref(),
                    None::<&FakeWifiReconciler>,
                    Some(wifi.as_ref()),
                    Some(client.as_ref()),
                )
                .await;
                desired.report_result(version, result);
            }
        })
    };
    tokio::time::timeout(Duration::from_secs(1), manager.rollback(&pending.token))
        .await
        .expect("rollback must not wait for Wi-Fi association or DHCP lease")
        .expect("configuration cancellation succeeds without external connectivity");
    assert!(manager.pending().await.is_empty());
    assert!(!desired.is_tentative("wan0").await);
    assert!(!directory
        .path()
        .join("interface-transactions/wan0.json")
        .exists());
    assert_eq!(*client.readiness_checks.lock().await, 0);
    if !device_present {
        let calls = client.disable_calls.lock().await;
        assert!(!calls.is_empty());
        assert!(calls.iter().all(|name| name == "wan0"));
    }
    assert_eq!(
        desired.committed_interface("wan0").await.unwrap(),
        Some(previous)
    );
    worker.abort();
}

#[tokio::test]
async fn rollback_completes_without_wifi_association_or_dhcp_lease() {
    rollback_without_external_connectivity(true).await;
}

#[tokio::test]
async fn rollback_completes_after_device_removal_and_releases_the_interface() {
    rollback_without_external_connectivity(false).await;
}

mod transaction_liveness;

#[tokio::test]
async fn mac_change_restarts_an_existing_dhcp_server_and_then_settles() {
    let mut config = hotplug_reconcile_config();
    let mac = traffic_masq_protocol::MacAddr::new([2, 7, 8, 9, 10, 11]);
    config
        .network
        .interfaces
        .get_mut("lan0")
        .unwrap()
        .mac_address = Some(mac);
    let directory = tempdir().unwrap();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let desired = DesiredNetworkState::new(config.clone(), overrides);
    let network = Arc::new(FakeNetworkProvider::default());
    network
        .add_interface_with_state("lan0", 7, true, vec![])
        .await;
    network
        .macs
        .lock()
        .await
        .insert("lan0".into(), [0, 1, 2, 3, 4, 5]);
    let dhcp = FakeDhcpReconciler::default();
    let spec = DhcpServiceSpec::from_interface_config(
        "lan0",
        &config.network.interfaces["lan0"],
        config.dhcp.default_lease_seconds,
    )
    .unwrap()
    .unwrap();
    dhcp.specs.lock().await.insert("lan0".into(), spec.clone());
    for _ in 0..2 {
        let failures = reconcile_network_runtime_once(
            &desired,
            &AddressOwnershipJournal::in_memory(),
            network.clone(),
            &dhcp,
            Some(&FakeWifiReconciler::default()),
            None::<&FakeWifiReconciler>,
            None::<&FakeDhcpClientReconciler>,
        )
        .await
        .unwrap();
        assert!(failures.is_empty(), "{failures:?}");
    }
    assert_eq!(
        network.mac_address("lan0").await.unwrap(),
        Some(mac.octets())
    );
    assert_eq!(*dhcp.disable_calls.lock().await, vec!["lan0"]);
    assert_eq!(dhcp.configure_calls.lock().await.len(), 1);
    assert_eq!(dhcp.spec("lan0").await, Some(spec));
}
