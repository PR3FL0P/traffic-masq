use crate::netlink::{AddressOwnership, TRAFFIC_MASQ_DHCP_ADDRESS_PROTOCOL};
use std::sync::atomic::{AtomicUsize, Ordering};

use tempfile::TempDir;

use super::*;
use crate::config::{DhcpClientInterfaceConfig, NetworkConfig};
use crate::netlink::{Ipv4AddressInfo, Ipv4RouteInfo, Ipv4RouteSpec, NetworkInterface};

const MAC: [u8; 6] = [2, 0, 0, 0, 0, 7];

#[derive(Default)]
struct FakeNetwork {
    interfaces: Mutex<Vec<NetworkInterface>>,
    addresses: Mutex<Vec<Ipv4AddressInfo>>,
    routes: Mutex<Vec<Ipv4RouteInfo>>,
    mac: Mutex<Vec<u8>>,
    fail_address_deletes: AtomicUsize,
}

impl FakeNetwork {
    fn detached() -> Arc<Self> {
        Arc::new(Self {
            mac: Mutex::new(MAC.to_vec()),
            ..Self::default()
        })
    }

    async fn present(index: u32) -> Arc<Self> {
        let network = Self::detached();
        network.attach("wan0", index).await;
        network
    }

    async fn attach(&self, name: &str, index: u32) {
        self.interfaces.lock().await.push(NetworkInterface {
            is_wireless: false,
            index,
            name: name.to_string(),
            is_up: true,
            rx_bytes: 0,
            tx_bytes: 0,
        });
    }

    async fn detach(&self, name: &str) {
        self.interfaces
            .lock()
            .await
            .retain(|interface| interface.name != name);
    }
}

#[async_trait]
impl NetworkProvider for FakeNetwork {
    async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        Ok(self.interfaces.lock().await.clone())
    }

    async fn hardware_address(&self, _interface: &str) -> Result<Vec<u8>> {
        Ok(self.mac.lock().await.clone())
    }

    async fn list_ipv4_addresses(&self, _interface: &str) -> Result<Vec<Ipv4AddressInfo>> {
        Ok(self.addresses.lock().await.clone())
    }

    async fn set_link_up(&self, _name: &str) -> Result<()> {
        Ok(())
    }

    async fn set_link_down(&self, _name: &str) -> Result<()> {
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
            interface_index: 7,
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
        if self.fail_address_deletes.load(Ordering::SeqCst) > 0 {
            self.fail_address_deletes.fetch_sub(1, Ordering::SeqCst);
            anyhow::bail!("injected address delete failure");
        }
        self.addresses
            .lock()
            .await
            .retain(|item| item.address != address || item.prefix_len != prefix_len);
        Ok(())
    }

    async fn list_ipv4_routes(&self) -> Result<Vec<Ipv4RouteInfo>> {
        Ok(self.routes.lock().await.clone())
    }

    async fn add_ipv4_route(&self, route: &Ipv4RouteSpec) -> Result<()> {
        self.routes.lock().await.push(Ipv4RouteInfo {
            destination: route.destination,
            gateway: route.gateway,
            output_interface_index: route.output_interface_index,
            table: route.table,
            metric: route.metric,
            protocol: route.protocol,
            scope: if route.gateway.is_some() { 0 } else { 253 },
        });
        Ok(())
    }

    async fn delete_ipv4_route(&self, route: &Ipv4RouteInfo) -> Result<()> {
        self.routes.lock().await.retain(|item| item != route);
        Ok(())
    }
}

type SentPackets = Arc<std::sync::Mutex<Vec<(Vec<u8>, SendKind)>>>;

#[derive(Default)]
struct FakeLauncher {
    launches: std::sync::Mutex<Vec<String>>,
    remembered: std::sync::Mutex<Vec<Option<Ipv4Addr>>>,
    sinks: std::sync::Mutex<Vec<Box<dyn DhcpClientActionSink>>>,
    sends: SentPackets,
    fail_next: AtomicUsize,

    exit_immediately: AtomicUsize,
}

struct FakeTransport(SentPackets);

#[async_trait]
impl DhcpClientTransport for FakeTransport {
    async fn receive(&self) -> Result<crate::dhcp::client::runtime::IngressDatagram> {
        std::future::pending().await
    }

    async fn send(&self, packet: &[u8], kind: SendKind) -> Result<()> {
        self.0.lock().unwrap().push((packet.to_vec(), kind));
        Ok(())
    }
}

#[async_trait]
impl DhcpClientLauncher for FakeLauncher {
    async fn launch(&self, launch: DhcpClientLaunch) -> Result<RunningDhcpClient> {
        if self.fail_next.load(Ordering::SeqCst) > 0 {
            self.fail_next.fetch_sub(1, Ordering::SeqCst);
            anyhow::bail!("injected launch failure");
        }
        self.launches.lock().unwrap().push(launch.interface.clone());
        self.remembered
            .lock()
            .unwrap()
            .push(launch.remembered.as_ref().map(|lease| lease.address));
        self.sinks.lock().unwrap().push(launch.sink);
        let (cancel, mut cancel_rx) = watch::channel(false);
        let exit = self.exit_immediately.load(Ordering::SeqCst) > 0;
        if exit {
            self.exit_immediately.fetch_sub(1, Ordering::SeqCst);
        }
        let task = tokio::spawn(async move {
            if exit {
                anyhow::bail!("injected actor failure");
            }
            while cancel_rx.changed().await.is_ok() {
                if *cancel_rx.borrow() {
                    break;
                }
            }
            Ok(())
        });
        Ok(RunningDhcpClient {
            cancel,
            task,
            transport: Arc::new(FakeTransport(self.sends.clone())),
        })
    }
}

impl FakeLauncher {
    fn launch_count(&self) -> usize {
        self.launches.lock().unwrap().len()
    }

    fn take_sink(&self) -> Box<dyn DhcpClientActionSink> {
        self.sinks.lock().unwrap().pop().expect("a launched sink")
    }
}

fn config(state_dir: &TempDir, interface: Option<DhcpClientInterfaceConfig>) -> AppConfig {
    let mut config = AppConfig::default();
    config.runtime.state_dir = state_dir.path().to_path_buf();
    let mut network = NetworkConfig::default();
    network.interfaces.insert(
        "wan0".to_string(),
        InterfaceConfig {
            role: InterfaceRole::Input,
            managed: interface.is_some(),
            ipv4: None,
            dhcp: None,
            dhcp_client: interface,
            wifi: None,
            wifi_client: None,
            nat: true,
        },
    );
    config.network = network;
    config
}

fn spec() -> DhcpClientSpec {
    DhcpClientSpec {
        interface: "wan0".to_string(),
        route_metric: 100,
        install_default_route: true,
        request_dns: true,
        send_release_on_shutdown: false,
    }
}

fn lease(address: Ipv4Addr) -> Lease {
    Lease {
        address,
        subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
        prefix_len: 24,
        routers: vec![Ipv4Addr::new(192, 0, 2, 1)],
        dns_servers: vec![Ipv4Addr::new(192, 0, 2, 53)],
        server_identifier: Ipv4Addr::new(192, 0, 2, 1),
        acquired_at: Duration::ZERO,
        renewal_at: Duration::from_secs(1800),
        rebinding_at: Duration::from_secs(3150),
        expires_at: Duration::from_secs(3600),
    }
}

async fn supervisor_with(
    state_dir: &TempDir,
    network: Arc<FakeNetwork>,
    launcher: Arc<FakeLauncher>,
) -> DhcpClientSupervisor {
    DhcpClientSupervisor::start_with_launcher(
        &config(state_dir, Some(DhcpClientInterfaceConfig::default())),
        network,
        launcher,
    )
    .await
    .expect("supervisor")
}

#[test]
fn spec_is_derived_only_from_an_enabled_block() {
    let mut interface = InterfaceConfig {
        role: InterfaceRole::Input,
        managed: true,
        ipv4: None,
        dhcp: None,
        dhcp_client: Some(DhcpClientInterfaceConfig::default()),
        wifi: None,
        wifi_client: None,
        nat: true,
    };
    let derived = DhcpClientSpec::from_interface_config("wan0", &interface)
        .expect("valid")
        .expect("spec");
    assert_eq!(derived, spec());
    derived.validate().expect("round-tripped spec stays valid");
    assert_eq!(
        derived.interface_config(),
        DhcpClientInterfaceConfig::default()
    );

    interface.dhcp_client.as_mut().unwrap().enabled = false;
    interface.managed = false;
    assert!(DhcpClientSpec::from_interface_config("wan0", &interface)
        .expect("valid")
        .is_none());

    interface.dhcp_client = None;
    assert!(DhcpClientSpec::from_interface_config("wan0", &interface)
        .expect("valid")
        .is_none());
}

#[tokio::test]
async fn absent_interface_waits_without_failing_startup_and_starts_on_hotplug() {
    let state_dir = TempDir::new().expect("state dir");
    let network = FakeNetwork::detached();
    let launcher = Arc::new(FakeLauncher::default());
    let supervisor = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;

    assert_eq!(launcher.launch_count(), 0);
    let status = supervisor.status("wan0").await.expect("status");
    assert_eq!(status.state, DhcpClientRunState::WaitingForInterface);
    assert!(status.lease.is_none());

    network.attach("wan0", 7).await;
    assert!(supervisor.ensure_alive().await.expect("ensure alive"));
    assert_eq!(launcher.launch_count(), 1);
    assert_eq!(
        supervisor.status("wan0").await.expect("status").state,
        DhcpClientRunState::Running
    );
}

#[tokio::test]
async fn repeated_reconcile_never_restarts_a_healthy_client() {
    let state_dir = TempDir::new().expect("state dir");
    let network = FakeNetwork::present(7).await;
    let launcher = Arc::new(FakeLauncher::default());
    let supervisor = supervisor_with(&state_dir, network, launcher.clone()).await;
    assert_eq!(launcher.launch_count(), 1);

    for _ in 0..5 {
        supervisor.reconcile(spec()).await;
        supervisor.ensure_alive().await.expect("ensure alive");
    }
    assert_eq!(launcher.launch_count(), 1);
}

#[tokio::test(start_paused = true)]
async fn launch_failure_degrades_and_retries_under_bounded_backoff() {
    let state_dir = TempDir::new().expect("state dir");
    let network = FakeNetwork::present(7).await;
    let launcher = Arc::new(FakeLauncher::default());
    launcher.fail_next.store(1, Ordering::SeqCst);
    let supervisor = supervisor_with(&state_dir, network, launcher.clone()).await;

    assert_eq!(launcher.launch_count(), 0);
    let status = supervisor.status("wan0").await.expect("status");
    assert!(matches!(status.state, DhcpClientRunState::Degraded { .. }));

    assert!(!supervisor.ensure_alive().await.expect("ensure alive"));
    assert_eq!(launcher.launch_count(), 0);

    tokio::time::advance(RESTART_BACKOFF_BASE + Duration::from_millis(1)).await;
    assert!(supervisor.ensure_alive().await.expect("ensure alive"));
    assert_eq!(launcher.launch_count(), 1);
    assert_eq!(
        supervisor.status("wan0").await.expect("status").state,
        DhcpClientRunState::Running
    );
}

#[tokio::test(start_paused = true)]
async fn a_task_that_exits_is_restarted_rather_than_left_dead() {
    let state_dir = TempDir::new().expect("state dir");
    let network = FakeNetwork::present(7).await;
    let launcher = Arc::new(FakeLauncher::default());
    launcher.exit_immediately.store(2, Ordering::SeqCst);
    let supervisor = supervisor_with(&state_dir, network, launcher.clone()).await;
    assert_eq!(launcher.launch_count(), 1);

    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(!supervisor.ensure_alive().await.expect("ensure alive"));
    assert_eq!(launcher.launch_count(), 1);

    tokio::time::advance(RESTART_BACKOFF_BASE + Duration::from_millis(1)).await;
    assert!(supervisor.ensure_alive().await.expect("ensure alive"));
    assert_eq!(launcher.launch_count(), 2);

    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(!supervisor.ensure_alive().await.expect("ensure alive"));
    assert_eq!(launcher.launch_count(), 2);

    tokio::time::advance(RESTART_BACKOFF_BASE).await;
    assert!(!supervisor.ensure_alive().await.expect("ensure alive"));
    assert_eq!(launcher.launch_count(), 2);

    tokio::time::advance(RESTART_BACKOFF_BASE + Duration::from_millis(1)).await;
    assert!(supervisor.ensure_alive().await.expect("ensure alive"));
    assert_eq!(launcher.launch_count(), 3);
}

#[tokio::test]
async fn replug_with_a_new_ifindex_restarts_the_client() {
    let state_dir = TempDir::new().expect("state dir");
    let network = FakeNetwork::present(7).await;
    let launcher = Arc::new(FakeLauncher::default());
    let supervisor = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;
    assert_eq!(launcher.launch_count(), 1);

    network.detach("wan0").await;
    assert!(supervisor.ensure_alive().await.expect("ensure alive"));
    assert_eq!(
        supervisor.status("wan0").await.expect("status").state,
        DhcpClientRunState::WaitingForInterface
    );

    network.attach("wan0", 11).await;
    assert!(supervisor.ensure_alive().await.expect("ensure alive"));
    assert_eq!(launcher.launch_count(), 2);
    assert!(!supervisor.ensure_alive().await.expect("ensure alive"));
}

#[tokio::test]
async fn an_acquired_lease_is_applied_persisted_and_reported() {
    let state_dir = TempDir::new().expect("state dir");
    let network = FakeNetwork::present(7).await;
    let launcher = Arc::new(FakeLauncher::default());
    let supervisor = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;

    let mut sink = launcher.take_sink();
    sink.lease_acquired(lease(Ipv4Addr::new(192, 0, 2, 42)))
        .await
        .expect("lease applied");

    let status = supervisor.status("wan0").await.expect("status");
    assert_eq!(status.state, DhcpClientRunState::Running);
    let applied = status.lease.expect("lease");
    assert_eq!(applied.address, Ipv4Addr::new(192, 0, 2, 42));
    assert_eq!(applied.state, DhcpClientLeaseState::Bound);
    assert_eq!(applied.owned_routes.len(), 2);
    assert!(applied
        .owned_routes
        .iter()
        .all(|route| route.protocol == TRAFFIC_MASQ_DHCP_ROUTE_PROTOCOL));
    assert_eq!(
        applied
            .owned_routes
            .iter()
            .find(|route| route.destination.prefix_len() == 0)
            .expect("default route")
            .metric,
        Some(100)
    );
    assert_eq!(
        network
            .list_ipv4_addresses("wan0")
            .await
            .expect("addresses"),
        vec![Ipv4AddressInfo {
            interface_index: 7,
            // A DHCP-held address is tagged as such, so it is
            // distinguishable from a hand-configured one.
            address: Ipv4Addr::new(192, 0, 2, 42),
            prefix_len: 24,
            protocol: Some(TRAFFIC_MASQ_DHCP_ADDRESS_PROTOCOL),
        }]
    );

    sink.cleanup_needed(lease(Ipv4Addr::new(192, 0, 2, 42)))
        .await
        .expect("cleanup");
    assert!(network
        .list_ipv4_addresses("wan0")
        .await
        .expect("addresses")
        .is_empty());
    assert!(network.list_ipv4_routes().await.expect("routes").is_empty());
    assert!(supervisor
        .status("wan0")
        .await
        .expect("status")
        .lease
        .is_none());
}

#[tokio::test]
async fn unresolved_persisted_ownership_cleanup_blocks_a_new_actor() {
    let state_dir = TempDir::new().expect("state dir");
    let network = FakeNetwork::present(7).await;
    let launcher = Arc::new(FakeLauncher::default());
    let supervisor = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;
    let mut sink = launcher.take_sink();
    sink.lease_acquired(lease(Ipv4Addr::new(192, 0, 2, 42)))
        .await
        .expect("lease applied");
    supervisor
        .shutdown(ShutdownPolicy::PreserveInterfaces)
        .await;

    let store = DhcpClientLeaseStore::new(state_dir.path()).expect("store");
    let mut persisted = store.load("wan0").expect("load").expect("lease");
    persisted.state = DhcpClientLeaseState::CleanupNeeded;
    store.save(&persisted).expect("save cleanup-needed state");
    network.fail_address_deletes.store(1, Ordering::SeqCst);

    let restarted = supervisor_with(&state_dir, network, launcher.clone()).await;
    assert_eq!(
        launcher.launch_count(),
        1,
        "a new DHCP actor must not start over unresolved owned kernel state"
    );
    assert!(matches!(
        restarted.status("wan0").await.expect("status").state,
        DhcpClientRunState::Degraded { .. }
    ));
}

#[tokio::test]
async fn statuses_reports_each_interface_once() {
    let state_dir = TempDir::new().expect("state dir");
    let network = FakeNetwork::present(7).await;
    let launcher = Arc::new(FakeLauncher::default());
    let supervisor = supervisor_with(&state_dir, network, launcher).await;

    let statuses = supervisor.statuses().await;
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].interface, "wan0");
}

#[tokio::test]
async fn startup_cleans_persisted_ownership_without_committed_client_intent() {
    let state_dir = TempDir::new().expect("state dir");
    let network = FakeNetwork::present(7).await;
    let launcher = Arc::new(FakeLauncher::default());
    let supervisor = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;
    let mut sink = launcher.take_sink();
    sink.lease_acquired(lease(Ipv4Addr::new(192, 0, 2, 42)))
        .await
        .expect("lease applied");
    supervisor
        .shutdown(ShutdownPolicy::PreserveInterfaces)
        .await;

    let restarted = DhcpClientSupervisor::start_with_launcher(
        &config(&state_dir, None),
        network.clone(),
        launcher.clone(),
    )
    .await
    .expect("restart without committed DHCP client");

    assert!(restarted.status("wan0").await.is_none());
    assert!(network.addresses.lock().await.is_empty());
    assert!(network.routes.lock().await.is_empty());
    let store = DhcpClientLeaseStore::new(state_dir.path()).expect("store");
    assert!(store.load("wan0").expect("load").is_none());
}

#[tokio::test]
async fn restart_rejects_lease_from_uncommitted_route_policy() {
    let state_dir = TempDir::new().expect("state dir");
    let network = FakeNetwork::present(7).await;
    let launcher = Arc::new(FakeLauncher::default());
    let supervisor = DhcpClientSupervisor::start_with_launcher(
        &config(&state_dir, None),
        network.clone(),
        launcher.clone(),
    )
    .await
    .expect("supervisor");

    let mut tentative = spec();
    tentative.route_metric = 777;
    supervisor.configure(tentative).await;
    let mut sink = launcher.take_sink();
    sink.lease_acquired(lease(Ipv4Addr::new(192, 0, 2, 42)))
        .await
        .expect("tentative lease applied");
    supervisor
        .shutdown(ShutdownPolicy::PreserveInterfaces)
        .await;
    assert!(network
        .routes
        .lock()
        .await
        .iter()
        .any(|route| route.metric == Some(777)));

    let restarted = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;
    assert_eq!(
        launcher.remembered.lock().unwrap().last(),
        Some(&None),
        "a lease acquired under an uncommitted route policy must not be adopted"
    );
    assert!(restarted
        .status("wan0")
        .await
        .expect("status")
        .lease
        .is_none());
    assert!(network.addresses.lock().await.is_empty());
    assert!(network.routes.lock().await.is_empty());
}

#[tokio::test]
async fn a_still_valid_lease_is_adopted_on_restart_instead_of_reacquired() {
    let state_dir = TempDir::new().expect("state dir");
    let network = FakeNetwork::present(7).await;
    let launcher = Arc::new(FakeLauncher::default());
    let supervisor = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;
    let mut sink = launcher.take_sink();
    sink.lease_acquired(lease(Ipv4Addr::new(192, 0, 2, 42)))
        .await
        .expect("lease applied");

    let restarted = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;
    assert_eq!(
        launcher
            .remembered
            .lock()
            .unwrap()
            .last()
            .copied()
            .flatten(),
        Some(Ipv4Addr::new(192, 0, 2, 42)),
        "a valid persisted lease must be adopted into INIT-REBOOT"
    );
    assert_eq!(
        restarted
            .status("wan0")
            .await
            .expect("status")
            .lease
            .expect("lease")
            .address,
        Ipv4Addr::new(192, 0, 2, 42)
    );
    drop(supervisor);
}

#[tokio::test]
async fn wifi_gate_blocks_until_completed_and_disconnect_removes_owned_state() {
    let state_dir = TempDir::new().expect("state dir");
    let network = FakeNetwork::present(7).await;
    let launcher = Arc::new(FakeLauncher::default());
    let supervisor = DhcpClientSupervisor::start_with_launcher(
        &config(&state_dir, None),
        network.clone(),
        launcher.clone(),
    )
    .await
    .expect("supervisor");

    supervisor.configure_with_link_ready(spec(), false).await;
    assert_eq!(launcher.launch_count(), 0, "no DHCP before association");
    supervisor.reconcile_with_link_ready(spec(), false).await;
    assert_eq!(
        launcher.launch_count(),
        0,
        "polling must not create a restart loop"
    );

    supervisor.reconcile_with_link_ready(spec(), true).await;
    assert_eq!(launcher.launch_count(), 1, "COMPLETED starts DHCP");
    let mut sink = launcher.take_sink();
    sink.lease_acquired(lease(Ipv4Addr::new(192, 0, 2, 42)))
        .await
        .expect("lease applied");

    supervisor.reconcile_with_link_ready(spec(), false).await;
    assert_eq!(
        launcher.launch_count(),
        1,
        "disconnect stops rather than restarts"
    );
    assert!(
        launcher.sends.lock().unwrap().is_empty(),
        "disconnect sends no RELEASE"
    );
    assert!(
        network.addresses.lock().await.is_empty(),
        "disconnect removes the DHCP address"
    );
    assert!(
        network.routes.lock().await.is_empty(),
        "disconnect removes every DHCP-owned route"
    );

    supervisor.reconcile_with_link_ready(spec(), true).await;
    assert_eq!(launcher.launch_count(), 2);
    assert_eq!(
        launcher
            .remembered
            .lock()
            .unwrap()
            .last()
            .copied()
            .flatten(),
        Some(Ipv4Addr::new(192, 0, 2, 42)),
        "reconnect revalidates the suspended lease without keeping its IP configured"
    );
}

#[tokio::test]
async fn link_not_ready_suspends_persisted_lease_but_removes_kernel_state() {
    let state_dir = TempDir::new().expect("state dir");
    let network = FakeNetwork::present(7).await;
    let launcher = Arc::new(FakeLauncher::default());
    let supervisor = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;
    let mut sink = launcher.take_sink();
    sink.lease_acquired(lease(Ipv4Addr::new(192, 0, 2, 42)))
        .await
        .expect("lease applied");
    supervisor.reconcile_with_link_ready(spec(), false).await;

    let store = DhcpClientLeaseStore::new(state_dir.path()).expect("store");
    assert!(network.addresses.lock().await.is_empty());
    assert!(network.routes.lock().await.is_empty());
    assert_eq!(
        store
            .load("wan0")
            .expect("load")
            .expect("suspended lease")
            .state,
        DhcpClientLeaseState::Suspended
    );
    supervisor.reconcile_with_link_ready(spec(), true).await;
    assert_eq!(
        launcher.remembered.lock().unwrap().last(),
        Some(&Some(Ipv4Addr::new(192, 0, 2, 42)))
    );
}

#[tokio::test]
async fn preserve_shutdown_keeps_owned_state_and_sends_no_release() {
    let state_dir = TempDir::new().expect("state dir");
    let network = FakeNetwork::present(7).await;
    let launcher = Arc::new(FakeLauncher::default());
    let supervisor = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;
    let mut sink = launcher.take_sink();
    sink.lease_acquired(lease(Ipv4Addr::new(192, 0, 2, 42)))
        .await
        .expect("lease applied");

    supervisor
        .shutdown(ShutdownPolicy::PreserveInterfaces)
        .await;

    assert!(launcher.sends.lock().unwrap().is_empty());
    assert_eq!(
        network
            .list_ipv4_addresses("wan0")
            .await
            .expect("addresses")
            .len(),
        1,
        "a preserved uplink must keep its address across a daemon restart"
    );
    assert_eq!(network.list_ipv4_routes().await.expect("routes").len(), 2);
}

#[tokio::test]
async fn destructive_shutdown_releases_when_asked_and_cleans_up_owned_state() {
    let state_dir = TempDir::new().expect("state dir");
    let network = FakeNetwork::present(7).await;
    let launcher = Arc::new(FakeLauncher::default());
    let mut config = config(&state_dir, Some(DhcpClientInterfaceConfig::default()));
    config
        .network
        .interfaces
        .get_mut("wan0")
        .unwrap()
        .dhcp_client
        .as_mut()
        .unwrap()
        .send_release_on_shutdown = true;
    let supervisor =
        DhcpClientSupervisor::start_with_launcher(&config, network.clone(), launcher.clone())
            .await
            .expect("supervisor");
    let mut sink = launcher.take_sink();
    sink.lease_acquired(lease(Ipv4Addr::new(192, 0, 2, 42)))
        .await
        .expect("lease applied");

    supervisor.shutdown(ShutdownPolicy::RestoreInterfaces).await;

    let sends = launcher.sends.lock().unwrap().clone();
    assert_eq!(sends.len(), 1, "exactly one RELEASE");
    assert_eq!(
        sends[0].1,
        SendKind::Unicast(Ipv4Addr::new(192, 0, 2, 1)),
        "RELEASE is unicast to the server that granted the lease"
    );
    assert!(network
        .list_ipv4_addresses("wan0")
        .await
        .expect("addresses")
        .is_empty());
    assert!(network.list_ipv4_routes().await.expect("routes").is_empty());
}

#[tokio::test]
async fn disabling_an_interface_stops_it_and_gives_back_owned_state() {
    let state_dir = TempDir::new().expect("state dir");
    let network = FakeNetwork::present(7).await;
    let launcher = Arc::new(FakeLauncher::default());
    let supervisor = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;
    let mut sink = launcher.take_sink();
    sink.lease_acquired(lease(Ipv4Addr::new(192, 0, 2, 42)))
        .await
        .expect("lease applied");

    let removed = supervisor.disable("wan0").await.expect("disable");
    assert_eq!(removed, Some(spec()));
    assert!(supervisor.status("wan0").await.is_none());
    assert!(network
        .list_ipv4_addresses("wan0")
        .await
        .expect("addresses")
        .is_empty());

    assert!(supervisor.disable("wan0").await.expect("disable").is_none());
}

#[tokio::test]
async fn failed_disable_cleanup_keeps_intent_and_retries_exactly() {
    let state_dir = TempDir::new().expect("state dir");
    let network = FakeNetwork::present(7).await;
    let launcher = Arc::new(FakeLauncher::default());
    let supervisor = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;
    let mut sink = launcher.take_sink();
    let address = Ipv4Addr::new(192, 0, 2, 42);
    sink.lease_acquired(lease(address))
        .await
        .expect("lease applied");

    network.fail_address_deletes.store(1, Ordering::SeqCst);
    supervisor
        .disable("wan0")
        .await
        .expect_err("transient cleanup failure must be reported");
    assert_eq!(supervisor.spec("wan0").await, Some(spec()));
    assert!(network
        .list_ipv4_addresses("wan0")
        .await
        .expect("addresses")
        .iter()
        .any(|item| item.address == address));

    let removed = supervisor
        .disable("wan0")
        .await
        .expect("cleanup retry succeeds");
    assert_eq!(removed, Some(spec()));
    assert!(supervisor.spec("wan0").await.is_none());
    assert!(network
        .list_ipv4_addresses("wan0")
        .await
        .expect("addresses")
        .is_empty());
}

#[tokio::test]
async fn a_refused_lease_application_degrades_the_client_without_touching_foreign_state() {
    let state_dir = TempDir::new().expect("state dir");
    let network = FakeNetwork::present(7).await;

    network.addresses.lock().await.push(Ipv4AddressInfo {
        interface_index: 7,
        address: Ipv4Addr::new(192, 0, 2, 42),
        prefix_len: 24,
        protocol: None,
    });
    let launcher = Arc::new(FakeLauncher::default());
    let supervisor = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;
    let mut sink = launcher.take_sink();

    let error = sink
        .lease_acquired(lease(Ipv4Addr::new(192, 0, 2, 42)))
        .await
        .expect_err("a foreign address must never be taken over");
    assert!(error.to_string().contains("wan0"));

    let status = supervisor.status("wan0").await.expect("status");
    assert!(matches!(status.state, DhcpClientRunState::Degraded { .. }));
    assert!(status.lease.is_none());
    assert_eq!(
        network
            .list_ipv4_addresses("wan0")
            .await
            .expect("addresses")
            .len(),
        1,
        "the foreign address must survive untouched"
    );
}

#[tokio::test]
async fn renew_now_restarts_with_remembered_lease_without_cleanup() {
    let state_dir = TempDir::new().expect("state dir");
    let network = FakeNetwork::present(7).await;
    let launcher = Arc::new(FakeLauncher::default());
    let supervisor = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;
    let mut sink = launcher.take_sink();
    let address = Ipv4Addr::new(192, 0, 2, 42);
    sink.lease_acquired(lease(address))
        .await
        .expect("apply lease");

    let status = supervisor.renew_now("wan0").await.expect("renew");
    assert_eq!(
        status.lease.as_ref().map(|lease| lease.address),
        Some(address)
    );
    assert_eq!(launcher.launch_count(), 2);
    assert_eq!(
        launcher
            .remembered
            .lock()
            .unwrap()
            .last()
            .copied()
            .flatten(),
        Some(address)
    );
    assert!(network
        .list_ipv4_addresses("wan0")
        .await
        .unwrap()
        .iter()
        .any(|item| item.address == address));
}

#[tokio::test]
async fn renew_now_reports_immediate_restart_failure() {
    let state_dir = TempDir::new().expect("state dir");
    let network = FakeNetwork::present(7).await;
    let launcher = Arc::new(FakeLauncher::default());
    let supervisor = supervisor_with(&state_dir, network, launcher.clone()).await;

    launcher.fail_next.store(1, Ordering::SeqCst);
    let error = supervisor
        .renew_now("wan0")
        .await
        .expect_err("failed restart must not be reported as a successful renew");
    assert!(error.to_string().contains("renew failed"));
    assert!(matches!(
        supervisor.status("wan0").await.expect("status").state,
        DhcpClientRunState::Degraded { .. }
    ));
}

#[tokio::test]
async fn release_and_reacquire_sends_release_cleans_exact_state_and_keeps_intent() {
    let state_dir = TempDir::new().expect("state dir");
    let network = FakeNetwork::present(7).await;
    let launcher = Arc::new(FakeLauncher::default());
    let supervisor = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;
    let mut sink = launcher.take_sink();
    let address = Ipv4Addr::new(192, 0, 2, 42);
    sink.lease_acquired(lease(address))
        .await
        .expect("apply lease");

    let status = supervisor
        .release_and_reacquire("wan0")
        .await
        .expect("release");
    assert!(status.lease.is_none());
    assert_eq!(launcher.launch_count(), 2);
    assert!(
        !launcher.sends.lock().unwrap().is_empty(),
        "explicit release must send a packet"
    );
    assert!(network
        .list_ipv4_addresses("wan0")
        .await
        .unwrap()
        .is_empty());
    assert_eq!(supervisor.spec("wan0").await, Some(spec()));
}

#[tokio::test]
async fn release_and_reacquire_reports_immediate_restart_failure() {
    let state_dir = TempDir::new().expect("state dir");
    let network = FakeNetwork::present(7).await;
    let launcher = Arc::new(FakeLauncher::default());
    let supervisor = supervisor_with(&state_dir, network, launcher.clone()).await;

    launcher.fail_next.store(1, Ordering::SeqCst);
    let error = supervisor
        .release_and_reacquire("wan0")
        .await
        .expect_err("failed restart must not be reported as a successful release/reacquire");
    assert!(error.to_string().contains("release/reacquire failed"));
    assert!(matches!(
        supervisor.status("wan0").await.expect("status").state,
        DhcpClientRunState::Degraded { .. }
    ));
}

#[test]
fn backoff_doubles_and_is_capped() {
    assert_eq!(backoff(1), RESTART_BACKOFF_BASE);
    assert_eq!(backoff(2), RESTART_BACKOFF_BASE * 2);
    assert_eq!(backoff(3), RESTART_BACKOFF_BASE * 4);
    assert_eq!(backoff(64), BACKOFF_CEILING);
}

#[test]
fn a_remembered_lease_carries_only_its_remaining_lifetime() {
    let persisted = DhcpClientLease {
        schema_version: DHCP_CLIENT_LEASE_SCHEMA_VERSION,
        state: DhcpClientLeaseState::Bound,
        interface: "wan0".into(),
        interface_index: 7,
        hardware_address: MAC.to_vec(),
        client_identifier: client_identifier(MAC),
        policy: None,
        server_identifier: Ipv4Addr::new(192, 0, 2, 1),
        address: Ipv4Addr::new(192, 0, 2, 42),
        prefix_len: 24,
        routers: vec![Ipv4Addr::new(192, 0, 2, 1)],
        dns_servers: vec![],
        lease_seconds: 3600,
        renewal_seconds: 1800,
        rebinding_seconds: 3150,
        expires_at_unix: current_unix_time() + 600,
        owned_routes: vec![],
    };
    let remembered = monotonic_lease(&persisted);
    assert_eq!(remembered.acquired_at, Duration::ZERO);
    assert!(remembered.expires_at <= Duration::from_secs(600));
    assert!(remembered.renewal_at < remembered.rebinding_at);
    assert!(remembered.rebinding_at < remembered.expires_at);
    assert_eq!(remembered.subnet_mask, Ipv4Addr::new(255, 255, 255, 0));
}

#[tokio::test]
async fn consecutive_failures_and_backoff_are_preserved_across_restarts_with_remembered_lease() {
    let state_dir = TempDir::new().expect("state dir");
    let network = FakeNetwork::present(7).await;
    let launcher = Arc::new(FakeLauncher::default());
    let supervisor = supervisor_with(&state_dir, network.clone(), launcher.clone()).await;
    let mut sink = launcher.take_sink();
    let address = Ipv4Addr::new(192, 0, 2, 42);
    sink.lease_acquired(lease(address))
        .await
        .expect("apply lease");

    // Fail first time
    supervisor
        .record_failure("wan0", "first failure".into())
        .await;
    {
        let tasks = supervisor.inner.tasks.lock().await;
        assert_eq!(tasks.get("wan0").unwrap().consecutive_failures, 1);
    }

    // Clear next_attempt_earliest so start_task is allowed to run
    {
        let mut tasks = supervisor.inner.tasks.lock().await;
        tasks.get_mut("wan0").unwrap().next_attempt_earliest = None;
    }
    supervisor.ensure_interface_alive("wan0").await;

    // Verify task restarted but failures were NOT wiped to 0
    {
        let tasks = supervisor.inner.tasks.lock().await;
        assert_eq!(tasks.get("wan0").unwrap().consecutive_failures, 1);
    }

    // Fail second time: must increment to 2
    supervisor
        .record_failure("wan0", "second failure".into())
        .await;
    {
        let tasks = supervisor.inner.tasks.lock().await;
        assert_eq!(tasks.get("wan0").unwrap().consecutive_failures, 2);
    }
}
