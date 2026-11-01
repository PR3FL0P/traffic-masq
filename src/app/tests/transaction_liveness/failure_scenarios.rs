//! Operator workflows through the same dispatch/admission service as HTTP/TUI.
//! Real transaction persistence, timers and reconciliation; only OS/network I/O
//! is simulated. The assertions cover runtime availability, storage recovery and shutdown.
use super::*;
use crate::api::model::{
    InterfaceEditRequest, ProvisionWifiClientRequest, WifiClientIpPolicy,
    WifiClientProfileWriteRequest,
};
use tokio::sync::oneshot;

const WATCHDOG: Duration = Duration::from_secs(5);
const ORIGINAL_LAN: &str = "192.0.2.1/24";
const NEW_LAN: &str = "192.0.2.99/24";

fn edit_lan(cidr: &str) -> Request {
    Request::ApplyInterfaceEdit {
        interface: "eth0".into(),
        edit: InterfaceEditRequest {
            wifi_concurrent: false,
            randomize_mac: false,
            mac_address: None,
            cidr: cidr.into(),
            role: InterfaceRole::Output,
            managed: true,
            allow_management_change: true,
        },
    }
}

async fn request(service: &ControlService, request: Request) -> Response {
    tokio::time::timeout(WATCHDOG, service.dispatch(request))
        .await
        .expect("control request must complete")
}

async fn expect_lan(service: &ControlService, cidr: &str) {
    let response = request(
        service,
        Request::GetInterfaceConfig {
            interface: "eth0".into(),
        },
    )
    .await;
    let Response::InterfaceConfig {
        config: Some(config),
        ..
    } = response
    else {
        panic!("operator must be able to read LAN settings: {response:?}");
    };
    assert_eq!(config.ipv4, Some(cidr.parse().unwrap()));
}

async fn rollback_if_pending(service: &ControlService, response: &Response) {
    if let Response::NetworkChangePending { change } = response {
        let response = request(
            service,
            Request::RollbackNetworkChange {
                token: change.token.clone(),
            },
        )
        .await;
        assert!(
            matches!(response, Response::NetworkChangeRolledBack { .. }),
            "{response:?}"
        );
    }
}

#[tokio::test]
async fn repro_lan_edit_before_runtime_worker_starts_must_not_offer_confirmation() {
    // Startup wiring is incomplete: API exists, but its runtime worker has not
    // attached yet. The operator edits the LAN address through the normal UI API.
    let fixture = Fixture::start_with_converger(0, Duration::ZERO, 60, false).await;
    expect_lan(&fixture.service, ORIGINAL_LAN).await;
    let response = request(&fixture.service, edit_lan(NEW_LAN)).await;
    let observed = fixture.network.list_ipv4_addresses("eth0").await.unwrap();
    let original_still_live = observed
        .iter()
        .any(|a| a.address == Ipv4Addr::new(192, 0, 2, 1));
    let candidate_is_live = observed
        .iter()
        .any(|a| a.address == Ipv4Addr::new(192, 0, 2, 99));
    rollback_if_pending(&fixture.service, &response).await;
    expect_lan(&fixture.service, ORIGINAL_LAN).await;
    assert!(
        original_still_live && !candidate_is_live,
        "no worker has applied the edit"
    );
    assert!(matches!(response, Response::Error { .. }),
        "the UI must show an unavailable-runtime error, not offer confirmation for an unapplied LAN address: {response:?}");
}

#[tokio::test]
async fn repro_confirmed_lan_remains_editable_after_temporary_journal_read_failure() {
    let fixture = Fixture::start(0, Duration::ZERO, 60).await;
    let applied = request(&fixture.service, edit_lan(NEW_LAN)).await;
    let Response::NetworkChangePending { change } = applied else {
        panic!("{applied:?}");
    };
    assert!(
        fixture
            .network
            .list_ipv4_addresses("eth0")
            .await
            .unwrap()
            .iter()
            .any(|a| a.address == Ipv4Addr::new(192, 0, 2, 99)),
        "the real reconciliation pass must apply the new address before confirmation"
    );

    // Inject an unreadable journal without chmod (which behaves differently as
    // root). Keep exact bytes and restore the file before the next user request.
    let journal = fixture
        ._directory
        .path()
        .join("interface-transactions/eth0.json");
    let saved = journal.with_extension("saved");
    std::fs::rename(&journal, &saved).unwrap();
    std::fs::create_dir(&journal).unwrap();
    let confirmed = request(
        &fixture.service,
        Request::CommitNetworkChange {
            token: change.token,
        },
    )
    .await;
    std::fs::remove_dir(&journal).unwrap();
    std::fs::rename(&saved, &journal).unwrap();
    assert!(
        matches!(confirmed, Response::NetworkChangeCommitted { .. }),
        "{confirmed:?}"
    );
    expect_lan(&fixture.service, NEW_LAN).await;

    // A normal reconciliation event also gets a chance to recover, with a
    // completion signal instead of sleeping for an assumed retry interval.
    fixture.desired.request_convergence();
    let pass = tokio::time::timeout(
        WATCHDOG,
        fixture.desired.pass_covering(fixture.desired.version()),
    )
    .await
    .unwrap();
    assert!(pass.error.is_none() && pass.failures.is_empty(), "{pass:?}");
    let next = request(&fixture.service, edit_lan(ORIGINAL_LAN)).await;
    rollback_if_pending(&fixture.service, &next).await;
    expect_lan(&fixture.service, NEW_LAN).await;
    assert!(matches!(next, Response::NetworkChangePending { .. }),
        "after storage recovers the operator must be able to edit LAN again without restarting the daemon: {next:?}");
}

// Rebuild the API with the same desired state/override writer and an injected OS
// adapter. Transaction managers and the real reconciliation worker stay real.
async fn service_with_network(
    fixture: &Fixture,
    network: Arc<dyn NetworkProvider>,
) -> ControlService {
    let config = fixture.desired.committed_config().await.unwrap();
    let dhcp = DhcpSupervisor::start(&config).await.unwrap();
    ControlService::from_runtime(
        ControlRuntime {
            active_config: config.clone(),
            base_config: config,
            network,
            dhcp,
            overrides: fixture.overrides.clone(),
            baselines: Vec::new(),
            ownership_journal: fixture.ownership.clone(),
            desired_state: fixture.desired.clone(),
            mutation_gate: fixture.gate.clone(),
        },
        ControlSubsystems::default(),
    )
}

#[test]
fn repro_activating_saved_wifi_must_not_freeze_other_operator_requests() {
    // One Tokio worker makes worker starvation reproducible. A real deployment
    // with several workers can mask it until enough storage operations stall.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (fixture, entered, release) = runtime.block_on(async {
        let mut fixture = Fixture::start(1, Duration::ZERO, 60).await;
        let mut config = fixture.desired.committed_config().await.unwrap();
        // Only preflight uses this executable; runtime Wi-Fi is the fixture's
        // process adapter, so no host supplicant or wireless device is touched.
        config.wifi_client.wpa_supplicant_binary = "/bin/true".into();
        let supervisor = WifiClientSupervisor::open_for_recovery(Default::default(), &config);
        fixture.service = service_with_network(&fixture, fixture.network.clone())
            .await
            .with_wifi_client_supervisor(supervisor);
        let created = request(
            &fixture.service,
            Request::CreateWifiClientProfile {
                profile: WifiClientProfileWriteRequest {
                    id: "office".into(),
                    ssid: "Office Wi-Fi".into(),
                    country_code: None,
                    security: crate::config::WifiClientSecurity::Wpa2,
                    priority: 0,
                    autoconnect: false,
                    passphrase: Some("office-test-password".into()),
                    clear_passphrase: false,
                },
            },
        )
        .await;
        assert!(
            matches!(created, Response::WifiClientProfile { .. }),
            "{created:?}"
        );
        expect_lan(&fixture.service, ORIGINAL_LAN).await;
        let path = fixture._directory.path().join("wifi/psk-client/wlan0");
        let (entered, release) = crate::atomic_file::pause_next_replacement(&path);
        (fixture, entered, release)
    });
    let service = fixture.service.clone();
    let handle = runtime.handle().clone();
    let worker = std::thread::spawn(move || {
        runtime.block_on(async move {
            let result = request(
                &fixture.service,
                Request::ProvisionWifiClient {
                    interface: "wlan0".into(),
                    settings: ProvisionWifiClientRequest {
                        profile_id: "office".into(),
                        ip_policy: WifiClientIpPolicy::Static {
                            cidr: "198.51.100.2/24".parse().unwrap(),
                        },
                    },
                },
            )
            .await;
            rollback_if_pending(&fixture.service, &result).await;
            assert!(
                matches!(result, Response::NetworkChangePending { .. }),
                "profile activation must work once storage is released: {result:?}"
            );
        })
    });
    entered
        .recv_timeout(WATCHDOG)
        .expect("profile activation must reach its credential write");
    let (read_tx, read_rx) = std::sync::mpsc::channel();
    let reader = handle.spawn(async move {
        let response = service
            .dispatch(Request::GetInterfaceConfig {
                interface: "eth0".into(),
            })
            .await;
        let _ = read_tx.send(response);
    });
    // Wait for an actual API response, not a sleep followed by a timing guess.
    // An OS-thread watchdog can observe starvation even if Tokio timers stall.
    let during_write = read_rx.recv_timeout(Duration::from_secs(1));
    let _ = release.send(());
    worker.join().unwrap();
    // Ensure a cancelled probe cannot be mistaken for an unresponsive service.
    let observer = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    observer.block_on(reader).unwrap();
    assert!(matches!(during_write, Ok(Response::InterfaceConfig { .. })),
        "a second operator must be able to read LAN settings while Wi-Fi credentials are being written: {during_write:?}");
}

/// A netlink request that has been sent but whose reply has not arrived yet.
/// Keep the fault at the OS boundary, not at an internal mutation mutex.
struct DelayedObservation {
    network: Arc<FakeNetworkProvider>,
    next: std::sync::Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>,
}

#[async_trait]
impl NetworkProvider for DelayedObservation {
    fn wireless_phy(&self, name: &str) -> Option<String> {
        self.network.wireless_phy(name)
    }
    async fn list_interfaces(&self) -> Result<Vec<crate::netlink::NetworkInterface>> {
        let next = self.next.lock().unwrap().take();
        if let Some((entered, release)) = next {
            let _ = entered.send(());
            let _ = release.await;
        }
        self.network.list_interfaces().await
    }
    async fn list_ipv4_addresses(&self, name: &str) -> Result<Vec<Ipv4AddressInfo>> {
        self.network.list_ipv4_addresses(name).await
    }
    async fn set_link_up(&self, name: &str) -> Result<()> {
        self.network.set_link_up(name).await
    }
    async fn set_link_down(&self, name: &str) -> Result<()> {
        self.network.set_link_down(name).await
    }
    async fn add_ipv4_address(
        &self,
        name: &str,
        address: Ipv4Addr,
        prefix: u8,
        owner: AddressOwnership,
    ) -> Result<()> {
        self.network
            .add_ipv4_address(name, address, prefix, owner)
            .await
    }
    async fn delete_ipv4_address(&self, name: &str, address: Ipv4Addr, prefix: u8) -> Result<()> {
        self.network
            .delete_ipv4_address(name, address, prefix)
            .await
    }
}

#[tokio::test(start_paused = true)]
async fn repro_shutdown_after_disconnected_lan_editor_must_have_bounded_drain() {
    let fixture = Fixture::start(0, Duration::ZERO, 60).await;
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let service = service_with_network(
        &fixture,
        Arc::new(DelayedObservation {
            network: fixture.network.clone(),
            next: std::sync::Mutex::new(Some((entered_tx, release_rx))),
        }),
    )
    .await;
    let editor = tokio::spawn({
        let service = service.clone();
        async move { service.dispatch(edit_lan(NEW_LAN)).await }
    });
    entered_rx.await.unwrap();
    // The operator loses the HTTP connection after the server accepts the edit.
    editor.abort();
    let _ = editor.await;
    // This is the same operation-drain entry point used by ApiServer on stop.
    // One virtual hour is a generous outer watchdog, not a production timeout.
    let stopped =
        tokio::time::timeout(Duration::from_secs(3600), service.finish_operations()).await;
    let _ = release_tx.send(());
    service.finish_operations().await;
    assert!(stopped.is_ok(),
        "stopping the service must reach a bounded drain/recovery decision after an accepted LAN edit stalls, even if its client disconnected");
}

#[tokio::test]
async fn lan_rollback_restores_runtime_and_storage_then_allows_a_confirmed_edit() {
    for expires in [false, true] {
        let fixture = Fixture::start(0, Duration::ZERO, if expires { 1 } else { 60 }).await;
        let applied = request(&fixture.service, edit_lan(NEW_LAN)).await;
        let Response::NetworkChangePending { change } = applied else {
            panic!("{applied:?}");
        };
        let addresses = fixture.network.list_ipv4_addresses("eth0").await.unwrap();
        assert!(addresses
            .iter()
            .any(|a| a.address == Ipv4Addr::new(192, 0, 2, 99)));
        assert_eq!(fixture.overrides.committed_revision().await, 0);
        let journal = fixture
            ._directory
            .path()
            .join("interface-transactions/eth0.json");
        assert!(journal.exists());
        // Reads and recovery remain usable through the normal admission path;
        // convenience writes cannot change the compensation target meanwhile.
        assert!(matches!(
            request(&fixture.service, Request::Ping).await,
            Response::Pong
        ));
        let blocked = request(
            &fixture.service,
            Request::WifiReload {
                interface: "eth0".into(),
            },
        )
        .await;
        assert!(
            matches!(blocked, Response::Error { message } if message.contains("transaction is pending"))
        );
        if expires {
            // No confirmation request: the daemon owns rollback even when the
            // operator has left. Wait for completion, not an assumed delay.
            tokio::time::timeout(WATCHDOG, async {
                loop {
                    let pending = request(&fixture.service, Request::PendingNetworkChanges).await;
                    if matches!(pending, Response::PendingNetworkChanges { ref changes } if changes.is_empty()) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }).await.expect("daemon timeout must finish rollback");
        } else {
            rollback_if_pending(&fixture.service, &Response::NetworkChangePending { change }).await;
        }
        expect_lan(&fixture.service, ORIGINAL_LAN).await;
        let addresses = fixture.network.list_ipv4_addresses("eth0").await.unwrap();
        assert!(addresses
            .iter()
            .any(|a| a.address == Ipv4Addr::new(192, 0, 2, 1)));
        assert!(!addresses
            .iter()
            .any(|a| a.address == Ipv4Addr::new(192, 0, 2, 99)));
        assert!(!journal.exists());
        assert!(!crate::core::recovery_control::control_path(&journal).exists());
        let base = fixture.desired.committed_config().await.unwrap();
        let disk = RuntimeOverrideManager::load(fixture._directory.path(), &base)
            .await
            .unwrap();
        assert_eq!(disk.committed_revision().await, 0);

        let next = request(&fixture.service, edit_lan(NEW_LAN)).await;
        let Response::NetworkChangePending { change } = next else {
            panic!("new edit must be admitted after rollback: {next:?}");
        };
        let committed = request(
            &fixture.service,
            Request::CommitNetworkChange {
                token: change.token,
            },
        )
        .await;
        assert!(
            matches!(committed, Response::NetworkChangeCommitted { .. }),
            "{committed:?}"
        );
        expect_lan(&fixture.service, NEW_LAN).await;
        let disk = RuntimeOverrideManager::load(fixture._directory.path(), &base)
            .await
            .unwrap();
        assert_eq!(disk.committed_revision().await, 1);
        assert_eq!(
            disk.snapshot()
                .await
                .effective_config(&base)
                .unwrap()
                .network
                .interfaces["eth0"]
                .ipv4,
            Some(NEW_LAN.parse().unwrap())
        );
    }
}
