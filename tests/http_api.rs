use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::client::conn::http1;
use hyper::{Request as HttpRequest, StatusCode};
use hyper_util::rt::TokioIo;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use tempfile::tempdir;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_rustls::TlsConnector;
use traffic_masq::api::client::ApiClient;
use traffic_masq::api::control::ControlService;
use traffic_masq::api::model::{
    ApiHttpsSettings, InterfaceOverrideRequest, ProvisioningOutputRequest, ProvisioningStage,
    ProvisioningUplinkRequest, Request, Response, RouterErrorDetail, RouterProposalRequest,
    RouterProvisioningApplyRequest, RouterProvisioningErrorDetail,
    RouterProvisioningPreviewRequest, RouterProvisioningRequest, VpnErrorDetail,
    WifiClientErrorDetail, WifiErrorDetail,
};
use traffic_masq::api::server::HttpApiServer;
use traffic_masq::auth::AuthService;
use traffic_masq::config::{
    AppConfig, InterfaceConfig, InterfaceRole, RouterConfig, TcpApiConfig, UplinkConfig,
    UplinkMode, WifiBand, WifiChannelWidth, WifiClientGlobalConfig, WifiClientSecurity, WifiConfig,
    WifiSecurity,
};
use traffic_masq::core::interface::{DhcpChangeAction, InterfaceChangePlan, InterfaceSnapshot};
use traffic_masq::core::route::{RoutePlan, RouteSnapshot};
use traffic_masq::core::router::{
    DhcpPlan, RouterDesired, RouterManager, RouterSubsystems, WifiPlan, WifiSnapshot,
};
use traffic_masq::core::router_transaction::{CoordinatorStatus, RouterTransactionCoordinator};
use traffic_masq::dhcp::supervisor::{DhcpServiceSpec, DhcpSupervisor};
use traffic_masq::firewall::{
    OwnedFirewallIntegrity, RouterDataplanePlan, RouterDataplaneSnapshot,
};
use traffic_masq::netlink::{AddressOwnership, Ipv4AddressInfo, NetworkInterface, NetworkProvider};
use traffic_masq::core::override_manager::RuntimeOverrideManager;
use traffic_masq::wifi::{HostapdSupervisor, WifiApSpec, WifiClientSpec, WifiClientSupervisor};

#[derive(Debug)]
struct FakeNetwork;

#[async_trait]
impl NetworkProvider for FakeNetwork {
    async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        Ok(vec![NetworkInterface {
            is_wireless: false,
            index: 7,
            name: "test0".to_string(),
            is_up: true,
            rx_bytes: 0,
            tx_bytes: 0,
        }])
    }

    async fn list_ipv4_addresses(&self, _interface: &str) -> Result<Vec<Ipv4AddressInfo>> {
        Ok(vec![Ipv4AddressInfo {
            interface_index: 7,
            address: Ipv4Addr::new(192, 168, 99, 1),
            prefix_len: 24,
            protocol: None,
        }])
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
        _address: Ipv4Addr,
        _prefix_len: u8,
        _ownership: AddressOwnership,
    ) -> Result<()> {
        Ok(())
    }

    async fn delete_ipv4_address(
        &self,
        _interface: &str,
        _address: Ipv4Addr,
        _prefix_len: u8,
    ) -> Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn dhcp_client_http_routes_allow_viewer_get_and_require_admin_for_put() -> Result<()> {
    let directory = tempdir()?;
    let mut config = AppConfig::default();
    config.runtime.socket_path = directory.path().join("traffic-masqd.sock");
    config.runtime.pid_path = directory.path().join("traffic-masqd.pid");
    config.runtime.state_dir = directory.path().join("state");
    config.dhcp.leases_dir = directory.path().join("leases");
    config.auth.database_path = directory.path().join("auth.sqlite3");
    config.auth.argon2_memory_kib = 1_024;
    config.auth.argon2_iterations = 1;
    let overrides = RuntimeOverrideManager::load(&config.runtime.state_dir, &config).await?;
    let dhcp = DhcpSupervisor::start(&config).await?;
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork);
    let control = ControlService::new(config.clone(), network, dhcp.clone(), overrides);
    let auth = AuthService::open(&config.auth).await?;
    auth.initialize_device_password("correct horse battery")
        .await?;
    let server = HttpApiServer::bind(&config, control, auth)?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(server.run(shutdown_rx));

    let client = ApiClient::new(&config.runtime.socket_path);
    client.login("correct horse battery").await?;
    let database_url = format!("sqlite://{}", config.auth.database_path.display());
    let pool = sqlx::SqlitePool::connect(&database_url).await?;
    sqlx::query("UPDATE users SET role = 'viewer' WHERE username = 'device'")
        .execute(&pool)
        .await?;

    assert!(matches!(
        client.request(&Request::DhcpClientStatus).await?,
        Response::DhcpClientError {
            detail: traffic_masq::api::model::DhcpClientErrorDetail::DhcpClientDisabled
        }
    ));
    let forbidden = client
        .request(&Request::ConfigureDhcpClient {
            interface: "wan0".into(),
            config: Default::default(),
        })
        .await
        .expect_err("viewer PUT must be forbidden");
    assert!(forbidden.to_string().contains("403"), "{forbidden:#}");

    sqlx::query("UPDATE users SET role = 'administrator' WHERE username = 'device'")
        .execute(&pool)
        .await?;
    assert!(matches!(
        client
            .request(&Request::ConfigureDhcpClient {
                interface: "wan0".into(),
                config: Default::default()
            })
            .await?,
        Response::DhcpClientError {
            detail: traffic_masq::api::model::DhcpClientErrorDetail::DhcpClientDisabled
        }
    ));

    shutdown_tx.send(true)?;
    server_task.await??;
    dhcp.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn authenticated_http_client_controls_daemon_over_unix_socket() -> Result<()> {
    let directory = tempdir()?;
    let mut config = AppConfig::default();
    config.runtime.socket_path = directory.path().join("traffic-masqd.sock");
    config.runtime.pid_path = directory.path().join("traffic-masqd.pid");
    config.runtime.state_dir = directory.path().join("state");
    config.dhcp.leases_dir = directory.path().join("leases");
    config.auth.database_path = directory.path().join("auth.sqlite3");
    config.auth.argon2_memory_kib = 1_024;
    config.auth.argon2_iterations = 1;
    config.network.interfaces.insert(
        "test0".to_string(),
        InterfaceConfig {
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some("192.168.99.1/24".parse()?),
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        },
    );
    config.validate()?;

    let overrides = RuntimeOverrideManager::load(&config.runtime.state_dir, &config).await?;
    let dhcp = DhcpSupervisor::start(&config).await?;
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork);
    let control = ControlService::new(config.clone(), network, dhcp.clone(), overrides.clone());
    let auth = AuthService::open(&config.auth).await?;
    auth.initialize_device_password("correct horse battery")
        .await?;

    let server = HttpApiServer::bind(&config, control, auth).expect("bind HTTP API");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(server.run(shutdown_rx));

    let admin = ApiClient::new(&config.runtime.socket_path);
    assert!(admin.auth_initialized().await?);
    assert!(admin.login("wrong password value").await.is_err());
    admin.login("correct horse battery").await?;
    match admin.request(&Request::ListInterfaces).await? {
        Response::Interfaces { interfaces } => {
            assert_eq!(interfaces.len(), 1);
            assert_eq!(interfaces[0].interface.name, "test0");
        }
        response => panic!("unexpected response: {response:?}"),
    }
    assert!(matches!(
        admin.request(&Request::Ping).await?,
        Response::Pong
    ));
    match admin.request(&Request::GetApiHttpsConfig).await? {
        Response::ApiHttpsConfig {
            active,
            desired,
            override_active,
            restart_required,
        } => {
            assert_eq!(active, ApiHttpsSettings::default());
            assert_eq!(desired, ApiHttpsSettings::default());
            assert!(!override_active);
            assert!(!restart_required);
        }
        response => panic!("unexpected response: {response:?}"),
    }
    let https_settings = ApiHttpsSettings {
        enabled: true,
        listen: "0.0.0.0:9443".to_string(),
        certificate_path: Some("/etc/traffic-masq/server.pem".to_string()),
        private_key_path: Some("/etc/traffic-masq/server-key.pem".to_string()),
    };
    match admin
        .request(&Request::ConfigureApiHttpsSettings {
            settings: https_settings.clone(),
        })
        .await?
    {
        Response::ApiHttpsConfig {
            active,
            desired,
            override_active,
            restart_required,
        } => {
            assert_eq!(active, ApiHttpsSettings::default());
            assert_eq!(desired, https_settings);
            assert!(override_active);
            assert!(restart_required);
        }
        response => panic!("unexpected response: {response:?}"),
    }
    assert!(overrides.snapshot().await.api.is_some());
    match admin.request(&Request::ResetApiHttpsSettings).await? {
        Response::ApiHttpsConfig {
            active,
            desired,
            override_active,
            restart_required,
        } => {
            assert_eq!(active, desired);
            assert!(!override_active);
            assert!(!restart_required);
        }
        response => panic!("unexpected response: {response:?}"),
    }
    assert!(overrides.snapshot().await.api.is_none());

    match admin.request(&Request::GetSecurityConfig).await? {
        Response::SecurityConfig {
            active,
            desired,
            override_active,
            restart_required,
        } => {
            assert_eq!(active, desired);
            assert!(!override_active);
            assert!(!restart_required);
        }
        response => panic!("unexpected response: {response:?}"),
    }
    let security_settings = traffic_masq::api::model::SecuritySettings {
        rollback_timeout_seconds: 120,
    };
    match admin
        .request(&Request::ConfigureSecuritySettings {
            settings: security_settings,
        })
        .await?
    {
        Response::SecurityConfig {
            desired,
            override_active,
            restart_required,
            ..
        } => {
            assert_eq!(desired, security_settings);
            assert!(override_active);
            assert!(restart_required);
        }
        response => panic!("unexpected response: {response:?}"),
    }
    assert!(overrides.snapshot().await.security.is_some());
    match admin.request(&Request::ResetSecuritySettings).await? {
        Response::SecurityConfig {
            active,
            desired,
            override_active,
            restart_required,
        } => {
            assert_eq!(active, desired);
            assert!(!override_active);
            assert!(!restart_required);
        }
        response => panic!("unexpected response: {response:?}"),
    }
    assert!(overrides.snapshot().await.security.is_none());

    let interface_config = InterfaceConfig {
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some("192.168.100.1/24".parse()?),
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    };
    let interface_edit = traffic_masq::api::model::InterfaceEditRequest {
        cidr: "192.168.100.1/24".to_string(),
        role: InterfaceRole::Output,
        managed: true,
        allow_management_change: false,
    };
    match admin
        .request(&Request::DryRunInterfaceEdit {
            interface: "test0".to_string(),
            edit: interface_edit.clone(),
        })
        .await?
    {
        Response::InterfacePlan { plan } => {
            assert_eq!(plan.interface, "test0");
            assert_eq!(plan.delete_ipv4.len(), 1);
            assert_eq!(
                plan.add_ipv4.expect("new address").address,
                Ipv4Addr::new(192, 168, 100, 1)
            );
        }
        response => panic!("unexpected response: {response:?}"),
    }

    let token = match admin
        .request(&Request::ApplyInterfaceEdit {
            interface: "test0".to_string(),
            edit: interface_edit.clone(),
        })
        .await?
    {
        Response::NetworkChangePending { change } => change.token,
        response => panic!("unexpected response: {response:?}"),
    };
    match admin.request(&Request::PendingNetworkChanges).await? {
        Response::PendingNetworkChanges { changes } => {
            assert_eq!(changes.len(), 1);
            assert_eq!(changes[0].token, token);
        }
        response => panic!("unexpected response: {response:?}"),
    }
    assert!(matches!(
        admin
            .request(&Request::RollbackNetworkChange { token })
            .await?,
        Response::NetworkChangeRolledBack { .. }
    ));
    assert!(overrides.snapshot().await.interfaces.is_empty());

    let token = match admin
        .request(&Request::ApplyInterfaceEdit {
            interface: "test0".to_string(),
            edit: interface_edit.clone(),
        })
        .await?
    {
        Response::NetworkChangePending { change } => change.token,
        response => panic!("unexpected response: {response:?}"),
    };
    assert!(matches!(
        admin
            .request(&Request::CommitNetworkChange { token })
            .await?,
        Response::NetworkChangeCommitted { .. }
    ));
    assert_eq!(
        overrides
            .snapshot()
            .await
            .interfaces
            .get("test0")
            .expect("committed override")
            .config,
        interface_config
    );

    let managed_false = InterfaceConfig {
        managed: false,
        ..interface_config.clone()
    };
    let managed_false_edit = traffic_masq::api::model::InterfaceEditRequest {
        cidr: "192.168.100.1/24".to_string(),
        role: InterfaceRole::Output,
        managed: false,
        allow_management_change: false,
    };
    let token = match admin
        .request(&Request::ApplyInterfaceEdit {
            interface: "test0".to_string(),
            edit: managed_false_edit,
        })
        .await?
    {
        Response::NetworkChangePending { change } => change.token,
        response => panic!("unexpected response: {response:?}"),
    };
    assert!(matches!(
        admin
            .request(&Request::CommitNetworkChange { token })
            .await?,
        Response::NetworkChangeCommitted { .. }
    ));
    match admin
        .request(&Request::GetInterfaceConfig {
            interface: "test0".to_string(),
        })
        .await?
    {
        Response::InterfaceConfig {
            config: Some(config),
            allow_management_change,
            ..
        } => {
            assert!(!config.managed);
            assert_eq!(config, managed_false);
            assert!(!allow_management_change);
        }
        response => panic!("unexpected response: {response:?}"),
    }
    admin
        .change_password("correct horse battery", "new correct horse battery")
        .await?;
    assert!(!admin.is_authenticated().await);
    assert!(admin.login("correct horse battery").await.is_err());
    admin.login("new correct horse battery").await?;
    admin.logout().await?;

    shutdown_tx.send(true)?;
    server_task.await??;
    dhcp.shutdown().await;
    assert!(!config.runtime.socket_path.exists());
    Ok(())
}

#[tokio::test]
async fn optional_tcp_listener_serves_http_only_after_tls_handshake() -> Result<()> {
    let directory = tempdir()?;
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".to_string()])?;
    let certificate_path = directory.path().join("server.pem");
    let private_key_path = directory.path().join("server-key.pem");
    std::fs::write(&certificate_path, cert.pem())?;
    std::fs::write(&private_key_path, key_pair.serialize_pem())?;

    let mut config = AppConfig::default();
    config.runtime.socket_path = directory.path().join("traffic-masqd.sock");
    config.runtime.pid_path = directory.path().join("traffic-masqd.pid");
    config.runtime.state_dir = directory.path().join("state");
    config.dhcp.leases_dir = directory.path().join("leases");
    config.auth.database_path = directory.path().join("auth.sqlite3");
    config.auth.argon2_memory_kib = 1_024;
    config.auth.argon2_iterations = 1;
    config.api.tcp = Some(TcpApiConfig {
        enabled: true,
        listen: "127.0.0.1:0".parse()?,
        certificate_path: Some(certificate_path),
        private_key_path: Some(private_key_path),
    });
    config.validate()?;

    let overrides = RuntimeOverrideManager::load(&config.runtime.state_dir, &config).await?;
    let dhcp = DhcpSupervisor::start(&config).await?;
    let control = ControlService::new(
        config.clone(),
        Arc::new(FakeNetwork),
        dhcp.clone(),
        overrides,
    );
    let auth = AuthService::open(&config.auth).await?;
    let server = HttpApiServer::bind(&config, control, auth)?;
    let https_address = server.tcp_local_addr()?.expect("HTTPS listener");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(server.run(shutdown_rx));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone())?;
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_config));
    let tcp = TcpStream::connect(https_address).await?;
    let server_name = rustls::pki_types::ServerName::try_from("localhost".to_string())?;
    let tls = connector.connect(server_name, tcp).await?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(tls)).await?;
    let connection_task = tokio::spawn(connection);
    let response = sender
        .send_request(
            HttpRequest::builder()
                .uri("/api/v1/status")
                .header("host", "localhost")
                .header("connection", "close")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await?.to_bytes();
    assert!(!body.is_empty());
    drop(sender);
    connection_task.await??;

    shutdown_tx.send(true)?;
    server_task.await??;
    dhcp.shutdown().await;
    Ok(())
}

#[derive(Default)]
struct FakeRouterSubsystems {
    unhealthy_interfaces: std::sync::Mutex<bool>,
    unhealthy_routes: std::sync::Mutex<bool>,
    unhealthy_dhcp: std::sync::Mutex<bool>,
    unhealthy_dataplane: std::sync::Mutex<bool>,
}

impl FakeRouterSubsystems {
    fn fail_health(&self, subsystem: &str) {
        let flag = match subsystem {
            "interfaces" => &self.unhealthy_interfaces,
            "routes" => &self.unhealthy_routes,
            "dhcp" => &self.unhealthy_dhcp,
            "dataplane" => &self.unhealthy_dataplane,
            other => panic!("unknown subsystem: {other}"),
        };
        *flag.lock().unwrap() = true;
    }
}

fn fake_dataplane_snapshot() -> RouterDataplaneSnapshot {
    RouterDataplaneSnapshot {
        ipv4_forwarding: true,
        owned: None,
        owned_firewall_integrity: OwnedFirewallIntegrity::Intact,
    }
}

#[async_trait]
impl RouterSubsystems for FakeRouterSubsystems {
    async fn plan_interfaces(&self, _: &RouterDesired) -> Result<Vec<InterfaceChangePlan>> {
        Ok(vec![InterfaceChangePlan {
            interface: "lan0".into(),
            delete_ipv4: Vec::new(),
            retag_ipv4: None,
            add_ipv4: None,
            set_link_up: false,
            management_change: false,
            dhcp_action: DhcpChangeAction::Unchanged,
            releasing_management: false,
        }])
    }

    async fn plan_uplink_wifi(
        &self,
        desired: &RouterDesired,
    ) -> Result<Vec<WifiPlan<WifiClientSpec>>> {
        Ok(desired
            .uplink_wifi
            .iter()
            .map(|spec| WifiPlan::Start {
                desired: spec.clone(),
            })
            .collect())
    }
    async fn plan_output_wifi(&self, desired: &RouterDesired) -> Result<Vec<WifiPlan<WifiApSpec>>> {
        Ok(desired
            .output_wifi
            .iter()
            .map(|spec| WifiPlan::Start {
                desired: spec.clone(),
            })
            .collect())
    }
    async fn snapshot_uplink_wifi(&self) -> Result<Vec<WifiSnapshot<WifiClientSpec>>> {
        Ok(Vec::new())
    }
    async fn snapshot_output_wifi(&self) -> Result<Vec<WifiSnapshot<WifiApSpec>>> {
        Ok(Vec::new())
    }
    async fn apply_uplink_wifi(&self, _: &[WifiPlan<WifiClientSpec>]) -> Result<()> {
        Ok(())
    }
    async fn apply_output_wifi(&self, _: &[WifiPlan<WifiApSpec>]) -> Result<()> {
        Ok(())
    }
    async fn rollback_uplink_wifi(&self, _: &[WifiSnapshot<WifiClientSpec>]) -> Result<()> {
        Ok(())
    }
    async fn rollback_output_wifi(&self, _: &[WifiSnapshot<WifiApSpec>]) -> Result<()> {
        Ok(())
    }
    async fn health_uplink_wifi(&self, _: &RouterDesired) -> Result<()> {
        Ok(())
    }
    async fn health_output_wifi(&self, _: &RouterDesired) -> Result<()> {
        Ok(())
    }
    async fn plan_routes(&self, _: &RouterDesired) -> Result<RoutePlan> {
        Ok(RoutePlan {
            add: Vec::new(),
            delete: Vec::new(),
        })
    }
    async fn plan_dhcp(&self, _: &RouterDesired) -> Result<Vec<DhcpPlan>> {
        Ok(Vec::new())
    }
    async fn plan_dataplane(&self, desired: &RouterDesired) -> Result<RouterDataplanePlan> {
        Ok(RouterDataplanePlan {
            snapshot: fake_dataplane_snapshot(),
            target: desired.dataplane.clone(),
            requires_apply: true,
        })
    }
    async fn snapshot_interfaces(&self) -> Result<Vec<InterfaceSnapshot>> {
        Ok(Vec::new())
    }
    async fn snapshot_routes(&self) -> Result<RouteSnapshot> {
        Ok(RouteSnapshot::empty())
    }
    async fn snapshot_dhcp(&self) -> Result<Vec<DhcpServiceSpec>> {
        Ok(Vec::new())
    }
    async fn snapshot_dataplane(&self) -> Result<RouterDataplaneSnapshot> {
        Ok(fake_dataplane_snapshot())
    }
    async fn apply_interfaces(&self, _: &[InterfaceChangePlan]) -> Result<()> {
        Ok(())
    }
    async fn apply_routes(&self, _: &RoutePlan) -> Result<()> {
        Ok(())
    }
    async fn apply_dhcp(&self, _: &[DhcpPlan]) -> Result<()> {
        Ok(())
    }
    async fn apply_dataplane(&self, _: &RouterDataplanePlan) -> Result<()> {
        Ok(())
    }
    async fn rollback_interfaces(&self, _: &[InterfaceSnapshot]) -> Result<()> {
        Ok(())
    }
    async fn rollback_routes(&self, _: &RouteSnapshot) -> Result<()> {
        Ok(())
    }
    async fn rollback_dhcp(&self, _: &[DhcpServiceSpec]) -> Result<()> {
        Ok(())
    }
    async fn rollback_dataplane(&self, _: &RouterDataplaneSnapshot) -> Result<()> {
        Ok(())
    }
    async fn health_interfaces(&self, _: &RouterDesired) -> Result<()> {
        if *self.unhealthy_interfaces.lock().unwrap() {
            anyhow::bail!("injected interfaces health failure");
        }
        Ok(())
    }
    async fn health_routes(&self, _: &RouterDesired) -> Result<()> {
        if *self.unhealthy_routes.lock().unwrap() {
            anyhow::bail!("injected routes health failure");
        }
        Ok(())
    }
    async fn health_dhcp(&self, _: &RouterDesired) -> Result<()> {
        if *self.unhealthy_dhcp.lock().unwrap() {
            anyhow::bail!("injected dhcp health failure");
        }
        Ok(())
    }
    async fn health_dataplane(&self, _: &RouterDesired) -> Result<()> {
        if *self.unhealthy_dataplane.lock().unwrap() {
            anyhow::bail!("injected dataplane health failure");
        }
        Ok(())
    }
}

fn router_proposal() -> RouterProposalRequest {
    RouterProposalRequest {
        set_router: Some(RouterConfig {
            enabled: true,
            uplink: Some(UplinkConfig {
                interface: "wan0".to_string(),
                mode: UplinkMode::External,
            }),
            owned_routes: Vec::new(),
            allow_default_route_change: false,
        }),
        clear_router: false,
        set_interfaces: [(
            "lan0".to_string(),
            InterfaceOverrideRequest {
                config: InterfaceConfig {
                    role: InterfaceRole::Output,
                    managed: true,
                    ipv4: Some("192.168.10.1/24".parse().unwrap()),
                    dhcp: None,
                    dhcp_client: None,
                    wifi: None,
                    wifi_client: None,
                },
                allow_management_change: false,
            },
        )]
        .into_iter()
        .collect(),
        remove_interfaces: Vec::new(),
    }
}

async fn router_enabled_test_server() -> Result<(
    tempfile::TempDir,
    AppConfig,
    ApiClient,
    tokio::task::JoinHandle<Result<()>>,
    watch::Sender<bool>,
    DhcpSupervisor,
)> {
    let mut config = AppConfig::default();
    config.network.interfaces.insert(
        "wan0".to_string(),
        InterfaceConfig {
            role: InterfaceRole::Input,
            managed: false,
            ipv4: None,
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        },
    );
    router_test_server_with(Arc::new(FakeRouterSubsystems::default()), config).await
}

async fn router_status_test_server(
    fake: Arc<FakeRouterSubsystems>,
) -> Result<(
    tempfile::TempDir,
    AppConfig,
    ApiClient,
    tokio::task::JoinHandle<Result<()>>,
    watch::Sender<bool>,
    DhcpSupervisor,
)> {
    let mut config = AppConfig::default();
    config.network.interfaces.insert(
        "wan0".to_string(),
        InterfaceConfig {
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
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some("192.168.10.1/24".parse().unwrap()),
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
        owned_routes: Vec::new(),
        allow_default_route_change: false,
    };
    router_test_server_with(fake, config).await
}

async fn router_test_server_with(
    fake: Arc<FakeRouterSubsystems>,
    mut config: AppConfig,
) -> Result<(
    tempfile::TempDir,
    AppConfig,
    ApiClient,
    tokio::task::JoinHandle<Result<()>>,
    watch::Sender<bool>,
    DhcpSupervisor,
)> {
    let directory = tempdir()?;
    config.runtime.socket_path = directory.path().join("traffic-masqd.sock");
    config.runtime.pid_path = directory.path().join("traffic-masqd.pid");
    config.runtime.state_dir = directory.path().join("state");
    config.dhcp.leases_dir = directory.path().join("leases");
    config.auth.database_path = directory.path().join("auth.sqlite3");
    config.auth.argon2_memory_kib = 1_024;
    config.auth.argon2_iterations = 1;
    config.validate()?;

    let overrides = RuntimeOverrideManager::load(&config.runtime.state_dir, &config).await?;
    let dhcp = DhcpSupervisor::start(&config).await?;
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork);
    let manager = RouterManager::new(fake);
    let coordinator =
        RouterTransactionCoordinator::new(manager, overrides.clone(), Duration::from_millis(300));
    let control = ControlService::new(config.clone(), network, dhcp.clone(), overrides)
        .with_router_coordinator(coordinator);
    let auth = AuthService::open(&config.auth).await?;
    auth.initialize_device_password("correct horse battery")
        .await?;

    let server = HttpApiServer::bind(&config, control, auth).expect("bind HTTP API");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(server.run(shutdown_rx));

    let admin = ApiClient::new(&config.runtime.socket_path);
    admin.login("correct horse battery").await?;

    Ok((directory, config, admin, server_task, shutdown_tx, dhcp))
}

#[tokio::test]
async fn router_endpoints_require_authentication() -> Result<()> {
    let (_directory, config, _admin, server_task, shutdown_tx, dhcp) =
        router_enabled_test_server().await?;

    let anonymous = ApiClient::new(&config.runtime.socket_path);
    assert!(!anonymous.is_authenticated().await);
    let error = anonymous
        .request(&Request::RouterStatus)
        .await
        .expect_err("router status must require authentication");
    assert!(error.to_string().contains("401") || error.to_string().contains("Unauthorized"));

    shutdown_tx.send(true)?;
    server_task.await??;
    dhcp.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn router_transaction_workflow_plan_apply_commit_over_http() -> Result<()> {
    let (_directory, _config, admin, server_task, shutdown_tx, dhcp) =
        router_enabled_test_server().await?;

    match admin.request(&Request::RouterStatus).await? {
        Response::RouterStatus { enabled, .. } => assert!(!enabled),
        response => panic!("unexpected response: {response:?}"),
    }

    match admin
        .request(&Request::RouterPlan {
            proposal: router_proposal(),
        })
        .await?
    {
        Response::RouterPlan { plan } => assert!(plan.desired.enabled),
        response => panic!("unexpected response: {response:?}"),
    }

    let token = match admin
        .request(&Request::RouterApply {
            proposal: router_proposal(),
        })
        .await?
    {
        Response::RouterTransactionPending { token, plan } => {
            assert!(plan.desired.enabled);
            token
        }
        response => panic!("unexpected response: {response:?}"),
    };
    assert!(!token.is_empty());

    match admin.request(&Request::RouterPendingTransaction).await? {
        Response::RouterPendingTransaction { status, .. } => {
            assert_eq!(status, CoordinatorStatus::Pending);
        }
        response => panic!("unexpected response: {response:?}"),
    }

    match admin.request(&Request::RouterCommit).await? {
        Response::RouterCommitted { revision } => assert_eq!(revision, 1),
        response => panic!("unexpected response: {response:?}"),
    }

    match admin.request(&Request::RouterStatus).await? {
        Response::RouterStatus { enabled, ready, .. } => {
            assert!(enabled);
            assert!(ready);
        }
        response => panic!("unexpected response: {response:?}"),
    }

    shutdown_tx.send(true)?;
    server_task.await??;
    dhcp.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn router_transaction_workflow_plan_apply_rollback_over_http() -> Result<()> {
    let (_directory, _config, admin, server_task, shutdown_tx, dhcp) =
        router_enabled_test_server().await?;

    match admin
        .request(&Request::RouterApply {
            proposal: router_proposal(),
        })
        .await?
    {
        Response::RouterTransactionPending { .. } => {}
        response => panic!("unexpected response: {response:?}"),
    }

    assert!(matches!(
        admin.request(&Request::RouterRollback).await?,
        Response::RouterRolledBack
    ));

    match admin.request(&Request::RouterPendingTransaction).await? {
        Response::RouterPendingTransaction { status, .. } => {
            assert_eq!(status, CoordinatorStatus::Idle);
        }
        response => panic!("unexpected response: {response:?}"),
    }

    match admin.request(&Request::RouterRollback).await? {
        Response::RouterError {
            detail: RouterErrorDetail::NoPendingTransaction,
        } => {}
        response => panic!("unexpected response: {response:?}"),
    }

    shutdown_tx.send(true)?;
    server_task.await??;
    dhcp.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn router_status_reports_unhealthy_subsystem_over_http() -> Result<()> {
    let fake = Arc::new(FakeRouterSubsystems::default());
    fake.fail_health("dhcp");
    let (_directory, _config, admin, server_task, shutdown_tx, dhcp) =
        router_status_test_server(fake).await?;

    match admin.request(&Request::RouterStatus).await? {
        Response::RouterStatus {
            enabled,
            ready,
            health,
            ..
        } => {
            assert!(enabled);
            assert!(!ready);
            assert!(health.interfaces.is_none());
            assert!(health.routes.is_none());
            assert!(health.dhcp.is_some());
            assert!(health.dataplane.is_none());
        }
        response => panic!("unexpected response: {response:?}"),
    }

    shutdown_tx.send(true)?;
    server_task.await??;
    dhcp.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn router_status_is_ready_when_all_subsystems_are_healthy_over_http() -> Result<()> {
    let fake = Arc::new(FakeRouterSubsystems::default());
    let (_directory, _config, admin, server_task, shutdown_tx, dhcp) =
        router_status_test_server(fake).await?;

    match admin.request(&Request::RouterStatus).await? {
        Response::RouterStatus {
            enabled,
            ready,
            health,
            ..
        } => {
            assert!(enabled);
            assert!(ready);
            assert!(health.interfaces.is_none());
            assert!(health.routes.is_none());
            assert!(health.dhcp.is_none());
            assert!(health.dataplane.is_none());
        }
        response => panic!("unexpected response: {response:?}"),
    }

    shutdown_tx.send(true)?;
    server_task.await??;
    dhcp.shutdown().await;
    Ok(())
}

#[derive(Debug, Clone)]
struct FakeVpnLink {
    private_key: traffic_masq::vpn::wireguard::WireGuardKey,
    up: bool,
}

#[derive(Default)]
struct FakeVpnProvider {
    links: std::sync::Mutex<std::collections::HashMap<String, FakeVpnLink>>,
}

#[async_trait]
impl traffic_masq::vpn::VpnProvider for FakeVpnProvider {
    async fn link_exists(&self, name: &str) -> Result<bool, traffic_masq::vpn::ProviderError> {
        Ok(self.links.lock().unwrap().contains_key(name))
    }

    async fn create_link(
        &self,
        name: &str,
        private_key: &traffic_masq::vpn::wireguard::WireGuardKey,
        _listen_port: Option<u16>,
    ) -> Result<(), traffic_masq::vpn::ProviderError> {
        let mut links = self.links.lock().unwrap();
        if links.contains_key(name) {
            return Err(traffic_masq::vpn::ProviderError::CommandFailed {
                command: "ip",
                status: "exit code: 1".to_string(),
                stderr: "link already exists".to_string(),
            });
        }
        links.insert(
            name.to_string(),
            FakeVpnLink {
                private_key: private_key.clone(),
                up: false,
            },
        );
        Ok(())
    }

    async fn set_addresses(
        &self,
        name: &str,
        _addresses: &[ipnet::IpNet],
    ) -> Result<(), traffic_masq::vpn::ProviderError> {
        self.require_link(name)
    }

    async fn set_peers(
        &self,
        name: &str,
        _peers: &[traffic_masq::vpn::WireGuardPeerConfig],
    ) -> Result<(), traffic_masq::vpn::ProviderError> {
        self.require_link(name)
    }

    async fn set_link_up(&self, name: &str) -> Result<(), traffic_masq::vpn::ProviderError> {
        let mut links = self.links.lock().unwrap();
        let link = links
            .get_mut(name)
            .ok_or_else(|| traffic_masq::vpn::ProviderError::NotFound(name.to_string()))?;
        link.up = true;
        Ok(())
    }

    async fn set_link_down(&self, name: &str) -> Result<(), traffic_masq::vpn::ProviderError> {
        let mut links = self.links.lock().unwrap();
        let link = links
            .get_mut(name)
            .ok_or_else(|| traffic_masq::vpn::ProviderError::NotFound(name.to_string()))?;
        link.up = false;
        Ok(())
    }

    async fn delete_link(&self, name: &str) -> Result<(), traffic_masq::vpn::ProviderError> {
        self.links
            .lock()
            .unwrap()
            .remove(name)
            .map(|_| ())
            .ok_or_else(|| traffic_masq::vpn::ProviderError::NotFound(name.to_string()))
    }

    async fn public_key(
        &self,
        name: &str,
    ) -> Result<Option<traffic_masq::vpn::wireguard::WireGuardKey>, traffic_masq::vpn::ProviderError>
    {
        use sha2::Digest;
        Ok(self.links.lock().unwrap().get(name).map(|link| {
            let digest = sha2::Sha256::digest(link.private_key.0);
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&digest[..32]);
            traffic_masq::vpn::wireguard::WireGuardKey(bytes)
        }))
    }

    async fn is_up(&self, name: &str) -> Result<bool, traffic_masq::vpn::ProviderError> {
        Ok(self
            .links
            .lock()
            .unwrap()
            .get(name)
            .map(|link| link.up)
            .unwrap_or(false))
    }
}

impl FakeVpnProvider {
    fn require_link(&self, name: &str) -> Result<(), traffic_masq::vpn::ProviderError> {
        if self.links.lock().unwrap().contains_key(name) {
            Ok(())
        } else {
            Err(traffic_masq::vpn::ProviderError::NotFound(name.to_string()))
        }
    }
}

const VPN_TEST_PRIVATE_KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
const VPN_TEST_PUBLIC_KEY: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

fn vpn_test_profile_contents() -> String {
    format!(
        "[Interface]\n\
         PrivateKey = {VPN_TEST_PRIVATE_KEY}\n\
         Address = 10.0.0.2/24\n\
         \n\
         [Peer]\n\
         PublicKey = {VPN_TEST_PUBLIC_KEY}\n\
         AllowedIPs = 0.0.0.0/0\n\
         Endpoint = 203.0.113.1:51820\n"
    )
}

#[tokio::test]
async fn vpn_profile_list_import_activate_status_deactivate_over_http() -> Result<()> {
    let directory = tempdir()?;
    let mut config = AppConfig::default();
    config.runtime.socket_path = directory.path().join("traffic-masqd.sock");
    config.runtime.pid_path = directory.path().join("traffic-masqd.pid");
    config.runtime.state_dir = directory.path().join("state");
    config.dhcp.leases_dir = directory.path().join("leases");
    config.auth.database_path = directory.path().join("auth.sqlite3");
    config.auth.argon2_memory_kib = 1_024;
    config.auth.argon2_iterations = 1;
    config.validate()?;

    let overrides = RuntimeOverrideManager::load(&config.runtime.state_dir, &config).await?;
    let dhcp = DhcpSupervisor::start(&config).await?;
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork);

    let vpn_store =
        traffic_masq::vpn::WireGuardProfileStore::new(directory.path().join("wireguard"));
    let active_profile_store = traffic_masq::vpn::ActiveProfileStore::new(
        directory.path().join("vpn-active-profile.json"),
    );
    let provider: Arc<dyn traffic_masq::vpn::VpnProvider> = Arc::new(FakeVpnProvider::default());
    let vpn_driver = traffic_masq::vpn::WireGuardVpnDriver::new(provider, vpn_store);
    let vpn_manager = Arc::new(traffic_masq::vpn::VpnManager::new(
        vpn_driver,
        active_profile_store,
    ));

    let control = ControlService::new(config.clone(), network, dhcp.clone(), overrides)
        .with_vpn_manager(vpn_manager);
    let auth = AuthService::open(&config.auth).await?;
    auth.initialize_device_password("correct horse battery")
        .await?;

    let server = HttpApiServer::bind(&config, control, auth).expect("bind HTTP API");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(server.run(shutdown_rx));

    let admin = ApiClient::new(&config.runtime.socket_path);
    admin.login("correct horse battery").await?;

    match admin.request(&Request::VpnListProfiles).await? {
        Response::VpnProfiles { profiles } => assert!(profiles.is_empty()),
        response => panic!("unexpected response: {response:?}"),
    }

    match admin
        .request(&Request::VpnImportProfile {
            name: "home.conf".to_string(),
            contents: vpn_test_profile_contents(),
        })
        .await?
    {
        Response::VpnProfileImported { name } => assert_eq!(name, "home.conf"),
        response => panic!("unexpected response: {response:?}"),
    }

    match admin.request(&Request::VpnListProfiles).await? {
        Response::VpnProfiles { profiles } => {
            assert_eq!(profiles.len(), 1);
            assert_eq!(profiles[0].name, "home.conf");

            let json = serde_json::to_string(&profiles)?;
            assert!(!json.contains(VPN_TEST_PRIVATE_KEY));
        }
        response => panic!("unexpected response: {response:?}"),
    }

    match admin.request(&Request::VpnStatus).await? {
        Response::VpnStatus { active } => assert!(active.is_none()),
        response => panic!("unexpected response: {response:?}"),
    }

    match admin
        .request(&Request::VpnActivate {
            name: "home.conf".to_string(),
        })
        .await?
    {
        Response::VpnActivated { active } => {
            assert_eq!(active.profile_name, "home.conf");
            assert!(active.up);
        }
        response => panic!("unexpected response: {response:?}"),
    }

    match admin.request(&Request::VpnStatus).await? {
        Response::VpnStatus {
            active: Some(active),
        } => {
            assert_eq!(active.profile_name, "home.conf");
            assert!(active.up);
        }
        response => panic!("unexpected response: {response:?}"),
    }

    match admin.request(&Request::VpnDeactivate).await? {
        Response::VpnDeactivated => {}
        response => panic!("unexpected response: {response:?}"),
    }

    match admin.request(&Request::VpnStatus).await? {
        Response::VpnStatus { active } => assert!(active.is_none()),
        response => panic!("unexpected response: {response:?}"),
    }

    match admin
        .request(&Request::VpnDeleteProfile {
            name: "home.conf".to_string(),
        })
        .await?
    {
        Response::VpnProfileDeleted { name } => assert_eq!(name, "home.conf"),
        response => panic!("unexpected response: {response:?}"),
    }

    shutdown_tx.send(true)?;
    server_task.await??;
    dhcp.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn vpn_requests_return_vpn_disabled_when_no_vpn_manager_is_attached() -> Result<()> {
    let directory = tempdir()?;
    let mut config = AppConfig::default();
    config.runtime.socket_path = directory.path().join("traffic-masqd.sock");
    config.runtime.pid_path = directory.path().join("traffic-masqd.pid");
    config.runtime.state_dir = directory.path().join("state");
    config.dhcp.leases_dir = directory.path().join("leases");
    config.auth.database_path = directory.path().join("auth.sqlite3");
    config.auth.argon2_memory_kib = 1_024;
    config.auth.argon2_iterations = 1;
    config.validate()?;

    let overrides = RuntimeOverrideManager::load(&config.runtime.state_dir, &config).await?;
    let dhcp = DhcpSupervisor::start(&config).await?;
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork);

    let control = ControlService::new(config.clone(), network, dhcp.clone(), overrides);
    let auth = AuthService::open(&config.auth).await?;
    auth.initialize_device_password("correct horse battery")
        .await?;

    let server = HttpApiServer::bind(&config, control, auth).expect("bind HTTP API");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(server.run(shutdown_rx));

    let admin = ApiClient::new(&config.runtime.socket_path);
    admin.login("correct horse battery").await?;

    match admin.request(&Request::VpnStatus).await? {
        Response::VpnError {
            detail: VpnErrorDetail::VpnDisabled,
        } => {}
        response => panic!("unexpected response: {response:?}"),
    }

    shutdown_tx.send(true)?;
    server_task.await??;
    dhcp.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn wifi_requests_return_wifi_disabled_when_no_supervisor_is_attached() -> Result<()> {
    let directory = tempdir()?;
    let mut config = AppConfig::default();
    config.runtime.socket_path = directory.path().join("traffic-masqd.sock");
    config.runtime.pid_path = directory.path().join("traffic-masqd.pid");
    config.runtime.state_dir = directory.path().join("state");
    config.dhcp.leases_dir = directory.path().join("leases");
    config.auth.database_path = directory.path().join("auth.sqlite3");
    config.auth.argon2_memory_kib = 1_024;
    config.auth.argon2_iterations = 1;
    config.validate()?;

    let overrides = RuntimeOverrideManager::load(&config.runtime.state_dir, &config).await?;
    let dhcp = DhcpSupervisor::start(&config).await?;
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork);

    let control = ControlService::new(config.clone(), network, dhcp.clone(), overrides);
    let auth = AuthService::open(&config.auth).await?;
    auth.initialize_device_password("correct horse battery")
        .await?;

    let server = HttpApiServer::bind(&config, control, auth).expect("bind HTTP API");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(server.run(shutdown_rx));

    let admin = ApiClient::new(&config.runtime.socket_path);
    admin.login("correct horse battery").await?;

    match admin.request(&Request::WifiStatus).await? {
        Response::WifiError {
            detail: WifiErrorDetail::WifiDisabled,
        } => {}
        response => panic!("unexpected response: {response:?}"),
    }
    match admin
        .request(&Request::GetWifiConfig {
            interface: "wlan0".to_string(),
        })
        .await?
    {
        Response::WifiError {
            detail: WifiErrorDetail::WifiDisabled,
        } => {}
        response => panic!("unexpected response: {response:?}"),
    }
    match admin
        .request(&Request::ListWifiStations {
            interface: "wlan0".to_string(),
        })
        .await?
    {
        Response::WifiError {
            detail: WifiErrorDetail::WifiDisabled,
        } => {}
        response => panic!("unexpected response: {response:?}"),
    }
    match admin
        .request(&Request::WifiClientScan {
            interface: "wlan1".to_string(),
        })
        .await?
    {
        Response::WifiClientError {
            detail: WifiClientErrorDetail::WifiClientDisabled,
        } => {}
        response => panic!("unexpected response: {response:?}"),
    }
    match admin.request(&Request::ListWifiClientProfiles).await? {
        Response::WifiClientProfileError {
            detail: traffic_masq::api::model::WifiClientProfileErrorDetail::WifiClientDisabled,
        } => {}
        response => panic!("unexpected response: {response:?}"),
    }

    shutdown_tx.send(true)?;
    server_task.await??;
    dhcp.shutdown().await;
    Ok(())
}

#[derive(Default)]
struct FakePolicyNetwork {
    interfaces: std::sync::Mutex<Vec<NetworkInterface>>,
    rules: std::sync::Mutex<Vec<traffic_masq::netlink::Ipv4RuleInfo>>,
    routes: std::sync::Mutex<Vec<traffic_masq::netlink::Ipv4RouteInfo>>,
}

impl FakePolicyNetwork {
    fn with_owned_interface() -> Arc<Self> {
        let network = Self::default();
        network.interfaces.lock().unwrap().push(NetworkInterface {
            is_wireless: false,
            index: 42,
            name: traffic_masq::vpn::manager::OWNED_INTERFACE_NAME.to_string(),
            is_up: true,
            rx_bytes: 0,
            tx_bytes: 0,
        });
        Arc::new(network)
    }
}

#[async_trait]
impl NetworkProvider for FakePolicyNetwork {
    async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        Ok(self.interfaces.lock().unwrap().clone())
    }

    async fn list_ipv4_addresses(&self, _interface: &str) -> Result<Vec<Ipv4AddressInfo>> {
        Ok(Vec::new())
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
        _address: Ipv4Addr,
        _prefix_len: u8,
        _ownership: AddressOwnership,
    ) -> Result<()> {
        Ok(())
    }

    async fn delete_ipv4_address(
        &self,
        _interface: &str,
        _address: Ipv4Addr,
        _prefix_len: u8,
    ) -> Result<()> {
        Ok(())
    }

    async fn list_ipv4_rules(&self) -> Result<Vec<traffic_masq::netlink::Ipv4RuleInfo>> {
        Ok(self.rules.lock().unwrap().clone())
    }

    async fn add_ipv4_rule(&self, rule: &traffic_masq::netlink::Ipv4RuleSpec) -> Result<()> {
        self.rules
            .lock()
            .unwrap()
            .push(traffic_masq::netlink::Ipv4RuleInfo {
                source: rule.source,
                destination: rule.destination,
                table: rule.table,
                priority: rule.priority,
                fw_mark: rule.fw_mark,
                fw_mask: rule.fw_mask,
                input_interface: rule.input_interface.clone(),
                output_interface: rule.output_interface.clone(),
            });
        Ok(())
    }

    async fn delete_ipv4_rule(&self, rule: &traffic_masq::netlink::Ipv4RuleInfo) -> Result<()> {
        self.rules.lock().unwrap().retain(|current| current != rule);
        Ok(())
    }

    async fn list_ipv4_routes(&self) -> Result<Vec<traffic_masq::netlink::Ipv4RouteInfo>> {
        Ok(self.routes.lock().unwrap().clone())
    }

    async fn add_ipv4_route(&self, route: &traffic_masq::netlink::Ipv4RouteSpec) -> Result<()> {
        self.routes
            .lock()
            .unwrap()
            .push(traffic_masq::netlink::Ipv4RouteInfo {
                destination: route.destination,
                gateway: route.gateway,
                output_interface_index: route.output_interface_index,
                table: route.table,
                metric: route.metric,
                protocol: route.protocol,
                scope: 253,
            });
        Ok(())
    }

    async fn delete_ipv4_route(&self, route: &traffic_masq::netlink::Ipv4RouteInfo) -> Result<()> {
        self.routes
            .lock()
            .unwrap()
            .retain(|current| current != route);
        Ok(())
    }
}

struct AlwaysEmptyNftExecutor;

impl traffic_masq::firewall::NftExecutor for AlwaysEmptyNftExecutor {
    fn execute(&self, arguments: &[&str], _input: &[u8]) -> Result<Vec<u8>> {
        match arguments {
            ["--json", "list", "ruleset"] => Ok(br#"{"nftables":[]}"#.to_vec()),
            ["-f", "-"] => Ok(Vec::new()),
            other => anyhow::bail!("unexpected nft invocation: {other:?}"),
        }
    }
}

#[tokio::test]
async fn vpn_policy_status_set_mode_clear_mode_over_http() -> Result<()> {
    let directory = tempdir()?;
    let mut config = AppConfig::default();
    config.network.interfaces.insert(
        "wan0".to_string(),
        InterfaceConfig {
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
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some("192.168.10.1/24".parse().unwrap()),
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
        owned_routes: Vec::new(),
        allow_default_route_change: false,
    };
    config.vpn.enabled = true;
    config.vpn.wireguard_config_dir = directory.path().join("wireguard");
    config.runtime.socket_path = directory.path().join("traffic-masqd.sock");
    config.runtime.pid_path = directory.path().join("traffic-masqd.pid");
    config.runtime.state_dir = directory.path().join("state");
    config.dhcp.leases_dir = directory.path().join("leases");
    config.auth.database_path = directory.path().join("auth.sqlite3");
    config.auth.argon2_memory_kib = 1_024;
    config.auth.argon2_iterations = 1;
    config.validate()?;

    let overrides = RuntimeOverrideManager::load(&config.runtime.state_dir, &config).await?;
    let dhcp = DhcpSupervisor::start(&config).await?;
    let network: Arc<dyn NetworkProvider> = FakePolicyNetwork::with_owned_interface();

    let vpn_store =
        traffic_masq::vpn::WireGuardProfileStore::new(config.vpn.wireguard_config_dir.clone());
    let active_profile_store = traffic_masq::vpn::ActiveProfileStore::new(
        directory.path().join("vpn-active-profile.json"),
    );
    let provider: Arc<dyn traffic_masq::vpn::VpnProvider> = Arc::new(FakeVpnProvider::default());
    let vpn_driver = traffic_masq::vpn::WireGuardVpnDriver::new(provider, vpn_store);
    let tunnel = Arc::new(traffic_masq::vpn::VpnManager::new(
        vpn_driver,
        active_profile_store,
    ));
    tunnel.import_profile("home.conf", vpn_test_profile_contents().as_bytes())?;
    tunnel.activate("home.conf").await?;

    let firewall_executor: Arc<dyn traffic_masq::firewall::NftExecutor> =
        Arc::new(AlwaysEmptyNftExecutor);
    let firewall = traffic_masq::firewall::vpn::VpnPolicyFirewallBackend::new(firewall_executor);
    let policy = Arc::new(
        traffic_masq::core::vpn_policy_manager::VpnPolicyManager::new(
            network.clone(),
            firewall,
            tunnel.clone(),
        ),
    );

    let control = ControlService::new(config.clone(), network, dhcp.clone(), overrides)
        .with_vpn_manager(tunnel)
        .with_vpn_policy_manager(policy);
    let auth = AuthService::open(&config.auth).await?;
    auth.initialize_device_password("correct horse battery")
        .await?;

    let server = HttpApiServer::bind(&config, control, auth).expect("bind HTTP API");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(server.run(shutdown_rx));

    let admin = ApiClient::new(&config.runtime.socket_path);
    admin.login("correct horse battery").await?;

    match admin.request(&Request::VpnPolicyStatus).await? {
        Response::VpnPolicyStatus { status } => {
            assert_eq!(status.mode, traffic_masq::config::VpnPolicyMode::Direct);
            assert!(!status.mode_override_active);
            assert!(!status.policy_active);
            assert!(status.tunnel_healthy);
        }
        response => panic!("unexpected response: {response:?}"),
    }

    match admin
        .request(&Request::VpnPolicySetMode {
            mode: traffic_masq::config::VpnPolicyMode::Vpn,
        })
        .await?
    {
        Response::VpnPolicyStatus { status } => {
            assert_eq!(status.mode, traffic_masq::config::VpnPolicyMode::Vpn);
            assert!(status.mode_override_active);
            assert!(status.policy_active);
            assert!(status.kill_switch_active);
        }
        response => panic!("unexpected response: {response:?}"),
    }

    match admin.request(&Request::VpnPolicyStatus).await? {
        Response::VpnPolicyStatus { status } => {
            assert_eq!(status.mode, traffic_masq::config::VpnPolicyMode::Vpn);
            assert!(status.policy_active);
        }
        response => panic!("unexpected response: {response:?}"),
    }

    match admin.request(&Request::VpnPolicyClearMode).await? {
        Response::VpnPolicyStatus { status } => {
            assert_eq!(status.mode, traffic_masq::config::VpnPolicyMode::Direct);
            assert!(!status.mode_override_active);
            assert!(!status.policy_active);
        }
        response => panic!("unexpected response: {response:?}"),
    }

    shutdown_tx.send(true)?;
    server_task.await??;
    dhcp.shutdown().await;
    Ok(())
}

#[derive(Debug)]
struct ProvisioningNetwork;

#[async_trait]
impl NetworkProvider for ProvisioningNetwork {
    async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        Ok(vec![
            NetworkInterface {
                index: 1,
                name: "eth0".to_string(),
                is_up: true,
                rx_bytes: 0,
                tx_bytes: 0,
                is_wireless: false,
            },
            NetworkInterface {
                index: 2,
                name: "wlan-up".to_string(),
                is_up: true,
                rx_bytes: 0,
                tx_bytes: 0,
                is_wireless: true,
            },
            NetworkInterface {
                index: 3,
                name: "wlan-out".to_string(),
                is_up: true,
                rx_bytes: 0,
                tx_bytes: 0,
                is_wireless: true,
            },
        ])
    }

    async fn list_ipv4_addresses(&self, interface: &str) -> Result<Vec<Ipv4AddressInfo>> {
        Ok(if interface == "eth0" {
            vec![Ipv4AddressInfo {
                interface_index: 1,
                address: Ipv4Addr::new(192, 168, 1, 20),
                prefix_len: 24,
                protocol: None,
            }]
        } else {
            Vec::new()
        })
    }

    async fn set_link_up(&self, _name: &str) -> Result<()> {
        Ok(())
    }

    async fn set_link_down(&self, _name: &str) -> Result<()> {
        Ok(())
    }

    async fn add_ipv4_address(
        &self,
        _: &str,
        _: Ipv4Addr,
        _: u8,
        _: AddressOwnership,
    ) -> Result<()> {
        Ok(())
    }

    async fn delete_ipv4_address(&self, _: &str, _: Ipv4Addr, _: u8) -> Result<()> {
        Ok(())
    }
}

struct ProvisioningServer {
    _directory: tempfile::TempDir,
    config: AppConfig,
    admin: ApiClient,
    server_task: tokio::task::JoinHandle<Result<()>>,
    shutdown: watch::Sender<bool>,
    dhcp: DhcpSupervisor,
    auth_database: String,
}

impl ProvisioningServer {
    async fn set_role(&self, role: &str) -> Result<()> {
        let pool = sqlx::SqlitePool::connect(&self.auth_database).await?;
        sqlx::query("UPDATE users SET role = ? WHERE username = 'device'")
            .bind(role)
            .execute(&pool)
            .await?;
        Ok(())
    }

    async fn shutdown(self) -> Result<()> {
        self.shutdown.send(true)?;
        self.server_task.await??;
        self.dhcp.shutdown().await;
        Ok(())
    }
}

async fn provisioning_test_server() -> Result<ProvisioningServer> {
    let directory = tempdir()?;
    let mut config = AppConfig::default();
    config.runtime.socket_path = directory.path().join("traffic-masqd.sock");
    config.runtime.pid_path = directory.path().join("traffic-masqd.pid");
    config.runtime.state_dir = directory.path().join("state");
    config.dhcp.leases_dir = directory.path().join("leases");
    config.auth.database_path = directory.path().join("auth.sqlite3");
    config.auth.argon2_memory_kib = 1_024;
    config.auth.argon2_iterations = 1;
    config.wifi = WifiConfig {
        enabled: true,
        hostapd_binary: std::path::PathBuf::from("/usr/sbin/hostapd"),
        runtime_dir: directory.path().join("hostapd"),
        restart_backoff_seconds: 1,
    };
    config.wifi_client = WifiClientGlobalConfig {
        enabled: true,
        wpa_supplicant_binary: std::path::PathBuf::from("/usr/sbin/wpa_supplicant"),
        runtime_dir: directory.path().join("wpa_supplicant"),
        restart_backoff_seconds: 1,
    };
    config.validate()?;

    let overrides = RuntimeOverrideManager::load(&config.runtime.state_dir, &config).await?;
    let dhcp = DhcpSupervisor::start(&config).await?;

    let wifi = HostapdSupervisor::start(&config).await?;
    let wifi_client = WifiClientSupervisor::start(&config).await?;
    let manager = RouterManager::new(Arc::new(FakeRouterSubsystems::default()));
    let coordinator =
        RouterTransactionCoordinator::new(manager, overrides.clone(), Duration::from_secs(30));
    let control = ControlService::new(
        config.clone(),
        Arc::new(ProvisioningNetwork) as Arc<dyn NetworkProvider>,
        dhcp.clone(),
        overrides,
    )
    .with_router_coordinator(coordinator)
    .with_wifi_supervisor(wifi)
    .with_wifi_client_supervisor(wifi_client);

    let auth = AuthService::open(&config.auth).await?;
    auth.initialize_device_password("correct horse battery")
        .await?;
    let server = HttpApiServer::bind(&config, control, auth)?;
    let (shutdown, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(server.run(shutdown_rx));

    let admin = ApiClient::new(&config.runtime.socket_path);
    admin.login("correct horse battery").await?;
    let auth_database = format!("sqlite://{}", config.auth.database_path.display());

    Ok(ProvisioningServer {
        _directory: directory,
        config,
        admin,
        server_task,
        shutdown,
        dhcp,
        auth_database,
    })
}

fn provisioning_request() -> RouterProvisioningRequest {
    RouterProvisioningRequest {
        uplink: ProvisioningUplinkRequest {
            interface: "wlan-up".to_string(),
            ssid: "upstream".to_string(),
            country_code: Some("PL".to_string()),
            security: WifiClientSecurity::Wpa2,
        },
        output: ProvisioningOutputRequest {
            interface: "wlan-out".to_string(),
            ssid: "traffic-masq".to_string(),
            country_code: Some("PL".to_string()),
            band: WifiBand::Ghz2,
            channel: 6,
            channel_width: WifiChannelWidth::Ht20,
            security: WifiSecurity::Wpa2,
            hidden: false,
            client_isolation: false,
            max_stations: 32,
        },
        downstream: Default::default(),
        allow_management_change: false,
    }
}

fn provisioning_preview(provisioning: RouterProvisioningRequest) -> Request {
    Request::RouterProvisioningPreview {
        request: RouterProvisioningPreviewRequest {
            provisioning,
            uplink_secret_pending: true,
            output_secret_pending: true,
        },
    }
}

fn provisioning_apply(provisioning: RouterProvisioningRequest) -> Request {
    Request::RouterProvisioningApply {
        request: RouterProvisioningApplyRequest {
            provisioning,
            uplink_passphrase: Some("upstream-secret".to_string()),
            output_passphrase: Some("downstream-secret".to_string()),
        },
    }
}

#[tokio::test]
async fn provisioning_minimal_request_previews_applies_and_commits_over_http() -> Result<()> {
    let server = provisioning_test_server().await?;

    let preview = match server
        .admin
        .request(&provisioning_preview(provisioning_request()))
        .await?
    {
        Response::RouterProvisioningPreview { preview } => preview,
        response => panic!("unexpected response: {response:?}"),
    };
    assert_eq!(
        preview.downstream.interface_ipv4,
        "10.77.0.1/24".parse().unwrap()
    );
    assert_eq!(preview.downstream.pool_start, Ipv4Addr::new(10, 77, 0, 100));
    assert_eq!(preview.downstream.pool_end, Ipv4Addr::new(10, 77, 0, 200));
    assert_eq!(preview.downstream.lease_seconds, 3_600);
    assert!(preview.downstream.dns_servers.is_empty());

    let token = match server
        .admin
        .request(&provisioning_apply(provisioning_request()))
        .await?
    {
        Response::RouterProvisioningApplied { token, preview } => {
            assert_eq!(
                preview.downstream.interface_ipv4,
                "10.77.0.1/24".parse().unwrap()
            );
            token
        }
        response => panic!("unexpected response: {response:?}"),
    };
    assert!(!token.is_empty());

    match server
        .admin
        .request(&Request::RouterProvisioningStatus)
        .await?
    {
        Response::RouterProvisioningStatus { status } => {
            assert_eq!(status.stage, ProvisioningStage::AwaitingConfirmation);
            assert_eq!(status.coordinator, CoordinatorStatus::Pending);
        }
        response => panic!("unexpected response: {response:?}"),
    }

    assert!(matches!(
        server.admin.request(&Request::RouterCommit).await?,
        Response::RouterCommitted { revision: 1 }
    ));

    match server
        .admin
        .request(&Request::RouterProvisioningStatus)
        .await?
    {
        Response::RouterProvisioningStatus { status } => {
            assert_eq!(status.stage, ProvisioningStage::Ready);
            assert!(status.enabled);
            assert!(status.ready);
        }
        response => panic!("unexpected response: {response:?}"),
    }

    match server.admin.request(&Request::RouterStatus).await? {
        Response::RouterStatus { enabled, ready, .. } => {
            assert!(enabled);
            assert!(ready);
        }
        response => panic!("unexpected response: {response:?}"),
    }

    server.shutdown().await
}

#[tokio::test]
async fn provisioning_apply_requires_an_administrator_while_preview_and_status_do_not() -> Result<()>
{
    let server = provisioning_test_server().await?;
    server.set_role("viewer").await?;

    assert!(matches!(
        server
            .admin
            .request(&provisioning_preview(provisioning_request()))
            .await?,
        Response::RouterProvisioningPreview { .. }
    ));
    assert!(matches!(
        server
            .admin
            .request(&Request::RouterProvisioningStatus)
            .await?,
        Response::RouterProvisioningStatus { .. }
    ));
    let forbidden = server
        .admin
        .request(&provisioning_apply(provisioning_request()))
        .await
        .expect_err("a viewer must not be able to provision");
    assert!(forbidden.to_string().contains("403"), "{forbidden:#}");

    let anonymous = ApiClient::new(&server.config.runtime.socket_path);
    let unauthorized = anonymous
        .request(&Request::RouterProvisioningStatus)
        .await
        .expect_err("provisioning status must require authentication");
    assert!(
        unauthorized.to_string().contains("401")
            || unauthorized.to_string().contains("Unauthorized"),
        "{unauthorized:#}"
    );

    server.set_role("administrator").await?;
    assert!(matches!(
        server
            .admin
            .request(&provisioning_apply(provisioning_request()))
            .await?,
        Response::RouterProvisioningApplied { .. }
    ));

    server.shutdown().await
}

#[tokio::test]
async fn provisioning_conflicts_and_rollback_are_typed_over_http() -> Result<()> {
    let server = provisioning_test_server().await?;

    match server
        .admin
        .request(&Request::RouterProvisioningApply {
            request: RouterProvisioningApplyRequest {
                provisioning: provisioning_request(),
                uplink_passphrase: Some("upstream-secret".to_string()),
                output_passphrase: None,
            },
        })
        .await?
    {
        Response::RouterProvisioningError {
            detail: RouterProvisioningErrorDetail::OutputSecretMissing { interface },
        } => assert_eq!(interface, "wlan-out"),
        response => panic!("unexpected response: {response:?}"),
    }

    let mut conflicting = provisioning_request();
    conflicting.downstream.interface_ipv4 = Some("192.168.1.1/24".parse().unwrap());
    match server
        .admin
        .request(&provisioning_preview(conflicting))
        .await?
    {
        Response::RouterProvisioningError {
            detail: RouterProvisioningErrorDetail::SubnetConflict { requested, .. },
        } => assert_eq!(requested, "192.168.1.0/24".parse().unwrap()),
        response => panic!("unexpected response: {response:?}"),
    }

    assert!(matches!(
        server
            .admin
            .request(&provisioning_apply(provisioning_request()))
            .await?,
        Response::RouterProvisioningApplied { .. }
    ));
    assert!(matches!(
        server
            .admin
            .request(&provisioning_apply(provisioning_request()))
            .await?,
        Response::RouterProvisioningError {
            detail: RouterProvisioningErrorDetail::TransactionPending
        }
    ));

    assert!(matches!(
        server.admin.request(&Request::RouterRollback).await?,
        Response::RouterRolledBack
    ));
    match server
        .admin
        .request(&Request::RouterProvisioningStatus)
        .await?
    {
        Response::RouterProvisioningStatus { status } => {
            assert_eq!(status.stage, ProvisioningStage::Inactive);
            assert!(!status.enabled);
            assert!(status.failures.is_empty());
        }
        response => panic!("unexpected response: {response:?}"),
    }

    server.shutdown().await
}

#[tokio::test]
async fn provisioning_responses_never_carry_key_material_over_http() -> Result<()> {
    let server = provisioning_test_server().await?;

    let applied = server
        .admin
        .request(&provisioning_apply(provisioning_request()))
        .await?;
    let encoded = serde_json::to_string(&applied)?;
    assert!(!encoded.contains("downstream-secret"), "{encoded}");
    assert!(!encoded.contains("upstream-secret"), "{encoded}");
    assert!(!encoded.contains("passphrase"), "{encoded}");

    assert!(matches!(
        server.admin.request(&Request::RouterCommit).await?,
        Response::RouterCommitted { .. }
    ));

    for request in [
        Request::RouterProvisioningStatus,
        provisioning_preview(provisioning_request()),
    ] {
        let encoded = serde_json::to_string(&server.admin.request(&request).await?)?;
        assert!(!encoded.contains("downstream-secret"), "{encoded}");
        assert!(!encoded.contains("upstream-secret"), "{encoded}");
        assert!(!encoded.contains("passphrase"), "{encoded}");
    }

    server.shutdown().await
}

#[tokio::test]
async fn provisioning_applies_advanced_overrides_over_http() -> Result<()> {
    let server = provisioning_test_server().await?;
    let mut request = provisioning_request();
    request.downstream.interface_ipv4 = Some("172.20.5.1/24".parse().unwrap());
    request.downstream.pool_start = Some(Ipv4Addr::new(172, 20, 5, 20));
    request.downstream.pool_end = Some(Ipv4Addr::new(172, 20, 5, 40));
    request.downstream.dns_servers = vec![Ipv4Addr::new(9, 9, 9, 9)];
    request.downstream.lease_seconds = Some(600);

    match server
        .admin
        .request(&provisioning_apply(request.clone()))
        .await?
    {
        Response::RouterProvisioningApplied { preview, .. } => {
            assert_eq!(
                preview.downstream.interface_ipv4,
                "172.20.5.1/24".parse().unwrap()
            );
            assert_eq!(preview.downstream.pool_end, Ipv4Addr::new(172, 20, 5, 40));
            assert_eq!(preview.downstream.lease_seconds, 600);
            assert_eq!(
                preview.downstream.dns_servers,
                vec![Ipv4Addr::new(9, 9, 9, 9)]
            );
        }
        response => panic!("unexpected response: {response:?}"),
    }
    assert!(matches!(
        server.admin.request(&Request::RouterCommit).await?,
        Response::RouterCommitted { .. }
    ));

    match server
        .admin
        .request(&Request::GetInterfaceConfig {
            interface: "wlan-out".to_string(),
        })
        .await?
    {
        Response::InterfaceConfig { config, .. } => {
            let config = config.expect("provisioned output interface");
            assert_eq!(config.ipv4, Some("172.20.5.1/24".parse().unwrap()));
            let dhcp = config.dhcp.expect("provisioned downstream DHCP settings");
            assert_eq!(dhcp.pool_start, Ipv4Addr::new(172, 20, 5, 20));
            assert_eq!(dhcp.pool_end, Ipv4Addr::new(172, 20, 5, 40));
            assert_eq!(dhcp.lease_seconds, Some(600));
            assert_eq!(dhcp.dns_servers, vec![Ipv4Addr::new(9, 9, 9, 9)]);
        }
        response => panic!("unexpected response: {response:?}"),
    }

    server.shutdown().await
}
