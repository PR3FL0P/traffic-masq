use crate::netlink::AddressOwnership;
use std::net::Ipv4Addr;

use anyhow::Result;
use async_trait::async_trait;

use crate::netlink::NetworkInterface;

use super::*;
use super::dhcp::*;
use super::interfaces::*;

#[test]
fn default_ap_dhcp_pool_uses_larger_side_of_router_in_24() {
    let settings = default_dhcp_settings("192.168.50.128/24".parse().unwrap()).unwrap();
    assert_eq!(settings.router, Ipv4Addr::new(192, 168, 50, 128));
    assert_eq!(settings.pool_start, Ipv4Addr::new(192, 168, 50, 1));
    assert_eq!(settings.pool_end, Ipv4Addr::new(192, 168, 50, 127));
    assert!(settings.dns_servers.is_empty());
    assert_eq!(settings.lease_seconds, None);
}

#[test]
fn default_ap_dhcp_pool_supports_30() {
    let settings = default_dhcp_settings("192.168.50.1/30".parse().unwrap()).unwrap();
    assert_eq!(settings.pool_start, Ipv4Addr::new(192, 168, 50, 2));
    assert_eq!(settings.pool_end, Ipv4Addr::new(192, 168, 50, 2));
}

#[test]
fn default_ap_dhcp_pool_rejects_31() {
    let error = default_dhcp_settings("192.168.50.0/31".parse().unwrap()).unwrap_err();
    assert!(error.contains("/31"));
}

struct FakeNetwork {
    addresses: Vec<Ipv4AddressInfo>,
}

#[async_trait]
impl NetworkProvider for FakeNetwork {
    async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        Ok(Vec::new())
    }

    async fn list_ipv4_addresses(&self, _interface: &str) -> Result<Vec<Ipv4AddressInfo>> {
        Ok(self.addresses.clone())
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

fn address(address: [u8; 4], prefix_len: u8) -> Ipv4AddressInfo {
    Ipv4AddressInfo {
        interface_index: 1,
        address: Ipv4Addr::from(address),
        prefix_len,
        protocol: None,
    }
}

fn dhcp_config() -> DhcpInterfaceConfig {
    DhcpInterfaceConfig {
        pool_start: Ipv4Addr::new(192, 168, 50, 10),
        pool_end: Ipv4Addr::new(192, 168, 50, 100),
        router: Ipv4Addr::new(192, 168, 50, 1),
        dns_servers: Vec::new(),
        lease_seconds: None,
    }
}

#[test]
fn interface_edit_preserves_client_and_nat_settings() {
    let existing = InterfaceConfig {
        role: InterfaceRole::Input,
        managed: true,
        ipv4: None,
        dhcp: None,
        dhcp_client: Some(crate::config::DhcpClientInterfaceConfig::default()),
        wifi: None,
        wifi_client: Some(crate::config::WifiClientConfig {
            ssid: "uplink".into(),
            country_code: None,
            security: crate::config::WifiClientSecurity::Open,
            passphrase_file: None,
        }),
        nat: false,
    };
    let (config, _) = interface_edit_request_to_config(
        InterfaceEditRequest {
            cidr: String::new(),
            role: InterfaceRole::Input,
            managed: true,
            allow_management_change: false,
        },
        Some(&existing),
    )
    .unwrap();
    assert_eq!(config.dhcp_client, existing.dhcp_client);
    assert_eq!(config.wifi_client, existing.wifi_client);
    assert!(!config.nat);
    config.validate("wlan0").unwrap();
}

#[test]
fn interface_edit_request_preserves_existing_dhcp_settings() {
    let existing_dhcp = dhcp_config();
    let existing = InterfaceConfig {
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some("192.168.50.1/24".parse().expect("valid cidr")),
        dhcp: Some(existing_dhcp.clone()),
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
        nat: true,
    };
    let edit = InterfaceEditRequest {
        cidr: "192.168.60.1/24".to_string(),
        role: InterfaceRole::Output,
        managed: true,
        allow_management_change: false,
    };

    let (config, allow_management_change) =
        interface_edit_request_to_config(edit, Some(&existing)).expect("edit must convert");

    assert_eq!(
        config.ipv4,
        Some("192.168.60.1/24".parse().expect("valid cidr"))
    );
    assert_eq!(config.dhcp, Some(existing_dhcp));
    assert!(!allow_management_change);
}

fn wifi_ap_config_fixture(ssid: &str) -> crate::config::WifiApConfig {
    crate::config::WifiApConfig {
        ssid: ssid.to_string(),
        country_code: None,
        band: crate::config::WifiBand::Ghz2,
        channel: 6,
        channel_width: crate::config::WifiChannelWidth::Ht20,
        security: crate::config::WifiSecurity::Wpa2,
        hidden: false,
        client_isolation: false,
        max_stations: 32,
        passphrase_file: None,
    }
}

#[test]
fn interface_edit_request_preserves_existing_wifi_settings_while_managed() {
    let existing_wifi = wifi_ap_config_fixture("home-net");
    let existing = InterfaceConfig {
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some("192.168.50.1/24".parse().expect("valid cidr")),
        dhcp: None,
        dhcp_client: None,
        wifi: Some(existing_wifi.clone()),
        wifi_client: None,
        nat: true,
    };
    let edit = InterfaceEditRequest {
        cidr: "192.168.60.1/24".to_string(),
        role: InterfaceRole::Output,
        managed: true,
        allow_management_change: false,
    };

    let (config, _) =
        interface_edit_request_to_config(edit, Some(&existing)).expect("edit must convert");

    assert_eq!(
        config.wifi,
        Some(existing_wifi),
        "an edit that never touches Managed must not silently wipe the AP config"
    );
}

#[test]
fn interface_edit_request_drops_wifi_settings_when_unmanaged() {
    let existing = InterfaceConfig {
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some("192.168.50.1/24".parse().expect("valid cidr")),
        dhcp: None,
        dhcp_client: None,
        wifi: Some(wifi_ap_config_fixture("home-net")),
        wifi_client: None,
        nat: true,
    };
    let edit = InterfaceEditRequest {
        cidr: String::new(),
        role: InterfaceRole::Output,
        managed: false,
        allow_management_change: true,
    };

    let (config, _) =
        interface_edit_request_to_config(edit, Some(&existing)).expect("edit must convert");

    assert_eq!(config.wifi, None);
}

#[test]
fn unmanaging_an_interface_with_a_running_ap_requires_explicit_confirmation() {
    let current = InterfaceConfig {
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some("192.168.50.1/24".parse().expect("valid cidr")),
        dhcp: None,
        dhcp_client: None,
        wifi: Some(wifi_ap_config_fixture("home-net")),
        wifi_client: None,
        nat: true,
    };
    let mut new_config = current.clone();
    new_config.managed = false;
    new_config.wifi = None;

    let error = ControlService::validate_router_service_management(
        "wlan0",
        Some(&current),
        &new_config,
        false,
    )
    .unwrap_err();
    assert!(error.to_string().contains("access point 'home-net'"));

    assert!(ControlService::validate_router_service_management(
        "wlan0",
        Some(&current),
        &new_config,
        true,
    )
    .is_ok());
}

#[test]
fn unmanaging_an_interface_with_no_router_services_needs_no_confirmation() {
    let current = InterfaceConfig {
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some("192.168.50.1/24".parse().expect("valid cidr")),
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
        nat: true,
    };
    let mut new_config = current.clone();
    new_config.managed = false;

    assert!(ControlService::validate_router_service_management(
        "wlan0",
        Some(&current),
        &new_config,
        false,
    )
    .is_ok());
}

#[test]
fn an_empty_cidr_removes_the_configured_address() {
    let existing = InterfaceConfig {
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some("192.168.50.1/24".parse().expect("valid cidr")),
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
        nat: true,
    };
    let edit = InterfaceEditRequest {
        cidr: String::new(),
        role: InterfaceRole::Output,
        managed: true,
        allow_management_change: false,
    };

    let (config, _) =
        interface_edit_request_to_config(edit, Some(&existing)).expect("edit must convert");

    assert_eq!(config.ipv4, None);
    assert!(
        config.managed,
        "removing the address must not stop managing the interface"
    );
}

#[test]
fn removing_the_address_under_a_dhcp_server_says_what_to_disable_first() {
    let existing = InterfaceConfig {
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some("192.168.50.1/24".parse().expect("valid cidr")),
        dhcp: Some(dhcp_config()),
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
        nat: true,
    };
    let edit = InterfaceEditRequest {
        cidr: String::new(),
        role: InterfaceRole::Output,
        managed: true,
        allow_management_change: false,
    };

    let error = interface_edit_request_to_config(edit, Some(&existing))
        .expect_err("a DHCP server cannot outlive the address it serves");
    assert_eq!(
        error.to_string(),
        "cannot remove the IPv4 address while a DHCP server is configured on this interface; disable DHCP first"
    );
}

#[tokio::test]
async fn selects_the_only_address_whose_subnet_validates_dhcp() {
    let network = FakeNetwork {
        addresses: vec![address([10, 0, 0, 1], 24), address([192, 168, 50, 1], 24)],
    };

    let spec = build_dhcp_spec("test0", dhcp_config(), &network, 3_600)
        .await
        .expect("one live subnet should match");

    assert_eq!(spec.server_ip, Ipv4Addr::new(192, 168, 50, 1));
    assert_eq!(spec.prefix_len, 24);
}

#[tokio::test]
async fn rejects_when_no_address_has_a_valid_dhcp_subnet() {
    let network = FakeNetwork {
        addresses: vec![address([10, 0, 0, 1], 24), address([172, 16, 0, 1], 16)],
    };

    let error = build_dhcp_spec("test0", dhcp_config(), &network, 3_600)
        .await
        .expect_err("no live subnet should match");

    assert!(error
        .to_string()
        .contains("no IPv4 address with a subnet valid"));
}

#[tokio::test]
async fn selects_the_live_address_that_matches_the_dhcp_router() {
    let network = FakeNetwork {
        addresses: vec![
            address([192, 168, 50, 1], 24),
            address([192, 168, 50, 2], 24),
        ],
    };

    let spec = build_dhcp_spec("test0", dhcp_config(), &network, 3_600)
        .await
        .expect("the DHCP router must identify the server address");

    assert_eq!(spec.server_ip, Ipv4Addr::new(192, 168, 50, 1));
    assert_eq!(spec.router, spec.server_ip);
}

use crate::config::{RouterConfig, UplinkConfig, UplinkMode};
use crate::core::interface::{DhcpChangeAction, InterfaceChangePlan};
use crate::core::route::{RoutePlan, RouteSnapshot};
use crate::core::router::{DhcpPlan, RouterSubsystems};
use crate::firewall::{OwnedFirewallIntegrity, RouterDataplanePlan, RouterDataplaneSnapshot};
use tempfile::tempdir;

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

fn router_base_config() -> AppConfig {
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
            nat: true,
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
            nat: true,
        },
    );
    config
}

fn router_proposal() -> RouterProposalRequest {
    RouterProposalRequest {
        set_router: Some(RouterConfig {
            forwarding: None,
            vpn_chain: Vec::new(),
            enabled: true,
            uplink: Some(UplinkConfig {
                interface: "wan0".to_string(),
                mode: UplinkMode::External,
            }),
            owned_routes: Vec::new(),
            allow_default_route_change: false,
        }),
        clear_router: false,
        set_interfaces: Default::default(),
        remove_interfaces: Vec::new(),
    }
}

/// Removing a runtime override has to fall back to the file configuration.
/// It only does so if overrides are merged onto the file config: merging
/// onto the already-merged startup config leaves the removed value baked in,
/// and makes the service disagree with the runtime reconcile loop, which
/// merges onto the file config.
#[tokio::test]
async fn removing_an_interface_override_falls_back_to_the_file_configuration() {
    let directory = tempdir().expect("tempdir");
    let base = router_base_config();
    let overrides = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .expect("overrides");

    let overridden = InterfaceConfig {
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some("10.9.9.1/24".parse().unwrap()),
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
        nat: true,
    };
    overrides
        .set_interface("lan0".to_string(), overridden, false)
        .await
        .expect("set override");

    // Constructed the way the daemon does it: the effective configuration
    // for what is running, the file configuration as the merge base.
    let effective = overrides
        .snapshot()
        .await
        .effective_config(&base)
        .expect("effective");
    let dhcp = DhcpSupervisor::start(&effective)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let service = ControlService::new(effective, network, dhcp, overrides.clone())
        .with_base_config(base.clone());

    let candidate = overrides
        .build_candidate(&RouterIntentProposal::new().remove_interface("lan0"))
        .await
        .expect("candidate");
    overrides
        .commit_candidate(&candidate)
        .await
        .expect("commit removal");

    match service
        .dispatch(Request::GetInterfaceConfig {
            interface: "lan0".to_string(),
        })
        .await
    {
        Response::InterfaceConfig { config, .. } => {
            let config = config.expect("lan0 is still in the file configuration");
            assert_eq!(
                config.ipv4, base.network.interfaces["lan0"].ipv4,
                "after the override is removed the file value must be reported"
            );
        }
        response => panic!("unexpected response: {response:?}"),
    }
}

#[tokio::test]
async fn api_https_settings_dispatch_persists_override_and_requires_restart() {
    let directory = tempdir().expect("tempdir");
    let mut config = router_base_config();
    config.api.tcp = Some(TcpApiConfig {
        enabled: false,
        listen: "127.0.0.1:8443".parse().expect("socket address"),
        certificate_path: None,
        private_key_path: None,
    });
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let service = ControlService::new(config.clone(), network, dhcp, overrides.clone());

    let settings = ApiHttpsSettings {
        enabled: true,
        listen: "0.0.0.0:9443".to_string(),
        certificate_path: Some("/etc/traffic-masq/server.pem".to_string()),
        private_key_path: Some("/etc/traffic-masq/server-key.pem".to_string()),
    };

    match service
        .dispatch(Request::ConfigureApiHttpsSettings {
            settings: settings.clone(),
        })
        .await
    {
        Response::ApiHttpsConfig {
            active,
            desired,
            override_active,
            restart_required,
        } => {
            assert!(!active.enabled);
            assert_eq!(desired, settings);
            assert!(override_active);
            assert!(restart_required);
        }
        response => panic!("unexpected response: {response:?}"),
    }
    assert!(overrides.snapshot().await.api.is_some());

    match service.dispatch(Request::ResetApiHttpsSettings).await {
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
}

#[tokio::test]
async fn security_settings_dispatch_persists_override_and_requires_restart() {
    let directory = tempdir().expect("tempdir");
    let config = router_base_config();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let service = ControlService::new(config.clone(), network, dhcp, overrides.clone());

    let settings = SecuritySettings {
        rollback_timeout_seconds: 120,
    };

    match service
        .dispatch(Request::ConfigureSecuritySettings { settings })
        .await
    {
        Response::SecurityConfig {
            active,
            desired,
            override_active,
            restart_required,
        } => {
            assert_eq!(active.rollback_timeout_seconds, 60);
            assert_eq!(desired, settings);
            assert!(override_active);
            assert!(restart_required);
        }
        response => panic!("unexpected response: {response:?}"),
    }
    assert!(overrides.snapshot().await.security.is_some());

    match service.dispatch(Request::ResetSecuritySettings).await {
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
}

async fn router_enabled_service() -> (ControlService, tempfile::TempDir) {
    router_enabled_service_with(Arc::new(FakeRouterSubsystems::default())).await
}

async fn router_enabled_service_with(
    fake: Arc<FakeRouterSubsystems>,
) -> (ControlService, tempfile::TempDir) {
    router_service_with_config(fake, router_base_config()).await
}

fn router_base_config_with_router_enabled() -> AppConfig {
    let mut config = router_base_config();
    config.router = RouterConfig {
        forwarding: None,
        vpn_chain: Vec::new(),
        enabled: true,
        uplink: Some(UplinkConfig {
            interface: "wan0".to_string(),
            mode: UplinkMode::External,
        }),
        owned_routes: Vec::new(),
        allow_default_route_change: false,
    };
    config
}

async fn router_service_with_config(
    fake: Arc<FakeRouterSubsystems>,
    mut config: AppConfig,
) -> (ControlService, tempfile::TempDir) {
    let directory = tempdir().expect("tempdir");
    config.runtime.state_dir = directory.path().to_path_buf();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let manager = crate::core::router::RouterManager::new(fake);
    let coordinator = RouterTransactionCoordinator::new(
        manager,
        overrides.clone(),
        Duration::from_millis(200),
    );
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let service = ControlService::new(config, network, dhcp, overrides)
        .with_router_coordinator(coordinator);
    (service, directory)
}

#[tokio::test]
async fn router_requests_are_rejected_when_router_mode_is_disabled() {
    let directory = tempdir().expect("tempdir");
    let config = router_base_config();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let service = ControlService::new(config, network, dhcp, overrides);

    for request in [
        Request::RouterStatus,
        Request::RouterPlan {
            proposal: router_proposal(),
        },
        Request::RouterApply {
            proposal: router_proposal(),
        },
        Request::RouterCommit {
            token: String::new(),
        },
        Request::RouterRollback {
            token: String::new(),
        },
        Request::RouterPendingTransaction,
    ] {
        let response = service.dispatch(request).await;
        assert!(matches!(
            response,
            Response::RouterError {
                detail: RouterErrorDetail::RouterDisabled
            }
        ));
    }
}

#[tokio::test]
async fn enabled_router_without_uplink_reports_unconfigured_provisioning_state() {
    let mut config = router_base_config_with_router_enabled();
    config.router.uplink = None;
    let (service, _directory) =
        router_service_with_config(Arc::new(FakeRouterSubsystems::default()), config).await;

    match service.dispatch(Request::RouterProvisioningStatus).await {
        Response::RouterProvisioningStatus { status } => {
            assert_eq!(status.stage, ProvisioningStage::Unconfigured);
            assert!(status.enabled);
            assert!(!status.ready);
            assert_eq!(status.coordinator, CoordinatorStatus::Idle);
        }
        other => panic!("expected unconfigured provisioning status, got {other:?}"),
    }
}

#[tokio::test]
async fn enabled_router_without_uplink_with_routes_reports_ready_provisioning_state() {
    let mut config = router_base_config_with_router_enabled();
    config.router.uplink = None;
    config.router.owned_routes = vec![crate::config::OwnedIpv4RouteConfig {
        destination: "10.0.0.0/24".parse().expect("destination"),
        gateway: Some(std::net::Ipv4Addr::new(192, 168, 1, 1)),
        output_interface: None,
        table: 254,
        metric: Some(100),
    }];
    let (service, _directory) =
        router_service_with_config(Arc::new(FakeRouterSubsystems::default()), config).await;

    match service.dispatch(Request::RouterProvisioningStatus).await {
        Response::RouterProvisioningStatus { status } => {
            assert_eq!(status.stage, ProvisioningStage::Ready);
            assert!(status.enabled);
            assert!(status.ready);
            assert_eq!(status.coordinator, CoordinatorStatus::Idle);
        }
        other => panic!("expected ready provisioning status, got {other:?}"),
    }
}

#[tokio::test]
async fn router_plan_apply_commit_workflow_dispatches_through_control_service() {
    let (service, _directory) = router_enabled_service().await;

    match service.dispatch(Request::RouterStatus).await {
        Response::RouterStatus { enabled, .. } => assert!(!enabled),
        other => panic!("unexpected response: {other:?}"),
    }

    match service
        .dispatch(Request::RouterPlan {
            proposal: router_proposal(),
        })
        .await
    {
        Response::RouterPlan { plan } => assert!(plan.desired.enabled),
        other => panic!("unexpected response: {other:?}"),
    }

    let token = match service
        .dispatch(Request::RouterApply {
            proposal: router_proposal(),
        })
        .await
    {
        Response::RouterTransactionPending { token, plan } => {
            assert!(plan.desired.enabled);
            token
        }
        other => panic!("unexpected response: {other:?}"),
    };
    assert!(!token.is_empty());

    match service.dispatch(Request::RouterPendingTransaction).await {
        Response::RouterPendingTransaction { status, .. } => {
            assert_eq!(
                status,
                crate::core::router_transaction::CoordinatorStatus::Pending
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }

    match service
        .dispatch(Request::RouterCommit {
            token: service
                .router
                .as_ref()
                .unwrap()
                .pending_token()
                .await
                .unwrap_or_default(),
        })
        .await
    {
        Response::RouterCommitted { revision } => assert_eq!(revision, 1),
        other => panic!("unexpected response: {other:?}"),
    }

    match service.dispatch(Request::RouterStatus).await {
        Response::RouterStatus { enabled, ready, .. } => {
            assert!(enabled);
            assert!(ready);
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn router_plan_apply_rollback_workflow_dispatches_through_control_service() {
    let (service, _directory) = router_enabled_service().await;

    match service
        .dispatch(Request::RouterApply {
            proposal: router_proposal(),
        })
        .await
    {
        Response::RouterTransactionPending { .. } => {}
        other => panic!("unexpected response: {other:?}"),
    }

    match service
        .dispatch(Request::RouterRollback {
            token: service
                .router
                .as_ref()
                .unwrap()
                .pending_token()
                .await
                .unwrap_or_default(),
        })
        .await
    {
        Response::RouterRolledBack => {}
        other => panic!("unexpected response: {other:?}"),
    }

    match service.dispatch(Request::RouterPendingTransaction).await {
        Response::RouterPendingTransaction { status, .. } => {
            assert_eq!(
                status,
                crate::core::router_transaction::CoordinatorStatus::Idle
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }

    match service
        .dispatch(Request::RouterRollback {
            token: service
                .router
                .as_ref()
                .unwrap()
                .pending_token()
                .await
                .unwrap_or_default(),
        })
        .await
    {
        Response::RouterError {
            detail: RouterErrorDetail::NoPendingTransaction,
        } => {}
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn second_concurrent_router_apply_is_rejected_with_typed_conflict() {
    let (service, _directory) = router_enabled_service().await;

    service
        .dispatch(Request::RouterApply {
            proposal: router_proposal(),
        })
        .await;

    match service
        .dispatch(Request::RouterApply {
            proposal: router_proposal(),
        })
        .await
    {
        Response::RouterError {
            detail: RouterErrorDetail::TransactionPending,
        } => {}
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn router_status_reports_ready_false_only_for_the_unhealthy_subsystem() {
    for subsystem in ["interfaces", "routes", "dhcp", "dataplane"] {
        let fake = Arc::new(FakeRouterSubsystems::default());
        fake.fail_health(subsystem);
        let (service, _directory) =
            router_service_with_config(fake, router_base_config_with_router_enabled()).await;

        match service.dispatch(Request::RouterStatus).await {
            Response::RouterStatus {
                enabled,
                ready,
                health,
                ..
            } => {
                assert!(enabled, "subsystem {subsystem}");
                assert!(!ready, "subsystem {subsystem}");
                let statuses = [
                    ("interfaces", health.interfaces.is_some()),
                    ("routes", health.routes.is_some()),
                    ("dhcp", health.dhcp.is_some()),
                    ("dataplane", health.dataplane.is_some()),
                ];
                for (name, is_unhealthy) in statuses {
                    assert_eq!(
                        is_unhealthy,
                        name == subsystem,
                        "subsystem {subsystem}: unexpected health.{name} state"
                    );
                }
            }
            other => panic!("unexpected response for {subsystem}: {other:?}"),
        }
    }
}

#[tokio::test]
async fn router_status_is_ready_when_all_subsystems_are_healthy() {
    let fake = Arc::new(FakeRouterSubsystems::default());
    let (service, _directory) =
        router_service_with_config(fake, router_base_config_with_router_enabled()).await;

    match service.dispatch(Request::RouterStatus).await {
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
        other => panic!("unexpected response: {other:?}"),
    }
}

use crate::test_support::FakeVpnProvider;
use std::collections::HashMap as StdHashMap;
use std::sync::Mutex as StdMutex;

const VALID_VPN_PRIVATE_KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
const VALID_VPN_PUBLIC_KEY: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
const OTHER_VPN_PRIVATE_KEY: &str = "SBmoW+ojuoJZeh6P/2sh8aetgAy4dTZTAO8UzHzKtGY=";

fn valid_vpn_profile_contents() -> String {
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

async fn vpn_enabled_service() -> (ControlService, tempfile::TempDir) {
    vpn_enabled_service_with_provider(FakeVpnProvider::default()).await
}

async fn vpn_enabled_service_with_provider(
    provider: FakeVpnProvider,
) -> (ControlService, tempfile::TempDir) {
    let directory = tempdir().expect("tempdir");
    let config = router_base_config();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let vpn_store = crate::vpn::WireGuardProfileStore::new(directory.path().join("wireguard"));
    let active_profile_store =
        crate::vpn::ActiveProfileStore::new(directory.path().join("active-profile.json"));
    let provider: Arc<dyn crate::vpn::VpnProvider> = Arc::new(provider);
    let driver = crate::vpn::WireGuardVpnDriver::new(provider, vpn_store);
    let vpn_manager = Arc::new(crate::vpn::VpnManager::new(driver, active_profile_store));
    let service =
        ControlService::new(config, network, dhcp, overrides).with_vpn_manager(vpn_manager);
    (service, directory)
}

#[tokio::test]
async fn vpn_requests_are_rejected_when_vpn_is_disabled() {
    let directory = tempdir().expect("tempdir");
    let config = router_base_config();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let service = ControlService::new(config, network, dhcp, overrides);

    for request in [
        Request::VpnListProfiles,
        Request::VpnImportProfile {
            name: "home.conf".to_string(),
            contents: valid_vpn_profile_contents(),
        },
        Request::VpnDeleteProfile {
            name: "home.conf".to_string(),
        },
        Request::VpnStatus,
        Request::VpnActivate {
            name: "home.conf".to_string(),
        },
        Request::VpnDeactivate,
    ] {
        let response = service.dispatch(request).await;
        assert!(matches!(
            response,
            Response::VpnError {
                detail: VpnErrorDetail::VpnDisabled
            }
        ));
    }
}

#[tokio::test]
async fn vpn_import_list_delete_profile_round_trip_never_leaks_the_private_key() {
    let (service, _directory) = vpn_enabled_service().await;

    match service
        .dispatch(Request::VpnImportProfile {
            name: "home.conf".to_string(),
            contents: valid_vpn_profile_contents(),
        })
        .await
    {
        Response::VpnProfileImported { name } => assert_eq!(name, "home.conf"),
        other => panic!("unexpected response: {other:?}"),
    }

    let profiles = match service.dispatch(Request::VpnListProfiles).await {
        Response::VpnProfiles { profiles } => profiles,
        other => panic!("unexpected response: {other:?}"),
    };
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].name, "home.conf");
    assert!(profiles[0].size_bytes > 0);

    let debug = format!("{profiles:?}");
    assert!(!debug.contains(VALID_VPN_PRIVATE_KEY));
    let json = serde_json::to_string(&profiles).expect("serialize");
    assert!(!json.contains(VALID_VPN_PRIVATE_KEY));

    match service
        .dispatch(Request::VpnDeleteProfile {
            name: "home.conf".to_string(),
        })
        .await
    {
        Response::VpnProfileDeleted { name } => assert_eq!(name, "home.conf"),
        other => panic!("unexpected response: {other:?}"),
    }

    match service.dispatch(Request::VpnListProfiles).await {
        Response::VpnProfiles { profiles } => assert!(profiles.is_empty()),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn vpn_delete_missing_profile_returns_typed_not_found() {
    let (service, _directory) = vpn_enabled_service().await;

    match service
        .dispatch(Request::VpnDeleteProfile {
            name: "missing.conf".to_string(),
        })
        .await
    {
        Response::VpnError {
            detail: VpnErrorDetail::NotFound { name },
        } => assert_eq!(name, "missing.conf"),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn vpn_activate_status_deactivate_workflow_dispatches_through_control_service() {
    let (service, _directory) = vpn_enabled_service().await;
    service
        .dispatch(Request::VpnImportProfile {
            name: "home.conf".to_string(),
            contents: valid_vpn_profile_contents(),
        })
        .await;

    match service.dispatch(Request::VpnStatus).await {
        Response::VpnStatus { active } => assert!(active.is_none()),
        other => panic!("unexpected response: {other:?}"),
    }

    match service
        .dispatch(Request::VpnActivate {
            name: "home.conf".to_string(),
        })
        .await
    {
        Response::VpnActivated { active } => {
            assert_eq!(active.profile_name, "home.conf");
            assert!(active.up);
        }
        other => panic!("unexpected response: {other:?}"),
    }

    match service.dispatch(Request::VpnStatus).await {
        Response::VpnStatus {
            active: Some(active),
        } => {
            assert_eq!(active.profile_name, "home.conf");
            assert!(active.up);
        }
        other => panic!("unexpected response: {other:?}"),
    }

    match service.dispatch(Request::VpnDeactivate).await {
        Response::VpnDeactivated => {}
        other => panic!("unexpected response: {other:?}"),
    }

    match service.dispatch(Request::VpnStatus).await {
        Response::VpnStatus { active } => assert!(active.is_none()),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn vpn_activate_conflict_with_foreign_interface_returns_typed_error() {
    let provider = FakeVpnProvider::default();
    provider.seed_foreign_link(
        crate::vpn::manager::OWNED_INTERFACE_NAME,
        OTHER_VPN_PRIVATE_KEY,
    );
    let (service, _directory) = vpn_enabled_service_with_provider(provider).await;
    service
        .dispatch(Request::VpnImportProfile {
            name: "home.conf".to_string(),
            contents: valid_vpn_profile_contents(),
        })
        .await;

    match service
        .dispatch(Request::VpnActivate {
            name: "home.conf".to_string(),
        })
        .await
    {
        Response::VpnError {
            detail: VpnErrorDetail::ForeignInterfaceConflict,
        } => {}
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn vpn_activate_when_already_active_returns_typed_error() {
    let (service, _directory) = vpn_enabled_service().await;
    service
        .dispatch(Request::VpnImportProfile {
            name: "home.conf".to_string(),
            contents: valid_vpn_profile_contents(),
        })
        .await;
    match service
        .dispatch(Request::VpnActivate {
            name: "home.conf".to_string(),
        })
        .await
    {
        Response::VpnActivated { .. } => {}
        other => panic!("unexpected response: {other:?}"),
    }

    match service
        .dispatch(Request::VpnActivate {
            name: "home.conf".to_string(),
        })
        .await
    {
        Response::VpnError {
            detail: VpnErrorDetail::AlreadyActive,
        } => {}
        other => panic!("unexpected response: {other:?}"),
    }
}

use crate::firewall::vpn::test_support::nft_ruleset;
use crate::firewall::vpn::{VpnPolicyFirewallBackend, VpnPolicyFirewallDesired};

fn vpn_policy_firewall_desired() -> VpnPolicyFirewallDesired {
    VpnPolicyFirewallDesired {
        protected_subnets: vec!["192.168.10.1/24".parse().unwrap()],
        vpn_interface: OWNED_INTERFACE_NAME.to_string(),
        physical_uplink: "wan0".to_string(),
    }
}

#[derive(Default)]
struct StatefulFakeNftExecutor {
    installed: StdMutex<Option<VpnPolicyFirewallDesired>>,
}

impl NftExecutor for StatefulFakeNftExecutor {
    fn execute(&self, arguments: &[&str], input: &[u8]) -> Result<Vec<u8>> {
        match arguments {
            ["--json", "list", "ruleset"] => {
                Ok(nft_ruleset(self.installed.lock().unwrap().as_ref()))
            }
            ["-f", "-"] => {
                let batch = String::from_utf8_lossy(input);
                let mut installed = self.installed.lock().unwrap();
                *installed = if batch.contains("table inet traffic_masq_vpn {") {
                    Some(vpn_policy_firewall_desired())
                } else {
                    None
                };
                Ok(Vec::new())
            }
            other => anyhow::bail!("unexpected nft invocation: {other:?}"),
        }
    }
}

#[derive(Default)]
struct FakePolicyNetwork {
    interfaces: StdMutex<Vec<NetworkInterface>>,
    rules: StdMutex<Vec<crate::netlink::Ipv4RuleInfo>>,
    routes: StdMutex<Vec<crate::netlink::Ipv4RouteInfo>>,
}

impl FakePolicyNetwork {
    fn with_owned_interface() -> Arc<Self> {
        let network = Self::default();
        network.interfaces.lock().unwrap().push(NetworkInterface {
            is_wireless: false,
            index: 42,
            name: OWNED_INTERFACE_NAME.to_string(),
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

    async fn list_ipv4_rules(&self) -> Result<Vec<crate::netlink::Ipv4RuleInfo>> {
        Ok(self.rules.lock().unwrap().clone())
    }

    async fn add_ipv4_rule(&self, rule: &crate::netlink::Ipv4RuleSpec) -> Result<()> {
        self.rules
            .lock()
            .unwrap()
            .push(crate::netlink::Ipv4RuleInfo {
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

    async fn delete_ipv4_rule(&self, rule: &crate::netlink::Ipv4RuleInfo) -> Result<()> {
        self.rules.lock().unwrap().retain(|current| current != rule);
        Ok(())
    }

    async fn list_ipv4_routes(&self) -> Result<Vec<crate::netlink::Ipv4RouteInfo>> {
        Ok(self.routes.lock().unwrap().clone())
    }

    async fn add_ipv4_route(&self, route: &crate::netlink::Ipv4RouteSpec) -> Result<()> {
        self.routes
            .lock()
            .unwrap()
            .push(crate::netlink::Ipv4RouteInfo {
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

    async fn delete_ipv4_route(&self, route: &crate::netlink::Ipv4RouteInfo) -> Result<()> {
        self.routes
            .lock()
            .unwrap()
            .retain(|current| current != route);
        Ok(())
    }
}

fn router_and_vpn_base_config(wireguard_dir: std::path::PathBuf) -> AppConfig {
    let mut config = router_base_config_with_router_enabled();
    config.vpn.enabled = true;
    config.vpn.wireguard_config_dir = wireguard_dir;
    config
}

struct VpnPolicyFixture {
    service: ControlService,
    overrides: RuntimeOverrideManager,
    network: Arc<FakePolicyNetwork>,
    _directory: tempfile::TempDir,
}

async fn vpn_policy_fixture(activate_tunnel: bool) -> VpnPolicyFixture {
    vpn_policy_fixture_with_router_chain(activate_tunnel, false).await
}

async fn vpn_policy_fixture_with_router_chain(
    activate_tunnel: bool,
    router_chain: bool,
) -> VpnPolicyFixture {
    let directory = tempdir().expect("tempdir");
    let mut config = router_and_vpn_base_config(directory.path().join("wireguard"));
    if router_chain {
        config.router.vpn_chain = vec![crate::config::VpnHopConfig {
            profile_name: "chain.conf".to_string(),
        }];
    }
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network = FakePolicyNetwork::with_owned_interface();

    let vpn_store =
        crate::vpn::WireGuardProfileStore::new(config.vpn.wireguard_config_dir.clone());
    let active_profile_store =
        crate::vpn::ActiveProfileStore::new(directory.path().join("active-profile.json"));
    let provider: Arc<dyn crate::vpn::VpnProvider> = Arc::new(FakeVpnProvider::default());
    let driver = crate::vpn::WireGuardVpnDriver::new(provider, vpn_store);
    let tunnel = Arc::new(crate::vpn::VpnManager::new(driver, active_profile_store));

    if activate_tunnel {
        tunnel
            .import_profile("home.conf", valid_vpn_profile_contents().as_bytes())
            .expect("import profile");
        tunnel.activate("home.conf").await.expect("activate tunnel");
    }

    let executor: Arc<dyn NftExecutor> = Arc::new(StatefulFakeNftExecutor::default());
    let firewall = VpnPolicyFirewallBackend::new(executor);
    let policy = Arc::new(VpnPolicyManager::new(
        network.clone(),
        firewall,
        tunnel.clone(),
    ));

    let service = ControlService::new(config, network.clone(), dhcp, overrides.clone())
        .with_vpn_manager(tunnel)
        .with_vpn_policy_manager(policy);

    VpnPolicyFixture {
        service,
        overrides,
        network,
        _directory: directory,
    }
}

#[tokio::test]
async fn vpn_policy_requests_are_rejected_when_vpn_is_disabled() {
    let directory = tempdir().expect("tempdir");
    let config = router_base_config();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let service = ControlService::new(config, network, dhcp, overrides);

    for request in [
        Request::VpnPolicyStatus,
        Request::VpnPolicySetMode {
            mode: VpnPolicyMode::Vpn,
        },
        Request::VpnPolicyClearMode,
    ] {
        match service.dispatch(request).await {
            Response::VpnPolicyError {
                detail: VpnPolicyErrorDetail::VpnDisabled,
            } => {}
            other => panic!("unexpected response: {other:?}"),
        }
    }
}

#[tokio::test]
async fn legacy_vpn_policy_mutations_are_blocked_when_router_chain_is_configured() {
    let fixture = vpn_policy_fixture_with_router_chain(true, true).await;

    for request in [
        Request::VpnPolicySetMode {
            mode: VpnPolicyMode::Vpn,
        },
        Request::VpnPolicyClearMode,
    ] {
        match fixture.service.dispatch(request).await {
            Response::VpnPolicyError {
                detail: VpnPolicyErrorDetail::Other { message },
            } => assert!(message.contains("router VPN chain")),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    assert!(fixture.network.rules.lock().unwrap().is_empty());
    assert!(fixture.network.routes.lock().unwrap().is_empty());
    assert!(fixture.overrides.snapshot().await.vpn_mode.is_none());
}

#[tokio::test]
async fn vpn_policy_set_mode_vpn_activates_when_tunnel_is_healthy_and_persists() {
    let fixture = vpn_policy_fixture(true).await;

    match fixture
        .service
        .dispatch(Request::VpnPolicySetMode {
            mode: VpnPolicyMode::Vpn,
        })
        .await
    {
        Response::VpnPolicyStatus { status } => {
            assert_eq!(status.mode, VpnPolicyMode::Vpn);
            assert!(status.mode_override_active);
            assert!(status.policy_active);
            assert!(status.kill_switch_active);
            assert!(status.tunnel_healthy);
            assert_eq!(status.physical_uplink.as_deref(), Some("wan0"));
            assert_eq!(
                status.protected_subnets,
                vec!["192.168.10.1/24".parse().unwrap()]
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }

    assert_eq!(
        fixture.overrides.effective_vpn_mode().await,
        VpnPolicyMode::Vpn
    );

    match fixture.service.dispatch(Request::VpnPolicyStatus).await {
        Response::VpnPolicyStatus { status } => assert!(status.policy_active),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn vpn_policy_set_mode_restores_runtime_snapshot_when_persistence_fails() {
    let fixture = vpn_policy_fixture(true).await;
    std::fs::create_dir(fixture._directory.path().join("runtime-overrides.json"))
        .expect("block override file rename");

    let response = fixture
        .service
        .dispatch(Request::VpnPolicySetMode {
            mode: VpnPolicyMode::Vpn,
        })
        .await;
    assert!(matches!(
        response,
        Response::VpnPolicyError {
            detail: VpnPolicyErrorDetail::Other { .. }
        }
    ));
    assert_eq!(
        fixture.overrides.effective_vpn_mode().await,
        VpnPolicyMode::Direct
    );
    match fixture.service.dispatch(Request::VpnPolicyStatus).await {
        Response::VpnPolicyStatus { status } => assert!(!status.policy_active),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn vpn_policy_set_mode_vpn_fails_closed_without_active_tunnel() {
    let fixture = vpn_policy_fixture(false).await;

    match fixture
        .service
        .dispatch(Request::VpnPolicySetMode {
            mode: VpnPolicyMode::Vpn,
        })
        .await
    {
        Response::VpnPolicyError {
            detail: VpnPolicyErrorDetail::TunnelUnhealthy { message },
        } => {
            assert!(message.contains("no active VPN tunnel"));
        }
        other => panic!("unexpected response: {other:?}"),
    }

    assert_eq!(
        fixture.overrides.effective_vpn_mode().await,
        VpnPolicyMode::Direct
    );

    match fixture.service.dispatch(Request::VpnPolicyStatus).await {
        Response::VpnPolicyStatus { status } => {
            assert!(!status.policy_active);
            assert!(!status.mode_override_active);
            assert_eq!(status.mode, VpnPolicyMode::Direct);
            assert!(!status.tunnel_healthy);
            assert!(status.tunnel.is_none());
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn vpn_policy_set_mode_direct_after_vpn_deactivates_and_persists() {
    let fixture = vpn_policy_fixture(true).await;
    fixture
        .service
        .dispatch(Request::VpnPolicySetMode {
            mode: VpnPolicyMode::Vpn,
        })
        .await;

    match fixture
        .service
        .dispatch(Request::VpnPolicySetMode {
            mode: VpnPolicyMode::Direct,
        })
        .await
    {
        Response::VpnPolicyStatus { status } => {
            assert_eq!(status.mode, VpnPolicyMode::Direct);
            assert!(status.mode_override_active);
            assert!(!status.policy_active);
        }
        other => panic!("unexpected response: {other:?}"),
    }

    assert_eq!(
        fixture.overrides.effective_vpn_mode().await,
        VpnPolicyMode::Direct
    );
}

#[tokio::test]
async fn vpn_policy_clear_mode_restores_runtime_snapshot_when_persistence_fails() {
    let fixture = vpn_policy_fixture(true).await;
    let response = fixture
        .service
        .dispatch(Request::VpnPolicySetMode {
            mode: VpnPolicyMode::Vpn,
        })
        .await;
    assert!(matches!(response, Response::VpnPolicyStatus { .. }));

    let override_path = fixture._directory.path().join("runtime-overrides.json");
    std::fs::remove_file(&override_path).expect("remove override file");
    std::fs::create_dir(&override_path).expect("block override file rename");

    let response = fixture.service.dispatch(Request::VpnPolicyClearMode).await;
    assert!(matches!(
        response,
        Response::VpnPolicyError {
            detail: VpnPolicyErrorDetail::Other { .. }
        }
    ));
    assert_eq!(
        fixture.overrides.effective_vpn_mode().await,
        VpnPolicyMode::Vpn
    );
    match fixture.service.dispatch(Request::VpnPolicyStatus).await {
        Response::VpnPolicyStatus { status } => assert!(status.policy_active),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn vpn_policy_clear_mode_falls_back_to_base_default() {
    let fixture = vpn_policy_fixture(true).await;
    fixture
        .service
        .dispatch(Request::VpnPolicySetMode {
            mode: VpnPolicyMode::Vpn,
        })
        .await;
    assert!(fixture.overrides.snapshot().await.vpn_mode.is_some());

    match fixture.service.dispatch(Request::VpnPolicyClearMode).await {
        Response::VpnPolicyStatus { status } => {
            assert_eq!(status.mode, VpnPolicyMode::Direct);
            assert!(!status.mode_override_active);
            assert!(!status.policy_active);
        }
        other => panic!("unexpected response: {other:?}"),
    }

    assert!(fixture.overrides.snapshot().await.vpn_mode.is_none());
}

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering as WifiOrdering};

use crate::config::{WifiBand, WifiChannelWidth, WifiConfig, WifiSecurity};
use crate::wifi::process::SupervisedProcess;
use crate::wifi::{HostapdSupervisor as WifiSupervisor, ProcessError as WifiProcessError};

struct FakeWifiHostapd {
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
    ctrl_path: std::path::PathBuf,
}

impl FakeWifiHostapd {
    fn spawn(ctrl_path: std::path::PathBuf, config_path: std::path::PathBuf) -> Self {
        let socket =
            std::os::unix::net::UnixDatagram::bind(&ctrl_path).expect("bind fake ctrl socket");
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("set read timeout");
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shutdown_for_thread = shutdown.clone();

        let join = std::thread::spawn(move || {
            let read_ssid = |path: &std::path::Path| -> String {
                let content = std::fs::read_to_string(path).expect("read fake config");
                let hex = content
                    .lines()
                    .find_map(|line| line.strip_prefix("ssid2="))
                    .expect("ssid2 present");
                let bytes: Vec<u8> = (0..hex.len())
                    .step_by(2)
                    .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
                    .collect();
                String::from_utf8(bytes).expect("utf8 ssid")
            };
            let mut ssid = read_ssid(&config_path);
            let mut buffer = [0u8; 4096];
            while !shutdown_for_thread.load(WifiOrdering::Relaxed) {
                let (read, from) = match socket.recv_from(&mut buffer) {
                    Ok(result) => result,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(_) => break,
                };
                let command = String::from_utf8_lossy(&buffer[..read]).into_owned();
                let reply = if command == "PING" {
                    "PONG\n".to_string()
                } else if command == "STATUS" {
                    format!("state=ENABLED\nssid[0]={ssid}\nbssid[0]=02:00:00:00:00:00\nnum_sta[0]=0\n")
                } else if command == "RELOAD" {
                    ssid = read_ssid(&config_path);
                    "OK\n".to_string()
                } else if command == "STA-FIRST" {
                    "FAIL\n".to_string()
                } else if command.starts_with("DEAUTHENTICATE ") {
                    "OK\n".to_string()
                } else {
                    "UNKNOWN COMMAND\n".to_string()
                };
                let _ = socket.send_to_addr(reply.as_bytes(), &from);
            }
        });

        Self {
            shutdown,
            join: Some(join),
            ctrl_path,
        }
    }
}

impl Drop for FakeWifiHostapd {
    fn drop(&mut self) {
        self.shutdown.store(true, WifiOrdering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        let _ = std::fs::remove_file(&self.ctrl_path);
    }
}

#[derive(Default)]
struct FakeWifiProcess {
    fail_spawn: std::sync::atomic::AtomicBool,
    responders: StdMutex<HashMap<u32, FakeWifiHostapd>>,
    configs: StdMutex<HashMap<u32, std::path::PathBuf>>,
    next_pid: AtomicU32,
}

impl FakeWifiProcess {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            next_pid: AtomicU32::new(2000),
            ..Default::default()
        })
    }
}

#[async_trait]
impl SupervisedProcess for FakeWifiProcess {
    async fn spawn(
        &self,
        _binary: &std::path::Path,
        config_path: &std::path::Path,
    ) -> Result<u32, WifiProcessError> {
        if self.fail_spawn.load(WifiOrdering::SeqCst) {
            return Err(WifiProcessError::Spawn {
                binary: _binary.to_path_buf(),
                source: std::io::Error::other("injected restoration spawn failure"),
            });
        }
        let pid = self.next_pid.fetch_add(1, WifiOrdering::Relaxed);
        let ctrl_path = config_path.with_extension("");
        let responder = FakeWifiHostapd::spawn(ctrl_path, config_path.to_path_buf());
        self.responders.lock().unwrap().insert(pid, responder);
        self.configs
            .lock()
            .unwrap()
            .insert(pid, config_path.to_path_buf());
        Ok(pid)
    }

    async fn is_alive(&self, pid: u32) -> Result<bool, WifiProcessError> {
        Ok(self.responders.lock().unwrap().contains_key(&pid))
    }

    async fn cmdline_contains(
        &self,
        pid: u32,
        config_path: &std::path::Path,
    ) -> Result<bool, WifiProcessError> {
        Ok(self
            .configs
            .lock()
            .unwrap()
            .get(&pid)
            .is_some_and(|recorded| recorded == config_path))
    }

    async fn pids_with_config_path(
        &self,
        _kind: crate::wifi::record::WifiProcessKind,
        config_path: &std::path::Path,
    ) -> Result<Vec<u32>, WifiProcessError> {
        let mut pids: Vec<u32> = self
            .configs
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(pid, recorded)| (recorded == config_path).then_some(*pid))
            .collect();
        pids.sort_unstable();
        Ok(pids)
    }

    async fn terminate(&self, pid: u32) -> Result<(), WifiProcessError> {
        self.responders.lock().unwrap().remove(&pid);
        self.configs.lock().unwrap().remove(&pid);
        Ok(())
    }

    async fn kill(&self, pid: u32) -> Result<(), WifiProcessError> {
        self.responders.lock().unwrap().remove(&pid);
        self.configs.lock().unwrap().remove(&pid);
        Ok(())
    }
}

fn wifi_ap_config(ssid: &str, security: WifiSecurity) -> crate::config::WifiApConfig {
    crate::config::WifiApConfig {
        ssid: ssid.to_string(),
        country_code: Some("PL".to_string()),
        band: WifiBand::Ghz2,
        channel: 6,
        channel_width: WifiChannelWidth::Ht20,
        security,
        hidden: false,
        client_isolation: false,
        max_stations: 32,
        passphrase_file: None,
    }
}

fn wifi_base_config(directory: &std::path::Path) -> AppConfig {
    let mut config = AppConfig::default();
    config.runtime.state_dir = directory.to_path_buf();
    config.wifi = WifiConfig {
        enabled: true,
        hostapd_binary: PathBuf::from("/usr/sbin/hostapd"),
        runtime_dir: directory.join("hostapd"),
        restart_backoff_seconds: 1,
    };
    config.network.interfaces.insert(
        "wlan0".to_string(),
        InterfaceConfig {
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some("192.168.101.1/24".parse().unwrap()),
            dhcp: None,
            dhcp_client: None,
            wifi: Some(wifi_ap_config("net-a", WifiSecurity::Open)),
            wifi_client: None,
            nat: true,
        },
    );
    config
}

struct WifiFixture {
    service: ControlService,
    process: Arc<FakeWifiProcess>,
    _directory: tempfile::TempDir,
}

async fn configure_wlan0(wifi: &WifiSupervisor, config: &AppConfig) {
    let interface_config = config
        .network
        .interfaces
        .get("wlan0")
        .expect("wlan0 declared");
    let spec = WifiApSpec::from_interface_config("wlan0", interface_config)
        .expect("valid")
        .expect("wifi declared on wlan0");
    wifi.configure(spec).await.expect("configure wlan0");
}

async fn wifi_enabled_fixture() -> WifiFixture {
    let directory = tempdir().expect("tempdir");
    let config = wifi_base_config(directory.path());
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let process = FakeWifiProcess::new();
    let wifi = WifiSupervisor::start_with_process(&config, process.clone())
        .await
        .expect("wifi supervisor");
    configure_wlan0(&wifi, &config).await;
    let service =
        ControlService::new(config, network, dhcp, overrides).with_wifi_supervisor(wifi);
    WifiFixture {
        service,
        process,
        _directory: directory,
    }
}

#[tokio::test]
async fn wifi_disable_reports_both_persistence_and_restoration_failure() {
    let fixture = wifi_enabled_fixture().await;
    std::fs::create_dir(fixture.service.overrides.path()).unwrap();
    fixture.process.fail_spawn.store(true, WifiOrdering::SeqCst);
    let response = fixture
        .service
        .dispatch(Request::DisableWifi {
            interface: "wlan0".into(),
        })
        .await;
    match response {
        Response::WifiError {
            detail: WifiErrorDetail::Other { message },
        } => {
            assert!(
                message.contains("failed to persist Wi-Fi disable"),
                "{message}"
            );
            assert!(message.contains("runtime restoration failed"), "{message}");
            assert!(message.contains("recovery required"), "{message}");
            assert!(!message.contains("runtime state was restored"));
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn wifi_requests_are_rejected_when_wifi_is_disabled() {
    let directory = tempdir().expect("tempdir");
    let config = router_base_config();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let service = ControlService::new(config, network, dhcp, overrides);

    for request in [
        Request::WifiStatus,
        Request::GetWifiConfig {
            interface: "wlan0".to_string(),
        },
        Request::ConfigureWifi {
            interface: "wlan0".to_string(),
            settings: WifiEditRequest {
                ssid: "net-a".to_string(),
                country_code: Some("PL".to_string()),
                band: WifiBand::Ghz2,
                channel: 6,
                channel_width: WifiChannelWidth::Ht20,
                security: WifiSecurity::Open,
                hidden: false,
                client_isolation: false,
                max_stations: 32,
            },
        },
        Request::DisableWifi {
            interface: "wlan0".to_string(),
        },
        Request::WifiSetPassphrase {
            interface: "wlan0".to_string(),
            passphrase: "correct horse battery".to_string(),
        },
        Request::ListWifiStations {
            interface: "wlan0".to_string(),
        },
        Request::WifiDeauthStation {
            interface: "wlan0".to_string(),
            mac: "02:00:00:00:00:01".to_string(),
        },
        Request::WifiReload {
            interface: "wlan0".to_string(),
        },
    ] {
        let response = service.dispatch(request).await;
        assert!(
            matches!(
                response,
                Response::WifiError {
                    detail: WifiErrorDetail::WifiDisabled
                }
            ),
            "{response:?}"
        );
    }
}

#[tokio::test]
async fn wifi_status_reports_a_configured_access_point_because_start_up_brought_it_up() {
    let fixture = wifi_enabled_fixture().await;

    assert_eq!(fixture.process.configs.lock().unwrap().len(), 1);

    match fixture.service.dispatch(Request::WifiStatus).await {
        Response::WifiStatus { interfaces } => {
            assert_eq!(interfaces.len(), 1);
            assert_eq!(interfaces[0].interface, "wlan0");
            assert_eq!(interfaces[0].spec.ssid, "net-a");
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn get_wifi_config_reports_none_for_an_interface_without_a_wifi_block() {
    let mut fixture_directory = tempdir().expect("tempdir");
    let mut config = wifi_base_config(fixture_directory.path());
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
            nat: true,
        },
    );
    let overrides = RuntimeOverrideManager::load(fixture_directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let process = FakeWifiProcess::new();
    let wifi = WifiSupervisor::start_with_process(&config, process)
        .await
        .expect("wifi supervisor");
    let service =
        ControlService::new(config, network, dhcp, overrides).with_wifi_supervisor(wifi);
    let _ = &mut fixture_directory;

    match service
        .dispatch(Request::GetWifiConfig {
            interface: "wan0".to_string(),
        })
        .await
    {
        Response::WifiConfig { interface, spec } => {
            assert_eq!(interface, "wan0");
            assert!(spec.is_none());
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn get_wifi_config_reports_unknown_interface_as_none_too() {
    let fixture = wifi_enabled_fixture().await;
    match fixture
        .service
        .dispatch(Request::GetWifiConfig {
            interface: "does-not-exist".to_string(),
        })
        .await
    {
        Response::WifiConfig { spec, .. } => assert!(spec.is_none()),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn configure_wifi_reconfigures_and_persists_the_new_ssid() {
    let fixture = wifi_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::ConfigureWifi {
            interface: "wlan0".to_string(),
            settings: WifiEditRequest {
                ssid: "net-b".to_string(),
                country_code: Some("PL".to_string()),
                band: WifiBand::Ghz2,
                channel: 6,
                channel_width: WifiChannelWidth::Ht20,
                security: WifiSecurity::Open,
                hidden: false,
                client_isolation: false,
                max_stations: 32,
            },
        })
        .await;
    match response {
        Response::WifiConfigured { spec } => assert_eq!(spec.ssid, "net-b"),
        other => panic!("unexpected response: {other:?}"),
    }

    match fixture
        .service
        .dispatch(Request::GetWifiConfig {
            interface: "wlan0".to_string(),
        })
        .await
    {
        Response::WifiConfig {
            spec: Some(spec), ..
        } => assert_eq!(spec.ssid, "net-b"),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn configure_wifi_on_an_unknown_interface_is_interface_not_found() {
    let fixture = wifi_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::ConfigureWifi {
            interface: "does-not-exist".to_string(),
            settings: WifiEditRequest {
                ssid: "net-a".to_string(),
                country_code: None,
                band: WifiBand::Ghz2,
                channel: 6,
                channel_width: WifiChannelWidth::Ht20,
                security: WifiSecurity::Open,
                hidden: false,
                client_isolation: false,
                max_stations: 32,
            },
        })
        .await;
    assert!(matches!(
        response,
        Response::WifiError {
            detail: WifiErrorDetail::InterfaceNotFound
        }
    ));
}

#[tokio::test]
async fn disable_wifi_stops_the_access_point_and_persists_the_removal() {
    let fixture = wifi_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::DisableWifi {
            interface: "wlan0".to_string(),
        })
        .await;
    assert!(matches!(
        response,
        Response::WifiDisabled { interface } if interface == "wlan0"
    ));

    match fixture.service.dispatch(Request::WifiStatus).await {
        Response::WifiStatus { interfaces } => assert!(interfaces.is_empty()),
        other => panic!("unexpected response: {other:?}"),
    }
    match fixture
        .service
        .dispatch(Request::GetWifiConfig {
            interface: "wlan0".to_string(),
        })
        .await
    {
        Response::WifiConfig { spec, .. } => assert!(spec.is_none()),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn list_wifi_stations_on_an_unconfigured_interface_is_interface_not_found() {
    let fixture = wifi_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::ListWifiStations {
            interface: "does-not-exist".to_string(),
        })
        .await;
    assert!(matches!(
        response,
        Response::WifiError {
            detail: WifiErrorDetail::InterfaceNotFound
        }
    ));
}

#[tokio::test]
async fn wifi_deauth_station_rejects_a_malformed_mac() {
    let fixture = wifi_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::WifiDeauthStation {
            interface: "wlan0".to_string(),
            mac: "not-a-mac".to_string(),
        })
        .await;
    assert!(matches!(
        response,
        Response::WifiError {
            detail: WifiErrorDetail::InvalidSpec { .. }
        }
    ));
}

#[tokio::test]
async fn wifi_reload_sends_reload_and_returns_the_current_spec() {
    let fixture = wifi_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::WifiReload {
            interface: "wlan0".to_string(),
        })
        .await;
    match response {
        Response::WifiConfigured { spec } => assert_eq!(spec.ssid, "net-a"),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn configure_wifi_to_wpa2_without_a_passphrase_is_refused_and_changes_nothing() {
    let fixture = wifi_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::ConfigureWifi {
            interface: "wlan0".to_string(),
            settings: WifiEditRequest {
                ssid: "net-a".to_string(),
                country_code: Some("PL".to_string()),
                band: WifiBand::Ghz2,
                channel: 6,
                channel_width: WifiChannelWidth::Ht20,
                security: WifiSecurity::Wpa2,
                hidden: false,
                client_isolation: false,
                max_stations: 32,
            },
        })
        .await;
    assert!(
        matches!(
            response,
            Response::WifiError {
                detail: WifiErrorDetail::PassphraseMissing
            }
        ),
        "{response:?}"
    );

    match fixture
        .service
        .dispatch(Request::GetWifiConfig {
            interface: "wlan0".to_string(),
        })
        .await
    {
        Response::WifiConfig {
            spec: Some(spec), ..
        } => assert_eq!(spec.security, WifiSecurity::Open),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn wifi_set_passphrase_applies_live_via_reload() {
    let directory = tempdir().expect("tempdir");
    let mut config = wifi_base_config(directory.path());
    config.network.interfaces.insert(
        "wlan0".to_string(),
        InterfaceConfig {
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some("192.168.101.1/24".parse().unwrap()),
            dhcp: None,
            dhcp_client: None,
            wifi: Some(wifi_ap_config("net-a", WifiSecurity::Wpa2)),
            wifi_client: None,
            nat: true,
        },
    );
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let process = FakeWifiProcess::new();
    let wifi = WifiSupervisor::start_with_process(&config, process)
        .await
        .expect("wifi supervisor");

    let passphrase_store = crate::wifi::PassphraseStore::new(directory.path().join("wifi/psk"));
    passphrase_store
        .set(
            "wlan0",
            &crate::wifi::WifiPassphrase::new("first passphrase").unwrap(),
        )
        .unwrap();
    configure_wlan0(&wifi, &config).await;
    let service =
        ControlService::new(config, network, dhcp, overrides).with_wifi_supervisor(wifi);

    match service
        .dispatch(Request::WifiSetPassphrase {
            interface: "wlan0".to_string(),
            passphrase: "second passphrase".to_string(),
        })
        .await
    {
        Response::WifiConfigured { spec } => assert_eq!(spec.security, WifiSecurity::Wpa2),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn no_wifi_response_variant_can_hold_a_passphrase() {
    fn assert_no_passphrase_field(spec: &WifiApSpec) {
        let WifiApSpec {
            interface: _,
            ssid: _,
            country_code: _,
            band: _,
            channel: _,
            channel_width: _,
            security: _,
            hidden: _,
            client_isolation: _,
            max_stations: _,
            passphrase_file: _,
        } = spec;
    }
    let _ = assert_no_passphrase_field;
}

#[tokio::test]
async fn wifi_configured_response_never_serializes_the_passphrase_that_was_just_set() {
    let directory = tempdir().expect("tempdir");
    let mut config = wifi_base_config(directory.path());
    config.network.interfaces.insert(
        "wlan0".to_string(),
        InterfaceConfig {
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some("192.168.101.1/24".parse().unwrap()),
            dhcp: None,
            dhcp_client: None,
            wifi: Some(wifi_ap_config("net-a", WifiSecurity::Wpa2)),
            wifi_client: None,
            nat: true,
        },
    );
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let process = FakeWifiProcess::new();

    let passphrase_store = crate::wifi::PassphraseStore::new(directory.path().join("wifi/psk"));
    passphrase_store
        .set(
            "wlan0",
            &crate::wifi::WifiPassphrase::new("seed passphrase").unwrap(),
        )
        .unwrap();
    let wifi = WifiSupervisor::start_with_process(&config, process)
        .await
        .expect("wifi supervisor");
    configure_wlan0(&wifi, &config).await;
    let service =
        ControlService::new(config, network, dhcp, overrides).with_wifi_supervisor(wifi);

    let secret = "super secret passphrase, must never leak";
    let response = service
        .dispatch(Request::WifiSetPassphrase {
            interface: "wlan0".to_string(),
            passphrase: secret.to_string(),
        })
        .await;
    let encoded = serde_json::to_string(&response).expect("serialize");
    assert!(
        !encoded.contains(secret),
        "a Wi-Fi response must never echo back a passphrase: {encoded}"
    );

    for other in [
        service.dispatch(Request::WifiStatus).await,
        service
            .dispatch(Request::GetWifiConfig {
                interface: "wlan0".to_string(),
            })
            .await,
        service
            .dispatch(Request::ListWifiStations {
                interface: "wlan0".to_string(),
            })
            .await,
    ] {
        let encoded = serde_json::to_string(&other).expect("serialize");
        assert!(!encoded.contains(secret), "{encoded}");
    }
}

use crate::config::{WifiClientGlobalConfig, WifiClientSecurity};
use crate::wifi::WifiClientSupervisor as ClientSupervisor;

struct FakeSupplicant {
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
    ctrl_path: std::path::PathBuf,
}

impl FakeSupplicant {
    fn spawn(
        ctrl_path: std::path::PathBuf,
        config_path: std::path::PathBuf,
        wpa_state: Arc<StdMutex<String>>,
    ) -> Self {
        let socket =
            std::os::unix::net::UnixDatagram::bind(&ctrl_path).expect("bind fake ctrl socket");
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("set read timeout");
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shutdown_for_thread = shutdown.clone();

        let join = std::thread::spawn(move || {
            let content = std::fs::read_to_string(&config_path).unwrap_or_default();
            let ssid = content
                .lines()
                .map(str::trim)
                .find_map(|line| line.strip_prefix("ssid="))
                .and_then(|hex| {
                    let bytes: Vec<u8> = (0..hex.len())
                        .step_by(2)
                        .filter_map(|index| {
                            if index + 2 <= hex.len() {
                                u8::from_str_radix(&hex[index..index + 2], 16).ok()
                            } else {
                                None
                            }
                        })
                        .collect();
                    String::from_utf8(bytes).ok()
                });

            let mut buffer = [0u8; 4096];
            let mut attached: Vec<std::os::unix::net::SocketAddr> = Vec::new();
            while !shutdown_for_thread.load(WifiOrdering::Relaxed) {
                let (read, from) = match socket.recv_from(&mut buffer) {
                    Ok(result) => result,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(_) => break,
                };
                let command = String::from_utf8_lossy(&buffer[..read]).into_owned();
                let reply = match command.as_str() {
                    "PING" => "PONG\n".to_string(),
                    "STATUS" => {
                        let state = wpa_state.lock().unwrap().clone();
                        let mut reply = format!("wpa_state={state}\n");
                        if let Some(ssid) = &ssid {
                            reply.push_str(&format!("ssid={ssid}\n"));
                        }
                        reply.push_str("bssid=02:00:00:00:00:01\nfreq=2437\n");
                        reply
                    }
                    "ATTACH" => {
                        attached.push(from.clone());
                        "OK\n".to_string()
                    }
                    "DETACH" => {
                        #[cfg(target_os = "linux")]
                        {
                            use std::os::linux::net::SocketAddrExt;
                            if let Some(name) = from.as_abstract_name() {
                                attached
                                    .retain(|address| address.as_abstract_name() != Some(name));
                            }
                        }
                        "OK\n".to_string()
                    }
                    "SCAN" => {
                        for addr in &attached {
                            let _ = socket.send_to_addr(b"<3>CTRL-EVENT-SCAN-RESULTS\n", addr);
                        }
                        "OK\n".to_string()
                    }
                    "SCAN_RESULTS" => "bssid / frequency / signal level / flags / ssid\n\
                         02:00:00:00:00:01\t2412\t-42\t[WPA2-PSK-CCMP][SAE][ESS]\tupstream\n"
                        .to_string(),
                    "RECONNECT" | "DISCONNECT" | "REASSOCIATE" => "OK\n".to_string(),
                    _ => "UNKNOWN COMMAND\n".to_string(),
                };
                let _ = socket.send_to_addr(reply.as_bytes(), &from);
            }
        });

        Self {
            shutdown,
            join: Some(join),
            ctrl_path,
        }
    }
}

impl Drop for FakeSupplicant {
    fn drop(&mut self) {
        self.shutdown.store(true, WifiOrdering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        let _ = std::fs::remove_file(&self.ctrl_path);
    }
}

struct FakeSupplicantProcess {
    fail_spawn: std::sync::atomic::AtomicBool,
    responders: StdMutex<HashMap<u32, FakeSupplicant>>,
    configs: StdMutex<HashMap<u32, std::path::PathBuf>>,
    next_pid: AtomicU32,
    wpa_state: Arc<StdMutex<String>>,
}

impl Default for FakeSupplicantProcess {
    fn default() -> Self {
        Self {
            fail_spawn: std::sync::atomic::AtomicBool::new(false),
            responders: StdMutex::new(HashMap::new()),
            configs: StdMutex::new(HashMap::new()),
            next_pid: AtomicU32::new(3000),
            wpa_state: Arc::new(StdMutex::new("COMPLETED".to_string())),
        }
    }
}

impl FakeSupplicantProcess {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn set_wpa_state(&self, state: &str) {
        *self.wpa_state.lock().unwrap() = state.to_string();
    }
}

#[async_trait]
impl SupervisedProcess for FakeSupplicantProcess {
    async fn spawn(
        &self,
        binary: &std::path::Path,
        config_path: &std::path::Path,
    ) -> Result<u32, WifiProcessError> {
        let interface = config_path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("wlan0");
        self.spawn_wifi_client(binary, interface, config_path).await
    }

    async fn spawn_wifi_client(
        &self,
        _binary: &std::path::Path,
        interface: &str,
        config_path: &std::path::Path,
    ) -> Result<u32, WifiProcessError> {
        if self.fail_spawn.load(WifiOrdering::SeqCst) {
            return Err(WifiProcessError::Spawn {
                binary: _binary.to_path_buf(),
                source: std::io::Error::other("injected restoration spawn failure"),
            });
        }
        let pid = self.next_pid.fetch_add(1, WifiOrdering::Relaxed);
        let ctrl_path = config_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new(""))
            .join(interface);
        let responder =
            FakeSupplicant::spawn(ctrl_path, config_path.to_path_buf(), self.wpa_state.clone());
        self.responders.lock().unwrap().insert(pid, responder);
        self.configs
            .lock()
            .unwrap()
            .insert(pid, config_path.to_path_buf());
        Ok(pid)
    }

    async fn is_alive(&self, pid: u32) -> Result<bool, WifiProcessError> {
        Ok(self.responders.lock().unwrap().contains_key(&pid))
    }

    async fn cmdline_contains(
        &self,
        pid: u32,
        config_path: &std::path::Path,
    ) -> Result<bool, WifiProcessError> {
        Ok(self
            .configs
            .lock()
            .unwrap()
            .get(&pid)
            .is_some_and(|recorded| recorded == config_path))
    }

    async fn pids_with_config_path(
        &self,
        _kind: crate::wifi::record::WifiProcessKind,
        config_path: &std::path::Path,
    ) -> Result<Vec<u32>, WifiProcessError> {
        let mut pids: Vec<u32> = self
            .configs
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(pid, recorded)| (recorded == config_path).then_some(*pid))
            .collect();
        pids.sort_unstable();
        Ok(pids)
    }

    async fn terminate(&self, pid: u32) -> Result<(), WifiProcessError> {
        self.responders.lock().unwrap().remove(&pid);
        self.configs.lock().unwrap().remove(&pid);
        Ok(())
    }

    async fn kill(&self, pid: u32) -> Result<(), WifiProcessError> {
        self.responders.lock().unwrap().remove(&pid);
        self.configs.lock().unwrap().remove(&pid);
        Ok(())
    }
}

fn wifi_client_base_config(directory: &std::path::Path) -> AppConfig {
    let mut config = AppConfig::default();
    config.runtime.state_dir = directory.to_path_buf();
    config.wifi_client = WifiClientGlobalConfig {
        enabled: true,
        wpa_supplicant_binary: PathBuf::from("/usr/sbin/wpa_supplicant"),
        runtime_dir: directory.join("wpa_supplicant"),
        restart_backoff_seconds: 1,
    };
    config.network.interfaces.insert(
        "wlan1".to_string(),
        InterfaceConfig {
            role: InterfaceRole::Input,
            managed: true,
            ipv4: None,
            dhcp: None,
            dhcp_client: Some(DhcpClientInterfaceConfig::default()),
            wifi: None,
            wifi_client: Some(crate::config::WifiClientConfig {
                ssid: "upstream".to_string(),
                country_code: Some("PL".to_string()),
                security: WifiClientSecurity::Open,
                passphrase_file: None,
            }),
            nat: true,
        },
    );
    config
}

struct WifiClientFixture {
    process: Arc<FakeSupplicantProcess>,
    service: ControlService,
    _directory: tempfile::TempDir,
}

struct FakeWirelessNetwork {
    interfaces: Vec<NetworkInterface>,
}

#[async_trait]
impl NetworkProvider for FakeWirelessNetwork {
    async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        Ok(self.interfaces.clone())
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
}

async fn wifi_client_enabled_fixture() -> WifiClientFixture {
    let directory = tempdir().expect("tempdir");
    let config = wifi_client_base_config(directory.path());
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeWirelessNetwork {
        interfaces: vec![
            NetworkInterface {
                name: "wlan1".to_string(),
                index: 1,
                is_up: true,
                rx_bytes: 0,
                tx_bytes: 0,
                is_wireless: true,
            },
            NetworkInterface {
                name: "wlan2".to_string(),
                index: 2,
                is_up: true,
                rx_bytes: 0,
                tx_bytes: 0,
                is_wireless: true,
            },
        ],
    });
    let process = FakeSupplicantProcess::new();
    let wifi_client = ClientSupervisor::start_with_process(&config, process.clone())
        .await
        .expect("wifi client supervisor");

    let interface_config = config
        .network
        .interfaces
        .get("wlan1")
        .expect("wlan1 declared");
    let spec = WifiClientSpec::from_interface_config("wlan1", interface_config)
        .expect("valid")
        .expect("wifi_client declared on wlan1");
    wifi_client.configure(spec).await.expect("configure wlan1");

    let dhcp_client = DhcpClientSupervisor::start(&config, network.clone())
        .await
        .expect("DHCP client supervisor");
    let service = ControlService::new(config, network, dhcp, overrides)
        .with_wifi_client_supervisor(wifi_client)
        .with_dhcp_client_supervisor(dhcp_client);
    WifiClientFixture {
        process,
        service,
        _directory: directory,
    }
}

#[tokio::test]
async fn wifi_client_disable_reports_both_persistence_and_restoration_failure() {
    let fixture = wifi_client_enabled_fixture().await;
    std::fs::create_dir(fixture.service.overrides.path()).unwrap();
    fixture.process.fail_spawn.store(true, WifiOrdering::SeqCst);
    let response = fixture
        .service
        .dispatch(Request::DisableWifiClient {
            interface: "wlan1".into(),
        })
        .await;
    match response {
        Response::WifiClientError {
            detail: WifiClientErrorDetail::Other { message },
        } => {
            assert!(
                message.contains("failed to persist Wi-Fi client disable"),
                "{message}"
            );
            assert!(message.contains("runtime restoration failed"), "{message}");
            assert!(!message.contains("runtime state was restored"));
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn wifi_client_requests_are_rejected_when_client_mode_is_disabled() {
    let directory = tempdir().expect("tempdir");
    let config = router_base_config();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let service = ControlService::new(config, network, dhcp, overrides);

    for request in [
        Request::WifiClientStatus,
        Request::GetWifiClientConfig {
            interface: "wlan1".to_string(),
        },
        Request::DisableWifiClient {
            interface: "wlan1".to_string(),
        },
        Request::WifiClientReconnect {
            interface: "wlan1".to_string(),
        },
        Request::WifiClientScan {
            interface: "wlan1".to_string(),
        },
        Request::WifiClientSetPassphrase {
            interface: "wlan1".to_string(),
            passphrase: "a-secret-value".to_string(),
        },
    ] {
        assert!(
            matches!(
                service.dispatch(request).await,
                Response::WifiClientError {
                    detail: WifiClientErrorDetail::WifiClientDisabled
                }
            ),
            "every client request must report the subsystem as disabled"
        );
    }
}

#[tokio::test]
async fn saved_wifi_client_profile_crud_activation_and_active_delete_guard() {
    let fixture = wifi_client_enabled_fixture().await;
    let create = fixture
        .service
        .dispatch(Request::CreateWifiClientProfile {
            profile: WifiClientProfileWriteRequest {
                id: "office".to_string(),
                ssid: "profile-network".to_string(),
                country_code: Some("PL".to_string()),
                security: WifiClientSecurity::Open,
                priority: 10,
                autoconnect: false,
                passphrase: None,
                clear_passphrase: false,
            },
        })
        .await;
    let Response::WifiClientProfile { profile } = create else {
        panic!("expected profile response, got {create:?}");
    };
    assert_eq!(profile.id, "office");
    assert!(!profile.has_passphrase);
    let serialized = serde_json::to_string(&profile).unwrap();
    assert!(serialized.contains("has_passphrase"));
    assert!(!serialized.contains("a-secret-value"));

    let Response::WifiClientProfiles { profiles } = fixture
        .service
        .dispatch(Request::ListWifiClientProfiles)
        .await
    else {
        panic!("expected profile list");
    };
    assert_eq!(profiles.len(), 1);

    let activated = fixture
        .service
        .dispatch(Request::ActivateWifiClientProfile {
            interface: "wlan1".to_string(),
            profile_id: "office".to_string(),
        })
        .await;
    let Response::WifiClientProfileActivated { status, .. } = activated else {
        panic!("expected activation response, got {activated:?}");
    };
    assert_eq!(status.spec.ssid, "profile-network");

    assert!(matches!(
        fixture
            .service
            .dispatch(Request::DeleteWifiClientProfile {
                id: "office".to_string(),
            })
            .await,
        Response::WifiClientProfileError {
            detail: WifiClientProfileErrorDetail::ProfileActive { .. }
        }
    ));
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::DeactivateWifiClientProfile {
                interface: "wlan1".to_string(),
            })
            .await,
        Response::WifiClientDisabled { .. }
    ));
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::DeleteWifiClientProfile {
                id: "office".to_string(),
            })
            .await,
        Response::WifiClientProfileDeleted { .. }
    ));
}

#[tokio::test]
async fn wifi_client_deactivate_preserves_managed_and_allows_subsequent_reactivation() {
    let fixture = wifi_client_enabled_fixture().await;
    let deactivated = fixture
        .service
        .dispatch(Request::DeactivateWifiClientProfile {
            interface: "wlan1".to_string(),
        })
        .await;
    assert!(matches!(deactivated, Response::WifiClientDisabled { .. }));

    // Interface must remain managed
    let effective = fixture.service.effective_config().await.unwrap();
    let iface = effective.network.interfaces.get("wlan1").unwrap();
    assert!(
        iface.managed,
        "interface must remain managed after deactivation"
    );

    // Reactivating a profile must succeed and auto-enable DHCP client
    let created = fixture
        .service
        .dispatch(Request::CreateWifiClientProfile {
            profile: WifiClientProfileWriteRequest {
                id: "home".to_string(),
                ssid: "home-wifi".to_string(),
                country_code: Some("US".to_string()),
                security: WifiClientSecurity::Open,
                priority: 0,
                autoconnect: false,
                passphrase: None,
                clear_passphrase: false,
            },
        })
        .await;
    assert!(matches!(created, Response::WifiClientProfile { .. }));

    let activated = fixture
        .service
        .dispatch(Request::ActivateWifiClientProfile {
            interface: "wlan1".to_string(),
            profile_id: "home".to_string(),
        })
        .await;
    assert!(matches!(
        activated,
        Response::WifiClientProfileActivated { .. }
    ));
}

#[tokio::test]
async fn autoconnect_is_blocked_by_pending_transaction_on_another_interface() {
    let fixture = wifi_client_enabled_fixture().await;
    let created = fixture
        .service
        .dispatch(Request::CreateWifiClientProfile {
            profile: WifiClientProfileWriteRequest {
                id: "saved".to_string(),
                ssid: "upstream".to_string(),
                country_code: Some("PL".to_string()),
                security: WifiClientSecurity::Wpa2,
                priority: 10,
                autoconnect: true,
                passphrase: Some("password123".to_string()),
                clear_passphrase: false,
            },
        })
        .await;
    assert!(matches!(created, Response::WifiClientProfile { .. }));

    let target = InterfaceConfig {
        role: InterfaceRole::Input,
        managed: true,
        ipv4: None,
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
        nat: false,
    };
    let pending = fixture
        .service
        .transactions
        .apply_transition("wlan2", &target, None, None, true)
        .await
        .expect("create pending transaction on wlan2");

    fixture.process.set_wpa_state("DISCONNECTED");
    fixture
        .service
        .autoconnect_wifi_once()
        .await
        .expect("autoconnect pass");

    let state = fixture.service.wifi_autoconnect.lock().await;
    assert!(
        state.attempts.get("wlan1").is_none(),
        "pending transaction on wlan2 must block autoconnect mutation on wlan1"
    );
    assert!(
        !state.connecting_since.contains_key("wlan1"),
        "blocked autoconnect must not enter the association grace period"
    );
    drop(state);

    let effective = fixture.service.effective_config().await.unwrap();
    assert_eq!(
        effective
            .network
            .interfaces
            .get("wlan1")
            .and_then(|interface| interface.wifi_client.as_ref())
            .map(|wifi| wifi.security),
        Some(WifiClientSecurity::Open),
        "blocked autoconnect must not replace the active Wi-Fi client configuration"
    );

    fixture
        .service
        .transactions
        .rollback(&pending.token)
        .await
        .expect("clean up pending wlan2 transaction");
}

#[tokio::test]
async fn autoconnect_does_not_launch_a_scan_during_secret_recovery() {
    let fixture = wifi_client_enabled_fixture().await;
    let created = fixture
        .service
        .dispatch(Request::CreateWifiClientProfile {
            profile: WifiClientProfileWriteRequest {
                id: "saved".into(),
                ssid: "saved-wifi".into(),
                country_code: Some("US".into()),
                security: WifiClientSecurity::Open,
                priority: 0,
                autoconnect: true,
                passphrase: None,
                clear_passphrase: false,
            },
        })
        .await;
    assert!(matches!(created, Response::WifiClientProfile { .. }));
    // Leave committed intent eligible for autoconnect, but require a temporary
    // supplicant for any scan. Recovery must prevent even this preliminary write.
    fixture
        .service
        .wifi_client
        .as_ref()
        .unwrap()
        .disable("wlan1")
        .await
        .unwrap();
    let next_pid = fixture.process.next_pid.load(WifiOrdering::Relaxed);
    let secrets = crate::core::provisioning_secret_transaction::ProvisioningSecretTransactionStore::in_state_dir(
        &fixture.service.config.runtime.state_dir,
    );
    secrets
        .stage(std::collections::BTreeMap::from([("wlan1".into(), None)]))
        .await
        .unwrap();

    fixture.service.autoconnect_wifi_once().await.unwrap();

    assert_eq!(
        fixture.process.next_pid.load(WifiOrdering::Relaxed),
        next_pid,
        "unresolved recovery must block temporary scan processes"
    );
}

#[tokio::test]
async fn queued_autoconnect_timeout_does_not_disable_a_new_association() {
    let fixture = wifi_client_enabled_fixture().await;
    let created = fixture
        .service
        .dispatch(Request::CreateWifiClientProfile {
            profile: WifiClientProfileWriteRequest {
                id: "saved".into(),
                ssid: "saved-wifi".into(),
                country_code: Some("US".into()),
                security: WifiClientSecurity::Open,
                priority: 0,
                autoconnect: true,
                passphrase: None,
                clear_passphrase: false,
            },
        })
        .await;
    assert!(matches!(created, Response::WifiClientProfile { .. }));
    fixture.process.set_wpa_state("ASSOCIATING");
    fixture
        .service
        .wifi_autoconnect
        .lock()
        .await
        .connecting_since
        .insert(
            "wlan1".into(),
            std::time::Instant::now() - std::time::Duration::from_secs(45),
        );

    // Hold the same gate as an admitted configuration request. Poll the
    // background pass until it is waiting for that request to finish.
    let mutation = fixture.service.network_mutations.write().await;
    let pass = fixture.service.autoconnect_wifi_once();
    tokio::pin!(pass);
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut pass)
        .await
        .is_err());
    // The admitted request starts a new association before releasing admission.
    fixture
        .service
        .wifi_autoconnect
        .lock()
        .await
        .resume("wlan1");
    drop(mutation);
    tokio::time::timeout(Duration::from_secs(5), pass)
        .await
        .unwrap()
        .unwrap();

    let effective = fixture.service.effective_config().await.unwrap();
    assert!(
        effective.network.interfaces["wlan1"].wifi_client.is_some(),
        "an expired timeout must not disable a newer association"
    );
    assert!(fixture
        .service
        .wifi_autoconnect
        .lock()
        .await
        .connecting_since
        .contains_key("wlan1"));
}

#[tokio::test]
async fn autoconnect_timeout_clears_stalled_profile_without_deadlock() {
    let fixture = wifi_client_enabled_fixture().await;
    let created = fixture
        .service
        .dispatch(Request::CreateWifiClientProfile {
            profile: WifiClientProfileWriteRequest {
                id: "saved".to_string(),
                ssid: "saved-wifi".to_string(),
                country_code: Some("US".to_string()),
                security: WifiClientSecurity::Open,
                priority: 0,
                autoconnect: true,
                passphrase: None,
                clear_passphrase: false,
            },
        })
        .await;
    assert!(matches!(created, Response::WifiClientProfile { .. }));

    let activated = fixture
        .service
        .dispatch(Request::ActivateWifiClientProfile {
            interface: "wlan1".to_string(),
            profile_id: "saved".to_string(),
        })
        .await;
    assert!(matches!(
        activated,
        Response::WifiClientProfileActivated { .. }
    ));

    // Simulate connecting_since exceeded ASSOCIATION_GRACE and wpa_state is not Completed
    fixture.process.set_wpa_state("ASSOCIATING");
    {
        let mut state = fixture.service.wifi_autoconnect.lock().await;
        state.connecting_since.insert(
            "wlan1".to_string(),
            std::time::Instant::now() - std::time::Duration::from_secs(45),
        );
    }

    // Must complete within 5 seconds without deadlocking
    let run = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        fixture.service.autoconnect_wifi_once(),
    )
    .await;
    assert!(run.is_ok(), "autoconnect_wifi_once deadlocked!");
    assert!(run.unwrap().is_ok());

    // Interface must remain managed and stalled wifi_client cleared
    let effective = fixture.service.effective_config().await.unwrap();
    let iface = effective.network.interfaces.get("wlan1").unwrap();
    assert!(iface.managed, "interface must remain managed");
    assert!(
        iface.wifi_client.is_none(),
        "stalled wifi_client must be cleared"
    );

    let state = fixture.service.wifi_autoconnect.lock().await;
    assert!(
        !state.suspended.contains("wlan1"),
        "autoconnect must not be suspended"
    );
    assert!(
        !state.connecting_since.contains_key("wlan1"),
        "connecting_since must be cleared"
    );
}

#[tokio::test]
async fn wifi_client_status_reports_the_live_association() {
    let fixture = wifi_client_enabled_fixture().await;
    let Response::WifiClientStatus { interfaces } =
        fixture.service.dispatch(Request::WifiClientStatus).await
    else {
        panic!("expected a client status response");
    };
    assert_eq!(interfaces.len(), 1);
    assert_eq!(interfaces[0].interface, "wlan1");
    assert_eq!(interfaces[0].spec.ssid, "upstream");
    assert!(interfaces[0].wpa_state.is_connected());
}

#[tokio::test]
async fn configure_wifi_client_applies_and_persists_the_new_network() {
    let fixture = wifi_client_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::ConfigureWifiClient {
            interface: "wlan1".to_string(),
            settings: WifiClientEditRequest {
                ssid: "somewhere-else".to_string(),
                country_code: Some("PL".to_string()),
                security: WifiClientSecurity::Open,
            },
        })
        .await;
    let Response::WifiClientConfigured { spec } = response else {
        panic!("expected a configured response, got {response:?}");
    };
    assert_eq!(spec.ssid, "somewhere-else");

    let Response::WifiClientConfig { spec, .. } = fixture
        .service
        .dispatch(Request::GetWifiClientConfig {
            interface: "wlan1".to_string(),
        })
        .await
    else {
        panic!("expected a config response");
    };
    assert_eq!(spec.expect("spec persisted").ssid, "somewhere-else");
}

#[tokio::test]
async fn configuring_an_unknown_interface_reports_it_as_not_found() {
    let fixture = wifi_client_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::ConfigureWifiClient {
            interface: "nope0".to_string(),
            settings: WifiClientEditRequest {
                ssid: "upstream".to_string(),
                country_code: None,
                security: WifiClientSecurity::Open,
            },
        })
        .await;
    assert!(
        matches!(
            response,
            Response::WifiClientError {
                detail: WifiClientErrorDetail::InterfaceNotFound
            }
        ),
        "got {response:?}"
    );
}

#[tokio::test]
async fn configuring_a_client_on_an_output_interface_is_an_invalid_spec() {
    let directory = tempdir().expect("tempdir");
    let mut config = wifi_client_base_config(directory.path());
    config.network.interfaces.insert(
        "wlan2".to_string(),
        InterfaceConfig {
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some("192.168.9.1/24".parse().unwrap()),
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
            nat: true,
        },
    );
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let wifi_client =
        ClientSupervisor::start_with_process(&config, FakeSupplicantProcess::new())
            .await
            .expect("wifi client supervisor");
    let service = ControlService::new(config, network, dhcp, overrides)
        .with_wifi_client_supervisor(wifi_client);

    let response = service
        .dispatch(Request::ConfigureWifiClient {
            interface: "wlan2".to_string(),
            settings: WifiClientEditRequest {
                ssid: "upstream".to_string(),
                country_code: None,
                security: WifiClientSecurity::Open,
            },
        })
        .await;
    assert!(
        matches!(
            response,
            Response::WifiClientError {
                detail: WifiClientErrorDetail::InvalidSpec { .. }
            }
        ),
        "got {response:?}"
    );
}

#[tokio::test]
async fn disable_wifi_client_stops_it_and_clears_the_persisted_block() {
    let fixture = wifi_client_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::DisableWifiClient {
            interface: "wlan1".to_string(),
        })
        .await;
    assert!(
        matches!(response, Response::WifiClientDisabled { .. }),
        "got {response:?}"
    );

    let Response::WifiClientStatus { interfaces } =
        fixture.service.dispatch(Request::WifiClientStatus).await
    else {
        panic!("expected a client status response");
    };
    assert!(
        interfaces.is_empty(),
        "a disabled client must not still be reported"
    );
}

#[tokio::test]
async fn a_passphrase_is_never_echoed_back_in_any_response() {
    const SECRET: &str = "a-very-secret-passphrase";
    let fixture = wifi_client_enabled_fixture().await;

    fixture
        .service
        .dispatch(Request::ConfigureWifiClient {
            interface: "wlan1".to_string(),
            settings: WifiClientEditRequest {
                ssid: "upstream".to_string(),
                country_code: Some("PL".to_string()),
                security: WifiClientSecurity::Wpa2,
            },
        })
        .await;
    let set = fixture
        .service
        .dispatch(Request::WifiClientSetPassphrase {
            interface: "wlan1".to_string(),
            passphrase: SECRET.to_string(),
        })
        .await;
    let status = fixture.service.dispatch(Request::WifiClientStatus).await;
    let config = fixture
        .service
        .dispatch(Request::GetWifiClientConfig {
            interface: "wlan1".to_string(),
        })
        .await;

    for response in [set, status, config] {
        let encoded = serde_json::to_string(&response).expect("serialize");
        assert!(
            !encoded.contains(SECRET),
            "a passphrase leaked into {encoded}"
        );
    }
}

#[tokio::test]
async fn reconnect_reports_the_network_it_reconnected_to() {
    let fixture = wifi_client_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::WifiClientReconnect {
            interface: "wlan1".to_string(),
        })
        .await;
    let Response::WifiClientConfigured { spec } = response else {
        panic!("expected the running spec back, got {response:?}");
    };
    assert_eq!(spec.ssid, "upstream");
}

#[tokio::test]
async fn reconnecting_an_unmanaged_interface_reports_it_as_not_found() {
    let fixture = wifi_client_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::WifiClientReconnect {
            interface: "wlan9".to_string(),
        })
        .await;
    assert!(
        matches!(
            response,
            Response::WifiClientError {
                detail: WifiClientErrorDetail::InterfaceNotFound
            }
        ),
        "got {response:?}"
    );
}

#[tokio::test]
async fn wifi_client_scan_on_configured_interface_returns_scan_results() {
    let fixture = wifi_client_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::WifiClientScan {
            interface: "wlan1".to_string(),
        })
        .await;
    let Response::WifiClientScanResults { interface, results } = response else {
        panic!("expected scan results, got {response:?}");
    };
    assert_eq!(interface, "wlan1");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ssid, "upstream");
}

#[tokio::test]
async fn wifi_client_scan_on_unconfigured_interface_performs_ephemeral_scan() {
    let fixture = wifi_client_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::WifiClientScan {
            interface: "wlan2".to_string(),
        })
        .await;
    let Response::WifiClientScanResults { interface, results } = response else {
        panic!("expected scan results, got {response:?}");
    };
    assert_eq!(interface, "wlan2");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ssid, "upstream");
}

#[tokio::test]
async fn wifi_client_scan_rejects_non_wireless_interface() {
    let directory = tempdir().expect("tempdir");
    let config = wifi_client_base_config(directory.path());
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> =
        Arc::new(ProvisioningNetwork::with_wireless(&["wlan1"]).with_address(
            "eth0",
            [192, 168, 1, 1],
            24,
        ));
    let wifi_client =
        ClientSupervisor::start_with_process(&config, FakeSupplicantProcess::new())
            .await
            .expect("wifi client supervisor");
    let service = ControlService::new(config, network, dhcp, overrides)
        .with_wifi_client_supervisor(wifi_client);

    let response = service
        .dispatch(Request::WifiClientScan {
            interface: "eth0".to_string(),
        })
        .await;
    assert!(
        matches!(
            response,
            Response::WifiClientError {
                detail: WifiClientErrorDetail::NotWireless
            }
        ),
        "expected NotWireless for non-wireless NIC, got {response:?}"
    );
}

#[tokio::test]
async fn wifi_client_scan_rejects_missing_interface_when_network_known() {
    let directory = tempdir().expect("tempdir");
    let config = wifi_client_base_config(directory.path());
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> =
        Arc::new(ProvisioningNetwork::with_wireless(&["wlan1"]));
    let wifi_client =
        ClientSupervisor::start_with_process(&config, FakeSupplicantProcess::new())
            .await
            .expect("wifi client supervisor");
    let service = ControlService::new(config, network, dhcp, overrides)
        .with_wifi_client_supervisor(wifi_client);

    let response = service
        .dispatch(Request::WifiClientScan {
            interface: "wlan9".to_string(),
        })
        .await;
    assert!(
        matches!(
            response,
            Response::WifiClientError {
                detail: WifiClientErrorDetail::InterfaceNotFound
            }
        ),
        "expected InterfaceNotFound, got {response:?}"
    );
}

struct DhcpClientControlFixture {
    service: ControlService,
    overrides: RuntimeOverrideManager,
    supervisor: DhcpClientSupervisor,
    directory: tempfile::TempDir,
}

async fn dhcp_client_control_fixture(enabled: bool) -> DhcpClientControlFixture {
    dhcp_client_control_fixture_with_router(enabled, false).await
}

async fn dhcp_client_control_fixture_with_router(
    enabled: bool,
    router_uplink: bool,
) -> DhcpClientControlFixture {
    let directory = tempdir().expect("tempdir");
    let mut config = AppConfig::default();
    config.runtime.state_dir = directory.path().to_path_buf();
    config.dhcp.leases_dir = directory.path().join("leases");
    if router_uplink {
        config.router.enabled = true;
        config.router.uplink = Some(UplinkConfig {
            interface: "wan0".to_string(),
            mode: UplinkMode::Dhcp,
        });
        config.network.interfaces.insert(
            "lan0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Output,
                managed: true,
                ipv4: Some("10.9.0.1/24".parse().expect("output subnet")),
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
                nat: true,
            },
        );
    }
    config.network.interfaces.insert(
        "wan0".to_string(),
        InterfaceConfig {
            role: InterfaceRole::Input,
            managed: true,
            ipv4: None,
            dhcp: None,
            dhcp_client: enabled.then(DhcpClientInterfaceConfig::default),
            wifi: None,
            wifi_client: Some(WifiClientConfig {
                ssid: "upstream".to_string(),
                country_code: Some("PL".to_string()),
                security: WifiClientSecurity::Open,
                passphrase_file: None,
            }),
            nat: true,
        },
    );
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("server supervisor");
    let supervisor = DhcpClientSupervisor::start(&config, network.clone())
        .await
        .expect("client supervisor");
    let service = ControlService::new(config, network, dhcp, overrides.clone())
        .with_dhcp_client_supervisor(supervisor.clone());
    DhcpClientControlFixture {
        service,
        overrides,
        supervisor,
        directory,
    }
}

#[tokio::test]
async fn dhcp_client_control_list_get_and_typed_missing_states() {
    let fixture = dhcp_client_control_fixture(true).await;
    assert!(matches!(
        fixture.service.dispatch(Request::DhcpClientStatus).await,
        Response::DhcpClientStatus { interfaces } if interfaces.len() == 1 && interfaces[0].interface == "wan0"
    ));
    assert!(matches!(
        fixture.service.dispatch(Request::GetDhcpClient { interface: "wan0".into() }).await,
        Response::DhcpClientInterface { status } if status.interface == "wan0"
    ));
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::GetDhcpClient {
                interface: "missing0".into()
            })
            .await,
        Response::DhcpClientError {
            detail: DhcpClientErrorDetail::InterfaceNotFound
        }
    ));
    let disabled = dhcp_client_control_fixture(false).await;
    assert!(matches!(
        disabled
            .service
            .dispatch(Request::GetDhcpClient {
                interface: "wan0".into()
            })
            .await,
        Response::DhcpClientError {
            detail: DhcpClientErrorDetail::Disabled
        }
    ));
}

#[tokio::test]
async fn dhcp_client_control_configure_preserves_wifi_client() {
    let fixture = dhcp_client_control_fixture(false).await;
    let response = fixture
        .service
        .dispatch(Request::ConfigureDhcpClient {
            interface: "wan0".into(),
            config: DhcpClientConfigRequest {
                route_metric: 77,
                ..Default::default()
            },
        })
        .await;
    assert!(
        matches!(response, Response::DhcpClientInterface { .. }),
        "{response:?}"
    );
    let persisted = fixture
        .overrides
        .effective_interface("wan0")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(persisted.dhcp_client.unwrap().route_metric, 77);
    assert_eq!(persisted.wifi_client.unwrap().ssid, "upstream");
    assert!(persisted.managed);
    assert_eq!(persisted.role, InterfaceRole::Input);
}

#[tokio::test]
async fn dhcp_client_control_configure_compensates_runtime_when_persistence_fails() {
    let fixture = dhcp_client_control_fixture(false).await;
    std::fs::create_dir(fixture.directory.path().join("runtime-overrides.json"))
        .expect("block override file rename");
    let response = fixture
        .service
        .dispatch(Request::ConfigureDhcpClient {
            interface: "wan0".into(),
            config: DhcpClientConfigRequest::default(),
        })
        .await;
    assert!(
        matches!(
            response,
            Response::DhcpClientError {
                detail: DhcpClientErrorDetail::PersistenceFailure { .. }
            }
        ),
        "{response:?}"
    );
    assert!(fixture.supervisor.spec("wan0").await.is_none());
}

#[tokio::test]
async fn dhcp_client_control_delete_cleans_runtime_and_persists_disabled_intent() {
    let fixture = dhcp_client_control_fixture(true).await;
    let response = fixture
        .service
        .dispatch(Request::DisableDhcpClient {
            interface: "wan0".into(),
        })
        .await;
    assert!(
        matches!(response, Response::DhcpClientDisabled { interface } if interface == "wan0")
    );
    assert!(fixture.supervisor.spec("wan0").await.is_none());
    let persisted = fixture
        .overrides
        .effective_interface("wan0")
        .await
        .unwrap()
        .unwrap();
    assert!(
        persisted.managed,
        "managed interface remains managed when dhcp client is disabled"
    );
    assert!(!persisted.dhcp_client.unwrap().enabled);
    assert_eq!(persisted.wifi_client.unwrap().ssid, "upstream");
}

#[tokio::test]
async fn dhcp_client_control_delete_refuses_router_held_uplink_without_touching_runtime() {
    let fixture = dhcp_client_control_fixture_with_router(true, true).await;
    let response = fixture
        .service
        .dispatch(Request::DisableDhcpClient {
            interface: "wan0".into(),
        })
        .await;
    assert!(
        matches!(
            response,
            Response::DhcpClientError {
                detail: DhcpClientErrorDetail::InvalidConfig { .. }
            }
        ),
        "{response:?}"
    );

    assert!(fixture.supervisor.spec("wan0").await.is_some());
    let persisted = fixture
        .overrides
        .effective_interface("wan0")
        .await
        .unwrap()
        .unwrap();
    assert!(persisted.managed);
    assert!(persisted.dhcp_client.unwrap().enabled);
}

#[tokio::test]
async fn dhcp_client_control_renew_and_release_dispatch_keep_intent() {
    let fixture = dhcp_client_control_fixture(true).await;
    for request in [
        Request::RenewDhcpClient {
            interface: "wan0".into(),
        },
        Request::ReleaseDhcpClient {
            interface: "wan0".into(),
        },
    ] {
        let response = fixture.service.dispatch(request).await;
        assert!(
            matches!(response, Response::DhcpClientInterface { ref status } if status.interface == "wan0"),
            "{response:?}"
        );
        assert!(fixture.supervisor.spec("wan0").await.is_some());
    }
}

#[tokio::test]
async fn disabling_wifi_client_also_cleans_up_and_disables_active_dhcp_client() {
    let directory = tempdir().expect("tempdir");
    let mut config = wifi_client_base_config(directory.path());
    let mut wlan1_cfg = config
        .network
        .interfaces
        .get("wlan1")
        .expect("wlan1 declared")
        .clone();
    wlan1_cfg.managed = true;
    wlan1_cfg.dhcp_client = Some(DhcpClientInterfaceConfig::default());
    config
        .network
        .interfaces
        .insert("wlan1".to_string(), wlan1_cfg.clone());

    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let wifi_client =
        ClientSupervisor::start_with_process(&config, FakeSupplicantProcess::new())
            .await
            .expect("wifi client supervisor");
    let wifi_spec = WifiClientSpec::from_interface_config("wlan1", &wlan1_cfg)
        .expect("valid")
        .expect("wifi_client declared on wlan1");
    wifi_client
        .configure(wifi_spec)
        .await
        .expect("configure wlan1 wifi");

    let dhcp_client = DhcpClientSupervisor::start(&config, network.clone())
        .await
        .expect("client supervisor");
    let dhcp_spec = DhcpClientSpec::from_interface_config("wlan1", &wlan1_cfg)
        .expect("valid")
        .expect("dhcp_client declared on wlan1");
    dhcp_client.configure(dhcp_spec).await;
    assert!(dhcp_client.spec("wlan1").await.is_some());

    let service = ControlService::new(config, network, dhcp, overrides.clone())
        .with_wifi_client_supervisor(wifi_client)
        .with_dhcp_client_supervisor(dhcp_client.clone());

    let response = service
        .dispatch(Request::DeactivateWifiClientProfile {
            interface: "wlan1".to_string(),
        })
        .await;
    assert!(
        matches!(response, Response::WifiClientDisabled { .. }),
        "got {response:?}"
    );

    // DHCP client supervisor must be stopped and purged
    assert!(dhcp_client.spec("wlan1").await.is_none());

    // Interface config in overrides must have wifi_client cleared and dhcp_client disabled
    let persisted = overrides
        .effective_interface("wlan1")
        .await
        .expect("overrides")
        .expect("interface wlan1 exists");
    assert!(persisted.wifi_client.is_none());
    assert!(persisted.managed);
    assert!(!persisted.dhcp_client.expect("dhcp_client block").enabled);

    // Reactivating a profile re-configures DHCP client in supervisor
    let created = service
        .dispatch(Request::CreateWifiClientProfile {
            profile: WifiClientProfileWriteRequest {
                id: "reactivate".to_string(),
                ssid: "reactivate-wifi".to_string(),
                country_code: Some("US".to_string()),
                security: WifiClientSecurity::Open,
                priority: 0,
                autoconnect: false,
                passphrase: None,
                clear_passphrase: false,
            },
        })
        .await;
    assert!(matches!(created, Response::WifiClientProfile { .. }));

    let activated = service
        .dispatch(Request::ActivateWifiClientProfile {
            interface: "wlan1".to_string(),
            profile_id: "reactivate".to_string(),
        })
        .await;
    assert!(matches!(
        activated,
        Response::WifiClientProfileActivated { .. }
    ));

    // DHCP client supervisor must now be re-configured
    assert!(dhcp_client.spec("wlan1").await.is_some());
    let persisted_again = overrides
        .effective_interface("wlan1")
        .await
        .expect("overrides")
        .expect("interface wlan1 exists");
    assert!(
        persisted_again
            .dhcp_client
            .expect("dhcp_client block")
            .enabled
    );
}

#[tokio::test]
async fn disabling_wifi_client_restores_dhcp_and_wifi_if_persistence_fails() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir().expect("tempdir");
    let mut config = wifi_client_base_config(directory.path());
    let mut wlan1_cfg = config
        .network
        .interfaces
        .get("wlan1")
        .expect("wlan1 declared")
        .clone();
    wlan1_cfg.managed = true;
    wlan1_cfg.dhcp_client = Some(DhcpClientInterfaceConfig::default());
    config
        .network
        .interfaces
        .insert("wlan1".to_string(), wlan1_cfg.clone());

    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let wifi_client =
        ClientSupervisor::start_with_process(&config, FakeSupplicantProcess::new())
            .await
            .expect("wifi client supervisor");
    let wifi_spec = WifiClientSpec::from_interface_config("wlan1", &wlan1_cfg)
        .expect("valid")
        .expect("wifi_client declared on wlan1");
    wifi_client
        .configure(wifi_spec)
        .await
        .expect("configure wlan1 wifi");

    let dhcp_client = DhcpClientSupervisor::start(&config, network.clone())
        .await
        .expect("client supervisor");
    let dhcp_spec = DhcpClientSpec::from_interface_config("wlan1", &wlan1_cfg)
        .expect("valid")
        .expect("dhcp_client declared on wlan1");
    dhcp_client.configure(dhcp_spec).await;
    assert!(dhcp_client.spec("wlan1").await.is_some());

    // Make the override directory read-only so set_interface will fail persistence
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o500))
        .expect("read-only permissions");

    let service = ControlService::new(config, network, dhcp, overrides.clone())
        .with_wifi_client_supervisor(wifi_client.clone())
        .with_dhcp_client_supervisor(dhcp_client.clone());

    let response = service
        .dispatch(Request::DeactivateWifiClientProfile {
            interface: "wlan1".to_string(),
        })
        .await;
    assert!(
        matches!(response, Response::WifiClientError { .. }),
        "got {response:?}"
    );

    // Restore permissions so tempdir cleanup doesn't error
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .expect("restore permissions");

    // Both Wi-Fi and DHCP client supervisors must be restored
    assert!(wifi_client.status("wlan1").await.is_some());
    assert!(dhcp_client.spec("wlan1").await.is_some());
}

#[tokio::test]
async fn disabling_wifi_client_fails_and_restores_state_if_dhcp_disable_fails() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir().expect("tempdir");
    let mut config = wifi_client_base_config(directory.path());
    let mut wlan1_cfg = config
        .network
        .interfaces
        .get("wlan1")
        .expect("wlan1 declared")
        .clone();
    wlan1_cfg.managed = true;
    wlan1_cfg.dhcp_client = Some(DhcpClientInterfaceConfig::default());
    config
        .network
        .interfaces
        .insert("wlan1".to_string(), wlan1_cfg.clone());

    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let wifi_client =
        ClientSupervisor::start_with_process(&config, FakeSupplicantProcess::new())
            .await
            .expect("wifi client supervisor");
    let wifi_spec = WifiClientSpec::from_interface_config("wlan1", &wlan1_cfg)
        .expect("valid")
        .expect("wifi_client declared on wlan1");
    wifi_client
        .configure(wifi_spec)
        .await
        .expect("configure wlan1 wifi");

    let dhcp_client = DhcpClientSupervisor::start(&config, network.clone())
        .await
        .expect("client supervisor");
    let dhcp_spec = DhcpClientSpec::from_interface_config("wlan1", &wlan1_cfg)
        .expect("valid")
        .expect("dhcp_client declared on wlan1");
    dhcp_client.configure(dhcp_spec).await;
    assert!(dhcp_client.spec("wlan1").await.is_some());

    let store =
        crate::dhcp::client::store::DhcpClientLeaseStore::new(&config.runtime.state_dir)
            .expect("store");
    let lease = crate::dhcp::client::lease::DhcpClientLease {
        schema_version: crate::dhcp::client::lease::DHCP_CLIENT_LEASE_SCHEMA_VERSION,
        state: crate::dhcp::client::lease::DhcpClientLeaseState::Bound,
        interface: "wlan1".into(),
        interface_index: 2,
        hardware_address: vec![2, 0, 0, 0, 0, 1],
        client_identifier: vec![1, 2, 0, 0, 0, 0, 1],
        policy: None,
        server_identifier: std::net::Ipv4Addr::new(192, 0, 2, 1),
        address: std::net::Ipv4Addr::new(192, 0, 2, 20),
        prefix_len: 24,
        routers: vec![std::net::Ipv4Addr::new(192, 0, 2, 1)],
        dns_servers: vec![std::net::Ipv4Addr::new(192, 0, 2, 53)],
        lease_seconds: 3600,
        renewal_seconds: 1800,
        rebinding_seconds: 3150,
        expires_at_unix: 10_000,
        owned_routes: Vec::new(),
    };
    store.save(&lease).expect("save initial lease");

    // Make dhcp-client directory read-only so cleanup save fails during dhcp disable
    let dhcp_client_dir = store.directory();
    std::fs::set_permissions(dhcp_client_dir, std::fs::Permissions::from_mode(0o500))
        .expect("read-only permissions");

    let service = ControlService::new(config, network, dhcp, overrides.clone())
        .with_wifi_client_supervisor(wifi_client.clone())
        .with_dhcp_client_supervisor(dhcp_client.clone());

    let response = service
        .dispatch(Request::DeactivateWifiClientProfile {
            interface: "wlan1".to_string(),
        })
        .await;
    assert!(
        matches!(response, Response::WifiClientError { .. }),
        "got {response:?}"
    );

    // Restore permissions
    std::fs::set_permissions(dhcp_client_dir, std::fs::Permissions::from_mode(0o700))
        .expect("restore permissions");

    // Both Wi-Fi and DHCP client supervisors must remain configured
    assert!(wifi_client.status("wlan1").await.is_some());
    assert!(dhcp_client.spec("wlan1").await.is_some());

    // Overrides must not have been modified
    let current = overrides
        .effective_interface("wlan1")
        .await
        .expect("overrides")
        .expect("interface exists");
    assert!(current.wifi_client.is_some());
    assert!(current.managed);
}

use crate::api::model::{ProvisioningOutputRequest, ProvisioningUplinkRequest};
use crate::core::router::{RouterManager, WifiPlan, WifiSnapshot};
use crate::core::router_provisioning::ProvisioningDownstreamOverrides;

#[derive(Default)]
struct FakeProvisioningSubsystems {
    applied_uplink_wifi: StdMutex<Vec<WifiClientSpec>>,
    applied_output_wifi: StdMutex<Vec<WifiApSpec>>,
    uplink_dhcp_unready: StdMutex<bool>,
    unhealthy_dataplane: StdMutex<bool>,
}

#[async_trait]
impl RouterSubsystems for FakeProvisioningSubsystems {
    async fn plan_interfaces(&self, _: &RouterDesired) -> Result<Vec<InterfaceChangePlan>> {
        Ok(Vec::new())
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
    async fn plan_output_wifi(
        &self,
        desired: &RouterDesired,
    ) -> Result<Vec<WifiPlan<WifiApSpec>>> {
        Ok(desired
            .output_wifi
            .iter()
            .map(|spec| WifiPlan::Start {
                desired: spec.clone(),
            })
            .collect())
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
    async fn snapshot_uplink_wifi(&self) -> Result<Vec<WifiSnapshot<WifiClientSpec>>> {
        Ok(Vec::new())
    }
    async fn snapshot_output_wifi(&self) -> Result<Vec<WifiSnapshot<WifiApSpec>>> {
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
    async fn apply_uplink_wifi(&self, plan: &[WifiPlan<WifiClientSpec>]) -> Result<()> {
        for step in plan {
            if let WifiPlan::Start { desired } = step {
                self.applied_uplink_wifi
                    .lock()
                    .unwrap()
                    .push(desired.clone());
            }
        }
        Ok(())
    }
    async fn apply_output_wifi(&self, plan: &[WifiPlan<WifiApSpec>]) -> Result<()> {
        for step in plan {
            if let WifiPlan::Start { desired } = step {
                self.applied_output_wifi
                    .lock()
                    .unwrap()
                    .push(desired.clone());
            }
        }
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
    async fn rollback_uplink_wifi(&self, _: &[WifiSnapshot<WifiClientSpec>]) -> Result<()> {
        Ok(())
    }
    async fn rollback_output_wifi(&self, _: &[WifiSnapshot<WifiApSpec>]) -> Result<()> {
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
        Ok(())
    }
    async fn health_uplink_wifi(&self, _: &RouterDesired) -> Result<()> {
        Ok(())
    }
    async fn health_output_wifi(&self, _: &RouterDesired) -> Result<()> {
        Ok(())
    }
    async fn health_routes(&self, _: &RouterDesired) -> Result<()> {
        Ok(())
    }
    async fn health_dhcp(&self, _: &RouterDesired) -> Result<()> {
        Ok(())
    }
    async fn health_uplink_dhcp(
        &self,
        _: &RouterDesired,
    ) -> Option<crate::core::router::RouterDhcpHealthReason> {
        self.uplink_dhcp_unready.lock().unwrap().then(|| {
            crate::core::router::RouterDhcpHealthReason::Waiting {
                interface: "wlan-up".to_string(),
            }
        })
    }
    async fn health_dataplane(&self, _: &RouterDesired) -> Result<()> {
        if *self.unhealthy_dataplane.lock().unwrap() {
            anyhow::bail!("injected dataplane health failure");
        }
        Ok(())
    }
}

#[derive(Default)]
struct ProvisioningNetwork {
    interfaces: Vec<NetworkInterface>,
    addresses: StdHashMap<String, Vec<Ipv4AddressInfo>>,
}

impl ProvisioningNetwork {
    fn with_wireless(names: &[&str]) -> Self {
        Self {
            interfaces: names
                .iter()
                .enumerate()
                .map(|(index, name)| NetworkInterface {
                    index: index as u32 + 1,
                    name: (*name).to_string(),
                    is_up: true,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    is_wireless: true,
                })
                .collect(),
            addresses: StdHashMap::new(),
        }
    }

    fn with_address(mut self, interface: &str, address: [u8; 4], prefix_len: u8) -> Self {
        self.interfaces.push(NetworkInterface {
            index: self.interfaces.len() as u32 + 1,
            name: interface.to_string(),
            is_up: true,
            rx_bytes: 0,
            tx_bytes: 0,
            is_wireless: false,
        });
        self.addresses.insert(
            interface.to_string(),
            vec![Ipv4AddressInfo {
                interface_index: self.interfaces.len() as u32,
                address: Ipv4Addr::from(address),
                prefix_len,
                protocol: None,
            }],
        );
        self
    }
}

#[async_trait]
impl NetworkProvider for ProvisioningNetwork {
    async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        Ok(self.interfaces.clone())
    }

    async fn list_ipv4_addresses(&self, interface: &str) -> Result<Vec<Ipv4AddressInfo>> {
        Ok(self.addresses.get(interface).cloned().unwrap_or_default())
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

struct ProvisioningFixture {
    service: ControlService,
    overrides: RuntimeOverrideManager,
    subsystems: Arc<FakeProvisioningSubsystems>,
    wifi: WifiSupervisor,
    wifi_client: ClientSupervisor,
    _directory: tempfile::TempDir,
}

fn provisioning_base_config(directory: &std::path::Path) -> AppConfig {
    let mut config = AppConfig::default();
    config.runtime.state_dir = directory.to_path_buf();
    config.wifi = WifiConfig {
        enabled: true,
        hostapd_binary: PathBuf::from("/usr/sbin/hostapd"),
        runtime_dir: directory.join("hostapd"),
        restart_backoff_seconds: 1,
    };
    config.wifi_client = WifiClientGlobalConfig {
        enabled: true,
        wpa_supplicant_binary: PathBuf::from("/usr/sbin/wpa_supplicant"),
        runtime_dir: directory.join("wpa_supplicant"),
        restart_backoff_seconds: 1,
    };
    config
}

async fn provisioning_fixture_with(
    subsystems: Arc<FakeProvisioningSubsystems>,
    config: AppConfig,
    network: ProvisioningNetwork,
    readiness_timeout: Duration,
) -> ProvisioningFixture {
    let directory = tempdir().expect("tempdir");
    let mut config = config;
    config.runtime.state_dir = directory.path().to_path_buf();
    config.wifi.runtime_dir = directory.path().join("hostapd");
    config.wifi_client.runtime_dir = directory.path().join("wpa_supplicant");
    config.validate().expect("valid provisioning base config");

    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");

    let wifi = WifiSupervisor::start(&config)
        .await
        .expect("wifi supervisor");
    let wifi_client = ClientSupervisor::start(&config)
        .await
        .expect("wifi client supervisor");
    let manager = RouterManager::new(subsystems.clone())
        .with_dhcp_readiness_timing(readiness_timeout, Duration::from_millis(10));
    let coordinator =
        RouterTransactionCoordinator::new(manager, overrides.clone(), Duration::from_secs(30));
    let service = ControlService::new(
        config,
        Arc::new(network) as Arc<dyn NetworkProvider>,
        dhcp,
        overrides.clone(),
    )
    .with_router_coordinator(coordinator)
    .with_wifi_supervisor(wifi.clone())
    .with_wifi_client_supervisor(wifi_client.clone());

    ProvisioningFixture {
        service,
        overrides,
        subsystems,
        wifi,
        wifi_client,
        _directory: directory,
    }
}

async fn provisioning_fixture() -> ProvisioningFixture {
    let directory = tempdir().expect("tempdir");
    provisioning_fixture_with(
        Arc::new(FakeProvisioningSubsystems::default()),
        provisioning_base_config(directory.path()),
        ProvisioningNetwork::with_wireless(&["wlan-up", "wlan-out"]),
        Duration::from_millis(200),
    )
    .await
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
        downstream: ProvisioningDownstreamOverrides::default(),
        allow_management_change: false,
    }
}

fn preview_request(provisioning: RouterProvisioningRequest) -> Request {
    Request::RouterProvisioningPreview {
        request: RouterProvisioningPreviewRequest {
            provisioning,
            uplink_secret_pending: true,
            output_secret_pending: true,
        },
    }
}

fn apply_request(provisioning: RouterProvisioningRequest) -> Request {
    Request::RouterProvisioningApply {
        request: RouterProvisioningApplyRequest {
            provisioning,
            uplink_passphrase: Some("upstream-secret".to_string()),
            output_passphrase: Some("downstream-secret".to_string()),
        },
    }
}

fn preview_of(response: Response) -> RouterProvisioningPreviewView {
    match response {
        Response::RouterProvisioningPreview { preview } => preview,
        other => panic!("expected a preview, got {other:?}"),
    }
}

fn provisioning_detail(response: Response) -> RouterProvisioningErrorDetail {
    match response {
        Response::RouterProvisioningError { detail } => detail,
        other => panic!("expected a provisioning error, got {other:?}"),
    }
}

#[tokio::test]
async fn provisioning_preview_derives_complete_downstream_defaults() {
    let fixture = provisioning_fixture().await;

    let preview = preview_of(
        fixture
            .service
            .dispatch(preview_request(provisioning_request()))
            .await,
    );

    assert_eq!(
        preview.downstream.interface_ipv4,
        "10.77.0.1/24".parse().unwrap()
    );
    assert_eq!(preview.downstream.subnet, "10.77.0.0/24".parse().unwrap());
    assert_eq!(preview.downstream.router, Ipv4Addr::new(10, 77, 0, 1));
    assert_eq!(preview.downstream.pool_start, Ipv4Addr::new(10, 77, 0, 100));
    assert_eq!(preview.downstream.pool_end, Ipv4Addr::new(10, 77, 0, 200));
    assert_eq!(preview.downstream.lease_seconds, DEFAULT_DHCP_LEASE_SECONDS);
    assert!(preview.downstream.dns_servers.is_empty());
    assert_eq!(preview.uplink.mode, UplinkMode::Dhcp);
    assert!(preview
        .warnings
        .contains(&ProvisioningWarning::NoDownstreamDns));
    assert!(preview
        .warnings
        .contains(&ProvisioningWarning::PendingSecret {
            interface: "wlan-out".to_string()
        }));

    assert_eq!(fixture.overrides.committed_revision().await, 0);
}

#[tokio::test]
async fn provisioning_preview_carries_no_secret_or_secret_path() {
    let fixture = provisioning_fixture().await;
    fixture
        .wifi
        .set_passphrase(
            "wlan-out",
            &WifiPassphrase::new("downstream-secret").expect("valid passphrase"),
        )
        .await
        .expect("stage AP secret");

    let response = fixture
        .service
        .dispatch(Request::RouterProvisioningPreview {
            request: RouterProvisioningPreviewRequest {
                provisioning: provisioning_request(),
                uplink_secret_pending: true,
                output_secret_pending: false,
            },
        })
        .await;
    let encoded = serde_json::to_string(&response).expect("serializable response");

    assert!(!encoded.contains("downstream-secret"), "{encoded}");
    assert!(!encoded.contains("passphrase_file"), "{encoded}");
    assert!(!encoded.contains("psk"), "{encoded}");
    let preview = preview_of(response);

    assert!(preview.output.secret_available);
    assert!(preview.uplink.secret_available);
}

#[tokio::test]
async fn provisioning_preview_relocates_a_conflicting_default_subnet() {
    let directory = tempdir().expect("tempdir");
    let fixture = provisioning_fixture_with(
        Arc::new(FakeProvisioningSubsystems::default()),
        provisioning_base_config(directory.path()),
        ProvisioningNetwork::with_wireless(&["wlan-up", "wlan-out"]).with_address(
            "eth0",
            [10, 77, 0, 5],
            24,
        ),
        Duration::from_millis(200),
    )
    .await;

    let preview = preview_of(
        fixture
            .service
            .dispatch(preview_request(provisioning_request()))
            .await,
    );

    assert_eq!(
        preview.downstream.interface_ipv4,
        "10.77.1.1/24".parse().unwrap()
    );
    assert!(preview
        .warnings
        .contains(&ProvisioningWarning::DownstreamSubnetRelocated {
            preferred: "10.77.0.0/24".parse().unwrap(),
            selected: "10.77.1.0/24".parse().unwrap(),
        }));
}

#[tokio::test]
async fn provisioning_rejects_a_management_interface_without_confirmation() {
    let directory = tempdir().expect("tempdir");
    let mut config = provisioning_base_config(directory.path());
    config.network.interfaces.insert(
        "wlan-up".to_string(),
        InterfaceConfig {
            role: InterfaceRole::None,
            managed: false,
            ipv4: Some("192.168.1.20/24".parse().unwrap()),
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
            nat: true,
        },
    );
    let fixture = provisioning_fixture_with(
        Arc::new(FakeProvisioningSubsystems::default()),
        config,
        ProvisioningNetwork::with_wireless(&["wlan-up", "wlan-out"]),
        Duration::from_millis(200),
    )
    .await;

    assert_eq!(
        provisioning_detail(
            fixture
                .service
                .dispatch(apply_request(provisioning_request()))
                .await
        ),
        RouterProvisioningErrorDetail::ManagementConfirmationRequired {
            interface: "wlan-up".to_string()
        }
    );
    assert_eq!(fixture.overrides.committed_revision().await, 0);
}

#[tokio::test]
async fn provisioning_rejects_a_protected_network_with_no_available_secret() {
    let fixture = provisioning_fixture().await;

    let response = fixture
        .service
        .dispatch(Request::RouterProvisioningApply {
            request: RouterProvisioningApplyRequest {
                provisioning: provisioning_request(),
                uplink_passphrase: Some("upstream-secret".to_string()),
                output_passphrase: None,
            },
        })
        .await;

    assert_eq!(
        provisioning_detail(response),
        RouterProvisioningErrorDetail::OutputSecretMissing {
            interface: "wlan-out".to_string()
        }
    );

    assert!(fixture
        .wifi_client
        .stored_passphrase("wlan-up")
        .await
        .expect("store readable")
        .is_none());
    assert_eq!(fixture.overrides.committed_revision().await, 0);
}

#[tokio::test]
async fn provisioning_apply_stages_secrets_and_opens_one_coordinator_transaction() {
    let fixture = provisioning_fixture().await;

    let (token, preview) = match fixture
        .service
        .dispatch(apply_request(provisioning_request()))
        .await
    {
        Response::RouterProvisioningApplied { token, preview } => (token, preview),
        other => panic!("expected an applied transaction, got {other:?}"),
    };
    assert!(!token.is_empty());
    assert!(preview.output.secret_available);
    assert!(preview.uplink.secret_available);
    assert!(!preview
        .warnings
        .iter()
        .any(|warning| matches!(warning, ProvisioningWarning::PendingSecret { .. })));

    assert!(fixture
        .wifi
        .stored_passphrase("wlan-out")
        .await
        .expect("store readable")
        .is_some());
    assert!(fixture
        .wifi_client
        .stored_passphrase("wlan-up")
        .await
        .expect("store readable")
        .is_some());
    assert_eq!(
        fixture.subsystems.applied_output_wifi.lock().unwrap().len(),
        1
    );
    assert_eq!(
        fixture.subsystems.applied_uplink_wifi.lock().unwrap().len(),
        1
    );

    match fixture
        .service
        .dispatch(Request::RouterProvisioningStatus)
        .await
    {
        Response::RouterProvisioningStatus { status } => {
            assert_eq!(status.stage, ProvisioningStage::AwaitingConfirmation);
            assert_eq!(status.coordinator, CoordinatorStatus::Pending);
        }
        other => panic!("expected provisioning status, got {other:?}"),
    }

    assert!(matches!(
        fixture
            .service
            .dispatch(Request::RouterCommit {
                token: fixture
                    .service
                    .router
                    .as_ref()
                    .unwrap()
                    .pending_token()
                    .await
                    .unwrap_or_default()
            })
            .await,
        Response::RouterCommitted { revision: 1 }
    ));

    match fixture
        .service
        .dispatch(Request::RouterProvisioningStatus)
        .await
    {
        Response::RouterProvisioningStatus { status } => {
            assert_eq!(status.stage, ProvisioningStage::Ready);
            assert!(status.enabled);
            assert!(status.ready);
            assert!(status.failures.is_empty());
        }
        other => panic!("expected provisioning status, got {other:?}"),
    }

    let output = fixture
        .overrides
        .effective_interface("wlan-out")
        .await
        .expect("effective interface")
        .expect("provisioned output interface");
    let dhcp = output.dhcp.expect("derived downstream DHCP service");
    assert_eq!(output.ipv4, Some("10.77.0.1/24".parse().unwrap()));
    assert_eq!(dhcp.pool_start, Ipv4Addr::new(10, 77, 0, 100));
    assert_eq!(dhcp.pool_end, Ipv4Addr::new(10, 77, 0, 200));
    assert_eq!(dhcp.lease_seconds, Some(DEFAULT_DHCP_LEASE_SECONDS));
}

#[tokio::test]
async fn provisioning_apply_is_idempotent_about_the_derived_subnet() {
    let fixture = provisioning_fixture().await;
    assert!(matches!(
        fixture
            .service
            .dispatch(apply_request(provisioning_request()))
            .await,
        Response::RouterProvisioningApplied { .. }
    ));
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::RouterCommit {
                token: fixture
                    .service
                    .router
                    .as_ref()
                    .unwrap()
                    .pending_token()
                    .await
                    .unwrap_or_default()
            })
            .await,
        Response::RouterCommitted { .. }
    ));

    let preview = preview_of(
        fixture
            .service
            .dispatch(preview_request(provisioning_request()))
            .await,
    );
    assert_eq!(
        preview.downstream.interface_ipv4,
        "10.77.0.1/24".parse().unwrap()
    );
}

#[tokio::test]
async fn provisioning_apply_refuses_a_second_concurrent_transaction() {
    let fixture = provisioning_fixture().await;
    assert!(matches!(
        fixture
            .service
            .dispatch(apply_request(provisioning_request()))
            .await,
        Response::RouterProvisioningApplied { .. }
    ));

    assert_eq!(
        provisioning_detail(
            fixture
                .service
                .dispatch(apply_request(provisioning_request()))
                .await
        ),
        RouterProvisioningErrorDetail::TransactionPending
    );
}

#[tokio::test]
async fn provisioning_apply_reports_a_readiness_timeout_and_restores_prior_secrets() {
    let directory = tempdir().expect("tempdir");
    let subsystems = Arc::new(FakeProvisioningSubsystems::default());
    *subsystems.uplink_dhcp_unready.lock().unwrap() = true;
    let fixture = provisioning_fixture_with(
        subsystems,
        provisioning_base_config(directory.path()),
        ProvisioningNetwork::with_wireless(&["wlan-up", "wlan-out"]),
        Duration::from_millis(50),
    )
    .await;

    let detail = provisioning_detail(
        fixture
            .service
            .dispatch(apply_request(provisioning_request()))
            .await,
    );
    assert!(
        matches!(
            detail,
            RouterProvisioningErrorDetail::ReadinessTimeout { .. }
        ),
        "{detail:?}"
    );

    assert!(fixture
        .wifi
        .stored_passphrase("wlan-out")
        .await
        .expect("store readable")
        .is_none());
    assert!(fixture
        .wifi_client
        .stored_passphrase("wlan-up")
        .await
        .expect("store readable")
        .is_none());
    assert_eq!(fixture.overrides.committed_revision().await, 0);
}

#[tokio::test]
async fn provisioning_status_reports_a_degraded_committed_topology() {
    let fixture = provisioning_fixture().await;
    assert!(matches!(
        fixture
            .service
            .dispatch(apply_request(provisioning_request()))
            .await,
        Response::RouterProvisioningApplied { .. }
    ));
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::RouterCommit {
                token: fixture
                    .service
                    .router
                    .as_ref()
                    .unwrap()
                    .pending_token()
                    .await
                    .unwrap_or_default()
            })
            .await,
        Response::RouterCommitted { .. }
    ));
    *fixture.subsystems.unhealthy_dataplane.lock().unwrap() = true;

    match fixture
        .service
        .dispatch(Request::RouterProvisioningStatus)
        .await
    {
        Response::RouterProvisioningStatus { status } => {
            assert_eq!(status.stage, ProvisioningStage::Degraded);
            assert!(status.enabled);
            assert!(!status.ready);
            assert!(status.readiness.dataplane.is_some());
            assert!(status.readiness.interfaces.is_none());
        }
        other => panic!("expected provisioning status, got {other:?}"),
    }
}

#[tokio::test]
async fn provisioning_requests_are_rejected_when_the_router_is_disabled() {
    let directory = tempdir().expect("tempdir");
    let config = provisioning_base_config(directory.path());
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let service = ControlService::new(
        config,
        Arc::new(ProvisioningNetwork::with_wireless(&["wlan-up", "wlan-out"]))
            as Arc<dyn NetworkProvider>,
        dhcp,
        overrides,
    );

    for request in [
        preview_request(provisioning_request()),
        apply_request(provisioning_request()),
        Request::RouterProvisioningStatus,
    ] {
        assert_eq!(
            provisioning_detail(service.dispatch(request).await),
            RouterProvisioningErrorDetail::RouterDisabled
        );
    }
}

#[tokio::test]
async fn provisioning_rejects_one_interface_in_both_roles() {
    let fixture = provisioning_fixture().await;
    let mut request = provisioning_request();
    request.output.interface = request.uplink.interface.clone();

    assert_eq!(
        provisioning_detail(fixture.service.dispatch(preview_request(request)).await),
        RouterProvisioningErrorDetail::InterfaceReused {
            interface: "wlan-up".to_string()
        }
    );
}

#[tokio::test]
async fn provisioning_rejects_an_interface_that_does_not_exist() {
    let fixture = provisioning_fixture().await;
    let mut request = provisioning_request();
    request.output.interface = "wlan-absent".to_string();

    assert_eq!(
        provisioning_detail(fixture.service.dispatch(preview_request(request)).await),
        RouterProvisioningErrorDetail::InterfaceNotFound {
            interface: "wlan-absent".to_string()
        }
    );
}

#[tokio::test]
async fn provisioning_rejects_an_advanced_pool_override_without_its_network() {
    let fixture = provisioning_fixture().await;
    let mut request = provisioning_request();
    request.downstream.pool_start = Some(Ipv4Addr::new(10, 77, 0, 50));
    request.downstream.pool_end = Some(Ipv4Addr::new(10, 77, 0, 60));

    assert!(
        matches!(
            provisioning_detail(fixture.service.dispatch(preview_request(request)).await),
            RouterProvisioningErrorDetail::InvalidPool { .. }
        ),
        "an explicit pool without an explicit network must be typed, not accepted"
    );
}

#[tokio::test]
async fn provisioning_applies_advanced_downstream_overrides_verbatim() {
    let fixture = provisioning_fixture().await;
    let mut request = provisioning_request();
    request.downstream = ProvisioningDownstreamOverrides {
        interface_ipv4: Some("172.20.5.1/24".parse().unwrap()),
        pool_start: Some(Ipv4Addr::new(172, 20, 5, 20)),
        pool_end: Some(Ipv4Addr::new(172, 20, 5, 40)),
        dns_servers: vec![Ipv4Addr::new(9, 9, 9, 9)],
        lease_seconds: Some(600),
    };

    let preview = preview_of(
        fixture
            .service
            .dispatch(preview_request(request.clone()))
            .await,
    );
    assert_eq!(
        preview.downstream.interface_ipv4,
        "172.20.5.1/24".parse().unwrap()
    );
    assert_eq!(preview.downstream.pool_start, Ipv4Addr::new(172, 20, 5, 20));
    assert_eq!(preview.downstream.pool_end, Ipv4Addr::new(172, 20, 5, 40));
    assert_eq!(
        preview.downstream.dns_servers,
        vec![Ipv4Addr::new(9, 9, 9, 9)]
    );
    assert_eq!(preview.downstream.lease_seconds, 600);
    assert!(!preview
        .warnings
        .contains(&ProvisioningWarning::NoDownstreamDns));

    assert!(matches!(
        fixture.service.dispatch(apply_request(request)).await,
        Response::RouterProvisioningApplied { .. }
    ));
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::RouterCommit {
                token: fixture
                    .service
                    .router
                    .as_ref()
                    .unwrap()
                    .pending_token()
                    .await
                    .unwrap_or_default()
            })
            .await,
        Response::RouterCommitted { .. }
    ));
    let output = fixture
        .overrides
        .effective_interface("wlan-out")
        .await
        .expect("effective interface")
        .expect("provisioned output interface");
    let dhcp = output.dhcp.expect("derived downstream DHCP service");
    assert_eq!(dhcp.pool_start, Ipv4Addr::new(172, 20, 5, 20));
    assert_eq!(dhcp.dns_servers, vec![Ipv4Addr::new(9, 9, 9, 9)]);
    assert_eq!(dhcp.lease_seconds, Some(600));
}

#[tokio::test]
async fn provisioning_rejects_an_explicit_downstream_conflict() {
    let directory = tempdir().expect("tempdir");
    let fixture = provisioning_fixture_with(
        Arc::new(FakeProvisioningSubsystems::default()),
        provisioning_base_config(directory.path()),
        ProvisioningNetwork::with_wireless(&["wlan-up", "wlan-out"]).with_address(
            "eth0",
            [192, 168, 1, 20],
            24,
        ),
        Duration::from_millis(200),
    )
    .await;
    let mut request = provisioning_request();
    request.downstream.interface_ipv4 = Some("192.168.1.1/24".parse().unwrap());

    let detail = provisioning_detail(fixture.service.dispatch(preview_request(request)).await);
    match detail {
        RouterProvisioningErrorDetail::SubnetConflict {
            requested,
            conflicting,
            ..
        } => {
            assert_eq!(requested, "192.168.1.0/24".parse().unwrap());
            assert_eq!(conflicting, "192.168.1.0/24".parse().unwrap());
        }
        other => panic!("expected a typed subnet conflict, got {other:?}"),
    }
}

#[test]
fn provisioning_apply_request_debug_redacts_key_material() {
    let formatted = format!(
        "{:?}",
        Request::RouterProvisioningApply {
            request: RouterProvisioningApplyRequest {
                provisioning: provisioning_request(),
                uplink_passphrase: Some("upstream-secret".to_string()),
                output_passphrase: None,
            },
        }
    );

    assert!(!formatted.contains("upstream-secret"), "{formatted}");
    assert!(formatted.contains("<redacted>"), "{formatted}");
    assert!(formatted.contains("<absent>"), "{formatted}");
}

struct RouteFakeNetwork {
    interfaces: Vec<NetworkInterface>,
    routes: Vec<crate::netlink::Ipv4RouteInfo>,
    route_error: Option<&'static str>,
}

#[async_trait]
impl NetworkProvider for RouteFakeNetwork {
    async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        Ok(self.interfaces.clone())
    }

    async fn list_ipv4_addresses(&self, _interface: &str) -> Result<Vec<Ipv4AddressInfo>> {
        Ok(Vec::new())
    }

    async fn list_ipv4_routes(&self) -> Result<Vec<crate::netlink::Ipv4RouteInfo>> {
        if let Some(message) = self.route_error {
            anyhow::bail!(message);
        }
        Ok(self.routes.clone())
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

async fn route_guard_service(
    route_error: Option<&'static str>,
) -> (ControlService, tempfile::TempDir) {
    let directory = tempdir().expect("tempdir");
    let mut config = router_base_config();
    config.runtime.state_dir = directory.path().to_path_buf();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(RouteFakeNetwork {
        interfaces: vec![NetworkInterface {
            index: 2,
            name: "lan0".to_string(),
            is_up: true,
            rx_bytes: 0,
            tx_bytes: 0,
            is_wireless: false,
        }],
        routes: vec![crate::netlink::Ipv4RouteInfo {
            destination: "0.0.0.0/0".parse().unwrap(),
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            output_interface_index: Some(2),
            table: 254,
            metric: Some(100),
            protocol: 3,
            scope: 0,
        }],
        route_error,
    });
    (
        ControlService::new(config, network, dhcp, overrides),
        directory,
    )
}

#[tokio::test]
async fn default_route_guard_covers_managed_to_unmanaged_and_input_transitions() {
    let (service, _directory) = route_guard_service(None).await;
    let current = router_base_config().network.interfaces["lan0"].clone();

    let mut unmanaged = current.clone();
    unmanaged.managed = false;
    let error = service
        .validate_default_route_management("lan0", Some(&current), &unmanaged, false)
        .await
        .expect_err("unmanaging the default-route interface needs confirmation");
    assert!(error.to_string().contains("default route"));

    let mut input = current.clone();
    input.role = InterfaceRole::Input;
    let error = service
        .validate_default_route_management("lan0", Some(&current), &input, false)
        .await
        .expect_err("re-roling the default-route interface needs confirmation");
    assert!(error.to_string().contains("default route"));

    service
        .validate_default_route_management("lan0", Some(&current), &input, true)
        .await
        .expect("explicit confirmation permits the transition");
}

#[tokio::test]
async fn default_route_guard_fails_closed_when_routes_cannot_be_observed() {
    let (service, _directory) = route_guard_service(Some("injected route dump failure")).await;
    let current = router_base_config().network.interfaces["lan0"].clone();

    let error = service
        .validate_default_route_management("lan0", Some(&current), &current, false)
        .await
        .expect_err("route observation failure must not bypass the safety guard");
    let message = format!("{error:#}");
    assert!(message.contains("failed to inspect IPv4 routes"), "{message}");
    assert!(message.contains("injected route dump failure"), "{message}");
}

#[tokio::test]
async fn list_routes_and_get_router_config_dispatch() {
    let directory = tempdir().expect("tempdir");
    let config = router_base_config();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(RouteFakeNetwork {
        interfaces: vec![
            NetworkInterface {
                index: 2,
                name: "eth0".to_string(),
                is_up: true,
                rx_bytes: 0,
                tx_bytes: 0,
                is_wireless: false,
            },
            NetworkInterface {
                index: 3,
                name: "wlan0".to_string(),
                is_up: true,
                rx_bytes: 0,
                tx_bytes: 0,
                is_wireless: true,
            },
        ],
        routes: vec![
            crate::netlink::Ipv4RouteInfo {
                destination: "0.0.0.0/0".parse().unwrap(),
                gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
                output_interface_index: Some(2),
                table: 254,
                metric: Some(100),
                protocol: 3, // Boot
                scope: 0,
            },
            crate::netlink::Ipv4RouteInfo {
                destination: "10.0.0.0/24".parse().unwrap(),
                gateway: None,
                output_interface_index: Some(3),
                table: 254,
                metric: None,
                protocol: 201, // TrafficMasqStatic
                scope: 253,
            },
            crate::netlink::Ipv4RouteInfo {
                destination: "127.0.0.1/32".parse().unwrap(),
                gateway: None,
                output_interface_index: Some(1),
                table: 255, // Local table
                metric: None,
                protocol: 2, // Kernel
                scope: 254,
            },
        ],
        route_error: None,
    });
    let service = ControlService::new(config.clone(), network, dhcp, overrides);

    let resp = service
        .dispatch(Request::ListRoutes {
            include_local_table: false,
        })
        .await;
    match resp {
        Response::Routes { routes } => {
            assert_eq!(routes.len(), 2);
            assert_eq!(routes[0].destination, "10.0.0.0/24".parse().unwrap());
            assert_eq!(routes[0].output_interface.as_deref(), Some("wlan0"));
            assert_eq!(
                routes[0].owner,
                crate::netlink::RouteOwner::TrafficMasqStatic
            );

            assert_eq!(routes[1].destination, "0.0.0.0/0".parse().unwrap());
            assert_eq!(routes[1].output_interface.as_deref(), Some("eth0"));
            assert_eq!(routes[1].owner, crate::netlink::RouteOwner::Boot);
        }
        other => panic!("unexpected response: {other:?}"),
    }

    let resp_all = service
        .dispatch(Request::ListRoutes {
            include_local_table: true,
        })
        .await;
    match resp_all {
        Response::Routes { routes } => {
            assert_eq!(routes.len(), 3);
            assert_eq!(routes[2].table, 255);
            assert_eq!(routes[2].destination, "127.0.0.1/32".parse().unwrap());
            assert_eq!(routes[2].owner, crate::netlink::RouteOwner::Kernel);
        }
        other => panic!("unexpected response: {other:?}"),
    }

    let cfg_resp = service.dispatch(Request::GetRouterConfig).await;
    match cfg_resp {
        Response::RouterConfig { config: router_cfg } => {
            assert_eq!(router_cfg.enabled, config.router.enabled);
        }
        other => panic!("unexpected response: {other:?}"),
    }
}
