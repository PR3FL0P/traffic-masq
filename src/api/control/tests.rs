use crate::core::transaction::InterfaceChange;
use crate::netlink::AddressOwnership;
use std::net::Ipv4Addr;

use anyhow::Result;
use async_trait::async_trait;

use crate::netlink::NetworkInterface;

use super::dhcp::*;
use super::interfaces::*;
use super::*;

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
        mac_address: None,
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
            mac_address: None,
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
        mac_address: None,
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
        mac_address: None,
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
        mac_address: None,
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
        mac_address: None,
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
        mac_address: None,
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
        mac_address: None,
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
        mac_address: None,
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
        mac_address: None,
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
        mac_address: None,
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
        mac_address: None,
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
        mac_address: None,
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
        mac_address: None,
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
use crate::core::router::{
    DhcpPlan, RouterSnapshot, RouterSubsystemPlan, RouterSubsystems, VpnChainSnapshot,
};
use crate::firewall::{OwnedFirewallIntegrity, RouterDataplanePlan, RouterDataplaneSnapshot};
use tempfile::tempdir;

#[derive(Default)]
struct FakeRouterSubsystems {
    cleanup_targets: std::sync::Mutex<Vec<RouterDesired>>,
    cleanup_started: tokio::sync::Notify,
    cleanup_hold: std::sync::Mutex<Option<Arc<tokio::sync::Notify>>>,
    cleanup_failure: std::sync::Mutex<bool>,
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

fn fake_router_snapshot() -> RouterSnapshot {
    RouterSnapshot {
        interfaces: Vec::new(),
        uplink_wifi: Vec::new(),
        uplink_dhcp: None,
        dhcp_clients: Vec::new(),
        output_wifi: Vec::new(),
        dhcp: Vec::new(),
        dhcp_absent_interfaces: Vec::new(),
        routes: RouteSnapshot::empty(),
        vpn_chain: VpnChainSnapshot::empty(),
        dataplane: fake_dataplane_snapshot(),
    }
}

#[async_trait]
impl RouterSubsystems for FakeRouterSubsystems {
    async fn cleanup_removed_dataplane(&self, desired: &RouterDesired) -> Result<()> {
        self.cleanup_targets.lock().unwrap().push(desired.clone());
        let hold = self.cleanup_hold.lock().unwrap().clone();
        self.cleanup_started.notify_one();
        if let Some(hold) = hold {
            hold.notified().await;
        }
        anyhow::ensure!(
            !*self.cleanup_failure.lock().unwrap(),
            "injected cleanup failure"
        );
        Ok(())
    }

    async fn plan_for(&self, desired: &RouterDesired) -> Result<RouterSubsystemPlan> {
        let interfaces = vec![InterfaceChangePlan {
            mac_address: None,
            interface: "lan0".into(),
            delete_ipv4: Vec::new(),
            retag_ipv4: None,
            add_ipv4: None,
            set_link_up: false,
            management_change: false,
            dhcp_action: DhcpChangeAction::Unchanged,
            releasing_management: false,
        }];
        if desired.uplink_wifi.is_some() {
            anyhow::bail!("uplink Wi-Fi runtime is unavailable");
        }
        if !desired.output_wifi.is_empty() {
            anyhow::bail!("output Wi-Fi runtime is unavailable");
        }
        let routes = self.plan_routes(desired).await?;
        let vpn_chain = self.plan_vpn_chain(desired).await?;
        let dataplane = self.plan_dataplane(desired).await?;
        Ok(RouterSubsystemPlan {
            interfaces,
            uplink_wifi: Vec::new(),
            output_wifi: Vec::new(),
            routes,
            dhcp: Vec::new(),
            vpn_chain,
            dataplane,
        })
    }
    async fn plan_routes(&self, _: &RouterDesired) -> Result<RoutePlan> {
        Ok(RoutePlan {
            add: Vec::new(),
            delete: Vec::new(),
        })
    }
    async fn plan_dataplane(&self, desired: &RouterDesired) -> Result<RouterDataplanePlan> {
        Ok(RouterDataplanePlan {
            snapshot: fake_dataplane_snapshot(),
            target: desired.dataplane.clone(),
            requires_apply: true,
        })
    }
    async fn snapshot_for(&self, _: &RouterDesired) -> Result<RouterSnapshot> {
        Ok(fake_router_snapshot())
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
    async fn rollback_dhcp_scoped(&self, _: &[DhcpServiceSpec], _: &[String]) -> Result<()> {
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
    async fn quiesce_uplink_dhcp(
        &self,
        desired: Option<&crate::dhcp::client::DhcpClientSpec>,
    ) -> Result<()> {
        anyhow::ensure!(
            desired.is_none(),
            "embedded DHCP client runtime is unavailable"
        );
        Ok(())
    }
    async fn apply_uplink_dhcp_candidate(
        &self,
        desired: Option<&crate::dhcp::client::DhcpClientSpec>,
    ) -> Result<bool> {
        anyhow::ensure!(
            desired.is_none(),
            "embedded DHCP client runtime is unavailable"
        );
        Ok(false)
    }
    async fn rollback_candidate_uplink_dhcp(&self) -> Result<()> {
        Ok(())
    }
    async fn rollback_dhcp_clients(
        &self,
        snapshots: &[crate::core::router::DhcpClientSnapshot],
        legacy: Option<&crate::dhcp::client::DhcpClientSpec>,
    ) -> Result<()> {
        anyhow::ensure!(
            snapshots.is_empty() && legacy.is_none(),
            "DHCP client restoration is unavailable"
        );
        Ok(())
    }
    async fn health_uplink_dhcp(
        &self,
        desired: &RouterDesired,
    ) -> Option<crate::core::router::RouterDhcpHealthReason> {
        desired.uplink_dhcp.as_ref().map(|spec| {
            crate::core::router::RouterDhcpHealthReason::IntentMissing {
                interface: spec.interface.clone(),
            }
        })
    }
}

fn router_base_config() -> AppConfig {
    let mut config = AppConfig::default();
    config.network.interfaces.insert(
        "wan0".to_string(),
        InterfaceConfig {
            mac_address: None,
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
            mac_address: None,
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
            uplink: Some(UplinkConfig {
                interface: "wan0".to_string(),
                mode: UplinkMode::External,
            }),
            owned_routes: Vec::new(),
            allow_default_route_change: false,
            route_host_traffic: false,
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
        mac_address: None,
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
    let service = ControlService::from_runtime(
        ControlRuntime {
            active_config: effective,
            base_config: base.clone(),
            network,
            dhcp,
            overrides: overrides.clone(),
            baselines: Vec::new(),
            ownership_journal: AddressOwnershipJournal::in_memory(),
            desired_state: DesiredNetworkState::new(base.clone(), overrides.clone()),
            mutation_gate: Arc::new(NetworkMutationGate::default()),
        },
        ControlSubsystems::default(),
    );

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
        uplink: Some(UplinkConfig {
            interface: "wan0".to_string(),
            mode: UplinkMode::External,
        }),
        owned_routes: Vec::new(),
        allow_default_route_change: false,
        route_host_traffic: false,
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
    let coordinator =
        RouterTransactionCoordinator::new(manager, overrides.clone(), Duration::from_secs(60));
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
        addresses: Vec::new(),
    });
    let service =
        ControlService::new(config, network, dhcp, overrides).with_router_coordinator(coordinator);
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
            proposal: router_proposal().into(),
        },
        Request::RouterApply {
            proposal: router_proposal().into(),
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
async fn router_without_intent_reports_inactive_provisioning_state() {
    let mut config = router_base_config_with_router_enabled();
    config.router.uplink = None;
    let (service, _directory) =
        router_service_with_config(Arc::new(FakeRouterSubsystems::default()), config).await;

    match service.dispatch(Request::RouterProvisioningStatus).await {
        Response::RouterProvisioningStatus { status } => {
            assert_eq!(status.stage, ProvisioningStage::Inactive);
            assert!(!status.enabled);
            assert!(!status.ready);
            assert_eq!(status.coordinator, CoordinatorStatus::Idle);
        }
        other => panic!("expected unconfigured provisioning status, got {other:?}"),
    }
}

#[tokio::test]
async fn explicit_forwarding_without_uplink_is_not_reported_as_unconfigured() {
    let mut config = router_base_config_with_router_enabled();
    config.router.uplink = None;
    config.router.forwarding = Some(vec![crate::config::ForwardingConfig {
        source_subnet: None,
        from: "lan0".to_string(),
        to: "wan0".to_string(),
        masquerade: true,
    }]);
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
async fn dhcp_uplink_plan_auto_enables_interface_dhcp_client() {
    let mut config = router_base_config();
    let wan = config
        .network
        .interfaces
        .get_mut("wan0")
        .expect("wan0 interface");
    wan.managed = true;
    wan.dhcp_client = None;

    let (service, _directory) =
        router_service_with_config(Arc::new(FakeRouterSubsystems::default()), config).await;
    let mut proposal = router_proposal();
    proposal
        .set_router
        .as_mut()
        .unwrap()
        .uplink
        .as_mut()
        .unwrap()
        .mode = UplinkMode::Dhcp;

    match service
        .dispatch(Request::RouterPlan {
            proposal: proposal.into(),
        })
        .await
    {
        Response::RouterPlan { plan } => {
            let dhcp = plan
                .desired
                .uplink_dhcp
                .expect("DHCP uplink should be derived automatically");
            assert_eq!(dhcp.interface, "wan0");
        }
        other => panic!("expected DHCP router plan, got {other:?}"),
    }
}

#[tokio::test]
async fn dhcp_uplink_plan_preserves_explicit_interface_override_while_enabling_dhcp() {
    let mut config = router_base_config();
    let wan = config
        .network
        .interfaces
        .get_mut("wan0")
        .expect("wan0 interface");
    wan.managed = true;

    let (service, _directory) =
        router_service_with_config(Arc::new(FakeRouterSubsystems::default()), config).await;
    let mut proposal = router_proposal();
    proposal
        .set_router
        .as_mut()
        .unwrap()
        .uplink
        .as_mut()
        .unwrap()
        .mode = UplinkMode::Dhcp;

    let mut override_config = proposal
        .set_interfaces
        .get("wan0")
        .map(|request| request.config.clone())
        .unwrap_or_else(|| InterfaceConfig {
            mac_address: None,
            role: InterfaceRole::Input,
            managed: true,
            ipv4: None,
            dhcp: None,
            dhcp_client: Some(DhcpClientInterfaceConfig {
                enabled: false,
                ..Default::default()
            }),
            wifi: None,
            wifi_client: None,
            nat: false,
        });
    override_config.nat = false;
    proposal.set_interfaces.insert(
        "wan0".to_string(),
        crate::api::model::InterfaceOverrideRequest {
            config: override_config,
            allow_management_change: false,
        },
    );

    match service
        .dispatch(Request::RouterPlan {
            proposal: proposal.into(),
        })
        .await
    {
        Response::RouterPlan { plan } => {
            let uplink = plan
                .desired
                .interfaces
                .iter()
                .find(|interface| interface.name == "wan0")
                .expect("wan0 desired interface");
            assert!(!uplink.config.nat);
            assert!(uplink
                .config
                .dhcp_client
                .as_ref()
                .is_some_and(|policy| policy.enabled));
        }
        other => panic!("expected DHCP router plan, got {other:?}"),
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
            proposal: router_proposal().into(),
        })
        .await
    {
        Response::RouterPlan { plan } => assert!(plan.desired.enabled),
        other => panic!("unexpected response: {other:?}"),
    }

    let token = match service
        .dispatch(Request::RouterApply {
            proposal: router_proposal().into(),
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
            proposal: router_proposal().into(),
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
            proposal: router_proposal().into(),
        })
        .await;

    match service
        .dispatch(Request::RouterApply {
            proposal: router_proposal().into(),
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
    let mut config = router_base_config();
    config.vpn.enabled = true;
    config.vpn.wireguard_import_dir = directory.path().join("sources");
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
        host_traffic: None,
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

    let vpn_store = crate::vpn::WireGuardProfileStore::new(config.vpn.wireguard_config_dir.clone());
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
async fn offline_router_save_cannot_change_host_vpn_routing() {
    let fixture = vpn_policy_fixture_with_router_chain(false, true).await;
    let current = fixture.service.effective_config().await.unwrap();
    let mut proposed = current.router.clone();
    proposed.route_host_traffic = true;
    let revision = fixture.overrides.committed_revision().await;
    let response = fixture
        .service
        .dispatch(Request::SaveRouterIntent {
            config: proposed.into(),
            expected_revision: revision,
        })
        .await;
    assert!(
        matches!(response, Response::RouterError { .. }),
        "{response:?}"
    );
    assert_eq!(fixture.overrides.committed_revision().await, revision);
    assert_eq!(
        fixture.service.effective_config().await.unwrap().router,
        current.router
    );
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
                    format!(
                        "state=ENABLED\nssid[0]={ssid}\nbssid[0]=02:00:00:00:00:00\nnum_sta[0]=0\n"
                    )
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
    after_stop: StdMutex<Option<Box<dyn Fn() + Send + Sync>>>,
    fail_stop: std::sync::atomic::AtomicBool,
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

    async fn identity_matches(
        &self,
        pid: u32,
        _kind: crate::wifi::record::WifiProcessKind,
        _binary_path: &std::path::Path,
        config_path: &std::path::Path,
        _started_at_unix: u64,
    ) -> Result<bool, WifiProcessError> {
        Ok(self
            .configs
            .lock()
            .unwrap()
            .get(&pid)
            .is_some_and(|recorded| recorded == config_path))
    }

    async fn process_start_ticks(&self, pid: u32) -> Result<Option<u64>, WifiProcessError> {
        Ok(self
            .configs
            .lock()
            .unwrap()
            .contains_key(&pid)
            .then_some(u64::from(pid)))
    }

    async fn boot_id(&self) -> Result<Option<String>, WifiProcessError> {
        Ok(Some("test-boot".to_string()))
    }

    async fn pids_matching_identity(
        &self,
        _kind: crate::wifi::record::WifiProcessKind,
        _binary_path: &std::path::Path,
        config_path: &std::path::Path,
        _started_at_unix: u64,
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

    async fn owns_unix_socket(
        &self,
        pid: u32,
        socket_path: &std::path::Path,
    ) -> Result<bool, WifiProcessError> {
        Ok(self
            .responders
            .lock()
            .unwrap()
            .get(&pid)
            .is_some_and(|responder| responder.ctrl_path.as_path() == socket_path))
    }

    async fn terminate(&self, pid: u32) -> Result<(), WifiProcessError> {
        if self.fail_stop.load(WifiOrdering::SeqCst) {
            return Err(WifiProcessError::Signal {
                pid,
                source: nix::errno::Errno::EPERM,
            });
        }
        self.responders.lock().unwrap().remove(&pid);
        self.configs.lock().unwrap().remove(&pid);
        if let Some(hook) = self.after_stop.lock().unwrap().take() {
            hook();
        }
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
            mac_address: None,
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
    network: Arc<crate::test_support::FakeNetworkProvider>,
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
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    network.add_interface("wlan0", 1).await;
    let process = FakeWifiProcess::new();
    let wifi = WifiSupervisor::start_with_process_and_radio(
        &config,
        process.clone(),
        Arc::new(crate::wifi::radio::AllowAllRadioValidator),
    )
    .await
    .expect("wifi supervisor");
    configure_wlan0(&wifi, &config).await;
    let service =
        ControlService::new(config, network.clone(), dhcp, overrides).with_wifi_supervisor(wifi);
    WifiFixture {
        network,
        service,
        process,
        _directory: directory,
    }
}

#[tokio::test]
async fn wifi_disable_commit_failure_keeps_the_candidate_pending_until_rollback() {
    let fixture = wifi_enabled_fixture().await;
    // Turn the override file path into a directory. The tentative apply should
    // still succeed; persistence is deliberately deferred until commit.
    std::fs::create_dir(fixture.service.overrides.path()).unwrap();
    let response = fixture
        .service
        .dispatch(Request::DisableWifi {
            interface: "wlan0".into(),
        })
        .await;
    let Response::NetworkChangePending { change } = response else {
        panic!("expected pending AP deactivation, got {response:?}");
    };

    let committed = fixture
        .service
        .dispatch(Request::CommitNetworkChange {
            token: change.token.clone(),
        })
        .await;
    assert!(matches!(committed, Response::Error { .. }), "{committed:?}");
    assert!(fixture
        .service
        .transactions
        .pending()
        .await
        .iter()
        .any(|pending| pending.token == change.token));

    assert!(matches!(
        fixture
            .service
            .dispatch(Request::RollbackNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeRolledBack { .. }
    ));
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

    assert!(matches!(
        service
            .dispatch(Request::GetWifiConfig {
                interface: "wlan0".to_string(),
            })
            .await,
        Response::WifiConfig { spec: None, .. }
    ));

    for request in [
        Request::WifiStatus,
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
            mac_address: None,
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
    let wifi = WifiSupervisor::start_with_process_and_radio(
        &config,
        process,
        Arc::new(crate::wifi::radio::AllowAllRadioValidator),
    )
    .await
    .expect("wifi supervisor");
    let service = ControlService::new(config, network, dhcp, overrides).with_wifi_supervisor(wifi);
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
async fn configure_wifi_keeps_the_new_ssid_tentative_until_commit() {
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
    let Response::NetworkChangePending { change } = response else {
        panic!("{response:?}")
    };
    assert_eq!(
        fixture
            .service
            .effective_config()
            .await
            .unwrap()
            .network
            .interfaces["wlan0"]
            .wifi
            .as_ref()
            .unwrap()
            .ssid,
        "net-a"
    );
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::CommitNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeCommitted { .. }
    ));

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
async fn provision_wifi_access_point_stays_pending_until_explicit_commit() {
    let directory = tempdir().expect("tempdir");
    let mut config = wifi_base_config(directory.path());
    config.wifi.hostapd_binary = PathBuf::from("/bin/true");
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    network.add_interface("wlan0", 1).await;
    network
        .interfaces
        .lock()
        .await
        .get_mut("wlan0")
        .expect("wlan0")
        .is_wireless = true;
    let process = FakeWifiProcess::new();
    let wifi = WifiSupervisor::start_with_process_and_radio(
        &config,
        process,
        Arc::new(crate::wifi::radio::AllowAllRadioValidator),
    )
    .await
    .expect("wifi supervisor");
    configure_wlan0(&wifi, &config).await;
    let service =
        ControlService::new(config, network, dhcp, overrides.clone()).with_wifi_supervisor(wifi);

    let response = service
        .dispatch(Request::ProvisionWifiAccessPoint {
            interface: "wlan0".into(),
            settings: WifiEditRequest {
                ssid: "net-b".into(),
                country_code: Some("PL".into()),
                band: WifiBand::Ghz2,
                channel: 11,
                channel_width: WifiChannelWidth::Ht20,
                security: WifiSecurity::Open,
                hidden: false,
                client_isolation: false,
                max_stations: 32,
            },
            passphrase: None,
            clear_passphrase: true,
            configure_dhcp: false,
            subnet: None,
            disable_dhcp: false,
        })
        .await;
    let token = match response {
        Response::NetworkChangePending { change } => change.token,
        other => panic!("unexpected response: {other:?}"),
    };

    assert!(!overrides.snapshot().await.interfaces.contains_key("wlan0"));
    match service
        .dispatch(Request::GetWifiConfig {
            interface: "wlan0".into(),
        })
        .await
    {
        Response::WifiConfig {
            spec: Some(spec), ..
        } => assert_eq!(spec.ssid, "net-a"),
        other => panic!("unexpected response: {other:?}"),
    }

    assert!(matches!(
        service
            .dispatch(Request::CommitNetworkChange { token })
            .await,
        Response::NetworkChangeCommitted { .. }
    ));
    assert!(overrides.snapshot().await.interfaces.contains_key("wlan0"));
    match service
        .dispatch(Request::GetWifiConfig {
            interface: "wlan0".into(),
        })
        .await
    {
        Response::WifiConfig {
            spec: Some(spec), ..
        } => {
            assert_eq!(spec.ssid, "net-b");
            assert_eq!(spec.channel, 11);
        }
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
async fn disable_wifi_is_tentative_until_explicit_commit() {
    let fixture = wifi_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::DisableWifi {
            interface: "wlan0".to_string(),
        })
        .await;
    let Response::NetworkChangePending { change } = response else {
        panic!("expected pending AP deactivation, got {response:?}");
    };

    // Committed intent is unchanged while the candidate is awaiting approval.
    match fixture
        .service
        .dispatch(Request::GetWifiConfig {
            interface: "wlan0".to_string(),
        })
        .await
    {
        Response::WifiConfig { spec, .. } => assert!(spec.is_some()),
        other => panic!("unexpected response: {other:?}"),
    }

    assert!(matches!(
        fixture
            .service
            .dispatch(Request::CommitNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeCommitted { .. }
    ));
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

#[test]
fn open_ap_passphrase_update_clears_stale_secret_for_legacy_clients() {
    let update =
        super::wifi::ap_passphrase_update(WifiSecurity::Open, None, false).expect("open AP update");
    assert!(matches!(update, crate::wifi::WifiPassphraseUpdate::Clear));
}

#[test]
fn replacing_or_clearing_ap_secret_removes_legacy_passphrase_file_fallback() {
    let previous = std::path::PathBuf::from("/run/legacy.psk");
    assert_eq!(
        super::wifi::ap_passphrase_file_update(
            Some(&previous),
            &crate::wifi::WifiPassphraseUpdate::Keep,
        ),
        Some(previous.clone())
    );
    assert!(super::wifi::ap_passphrase_file_update(
        Some(&previous),
        &crate::wifi::WifiPassphraseUpdate::Clear,
    )
    .is_none());
    assert!(super::wifi::ap_passphrase_file_update(
        Some(&previous),
        &crate::wifi::WifiPassphraseUpdate::Set(
            crate::wifi::WifiPassphrase::new("replacement password").unwrap(),
        ),
    )
    .is_none());
}

#[test]
fn ap_passphrase_update_rejects_set_and_clear_together() {
    let error = super::wifi::ap_passphrase_update(
        WifiSecurity::Wpa2,
        Some("correct horse battery".into()),
        true,
    )
    .expect_err("set and clear must conflict");
    assert!(matches!(error, WifiErrorDetail::InvalidSpec { .. }));
}

#[test]
fn secured_ap_passphrase_update_rejects_clear_without_replacement() {
    let error = super::wifi::ap_passphrase_update(WifiSecurity::Wpa2, None, true)
        .expect_err("secured AP cannot clear its only credential");
    assert!(matches!(error, WifiErrorDetail::InvalidSpec { .. }));
}

#[tokio::test]
async fn configure_wifi_wpa2_to_open_clears_the_stored_passphrase() {
    let directory = tempdir().expect("tempdir");
    let mut config = wifi_base_config(directory.path());
    config.network.interfaces.get_mut("wlan0").unwrap().wifi =
        Some(wifi_ap_config("net-a", WifiSecurity::Wpa2));
    let store = crate::wifi::PassphraseStore::new(directory.path().join("wifi/psk-ap"));
    store
        .set(
            "wlan0",
            &crate::wifi::WifiPassphrase::new("original password").unwrap(),
        )
        .unwrap();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    network.add_interface("wlan0", 1).await;
    let wifi = WifiSupervisor::start_with_process_and_radio(
        &config,
        FakeWifiProcess::new(),
        Arc::new(crate::wifi::radio::AllowAllRadioValidator),
    )
    .await
    .expect("wifi supervisor");
    configure_wlan0(&wifi, &config).await;
    let service = ControlService::new(config, network, dhcp, overrides).with_wifi_supervisor(wifi);

    let response = service
        .dispatch(Request::ConfigureWifi {
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
        })
        .await;
    assert!(
        matches!(response, Response::NetworkChangePending { .. }),
        "{response:?}"
    );
    assert!(store.get("wlan0").unwrap().is_none());
}

#[tokio::test]
async fn disable_wifi_secret_clear_rolls_back_and_commits_with_the_network_change() {
    let fixture = wifi_enabled_fixture().await;
    let store = crate::wifi::PassphraseStore::new(fixture._directory.path().join("wifi/psk-ap"));
    store
        .set(
            "wlan0",
            &crate::wifi::WifiPassphrase::new("stale password").unwrap(),
        )
        .unwrap();

    let first = fixture
        .service
        .dispatch(Request::DisableWifi {
            interface: "wlan0".to_string(),
        })
        .await;
    let Response::NetworkChangePending { change } = first else {
        panic!("expected pending AP deactivation, got {first:?}");
    };
    assert!(store.get("wlan0").unwrap().is_none());
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::RollbackNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeRolledBack { .. }
    ));
    assert_eq!(
        store.get("wlan0").unwrap().unwrap().expose(),
        "stale password"
    );

    let second = fixture
        .service
        .dispatch(Request::DisableWifi {
            interface: "wlan0".to_string(),
        })
        .await;
    let Response::NetworkChangePending { change } = second else {
        panic!("expected pending AP deactivation, got {second:?}");
    };
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::CommitNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeCommitted { .. }
    ));
    assert!(store.get("wlan0").unwrap().is_none());
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
            mac_address: None,
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
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    network.add_interface("wlan0", 1).await;
    let process = FakeWifiProcess::new();
    let wifi = WifiSupervisor::start_with_process_and_radio(
        &config,
        process,
        Arc::new(crate::wifi::radio::AllowAllRadioValidator),
    )
    .await
    .expect("wifi supervisor");

    let passphrase_store = crate::wifi::PassphraseStore::new(directory.path().join("wifi/psk-ap"));
    passphrase_store
        .set(
            "wlan0",
            &crate::wifi::WifiPassphrase::new("first passphrase").unwrap(),
        )
        .unwrap();
    configure_wlan0(&wifi, &config).await;
    let service = ControlService::new(config, network, dhcp, overrides).with_wifi_supervisor(wifi);

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
    fn assert_no_passphrase_field(spec: &crate::api::model::WifiApSpecView) {
        let crate::api::model::WifiApSpecView {
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
            mac_address: None,
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

    let passphrase_store = crate::wifi::PassphraseStore::new(directory.path().join("wifi/psk-ap"));
    passphrase_store
        .set(
            "wlan0",
            &crate::wifi::WifiPassphrase::new("seed passphrase").unwrap(),
        )
        .unwrap();
    let wifi = WifiSupervisor::start_with_process_and_radio(
        &config,
        process,
        Arc::new(crate::wifi::radio::AllowAllRadioValidator),
    )
    .await
    .expect("wifi supervisor");
    configure_wlan0(&wifi, &config).await;
    let service = ControlService::new(config, network, dhcp, overrides).with_wifi_supervisor(wifi);

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
                                attached.retain(|address| address.as_abstract_name() != Some(name));
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
                    "BSS FIRST" => "id=0\nbssid=02:00:00:00:00:01\nfreq=2412\nlevel=-42\nflags=[WPA2-PSK-CCMP][SAE][ESS]\nssid=upstream\n".to_string(),
                    "BSS NEXT-0" => String::new(),
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

    async fn identity_matches(
        &self,
        pid: u32,
        _kind: crate::wifi::record::WifiProcessKind,
        _binary_path: &std::path::Path,
        config_path: &std::path::Path,
        _started_at_unix: u64,
    ) -> Result<bool, WifiProcessError> {
        Ok(self
            .configs
            .lock()
            .unwrap()
            .get(&pid)
            .is_some_and(|recorded| recorded == config_path))
    }

    async fn process_start_ticks(&self, pid: u32) -> Result<Option<u64>, WifiProcessError> {
        Ok(self
            .configs
            .lock()
            .unwrap()
            .contains_key(&pid)
            .then_some(u64::from(pid)))
    }

    async fn boot_id(&self) -> Result<Option<String>, WifiProcessError> {
        Ok(Some("test-boot".to_string()))
    }

    async fn pids_matching_identity(
        &self,
        _kind: crate::wifi::record::WifiProcessKind,
        _binary_path: &std::path::Path,
        config_path: &std::path::Path,
        _started_at_unix: u64,
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

    async fn owns_unix_socket(
        &self,
        pid: u32,
        socket_path: &std::path::Path,
    ) -> Result<bool, WifiProcessError> {
        Ok(self
            .responders
            .lock()
            .unwrap()
            .get(&pid)
            .is_some_and(|responder| responder.ctrl_path.as_path() == socket_path))
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
            mac_address: None,
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
    network: Arc<FakeWirelessNetwork>,
    process: Arc<FakeSupplicantProcess>,
    service: ControlService,
    _directory: tempfile::TempDir,
}

struct FakeWirelessNetwork {
    missing: std::sync::atomic::AtomicBool,
    interfaces: Vec<NetworkInterface>,
}

#[async_trait]
impl NetworkProvider for FakeWirelessNetwork {
    async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        if self.missing.load(WifiOrdering::SeqCst) {
            return Ok(Vec::new());
        }
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
    let network = Arc::new(FakeWirelessNetwork {
        missing: Default::default(),
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
    let service = ControlService::new(config, network.clone(), dhcp, overrides)
        .with_wifi_client_supervisor(wifi_client)
        .with_dhcp_client_supervisor(dhcp_client);
    WifiClientFixture {
        network,
        process,
        service,
        _directory: directory,
    }
}

#[tokio::test]
async fn wifi_client_disable_commit_failure_keeps_the_candidate_pending() {
    let fixture = wifi_client_enabled_fixture().await;
    std::fs::create_dir(fixture.service.overrides.path()).unwrap();
    let response = fixture
        .service
        .dispatch(Request::DisableWifiClient {
            interface: "wlan1".into(),
        })
        .await;
    let Response::NetworkChangePending { change } = response else {
        panic!("expected pending client deactivation, got {response:?}");
    };

    let committed = fixture
        .service
        .dispatch(Request::CommitNetworkChange {
            token: change.token.clone(),
        })
        .await;
    assert!(matches!(committed, Response::Error { .. }), "{committed:?}");
    assert!(fixture
        .service
        .transactions
        .pending()
        .await
        .iter()
        .any(|pending| pending.token == change.token));

    assert!(matches!(
        fixture
            .service
            .dispatch(Request::RollbackNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeRolledBack { .. }
    ));
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

    assert!(matches!(
        service
            .dispatch(Request::GetWifiClientConfig {
                interface: "wlan1".to_string(),
            })
            .await,
        Response::WifiClientConfig { spec: None, .. }
    ));

    for request in [
        Request::WifiClientStatus,
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
        .activate_wifi_client_profile_internal("wlan1".to_string(), "office".to_string())
        .await;
    assert!(matches!(
        activated,
        Response::WifiClientProfileActivated { .. }
    ));
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

    let response = fixture
        .service
        .dispatch(Request::DeactivateWifiClientProfile {
            interface: "wlan1".to_string(),
        })
        .await;
    let Response::NetworkChangePending { change } = response else {
        panic!("expected pending client deactivation, got {response:?}");
    };
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::CommitNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeCommitted { .. }
    ));

    // This fixture has no convergence worker. Realize the committed removal
    // before checking the runtime-based active-profile deletion guard.
    fixture
        .service
        .wifi_client
        .as_ref()
        .unwrap()
        .disable("wlan1")
        .await
        .unwrap();

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
    let Response::NetworkChangePending { change } = deactivated else {
        panic!("expected pending client deactivation, got {deactivated:?}");
    };
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::CommitNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeCommitted { .. }
    ));

    let effective = fixture.service.effective_config().await.unwrap();
    let iface = effective.network.interfaces.get("wlan1").unwrap();
    assert!(
        iface.managed,
        "interface must remain managed after deactivation"
    );
    assert!(iface.wifi_client.is_none());

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
        .activate_wifi_client_profile_internal("wlan1".to_string(), "home".to_string())
        .await;
    assert!(matches!(
        activated,
        Response::WifiClientProfileActivated { .. }
    ));
}

#[tokio::test]
async fn manual_client_deactivation_suspends_autoconnect_only_after_commit() {
    let fixture = wifi_client_enabled_fixture().await;

    let first = fixture
        .service
        .dispatch(Request::DeactivateWifiClientProfile {
            interface: "wlan1".to_string(),
        })
        .await;
    let Response::NetworkChangePending { change } = first else {
        panic!("expected pending client deactivation, got {first:?}");
    };
    assert!(!fixture
        .service
        .wifi_autoconnect
        .lock()
        .await
        .suspended
        .contains("wlan1"));
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::RollbackNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeRolledBack { .. }
    ));
    assert!(!fixture
        .service
        .wifi_autoconnect
        .lock()
        .await
        .suspended
        .contains("wlan1"));

    let second = fixture
        .service
        .dispatch(Request::DeactivateWifiClientProfile {
            interface: "wlan1".to_string(),
        })
        .await;
    let Response::NetworkChangePending { change } = second else {
        panic!("expected pending client deactivation, got {second:?}");
    };
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::CommitNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeCommitted { .. }
    ));
    assert!(fixture
        .service
        .wifi_autoconnect
        .lock()
        .await
        .suspended
        .contains("wlan1"));
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
        mac_address: None,
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
        .apply(
            "wlan2",
            InterfaceChange {
                config: &target,
                previous: None,
                current_role: None,
                allow_management_change: true,
                passphrase: crate::wifi::WifiPassphraseUpdate::Keep,
            },
        )
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
        !state.attempts.contains_key("wlan1"),
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
        .stage(std::collections::BTreeMap::from([(
            "wlan1".into(),
            (crate::wifi::store::WifiCredentialRole::Client, None),
        )]))
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
        .activate_wifi_client_profile_internal("wlan1".to_string(), "saved".to_string())
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
async fn configure_wifi_client_keeps_the_new_network_tentative_until_commit() {
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
    let Response::NetworkChangePending { change } = response else {
        panic!("{response:?}")
    };
    assert_eq!(
        fixture
            .service
            .effective_config()
            .await
            .unwrap()
            .network
            .interfaces["wlan1"]
            .wifi_client
            .as_ref()
            .unwrap()
            .ssid,
        "upstream"
    );
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::CommitNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeCommitted { .. }
    ));

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
            mac_address: None,
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
    let wifi_client = ClientSupervisor::start_with_process(&config, FakeSupplicantProcess::new())
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
async fn disable_wifi_client_is_tentative_until_explicit_commit() {
    let fixture = wifi_client_enabled_fixture().await;
    let response = fixture
        .service
        .dispatch(Request::DisableWifiClient {
            interface: "wlan1".to_string(),
        })
        .await;
    let Response::NetworkChangePending { change } = response else {
        panic!("expected pending client deactivation, got {response:?}");
    };

    let before = fixture.service.effective_config().await.unwrap();
    assert!(before.network.interfaces["wlan1"].wifi_client.is_some());

    assert!(matches!(
        fixture
            .service
            .dispatch(Request::CommitNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeCommitted { .. }
    ));
    let after = fixture.service.effective_config().await.unwrap();
    assert!(after.network.interfaces["wlan1"].wifi_client.is_none());
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
async fn wifi_client_scan_rejects_configured_ap_without_hostapd_task() {
    let directory = tempdir().unwrap();
    let mut config = wifi_client_base_config(directory.path());
    let mut ap = config.network.interfaces["wlan1"].clone();
    ap.role = InterfaceRole::Output;
    ap.wifi_client = None;
    ap.dhcp_client = None;
    ap.wifi = Some(wifi_ap_config("hotspot", WifiSecurity::Open));
    config.network.interfaces.insert("wlan0".into(), ap);
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&config).await.unwrap();
    let process = FakeSupplicantProcess::new();
    let wifi_client = ClientSupervisor::start_with_process(&config, process.clone())
        .await
        .unwrap();
    let before = process.configs.lock().unwrap().len();
    let network: Arc<dyn NetworkProvider> =
        Arc::new(ProvisioningNetwork::with_wireless(&["wlan0", "wlan1"]));
    // No AP supervisor: configured APs must still never spawn a scan supplicant.
    let service = ControlService::new(config, network, dhcp, overrides)
        .with_wifi_client_supervisor(wifi_client);
    let response = service
        .dispatch(Request::WifiClientScan {
            interface: "wlan0".into(),
        })
        .await;
    assert!(
        matches!(response, Response::WifiClientError {
        detail: WifiClientErrorDetail::InvalidSpec { ref message }
    } if message.contains("access point")),
        "{response:?}"
    );
    assert_eq!(process.configs.lock().unwrap().len(), before);
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
    let network: Arc<dyn NetworkProvider> = Arc::new(
        ProvisioningNetwork::with_wireless(&["wlan1"]).with_address("eth0", [192, 168, 1, 1], 24),
    );
    let wifi_client = ClientSupervisor::start_with_process(&config, FakeSupplicantProcess::new())
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
    let wifi_client = ClientSupervisor::start_with_process(&config, FakeSupplicantProcess::new())
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
        config.router.uplink = Some(UplinkConfig {
            interface: "wan0".to_string(),
            mode: UplinkMode::Dhcp,
        });
        config.network.interfaces.insert(
            "lan0".to_string(),
            InterfaceConfig {
                mac_address: None,
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
            mac_address: None,
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
async fn dhcp_client_control_rejects_interface_transitions_without_mutation() {
    for (role, managed, ipv4) in [
        (InterfaceRole::None, false, None),
        (InterfaceRole::None, true, None),
        (InterfaceRole::Output, true, Some("192.168.50.1/24")),
        (InterfaceRole::Input, false, None),
        (InterfaceRole::Input, true, Some("192.168.50.1/24")),
    ] {
        let fixture = dhcp_client_control_fixture(false).await;
        let mut original = fixture
            .overrides
            .effective_interface("wan0")
            .await
            .unwrap()
            .unwrap();
        original.role = role;
        original.managed = managed;
        original.ipv4 = ipv4.map(|value| value.parse().unwrap());
        original.wifi_client = None;
        if role == InterfaceRole::Output {
            original.dhcp = Some(dhcp_config());
        }
        fixture
            .overrides
            .set_interface("wan0".into(), original.clone(), false)
            .await
            .unwrap();
        let before = fixture.overrides.snapshot().await;
        let persisted_before = std::fs::read(fixture.overrides.path()).unwrap();

        let response = fixture
            .service
            .dispatch(Request::ConfigureDhcpClient {
                interface: "wan0".into(),
                config: DhcpClientConfigRequest::default(),
            })
            .await;
        assert!(
            matches!(response, Response::DhcpClientError {
                detail: DhcpClientErrorDetail::InvalidConfig { ref message }
            } if message.contains("apply and commit")),
            "{role:?}, managed={managed}, ipv4={ipv4:?}: {response:?}"
        );
        assert_eq!(fixture.overrides.snapshot().await, before);
        assert_eq!(
            std::fs::read(fixture.overrides.path()).unwrap(),
            persisted_before
        );
        assert!(fixture.supervisor.spec("wan0").await.is_none());
        assert!(fixture.service.transactions.pending().await.is_empty());
    }
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

// Exercise real admission/execution gates, interface journals and the DHCP
// supervisor. DHCP sees a detached device so these tests never open raw sockets;
// the transaction observer sees the device to allow a confirmed policy edit.
async fn dhcp_route_policy_fixture(
    timeout_seconds: u64,
) -> (DhcpClientControlFixture, tokio::task::JoinHandle<()>) {
    let mut fixture = dhcp_client_control_fixture(true).await;
    let mut config = fixture.service.base_config.clone();
    config.security.rollback_timeout_seconds = timeout_seconds;
    config
        .network
        .interfaces
        .get_mut("wan0")
        .unwrap()
        .wifi_client = None;
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    network.add_interface("wan0", 1).await;
    let desired = DesiredNetworkState::new(config.clone(), fixture.overrides.clone());
    desired.attach_converger();
    fixture.service = ControlService::from_runtime(
        ControlRuntime {
            active_config: config.clone(),
            base_config: config,
            network,
            dhcp: fixture.service.dhcp.clone(),
            overrides: fixture.overrides.clone(),
            baselines: Vec::new(),
            ownership_journal: AddressOwnershipJournal::in_memory(),
            desired_state: desired.clone(),
            mutation_gate: Arc::new(NetworkMutationGate::default()),
        },
        ControlSubsystems {
            dhcp_client: Some(fixture.supervisor.clone()),
            ..ControlSubsystems::default()
        },
    );
    let gate = fixture.service.network_mutations.clone();
    let supervisor = fixture.supervisor.clone();
    let worker = tokio::spawn(async move {
        loop {
            let version = desired.version();
            {
                let _execution = gate.read().await;
                let config = desired.effective().await.unwrap();
                let spec = DhcpClientSpec::from_interface_config(
                    "wan0",
                    &config.network.interfaces["wan0"],
                )
                .unwrap()
                .unwrap();
                supervisor.configure(spec).await;
                desired.report_result(version, Ok(BTreeMap::new()));
            }
            desired.changed().await;
        }
    });
    (fixture, worker)
}

#[tokio::test]
async fn dhcp_route_policy_requires_commit_and_rollback_restores_runtime() {
    for install_default_route in [true, false] {
        let (fixture, worker) = dhcp_route_policy_fixture(30).await;
        let previous = fixture.overrides.snapshot().await;
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            fixture.service.dispatch(Request::ConfigureDhcpClient {
                interface: "wan0".into(),
                config: DhcpClientConfigRequest {
                    route_metric: 777,
                    install_default_route,
                    ..Default::default()
                },
            }),
        )
        .await
        .expect("DHCP transaction must release execution for convergence");
        let Response::NetworkChangePending { change } = response else {
            worker.abort();
            panic!("{response:?}");
        };
        assert_eq!(fixture.overrides.snapshot().await, previous);
        let runtime = fixture.supervisor.spec("wan0").await.unwrap();
        assert_eq!(runtime.route_metric, 777);
        assert_eq!(runtime.install_default_route, install_default_route);
        assert!(fixture
            .directory
            .path()
            .join("interface-transactions/wan0.json")
            .exists());
        let blocked = fixture
            .service
            .dispatch(Request::RenewDhcpClient {
                interface: "wan0".into(),
            })
            .await;
        assert!(matches!(blocked, Response::Error { message } if message.contains("pending")));
        let rollback = fixture
            .service
            .dispatch(Request::RollbackNetworkChange {
                token: change.token,
            })
            .await;
        assert!(
            matches!(rollback, Response::NetworkChangeRolledBack { .. }),
            "{rollback:?}"
        );
        assert_eq!(fixture.overrides.snapshot().await, previous);
        let runtime = fixture.supervisor.spec("wan0").await.unwrap();
        assert_eq!(
            runtime.route_metric,
            DhcpClientConfigRequest::default().route_metric
        );
        assert!(runtime.install_default_route);
        assert!(!fixture
            .directory
            .path()
            .join("interface-transactions/wan0.json")
            .exists());
        worker.abort();
    }
}

#[tokio::test]
async fn dhcp_default_route_policy_is_persisted_only_after_confirmation() {
    let (fixture, worker) = dhcp_route_policy_fixture(30).await;
    let response = fixture
        .service
        .dispatch(Request::ConfigureDhcpClient {
            interface: "wan0".into(),
            config: DhcpClientConfigRequest {
                install_default_route: false,
                ..Default::default()
            },
        })
        .await;
    let Response::NetworkChangePending { change } = response else {
        worker.abort();
        panic!("{response:?}");
    };
    assert!(
        fixture
            .overrides
            .effective_interface("wan0")
            .await
            .unwrap()
            .unwrap()
            .dhcp_client
            .unwrap()
            .install_default_route
    );
    let response = fixture
        .service
        .dispatch(Request::CommitNetworkChange {
            token: change.token,
        })
        .await;
    assert!(
        matches!(response, Response::NetworkChangeCommitted { .. }),
        "{response:?}"
    );
    assert!(
        !fixture
            .overrides
            .effective_interface("wan0")
            .await
            .unwrap()
            .unwrap()
            .dhcp_client
            .unwrap()
            .install_default_route
    );
    assert!(
        !fixture
            .supervisor
            .spec("wan0")
            .await
            .unwrap()
            .install_default_route
    );
    assert!(fixture.service.transactions.pending().await.is_empty());
    worker.abort();
}

#[tokio::test]
async fn dhcp_route_policy_refuses_changes_without_a_running_converger() {
    let fixture = dhcp_client_control_fixture(true).await;
    fixture.service.transactions.require_converger(true);
    let before = fixture.overrides.snapshot().await;
    let response = fixture
        .service
        .dispatch(Request::ConfigureDhcpClient {
            interface: "wan0".into(),
            config: DhcpClientConfigRequest {
                install_default_route: false,
                ..Default::default()
            },
        })
        .await;
    assert!(
        matches!(response, Response::Error { message } if message.contains("converger unavailable"))
    );
    assert_eq!(fixture.overrides.snapshot().await, before);
    assert!(
        fixture
            .supervisor
            .spec("wan0")
            .await
            .unwrap()
            .install_default_route
    );
    assert!(fixture.service.transactions.pending().await.is_empty());
}

#[tokio::test]
async fn dhcp_route_policy_timeout_restores_committed_policy() {
    let (fixture, worker) = dhcp_route_policy_fixture(1).await;
    let previous = fixture.overrides.snapshot().await;
    let response = fixture
        .service
        .dispatch(Request::ConfigureDhcpClient {
            interface: "wan0".into(),
            config: DhcpClientConfigRequest {
                install_default_route: false,
                ..Default::default()
            },
        })
        .await;
    assert!(
        matches!(response, Response::NetworkChangePending { .. }),
        "{response:?}"
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while !fixture.service.transactions.pending().await.is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("confirmation timer must finish rollback");
    assert_eq!(fixture.overrides.snapshot().await, previous);
    assert!(
        fixture
            .supervisor
            .spec("wan0")
            .await
            .unwrap()
            .install_default_route
    );
    assert!(!fixture
        .directory
        .path()
        .join("interface-transactions/wan0.json")
        .exists());
    worker.abort();
}

#[tokio::test]
async fn interrupted_dhcp_route_policy_is_recovered_from_committed_intent() {
    let (fixture, worker) = dhcp_route_policy_fixture(30).await;
    let response = fixture
        .service
        .dispatch(Request::ConfigureDhcpClient {
            interface: "wan0".into(),
            config: DhcpClientConfigRequest {
                install_default_route: false,
                ..Default::default()
            },
        })
        .await;
    assert!(
        matches!(response, Response::NetworkChangePending { .. }),
        "{response:?}"
    );
    worker.abort();
    let committed = fixture.overrides.snapshot().await;
    let manager = crate::core::interface::InterfaceManager::new(
        fixture.service.network.clone(),
        AddressOwnershipJournal::in_memory(),
    );
    // Startup restores the interface journal before DHCP ownership recovery
    // and reconfiguration from the last committed policy.
    crate::core::transaction::recover_interface_transactions(
        fixture.directory.path(),
        &manager,
        &committed,
        &crate::wifi::WifiRuntimeDirs::new(
            fixture.directory.path().join("hostapd"),
            fixture.directory.path().join("wpa_supplicant"),
        ),
    )
    .await
    .unwrap();
    let restarted = DhcpClientSupervisor::start(
        &committed
            .effective_config(&fixture.service.base_config)
            .unwrap(),
        Arc::new(FakeNetwork {
            addresses: Vec::new(),
        }),
    )
    .await
    .unwrap();
    assert!(restarted.spec("wan0").await.unwrap().install_default_route);
    assert_eq!(fixture.overrides.snapshot().await, committed);
    assert!(!fixture
        .directory
        .path()
        .join("interface-transactions/wan0.json")
        .exists());
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
    let mut original = fixture
        .overrides
        .effective_interface("wan0")
        .await
        .unwrap()
        .unwrap();
    let policy = original.dhcp_client.as_mut().unwrap();
    policy.route_metric = 777;
    policy.install_default_route = false;
    policy.request_dns = false;
    policy.send_release_on_shutdown = false;
    let mut expected = policy.clone();
    expected.enabled = false;
    fixture
        .overrides
        .set_interface("wan0".into(), original, false)
        .await
        .unwrap();
    let response = fixture
        .service
        .dispatch(Request::DisableDhcpClient {
            interface: "wan0".into(),
        })
        .await;
    assert!(matches!(response, Response::DhcpClientDisabled { interface } if interface == "wan0"));
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
    assert_eq!(persisted.dhcp_client.unwrap(), expected);
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
async fn wifi_client_deactivation_disables_only_wifi_owned_dhcp_on_commit() {
    let directory = tempdir().expect("tempdir");
    let mut config = wifi_client_base_config(directory.path());
    let mut wlan1_cfg = config.network.interfaces["wlan1"].clone();
    wlan1_cfg.dhcp_client = Some(DhcpClientInterfaceConfig {
        wifi_owned: true,
        ..Default::default()
    });
    config
        .network
        .interfaces
        .insert("wlan1".to_string(), wlan1_cfg);
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeWirelessNetwork {
        missing: Default::default(),
        interfaces: vec![NetworkInterface {
            name: "wlan1".into(),
            index: 1,
            is_up: true,
            rx_bytes: 0,
            tx_bytes: 0,
            is_wireless: true,
        }],
    });
    let wifi_client = ClientSupervisor::start_with_process(&config, FakeSupplicantProcess::new())
        .await
        .expect("wifi client supervisor");
    let service = ControlService::new(config, network, dhcp, overrides.clone())
        .with_wifi_client_supervisor(wifi_client);

    let response = service
        .dispatch(Request::DeactivateWifiClientProfile {
            interface: "wlan1".to_string(),
        })
        .await;
    let Response::NetworkChangePending { change } = response else {
        panic!("expected pending client deactivation, got {response:?}");
    };
    let committed_before = overrides
        .effective_interface("wlan1")
        .await
        .unwrap()
        .unwrap();
    assert!(committed_before.wifi_client.is_some());
    assert!(committed_before.dhcp_client.unwrap().enabled);

    assert!(matches!(
        service
            .dispatch(Request::CommitNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeCommitted { .. }
    ));
    let committed = overrides
        .effective_interface("wlan1")
        .await
        .unwrap()
        .unwrap();
    assert!(committed.wifi_client.is_none());
    let policy = committed.dhcp_client.expect("dhcp client policy");
    assert!(!policy.enabled);
    assert!(!policy.wifi_owned);
}

#[tokio::test]
async fn wifi_client_deactivation_commit_failure_can_be_rolled_back_cleanly() {
    let fixture = wifi_client_enabled_fixture().await;
    std::fs::create_dir(fixture.service.overrides.path()).unwrap();
    let original = fixture
        .service
        .effective_config()
        .await
        .unwrap()
        .network
        .interfaces["wlan1"]
        .clone();

    let response = fixture
        .service
        .dispatch(Request::DeactivateWifiClientProfile {
            interface: "wlan1".to_string(),
        })
        .await;
    let Response::NetworkChangePending { change } = response else {
        panic!("expected pending client deactivation, got {response:?}");
    };
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::CommitNetworkChange {
                token: change.token.clone()
            })
            .await,
        Response::Error { .. }
    ));
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::RollbackNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeRolledBack { .. }
    ));
    assert_eq!(
        fixture
            .service
            .effective_config()
            .await
            .unwrap()
            .network
            .interfaces["wlan1"],
        original
    );
}

#[tokio::test]
async fn wifi_client_deactivation_rollback_preserves_wifi_owned_dhcp_intent() {
    let directory = tempdir().expect("tempdir");
    let mut config = wifi_client_base_config(directory.path());
    let mut wlan1_cfg = config.network.interfaces["wlan1"].clone();
    wlan1_cfg.dhcp_client = Some(DhcpClientInterfaceConfig {
        wifi_owned: true,
        ..Default::default()
    });
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
    let network: Arc<dyn NetworkProvider> = Arc::new(FakeWirelessNetwork {
        missing: Default::default(),
        interfaces: vec![NetworkInterface {
            name: "wlan1".into(),
            index: 1,
            is_up: true,
            rx_bytes: 0,
            tx_bytes: 0,
            is_wireless: true,
        }],
    });
    let wifi_client = ClientSupervisor::start_with_process(&config, FakeSupplicantProcess::new())
        .await
        .expect("wifi client supervisor");
    let service = ControlService::new(config, network, dhcp, overrides.clone())
        .with_wifi_client_supervisor(wifi_client);

    let response = service
        .dispatch(Request::DeactivateWifiClientProfile {
            interface: "wlan1".to_string(),
        })
        .await;
    let Response::NetworkChangePending { change } = response else {
        panic!("expected pending client deactivation, got {response:?}");
    };
    assert!(matches!(
        service
            .dispatch(Request::RollbackNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeRolledBack { .. }
    ));
    assert_eq!(
        overrides
            .effective_interface("wlan1")
            .await
            .unwrap()
            .unwrap(),
        wlan1_cfg
    );
}

#[tokio::test]
async fn internal_wifi_client_disable_cleans_up_wifi_owned_dhcp() {
    let directory = tempdir().expect("tempdir");
    let mut config = wifi_client_base_config(directory.path());
    let mut wlan1_cfg = config
        .network
        .interfaces
        .get("wlan1")
        .expect("wlan1 declared")
        .clone();
    wlan1_cfg.managed = true;
    wlan1_cfg.dhcp_client = Some(DhcpClientInterfaceConfig {
        wifi_owned: true,
        ..Default::default()
    });
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
    let wifi_client = ClientSupervisor::start_with_process(&config, FakeSupplicantProcess::new())
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
        .disable_wifi_client_locked("wlan1".to_string())
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
        .activate_wifi_client_profile_internal("wlan1".to_string(), "reactivate".to_string())
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
async fn internal_wifi_client_disable_restores_state_if_persistence_fails() {
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
    wlan1_cfg.dhcp_client = Some(DhcpClientInterfaceConfig {
        wifi_owned: true,
        ..Default::default()
    });
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
    let wifi_client = ClientSupervisor::start_with_process(&config, FakeSupplicantProcess::new())
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
        .disable_wifi_client_locked("wlan1".to_string())
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
async fn internal_wifi_client_disable_restores_state_if_dhcp_disable_fails() {
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
    wlan1_cfg.dhcp_client = Some(DhcpClientInterfaceConfig {
        wifi_owned: true,
        ..Default::default()
    });
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
    let wifi_client = ClientSupervisor::start_with_process(&config, FakeSupplicantProcess::new())
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

    let store = crate::dhcp::client::store::DhcpClientLeaseStore::new(&config.runtime.state_dir)
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
        .disable_wifi_client_locked("wlan1".to_string())
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
    rollback_unavailable: StdMutex<bool>,
}

#[async_trait]
impl RouterSubsystems for FakeProvisioningSubsystems {
    async fn plan_for(&self, desired: &RouterDesired) -> Result<RouterSubsystemPlan> {
        let uplink_wifi = desired
            .uplink_wifi
            .iter()
            .map(|spec| WifiPlan::Start {
                desired: spec.clone(),
            })
            .collect();
        let output_wifi = desired
            .output_wifi
            .iter()
            .map(|spec| WifiPlan::Start {
                desired: spec.clone(),
            })
            .collect();
        let routes = self.plan_routes(desired).await?;
        let vpn_chain = self.plan_vpn_chain(desired).await?;
        let dataplane = self.plan_dataplane(desired).await?;
        Ok(RouterSubsystemPlan {
            interfaces: Vec::new(),
            uplink_wifi,
            output_wifi,
            routes,
            dhcp: Vec::new(),
            vpn_chain,
            dataplane,
        })
    }
    async fn plan_routes(&self, _: &RouterDesired) -> Result<RoutePlan> {
        Ok(RoutePlan {
            add: Vec::new(),
            delete: Vec::new(),
        })
    }
    async fn plan_dataplane(&self, desired: &RouterDesired) -> Result<RouterDataplanePlan> {
        Ok(RouterDataplanePlan {
            snapshot: fake_dataplane_snapshot(),
            target: desired.dataplane.clone(),
            requires_apply: true,
        })
    }
    async fn snapshot_for(&self, _: &RouterDesired) -> Result<RouterSnapshot> {
        Ok(fake_router_snapshot())
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
    async fn rollback_dhcp_scoped(&self, _: &[DhcpServiceSpec], _: &[String]) -> Result<()> {
        Ok(())
    }
    async fn rollback_dataplane(&self, _: &RouterDataplaneSnapshot) -> Result<()> {
        if *self.rollback_unavailable.lock().unwrap() {
            return Err(crate::core::recovery_control::failure(
                crate::core::recovery_control::FailureKind::Transient,
                "injected temporary dataplane rollback failure",
            ));
        }
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
    async fn quiesce_uplink_dhcp(
        &self,
        _desired: Option<&crate::dhcp::client::DhcpClientSpec>,
    ) -> Result<()> {
        Ok(())
    }
    async fn apply_uplink_dhcp_candidate(
        &self,
        desired: Option<&crate::dhcp::client::DhcpClientSpec>,
    ) -> Result<bool> {
        Ok(desired.is_some())
    }
    async fn rollback_candidate_uplink_dhcp(&self) -> Result<()> {
        Ok(())
    }
    async fn rollback_dhcp_clients(
        &self,
        _snapshots: &[crate::core::router::DhcpClientSnapshot],
        _legacy: Option<&crate::dhcp::client::DhcpClientSpec>,
    ) -> Result<()> {
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
            mac_address: None,
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
    assert!(
        message.contains("failed to inspect IPv4 routes"),
        "{message}"
    );
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
                traffic_masq_protocol::RouteOwnerView::TrafficMasqStatic
            );

            assert_eq!(routes[1].destination, "0.0.0.0/0".parse().unwrap());
            assert_eq!(routes[1].output_interface.as_deref(), Some("eth0"));
            assert_eq!(routes[1].owner, traffic_masq_protocol::RouteOwnerView::Boot);
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
            assert_eq!(
                routes[2].owner,
                traffic_masq_protocol::RouteOwnerView::Kernel
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }

    let cfg_resp = service.dispatch(Request::GetRouterConfig).await;
    match cfg_resp {
        Response::RouterConfig { config: router_cfg } => {
            assert_eq!(router_cfg.is_active(), config.router.is_active());
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn unrelated_recovery_does_not_block_interface_commit_or_rollback() {
    let directory = tempdir().unwrap();
    let mut config = AppConfig::default();
    config.runtime.state_dir = directory.path().to_path_buf();
    config.dhcp.leases_dir = directory.path().join("leases");
    let interface = InterfaceConfig {
        mac_address: None,
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some("192.168.77.1/24".parse().unwrap()),
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
        nat: true,
    };
    config
        .network
        .interfaces
        .insert("eth0".into(), interface.clone());
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    network.add_interface("eth0", 1).await;
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&config).await.unwrap();
    let service = ControlService::new(config, network, dhcp, overrides.clone());
    crate::core::recovery::block_interface(directory.path(), "wlan0", "invalid snapshot".into());

    for commit in [true, false] {
        let token = match service
            .dispatch(Request::ApplyInterface {
                interface: "eth0".into(),
                config: interface.clone().into(),
                allow_management_change: false,
            })
            .await
        {
            Response::NetworkChangePending { change } => change.token,
            other => panic!("apply rejected: {other:?}"),
        };
        // A block on this transaction's own interface must still be enforced.
        crate::core::recovery::block_interface(
            directory.path(),
            "eth0",
            "recovery required".into(),
        );
        let request = if commit {
            Request::CommitNetworkChange {
                token: token.clone(),
            }
        } else {
            Request::RollbackNetworkChange {
                token: token.clone(),
            }
        };
        assert!(matches!(
            service.dispatch(request).await,
            Response::Error { .. }
        ));
        crate::core::recovery::unblock_interface(directory.path(), "eth0");
        let response = service
            .dispatch(if commit {
                Request::CommitNetworkChange { token }
            } else {
                Request::RollbackNetworkChange { token }
            })
            .await;
        if commit {
            assert!(
                matches!(response, Response::NetworkChangeCommitted { .. }),
                "{response:?}"
            );
            assert!(overrides.snapshot().await.interfaces.contains_key("eth0"));
        } else {
            assert!(
                matches!(response, Response::NetworkChangeRolledBack { .. }),
                "{response:?}"
            );
        }
        assert!(service.transactions.pending().await.is_empty());
    }
}

#[tokio::test]
async fn saved_ap_profile_activation_stays_pending_until_explicit_commit() {
    let directory = tempdir().expect("tempdir");
    let mut config = wifi_base_config(directory.path());
    config.wifi.hostapd_binary = PathBuf::from("/bin/true");
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .expect("overrides");
    let dhcp = DhcpSupervisor::start(&config)
        .await
        .expect("dhcp supervisor");
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    network.add_interface("wlan0", 1).await;
    network
        .interfaces
        .lock()
        .await
        .get_mut("wlan0")
        .expect("wlan0")
        .is_wireless = true;
    let process = FakeWifiProcess::new();
    let wifi = WifiSupervisor::start_with_process_and_radio(
        &config,
        process,
        Arc::new(crate::wifi::radio::AllowAllRadioValidator),
    )
    .await
    .expect("wifi supervisor");
    configure_wlan0(&wifi, &config).await;
    let service =
        ControlService::new(config, network, dhcp, overrides.clone()).with_wifi_supervisor(wifi);

    let saved = service
        .dispatch(Request::SaveWifiApProfile {
            profile: crate::api::model::WifiApProfileWriteRequest {
                id: "guest".into(),
                configuration: crate::api::model::ProvisionWifiAccessPointRequest {
                    settings: WifiEditRequest {
                        ssid: "net-b".into(),
                        country_code: Some("PL".into()),
                        band: WifiBand::Ghz2,
                        channel: 11,
                        channel_width: WifiChannelWidth::Ht20,
                        security: WifiSecurity::Open,
                        hidden: false,
                        client_isolation: true,
                        max_stations: 32,
                    },
                    passphrase: None,
                    clear_passphrase: true,
                    configure_dhcp: false,
                    subnet: None,
                    disable_dhcp: false,
                },
            },
        })
        .await;
    assert!(
        matches!(saved, Response::WifiApProfileSaved { .. }),
        "{saved:?}"
    );
    let response = service
        .dispatch(Request::ActivateWifiApProfile {
            interface: "wlan0".into(),
            profile_id: "guest".into(),
        })
        .await;
    let token = match response {
        Response::NetworkChangePending { change } => change.token,
        other => panic!("unexpected response: {other:?}"),
    };

    assert!(!overrides.snapshot().await.interfaces.contains_key("wlan0"));
    match service
        .dispatch(Request::GetWifiConfig {
            interface: "wlan0".into(),
        })
        .await
    {
        Response::WifiConfig {
            spec: Some(spec), ..
        } => assert_eq!(spec.ssid, "net-a"),
        other => panic!("unexpected response: {other:?}"),
    }

    assert!(matches!(
        service
            .dispatch(Request::CommitNetworkChange { token })
            .await,
        Response::NetworkChangeCommitted { .. }
    ));
    assert!(overrides.snapshot().await.interfaces.contains_key("wlan0"));
    match service
        .dispatch(Request::GetWifiConfig {
            interface: "wlan0".into(),
        })
        .await
    {
        Response::WifiConfig {
            spec: Some(spec), ..
        } => {
            assert_eq!(spec.ssid, "net-b");
            assert_eq!(spec.channel, 11);
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn configure_client_open_erases_obsolete_stored_credentials() {
    let fixture = wifi_client_enabled_fixture().await;
    let wifi = fixture.service.wifi_client.as_ref().unwrap();
    wifi.set_passphrase("wlan1", &WifiPassphrase::new("obsolete-password").unwrap())
        .await
        .unwrap();
    let response = fixture
        .service
        .dispatch(Request::ConfigureWifiClient {
            interface: "wlan1".into(),
            settings: WifiClientEditRequest {
                ssid: "open-network".into(),
                country_code: Some("PL".into()),
                security: WifiClientSecurity::Open,
            },
        })
        .await;
    assert!(
        matches!(response, Response::NetworkChangePending { .. }),
        "{response:?}"
    );
    assert!(wifi.stored_passphrase("wlan1").await.unwrap().is_none());
}

#[tokio::test]
async fn wifi_client_provision_keeps_ip_policy_tentative_and_restores_on_rollback() {
    let directory = tempdir().unwrap();
    let mut config = wifi_client_base_config(directory.path());
    config.wifi_client.wpa_supplicant_binary = PathBuf::from("/bin/true");
    let original = config.network.interfaces["wlan1"].clone();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&config).await.unwrap();
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    network.add_interface("wlan1", 1).await;
    let wifi = ClientSupervisor::start_with_process(&config, FakeSupplicantProcess::new())
        .await
        .unwrap();
    let service = ControlService::new(config, network, dhcp, overrides.clone())
        .with_wifi_client_supervisor(wifi);
    assert!(matches!(
        service
            .dispatch(Request::CreateWifiClientProfile {
                profile: WifiClientProfileWriteRequest {
                    id: "candidate".into(),
                    ssid: "candidate".into(),
                    country_code: None,
                    security: WifiClientSecurity::Open,
                    priority: 0,
                    autoconnect: false,
                    passphrase: None,
                    clear_passphrase: false,
                }
            })
            .await,
        Response::WifiClientProfile { .. }
    ));
    let response = service
        .dispatch(Request::ProvisionWifiClient {
            interface: "wlan1".into(),
            settings: crate::api::model::ProvisionWifiClientRequest {
                profile_id: "candidate".into(),
                ip_policy: crate::api::model::WifiClientIpPolicy::Static {
                    cidr: "192.168.77.2/24".parse().unwrap(),
                },
            },
        })
        .await;
    let Response::NetworkChangePending { change } = response else {
        panic!("{response:?}")
    };
    assert_eq!(
        overrides
            .effective_interface("wlan1")
            .await
            .unwrap()
            .unwrap(),
        original
    );
    assert!(matches!(
        service
            .dispatch(Request::RollbackNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeRolledBack { .. }
    ));
    assert_eq!(
        overrides
            .effective_interface("wlan1")
            .await
            .unwrap()
            .unwrap(),
        original
    );
}

#[tokio::test]
async fn wifi_deactivate_preserves_independent_dhcp_intent() {
    let fixture = wifi_client_enabled_fixture().await;
    let before = fixture
        .service
        .overrides
        .effective_interface("wlan1")
        .await
        .unwrap()
        .unwrap()
        .dhcp_client;
    let response = fixture
        .service
        .dispatch(Request::DeactivateWifiClientProfile {
            interface: "wlan1".into(),
        })
        .await;
    let Response::NetworkChangePending { change } = response else {
        panic!("expected pending client deactivation, got {response:?}");
    };
    assert!(matches!(
        fixture
            .service
            .dispatch(Request::CommitNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeCommitted { .. }
    ));
    let after = fixture
        .service
        .overrides
        .effective_interface("wlan1")
        .await
        .unwrap()
        .unwrap()
        .dhcp_client;
    assert_eq!(before, after);
    assert!(after.unwrap().enabled);
}

#[tokio::test]
async fn hotspot_provision_uses_preassigned_output_role_and_subnet_atomically() {
    let directory = tempdir().unwrap();
    let mut config = wifi_base_config(directory.path());
    config.wifi.hostapd_binary = PathBuf::from("/bin/true");
    config.network.interfaces.get_mut("wlan0").unwrap().wifi = None;
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&config).await.unwrap();
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    network.add_interface("wlan0", 1).await;
    network
        .interfaces
        .lock()
        .await
        .get_mut("wlan0")
        .unwrap()
        .is_wireless = true;
    let wifi = WifiSupervisor::start_with_process_and_radio(
        &config,
        FakeWifiProcess::new(),
        Arc::new(crate::wifi::radio::AllowAllRadioValidator),
    )
    .await
    .unwrap();
    let service =
        ControlService::new(config, network, dhcp, overrides.clone()).with_wifi_supervisor(wifi);
    let response = service
        .dispatch(Request::ProvisionWifiAccessPoint {
            interface: "wlan0".into(),
            settings: WifiEditRequest {
                ssid: "hotspot".into(),
                country_code: Some("PL".into()),
                band: WifiBand::Ghz2,
                channel: 6,
                channel_width: WifiChannelWidth::Ht20,
                security: WifiSecurity::Open,
                hidden: false,
                client_isolation: false,
                max_stations: 32,
            },
            passphrase: None,
            clear_passphrase: true,
            configure_dhcp: true,
            subnet: Some("192.168.50.1/24".parse().unwrap()),
            disable_dhcp: false,
        })
        .await;
    let Response::NetworkChangePending { change } = response else {
        panic!("{response:?}")
    };
    assert!(overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap()
        .wifi
        .is_none());
    assert!(matches!(
        service
            .dispatch(Request::CommitNetworkChange {
                token: change.token
            })
            .await,
        Response::NetworkChangeCommitted { .. }
    ));
    let committed = overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap();
    assert!(committed.managed);
    assert_eq!(committed.role, InterfaceRole::Output);
    assert_eq!(committed.ipv4, Some("192.168.50.1/24".parse().unwrap()));
    assert_eq!(committed.wifi.unwrap().ssid, "hotspot");
    assert_eq!(
        committed.dhcp.unwrap().router,
        "192.168.50.1".parse::<Ipv4Addr>().unwrap()
    );
}

#[tokio::test]
async fn uncertain_dhcp_commit_preserves_candidate_and_blocks_subsequent_mutations() {
    let fixture = dhcp_client_control_fixture(false).await;
    fixture
        .overrides
        .save_committed(fixture.overrides.snapshot().await)
        .await
        .unwrap();
    crate::atomic_file::fail_replacement_and_compensation(fixture.overrides.path());
    let response = fixture
        .service
        .dispatch(Request::ConfigureDhcpClient {
            interface: "wan0".into(),
            config: DhcpClientConfigRequest::default(),
        })
        .await;
    assert!(
        matches!(response, Response::DhcpClientError {
        detail: DhcpClientErrorDetail::PersistenceFailure { ref message }
    } if message.contains("commit_indeterminate")),
        "{response:?}"
    );
    assert!(fixture.supervisor.spec("wan0").await.is_some());
    let response = fixture
        .service
        .dispatch(Request::DisableDhcpClient {
            interface: "wan0".into(),
        })
        .await;
    assert!(
        matches!(response, Response::Error { ref message } if message.contains("commit_indeterminate")),
        "{response:?}"
    );
    assert!(fixture.supervisor.spec("wan0").await.is_some());
}

#[tokio::test]
async fn queued_autoconnect_observes_commit_fence_after_admission() {
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
    fixture
        .service
        .wifi_client
        .as_ref()
        .unwrap()
        .disable("wlan1")
        .await
        .unwrap();
    let next_pid = fixture.process.next_pid.load(WifiOrdering::Relaxed);
    let mutation = fixture.service.network_mutations.write().await;
    let pass = fixture.service.autoconnect_wifi_once();
    tokio::pin!(pass);
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut pass)
        .await
        .is_err());
    crate::core::recovery::fence_commit(
        &fixture.service.config.runtime.state_dir,
        "commit failed while autoconnect waited for admission".into(),
    );
    drop(mutation);
    tokio::time::timeout(Duration::from_secs(5), pass)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        fixture.process.next_pid.load(WifiOrdering::Relaxed),
        next_pid,
        "a queued scan must not launch a supplicant after an uncertain commit"
    );
}

#[tokio::test]
async fn settings_writes_wait_for_network_execution_and_observe_commit_fence() {
    for request in [
        Request::ResetApiHttpsSettings,
        Request::ResetSecuritySettings,
    ] {
        let fixture = dhcp_client_control_fixture(false).await;
        let revision = fixture.overrides.committed_revision().await;
        let execution = fixture.service.network_mutations.execute().await;
        let write = fixture.service.dispatch(request);
        tokio::pin!(write);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut write)
                .await
                .is_err(),
            "settings must not write shared intent during runtime execution"
        );
        crate::core::recovery::fence_commit(
            &fixture.service.config.runtime.state_dir,
            "uncertain network commit".into(),
        );
        drop(execution);
        let response = write.await;
        assert!(
            matches!(response, Response::Error { ref message } if message.contains("commit_indeterminate")),
            "{response:?}"
        );
        assert_eq!(fixture.overrides.committed_revision().await, revision);
    }
}

async fn shared_phy_wifi_service() -> (ControlService, tempfile::TempDir) {
    let directory = tempdir().unwrap();
    let mut config = wifi_client_base_config(directory.path());
    let ap_config = wifi_base_config(directory.path());
    config.wifi = ap_config.wifi;
    config.wifi.hostapd_binary = PathBuf::from("/bin/true");
    config.wifi_client.wpa_supplicant_binary = PathBuf::from("/bin/true");
    config.network.interfaces.insert(
        "wlan0".into(),
        ap_config.network.interfaces["wlan0"].clone(),
    );
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    for (name, index) in [("wlan0", 1), ("wlan1", 2)] {
        network.add_interface(name, index).await;
        network
            .interfaces
            .lock()
            .await
            .get_mut(name)
            .unwrap()
            .is_wireless = true;
        network
            .wireless_phys
            .lock()
            .unwrap()
            .insert(name.into(), "shared-radio".into());
    }
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&config).await.unwrap();
    let wifi = WifiSupervisor::start_with_process_and_radio(
        &config,
        FakeWifiProcess::new(),
        Arc::new(crate::wifi::radio::AllowAllRadioValidator),
    )
    .await
    .unwrap();
    let client = ClientSupervisor::start_with_process(&config, FakeSupplicantProcess::new())
        .await
        .unwrap();
    let service = ControlService::new(config, network, dhcp, overrides)
        .with_wifi_supervisor(wifi)
        .with_wifi_client_supervisor(client);
    let response = service
        .dispatch(Request::CreateWifiClientProfile {
            profile: WifiClientProfileWriteRequest {
                id: "radio-test".into(),
                ssid: "upstream".into(),
                country_code: Some("PL".into()),
                security: WifiClientSecurity::Open,
                priority: 0,
                autoconnect: true,
                passphrase: None,
                clear_passphrase: false,
            },
        })
        .await;
    assert!(
        matches!(response, Response::WifiClientProfile { .. }),
        "{response:?}"
    );
    (service, directory)
}

#[tokio::test]
async fn every_wifi_admission_path_rejects_mixed_roles_on_one_phy_before_mutation() {
    let (service, _directory) = shared_phy_wifi_service().await;
    let ap = WifiEditRequest {
        ssid: "changed-ap".into(),
        country_code: Some("PL".into()),
        band: WifiBand::Ghz2,
        channel: 6,
        channel_width: WifiChannelWidth::Ht20,
        security: WifiSecurity::Open,
        hidden: false,
        client_isolation: false,
        max_stations: 32,
    };
    for request in [
        Request::ConfigureWifi {
            interface: "wlan0".into(),
            settings: ap.clone(),
        },
        Request::ProvisionWifiAccessPoint {
            interface: "wlan0".into(),
            settings: ap,
            passphrase: None,
            clear_passphrase: true,
            configure_dhcp: false,
            subnet: None,
            disable_dhcp: false,
        },
        Request::ConfigureWifiClient {
            interface: "wlan1".into(),
            settings: WifiClientEditRequest {
                ssid: "changed-sta".into(),
                country_code: Some("PL".into()),
                security: WifiClientSecurity::Open,
            },
        },
        Request::ProvisionWifiClient {
            interface: "wlan1".into(),
            settings: crate::api::model::ProvisionWifiClientRequest {
                profile_id: "radio-test".into(),
                ip_policy: crate::api::model::WifiClientIpPolicy::Preserve,
            },
        },
        Request::ActivateWifiClientProfile {
            interface: "wlan1".into(),
            profile_id: "radio-test".into(),
        },
        Request::WifiClientScan {
            interface: "wlan1".into(),
        },
    ] {
        let response = service.dispatch(request).await;
        assert!(
            serde_json::to_string(&response)
                .unwrap()
                .contains("shared-radio"),
            "{response:?}"
        );
        assert!(service.transactions.pending().await.is_empty());
        assert!(service.overrides.snapshot().await.interfaces.is_empty());
    }
    let response = service
        .activate_wifi_client_profile_internal("wlan1".into(), "radio-test".into())
        .await;
    assert!(
        serde_json::to_string(&response)
            .unwrap()
            .contains("shared-radio"),
        "{response:?}"
    );
    service.autoconnect_wifi_once().await.unwrap();
    assert!(service.overrides.snapshot().await.interfaces.is_empty());
    assert!(service
        .wifi
        .as_ref()
        .unwrap()
        .status("wlan0")
        .await
        .is_none());
    assert!(service
        .wifi_client
        .as_ref()
        .unwrap()
        .status("wlan1")
        .await
        .is_none());
}

#[tokio::test]
async fn operator_profile_activation_is_tentative_and_rollback_restores_committed_config() {
    let fixture = wifi_client_enabled_fixture().await;
    let original = fixture
        .service
        .effective_config()
        .await
        .unwrap()
        .network
        .interfaces["wlan1"]
        .clone();
    fixture
        .service
        .dispatch(Request::CreateWifiClientProfile {
            profile: WifiClientProfileWriteRequest {
                id: "tentative".into(),
                ssid: "tentative-network".into(),
                country_code: Some("PL".into()),
                security: WifiClientSecurity::Open,
                priority: 0,
                autoconnect: false,
                passphrase: None,
                clear_passphrase: false,
            },
        })
        .await;
    let response = fixture
        .service
        .dispatch(Request::ActivateWifiClientProfile {
            interface: "wlan1".into(),
            profile_id: "tentative".into(),
        })
        .await;
    let Response::NetworkChangePending { change } = response else {
        panic!("{response:?}")
    };
    assert_eq!(
        fixture
            .service
            .effective_config()
            .await
            .unwrap()
            .network
            .interfaces["wlan1"],
        original
    );
    assert!(fixture
        .service
        .overrides
        .snapshot()
        .await
        .interfaces
        .is_empty());
    let response = fixture
        .service
        .dispatch(Request::RollbackNetworkChange {
            token: change.token,
        })
        .await;
    assert!(
        matches!(response, Response::NetworkChangeRolledBack { .. }),
        "{response:?}"
    );
    assert_eq!(
        fixture
            .service
            .effective_config()
            .await
            .unwrap()
            .network
            .interfaces["wlan1"],
        original
    );
    assert!(fixture.service.transactions.pending().await.is_empty());
}

#[tokio::test]
async fn client_configuration_converges_before_reply_and_rollback_restores_runtime_without_deadlock(
) {
    let fixture = wifi_client_enabled_fixture().await;
    let desired = DesiredNetworkState::new(
        fixture.service.base_config.clone(),
        fixture.service.overrides.clone(),
    );
    desired.attach_converger();
    let service = ControlService::from_runtime(
        ControlRuntime {
            active_config: fixture.service.config.clone(),
            base_config: fixture.service.base_config.clone(),
            network: fixture.service.network.clone(),
            dhcp: fixture.service.dhcp.clone(),
            overrides: fixture.service.overrides.clone(),
            baselines: Vec::new(),
            ownership_journal: AddressOwnershipJournal::in_memory(),
            desired_state: desired.clone(),
            mutation_gate: Arc::new(NetworkMutationGate::default()),
        },
        ControlSubsystems {
            wifi_client: fixture.service.wifi_client.clone(),
            ..ControlSubsystems::default()
        },
    );
    let runtime = service.wifi_client.as_ref().unwrap().clone();
    let gate = service.network_mutations.clone();
    let worker_desired = desired.clone();
    let worker_runtime = runtime.clone();
    let worker = tokio::spawn(async move {
        loop {
            let version = worker_desired.version();
            {
                // Same gate as the daemon's convergence pass: dispatch must
                // release exclusive execution while retaining API admission.
                let _execution = gate.read().await;
                let config = worker_desired.effective().await.unwrap();
                let spec = WifiClientSpec::from_interface_config(
                    "wlan1",
                    &config.network.interfaces["wlan1"],
                )
                .unwrap()
                .unwrap();
                let result = worker_runtime
                    .configure(spec)
                    .await
                    .map_err(anyhow::Error::from);
                worker_desired.report_result(version, result.map(|_| BTreeMap::new()));
            }
            worker_desired.changed().await;
        }
    });
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        service.dispatch(Request::ConfigureWifiClient {
            interface: "wlan1".into(),
            settings: WifiClientEditRequest {
                ssid: "tentative-runtime".into(),
                country_code: Some("PL".into()),
                security: WifiClientSecurity::Open,
            },
        }),
    )
    .await
    .expect("dispatch must not hold convergence's execution lock");
    let Response::NetworkChangePending { change } = response else {
        worker.abort();
        panic!("{response:?}")
    };
    assert_eq!(
        runtime.status("wlan1").await.unwrap().spec.ssid,
        "tentative-runtime"
    );
    assert_eq!(
        service.effective_config().await.unwrap().network.interfaces["wlan1"]
            .wifi_client
            .as_ref()
            .unwrap()
            .ssid,
        "upstream"
    );
    let rollback = tokio::time::timeout(
        Duration::from_secs(5),
        service.dispatch(Request::RollbackNetworkChange {
            token: change.token,
        }),
    )
    .await
    .unwrap();
    assert!(
        matches!(rollback, Response::NetworkChangeRolledBack { .. }),
        "{rollback:?}"
    );
    assert_eq!(runtime.status("wlan1").await.unwrap().spec.ssid, "upstream");
    worker.abort();
}

#[tokio::test]
async fn wifi_provisioning_rejects_interfaces_without_the_required_role() {
    let ap = wifi_enabled_fixture().await;
    let client = wifi_client_enabled_fixture().await;
    let mut input = client.service.base_config.network.interfaces["wlan1"].clone();
    input.wifi_client = None;
    ap.service
        .overrides
        .set_interface("input".into(), input, false)
        .await
        .unwrap();
    let mut output = ap.service.base_config.network.interfaces["wlan0"].clone();
    output.wifi = None;
    client
        .service
        .overrides
        .set_interface("output".into(), output, false)
        .await
        .unwrap();
    for interface in ["missing", "input"] {
        let response = ap
            .service
            .dispatch(Request::ProvisionWifiAccessPoint {
                interface: interface.into(),
                settings: WifiEditRequest {
                    ssid: "test".into(),
                    country_code: None,
                    band: WifiBand::Ghz2,
                    channel: 0,
                    channel_width: WifiChannelWidth::Ht20,
                    security: WifiSecurity::Open,
                    hidden: false,
                    client_isolation: false,
                    max_stations: 32,
                },
                passphrase: None,
                clear_passphrase: true,
                configure_dhcp: true,
                subnet: Some("192.168.50.1/24".parse().unwrap()),
                disable_dhcp: false,
            })
            .await;
        assert!(
            matches!(response, Response::WifiError {
            detail: WifiErrorDetail::InvalidSpec { ref message }
        } if message.contains("managed output")),
            "{response:?}"
        );
    }
    for interface in ["missing", "output"] {
        let response = client
            .service
            .dispatch(Request::ProvisionWifiClient {
                interface: interface.into(),
                settings: crate::api::model::ProvisionWifiClientRequest {
                    profile_id: "unused".into(),
                    ip_policy: crate::api::model::WifiClientIpPolicy::Dhcp,
                },
            })
            .await;
        assert!(
            matches!(response, Response::WifiClientError {
            detail: WifiClientErrorDetail::InvalidSpec { ref message }
        } if message.contains("managed input")),
            "{response:?}"
        );
    }
}

#[tokio::test]
async fn explicit_router_retry_bypasses_only_its_own_persisted_stop() {
    let (service, directory) = router_enabled_service().await;
    let token = match service
        .dispatch(Request::RouterApply {
            proposal: router_proposal().into(),
        })
        .await
    {
        Response::RouterTransactionPending { token, .. } => token,
        response => panic!("unexpected response: {response:?}"),
    };
    let journal = directory.path().join("router-transaction.json");
    crate::core::recovery_control::stop(
        &journal,
        crate::core::recovery_control::FailureKind::Conflict,
        "external conflict",
    )
    .await
    .unwrap();
    match service.dispatch(Request::RouterPendingTransaction).await {
        Response::RouterPendingTransaction {
            status,
            recovery: Some(notice),
            ..
        } => {
            assert_eq!(status, CoordinatorStatus::RecoveryRequired);
            let progress = notice.recovery_progress.unwrap();
            assert_eq!(
                progress.failure_kind,
                traffic_masq_protocol::RecoveryFailureKind::Conflict
            );
            assert!(!progress.automatic_recovery);
        }
        response => panic!("unexpected response: {response:?}"),
    }
    assert!(!matches!(
        service
            .dispatch(Request::RouterCommit {
                token: token.clone()
            })
            .await,
        Response::RouterCommitted { .. }
    ));
    assert!(matches!(
        service.dispatch(Request::RouterRollback { token }).await,
        Response::RouterRolledBack
    ));
    assert!(!journal.exists());
}

#[tokio::test]
async fn missing_interface_inventory_save_forget_reset_and_stale_editor() {
    use traffic_masq_protocol::InterfacePresence;
    let directory = tempdir().unwrap();
    let mut base = router_base_config();
    base.runtime.state_dir = directory.path().into();
    let overrides = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&base).await.unwrap();
    let service = ControlService::new(
        base.clone(),
        Arc::new(FakeNetwork {
            addresses: Vec::new(),
        }),
        dhcp,
        overrides.clone(),
    );
    let revision = match service.dispatch(Request::ListInterfaceInventory).await {
        Response::InterfaceInventory {
            interfaces,
            revision,
            ..
        } => {
            let lan = interfaces
                .iter()
                .find(|entry| entry.name == "lan0")
                .unwrap();
            assert_eq!(lan.presence, InterfacePresence::Missing);
            assert!(lan.observed.is_none());
            assert!(lan.configured.is_some());
            revision
        }
        response => panic!("{response:?}"),
    };
    let response = service
        .dispatch(Request::ForgetInterfaceConfig {
            interface: "lan0".into(),
            expected_revision: revision,
        })
        .await;
    assert!(
        matches!(response, Response::InterfaceIntentSaved { .. }),
        "{response:?}"
    );
    assert!(overrides
        .effective_interface("lan0")
        .await
        .unwrap()
        .is_none());
    let response = service
        .dispatch(Request::SaveInterfaceConfig {
            interface: "lan0".into(),
            config: base.network.interfaces["lan0"].clone().into(),
            allow_management_change: false,
            expected_revision: revision,
        })
        .await;
    assert!(matches!(response, Response::Error { .. }));
    assert!(overrides
        .effective_interface("lan0")
        .await
        .unwrap()
        .is_none());
    let restarted = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    assert!(restarted
        .effective_interface("lan0")
        .await
        .unwrap()
        .is_none());
    let response = service
        .dispatch(Request::ResetInterfaceOverride {
            interface: "lan0".into(),
            expected_revision: overrides.committed_revision().await,
        })
        .await;
    assert!(
        matches!(response, Response::InterfaceIntentSaved { .. }),
        "{response:?}"
    );
    assert_eq!(
        overrides.effective_interface("lan0").await.unwrap(),
        Some(base.network.interfaces["lan0"].clone())
    );
}

#[tokio::test]
async fn inventory_observation_failure_retains_cache_and_blocks_offline_writes() {
    use traffic_masq_protocol::InterfacePresence;
    let directory = tempdir().unwrap();
    let mut base = router_base_config();
    base.runtime.state_dir = directory.path().into();
    let overrides = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    network.add_interface("lan0", 7).await;
    let dhcp = DhcpSupervisor::start(&base).await.unwrap();
    let service = ControlService::new(base, network.clone(), dhcp, overrides.clone());
    assert!(matches!(
        service.dispatch(Request::ListInterfaceInventory).await,
        Response::InterfaceInventory { .. }
    ));
    *network.fail_interface_observation.lock().await = true;
    match service.dispatch(Request::ListInterfaceInventory).await {
        Response::InterfaceInventory {
            interfaces,
            observation_error,
            ..
        } => {
            assert!(observation_error.is_some());
            let lan = interfaces
                .iter()
                .find(|entry| entry.name == "lan0")
                .unwrap();
            assert_eq!(lan.presence, InterfacePresence::Unknown);
            assert!(lan.observation_stale);
            assert_eq!(lan.observed.as_ref().unwrap().interface.index, 7);
            assert!(interfaces
                .iter()
                .all(|entry| entry.presence == InterfacePresence::Unknown));
        }
        response => panic!("{response:?}"),
    }
    let revision = overrides.committed_revision().await;
    assert!(matches!(
        service
            .dispatch(Request::ForgetInterfaceConfig {
                interface: "lan0".into(),
                expected_revision: revision,
            })
            .await,
        Response::Error { .. }
    ));
    assert_eq!(overrides.committed_revision().await, revision);
    assert!(overrides
        .effective_interface("lan0")
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn dhcp_client_disable_persists_when_runtime_spec_is_absent() {
    let fixture = dhcp_client_control_fixture(true).await;
    fixture.supervisor.disable("wan0").await.unwrap();
    assert!(fixture.supervisor.spec("wan0").await.is_none());
    let response = fixture
        .service
        .dispatch(Request::DisableDhcpClient {
            interface: "wan0".into(),
        })
        .await;
    assert!(
        matches!(response, Response::DhcpClientDisabled { .. }),
        "{response:?}"
    );
    assert!(
        !fixture
            .overrides
            .effective_interface("wan0")
            .await
            .unwrap()
            .unwrap()
            .dhcp_client
            .unwrap()
            .enabled
    );
    let reloaded =
        crate::state::overrides::RuntimeOverrideStore::in_state_dir(fixture.directory.path())
            .load()
            .await
            .unwrap();
    assert!(
        !reloaded.interfaces["wan0"]
            .config
            .dhcp_client
            .as_ref()
            .unwrap()
            .enabled
    );
}

#[tokio::test]
async fn saved_dhcp_pool_is_readable_without_device_or_runtime_spec() {
    let directory = tempdir().unwrap();
    let mut base = router_base_config();
    base.runtime.state_dir = directory.path().into();
    let lan = base.network.interfaces.get_mut("lan0").unwrap();
    lan.ipv4 = Some("192.168.50.1/24".parse().unwrap());
    lan.dhcp = Some(dhcp_config());
    let overrides = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    let runtime_base = router_base_config();
    let dhcp = DhcpSupervisor::start(&runtime_base).await.unwrap();
    assert!(dhcp.spec("lan0").await.is_none());
    let service = ControlService::new(
        base,
        Arc::new(FakeNetwork {
            addresses: Vec::new(),
        }),
        dhcp,
        overrides,
    );
    match service
        .dispatch(Request::GetDhcpConfig {
            interface: "lan0".into(),
        })
        .await
    {
        Response::DhcpConfig {
            spec: Some(spec), ..
        } => {
            assert_eq!(spec.pool_start, dhcp_config().pool_start);
            assert_eq!(spec.pool_end, dhcp_config().pool_end);
        }
        response => panic!("{response:?}"),
    }
}

#[tokio::test]
async fn offline_intent_writers_reject_live_targets_and_serialize_stale_revisions() {
    let directory = tempdir().unwrap();
    let mut base = router_base_config();
    base.runtime.state_dir = directory.path().into();
    let overrides = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    network.add_interface("lan0", 7).await;
    let dhcp = DhcpSupervisor::start(&base).await.unwrap();
    let service = ControlService::new(base.clone(), network.clone(), dhcp, overrides.clone());
    let response = service
        .dispatch(Request::ForgetInterfaceConfig {
            interface: "lan0".into(),
            expected_revision: 0,
        })
        .await;
    assert!(matches!(response, Response::Error { .. }));
    assert_eq!(overrides.committed_revision().await, 0);
    network.interfaces.lock().await.clear();
    let forget = Request::ForgetInterfaceConfig {
        interface: "lan0".into(),
        expected_revision: 0,
    };
    let save = Request::SaveInterfaceConfig {
        interface: "lan0".into(),
        config: base.network.interfaces["lan0"].clone().into(),
        expected_revision: 0,
        allow_management_change: false,
    };
    let (first, second) = tokio::join!(service.dispatch(forget), service.dispatch(save));
    assert_eq!(
        [first, second]
            .iter()
            .filter(|response| matches!(response, Response::InterfaceIntentSaved { .. }))
            .count(),
        1
    );
    assert_eq!(overrides.committed_revision().await, 1);
}

#[tokio::test]
async fn offline_intent_respects_interface_recovery_fence() {
    let directory = tempdir().unwrap();
    let mut base = router_base_config();
    base.runtime.state_dir = directory.path().into();
    let overrides = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&base).await.unwrap();
    let service = ControlService::new(
        base,
        Arc::new(FakeNetwork {
            addresses: Vec::new(),
        }),
        dhcp,
        overrides.clone(),
    );
    crate::core::recovery::block_interface(
        directory.path(),
        "lan0",
        "retained transaction proof".into(),
    );
    let response = service
        .dispatch(Request::ForgetInterfaceConfig {
            interface: "lan0".into(),
            expected_revision: 0,
        })
        .await;
    crate::core::recovery::unblock_interface(directory.path(), "lan0");
    assert!(matches!(response, Response::Error { .. }), "{response:?}");
    assert_eq!(overrides.committed_revision().await, 0);
    assert!(overrides
        .effective_interface("lan0")
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn unused_vpn_profile_storage_remains_available_with_execution_disabled() {
    let (service, _directory) = vpn_enabled_service().await;
    service.overrides.set_vpn_enabled(false).await.unwrap();
    assert!(matches!(
        service
            .dispatch(Request::VpnImportProfile {
                name: "offline.conf".into(),
                contents: valid_vpn_profile_contents()
            })
            .await,
        Response::VpnProfileImported { .. }
    ));
    assert!(
        matches!(service.dispatch(Request::VpnListProfiles).await, Response::VpnProfiles { profiles } if profiles.len() == 1)
    );
    assert!(matches!(
        service
            .dispatch(Request::VpnDeleteProfile {
                name: "offline.conf".into()
            })
            .await,
        Response::VpnProfileDeleted { .. }
    ));
}

#[tokio::test]
async fn offline_save_cleans_retained_missing_dhcp_client_runtime() {
    let fixture = dhcp_client_control_fixture(true).await;
    let config = fixture
        .overrides
        .effective_interface("wan0")
        .await
        .unwrap()
        .unwrap();
    let revision = fixture.overrides.committed_revision().await;
    let response = fixture
        .service
        .dispatch(Request::SaveInterfaceConfig {
            interface: "wan0".into(),
            config: config.clone().into(),
            allow_management_change: false,
            expected_revision: revision,
        })
        .await;
    assert!(
        matches!(
            response,
            Response::InterfaceIntentSaved { deferred: true, .. }
        ),
        "{response:?}"
    );
    assert_eq!(fixture.overrides.committed_revision().await, revision + 1);
    assert_eq!(
        fixture.overrides.effective_interface("wan0").await.unwrap(),
        Some(config)
    );
    assert!(fixture.supervisor.spec("wan0").await.is_none());
}

async fn saved_wifi_without_runtime() -> (ControlService, tempfile::TempDir) {
    let directory = tempdir().unwrap();
    let mut base = wifi_base_config(directory.path());
    base.network
        .interfaces
        .get_mut("wlan0")
        .unwrap()
        .wifi
        .as_mut()
        .unwrap()
        .security = WifiSecurity::Wpa2;
    let store = crate::wifi::store::PassphraseStore::for_role(
        directory.path(),
        crate::wifi::store::WifiCredentialRole::Ap,
    );
    store
        .set("wlan0", &WifiPassphrase::new("previous-password").unwrap())
        .unwrap();
    base.network
        .interfaces
        .get_mut("wlan0")
        .unwrap()
        .wifi
        .as_mut()
        .unwrap()
        .passphrase_file = Some(store.directory().join("wlan0"));
    let overrides = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&base).await.unwrap();
    let service = ControlService::new(
        base,
        Arc::new(crate::test_support::FakeNetworkProvider::default()),
        dhcp,
        overrides,
    );
    (service, directory)
}

#[tokio::test]
async fn wifi_inventory_and_config_include_saved_missing_ap_without_runtime() {
    let (service, _directory) = saved_wifi_without_runtime().await;
    match service.dispatch(Request::ListWifiInventory).await {
        Response::WifiInventory { interfaces, .. } => {
            assert_eq!(interfaces.len(), 1);
            let row = &interfaces[0];
            assert_eq!(
                row.interface.presence,
                traffic_masq_protocol::InterfacePresence::Missing
            );
            assert!(row.interface.observed.is_none());
            assert!(row.ap_runtime.is_none());
            assert!(row.client_runtime.is_none());
            assert_eq!(
                row.interface
                    .configured
                    .as_ref()
                    .unwrap()
                    .wifi
                    .as_ref()
                    .unwrap()
                    .ssid,
                "net-a"
            );
        }
        response => panic!("{response:?}"),
    }
    assert!(matches!(
        service
            .dispatch(Request::GetWifiConfig {
                interface: "wlan0".into()
            })
            .await,
        Response::WifiConfig { spec: Some(_), .. }
    ));
}

#[tokio::test]
async fn missing_wifi_password_creates_new_durable_reference_and_preserves_old_secret() {
    let (service, directory) = saved_wifi_without_runtime().await;
    let old_config = service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap();
    let old_file = old_config
        .wifi
        .as_ref()
        .unwrap()
        .passphrase_file
        .clone()
        .unwrap();
    let response = service
        .dispatch(Request::WifiSetPassphrase {
            interface: "wlan0".into(),
            passphrase: "replacement-password".into(),
        })
        .await;
    assert!(
        matches!(
            response,
            Response::InterfaceIntentSaved { deferred: true, .. }
        ),
        "{response:?}"
    );
    let saved = service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap();
    let new_file = saved.wifi.unwrap().passphrase_file.unwrap();
    assert_ne!(old_file, new_file);
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&new_file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(new_file.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let wire = serde_json::to_string(&response).unwrap();
    assert!(!wire.contains("replacement-password"));
    assert!(!wire.contains("previous-password"));
    assert_eq!(
        std::fs::read_to_string(&old_file).unwrap(),
        "previous-password"
    );
    assert_eq!(
        std::fs::read_to_string(&new_file).unwrap(),
        "replacement-password"
    );
    let restarted = RuntimeOverrideManager::load(directory.path(), &service.base_config)
        .await
        .unwrap();
    assert_eq!(
        restarted
            .effective_interface("wlan0")
            .await
            .unwrap()
            .unwrap()
            .wifi
            .unwrap()
            .passphrase_file,
        Some(new_file)
    );
    let response = service
        .dispatch(Request::DisableWifi {
            interface: "wlan0".into(),
        })
        .await;
    assert!(
        matches!(response, Response::InterfaceIntentSaved { .. }),
        "{response:?}"
    );
    assert!(service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap()
        .wifi
        .is_none());
    assert!(old_file.exists());
}

#[tokio::test]
async fn offline_wifi_secret_commit_failure_keeps_previous_intent_and_credential() {
    let (service, _directory) = saved_wifi_without_runtime().await;
    let previous = service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap();
    let previous_file = previous
        .wifi
        .as_ref()
        .unwrap()
        .passphrase_file
        .as_ref()
        .unwrap();
    std::fs::create_dir(service.overrides.path()).unwrap();
    let response = service
        .dispatch(Request::SaveWifiInterface {
            interface: "wlan0".into(),
            config: previous.clone().into(),
            expected_revision: 0,
            passphrase: Some("replacement-password".into()),
        })
        .await;
    assert!(matches!(response, Response::Error { .. }), "{response:?}");
    assert_eq!(service.overrides.committed_revision().await, 0);
    assert_eq!(
        service
            .overrides
            .effective_interface("wlan0")
            .await
            .unwrap(),
        Some(previous.clone())
    );
    assert_eq!(
        std::fs::read_to_string(previous_file).unwrap(),
        "previous-password"
    );
}

#[tokio::test]
async fn stale_wifi_editor_cannot_restore_forgotten_configuration_or_change_its_secret() {
    let (service, _directory) = saved_wifi_without_runtime().await;
    let previous = service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap();
    let old_file = previous
        .wifi
        .as_ref()
        .unwrap()
        .passphrase_file
        .as_ref()
        .unwrap();
    let response = service
        .dispatch(Request::ForgetInterfaceConfig {
            interface: "wlan0".into(),
            expected_revision: 0,
        })
        .await;
    assert!(matches!(response, Response::InterfaceIntentSaved { .. }));
    let response = service
        .dispatch(Request::SaveWifiInterface {
            interface: "wlan0".into(),
            config: previous.clone().into(),
            expected_revision: 0,
            passphrase: Some("replacement-password".into()),
        })
        .await;
    assert!(matches!(response, Response::Error { .. }));
    assert!(service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        std::fs::read_to_string(old_file).unwrap(),
        "previous-password"
    );
}

#[tokio::test]
async fn saved_missing_client_password_and_disable_preserve_independent_dhcp_policy() {
    let directory = tempdir().unwrap();
    let mut base = wifi_base_config(directory.path());
    let cfg = base.network.interfaces.get_mut("wlan0").unwrap();
    cfg.role = InterfaceRole::Input;
    cfg.ipv4 = None;
    cfg.wifi = None;
    cfg.dhcp_client = Some(DhcpClientInterfaceConfig {
        enabled: true,
        wifi_owned: false,
        ..Default::default()
    });
    cfg.wifi_client = Some(WifiClientConfig {
        ssid: "saved-uplink".into(),
        country_code: None,
        security: WifiClientSecurity::Wpa2,
        passphrase_file: None,
    });
    let overrides = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&base).await.unwrap();
    let service = ControlService::new(
        base.clone(),
        Arc::new(crate::test_support::FakeNetworkProvider::default()),
        dhcp,
        overrides,
    );
    assert!(matches!(
        service
            .dispatch(Request::GetWifiClientConfig {
                interface: "wlan0".into()
            })
            .await,
        Response::WifiClientConfig { spec: Some(_), .. }
    ));
    let response = service
        .dispatch(Request::WifiClientSetPassphrase {
            interface: "wlan0".into(),
            passphrase: "client-password".into(),
        })
        .await;
    assert!(
        matches!(response, Response::InterfaceIntentSaved { .. }),
        "{response:?}"
    );
    let saved = service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap();
    let file = saved.wifi_client.unwrap().passphrase_file.unwrap();
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "client-password");
    let response = service
        .dispatch(Request::DisableWifiClient {
            interface: "wlan0".into(),
        })
        .await;
    assert!(
        matches!(response, Response::InterfaceIntentSaved { .. }),
        "{response:?}"
    );
    let saved = service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap();
    assert!(saved.wifi_client.is_none());
    assert!(saved.dhcp_client.unwrap().enabled);
    assert!(file.exists());
    let restarted = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    assert!(restarted
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap()
        .wifi_client
        .is_none());
}

#[tokio::test]
async fn unplugged_ap_disable_stops_owned_process_before_committing_intent() {
    let fixture = wifi_enabled_fixture().await;
    let runtime = fixture.service.wifi.as_ref().unwrap();
    let pid = runtime.status("wlan0").await.unwrap().pid;
    fixture.network.interfaces.lock().await.remove("wlan0");
    let response = fixture
        .service
        .dispatch(Request::DisableWifi {
            interface: "wlan0".into(),
        })
        .await;
    assert!(
        matches!(
            response,
            Response::InterfaceIntentSaved { deferred: true, .. }
        ),
        "{response:?}"
    );
    assert!(!fixture.process.is_alive(pid).await.unwrap());
    assert!(runtime.status("wlan0").await.is_none());
    assert!(fixture
        .service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap()
        .wifi
        .is_none());
    let restarted =
        RuntimeOverrideManager::load(fixture._directory.path(), &fixture.service.base_config)
            .await
            .unwrap();
    assert!(restarted
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap()
        .wifi
        .is_none());
    runtime.ensure_alive().await.unwrap();
    assert!(fixture.process.configs.lock().unwrap().is_empty());
}

#[tokio::test]
async fn stale_or_unknown_offline_edit_does_not_stop_retained_ap() {
    for unknown in [false, true] {
        let fixture = wifi_enabled_fixture().await;
        let runtime = fixture.service.wifi.as_ref().unwrap();
        let pid = runtime.status("wlan0").await.unwrap().pid;
        let mut config = fixture
            .service
            .overrides
            .effective_interface("wlan0")
            .await
            .unwrap()
            .unwrap();
        config.wifi = None;
        fixture.network.interfaces.lock().await.remove("wlan0");
        *fixture.network.fail_interface_observation.lock().await = unknown;
        let response = fixture
            .service
            .dispatch(Request::SaveWifiInterface {
                interface: "wlan0".into(),
                config: config.into(),
                expected_revision: if unknown { 0 } else { 7 },
                passphrase: None,
            })
            .await;
        assert!(matches!(response, Response::Error { .. }), "{response:?}");
        assert!(fixture.process.is_alive(pid).await.unwrap());
        assert!(runtime.status("wlan0").await.is_some());
        assert_eq!(fixture.service.overrides.committed_revision().await, 0);
    }
}

#[tokio::test]
async fn unplugged_ap_persistence_failure_keeps_previous_durable_intent_and_wakes_reconcile() {
    let fixture = wifi_enabled_fixture().await;
    let runtime = fixture.service.wifi.as_ref().unwrap();
    let pid = runtime.status("wlan0").await.unwrap().pid;
    let previous = fixture
        .service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap();
    fixture.network.interfaces.lock().await.remove("wlan0");
    std::fs::create_dir(fixture.service.overrides.path()).unwrap();
    let response = fixture
        .service
        .dispatch(Request::DisableWifi {
            interface: "wlan0".into(),
        })
        .await;
    assert!(matches!(response, Response::Error { .. }), "{response:?}");
    assert!(!fixture.process.is_alive(pid).await.unwrap());
    assert!(runtime.status("wlan0").await.is_none());
    assert_eq!(fixture.service.overrides.committed_revision().await, 0);
    assert_eq!(
        fixture
            .service
            .overrides
            .effective_interface("wlan0")
            .await
            .unwrap(),
        Some(previous.clone())
    );
    tokio::time::timeout(
        Duration::from_millis(100),
        fixture.service.overrides.changed(),
    )
    .await
    .unwrap();
    std::fs::remove_dir(fixture.service.overrides.path()).unwrap();
    let restarted =
        RuntimeOverrideManager::load(fixture._directory.path(), &fixture.service.base_config)
            .await
            .unwrap();
    assert_eq!(
        restarted.effective_interface("wlan0").await.unwrap(),
        Some(previous)
    );
}

#[tokio::test]
async fn unplugged_ap_changed_process_proof_blocks_cleanup_and_preserves_intent() {
    let fixture = wifi_enabled_fixture().await;
    let runtime = fixture.service.wifi.as_ref().unwrap();
    let pid = runtime.status("wlan0").await.unwrap().pid;
    fixture.network.interfaces.lock().await.remove("wlan0");
    // Model PID reuse / external replacement of the recorded process identity.
    fixture
        .process
        .configs
        .lock()
        .unwrap()
        .insert(pid, fixture._directory.path().join("foreign.conf"));
    let response = fixture
        .service
        .dispatch(Request::DisableWifi {
            interface: "wlan0".into(),
        })
        .await;
    assert!(matches!(response, Response::Error { .. }), "{response:?}");
    assert!(fixture.process.is_alive(pid).await.unwrap());
    assert!(runtime.status("wlan0").await.is_some());
    assert_eq!(fixture.service.overrides.committed_revision().await, 0);
    assert!(fixture
        .service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap()
        .wifi
        .is_some());
}

#[tokio::test]
async fn unplugged_client_disable_stops_supplicant_and_dhcp_before_commit() {
    let fixture = wifi_client_enabled_fixture().await;
    let runtime = fixture.service.wifi_client.as_ref().unwrap();
    let dhcp = fixture.service.dhcp_client.as_ref().unwrap();
    let pid = runtime.status("wlan1").await.unwrap().pid;
    fixture.network.missing.store(true, WifiOrdering::SeqCst);
    let response = fixture
        .service
        .dispatch(Request::DisableWifiClient {
            interface: "wlan1".into(),
        })
        .await;
    assert!(
        matches!(
            response,
            Response::InterfaceIntentSaved { deferred: true, .. }
        ),
        "{response:?}"
    );
    assert!(!fixture.process.is_alive(pid).await.unwrap());
    assert!(runtime.status("wlan1").await.is_none());
    assert!(dhcp.spec("wlan1").await.is_none());
    let config = fixture
        .service
        .overrides
        .effective_interface("wlan1")
        .await
        .unwrap()
        .unwrap();
    assert!(config.wifi_client.is_none());
    // The fixture's DHCP policy was configured independently of Wi-Fi.
    assert!(config.dhcp_client.unwrap().enabled);
    runtime.ensure_alive().await.unwrap();
    assert!(fixture.process.configs.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unplugged_ap_provisioning_commits_new_secret_after_runtime_cleanup() {
    let fixture = wifi_enabled_fixture().await;
    let runtime = fixture.service.wifi.as_ref().unwrap();
    let pid = runtime.status("wlan0").await.unwrap().pid;
    fixture.network.interfaces.lock().await.remove("wlan0");
    let mut config = fixture
        .service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap();
    let ap = config.wifi.as_mut().unwrap();
    ap.ssid = "new-offline-ap".into();
    ap.security = WifiSecurity::Wpa2;
    let response = fixture
        .service
        .dispatch(Request::SaveWifiInterface {
            interface: "wlan0".into(),
            config: config.into(),
            expected_revision: 0,
            passphrase: Some("offline-new-password".into()),
        })
        .await;
    assert!(
        matches!(
            response,
            Response::InterfaceIntentSaved { deferred: true, .. }
        ),
        "{response:?}"
    );
    assert!(!fixture.process.is_alive(pid).await.unwrap());
    assert!(runtime.status("wlan0").await.is_none());
    let config = fixture
        .service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap();
    let ap = config.wifi.unwrap();
    assert_eq!(ap.ssid, "new-offline-ap");
    assert_eq!(
        std::fs::read_to_string(ap.passphrase_file.unwrap()).unwrap(),
        "offline-new-password"
    );
}

#[tokio::test]
async fn unplugged_ap_orphaned_or_interrupted_ownership_cannot_be_forgotten() {
    for interrupted in [false, true] {
        let mut fixture = wifi_enabled_fixture().await;
        let pid = fixture
            .service
            .wifi
            .as_ref()
            .unwrap()
            .status("wlan0")
            .await
            .unwrap()
            .pid;
        fixture.network.interfaces.lock().await.remove("wlan0");
        if interrupted {
            let store = crate::wifi::record::WifiRecordStore::for_access_point(
                fixture._directory.path().join("wifi"),
                &fixture.service.config.wifi.runtime_dir,
                "wlan0",
            );
            store.mark_transition().await.unwrap();
        } else {
            // Reopen without task adoption: the durable process record remains.
            fixture.service.wifi = Some(WifiSupervisor::open_with_process_for_recovery(
                &fixture.service.config,
                fixture.process.clone(),
            ));
        }
        let response = fixture
            .service
            .dispatch(Request::ForgetInterfaceConfig {
                interface: "wlan0".into(),
                expected_revision: 0,
            })
            .await;
        assert!(matches!(response, Response::Error { .. }), "{response:?}");
        assert!(fixture.process.is_alive(pid).await.unwrap());
        assert_eq!(fixture.service.overrides.committed_revision().await, 0);
        assert!(fixture
            .service
            .overrides
            .effective_interface("wlan0")
            .await
            .unwrap()
            .is_some());
    }
}

#[tokio::test]
async fn unplugged_ap_cleanup_failure_retains_process_record_and_allows_verified_retry() {
    let fixture = wifi_enabled_fixture().await;
    let runtime = fixture.service.wifi.as_ref().unwrap();
    let pid = runtime.status("wlan0").await.unwrap().pid;
    fixture.network.interfaces.lock().await.remove("wlan0");
    fixture.process.fail_stop.store(true, WifiOrdering::SeqCst);
    let store = crate::wifi::record::WifiRecordStore::for_access_point(
        fixture._directory.path().join("wifi"),
        &fixture.service.config.wifi.runtime_dir,
        "wlan0",
    );
    let previous = store.load().await.unwrap().unwrap();
    let response = fixture
        .service
        .dispatch(Request::ForgetInterfaceConfig {
            interface: "wlan0".into(),
            expected_revision: 0,
        })
        .await;
    assert!(
        matches!(response, Response::Error { ref message } if message.contains("previous saved intent retained")),
        "{response:?}"
    );
    assert!(fixture.process.is_alive(pid).await.unwrap());
    assert_eq!(store.load().await.unwrap(), Some(previous));
    assert_eq!(fixture.service.overrides.committed_revision().await, 0);
    fixture.process.fail_stop.store(false, WifiOrdering::SeqCst);
    let response = fixture
        .service
        .dispatch(Request::ForgetInterfaceConfig {
            interface: "wlan0".into(),
            expected_revision: 0,
        })
        .await;
    assert!(
        matches!(response, Response::InterfaceIntentSaved { .. }),
        "{response:?}"
    );
    assert!(!fixture.process.is_alive(pid).await.unwrap());
    assert!(store.load().await.unwrap().is_none());
    assert!(fixture
        .service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn replug_during_cleanup_does_not_commit_offline_intent_or_touch_replacement() {
    let fixture = wifi_enabled_fixture().await;
    let network = fixture.network.clone();
    fixture.network.interfaces.lock().await.remove("wlan0");
    let mut replacement = fixture.service.network.list_interfaces().await.unwrap();
    assert!(replacement.is_empty());
    replacement.push(NetworkInterface {
        name: "wlan0".into(),
        index: 99,
        is_up: true,
        rx_bytes: 0,
        tx_bytes: 0,
        is_wireless: true,
    });
    *fixture.process.after_stop.lock().unwrap() = Some(Box::new(move || {
        network
            .interfaces
            .try_lock()
            .unwrap()
            .insert("wlan0".into(), replacement[0].clone());
    }));
    let response = fixture
        .service
        .dispatch(Request::ForgetInterfaceConfig {
            interface: "wlan0".into(),
            expected_revision: 0,
        })
        .await;
    assert!(
        matches!(response, Response::Error { ref message } if message.contains("observation changed")),
        "{response:?}"
    );
    assert_eq!(fixture.service.overrides.committed_revision().await, 0);
    assert!(fixture
        .service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .is_some());
    assert_eq!(fixture.network.interfaces.lock().await["wlan0"].index, 99);
    assert!(fixture.process.configs.lock().unwrap().is_empty());
}

#[tokio::test]
async fn partially_stopped_ap_cleanup_preserves_intent_until_storage_is_repaired() {
    let fixture = wifi_enabled_fixture().await;
    let runtime = fixture.service.wifi.as_ref().unwrap();
    let pid = runtime.status("wlan0").await.unwrap().pid;
    fixture.network.interfaces.lock().await.remove("wlan0");
    let config_path = fixture.process.configs.lock().unwrap()[&pid].clone();
    let bad_path = config_path.clone();
    *fixture.process.after_stop.lock().unwrap() = Some(Box::new(move || {
        std::fs::remove_file(&bad_path).unwrap();
        std::fs::create_dir(&bad_path).unwrap();
    }));
    let response = fixture
        .service
        .dispatch(Request::DisableWifi {
            interface: "wlan0".into(),
        })
        .await;
    assert!(matches!(response, Response::Error { .. }), "{response:?}");
    assert!(!fixture.process.is_alive(pid).await.unwrap());
    assert_eq!(fixture.service.overrides.committed_revision().await, 0);
    assert!(fixture
        .service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap()
        .wifi
        .is_some());
    std::fs::remove_dir(config_path).unwrap();
    let response = fixture
        .service
        .dispatch(Request::DisableWifi {
            interface: "wlan0".into(),
        })
        .await;
    assert!(
        matches!(response, Response::InterfaceIntentSaved { .. }),
        "{response:?}"
    );
    assert!(runtime.status("wlan0").await.is_none());
    assert!(fixture
        .service
        .overrides
        .effective_interface("wlan0")
        .await
        .unwrap()
        .unwrap()
        .wifi
        .is_none());
}

async fn offline_client_profile_fixture() -> (ControlService, tempfile::TempDir) {
    let directory = tempdir().unwrap();
    let mut base = wifi_client_base_config(directory.path());
    let config = base.network.interfaces.get_mut("wlan1").unwrap();
    config.ipv4 = Some("192.0.2.10/24".parse().unwrap());
    config.dhcp_client.as_mut().unwrap().enabled = false;
    let overrides = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&base).await.unwrap();
    let service = ControlService::new(
        base,
        Arc::new(crate::test_support::FakeNetworkProvider::default()),
        dhcp,
        overrides,
    );
    let response = service
        .dispatch(Request::CreateWifiClientProfile {
            profile: WifiClientProfileWriteRequest {
                id: "saved-uplink".into(),
                ssid: "Offline uplink".into(),
                country_code: Some("UA".into()),
                security: WifiClientSecurity::Wpa2,
                priority: 0,
                autoconnect: false,
                passphrase: Some("profile-original-password".into()),
                clear_passphrase: false,
            },
        })
        .await;
    assert!(
        matches!(response, Response::WifiClientProfile { .. }),
        "{response:?}"
    );
    (service, directory)
}

#[tokio::test]
async fn offline_client_profile_preserves_or_updates_ip_policy_without_execution() {
    use traffic_masq_protocol::{ProvisionWifiClientRequest, WifiClientIpPolicy};
    for policy in [
        WifiClientIpPolicy::Preserve,
        WifiClientIpPolicy::Dhcp,
        WifiClientIpPolicy::Static {
            cidr: "198.51.100.10/24".parse().unwrap(),
        },
    ] {
        let (service, directory) = offline_client_profile_fixture().await;
        let response = service
            .dispatch(Request::SaveWifiClientProfile {
                interface: "wlan1".into(),
                settings: ProvisionWifiClientRequest {
                    profile_id: "saved-uplink".into(),
                    ip_policy: policy.clone(),
                },
                expected_revision: 0,
            })
            .await;
        assert!(
            matches!(
                response,
                Response::InterfaceIntentSaved {
                    deferred: true,
                    revision: 1,
                    ..
                }
            ),
            "{response:?}"
        );
        let config = service
            .overrides
            .effective_interface("wlan1")
            .await
            .unwrap()
            .unwrap();
        match policy {
            WifiClientIpPolicy::Preserve => {
                assert_eq!(config.ipv4, Some("192.0.2.10/24".parse().unwrap()))
            }
            WifiClientIpPolicy::Dhcp => {
                assert!(config.ipv4.is_none());
                assert!(config.dhcp_client.as_ref().unwrap().enabled);
            }
            WifiClientIpPolicy::Static { cidr } => {
                assert_eq!(config.ipv4, Some(cidr));
                assert!(!config.dhcp_client.as_ref().unwrap().enabled);
            }
        }
        assert!(!config.dhcp_client.as_ref().unwrap().wifi_owned);
        let client = config.wifi_client.as_ref().unwrap();
        assert_eq!(client.ssid, "Offline uplink");
        assert_eq!(
            std::fs::read_to_string(client.passphrase_file.as_ref().unwrap()).unwrap(),
            "profile-original-password"
        );
        assert!(!serde_json::to_string(&response)
            .unwrap()
            .contains("profile-original-password"));
        let restarted = RuntimeOverrideManager::load(directory.path(), &service.base_config)
            .await
            .unwrap();
        assert_eq!(
            restarted.effective_interface("wlan1").await.unwrap(),
            Some(config)
        );
        match service.dispatch(Request::ListWifiInventory).await {
            Response::WifiInventory {
                ap_execution_available,
                client_execution_available,
                interfaces,
                ..
            } => {
                assert!(!ap_execution_available && !client_execution_available);
                assert!(
                    interfaces
                        .iter()
                        .any(|entry| entry.interface.name == "wlan1"
                            && entry.client_runtime.is_none())
                );
            }
            response => panic!("{response:?}"),
        }
    }
}

#[tokio::test]
async fn offline_profile_reference_is_immutable_and_stale_selection_cannot_replace_it() {
    use traffic_masq_protocol::{ProvisionWifiClientRequest, WifiClientIpPolicy};
    let (service, _directory) = offline_client_profile_fixture().await;
    let settings = ProvisionWifiClientRequest {
        profile_id: "saved-uplink".into(),
        ip_policy: WifiClientIpPolicy::Preserve,
    };
    assert!(matches!(
        service
            .dispatch(Request::SaveWifiClientProfile {
                interface: "wlan1".into(),
                settings: settings.clone(),
                expected_revision: 0,
            })
            .await,
        Response::InterfaceIntentSaved { .. }
    ));
    let previous = service
        .overrides
        .effective_interface("wlan1")
        .await
        .unwrap()
        .unwrap();
    let profile = WifiClientProfileWriteRequest {
        id: "saved-uplink".into(),
        ssid: "Updated profile".into(),
        country_code: Some("UA".into()),
        security: WifiClientSecurity::Wpa2,
        priority: 0,
        autoconnect: false,
        passphrase: Some("profile-updated-password".into()),
        clear_passphrase: false,
    };
    let response = service
        .dispatch(Request::UpdateWifiClientProfile {
            id: "saved-uplink".into(),
            profile: profile.clone(),
        })
        .await;
    assert!(
        matches!(response, Response::WifiClientProfile { .. }),
        "{response:?}"
    );
    assert_eq!(
        std::fs::read_to_string(
            previous
                .wifi_client
                .as_ref()
                .unwrap()
                .passphrase_file
                .as_ref()
                .unwrap()
        )
        .unwrap(),
        "profile-original-password"
    );
    let response = service
        .dispatch(Request::SaveWifiClientProfile {
            interface: "wlan1".into(),
            settings: settings.clone(),
            expected_revision: 0,
        })
        .await;
    assert!(matches!(response, Response::Error { .. }), "{response:?}");
    assert_eq!(
        service
            .overrides
            .effective_interface("wlan1")
            .await
            .unwrap(),
        Some(previous)
    );
    let response = service
        .dispatch(Request::DeleteWifiClientProfile {
            id: "saved-uplink".into(),
        })
        .await;
    assert!(
        matches!(response, Response::WifiClientProfileDeleted { .. }),
        "{response:?}"
    );
    let retained = service
        .overrides
        .effective_interface("wlan1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(retained.wifi_client.unwrap().passphrase_file.unwrap()).unwrap(),
        "profile-original-password"
    );
    assert!(matches!(
        service
            .dispatch(Request::ForgetInterfaceConfig {
                interface: "wlan1".into(),
                expected_revision: 1
            })
            .await,
        Response::InterfaceIntentSaved { .. }
    ));
    let response = service
        .dispatch(Request::SaveWifiClientProfile {
            interface: "wlan1".into(),
            settings,
            expected_revision: 2,
        })
        .await;
    assert!(matches!(response, Response::Error { .. }), "{response:?}");
    assert!(service
        .overrides
        .effective_interface("wlan1")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn offline_profile_save_rejects_present_target_before_stopping_supplicant() {
    let fixture = wifi_client_enabled_fixture().await;
    let runtime = fixture.service.wifi_client.as_ref().unwrap();
    let pid = runtime.status("wlan1").await.unwrap().pid;
    let response = fixture
        .service
        .dispatch(Request::SaveWifiClientProfile {
            interface: "wlan1".into(),
            settings: traffic_masq_protocol::ProvisionWifiClientRequest {
                profile_id: "nonexistent".into(),
                ip_policy: traffic_masq_protocol::WifiClientIpPolicy::Dhcp,
            },
            expected_revision: 0,
        })
        .await;
    assert!(
        matches!(response, Response::Error { ref message } if message.contains("present")),
        "{response:?}"
    );
    assert!(fixture.process.is_alive(pid).await.unwrap());
    assert_eq!(fixture.service.overrides.committed_revision().await, 0);
}

#[tokio::test]
async fn wifi_liveness_cannot_restart_a_task_removed_or_changed_by_newer_intent() {
    let ap = wifi_enabled_fixture().await;
    let client = wifi_client_enabled_fixture().await;
    ap.process.responders.lock().unwrap().clear();
    ap.process.configs.lock().unwrap().clear();
    client.process.responders.lock().unwrap().clear();
    client.process.configs.lock().unwrap().clear();
    for removed in [false, true] {
        let mut config = ap.service.base_config.clone();
        if removed {
            config.network.interfaces.get_mut("wlan0").unwrap().wifi = None;
        } else {
            config
                .network
                .interfaces
                .get_mut("wlan0")
                .unwrap()
                .wifi
                .as_mut()
                .unwrap()
                .ssid = "newer-ap".into();
        }
        assert!(!ap
            .service
            .wifi
            .as_ref()
            .unwrap()
            .ensure_alive_for_config(&config)
            .await
            .unwrap());
        assert!(ap.process.configs.lock().unwrap().is_empty());
        let mut config = client.service.base_config.clone();
        if removed {
            config
                .network
                .interfaces
                .get_mut("wlan1")
                .unwrap()
                .wifi_client = None;
        } else {
            config
                .network
                .interfaces
                .get_mut("wlan1")
                .unwrap()
                .wifi_client
                .as_mut()
                .unwrap()
                .ssid = "newer-client".into();
        }
        assert!(!client
            .service
            .wifi_client
            .as_ref()
            .unwrap()
            .ensure_alive_for_config(&config)
            .await
            .unwrap());
        assert!(client.process.configs.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn offline_client_disable_suspends_autoconnect_until_explicit_profile_save() {
    let (service, _directory) = offline_client_profile_fixture().await;
    let response = service
        .dispatch(Request::DisableWifiClient {
            interface: "wlan1".into(),
        })
        .await;
    assert!(
        matches!(response, Response::InterfaceIntentSaved { .. }),
        "{response:?}"
    );
    assert!(service
        .wifi_autoconnect
        .lock()
        .await
        .suspended
        .contains("wlan1"));
    let response = service
        .dispatch(Request::SaveWifiClientProfile {
            interface: "wlan1".into(),
            expected_revision: 1,
            settings: traffic_masq_protocol::ProvisionWifiClientRequest {
                profile_id: "saved-uplink".into(),
                ip_policy: traffic_masq_protocol::WifiClientIpPolicy::Dhcp,
            },
        })
        .await;
    assert!(
        matches!(response, Response::InterfaceIntentSaved { .. }),
        "{response:?}"
    );
    assert!(!service
        .wifi_autoconnect
        .lock()
        .await
        .suspended
        .contains("wlan1"));
}

#[tokio::test]
async fn router_intent_preview_with_missing_dependencies_is_observational() {
    use traffic_masq_protocol::{InterfaceReadiness, InterfaceReadinessBlocker};
    let (service, directory) = router_enabled_service().await;
    let revision = service.overrides.committed_revision().await;
    match service
        .dispatch(Request::RouterIntentPreview {
            proposal: router_proposal().into(),
        })
        .await
    {
        Response::RouterIntentPreview {
            revision: preview_revision,
            config,
            desired,
            device_readiness,
            blockers,
            execution_available,
        } => {
            assert_eq!(preview_revision, revision);
            assert!(config.is_active() && desired.enabled && execution_available);
            assert_eq!(device_readiness, InterfaceReadiness::WaitingDevice);
            assert_eq!(
                blockers,
                vec![
                    InterfaceReadinessBlocker::MissingInterface {
                        interface: "lan0".into()
                    },
                    InterfaceReadinessBlocker::MissingInterface {
                        interface: "wan0".into()
                    },
                ]
            );
            // Legacy sharing is derived without a device or a runtime plan.
            assert!(matches!(
                desired.dataplane,
                traffic_masq_protocol::RouterDataplaneTargetView::Enabled(_)
            ));
        }
        response => panic!("{response:?}"),
    }
    assert_eq!(service.overrides.committed_revision().await, revision);
    assert!(!service.effective_config().await.unwrap().router.is_active());
    assert!(matches!(
        service.dispatch(Request::RouterPendingTransaction).await,
        Response::RouterPendingTransaction { token: None, .. }
    ));
    assert!(!directory.path().join("router-transaction.json").exists());
}

#[tokio::test]
async fn router_intent_preview_without_execution_preserves_saved_routes() {
    let directory = tempdir().unwrap();
    let mut config = router_base_config();
    config.runtime.state_dir = directory.path().into();
    config
        .router
        .owned_routes
        .push(crate::config::OwnedIpv4RouteConfig {
            destination: "10.30.0.0/16".parse().unwrap(),
            gateway: None,
            output_interface: Some("lan0".into()),
            table: 254,
            metric: Some(50),
        });
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&config).await.unwrap();
    let service = ControlService::new(
        config,
        Arc::new(FakeNetwork { addresses: vec![] }),
        dhcp,
        overrides,
    );
    match service
        .dispatch(Request::RouterIntentPreview {
            proposal: Default::default(),
        })
        .await
    {
        Response::RouterIntentPreview {
            config,
            desired,
            execution_available,
            ..
        } => {
            assert!(!execution_available);
            assert!(config.is_active());
            assert_eq!(config.owned_routes.len(), 1);
            assert_eq!(
                config.owned_routes[0].output_interface.as_deref(),
                Some("lan0")
            );
            assert_eq!(desired.routes.len(), 1);
        }
        response => panic!("{response:?}"),
    }
}

#[tokio::test]
async fn router_intent_preview_distinguishes_unknown_and_ready_and_rejects_invalid_intent() {
    use traffic_masq_protocol::{InterfaceReadiness, InterfaceReadinessBlocker};
    let directory = tempdir().unwrap();
    let mut config = router_base_config();
    config.runtime.state_dir = directory.path().into();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&config).await.unwrap();
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    let service = ControlService::new(config, network.clone(), dhcp, overrides.clone());
    network.add_interface("lan0", 7).await;
    network.add_interface("wan0", 8).await;
    assert!(matches!(service.dispatch(Request::RouterIntentPreview {
        proposal: router_proposal().into(),
    }).await, Response::RouterIntentPreview {
        device_readiness: InterfaceReadiness::Ready, blockers, ..
    } if blockers.is_empty()));
    *network.fail_interface_observation.lock().await = true;
    assert!(matches!(service.dispatch(Request::RouterIntentPreview {
        proposal: router_proposal().into(),
    }).await, Response::RouterIntentPreview {
        device_readiness: InterfaceReadiness::Unknown, blockers, ..
    } if matches!(blockers.as_slice(), [InterfaceReadinessBlocker::ObservationFailed { .. }])));
    let mut invalid = router_proposal();
    invalid
        .set_router
        .as_mut()
        .unwrap()
        .uplink
        .as_mut()
        .unwrap()
        .interface = "not-configured".into();
    assert!(matches!(
        service
            .dispatch(Request::RouterIntentPreview {
                proposal: invalid.into()
            })
            .await,
        Response::RouterError { .. }
    ));
    assert_eq!(overrides.committed_revision().await, 0);
}

fn router_with_two_saved_sharing_rules() -> AppConfig {
    let mut config = router_base_config_with_router_enabled();
    config
        .router
        .owned_routes
        .push(crate::config::OwnedIpv4RouteConfig {
            destination: "203.0.113.0/24".parse().unwrap(),
            gateway: None,
            output_interface: Some("wan0".into()),
            table: 254,
            metric: Some(100),
        });
    config.router.forwarding = Some(vec![
        crate::config::ForwardingConfig {
            from: "lan0".into(),
            to: "wan0".into(),
            source_subnet: None,
            masquerade: true,
        },
        crate::config::ForwardingConfig {
            from: "absent_lan".into(),
            to: "absent_wan".into(),
            source_subnet: None,
            masquerade: true,
        },
    ]);
    config
}

#[tokio::test]
async fn saved_router_intent_removes_missing_rules_independently_and_survives_restart() {
    let fake = Arc::new(FakeRouterSubsystems::default());
    let base = router_with_two_saved_sharing_rules();
    let (service, directory) = router_service_with_config(fake.clone(), base.clone()).await;
    let original = service.current_router_desired().await.unwrap();
    let mut saved = base.router.clone();
    saved.owned_routes.clear();
    saved.forwarding.as_mut().unwrap().remove(0);
    let revision = match service
        .dispatch(Request::SaveRouterIntent {
            config: saved.clone().into(),
            expected_revision: 0,
        })
        .await
    {
        Response::RouterIntentSaved {
            revision,
            deferred,
            missing_dependencies,
            cleanup_blockers,
            ..
        } => {
            assert!(deferred);
            assert!(missing_dependencies.contains(&"absent_wan".into()));
            assert!(cleanup_blockers.is_empty());
            revision
        }
        response => panic!("{response:?}"),
    };
    assert_eq!(service.effective_config().await.unwrap().router, saved);
    assert!(service
        .router
        .as_ref()
        .unwrap()
        .cleanup_removed_dataplane(&original)
        .await
        .is_err());
    let restarted = RuntimeOverrideManager::load(directory.path(), &service.config)
        .await
        .unwrap();
    let snapshot = restarted.snapshot().await;
    assert_eq!(snapshot.router.as_ref(), Some(&saved));
    assert!(matches!(
        service
            .dispatch(Request::SaveRouterIntent {
                config: base.router.into(),
                expected_revision: 0,
            })
            .await,
        Response::RouterError {
            detail: RouterErrorDetail::StaleCandidate { .. }
        }
    ));
    assert_eq!(fake.cleanup_targets.lock().unwrap().len(), 1);
    saved.forwarding = Some(vec![]);
    assert!(matches!(
        service
            .dispatch(Request::SaveRouterIntent {
                config: saved.clone().into(),
                expected_revision: revision,
            })
            .await,
        Response::RouterIntentSaved { .. }
    ));
    assert_eq!(service.effective_config().await.unwrap().router, saved);
    assert_eq!(fake.cleanup_targets.lock().unwrap().len(), 2);
    assert!(!directory.path().join("router-transaction.json").exists());
}

#[tokio::test]
async fn saved_router_intent_reports_cleanup_failure_after_durable_commit() {
    let fake = Arc::new(FakeRouterSubsystems::default());
    *fake.cleanup_failure.lock().unwrap() = true;
    let base = router_with_two_saved_sharing_rules();
    let (service, _) = router_service_with_config(fake.clone(), base.clone()).await;
    let mut saved = base.router;
    saved.forwarding = Some(vec![]);
    assert!(matches!(service.dispatch(Request::SaveRouterIntent {
        config: saved.clone().into(), expected_revision: 0,
    }).await, Response::RouterIntentSaved { revision: 1, cleanup_blockers, .. }
        if cleanup_blockers.iter().any(|blocker| blocker.contains("injected cleanup failure"))));
    assert_eq!(service.effective_config().await.unwrap().router, saved);
    assert_eq!(
        service.router.as_ref().unwrap().status().await,
        CoordinatorStatus::Idle
    );
    *fake.cleanup_failure.lock().unwrap() = false;
    service
        .router
        .as_ref()
        .unwrap()
        .cleanup_removed_dataplane(&service.current_router_desired().await.unwrap())
        .await
        .unwrap();
    assert_eq!(service.overrides.committed_revision().await, 1);
}

#[tokio::test]
async fn saved_router_intent_blocks_unknown_live_and_non_router_changes() {
    let directory = tempdir().unwrap();
    let mut config = router_with_two_saved_sharing_rules();
    config.runtime.state_dir = directory.path().into();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&config).await.unwrap();
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    let fake = Arc::new(FakeRouterSubsystems::default());
    let coordinator = RouterTransactionCoordinator::new(
        crate::core::router::RouterManager::new(fake.clone()),
        overrides.clone(),
        Duration::from_secs(30),
    );
    let service = ControlService::new(config.clone(), network.clone(), dhcp, overrides.clone())
        .with_router_coordinator(coordinator);
    let mut saved = config.router.clone();
    saved.forwarding.as_mut().unwrap().pop();
    *network.fail_interface_observation.lock().await = true;
    assert!(matches!(
        service
            .dispatch(Request::SaveRouterIntent {
                config: saved.clone().into(),
                expected_revision: 0
            })
            .await,
        Response::RouterError { .. }
    ));
    *network.fail_interface_observation.lock().await = false;
    for (index, name) in ["lan0", "wan0", "absent_lan", "absent_wan"]
        .into_iter()
        .enumerate()
    {
        network.add_interface(name, index as u32 + 1).await;
    }
    assert!(matches!(
        service
            .dispatch(Request::SaveRouterIntent {
                config: saved.clone().into(),
                expected_revision: 0
            })
            .await,
        Response::RouterError { .. }
    ));
    saved.uplink = None;
    assert!(matches!(
        service
            .dispatch(Request::SaveRouterIntent {
                config: saved.into(),
                expected_revision: 0
            })
            .await,
        Response::RouterError { .. }
    ));
    assert_eq!(overrides.committed_revision().await, 0);
    assert!(fake.cleanup_targets.lock().unwrap().is_empty());
}

#[tokio::test]
async fn saved_router_intent_preserves_pending_transaction_and_supports_disabled_storage() {
    let fake = Arc::new(FakeRouterSubsystems::default());
    let base = router_with_two_saved_sharing_rules();
    let (service, _) = router_service_with_config(fake.clone(), base.clone()).await;
    let token = match service
        .dispatch(Request::RouterApply {
            proposal: Default::default(),
        })
        .await
    {
        Response::RouterTransactionPending { token, .. } => token,
        response => panic!("{response:?}"),
    };
    assert!(matches!(
        service
            .dispatch(Request::SaveRouterIntent {
                config: base.router.into(),
                expected_revision: 0
            })
            .await,
        Response::Error { .. }
    ));
    assert_eq!(service.overrides.committed_revision().await, 0);
    assert!(fake.cleanup_targets.lock().unwrap().is_empty());
    assert!(matches!(
        service.dispatch(Request::RouterRollback { token }).await,
        Response::RouterRolledBack
    ));

    let directory = tempdir().unwrap();
    let mut base = router_base_config();
    base.runtime.state_dir = directory.path().into();
    let overrides = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&base).await.unwrap();
    let service = ControlService::new(
        base,
        Arc::new(FakeNetwork { addresses: vec![] }),
        dhcp,
        overrides,
    );
    let saved = crate::config::RouterConfig {
        forwarding: Some(vec![]),
        ..Default::default()
    };
    assert!(
        matches!(service.dispatch(Request::SaveRouterIntent { config: saved.into(), expected_revision: 0 }).await,
        Response::RouterIntentSaved { execution_available: false, cleanup_blockers, .. } if !cleanup_blockers.is_empty())
    );
}

#[tokio::test]
async fn cancelled_router_cleanup_keeps_coordination_until_writes_settle() {
    let fake = Arc::new(FakeRouterSubsystems::default());
    let hold = Arc::new(tokio::sync::Notify::new());
    *fake.cleanup_hold.lock().unwrap() = Some(hold.clone());
    let (service, _) =
        router_service_with_config(fake.clone(), router_with_two_saved_sharing_rules()).await;
    let router = service.router.clone().unwrap();
    let desired = service.current_router_desired().await.unwrap();
    let caller = tokio::spawn({
        let router = router.clone();
        async move { router.cleanup_removed_dataplane(&desired).await }
    });
    fake.cleanup_started.notified().await;
    caller.abort();
    let _ = caller.await;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), router.status())
            .await
            .is_err()
    );
    hold.notify_one();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), router.status())
            .await
            .unwrap(),
        CoordinatorStatus::Idle
    );
    assert_eq!(service.overrides.committed_revision().await, 0);
}

#[tokio::test]
async fn uncertain_router_intent_commit_never_cleans_runtime_and_fences_later_saves() {
    let fake = Arc::new(FakeRouterSubsystems::default());
    let (service, _) =
        router_service_with_config(fake.clone(), router_with_two_saved_sharing_rules()).await;
    service
        .overrides
        .save_committed(service.overrides.snapshot().await)
        .await
        .unwrap();
    let revision = service.overrides.committed_revision().await;
    crate::atomic_file::fail_replacement_and_compensation(service.overrides.path());
    let mut saved = service.effective_config().await.unwrap().router;
    saved.forwarding = Some(vec![]);
    assert!(matches!(
        service
            .dispatch(Request::SaveRouterIntent {
                config: saved.clone().into(),
                expected_revision: revision
            })
            .await,
        Response::RouterError { .. }
    ));
    assert!(fake.cleanup_targets.lock().unwrap().is_empty());
    assert!(
        matches!(service.dispatch(Request::SaveRouterIntent { config: saved.into(), expected_revision: revision }).await,
        Response::Error { message } if message.contains("commit_indeterminate"))
    );
    assert!(fake.cleanup_targets.lock().unwrap().is_empty());
}

#[tokio::test]
async fn route_inventory_keeps_missing_saved_routes_and_does_not_adopt_foreign_routes() {
    use traffic_masq_protocol::InterfacePresence;
    let directory = tempdir().unwrap();
    let mut config = router_base_config();
    config.runtime.state_dir = directory.path().into();
    let saved = crate::config::OwnedIpv4RouteConfig {
        destination: "203.0.113.0/24".parse().unwrap(),
        gateway: None,
        output_interface: Some("wan0".into()),
        table: 254,
        metric: Some(100),
    };
    config.router.owned_routes = vec![saved.clone()];
    let observed = crate::netlink::Ipv4RouteInfo {
        destination: saved.destination,
        gateway: None,
        output_interface_index: Some(7),
        table: 254,
        metric: Some(100),
        protocol: 4,
        scope: 253,
    };
    let network = Arc::new(crate::test_support::FakeNetworkProvider::default());
    *network.routes.lock().await = vec![observed.clone()];
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&config).await.unwrap();
    let service = ControlService::new(config, network.clone(), dhcp, overrides);
    match service
        .dispatch(Request::ListRouteInventory {
            include_local_table: false,
        })
        .await
    {
        Response::RouteInventory {
            revision,
            config,
            routes,
            observation_error,
        } => {
            assert_eq!(revision, 0);
            assert!(config.is_active());
            assert_eq!(routes.len(), 2);
            assert!(routes[0].configured.is_some());
            assert!(routes[0].observed.is_none());
            assert_eq!(routes[0].output_presence, Some(InterfacePresence::Missing));
            assert!(routes[1].configured.is_none());
            assert_eq!(routes[1].observed.as_ref().unwrap().protocol, 4);
            assert!(observation_error.is_none());
        }
        response => panic!("{response:?}"),
    }
    network.add_interface("wan0", 7).await;
    *network.routes.lock().await = vec![crate::netlink::Ipv4RouteInfo {
        protocol: crate::netlink::TRAFFIC_MASQ_ROUTE_PROTOCOL,
        ..observed
    }];
    match service
        .dispatch(Request::ListRouteInventory {
            include_local_table: false,
        })
        .await
    {
        Response::RouteInventory { routes, .. } => {
            assert_eq!(routes.len(), 1);
            assert!(routes[0].configured.is_some() && routes[0].observed.is_some());
            assert_eq!(routes[0].output_presence, Some(InterfacePresence::Present));
        }
        response => panic!("{response:?}"),
    }
    *network.fail_interface_observation.lock().await = true;
    match service
        .dispatch(Request::ListRouteInventory {
            include_local_table: false,
        })
        .await
    {
        Response::RouteInventory {
            routes,
            observation_error,
            ..
        } => {
            assert_eq!(routes[0].output_presence, Some(InterfacePresence::Unknown));
            assert!(routes[0].observed.is_none());
            assert!(routes[1].configured.is_none());
            assert!(observation_error.is_some());
        }
        response => panic!("{response:?}"),
    }
}

#[tokio::test]
async fn route_inventory_reports_observation_failure_without_losing_saved_configuration() {
    let directory = tempdir().unwrap();
    let mut config = router_with_two_saved_sharing_rules();
    config.runtime.state_dir = directory.path().into();
    let overrides = RuntimeOverrideManager::load(directory.path(), &config)
        .await
        .unwrap();
    let dhcp = DhcpSupervisor::start(&config).await.unwrap();
    let service = ControlService::new(
        config.clone(),
        Arc::new(RouteFakeNetwork {
            interfaces: vec![],
            routes: vec![],
            route_error: Some("netlink unavailable"),
        }),
        dhcp,
        overrides,
    );
    match service
        .dispatch(Request::ListRouteInventory {
            include_local_table: false,
        })
        .await
    {
        Response::RouteInventory {
            config: saved,
            routes,
            observation_error,
            ..
        } => {
            assert_eq!(saved.owned_routes.len(), config.router.owned_routes.len());
            assert!(routes
                .iter()
                .all(|row| row.configured.is_some() && row.observed.is_none()));
            assert!(observation_error.unwrap().contains("netlink unavailable"));
        }
        response => panic!("{response:?}"),
    }
}

#[tokio::test]
async fn router_status_separates_saved_revision_from_historical_applied_revision() {
    let (service, _) = router_service_with_config(
        Arc::new(FakeRouterSubsystems::default()),
        router_with_two_saved_sharing_rules(),
    )
    .await;
    let router = service.router.as_ref().unwrap();
    assert!(router.last_applied_revision().is_none());
    router
        .repair(service.current_router_desired().await.unwrap())
        .await
        .unwrap();
    assert_eq!(router.last_applied_revision(), Some(0));
    let mut saved = service.effective_config().await.unwrap().router;
    saved.forwarding = Some(vec![]);
    assert!(matches!(
        service
            .dispatch(Request::SaveRouterIntent {
                config: saved.into(),
                expected_revision: 0
            })
            .await,
        Response::RouterIntentSaved { revision: 1, .. }
    ));
    assert!(matches!(
        service.dispatch(Request::RouterStatus).await,
        Response::RouterStatus {
            desired_revision: Some(1),
            last_applied_revision: Some(0),
            ..
        }
    ));
    let restarted = RouterTransactionCoordinator::new(
        router.manager(),
        service.overrides.clone(),
        Duration::from_secs(30),
    );
    assert!(restarted.last_applied_revision().is_none());
    restarted
        .reconcile_dataplane(service.current_router_desired().await.unwrap())
        .await
        .unwrap();
    assert_eq!(restarted.last_applied_revision(), Some(1));
}

#[tokio::test]
async fn vpn_source_import_copies_profile_without_exposing_keys_or_changing_source() {
    let (service, directory) = vpn_enabled_service().await;
    let source = directory.path().join("sources");
    std::fs::create_dir(&source).unwrap();
    let contents =
        valid_vpn_profile_contents().replace("203.0.113.1:51820", "wg010.njalla.no:51820");
    std::fs::write(source.join("wg0.conf"), &contents).unwrap();
    let response = service.dispatch(Request::VpnListSources).await;
    assert!(!serde_json::to_string(&response)
        .unwrap()
        .contains(VALID_VPN_PRIVATE_KEY));
    match response {
        Response::VpnSources {
            directory: path,
            profiles,
        } => {
            assert_eq!(path, source.display().to_string());
            assert_eq!(profiles.len(), 1);
            assert_eq!(profiles[0].name, "wg0.conf");
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        service
            .dispatch(Request::VpnImportFromSource {
                name: "wg0.conf".into()
            })
            .await,
        Response::VpnProfileImported { .. }
    ));
    assert_eq!(
        std::fs::read_to_string(source.join("wg0.conf")).unwrap(),
        contents
    );
    assert_eq!(
        std::fs::read_to_string(directory.path().join("wireguard/wg0.conf")).unwrap(),
        contents
    );
    assert!(matches!(
        service
            .dispatch(Request::VpnImportFromSource {
                name: "../wg0.conf".into()
            })
            .await,
        Response::Error { .. }
    ));
}

// Exercise both production timers through an accepted provisioning request.
// A transient router failure must not orphan the other half of the transaction.
#[tokio::test]
async fn regression_provisioning_secrets_follow_successful_automatic_router_retry() {
    let directory = tempdir().unwrap();
    let mut config = provisioning_base_config(directory.path());
    config.security.rollback_timeout_seconds = 1;
    let mut fixture = provisioning_fixture_with(
        Arc::new(FakeProvisioningSubsystems::default()),
        config,
        ProvisioningNetwork::with_wireless(&["wlan-up", "wlan-out"]),
        Duration::from_millis(200),
    )
    .await;
    fixture.service = fixture
        .service
        .with_router_coordinator(RouterTransactionCoordinator::new(
            RouterManager::new(fixture.subsystems.clone()),
            fixture.overrides.clone(),
            Duration::from_secs(1),
        ));
    *fixture.subsystems.rollback_unavailable.lock().unwrap() = true;
    let response = fixture
        .service
        .dispatch(apply_request(provisioning_request()))
        .await;
    assert!(
        matches!(response, Response::RouterProvisioningApplied { .. }),
        "{response:?}"
    );
    let router = fixture.service.router.as_ref().unwrap();
    // Wait for the failed attempt to complete; elapsed time alone does not
    // prove the timer's filesystem work has finished.
    tokio::time::timeout(Duration::from_secs(5), async {
        while router.status().await != CoordinatorStatus::RollbackFailed {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("automatic router rollback must encounter the injected failure");
    *fixture.subsystems.rollback_unavailable.lock().unwrap() = false;
    tokio::time::timeout(Duration::from_secs(5), async {
        while router.status().await != CoordinatorStatus::Idle {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("transient router failure must recover automatically");
    assert_eq!(fixture.overrides.committed_revision().await, 0);

    let restored = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let uplink = fixture
                .wifi_client
                .stored_passphrase("wlan-up")
                .await
                .unwrap();
            let output = fixture.wifi.stored_passphrase("wlan-out").await.unwrap();
            if uplink.is_none()
                && output.is_none()
                && !fixture
                    ._directory
                    .path()
                    .join("router-provisioning-secrets.json")
                    .exists()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(restored.is_ok(),
        "router recovered automatically, but uncommitted provisioning secrets/journal remain; ordinary network mutations stay blocked");
}
