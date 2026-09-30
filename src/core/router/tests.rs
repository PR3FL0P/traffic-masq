use std::net::Ipv4Addr;
use std::sync::Mutex;

use crate::config::{
    DhcpClientInterfaceConfig, DhcpInterfaceConfig, InterfaceConfig, RouterConfig, UplinkConfig,
    UplinkMode,
};
use crate::core::interface::DhcpChangeAction;
use crate::firewall::OwnedFirewallIntegrity;
use crate::netlink::{Ipv4RouteSpec, TRAFFIC_MASQ_ROUTE_PROTOCOL};

use super::*;

#[test]
fn vpn_chain_requires_enabled_vpn_runtime() {
    let mut config = enabled_config();
    config.router.vpn_chain = vec![crate::config::VpnHopConfig {
        profile_name: "home.conf".into(),
    }];
    assert!(RouterDesired::from_effective_config(&config)
        .unwrap_err()
        .to_string()
        .contains("Enable VPN"));
    config.vpn.enabled = true;
    assert_eq!(
        RouterDesired::from_effective_config(&config)
            .unwrap()
            .vpn_chain
            .len(),
        1
    );
}

fn enabled_config() -> AppConfig {
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
    for (name, address, pool_start, pool_end) in [
        ("lan0", "192.168.10.1/24", 100, 150),
        ("lan1", "192.168.20.1/24", 100, 150),
    ] {
        let ipv4: ipnet::Ipv4Net = address.parse().expect("IPv4 network");
        let octet = ipv4.addr().octets()[2];
        config.network.interfaces.insert(
            name.to_string(),
            InterfaceConfig {
                role: InterfaceRole::Output,
                managed: true,
                ipv4: Some(ipv4),
                dhcp: Some(DhcpInterfaceConfig {
                    pool_start: Ipv4Addr::new(192, 168, octet, pool_start),
                    pool_end: Ipv4Addr::new(192, 168, octet, pool_end),
                    router: ipv4.addr(),
                    dns_servers: Vec::new(),
                    lease_seconds: None,
                }),
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
                nat: true,
            },
        );
    }
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
    config
}

#[test]
fn explicit_connections_replace_legacy_nat_and_empty_does_not_restore_it() {
    let mut config = enabled_config();
    let connections = vec![crate::config::ForwardingConfig {
        source_subnet: None,
        from: "lan0".into(),
        to: "wg0".into(),
        masquerade: false,
    }];
    config.router.forwarding = Some(connections.clone());
    let desired = RouterDesired::from_effective_config(&config).unwrap();
    let RouterDataplaneTarget::Enabled(dataplane) = desired.dataplane else {
        panic!("enabled");
    };
    assert_eq!(dataplane.forwarding, Some(connections));
    assert!(dataplane.outputs.is_empty());
    assert!(dataplane.uplink.is_empty());
    assert_eq!(desired.dhcp.len(), 2);
    assert_eq!(desired.routes.len(), 1);
    config.router.forwarding = Some(vec![]);
    assert_eq!(
        RouterDesired::from_effective_config(&config)
            .unwrap()
            .dataplane,
        RouterDataplaneTarget::Disabled
    );
}

#[test]
fn builds_enabled_router_desired_from_one_effective_config() {
    let desired = RouterDesired::from_effective_config(&enabled_config()).expect("desired");
    assert!(desired.enabled);
    assert!(desired.uplink_wifi.is_none());
    assert!(desired.output_wifi.is_empty());
    assert_eq!(desired.dhcp.len(), 2);
    assert_eq!(desired.routes.len(), 1);
    assert!(!desired.allow_default_route_change);
    assert_eq!(
        desired.dataplane,
        RouterDataplaneTarget::Enabled(RouterDataplaneDesired {
            forwarding: None,
            uplink: "wan0".to_string(),
            outputs: vec![
                OutputNetwork {
                    interface: "lan0".to_string(),
                    subnet: "192.168.10.0/24".parse().expect("subnet"),
                },
                OutputNetwork {
                    interface: "lan1".to_string(),
                    subnet: "192.168.20.0/24".parse().expect("subnet"),
                },
            ],
        })
    );
}

#[test]
fn dhcp_uplink_desired_requires_the_exact_client_intent() {
    let mut config = enabled_config();
    let uplink = config.network.interfaces.get_mut("wan0").unwrap();
    uplink.managed = true;
    uplink.dhcp_client = Some(DhcpClientInterfaceConfig {
        route_metric: 321,
        request_dns: false,
        ..DhcpClientInterfaceConfig::default()
    });
    config.router.uplink.as_mut().unwrap().mode = UplinkMode::Dhcp;

    let desired = RouterDesired::from_effective_config(&config).expect("desired");
    let intent = desired.uplink_dhcp.expect("DHCP uplink intent");
    assert_eq!(intent.interface, "wan0");
    assert_eq!(intent.route_metric, 321);
    assert!(!intent.request_dns);
}

#[test]
fn switching_to_connections_preserves_existing_uplink_services() {
    let mut config = enabled_config();
    let uplink = config.network.interfaces.get_mut("wan0").unwrap();
    uplink.managed = true;
    uplink.dhcp_client = Some(DhcpClientInterfaceConfig::default());
    config.router.uplink.as_mut().unwrap().mode = UplinkMode::Dhcp;
    let before = RouterDesired::from_effective_config(&config).unwrap();
    config.router.forwarding = Some(vec![]);
    let after = RouterDesired::from_effective_config(&config).unwrap();
    assert_eq!(after.uplink_dhcp, before.uplink_dhcp);
    assert_eq!(after.uplink_wifi, before.uplink_wifi);
    assert_eq!(after.output_wifi, before.output_wifi);
    assert_eq!(after.dhcp, before.dhcp);
    assert_eq!(after.interfaces.len(), before.interfaces.len());
}

#[test]
fn disabled_router_does_not_claim_routes_or_dataplane() {
    let mut config = enabled_config();
    config.router.enabled = false;
    let desired = RouterDesired::from_effective_config(&config).expect("desired");
    assert!(!desired.enabled);
    assert!(desired.uplink_wifi.is_none());
    assert!(desired.output_wifi.is_empty());
    assert_eq!(desired.dhcp.len(), 2);
    assert!(desired.routes.is_empty());
    assert!(!desired.allow_default_route_change);
    assert_eq!(desired.dataplane, RouterDataplaneTarget::Disabled);
}

#[test]
fn enabled_router_without_uplink_claims_routes_with_disabled_dataplane() {
    let mut config = enabled_config();
    config.router.uplink = None;

    let desired = RouterDesired::from_effective_config(&config).expect("desired");

    assert!(desired.enabled);
    assert_eq!(desired.interfaces.len(), 2);
    assert_eq!(desired.routes.len(), 1);
    assert!(desired.uplink_wifi.is_none());
    assert!(desired.uplink_dhcp.is_none());
    assert_eq!(desired.dataplane, RouterDataplaneTarget::Disabled);
}

#[test]
fn dhcp_snapshot_serialization_excludes_dynamic_lease_state() {
    let snapshot = DhcpClientSnapshot {
        interface: "wan0".into(),
        spec: None,
        lease: None,
    };
    let encoded = serde_json::to_value(snapshot).expect("serialize snapshot");
    assert!(encoded.get("lease").is_none());
}

#[test]
fn legacy_dhcp_snapshot_lease_field_is_ignored() {
    let snapshot: DhcpClientSnapshot =
        serde_json::from_str(r#"{"interface":"wan0","spec":null,"lease":{"legacy":"ignored"}}"#)
            .expect("legacy snapshot");
    assert_eq!(snapshot.interface, "wan0");
    assert!(snapshot.spec.is_none());
    assert!(snapshot.lease.is_none());
}

struct FakeSubsystems {
    events: Mutex<Vec<String>>,
    fail: Mutex<Option<String>>,
    rollback_fail: Mutex<Option<String>>,
    default_route: bool,
    quiesce_dhcp: bool,
}

impl FakeSubsystems {
    fn new(fail: Option<&str>) -> Arc<Self> {
        Arc::new(Self {
            events: Mutex::new(Vec::new()),
            fail: Mutex::new(fail.map(str::to_string)),
            rollback_fail: Mutex::new(None),
            default_route: false,
            quiesce_dhcp: false,
        })
    }

    fn with_default_route() -> Arc<Self> {
        Arc::new(Self {
            events: Mutex::new(Vec::new()),
            fail: Mutex::new(None),
            rollback_fail: Mutex::new(None),
            default_route: true,
            quiesce_dhcp: false,
        })
    }

    fn with_quiesced_dhcp(fail: Option<&str>) -> Arc<Self> {
        Arc::new(Self {
            events: Mutex::new(Vec::new()),
            fail: Mutex::new(fail.map(str::to_string)),
            rollback_fail: Mutex::new(None),
            default_route: false,
            quiesce_dhcp: true,
        })
    }

    fn event(&self, event: &str) -> Result<()> {
        self.events.lock().unwrap().push(event.to_string());
        if self.fail.lock().unwrap().as_deref() == Some(event) {
            anyhow::bail!("injected {event} failure");
        }
        if event.starts_with("rollback_")
            && self.rollback_fail.lock().unwrap().as_deref() == Some(event)
        {
            anyhow::bail!("injected {event} failure");
        }
        Ok(())
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
}

fn dataplane_snapshot() -> RouterDataplaneSnapshot {
    RouterDataplaneSnapshot {
        ipv4_forwarding: false,
        owned: None,
        owned_firewall_integrity: OwnedFirewallIntegrity::Intact,
    }
}

fn plan() -> RouterPlan {
    let desired = RouterDesired::from_effective_config(&enabled_config()).unwrap();
    RouterPlan {
        desired: desired.clone(),
        interfaces: vec![InterfaceChangePlan {
            interface: "lan0".into(),
            delete_ipv4: Vec::new(),
            retag_ipv4: None,
            add_ipv4: None,
            set_link_up: false,
            management_change: false,
            dhcp_action: DhcpChangeAction::Unchanged,
            releasing_management: false,
        }],
        uplink_wifi: Vec::new(),
        output_wifi: Vec::new(),
        dhcp: Vec::new(),
        routes: RoutePlan {
            add: Vec::new(),
            delete: Vec::new(),
        },
        vpn_chain: VpnChainPlan::empty(),
        dataplane: RouterDataplanePlan {
            snapshot: dataplane_snapshot(),
            target: desired.dataplane,
            requires_apply: true,
        },
        risk: RouterRisk::default(),
    }
}

#[async_trait]
impl RouterSubsystems for FakeSubsystems {
    async fn plan_interfaces(&self, _: &RouterDesired) -> Result<Vec<InterfaceChangePlan>> {
        self.event("plan_interfaces")?;
        Ok(plan().interfaces)
    }
    async fn plan_uplink_wifi(&self, _: &RouterDesired) -> Result<Vec<WifiPlan<WifiClientSpec>>> {
        self.event("plan_uplink_wifi")?;
        Ok(Vec::new())
    }
    async fn plan_output_wifi(&self, _: &RouterDesired) -> Result<Vec<WifiPlan<WifiApSpec>>> {
        self.event("plan_output_wifi")?;
        Ok(Vec::new())
    }
    async fn plan_routes(&self, _: &RouterDesired) -> Result<RoutePlan> {
        self.event("plan_routes")?;
        let add = self.default_route.then(|| Ipv4RouteSpec {
            destination: "0.0.0.0/0".parse().unwrap(),
            gateway: None,
            output_interface_index: Some(1),
            table: 254,
            metric: None,
            protocol: TRAFFIC_MASQ_ROUTE_PROTOCOL,
        });
        Ok(RoutePlan {
            add: add.into_iter().collect(),
            delete: Vec::new(),
        })
    }
    async fn plan_dhcp(&self, _: &RouterDesired) -> Result<Vec<DhcpPlan>> {
        self.event("plan_dhcp")?;
        Ok(Vec::new())
    }
    async fn plan_dataplane(&self, desired: &RouterDesired) -> Result<RouterDataplanePlan> {
        self.event("plan_dataplane")?;
        Ok(RouterDataplanePlan {
            snapshot: dataplane_snapshot(),
            target: desired.dataplane.clone(),
            requires_apply: true,
        })
    }
    async fn snapshot_for(&self, _: &RouterDesired) -> Result<RouterSnapshot> {
        self.event("snapshot_for")?;
        Ok(RouterSnapshot {
            interfaces: Vec::new(),
            uplink_wifi: Vec::new(),
            uplink_dhcp: None,
            dhcp_clients: Vec::new(),
            output_wifi: Vec::new(),
            dhcp: Vec::new(),
            dhcp_absent_interfaces: Vec::new(),
            routes: RouteSnapshot::empty(),
            vpn_chain: VpnChainSnapshot::empty(),
            dataplane: dataplane_snapshot(),
        })
    }
    async fn quiesce_uplink_dhcp(&self, _: Option<&DhcpClientSpec>) -> Result<()> {
        if self.quiesce_dhcp {
            self.event("quiesce_uplink_dhcp")?;
        }
        Ok(())
    }
    async fn apply_interfaces(&self, _: &[InterfaceChangePlan]) -> Result<()> {
        self.event("apply_interfaces")
    }
    async fn apply_uplink_wifi(&self, _: &[WifiPlan<WifiClientSpec>]) -> Result<()> {
        self.event("apply_uplink_wifi")
    }
    async fn apply_uplink_dhcp_candidate(&self, _: Option<&DhcpClientSpec>) -> Result<bool> {
        Ok(self.quiesce_dhcp)
    }
    async fn apply_output_wifi(&self, _: &[WifiPlan<WifiApSpec>]) -> Result<()> {
        self.event("apply_output_wifi")
    }
    async fn apply_routes(&self, _: &RoutePlan) -> Result<()> {
        self.event("apply_routes")
    }
    async fn apply_dhcp(&self, _: &[DhcpPlan]) -> Result<()> {
        self.event("apply_dhcp")
    }
    async fn apply_dataplane(&self, _: &RouterDataplanePlan) -> Result<()> {
        self.event("apply_dataplane")
    }
    async fn rollback_candidate_uplink_dhcp(&self) -> Result<()> {
        if self.quiesce_dhcp {
            self.event("rollback_candidate_uplink_dhcp")
        } else {
            Ok(())
        }
    }
    async fn rollback_interfaces(&self, _: &[InterfaceSnapshot]) -> Result<()> {
        self.event("rollback_interfaces")
    }
    async fn rollback_dhcp_clients(
        &self,
        _: &[DhcpClientSnapshot],
        _: Option<&DhcpClientSpec>,
    ) -> Result<()> {
        if self.quiesce_dhcp {
            self.event("rollback_uplink_dhcp")
        } else {
            Ok(())
        }
    }
    async fn rollback_uplink_wifi(&self, _: &[WifiSnapshot<WifiClientSpec>]) -> Result<()> {
        self.event("rollback_uplink_wifi")
    }
    async fn rollback_output_wifi(&self, _: &[WifiSnapshot<WifiApSpec>]) -> Result<()> {
        self.event("rollback_output_wifi")
    }
    async fn rollback_routes(&self, _: &RouteSnapshot) -> Result<()> {
        self.event("rollback_routes")
    }
    async fn rollback_dhcp_scoped(&self, _: &[DhcpServiceSpec], _: &[String]) -> Result<()> {
        self.event("rollback_dhcp")
    }
    async fn rollback_dataplane(&self, _: &RouterDataplaneSnapshot) -> Result<()> {
        self.event("rollback_dataplane")
    }
    async fn health_interfaces(&self, _: &RouterDesired) -> Result<()> {
        self.event("health_interfaces")
    }
    async fn health_uplink_wifi(&self, _: &RouterDesired) -> Result<()> {
        self.event("health_uplink_wifi")
    }
    async fn health_output_wifi(&self, _: &RouterDesired) -> Result<()> {
        self.event("health_output_wifi")
    }
    async fn health_routes(&self, _: &RouterDesired) -> Result<()> {
        self.event("health_routes")
    }
    async fn health_dhcp(&self, _: &RouterDesired) -> Result<()> {
        self.event("health_dhcp")
    }
    async fn health_dataplane(&self, _: &RouterDesired) -> Result<()> {
        self.event("health_dataplane")
    }
}

#[tokio::test]
async fn access_point_stop_precedes_station_apply_and_is_compensated_on_failure() {
    let fake = FakeSubsystems::new(Some("apply_uplink_wifi"));
    let mut plan = plan();
    plan.output_wifi.push(WifiPlan::Stop {
        current: WifiApSpec {
            interface: "wlan0".into(),
            ssid: "old-ap".into(),
            country_code: None,
            band: crate::config::WifiBand::Ghz2,
            channel: 1,
            channel_width: crate::config::WifiChannelWidth::Ht20,
            security: crate::config::WifiSecurity::Open,
            hidden: false,
            client_isolation: false,
            max_stations: 32,
            passphrase_file: None,
        },
    });
    RouterManager::new(fake.clone())
        .apply(&plan)
        .await
        .unwrap_err();
    let events = fake.events();
    let position = |name: &str| events.iter().position(|event| event == name).unwrap();
    assert!(position("apply_output_wifi") < position("apply_uplink_wifi"));
    assert!(position("rollback_uplink_wifi") < position("rollback_output_wifi"));
}

#[tokio::test]
async fn snapshots_before_first_mutation_and_exact_success_order() {
    let fake = FakeSubsystems::new(None);
    RouterManager::new(fake.clone())
        .apply(&plan())
        .await
        .unwrap();
    assert_eq!(
        fake.events(),
        [
            "snapshot_for",
            "apply_interfaces",
            "apply_uplink_wifi",
            "apply_output_wifi",
            "apply_dhcp",
            "apply_routes",
            "apply_dataplane",
            "health_interfaces",
            "health_uplink_wifi",
            "health_output_wifi",
            "health_dhcp",
            "health_routes",
            "health_dataplane",
        ]
    );
}

#[tokio::test]
async fn dhcp_is_quiesced_before_interface_mutation_and_restored_after_interface_rollback() {
    let fake = FakeSubsystems::with_quiesced_dhcp(Some("apply_interfaces"));
    RouterManager::new(fake.clone())
        .apply(&plan())
        .await
        .unwrap_err();

    let events = fake.events();
    let quiesce = events
        .iter()
        .position(|event| event == "quiesce_uplink_dhcp")
        .expect("DHCP quiesce");
    let apply = events
        .iter()
        .position(|event| event == "apply_interfaces")
        .expect("interface apply");
    let rollback_interface = events
        .iter()
        .position(|event| event == "rollback_interfaces")
        .expect("interface rollback");
    let rollback_dhcp = events
        .iter()
        .position(|event| event == "rollback_uplink_dhcp")
        .expect("DHCP rollback");

    assert!(quiesce < apply);
    assert!(rollback_interface < rollback_dhcp);
}

#[tokio::test]
async fn candidate_dhcp_is_stopped_before_interfaces_and_previous_dhcp_restored_afterwards() {
    let fake = FakeSubsystems::with_quiesced_dhcp(Some("apply_output_wifi"));
    RouterManager::new(fake.clone())
        .apply(&plan())
        .await
        .unwrap_err();

    let events = fake.events();
    let candidate = events
        .iter()
        .position(|event| event == "rollback_candidate_uplink_dhcp")
        .expect("candidate DHCP rollback");
    let interface = events
        .iter()
        .position(|event| event == "rollback_interfaces")
        .expect("interface rollback");
    let previous = events
        .iter()
        .position(|event| event == "rollback_uplink_dhcp")
        .expect("previous DHCP restoration");

    assert!(candidate < interface);
    assert!(interface < previous);
}

#[tokio::test]
async fn every_stage_and_health_failure_rolls_back_started_stages_in_reverse() {
    let full_reverse = vec![
        "rollback_dataplane",
        "rollback_routes",
        "rollback_dhcp",
        "rollback_output_wifi",
        "rollback_uplink_wifi",
        "rollback_interfaces",
    ];
    for (failure, rollbacks) in [
        ("apply_interfaces", vec!["rollback_interfaces"]),
        (
            "apply_uplink_wifi",
            vec!["rollback_uplink_wifi", "rollback_interfaces"],
        ),
        (
            "apply_output_wifi",
            vec![
                "rollback_output_wifi",
                "rollback_uplink_wifi",
                "rollback_interfaces",
            ],
        ),
        (
            "apply_dhcp",
            vec![
                "rollback_dhcp",
                "rollback_output_wifi",
                "rollback_uplink_wifi",
                "rollback_interfaces",
            ],
        ),
        (
            "apply_routes",
            vec![
                "rollback_routes",
                "rollback_dhcp",
                "rollback_output_wifi",
                "rollback_uplink_wifi",
                "rollback_interfaces",
            ],
        ),
        ("apply_dataplane", full_reverse.clone()),
        ("health_interfaces", full_reverse.clone()),
        ("health_uplink_wifi", full_reverse.clone()),
        ("health_output_wifi", full_reverse.clone()),
        ("health_dhcp", full_reverse.clone()),
        ("health_routes", full_reverse.clone()),
        ("health_dataplane", full_reverse.clone()),
    ] {
        let fake = FakeSubsystems::new(Some(failure));
        RouterManager::new(fake.clone())
            .apply(&plan())
            .await
            .unwrap_err();
        let actual: Vec<_> = fake
            .events()
            .into_iter()
            .filter(|event| event.starts_with("rollback_"))
            .collect();
        assert_eq!(actual, rollbacks, "failure at {failure}");
    }
}

#[tokio::test]
async fn rollback_continues_and_error_preserves_original_and_rollback_failure() {
    let fake = FakeSubsystems::new(Some("health_interfaces"));
    *fake.rollback_fail.lock().unwrap() = Some("rollback_dhcp".into());
    let error = RouterManager::new(fake.clone())
        .apply(&plan())
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("injected health_interfaces failure"));
    assert!(error.contains("injected rollback_dhcp failure"));
    assert!(fake.events().ends_with(&[
        "rollback_dataplane".into(),
        "rollback_routes".into(),
        "rollback_dhcp".into(),
        "rollback_output_wifi".into(),
        "rollback_uplink_wifi".into(),
        "rollback_interfaces".into(),
    ]));
}

#[tokio::test]
async fn plan_aggregates_default_route_risk() {
    let fake = FakeSubsystems::with_default_route();
    let desired = RouterDesired::from_effective_config(&enabled_config()).unwrap();
    let router_plan = RouterManager::new(fake).plan(desired).await.unwrap();
    assert!(router_plan.risk.changes_default_route);
    assert!(!router_plan.risk.requires_management_confirmation);
}

#[tokio::test]
async fn health_reports_only_the_failing_subsystem() {
    let desired = RouterDesired::from_effective_config(&enabled_config()).unwrap();

    for failing in [
        "health_interfaces",
        "health_routes",
        "health_dhcp",
        "health_dataplane",
    ] {
        let fake = FakeSubsystems::new(Some(failing));
        let report = RouterManager::new(fake).health(&desired).await;
        assert!(!report.ready(), "failing {failing}");

        let fields = [
            ("health_interfaces", &report.interfaces),
            ("health_routes", &report.routes),
            ("health_dhcp", &report.dhcp),
            ("health_dataplane", &report.dataplane),
        ];
        for (event, value) in fields {
            if event == failing {
                assert!(value.is_some(), "expected {event} to be unhealthy");
            } else {
                assert!(value.is_none(), "expected {event} to stay healthy");
            }
        }
    }
}

#[tokio::test]
async fn health_is_ready_when_every_subsystem_succeeds() {
    let desired = RouterDesired::from_effective_config(&enabled_config()).unwrap();
    let fake = FakeSubsystems::new(None);
    let report = RouterManager::new(fake).health(&desired).await;
    assert!(report.ready());
    assert!(report.interfaces.is_none());
    assert!(report.routes.is_none());
    assert!(report.dhcp.is_none());
    assert!(report.dataplane.is_none());
}
