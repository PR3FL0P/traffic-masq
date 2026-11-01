use super::super::*;

#[derive(Default)]
pub(in crate::api::control::tests) struct FakeRouterSubsystems {
    pub(in crate::api::control::tests) cleanup_targets: std::sync::Mutex<Vec<RouterDesired>>,
    pub(in crate::api::control::tests) cleanup_started: tokio::sync::Notify,
    pub(in crate::api::control::tests) cleanup_hold:
        std::sync::Mutex<Option<Arc<tokio::sync::Notify>>>,
    pub(in crate::api::control::tests) cleanup_failure: std::sync::Mutex<bool>,
    pub(in crate::api::control::tests) health_pending: std::sync::atomic::AtomicBool,
    pub(in crate::api::control::tests) unhealthy_interfaces: std::sync::Mutex<bool>,
    pub(in crate::api::control::tests) unhealthy_routes: std::sync::Mutex<bool>,
    pub(in crate::api::control::tests) unhealthy_dhcp: std::sync::Mutex<bool>,
    pub(in crate::api::control::tests) unhealthy_dataplane: std::sync::Mutex<bool>,
}

impl FakeRouterSubsystems {
    pub(in crate::api::control::tests) fn fail_health(&self, subsystem: &str) {
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

pub(in crate::api::control::tests) fn fake_dataplane_snapshot() -> RouterDataplaneSnapshot {
    RouterDataplaneSnapshot {
        ipv4_forwarding: true,
        owned: None,
        owned_firewall_integrity: OwnedFirewallIntegrity::Intact,
    }
}

pub(in crate::api::control::tests) fn fake_router_snapshot() -> RouterSnapshot {
    RouterSnapshot {
        interfaces: Vec::new(),
        uplink_wifi: Vec::new(),
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
        if self
            .health_pending
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            std::future::pending::<()>().await;
        }
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
    ) -> Result<()> {
        anyhow::ensure!(
            snapshots.is_empty(),
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

pub(in crate::api::control::tests) fn router_base_config() -> AppConfig {
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
            ipv4: Some("192.168.10.1/24".parse().unwrap()),
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        },
    );
    config
}

pub(in crate::api::control::tests) fn router_proposal() -> RouterProposalRequest {
    RouterProposalRequest {
        expected_revision: None,
        expected_fingerprint: None,
        set_router: Some(RouterConfig {
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
            owned_routes: Vec::new(),
            allow_default_route_change: false,
            route_host_traffic: false,
        }),
        clear_router: false,
        set_interfaces: Default::default(),
        remove_interfaces: Vec::new(),
    }
}

pub(in crate::api::control::tests) async fn router_enabled_service(
) -> (ControlService, tempfile::TempDir) {
    router_enabled_service_with(Arc::new(FakeRouterSubsystems::default())).await
}

pub(in crate::api::control::tests) async fn router_enabled_service_with(
    fake: Arc<FakeRouterSubsystems>,
) -> (ControlService, tempfile::TempDir) {
    router_service_with_config(fake, router_base_config()).await
}

pub(in crate::api::control::tests) fn router_base_config_with_router_enabled() -> AppConfig {
    let mut config = router_base_config();
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
        owned_routes: Vec::new(),
        allow_default_route_change: false,
        route_host_traffic: false,
    };
    config
}

pub(in crate::api::control::tests) async fn router_service_with_config(
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
    let service = ControlService::new_detached(config, network, dhcp, overrides)
        .with_router_coordinator(coordinator);
    (service, directory)
}

pub(in crate::api::control::tests) fn router_with_two_saved_sharing_rules() -> AppConfig {
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
