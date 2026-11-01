use super::super::*;

#[derive(Default)]
pub(in crate::api::control::tests) struct FakeProvisioningSubsystems {
    pub(in crate::api::control::tests) plan_unavailable: StdMutex<bool>,
    pub(in crate::api::control::tests) applied_uplink_wifi: StdMutex<Vec<WifiClientSpec>>,
    pub(in crate::api::control::tests) applied_output_wifi: StdMutex<Vec<WifiApSpec>>,
    pub(in crate::api::control::tests) uplink_dhcp_unready: StdMutex<bool>,
    pub(in crate::api::control::tests) unhealthy_dataplane: StdMutex<bool>,
    pub(in crate::api::control::tests) rollback_unavailable: StdMutex<bool>,
}

#[async_trait]
impl RouterSubsystems for FakeProvisioningSubsystems {
    async fn plan_for(&self, desired: &RouterDesired) -> Result<RouterSubsystemPlan> {
        anyhow::ensure!(
            !*self.plan_unavailable.lock().unwrap(),
            "injected planning failure"
        );
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
    ) -> Result<()> {
        Ok(())
    }
}

#[derive(Default)]
pub(in crate::api::control::tests) struct ProvisioningNetwork {
    pub(in crate::api::control::tests) interfaces: Vec<NetworkInterface>,
    pub(in crate::api::control::tests) addresses: StdHashMap<String, Vec<Ipv4AddressInfo>>,
}

impl ProvisioningNetwork {
    pub(in crate::api::control::tests) fn with_wireless(names: &[&str]) -> Self {
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

    pub(in crate::api::control::tests) fn with_address(
        mut self,
        interface: &str,
        address: [u8; 4],
        prefix_len: u8,
    ) -> Self {
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

pub(in crate::api::control::tests) struct ProvisioningFixture {
    pub(in crate::api::control::tests) service: ControlService,
    pub(in crate::api::control::tests) overrides: RuntimeOverrideManager,
    pub(in crate::api::control::tests) subsystems: Arc<FakeProvisioningSubsystems>,
    pub(in crate::api::control::tests) wifi: WifiSupervisor,
    pub(in crate::api::control::tests) wifi_client: ClientSupervisor,
    pub(in crate::api::control::tests) _directory: tempfile::TempDir,
}

pub(in crate::api::control::tests) fn provisioning_base_config(
    directory: &std::path::Path,
) -> AppConfig {
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

pub(in crate::api::control::tests) async fn provisioning_fixture_with(
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
    let service = ControlService::new_detached(
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

pub(in crate::api::control::tests) async fn provisioning_fixture() -> ProvisioningFixture {
    let directory = tempdir().expect("tempdir");
    provisioning_fixture_with(
        Arc::new(FakeProvisioningSubsystems::default()),
        provisioning_base_config(directory.path()),
        ProvisioningNetwork::with_wireless(&["wlan-up", "wlan-out"]),
        Duration::from_millis(200),
    )
    .await
}

pub(in crate::api::control::tests) fn provisioning_request() -> RouterProvisioningRequest {
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

pub(in crate::api::control::tests) fn preview_request(
    provisioning: RouterProvisioningRequest,
) -> Request {
    Request::RouterProvisioningPreview {
        request: RouterProvisioningPreviewRequest {
            provisioning,
            uplink_secret_pending: true,
            output_secret_pending: true,
        },
    }
}

pub(in crate::api::control::tests) fn apply_request(
    provisioning: RouterProvisioningRequest,
) -> Request {
    Request::RouterProvisioningApply {
        request: RouterProvisioningApplyRequest {
            provisioning,
            uplink_passphrase: Some("upstream-secret".to_string()),
            output_passphrase: Some("downstream-secret".to_string()),
        },
    }
}

pub(in crate::api::control::tests) fn preview_of(
    response: Response,
) -> RouterProvisioningPreviewView {
    match response {
        Response::RouterProvisioningPreview { preview } => preview,
        other => panic!("expected a preview, got {other:?}"),
    }
}

pub(in crate::api::control::tests) fn provisioning_detail(
    response: Response,
) -> RouterProvisioningErrorDetail {
    match response {
        Response::RouterProvisioningError { detail } => detail,
        other => panic!("expected a provisioning error, got {other:?}"),
    }
}
