use super::super::*;

pub(in crate::api::control::tests) struct RouteFakeNetwork {
    pub(in crate::api::control::tests) interfaces: Vec<NetworkInterface>,
    pub(in crate::api::control::tests) routes: Vec<crate::netlink::Ipv4RouteInfo>,
    pub(in crate::api::control::tests) route_error: Option<&'static str>,
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

pub(in crate::api::control::tests) async fn route_guard_service(
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
        ControlService::new_detached(config, network, dhcp, overrides),
        directory,
    )
}
