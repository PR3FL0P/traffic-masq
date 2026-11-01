use super::super::*;

pub(in crate::api::control::tests) struct FakeNetwork {
    pub(in crate::api::control::tests) addresses: Vec<Ipv4AddressInfo>,
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

pub(in crate::api::control::tests) fn address(address: [u8; 4], prefix_len: u8) -> Ipv4AddressInfo {
    Ipv4AddressInfo {
        interface_index: 1,
        address: Ipv4Addr::from(address),
        prefix_len,
        protocol: None,
    }
}

pub(in crate::api::control::tests) fn dhcp_config() -> DhcpInterfaceConfig {
    DhcpInterfaceConfig {
        pool_start: Ipv4Addr::new(192, 168, 50, 10),
        pool_end: Ipv4Addr::new(192, 168, 50, 100),
        router: Ipv4Addr::new(192, 168, 50, 1),
        dns_servers: Vec::new(),
        lease_seconds: None,
    }
}

pub(in crate::api::control::tests) fn wifi_ap_config_fixture(
    ssid: &str,
) -> crate::config::WifiApConfig {
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
