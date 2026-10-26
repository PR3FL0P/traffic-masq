use super::*;

pub(super) fn default_dhcp_settings(
    cidr: ipnet::Ipv4Net,
    dns_servers: Vec<std::net::Ipv4Addr>,
) -> Result<DhcpEditRequest, String> {
    let (start, end) = crate::dhcp::defaults::suggest_pool(cidr)?;
    let router = cidr.addr();

    Ok(DhcpEditRequest {
        pool_start: start,
        pool_end: end,
        router,
        dns_servers,
        lease_seconds: None,
    })
}

impl ControlService {
    pub(super) async fn apply_dhcp_settings(
        &self,
        interface: String,
        settings: Option<DhcpInterfaceConfig>,
    ) -> Response {
        let _mutation = self.dhcp_mutations.lock().await;
        let previous = match self.overrides.effective_interface(&interface).await {
            Ok(Some(config)) => config,
            Ok(None) => {
                return super::runtime::error_response(anyhow::anyhow!(
                    "interface {interface} is not configured"
                ))
            }
            Err(error) => return super::runtime::error_response(error),
        };
        let mut next = previous.clone();
        if let Some(settings) = &settings {
            if let Err(error) = build_effective_dhcp_service(
                &interface,
                settings.clone(),
                &self.overrides,
                self.network.as_ref(),
                self.base_config.dhcp.default_lease_seconds,
            )
            .await
            {
                return super::runtime::error_response(error);
            }
        }
        next.dhcp = settings;
        self.transactions
            .apply(
                &interface,
                crate::core::transaction::InterfaceChange {
                    config: &next,
                    previous: Some(&previous),
                    current_role: Some(previous.role),
                    allow_management_change: true,
                    passphrase: crate::wifi::WifiPassphraseUpdate::Keep,
                },
            )
            .await
            .map(|change| Response::NetworkChangePending { change })
            .unwrap_or_else(super::runtime::error_response)
    }
}

pub(super) async fn build_effective_dhcp_service(
    interface: &str,
    dhcp: DhcpInterfaceConfig,
    overrides: &RuntimeOverrideManager,
    network_provider: &dyn NetworkProvider,
    default_lease_seconds: u32,
) -> Result<DhcpServiceSpec> {
    let mut interface_config = overrides
        .effective_interface(interface)
        .await?
        .ok_or_else(|| anyhow::anyhow!("interface {interface} is not configured"))?;
    if !interface_config.managed || interface_config.role != InterfaceRole::Output {
        anyhow::bail!("DHCP requires a managed output interface: {interface}");
    }
    let spec = build_dhcp_spec(
        interface,
        dhcp.clone(),
        network_provider,
        default_lease_seconds,
    )
    .await?;
    interface_config.ipv4 = Some(ipnet::Ipv4Net::new(spec.server_ip, spec.prefix_len)?);
    interface_config.dhcp = Some(dhcp);
    interface_config.validate(interface)?;
    Ok(spec)
}

pub(super) async fn build_dhcp_spec(
    interface: &str,
    dhcp: DhcpInterfaceConfig,
    network_provider: &dyn NetworkProvider,
    default_lease_seconds: u32,
) -> Result<DhcpServiceSpec> {
    let addresses = network_provider.list_ipv4_addresses(interface).await?;
    let network = select_dhcp_network(interface, &addresses, &dhcp)?;
    let interface_config = InterfaceConfig {
        wifi_concurrent: false,
        mac_address: None,
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some(network),
        dhcp: Some(dhcp.clone()),
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    };
    DhcpServiceSpec::from_interface_config(interface, &interface_config, default_lease_seconds)?
        .ok_or_else(|| anyhow::anyhow!("DHCP is not enabled by the interface configuration"))
}

pub(super) fn select_dhcp_network(
    interface: &str,
    addresses: &[Ipv4AddressInfo],
    dhcp: &DhcpInterfaceConfig,
) -> Result<ipnet::Ipv4Net> {
    let mut candidates = Vec::new();

    for address in addresses {
        let Ok(network) = ipnet::Ipv4Net::new(address.address, address.prefix_len) else {
            continue;
        };
        let candidate = InterfaceConfig {
            wifi_concurrent: false,
            mac_address: None,
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some(network),
            dhcp: Some(dhcp.clone()),
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        };
        if candidate.validate(interface).is_ok() {
            candidates.push(network);
        }
    }

    match candidates.as_slice() {
        [network] => Ok(*network),
        [] => anyhow::bail!(
            "interface {interface} has no IPv4 address with a subnet valid for DHCP pool {}-{} and router {}",
            dhcp.pool_start,
            dhcp.pool_end,
            dhcp.router
        ),
        _ => {
            let candidates = candidates
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "interface {interface} has multiple IPv4 addresses with subnets valid for DHCP pool {}-{} and router {}: {candidates}",
                dhcp.pool_start,
                dhcp.pool_end,
                dhcp.router
            )
        }
    }
}
