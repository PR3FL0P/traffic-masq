use super::*;

pub(super) fn default_dhcp_settings(cidr: ipnet::Ipv4Net) -> Result<DhcpEditRequest, String> {
    let (start, end) = crate::dhcp::defaults::suggest_pool(cidr)?;
    let router = cidr.addr();

    Ok(DhcpEditRequest {
        pool_start: start,
        pool_end: end,
        router,
        dns_servers: Vec::new(),
        lease_seconds: None,
    })
}

pub(super) fn dhcp_edit_request_to_config(settings: DhcpEditRequest) -> DhcpInterfaceConfig {
    DhcpInterfaceConfig {
        pool_start: settings.pool_start,
        pool_end: settings.pool_end,
        router: settings.router,
        dns_servers: settings.dns_servers,
        lease_seconds: settings.lease_seconds,
    }
}

pub(super) async fn configure_dhcp_persisted(
    dhcp: &DhcpSupervisor,
    overrides: &RuntimeOverrideManager,
    spec: DhcpServiceSpec,
) -> Result<()> {
    let interface = spec.interface.clone();
    let previous = dhcp.spec(&interface).await;
    let mut interface_config = overrides
        .effective_interface(&interface)
        .await?
        .ok_or_else(|| anyhow::anyhow!("interface {interface} is not configured"))?;
    interface_config.dhcp = Some(DhcpInterfaceConfig {
        pool_start: spec.pool_start,
        pool_end: spec.pool_end,
        router: spec.router,
        dns_servers: spec.dns_servers.clone(),
        lease_seconds: Some(spec.lease_seconds),
    });
    dhcp.configure(spec).await?;

    if let Err(error) = overrides
        .set_interface(interface.clone(), interface_config, false)
        .await
    {
        if crate::atomic_file::is_indeterminate_write(&error) {
            return Err(error);
        }
        let restoration = match previous {
            Some(previous) => dhcp.configure(previous).await,
            None => dhcp.disable(&interface).await.map(|_| ()),
        };
        return match restoration {
            Ok(()) => Err(error).context("failed to persist DHCP override; runtime state was restored"),
            Err(rollback) => Err(error).context(format!(
                "failed to persist DHCP override; runtime restoration also failed: {rollback:#}; recovery required"
            )),
        };
    }

    Ok(())
}

pub(super) async fn disable_dhcp_persisted(
    dhcp: &DhcpSupervisor,
    overrides: &RuntimeOverrideManager,
    interface: &str,
) -> Result<()> {
    let previous = dhcp.spec(interface).await;
    let mut interface_config = overrides
        .effective_interface(interface)
        .await?
        .ok_or_else(|| anyhow::anyhow!("interface {interface} is not configured"))?;
    interface_config.dhcp = None;
    dhcp.disable(interface).await?;

    if let Err(error) = overrides
        .set_interface(interface.to_string(), interface_config, false)
        .await
    {
        if crate::atomic_file::is_indeterminate_write(&error) {
            return Err(error);
        }
        let restoration = match previous {
            Some(previous) => dhcp.configure(previous).await,
            None => Ok(()),
        };
        return match restoration {
            Ok(()) => Err(error)
                .context("failed to persist DHCP disable override; runtime state was restored"),
            Err(rollback) => Err(error).context(format!(
                "failed to persist DHCP disable override; runtime restoration also failed: {rollback:#}; recovery required"
            )),
        };
    }

    Ok(())
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
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some(network),
        dhcp: Some(dhcp.clone()),
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
        nat: true,
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
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some(network),
            dhcp: Some(dhcp.clone()),
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
            nat: true,
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
