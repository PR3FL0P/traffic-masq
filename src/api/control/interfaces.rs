use super::*;

impl ControlService {
    pub(super) async fn validate_default_route_management(
        &self,
        interface: &str,
        current: Option<&InterfaceConfig>,
        config: &InterfaceConfig,
        allow_management_change: bool,
    ) -> Result<()> {
        if allow_management_change
            || (!config.managed && !current.is_some_and(|current| current.managed))
        {
            return Ok(());
        }

        let Some(index) = self
            .network
            .list_interfaces()
            .await?
            .into_iter()
            .find(|candidate| candidate.name == interface)
            .map(|candidate| candidate.index)
        else {
            return Ok(());
        };
        let routes = self
            .network
            .list_ipv4_routes()
            .await
            .with_context(|| format!("failed to inspect IPv4 routes before changing {interface}"))?;
        let carries_default_route = routes
            .iter()
            .any(|route| {
                route.destination.prefix_len() == 0 && route.output_interface_index == Some(index)
            });
        if carries_default_route {
            anyhow::bail!(
                "interface {interface} carries the default route; set allow_management_change=true to confirm the connectivity risk"
            );
        }
        Ok(())
    }

    /// Unmanaging (or re-roling away from Output) an interface that currently
    /// carries a router-owned AP or DHCP server does not stop those services
    /// — they are only started/stopped by `RouterManager::apply`, which this
    /// edit path never triggers. Rather than silently leaving hostapd/dnsmasq
    /// running on an interface that just lost its IP, require the same
    /// explicit confirmation already used for the default-route and
    /// Management-role risks, and tell the operator where to actually finish
    /// the job (the Router tab), instead of "fixing" it with a second,
    /// independently-triggered mutation path into router state.
    pub(super) fn validate_router_service_management(
        interface: &str,
        current: Option<&InterfaceConfig>,
        new_config: &InterfaceConfig,
        allow_management_change: bool,
    ) -> Result<()> {
        if allow_management_change {
            return Ok(());
        }
        let Some(current) = current else {
            return Ok(());
        };
        if current.role != InterfaceRole::Output || !current.managed {
            return Ok(());
        }
        let losing_service = new_config.role != InterfaceRole::Output || !new_config.managed;
        if !losing_service {
            return Ok(());
        }
        if current.wifi.is_none() && current.dhcp.is_none() {
            return Ok(());
        }
        let mut running = Vec::new();
        if let Some(wifi) = &current.wifi {
            running.push(format!("access point '{}'", wifi.ssid));
        }
        if current.dhcp.is_some() {
            running.push("DHCP server".to_string());
        }
        anyhow::bail!(
            "{interface} still runs {} started by the router; set allow_management_change=true to confirm, then re-apply the router config to actually stop them",
            running.join(" and ")
        );
    }

    pub(super) async fn interface_config_response(&self, interface: String) -> Result<Response> {
        let snapshot = self.overrides.snapshot().await;
        let effective = snapshot.effective_config(&self.base_config)?;
        let config = effective.network.interfaces.get(&interface).cloned();
        let allow_management_change = snapshot
            .interfaces
            .get(&interface)
            .map(|value| value.allow_management_change)
            .unwrap_or(false);
        Ok(Response::InterfaceConfig {
            interface,
            config,
            allow_management_change,
        })
    }

    pub(super) async fn effective_config(&self) -> Result<AppConfig, String> {
        self.overrides
            .snapshot()
            .await
            .effective_config(&self.base_config)
            .map_err(|error| error.to_string())
    }
}

pub(super) fn interface_edit_request_to_config(
    edit: InterfaceEditRequest,
    existing: Option<&InterfaceConfig>,
) -> Result<(InterfaceConfig, bool)> {
    if !edit.managed && !edit.cidr.trim().is_empty() {
        anyhow::bail!("cannot change IP while the interface is unmanaged; enable Managed first");
    }
    // An empty CIDR is the removal request: the interface keeps its role and
    // stays managed, it just stops carrying an address. The DHCP server cannot
    // follow it there — it serves the subnet of that very address — so name the
    // conflict here rather than letting interface validation report a missing
    // address the operator deliberately removed.
    if edit.managed
        && edit.cidr.trim().is_empty()
        && existing.is_some_and(|config| config.dhcp.is_some())
    {
        anyhow::bail!(
            "cannot remove the IPv4 address while a DHCP server is configured on this interface; disable DHCP first"
        );
    }
    let ipv4 = if edit.cidr.trim().is_empty() {
        None
    } else {
        Some(edit.cidr.trim().parse()?)
    };
    let is_output = edit.role == InterfaceRole::Output;
    let is_input = edit.role == InterfaceRole::Input;

    let dhcp = if is_output && edit.managed {
        existing.and_then(|config| config.dhcp.clone())
    } else {
        None
    };
    let wifi = if is_output && edit.managed {
        existing.and_then(|config| config.wifi.clone())
    } else {
        None
    };
    let dhcp_client = if is_input && edit.managed && ipv4.is_none() {
        existing.and_then(|config| config.dhcp_client.clone())
    } else {
        None
    };
    let wifi_client = if is_input {
        existing
            .filter(|config| edit.managed || !config.managed)
            .and_then(|config| config.wifi_client.clone())
    } else {
        None
    };

    Ok((
        InterfaceConfig {
            role: edit.role,
            managed: edit.managed,
            ipv4,
            dhcp,
            dhcp_client,
            wifi,
            wifi_client,
            nat: existing.is_none_or(|config| config.nat),
        },
        edit.allow_management_change,
    ))
}

pub(super) async fn interface_statuses(
    network: &dyn NetworkProvider,
    transactions: &NetworkTransactionManager,
) -> Result<Vec<InterfaceStatus>> {
    let mut result = Vec::new();
    let routes = match network.list_ipv4_routes().await {
        Ok(routes) => routes,
        Err(error) => {
            tracing::warn!(%error, "failed to inspect IPv4 routes while listing interfaces");
            Vec::new()
        }
    };
    for interface in network.list_interfaces().await? {
        let ipv4_addresses = network.list_ipv4_addresses(&interface.name).await?;
        let has_default_route = routes.iter().any(|route| {
            route.destination.prefix_len() == 0
                && route.output_interface_index == Some(interface.index)
        });
        let mut owned = Vec::new();
        for address in &ipv4_addresses {
            if transactions.owns_address(&interface.name, address).await {
                owned.push(address.clone());
            }
        }
        result.push(InterfaceStatus {
            owned_ipv4_addresses: Some(owned),
            interface,
            ipv4_addresses,
            has_default_route,
        });
    }
    result.sort_by(|left, right| left.interface.name.cmp(&right.interface.name));
    Ok(result)
}
