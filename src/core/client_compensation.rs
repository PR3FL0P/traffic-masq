use crate::dhcp::client::{DhcpClientRunState, DhcpClientSpec, DhcpClientSupervisor};
use crate::wifi::{WifiClientSpec, WifiClientSupervisor, WifiPassphrase};
use anyhow::Result;

pub(crate) async fn configure_dhcp_client_checked(
    supervisor: &DhcpClientSupervisor,
    spec: DhcpClientSpec,
    link_ready: bool,
) -> Result<()> {
    let interface = spec.interface.clone();
    supervisor.configure_with_link_ready(spec, link_ready).await;
    let status = supervisor
        .status(&interface)
        .await
        .ok_or_else(|| anyhow::anyhow!("DHCP client disappeared after configuration"))?;
    if let DhcpClientRunState::Degraded { reason } = status.state {
        anyhow::bail!("DHCP client failed to start on {interface}: {reason}");
    }
    Ok(())
}

pub(crate) async fn restore_dhcp_client(
    supervisor: &DhcpClientSupervisor,
    interface: &str,
    previous: Option<DhcpClientSpec>,
    link_ready: bool,
) -> Result<()> {
    match previous {
        Some(spec) => configure_dhcp_client_checked(supervisor, spec, link_ready).await,
        None => {
            supervisor.disable(interface).await?;
            Ok(())
        }
    }
}

pub(crate) async fn restore_wifi_client_secret(
    supervisor: &WifiClientSupervisor,
    interface: &str,
    previous: Option<&WifiPassphrase>,
) -> Result<()> {
    match previous {
        Some(passphrase) => supervisor.set_passphrase(interface, passphrase).await?,
        None => supervisor.clear_passphrase(interface).await?,
    }
    Ok(())
}

pub(crate) async fn compensate_wifi_client(
    supervisor: &WifiClientSupervisor,
    interface: &str,
    previous_spec: Option<WifiClientSpec>,
    previous_secret: Option<WifiPassphrase>,
) -> Result<()> {
    let mut failures = Vec::new();
    if let Err(error) =
        restore_wifi_client_secret(supervisor, interface, previous_secret.as_ref()).await
    {
        failures.push(format!("secret restoration failed: {error:#}"));
    }
    let runtime = match previous_spec {
        Some(spec) => supervisor.configure(spec).await,
        None => supervisor.disable(interface).await.map(|_| ()),
    };
    if let Err(error) = runtime {
        failures.push(format!("supplicant restoration failed: {error:#}"));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(failures.join("; "))
    }
}
