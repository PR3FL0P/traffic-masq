//! Internal autoconnect activation. The caller holds network admission/execution
//! and the client mutation lock; operator activation uses commit-confirm instead.
use crate::config::{InterfaceConfig, NetworkConfig};
use crate::core::client_compensation::*;
use crate::core::override_manager::RuntimeOverrideManager;
use crate::dhcp::client::{DhcpClientSpec, DhcpClientSupervisor};
use crate::netlink::NetworkProvider;
use crate::wifi::{WifiClientSpec, WifiClientSupervisor, WifiPassphrase};
use anyhow::Context;

pub(crate) enum ActivationError {
    Invalid(String),
    Activation(String),
    Persistence(anyhow::Error),
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn activate(
    wifi: &WifiClientSupervisor,
    dhcp: Option<&DhcpClientSupervisor>,
    overrides: &RuntimeOverrideManager,
    network: &dyn NetworkProvider,
    effective: &NetworkConfig,
    interface: &str,
    target: InterfaceConfig,
    auto_dhcp: bool,
    secret: Option<WifiPassphrase>,
) -> Result<(), ActivationError> {
    let spec = WifiClientSpec::from_interface_config(interface, &target)
        .map_err(|e| ActivationError::Invalid(e.to_string()))?
        .ok_or_else(|| {
            ActivationError::Invalid(format!(
                "profile activation requires a managed input interface on '{interface}'"
            ))
        })?;
    crate::wifi::policy::WifiRadioPolicy::validate_transition(
        effective,
        interface,
        &target,
        |name| network.wireless_phy(name),
    )
    .map_err(|e| ActivationError::Invalid(e.to_string()))?;
    let status = wifi.status(interface).await;
    let link_ready = status.as_ref().is_none_or(|s| s.wpa_state.is_connected());
    let previous_spec = status.map(|s| s.spec);
    let previous_secret = wifi
        .stored_passphrase(interface)
        .await
        .map_err(|e| ActivationError::Activation(e.to_string()))?;
    let mut wifi_changed = false;
    let mut dhcp_changed = false;
    let mut previous_dhcp = None;
    let mut persisting = false;
    let result: anyhow::Result<()> = async {
        match secret.as_ref() {
            Some(secret) => wifi.set_passphrase(interface, secret).await?,
            None => wifi.clear_passphrase(interface).await?,
        }
        // A failed configure can partially change runtime state.
        wifi_changed = true;
        wifi.configure(spec).await?;
        if auto_dhcp {
            let dhcp = dhcp.expect("DHCP client availability checked by target construction");
            let spec = DhcpClientSpec::from_interface_config(interface, &target)?.context(
                "profile activation could not derive the required DHCP client specification",
            )?;
            previous_dhcp = dhcp.spec(interface).await;
            dhcp_changed = true;
            configure_dhcp_client_checked(dhcp, spec, false)
                .await
                .context("failed to configure DHCP client for activated profile")?;
        }
        persisting = true;
        overrides
            .set_interface(interface.to_owned(), target, false)
            .await?;
        Ok(())
    }
    .await;
    let Err(error) = result else {
        return Ok(());
    };
    // The on-disk outcome is unknown: preserve runtime and the recovery fence.
    if persisting && crate::atomic_file::is_indeterminate_write(&error) {
        return Err(ActivationError::Persistence(error));
    }
    let mut failures = Vec::new();
    let restored = if wifi_changed {
        compensate_wifi_client(wifi, interface, previous_spec, previous_secret).await
    } else {
        restore_wifi_client_secret(wifi, interface, previous_secret.as_ref()).await
    };
    if let Err(error) = restored {
        failures.push(format!("Wi-Fi client: {error:#}"));
    }
    if dhcp_changed {
        if let Err(error) = restore_dhcp_client(
            dhcp.expect("DHCP was changed"),
            interface,
            previous_dhcp,
            link_ready,
        )
        .await
        {
            failures.push(format!("DHCP client: {error:#}"));
        }
    }
    let message = if failures.is_empty() {
        format!("{error:#}; prior state was restored")
    } else {
        format!(
            "{error:#}; rollback was incomplete: {}; recovery required",
            failures.join("; ")
        )
    };
    Err(if persisting {
        ActivationError::Persistence(anyhow::anyhow!(message))
    } else {
        ActivationError::Activation(message)
    })
}
