pub mod ctrl;
pub mod profile;
pub mod render;
pub mod supervisor;

pub use ctrl::{
    WpaState, WpaSupplicantCtrlClient, WpaSupplicantEvent, WpaSupplicantEventClient,
    WpaSupplicantScanResult, WpaSupplicantScanSecurity, WpaSupplicantStatus,
};
pub use profile::{
    WifiClientProfileError, WifiClientProfileInput, WifiClientProfileMetadata,
    WifiClientProfileSecretUpdate, WifiClientProfileStore, WifiClientProfileSummary,
};
pub use render::{
    render_wpa_supplicant_config, ClientRenderError, ClientRenderInput, RenderedClientConfig,
};
pub use supervisor::{ClientSupervisorError, WifiClientStatus, WifiClientSupervisor};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::config::{InterfaceConfig, InterfaceRole, WifiClientConfig, WifiClientSecurity};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifiClientSpec {
    pub interface: String,
    pub ssid: String,
    pub country_code: Option<String>,
    pub security: WifiClientSecurity,
    pub passphrase_file: Option<PathBuf>,
}

impl WifiClientSpec {
    pub fn from_interface_config(
        interface: &str,
        config: &InterfaceConfig,
    ) -> Result<Option<Self>> {
        config.validate(interface)?;

        if !config.managed || config.role != InterfaceRole::Input {
            return Ok(None);
        }
        let Some(wifi_client) = config.wifi_client.as_ref() else {
            return Ok(None);
        };

        let spec = Self::from_parts(interface, wifi_client);
        spec.validate()?;
        Ok(Some(spec))
    }

    fn from_parts(interface: &str, wifi_client: &WifiClientConfig) -> Self {
        Self {
            interface: interface.to_string(),
            ssid: wifi_client.ssid.clone(),
            country_code: wifi_client.country_code.clone(),
            security: wifi_client.security,
            passphrase_file: wifi_client.passphrase_file.clone(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        crate::config::validate_interface_name(&self.interface)?;

        let config = InterfaceConfig {
            wifi_concurrent: false,
            mac_address: None,
            role: InterfaceRole::Input,
            managed: true,
            ipv4: None,
            dhcp: None,
            dhcp_client: Some(crate::config::DhcpClientInterfaceConfig {
                enabled: true,
                ..Default::default()
            }),
            wifi: None,
            wifi_client: Some(self.wifi_client_config()),
        };
        config.validate(&self.interface)
    }

    pub fn wifi_client_config(&self) -> WifiClientConfig {
        WifiClientConfig {
            ssid: self.ssid.clone(),
            country_code: self.country_code.clone(),
            security: self.security,
            passphrase_file: self.passphrase_file.clone(),
        }
    }

    pub fn requires_passphrase(&self) -> bool {
        self.security.requires_passphrase()
    }
}

#[cfg(test)]
mod tests;
