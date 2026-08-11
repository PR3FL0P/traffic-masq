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

        if config.role != InterfaceRole::Input {
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
            role: InterfaceRole::Input,
            managed: false,
            ipv4: None,
            dhcp: None,
            dhcp_client: None,
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
mod tests {
    use super::*;
    use crate::config::WifiClientConfig as ClientConfig;

    fn client_config(ssid: &str) -> ClientConfig {
        ClientConfig {
            ssid: ssid.to_string(),
            country_code: Some("PL".to_string()),
            security: WifiClientSecurity::Wpa2,
            passphrase_file: None,
        }
    }

    fn interface(wifi_client: Option<ClientConfig>) -> InterfaceConfig {
        InterfaceConfig {
            role: InterfaceRole::Input,
            managed: false,
            ipv4: None,
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client,
        }
    }

    #[test]
    fn derives_a_spec_from_an_unmanaged_input_interface() {
        let spec =
            WifiClientSpec::from_interface_config("wlan0", &interface(Some(client_config("home"))))
                .expect("valid")
                .expect("spec");

        assert_eq!(spec.interface, "wlan0");
        assert_eq!(spec.ssid, "home");
        assert!(spec.requires_passphrase());
    }

    #[test]
    fn interface_without_a_wifi_client_block_has_no_spec() {
        let spec = WifiClientSpec::from_interface_config("wlan0", &interface(None)).expect("valid");
        assert!(spec.is_none());
    }

    #[test]
    fn output_or_managed_interface_is_rejected_rather_than_skipped() {
        let mut config = interface(Some(client_config("home")));
        config.role = InterfaceRole::Output;
        assert!(WifiClientSpec::from_interface_config("wlan0", &config).is_err());

        let mut config = interface(Some(client_config("home")));
        config.managed = true;
        assert!(WifiClientSpec::from_interface_config("wlan0", &config).is_err());
    }

    #[test]
    fn a_spec_round_trips_through_its_wifi_client_config() {
        let spec =
            WifiClientSpec::from_interface_config("wlan0", &interface(Some(client_config("home"))))
                .expect("valid")
                .expect("spec");
        assert_eq!(spec.wifi_client_config(), client_config("home"));
        spec.validate().expect("round-tripped spec stays valid");
    }

    #[test]
    fn validate_rejects_a_spec_the_config_validator_would_reject() {
        let mut spec =
            WifiClientSpec::from_interface_config("wlan0", &interface(Some(client_config("home"))))
                .expect("valid")
                .expect("spec");
        spec.ssid = String::new();
        assert!(spec.validate().is_err());

        let mut spec =
            WifiClientSpec::from_interface_config("wlan0", &interface(Some(client_config("home"))))
                .expect("valid")
                .expect("spec");
        spec.interface = String::new();
        assert!(spec.validate().is_err());
    }

    #[test]
    fn an_ap_and_a_client_block_cannot_coexist_on_one_interface() {
        let mut config = interface(Some(client_config("home")));
        config.role = InterfaceRole::Output;
        config.managed = true;
        config.wifi = Some(crate::config::WifiApConfig {
            ssid: "ap-side".to_string(),
            country_code: Some("PL".to_string()),
            band: crate::config::WifiBand::Ghz2,
            channel: 6,
            channel_width: crate::config::WifiChannelWidth::Ht20,
            security: crate::config::WifiSecurity::Open,
            hidden: false,
            client_isolation: false,
            max_stations: 32,
            passphrase_file: None,
        });

        let error = config.validate("wlan0").expect_err("must be rejected");
        assert!(
            error.to_string().contains("cannot be both"),
            "expected the mutual-exclusion error specifically, got: {error}"
        );
    }
}
