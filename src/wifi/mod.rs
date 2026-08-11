pub mod client;
pub mod ctrl;
mod ctrl_transport;
pub mod process;
pub mod record;
pub mod render;
pub mod secret;
pub mod store;
pub mod supervisor;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::config::{
    InterfaceConfig, InterfaceRole, WifiApConfig, WifiBand, WifiChannelWidth, WifiSecurity,
};

pub use client::{
    ClientSupervisorError, WifiClientProfileError, WifiClientProfileInput,
    WifiClientProfileMetadata, WifiClientProfileSecretUpdate, WifiClientProfileStore,
    WifiClientProfileSummary, WifiClientSpec, WifiClientStatus, WifiClientSupervisor, WpaState,
    WpaSupplicantCtrlClient, WpaSupplicantEvent, WpaSupplicantEventClient, WpaSupplicantScanResult,
    WpaSupplicantScanSecurity, WpaSupplicantStatus,
};
pub use ctrl::{
    CtrlError, HostapdCtrlClient, HostapdEvent, HostapdEventClient, HostapdState, HostapdStatus,
    MacAddr, MacAddrParseError, Station,
};
pub use process::{ProcessError, SupervisedProcess, TokioSupervisedProcess};
pub use record::{PersistedWifiRecord, WifiProcessKind, WifiRecordError, WifiRecordStore};
pub use render::{
    config_path, render_hostapd_config, ApRenderInput, RenderError, RenderedApConfig, WifiDigest,
};
pub use secret::{PassphraseError, WifiPassphrase};
pub use store::{
    resolve_passphrase, PassphraseStore, PassphraseStoreError, ResolvePassphraseError,
};
pub use supervisor::{HostapdSupervisor, SupervisorError, WifiApStatus};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifiApSpec {
    pub interface: String,
    pub ssid: String,
    pub country_code: Option<String>,
    pub band: WifiBand,

    pub channel: u8,
    pub channel_width: WifiChannelWidth,
    pub security: WifiSecurity,
    pub hidden: bool,
    pub client_isolation: bool,
    pub max_stations: u16,
    pub passphrase_file: Option<PathBuf>,
}

impl WifiApSpec {
    pub fn from_interface_config(
        interface: &str,
        config: &InterfaceConfig,
    ) -> Result<Option<Self>> {
        config.validate(interface)?;

        if !config.managed || config.role != InterfaceRole::Output {
            return Ok(None);
        }
        let Some(wifi) = config.wifi.as_ref() else {
            return Ok(None);
        };

        let spec = Self::from_parts(interface, wifi);
        spec.validate()?;
        Ok(Some(spec))
    }

    fn from_parts(interface: &str, wifi: &WifiApConfig) -> Self {
        Self {
            interface: interface.to_string(),
            ssid: wifi.ssid.clone(),
            country_code: wifi.country_code.clone(),
            band: wifi.band,
            channel: wifi.channel,
            channel_width: wifi.channel_width,
            security: wifi.security,
            hidden: wifi.hidden,
            client_isolation: wifi.client_isolation,
            max_stations: wifi.max_stations,
            passphrase_file: wifi.passphrase_file.clone(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        crate::config::validate_interface_name(&self.interface)?;

        let config = InterfaceConfig {
            role: InterfaceRole::Output,
            managed: true,
            ipv4: None,
            dhcp: None,
            dhcp_client: None,
            wifi: Some(self.access_point_config()),
            wifi_client: None,
        };
        config.validate(&self.interface)
    }

    pub fn access_point_config(&self) -> WifiApConfig {
        WifiApConfig {
            ssid: self.ssid.clone(),
            country_code: self.country_code.clone(),
            band: self.band,
            channel: self.channel,
            channel_width: self.channel_width,
            security: self.security,
            hidden: self.hidden,
            client_isolation: self.client_isolation,
            max_stations: self.max_stations,
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

    fn ap_config() -> WifiApConfig {
        WifiApConfig {
            ssid: "traffic-masq".to_string(),
            country_code: Some("PL".to_string()),
            band: WifiBand::Ghz2,
            channel: 6,
            channel_width: WifiChannelWidth::Ht20,
            security: WifiSecurity::Wpa2,
            hidden: false,
            client_isolation: false,
            max_stations: 32,
            passphrase_file: None,
        }
    }

    fn interface(wifi: Option<WifiApConfig>) -> InterfaceConfig {
        InterfaceConfig {
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some("192.168.101.1/24".parse().expect("network")),
            dhcp: None,
            dhcp_client: None,
            wifi,
            wifi_client: None,
        }
    }

    #[test]
    fn derives_a_spec_from_a_managed_output_interface() {
        let spec = WifiApSpec::from_interface_config("wlan0", &interface(Some(ap_config())))
            .expect("valid")
            .expect("spec");

        assert_eq!(spec.interface, "wlan0");
        assert_eq!(spec.ssid, "traffic-masq");
        assert_eq!(spec.band, WifiBand::Ghz2);
        assert_eq!(spec.channel, 6);
        assert!(spec.requires_passphrase());
    }

    #[test]
    fn interface_without_a_wifi_block_has_no_spec() {
        let spec = WifiApSpec::from_interface_config("wlan0", &interface(None)).expect("valid");
        assert!(spec.is_none());
    }

    #[test]
    fn unmanaged_or_non_output_interface_is_rejected_rather_than_skipped() {
        let mut config = interface(Some(ap_config()));
        config.managed = false;
        assert!(WifiApSpec::from_interface_config("wlan0", &config).is_err());

        let mut config = interface(Some(ap_config()));
        config.role = InterfaceRole::Input;
        assert!(WifiApSpec::from_interface_config("wlan0", &config).is_err());
    }

    #[test]
    fn a_spec_round_trips_through_its_access_point_config() {
        let spec = WifiApSpec::from_interface_config("wlan0", &interface(Some(ap_config())))
            .expect("valid")
            .expect("spec");
        assert_eq!(spec.access_point_config(), ap_config());
        spec.validate().expect("round-tripped spec stays valid");
    }

    #[test]
    fn validate_rejects_a_spec_the_config_validator_would_reject() {
        let mut spec = WifiApSpec::from_interface_config("wlan0", &interface(Some(ap_config())))
            .expect("valid")
            .expect("spec");
        spec.channel = 36;
        assert!(spec.validate().is_err());

        let mut spec = WifiApSpec::from_interface_config("wlan0", &interface(Some(ap_config())))
            .expect("valid")
            .expect("spec");
        spec.interface = String::new();
        assert!(spec.validate().is_err());
    }
}
