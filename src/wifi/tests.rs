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
        wifi_concurrent: false,
        mac_address: None,
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
