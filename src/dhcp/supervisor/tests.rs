use super::*;

#[test]
fn default_config_starts_no_dhcp_services() {
    let specs = DhcpSupervisor::service_specs(&AppConfig::default()).expect("specs");
    assert!(specs.is_empty());
}

#[test]
fn example_config_creates_wlan0_service() {
    let config: AppConfig = toml::from_str(include_str!("../../../examples/config.toml"))
        .expect("example config should parse");
    let specs = DhcpSupervisor::service_specs(&config).expect("specs");

    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].interface, "wlan0");
    assert_eq!(specs[0].server_ip, Ipv4Addr::new(192, 168, 50, 1));
    assert_eq!(specs[0].prefix_len, 24);
    assert_eq!(specs[0].pool_start, Ipv4Addr::new(192, 168, 50, 100));
    assert_eq!(specs[0].pool_end, Ipv4Addr::new(192, 168, 50, 200));
    assert_eq!(specs[0].lease_seconds, 86_400);
}

#[test]
fn service_spec_is_derived_from_the_complete_interface_config() {
    let config: AppConfig = toml::from_str(include_str!("../../../examples/config.toml"))
        .expect("example config should parse");
    let interface = config
        .network
        .interfaces
        .get("wlan0")
        .expect("wlan0 config");

    let spec = DhcpServiceSpec::from_interface_config(
        "wlan0",
        interface,
        config.dhcp.default_lease_seconds,
    )
    .expect("valid service")
    .expect("DHCP should be enabled");

    assert_eq!(spec.server_ip, interface.ipv4.expect("IPv4").addr());
    assert_eq!(spec.router, spec.server_ip);
}

#[test]
fn service_spec_is_absent_for_an_output_without_dhcp() {
    let interface = InterfaceConfig {
        wifi_concurrent: false,
        randomize_mac: false,
        mac_address: None,
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some("192.168.44.1/24".parse().expect("network")),
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    };

    assert!(
        DhcpServiceSpec::from_interface_config("lan0", &interface, 3600)
            .expect("valid interface")
            .is_none()
    );
}

#[tokio::test]
async fn start_skips_absent_configured_dhcp_interface_instead_of_failing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut config = AppConfig::default();
    config.dhcp.leases_dir = temp.path().join("leases");
    config.network.interfaces.insert(
        "tm-test-absent0".to_string(),
        InterfaceConfig {
            wifi_concurrent: false,
            randomize_mac: false,
            mac_address: None,
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some("192.168.77.1/24".parse().expect("network")),
            dhcp: Some(DhcpInterfaceConfig {
                pool_start: Ipv4Addr::new(192, 168, 77, 10),
                pool_end: Ipv4Addr::new(192, 168, 77, 100),
                router: Ipv4Addr::new(192, 168, 77, 1),
                dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
                lease_seconds: Some(3_600),
            }),
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        },
    );

    let supervisor = DhcpSupervisor::start(&config)
        .await
        .expect("startup must tolerate a configured-but-absent DHCP interface");

    assert!(supervisor.spec("tm-test-absent0").await.is_none());
}
