#[test]
fn explicit_forwarding_accepts_unmanaged_and_vpn_interfaces_without_a_global_uplink() {
    let mut config = AppConfig::default();
    config.router.enabled = true;
    config.router.forwarding = Some(vec![
        ForwardingConfig {
            source_subnet: None,
            from: "eth1".into(),
            to: "wg0".into(),
            masquerade: true,
        },
        ForwardingConfig {
            source_subnet: None,
            from: "wg0".into(),
            to: "wg1".into(),
            masquerade: false,
        },
    ]);
    config.validate().unwrap();
    let encoded = toml::to_string(&config).unwrap();
    let decoded: AppConfig = toml::from_str(&encoded).unwrap();
    assert_eq!(decoded.router.forwarding, config.router.forwarding);
    config.router.forwarding = Some(vec![]);
    let decoded: AppConfig = toml::from_str(&toml::to_string(&config).unwrap()).unwrap();
    assert_eq!(decoded.router.forwarding, Some(vec![]));
}

#[test]
fn forwarding_rejects_self_links_duplicates_and_unsafe_names() {
    let rule = ForwardingConfig {
        source_subnet: None,
        from: "lan0".into(),
        to: "wan0".into(),
        masquerade: true,
    };
    assert!(validate_forwarding(&[rule.clone(), rule.clone()]).is_err());
    assert!(validate_forwarding(&[ForwardingConfig {
        to: "lan0".into(),
        ..rule.clone()
    }])
    .is_err());
    assert!(validate_forwarding(&[ForwardingConfig {
        to: "wan*".into(),
        ..rule
    }])
    .is_err());
}

#[test]
fn explicit_forwarding_refuses_ambiguous_global_vpn_policy() {
    let mut config = AppConfig::default();
    config.router.forwarding = Some(vec![]);
    config.router.vpn_chain = vec![VpnHopConfig {
        profile_name: "vpn.conf".into(),
    }];
    assert!(config
        .validate()
        .unwrap_err()
        .to_string()
        .contains("vpn_chain"));
    config.router.vpn_chain.clear();
    config.vpn.policy.default_mode = VpnPolicyMode::Vpn;
    assert!(config
        .validate()
        .unwrap_err()
        .to_string()
        .contains("global VPN policy"));
}

#[test]
fn legacy_management_role_reads_as_none_and_serializes_canonically() {
    let config: InterfaceConfig =
        toml::from_str("role = \"management\"\nmanaged = false\n").unwrap();
    assert_eq!(config.role, InterfaceRole::None);
    let encoded = toml::to_string(&config).unwrap();
    assert!(encoded.contains("role = \"none\""));
    assert!(!encoded.contains("management"));
}

use super::*;

#[test]
fn vpn_source_and_store_must_differ_before_directory_creation() {
    let directory = tempfile::tempdir().unwrap();
    let real = directory.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let alias = directory.path().join("alias");
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    let mut config = AppConfig::default();
    config.vpn.wireguard_config_dir = real.join("profiles");
    for source in [
        real.join("profiles"),
        real.join("unused/../profiles"),
        alias.join("profiles"),
    ] {
        config.vpn.wireguard_import_dir = source;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("wireguard_import_dir must differ"));
    }
    config.vpn.wireguard_import_dir = alias.join("sources");
    config.validate().unwrap();
    assert!(!real.join("profiles").exists());
    assert!(!real.join("sources").exists());
}

#[test]
fn vpn_directory_validation_does_not_require_daemon_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let private = directory.path().join("private");
    std::fs::create_dir(&private).unwrap();
    let mut config = AppConfig::default();
    config.vpn.wireguard_config_dir = private.join("profiles");
    config.vpn.wireguard_import_dir = private.join("sources");
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o000)).unwrap();
    let result = config.validate();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
    result.expect("configuration inspection must not require daemon directory access");
}

fn input_interface() -> InterfaceConfig {
    InterfaceConfig {
        nat: true,
        role: InterfaceRole::Input,
        managed: false,
        ipv4: None,
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    }
}

fn output_interface(ipv4: &str, pool_start: Ipv4Addr, pool_end: Ipv4Addr) -> InterfaceConfig {
    InterfaceConfig {
        nat: true,
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some(ipv4.parse().expect("valid network")),
        dhcp: Some(DhcpInterfaceConfig {
            pool_start,
            pool_end,
            router: ipv4
                .split('/')
                .next()
                .expect("address")
                .parse()
                .expect("router"),
            dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
            lease_seconds: Some(3600),
        }),
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    }
}

fn valid_router_config() -> AppConfig {
    let mut config = AppConfig::default();
    config
        .network
        .interfaces
        .insert("wan0".to_string(), input_interface());
    config.network.interfaces.insert(
        "lan0".to_string(),
        output_interface(
            "192.168.10.1/24",
            Ipv4Addr::new(192, 168, 10, 100),
            Ipv4Addr::new(192, 168, 10, 200),
        ),
    );
    config.network.interfaces.insert(
        "lan1".to_string(),
        output_interface(
            "192.168.20.1/24",
            Ipv4Addr::new(192, 168, 20, 100),
            Ipv4Addr::new(192, 168, 20, 200),
        ),
    );
    config.router = RouterConfig {
        forwarding: None,
        vpn_chain: Vec::new(),
        enabled: true,
        uplink: Some(UplinkConfig {
            interface: "wan0".to_string(),
            mode: UplinkMode::External,
        }),
        owned_routes: vec![OwnedIpv4RouteConfig {
            destination: "203.0.113.0/24".parse().expect("route destination"),
            gateway: None,
            output_interface: Some("wan0".to_string()),
            table: 254,
            metric: Some(100),
        }],
        allow_default_route_change: false,
    };
    config
}

#[test]
fn rejects_dhcp_router_that_differs_from_output_interface_address() {
    let interface = output_interface(
        "192.168.10.1/24",
        Ipv4Addr::new(192, 168, 10, 100),
        Ipv4Addr::new(192, 168, 10, 200),
    );
    let mut interface = interface;
    interface.dhcp.as_mut().expect("DHCP config").router = Ipv4Addr::new(192, 168, 10, 254);

    let error = interface
        .validate("lan0")
        .expect_err("external DHCP gateway is not supported");
    assert!(error
        .to_string()
        .contains("must match the output interface IPv4 address"));
}

#[test]
fn example_config_parses_and_validates() {
    let config: AppConfig = toml::from_str(include_str!("../../examples/config.toml"))
        .expect("example config should parse");
    config.validate().expect("example config should validate");
}

#[test]
fn example_config_documents_both_wifi_sections_disabled() {
    let raw = include_str!("../../examples/config.toml");
    let config: AppConfig = toml::from_str(raw).expect("example config should parse");

    assert!(
        raw.contains("[wifi]"),
        "the AP section should be documented"
    );
    assert!(
        raw.contains("[wifi_client]"),
        "the client section should be documented"
    );
    assert!(!config.wifi.enabled, "the example must not start an AP");
    assert!(
        !config.wifi_client.enabled,
        "the example must not join a network"
    );

    // The warning is a wrapped comment. Match the sentence as it reads,
    // not as it happens to be broken across lines: rewrapping the example
    // must not look like deleting the warning.
    let unwrapped = raw
        .lines()
        .map(|line| line.trim_start_matches('#').trim())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        unwrapped.contains("does NOT give this interface an IP address"),
        "the external-address-acquisition warning must stay in the example"
    );
}

#[test]
fn example_config_describes_a_complete_working_router() {
    let config: AppConfig = toml::from_str(include_str!("../../examples/config.toml"))
        .expect("example config should parse");

    assert!(config.router.enabled, "example should demonstrate routing");
    assert!(config.router.uplink.is_none());
    assert_eq!(
        config.router.forwarding,
        Some(vec![ForwardingConfig {
            source_subnet: None,
            from: "wlan0".into(),
            to: "wan0".into(),
            masquerade: true,
        }])
    );
    assert!(
        !config.router.allow_default_route_change,
        "example must not ship with default-route replacement pre-authorized"
    );

    let uplink_interface = config
        .network
        .interfaces
        .get("wan0")
        .expect("uplink is declared");
    assert_eq!(uplink_interface.role, InterfaceRole::Input);
    assert!(
        !uplink_interface.managed,
        "an external uplink must stay unmanaged"
    );

    let management = config
        .network
        .interfaces
        .get("eth0")
        .expect("example shows an outside-router interface");
    assert_eq!(management.role, InterfaceRole::None);
    assert!(!management.managed);

    let lan = config
        .network
        .interfaces
        .get("wlan0")
        .expect("example shows a managed LAN");
    assert_eq!(lan.role, InterfaceRole::Output);
    assert!(lan.managed);
    assert!(lan.ipv4.is_some());
    assert!(lan.dhcp.is_some());

    assert!(!config.vpn.enabled);
    assert_eq!(config.vpn.policy.default_mode, VpnPolicyMode::Direct);
    assert!(config.api.tcp.as_ref().is_some_and(|tcp| !tcp.enabled));
}

#[test]
fn default_config_does_not_manage_any_interface() {
    let config = AppConfig::default();
    assert!(config.network.interfaces.is_empty());
    assert_eq!(config.router, RouterConfig::default());
    assert!(!config.router.enabled);
    assert_eq!(config.vpn.policy.default_mode, VpnPolicyMode::Direct);
    assert_eq!(
        config.vpn.policy.protected_subnets,
        VpnProtectedSubnets::AllManagedOutputSubnets
    );
    config.validate().expect("default config should be valid");
}

#[test]
fn legacy_vpn_config_without_policy_uses_stage_06_defaults() {
    let mut legacy = toml::Value::try_from(AppConfig::default()).expect("serialize config");
    let root = legacy.as_table_mut().expect("root table");
    let vpn = root
        .get_mut("vpn")
        .and_then(toml::Value::as_table_mut)
        .expect("vpn table");
    vpn.remove("policy");
    vpn.insert("enabled".into(), toml::Value::Boolean(true));

    let config: AppConfig = legacy.try_into().expect("legacy config should parse");
    assert_eq!(config.vpn.policy.default_mode, VpnPolicyMode::Direct);
    assert_eq!(
        config.vpn.policy.protected_subnets,
        VpnProtectedSubnets::AllManagedOutputSubnets
    );
    config.validate().expect("legacy config should validate");
}

#[test]
fn vpn_policy_vpn_mode_requires_vpn_manager_to_be_enabled() {
    let mut config = valid_router_config();
    config.vpn.policy.default_mode = VpnPolicyMode::Vpn;

    let error = config
        .validate()
        .expect_err("VPN mode requires vpn.enabled");
    assert!(error
        .to_string()
        .contains("vpn.policy.default_mode = \"vpn\" requires vpn.enabled = true"));
}

#[test]
fn vpn_policy_vpn_mode_requires_router_baseline() {
    let mut config = AppConfig::default();
    config.vpn.enabled = true;
    config.vpn.policy.default_mode = VpnPolicyMode::Vpn;

    let error = config
        .validate()
        .expect_err("VPN mode requires router baseline");
    assert!(error
        .to_string()
        .contains("vpn.policy.default_mode = \"vpn\" requires router.enabled = true"));
}

#[test]
fn vpn_policy_vpn_mode_accepts_valid_router_baseline() {
    let mut config = valid_router_config();
    config.vpn.enabled = true;
    config.vpn.policy.default_mode = VpnPolicyMode::Vpn;

    config
        .validate()
        .expect("vpn mode should validate on top of a valid router baseline");
}

#[test]
fn valid_single_uplink_multi_output_router_passes_validation() {
    valid_router_config()
        .validate()
        .expect("single uplink and multiple outputs should be valid");
}

#[test]
fn enabled_router_without_uplink_is_valid_but_unconfigured() {
    let mut config = valid_router_config();
    config.router.uplink = None;
    config
        .validate()
        .expect("an enabled router may await interactive provisioning");
}

#[test]
fn enabled_router_rejects_uplink_with_wrong_interface_role() {
    let mut config = valid_router_config();
    config
        .network
        .interfaces
        .get_mut("wan0")
        .expect("uplink")
        .role = InterfaceRole::None;
    assert!(config
        .validate()
        .expect_err("outside-router interface cannot be uplink")
        .to_string()
        .contains("must have the input role"));
}

#[test]
fn enabled_router_rejects_missing_outputs() {
    let mut config = valid_router_config();
    config
        .network
        .interfaces
        .retain(|_, interface| interface.role != InterfaceRole::Output);
    assert!(config
        .validate()
        .expect_err("output is required")
        .to_string()
        .contains("at least one managed output"));
}

#[test]
fn owned_default_route_requires_explicit_permission() {
    let mut config = valid_router_config();
    config.router.owned_routes[0].destination = "0.0.0.0/0".parse().expect("default route");
    assert!(config
        .validate()
        .expect_err("default route needs permission")
        .to_string()
        .contains("allow_default_route_change"));

    config.router.allow_default_route_change = true;
    config
        .validate()
        .expect("explicitly permitted default route should be valid");
}

#[test]
fn rejects_route_ownership_violations() {
    let mut config = valid_router_config();
    config.network.interfaces.insert(
        "disabled0".to_string(),
        InterfaceConfig {
            nat: true,
            role: InterfaceRole::Disabled,
            managed: false,
            ipv4: None,
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        },
    );
    config.router.owned_routes[0].output_interface = Some("disabled0".to_string());
    assert!(config
        .validate()
        .expect_err("disabled role cannot own route")
        .to_string()
        .contains("cannot own a router route"));

    // Non-disabled roles (None, unselected Input) and host interfaces not in network.interfaces are permitted
    let mut config = valid_router_config();
    config.network.interfaces.insert(
        "unmanaged0".to_string(),
        InterfaceConfig {
            nat: true,
            role: InterfaceRole::None,
            managed: false,
            ipv4: None,
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        },
    );
    config.router.owned_routes[0].output_interface = Some("unmanaged0".to_string());
    config
        .validate()
        .expect("unmanaged interface should be valid for static route");

    let mut config = valid_router_config();
    config
        .network
        .interfaces
        .insert("other-wan".to_string(), input_interface());
    config.router.owned_routes[0].output_interface = Some("other-wan".to_string());
    config
        .validate()
        .expect("unselected input interface should be valid for static route");

    let mut config = valid_router_config();
    config.router.owned_routes[0].output_interface = Some("eth9".to_string());
    config.validate().expect(
        "system interface not declared in network.interfaces should pass config validation",
    );
}

#[test]
fn router_without_uplink_validates_routes_and_detects_duplicates() {
    let mut config = valid_router_config();
    config.router.uplink = None;
    config.router.owned_routes = vec![
        OwnedIpv4RouteConfig {
            destination: "10.0.0.0/24".parse().expect("destination"),
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            output_interface: None,
            table: 254,
            metric: None,
        },
        OwnedIpv4RouteConfig {
            destination: "10.0.0.0/24".parse().expect("destination"),
            gateway: Some(Ipv4Addr::new(192, 168, 1, 2)),
            output_interface: None,
            table: 254,
            metric: Some(0),
        },
    ];

    let error = config
        .validate()
        .expect_err("duplicate routes with None and Some(0) metrics must be rejected");
    assert!(error
        .to_string()
        .contains("duplicate router owned IPv4 route"));

    // Valid single route without uplink
    config.router.owned_routes.pop();
    config
        .validate()
        .expect("valid router without uplink should validate");

    // Reject host bits in CIDR
    config.router.owned_routes[0].destination = "192.168.100.5/24".parse().unwrap();
    let error = config
        .validate()
        .expect_err("destination with host bits must be rejected");
    assert!(error.to_string().contains("has host bits set"));

    // Reject RT_TABLE_LOCAL (255)
    config.router.owned_routes[0].destination = "192.168.100.0/24".parse().unwrap();
    config.router.owned_routes[0].table = 255;
    let error = config.validate().expect_err("table 255 must be rejected");
    assert!(error.to_string().contains("RT_TABLE_LOCAL (255)"));
}

#[test]
fn legacy_config_uses_api_auth_and_runtime_defaults() {
    let mut legacy = toml::Value::try_from(AppConfig::default()).expect("serialize config");
    let root = legacy.as_table_mut().expect("root table");
    root.remove("api");
    root.remove("auth");
    root.remove("router");
    let runtime = root
        .get_mut("runtime")
        .and_then(toml::Value::as_table_mut)
        .expect("runtime table");
    runtime.remove("socket_group");
    runtime.remove("shutdown_policy");

    let config: AppConfig = legacy.try_into().expect("legacy config should parse");
    assert_eq!(config.api, ApiConfig::default());
    assert_eq!(config.auth, AuthConfig::default());
    assert_eq!(config.router, RouterConfig::default());
    assert_eq!(config.runtime.socket_group, None);
    assert_eq!(
        config.runtime.shutdown_policy,
        ShutdownPolicy::PreserveInterfaces
    );
}

#[test]
fn tcp_api_is_disabled_by_default_and_requires_distinct_tls_paths() {
    let mut config = AppConfig::default();
    assert_eq!(config.api, ApiConfig::default());

    config.api.tcp = Some(TcpApiConfig::default());
    config
        .validate()
        .expect("disabled TCP listener should not require TLS paths");

    let tcp = config.api.tcp.as_mut().expect("TCP config");
    tcp.enabled = true;
    assert!(config.validate().is_err());

    let tcp = config.api.tcp.as_mut().expect("TCP config");
    tcp.certificate_path = Some(PathBuf::from("/etc/traffic-masq/server.pem"));
    tcp.private_key_path = Some(PathBuf::from("/etc/traffic-masq/server.pem"));
    assert!(config.validate().is_err());

    config
        .api
        .tcp
        .as_mut()
        .expect("TCP config")
        .private_key_path = Some(PathBuf::from("/etc/traffic-masq/server-key.pem"));
    config
        .validate()
        .expect("enabled TCP listener should accept distinct TLS paths");
}

#[test]
fn tcp_api_uses_loopback_default_listen_address() {
    let tcp: TcpApiConfig = toml::from_str("enabled = false").expect("TCP config");
    assert_eq!(
        tcp.listen,
        "127.0.0.1:8443".parse().expect("socket address")
    );
}

#[test]
fn auth_defaults_match_approved_limits() {
    let auth = AuthConfig::default();
    assert_eq!(
        auth.database_path,
        PathBuf::from("/var/lib/traffic-masq/auth.sqlite3")
    );
    assert_eq!(auth.session_idle_seconds, 1_800);
    assert_eq!(auth.session_absolute_seconds, 28_800);
    assert_eq!(auth.argon2_memory_kib, 32_768);
    assert_eq!(auth.argon2_iterations, 3);
    assert_eq!(auth.argon2_parallelism, 1);
    assert_eq!(auth.max_concurrent_logins, 2);
    auth.validate().expect("auth defaults should validate");
}

#[test]
fn auth_rejects_zero_limits_and_idle_longer_than_absolute() {
    let invalid = [
        AuthConfig {
            session_idle_seconds: 0,
            ..AuthConfig::default()
        },
        AuthConfig {
            session_absolute_seconds: 0,
            ..AuthConfig::default()
        },
        AuthConfig {
            argon2_memory_kib: 0,
            ..AuthConfig::default()
        },
        AuthConfig {
            argon2_iterations: 0,
            ..AuthConfig::default()
        },
        AuthConfig {
            argon2_parallelism: 0,
            ..AuthConfig::default()
        },
        AuthConfig {
            max_concurrent_logins: 0,
            ..AuthConfig::default()
        },
        AuthConfig {
            session_idle_seconds: 28_801,
            ..AuthConfig::default()
        },
    ];

    for auth in invalid {
        assert!(auth.validate().is_err());
    }
}

#[test]
fn runtime_rejects_empty_socket_group_and_path_conflicts() {
    let mut config = AppConfig::default();
    config.runtime.socket_group = Some("   ".to_string());
    assert!(config.validate().is_err());

    config.runtime.socket_group = None;
    config.runtime.socket_path = config.runtime.pid_path.clone();
    assert!(config.validate().is_err());

    config.runtime.socket_path = process_lock_path(&config.runtime.pid_path);
    assert!(config.validate().is_err());
}

#[test]
fn valid_output_dhcp_config_passes_validation() {
    let mut config = AppConfig::default();
    config.network.interfaces.insert(
        "wlan0".to_string(),
        output_interface(
            "192.168.10.1/24",
            Ipv4Addr::new(192, 168, 10, 100),
            Ipv4Addr::new(192, 168, 10, 200),
        ),
    );

    config.validate().expect("config should be valid");
}

#[test]
fn rejects_pool_outside_interface_network() {
    let mut config = AppConfig::default();
    config.network.interfaces.insert(
        "wlan0".to_string(),
        output_interface(
            "192.168.10.1/24",
            Ipv4Addr::new(192, 168, 11, 100),
            Ipv4Addr::new(192, 168, 11, 200),
        ),
    );

    assert!(config.validate().is_err());
}

#[test]
fn rejects_interface_address_inside_pool() {
    let mut config = AppConfig::default();
    config.network.interfaces.insert(
        "wlan0".to_string(),
        output_interface(
            "192.168.10.100/24",
            Ipv4Addr::new(192, 168, 10, 100),
            Ipv4Addr::new(192, 168, 10, 200),
        ),
    );

    assert!(config.validate().is_err());
}

#[test]
fn rejects_overlapping_managed_networks() {
    let mut config = AppConfig::default();
    config.network.interfaces.insert(
        "wlan0".to_string(),
        output_interface(
            "192.168.10.1/24",
            Ipv4Addr::new(192, 168, 10, 100),
            Ipv4Addr::new(192, 168, 10, 150),
        ),
    );
    config.network.interfaces.insert(
        "usb0".to_string(),
        output_interface(
            "192.168.10.2/25",
            Ipv4Addr::new(192, 168, 10, 10),
            Ipv4Addr::new(192, 168, 10, 20),
        ),
    );

    assert!(config.validate().is_err());
}

fn access_point() -> WifiApConfig {
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

fn wifi_interface(wifi: WifiApConfig) -> InterfaceConfig {
    let mut config = output_interface(
        "192.168.30.1/24",
        Ipv4Addr::new(192, 168, 30, 100),
        Ipv4Addr::new(192, 168, 30, 200),
    );
    config.wifi = Some(wifi);
    config
}

fn config_with_access_point(wifi: WifiApConfig) -> AppConfig {
    let mut config = AppConfig::default();
    config
        .network
        .interfaces
        .insert("wlan0".to_string(), wifi_interface(wifi));
    config
}

#[test]
fn accepts_an_access_point_on_a_managed_output_interface() {
    config_with_access_point(access_point())
        .validate()
        .expect("valid access point");
}

#[test]
fn rejects_an_access_point_on_an_unmanaged_or_non_output_interface() {
    let mut config = config_with_access_point(access_point());
    config
        .network
        .interfaces
        .get_mut("wlan0")
        .expect("interface")
        .managed = false;
    assert!(config.validate().is_err());

    let mut config = config_with_access_point(access_point());
    let interface = config
        .network
        .interfaces
        .get_mut("wlan0")
        .expect("interface");
    interface.role = InterfaceRole::None;
    interface.dhcp = None;
    assert!(config.validate().is_err());
}

#[test]
fn rejects_an_ssid_that_cannot_fit_or_cannot_be_advertised() {
    let mut empty = access_point();
    empty.ssid = String::new();
    assert!(config_with_access_point(empty).validate().is_err());

    let mut overlong = access_point();
    overlong.ssid = "a".repeat(MAX_SSID_BYTES + 1);
    assert!(config_with_access_point(overlong).validate().is_err());

    let mut multibyte = access_point();
    multibyte.ssid = "ы".repeat(17);
    assert!(config_with_access_point(multibyte).validate().is_err());

    let mut control = access_point();
    control.ssid = "traffic\nmasq".to_string();
    assert!(config_with_access_point(control).validate().is_err());
}

#[test]
fn rejects_a_channel_that_does_not_belong_to_the_band() {
    let mut wrong_band = access_point();
    wrong_band.channel = 36;
    assert!(config_with_access_point(wrong_band).validate().is_err());

    let mut nonexistent = access_point();
    nonexistent.channel = 15;
    assert!(config_with_access_point(nonexistent).validate().is_err());

    let mut acs = access_point();
    acs.channel = 0;
    config_with_access_point(acs).validate().expect("acs");
}

#[test]
fn requires_a_country_code_on_5_ghz_and_rejects_a_malformed_one() {
    let mut missing = access_point();
    missing.band = WifiBand::Ghz5;
    missing.channel = 36;
    missing.country_code = None;
    assert!(config_with_access_point(missing).validate().is_err());

    let mut lowercase = access_point();
    lowercase.country_code = Some("pl".to_string());
    assert!(config_with_access_point(lowercase).validate().is_err());

    let mut too_long = access_point();
    too_long.country_code = Some("POL".to_string());
    assert!(config_with_access_point(too_long).validate().is_err());

    let mut band_2g = access_point();
    band_2g.country_code = None;
    config_with_access_point(band_2g)
        .validate()
        .expect("2.4ghz");
}

#[test]
fn rejects_vht80_outside_5_ghz() {
    let mut wide = access_point();
    wide.channel_width = WifiChannelWidth::Vht80;
    assert!(config_with_access_point(wide).validate().is_err());

    let mut wide_5g = access_point();
    wide_5g.channel_width = WifiChannelWidth::Vht80;
    wide_5g.band = WifiBand::Ghz5;
    wide_5g.channel = 36;
    config_with_access_point(wide_5g).validate().expect("5ghz");
}

#[test]
fn rejects_an_unusable_station_limit() {
    let mut zero = access_point();
    zero.max_stations = 0;
    assert!(config_with_access_point(zero).validate().is_err());

    let mut too_many = access_point();
    too_many.max_stations = MAX_WIFI_STATIONS + 1;
    assert!(config_with_access_point(too_many).validate().is_err());
}

#[test]
fn rejects_a_passphrase_file_that_is_relative_or_contradicts_open_security() {
    let mut relative = access_point();
    relative.passphrase_file = Some(PathBuf::from("secrets/wlan0.psk"));
    assert!(config_with_access_point(relative).validate().is_err());

    let mut open = access_point();
    open.security = WifiSecurity::Open;
    open.passphrase_file = Some(PathBuf::from("/etc/traffic-masq/wlan0.psk"));
    assert!(config_with_access_point(open).validate().is_err());

    let mut absolute = access_point();
    absolute.passphrase_file = Some(PathBuf::from("/etc/traffic-masq/wlan0.psk"));
    config_with_access_point(absolute)
        .validate()
        .expect("absolute passphrase file");
}

#[test]
fn rejects_two_interfaces_advertising_one_ssid_on_one_band() {
    let mut config = config_with_access_point(access_point());
    let mut second = output_interface(
        "192.168.40.1/24",
        Ipv4Addr::new(192, 168, 40, 100),
        Ipv4Addr::new(192, 168, 40, 200),
    );
    second.wifi = Some(access_point());
    config
        .network
        .interfaces
        .insert("wlan1".to_string(), second);
    assert!(config.validate().is_err());

    let mut other_band = access_point();
    other_band.band = WifiBand::Ghz5;
    other_band.channel = 36;
    config
        .network
        .interfaces
        .get_mut("wlan1")
        .expect("interface")
        .wifi = Some(other_band);
    config.validate().expect("dual band");
}

#[test]
fn rejects_a_global_wifi_section_that_cannot_work() {
    let mut relative_binary = AppConfig::default();
    relative_binary.wifi.hostapd_binary = PathBuf::from("hostapd");
    assert!(relative_binary.validate().is_err());

    let mut relative_iw = AppConfig::default();
    relative_iw.wifi.iw_binary = PathBuf::from("iw");
    assert!(relative_iw.validate().is_err());

    let mut relative_runtime = AppConfig::default();
    relative_runtime.wifi.runtime_dir = PathBuf::from("hostapd");
    assert!(relative_runtime.validate().is_err());

    let mut no_backoff = AppConfig::default();
    no_backoff.wifi.restart_backoff_seconds = 0;
    assert!(no_backoff.validate().is_err());
}

#[test]
fn a_config_without_a_wifi_section_still_loads_with_wifi_disabled() {
    let config: AppConfig = toml::from_str(
        r#"
        [runtime]
        state_dir = "/var/lib/traffic-masq"
        log_dir = "/var/log/traffic-masq"
        socket_path = "/run/traffic-masq/traffic-masqd.sock"
        pid_path = "/run/traffic-masq/traffic-masqd.pid"

        [network]

        [dhcp]
        leases_dir = "/var/lib/traffic-masq/dhcp/leases"
        default_lease_seconds = 86400

        [vpn]
        wireguard_config_dir = "/var/lib/traffic-masq/vpn/wireguard"

        [security]
        rollback_timeout_seconds = 60
        "#,
    )
    .expect("config without a [wifi] section parses");

    assert!(!config.wifi.enabled);
    config.validate().expect("valid");
}

fn client_association(ssid: &str) -> WifiClientConfig {
    WifiClientConfig {
        ssid: ssid.to_string(),
        country_code: Some("PL".to_string()),
        security: WifiClientSecurity::Wpa2,
        passphrase_file: None,
    }
}

fn client_interface(wifi_client: WifiClientConfig) -> InterfaceConfig {
    InterfaceConfig {
        nat: true,
        role: InterfaceRole::Input,
        managed: true,
        ipv4: None,
        dhcp: None,
        dhcp_client: Some(DhcpClientInterfaceConfig {
            enabled: true,
            ..Default::default()
        }),
        wifi: None,
        wifi_client: Some(wifi_client),
    }
}

fn config_with_wifi_client(wifi_client: WifiClientConfig) -> AppConfig {
    let mut config = AppConfig::default();
    config
        .network
        .interfaces
        .insert("wan_wifi".to_string(), client_interface(wifi_client));
    config
}

#[test]
fn accepts_a_wifi_client_on_a_managed_input_interface() {
    config_with_wifi_client(client_association("upstream"))
        .validate()
        .expect("valid wifi client");
}

#[test]
fn rejects_a_wifi_client_on_an_unmanaged_or_non_input_interface() {
    let mut config = config_with_wifi_client(client_association("upstream"));
    config
        .network
        .interfaces
        .get_mut("wan_wifi")
        .expect("interface")
        .managed = false;
    assert!(config.validate().is_err());

    let mut config = config_with_wifi_client(client_association("upstream"));
    config
        .network
        .interfaces
        .get_mut("wan_wifi")
        .expect("interface")
        .role = InterfaceRole::Output;
    assert!(config.validate().is_err());
}

#[test]
fn rejects_a_wifi_client_ssid_that_cannot_fit_or_cannot_be_advertised() {
    let mut empty = client_association("upstream");
    empty.ssid = String::new();
    assert!(config_with_wifi_client(empty).validate().is_err());

    let mut overlong = client_association("upstream");
    overlong.ssid = "a".repeat(MAX_SSID_BYTES + 1);
    assert!(config_with_wifi_client(overlong).validate().is_err());

    let mut control = client_association("upstream");
    control.ssid = "wan\nwifi".to_string();
    assert!(config_with_wifi_client(control).validate().is_err());
}

#[test]
fn rejects_a_malformed_wifi_client_country_code() {
    let mut lowercase = client_association("upstream");
    lowercase.country_code = Some("pl".to_string());
    assert!(config_with_wifi_client(lowercase).validate().is_err());

    let mut too_long = client_association("upstream");
    too_long.country_code = Some("POL".to_string());
    assert!(config_with_wifi_client(too_long).validate().is_err());

    let mut none = client_association("upstream");
    none.country_code = None;
    config_with_wifi_client(none)
        .validate()
        .expect("no country code");
}

#[test]
fn rejects_a_wifi_client_passphrase_file_that_is_relative_or_contradicts_open_security() {
    let mut relative = client_association("upstream");
    relative.passphrase_file = Some(PathBuf::from("secrets/wan.psk"));
    assert!(config_with_wifi_client(relative).validate().is_err());

    let mut open = client_association("upstream");
    open.security = WifiClientSecurity::Open;
    open.passphrase_file = Some(PathBuf::from("/etc/traffic-masq/wan.psk"));
    assert!(config_with_wifi_client(open).validate().is_err());

    let mut absolute = client_association("upstream");
    absolute.passphrase_file = Some(PathBuf::from("/etc/traffic-masq/wan.psk"));
    config_with_wifi_client(absolute)
        .validate()
        .expect("absolute passphrase file");
}

#[test]
fn rejects_a_global_wifi_client_section_that_cannot_work() {
    let mut relative_binary = AppConfig::default();
    relative_binary.wifi_client.wpa_supplicant_binary = PathBuf::from("wpa_supplicant");
    assert!(relative_binary.validate().is_err());

    let mut relative_runtime = AppConfig::default();
    relative_runtime.wifi_client.runtime_dir = PathBuf::from("wpa_supplicant");
    assert!(relative_runtime.validate().is_err());

    let mut no_backoff = AppConfig::default();
    no_backoff.wifi_client.restart_backoff_seconds = 0;
    assert!(no_backoff.validate().is_err());
}

#[test]
fn a_config_without_a_wifi_client_section_still_loads_with_it_disabled() {
    let config: AppConfig = toml::from_str(
        r#"
        [runtime]
        state_dir = "/var/lib/traffic-masq"
        log_dir = "/var/log/traffic-masq"
        socket_path = "/run/traffic-masq/traffic-masqd.sock"
        pid_path = "/run/traffic-masq/traffic-masqd.pid"

        [network]

        [dhcp]
        leases_dir = "/var/lib/traffic-masq/dhcp/leases"
        default_lease_seconds = 86400

        [vpn]
        wireguard_config_dir = "/var/lib/traffic-masq/vpn/wireguard"

        [security]
        rollback_timeout_seconds = 60
        "#,
    )
    .expect("config without a [wifi_client] section parses");

    assert!(!config.wifi_client.enabled);
    config.validate().expect("valid");
}

fn dhcp_client() -> DhcpClientInterfaceConfig {
    DhcpClientInterfaceConfig::default()
}

#[test]
fn dhcp_client_defaults_and_legacy_absence_are_backward_compatible() {
    let interface: InterfaceConfig = toml::from_str("role = \"input\"").expect("legacy interface");
    assert!(interface.dhcp_client.is_none());

    let interface: InterfaceConfig =
        toml::from_str("role = \"input\"\nmanaged = true\n[dhcp_client]\n")
            .expect("DHCP client interface");
    assert_eq!(interface.dhcp_client, Some(dhcp_client()));
}

#[test]
fn accepts_external_and_managed_dhcp_input_matrix() {
    let external_wired = input_interface();
    external_wired
        .validate("wan0")
        .expect("external unmanaged wired");

    let managed_wifi = client_interface(client_association("upstream"));
    managed_wifi
        .validate("wlan0")
        .expect("managed Wi-Fi DHCP input");

    let mut unmanaged_wifi = managed_wifi.clone();
    unmanaged_wifi.managed = false;
    assert!(unmanaged_wifi.validate("wlan0").is_err());

    let mut managed_wired = input_interface();
    managed_wired.managed = true;
    managed_wired.dhcp_client = Some(dhcp_client());
    managed_wired
        .validate("wan0")
        .expect("managed wired DHCP input");
}

#[test]
fn accepts_existing_static_input_semantics() {
    let mut existing_static_owner = input_interface();
    existing_static_owner.managed = true;
    existing_static_owner.ipv4 = Some("192.0.2.2/24".parse().unwrap());
    existing_static_owner
        .validate("wan0")
        .expect("existing managed static input semantics remain valid");

    let mut managed_wifi_static = client_interface(client_association("upstream"));
    managed_wifi_static.dhcp_client = None;
    managed_wifi_static.ipv4 = Some("192.0.2.50/24".parse().unwrap());
    managed_wifi_static
        .validate("wlan0")
        .expect("managed Wi-Fi static input");

    let mut conflict = managed_wifi_static;
    conflict.dhcp_client = Some(dhcp_client());
    let err = conflict
        .validate("wlan0")
        .expect_err("static IP and DHCP client are mutually exclusive");
    assert!(err
        .to_string()
        .contains("both a static IPv4 address and an enabled DHCP client"));
}

#[test]
fn rejects_invalid_dhcp_client_ownership_combinations() {
    for role in [
        InterfaceRole::Output,
        InterfaceRole::None,
        InterfaceRole::Disabled,
    ] {
        let mut interface = input_interface();
        interface.role = role;
        interface.dhcp_client = Some(DhcpClientInterfaceConfig {
            enabled: false,
            ..dhcp_client()
        });
        assert!(interface.validate("bad0").is_err(), "role {role:?}");
    }

    let mut unmanaged = input_interface();
    unmanaged.dhcp_client = Some(dhcp_client());
    let error = unmanaged.validate("wan0").expect_err("ownership conflict");
    assert!(error.to_string().contains("requires a managed input"));
}

#[test]
fn router_uplink_modes_preserve_explicit_ownership() {
    let mut config = valid_router_config();
    let wan = config.network.interfaces.get_mut("wan0").unwrap();
    wan.managed = true;
    wan.dhcp_client = Some(dhcp_client());
    config.router.uplink.as_mut().unwrap().mode = UplinkMode::Dhcp;
    config.validate().expect("DHCP-owned uplink");

    config.router.uplink.as_mut().unwrap().mode = UplinkMode::External;
    assert!(config
        .validate()
        .expect_err("external may not claim ownership")
        .to_string()
        .contains("external router uplink must be unmanaged"));

    config.router.uplink.as_mut().unwrap().mode = UplinkMode::Dhcp;
    config
        .network
        .interfaces
        .get_mut("wan0")
        .unwrap()
        .dhcp_client = None;
    assert!(config
        .validate()
        .expect_err("DHCP mode requires DHCP client")
        .to_string()
        .contains("enabled dhcp_client block"));
}

#[test]
fn an_ap_and_a_client_block_are_mutually_exclusive() {
    let mut config = client_interface(client_association("upstream"));
    config.role = InterfaceRole::Output;
    config.managed = true;
    config.wifi = Some(access_point());

    let error = config.validate("wlan0").expect_err("must be rejected");
    assert!(
        error.to_string().contains("cannot be both"),
        "expected the mutual-exclusion error specifically, got: {error}"
    );
}

/// A pre-`nat`-field `InterfaceConfig` (an upgrade from before this
/// field existed) must deserialize with NAT still on for every output —
/// today's behavior — not silently turn NAT off because the key is
/// missing.
#[test]
fn interface_config_without_a_nat_key_defaults_nat_to_true() {
    let toml = r#"
        role = "output"
        managed = true
        ipv4 = "192.168.10.1/24"
    "#;
    let interface: InterfaceConfig = toml::from_str(toml).expect("pre-nat fixture parses");
    assert!(
        interface.nat,
        "a config predating InterfaceConfig.nat must still get NAT on upgrade"
    );
}

/// A pre-`vpn_chain`-field `RouterConfig` (an upgrade from before the
/// hop chain existed) must deserialize with an empty chain, not fail to
/// parse or silently synthesize one at the `RouterConfig` level (that is
/// `migrate_vpn_policy_mode_to_chain`'s job, exercised separately).
#[test]
fn router_config_without_a_vpn_chain_key_defaults_to_an_empty_chain() {
    let toml = r#"
        enabled = true
        allow_default_route_change = false

        [uplink]
        interface = "wan0"
        mode = "external"
    "#;
    let router: RouterConfig = toml::from_str(toml).expect("pre-vpn_chain fixture parses");
    assert!(
        router.vpn_chain.is_empty(),
        "a config predating RouterConfig.vpn_chain must load with an empty chain"
    );
}

#[test]
fn vpn_chain_longer_than_the_cap_is_rejected() {
    let mut config = valid_router_config();
    config.router.vpn_chain = (0..=MAX_VPN_CHAIN_LEN)
        .map(|i| VpnHopConfig {
            profile_name: format!("hop{i}.conf"),
        })
        .collect();

    let error = config.validate().expect_err("chain longer than the cap");
    assert!(error.to_string().contains("exceeds the maximum"));
}

#[test]
fn unvalidated_load_preserves_recovery_paths_when_unrelated_admission_fails() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("config.toml");
    let mut config = AppConfig::default();
    config.runtime.state_dir = directory.path().join("state");
    config.auth.argon2_iterations = 0;
    std::fs::write(&path, toml::to_string_pretty(&config).unwrap()).expect("write config");

    let decoded = AppConfig::load_unvalidated(&path).expect("decode without admission");
    assert_eq!(decoded.runtime.state_dir, config.runtime.state_dir);
    assert!(decoded.validate().is_err());
    assert!(AppConfig::load(&path).is_err());
}

#[test]
fn router_recovery_validation_ignores_unrelated_auth_and_api_settings() {
    let mut config = AppConfig::default();
    config.auth.argon2_iterations = 0;
    config.api.tcp = Some(TcpApiConfig {
        enabled: true,
        listen: "127.0.0.1:9443".parse().unwrap(),
        certificate_path: Some("/tmp/same.pem".into()),
        private_key_path: Some("/tmp/same.pem".into()),
    });

    assert!(config.validate().is_err());
    config
        .validate_router_recovery()
        .expect("unrelated auth/API admission must not suppress router recovery");
}
