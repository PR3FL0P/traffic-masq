use super::*;

fn context() -> RouterProvisioningContext {
    let mut config = AppConfig::default();
    config.wifi.enabled = true;
    config.wifi_client.enabled = true;
    RouterProvisioningContext {
        effective_config: config,
        wifi_runtime_available: true,
        wifi_client_runtime_available: true,
        interfaces: BTreeMap::from([
            (
                "wlan-up".to_owned(),
                ProvisioningInterfaceObservation {
                    role: None,
                    wireless_phy: Some("phy1".to_owned()),
                },
            ),
            (
                "wlan-out".to_owned(),
                ProvisioningInterfaceObservation {
                    role: None,
                    wireless_phy: Some("phy2".to_owned()),
                },
            ),
        ]),
        known_networks: Vec::new(),
        runtime_ap_secrets: BTreeSet::from(["wlan-out".to_owned()]),
        runtime_sta_secrets: BTreeSet::from(["wlan-up".to_owned()]),
    }
}

fn desired() -> RouterProvisioningDesired {
    RouterProvisioningDesired {
        uplink: ProvisioningUplink {
            interface: "wlan-up".to_owned(),
            ssid: "upstream".to_owned(),
            country_code: None,
            security: WifiClientSecurity::Wpa2,
            passphrase_file: None,
        },
        output: ProvisioningOutput {
            interface: "wlan-out".to_owned(),
            ssid: "traffic-masq".to_owned(),
            country_code: None,
            band: WifiBand::Ghz2,
            channel: 6,
            channel_width: WifiChannelWidth::Ht20,
            security: WifiSecurity::Wpa2,
            hidden: false,
            client_isolation: false,
            max_stations: 32,
            passphrase_file: None,
        },
        downstream: ProvisioningDownstreamOverrides::default(),
        allow_management_change: false,
    }
}

/// Provisioning is gated on whether the daemon can actually drive Wi-Fi,
/// not on the `enabled` flag in the file — otherwise a box that started
/// with Wi-Fi off could never be provisioned as a router without a restart.
#[test]
fn provisioning_is_gated_on_the_runtime_not_on_the_config_flag() {
    let mut context = context();
    context.effective_config.wifi.enabled = false;
    context.effective_config.wifi_client.enabled = false;
    assert!(
        derive_router_provisioning(&desired(), &context).is_ok(),
        "the startup hint must not block provisioning"
    );

    let mut without_ap = context.clone();
    without_ap.wifi_runtime_available = false;
    assert_eq!(
        derive_router_provisioning(&desired(), &without_ap),
        Err(RouterProvisioningError::GlobalServiceDisabled { service: "wifi" })
    );

    let mut without_sta = context;
    without_sta.wifi_client_runtime_available = false;
    assert_eq!(
        derive_router_provisioning(&desired(), &without_sta),
        Err(RouterProvisioningError::GlobalServiceDisabled {
            service: "wifi_client"
        })
    );
}

#[test]
fn minimal_request_derives_and_applies_complete_dhcp_defaults() {
    let effective = derive_router_provisioning(&desired(), &context()).unwrap();

    assert_eq!(
        effective.output_interface.ipv4,
        Some("10.77.0.1/24".parse().unwrap())
    );
    let dhcp = effective.output_interface.dhcp.as_ref().unwrap();
    assert_eq!(dhcp.pool_start, Ipv4Addr::new(10, 77, 0, 100));
    assert_eq!(dhcp.pool_end, Ipv4Addr::new(10, 77, 0, 200));
    assert_eq!(dhcp.router, Ipv4Addr::new(10, 77, 0, 1));
    assert!(dhcp.dns_servers.is_empty());
    assert_eq!(dhcp.lease_seconds, Some(DEFAULT_DHCP_LEASE_SECONDS));
    assert_eq!(
        effective.uplink_interface.dhcp_client.as_ref().unwrap(),
        &DhcpClientInterfaceConfig::default()
    );
    assert_eq!(
        effective.router.uplink.as_ref().unwrap().mode,
        UplinkMode::Dhcp
    );
    assert_eq!(
        effective.router.forwarding,
        Some(vec![ForwardingConfig {
            source_subnet: None,
            from: "wlan-out".to_string(),
            to: "wlan-up".to_string(),
            masquerade: true,
        }])
    );
    let _proposal = effective.into_router_intent_proposal();
}

#[test]
fn conflicting_default_selects_next_documented_candidate() {
    let mut context = context();
    context.known_networks.push(ProvisioningKnownNetwork {
        network: "10.77.0.0/24".parse().unwrap(),
        source: "management eth0".to_owned(),
    });

    let effective = derive_router_provisioning(&desired(), &context).unwrap();
    assert_eq!(
        effective.output_interface.ipv4,
        Some("10.77.1.1/24".parse().unwrap())
    );
}

#[test]
fn explicit_conflict_is_typed_and_never_silently_replaced() {
    let mut context = context();
    context.known_networks.push(ProvisioningKnownNetwork {
        network: "192.168.1.0/24".parse().unwrap(),
        source: "DHCP uplink lease".to_owned(),
    });
    let mut desired = desired();
    desired.downstream.interface_ipv4 = Some("192.168.1.1/24".parse().unwrap());

    assert_eq!(
        derive_router_provisioning(&desired, &context).unwrap_err(),
        RouterProvisioningError::SubnetConflict {
            requested: "192.168.1.0/24".parse().unwrap(),
            conflicting: "192.168.1.0/24".parse().unwrap(),
            conflict_source: "DHCP uplink lease".to_owned(),
        }
    );
}

#[test]
fn protected_network_requires_secret_availability_before_derivation() {
    let mut context = context();
    context.runtime_ap_secrets.clear();

    assert_eq!(
        derive_router_provisioning(&desired(), &context).unwrap_err(),
        RouterProvisioningError::MissingOutputSecret {
            interface: "wlan-out".to_owned(),
        }
    );
}

#[test]
fn same_phy_is_rejected_even_when_interface_names_differ() {
    let mut context = context();
    context.interfaces.get_mut("wlan-out").unwrap().wireless_phy = Some("phy1".to_owned());

    assert_eq!(
        derive_router_provisioning(&desired(), &context).unwrap_err(),
        RouterProvisioningError::RadioReused {
            phy: "phy1".to_owned(),
            uplink: "wlan-up".to_owned(),
            output: "wlan-out".to_owned(),
        }
    );
}

#[test]
fn management_role_requires_explicit_confirmation() {
    let mut context = context();
    context.interfaces.get_mut("wlan-up").unwrap().role = Some(InterfaceRole::None);

    assert_eq!(
        derive_router_provisioning(&desired(), &context).unwrap_err(),
        RouterProvisioningError::ManagementConfirmationRequired {
            interface: "wlan-up".to_owned(),
        }
    );
}

#[test]
fn provisioning_checks_existing_allocations_beyond_the_selected_pair() {
    let mut context = context();
    let existing: InterfaceConfig = serde_json::from_value(serde_json::json!({
        "managed": true, "role": "output", "ipv4": "192.168.90.1/24",
        "wifi": {"ssid": "existing-ap", "channel": 6, "security": "open"}
    }))
    .unwrap();
    context
        .effective_config
        .network
        .interfaces
        .insert("existing-ap".into(), existing);
    context.interfaces.insert(
        "existing-ap".into(),
        ProvisioningInterfaceObservation {
            role: Some(InterfaceRole::Output),
            wireless_phy: Some("phy1".into()),
        },
    );
    assert_eq!(
        derive_router_provisioning(&desired(), &context).unwrap_err(),
        RouterProvisioningError::RadioReused {
            phy: "phy1".into(),
            uplink: "wlan-up".into(),
            output: "existing-ap".into(),
        }
    );
}
