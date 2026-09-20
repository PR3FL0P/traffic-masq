use crate::config::{InterfaceRole, UplinkConfig, UplinkMode};

use super::*;

fn base_config() -> AppConfig {
    AppConfig::default()
}

/// The converger has no timer any more, so a change that does not announce
/// itself is a change that never gets applied.
fn interface_config(address: &str) -> InterfaceConfig {
    InterfaceConfig {
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some(address.parse().expect("network")),
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
        nat: true,
    }
}

/// A successful, self-contained mutation, for tests that need the store to
/// change but do not care what changed. `set_dhcp` used to serve this role.

#[test]
fn effective_config_applies_api_override() {
    let mut base = base_config();
    base.api.tcp = Some(crate::config::TcpApiConfig {
        enabled: false,
        listen: "127.0.0.1:8443".parse().expect("socket address"),
        certificate_path: None,
        private_key_path: None,
    });

    let overrides = RuntimeOverrides {
        api: Some(ApiConfig {
            tcp: Some(crate::config::TcpApiConfig {
                enabled: true,
                listen: "192.0.2.10:9443".parse().expect("socket address"),
                certificate_path: Some("/etc/traffic-masq/server.pem".into()),
                private_key_path: Some("/etc/traffic-masq/server-key.pem".into()),
            }),
        }),
        ..RuntimeOverrides::default()
    };

    let effective = overrides.effective_config(&base).expect("effective config");
    let tcp = effective.api.tcp.expect("api tcp");
    assert!(tcp.enabled);
    assert_eq!(
        tcp.listen,
        "192.0.2.10:9443".parse().expect("socket address")
    );
}

#[test]
fn effective_config_revalidates_router_against_interface_overrides() {
    let mut base = base_config();
    base.network.interfaces.insert(
        "wan0".to_string(),
        InterfaceConfig {
            role: InterfaceRole::Input,
            managed: false,
            ipv4: None,
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
            nat: true,
        },
    );
    base.network
        .interfaces
        .insert("lan0".to_string(), interface_config("192.168.10.1/24"));
    base.router.enabled = true;
    base.router.uplink = Some(UplinkConfig {
        interface: "wan0".to_string(),
        mode: UplinkMode::External,
    });
    base.validate().expect("base router config");

    let mut overrides = RuntimeOverrides::default();
    overrides.interfaces.insert(
        "wan0".to_string(),
        InterfaceOverride {
            config: InterfaceConfig {
                role: InterfaceRole::None,
                managed: false,
                ipv4: None,
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
                nat: true,
            },
            allow_management_change: true,
        },
    );

    assert!(overrides.effective_network(&base.network).is_ok());
    assert!(overrides.effective_config(&base).is_err());
}
