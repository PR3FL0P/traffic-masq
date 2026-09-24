#[tokio::test]
async fn saturated_unix_listener_stops_with_idle_clients() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let (stop, shutdown) = watch::channel(false);
    let server = tokio::spawn(run_unix_accept_loop(listener, Router::new(), shutdown));
    let mut clients = Vec::new();
    for _ in 0..MAX_CONCURRENT_UNIX_CONNECTIONS {
        clients.push(UnixStream::connect(&path).await.unwrap());
    }
    let mut excess = UnixStream::connect(&path).await.unwrap();
    excess
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut byte = [0];
    assert!(timeout(Duration::from_millis(50), excess.read(&mut byte))
        .await
        .is_err());
    stop.send(true).unwrap();
    timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn shutdown_interrupts_an_incomplete_handshake() {
    let (stop, shutdown) = watch::channel(false);
    let task = tokio::spawn(until_shutdown(std::future::pending(), shutdown));
    stop.send(true).unwrap();
    timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

use std::net::Ipv4Addr;

use super::*;
use crate::config::InterfaceRole;

fn principal(role: Role) -> Principal {
    Principal {
        user_id: 1,
        username: "test-user".to_owned(),
        role,
    }
}

fn interface_config() -> InterfaceConfig {
    InterfaceConfig {
        nat: true,
        role: InterfaceRole::Output,
        managed: true,
        ipv4: None,
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    }
}

fn dhcp_config() -> DhcpInterfaceConfig {
    DhcpInterfaceConfig {
        pool_start: Ipv4Addr::new(192, 0, 2, 10),
        pool_end: Ipv4Addr::new(192, 0, 2, 20),
        router: Ipv4Addr::new(192, 0, 2, 1),
        dns_servers: Vec::new(),
        lease_seconds: None,
    }
}

fn interface_edit() -> InterfaceEditRequest {
    InterfaceEditRequest {
        cidr: "192.0.2.1/24".to_owned(),
        role: InterfaceRole::Output,
        managed: true,
        allow_management_change: false,
    }
}

fn dhcp_edit() -> DhcpEditRequest {
    DhcpEditRequest {
        pool_start: Ipv4Addr::new(192, 0, 2, 10),
        pool_end: Ipv4Addr::new(192, 0, 2, 20),
        router: Ipv4Addr::new(192, 0, 2, 1),
        dns_servers: Vec::new(),
        lease_seconds: None,
    }
}

fn api_https_settings() -> ApiHttpsSettings {
    ApiHttpsSettings {
        enabled: true,
        listen: "0.0.0.0:9443".to_owned(),
        certificate_path: Some("/etc/traffic-masq/server.pem".to_owned()),
        private_key_path: Some("/etc/traffic-masq/server-key.pem".to_owned()),
    }
}

#[test]
fn dhcp_client_routes_allow_viewer_gets_and_require_admin_for_every_mutation() {
    for request in [
        Request::DhcpClientStatus,
        Request::GetDhcpClient {
            interface: "wan0".into(),
        },
    ] {
        assert!(authorize_control_request(&principal(Role::Viewer), &request).is_ok());
        assert!(authorize_control_request(&principal(Role::Administrator), &request).is_ok());
    }
    for request in [
        Request::ConfigureDhcpClient {
            interface: "wan0".into(),
            config: DhcpClientConfigRequest::default(),
        },
        Request::DisableDhcpClient {
            interface: "wan0".into(),
        },
        Request::RenewDhcpClient {
            interface: "wan0".into(),
        },
        Request::ReleaseDhcpClient {
            interface: "wan0".into(),
        },
    ] {
        assert!(matches!(
            authorize_control_request(&principal(Role::Viewer), &request),
            Err(ApiError::Forbidden)
        ));
        assert!(matches!(
            authorize_control_request(&principal(Role::Operator), &request),
            Err(ApiError::Forbidden)
        ));
        assert!(authorize_control_request(&principal(Role::Administrator), &request).is_ok());
    }
}

#[test]
fn every_control_request_has_the_expected_authorization_class() {
    let read_requests = [
        Request::Ping,
        Request::GetVpnConfig,
        Request::GetApiHttpsConfig,
        Request::ListInterfaces,
        Request::DhcpStatus,
        Request::DhcpClientStatus,
        Request::GetDhcpClient {
            interface: "wan0".to_owned(),
        },
        Request::GetDhcpConfig {
            interface: "eth0".to_owned(),
        },
        Request::ListLeases {
            interface: "eth0".to_owned(),
        },
        Request::DryRunInterface {
            interface: "eth0".to_owned(),
            config: interface_config(),
            allow_management_change: false,
        },
        Request::DryRunInterfaceEdit {
            interface: "eth0".to_owned(),
            edit: interface_edit(),
        },
        Request::PendingNetworkChanges,
        Request::VpnPolicyStatus,
        Request::GetSecurityConfig,
        Request::WifiClientStatus,
        Request::GetWifiClientConfig {
            interface: "wlan0".to_owned(),
        },
        Request::ListWifiClientProfiles,
        Request::GetWifiClientProfile {
            id: "office".to_owned(),
        },
    ];
    for request in read_requests {
        assert!(!control_request_requires_administrator(&request));
        assert!(authorize_control_request(&principal(Role::Viewer), &request).is_ok());
        assert!(authorize_control_request(&principal(Role::Operator), &request).is_ok());
    }

    let mutation_requests = [
        Request::ConfigureApiHttpsSettings {
            settings: api_https_settings(),
        },
        Request::ResetApiHttpsSettings,
        Request::ConfigureDhcp {
            interface: "eth0".to_owned(),
            config: dhcp_config(),
        },
        Request::ConfigureDhcpSettings {
            interface: "eth0".to_owned(),
            settings: dhcp_edit(),
        },
        Request::DisableDhcp {
            interface: "eth0".to_owned(),
        },
        Request::ConfigureDhcpClient {
            interface: "wan0".to_owned(),
            config: DhcpClientConfigRequest::default(),
        },
        Request::DisableDhcpClient {
            interface: "wan0".to_owned(),
        },
        Request::RenewDhcpClient {
            interface: "wan0".to_owned(),
        },
        Request::ReleaseDhcpClient {
            interface: "wan0".to_owned(),
        },
        Request::ApplyInterface {
            interface: "eth0".to_owned(),
            config: interface_config(),
            allow_management_change: false,
        },
        Request::ApplyInterfaceEdit {
            interface: "eth0".to_owned(),
            edit: interface_edit(),
        },
        Request::CommitNetworkChange {
            token: "transaction-token".to_owned(),
        },
        Request::RollbackNetworkChange {
            token: "transaction-token".to_owned(),
        },
        Request::SetVpnEnabled { enabled: true },
        Request::VpnPolicySetMode {
            mode: crate::config::VpnPolicyMode::Direct,
        },
        Request::VpnPolicyClearMode,
        Request::ConfigureSecuritySettings {
            settings: SecuritySettings {
                rollback_timeout_seconds: 60,
            },
        },
        Request::ResetSecuritySettings,
        Request::ProvisionWifiAccessPoint {
            interface: "wlan0".to_owned(),
            settings: WifiEditRequest {
                ssid: "provisioned".to_owned(),
                country_code: None,
                band: Default::default(),
                channel: 0,
                channel_width: Default::default(),
                security: Default::default(),
                hidden: false,
                client_isolation: false,
                max_stations: 32,
            },
            passphrase: Some("write-only-secret".into()),
            clear_passphrase: false,
            configure_dhcp: true,
        },
        Request::ConfigureWifiClient {
            interface: "wlan0".to_owned(),
            settings: WifiClientEditRequest {
                ssid: "upstream".to_owned(),
                country_code: None,
                security: crate::config::WifiClientSecurity::Open,
            },
        },
        Request::DisableWifiClient {
            interface: "wlan0".to_owned(),
        },
        Request::WifiClientSetPassphrase {
            interface: "wlan0".to_owned(),
            passphrase: "a-secret-value".to_owned(),
        },
        Request::WifiClientReconnect {
            interface: "wlan0".to_owned(),
        },
        Request::WifiClientScan {
            interface: "wlan0".to_owned(),
        },
        Request::CreateWifiClientProfile {
            profile: WifiClientProfileWriteRequest {
                id: "office".to_owned(),
                ssid: "upstream".to_owned(),
                country_code: None,
                security: crate::config::WifiClientSecurity::Open,
                priority: 0,
                autoconnect: false,
                passphrase: None,
                clear_passphrase: false,
            },
        },
        Request::UpdateWifiClientProfile {
            id: "office".to_owned(),
            profile: WifiClientProfileWriteRequest {
                id: "office".to_owned(),
                ssid: "updated".to_owned(),
                country_code: None,
                security: crate::config::WifiClientSecurity::Open,
                priority: 1,
                autoconnect: false,
                passphrase: None,
                clear_passphrase: false,
            },
        },
        Request::DeleteWifiClientProfile {
            id: "office".to_owned(),
        },
        Request::ActivateWifiClientProfile {
            interface: "wlan0".to_owned(),
            profile_id: "office".to_owned(),
        },
        Request::DeactivateWifiClientProfile {
            interface: "wlan0".to_owned(),
        },
    ];
    for request in mutation_requests {
        assert!(control_request_requires_administrator(&request));
        assert!(matches!(
            authorize_control_request(&principal(Role::Viewer), &request),
            Err(ApiError::Forbidden)
        ));
        assert!(matches!(
            authorize_control_request(&principal(Role::Operator), &request),
            Err(ApiError::Forbidden)
        ));
        assert!(authorize_control_request(&principal(Role::Administrator), &request).is_ok());
    }
}

#[test]
fn first_time_initialization_accepts_only_local_root_connections() {
    assert!(ConnectionInfo::Unix {
        pid: Some(1),
        uid: Some(0),
        gid: Some(0),
    }
    .is_local_root());
    assert!(!ConnectionInfo::Unix {
        pid: Some(1000),
        uid: Some(1000),
        gid: Some(1000),
    }
    .is_local_root());
    assert!(!ConnectionInfo::Tls {
        peer: "127.0.0.1:12345".parse().expect("peer"),
    }
    .is_local_root());
}

#[test]
fn bearer_header_parser_is_strict_and_case_insensitive() {
    use axum::http::HeaderValue;

    assert_eq!(
        bearer_token(Some(&HeaderValue::from_static("Bearer opaque-token"))),
        Some("opaque-token")
    );
    assert_eq!(
        bearer_token(Some(&HeaderValue::from_static("bearer opaque-token"))),
        Some("opaque-token")
    );
    assert_eq!(
        bearer_token(Some(&HeaderValue::from_static("Basic opaque-token"))),
        None
    );
    assert_eq!(
        bearer_token(Some(&HeaderValue::from_static("Bearer one two"))),
        None
    );
}
