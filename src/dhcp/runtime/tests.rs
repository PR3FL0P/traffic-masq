use super::*;
#[cfg(target_os = "linux")]
use crate::dhcp::packet::DhcpMessageType;
#[cfg(target_os = "linux")]
use crate::dhcp::server::DhcpServerConfig;

#[cfg(target_os = "linux")]
#[tokio::test]
async fn shared_dhcp_persistence_failure_rolls_back_lease_allocation() {
    use std::time::Duration;

    let directory = tempfile::tempdir().expect("tempdir");
    let blocked_parent = directory.path().join("not-a-directory");
    std::fs::write(&blocked_parent, b"block").expect("block parent");
    let leases = crate::dhcp::lease::LeaseManager::new(crate::dhcp::lease::LeasePoolConfig {
        start: Ipv4Addr::new(192, 168, 50, 100),
        end: Ipv4Addr::new(192, 168, 50, 110),
        lease_time: Duration::from_secs(3600),
    })
    .expect("lease pool");
    let mut service = SharedDhcpService {
        handler: DhcpHandler::new(
            DhcpServerConfig {
                server_ip: Ipv4Addr::new(192, 168, 50, 1),
                router: Ipv4Addr::new(192, 168, 50, 1),
                subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
                dns_servers: vec![],
            },
            leases,
        ),
        lease_store: LeaseStore::for_interface(&blocked_parent, "wlan0"),
        server_ip: Ipv4Addr::new(192, 168, 50, 1),
        persisted_leases: vec![],
    };
    let before = service.handler.lease_snapshot();
    let mut discover = vec![0_u8; 240];
    discover[0] = 1;
    discover[1] = 1;
    discover[2] = 6;
    discover[4..8].copy_from_slice(&1_u32.to_be_bytes());
    discover[28..34].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    discover[236..240].copy_from_slice(&crate::dhcp::packet::DHCP_MAGIC_COOKIE);
    discover.extend_from_slice(&[53, 1, DhcpMessageType::Discover.as_u8(), 255]);

    service
        .handle_and_persist(&discover)
        .await
        .expect_err("invalid lease store must abort the DHCP packet transaction");
    assert_eq!(service.handler.lease_snapshot(), before);
    assert!(service.persisted_leases.is_empty());
}

#[test]
fn default_runtime_config_uses_dhcp_ports() {
    let config = DhcpRuntimeConfig::default();
    assert_eq!(config.server_port, 67);
    assert_eq!(config.client_port, 68);
    assert_eq!(config.bind_address, Ipv4Addr::UNSPECIFIED);
    assert_eq!(config.response_address, Ipv4Addr::BROADCAST);
    assert!(config.interface.is_none());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn occupied_udp_port_reports_its_owner_without_stopping_it() {
    let listener = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let config = DhcpRuntimeConfig {
        bind_address: Ipv4Addr::LOCALHOST,
        server_port: listener.local_addr().unwrap().port(),
        ..DhcpRuntimeConfig::default()
    };
    let error = create_dhcp_socket(&config).unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains(&format!("PID {}", std::process::id())));
    assert!(message.contains("sudo ss -lunp"));
    assert!(message.contains("will not stop another service"));
    assert!(error.chain().any(|cause| cause
        .downcast_ref::<std::io::Error>()
        .is_some_and(|io| io.kind() == std::io::ErrorKind::AddrInUse)));
    assert!(listener.local_addr().is_ok());
}

#[test]
fn bind_permission_and_address_failures_do_not_claim_a_foreign_listener() {
    let config = DhcpRuntimeConfig::default();
    let permission = super::dhcp_bind_advice(&config, Some(nix::libc::EACCES));
    assert!(permission.contains("permission denial does not prove"));
    assert!(!permission.contains("systemctl stop"));
    let address = super::dhcp_bind_advice(&config, Some(nix::libc::EADDRNOTAVAIL));
    assert!(address.contains("network namespace"));
    assert!(!address.contains("listener candidates"));
}
