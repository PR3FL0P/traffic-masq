use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
use tempfile::tempdir;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use traffic_masq::dhcp::lease::{LeaseManager, LeasePoolConfig};
use traffic_masq::dhcp::packet::{DhcpMessageType, DhcpPacket, DHCP_MAGIC_COOKIE};
use traffic_masq::dhcp::runtime::{create_dhcp_socket, DhcpRuntime, DhcpRuntimeConfig};
use traffic_masq::dhcp::server::{DhcpHandler, DhcpServerConfig};
use traffic_masq::dhcp::store::LeaseStore;

#[tokio::test]
async fn udp_runtime_serves_discover_and_request() -> Result<()> {
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let client_port = client.local_addr()?.port();

    let runtime_config = DhcpRuntimeConfig {
        interface: None,
        bind_address: Ipv4Addr::LOCALHOST,
        response_address: Ipv4Addr::LOCALHOST,
        server_port: 0,
        client_port,
        max_packet_size: 1500,
    };

    let server_socket = create_dhcp_socket(&runtime_config)?;
    let server_address = server_socket.local_addr()?;
    let lease_dir = tempdir()?;
    let lease_store = LeaseStore::for_interface(lease_dir.path(), "loopback-test");
    let runtime =
        DhcpRuntime::new(runtime_config, handler()?).with_lease_store(lease_store.clone());

    let server_task = tokio::spawn(runtime.run_n_with_socket(server_socket, 2));

    let discover = request_packet(DhcpMessageType::Discover, None);
    client.send_to(&discover, server_address).await?;
    let offer = receive_packet(&client).await?;
    let offer = DhcpPacket::parse(&offer)?;
    assert_eq!(offer.message_type(), Some(DhcpMessageType::Offer));
    let offered_ip = offer.yiaddr;
    assert_eq!(offered_ip, Ipv4Addr::new(192, 168, 77, 100));

    let request = request_packet(DhcpMessageType::Request, Some(offered_ip));
    client.send_to(&request, server_address).await?;
    let ack = receive_packet(&client).await?;
    let ack = DhcpPacket::parse(&ack)?;
    assert_eq!(ack.message_type(), Some(DhcpMessageType::Ack));
    assert_eq!(ack.yiaddr, offered_ip);

    timeout(Duration::from_secs(2), server_task)
        .await
        .context("DHCP runtime task did not finish")???;

    let persisted = lease_store.load().await?;
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].ip, offered_ip);

    Ok(())
}

fn handler() -> Result<DhcpHandler> {
    let leases = LeaseManager::new(LeasePoolConfig {
        start: Ipv4Addr::new(192, 168, 77, 100),
        end: Ipv4Addr::new(192, 168, 77, 110),
        lease_time: Duration::from_secs(3600),
    })?;

    Ok(DhcpHandler::new(
        DhcpServerConfig {
            server_ip: Ipv4Addr::new(192, 168, 77, 1),
            router: Ipv4Addr::new(192, 168, 77, 1),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
        },
        leases,
    ))
}

fn request_packet(message_type: DhcpMessageType, requested_ip: Option<Ipv4Addr>) -> Vec<u8> {
    let mut packet = vec![0_u8; 240];
    packet[0] = 1;
    packet[1] = 1;
    packet[2] = 6;
    packet[4..8].copy_from_slice(&0xaabb_ccdd_u32.to_be_bytes());
    packet[28..34].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
    packet.extend_from_slice(&[53, 1, message_type.as_u8()]);

    if let Some(ip) = requested_ip {
        packet.extend_from_slice(&[50, 4]);
        packet.extend_from_slice(&ip.octets());
    }

    packet.push(255);
    packet
}

async fn receive_packet(socket: &UdpSocket) -> Result<Vec<u8>> {
    let mut buffer = vec![0_u8; 1500];
    let (len, source) = timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
        .await
        .context("timed out waiting for DHCP response")??;

    assert!(matches!(source, SocketAddr::V4(_)));
    buffer.truncate(len);
    Ok(buffer)
}
