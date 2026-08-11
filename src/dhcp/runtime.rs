use std::collections::HashMap;
use std::io::{IoSlice, IoSliceMut};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket as StdUdpSocket};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;

use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use nix::net::if_::if_nametoindex;
#[cfg(target_os = "linux")]
use nix::sys::socket::{
    bind, recvmsg, sendmsg, setsockopt, socket, sockopt, AddressFamily, ControlMessage,
    ControlMessageOwned, MsgFlags, SockFlag, SockType, SockaddrIn,
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::dhcp::lease::DhcpLease;
use crate::dhcp::server::DhcpHandler;
use crate::dhcp::store::LeaseStore;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpRuntimeConfig {
    pub interface: Option<String>,
    pub bind_address: Ipv4Addr,
    pub response_address: Ipv4Addr,
    pub server_port: u16,
    pub client_port: u16,
    pub max_packet_size: usize,
}

impl Default for DhcpRuntimeConfig {
    fn default() -> Self {
        Self {
            interface: None,
            bind_address: Ipv4Addr::UNSPECIFIED,
            response_address: Ipv4Addr::BROADCAST,
            server_port: 67,
            client_port: 68,
            max_packet_size: 1500,
        }
    }
}

#[derive(Debug)]
pub struct DhcpRuntime {
    config: DhcpRuntimeConfig,
    handler: DhcpHandler,
    lease_store: Option<LeaseStore>,
}

impl DhcpRuntime {
    pub fn new(config: DhcpRuntimeConfig, handler: DhcpHandler) -> Self {
        Self {
            config,
            handler,
            lease_store: None,
        }
    }

    pub fn with_lease_store(mut self, lease_store: LeaseStore) -> Self {
        self.lease_store = Some(lease_store);
        self
    }

    pub async fn run(self) -> Result<()> {
        let socket = create_dhcp_socket(&self.config)?;
        self.run_with_socket(socket).await
    }

    pub async fn run_with_socket(mut self, socket: UdpSocket) -> Result<()> {
        loop {
            self.process_next_datagram(&socket).await?;
        }
    }

    pub async fn run_once(mut self) -> Result<()> {
        let socket = create_dhcp_socket(&self.config)?;
        self.process_next_datagram(&socket).await
    }

    pub async fn run_once_with_socket(mut self, socket: UdpSocket) -> Result<()> {
        self.process_next_datagram(&socket).await
    }

    pub async fn run_n_with_socket(mut self, socket: UdpSocket, packet_count: usize) -> Result<()> {
        for _ in 0..packet_count {
            self.process_next_datagram(&socket).await?;
        }
        Ok(())
    }

    async fn process_next_datagram(&mut self, socket: &UdpSocket) -> Result<()> {
        let mut buffer = vec![0_u8; self.config.max_packet_size];
        let (len, source) = socket.recv_from(&mut buffer).await?;
        let handled = match self.handler.handle_packet(&buffer[..len]) {
            Ok(Some(response)) => {
                let destination =
                    SocketAddrV4::new(self.config.response_address, self.config.client_port);
                socket.send_to(&response, destination).await?;
                true
            }
            Ok(None) => true,
            Err(error) => {
                tracing::warn!(%source, %error, "failed to handle DHCP packet");
                false
            }
        };
        if handled {
            if let Some(store) = &self.lease_store {
                store.save(&self.handler.lease_snapshot()).await?;
            }
        }
        Ok(())
    }
}

pub fn create_dhcp_socket(config: &DhcpRuntimeConfig) -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("failed to create DHCP UDP socket")?;
    socket
        .set_reuse_address(true)
        .context("failed to set SO_REUSEADDR")?;
    socket
        .set_broadcast(true)
        .context("failed to set SO_BROADCAST")?;
    let address = SockAddr::from(SocketAddrV4::new(config.bind_address, config.server_port));
    socket.bind(&address).with_context(|| {
        format!(
            "failed to bind DHCP socket to {}:{}",
            config.bind_address, config.server_port
        )
    })?;
    socket
        .set_nonblocking(true)
        .context("failed to set DHCP socket nonblocking")?;
    let std_socket: StdUdpSocket = socket.into();
    UdpSocket::from_std(std_socket).context("failed to convert DHCP socket to tokio UdpSocket")
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct SharedDhcpService {
    pub handler: DhcpHandler,
    pub lease_store: LeaseStore,
    pub server_ip: Ipv4Addr,

    pub persisted_leases: Vec<DhcpLease>,
}

#[cfg(target_os = "linux")]
impl SharedDhcpService {
    async fn persist_if_changed(&mut self) -> Result<()> {
        let current = self.handler.lease_snapshot();
        if current == self.persisted_leases {
            return Ok(());
        }
        self.lease_store.save(&current).await?;
        self.persisted_leases = current;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
pub(crate) struct SharedDhcpServices {
    inner: Arc<Mutex<HashMap<u32, SharedDhcpService>>>,
}

#[cfg(target_os = "linux")]
impl SharedDhcpServices {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn replace(&self, interface: &str, service: SharedDhcpService) -> Result<u32> {
        let ifindex = if_nametoindex(interface)
            .with_context(|| format!("failed to resolve interface index for {interface}"))?;
        let mut services = self.inner.lock().await;
        services.insert(ifindex, service);
        tracing::debug!(%interface, ifindex, service_count = services.len(), "registered shared DHCP service");
        Ok(ifindex)
    }

    pub async fn remove(&self, ifindex: u32) {
        self.inner.lock().await.remove(&ifindex);
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct SharedDhcpRuntime {
    socket: AsyncFd<OwnedFd>,
    services: SharedDhcpServices,
    config: DhcpRuntimeConfig,
}

#[cfg(target_os = "linux")]
impl SharedDhcpRuntime {
    pub fn bind(config: DhcpRuntimeConfig, services: SharedDhcpServices) -> Result<Self> {
        let fd = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
            None,
        )
        .context("failed to create shared DHCP socket")?;
        setsockopt(&fd, sockopt::ReuseAddr, &true).context("failed to set SO_REUSEADDR")?;
        setsockopt(&fd, sockopt::Broadcast, &true).context("failed to set SO_BROADCAST")?;
        setsockopt(&fd, sockopt::Ipv4PacketInfo, &true).context("failed to set IP_PKTINFO")?;
        let address = SockaddrIn::from(SocketAddrV4::new(config.bind_address, config.server_port));
        bind(fd.as_raw_fd(), &address).with_context(|| {
            format!(
                "failed to bind shared DHCP socket to {}:{}",
                config.bind_address, config.server_port
            )
        })?;
        Ok(Self {
            socket: AsyncFd::new(fd).context("failed to register shared DHCP socket")?,
            services,
            config,
        })
    }

    pub async fn run(self) -> Result<()> {
        let mut buffer = vec![0_u8; self.config.max_packet_size];
        loop {
            let (len, ifindex) = self.recv(&mut buffer).await?;
            self.dispatch(ifindex, &buffer[..len]).await;
        }
    }

    async fn recv(&self, buffer: &mut [u8]) -> Result<(usize, u32)> {
        loop {
            let mut ready = self.socket.readable().await?;
            let result = ready.try_io(|fd| {
                let mut iov = [IoSliceMut::new(buffer)];
                let mut cmsg = nix::cmsg_space!(nix::libc::in_pktinfo);
                let message = recvmsg::<SockaddrIn>(
                    fd.get_ref().as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsg),
                    MsgFlags::empty(),
                )?;
                let ifindex = message
                    .cmsgs()?
                    .find_map(|control| match control {
                        ControlMessageOwned::Ipv4PacketInfo(info) => Some(info.ipi_ifindex as u32),
                        _ => None,
                    })
                    .ok_or(nix::errno::Errno::ENOMSG)?;
                Ok((message.bytes, ifindex))
            });
            match result {
                Ok(value) => {
                    return value.context("failed to receive DHCP datagram with IP_PKTINFO")
                }
                Err(_would_block) => continue,
            }
        }
    }

    async fn dispatch(&self, ifindex: u32, packet: &[u8]) {
        let mut services = self.services.inner.lock().await;
        tracing::debug!(
            ifindex,
            service_count = services.len(),
            "received shared DHCP datagram"
        );
        let Some(service) = services.get_mut(&ifindex) else {
            tracing::debug!(ifindex, "ignoring DHCP packet from unconfigured interface");
            return;
        };
        let response = match service.handler.handle_packet(packet) {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(ifindex, %error, "failed to handle DHCP packet");
                return;
            }
        };
        if let Some(response) = response {
            let server_ip = service.server_ip;
            if let Err(error) = self.send(ifindex, server_ip, &response).await {
                tracing::warn!(ifindex, %error, "failed to send DHCP response");
                return;
            }
        }
        if let Err(error) = service.persist_if_changed().await {
            tracing::warn!(ifindex, %error, "failed to persist DHCP leases");
        }
    }

    async fn send(&self, ifindex: u32, server_ip: Ipv4Addr, packet: &[u8]) -> Result<()> {
        let destination = SockaddrIn::from(SocketAddrV4::new(
            self.config.response_address,
            self.config.client_port,
        ));
        let info = nix::libc::in_pktinfo {
            ipi_ifindex: ifindex as i32,
            ipi_spec_dst: nix::libc::in_addr {
                s_addr: u32::from_ne_bytes(server_ip.octets()),
            },
            ipi_addr: nix::libc::in_addr { s_addr: 0 },
        };
        loop {
            let mut ready = self.socket.writable().await?;
            let result = ready.try_io(|fd| {
                let iov = [IoSlice::new(packet)];
                Ok(sendmsg(
                    fd.get_ref().as_raw_fd(),
                    &iov,
                    &[ControlMessage::Ipv4PacketInfo(&info)],
                    MsgFlags::empty(),
                    Some(&destination),
                )?)
            });
            match result {
                Ok(value) => {
                    value.context("sendmsg DHCP response failed")?;
                    return Ok(());
                }
                Err(_would_block) => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_runtime_config_uses_dhcp_ports() {
        let config = DhcpRuntimeConfig::default();
        assert_eq!(config.server_port, 67);
        assert_eq!(config.client_port, 68);
        assert_eq!(config.bind_address, Ipv4Addr::UNSPECIFIED);
        assert_eq!(config.response_address, Ipv4Addr::BROADCAST);
        assert!(config.interface.is_none());
    }
}
