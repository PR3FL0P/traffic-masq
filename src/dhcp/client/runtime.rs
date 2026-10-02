use std::ffi::OsString;
use std::io::{IoSlice, IoSliceMut};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use nix::sys::socket::{
    bind, recvmsg, sendmsg, setsockopt, socket, sockopt, AddressFamily, ControlMessage,
    ControlMessageOwned, MsgFlags, SockFlag, SockType, SockaddrIn,
};
use rand::Rng;
use tokio::io::unix::AsyncFd;
use tokio::sync::watch;

use super::state_machine::{Action, DhcpClientStateMachine, Lease, MonotonicTime, SendKind};

pub const DHCP_SERVER_PORT: u16 = 67;
pub const DHCP_CLIENT_PORT: u16 = 68;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpClientRuntimeConfig {
    pub interface: String,
    pub interface_index: u32,
    pub hardware_address: [u8; 6],
    pub server_port: u16,
    pub client_port: u16,
    pub max_packet_size: usize,
}

impl DhcpClientRuntimeConfig {
    pub fn new(
        interface: impl Into<String>,
        interface_index: u32,
        hardware_address: [u8; 6],
    ) -> Self {
        Self {
            interface: interface.into(),
            interface_index,
            hardware_address,
            server_port: DHCP_SERVER_PORT,
            client_port: DHCP_CLIENT_PORT,
            max_packet_size: 1500,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.interface.is_empty() || self.interface.as_bytes().contains(&0) {
            bail!("invalid DHCP client interface name");
        }
        if self.interface_index == 0 {
            bail!("DHCP client interface index must be nonzero");
        }
        if self.max_packet_size < 576 {
            bail!("DHCP client packet buffer must be at least 576 bytes");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressDatagram {
    pub bytes: Vec<u8>,
    pub interface_index: u32,
}

#[async_trait]
pub trait DhcpClientTransport: Send + Sync {
    async fn receive(&self) -> Result<IngressDatagram>;
    async fn send(&self, packet: &[u8], kind: SendKind) -> Result<()>;
}

#[async_trait]
pub trait DuplicateAddressDetector: Send + Sync {
    async fn is_duplicate(
        &self,
        interface: &str,
        interface_index: u32,
        address: Ipv4Addr,
    ) -> Result<bool>;
}

#[derive(Debug, Default)]
pub struct UnavailableDad;

#[async_trait]
impl DuplicateAddressDetector for UnavailableDad {
    async fn is_duplicate(
        &self,
        _interface: &str,
        _interface_index: u32,
        _address: Ipv4Addr,
    ) -> Result<bool> {
        bail!("active ARP duplicate-address detection is unavailable")
    }
}

const ARP_FRAME_LEN: usize = 42;
const ARP_PROBE_COUNT: usize = 3;
const ARP_PROBE_WAIT_MAX: Duration = Duration::from_secs(1);
const ARP_PROBE_MIN: Duration = Duration::from_secs(1);
const ARP_PROBE_MAX: Duration = Duration::from_secs(2);
const ARP_ANNOUNCE_WAIT: Duration = Duration::from_secs(2);

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
pub struct LinuxArpDad {
    hardware_address: [u8; 6],
}

#[cfg(target_os = "linux")]
impl LinuxArpDad {
    pub fn new(hardware_address: [u8; 6]) -> Result<Self> {
        validate_hardware_address(hardware_address)?;
        Ok(Self { hardware_address })
    }
}

fn validate_hardware_address(address: [u8; 6]) -> Result<()> {
    if address == [0; 6] || address == [0xff; 6] || address[0] & 1 != 0 {
        bail!("ARP duplicate-address detection requires a unicast hardware address");
    }
    Ok(())
}

fn arp_probe(source: [u8; 6], candidate: Ipv4Addr) -> [u8; ARP_FRAME_LEN] {
    let mut frame = [0u8; ARP_FRAME_LEN];
    frame[..6].fill(0xff);
    frame[6..12].copy_from_slice(&source);
    frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    frame[14..16].copy_from_slice(&1u16.to_be_bytes());
    frame[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
    frame[18] = 6;
    frame[19] = 4;
    frame[20..22].copy_from_slice(&1u16.to_be_bytes());
    frame[22..28].copy_from_slice(&source);

    frame[32..38].fill(0);
    frame[38..42].copy_from_slice(&candidate.octets());
    frame
}

fn arp_conflicts(frame: &[u8], own_mac: [u8; 6], candidate: Ipv4Addr) -> bool {
    if frame.len() < ARP_FRAME_LEN
        || frame[12..14] != 0x0806u16.to_be_bytes()
        || frame[14..16] != 1u16.to_be_bytes()
        || frame[16..18] != 0x0800u16.to_be_bytes()
        || frame[18] != 6
        || frame[19] != 4
        || !matches!(u16::from_be_bytes([frame[20], frame[21]]), 1 | 2)
        || frame[6..12] != frame[22..28]
        || frame[22..28] == own_mac
    {
        return false;
    }
    let sender = Ipv4Addr::new(frame[28], frame[29], frame[30], frame[31]);
    let target = Ipv4Addr::new(frame[38], frame[39], frame[40], frame[41]);
    sender == candidate || (sender.is_unspecified() && target == candidate)
}

#[async_trait]
trait ArpPacketIo: Send + Sync {
    async fn send(&self, frame: &[u8]) -> Result<()>;
    async fn receive_until(&self, deadline: Instant) -> Result<Option<Vec<u8>>>;
}

async fn probe_with_io(
    io: &dyn ArpPacketIo,
    hardware_address: [u8; 6],
    candidate: Ipv4Addr,
) -> Result<bool> {
    let initial_wait = random_duration(Duration::ZERO, ARP_PROBE_WAIT_MAX);
    let intervals = std::array::from_fn(|_| random_duration(ARP_PROBE_MIN, ARP_PROBE_MAX));
    probe_with_io_timing(io, hardware_address, candidate, initial_wait, intervals).await
}

async fn probe_with_io_timing(
    io: &dyn ArpPacketIo,
    hardware_address: [u8; 6],
    candidate: Ipv4Addr,
    initial_wait: Duration,
    intervals: [Duration; ARP_PROBE_COUNT - 1],
) -> Result<bool> {
    let probe = arp_probe(hardware_address, candidate);
    let deadline = Instant::now() + initial_wait;
    while let Some(frame) = io.receive_until(deadline).await? {
        if arp_conflicts(&frame, hardware_address, candidate) {
            return Ok(true);
        }
    }
    for probe_index in 0..ARP_PROBE_COUNT {
        io.send(&probe).await?;
        let wait = intervals
            .get(probe_index)
            .copied()
            .unwrap_or(ARP_ANNOUNCE_WAIT);
        let deadline = Instant::now() + wait;
        while let Some(frame) = io.receive_until(deadline).await? {
            if arp_conflicts(&frame, hardware_address, candidate) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn random_duration(min: Duration, max: Duration) -> Duration {
    let min_millis = min.as_millis() as u64;
    let max_millis = max.as_millis() as u64;
    Duration::from_millis(rand::thread_rng().gen_range(min_millis..=max_millis))
}

#[cfg(target_os = "linux")]
struct LinuxArpSocket(AsyncFd<OwnedFd>);

#[cfg(target_os = "linux")]
impl LinuxArpSocket {
    fn bind(interface_index: u32) -> Result<Self> {
        let protocol = (nix::libc::ETH_P_ARP as u16).to_be() as i32;
        let raw = unsafe {
            nix::libc::socket(
                nix::libc::AF_PACKET,
                nix::libc::SOCK_RAW | nix::libc::SOCK_NONBLOCK | nix::libc::SOCK_CLOEXEC,
                protocol,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to create ARP packet socket");
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let address = nix::libc::sockaddr_ll {
            sll_family: nix::libc::AF_PACKET as u16,
            sll_protocol: (nix::libc::ETH_P_ARP as u16).to_be(),
            sll_ifindex: interface_index as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let result = unsafe {
            nix::libc::bind(
                fd.as_raw_fd(),
                (&address as *const nix::libc::sockaddr_ll).cast(),
                std::mem::size_of_val(&address) as nix::libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to bind ARP packet socket to interface");
        }
        Ok(Self(
            AsyncFd::new(fd).context("failed to register ARP packet socket")?,
        ))
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl ArpPacketIo for LinuxArpSocket {
    async fn send(&self, frame: &[u8]) -> Result<()> {
        loop {
            let mut ready = self.0.writable().await?;
            match ready.try_io(|fd| {
                let sent = unsafe {
                    nix::libc::send(
                        fd.get_ref().as_raw_fd(),
                        frame.as_ptr().cast(),
                        frame.len(),
                        0,
                    )
                };
                if sent < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(sent as usize)
                }
            }) {
                Ok(Ok(sent)) if sent == frame.len() => return Ok(()),
                Ok(Ok(sent)) => bail!("short ARP frame send: {sent} of {} bytes", frame.len()),
                Ok(Err(error)) => return Err(error).context("failed to send ARP probe"),
                Err(_) => continue,
            }
        }
    }

    async fn receive_until(&self, deadline: Instant) -> Result<Option<Vec<u8>>> {
        let deadline = tokio::time::Instant::from_std(deadline);
        loop {
            let mut ready = match tokio::time::timeout_at(deadline, self.0.readable()).await {
                Ok(ready) => ready?,
                Err(_) => return Ok(None),
            };
            let mut frame = vec![0u8; 2048];
            match ready.try_io(|fd| {
                let received = unsafe {
                    nix::libc::recv(
                        fd.get_ref().as_raw_fd(),
                        frame.as_mut_ptr().cast(),
                        frame.len(),
                        0,
                    )
                };
                if received < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(received as usize)
                }
            }) {
                Ok(Ok(received)) => {
                    frame.truncate(received);
                    return Ok(Some(frame));
                }
                Ok(Err(error)) => return Err(error).context("failed to receive ARP packet"),
                Err(_) => continue,
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl DuplicateAddressDetector for LinuxArpDad {
    async fn is_duplicate(
        &self,
        interface: &str,
        interface_index: u32,
        address: Ipv4Addr,
    ) -> Result<bool> {
        if interface.is_empty() || interface.as_bytes().contains(&0) || interface_index == 0 {
            bail!("invalid interface for ARP duplicate-address detection");
        }
        let name = std::ffi::CString::new(interface).context("invalid interface name")?;
        let actual_index = unsafe { nix::libc::if_nametoindex(name.as_ptr()) };
        if actual_index == 0 {
            return Err(std::io::Error::last_os_error()).context("ARP interface does not exist");
        }
        if actual_index != interface_index {
            bail!("ARP interface index mismatch: {interface} is {actual_index}, expected {interface_index}");
        }
        validate_hardware_address(self.hardware_address)?;
        if address.is_unspecified() || address.is_broadcast() || address.is_multicast() {
            bail!("invalid candidate address for ARP duplicate-address detection");
        }
        let socket = LinuxArpSocket::bind(interface_index)?;
        probe_with_io(&socket, self.hardware_address, address).await
    }
}

#[async_trait]
pub trait DhcpClientActionSink: Send {
    async fn lease_acquired(&mut self, lease: Lease) -> Result<()>;
    async fn lease_lost(&mut self) -> Result<()>;
    async fn cleanup_needed(&mut self, lease: Lease) -> Result<()>;
}

#[async_trait]
impl DhcpClientActionSink for Box<dyn DhcpClientActionSink> {
    async fn lease_acquired(&mut self, lease: Lease) -> Result<()> {
        (**self).lease_acquired(lease).await
    }
    async fn lease_lost(&mut self) -> Result<()> {
        (**self).lease_lost().await
    }
    async fn cleanup_needed(&mut self, lease: Lease) -> Result<()> {
        (**self).cleanup_needed(lease).await
    }
}

#[derive(Debug, Default)]
pub struct NoopActionSink;

#[async_trait]
impl DhcpClientActionSink for NoopActionSink {
    async fn lease_acquired(&mut self, _lease: Lease) -> Result<()> {
        Ok(())
    }
    async fn lease_lost(&mut self) -> Result<()> {
        Ok(())
    }
    async fn cleanup_needed(&mut self, _lease: Lease) -> Result<()> {
        Ok(())
    }
}

const ETHERNET_HEADER_LEN: usize = 14;
const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const IPV4_UDP_PROTOCOL: u8 = 17;
const DHCP_IP_TTL: u8 = 64;

#[cfg(target_os = "linux")]
/// Open a packet socket bound to the selected interface for DHCP frame transport.
fn packet_socket(interface_index: u32) -> Result<OwnedFd> {
    let protocol = (nix::libc::ETH_P_IP as u16).to_be() as i32;
    let raw = unsafe {
        nix::libc::socket(
            nix::libc::AF_PACKET,
            nix::libc::SOCK_RAW | nix::libc::SOCK_NONBLOCK | nix::libc::SOCK_CLOEXEC,
            protocol,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to create DHCP packet socket");
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let address = nix::libc::sockaddr_ll {
        sll_family: nix::libc::AF_PACKET as u16,
        sll_protocol: (nix::libc::ETH_P_IP as u16).to_be(),
        sll_ifindex: interface_index as i32,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };
    let result = unsafe {
        nix::libc::bind(
            fd.as_raw_fd(),
            (&address as *const nix::libc::sockaddr_ll).cast(),
            std::mem::size_of_val(&address) as nix::libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to bind DHCP packet socket to interface");
    }
    Ok(fd)
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from(chunk[0]) << 8
        };
        sum += u32::from(word);
        sum = (sum & 0xffff) + (sum >> 16);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn udp_checksum(source: Ipv4Addr, destination: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut input = Vec::with_capacity(12 + udp.len());
    input.extend_from_slice(&source.octets());
    input.extend_from_slice(&destination.octets());
    input.push(0);
    input.push(IPV4_UDP_PROTOCOL);
    input.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    input.extend_from_slice(udp);
    let checksum = internet_checksum(&input);
    if checksum == 0 {
        0xffff
    } else {
        checksum
    }
}

/// Build an Ethernet/IPv4/UDP frame containing a DHCP payload and its checksums.
fn encode_dhcp_frame(
    payload: &[u8],
    source_mac: [u8; 6],
    source_ip: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
) -> Result<Vec<u8>> {
    let udp_len = UDP_HEADER_LEN
        .checked_add(payload.len())
        .context("DHCP payload length overflow")?;
    let ip_len = IPV4_HEADER_LEN
        .checked_add(udp_len)
        .context("DHCP frame length overflow")?;
    if ip_len > u16::MAX as usize {
        bail!("DHCP payload is too large for IPv4");
    }
    let mut frame = vec![0; ETHERNET_HEADER_LEN + ip_len];
    frame[..6].fill(0xff);
    frame[6..12].copy_from_slice(&source_mac);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let ip = &mut frame[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + IPV4_HEADER_LEN];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    ip[8] = DHCP_IP_TTL;
    ip[9] = IPV4_UDP_PROTOCOL;
    ip[12..16].copy_from_slice(&source_ip.octets());
    ip[16..20].copy_from_slice(&Ipv4Addr::BROADCAST.octets());
    let checksum = internet_checksum(ip);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());
    let udp_start = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN;
    let udp = &mut frame[udp_start..];
    udp[..2].copy_from_slice(&source_port.to_be_bytes());
    udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[UDP_HEADER_LEN..].copy_from_slice(payload);
    let checksum = udp_checksum(source_ip, Ipv4Addr::BROADCAST, udp);
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());
    Ok(frame)
}

/// Validate an incoming frame and extract a DHCP payload addressed to this client.
fn parse_dhcp_frame(frame: &[u8], own_mac: [u8; 6]) -> Option<&[u8]> {
    if frame.len() < ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN
        || (frame[..6] != [0xff; 6] && frame[..6] != own_mac)
        || frame[12..14] != 0x0800u16.to_be_bytes()
    {
        return None;
    }
    let ip = &frame[ETHERNET_HEADER_LEN..];
    let header_len = usize::from(ip[0] & 0x0f) * 4;
    if ip[0] >> 4 != 4 || header_len < IPV4_HEADER_LEN || ip.len() < header_len + UDP_HEADER_LEN {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    let fragment = u16::from_be_bytes([ip[6], ip[7]]);
    if total_len < header_len + UDP_HEADER_LEN
        || total_len > ip.len()
        || fragment & 0x3fff != 0
        || ip[9] != IPV4_UDP_PROTOCOL
        || internet_checksum(&ip[..header_len]) != 0
    {
        return None;
    }
    let source = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let destination = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
    if destination != Ipv4Addr::BROADCAST && frame[..6] != own_mac {
        return None;
    }
    let udp = &ip[header_len..total_len];
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if u16::from_be_bytes([udp[0], udp[1]]) != DHCP_SERVER_PORT
        || u16::from_be_bytes([udp[2], udp[3]]) != DHCP_CLIENT_PORT
        || udp_len < UDP_HEADER_LEN
        || udp_len != udp.len()
    {
        return None;
    }
    let wire_checksum = u16::from_be_bytes([udp[6], udp[7]]);
    if wire_checksum != 0 {
        let mut checked = udp.to_vec();
        checked[6..8].fill(0);
        if udp_checksum(source, destination, &checked) != wire_checksum {
            return None;
        }
    }
    Some(&udp[UDP_HEADER_LEN..])
}

#[cfg(target_os = "linux")]
pub struct LinuxDhcpClientSocket {
    udp_socket: AsyncFd<OwnedFd>,
    packet_socket: AsyncFd<OwnedFd>,
    config: DhcpClientRuntimeConfig,
}

#[cfg(target_os = "linux")]
impl LinuxDhcpClientSocket {
    pub fn bind(config: DhcpClientRuntimeConfig) -> Result<Self> {
        config.validate()?;
        let fd = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
            None,
        )
        .context("failed to create DHCP client UDP socket")?;
        setsockopt(&fd, sockopt::ReuseAddr, &true).context("failed to set SO_REUSEADDR")?;
        setsockopt(&fd, sockopt::Broadcast, &true).context("failed to set SO_BROADCAST")?;
        setsockopt(
            &fd,
            sockopt::BindToDevice,
            &OsString::from(&config.interface),
        )
        .with_context(|| format!("failed to set SO_BINDTODEVICE for {}", config.interface))?;
        setsockopt(&fd, sockopt::Ipv4PacketInfo, &true).context("failed to set IP_PKTINFO")?;
        let address =
            SockaddrIn::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, config.client_port));
        bind(fd.as_raw_fd(), &address).with_context(|| {
            format!("failed to bind DHCP client UDP port {}", config.client_port)
        })?;
        let packet_fd = packet_socket(config.interface_index)?;
        Ok(Self {
            udp_socket: AsyncFd::new(fd).context("failed to register DHCP client UDP socket")?,
            packet_socket: AsyncFd::new(packet_fd)
                .context("failed to register DHCP client packet socket")?,
            config,
        })
    }

    async fn receive_udp(&self) -> Result<IngressDatagram> {
        let mut buffer = vec![0; self.config.max_packet_size];
        loop {
            let mut ready = self.udp_socket.readable().await?;
            let result = ready.try_io(|fd| {
                let mut iov = [IoSliceMut::new(&mut buffer)];
                let mut cmsg = nix::cmsg_space!(nix::libc::in_pktinfo);
                let message = recvmsg::<SockaddrIn>(
                    fd.get_ref().as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsg),
                    MsgFlags::empty(),
                )?;
                let interface_index = message
                    .cmsgs()?
                    .find_map(|control| match control {
                        ControlMessageOwned::Ipv4PacketInfo(info) => Some(info.ipi_ifindex as u32),
                        _ => None,
                    })
                    .ok_or(nix::errno::Errno::ENOMSG)?;
                Ok((message.bytes, interface_index))
            });
            match result {
                Ok(value) => {
                    let (length, interface_index) =
                        value.context("failed to receive DHCP client datagram")?;
                    buffer.truncate(length);
                    return Ok(IngressDatagram {
                        bytes: buffer,
                        interface_index,
                    });
                }
                Err(_) => continue,
            }
        }
    }

    async fn receive_packet(&self) -> Result<IngressDatagram> {
        loop {
            let mut ready = self.packet_socket.readable().await?;
            let mut frame = vec![0; self.config.max_packet_size + ETHERNET_HEADER_LEN];
            let result = ready.try_io(|fd| {
                let received = unsafe {
                    nix::libc::recv(
                        fd.get_ref().as_raw_fd(),
                        frame.as_mut_ptr().cast(),
                        frame.len(),
                        0,
                    )
                };
                if received < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(received as usize)
                }
            });
            match result {
                Ok(Ok(length)) => {
                    frame.truncate(length);
                    if let Some(bytes) = parse_dhcp_frame(&frame, self.config.hardware_address) {
                        return Ok(IngressDatagram {
                            bytes: bytes.to_vec(),
                            interface_index: self.config.interface_index,
                        });
                    }
                }
                Ok(Err(error)) => return Err(error).context("failed to receive DHCP packet frame"),
                Err(_) => continue,
            }
        }
    }

    #[cfg(test)]
    fn raw_fd(&self) -> std::os::fd::RawFd {
        self.udp_socket.get_ref().as_raw_fd()
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl DhcpClientTransport for LinuxDhcpClientSocket {
    async fn receive(&self) -> Result<IngressDatagram> {
        tokio::select! {
            datagram = self.receive_packet() => datagram,
            datagram = self.receive_udp() => datagram,
        }
    }

    async fn send(&self, packet: &[u8], kind: SendKind) -> Result<()> {
        if kind == SendKind::Broadcast {
            let source_ip = packet
                .get(12..16)
                .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                .map(Ipv4Addr::from)
                .context("DHCP packet is too short to contain ciaddr")?;
            let frame = encode_dhcp_frame(
                packet,
                self.config.hardware_address,
                source_ip,
                self.config.client_port,
                self.config.server_port,
            )?;
            loop {
                let mut ready = self.packet_socket.writable().await?;
                match ready.try_io(|fd| {
                    let sent = unsafe {
                        nix::libc::send(
                            fd.get_ref().as_raw_fd(),
                            frame.as_ptr().cast(),
                            frame.len(),
                            0,
                        )
                    };
                    if sent < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(sent as usize)
                    }
                }) {
                    Ok(Ok(sent)) if sent == frame.len() => return Ok(()),
                    Ok(Ok(sent)) => bail!("short DHCP frame send: {sent} of {} bytes", frame.len()),
                    Ok(Err(error)) => {
                        return Err(error).context("failed to send DHCP packet frame")
                    }
                    Err(_) => continue,
                }
            }
        }
        let SendKind::Unicast(address) = kind else {
            unreachable!()
        };
        let destination = SockaddrIn::from(SocketAddrV4::new(address, self.config.server_port));
        let info = nix::libc::in_pktinfo {
            ipi_ifindex: self.config.interface_index as i32,
            ipi_spec_dst: nix::libc::in_addr { s_addr: 0 },
            ipi_addr: nix::libc::in_addr { s_addr: 0 },
        };
        loop {
            let mut ready = self.udp_socket.writable().await?;
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
                    value.context("failed to send DHCP client datagram")?;
                    return Ok(());
                }
                Err(_would_block) => continue,
            }
        }
    }
}

pub struct DhcpClientActor<T, D, S> {
    config: DhcpClientRuntimeConfig,
    transport: Arc<T>,
    dad: Arc<D>,
    sink: S,
    state_machine: DhcpClientStateMachine,
    epoch: Instant,
    remembered: Option<Lease>,
}

impl<T, D, S> DhcpClientActor<T, D, S>
where
    T: DhcpClientTransport + 'static,
    D: DuplicateAddressDetector + 'static,
    S: DhcpClientActionSink,
{
    pub fn new(
        config: DhcpClientRuntimeConfig,
        transport: Arc<T>,
        dad: Arc<D>,
        sink: S,
    ) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            state_machine: DhcpClientStateMachine::new(config.hardware_address),
            config,
            transport,
            dad,
            sink,
            epoch: Instant::now(),
            remembered: None,
        })
    }

    pub fn with_remembered_lease(mut self, lease: Lease) -> Self {
        self.remembered = Some(lease);
        self
    }

    pub async fn run(mut self, mut cancel: watch::Receiver<bool>) -> Result<()> {
        if *cancel.borrow() {
            return Ok(());
        }
        let remembered = self.remembered.take();
        let actions =
            self.state_machine
                .link_ready(self.now(), random_xid(), remembered, random_jitter());
        if self.drive_or_cancel(actions, &mut cancel).await?.is_none() {
            return Ok(());
        }
        let mut wake = self.state_machine.deadline();
        loop {
            let deadline = wake.unwrap_or_else(|| self.now() + Duration::from_secs(3600));
            let sleep =
                tokio::time::sleep_until(tokio::time::Instant::from_std(self.epoch + deadline));
            tokio::pin!(sleep);
            tokio::select! {
                changed = cancel.changed() => {
                    if changed.is_err() || *cancel.borrow() { return Ok(()); }
                }
                datagram = self.transport.receive() => {
                    let datagram = datagram?;
                    if datagram.interface_index != self.config.interface_index {
                        tracing::debug!(received_ifindex = datagram.interface_index, expected_ifindex = self.config.interface_index, "ignoring DHCP reply from wrong interface");
                        continue;
                    }
                    let actions = self.state_machine.receive(self.now(), &datagram.bytes, random_jitter());
                    if self.drive_or_cancel(actions, &mut cancel).await?.is_none() {
                        return Ok(());
                    }



                    wake = self.state_machine.deadline();
                }
                () = &mut sleep => {
                    let actions = self.state_machine.timeout(self.now(), random_xid(), random_jitter());
                    if self.drive_or_cancel(actions, &mut cancel).await?.is_none() {
                        return Ok(());
                    }
                    wake = self.state_machine.deadline();
                }
            }
        }
    }

    fn now(&self) -> MonotonicTime {
        self.epoch.elapsed()
    }

    async fn drive_or_cancel(
        &mut self,
        actions: Vec<Action>,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<Option<Option<MonotonicTime>>> {
        tokio::select! {
            result = self.drive(actions) => result.map(Some),
            () = wait_for_cancellation(cancel) => Ok(None),
        }
    }

    /// Execute state-machine actions, notifying lease ownership callbacks and scheduling the next wakeup.
    async fn drive(&mut self, actions: Vec<Action>) -> Result<Option<MonotonicTime>> {
        let mut wake = None;
        for action in actions {
            match action {
                Action::Send { packet, kind } => {
                    self.transport.send(&packet, kind).await?;
                    let message_type = crate::dhcp::packet::DhcpPacket::parse(&packet)
                        .ok()
                        .and_then(|packet| packet.message_type());
                    tracing::info!(interface = %self.config.interface, ?message_type, ?kind, "DHCP packet sent");
                }
                Action::WakeAt(deadline) => {
                    wake = Some(wake.map_or(deadline, |old: Duration| old.min(deadline)))
                }
                Action::LeaseAcquired(lease) => {
                    tracing::info!(interface = %self.config.interface, address = %lease.address, server = %lease.server_identifier, "DHCP ACK accepted; probing for duplicate address");
                    if self
                        .dad
                        .is_duplicate(
                            &self.config.interface,
                            self.config.interface_index,
                            lease.address,
                        )
                        .await?
                    {
                        tracing::warn!(interface = %self.config.interface, address = %lease.address, "DHCP address conflict detected; declining lease");
                        let actions = self
                            .state_machine
                            .address_conflict(self.now(), random_jitter());
                        let conflict_wake = Box::pin(self.drive(actions)).await?;
                        wake = conflict_wake.or(wake);
                    } else {
                        let address = lease.address;
                        self.sink.lease_acquired(lease).await?;
                        tracing::info!(interface = %self.config.interface, %address, "DHCP lease installed");
                    }
                }
                Action::LeaseLost => self.sink.lease_lost().await?,
                Action::CleanupNeeded(lease) => self.sink.cleanup_needed(lease).await?,
                Action::ReplyIgnored(super::state_machine::IgnoreReason::Invalid(reason)) => {
                    tracing::warn!(interface = %self.config.interface, %reason, "DHCP reply rejected");
                }
                Action::ReplyIgnored(reason) => {
                    tracing::debug!(interface = %self.config.interface, ?reason, "DHCP reply ignored");
                }
            }
        }
        Ok(wake)
    }
}

/// Wait until cancellation is requested or its watch channel is closed.
async fn wait_for_cancellation(cancel: &mut watch::Receiver<bool>) {
    loop {
        if *cancel.borrow() || cancel.changed().await.is_err() {
            return;
        }
    }
}

fn random_xid() -> u32 {
    rand::thread_rng().gen()
}
fn random_jitter() -> i32 {
    rand::thread_rng().gen_range(-1000..=1000)
}

#[cfg(test)]
mod tests;
