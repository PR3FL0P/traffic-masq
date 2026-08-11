#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader as StdBufReader};
use std::net::{Ipv4Addr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;
use traffic_masq::dhcp::client::runtime::{
    DhcpClientActionSink, DhcpClientActor, DhcpClientRuntimeConfig, DuplicateAddressDetector,
    LinuxDhcpClientSocket, DHCP_CLIENT_PORT, DHCP_SERVER_PORT,
};
use traffic_masq::dhcp::client::Lease;
use traffic_masq::dhcp::packet::{
    finish_options, push_option, DhcpMessageType, DhcpPacket, BOOTREPLY, DHCP_FIXED_HEADER_LEN,
    DHCP_MAGIC_COOKIE, ETHERNET_HLEN, ETHERNET_HTYPE, OPTION_DNS_SERVERS, OPTION_LEASE_TIME,
    OPTION_MESSAGE_TYPE, OPTION_REBINDING_TIME, OPTION_RENEWAL_TIME, OPTION_ROUTERS,
    OPTION_SERVER_IDENTIFIER, OPTION_SUBNET_MASK,
};

static NAMESPACE_TEST_LOCK: Mutex<()> = Mutex::new(());
const TEST_TIMEOUT: Duration = Duration::from_secs(15);
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const LIFECYCLE_LEASE: u32 = 8;
const LIFECYCLE_T1: u32 = 2;
const LIFECYCLE_T2: u32 = 5;

#[derive(Clone, Copy)]
enum ServerMode {
    Acquire,
    Renew,
    Rebind,
    Expire,
}

impl ServerMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Acquire => "acquire",
            Self::Renew => "renew",
            Self::Rebind => "rebind",
            Self::Expire => "expire",
        }
    }
}

struct Segment {
    namespace: String,
    client_if: String,
    server_if: String,
    server: Option<Child>,
    reports: Option<mpsc::UnboundedReceiver<String>>,
    report_reader: Option<std::thread::JoinHandle<()>>,
}

impl Segment {
    fn new(tag: char, suffix: &str) -> Result<Self> {
        let mut segment = Self {
            namespace: format!("tmdc{tag}{suffix}"),
            client_if: format!("tmc{tag}{suffix}"),
            server_if: format!("tms{tag}{suffix}"),
            server: None,
            reports: None,
            report_reader: None,
        };
        if let Err(error) = segment.setup() {
            segment.cleanup();
            return Err(error);
        }
        Ok(segment)
    }

    fn setup(&mut self) -> Result<()> {
        run_ip(&["netns", "add", &self.namespace])?;
        run_ip(&[
            "link",
            "add",
            &self.client_if,
            "type",
            "veth",
            "peer",
            "name",
            &self.server_if,
        ])?;
        run_ip(&["link", "set", &self.server_if, "netns", &self.namespace])?;
        run_ip(&["link", "set", &self.client_if, "up"])?;
        run_ip(&["-n", &self.namespace, "link", "set", "lo", "up"])?;
        run_ip(&[
            "-n",
            &self.namespace,
            "addr",
            "add",
            "192.0.2.1/24",
            "dev",
            &self.server_if,
        ])?;
        run_ip(&["-n", &self.namespace, "link", "set", &self.server_if, "up"])?;

        run_ip(&[
            "-n",
            &self.namespace,
            "route",
            "add",
            "255.255.255.255/32",
            "dev",
            &self.server_if,
        ])?;
        Ok(())
    }

    async fn start_server(&mut self, offered: Ipv4Addr, mode: ServerMode) -> Result<()> {
        let executable =
            std::env::current_exe().context("failed to locate integration-test binary")?;
        let mut child = Command::new("ip")
            .args(["netns", "exec", &self.namespace])
            .arg(executable)
            .args([
                "--ignored",
                "--exact",
                "fake_dhcp_server_process",
                "--nocapture",
            ])
            .env("TRAFFIC_MASQ_FAKE_DHCP_SERVER", "1")
            .env("TRAFFIC_MASQ_FAKE_DHCP_ADDRESS", offered.to_string())
            .env("TRAFFIC_MASQ_FAKE_DHCP_MODE", mode.as_str())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("failed to launch fake DHCP server in namespace")?;
        let stdout = child
            .stdout
            .take()
            .context("fake server stdout was not piped")?;
        let (report_tx, mut report_rx) = mpsc::unbounded_channel();
        let reader = std::thread::spawn(move || {
            for line in StdBufReader::new(stdout).lines() {
                match line {
                    Ok(line) => {
                        if report_tx.send(line).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = report_tx.send(format!("FAKE_DHCP_STDOUT_ERROR {error}"));
                        break;
                    }
                }
            }
        });
        let ready = timeout(TEST_TIMEOUT, async {
            while let Some(line) = report_rx.recv().await {
                if line.trim() == "FAKE_DHCP_READY" {
                    return Ok(());
                }
            }
            bail!("fake DHCP server stdout closed before readiness")
        })
        .await
        .context("fake DHCP server did not become ready")??;
        let _ = ready;
        self.server = Some(child);
        self.reports = Some(report_rx);
        self.report_reader = Some(reader);
        Ok(())
    }

    async fn expect_report(&mut self, expected: &str) -> Result<()> {
        let reports = self
            .reports
            .as_mut()
            .context("fake server is not running")?;
        let mut observed = Vec::new();
        timeout(TEST_TIMEOUT, async {
            while let Some(line) = reports.recv().await {
                if line.trim() == expected {
                    return Ok(());
                }
                observed.push(line);
            }
            bail!(
                "fake DHCP server exited before {expected}; output: {}",
                observed.join(" | ")
            )
        })
        .await
        .with_context(|| format!("timed out waiting for fake-server report {expected}"))??;
        Ok(())
    }

    fn interface_identity(&self) -> Result<(u32, [u8; 6])> {
        let index = std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", self.client_if))
            .with_context(|| {
                format!(
                    "failed to read sysfs for {}; under `unshare --net` /sys still describes the \
                     host namespace, so run these tests with `ip netns exec` instead",
                    self.client_if
                )
            })?
            .trim()
            .parse()
            .context("invalid veth ifindex")?;
        let text = std::fs::read_to_string(format!("/sys/class/net/{}/address", self.client_if))?;
        let bytes = text
            .trim()
            .split(':')
            .map(|part| u8::from_str_radix(part, 16))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mac: [u8; 6] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid veth MAC"))?;
        Ok((index, mac))
    }

    fn cleanup(&mut self) {
        if let Some(mut child) = self.server.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.reports.take();
        if let Some(reader) = self.report_reader.take() {
            let _ = reader.join();
        }
        let _ = Command::new("ip")
            .args(["link", "del", &self.client_if])
            .status();
        let _ = Command::new("ip")
            .args(["netns", "del", &self.namespace])
            .status();
    }
}

impl Drop for Segment {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[derive(Clone)]
struct NoDuplicate;

#[async_trait]
impl DuplicateAddressDetector for NoDuplicate {
    async fn is_duplicate(&self, _: &str, _: u32, _: Ipv4Addr) -> Result<bool> {
        Ok(false)
    }
}

struct LeaseSink(mpsc::UnboundedSender<Lease>);

#[async_trait]
impl DhcpClientActionSink for LeaseSink {
    async fn lease_acquired(&mut self, lease: Lease) -> Result<()> {
        self.0
            .send(lease)
            .map_err(|_| anyhow::anyhow!("lease receiver closed"))
    }
    async fn lease_lost(&mut self) -> Result<()> {
        Ok(())
    }
    async fn cleanup_needed(&mut self, _: Lease) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
enum LifecycleEvent {
    Acquired,
    CleanupNeeded,
    LeaseLost,
}

struct LifecycleSink {
    interface: String,
    events: mpsc::UnboundedSender<LifecycleEvent>,
}

#[async_trait]
impl DhcpClientActionSink for LifecycleSink {
    async fn lease_acquired(&mut self, lease: Lease) -> Result<()> {
        run_ip(&[
            "addr",
            "add",
            &format!("{}/{}", lease.address, lease.prefix_len),
            "dev",
            &self.interface,
        ])?;
        self.events
            .send(LifecycleEvent::Acquired)
            .map_err(|_| anyhow::anyhow!("lifecycle receiver closed"))
    }

    async fn cleanup_needed(&mut self, lease: Lease) -> Result<()> {
        run_ip(&[
            "addr",
            "del",
            &format!("{}/{}", lease.address, lease.prefix_len),
            "dev",
            &self.interface,
        ])?;
        self.events
            .send(LifecycleEvent::CleanupNeeded)
            .map_err(|_| anyhow::anyhow!("lifecycle receiver closed"))
    }

    async fn lease_lost(&mut self) -> Result<()> {
        self.events
            .send(LifecycleEvent::LeaseLost)
            .map_err(|_| anyhow::anyhow!("lifecycle receiver closed"))
    }
}

#[tokio::test]
#[ignore = "requires Linux root and iproute2; run explicitly on a disposable host"]
async fn real_port_68_acquisition_is_parallel_and_interface_isolated() -> Result<()> {
    require_root_and_ip()?;
    let _guard = namespace_guard()?;
    let suffix = unique_suffix();
    let mut first = Segment::new('a', &suffix)?;
    let mut second = Segment::new('b', &suffix)?;
    let first_address = Ipv4Addr::new(192, 0, 2, 101);
    let second_address = Ipv4Addr::new(192, 0, 2, 102);
    first
        .start_server(first_address, ServerMode::Acquire)
        .await?;
    second
        .start_server(second_address, ServerMode::Acquire)
        .await?;

    let (first_task, first_cancel, mut first_leases) = start_acquisition_client(&first)?;
    let (second_task, second_cancel, mut second_leases) = start_acquisition_client(&second)?;
    let (first_lease, second_lease) = timeout(TEST_TIMEOUT, async {
        tokio::try_join!(
            async {
                first_leases
                    .recv()
                    .await
                    .context("first client stopped without a lease")
            },
            async {
                second_leases
                    .recv()
                    .await
                    .context("second client stopped without a lease")
            }
        )
    })
    .await
    .context("parallel DHCP acquisition timed out")??;

    assert_eq!(first_lease.address, first_address);
    assert_eq!(second_lease.address, second_address);
    assert_ne!(
        first_lease.address, second_lease.address,
        "leases crossed isolated veth segments"
    );
    stop_client(first_task, first_cancel).await?;
    stop_client(second_task, second_cancel).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires Linux root and iproute2; run explicitly on a disposable host"]
async fn t1_renewal_is_unicast_with_ciaddr() -> Result<()> {
    let (_guard, mut segment, task, cancel, mut events) =
        start_lifecycle_fixture('r', ServerMode::Renew).await?;
    expect_event(&mut events, LifecycleEvent::Acquired).await?;
    segment.expect_report("OBSERVED_T1_UNICAST").await?;
    stop_client(task, cancel).await
}

#[tokio::test]
#[ignore = "requires Linux root and iproute2; run explicitly on a disposable host"]
async fn t2_rebinding_is_broadcast_when_renewal_server_is_silent() -> Result<()> {
    let (_guard, mut segment, task, cancel, mut events) =
        start_lifecycle_fixture('b', ServerMode::Rebind).await?;
    expect_event(&mut events, LifecycleEvent::Acquired).await?;
    segment.expect_report("OBSERVED_T1_SILENT").await?;
    segment.expect_report("OBSERVED_T2_BROADCAST").await?;
    stop_client(task, cancel).await
}

#[tokio::test]
#[ignore = "requires Linux root and iproute2; run explicitly on a disposable host"]
async fn expiry_cleans_owned_address_reports_loss_and_restarts_discover() -> Result<()> {
    let (_guard, mut segment, task, cancel, mut events) =
        start_lifecycle_fixture('e', ServerMode::Expire).await?;
    expect_event(&mut events, LifecycleEvent::Acquired).await?;
    expect_event(&mut events, LifecycleEvent::CleanupNeeded).await?;
    expect_event(&mut events, LifecycleEvent::LeaseLost).await?;
    segment.expect_report("OBSERVED_EXPIRY_DISCOVER").await?;
    let offered = Ipv4Addr::new(192, 0, 2, 110);
    let output = Command::new("ip")
        .args(["-4", "-o", "addr", "show", "dev", &segment.client_if])
        .output()?;
    if !output.status.success() {
        bail!("failed to inspect client address after expiry");
    }
    if String::from_utf8_lossy(&output.stdout).contains(&offered.to_string()) {
        bail!("owned lease address remained after cleanup_needed");
    }
    stop_client(task, cancel).await
}

type ClientTask = tokio::task::JoinHandle<Result<()>>;

fn start_acquisition_client(
    segment: &Segment,
) -> Result<(
    ClientTask,
    watch::Sender<bool>,
    mpsc::UnboundedReceiver<Lease>,
)> {
    let (lease_tx, lease_rx) = mpsc::unbounded_channel();
    let (task, cancel) = start_client(segment, LeaseSink(lease_tx))?;
    Ok((task, cancel, lease_rx))
}

fn start_client<S: DhcpClientActionSink + 'static>(
    segment: &Segment,
    sink: S,
) -> Result<(ClientTask, watch::Sender<bool>)> {
    let (index, mac) = segment.interface_identity()?;
    let config = DhcpClientRuntimeConfig::new(&segment.client_if, index, mac);
    assert_eq!(config.client_port, DHCP_CLIENT_PORT);
    assert_eq!(config.server_port, DHCP_SERVER_PORT);
    let socket = std::sync::Arc::new(LinuxDhcpClientSocket::bind(config.clone())?);
    let actor = DhcpClientActor::new(config, socket, std::sync::Arc::new(NoDuplicate), sink)?;
    let (cancel_tx, cancel_rx) = watch::channel(false);
    Ok((tokio::spawn(actor.run(cancel_rx)), cancel_tx))
}

async fn start_lifecycle_fixture(
    tag: char,
    mode: ServerMode,
) -> Result<(
    std::sync::MutexGuard<'static, ()>,
    Segment,
    ClientTask,
    watch::Sender<bool>,
    mpsc::UnboundedReceiver<LifecycleEvent>,
)> {
    require_root_and_ip()?;
    let guard = namespace_guard()?;
    let mut segment = Segment::new(tag, &unique_suffix())?;
    segment
        .start_server(Ipv4Addr::new(192, 0, 2, 110), mode)
        .await?;
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let sink = LifecycleSink {
        interface: segment.client_if.clone(),
        events: event_tx,
    };
    let (task, cancel) = start_client(&segment, sink)?;
    Ok((guard, segment, task, cancel, event_rx))
}

async fn expect_event(
    events: &mut mpsc::UnboundedReceiver<LifecycleEvent>,
    expected: LifecycleEvent,
) -> Result<()> {
    let actual = timeout(TEST_TIMEOUT, events.recv())
        .await
        .with_context(|| format!("timed out waiting for {expected:?}"))?
        .context("client stopped reporting lifecycle events")?;
    if actual != expected {
        bail!("expected lifecycle event {expected:?}, got {actual:?}");
    }
    Ok(())
}

async fn stop_client(task: ClientTask, cancel: watch::Sender<bool>) -> Result<()> {
    cancel.send(true).ok();
    timeout(TEST_TIMEOUT, task)
        .await
        .context("client cancellation timed out")???;
    Ok(())
}

#[test]
#[ignore]
fn fake_dhcp_server_process() -> Result<()> {
    if std::env::var_os("TRAFFIC_MASQ_FAKE_DHCP_SERVER").is_none() {
        return Ok(());
    }
    let offered: Ipv4Addr = std::env::var("TRAFFIC_MASQ_FAKE_DHCP_ADDRESS")?.parse()?;
    let mode = std::env::var("TRAFFIC_MASQ_FAKE_DHCP_MODE")?;
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, DHCP_SERVER_PORT))?;
    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(TEST_TIMEOUT))?;
    println!("FAKE_DHCP_READY");

    let mut buffer = [0_u8; 1500];
    let (discover_len, discover_source) = socket.recv_from(&mut buffer)?;
    validate_discover(&buffer[..discover_len], discover_source)?;
    let discover = DhcpPacket::parse(&buffer[..discover_len])?;
    let discover_xid = discover.xid;
    socket.send_to(
        &reply(&discover, offered, DhcpMessageType::Offer, &mode)?,
        (Ipv4Addr::BROADCAST, DHCP_CLIENT_PORT),
    )?;

    let (request_len, request_source) = socket.recv_from(&mut buffer)?;
    if request_source != (Ipv4Addr::UNSPECIFIED, DHCP_CLIENT_PORT).into() {
        bail!("expected selecting DHCPREQUEST from 0.0.0.0:68, got {request_source}");
    }
    let request = DhcpPacket::parse(&buffer[..request_len])?;
    if request.strict_message_type()? != Some(DhcpMessageType::Request)
        || request.requested_ip() != Some(offered)
        || request.server_identifier() != Some(SERVER_IP)
    {
        bail!("received invalid selecting DHCPREQUEST");
    }
    socket.send_to(
        &reply(&request, offered, DhcpMessageType::Ack, &mode)?,
        (Ipv4Addr::BROADCAST, DHCP_CLIENT_PORT),
    )?;
    let acknowledged_at = std::time::Instant::now();
    if mode == "acquire" {
        return Ok(());
    }

    loop {
        let (len, source) = socket.recv_from(&mut buffer)?;
        let packet = DhcpPacket::parse(&buffer[..len])?;
        match packet.strict_message_type()? {
            Some(DhcpMessageType::Request) => {
                validate_extension_request(&packet, source, offered)?;
                if packet.flags & 0x8000 == 0 {
                    println!("OBSERVED_T1_SILENT");
                    if mode == "renew" {
                        println!("OBSERVED_T1_UNICAST");
                        return Ok(());
                    }
                } else {
                    if mode == "rebind" {
                        println!("OBSERVED_T2_BROADCAST");
                        return Ok(());
                    }
                    if mode != "expire" {
                        bail!("unexpected rebinding request in fake-server mode {mode}");
                    }
                }
            }
            Some(DhcpMessageType::Discover) => {
                validate_discover(&buffer[..len], source)?;
                if packet.xid == discover_xid {
                    continue;
                }
                if mode == "expire" {
                    println!("OBSERVED_EXPIRY_DISCOVER");
                    return Ok(());
                }
                bail!(
                    "unexpected new DHCPDISCOVER transaction in fake-server mode {mode}: initial_xid={discover_xid:#010x}, new_xid={:#010x}, elapsed_after_ack={:?}",
                    packet.xid,
                    acknowledged_at.elapsed()
                );
            }
            kind => bail!("unexpected post-acquisition DHCP message {kind:?}"),
        }
    }
}

fn validate_discover(bytes: &[u8], source: std::net::SocketAddr) -> Result<()> {
    if source != (Ipv4Addr::UNSPECIFIED, DHCP_CLIENT_PORT).into() {
        bail!("expected DHCPDISCOVER from 0.0.0.0:68, got {source}");
    }
    let packet = DhcpPacket::parse(bytes)?;
    if packet.strict_message_type()? != Some(DhcpMessageType::Discover)
        || !packet.ciaddr.is_unspecified()
    {
        bail!("received invalid DHCPDISCOVER");
    }
    Ok(())
}

fn validate_extension_request(
    packet: &DhcpPacket<'_>,
    source: std::net::SocketAddr,
    offered: Ipv4Addr,
) -> Result<()> {
    if packet.strict_message_type()? != Some(DhcpMessageType::Request)
        || packet.ciaddr != offered
        || packet.requested_ip().is_some()
        || packet.server_identifier().is_some()
    {
        bail!("renew/rebind request did not use ciaddr or included option 50/54");
    }
    if source != (offered, DHCP_CLIENT_PORT).into() {
        bail!("renew/rebind source was {source}, expected {offered}:68");
    }
    Ok(())
}

fn reply(
    request: &DhcpPacket<'_>,
    offered: Ipv4Addr,
    kind: DhcpMessageType,
    mode: &str,
) -> Result<Vec<u8>> {
    let mut packet = vec![0; DHCP_FIXED_HEADER_LEN + DHCP_MAGIC_COOKIE.len()];
    packet[0] = BOOTREPLY;
    packet[1] = ETHERNET_HTYPE;
    packet[2] = ETHERNET_HLEN;
    packet[4..8].copy_from_slice(&request.xid.to_be_bytes());
    packet[16..20].copy_from_slice(&offered.octets());
    packet[20..24].copy_from_slice(&SERVER_IP.octets());
    packet[28..44].copy_from_slice(&request.chaddr);
    packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
    push_option(&mut packet, OPTION_MESSAGE_TYPE, &[kind.as_u8()])?;
    push_option(&mut packet, OPTION_SERVER_IDENTIFIER, &SERVER_IP.octets())?;
    if kind == DhcpMessageType::Ack {
        push_option(&mut packet, OPTION_SUBNET_MASK, &[255, 255, 255, 0])?;
        push_option(&mut packet, OPTION_ROUTERS, &SERVER_IP.octets())?;
        push_option(&mut packet, OPTION_DNS_SERVERS, &[192, 0, 2, 53])?;
        let (lease, t1, t2) = if mode == "acquire" {
            (60_u32, 30_u32, 52_u32)
        } else {
            (LIFECYCLE_LEASE, LIFECYCLE_T1, LIFECYCLE_T2)
        };
        push_option(&mut packet, OPTION_LEASE_TIME, &lease.to_be_bytes())?;
        push_option(&mut packet, OPTION_RENEWAL_TIME, &t1.to_be_bytes())?;
        push_option(&mut packet, OPTION_REBINDING_TIME, &t2.to_be_bytes())?;
    }
    finish_options(&mut packet);
    Ok(packet)
}

fn namespace_guard() -> Result<std::sync::MutexGuard<'static, ()>> {
    NAMESPACE_TEST_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("namespace lock poisoned"))
}

fn require_root_and_ip() -> Result<()> {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .context("failed to run id -u")?;
    if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim() != "0" {
        bail!("this ignored integration test must be run as root");
    }
    let status = Command::new("ip")
        .arg("-V")
        .status()
        .context("iproute2 is required")?;
    if !status.success() {
        bail!("ip -V command probe failed");
    }
    require_isolated_network_namespace()
}

fn require_isolated_network_namespace() -> Result<()> {
    if std::env::var_os("TRAFFIC_MASQ_ALLOW_HOST_NETNS").is_some() {
        return Ok(());
    }
    let ours =
        std::fs::read_link("/proc/self/ns/net").context("failed to read this network namespace")?;
    let host = std::fs::read_link("/proc/1/ns/net")
        .context("failed to read the host network namespace")?;
    if ours == host {
        bail!(
            "refusing to run in the host network namespace: a host DHCP client would claim the \
             test veth and inject DHCPDISCOVER traffic onto the segment. Re-run under \
             `ip netns exec <name> ...` (see this file's module header), or set \
             TRAFFIC_MASQ_ALLOW_HOST_NETNS=1 if nothing can manage the test interfaces."
        );
    }
    Ok(())
}

fn run_ip(args: &[&str]) -> Result<()> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .context("failed to execute ip")?;
    if !output.status.success() {
        bail!(
            "ip command failed: ip {args:?}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .subsec_nanos();
    format!("{:04x}", (nanos ^ std::process::id()) & 0xffff)
}
