use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use tempfile::tempdir;
use tokio::time::sleep;
use traffic_masq::config::AppConfig;
use traffic_masq::dhcp::supervisor::{DhcpServiceSpec, DhcpSupervisor};
use traffic_masq::netlink::{AddressOwnership, NetworkProvider, RtnetlinkNetworkProvider};

static NAMESPACE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct DhcpNetnsFixture {
    ns: String,
    host_if: String,
    peer_if: String,
    lease_script: PathBuf,
}

impl DhcpNetnsFixture {
    fn new() -> Result<Self> {
        require_root()?;
        require_command("ip", &["-V"])?;
        require_command("udhcpc", &["--help"])?;

        let suffix = unique_suffix();
        let lease_script = std::env::temp_dir().join(format!("traffic-masq-udhcpc-{suffix}.sh"));
        std::fs::write(
            &lease_script,
            "#!/bin/sh\ncase \"$1\" in\n  bound|renew)\n    ip -4 addr flush dev \"$interface\"\n    ip -4 addr add \"$ip/24\" dev \"$interface\"\n    ;;\n  deconfig)\n    ip -4 addr flush dev \"$interface\"\n    ;;\nesac\n",
        )?;
        std::fs::set_permissions(&lease_script, std::fs::Permissions::from_mode(0o700))?;
        let fixture = Self {
            ns: format!("tmdhcp{suffix}"),
            host_if: format!("tdh{suffix}"),
            peer_if: format!("tdp{suffix}"),
            lease_script,
        };

        run("ip", &["netns", "add", fixture.ns.as_str()])?;
        run(
            "ip",
            &[
                "link",
                "add",
                fixture.host_if.as_str(),
                "type",
                "veth",
                "peer",
                "name",
                fixture.peer_if.as_str(),
            ],
        )?;
        run(
            "ip",
            &[
                "link",
                "set",
                fixture.peer_if.as_str(),
                "netns",
                fixture.ns.as_str(),
            ],
        )?;
        run(
            "ip",
            &["-n", fixture.ns.as_str(), "link", "set", "lo", "up"],
        )?;
        run(
            "ip",
            &[
                "-n",
                fixture.ns.as_str(),
                "link",
                "set",
                fixture.peer_if.as_str(),
                "up",
            ],
        )?;

        Ok(fixture)
    }
}

impl Drop for DhcpNetnsFixture {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["link", "del", self.host_if.as_str()])
            .status();
        let _ = Command::new("ip")
            .args(["netns", "del", self.ns.as_str()])
            .status();
        let _ = std::fs::remove_file(&self.lease_script);
    }
}

#[tokio::test]
#[ignore = "requires root, iproute2 and udhcpc; run only on a disposable Linux test host"]
async fn two_output_interfaces_serve_isolated_dhcp_pools_concurrently() -> Result<()> {
    init_test_logging();
    let _test_guard = NAMESPACE_TEST_LOCK.lock().await;
    let first = DhcpNetnsFixture::new()?;
    let second = DhcpNetnsFixture::new()?;
    let network = RtnetlinkNetworkProvider::connect()?;
    let leases = tempdir()?;
    let mut config = AppConfig::default();
    config.dhcp.leases_dir = leases.path().to_path_buf();
    let supervisor = DhcpSupervisor::start(&config).await?;

    configure_server(
        &supervisor,
        &network,
        &first,
        Ipv4Addr::new(192, 168, 88, 1),
        88,
    )
    .await?;
    configure_server(
        &supervisor,
        &network,
        &second,
        Ipv4Addr::new(192, 168, 89, 1),
        89,
    )
    .await?;
    sleep(Duration::from_millis(150)).await;
    let running = supervisor.running_interfaces().await;
    assert_eq!(
        running.len(),
        2,
        "both DHCP services must be running: {running:?}"
    );
    assert!(running.contains(&first.host_if));
    assert!(running.contains(&second.host_if));
    eprintln!(
        "configured DHCP outputs: first={}, second={}",
        first.host_if, second.host_if
    );

    acquire_lease(&first).await?;
    acquire_lease(&second).await?;

    assert_client_subnet(&first, "192.168.88.")?;
    assert_client_subnet(&second, "192.168.89.")?;

    flush_client(&first)?;
    network
        .delete_ipv4_address(&first.host_if, Ipv4Addr::new(192, 168, 88, 1), 24)
        .await?;
    configure_server(
        &supervisor,
        &network,
        &first,
        Ipv4Addr::new(192, 168, 90, 1),
        90,
    )
    .await?;
    sleep(Duration::from_millis(100)).await;
    acquire_lease(&first).await?;
    assert_client_subnet(&first, "192.168.90.")?;

    flush_client(&first)?;
    network
        .delete_ipv4_address(&first.host_if, Ipv4Addr::new(192, 168, 90, 1), 24)
        .await?;
    configure_server(
        &supervisor,
        &network,
        &first,
        Ipv4Addr::new(192, 168, 88, 1),
        88,
    )
    .await?;
    sleep(Duration::from_millis(100)).await;
    acquire_lease(&first).await?;
    assert_client_subnet(&first, "192.168.88.")?;

    supervisor.shutdown().await;
    Ok(())
}

async fn configure_server(
    supervisor: &DhcpSupervisor,
    network: &RtnetlinkNetworkProvider,
    fixture: &DhcpNetnsFixture,
    server_ip: Ipv4Addr,
    subnet: u8,
) -> Result<()> {
    network.set_link_up(&fixture.host_if).await?;
    network
        .add_ipv4_address(&fixture.host_if, server_ip, 24, AddressOwnership::Static)
        .await?;
    supervisor
        .configure(DhcpServiceSpec {
            interface: fixture.host_if.clone(),
            server_ip,
            prefix_len: 24,
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            pool_start: Ipv4Addr::new(192, 168, subnet, 100),
            pool_end: Ipv4Addr::new(192, 168, subnet, 110),
            router: server_ip,
            dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
            lease_seconds: 300,
        })
        .await
}

async fn acquire_lease(fixture: &DhcpNetnsFixture) -> Result<()> {
    let status = tokio::process::Command::new("ip")
        .args([
            "netns",
            "exec",
            fixture.ns.as_str(),
            "udhcpc",
            "-i",
            fixture.peer_if.as_str(),
            "-n",
            "-q",
            "-f",
            "-t",
            "3",
            "-T",
            "1",
            "-s",
            fixture
                .lease_script
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("lease script path is not UTF-8"))?,
        ])
        .status()
        .await
        .context("failed to execute udhcpc in network namespace")?;
    if !status.success() {
        bail!("udhcpc failed in namespace {}", fixture.ns);
    }
    Ok(())
}

fn flush_client(fixture: &DhcpNetnsFixture) -> Result<()> {
    run(
        "ip",
        &[
            "-n",
            fixture.ns.as_str(),
            "-4",
            "addr",
            "flush",
            "dev",
            fixture.peer_if.as_str(),
        ],
    )
}

fn assert_client_subnet(fixture: &DhcpNetnsFixture, expected: &str) -> Result<()> {
    let output = Command::new("ip")
        .args([
            "-n",
            fixture.ns.as_str(),
            "-4",
            "addr",
            "show",
            "dev",
            fixture.peer_if.as_str(),
        ])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains(expected) {
        bail!("client did not receive address from {expected}: {stdout}");
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires root, iproute2 and udhcpc; run only on a disposable Linux test host"]
async fn embedded_dhcp_assigns_lease_to_namespace_client() -> Result<()> {
    init_test_logging();
    let _test_guard = NAMESPACE_TEST_LOCK.lock().await;
    let fixture = DhcpNetnsFixture::new()?;
    let network = RtnetlinkNetworkProvider::connect()?;
    let server_ip = Ipv4Addr::new(192, 168, 88, 1);

    let leases = tempdir()?;
    let mut config = AppConfig::default();
    config.dhcp.leases_dir = leases.path().to_path_buf();
    let supervisor = DhcpSupervisor::start(&config).await?;
    configure_server(&supervisor, &network, &fixture, server_ip, 88).await?;
    sleep(Duration::from_millis(150)).await;

    let client_status = tokio::process::Command::new("ip")
        .args([
            "netns",
            "exec",
            fixture.ns.as_str(),
            "udhcpc",
            "-i",
            fixture.peer_if.as_str(),
            "-n",
            "-q",
            "-f",
            "-t",
            "3",
            "-T",
            "1",
            "-s",
            fixture
                .lease_script
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("lease script path is not UTF-8"))?,
        ])
        .status()
        .await
        .context("failed to execute udhcpc in network namespace")?;

    supervisor.shutdown().await;

    if !client_status.success() {
        bail!("udhcpc did not obtain a lease");
    }

    let output = Command::new("ip")
        .args([
            "-n",
            fixture.ns.as_str(),
            "-4",
            "addr",
            "show",
            "dev",
            fixture.peer_if.as_str(),
        ])
        .output()
        .context("failed to inspect namespace client address")?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("192.168.88."),
        "namespace client did not receive an address from the configured pool: {stdout}"
    );

    Ok(())
}

fn init_test_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("traffic_masq=debug")
        .with_test_writer()
        .try_init();
}

fn require_root() -> Result<()> {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .context("failed to run id -u")?;
    let uid = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if !output.status.success() || uid != "0" {
        bail!("this ignored integration test must be run as root");
    }

    Ok(())
}

fn require_command(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("required command is not available: {program}"))?;

    if !status.success() {
        bail!("required command failed its availability check: {program}");
    }

    Ok(())
}

fn run(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("failed to execute {program}"))?;

    if !status.success() {
        bail!("command failed: {program} {args:?}");
    }

    Ok(())
}

fn unique_suffix() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_millis();
    let pid = std::process::id();
    format!("{:05}", (millis as u32 ^ pid) % 100_000)
}
