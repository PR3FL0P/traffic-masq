use std::fs;
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use traffic_masq::firewall::{
    Ipv4ForwardingBackend, LinuxRouterDataplaneProvider, NftCommandExecutor, NftablesBackend,
    OutputNetwork, ProcSysIpv4ForwardingIo, RouterDataplaneDesired, RouterDataplaneManager,
};
use traffic_masq::netlink::RtnetlinkNetworkProvider;

static NAMESPACE_TEST_LOCK: Mutex<()> = Mutex::new(());
const IPV4_FORWARDING_PATH: &str = "/proc/sys/net/ipv4/ip_forward";

struct RouterDataplaneFixture {
    client_ns: String,
    upstream_ns: String,
    lan_if: String,
    client_if: String,
    uplink_if: String,
    upstream_if: String,
    foreign_table: String,
    original_forwarding: Vec<u8>,
    original_owned_table: Option<Vec<u8>>,
}

impl RouterDataplaneFixture {
    fn new() -> Result<Self> {
        require_root()?;
        require_command("ip", &["-V"])?;
        require_command("nft", &["--version"])?;
        require_command("ping", &["-V"])?;

        let suffix = unique_suffix();
        let mut fixture = Self {
            client_ns: format!("tmc{suffix}"),
            upstream_ns: format!("tmu{suffix}"),
            lan_if: format!("tml{suffix}"),
            client_if: format!("tmcp{suffix}"),
            uplink_if: format!("tmup{suffix}"),
            upstream_if: format!("tmusp{suffix}"),
            foreign_table: format!("tmf{suffix}"),
            original_forwarding: fs::read(IPV4_FORWARDING_PATH)
                .context("failed to snapshot IPv4 forwarding")?,
            original_owned_table: snapshot_owned_table()?,
        };

        if let Err(error) = fixture.setup() {
            fixture.cleanup();
            return Err(error);
        }
        Ok(fixture)
    }

    fn setup(&mut self) -> Result<()> {
        run("ip", &["netns", "add", &self.client_ns])?;
        run("ip", &["netns", "add", &self.upstream_ns])?;
        create_veth(&self.lan_if, &self.client_if, &self.client_ns)?;
        create_veth(&self.uplink_if, &self.upstream_if, &self.upstream_ns)?;

        run("ip", &["addr", "add", "192.0.2.1/24", "dev", &self.lan_if])?;
        run("ip", &["link", "set", &self.lan_if, "up"])?;
        run(
            "ip",
            &["addr", "add", "198.51.100.1/24", "dev", &self.uplink_if],
        )?;
        run("ip", &["link", "set", &self.uplink_if, "up"])?;

        configure_namespace_interface(&self.client_ns, &self.client_if, "192.0.2.2/24")?;
        run(
            "ip",
            &[
                "-n",
                &self.client_ns,
                "route",
                "add",
                "default",
                "via",
                "192.0.2.1",
            ],
        )?;
        configure_namespace_interface(&self.upstream_ns, &self.upstream_if, "198.51.100.2/24")?;

        let batch = format!(
            "table inet {} {{\n  chain sentinel {{\n    type filter hook input priority 300; policy accept;\n    counter\n  }}\n}}\n",
            self.foreign_table
        );
        run_with_input("nft", &["-f", "-"], batch.as_bytes())?;
        Ok(())
    }

    fn assert_foreign_table_exists(&self) -> Result<()> {
        run("nft", &["list", "table", "inet", &self.foreign_table])
    }

    fn cleanup(&mut self) {
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", &self.foreign_table])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = restore_owned_table(self.original_owned_table.as_deref());
        let _ = fs::write(IPV4_FORWARDING_PATH, &self.original_forwarding);
        let _ = Command::new("ip")
            .args(["netns", "del", &self.client_ns])
            .status();
        let _ = Command::new("ip")
            .args(["netns", "del", &self.upstream_ns])
            .status();
    }
}

impl Drop for RouterDataplaneFixture {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[tokio::test]
#[ignore = "requires root, Linux, iproute2, nftables and ping; run explicitly on a disposable test host"]
async fn production_forwarding_and_nftables_route_and_masquerade() -> Result<()> {
    let _test_guard = NAMESPACE_TEST_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("namespace test lock is poisoned"))?;
    let fixture = RouterDataplaneFixture::new()?;
    let provider = LinuxRouterDataplaneProvider::new(
        Ipv4ForwardingBackend::new(ProcSysIpv4ForwardingIo),
        NftablesBackend::new(NftCommandExecutor),
        RtnetlinkNetworkProvider::connect().context("failed to connect rtnetlink preflight")?,
    );
    let manager = RouterDataplaneManager::new(provider);
    let desired = RouterDataplaneDesired {
        uplink: fixture.uplink_if.clone(),
        outputs: vec![OutputNetwork {
            interface: fixture.lan_if.clone(),
            subnet: "192.0.2.0/24".parse()?,
        }],
    };

    let plan = manager.plan(desired.clone()).await?;
    let snapshot = manager.apply(&plan).await?;
    fixture.assert_foreign_table_exists()?;

    run(
        "ip",
        &[
            "netns",
            "exec",
            &fixture.client_ns,
            "ping",
            "-c",
            "2",
            "-W",
            "2",
            "198.51.100.2",
        ],
    )?;

    let owned_before_reapply =
        command_output("nft", &["--json", "list", "table", "inet", "traffic_masq"])?.stdout;
    let reapply_plan = manager.plan(desired).await?;
    assert!(
        !reapply_plan.requires_apply,
        "production observe must recognize the already-applied desired state"
    );
    manager.apply(&reapply_plan).await?;
    let owned_after_reapply =
        command_output("nft", &["--json", "list", "table", "inet", "traffic_masq"])?.stdout;
    assert_eq!(
        owned_after_reapply, owned_before_reapply,
        "idempotent reapply must not recreate or duplicate owned nftables objects"
    );
    fixture.assert_foreign_table_exists()?;

    manager.rollback(&snapshot).await?;
    fixture.assert_foreign_table_exists()?;
    assert_eq!(
        fs::read(IPV4_FORWARDING_PATH)?,
        fixture.original_forwarding,
        "rollback must restore the original IPv4 forwarding value"
    );
    assert_eq!(snapshot_owned_table()?, fixture.original_owned_table);
    Ok(())
}

fn create_veth(host_if: &str, peer_if: &str, peer_ns: &str) -> Result<()> {
    run(
        "ip",
        &[
            "link", "add", host_if, "type", "veth", "peer", "name", peer_if,
        ],
    )?;
    run("ip", &["link", "set", peer_if, "netns", peer_ns])
}

fn configure_namespace_interface(ns: &str, interface: &str, address: &str) -> Result<()> {
    run("ip", &["-n", ns, "link", "set", "lo", "up"])?;
    run("ip", &["-n", ns, "addr", "add", address, "dev", interface])?;
    run("ip", &["-n", ns, "link", "set", interface, "up"])
}

fn snapshot_owned_table() -> Result<Option<Vec<u8>>> {
    let output = Command::new("nft")
        .args(["list", "table", "inet", "traffic_masq"])
        .output()
        .context("failed to inspect the project-owned nftables table")?;
    if output.status.success() {
        return Ok(Some(output.stdout));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("No such file or directory") {
        return Ok(None);
    }
    bail!("failed to snapshot project-owned nftables table: {stderr}")
}

fn restore_owned_table(snapshot: Option<&[u8]>) -> Result<()> {
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "traffic_masq"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if let Some(table) = snapshot {
        run_with_input("nft", &["-f", "-"], table)?;
    }
    Ok(())
}

fn require_root() -> Result<()> {
    let output = command_output("id", &["-u"])?;
    if String::from_utf8_lossy(&output.stdout).trim() != "0" {
        bail!("this ignored integration test must be run as root");
    }
    Ok(())
}

fn require_command(program: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("required command is not available: {program}"))?;
    if !output.success() {
        bail!("required command failed its availability check: {program}");
    }
    Ok(())
}

fn command_output(program: &str, args: &[&str]) -> Result<Output> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute {program}"))?;
    if !output.status.success() {
        bail!(
            "command failed: {program} {args:?}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output)
}

fn run(program: &str, args: &[&str]) -> Result<()> {
    command_output(program, args).map(|_| ())
}

fn run_with_input(program: &str, args: &[&str], input: &[u8]) -> Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to execute {program}"))?;
    use std::io::Write;
    child
        .stdin
        .take()
        .context("child stdin was not available")?
        .write_all(input)?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "command failed: {program} {args:?}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .subsec_nanos();
    format!("{:05}", (nanos ^ std::process::id()) % 100_000)
}
