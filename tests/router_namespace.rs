use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use tempfile::tempdir;
use tokio::time::timeout;
use traffic_masq::api::client::ApiClient;
use traffic_masq::api::model::Request;
use traffic_masq::config::{
    AppConfig, DhcpInterfaceConfig, InterfaceConfig, InterfaceRole, RouterConfig, ShutdownPolicy,
    UplinkConfig, UplinkMode,
};

mod support;

use support::namespace::{
    create_veth, require_command, require_root, run, unique_suffix, wait_for_listener_ready,
};

static NAMESPACE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const WAIT_TIMEOUT: Duration = Duration::from_secs(30);

const CLIENT_SUBNET: &str = "192.0.2.0/24";
const CLIENT_ROUTER: &str = "192.0.2.1";
const CLIENT_POOL_START: &str = "192.0.2.100";
const CLIENT_POOL_END: &str = "192.0.2.150";
const CLIENT_DNS: &str = "8.8.8.8";
const UPLINK_HOST_ADDR: &str = "198.51.100.1";
const UPSTREAM_ADDR: &str = "198.51.100.2";
const ECHO_PORT: u16 = 18421;

struct RouterNamespaceFixture {
    client_ns: String,
    upstream_ns: String,
    lan_if: String,
    client_if: String,
    uplink_if: String,
    upstream_if: String,
    temp: tempfile::TempDir,
    config: AppConfig,
    config_path: PathBuf,
    lease_script: PathBuf,
    lease_result: PathBuf,
    daemon: Option<std::process::Child>,

    forwarding_baseline: String,
}

impl RouterNamespaceFixture {
    async fn new() -> Result<Self> {
        require_root()?;
        require_command("ip", &["-V"])?;
        require_command("nft", &["--version"])?;
        require_command("udhcpc", &["--help"])?;
        require_command("python3", &["--version"])?;

        let suffix = unique_suffix();
        let temp = tempdir().context("failed to create temp state directory")?;
        let lease_script = temp.path().join("udhcpc-bound.sh");
        let lease_result = temp.path().join("lease-result.txt");
        write_lease_script(&lease_script, &lease_result)?;

        let forwarding_baseline = fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .context("failed to read pre-test IPv4 forwarding sysctl")?
            .trim()
            .to_string();

        let lan_if = format!("tmrl{suffix}");
        let client_if = format!("tmrc{suffix}");
        let uplink_if = format!("tmru{suffix}");
        let upstream_if = format!("tmrs{suffix}");
        let client_ns = format!("tmrcn{suffix}");
        let upstream_ns = format!("tmrun{suffix}");

        let config = build_config(&temp, &lan_if, &uplink_if);
        config
            .validate()
            .context("router namespace fixture built an invalid AppConfig")?;
        let config_path = temp.path().join("traffic-masqd.toml");
        fs::write(
            &config_path,
            toml::to_string_pretty(&config).context("failed to serialize test config")?,
        )
        .context("failed to write test config")?;

        let mut fixture = Self {
            client_ns,
            upstream_ns,
            lan_if,
            client_if,
            uplink_if,
            upstream_if,
            temp,
            config,
            config_path,
            lease_script,
            lease_result,
            daemon: None,
            forwarding_baseline,
        };

        if let Err(error) = fixture.setup_topology() {
            fixture.dump_state_on_failure("topology setup");
            fixture.cleanup();
            return Err(error);
        }
        Ok(fixture)
    }

    fn setup_topology(&mut self) -> Result<()> {
        run("ip", &["netns", "add", &self.client_ns])?;
        run("ip", &["netns", "add", &self.upstream_ns])?;
        create_veth(&self.lan_if, &self.client_if, &self.client_ns)?;
        create_veth(&self.uplink_if, &self.upstream_if, &self.upstream_ns)?;

        run("ip", &["link", "set", &self.lan_if, "up"])?;

        run(
            "ip",
            &[
                "addr",
                "add",
                &format!("{UPLINK_HOST_ADDR}/24"),
                "dev",
                &self.uplink_if,
            ],
        )?;
        run("ip", &["link", "set", &self.uplink_if, "up"])?;

        run("ip", &["-n", &self.client_ns, "link", "set", "lo", "up"])?;
        run(
            "ip",
            &["-n", &self.client_ns, "link", "set", &self.client_if, "up"],
        )?;

        run("ip", &["-n", &self.upstream_ns, "link", "set", "lo", "up"])?;
        run(
            "ip",
            &[
                "-n",
                &self.upstream_ns,
                "addr",
                "add",
                &format!("{UPSTREAM_ADDR}/24"),
                "dev",
                &self.upstream_if,
            ],
        )?;
        run(
            "ip",
            &[
                "-n",
                &self.upstream_ns,
                "link",
                "set",
                &self.upstream_if,
                "up",
            ],
        )?;

        Ok(())
    }

    async fn start_daemon(&mut self) -> Result<()> {
        let binary = env!("CARGO_BIN_EXE_traffic-masqd");
        let stdout_log = fs::File::create(self.temp.path().join("daemon-stdout.log"))
            .context("failed to create daemon stdout log")?;
        let stderr_log = fs::File::create(self.temp.path().join("daemon-stderr.log"))
            .context("failed to create daemon stderr log")?;
        let child = Command::new(binary)
            .arg("--config")
            .arg(&self.config_path)
            .arg("run")
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout_log))
            .stderr(Stdio::from(stderr_log))
            .spawn()
            .context("failed to spawn traffic-masqd")?;
        self.daemon = Some(child);

        let client = ApiClient::new(self.config.runtime.socket_path.clone());
        let ready = timeout(WAIT_TIMEOUT, async {
            loop {
                if client.request(&Request::Ping).await.is_ok() {
                    return;
                }
                if let Some(child) = &mut self.daemon {
                    if let Ok(Some(status)) = child.try_wait() {
                        panic!("traffic-masqd exited during startup with status {status}");
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        ready.context("traffic-masqd did not become ready in time")?;
        Ok(())
    }

    async fn stop_daemon_gracefully(&mut self) -> Result<()> {
        let Some(mut child) = self.daemon.take() else {
            bail!("daemon was not running");
        };
        let pid = i32::try_from(child.id()).context("daemon PID exceeds pid_t range")?;
        kill(Pid::from_raw(pid), Signal::SIGTERM).context("failed to send SIGTERM to daemon")?;

        let exited = timeout(WAIT_TIMEOUT, async {
            loop {
                if let Ok(Some(status)) = child.try_wait() {
                    return status;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .context("traffic-masqd did not stop within the timeout")?;

        if !exited.success() {
            bail!("traffic-masqd exited with non-zero status on graceful shutdown: {exited}");
        }
        Ok(())
    }

    fn dump_state_on_failure(&self, phase: &str) {
        eprintln!("=== router_namespace failure dump ({phase}) ===");
        for (label, args) in [
            (
                "client ns addresses",
                vec!["-n", &self.client_ns, "addr", "show"],
            ),
            (
                "client ns routes",
                vec!["-n", &self.client_ns, "route", "show"],
            ),
            (
                "upstream ns addresses",
                vec!["-n", &self.upstream_ns, "addr", "show"],
            ),
            ("host lan_if", vec!["addr", "show", "dev", &self.lan_if]),
            (
                "host uplink_if",
                vec!["addr", "show", "dev", &self.uplink_if],
            ),
            ("host routes", vec!["route", "show"]),
        ] {
            eprintln!("--- ip {label} ---");
            let _ = Command::new("ip").args(&args).status();
        }
        eprintln!("--- nft owned table (traffic_masq) ---");
        let _ = Command::new("nft")
            .args(["list", "table", "inet", "traffic_masq"])
            .status();
        eprintln!("--- ipv4 forwarding ---");
        if let Ok(value) = fs::read_to_string("/proc/sys/net/ipv4/ip_forward") {
            eprintln!("{}", value.trim());
        }
        for name in ["daemon-stdout.log", "daemon-stderr.log"] {
            let path = self.temp.path().join(name);
            eprintln!("--- {name} ---");
            if let Ok(contents) = fs::read_to_string(&path) {
                eprintln!("{contents}");
            }
        }
        let log_dir = self.config.runtime.log_dir.clone();
        if let Ok(entries) = fs::read_dir(&log_dir) {
            for entry in entries.flatten() {
                eprintln!("--- daemon log: {} ---", entry.path().display());
                if let Ok(contents) = fs::read_to_string(entry.path()) {
                    eprintln!("{contents}");
                }
            }
        }
        eprintln!("=== end failure dump ===");
    }

    fn cleanup(&mut self) {
        if let Some(mut child) = self.daemon.take() {
            if let Ok(pid) = i32::try_from(child.id()) {
                let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
            }
            let _ = child.wait();
        }
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", "traffic_masq"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = fs::write("/proc/sys/net/ipv4/ip_forward", b"0\n");
        let _ = Command::new("ip")
            .args(["link", "del", &self.lan_if])
            .status();
        let _ = Command::new("ip")
            .args(["link", "del", &self.uplink_if])
            .status();
        let _ = Command::new("ip")
            .args(["netns", "del", &self.client_ns])
            .status();
        let _ = Command::new("ip")
            .args(["netns", "del", &self.upstream_ns])
            .status();
    }
}

impl Drop for RouterNamespaceFixture {
    fn drop(&mut self) {
        self.cleanup();
    }
}

fn build_config(temp: &tempfile::TempDir, lan_if: &str, uplink_if: &str) -> AppConfig {
    let mut config = AppConfig::default();
    config.runtime.state_dir = temp.path().join("state");
    config.runtime.log_dir = temp.path().join("log");
    config.runtime.socket_path = temp.path().join("traffic-masqd.sock");
    config.runtime.pid_path = temp.path().join("traffic-masqd.pid");

    config.runtime.shutdown_policy = ShutdownPolicy::RestoreInterfaces;

    config.dhcp.leases_dir = temp.path().join("dhcp-leases");
    config.dhcp.default_lease_seconds = 120;

    config.auth.database_path = temp.path().join("auth.sqlite3");

    config.auth.argon2_memory_kib = 1_024;
    config.auth.argon2_iterations = 1;

    config.network.interfaces.insert(
        uplink_if.to_string(),
        InterfaceConfig {
            mac_address: None,
            nat: true,
            role: InterfaceRole::Input,
            managed: false,
            ipv4: None,
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        },
    );
    config.network.interfaces.insert(
        lan_if.to_string(),
        InterfaceConfig {
            mac_address: None,
            nat: true,
            role: InterfaceRole::Output,
            managed: true,

            ipv4: Some(
                format!("{CLIENT_ROUTER}/24")
                    .parse()
                    .expect("client interface address"),
            ),
            dhcp: Some(DhcpInterfaceConfig {
                pool_start: CLIENT_POOL_START.parse().expect("pool start"),
                pool_end: CLIENT_POOL_END.parse().expect("pool end"),
                router: CLIENT_ROUTER.parse().expect("router"),
                dns_servers: vec![CLIENT_DNS.parse().expect("dns")],
                lease_seconds: Some(120),
            }),
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        },
    );

    config.router = RouterConfig {
        forwarding: None,
        vpn_chain: Vec::new(),
        uplink: Some(UplinkConfig {
            interface: uplink_if.to_string(),
            mode: UplinkMode::External,
        }),
        owned_routes: Vec::new(),
        allow_default_route_change: false,
        route_host_traffic: false,
    };

    config
}

fn write_lease_script(script_path: &std::path::Path, result_path: &std::path::Path) -> Result<()> {
    let contents = format!(
        "#!/bin/sh\ncase \"$1\" in\n  bound|renew)\n    ip -4 addr flush dev \"$interface\"\n    ip -4 addr add \"$ip/$subnet\" dev \"$interface\"\n    for r in $router; do ip route replace default via \"$r\" dev \"$interface\"; done\n    {{\n      echo \"ip=$ip\"\n      echo \"subnet=$subnet\"\n      echo \"router=$router\"\n      echo \"dns=$dns\"\n    }} > {result:?}\n    ;;\n  deconfig)\n    ip -4 addr flush dev \"$interface\"\n    ;;\nesac\n",
        result = result_path
    );
    fs::write(script_path, contents).context("failed to write udhcpc bound script")?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(script_path, fs::Permissions::from_mode(0o700))
        .context("failed to make udhcpc bound script executable")?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires root, Linux, iproute2, nftables, udhcpc and python3; spawns a real traffic-masqd process; run only on a disposable test host"]
async fn daemon_serves_dhcp_forwards_and_masquerades_client_traffic() -> Result<()> {
    let _test_guard = NAMESPACE_TEST_LOCK.lock().await;

    let mut fixture = RouterNamespaceFixture::new().await?;
    if let Err(error) = run_happy_path(&mut fixture).await {
        fixture.dump_state_on_failure("happy path");
        return Err(error);
    }
    Ok(())
}

async fn run_happy_path(fixture: &mut RouterNamespaceFixture) -> Result<()> {
    timeout(WAIT_TIMEOUT, fixture.start_daemon())
        .await
        .context("timed out waiting to start traffic-masqd")??;

    timeout(WAIT_TIMEOUT, acquire_lease(fixture))
        .await
        .context("timed out acquiring DHCP lease")??;

    assert_lease_matches_config(fixture)?;

    let server = spawn_echo_server(fixture).await?;

    let echoed = timeout(WAIT_TIMEOUT, connect_and_echo(fixture))
        .await
        .context("timed out connecting to the upstream echo server")??;
    assert_eq!(
        echoed, "traffic-masq-e2e",
        "item 9: established reverse traffic must deliver the echoed payload back to the client"
    );

    let server_output = timeout(WAIT_TIMEOUT, async {
        tokio::task::spawn_blocking(move || server.wait_with_output())
            .await
            .context("echo server task panicked")?
            .context("failed to wait for echo server")
    })
    .await
    .context("timed out waiting for the echo server to finish")??;
    if !server_output.status.success() {
        bail!(
            "upstream echo server failed: {}",
            String::from_utf8_lossy(&server_output.stderr)
        );
    }
    let observed_peer = String::from_utf8_lossy(&server_output.stdout)
        .trim()
        .to_string();

    assert_eq!(
        observed_peer, UPLINK_HOST_ADDR,
        "upstream must observe the router uplink address as the TCP peer (masquerade), not the private client address"
    );

    timeout(WAIT_TIMEOUT, fixture.stop_daemon_gracefully())
        .await
        .context("timed out stopping traffic-masqd")??;
    assert_dataplane_rolled_back(fixture)?;

    Ok(())
}

async fn acquire_lease(fixture: &RouterNamespaceFixture) -> Result<()> {
    let status = tokio::process::Command::new("ip")
        .args([
            "netns",
            "exec",
            &fixture.client_ns,
            "udhcpc",
            "-i",
            &fixture.client_if,
            "-n",
            "-q",
            "-f",
            "-t",
            "5",
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
        .context("failed to execute udhcpc in client namespace")?;
    if !status.success() {
        bail!(
            "udhcpc failed to obtain a lease in namespace {}",
            fixture.client_ns
        );
    }
    Ok(())
}

fn assert_lease_matches_config(fixture: &RouterNamespaceFixture) -> Result<()> {
    let contents = fs::read_to_string(&fixture.lease_result)
        .context("udhcpc bound script did not write a lease result file")?;
    let mut ip = None;
    let mut subnet = None;
    let mut router = None;
    let mut dns = None;
    for line in contents.lines() {
        if let Some(value) = line.strip_prefix("ip=") {
            ip = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("subnet=") {
            subnet = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("router=") {
            router = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("dns=") {
            dns = Some(value.to_string());
        }
    }

    let ip: Ipv4Addr = ip
        .context("lease result missing ip")?
        .parse()
        .context("lease result ip is not a valid IPv4 address")?;
    let expected_subnet: ipnet::Ipv4Net = CLIENT_SUBNET.parse().expect("client subnet");
    if !expected_subnet.contains(&ip) || ip == expected_subnet.addr() {
        bail!("leased address {ip} is not inside the configured client pool {CLIENT_SUBNET}");
    }
    let start: Ipv4Addr = CLIENT_POOL_START.parse().expect("pool start");
    let end: Ipv4Addr = CLIENT_POOL_END.parse().expect("pool end");
    if !(u32::from(start)..=u32::from(end)).contains(&u32::from(ip)) {
        bail!("leased address {ip} is outside the configured pool {CLIENT_POOL_START}-{CLIENT_POOL_END}");
    }

    let subnet = subnet.context("lease result missing subnet")?;
    if subnet.trim() != "255.255.255.0" {
        bail!("leased subnet mask {subnet} does not match the configured /24 client subnet");
    }

    let router = router.context("lease result missing router")?;
    if router.split_whitespace().next() != Some(CLIENT_ROUTER) {
        bail!("leased default gateway {router} does not match configured router {CLIENT_ROUTER}");
    }

    let dns = dns.context("lease result missing dns")?;
    if !dns.split_whitespace().any(|server| server == CLIENT_DNS) {
        bail!("leased DNS options {dns} do not include configured DNS server {CLIENT_DNS}");
    }

    Ok(())
}

async fn spawn_echo_server(fixture: &RouterNamespaceFixture) -> Result<std::process::Child> {
    let ready = tempfile::NamedTempFile::new_in(fixture.temp.path())
        .context("failed to create echo listener readiness file")?;
    let script = format!(
        "import socket, sys\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\ns.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\ns.settimeout(25)\ns.bind(('{UPSTREAM_ADDR}', {ECHO_PORT}))\ns.listen(1)\nwith open(sys.argv[1], 'w') as ready:\n    ready.write('ready')\nconn, addr = s.accept()\nconn.settimeout(25)\ndata = conn.recv(4096)\nconn.sendall(data)\nconn.close()\nprint(addr[0], flush=True)\n"
    );
    let child = Command::new("ip")
        .args([
            "netns",
            "exec",
            &fixture.upstream_ns,
            "python3",
            "-c",
            &script,
        ])
        .arg(ready.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn upstream TCP echo server")?;
    wait_for_listener_ready(child, ready.path(), WAIT_TIMEOUT).await
}

async fn connect_and_echo(fixture: &RouterNamespaceFixture) -> Result<String> {
    let script = format!(
        "import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\ns.settimeout(20)\ns.connect(('{UPSTREAM_ADDR}', {ECHO_PORT}))\ns.sendall(b'traffic-masq-e2e')\ndata = s.recv(4096)\ns.close()\nprint(data.decode(), end='')\n"
    );
    let output = tokio::process::Command::new("ip")
        .args([
            "netns",
            "exec",
            &fixture.client_ns,
            "python3",
            "-c",
            &script,
        ])
        .output()
        .await
        .context("failed to execute client echo probe")?;
    if !output.status.success() {
        bail!(
            "client failed to reach upstream echo server: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn assert_dataplane_rolled_back(fixture: &RouterNamespaceFixture) -> Result<()> {
    let output = Command::new("nft")
        .args(["list", "table", "inet", "traffic_masq"])
        .output()
        .context("failed to inspect the owned nftables table after shutdown")?;
    if output.status.success() {
        bail!("owned nftables table `traffic_masq` still exists after graceful shutdown with RestoreInterfaces policy");
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.contains("No such file or directory") {
        bail!("unexpected error inspecting owned nftables table after shutdown: {stderr}");
    }

    let forwarding = fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
        .context("failed to read IPv4 forwarding sysctl after shutdown")?;
    if forwarding.trim() != fixture.forwarding_baseline {
        bail!(
            "IPv4 forwarding was not restored to its pre-test value ({}) after graceful shutdown: {}",
            fixture.forwarding_baseline,
            forwarding.trim()
        );
    }

    Ok(())
}
