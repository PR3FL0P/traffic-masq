use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

static NAMESPACE_TEST_LOCK: Mutex<()> = Mutex::new(());

const WAIT_TIMEOUT: Duration = Duration::from_secs(30);

const BLOCKED_FLOW_TIMEOUT: Duration = Duration::from_secs(5);

const CLIENT_SUBNET: &str = "192.0.2.0/24";
const CLIENT_ROUTER: &str = "192.0.2.1";
const CLIENT_POOL_START: &str = "192.0.2.100";
const CLIENT_POOL_END: &str = "192.0.2.150";
const CLIENT_DNS: &str = "8.8.8.8";
const UPLINK_HOST_ADDR: &str = "198.51.100.1";
const UPSTREAM_ADDR: &str = "198.51.100.2";
const ECHO_PORT: u16 = 18521;
const FOREIGN_ROUTE_DEST: &str = "203.0.113.0/24";
const FOREIGN_ROUTE_GATEWAY: &str = "198.51.100.99";
const MANAGEMENT_ADDR: &str = "203.0.113.1/24";

struct FixtureOptions {
    bring_uplink_up: bool,

    bogus_uplink: bool,

    foreign_state: bool,

    management_interface: bool,
}

impl Default for FixtureOptions {
    fn default() -> Self {
        Self {
            bring_uplink_up: true,
            bogus_uplink: false,
            foreign_state: false,
            management_interface: false,
        }
    }
}

struct RouterNamespaceFixture {
    client_ns: String,
    upstream_ns: String,
    lan_if: String,
    client_if: String,
    uplink_if: String,
    upstream_if: String,
    foreign_table: String,
    management_if: String,
    management_peer_if: String,
    options: FixtureOptions,
    temp: tempfile::TempDir,
    config: AppConfig,
    config_path: PathBuf,
    lease_script: PathBuf,
    lease_result: PathBuf,
    daemon: Option<std::process::Child>,
    forwarding_baseline: String,
}

impl RouterNamespaceFixture {
    async fn new(options: FixtureOptions) -> Result<Self> {
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

        let lan_if = format!("tnrl{suffix}");
        let client_if = format!("tnrc{suffix}");
        let uplink_if = format!("tnru{suffix}");
        let upstream_if = format!("tnrs{suffix}");
        let client_ns = format!("tnrcn{suffix}");
        let upstream_ns = format!("tnrun{suffix}");
        let foreign_table = format!("tnrf{suffix}");
        let management_if = format!("tnrm{suffix}");
        let management_peer_if = format!("tnrmp{suffix}");

        let uplink_config_name = if options.bogus_uplink {
            format!("tnrbogus{suffix}")
        } else {
            uplink_if.clone()
        };

        let mut config = build_config(&temp, &lan_if, &uplink_config_name);
        if options.management_interface {
            config.network.interfaces.insert(
                management_if.clone(),
                InterfaceConfig {
                    nat: true,
                    role: InterfaceRole::None,
                    managed: true,
                    ipv4: Some(MANAGEMENT_ADDR.parse().expect("management address")),
                    dhcp: None,
                    dhcp_client: None,
                    wifi: None,
                    wifi_client: None,
                },
            );
        }
        config
            .validate()
            .context("router namespace negative fixture built an invalid AppConfig")?;
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
            foreign_table,
            management_if,
            management_peer_if,
            options,
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

        run("ip", &["link", "set", &self.lan_if, "up"])?;

        if !self.options.bogus_uplink {
            create_veth(&self.uplink_if, &self.upstream_if, &self.upstream_ns)?;
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
            if self.options.bring_uplink_up {
                run("ip", &["link", "set", &self.uplink_if, "up"])?;
            }

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
        }

        run("ip", &["-n", &self.client_ns, "link", "set", "lo", "up"])?;
        run(
            "ip",
            &["-n", &self.client_ns, "link", "set", &self.client_if, "up"],
        )?;

        if self.options.foreign_state {
            let batch = format!(
                "table inet {} {{\n  chain sentinel {{\n    type filter hook input priority 300; policy accept;\n    counter\n  }}\n}}\n",
                self.foreign_table
            );
            run_with_input("nft", &["-f", "-"], batch.as_bytes())?;

            run(
                "ip",
                &[
                    "route",
                    "add",
                    FOREIGN_ROUTE_DEST,
                    "via",
                    FOREIGN_ROUTE_GATEWAY,
                    "dev",
                    &self.uplink_if,
                ],
            )?;
        }

        if self.options.management_interface {
            create_veth(&self.management_if, &self.management_peer_if, "").or_else(|_| {
                run(
                    "ip",
                    &[
                        "link",
                        "add",
                        &self.management_if,
                        "type",
                        "veth",
                        "peer",
                        "name",
                        &self.management_peer_if,
                    ],
                )
            })?;
            run(
                "ip",
                &["addr", "add", MANAGEMENT_ADDR, "dev", &self.management_if],
            )?;
            run("ip", &["link", "set", &self.management_if, "up"])?;

            run("ip", &["link", "set", &self.management_peer_if, "up"])?;
            wait_for_link_carrier_up(&self.management_if)?;
        }

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

    async fn start_daemon_expect_failure(&mut self) -> Result<()> {
        let binary = env!("CARGO_BIN_EXE_traffic-masqd");
        let stdout_log = fs::File::create(self.temp.path().join("daemon-stdout.log"))
            .context("failed to create daemon stdout log")?;
        let stderr_log = fs::File::create(self.temp.path().join("daemon-stderr.log"))
            .context("failed to create daemon stderr log")?;
        let mut child = Command::new(binary)
            .arg("--config")
            .arg(&self.config_path)
            .arg("run")
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout_log))
            .stderr(Stdio::from(stderr_log))
            .spawn()
            .context("failed to spawn traffic-masqd")?;

        let status = timeout(WAIT_TIMEOUT, async {
            loop {
                if let Ok(Some(status)) = child.try_wait() {
                    return status;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .context("traffic-masqd did not exit in time (expected an early startup failure)")?;

        if status.success() {
            bail!("traffic-masqd was expected to fail at startup but exited successfully");
        }
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

    fn daemon_is_alive(&mut self) -> bool {
        match &mut self.daemon {
            Some(child) => matches!(child.try_wait(), Ok(None)),
            None => false,
        }
    }

    fn dump_state_on_failure(&self, phase: &str) {
        eprintln!("=== router_namespace_negative failure dump ({phase}) ===");
        for (label, args) in [
            (
                "client ns addresses",
                vec!["-n", &self.client_ns, "addr", "show"],
            ),
            (
                "upstream ns addresses",
                vec!["-n", &self.upstream_ns, "addr", "show"],
            ),
            ("host lan_if", vec!["addr", "show", "dev", &self.lan_if]),
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
        if self.options.foreign_state {
            let _ = Command::new("nft")
                .args(["delete", "table", "inet", &self.foreign_table])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = Command::new("ip")
                .args(["route", "del", FOREIGN_ROUTE_DEST])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = fs::write("/proc/sys/net/ipv4/ip_forward", b"0\n");
        let _ = Command::new("ip")
            .args(["link", "del", &self.lan_if])
            .status();
        if !self.options.bogus_uplink {
            let _ = Command::new("ip")
                .args(["link", "del", &self.uplink_if])
                .status();
        }
        if self.options.management_interface {
            let _ = Command::new("ip")
                .args(["link", "del", &self.management_if])
                .status();
        }
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
        enabled: true,
        uplink: Some(UplinkConfig {
            interface: uplink_if.to_string(),
            mode: UplinkMode::External,
        }),
        owned_routes: Vec::new(),
        allow_default_route_change: false,
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

fn leased_client_ip(fixture: &RouterNamespaceFixture) -> Result<Ipv4Addr> {
    let contents = fs::read_to_string(&fixture.lease_result)
        .context("udhcpc bound script did not write a lease result file")?;
    for line in contents.lines() {
        if let Some(value) = line.strip_prefix("ip=") {
            return value
                .parse()
                .context("lease result ip is not a valid IPv4 address");
        }
    }
    bail!("lease result missing ip")
}

fn spawn_echo_server(fixture: &RouterNamespaceFixture) -> Result<std::process::Child> {
    let script = format!(
        "import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\ns.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\ns.settimeout(25)\ns.bind(('{UPSTREAM_ADDR}', {ECHO_PORT}))\ns.listen(1)\nconn, addr = s.accept()\nconn.settimeout(25)\ndata = conn.recv(4096)\nconn.sendall(data)\nconn.close()\nprint(addr[0], flush=True)\n"
    );
    Command::new("ip")
        .args([
            "netns",
            "exec",
            &fixture.upstream_ns,
            "python3",
            "-c",
            &script,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn upstream TCP echo server")
}

async fn connect_and_echo(fixture: &RouterNamespaceFixture, timeout_secs: u64) -> Result<String> {
    let script = format!(
        "import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\ns.settimeout({timeout_secs})\ns.connect(('{UPSTREAM_ADDR}', {ECHO_PORT}))\ns.sendall(b'traffic-masq-e2e')\ndata = s.recv(4096)\ns.close()\nprint(data.decode(), end='')\n"
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

fn assert_no_owned_nft_table() -> Result<()> {
    let output = Command::new("nft")
        .args(["list", "table", "inet", "traffic_masq"])
        .output()
        .context("failed to inspect the owned nftables table")?;
    if output.status.success() {
        bail!("owned nftables table `traffic_masq` unexpectedly exists");
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.contains("No such file or directory") {
        bail!("unexpected error inspecting owned nftables table: {stderr}");
    }
    Ok(())
}

fn normalize_nft_output(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    text.lines()
        .map(|line| {
            if let Some(idx) = line.find("counter packets") {
                let (prefix, _) = line.split_at(idx);
                format!("{prefix}counter packets <n> bytes <n>")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn owned_nft_table_snapshot() -> Result<Option<Vec<u8>>> {
    let output = Command::new("nft")
        .args(["--json", "list", "table", "inet", "traffic_masq"])
        .output()
        .context("failed to inspect the owned nftables table")?;
    if output.status.success() {
        return Ok(Some(output.stdout));
    }
    Ok(None)
}

fn host_ipv4_addresses(interface: &str) -> Result<String> {
    let output = Command::new("ip")
        .args(["-4", "addr", "show", "dev", interface])
        .output()
        .with_context(|| format!("failed to inspect addresses on {interface}"))?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn wait_for_link_carrier_up(interface: &str) -> Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let state = host_ipv4_addresses(interface)?;
        if state.contains("LOWER_UP") {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            bail!("timed out waiting for {interface} to report LOWER_UP carrier state: {state}");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

fn route_exists(destination: &str) -> Result<bool> {
    let output = Command::new("ip")
        .args(["route", "show", destination])
        .output()
        .context("failed to inspect host routes")?;
    Ok(!String::from_utf8_lossy(&output.stdout).trim().is_empty())
}

#[tokio::test]
#[ignore = "requires root, Linux, iproute2, nftables, udhcpc and python3; spawns a real traffic-masqd process; run only on a disposable test host"]
async fn uplink_down_blocks_new_flows_without_crashing_daemon() -> Result<()> {
    let _test_guard = NAMESPACE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let mut fixture = RouterNamespaceFixture::new(FixtureOptions {
        bring_uplink_up: false,
        ..FixtureOptions::default()
    })
    .await?;

    let result: Result<()> = async {
        timeout(WAIT_TIMEOUT, fixture.start_daemon())
            .await
            .context("timed out waiting to start traffic-masqd")??;
        timeout(WAIT_TIMEOUT, acquire_lease(&fixture))
            .await
            .context("timed out acquiring DHCP lease")??;

        let server = spawn_echo_server(&fixture)?;
        tokio::time::sleep(Duration::from_millis(300)).await;













        run("ip", &["link", "set", &fixture.uplink_if, "down"])?;

        let probe = timeout(BLOCKED_FLOW_TIMEOUT, connect_and_echo(&fixture, 3)).await;
        let flow_blocked = match probe {
            Ok(Ok(_)) => false,
            Ok(Err(_)) | Err(_) => true,
        };
        let _ = Command::new("ip")
            .args(["netns", "exec", &fixture.upstream_ns, "kill", "-9", "1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = server.wait_with_output();

        assert!(
            flow_blocked,
            "a new client->upstream TCP flow must not succeed while the uplink is administratively down"
        );

        let client = ApiClient::new(fixture.config.runtime.socket_path.clone());
        timeout(Duration::from_secs(5), client.request(&Request::Ping))
            .await
            .context("daemon stopped answering Ping while uplink was down")?
            .context("daemon Ping request failed while uplink was down")?;
        assert!(
            fixture.daemon_is_alive(),
            "traffic-masqd must not crash when the uplink goes down"
        );

        Ok(())
    }
    .await;

    if let Err(error) = &result {
        fixture.dump_state_on_failure("uplink down");
        eprintln!("failure: {error:#}");
    }

    let _ = timeout(WAIT_TIMEOUT, fixture.stop_daemon_gracefully()).await;
    result
}

#[tokio::test]
#[ignore = "requires root and Linux/iproute2; spawns a real traffic-masqd process; run only on a disposable test host"]
async fn invalid_overlapping_output_subnet_is_rejected_before_any_mutation() -> Result<()> {
    let _test_guard = NAMESPACE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    require_root()?;
    require_command("ip", &["-V"])?;
    let suffix = unique_suffix();
    let temp = tempdir().context("failed to create temp state directory")?;
    let lan_a = format!("tnoa{suffix}");
    let lan_b = format!("tnob{suffix}");
    let uplink = format!("tnou{suffix}");

    let cleanup = || {
        let _ = Command::new("ip").args(["link", "del", &lan_a]).status();
        let _ = Command::new("ip").args(["link", "del", &lan_b]).status();
        let _ = Command::new("ip").args(["link", "del", &uplink]).status();
    };

    let setup = (|| -> Result<()> {
        run("ip", &["link", "add", &lan_a, "type", "dummy"])?;
        run("ip", &["link", "add", &lan_b, "type", "dummy"])?;
        run("ip", &["link", "add", &uplink, "type", "dummy"])?;
        Ok(())
    })();
    if let Err(error) = setup {
        cleanup();
        return Err(error);
    }

    let result: Result<()> = (|| {
        let mut config = build_config(&temp, &lan_a, &uplink);

        config.network.interfaces.insert(
            lan_b.clone(),
            InterfaceConfig {
                nat: true,
                role: InterfaceRole::Output,
                managed: true,
                ipv4: Some("192.0.2.64/25".parse().expect("overlapping subnet")),
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
            },
        );

        let config_path = temp.path().join("traffic-masqd.toml");
        fs::write(
            &config_path,
            toml::to_string_pretty(&config).context("failed to serialize test config")?,
        )?;

        let binary = env!("CARGO_BIN_EXE_traffic-masqd");
        let output = Command::new(binary)
            .arg("--config")
            .arg(&config_path)
            .arg("run")
            .output()
            .context("failed to run traffic-masqd with an invalid config")?;
        if output.status.success() {
            bail!("traffic-masqd was expected to reject overlapping output subnets at startup");
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.to_lowercase().contains("overlap") {
            bail!("traffic-masqd startup failure did not mention overlapping networks: {stderr}");
        }

        assert_no_owned_nft_table()?;
        let forwarding = fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .context("failed to read IPv4 forwarding sysctl")?;
        assert_eq!(
            forwarding.trim(),
            "0",
            "IPv4 forwarding must be untouched by a daemon that never started"
        );
        for interface in [&lan_a, &lan_b] {
            let addresses = host_ipv4_addresses(interface)?;
            assert!(
                !addresses.contains("192.0.2."),
                "interface {interface} must not have received an address from a daemon that never started: {addresses}"
            );
        }
        Ok(())
    })();

    cleanup();
    result
}

#[tokio::test]
#[ignore = "requires root, Linux, iproute2 and nftables; spawns a real traffic-masqd process; run only on a disposable test host"]
async fn firewall_apply_failure_rolls_back_interfaces_routes_and_forwarding() -> Result<()> {
    let _test_guard = NAMESPACE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let mut fixture = RouterNamespaceFixture::new(FixtureOptions {
        bogus_uplink: true,
        ..FixtureOptions::default()
    })
    .await?;

    let lan_before = host_ipv4_addresses(&fixture.lan_if)?;
    assert!(
        !lan_before.contains("192.0.2."),
        "sanity: lan_if must have no client address before the daemon ever starts"
    );

    let result: Result<()> = async {
        timeout(WAIT_TIMEOUT, fixture.start_daemon_expect_failure())
            .await
            .context("timed out waiting for traffic-masqd to fail at startup")??;

        assert_no_owned_nft_table()?;
        let forwarding = fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .context("failed to read IPv4 forwarding sysctl")?;
        assert_eq!(
            forwarding.trim(),
            fixture.forwarding_baseline,
            "IPv4 forwarding must roll back to its pre-test baseline after a dataplane apply failure"
        );
        let lan_after = host_ipv4_addresses(&fixture.lan_if)?;
        assert!(
            !lan_after.contains("192.0.2."),
            "lan_if must be rolled back to its pre-daemon state (no address) after a dataplane apply failure: {lan_after}"
        );
        Ok(())
    }
    .await;

    if let Err(error) = &result {
        fixture.dump_state_on_failure("firewall apply failure");
        eprintln!("failure: {error:#}");
    }
    result
}

#[tokio::test]
#[ignore = "requires root, Linux, iproute2, nftables, udhcpc and python3; spawns real traffic-masqd processes; run only on a disposable test host"]
async fn restart_does_not_duplicate_state_and_client_gets_a_lease_again() -> Result<()> {
    let _test_guard = NAMESPACE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let mut fixture = RouterNamespaceFixture::new(FixtureOptions::default()).await?;

    fixture.config.runtime.shutdown_policy = ShutdownPolicy::PreserveInterfaces;
    fs::write(
        &fixture.config_path,
        toml::to_string_pretty(&fixture.config).context("failed to rewrite test config")?,
    )
    .context("failed to persist PreserveInterfaces shutdown policy")?;

    let result: Result<()> = async {
        timeout(WAIT_TIMEOUT, fixture.start_daemon())
            .await
            .context("timed out starting traffic-masqd (first run)")??;
        timeout(WAIT_TIMEOUT, acquire_lease(&fixture))
            .await
            .context("timed out acquiring the first DHCP lease")??;

        let addr_before = host_ipv4_addresses(&fixture.lan_if)?;
        let table_before = owned_nft_table_snapshot()?
            .context("owned nftables table must exist after the first startup")?;
        let routes_before = Command::new("ip")
            .args(["route", "show"])
            .output()
            .context("failed to snapshot host routes")?
            .stdout;

        timeout(WAIT_TIMEOUT, fixture.stop_daemon_gracefully())
            .await
            .context("timed out stopping traffic-masqd (first run)")??;

        timeout(WAIT_TIMEOUT, fixture.start_daemon())
            .await
            .context("timed out starting traffic-masqd (second run)")??;

        let addr_after = host_ipv4_addresses(&fixture.lan_if)?;
        assert_eq!(
            addr_before, addr_after,
            "restart must not add a duplicate IPv4 address to lan_if"
        );
        let table_after = owned_nft_table_snapshot()?
            .context("owned nftables table must exist after the restart")?;
        assert_eq!(
            table_before, table_after,
            "restart must not duplicate or otherwise change owned nftables objects"
        );
        let routes_after = Command::new("ip")
            .args(["route", "show"])
            .output()
            .context("failed to snapshot host routes after restart")?
            .stdout;
        assert_eq!(
            routes_before, routes_after,
            "restart must not duplicate host routes"
        );

        timeout(WAIT_TIMEOUT, acquire_lease(&fixture))
            .await
            .context("timed out acquiring a DHCP lease from the restarted daemon")??;

        timeout(WAIT_TIMEOUT, fixture.stop_daemon_gracefully())
            .await
            .context("timed out stopping traffic-masqd (second run)")??;
        Ok(())
    }
    .await;

    if let Err(error) = &result {
        fixture.dump_state_on_failure("restart");
        eprintln!("failure: {error:#}");
    }
    result
}

#[tokio::test]
#[ignore = "requires root, Linux, iproute2, nftables, udhcpc and python3; spawns a real traffic-masqd process; run only on a disposable test host"]
async fn foreign_route_and_nftables_table_survive_apply_rollback_and_shutdown() -> Result<()> {
    let _test_guard = NAMESPACE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let mut fixture = RouterNamespaceFixture::new(FixtureOptions {
        foreign_state: true,
        ..FixtureOptions::default()
    })
    .await?;

    let foreign_table_before = Command::new("nft")
        .args(["list", "table", "inet", &fixture.foreign_table])
        .output()
        .context("failed to snapshot the foreign nftables table before the daemon starts")?
        .stdout;
    assert!(
        route_exists(FOREIGN_ROUTE_DEST)?,
        "sanity: foreign route must exist before the daemon starts"
    );

    let result: Result<()> = async {
        timeout(WAIT_TIMEOUT, fixture.start_daemon())
            .await
            .context("timed out starting traffic-masqd")??;
        timeout(WAIT_TIMEOUT, acquire_lease(&fixture))
            .await
            .context("timed out acquiring a DHCP lease")??;

        let server = spawn_echo_server(&fixture)?;
        tokio::time::sleep(Duration::from_millis(300)).await;
        timeout(WAIT_TIMEOUT, connect_and_echo(&fixture, 20))
            .await
            .context("timed out reaching the upstream echo server")??;
        let _ = timeout(WAIT_TIMEOUT, async {
            tokio::task::spawn_blocking(move || server.wait_with_output())
                .await
                .ok()
        })
        .await;



        let table_mid = Command::new("nft")
            .args(["list", "table", "inet", &fixture.foreign_table])
            .output()
            .context("failed to inspect the foreign nftables table while the daemon is running")?
            .stdout;
        assert_eq!(
            normalize_nft_output(&foreign_table_before),
            normalize_nft_output(&table_mid),
            "foreign nftables table must be unchanged (ignoring traffic counters) while the daemon's own table is applied"
        );
        assert!(
            route_exists(FOREIGN_ROUTE_DEST)?,
            "foreign route must still exist while the daemon is running"
        );

        timeout(WAIT_TIMEOUT, fixture.stop_daemon_gracefully())
            .await
            .context("timed out stopping traffic-masqd")??;

        let table_after = Command::new("nft")
            .args(["list", "table", "inet", &fixture.foreign_table])
            .output()
            .context("failed to inspect the foreign nftables table after shutdown")?
            .stdout;
        assert_eq!(
            normalize_nft_output(&foreign_table_before),
            normalize_nft_output(&table_after),
            "foreign nftables table must be unchanged (ignoring traffic counters) after graceful shutdown"
        );
        assert!(
            route_exists(FOREIGN_ROUTE_DEST)?,
            "foreign route must still exist after graceful shutdown"
        );
        assert_no_owned_nft_table()?;
        Ok(())
    }
    .await;

    if let Err(error) = &result {
        fixture.dump_state_on_failure("foreign state survival");
        eprintln!("failure: {error:#}");
    }
    result
}

#[tokio::test]
#[ignore = "requires root, Linux, iproute2, nftables, udhcpc and python3; spawns a real traffic-masqd process; run only on a disposable test host"]
async fn new_inbound_from_upstream_is_blocked_established_reply_is_allowed() -> Result<()> {
    let _test_guard = NAMESPACE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let mut fixture = RouterNamespaceFixture::new(FixtureOptions::default()).await?;

    let result: Result<()> = async {
        timeout(WAIT_TIMEOUT, fixture.start_daemon())
            .await
            .context("timed out starting traffic-masqd")??;
        timeout(WAIT_TIMEOUT, acquire_lease(&fixture))
            .await
            .context("timed out acquiring a DHCP lease")??;
        let client_ip = leased_client_ip(&fixture)?;



        let server = spawn_echo_server(&fixture)?;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let echoed = timeout(WAIT_TIMEOUT, connect_and_echo(&fixture, 20))
            .await
            .context("timed out reaching the upstream echo server")??;
        assert_eq!(
            echoed, "traffic-masq-e2e",
            "established reverse traffic must be allowed back to the client"
        );
        let _ = timeout(WAIT_TIMEOUT, async {
            tokio::task::spawn_blocking(move || server.wait_with_output())
                .await
                .ok()
        })
        .await;








        run(
            "ip",
            &[
                "-n",
                &fixture.upstream_ns,
                "route",
                "add",
                CLIENT_SUBNET,
                "via",
                UPLINK_HOST_ADDR,
            ],
        )?;

        let client_server = spawn_client_listener(&fixture)?;
        tokio::time::sleep(Duration::from_millis(300)).await;

        let probe = timeout(
            BLOCKED_FLOW_TIMEOUT,
            connect_from_upstream(&fixture, client_ip),
        )
        .await;
        let blocked = !matches!(probe, Ok(Ok(())));
        assert!(
            blocked,
            "a new inbound connection from upstream directly to the client's private address must be blocked"
        );

        let _ = Command::new("ip")
            .args(["netns", "exec", &fixture.client_ns, "kill", "-9", "1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = client_server.wait_with_output();

        Ok(())
    }
    .await;

    if let Err(error) = &result {
        fixture.dump_state_on_failure("new inbound blocked");
        eprintln!("failure: {error:#}");
    }
    let _ = timeout(WAIT_TIMEOUT, fixture.stop_daemon_gracefully()).await;
    result
}

fn spawn_client_listener(fixture: &RouterNamespaceFixture) -> Result<std::process::Child> {
    let script = "import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\ns.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\ns.settimeout(6)\ns.bind(('0.0.0.0', 18522))\ns.listen(1)\ntry:\n    conn, addr = s.accept()\n    conn.close()\nexcept socket.timeout:\n    pass\n";
    Command::new("ip")
        .args(["netns", "exec", &fixture.client_ns, "python3", "-c", script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to spawn client listener")
}

async fn connect_from_upstream(
    fixture: &RouterNamespaceFixture,
    client_ip: Ipv4Addr,
) -> Result<()> {
    let script = format!(
        "import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\ns.settimeout(4)\ns.connect(('{client_ip}', 18522))\ns.close()\n"
    );
    let output = tokio::process::Command::new("ip")
        .args([
            "netns",
            "exec",
            &fixture.upstream_ns,
            "python3",
            "-c",
            &script,
        ])
        .output()
        .await
        .context("failed to execute upstream connect probe")?;
    if !output.status.success() {
        bail!(
            "upstream connect attempt to the client did not succeed (expected for this scenario): {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires root and Linux/iproute2; spawns a real traffic-masqd process; run only on a disposable test host"]
async fn management_interface_is_never_touched_without_explicit_allow() -> Result<()> {
    let _test_guard = NAMESPACE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let mut fixture = RouterNamespaceFixture::new(FixtureOptions {
        management_interface: true,
        ..FixtureOptions::default()
    })
    .await?;

    let management_before = host_ipv4_addresses(&fixture.management_if)?;
    assert!(
        management_before.contains("203.0.113.1"),
        "sanity: management interface must already carry its pre-daemon address: {management_before}"
    );

    let result: Result<()> = async {
        timeout(WAIT_TIMEOUT, fixture.start_daemon_expect_failure())
            .await
            .context("timed out waiting for traffic-masqd to refuse the management interface change")??;

        let management_after = host_ipv4_addresses(&fixture.management_if)?;
        assert_eq!(
            management_before, management_after,
            "management interface must be completely untouched by a daemon that refused to start"
        );

        let stderr_log = fixture.temp.path().join("daemon-stderr.log");
        let log_contents = fs::read_to_string(&stderr_log).unwrap_or_default();
        let stdout_log = fixture.temp.path().join("daemon-stdout.log");
        let stdout_contents = fs::read_to_string(&stdout_log).unwrap_or_default();
        assert!(
            log_contents.contains("outside-router")
                || stdout_contents.contains("outside-router")
                || log_contents.contains("refusing")
                || stdout_contents.contains("refusing"),
            "daemon output should explain the refusal; stdout={stdout_contents:?} stderr={log_contents:?}"
        );
        Ok(())
    }
    .await;

    if let Err(error) = &result {
        fixture.dump_state_on_failure("management path");
        eprintln!("failure: {error:#}");
    }
    result
}

fn create_veth(host_if: &str, peer_if: &str, peer_ns: &str) -> Result<()> {
    run(
        "ip",
        &[
            "link", "add", host_if, "type", "veth", "peer", "name", peer_if,
        ],
    )?;
    if peer_ns.is_empty() {
        return Ok(());
    }
    run("ip", &["link", "set", peer_if, "netns", peer_ns])
}

fn require_root() -> Result<()> {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .context("failed to run id -u")?;
    if String::from_utf8_lossy(&output.stdout).trim() != "0" {
        bail!("this ignored integration test must be run as root");
    }
    Ok(())
}

fn require_command(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("required command is not available: {program}"))?;
    if !status.success() {
        bail!("required command failed its availability check: {program}");
    }
    Ok(())
}

fn run(program: &str, args: &[&str]) -> Result<()> {
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
    Ok(())
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
