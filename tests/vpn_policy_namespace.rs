use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use tempfile::tempdir;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;
use traffic_masq::api::client::ApiClient;
use traffic_masq::api::model::{Request, Response};
use traffic_masq::config::{
    AppConfig, InterfaceConfig, InterfaceRole, RouterConfig, ShutdownPolicy, UplinkConfig,
    UplinkMode, VpnPolicyMode,
};

mod support;

use support::namespace::{create_veth, require_command, require_root, run, unique_suffix};

static NAMESPACE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const WAIT_TIMEOUT: Duration = Duration::from_secs(30);

const EXPECTED_FAILURE_CONNECT_SECS: u64 = 5;

const CLIENT_SUBNET_PREFIX: u8 = 24;
const CLIENT_ROUTER: &str = "192.0.2.1";
const CLIENT_ADDR: &str = "192.0.2.50";
const UPLINK_HOST_ADDR: &str = "198.51.100.1";
const UPSTREAM_ADDR: &str = "198.51.100.2";
const HOST_LISTEN_PORT: u16 = 51820;
const PEER_LISTEN_PORT: u16 = 51821;
const HOST_TUNNEL_ADDR: &str = "10.60.0.1";
const PEER_TUNNEL_ADDR: &str = "10.60.0.2";
const ECHO_PORT_DIRECT: u16 = 18601;
const ECHO_PORT_VPN: u16 = 18602;
const ECHO_PAYLOAD: &str = "traffic-masq-vpn-policy-e2e";

struct VpnPolicyNamespaceFixture {
    client_ns: String,
    upstream_ns: String,
    lan_if: String,
    client_if: String,
    uplink_if: String,
    upstream_if: String,
    peer_wg_if: String,
    temp: tempfile::TempDir,
    config: AppConfig,
    config_path: PathBuf,
    daemon: Option<std::process::Child>,

    forwarding_baseline: String,
}

impl VpnPolicyNamespaceFixture {
    async fn new() -> Result<Self> {
        require_root()?;
        require_command("ip", &["-V"])?;
        require_command("nft", &["--version"])?;
        require_command("wg", &["--version"])?;
        require_command("python3", &["--version"])?;

        let suffix = unique_suffix();
        let temp = tempdir().context("failed to create temp state directory")?;

        let forwarding_baseline = fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .context("failed to read pre-test IPv4 forwarding sysctl")?
            .trim()
            .to_string();

        let lan_if = format!("tmvl{suffix}");
        let client_if = format!("tmvc{suffix}");
        let uplink_if = format!("tmvu{suffix}");
        let upstream_if = format!("tmvs{suffix}");
        let peer_wg_if = format!("tmvw{suffix}");
        let client_ns = format!("tmvcn{suffix}");
        let upstream_ns = format!("tmvun{suffix}");

        let config = build_config(&temp, &lan_if, &uplink_if);
        config
            .validate()
            .context("vpn policy namespace fixture built an invalid AppConfig")?;
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
            peer_wg_if,
            temp,
            config,
            config_path,
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
            &[
                "-n",
                &self.client_ns,
                "addr",
                "add",
                &format!("{CLIENT_ADDR}/{CLIENT_SUBNET_PREFIX}"),
                "dev",
                &self.client_if,
            ],
        )?;
        run(
            "ip",
            &["-n", &self.client_ns, "link", "set", &self.client_if, "up"],
        )?;
        run(
            "ip",
            &[
                "-n",
                &self.client_ns,
                "route",
                "add",
                "default",
                "via",
                CLIENT_ROUTER,
                "dev",
                &self.client_if,
            ],
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

    fn setup_peer_wireguard_interface(&self, host_public_key: &str) -> Result<String> {
        let peer_private_key = wg_genkey()?;
        let peer_public_key = wg_pubkey(&peer_private_key)?;

        run(
            "ip",
            &[
                "netns",
                "exec",
                &self.upstream_ns,
                "ip",
                "link",
                "add",
                &self.peer_wg_if,
                "type",
                "wireguard",
            ],
        )?;

        run_with_stdin(
            "ip",
            &[
                "netns",
                "exec",
                &self.upstream_ns,
                "wg",
                "setconf",
                &self.peer_wg_if,
                "/dev/stdin",
            ],
            format!(
                "[Interface]\nPrivateKey = {peer_private_key}\nListenPort = {PEER_LISTEN_PORT}\n\
                 [Peer]\nPublicKey = {host_public_key}\nAllowedIPs = {HOST_TUNNEL_ADDR}/32\n\
                 Endpoint = {UPLINK_HOST_ADDR}:{HOST_LISTEN_PORT}\n"
            )
            .as_bytes(),
        )?;

        run(
            "ip",
            &[
                "netns",
                "exec",
                &self.upstream_ns,
                "ip",
                "addr",
                "add",
                &format!("{PEER_TUNNEL_ADDR}/24"),
                "dev",
                &self.peer_wg_if,
            ],
        )?;
        run(
            "ip",
            &[
                "netns",
                "exec",
                &self.upstream_ns,
                "ip",
                "link",
                "set",
                &self.peer_wg_if,
                "up",
            ],
        )?;

        Ok(peer_public_key)
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
        eprintln!("=== vpn_policy_namespace failure dump ({phase}) ===");
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
            ("host tm-wg0", vec!["addr", "show", "dev", "tm-wg0"]),
            ("ip rule", vec!["rule", "show"]),
            ("ip rule (detailed, JSON)", vec!["-d", "-j", "rule", "show"]),
            (
                "ip route table 30100",
                vec!["route", "show", "table", "30100"],
            ),
        ] {
            eprintln!("--- ip {label} ---");
            let _ = Command::new("ip").args(&args).status();
        }
        eprintln!("--- nft owned table (traffic_masq) ---");
        let _ = Command::new("nft")
            .args(["list", "table", "inet", "traffic_masq"])
            .status();
        eprintln!("--- nft owned table (traffic_masq_vpn) ---");
        let _ = Command::new("nft")
            .args(["list", "table", "inet", "traffic_masq_vpn"])
            .status();
        eprintln!("--- wg show tm-wg0 ---");
        let _ = Command::new("wg").args(["show", "tm-wg0"]).status();
        eprintln!("--- wg show (peer, in upstream_ns) ---");
        let _ = Command::new("ip")
            .args([
                "netns",
                "exec",
                &self.upstream_ns,
                "wg",
                "show",
                &self.peer_wg_if,
            ])
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

        let _ = Command::new("ip")
            .args(["rule", "del", "priority", "10100"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = Command::new("ip")
            .args(["route", "flush", "table", "30100"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", "traffic_masq_vpn"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", "traffic_masq"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = Command::new("ip")
            .args(["link", "delete", "tm-wg0"])
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

impl Drop for VpnPolicyNamespaceFixture {
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
                format!("{CLIENT_ROUTER}/{CLIENT_SUBNET_PREFIX}")
                    .parse()
                    .expect("lan interface address"),
            ),

            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        },
    );

    config.router = RouterConfig {
        port_forwards: Vec::new(),
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

    config.vpn.enabled = true;
    config.vpn.wireguard_config_dir = temp.path().join("vpn-wireguard");

    config
}

#[tokio::test]
#[ignore = "requires root, Linux, iproute2, nftables and wireguard-tools (wg); spawns a real traffic-masqd process and creates real kernel network/WireGuard state; run only on a disposable test host"]
async fn vpn_traffic_policy_direct_vpn_failclosed_and_reconnect() -> Result<()> {
    let _test_guard = NAMESPACE_TEST_LOCK.lock().await;

    let mut fixture = VpnPolicyNamespaceFixture::new().await?;
    if let Err(error) = run_scenario(&mut fixture).await {
        fixture.dump_state_on_failure("scenario");
        return Err(error);
    }
    Ok(())
}

async fn run_scenario(fixture: &mut VpnPolicyNamespaceFixture) -> Result<()> {
    timeout(WAIT_TIMEOUT, fixture.start_daemon())
        .await
        .context("timed out waiting to start traffic-masqd")??;

    let client = ApiClient::new(fixture.config.runtime.socket_path.clone());
    client
        .initialize("vpn-policy-namespace-test-password")
        .await
        .context("failed to initialize device password for the test daemon")?;

    assert_management_path_reachable(&client).await?;
    assert_vpn_policy_status(&client, VpnPolicyMode::Direct, false, false).await?;
    timeout(
        WAIT_TIMEOUT,
        probe_echo_succeeds(
            &fixture.upstream_ns,
            UPSTREAM_ADDR,
            ECHO_PORT_DIRECT,
            &fixture.client_ns,
            UPSTREAM_ADDR,
            ECHO_PORT_DIRECT,
            UPLINK_HOST_ADDR,
        ),
    )
    .await
    .context("timed out on direct-mode echo probe before VPN import")??;

    let host_private_key = wg_genkey()?;
    let host_public_key = wg_pubkey(&host_private_key)?;
    let peer_public_key = fixture.setup_peer_wireguard_interface(&host_public_key)?;

    let profile_contents = format!(
        "[Interface]\nPrivateKey = {host_private_key}\nAddress = {HOST_TUNNEL_ADDR}/24\n\
         ListenPort = {HOST_LISTEN_PORT}\n\n[Peer]\nPublicKey = {peer_public_key}\n\
         AllowedIPs = {PEER_TUNNEL_ADDR}/32\nEndpoint = {UPSTREAM_ADDR}:{PEER_LISTEN_PORT}\n\
         PersistentKeepalive = 1\n"
    );
    import_and_activate_tunnel(&client, "peer.conf", &profile_contents).await?;
    timeout(WAIT_TIMEOUT, wait_for_handshake())
        .await
        .context("timed out waiting for the initial WireGuard handshake")??;

    assert_vpn_policy_status(&client, VpnPolicyMode::Direct, false, false).await?;
    timeout(
        WAIT_TIMEOUT,
        probe_echo_fails(
            &fixture.upstream_ns,
            PEER_TUNNEL_ADDR,
            ECHO_PORT_VPN,
            &fixture.client_ns,
            PEER_TUNNEL_ADDR,
            ECHO_PORT_VPN,
        ),
    )
    .await
    .context("timed out on pre-activation VPN-target probe")??;

    set_vpn_policy_mode(&client, VpnPolicyMode::Vpn).await?;
    assert_vpn_policy_status(&client, VpnPolicyMode::Vpn, true, true).await?;
    assert_management_path_reachable(&client).await?;

    timeout(
        WAIT_TIMEOUT,
        probe_echo_fails(
            &fixture.upstream_ns,
            UPSTREAM_ADDR,
            ECHO_PORT_DIRECT,
            &fixture.client_ns,
            UPSTREAM_ADDR,
            ECHO_PORT_DIRECT,
        ),
    )
    .await
    .context("direct uplink bypassed active VPN policy")??;

    let (rx_before, tx_before) = wg_transfer_bytes("tm-wg0")?;
    timeout(
        WAIT_TIMEOUT,
        probe_echo_succeeds(
            &fixture.upstream_ns,
            PEER_TUNNEL_ADDR,
            ECHO_PORT_VPN,
            &fixture.client_ns,
            PEER_TUNNEL_ADDR,
            ECHO_PORT_VPN,
            HOST_TUNNEL_ADDR,
        ),
    )
    .await
    .context("timed out on VPN-mode echo probe")??;
    let (rx_after, tx_after) = wg_transfer_bytes("tm-wg0")?;
    if rx_after <= rx_before || tx_after <= tx_before {
        bail!(
            "tm-wg0 transfer counters did not grow across a real echo round-trip: \
             rx {rx_before}->{rx_after}, tx {tx_before}->{tx_after}"
        );
    }

    let (_rx_before_keepalive, tx_before_keepalive) = wg_transfer_bytes("tm-wg0")?;
    timeout(
        WAIT_TIMEOUT,
        wait_for_tx_growth("tm-wg0", tx_before_keepalive),
    )
    .await
    .context("WireGuard endpoint traffic stalled after VPN policy activation — possible tunnel recursion")??;

    match client
        .request(&Request::VpnDeactivate)
        .await
        .context("VpnDeactivate request failed")?
    {
        Response::VpnDeactivated => {}
        other => bail!("unexpected response to VpnDeactivate: {other:?}"),
    }

    timeout(
        Duration::from_secs(EXPECTED_FAILURE_CONNECT_SECS + 5),
        probe_echo_fails(
            &fixture.upstream_ns,
            PEER_TUNNEL_ADDR,
            ECHO_PORT_VPN,
            &fixture.client_ns,
            PEER_TUNNEL_ADDR,
            ECHO_PORT_VPN,
        ),
    )
    .await
    .context("timed out on fail-closed VPN-target probe")??;

    timeout(
        WAIT_TIMEOUT,
        probe_echo_fails(
            &fixture.upstream_ns,
            UPSTREAM_ADDR,
            ECHO_PORT_DIRECT,
            &fixture.client_ns,
            UPSTREAM_ADDR,
            ECHO_PORT_DIRECT,
        ),
    )
    .await
    .context("direct uplink leaked traffic while the VPN tunnel was down")??;

    let status_during_outage = fetch_vpn_policy_status(&client).await?;
    if status_during_outage.tunnel_healthy {
        bail!("VPN policy status reports tunnel_healthy=true after VpnDeactivate tore down tm-wg0");
    }
    if !status_during_outage.policy_active {
        bail!(
            "VPN policy status reports policy_active=false after tunnel teardown alone — \
             VpnDeactivate must not implicitly deactivate VPN traffic policy"
        );
    }
    assert_management_path_reachable(&client).await?;

    match client
        .request(&Request::VpnActivate {
            name: "peer.conf".to_string(),
        })
        .await
        .context("VpnActivate (reconnect) request failed")?
    {
        Response::VpnActivated { active } => assert!(active.up, "reconnected interface must be up"),
        other => bail!("unexpected response to VpnActivate (reconnect): {other:?}"),
    }
    timeout(WAIT_TIMEOUT, wait_for_handshake())
        .await
        .context("timed out waiting for the post-reconnect WireGuard handshake")??;

    set_vpn_policy_mode(&client, VpnPolicyMode::Vpn).await?;
    assert_vpn_policy_status(&client, VpnPolicyMode::Vpn, true, true).await?;

    let policy_rule_count = count_policy_rules()?;
    let policy_route_count = count_policy_routes()?;
    if policy_rule_count != 1 {
        bail!("expected exactly one reserved VPN policy IPv4 rule after reconnect, found {policy_rule_count}");
    }
    if policy_route_count != 1 {
        bail!("expected exactly one reserved VPN policy IPv4 route after reconnect, found {policy_route_count}");
    }

    timeout(
        WAIT_TIMEOUT,
        probe_echo_succeeds(
            &fixture.upstream_ns,
            PEER_TUNNEL_ADDR,
            ECHO_PORT_VPN,
            &fixture.client_ns,
            PEER_TUNNEL_ADDR,
            ECHO_PORT_VPN,
            HOST_TUNNEL_ADDR,
        ),
    )
    .await
    .context("timed out on post-reconnect VPN-mode echo probe")??;

    match client
        .request(&Request::VpnPolicyClearMode)
        .await
        .context("VpnPolicyClearMode request failed")?
    {
        Response::VpnPolicyStatus { status } => {
            if status.mode != VpnPolicyMode::Direct || status.policy_active {
                bail!("VpnPolicyClearMode did not restore direct mode: {status:?}");
            }
        }
        other => bail!("unexpected response to VpnPolicyClearMode: {other:?}"),
    }
    if count_policy_rules()? != 0 {
        bail!("reserved VPN policy IPv4 rule still present after clearing mode to direct");
    }
    if count_policy_routes()? != 0 {
        bail!("reserved VPN policy IPv4 route still present after clearing mode to direct");
    }
    timeout(
        WAIT_TIMEOUT,
        probe_echo_succeeds(
            &fixture.upstream_ns,
            UPSTREAM_ADDR,
            ECHO_PORT_DIRECT,
            &fixture.client_ns,
            UPSTREAM_ADDR,
            ECHO_PORT_DIRECT,
            UPLINK_HOST_ADDR,
        ),
    )
    .await
    .context("timed out on final direct-mode echo probe")??;

    let _ = client.request(&Request::VpnDeactivate).await;

    timeout(WAIT_TIMEOUT, fixture.stop_daemon_gracefully())
        .await
        .context("timed out stopping traffic-masqd")??;
    assert_router_dataplane_rolled_back(fixture)?;

    Ok(())
}

async fn assert_management_path_reachable(client: &ApiClient) -> Result<()> {
    client
        .request(&Request::Ping)
        .await
        .context("management path (Ping) unreachable")?;
    match client
        .request(&Request::RouterStatus)
        .await
        .context("management path (RouterStatus) unreachable")?
    {
        Response::RouterStatus { .. } => Ok(()),
        other => bail!("unexpected response to RouterStatus: {other:?}"),
    }
}

async fn fetch_vpn_policy_status(
    client: &ApiClient,
) -> Result<traffic_masq::api::model::VpnPolicyStatusView> {
    match client
        .request(&Request::VpnPolicyStatus)
        .await
        .context("VpnPolicyStatus request failed")?
    {
        Response::VpnPolicyStatus { status } => Ok(status),
        other => bail!("unexpected response to VpnPolicyStatus: {other:?}"),
    }
}

async fn assert_vpn_policy_status(
    client: &ApiClient,
    expected_mode: VpnPolicyMode,
    expected_policy_active: bool,
    expected_kill_switch_active: bool,
) -> Result<()> {
    let status = fetch_vpn_policy_status(client).await?;
    if status.mode != expected_mode {
        bail!(
            "expected VPN policy mode {expected_mode:?}, got {:?}",
            status.mode
        );
    }
    if status.policy_active != expected_policy_active {
        bail!(
            "expected VPN policy policy_active={expected_policy_active}, got {}",
            status.policy_active
        );
    }
    if status.kill_switch_active != expected_kill_switch_active {
        bail!(
            "expected VPN policy kill_switch_active={expected_kill_switch_active}, got {}",
            status.kill_switch_active
        );
    }
    Ok(())
}

async fn set_vpn_policy_mode(client: &ApiClient, mode: VpnPolicyMode) -> Result<()> {
    match client
        .request(&Request::VpnPolicySetMode { mode })
        .await
        .context("VpnPolicySetMode request failed")?
    {
        Response::VpnPolicyStatus { status } if status.mode == mode => Ok(()),
        Response::VpnPolicyStatus { status } => {
            bail!("VpnPolicySetMode({mode:?}) did not take effect: {status:?}")
        }
        other => bail!("unexpected response to VpnPolicySetMode: {other:?}"),
    }
}

async fn import_and_activate_tunnel(client: &ApiClient, name: &str, contents: &str) -> Result<()> {
    match client
        .request(&Request::VpnImportProfile {
            name: name.to_string(),
            contents: contents.to_string(),
        })
        .await
        .context("VpnImportProfile request failed")?
    {
        Response::VpnProfileImported { name: imported } => assert_eq!(imported, name),
        other => bail!("unexpected response to VpnImportProfile: {other:?}"),
    }

    match client
        .request(&Request::VpnActivate {
            name: name.to_string(),
        })
        .await
        .context("VpnActivate request failed")?
    {
        Response::VpnActivated { active } => {
            assert_eq!(active.interface, "tm-wg0");
            assert_eq!(active.profile_name, name);
            assert!(
                active.up,
                "activated interface must report administratively up"
            );
        }
        other => bail!("unexpected response to VpnActivate: {other:?}"),
    }
    Ok(())
}

async fn probe_echo_succeeds(
    server_ns: &str,
    bind_addr: &str,
    port: u16,
    client_ns: &str,
    target_addr: &str,
    target_port: u16,
    expected_peer_addr: &str,
) -> Result<()> {
    let server = spawn_echo_server_in(server_ns, bind_addr, port).await?;
    let echoed = connect_and_echo(client_ns, target_addr, target_port, WAIT_TIMEOUT.as_secs())
        .await?
        .context("expected echo connection was blocked")?;
    if echoed != ECHO_PAYLOAD {
        bail!("echo server returned unexpected payload: {echoed:?}");
    }
    let server_output = server
        .wait_with_output()
        .await
        .context("failed to wait for echo server")?;
    if !server_output.status.success() {
        bail!(
            "echo server in {server_ns} failed: {}",
            String::from_utf8_lossy(&server_output.stderr)
        );
    }
    let observed_peer = String::from_utf8_lossy(&server_output.stdout)
        .trim()
        .to_string();
    if observed_peer != expected_peer_addr {
        bail!(
            "echo server in {server_ns} observed peer {observed_peer}, expected {expected_peer_addr}"
        );
    }
    Ok(())
}

async fn probe_echo_fails(
    server_ns: &str,
    bind_addr: &str,
    port: u16,
    client_ns: &str,
    target_addr: &str,
    target_port: u16,
) -> Result<()> {
    let mut server = spawn_echo_server_in(server_ns, bind_addr, port).await?;
    let result = connect_and_echo(
        client_ns,
        target_addr,
        target_port,
        EXPECTED_FAILURE_CONNECT_SECS,
    )
    .await?;
    if result.is_some() {
        bail!("connection to {target_addr}:{target_port} unexpectedly succeeded — traffic bypassed VPN isolation");
    }
    if let Some(status) = server.try_wait()? {
        bail!("echo server exited before the blocked probe completed: {status}");
    }
    server.kill().await.context("failed to stop echo server")?;
    Ok(())
}

async fn spawn_echo_server_in(
    ns: &str,
    bind_addr: &str,
    port: u16,
) -> Result<tokio::process::Child> {
    let script = format!(
        "import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\ns.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\ns.settimeout(25)\ns.bind(('{bind_addr}', {port}))\ns.listen(1)\nprint('READY', flush=True)\nconn, addr = s.accept()\nconn.settimeout(25)\ndata = conn.recv(4096)\nconn.sendall(data)\nconn.close()\nprint(addr[0], flush=True)\n"
    );
    let mut server = tokio::process::Command::new("ip")
        .args(["netns", "exec", ns, "python3", "-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("failed to spawn TCP echo server")?;
    let mut ready = [0; 6];
    timeout(
        WAIT_TIMEOUT,
        server
            .stdout
            .as_mut()
            .context("echo stdout unavailable")?
            .read_exact(&mut ready),
    )
    .await
    .context("echo server readiness timed out")??;
    anyhow::ensure!(&ready == b"READY\n", "echo server did not signal readiness");
    Ok(server)
}

async fn connect_and_echo(
    ns: &str,
    target_addr: &str,
    port: u16,
    connect_timeout_secs: u64,
) -> Result<Option<String>> {
    let script = format!(
        "import errno, socket, sys\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\ns.settimeout({connect_timeout_secs})\ntry:\n s.connect(('{target_addr}', {port}))\nexcept OSError as error:\n if isinstance(error, TimeoutError) or error.errno in (errno.ECONNREFUSED, errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ETIMEDOUT):\n  sys.exit(42)\n raise\ns.sendall(b'{ECHO_PAYLOAD}')\ndata = s.recv(4096)\ns.close()\nprint(data.decode(), end='')\n"
    );
    let output = tokio::process::Command::new("ip")
        .args(["netns", "exec", ns, "python3", "-c", &script])
        .kill_on_drop(true)
        .output()
        .await
        .context("failed to execute client echo probe")?;
    decode_echo_output(output)
        .with_context(|| format!("client probe in {ns} to {target_addr}:{port} failed"))
}

fn decode_echo_output(output: std::process::Output) -> Result<Option<String>> {
    if output.status.code() == Some(42) {
        return Ok(None);
    }
    if !output.status.success() {
        bail!(
            "echo probe failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(Some(
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
    ))
}

#[test]
fn broken_probe_is_not_evidence_of_blocked_traffic() {
    use std::os::unix::process::ExitStatusExt;
    let output = |code| std::process::Output {
        status: std::process::ExitStatus::from_raw(code << 8),
        stdout: ECHO_PAYLOAD.as_bytes().to_vec(),
        stderr: b"probe failure".to_vec(),
    };
    assert_eq!(decode_echo_output(output(42)).unwrap(), None);
    assert!(decode_echo_output(output(1)).is_err());
    assert!(decode_echo_output(output(127)).is_err());
    assert_eq!(
        decode_echo_output(output(0)).unwrap().as_deref(),
        Some(ECHO_PAYLOAD)
    );
}

async fn wait_for_handshake() -> Result<()> {
    loop {
        if latest_handshake_timestamp("tm-wg0")? > 0 {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn wait_for_tx_growth(interface: &str, baseline_tx: u64) -> Result<()> {
    loop {
        let (_rx, tx) = wg_transfer_bytes(interface)?;
        if tx > baseline_tx {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn latest_handshake_timestamp(interface: &str) -> Result<u64> {
    let output = Command::new("wg")
        .args(["show", interface, "latest-handshakes"])
        .output()
        .context("failed to run `wg show latest-handshakes`")?;
    if !output.status.success() {
        return Ok(0);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text
        .split_whitespace()
        .last()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0))
}

fn wg_transfer_bytes(interface: &str) -> Result<(u64, u64)> {
    let output = Command::new("wg")
        .args(["show", interface, "transfer"])
        .output()
        .context("failed to run `wg show transfer`")?;
    if !output.status.success() {
        bail!(
            "`wg show {interface} transfer` failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let fields: Vec<&str> = text.split_whitespace().collect();

    let &[_, rx, tx] = fields.as_slice() else {
        bail!("unexpected `wg show {interface} transfer` output: {text:?}");
    };
    Ok((
        rx.parse().context("failed to parse rx byte count")?,
        tx.parse().context("failed to parse tx byte count")?,
    ))
}

fn count_policy_rules() -> Result<usize> {
    let output = Command::new("ip")
        .args(["rule", "show"])
        .output()
        .context("failed to run `ip rule show`")?;
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.contains("lookup 30100"))
        .count())
}

fn count_policy_routes() -> Result<usize> {
    let output = Command::new("ip")
        .args(["route", "show", "table", "30100"])
        .output()
        .context("failed to run `ip route show table 30100`")?;
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count())
}

fn assert_router_dataplane_rolled_back(fixture: &VpnPolicyNamespaceFixture) -> Result<()> {
    let output = Command::new("nft")
        .args(["list", "table", "inet", "traffic_masq"])
        .output()
        .context("failed to inspect the owned router nftables table after shutdown")?;
    if output.status.success() {
        bail!("owned nftables table `traffic_masq` still exists after graceful shutdown with RestoreInterfaces policy");
    }

    let vpn_table = Command::new("nft")
        .args(["list", "table", "inet", "traffic_masq_vpn"])
        .output()
        .context("failed to inspect the owned VPN policy nftables table after shutdown")?;
    if vpn_table.status.success() {
        bail!("owned nftables table `traffic_masq_vpn` still exists after graceful shutdown");
    }

    if count_policy_rules()? != 0 {
        bail!("reserved VPN policy IPv4 rule still exists after graceful shutdown");
    }

    let wg_link = Command::new("ip")
        .args(["link", "show", "dev", "tm-wg0"])
        .output()
        .context("failed to check tm-wg0 after shutdown")?;
    if wg_link.status.success() {
        bail!("tm-wg0 still exists after graceful shutdown");
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

fn wg_genkey() -> Result<String> {
    let output = Command::new("wg")
        .arg("genkey")
        .output()
        .context("failed to run `wg genkey`")?;
    if !output.status.success() {
        bail!(
            "`wg genkey` failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn wg_pubkey(private_key: &str) -> Result<String> {
    use std::io::Write;
    let mut child = Command::new("wg")
        .arg("pubkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn `wg pubkey`")?;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(private_key.as_bytes())
        .context("failed to write private key to `wg pubkey` stdin")?;
    let output = child
        .wait_with_output()
        .context("failed to wait for `wg pubkey`")?;
    if !output.status.success() {
        bail!(
            "`wg pubkey` failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn run_with_stdin(program: &str, args: &[&str], stdin_data: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn {program}"))?;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(stdin_data)
        .with_context(|| format!("failed to write to {program} stdin"))?;
    let output = child
        .wait_with_output()
        .with_context(|| format!("failed to wait for {program}"))?;
    if !output.status.success() {
        bail!(
            "command failed: {program} {args:?}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}
