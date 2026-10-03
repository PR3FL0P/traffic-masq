use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use tempfile::tempdir;
use tokio::time::timeout;
use traffic_masq::api::client::ApiClient;
use traffic_masq::api::model::{Request, Response};
use traffic_masq::config::AppConfig;

mod support;

use support::namespace::{require_command, require_root, run, unique_suffix};

static NAMESPACE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const WAIT_TIMEOUT: Duration = Duration::from_secs(30);

const HOST_UNDERLAY_ADDR: &str = "10.50.0.1";
const PEER_UNDERLAY_ADDR: &str = "10.50.0.2";
const HOST_LISTEN_PORT: u16 = 51820;
const PEER_LISTEN_PORT: u16 = 51821;
const HOST_TUNNEL_ADDR: &str = "10.60.0.1";
const PEER_TUNNEL_ADDR: &str = "10.60.0.2";

struct VpnNamespaceFixture {
    peer_ns: String,
    host_veth: String,
    peer_veth: String,
    peer_wg_if: String,
    temp: tempfile::TempDir,
    config: AppConfig,
    config_path: PathBuf,
    daemon: Option<std::process::Child>,
}

impl VpnNamespaceFixture {
    async fn new() -> Result<Self> {
        require_root()?;
        require_command("ip", &["-V"])?;
        require_command("wg", &["--version"])?;

        let suffix = unique_suffix();
        let temp = tempdir().context("failed to create temp state directory")?;

        let host_veth = format!("vpnh{suffix}");
        let peer_veth = format!("vpnp{suffix}");
        let peer_wg_if = format!("vpnw{suffix}");
        let peer_ns = format!("vpnns{suffix}");

        let config = build_config(&temp);
        config
            .validate()
            .context("vpn namespace fixture built an invalid AppConfig")?;
        let config_path = temp.path().join("traffic-masqd.toml");
        fs::write(
            &config_path,
            toml::to_string_pretty(&config).context("failed to serialize test config")?,
        )
        .context("failed to write test config")?;

        let mut fixture = Self {
            peer_ns,
            host_veth,
            peer_veth,
            peer_wg_if,
            temp,
            config,
            config_path,
            daemon: None,
        };

        if let Err(error) = fixture.setup_topology() {
            fixture.dump_state_on_failure("topology setup");
            fixture.cleanup();
            return Err(error);
        }
        Ok(fixture)
    }

    fn setup_topology(&mut self) -> Result<()> {
        run("ip", &["netns", "add", &self.peer_ns])?;
        run(
            "ip",
            &[
                "link",
                "add",
                &self.host_veth,
                "type",
                "veth",
                "peer",
                "name",
                &self.peer_veth,
            ],
        )?;
        run(
            "ip",
            &["link", "set", &self.peer_veth, "netns", &self.peer_ns],
        )?;

        run(
            "ip",
            &[
                "addr",
                "add",
                &format!("{HOST_UNDERLAY_ADDR}/30"),
                "dev",
                &self.host_veth,
            ],
        )?;
        run("ip", &["link", "set", &self.host_veth, "up"])?;

        run("ip", &["-n", &self.peer_ns, "link", "set", "lo", "up"])?;
        run(
            "ip",
            &[
                "-n",
                &self.peer_ns,
                "addr",
                "add",
                &format!("{PEER_UNDERLAY_ADDR}/30"),
                "dev",
                &self.peer_veth,
            ],
        )?;
        run(
            "ip",
            &["-n", &self.peer_ns, "link", "set", &self.peer_veth, "up"],
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
                &self.peer_ns,
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
                &self.peer_ns,
                "wg",
                "setconf",
                &self.peer_wg_if,
                "/dev/stdin",
            ],
            format!(
                "[Interface]\nPrivateKey = {peer_private_key}\nListenPort = {PEER_LISTEN_PORT}\n\
                 [Peer]\nPublicKey = {host_public_key}\nAllowedIPs = {HOST_TUNNEL_ADDR}/32\n\
                 Endpoint = {HOST_UNDERLAY_ADDR}:{HOST_LISTEN_PORT}\n"
            )
            .as_bytes(),
        )?;

        run(
            "ip",
            &[
                "netns",
                "exec",
                &self.peer_ns,
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
                &self.peer_ns,
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
        eprintln!("=== vpn_wireguard_namespace failure dump ({phase}) ===");
        eprintln!("--- host tm-wg0 ---");
        let _ = Command::new("ip")
            .args(["addr", "show", "dev", "tm-wg0"])
            .status();
        let _ = Command::new("wg").args(["show", "tm-wg0"]).status();
        eprintln!("--- peer ns wg interface ---");
        let _ = Command::new("ip")
            .args([
                "netns",
                "exec",
                &self.peer_ns,
                "wg",
                "show",
                &self.peer_wg_if,
            ])
            .status();
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
            .args(["link", "delete", "tm-wg0"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = Command::new("ip")
            .args(["link", "del", &self.host_veth])
            .status();
        let _ = Command::new("ip")
            .args(["netns", "del", &self.peer_ns])
            .status();
    }
}

impl Drop for VpnNamespaceFixture {
    fn drop(&mut self) {
        self.cleanup();
    }
}

fn build_config(temp: &tempfile::TempDir) -> AppConfig {
    let mut config = AppConfig::default();
    config.runtime.state_dir = temp.path().join("state");
    config.runtime.log_dir = temp.path().join("log");
    config.runtime.socket_path = temp.path().join("traffic-masqd.sock");
    config.runtime.pid_path = temp.path().join("traffic-masqd.pid");

    config.dhcp.leases_dir = temp.path().join("dhcp-leases");

    config.auth.database_path = temp.path().join("auth.sqlite3");

    config.auth.argon2_memory_kib = 1_024;
    config.auth.argon2_iterations = 1;

    config.vpn.enabled = true;
    config.vpn.wireguard_config_dir = temp.path().join("vpn-wireguard");
    config.vpn.wireguard_import_dir = temp.path().join("wireguard-sources");

    config
}

#[tokio::test]
#[ignore = "requires root, Linux, iproute2 and wireguard-tools (wg); spawns a real traffic-masqd process and creates a real kernel WireGuard interface; run only on a disposable test host"]
async fn daemon_establishes_real_wireguard_handshake_and_tunnels_traffic() -> Result<()> {
    let _test_guard = NAMESPACE_TEST_LOCK.lock().await;

    let mut fixture = VpnNamespaceFixture::new().await?;
    if let Err(error) = run_happy_path(&mut fixture).await {
        fixture.dump_state_on_failure("happy path");
        return Err(error);
    }
    Ok(())
}

async fn run_happy_path(fixture: &mut VpnNamespaceFixture) -> Result<()> {
    let host_private_key = wg_genkey()?;
    let host_public_key = wg_pubkey(&host_private_key)?;

    let peer_public_key = fixture.setup_peer_wireguard_interface(&host_public_key)?;

    timeout(WAIT_TIMEOUT, fixture.start_daemon())
        .await
        .context("timed out waiting to start traffic-masqd")??;

    let client = ApiClient::new(fixture.config.runtime.socket_path.clone());

    client
        .initialize("vpn-namespace-test-password")
        .await
        .context("failed to initialize device password for the test daemon")?;

    let profile_contents = format!(
        "[Interface]\nPrivateKey = {host_private_key}\nAddress = {HOST_TUNNEL_ADDR}/24\n\
         ListenPort = {HOST_LISTEN_PORT}\nMTU = 1280\n\n[Peer]\nPublicKey = {peer_public_key}\n\
         AllowedIPs = {PEER_TUNNEL_ADDR}/32\nEndpoint = {PEER_UNDERLAY_ADDR}:{PEER_LISTEN_PORT}\n\
         PersistentKeepalive = 1\n"
    );

    fs::create_dir_all(&fixture.config.vpn.wireguard_import_dir)?;
    let source_path = fixture.config.vpn.wireguard_import_dir.join("peer.conf");
    fs::write(&source_path, &profile_contents)?;
    let sources = client.request(&Request::VpnListSources).await?;
    assert!(!serde_json::to_string(&sources)?.contains(&host_private_key));
    match sources {
        Response::VpnSources { profiles, .. } => {
            assert_eq!(profiles.len(), 1);
            assert_eq!(profiles[0].name, "peer.conf");
        }
        other => bail!("unexpected source list: {other:?}"),
    }
    let import_response = client
        .request(&Request::VpnImportFromSource {
            name: "peer.conf".to_string(),
        })
        .await
        .context("VpnImportProfile request failed")?;
    match import_response {
        Response::VpnProfileImported { name } => assert_eq!(name, "peer.conf"),
        other => bail!("unexpected response to VpnImportProfile: {other:?}"),
    }

    assert_eq!(fs::read_to_string(&source_path)?, profile_contents);

    let activate_response = client
        .request(&Request::VpnActivate {
            name: "peer.conf".to_string(),
        })
        .await
        .context("VpnActivate request failed")?;
    match activate_response {
        Response::VpnActivated { active } => {
            assert_eq!(active.interface, "tm-wg0");
            assert_eq!(active.profile_name, "peer.conf");
            assert!(
                active.up,
                "activated interface must report administratively up"
            );
        }
        other => bail!("unexpected response to VpnActivate: {other:?}"),
    }

    let link = Command::new("ip")
        .args(["-j", "link", "show", "dev", "tm-wg0"])
        .output()?;
    assert!(link.status.success());
    let link: serde_json::Value = serde_json::from_slice(&link.stdout)?;
    assert_eq!(link[0]["mtu"], 1280);

    timeout(WAIT_TIMEOUT, wait_for_handshake())
        .await
        .context("timed out waiting for a WireGuard handshake between tm-wg0 and the peer")??;

    timeout(WAIT_TIMEOUT, async {
        tokio::task::spawn_blocking(|| {
            let status = Command::new("ping")
                .args(["-I", "tm-wg0", "-c", "3", "-W", "3", PEER_TUNNEL_ADDR])
                .status()
                .context("failed to execute ping through tm-wg0")?;
            if !status.success() {
                bail!("ping through tm-wg0 to peer tunnel address did not succeed");
            }
            Ok(())
        })
        .await
        .context("ping task panicked")?
    })
    .await
    .context("timed out pinging the peer through the WireGuard tunnel")??;

    let status_response = client
        .request(&Request::VpnStatus)
        .await
        .context("VpnStatus request failed")?;
    match status_response {
        Response::VpnStatus {
            active: Some(active),
        } => {
            assert_eq!(active.interface, "tm-wg0");
            assert!(active.up);
        }
        other => bail!("unexpected response to VpnStatus: {other:?}"),
    }

    let deactivate_response = client
        .request(&Request::VpnDeactivate)
        .await
        .context("VpnDeactivate request failed")?;
    match deactivate_response {
        Response::VpnDeactivated => {}
        other => bail!("unexpected response to VpnDeactivate: {other:?}"),
    }

    let link_show = Command::new("ip")
        .args(["link", "show", "dev", "tm-wg0"])
        .output()
        .context("failed to check tm-wg0 after deactivate")?;
    if link_show.status.success() {
        bail!("tm-wg0 still exists after VpnDeactivate");
    }

    timeout(WAIT_TIMEOUT, fixture.stop_daemon_gracefully())
        .await
        .context("timed out stopping traffic-masqd")??;

    Ok(())
}

async fn wait_for_handshake() -> Result<()> {
    loop {
        let output = tokio::process::Command::new("wg")
            .args(["show", "tm-wg0", "latest-handshakes"])
            .output()
            .await
            .context("failed to run `wg show tm-wg0 latest-handshakes`")?;
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);

            if let Some(timestamp) = text.split_whitespace().last() {
                if timestamp.parse::<u64>().unwrap_or(0) > 0 {
                    return Ok(());
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
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
