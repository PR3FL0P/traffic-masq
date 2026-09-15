use std::env;
use std::fs;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use tempfile::tempdir;
use tokio::time::{sleep, timeout};
use traffic_masq::api::client::ApiClient;
use traffic_masq::api::model::{Request, Response};
use traffic_masq::config::{
    AppConfig, InterfaceConfig, InterfaceRole, ShutdownPolicy, WifiClientConfig, WifiClientSecurity,
};
use traffic_masq::wifi::WpaState;

static PHYSICAL_WIFI_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const WAIT_TIMEOUT: Duration = Duration::from_secs(60);
const STOP_GRACE: Duration = Duration::from_secs(5);

struct Inputs {
    interface: String,
    ssid: String,
    psk_file: PathBuf,
}

struct PhysicalWifiFixture {
    namespace: String,
    original_interface: String,
    namespace_interface: String,
    phy: String,
    ssid: String,
    temp: tempfile::TempDir,
    config: AppConfig,
    config_path: PathBuf,
    daemon: Option<Child>,
    daemon_pid: Option<u32>,
    supplicant_pid: Option<u32>,
    phy_in_namespace: bool,
}

impl PhysicalWifiFixture {
    fn new() -> Result<Self> {
        require_linux_root_and_tools()?;
        let inputs = Inputs::from_env()?;
        validate_interface(&inputs.interface)?;
        validate_psk_file(&inputs.psk_file)?;
        refuse_management_uplink(&inputs.interface)?;

        let phy = interface_phy(&inputs.interface)?;
        validate_managed_capability(&phy)?;
        let phy_interfaces = interfaces_on_phy(None, &phy)?;
        if phy_interfaces != [inputs.interface.clone()] {
            bail!(
                "refusing to move {phy}: it owns interfaces {phy_interfaces:?}, not only the selected interface"
            );
        }

        let namespace = format!("tmwph{}", unique_suffix());
        let temp = tempdir().context("failed to create test state directory")?;
        let config_path = temp.path().join("traffic-masqd.toml");
        let mut fixture = Self {
            namespace,
            original_interface: inputs.interface,
            namespace_interface: String::new(),
            phy,
            ssid: inputs.ssid,
            temp,
            config: AppConfig::default(),
            config_path,
            daemon: None,
            daemon_pid: None,
            supplicant_pid: None,
            phy_in_namespace: false,
        };
        if let Err(error) = fixture.setup(inputs.psk_file) {
            fixture.dump_diagnostics("setup failure");
            fixture.cleanup();
            return Err(error);
        }
        Ok(fixture)
    }

    fn setup(&mut self, psk_file: PathBuf) -> Result<()> {
        run("ip", &["netns", "add", &self.namespace])?;
        run(
            "iw",
            &["phy", &self.phy, "set", "netns", "name", &self.namespace],
        )?;
        self.phy_in_namespace = true;

        let interfaces = interfaces_on_phy(Some(&self.namespace), &self.phy)?;
        if interfaces.len() != 1 {
            bail!(
                "expected one interface on {} after moving it, found {interfaces:?}",
                self.phy
            );
        }
        self.namespace_interface = interfaces[0].clone();
        run_ns(&self.namespace, "ip", &["link", "set", "lo", "up"])?;
        run_ns(
            &self.namespace,
            "ip",
            &["link", "set", &self.namespace_interface, "down"],
        )?;
        run_ns(
            &self.namespace,
            "iw",
            &["dev", &self.namespace_interface, "set", "type", "managed"],
        )?;
        run_ns(
            &self.namespace,
            "ip",
            &["link", "set", &self.namespace_interface, "up"],
        )?;

        self.config.runtime.state_dir = self.temp.path().join("state");
        self.config.runtime.log_dir = self.temp.path().join("log");
        self.config.runtime.socket_path = self.temp.path().join("traffic-masqd.sock");
        self.config.runtime.pid_path = self.temp.path().join("traffic-masqd.pid");
        self.config.runtime.shutdown_policy = ShutdownPolicy::PreserveInterfaces;
        self.config.auth.database_path = self.temp.path().join("auth.sqlite3");
        self.config.auth.argon2_memory_kib = 1_024;
        self.config.auth.argon2_iterations = 1;
        self.config.router.enabled = false;
        self.config.wifi.enabled = false;
        self.config.wifi_client.enabled = true;
        self.config.wifi_client.wpa_supplicant_binary = command_path("wpa_supplicant")?;
        self.config.wifi_client.runtime_dir = self.temp.path().join("wpa_supplicant");
        self.config.wifi_client.restart_backoff_seconds = 1;
        self.config.network.interfaces.insert(
            self.namespace_interface.clone(),
            InterfaceConfig {
                nat: true,
                role: InterfaceRole::Input,
                managed: false,
                ipv4: None,
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: Some(WifiClientConfig {
                    ssid: self.ssid.clone(),
                    country_code: None,
                    security: WifiClientSecurity::Wpa2,
                    passphrase_file: Some(psk_file),
                }),
            },
        );
        self.config
            .validate()
            .context("physical Wi-Fi fixture built an invalid AppConfig")?;
        fs::write(
            &self.config_path,
            toml::to_string_pretty(&self.config).context("failed to serialize AppConfig")?,
        )
        .context("failed to write daemon configuration")?;
        Ok(())
    }

    async fn run_test(&mut self) -> Result<()> {
        let stdout = fs::File::create(self.temp.path().join("daemon.stdout"))?;
        let stderr = fs::File::create(self.temp.path().join("daemon.stderr"))?;
        self.daemon = Some(spawn_ns(
            &self.namespace,
            env!("CARGO_BIN_EXE_traffic-masqd"),
            &["--config", path_str(&self.config_path)?, "run"],
            stdout,
            stderr,
        )?);

        let client = ApiClient::new(self.config.runtime.socket_path.clone());
        timeout(WAIT_TIMEOUT, async {
            loop {
                ensure_child_running(self.daemon.as_mut(), "traffic-masqd")?;
                if matches!(client.request(&Request::Ping).await, Ok(Response::Pong)) {
                    return Ok::<(), anyhow::Error>(());
                }
                sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .context("traffic-masqd API did not become ready before timeout")??;
        self.daemon_pid = Some(read_pid_file(&self.config.runtime.pid_path)?);
        client
            .initialize("physical-test-device-password")
            .await
            .context("failed to initialize authentication for physical Wi-Fi test")?;

        timeout(WAIT_TIMEOUT, async {
            loop {
                ensure_child_running(self.daemon.as_mut(), "traffic-masqd")?;
                match client.request(&Request::WifiClientStatus).await {
                    Ok(Response::WifiClientStatus { interfaces }) => {
                        if let Some(status) = interfaces
                            .iter()
                            .find(|status| status.interface == self.namespace_interface)
                        {
                            if status.wpa_state == WpaState::Completed {
                                if status.spec.ssid != self.ssid {
                                    bail!("daemon completed association to an unexpected SSID");
                                }
                                self.supplicant_pid = Some(status.pid);
                                return Ok::<(), anyhow::Error>(());
                            }
                        }
                    }
                    Ok(response) => bail!("unexpected Wi-Fi client status response: {response:?}"),
                    Err(error) => bail!("Wi-Fi client status request failed: {error}"),
                }
                sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .context("Wi-Fi client did not reach COMPLETED before timeout")??;

        let link = output_ns(
            &self.namespace,
            "iw",
            &["dev", &self.namespace_interface, "link"],
        )?;
        let link_text = String::from_utf8_lossy(&link.stdout);
        if !link.status.success()
            || !link_text.contains("Connected to ")
            || !link_text.contains(&self.ssid)
        {
            bail!("iw link did not independently confirm association");
        }

        self.stop_daemon().await?;
        let pid = self
            .supplicant_pid
            .context("daemon status did not report a supplicant PID")?;
        if !pid_alive(pid) {
            bail!("PreserveInterfaces did not leave the tracked wpa_supplicant running");
        }
        stop_pid_blocking(pid, "wpa_supplicant");
        self.supplicant_pid = None;
        Ok(())
    }

    async fn stop_daemon(&mut self) -> Result<()> {
        let mut child = self.daemon.take().context("daemon was not running")?;
        let daemon_pid = self.daemon_pid.context("daemon PID was not recorded")?;
        signal_pid(daemon_pid, Signal::SIGTERM, "traffic-masqd")?;
        timeout(STOP_GRACE, async {
            loop {
                if let Some(status) = child.try_wait()? {
                    if !status.success() {
                        bail!("traffic-masqd exited with status {status}");
                    }
                    return Ok::<(), anyhow::Error>(());
                }
                sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .context("traffic-masqd did not stop within cleanup grace period")??;
        self.daemon_pid = None;
        Ok(())
    }

    fn dump_diagnostics(&self, phase: &str) {
        eprintln!("=== physical Wi-Fi diagnostics ({phase}; SSID and secret omitted) ===");
        for (label, path) in [
            ("daemon stdout", self.temp.path().join("daemon.stdout")),
            ("daemon stderr", self.temp.path().join("daemon.stderr")),
        ] {
            if let Ok(contents) = fs::read_to_string(path) {
                eprintln!("--- {label} ---\n{}", redact_ssid(&contents, &self.ssid));
            }
        }
        if let Ok(entries) = fs::read_dir(&self.config.runtime.log_dir) {
            for entry in entries.flatten() {
                if entry.file_type().is_ok_and(|kind| kind.is_file()) {
                    if let Ok(contents) = fs::read_to_string(entry.path()) {
                        eprintln!(
                            "--- daemon log {} ---\n{}",
                            entry.file_name().to_string_lossy(),
                            redact_ssid(&contents, &self.ssid)
                        );
                    }
                }
            }
        }
        if self.phy_in_namespace {
            for (label, program, args) in [
                ("links", "ip", vec!["link", "show"]),
                ("wireless devices", "iw", vec!["dev"]),
            ] {
                if let Ok(output) = output_ns(&self.namespace, program, &args) {
                    eprintln!(
                        "--- {label} ---\n{}",
                        redact_ssid(&output_text(&output), &self.ssid)
                    );
                }
            }
        }
        eprintln!("=== end diagnostics ===");
    }

    fn cleanup(&mut self) {
        if let Some(pid) = self.daemon_pid.take() {
            stop_pid_blocking(pid, "traffic-masqd");
        }
        if let Some(child) = self.daemon.take() {
            stop_child_blocking(child, "ip netns exec wrapper");
        }
        if let Some(pid) = self.supplicant_pid.take() {
            stop_pid_blocking(pid, "wpa_supplicant");
        }

        if self.phy_in_namespace {
            let result = output_ns(
                &self.namespace,
                "iw",
                &["phy", &self.phy, "set", "netns", "1"],
            );
            match result {
                Ok(output) if output.status.success() => self.phy_in_namespace = false,
                Ok(output) => self.print_recovery(&output_text(&output)),
                Err(error) => self.print_recovery(&format!("{error:#}")),
            }
        }
        if !self.phy_in_namespace {
            let _ = Command::new("ip")
                .args(["netns", "del", &self.namespace])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = Command::new("ip")
                .args(["link", "set", &self.original_interface, "up"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }

    fn print_recovery(&self, detail: &str) {
        eprintln!(
            "\n!!! PHYSICAL WI-FI RECOVERY REQUIRED !!!\nFailed to return {} to the root namespace: {}\nRun immediately:\n  sudo ip netns exec {} iw phy {} set netns 1\n  sudo ip netns del {}\n  sudo ip link set {} up\n!!! DO NOT DELETE THE NAMESPACE BEFORE MOVING THE PHY !!!\n",
            self.phy, detail, self.namespace, self.phy, self.namespace, self.original_interface
        );
    }
}

impl Drop for PhysicalWifiFixture {
    fn drop(&mut self) {
        self.cleanup();
    }
}

impl Inputs {
    fn from_env() -> Result<Self> {
        Ok(Self {
            interface: required_env("TRAFFIC_MASQ_WIFI_INTERFACE")?,
            ssid: required_env("TRAFFIC_MASQ_WIFI_SSID")?,
            psk_file: PathBuf::from(required_env("TRAFFIC_MASQ_WIFI_PSK_FILE")?),
        })
    }
}

#[tokio::test]
#[ignore = "moves a user-selected physical Wi-Fi PHY; requires explicit root execution and a separate management uplink"]
async fn physical_wpa2_client_associates_without_touching_management_uplink() -> Result<()> {
    let _guard = PHYSICAL_WIFI_TEST_LOCK.lock().await;
    let mut fixture = PhysicalWifiFixture::new()?;
    let result = fixture.run_test().await;
    if let Err(error) = result {
        fixture.dump_diagnostics("test failure");
        return Err(error);
    }
    Ok(())
}

fn required_env(name: &str) -> Result<String> {
    let value =
        env::var(name).with_context(|| format!("required environment variable {name} is unset"))?;
    if value.is_empty() {
        bail!("required environment variable {name} is empty");
    }
    Ok(value)
}

fn read_pid_file(path: &Path) -> Result<u32> {
    fs::read_to_string(path)
        .with_context(|| format!("failed to read daemon PID file {}", path.display()))?
        .trim()
        .parse()
        .with_context(|| format!("daemon PID file {} is invalid", path.display()))
}

fn require_linux_root_and_tools() -> Result<()> {
    if !cfg!(target_os = "linux") {
        bail!("this ignored integration test is Linux-only");
    }
    if !nix::unistd::Uid::effective().is_root() {
        bail!("this ignored integration test must be run as root");
    }
    for (program, args) in [
        ("ip", &["-V"][..]),
        ("iw", &["--version"][..]),
        ("wpa_supplicant", &["-v"][..]),
    ] {
        let status = Command::new(program)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .with_context(|| format!("required command `{program}` is unavailable"))?;
        if !status.success() {
            bail!("required command `{program}` failed its version probe");
        }
    }
    Ok(())
}

fn validate_interface(interface: &str) -> Result<()> {
    if interface.len() > 15
        || interface.is_empty()
        || !interface
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        bail!("TRAFFIC_MASQ_WIFI_INTERFACE is not a valid Linux interface name");
    }
    let path = Path::new("/sys/class/net").join(interface);
    if !path.exists() {
        bail!("selected interface does not exist");
    }
    if !path.join("wireless").exists() || !path.join("phy80211").exists() {
        bail!("selected interface is not an nl80211 wireless interface");
    }
    Ok(())
}

fn validate_psk_file(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("TRAFFIC_MASQ_WIFI_PSK_FILE must be absolute");
    }
    let metadata = fs::symlink_metadata(path).context("failed to inspect PSK file metadata")?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.file_type().is_socket()
    {
        bail!("PSK path must be a regular non-symlink file");
    }
    if metadata.permissions().mode() & 0o777 != 0o600 {
        bail!("PSK file must have mode 0600");
    }
    Ok(())
}

fn refuse_management_uplink(interface: &str) -> Result<()> {
    for args in [
        vec!["route", "get", "1.1.1.1"],
        vec!["-6", "route", "get", "2606:4700:4700::1111"],
    ] {
        let output = Command::new("ip")
            .args(&args)
            .output()
            .context("failed to inspect routes")?;
        if output.status.success()
            && route_uses_interface(&String::from_utf8_lossy(&output.stdout), interface)
        {
            bail!("refusing selected interface because it is used by the current best route");
        }
    }
    Ok(())
}

fn route_uses_interface(routes: &str, interface: &str) -> bool {
    routes.lines().any(|line| {
        let words: Vec<_> = line.split_whitespace().collect();
        words.windows(2).any(|pair| pair == ["dev", interface])
    })
}

fn interface_phy(interface: &str) -> Result<String> {
    let target = fs::canonicalize(Path::new("/sys/class/net").join(interface).join("phy80211"))
        .context("failed to identify selected interface PHY")?;
    target
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .context("selected interface PHY name is not valid UTF-8")
}

fn validate_managed_capability(phy: &str) -> Result<()> {
    let output = Command::new("iw").args(["phy", phy, "info"]).output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() || !text.lines().any(|line| line.trim() == "* managed") {
        bail!("selected PHY does not advertise managed/station mode support");
    }
    Ok(())
}

fn interfaces_on_phy(namespace: Option<&str>, phy: &str) -> Result<Vec<String>> {
    let output = match namespace {
        Some(namespace) => output_ns(namespace, "iw", &["dev"]),
        None => Command::new("iw")
            .arg("dev")
            .output()
            .context("failed to run iw dev"),
    }?;
    if !output.status.success() {
        bail!("failed to enumerate wireless interfaces");
    }
    let mut current_phy = None;
    let mut interfaces = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let trimmed = line.trim();
        if let Some(index) = trimmed.strip_prefix("phy#") {
            current_phy = Some(format!("phy{index}"));
        } else if current_phy.as_deref() == Some(phy) {
            if let Some(interface) = trimmed.strip_prefix("Interface ") {
                interfaces.push(interface.to_string());
            }
        }
    }
    Ok(interfaces)
}

fn command_path(program: &str) -> Result<PathBuf> {
    for directory in env::split_paths(&env::var_os("PATH").unwrap_or_default()) {
        let candidate = directory.join(program);
        if candidate.is_file() {
            return fs::canonicalize(candidate)
                .with_context(|| format!("failed to resolve {program}"));
        }
    }
    bail!("could not resolve required command {program}")
}

fn spawn_ns(
    namespace: &str,
    program: &str,
    args: &[&str],
    stdout: fs::File,
    stderr: fs::File,
) -> Result<Child> {
    Command::new("ip")
        .args(["netns", "exec", namespace, program])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .with_context(|| format!("failed to spawn {program} in network namespace"))
}

fn output_ns(namespace: &str, program: &str, args: &[&str]) -> Result<Output> {
    Command::new("ip")
        .args(["netns", "exec", namespace, program])
        .args(args)
        .output()
        .with_context(|| format!("failed to run {program} in network namespace"))
}

fn run_ns(namespace: &str, program: &str, args: &[&str]) -> Result<()> {
    let output = output_ns(namespace, program, args)?;
    if !output.status.success() {
        bail!(
            "{program} failed in network namespace: {}",
            output_text(&output)
        );
    }
    Ok(())
}

fn run(program: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(program).args(args).output()?;
    if !output.status.success() {
        bail!("{program} failed: {}", output_text(&output));
    }
    Ok(())
}

fn ensure_child_running(child: Option<&mut Child>, name: &str) -> Result<()> {
    let child = child.with_context(|| format!("{name} child is not tracked"))?;
    if let Some(status) = child.try_wait()? {
        bail!("{name} exited unexpectedly with status {status}");
    }
    Ok(())
}

fn signal_pid(pid: u32, signal: Signal, name: &str) -> Result<()> {
    let raw = i32::try_from(pid).context("process PID exceeds pid_t range")?;
    kill(Pid::from_raw(raw), signal).with_context(|| format!("failed to signal {name}"))
}

fn stop_child_blocking(mut child: Child, name: &str) {
    stop_pid_blocking(child.id(), name);
    let _ = child.try_wait();
}

fn stop_pid_blocking(pid: u32, name: &str) {
    let Ok(raw) = i32::try_from(pid) else { return };
    let process = Pid::from_raw(raw);
    let _ = kill(process, Signal::SIGTERM);
    let deadline = Instant::now() + STOP_GRACE;
    while Instant::now() < deadline {
        if !pid_alive(pid) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    eprintln!("cleanup: tracked {name} ignored SIGTERM; sending SIGKILL");
    let _ = kill(process, Signal::SIGKILL);
}

fn pid_alive(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn redact_ssid(text: &str, ssid: &str) -> String {
    text.replace(ssid, "<redacted-ssid>")
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str().context("test path is not valid UTF-8")
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after Unix epoch")
        .as_nanos();
    format!(
        "{:08x}",
        (nanos as u64 ^ u64::from(std::process::id())) as u32
    )
}
