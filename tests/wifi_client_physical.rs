use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use nix::sys::signal::Signal;
use tempfile::tempdir;
use tokio::time::{sleep, timeout};
use traffic_masq::api::client::ApiClient;
use traffic_masq::api::model::{Request, Response};
use traffic_masq::config::{
    AppConfig, InterfaceConfig, InterfaceRole, ShutdownPolicy, WifiClientConfig, WifiClientSecurity,
};
use traffic_masq::wifi::WpaState;

mod support;

use support::wifi::{
    command_path, ensure_child_running, interface_phy, interfaces_on_phy, output_ns, output_text,
    path_str, pid_alive, read_pid_file, redact_ssid, refuse_management_uplink, run, run_ns,
    spawn_ns, stop_child, stop_child_blocking, stop_pid_blocking, unique_suffix,
    validate_interface, validate_psk_file,
};

static PHYSICAL_WIFI_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const WAIT_TIMEOUT: Duration = Duration::from_secs(60);
const STOP_GRACE: Duration = Duration::from_secs(5);

struct Inputs {
    interface: String,
    ssid: String,
    psk_file: Option<PathBuf>,
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
        Self::with_inputs(Inputs::from_env()?)
    }

    fn with_inputs(inputs: Inputs) -> Result<Self> {
        require_linux_root_and_tools()?;
        validate_interface(&inputs.interface, "TRAFFIC_MASQ_WIFI_INTERFACE")?;
        if let Some(path) = &inputs.psk_file {
            validate_psk_file(path, "TRAFFIC_MASQ_WIFI_PSK_FILE")?;
        }
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

    fn setup(&mut self, psk_file: Option<PathBuf>) -> Result<()> {
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
        self.config.runtime.shutdown_policy = if psk_file.is_some() {
            ShutdownPolicy::PreserveInterfaces
        } else {
            ShutdownPolicy::RestoreInterfaces
        };
        self.config.auth.database_path = self.temp.path().join("auth.sqlite3");
        self.config.auth.argon2_memory_kib = 1_024;
        self.config.auth.argon2_iterations = 1;
        self.config.wifi.enabled = false;
        self.config.wifi_client.enabled = true;
        self.config.wifi_client.wpa_supplicant_binary = command_path("wpa_supplicant")?;
        self.config.wifi_client.runtime_dir = self.temp.path().join("wpa_supplicant");
        self.config.wifi_client.restart_backoff_seconds = 1;
        self.config.network.interfaces.insert(
            self.namespace_interface.clone(),
            InterfaceConfig {
                mac_address: None,
                role: InterfaceRole::Input,
                managed: false,
                ipv4: None,
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: if let Some(psk_file) = psk_file {
                    Some(WifiClientConfig {
                        ssid: self.ssid.clone(),
                        country_code: None,
                        security: match env::var("TRAFFIC_MASQ_WIFI_SECURITY").as_deref() {
                            Ok("wpa3") => WifiClientSecurity::Wpa3,
                            Ok("wpa2_wpa3") => WifiClientSecurity::Wpa2Wpa3,
                            Ok("wpa2") | Err(_) => WifiClientSecurity::Wpa2,
                            Ok(other) => bail!("unsupported TRAFFIC_MASQ_WIFI_SECURITY: {other}"),
                        },
                        passphrase_file: Some(psk_file),
                    })
                } else {
                    None
                },
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

    async fn start_daemon(&mut self) -> Result<ApiClient> {
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

        Ok(client)
    }

    async fn run_test(&mut self) -> Result<()> {
        let client = self.start_daemon().await?;
        timeout(WAIT_TIMEOUT, async {
            loop {
                ensure_child_running(self.daemon.as_mut(), "traffic-masqd")?;
                match client.request(&Request::WifiClientStatus).await {
                    Ok(Response::WifiClientStatus { interfaces }) => {
                        if let Some(status) = interfaces
                            .iter()
                            .find(|status| status.interface == self.namespace_interface)
                        {
                            if status.wpa_state == WpaState::Completed.into() {
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
        let child = self.daemon.take().context("daemon was not running")?;
        stop_child(child, Signal::SIGTERM, STOP_GRACE, "traffic-masqd").await?;
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
            psk_file: Some(PathBuf::from(required_env("TRAFFIC_MASQ_WIFI_PSK_FILE")?)),
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

#[tokio::test]
#[ignore = "moves a selected physical PHY; requires root and a separate management uplink"]
async fn physical_tui_scan_discovers_real_networks() -> Result<()> {
    run_physical_tui_test(true).await
}

#[tokio::test]
#[ignore = "moves a selected physical PHY; requires root and a separate management uplink"]
async fn physical_tui_static_ipv4_reaches_the_kernel() -> Result<()> {
    run_physical_tui_test(false).await
}

async fn run_physical_tui_test(scan: bool) -> Result<()> {
    let _guard = PHYSICAL_WIFI_TEST_LOCK.lock().await;
    let mut fixture = PhysicalWifiFixture::with_inputs(Inputs {
        interface: required_env("TRAFFIC_MASQ_WIFI_INTERFACE")?,
        ssid: "scan-only-test".into(),
        psk_file: None,
    })?;
    let result = async {
        let client = fixture.start_daemon().await?;
        let interface = fixture.namespace_interface.clone();
        if scan {
            match client
                .request(&Request::WifiClientScan {
                    interface: interface.clone(),
                })
                .await?
            {
                Response::WifiClientScanResults {
                    interface: scanned,
                    results,
                } => {
                    assert_eq!(scanned, interface);
                    anyhow::ensure!(
                        !results.is_empty(),
                        "no networks discovered by the real scan; run within range of an AP"
                    );
                    println!("Real daemon scan returned {} networks", results.len());
                }
                response => bail!("TUI scan request failed: {response:?}"),
            }
            fixture.stop_daemon().await?;
            return Ok(());
        }
        let edit = traffic_masq::api::model::InterfaceEditRequest {
            mac_address: None,
            cidr: "198.18.0.1/24".into(),
            role: InterfaceRole::Input,
            managed: true,
            allow_management_change: true,
        };
        match client
            .request(&Request::DryRunInterfaceEdit {
                interface: interface.clone(),
                edit: edit.clone(),
            })
            .await?
        {
            Response::InterfacePlan { plan } => assert!(plan.add_ipv4.is_some()),
            response => bail!("TUI IP preview failed: {response:?}"),
        }
        let token = match client
            .request(&Request::ApplyInterfaceEdit {
                interface: interface.clone(),
                edit,
            })
            .await?
        {
            Response::NetworkChangePending { change } => change.token,
            response => bail!("TUI IP apply failed: {response:?}"),
        };
        let kernel = output_ns(
            &fixture.namespace,
            "ip",
            &["-j", "-4", "address", "show", "dev", &interface],
        )?;
        anyhow::ensure!(kernel.status.success(), "kernel address observation failed");
        let links: serde_json::Value = serde_json::from_slice(&kernel.stdout)?;
        assert!(
            links[0]["addr_info"]
                .as_array()
                .context("ip addr_info missing")?
                .iter()
                .any(|address| address["local"] == "198.18.0.1" && address["prefixlen"] == 24),
            "API success must correspond to the real kernel address"
        );
        match client
            .request(&Request::CommitNetworkChange { token })
            .await?
        {
            Response::NetworkChangeCommitted { .. } => {}
            response => bail!("TUI IP confirmation failed: {response:?}"),
        }
        println!("Real daemon IP preview, apply, kernel verification and commit passed");
        let clear = traffic_masq::api::model::InterfaceEditRequest {
            mac_address: None,
            cidr: String::new(),
            role: InterfaceRole::Input,
            managed: true,
            allow_management_change: true,
        };
        let token = match client
            .request(&Request::ApplyInterfaceEdit {
                interface: interface.clone(),
                edit: clear,
            })
            .await?
        {
            Response::NetworkChangePending { change } => change.token,
            response => bail!("TUI IP removal failed: {response:?}"),
        };
        let kernel = output_ns(
            &fixture.namespace,
            "ip",
            &["-j", "-4", "address", "show", "dev", &interface],
        )?;
        anyhow::ensure!(
            kernel.status.success(),
            "kernel address observation failed after removal"
        );
        let links: serde_json::Value = serde_json::from_slice(&kernel.stdout)?;
        assert!(!links[0]["addr_info"]
            .as_array()
            .context("ip addr_info missing")?
            .iter()
            .any(|address| address["local"] == "198.18.0.1"));
        match client
            .request(&Request::CommitNetworkChange { token })
            .await?
        {
            Response::NetworkChangeCommitted { .. } => {}
            response => bail!("TUI IP removal confirmation failed: {response:?}"),
        }
        fixture.stop_daemon().await?;
        Ok(())
    }
    .await;
    if result.is_err() {
        fixture.dump_diagnostics("scan/IP test failure");
    }
    result
}

fn required_env(name: &str) -> Result<String> {
    let value =
        env::var(name).with_context(|| format!("required environment variable {name} is unset"))?;
    if value.is_empty() {
        bail!("required environment variable {name} is empty");
    }
    Ok(value)
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

fn validate_managed_capability(phy: &str) -> Result<()> {
    let output = Command::new("iw").args(["phy", phy, "info"]).output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() || !text.lines().any(|line| line.trim() == "* managed") {
        bail!("selected PHY does not advertise managed/station mode support");
    }
    Ok(())
}
