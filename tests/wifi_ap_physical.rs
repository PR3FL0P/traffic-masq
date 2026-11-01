use std::env;
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use nix::sys::signal::Signal;
use tempfile::tempdir;
use tokio::time::{sleep, timeout};
use traffic_masq::api::client::ApiClient;
use traffic_masq::api::model::{Request, Response};
use traffic_masq::config::{
    AppConfig, DhcpInterfaceConfig, InterfaceConfig, InterfaceRole, ShutdownPolicy, WifiApConfig,
    WifiBand, WifiChannelWidth, WifiSecurity,
};
use traffic_masq::wifi::HostapdState;

mod support;

use support::wifi::{
    command_path, ensure_child_running, interface_phy, interfaces_on_phy, output_ns, output_text,
    path_str, pid_alive, read_pid_file, redact_ssid, refuse_management_uplink, run, run_ns,
    spawn_ns, stop_child, stop_child_blocking, stop_pid_blocking, unique_suffix,
    validate_interface, validate_psk_file,
};

static PHYSICAL_WIFI_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const WAIT_TIMEOUT: Duration = Duration::from_secs(60);
const STATION_TIMEOUT: Duration = Duration::from_secs(120);
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
    hostapd_pid: Option<u32>,
    phy_in_namespace: bool,
}

impl PhysicalWifiFixture {
    fn new() -> Result<Self> {
        require_linux_root_and_tools()?;
        let inputs = Inputs::from_env()?;
        validate_interface(&inputs.interface, "TRAFFIC_MASQ_WIFI_INTERFACE")?;
        validate_psk_file(&inputs.psk_file, "TRAFFIC_MASQ_AP_PSK_FILE")?;
        refuse_management_uplink(&inputs.interface)?;

        let phy = interface_phy(&inputs.interface)?;
        validate_ap_capability(&phy)?;
        let phy_interfaces = interfaces_on_phy(None, &phy)?;
        if phy_interfaces != [inputs.interface.clone()] {
            bail!(
                "refusing to move {phy}: it owns interfaces {phy_interfaces:?}, not only the selected interface"
            );
        }

        let namespace = format!("tmwap{}", unique_suffix());
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
            hostapd_pid: None,
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
            &["dev", &self.namespace_interface, "set", "type", "__ap"],
        )?;

        self.config.runtime.state_dir = self.temp.path().join("state");
        self.config.runtime.log_dir = self.temp.path().join("log");
        self.config.runtime.socket_path = self.temp.path().join("traffic-masqd.sock");
        self.config.runtime.pid_path = self.temp.path().join("traffic-masqd.pid");
        self.config.runtime.shutdown_policy = ShutdownPolicy::RestoreInterfaces;
        self.config.auth.database_path = self.temp.path().join("auth.sqlite3");
        self.config.auth.argon2_memory_kib = 1_024;
        self.config.auth.argon2_iterations = 1;
        self.config.vpn.enabled = false;
        self.config.wifi_client.enabled = false;
        self.config.wifi.enabled = true;
        self.config.wifi.hostapd_binary = command_path("hostapd")?;
        self.config.wifi.runtime_dir = self.temp.path().join("hostapd");
        self.config.wifi.restart_backoff_seconds = 1;
        self.config.dhcp.leases_dir = self.temp.path().join("dhcp-leases");
        self.config.network.interfaces.insert(
            self.namespace_interface.clone(),
            InterfaceConfig {
                wifi_concurrent: false,
                randomize_mac: false,
                mac_address: None,
                role: InterfaceRole::Output,
                managed: true,
                ipv4: Some(ipnet::Ipv4Net::from_str("10.77.0.1/24")?),
                dhcp: Some(DhcpInterfaceConfig {
                    pool_start: Ipv4Addr::new(10, 77, 0, 100),
                    pool_end: Ipv4Addr::new(10, 77, 0, 150),
                    router: Ipv4Addr::new(10, 77, 0, 1),
                    dns_servers: vec![Ipv4Addr::new(1, 1, 1, 1)],
                    lease_seconds: None,
                }),
                dhcp_client: None,
                wifi: Some(WifiApConfig {
                    ssid: self.ssid.clone(),
                    country_code: None,
                    band: WifiBand::Ghz2,
                    channel: 6,
                    channel_width: WifiChannelWidth::Ht20,
                    security: WifiSecurity::Wpa2,
                    hidden: false,
                    client_isolation: false,
                    max_stations: 32,
                    passphrase_file: Some(psk_file),
                }),
                wifi_client: None,
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
                match client.request(&Request::WifiStatus).await {
                    Ok(Response::WifiStatus { interfaces }) => {
                        if let Some(status) = interfaces
                            .iter()
                            .find(|status| status.interface == self.namespace_interface)
                        {
                            if status.hostapd_state == HostapdState::Enabled.into() {
                                if status.spec.ssid != self.ssid {
                                    bail!("daemon enabled an access point with an unexpected SSID");
                                }
                                self.hostapd_pid = Some(status.pid);
                                return Ok::<(), anyhow::Error>(());
                            }
                        }
                    }
                    Ok(_) => bail!("unexpected Wi-Fi status response"),
                    Err(error) => bail!("Wi-Fi status request failed: {error}"),
                }
                sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .context("access point did not reach ENABLED before timeout")??;

        println!(
            "\nACCESS POINT READY: connect a phone to the SSID supplied in TRAFFIC_MASQ_AP_SSID now. Waiting up to 120 seconds for association and DHCP.\n"
        );
        timeout(STATION_TIMEOUT, async {
            loop {
                ensure_child_running(self.daemon.as_mut(), "traffic-masqd")?;
                let stations = match client
                    .request(&Request::ListWifiStations {
                        interface: self.namespace_interface.clone(),
                    })
                    .await
                {
                    Ok(Response::WifiStations { stations, .. }) => stations,
                    Ok(_) => bail!("unexpected station-list response"),
                    Err(error) => bail!("station-list request failed: {error}"),
                };
                if !stations.is_empty() {
                    match client
                        .request(&Request::ListLeases {
                            interface: self.namespace_interface.clone(),
                        })
                        .await
                    {
                        Ok(Response::Leases { leases, .. }) if !leases.is_empty() => {
                            assert!(
                                !stations.is_empty(),
                                "station list unexpectedly became empty"
                            );
                            assert!(
                                !leases.is_empty(),
                                "DHCP lease list unexpectedly became empty"
                            );
                            return Ok::<(), anyhow::Error>(());
                        }
                        Ok(Response::Leases { .. }) => {}
                        Ok(_) => bail!("unexpected DHCP lease-list response"),
                        Err(error) => bail!("DHCP lease-list request failed: {error}"),
                    }
                }
                sleep(Duration::from_millis(500)).await;
            }
        })
        .await
        .context("no associated phone with a DHCP lease was observed within 120 seconds")??;
        self.stop_daemon().await?;
        if let Some(pid) = self.hostapd_pid.take() {
            if pid_alive(pid) {
                bail!("RestoreInterfaces did not stop tracked hostapd process {pid}");
            }
        }
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
        if let Some(pid) = self.hostapd_pid.take() {
            stop_pid_blocking(pid, "hostapd");
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
            ssid: required_env("TRAFFIC_MASQ_AP_SSID")?,
            psk_file: PathBuf::from(required_env("TRAFFIC_MASQ_AP_PSK_FILE")?),
        })
    }
}

#[tokio::test]
#[ignore = "moves a user-selected physical Wi-Fi PHY; requires explicit root execution and a separate management uplink"]
async fn physical_wpa2_ap_serves_a_station_without_touching_management_uplink() -> Result<()> {
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
        ("hostapd", &["-v"][..]),
    ] {
        let status = Command::new(program)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .with_context(|| format!("required command `{program}` is unavailable"))?;

        if !status.success() && program != "hostapd" {
            bail!("required command `{program}` failed its version probe");
        }
    }
    Ok(())
}

fn validate_ap_capability(phy: &str) -> Result<()> {
    let output = Command::new("iw").args(["phy", phy, "info"]).output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() || !text.lines().any(|line| line.trim() == "* AP") {
        bail!("selected PHY does not advertise AP mode support");
    }
    Ok(())
}
