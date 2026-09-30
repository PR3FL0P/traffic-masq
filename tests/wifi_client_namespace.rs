use std::fs;
use std::path::{Path, PathBuf};
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
    command_path, ensure_child_running, list_interfaces, list_phys, output_ns, output_text,
    path_str, pid_alive, rename_interface, run, run_ns, spawn_ns, stop_child, stop_child_blocking,
    stop_pid_blocking, unique_suffix,
};

static NAMESPACE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const SSID: &str = "traffic-masq-hwsim-e2e";
const PASSPHRASE: &str = "traffic-masq-test-only-psk";
const AP_IF: &str = "tm-ap0";
const STA_IF: &str = "tm-sta0";

struct WifiClientNamespaceFixture {
    namespace: String,
    temp: tempfile::TempDir,
    config: AppConfig,
    config_path: PathBuf,
    hostapd_config_path: PathBuf,
    module_loaded_by_test: bool,
    hostapd: Option<Child>,
    daemon: Option<Child>,
    supplicant_pid: Option<u32>,
    daemon_generation: u8,
}

impl WifiClientNamespaceFixture {
    fn new() -> Result<Self> {
        require_linux_root_and_tools()?;
        if Path::new("/sys/module/mac80211_hwsim").exists() {
            bail!(
                "refusing to run: mac80211_hwsim is already loaded; the test cannot safely claim or unload radios it did not create"
            );
        }

        let suffix = unique_suffix();
        let namespace = format!("tmwifi{suffix}");
        let temp = tempdir().context("failed to create test state directory")?;
        let config_path = temp.path().join("traffic-masqd.toml");
        let hostapd_config_path = temp.path().join("hostapd.conf");
        let mut fixture = Self {
            namespace,
            config: AppConfig::default(),
            config_path,
            hostapd_config_path,
            temp,
            module_loaded_by_test: false,
            hostapd: None,
            daemon: None,
            supplicant_pid: None,
            daemon_generation: 0,
        };

        if let Err(error) = fixture.setup() {
            fixture.dump_diagnostics("setup failure");
            fixture.cleanup();
            return Err(error);
        }
        Ok(fixture)
    }

    fn setup(&mut self) -> Result<()> {
        let phys_before = list_phys(None)?;
        run("modprobe", &["mac80211_hwsim", "radios=2"])?;
        self.module_loaded_by_test = true;

        let phys_after = list_phys(None)?;
        let new_phys: Vec<_> = phys_after.difference(&phys_before).cloned().collect();
        if new_phys.len() != 2 {
            bail!(
                "mac80211_hwsim created {} new PHYs instead of exactly 2: {:?}",
                new_phys.len(),
                new_phys
            );
        }

        run("ip", &["netns", "add", &self.namespace])?;
        for phy in &new_phys {
            run("iw", &["phy", phy, "set", "netns", "name", &self.namespace])?;
        }

        let interfaces = list_interfaces(Some(&self.namespace))?;
        if interfaces.len() != 2 {
            bail!(
                "expected exactly two hwsim interfaces in namespace {}, found {:?}",
                self.namespace,
                interfaces
            );
        }
        rename_interface(&self.namespace, &interfaces[0], AP_IF)?;
        rename_interface(&self.namespace, &interfaces[1], STA_IF)?;
        run_ns(&self.namespace, "ip", &["link", "set", "lo", "up"])?;
        run_ns(
            &self.namespace,
            "iw",
            &["dev", AP_IF, "set", "type", "__ap"],
        )?;

        fs::write(
            &self.hostapd_config_path,
            format!(
                "interface={AP_IF}\ndriver=nl80211\nssid={SSID}\nhw_mode=g\nchannel=1\nwpa=2\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\nwpa_passphrase={PASSPHRASE}\n"
            ),
        )
        .context("failed to write hostapd test configuration")?;

        let passphrase_path = self.temp.path().join("wifi-client.psk");
        fs::write(&passphrase_path, format!("{PASSPHRASE}\n"))
            .context("failed to write client passphrase file")?;

        self.config.runtime.state_dir = self.temp.path().join("state");
        self.config.runtime.log_dir = self.temp.path().join("log");
        self.config.runtime.socket_path = self.temp.path().join("traffic-masqd.sock");
        self.config.runtime.pid_path = self.temp.path().join("traffic-masqd.pid");
        self.config.runtime.shutdown_policy = ShutdownPolicy::PreserveInterfaces;
        self.config.auth.database_path = self.temp.path().join("auth.sqlite3");
        self.config.auth.argon2_memory_kib = 1_024;
        self.config.auth.argon2_iterations = 1;
        self.config.wifi_client.enabled = true;
        self.config.wifi_client.wpa_supplicant_binary = command_path("wpa_supplicant")?;
        self.config.wifi_client.runtime_dir = self.temp.path().join("wpa_supplicant");
        self.config.wifi_client.restart_backoff_seconds = 1;
        self.config.network.interfaces.insert(
            STA_IF.to_string(),
            InterfaceConfig {
                nat: true,
                role: InterfaceRole::Input,
                managed: false,
                ipv4: None,
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: Some(WifiClientConfig {
                    ssid: SSID.to_string(),
                    country_code: Some("US".to_string()),
                    security: WifiClientSecurity::Wpa2,
                    passphrase_file: Some(passphrase_path),
                }),
            },
        );
        self.config
            .validate()
            .context("Wi-Fi namespace fixture built an invalid AppConfig")?;
        fs::write(
            &self.config_path,
            toml::to_string_pretty(&self.config).context("failed to serialize AppConfig")?,
        )
        .context("failed to write daemon configuration")?;
        Ok(())
    }

    async fn start_hostapd(&mut self) -> Result<()> {
        let stdout = fs::File::create(self.temp.path().join("hostapd-stdout.log"))?;
        let stderr = fs::File::create(self.temp.path().join("hostapd-stderr.log"))?;
        self.hostapd = Some(spawn_ns(
            &self.namespace,
            "hostapd",
            &[path_str(&self.hostapd_config_path)?],
            stdout,
            stderr,
        )?);
        self.wait_child_alive("hostapd").await
    }

    async fn start_daemon(&mut self) -> Result<()> {
        self.daemon_generation += 1;
        let stdout_path = self
            .temp
            .path()
            .join(format!("daemon-{}-stdout.log", self.daemon_generation));
        let stderr_path = self
            .temp
            .path()
            .join(format!("daemon-{}-stderr.log", self.daemon_generation));
        let stdout = fs::File::create(stdout_path)?;
        let stderr = fs::File::create(stderr_path)?;
        let binary = env!("CARGO_BIN_EXE_traffic-masqd");
        self.daemon = Some(spawn_ns(
            &self.namespace,
            binary,
            &["--config", path_str(&self.config_path)?, "run"],
            stdout,
            stderr,
        )?);

        let client = ApiClient::new(self.config.runtime.socket_path.clone());
        timeout(WAIT_TIMEOUT, async {
            loop {
                if client.request(&Request::Ping).await.is_ok() {
                    return Ok::<(), anyhow::Error>(());
                }
                ensure_child_running(self.daemon.as_mut(), "traffic-masqd")?;
                sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .context("traffic-masqd did not become API-ready in time")??;
        Ok(())
    }

    async fn wait_child_alive(&mut self, name: &str) -> Result<()> {
        sleep(Duration::from_secs(1)).await;
        let child = if name == "hostapd" {
            self.hostapd.as_mut()
        } else {
            self.daemon.as_mut()
        };
        ensure_child_running(child, name)
    }

    async fn wait_completed(&mut self) -> Result<u32> {
        let client = ApiClient::new(self.config.runtime.socket_path.clone());
        timeout(WAIT_TIMEOUT, async {
            loop {
                ensure_child_running(self.daemon.as_mut(), "traffic-masqd")?;
                match client.request(&Request::WifiClientStatus).await {
                    Ok(Response::WifiClientStatus { interfaces }) => {
                        if let Some(status) = interfaces.iter().find(|s| s.interface == STA_IF) {
                            if status.wpa_state == WpaState::Completed.into() {
                                return Ok(status.pid);
                            }
                        }
                    }
                    Ok(other) => bail!("unexpected WifiClientStatus response: {other:?}"),
                    Err(_) => {}
                }
                sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .context("Wi-Fi client did not reach COMPLETED before timeout")?
    }

    fn assert_kernel_association(&self) -> Result<()> {
        let link = output_ns(&self.namespace, "iw", &["dev", STA_IF, "link"])?;
        let link_text = output_text(&link);
        if !link.status.success()
            || !link_text.contains("Connected to ")
            || !link_text.contains(SSID)
        {
            bail!("iw link did not independently confirm association: {link_text}");
        }

        let stations = output_ns(&self.namespace, "iw", &["dev", AP_IF, "station", "dump"])?;
        let station_text = output_text(&stations);
        if !stations.status.success() || !station_text.contains("Station ") {
            bail!("AP station dump contains no associated station: {station_text}");
        }
        Ok(())
    }

    async fn stop_daemon_gracefully(&mut self) -> Result<()> {
        let child = self.daemon.take().context("daemon was not running")?;
        stop_child(child, Signal::SIGTERM, WAIT_TIMEOUT, "traffic-masqd").await
    }

    async fn assert_supplicant_survives_and_is_adopted(&mut self, original_pid: u32) -> Result<()> {
        if !pid_alive(original_pid) {
            bail!("wpa_supplicant PID {original_pid} did not survive PreserveInterfaces shutdown");
        }
        self.start_daemon().await?;
        let adopted_pid = self.wait_completed().await?;
        if adopted_pid != original_pid {
            bail!(
                "replacement daemon did not adopt wpa_supplicant: expected PID {original_pid}, got {adopted_pid}"
            );
        }
        self.supplicant_pid = Some(adopted_pid);
        Ok(())
    }

    fn dump_diagnostics(&mut self, phase: &str) {
        eprintln!("=== wifi_client_namespace diagnostics ({phase}; secrets redacted) ===");
        for (label, program, args) in [
            (
                "namespace links",
                "ip",
                vec!["-n", &self.namespace, "link", "show"],
            ),
            ("wireless devices", "iw", vec!["dev"]),
        ] {
            eprintln!("--- {label} ---");
            let output = if program == "iw" {
                output_ns(&self.namespace, program, &args)
            } else {
                Command::new(program)
                    .args(&args)
                    .output()
                    .context("diagnostic command failed")
            };
            if let Ok(output) = output {
                eprintln!("{}", redact(&output_text(&output)));
            }
        }
        for (label, args) in [
            ("STA link", vec!["dev", STA_IF, "link"]),
            ("AP stations", vec!["dev", AP_IF, "station", "dump"]),
        ] {
            eprintln!("--- {label} ---");
            if let Ok(output) = output_ns(&self.namespace, "iw", &args) {
                eprintln!("{}", redact(&output_text(&output)));
            }
        }
        if let Ok(entries) = fs::read_dir(self.temp.path()) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("log") {
                    eprintln!("--- {} ---", path.display());
                    if let Ok(text) = fs::read_to_string(path) {
                        eprintln!("{}", redact(&text));
                    }
                }
            }
        }
        eprintln!("=== end diagnostics ===");
    }

    fn cleanup(&mut self) {
        if let Some(child) = self.daemon.take() {
            stop_child_blocking(child, "traffic-masqd");
        }
        if let Some(pid) = self.supplicant_pid.take() {
            stop_pid_blocking(pid, "wpa_supplicant");
        }
        if let Some(child) = self.hostapd.take() {
            stop_child_blocking(child, "hostapd");
        }
        let _ = Command::new("ip")
            .args(["netns", "del", &self.namespace])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if self.module_loaded_by_test {
            let _ = Command::new("modprobe")
                .args(["-r", "mac80211_hwsim"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            self.module_loaded_by_test = false;
        }
    }
}

impl Drop for WifiClientNamespaceFixture {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[tokio::test]
#[ignore = "requires root, Linux, mac80211_hwsim, iproute2, iw, hostapd and wpa_supplicant; mutates kernel radio state; run only on a disposable test host"]
async fn wpa2_client_associates_survives_shutdown_and_is_adopted() -> Result<()> {
    let _guard = NAMESPACE_TEST_LOCK.lock().await;
    let mut fixture = WifiClientNamespaceFixture::new()?;
    let result = async {
        fixture.start_hostapd().await?;
        fixture.start_daemon().await?;
        let original_pid = fixture.wait_completed().await?;
        fixture.supplicant_pid = Some(original_pid);
        fixture.assert_kernel_association()?;
        fixture.stop_daemon_gracefully().await?;
        fixture
            .assert_supplicant_survives_and_is_adopted(original_pid)
            .await?;
        fixture.assert_kernel_association()?;
        Ok(())
    }
    .await;
    if let Err(error) = result {
        fixture.dump_diagnostics("E2E failure");
        return Err(error);
    }
    Ok(())
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
        ("wpa_supplicant", &["-v"][..]),
        ("modprobe", &["--version"][..]),
        ("modinfo", &["--version"][..]),
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

    let module = Command::new("modinfo")
        .arg("mac80211_hwsim")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("failed to probe mac80211_hwsim availability")?;
    if !module.success() {
        let kernel = Command::new("uname")
            .arg("-r")
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|value| value.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        bail!(
            "mac80211_hwsim is unavailable for kernel {kernel}; install the matching kernel modules package or boot a kernel that provides CONFIG_MAC80211_HWSIM, then rerun this test"
        );
    }
    Ok(())
}

fn redact(text: &str) -> String {
    text.replace(PASSPHRASE, "<redacted-passphrase>")
}
