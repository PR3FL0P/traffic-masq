use std::env;
use std::fs;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use nix::sys::signal::Signal;
use tempfile::tempdir;
use tokio::time::{sleep, timeout};
use traffic_masq::api::client::ApiClient;
use traffic_masq::api::model::{
    DhcpClientConfigRequest, DhcpClientErrorDetail, DhcpClientOperationalState, Request, Response,
    RouterProposalRequest, WifiEditRequest,
};
use traffic_masq::config::{
    AppConfig, DhcpClientInterfaceConfig, DhcpInterfaceConfig, InterfaceConfig, InterfaceRole,
    RouterConfig, ShutdownPolicy, UplinkConfig, UplinkMode, WifiApConfig, WifiBand,
    WifiChannelWidth, WifiClientConfig, WifiClientSecurity, WifiSecurity,
};
use traffic_masq::dhcp::client::{DhcpClientLease, DhcpClientLeaseState, DhcpClientLeaseStore};
use traffic_masq::wifi::{HostapdState, WpaState};

mod support;

use support::wifi::{
    command_path, ensure_child_running, interface_phy, interfaces_on_phy, output_ns, output_text,
    path_str, pid_alive, read_pid_file, run, run_ns, spawn_ns, stop_child, stop_child_blocking,
    stop_pid_blocking, unique_suffix, validate_interface, validate_psk_file,
};

static PHYSICAL_WIFI_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const WAIT_TIMEOUT: Duration = Duration::from_secs(60);
const STATION_TIMEOUT: Duration = Duration::from_secs(120);
const OPERATOR_USB_TIMEOUT: Duration = Duration::from_secs(180);
const STOP_GRACE: Duration = Duration::from_secs(5);
const LONG_T1_DEFAULT_MAX_WAIT: Duration = Duration::from_secs(2 * 60 * 60);
const LONG_T1_MARGIN: Duration = Duration::from_secs(30);
const LONG_T1_HEALTH_INTERVAL: Duration = Duration::from_secs(5);
const LONG_T1_PROGRESS_INTERVAL: Duration = Duration::from_secs(60);

struct Inputs {
    uplink_interface: String,
    output_interface: String,
    upstream_ssid: String,
    upstream_psk_file: PathBuf,
    ap_ssid: String,
    ap_psk_file: PathBuf,
}

struct PhysicalWifiFixture {
    namespace: String,
    original_uplink: String,
    original_output: String,
    uplink_interface: String,
    output_interface: String,
    uplink_phy: String,
    output_phy: String,
    upstream_ssid: String,
    ap_ssid: String,
    upstream_psk_secret: String,
    ap_psk_secret: String,
    temp: tempfile::TempDir,
    config: AppConfig,
    config_path: PathBuf,
    daemon: Option<Child>,
    daemon_pid: Option<u32>,
    hostapd_pid: Option<u32>,
    supplicant_pid: Option<u32>,
    uplink_phy_in_namespace: bool,
    output_phy_in_namespace: bool,
}

impl PhysicalWifiFixture {
    fn new() -> Result<Self> {
        require_linux_root_and_tools()?;
        let inputs = Inputs::from_env()?;
        validate_interface(&inputs.uplink_interface, "TRAFFIC_MASQ_UPLINK_INTERFACE")?;
        validate_interface(&inputs.output_interface, "TRAFFIC_MASQ_OUTPUT_INTERFACE")?;
        validate_psk_file(&inputs.upstream_psk_file, "TRAFFIC_MASQ_UPSTREAM_PSK_FILE")?;
        validate_psk_file(&inputs.ap_psk_file, "TRAFFIC_MASQ_AP_PSK_FILE")?;
        verify_management_disruption_guard(
            env::var("TRAFFIC_MASQ_ALLOW_MANAGEMENT_DISRUPTION")
                .ok()
                .as_deref(),
        )?;
        for obsolete in [
            "TRAFFIC_MASQ_UPSTREAM_ADDRESS",
            "TRAFFIC_MASQ_UPSTREAM_GATEWAY",
        ] {
            if env::var_os(obsolete).is_some() {
                bail!("{obsolete} is obsolete and must be unset; the embedded DHCP client owns uplink L3 state");
            }
        }
        let uplink_phy = interface_phy(&inputs.uplink_interface)?;
        let output_phy = interface_phy(&inputs.output_interface)?;
        if uplink_phy == output_phy {
            bail!("uplink and output interfaces must be on distinct PHYs");
        }
        validate_managed_capability(&uplink_phy)?;
        validate_ap_capability(&output_phy)?;
        validate_only_interface(&uplink_phy, &inputs.uplink_interface)?;
        validate_only_interface(&output_phy, &inputs.output_interface)?;

        let upstream_psk_secret = read_secret_for_redaction(&inputs.upstream_psk_file)?;
        let ap_psk_secret = read_secret_for_redaction(&inputs.ap_psk_file)?;
        let namespace = format!("tmwrt{}", unique_suffix());
        let temp = tempdir().context("failed to create test state directory")?;
        let config_path = temp.path().join("traffic-masqd.toml");
        let mut fixture = Self {
            namespace,
            original_uplink: inputs.uplink_interface.clone(),
            original_output: inputs.output_interface.clone(),
            uplink_interface: inputs.uplink_interface.clone(),
            output_interface: inputs.output_interface.clone(),
            uplink_phy,
            output_phy,
            upstream_ssid: inputs.upstream_ssid.clone(),
            ap_ssid: inputs.ap_ssid.clone(),
            upstream_psk_secret,
            ap_psk_secret,
            temp,
            config: AppConfig::default(),
            config_path,
            daemon: None,
            daemon_pid: None,
            hostapd_pid: None,
            supplicant_pid: None,
            uplink_phy_in_namespace: false,
            output_phy_in_namespace: false,
        };
        if let Err(error) = fixture.setup(inputs.upstream_psk_file, inputs.ap_psk_file) {
            fixture.dump_diagnostics("setup failure");
            fixture.cleanup();
            return Err(error);
        }
        Ok(fixture)
    }

    fn setup(&mut self, upstream_psk: PathBuf, ap_psk: PathBuf) -> Result<()> {
        run("ip", &["netns", "add", &self.namespace])?;
        run(
            "iw",
            &[
                "phy",
                &self.uplink_phy,
                "set",
                "netns",
                "name",
                &self.namespace,
            ],
        )?;
        self.uplink_phy_in_namespace = true;
        run(
            "iw",
            &[
                "phy",
                &self.output_phy,
                "set",
                "netns",
                "name",
                &self.namespace,
            ],
        )?;
        self.output_phy_in_namespace = true;

        self.uplink_interface = sole_interface_in_namespace(&self.namespace, &self.uplink_phy)?;
        self.output_interface = sole_interface_in_namespace(&self.namespace, &self.output_phy)?;
        run_ns(&self.namespace, "ip", &["link", "set", "lo", "up"])?;
        set_wifi_type(&self.namespace, &self.uplink_interface, "managed")?;
        set_wifi_type(&self.namespace, &self.output_interface, "__ap")?;

        self.config.runtime.state_dir = self.temp.path().join("state");
        self.config.runtime.log_dir = self.temp.path().join("log");
        self.config.runtime.socket_path = self.temp.path().join("traffic-masqd.sock");
        self.config.runtime.pid_path = self.temp.path().join("traffic-masqd.pid");
        self.config.runtime.shutdown_policy = ShutdownPolicy::RestoreInterfaces;
        self.config.auth.database_path = self.temp.path().join("auth.sqlite3");
        self.config.auth.argon2_memory_kib = 1_024;
        self.config.auth.argon2_iterations = 1;
        self.config.vpn.enabled = false;
        self.config.wifi.enabled = true;
        self.config.wifi.hostapd_binary = command_path("hostapd")?;
        self.config.wifi.runtime_dir = self.temp.path().join("hostapd");
        self.config.wifi.restart_backoff_seconds = 1;
        self.config.wifi_client.enabled = true;
        self.config.wifi_client.wpa_supplicant_binary = command_path("wpa_supplicant")?;
        self.config.wifi_client.runtime_dir = self.temp.path().join("wpa_supplicant");
        self.config.wifi_client.restart_backoff_seconds = 1;
        self.config.dhcp.leases_dir = self.temp.path().join("dhcp-leases");
        self.config.router.uplink = Some(UplinkConfig {
            interface: self.uplink_interface.clone(),
            mode: UplinkMode::Dhcp,
        });
        self.config.network.interfaces.insert(
            self.uplink_interface.clone(),
            InterfaceConfig {
                wifi_concurrent: false,
                randomize_mac: false,
                mac_address: None,
                role: InterfaceRole::Input,
                managed: true,
                ipv4: None,
                dhcp: None,
                dhcp_client: Some(DhcpClientInterfaceConfig::default()),
                wifi: None,
                wifi_client: Some(WifiClientConfig {
                    ssid: self.upstream_ssid.clone(),
                    country_code: None,
                    security: WifiClientSecurity::Wpa2,
                    passphrase_file: Some(upstream_psk),
                }),
            },
        );
        self.config.network.interfaces.insert(
            self.output_interface.clone(),
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
                    ssid: self.ap_ssid.clone(),
                    country_code: None,
                    band: WifiBand::Ghz2,
                    channel: 6,
                    channel_width: WifiChannelWidth::Ht20,
                    security: WifiSecurity::Wpa2,
                    hidden: false,
                    client_isolation: false,
                    max_stations: 32,
                    passphrase_file: Some(ap_psk),
                }),
                wifi_client: None,
            },
        );
        self.config
            .validate()
            .context("physical router fixture built an invalid AppConfig")?;
        fs::write(&self.config_path, toml::to_string_pretty(&self.config)?)?;
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
                    return Ok::<_, anyhow::Error>(());
                }
                sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .context("traffic-masqd API did not become ready before timeout")??;
        self.daemon_pid = Some(read_pid_file(&self.config.runtime.pid_path)?);
        verify_real_daemon_pid(self.daemon_pid.unwrap())?;
        let test_password = format!("physical-router-test-{}", unique_suffix());
        if client
            .auth_initialized()
            .await
            .context("authentication readiness check failed")?
        {
            client
                .login(&test_password)
                .await
                .context("authentication was already initialized with an unknown credential")?;
        } else {
            client
                .initialize(&test_password)
                .await
                .context("failed to initialize authentication")?;
        }

        timeout(WAIT_TIMEOUT, async {
            loop {
                ensure_child_running(self.daemon.as_mut(), "traffic-masqd")?;
                if let Ok(Response::WifiClientStatus { interfaces }) =
                    client.request(&Request::WifiClientStatus).await
                {
                    if let Some(status) = interfaces.iter().find(|s| {
                        s.interface == self.uplink_interface
                            && s.wpa_state == WpaState::Completed.into()
                    }) {
                        if status.spec.ssid != self.upstream_ssid {
                            bail!("STA associated to an unexpected SSID");
                        }
                        self.supplicant_pid = Some(status.pid);
                        return Ok::<_, anyhow::Error>(());
                    }
                }
                sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .context("STA did not reach COMPLETED before timeout")??;

        let (dhcp_address, upstream_gateway) = timeout(WAIT_TIMEOUT, async {
            loop {
                ensure_child_running(self.daemon.as_mut(), "traffic-masqd")?;
                if let Ok(Response::DhcpClientStatus { interfaces }) =
                    client.request(&Request::DhcpClientStatus).await
                {
                    if let Some(status) = interfaces.iter().find(|status| {
                        status.interface == self.uplink_interface
                            && status.state == DhcpClientOperationalState::Running
                    }) {




                        if let (Some(address), Some(prefix)) =
                            (status.address, status.prefix_length)
                        {
                            verify_dhcp_address(
                                &self.namespace,
                                &self.uplink_interface,
                                address,
                                prefix,
                            )?;
                            let gateway = verify_protocol_202_default_route(
                                &self.namespace,
                                &self.uplink_interface,
                            )?;
                            return Ok::<_, anyhow::Error>((address, gateway));
                        }
                    }
                }
                sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .context("DHCP phase: client did not bind an address and protocol-202 default route before timeout")??;
        timeout(WAIT_TIMEOUT, async {
            loop {
                ensure_child_running(self.daemon.as_mut(), "traffic-masqd")?;
                let router_ready = matches!(
                    client.request(&Request::RouterStatus).await,
                    Ok(Response::RouterStatus {
                        enabled: true,
                        ready: true,
                        ..
                    })
                );
                if let Ok(Response::WifiStatus { interfaces }) =
                    client.request(&Request::WifiStatus).await
                {
                    if router_ready {
                        if let Some(status) = interfaces.iter().find(|s| {
                            s.interface == self.output_interface
                                && s.hostapd_state == HostapdState::Enabled.into()
                        }) {
                            if status.spec.ssid != self.ap_ssid {
                                bail!("AP enabled with an unexpected SSID");
                            }
                            self.hostapd_pid = Some(status.pid);
                            return Ok::<_, anyhow::Error>(());
                        }
                    }
                }
                sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .context("router and AP did not become ready before timeout")??;

        verify_ping(
            &self.namespace,
            &self.uplink_interface,
            &upstream_gateway.to_string(),
            "upstream gateway",
        )?;
        verify_ping(
            &self.namespace,
            &self.uplink_interface,
            "1.1.1.1",
            "public Internet address",
        )?;
        println!(
            "DHCP BOUND: uplink address {dhcp_address} and protocol-202 default route verified"
        );
        inspect_owned_nftables(
            &self.namespace,
            &self.uplink_interface,
            &self.output_interface,
        )?;
        println!("\nROUTER READY: connect a phone to TRAFFIC_MASQ_AP_SSID and generate traffic if desired. Waiting up to 120 seconds for station association and DHCP. The test does not require assertions against the inaccessible phone.\n");
        timeout(STATION_TIMEOUT, async {
            loop {
                ensure_child_running(self.daemon.as_mut(), "traffic-masqd")?;
                let stations = match client
                    .request(&Request::ListWifiStations {
                        interface: self.output_interface.clone(),
                    })
                    .await
                {
                    Ok(Response::WifiStations { stations, .. }) => stations,
                    Ok(_) => bail!("unexpected station-list response"),
                    Err(error) => bail!("station-list request failed: {error}"),
                };
                if !stations.is_empty() {
                    if let Ok(Response::Leases { leases, .. }) = client
                        .request(&Request::ListLeases {
                            interface: self.output_interface.clone(),
                        })
                        .await
                    {
                        if !leases.is_empty() {
                            return Ok::<_, anyhow::Error>(());
                        }
                    }
                }
                sleep(Duration::from_millis(500)).await;
            }
        })
        .await
        .context("no associated phone with a DHCP lease was observed within 120 seconds")??;
        self.stop_daemon().await?;
        for (pid, name) in [
            (self.hostapd_pid.take(), "hostapd"),
            (self.supplicant_pid.take(), "wpa_supplicant"),
        ] {
            if pid.is_some_and(pid_alive) {
                bail!("RestoreInterfaces did not stop tracked {name}");
            }
        }
        Ok(())
    }

    async fn run_usb_replug_test(&mut self) -> Result<()> {
        let password = format!("physical-usb-replug-test-{}", unique_suffix());
        let client = self.start_daemon("usb-replug", &password).await?;
        let (address, prefix, gateway) = self
            .wait_for_autonomous_router(&client, None)
            .await
            .context("initial autonomous path did not become ready")?;
        let initial_lease = self.load_bound_lease()?;
        verify_lease_evidence(&initial_lease, address, prefix, gateway)?;
        let initial_hostapd_pid = self.hostapd_pid.context("AP PID was not recorded")?;
        verify_output_side_operational(self, &client, initial_hostapd_pid).await?;

        println!(
            "\nUSB UNPLUG REQUIRED: physically unplug ONLY the USB Wi-Fi adapter corresponding to TRAFFIC_MASQ_UPLINK_INTERFACE={}. Do not unplug the output/AP adapter. This test will never unbind USB, unload a driver, delete a PHY, or simulate removal. Waiting up to 180 seconds...\n",
            self.original_uplink
        );
        io::stdout().flush()?;
        timeout(OPERATOR_USB_TIMEOUT, async {
            loop {
                ensure_child_running(self.daemon.as_mut(), "traffic-masqd")?;
                let interface_gone = !interface_exists(Some(&self.namespace), &self.uplink_interface)?;
                let phy_gone = !phy_exists(Some(&self.namespace), &self.uplink_phy)?;
                if interface_gone && phy_gone {
                    self.uplink_phy_in_namespace = false;
                    break Ok::<_, anyhow::Error>(());
                }
                sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .context("operator USB-unplug deadline expired before both the configured uplink interface and its PHY disappeared")??;

        timeout(WAIT_TIMEOUT, async {
            loop {
                ensure_child_running(self.daemon.as_mut(), "traffic-masqd")?;
                let daemon_alive = matches!(client.request(&Request::Ping).await, Ok(Response::Pong));
                let dhcp_not_running = match client.request(&Request::DhcpClientStatus).await {
                    Ok(Response::DhcpClientStatus { interfaces }) => interfaces
                        .iter()
                        .find(|status| status.interface == self.uplink_interface)
                        .is_none_or(|status| {
                            matches!(
                                status.state,
                                DhcpClientOperationalState::Waiting
                                    | DhcpClientOperationalState::Degraded
                            )
                        }),
                    _ => false,
                };
                if daemon_alive && dhcp_not_running {
                    verify_output_side_operational(self, &client, initial_hostapd_pid).await?;
                    return Ok::<_, anyhow::Error>(());
                }
                sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .context("daemon did not remain alive with DHCP waiting/degraded/no running actor and an operational AP/output side after unplug")??;

        println!(
            "\nUSB REPLUG REQUIRED: physically reconnect that same USB adapter now. The test requires udev to restore the configured name TRAFFIC_MASQ_UPLINK_INTERFACE={}; it will not operate an unknown or renamed interface. Waiting up to 180 seconds...\n",
            self.original_uplink
        );
        io::stdout().flush()?;
        let returned_phy = timeout(OPERATOR_USB_TIMEOUT, async {
            loop {
                ensure_child_running(self.daemon.as_mut(), "traffic-masqd")?;
                if interface_exists(None, &self.original_uplink)? {
                    validate_interface(&self.original_uplink, "TRAFFIC_MASQ_UPLINK_INTERFACE")?;
                    let phy = interface_phy(&self.original_uplink)?;
                    validate_only_interface(&phy, &self.original_uplink)?;
                    return Ok::<_, anyhow::Error>(phy);
                }
                sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .map_err(|_| {
            let observed = Command::new("iw")
                .arg("dev")
                .output()
                .map(|output| output_text(&output))
                .unwrap_or_else(|error| format!("unable to enumerate interfaces: {error}"));
            anyhow::anyhow!(
                "operator USB-replug deadline expired: udev did not restore configured interface {}. Check the adapter and add a persistent udev naming rule if it returned under another name. Observed wireless interfaces:\n{}",
                self.original_uplink,
                self.redact(&observed)
            )
        })??;

        run(
            "iw",
            &[
                "phy",
                &returned_phy,
                "set",
                "netns",
                "name",
                &self.namespace,
            ],
        )
        .context("the same-name replugged USB PHY could not be returned to the isolated fixture namespace")?;
        self.uplink_phy = returned_phy;
        self.uplink_phy_in_namespace = true;
        if !interface_exists(Some(&self.namespace), &self.uplink_interface)?
            || !phy_exists(Some(&self.namespace), &self.uplink_phy)?
        {
            bail!("replugged uplink PHY/interface did not appear in the fixture namespace");
        }

        let (recovered_address, recovered_prefix, recovered_gateway) = self
            .wait_for_autonomous_router_with_timeout(&client, None, OPERATOR_USB_TIMEOUT)
            .await
            .context("replug recovery timed out before wpa COMPLETED, DHCP bind/adopt/reacquire, protocol-202 route, and router readiness")?;
        let recovered_lease = self.load_bound_lease()?;
        verify_lease_evidence(
            &recovered_lease,
            recovered_address,
            recovered_prefix,
            recovered_gateway,
        )?;
        verify_ping(
            &self.namespace,
            &self.uplink_interface,
            &recovered_gateway.to_string(),
            "recovered upstream gateway",
        )?;
        verify_output_side_operational(self, &client, initial_hostapd_pid).await?;
        println!(
            "USB REPLUG RECOVERY: daemon survived; DHCP degraded/waited while absent; same configured uplink returned and reached wpa COMPLETED, {recovered_address}/{recovered_prefix}, protocol-202 gateway {recovered_gateway}, exact bound ownership, and router ready; hostapd PID {initial_hostapd_pid} and downstream service remained operational"
        );
        Ok(())
    }

    async fn run_explicit_renew_test(&mut self) -> Result<()> {
        self.config.runtime.shutdown_policy = ShutdownPolicy::PreserveInterfaces;
        fs::write(&self.config_path, toml::to_string_pretty(&self.config)?)?;
        let password = format!("physical-renew-test-{}", unique_suffix());

        let client = self.start_daemon("explicit-renew", &password).await?;
        let (address, prefix, gateway) = self
            .wait_for_autonomous_router(&client, None)
            .await
            .context("initial autonomous path did not become ready")?;
        let initial_lease = self.load_bound_lease()?;
        verify_lease_evidence(&initial_lease, address, prefix, gateway)?;
        let lease_path = self.bound_lease_path();
        let initial_modified = fs::metadata(&lease_path)?
            .modified()
            .context("persisted DHCP ownership record has no modification time")?;
        let hostapd_pid = self.hostapd_pid.context("hostapd PID was not recorded")?;
        let supplicant_pid = self
            .supplicant_pid
            .context("wpa_supplicant PID was not recorded")?;

        match client
            .request(&Request::RenewDhcpClient {
                interface: self.uplink_interface.clone(),
            })
            .await
            .context("explicit DHCP renew API request failed")?
        {
            Response::DhcpClientInterface { .. } => {}
            response => bail!("explicit DHCP renew returned unexpected response: {response:?}"),
        }

        let renewed_lease = timeout(WAIT_TIMEOUT, async {
            loop {
                ensure_child_running(self.daemon.as_mut(), "traffic-masqd")?;
                let persisted = self.load_bound_lease();
                let modified = fs::metadata(&lease_path).and_then(|metadata| metadata.modified());
                let dhcp = client.request(&Request::DhcpClientStatus).await;
                let router = client.request(&Request::RouterStatus).await;
                if let (
                    Ok(lease),
                    Ok(modified),
                    Ok(Response::DhcpClientStatus { interfaces }),
                    Ok(Response::RouterStatus {
                        enabled: true,
                        ready: true,
                        ..
                    }),
                ) = (persisted, modified, dhcp, router)
                {
                    let bound = interfaces.iter().any(|status| {
                        status.interface == self.uplink_interface
                            && status.state == DhcpClientOperationalState::Running
                            && status.address == Some(address)
                            && status.prefix_length == Some(prefix)
                            && status.server == Some(initial_lease.server_identifier)
                    });
                    if bound && modified > initial_modified {
                        return Ok::<_, anyhow::Error>(lease);
                    }
                }
                sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .context("explicit renew did not produce a fresh persisted bound transaction and ready router before timeout")??;

        verify_lease_evidence(&renewed_lease, address, prefix, gateway)?;
        if renewed_lease.interface != initial_lease.interface
            || renewed_lease.interface_index != initial_lease.interface_index
            || renewed_lease.hardware_address != initial_lease.hardware_address
            || renewed_lease.client_identifier != initial_lease.client_identifier
            || renewed_lease.server_identifier != initial_lease.server_identifier
            || renewed_lease.address != initial_lease.address
            || renewed_lease.prefix_len != initial_lease.prefix_len
            || renewed_lease.owned_routes != initial_lease.owned_routes
        {
            bail!("explicit renew changed DHCP ownership identity, address, server, prefix, or exact routes");
        }
        verify_dhcp_address(&self.namespace, &self.uplink_interface, address, prefix)?;
        if verify_protocol_202_default_route(&self.namespace, &self.uplink_interface)? != gateway {
            bail!("explicit renew changed the protocol-202 default-route gateway");
        }
        verify_ping(
            &self.namespace,
            &self.uplink_interface,
            &gateway.to_string(),
            "upstream gateway after explicit renew",
        )?;
        self.verify_ap_processes(&client, hostapd_pid, supplicant_pid)
            .await?;
        println!(
            "EXPLICIT RENEW: fresh bound ownership record observed for {address}/{prefix} via server {}, exact protocol-202 routes retained, router ready, gateway reachable; hostapd PID {hostapd_pid} and wpa_supplicant PID {supplicant_pid} retained",
            renewed_lease.server_identifier
        );
        Ok(())
    }

    async fn run_natural_t1_test(&mut self, max_wait: Duration) -> Result<()> {
        let password = format!("physical-natural-t1-test-{}", unique_suffix());
        let client = self.start_daemon("natural-t1", &password).await?;
        let (address, prefix, gateway) = self
            .wait_for_autonomous_router(&client, None)
            .await
            .context("initial autonomous path did not become ready")?;
        let initial = self.load_bound_lease()?;
        verify_lease_evidence(&initial, address, prefix, gateway)?;
        let lease_path = self.bound_lease_path();
        let initial_modified = fs::metadata(&lease_path)?.modified()?;
        let now = unix_time_seconds()?;
        let wait_until_t1 = natural_t1_wait(&initial, now, max_wait)?;
        let initial_t1_unix = now + wait_until_t1.as_secs();
        let deadline = wait_until_t1
            .checked_add(LONG_T1_MARGIN)
            .context("natural T1 wait deadline overflowed")?;
        let hostapd_pid = self.hostapd_pid.context("hostapd PID was not recorded")?;
        let supplicant_pid = self
            .supplicant_pid
            .context("wpa_supplicant PID was not recorded")?;
        println!(
            "NATURAL T1: lease expires at Unix {}, T1 is Unix {}; waiting {} seconds plus {} seconds margin (safe cap {} seconds)",
            initial.expires_at_unix,
            initial_t1_unix,
            wait_until_t1.as_secs(),
            LONG_T1_MARGIN.as_secs(),
            max_wait.as_secs()
        );

        let started = Instant::now();
        let mut next_progress = LONG_T1_PROGRESS_INTERVAL;
        let renewed = timeout(deadline, async {
            loop {
                ensure_child_running(self.daemon.as_mut(), "traffic-masqd")?;
                let elapsed = started.elapsed();
                let current = self.load_bound_lease()?;
                let modified = fs::metadata(&lease_path)?.modified()?;
                let dhcp = client.request(&Request::DhcpClientStatus).await;
                let router = client.request(&Request::RouterStatus).await;
                let sta = client.request(&Request::WifiClientStatus).await;
                let ap = client.request(&Request::WifiStatus).await;
                let healthy = matches!(router, Ok(Response::RouterStatus { enabled: true, ready: true, .. }))
                    && matches!(dhcp, Ok(Response::DhcpClientStatus { ref interfaces }) if interfaces.iter().any(|status|
                        status.interface == self.uplink_interface
                            && status.state == DhcpClientOperationalState::Running
                            && status.address == Some(address)
                            && status.prefix_length == Some(prefix)
                            && status.server == Some(initial.server_identifier)
                            && status.expires_at_unix == Some(current.expires_at_unix)))
                    && matches!(sta, Ok(Response::WifiClientStatus { ref interfaces }) if interfaces.iter().any(|status|
                        status.interface == self.uplink_interface
                            && status.wpa_state == WpaState::Completed.into()
                            && status.pid == supplicant_pid))
                    && matches!(ap, Ok(Response::WifiStatus { ref interfaces }) if interfaces.iter().any(|status|
                        status.interface == self.output_interface
                            && status.hostapd_state == HostapdState::Enabled.into()
                            && status.pid == hostapd_pid));
                if !healthy {
                    bail!("daemon/router/AP/STA/DHCP health or retained PID proof failed while waiting for natural T1");
                }
                verify_lease_identity_and_routes(&initial, &current)?;
                verify_dhcp_address(&self.namespace, &self.uplink_interface, address, prefix)?;
                if verify_protocol_202_default_route(&self.namespace, &self.uplink_interface)? != gateway {
                    bail!("protocol-202 default-route gateway changed while waiting for natural T1");
                }

                let crossed_t1 = unix_time_seconds()? >= initial_t1_unix;
                let schedule_advanced = current.expires_at_unix > initial.expires_at_unix
                    && lease_acquired_at(&current)? > lease_acquired_at(&initial)?;
                let rewritten_after_t1 = modified > initial_modified
                    && modified.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
                        >= initial_t1_unix;
                if crossed_t1 && schedule_advanced && rewritten_after_t1 {
                    return Ok::<_, anyhow::Error>(current);
                }
                if elapsed >= next_progress {
                    println!(
                        "NATURAL T1 progress: elapsed {}s, {}s until initial T1, daemon/STA/AP/router/DHCP/address/protocol-202 route healthy; no renewal API called",
                        elapsed.as_secs(),
                        initial_t1_unix.saturating_sub(unix_time_seconds()?)
                    );
                    next_progress += LONG_T1_PROGRESS_INTERVAL;
                }
                sleep(LONG_T1_HEALTH_INTERVAL).await;
            }
        })
        .await
        .context("natural T1 did not produce a correlated bound lease renewal before the bounded deadline")??;

        verify_lease_evidence(&renewed, address, prefix, gateway)?;
        verify_ping(
            &self.namespace,
            &self.uplink_interface,
            &gateway.to_string(),
            "upstream gateway after natural T1 renewal",
        )?;
        self.verify_ap_processes(&client, hostapd_pid, supplicant_pid)
            .await?;
        println!(
            "NATURAL T1 RENEWED: exact identity/address/routes retained; expiry advanced {} -> {}, gateway reachable, router ready; hostapd PID {hostapd_pid} and wpa_supplicant PID {supplicant_pid} retained",
            initial.expires_at_unix, renewed.expires_at_unix
        );
        Ok(())
    }

    async fn wait_for_bound_uplink_client(&mut self, client: &ApiClient) -> Result<()> {
        timeout(WAIT_TIMEOUT, async {
            loop {
                ensure_child_running(self.daemon.as_mut(), "traffic-masqd")?;
                if let Ok(Response::DhcpClientStatus { interfaces }) =
                    client.request(&Request::DhcpClientStatus).await
                {
                    if interfaces.iter().any(|status| {
                        status.interface == self.uplink_interface
                            && status.state == DhcpClientOperationalState::Running
                            && status.address.is_some()
                    }) {
                        return Ok::<_, anyhow::Error>(());
                    }
                }
                sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .context("uplink DHCP client did not report a bound address before timeout")?
    }

    async fn commit_router(&self, client: &ApiClient, router: RouterConfig) -> Result<()> {
        let token = match client
            .request(&Request::RouterApply {
                proposal: RouterProposalRequest {
                    set_router: Some(router),
                    ..RouterProposalRequest::default()
                }
                .into(),
            })
            .await?
        {
            Response::RouterTransactionPending { token, .. } => token,
            response => bail!("router apply returned unexpected response: {response:?}"),
        };
        match client.request(&Request::RouterCommit { token }).await? {
            Response::RouterCommitted { .. } => Ok(()),
            response => bail!("router commit returned unexpected response: {response:?}"),
        }
    }

    async fn run_foreign_state_survival_test(&mut self) -> Result<()> {
        let password = format!("physical-foreign-state-test-{}", unique_suffix());
        let client = self.start_daemon("foreign-state", &password).await?;
        let (address, prefix, gateway) = self
            .wait_for_autonomous_router(&client, None)
            .await
            .context("initial autonomous path did not become ready")?;
        let lease = self.load_bound_lease()?;
        verify_lease_evidence(&lease, address, prefix, gateway)?;

        const FOREIGN_ADDRESS: &str = "198.18.0.2/30";
        const FOREIGN_DESTINATION: &str = "198.19.255.254/32";
        const FOREIGN_PROTOCOL: &str = "99";
        run_ns(
            &self.namespace,
            "ip",
            &[
                "-4",
                "address",
                "add",
                FOREIGN_ADDRESS,
                "dev",
                &self.uplink_interface,
            ],
        )?;
        run_ns(
            &self.namespace,
            "ip",
            &[
                "-4",
                "route",
                "add",
                FOREIGN_DESTINATION,
                "dev",
                &self.uplink_interface,
                "protocol",
                FOREIGN_PROTOCOL,
                "metric",
                "4242",
            ],
        )?;
        let foreign_address_before =
            exact_address_line(&self.namespace, &self.uplink_interface, FOREIGN_ADDRESS)?;
        let foreign_route_before =
            exact_route_line(&self.namespace, &self.uplink_interface, FOREIGN_DESTINATION)?;

        match client
            .request(&Request::DisableDhcpClient {
                interface: self.uplink_interface.clone(),
            })
            .await
            .context("DHCP-client DELETE against a router-held uplink failed to answer")?
        {
            Response::DhcpClientError {
                detail: DhcpClientErrorDetail::InvalidConfig { .. },
            } => {}
            response => bail!(
                "DHCP-client DELETE against a router-held uplink returned {response:?} instead of a typed invalid_config refusal"
            ),
        }
        if !dhcp_owned_state_present(&self.namespace, &self.uplink_interface, address, prefix)? {
            bail!("refused DHCP-client DELETE tore down owned uplink state anyway");
        }
        verify_lease_evidence(&self.load_bound_lease()?, address, prefix, gateway)?;

        self.commit_router(&client, RouterConfig::default())
            .await
            .context("failed to retire router mode before the survival proof")?;
        timeout(WAIT_TIMEOUT, async {
            loop {
                ensure_child_running(self.daemon.as_mut(), "traffic-masqd")?;
                if !dhcp_owned_state_present(
                    &self.namespace,
                    &self.uplink_interface,
                    address,
                    prefix,
                )? {
                    return Ok::<_, anyhow::Error>(());
                }
                sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .context(
            "retiring router mode did not remove exact owned address/routes before timeout",
        )??;

        match client
            .request(&Request::DisableDhcpClient {
                interface: self.uplink_interface.clone(),
            })
            .await
            .context("DHCP-client DELETE after router retirement failed to answer")?
        {
            Response::DhcpClientError {
                detail: DhcpClientErrorDetail::Disabled,
            } => {}
            response => bail!(
                "DHCP-client DELETE after router retirement returned {response:?} instead of a typed disabled result"
            ),
        }

        let foreign_address_after =
            exact_address_line(&self.namespace, &self.uplink_interface, FOREIGN_ADDRESS)?;
        let foreign_route_after =
            exact_route_line(&self.namespace, &self.uplink_interface, FOREIGN_DESTINATION)?;
        if foreign_address_after != foreign_address_before
            || foreign_route_after != foreign_route_before
        {
            bail!("DHCP ownership cleanup changed or removed exact foreign address/route state");
        }

        match client
            .request(&Request::ConfigureDhcpClient {
                interface: self.uplink_interface.clone(),
                config: DhcpClientConfigRequest::default(),
            })
            .await
            .context("failed to re-enable DHCP client after survival proof")?
        {
            Response::DhcpClientInterface { .. } => {}
            response => bail!("DHCP-client re-enable returned unexpected response: {response:?}"),
        }
        self.wait_for_bound_uplink_client(&client)
            .await
            .context("uplink client did not rebind before router mode was restored")?;
        self.commit_router(&client, self.config.router.clone())
            .await
            .context("failed to restore router mode after the survival proof")?;
        let _ = self
            .wait_for_autonomous_router(&client, None)
            .await
            .context("autonomous fixture did not recover after router mode was restored")?;
        run_ns(
            &self.namespace,
            "ip",
            &[
                "-4",
                "route",
                "del",
                FOREIGN_DESTINATION,
                "dev",
                &self.uplink_interface,
                "protocol",
                FOREIGN_PROTOCOL,
                "metric",
                "4242",
            ],
        )?;
        run_ns(
            &self.namespace,
            "ip",
            &[
                "-4",
                "address",
                "del",
                FOREIGN_ADDRESS,
                "dev",
                &self.uplink_interface,
            ],
        )?;
        println!(
            "FOREIGN STATE SURVIVAL: DHCP-client DELETE against the router-held uplink was refused as invalid_config without disturbing the running client; retiring router mode then removed only {address}/{prefix} and protocol-202 routes; exact foreign {FOREIGN_ADDRESS} and protocol-{FOREIGN_PROTOCOL} route {FOREIGN_DESTINATION} remained byte-for-byte; restoring router mode recovered the fixture"
        );
        Ok(())
    }

    async fn run_ap_restart_reassociation_test(&mut self) -> Result<()> {
        self.config.runtime.shutdown_policy = ShutdownPolicy::PreserveInterfaces;
        fs::write(&self.config_path, toml::to_string_pretty(&self.config)?)?;
        let password = format!("physical-ap-restart-test-{}", unique_suffix());

        let client = self.start_daemon("ap-restart", &password).await?;
        let (address, prefix, gateway) = self
            .wait_for_autonomous_router(&client, None)
            .await
            .context("initial autonomous path did not become ready")?;
        let initial_lease = self.load_bound_lease()?;
        verify_lease_evidence(&initial_lease, address, prefix, gateway)?;
        let initial_hostapd_pid = self.hostapd_pid.context("hostapd PID was not recorded")?;
        let supplicant_pid = self
            .supplicant_pid
            .context("wpa_supplicant PID was not recorded")?;
        self.wait_for_phone_path(
            &client,
            "INITIAL PHONE PATH: connect the phone to the test AP; waiting up to 120 seconds for station association and downstream DHCP.",
        )
        .await?;

        let settings = WifiEditRequest {
            ssid: self.ap_ssid.clone(),
            country_code: None,
            band: WifiBand::Ghz2,
            channel: 1,
            channel_width: WifiChannelWidth::Ht20,
            security: WifiSecurity::Wpa2,
            hidden: false,
            client_isolation: false,
            max_stations: 32,
        };
        let pending = match client
            .request(&Request::ProvisionWifiAccessPoint {
                interface: self.output_interface.clone(),
                settings,

                passphrase: Some(self.ap_psk_secret.clone()),
                clear_passphrase: false,
                configure_dhcp: true,
                subnet: None,
                disable_dhcp: false,
            })
            .await
            .context("supported AP reconfiguration API request failed")?
        {
            Response::NetworkChangePending { change }
                if change.interface == self.output_interface =>
            {
                change
            }
            response => bail!("AP reconfiguration returned unexpected response: {response:?}"),
        };
        match client
            .request(&Request::CommitNetworkChange {
                token: pending.token,
            })
            .await
            .context("AP reconfiguration commit request failed")?
        {
            Response::NetworkChangeCommitted { .. } => {}
            response => {
                bail!("AP reconfiguration commit returned unexpected response: {response:?}")
            }
        }

        let (retained_address, retained_prefix, retained_gateway) = self
            .wait_for_autonomous_router(&client, None)
            .await
            .context("autonomous router did not recover after supervised AP restart")?;
        let restarted_hostapd_pid = self.hostapd_pid.context("restarted hostapd PID missing")?;
        if restarted_hostapd_pid == initial_hostapd_pid {
            bail!("channel-changing AP provisioning should restart, not reload, hostapd");
        }
        if pid_alive(initial_hostapd_pid) {
            bail!("supervised AP restart left the previous owned hostapd PID alive");
        }
        if self.supplicant_pid != Some(supplicant_pid) {
            bail!("AP restart replaced the upstream wpa_supplicant process");
        }
        if (retained_address, retained_prefix, retained_gateway) != (address, prefix, gateway) {
            bail!("AP restart changed the upstream DHCP address, prefix, or protocol-202 gateway");
        }
        let retained_lease = self.load_bound_lease()?;
        if retained_lease != initial_lease {
            bail!("AP restart changed the persisted upstream DHCP lease or ownership evidence");
        }
        verify_dhcp_address(&self.namespace, &self.uplink_interface, address, prefix)?;
        if verify_protocol_202_default_route(&self.namespace, &self.uplink_interface)? != gateway {
            bail!("AP restart changed the protocol-202 default-route gateway");
        }
        verify_ping(
            &self.namespace,
            &self.uplink_interface,
            &gateway.to_string(),
            "upstream gateway after AP restart",
        )?;
        self.wait_for_phone_path(
            &client,
            "AP RESTARTED: reconnect the phone to the test AP if it did not reconnect automatically; waiting up to 120 seconds for station association and downstream DHCP.",
        )
        .await?;
        println!(
            "AP RESTART/REASSOCIATION: hostapd PID {initial_hostapd_pid} -> {restarted_hostapd_pid} through commit-confirm AP channel change; wpa_supplicant PID {supplicant_pid}, upstream {address}/{prefix}, protocol-202 gateway {gateway}, exact bound lease, router readiness, phone station, and downstream DHCP retained/re-established"
        );
        Ok(())
    }

    async fn wait_for_phone_path(&mut self, client: &ApiClient, prompt: &str) -> Result<()> {
        println!("\n{prompt}\n");
        timeout(STATION_TIMEOUT, async {
            loop {
                ensure_child_running(self.daemon.as_mut(), "traffic-masqd")?;
                let stations = client
                    .request(&Request::ListWifiStations {
                        interface: self.output_interface.clone(),
                    })
                    .await;
                let leases = client
                    .request(&Request::ListLeases {
                        interface: self.output_interface.clone(),
                    })
                    .await;
                if matches!(stations, Ok(Response::WifiStations { ref stations, .. }) if !stations.is_empty())
                    && matches!(leases, Ok(Response::Leases { ref leases, .. }) if !leases.is_empty())
                {
                    return Ok::<_, anyhow::Error>(());
                }
                sleep(Duration::from_millis(500)).await;
            }
        })
        .await
        .context("phone station association and downstream DHCP lease were not both observed within 120 seconds")?
    }

    async fn verify_ap_processes(
        &mut self,
        client: &ApiClient,
        hostapd_pid: u32,
        supplicant_pid: u32,
    ) -> Result<()> {
        timeout(WAIT_TIMEOUT, async {
            loop {
                ensure_child_running(self.daemon.as_mut(), "traffic-masqd")?;
                let sta = client.request(&Request::WifiClientStatus).await;
                let ap = client.request(&Request::WifiStatus).await;
                if let (
                    Ok(Response::WifiClientStatus { interfaces: sta }),
                    Ok(Response::WifiStatus { interfaces: ap }),
                ) = (sta, ap)
                {
                    let same_sta = sta.iter().any(|status| {
                        status.interface == self.uplink_interface
                            && status.wpa_state == WpaState::Completed.into()
                            && status.pid == supplicant_pid
                    });
                    let same_ap = ap.iter().any(|status| {
                        status.interface == self.output_interface
                            && status.hostapd_state == HostapdState::Enabled.into()
                            && status.pid == hostapd_pid
                    });
                    if same_sta && same_ap {
                        return Ok::<_, anyhow::Error>(());
                    }
                }
                sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .context("AP processes were not retained and healthy after explicit renew")?
    }

    async fn run_preserve_restart_test(&mut self) -> Result<()> {
        self.config.runtime.shutdown_policy = ShutdownPolicy::PreserveInterfaces;
        fs::write(&self.config_path, toml::to_string_pretty(&self.config)?)?;
        let password = format!("physical-preserve-test-{}", unique_suffix());

        let first_client = self.start_daemon("preserve-first", &password).await?;
        let (address, prefix, gateway) = self
            .wait_for_autonomous_router(&first_client, None)
            .await
            .context("initial autonomous path did not become ready")?;
        let initial_lease = self.load_bound_lease()?;
        verify_lease_evidence(&initial_lease, address, prefix, gateway)?;
        let hostapd_pid = self.hostapd_pid.context("hostapd PID was not recorded")?;
        let supplicant_pid = self
            .supplicant_pid
            .context("wpa_supplicant PID was not recorded")?;

        self.stop_daemon().await?;
        verify_dhcp_address(&self.namespace, &self.uplink_interface, address, prefix)?;
        let preserved_gateway =
            verify_protocol_202_default_route(&self.namespace, &self.uplink_interface)?;
        if preserved_gateway != gateway {
            bail!("PreserveInterfaces changed the protocol-202 default-route gateway");
        }
        for (pid, name) in [(hostapd_pid, "hostapd"), (supplicant_pid, "wpa_supplicant")] {
            if !pid_alive(pid) {
                bail!("PreserveInterfaces stopped tracked {name}");
            }
        }
        let preserved_lease = self.load_bound_lease()?;
        if preserved_lease != initial_lease {
            bail!("PreserveInterfaces changed the persisted DHCP ownership record");
        }

        let second_client = self.start_daemon("preserve-restart", &password).await?;
        let (restarted_address, restarted_prefix, restarted_gateway) = self
            .wait_for_autonomous_router(&second_client, Some((hostapd_pid, supplicant_pid)))
            .await
            .context("restarted daemon did not adopt the autonomous path")?;
        if (restarted_address, restarted_prefix, restarted_gateway) != (address, prefix, gateway) {
            bail!("restarted daemon did not retain the adopted DHCP address and default route");
        }
        let adopted_lease = self.load_bound_lease()?;
        verify_lease_evidence(&adopted_lease, address, prefix, gateway)?;
        if adopted_lease.interface != initial_lease.interface
            || adopted_lease.interface_index != initial_lease.interface_index
            || adopted_lease.hardware_address != initial_lease.hardware_address
            || adopted_lease.client_identifier != initial_lease.client_identifier
            || adopted_lease.server_identifier != initial_lease.server_identifier
            || adopted_lease.address != initial_lease.address
            || adopted_lease.prefix_len != initial_lease.prefix_len
            || adopted_lease.owned_routes != initial_lease.owned_routes
        {
            bail!("restart changed the persisted DHCP ownership identity or exact kernel objects");
        }
        println!(
            "PRESERVE ADOPTION: address {address}/{prefix}, protocol-202 gateway {gateway}, bound ownership record, router ready; hostapd PID {hostapd_pid} and wpa_supplicant PID {supplicant_pid} adopted"
        );
        Ok(())
    }

    async fn start_daemon(&mut self, log_stem: &str, password: &str) -> Result<ApiClient> {
        let stdout = fs::File::create(self.temp.path().join(format!("{log_stem}.stdout")))?;
        let stderr = fs::File::create(self.temp.path().join(format!("{log_stem}.stderr")))?;
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
                    return Ok::<_, anyhow::Error>(());
                }
                sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .context("traffic-masqd API did not become ready before timeout")??;
        self.daemon_pid = Some(read_pid_file(&self.config.runtime.pid_path)?);
        verify_real_daemon_pid(self.daemon_pid.unwrap())?;
        if client.auth_initialized().await? {
            client.login(password).await?;
        } else {
            client.initialize(password).await?;
        }
        Ok(client)
    }

    async fn wait_for_autonomous_router(
        &mut self,
        client: &ApiClient,
        expected_preserved_pids: Option<(u32, u32)>,
    ) -> Result<(Ipv4Addr, u8, Ipv4Addr)> {
        self.wait_for_autonomous_router_with_timeout(client, expected_preserved_pids, WAIT_TIMEOUT)
            .await
    }

    async fn wait_for_autonomous_router_with_timeout(
        &mut self,
        client: &ApiClient,
        expected_preserved_pids: Option<(u32, u32)>,
        deadline: Duration,
    ) -> Result<(Ipv4Addr, u8, Ipv4Addr)> {
        timeout(deadline, async {
            loop {
                ensure_child_running(self.daemon.as_mut(), "traffic-masqd")?;
                let wifi_client = client.request(&Request::WifiClientStatus).await;
                let dhcp = client.request(&Request::DhcpClientStatus).await;
                let router = client.request(&Request::RouterStatus).await;
                let wifi = client.request(&Request::WifiStatus).await;
                if let (
                    Ok(Response::WifiClientStatus { interfaces: sta }),
                    Ok(Response::DhcpClientStatus { interfaces: dhcp }),
                    Ok(Response::RouterStatus {
                        enabled: true,
                        ready: true,
                        ..
                    }),
                    Ok(Response::WifiStatus { interfaces: ap }),
                ) = (wifi_client, dhcp, router, wifi)
                {
                    let sta = sta.iter().find(|status| {
                        status.interface == self.uplink_interface
                            && status.wpa_state == WpaState::Completed.into()
                    });
                    let dhcp = dhcp.iter().find(|status| {
                        status.interface == self.uplink_interface
                            && status.state == DhcpClientOperationalState::Running
                    });
                    let ap = ap.iter().find(|status| {
                        status.interface == self.output_interface
                            && status.hostapd_state == HostapdState::Enabled.into()
                    });
                    if let (Some(sta), Some(_dhcp_status), Some(ap), Some(address), Some(prefix)) = (
                        sta,
                        dhcp,
                        ap,
                        dhcp.and_then(|status| status.address),
                        dhcp.and_then(|status| status.prefix_length),
                    )
                    {
                        if let Some((hostapd_pid, supplicant_pid)) = expected_preserved_pids {
                            if ap.pid != hostapd_pid || sta.pid != supplicant_pid {
                                bail!("daemon restart replaced rather than adopted preserved hostapd/wpa_supplicant processes");
                            }
                        }
                        self.hostapd_pid = Some(ap.pid);
                        self.supplicant_pid = Some(sta.pid);
                        verify_dhcp_address(&self.namespace, &self.uplink_interface, address, prefix)?;
                        let gateway = verify_protocol_202_default_route(
                            &self.namespace,
                            &self.uplink_interface,
                        )?;
                        return Ok::<_, anyhow::Error>((address, prefix, gateway));
                    }
                }
                sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .context("autonomous router readiness timed out")?
    }

    fn bound_lease_path(&self) -> PathBuf {
        self.config
            .runtime
            .state_dir
            .join("dhcp-client")
            .join(format!("{}.json", self.uplink_interface))
    }

    fn load_bound_lease(&self) -> Result<DhcpClientLease> {
        let store = DhcpClientLeaseStore::new(&self.config.runtime.state_dir)?;
        let lease = store
            .load(&self.uplink_interface)?
            .context("persisted DHCP ownership record is missing")?;
        if lease.state != DhcpClientLeaseState::Bound {
            bail!("persisted DHCP ownership record is not bound");
        }
        Ok(lease)
    }

    async fn stop_daemon(&mut self) -> Result<()> {
        let child = self.daemon.take().context("daemon was not running")?;
        stop_child(child, Signal::SIGTERM, STOP_GRACE, "traffic-masqd").await?;
        self.daemon_pid = None;
        Ok(())
    }

    fn dump_diagnostics(&self, phase: &str) {
        eprintln!(
            "=== physical router diagnostics ({phase}; both SSIDs and all secrets omitted) ==="
        );
        let mut diagnostic_paths = vec![
            self.temp.path().join("daemon.stdout"),
            self.temp.path().join("daemon.stderr"),
            self.temp.path().join("preserve-first.stdout"),
            self.temp.path().join("preserve-first.stderr"),
            self.temp.path().join("preserve-restart.stdout"),
            self.temp.path().join("preserve-restart.stderr"),
            self.temp.path().join("ap-restart.stdout"),
            self.temp.path().join("ap-restart.stderr"),
            self.temp.path().join("foreign-state.stdout"),
            self.temp.path().join("foreign-state.stderr"),
            self.temp.path().join("usb-replug.stdout"),
            self.temp.path().join("usb-replug.stderr"),
        ];
        diagnostic_paths.push(
            self.config
                .runtime
                .state_dir
                .join("dhcp-client")
                .join(format!("{}.json", self.uplink_interface)),
        );
        for path in diagnostic_paths {
            if let Ok(text) = fs::read_to_string(path) {
                eprintln!("{}", self.redact(&text));
            }
        }
        if let Ok(entries) = fs::read_dir(&self.config.runtime.log_dir) {
            for entry in entries.flatten() {
                if entry.file_type().is_ok_and(|t| t.is_file()) {
                    if let Ok(text) = fs::read_to_string(entry.path()) {
                        eprintln!(
                            "--- {} ---\n{}",
                            entry.file_name().to_string_lossy(),
                            self.redact(&text)
                        );
                    }
                }
            }
        }
        if self.uplink_phy_in_namespace || self.output_phy_in_namespace {
            for (program, args) in [
                ("ip", &["address", "show"][..]),
                ("ip", &["route", "show"][..]),
                ("iw", &["dev"][..]),
                ("nft", &["list", "table", "inet", "traffic_masq"][..]),
            ] {
                if let Ok(output) = output_ns(&self.namespace, program, args) {
                    eprintln!("--- {program} ---\n{}", self.redact(&output_text(&output)));
                }
            }
        }
    }

    fn redact(&self, text: &str) -> String {
        text.replace(&self.upstream_ssid, "<redacted-upstream-ssid>")
            .replace(&self.ap_ssid, "<redacted-ap-ssid>")
            .replace(&self.upstream_psk_secret, "<redacted-upstream-psk>")
            .replace(&self.ap_psk_secret, "<redacted-ap-psk>")
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
        if let Some(pid) = self.supplicant_pid.take() {
            stop_pid_blocking(pid, "wpa_supplicant");
        }
        self.return_phy(true);
        self.return_phy(false);
        if !self.uplink_phy_in_namespace && !self.output_phy_in_namespace {
            let _ = Command::new("ip")
                .args(["netns", "del", &self.namespace])
                .status();
            for interface in [&self.original_uplink, &self.original_output] {
                let _ = Command::new("ip")
                    .args(["link", "set", interface, "up"])
                    .status();
            }
        }
    }

    fn return_phy(&mut self, uplink: bool) {
        let (in_ns, phy, interface) = if uplink {
            (
                &mut self.uplink_phy_in_namespace,
                &self.uplink_phy,
                &self.original_uplink,
            )
        } else {
            (
                &mut self.output_phy_in_namespace,
                &self.output_phy,
                &self.original_output,
            )
        };
        if !*in_ns {
            return;
        }
        match output_ns(&self.namespace, "iw", &["phy", phy, "set", "netns", "1"]) {
            Ok(output) if output.status.success() => *in_ns = false,
            Ok(output) => print_recovery(&self.namespace, phy, interface, &output_text(&output)),
            Err(error) => print_recovery(&self.namespace, phy, interface, &format!("{error:#}")),
        }
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
            uplink_interface: required_env("TRAFFIC_MASQ_UPLINK_INTERFACE")?,
            output_interface: required_env("TRAFFIC_MASQ_OUTPUT_INTERFACE")?,
            upstream_ssid: required_env("TRAFFIC_MASQ_UPSTREAM_SSID")?,
            upstream_psk_file: PathBuf::from(required_env("TRAFFIC_MASQ_UPSTREAM_PSK_FILE")?),
            ap_ssid: required_env("TRAFFIC_MASQ_AP_SSID")?,
            ap_psk_file: PathBuf::from(required_env("TRAFFIC_MASQ_AP_PSK_FILE")?),
        })
    }
}

#[tokio::test]
#[ignore = "moves two physical Wi-Fi PHYs and requires root, real hardware, Internet, and a phone"]
async fn physical_wifi_router_serves_phone_through_upstream_sta() -> Result<()> {
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
#[ignore = "long natural DHCP T1 wait; moves two physical Wi-Fi PHYs and requires explicit opt-in, root, real hardware, and Internet"]
async fn physical_wifi_router_natural_t1_renews_dhcp_lease() -> Result<()> {
    let _guard = PHYSICAL_WIFI_TEST_LOCK.lock().await;
    verify_long_t1_guard(env::var("TRAFFIC_MASQ_LONG_T1").ok().as_deref())?;
    let max_wait = long_t1_max_wait(
        env::var("TRAFFIC_MASQ_LONG_T1_MAX_WAIT_SECONDS")
            .ok()
            .as_deref(),
    )?;
    let mut fixture = PhysicalWifiFixture::new()?;
    let result = fixture.run_natural_t1_test(max_wait).await;
    if let Err(error) = result {
        fixture.dump_diagnostics("natural T1 renewal failure");
        return Err(error);
    }
    Ok(())
}

#[tokio::test]
#[ignore = "moves two physical Wi-Fi PHYs and requires root, real hardware, and Internet"]
async fn physical_wifi_router_explicit_renew_revalidates_dhcp_lease() -> Result<()> {
    let _guard = PHYSICAL_WIFI_TEST_LOCK.lock().await;
    let mut fixture = PhysicalWifiFixture::new()?;
    let result = fixture.run_explicit_renew_test().await;
    if let Err(error) = result {
        fixture.dump_diagnostics("explicit DHCP renew failure");
        return Err(error);
    }
    Ok(())
}

#[tokio::test]
#[ignore = "moves two physical Wi-Fi PHYs and requires root, real hardware, Internet, and a phone"]
async fn physical_wifi_router_ap_restart_reassociates_phone_without_disrupting_uplink() -> Result<()>
{
    let _guard = PHYSICAL_WIFI_TEST_LOCK.lock().await;
    let mut fixture = PhysicalWifiFixture::new()?;
    let result = fixture.run_ap_restart_reassociation_test().await;
    if let Err(error) = result {
        fixture.dump_diagnostics("AP restart/reassociation failure");
        return Err(error);
    }
    Ok(())
}

#[tokio::test]
#[ignore = "moves two physical Wi-Fi PHYs and requires root, real hardware, and Internet"]
async fn physical_wifi_router_foreign_address_and_route_survive_owned_cleanup() -> Result<()> {
    let _guard = PHYSICAL_WIFI_TEST_LOCK.lock().await;
    let mut fixture = PhysicalWifiFixture::new()?;
    let result = fixture.run_foreign_state_survival_test().await;
    if let Err(error) = result {
        fixture.dump_diagnostics("foreign-state survival failure");
        return Err(error);
    }
    Ok(())
}

#[tokio::test]
#[ignore = "moves two physical Wi-Fi PHYs and requires root, real hardware, and Internet"]
async fn physical_wifi_router_preserve_restart_adopts_dhcp_lease() -> Result<()> {
    let _guard = PHYSICAL_WIFI_TEST_LOCK.lock().await;
    let mut fixture = PhysicalWifiFixture::new()?;
    let result = fixture.run_preserve_restart_test().await;
    if let Err(error) = result {
        fixture.dump_diagnostics("preserve/restart adoption failure");
        return Err(error);
    }
    Ok(())
}

#[tokio::test]
#[ignore = "operator must physically unplug/replug the USB uplink; requires root, real hardware, and Internet"]
async fn physical_wifi_router_usb_uplink_unplug_replug_recovers() -> Result<()> {
    let _guard = PHYSICAL_WIFI_TEST_LOCK.lock().await;
    verify_operator_usb_replug_guard(env::var("TRAFFIC_MASQ_OPERATOR_USB_REPLUG").ok().as_deref())?;
    let mut fixture = PhysicalWifiFixture::new()?;
    let result = fixture.run_usb_replug_test().await;
    if let Err(error) = result {
        fixture.dump_diagnostics("operator USB unplug/replug failure");
        return Err(error);
    }
    Ok(())
}

fn verify_lease_evidence(
    lease: &DhcpClientLease,
    address: Ipv4Addr,
    prefix: u8,
    gateway: Ipv4Addr,
) -> Result<()> {
    if lease.state != DhcpClientLeaseState::Bound
        || lease.address != address
        || lease.prefix_len != prefix
        || !lease.owned_routes.iter().any(|route| {
            route.destination.prefix_len() == 0
                && route.gateway == Some(gateway)
                && route.protocol == 202
        })
    {
        bail!("persisted bound lease does not prove the observed address and protocol-202 default route");
    }
    Ok(())
}

fn verify_lease_identity_and_routes(
    initial: &DhcpClientLease,
    current: &DhcpClientLease,
) -> Result<()> {
    if current.state != DhcpClientLeaseState::Bound
        || current.interface != initial.interface
        || current.interface_index != initial.interface_index
        || current.hardware_address != initial.hardware_address
        || current.client_identifier != initial.client_identifier
        || current.server_identifier != initial.server_identifier
        || current.address != initial.address
        || current.prefix_len != initial.prefix_len
        || current.owned_routes != initial.owned_routes
    {
        bail!("natural renewal changed bound state, exact identity, server, address, prefix, or owned routes");
    }
    Ok(())
}

fn lease_acquired_at(lease: &DhcpClientLease) -> Result<u64> {
    lease
        .expires_at_unix
        .checked_sub(u64::from(lease.lease_seconds))
        .context("persisted lease expiry predates its lease duration")
}

fn natural_t1_wait(lease: &DhcpClientLease, now_unix: u64, max_wait: Duration) -> Result<Duration> {
    let acquired_at = lease_acquired_at(lease)?;
    let t1_unix = acquired_at
        .checked_add(u64::from(lease.renewal_seconds))
        .context("persisted lease T1 timestamp overflowed")?;
    let seconds = t1_unix.checked_sub(now_unix).context(
        "persisted lease T1 is expired or due now; refusing a long-run test without a positive wait",
    )?;
    if seconds == 0 {
        bail!("persisted lease T1 is due now; refusing a zero-second long-run wait");
    }
    if seconds > max_wait.as_secs() {
        bail!(
            "actual {} second wait until persisted lease T1 exceeds safe cap {} seconds; adjust TRAFFIC_MASQ_LONG_T1_MAX_WAIT_SECONDS deliberately",
            seconds,
            max_wait.as_secs()
        );
    }
    Ok(Duration::from_secs(seconds))
}

fn unix_time_seconds() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs())
}

fn verify_long_t1_guard(value: Option<&str>) -> Result<()> {
    if value != Some("1") {
        bail!("natural-T1 long-run guard refused the test; set TRAFFIC_MASQ_LONG_T1=1 explicitly");
    }
    Ok(())
}

fn long_t1_max_wait(value: Option<&str>) -> Result<Duration> {
    let seconds = match value {
        None => LONG_T1_DEFAULT_MAX_WAIT.as_secs(),
        Some(value) => value.parse::<u64>().context(
            "TRAFFIC_MASQ_LONG_T1_MAX_WAIT_SECONDS must be an integer number of seconds",
        )?,
    };
    if seconds == 0 {
        bail!("TRAFFIC_MASQ_LONG_T1_MAX_WAIT_SECONDS must be greater than zero");
    }
    Ok(Duration::from_secs(seconds))
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
        ("wpa_supplicant", &["-v"][..]),
        ("nft", &["--version"][..]),
        ("ping", &["-V"][..]),
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

fn verify_management_disruption_guard(value: Option<&str>) -> Result<()> {
    if value != Some("1") {
        bail!(
            "management-disruption guard refused to move Wi-Fi PHYs; set TRAFFIC_MASQ_ALLOW_MANAGEMENT_DISRUPTION=1 only from a local console"
        );
    }
    Ok(())
}

#[test]
fn management_disruption_requires_exact_opt_in() {
    assert!(verify_management_disruption_guard(None).is_err());
    assert!(verify_management_disruption_guard(Some("0")).is_err());
    assert!(verify_management_disruption_guard(Some("true")).is_err());
    verify_management_disruption_guard(Some("1")).unwrap();
}

fn verify_operator_usb_replug_guard(value: Option<&str>) -> Result<()> {
    if value != Some("1") {
        bail!(
            "operator USB-replug guard refused the physical test; set TRAFFIC_MASQ_OPERATOR_USB_REPLUG=1 only when an operator is present to unplug/replug the selected adapter"
        );
    }
    Ok(())
}

#[test]
fn natural_t1_requires_exact_opt_in_and_valid_cap() {
    assert!(verify_long_t1_guard(None).is_err());
    assert!(verify_long_t1_guard(Some("true")).is_err());
    verify_long_t1_guard(Some("1")).unwrap();
    assert_eq!(long_t1_max_wait(None).unwrap(), LONG_T1_DEFAULT_MAX_WAIT);
    assert_eq!(
        long_t1_max_wait(Some("90")).unwrap(),
        Duration::from_secs(90)
    );
    assert!(long_t1_max_wait(Some("0")).is_err());
    assert!(long_t1_max_wait(Some("nope")).is_err());
}

#[test]
fn natural_t1_wait_uses_persisted_timestamps_and_refuses_unreasonable_waits() {
    let mut lease = test_bound_lease_for_t1();
    assert_eq!(
        natural_t1_wait(&lease, 8_100, Duration::from_secs(2_000)).unwrap(),
        Duration::from_secs(100)
    );
    assert!(natural_t1_wait(&lease, 8_200, Duration::from_secs(2_000)).is_err());
    assert!(natural_t1_wait(&lease, 8_201, Duration::from_secs(2_000)).is_err());
    assert!(natural_t1_wait(&lease, 8_100, Duration::from_secs(99)).is_err());
    lease.expires_at_unix = 3_000;
    assert!(natural_t1_wait(&lease, 1, Duration::from_secs(10_000)).is_err());
}

fn test_bound_lease_for_t1() -> DhcpClientLease {
    DhcpClientLease {
        schema_version: 1,
        state: DhcpClientLeaseState::Bound,
        interface: "wlan0".into(),
        interface_index: 2,
        hardware_address: vec![0, 1, 2, 3, 4, 5],
        client_identifier: vec![1, 0, 1, 2, 3, 4, 5],
        policy: None,
        server_identifier: Ipv4Addr::new(192, 0, 2, 1),
        address: Ipv4Addr::new(192, 0, 2, 2),
        prefix_len: 24,
        routers: vec![Ipv4Addr::new(192, 0, 2, 1)],
        dns_servers: vec![],
        lease_seconds: 3_600,
        renewal_seconds: 1_800,
        rebinding_seconds: 3_150,
        expires_at_unix: 10_000,
        owned_routes: vec![],
    }
}

#[test]
fn operator_usb_replug_requires_exact_opt_in() {
    assert!(verify_operator_usb_replug_guard(None).is_err());
    assert!(verify_operator_usb_replug_guard(Some("0")).is_err());
    assert!(verify_operator_usb_replug_guard(Some("true")).is_err());
    verify_operator_usb_replug_guard(Some("1")).unwrap();
}

fn read_secret_for_redaction(path: &Path) -> Result<String> {
    let secret = fs::read_to_string(path).context("failed to read PSK file")?;
    let secret = secret.trim().to_owned();
    if secret.is_empty() {
        bail!("PSK file must not be empty");
    }
    Ok(secret)
}

fn validate_managed_capability(phy: &str) -> Result<()> {
    let output = Command::new("iw").args(["phy", phy, "info"]).output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() || !text.lines().any(|line| line.trim() == "* managed") {
        bail!("uplink PHY does not advertise managed/station mode support");
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

fn validate_only_interface(phy: &str, interface: &str) -> Result<()> {
    let interfaces = interfaces_on_phy(None, phy)?;
    if interfaces != [interface.to_string()] {
        bail!("refusing to move {phy}: it owns interfaces {interfaces:?}, not only {interface}");
    }
    Ok(())
}

fn sole_interface_in_namespace(namespace: &str, phy: &str) -> Result<String> {
    let interfaces = interfaces_on_phy(Some(namespace), phy)?;
    if interfaces.len() != 1 {
        bail!("expected exactly one interface on {phy} after moving it, found {interfaces:?}");
    }
    Ok(interfaces[0].clone())
}

fn set_wifi_type(namespace: &str, interface: &str, kind: &str) -> Result<()> {
    run_ns(namespace, "ip", &["link", "set", interface, "down"])?;
    run_ns(namespace, "iw", &["dev", interface, "set", "type", kind])
}

fn verify_dhcp_address(
    namespace: &str,
    interface: &str,
    address: Ipv4Addr,
    prefix: u8,
) -> Result<()> {
    let output = output_ns(
        namespace,
        "ip",
        &["-4", "-o", "address", "show", "dev", interface],
    )?;
    let expected = format!("inet {address}/{prefix}");
    if !output.status.success() || !String::from_utf8_lossy(&output.stdout).contains(&expected) {
        bail!("DHCP bound address is not installed on the managed uplink");
    }
    Ok(())
}

fn exact_address_line(namespace: &str, interface: &str, cidr: &str) -> Result<String> {
    let output = output_ns(
        namespace,
        "ip",
        &["-4", "-o", "address", "show", "dev", interface, "to", cidr],
    )?;
    let text = String::from_utf8(output.stdout).context("foreign address output was not UTF-8")?;
    if !output.status.success() || text.lines().count() != 1 || !text.contains(cidr) {
        bail!("exact foreign address was not observed uniquely");
    }
    Ok(text)
}

fn exact_route_line(namespace: &str, interface: &str, destination: &str) -> Result<String> {
    let output = output_ns(namespace, "ip", &["-4", "-o", "route", "show", destination])?;
    let text = String::from_utf8(output.stdout).context("foreign route output was not UTF-8")?;

    let rendered_destination = destination.strip_suffix("/32").unwrap_or(destination);
    if !output.status.success()
        || text.lines().count() != 1
        || !text.contains(rendered_destination)
        || !text.contains(&format!("dev {interface}"))
        || !text.contains("metric 4242")
    {
        bail!("exact foreign route was not observed uniquely");
    }
    Ok(text)
}

fn dhcp_owned_state_present(
    namespace: &str,
    interface: &str,
    address: Ipv4Addr,
    prefix: u8,
) -> Result<bool> {
    let addresses = output_ns(
        namespace,
        "ip",
        &[
            "-4",
            "-o",
            "address",
            "show",
            "dev",
            interface,
            "to",
            &format!("{address}/{prefix}"),
        ],
    )?;
    let routes = output_ns(
        namespace,
        "ip",
        &[
            "-4", "-o", "route", "show", "protocol", "202", "dev", interface,
        ],
    )?;
    if !addresses.status.success() || !routes.status.success() {
        bail!("failed to inspect exact DHCP-owned kernel state after cleanup");
    }
    Ok(!addresses.stdout.is_empty() || !routes.stdout.is_empty())
}

fn verify_protocol_202_default_route(namespace: &str, interface: &str) -> Result<Ipv4Addr> {
    let output = output_ns(
        namespace,
        "ip",
        &[
            "-4", "route", "show", "default", "protocol", "202", "dev", interface,
        ],
    )?;
    let text = String::from_utf8_lossy(&output.stdout);
    let words: Vec<_> = text.split_whitespace().collect();
    let gateway = words
        .windows(2)
        .find_map(|pair| (pair[0] == "via").then_some(pair[1]))
        .context("DHCP client did not install a protocol-202 default route with a gateway")?;
    if !output.status.success() || words.first() != Some(&"default") {
        bail!("DHCP client protocol-202 default route query failed");
    }
    gateway
        .parse()
        .context("DHCP client protocol-202 default route has an invalid gateway")
}

fn interface_exists(namespace: Option<&str>, interface: &str) -> Result<bool> {
    let output = match namespace {
        Some(namespace) => output_ns(namespace, "ip", &["link", "show", "dev", interface])?,
        None => Command::new("ip")
            .args(["link", "show", "dev", interface])
            .output()
            .context("failed to inspect host interface")?,
    };
    Ok(output.status.success())
}

fn phy_exists(namespace: Option<&str>, phy: &str) -> Result<bool> {
    let output = match namespace {
        Some(namespace) => output_ns(namespace, "iw", &["phy", phy, "info"])?,
        None => Command::new("iw")
            .args(["phy", phy, "info"])
            .output()
            .context("failed to inspect host PHY")?,
    };
    Ok(output.status.success())
}

async fn verify_output_side_operational(
    fixture: &mut PhysicalWifiFixture,
    client: &ApiClient,
    expected_hostapd_pid: u32,
) -> Result<()> {
    ensure_child_running(fixture.daemon.as_mut(), "traffic-masqd")?;
    if !pid_alive(expected_hostapd_pid) {
        bail!("tracked AP process exited during USB disruption");
    }
    match client.request(&Request::WifiStatus).await? {
        Response::WifiStatus { interfaces }
            if interfaces.iter().any(|status| {
                status.interface == fixture.output_interface
                    && status.hostapd_state == HostapdState::Enabled.into()
                    && status.pid == expected_hostapd_pid
            }) => {}
        _ => bail!("AP/output Wi-Fi service was not enabled with its original PID"),
    }
    let output_address = output_ns(
        &fixture.namespace,
        "ip",
        &["-4", "address", "show", "dev", &fixture.output_interface],
    )?;
    if !output_address.status.success()
        || !String::from_utf8_lossy(&output_address.stdout).contains("10.77.0.1/24")
    {
        bail!("output interface lost its configured downstream address");
    }
    if !matches!(
        client
            .request(&Request::ListLeases {
                interface: fixture.output_interface.clone(),
            })
            .await,
        Ok(Response::Leases { .. })
    ) {
        bail!("downstream DHCP lease service did not answer during USB disruption");
    }
    Ok(())
}

fn verify_real_daemon_pid(pid: u32) -> Result<()> {
    let exe = fs::canonicalize(Path::new("/proc").join(pid.to_string()).join("exe"))
        .context("daemon PID does not identify a live executable")?;
    let expected = fs::canonicalize(env!("CARGO_BIN_EXE_traffic-masqd"))?;
    if exe != expected {
        bail!("PID file does not identify the spawned traffic-masqd binary");
    }
    Ok(())
}

fn verify_ping(namespace: &str, interface: &str, destination: &str, label: &str) -> Result<()> {
    let output = output_ns(
        namespace,
        "ping",
        &["-I", interface, "-c", "3", "-W", "3", destination],
    )?;
    if !output.status.success() {
        bail!("could not ping {label}: {}", output_text(&output));
    }
    Ok(())
}

fn inspect_owned_nftables(namespace: &str, uplink: &str, output_interface: &str) -> Result<()> {
    let nft = command_path("nft")?;
    let result = output_ns(
        namespace,
        path_str(&nft)?,
        &["list", "table", "inet", "traffic_masq"],
    )?;
    let text = String::from_utf8_lossy(&result.stdout);
    if !result.status.success()
        || !text.contains("chain postrouting")
        || !text.contains("masquerade")
        || !text.contains(uplink)
        || !text.contains(output_interface)
    {
        bail!(
            "owned nftables table is missing router/NAT state: {}",
            output_text(&result)
        );
    }
    Ok(())
}

fn print_recovery(namespace: &str, phy: &str, interface: &str, detail: &str) {
    eprintln!("\n!!! PHYSICAL WI-FI RECOVERY REQUIRED FOR {phy} !!!\n{detail}\nRun immediately (repeat independently for every PHY reported):\n  sudo ip netns exec {namespace} iw phy {phy} set netns 1\n  sudo ip link set {interface} up\nOnly after BOTH PHYs are back:\n  sudo ip netns del {namespace}\n!!! DO NOT DELETE THE NAMESPACE FIRST !!!\n");
}
