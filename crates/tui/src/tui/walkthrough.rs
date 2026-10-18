//! Continuous, event-driven documentation recording using the real TUI handlers.
//! Only the daemon is simulated; input, forms, navigation and timers are live.
use super::api::model::{Request, Response};
use super::*;
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use ratatui::{backend::TestBackend, buffer::Buffer};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use traffic_masq_protocol::*;

const WIDTH: u16 = 120;
const HEIGHT: u16 = 30;
const TICK_MS: u64 = 50;

struct DemoNetwork {
    configs: BTreeMap<String, InterfaceConfigView>,
    suppressed: BTreeSet<String>,
    pending: Option<(PendingNetworkChange, BTreeMap<String, InterfaceConfigView>)>,
    revision: u64,
    samples: u64,
    calls: Vec<String>,
}
impl DemoNetwork {
    fn new() -> Self {
        let config = |value| serde_json::from_value(value).unwrap();
        Self {
            configs: BTreeMap::from([
                (
                    "lan0".into(),
                    config(
                        serde_json::json!({"role":"output", "managed":true, "ipv4":"192.168.50.1/24"}),
                    ),
                ),
                (
                    "usb-lan0".into(),
                    config(
                        serde_json::json!({"role":"output", "managed":true, "ipv4":"192.168.70.1/24"}),
                    ),
                ),
                (
                    "wlan0".into(),
                    config(
                        serde_json::json!({"role":"input", "managed":true, "wifi_client":{"ssid":"Home Wi-Fi", "security":"wpa2"}, "dhcp_client":{"enabled":true}}),
                    ),
                ),
                (
                    "wlan1".into(),
                    config(
                        serde_json::json!({"role":"output", "managed":true, "ipv4":"172.20.0.1/24", "wifi":{"ssid":"traffic-masq", "country_code":"UA", "security":"wpa2", "passphrase_file":"/demo/ap.secret"}}),
                    ),
                ),
            ]),
            suppressed: BTreeSet::new(),
            pending: None,
            revision: 1,
            samples: 0,
            calls: vec![],
        }
    }
    fn inventory(&self) -> Vec<InterfaceInventoryEntry> {
        ["lan0", "usb-lan0", "wlan0", "wlan1"]
            .into_iter()
            .enumerate()
            .map(|(index, name)| {
                let config = self.configs.get(name).cloned();
                let missing = name == "usb-lan0";
                let observed = (!missing).then(|| {
                    let cidr = config
                        .as_ref()
                        .and_then(|c| c.ipv4)
                        .or_else(|| (name == "wlan0").then(|| "192.0.2.20/24".parse().unwrap()));
                    InterfaceStatusView {
                        interface: NetworkInterfaceView {
                            index: index as u32 + 1,
                            name: name.into(),
                            is_up: true,
                            rx_bytes: 1_000_000 + self.samples * 90000,
                            tx_bytes: 300_000 + self.samples * 12000,
                            is_wireless: name.starts_with("wlan"),
                        },
                        ipv4_addresses: cidr
                            .map(|cidr| Ipv4AddressInfoView {
                                interface_index: index as u32 + 1,
                                address: cidr.addr(),
                                prefix_len: cidr.prefix_len(),
                                protocol: Some(
                                    if name == "wlan0"
                                        && config.as_ref().is_some_and(|c| c.ipv4.is_none())
                                    {
                                        202
                                    } else {
                                        201
                                    },
                                ),
                            })
                            .into_iter()
                            .collect(),
                        owned_ipv4_addresses: None,
                        has_default_route: name == "wlan0",
                    }
                });
                InterfaceInventoryEntry {
                    name: name.into(),
                    configured: config,
                    observed,
                    config_source: if self.suppressed.contains(name) {
                        InterfaceConfigSource::None
                    } else {
                        InterfaceConfigSource::Base
                    },
                    presence: if missing {
                        InterfacePresence::Missing
                    } else {
                        InterfacePresence::Present
                    },
                    observation_stale: false,
                    suppressed: self.suppressed.contains(name),
                    readiness: if missing {
                        InterfaceReadiness::WaitingDevice
                    } else {
                        InterfaceReadiness::Ready
                    },
                    blockers: vec![],
                    references: if missing {
                        vec!["saved route: table 100".into()]
                    } else {
                        vec![]
                    },
                }
            })
            .collect()
    }
    fn begin(
        &mut self,
        interface: String,
        before: BTreeMap<String, InterfaceConfigView>,
    ) -> Response {
        let change = PendingNetworkChange {
            token: format!("demo-{}", self.revision),
            interface,
            rollback_timeout_seconds: 30,
            expires_at_unix: current_unix_time() + 30,
            phase: Default::default(),
            last_error: None,
            recovery_progress: None,
        };
        self.pending = Some((change.clone(), before));
        Response::NetworkChangePending { change }
    }
    fn respond(&mut self, request: Request) -> Response {
        let kind = serde_json::to_value(&request).unwrap()["type"]
            .as_str()
            .unwrap()
            .to_owned();
        self.calls.push(kind);
        match request {
            Request::ListInterfaceInventory => {
                self.samples += 1;
                Response::InterfaceInventory {
                    revision: self.revision,
                    interfaces: self.inventory(),
                    suppressed_interfaces: self.suppressed.iter().cloned().collect(),
                    observation_error: None,
                    base_config: Some(InterfaceBaseConfigView {
                        file: Some("/etc/traffic-masq/config.toml".into()),
                        interfaces: vec![
                            "lan0".into(),
                            "usb-lan0".into(),
                            "wlan0".into(),
                            "wlan1".into(),
                        ],
                    }),
                }
            }
            Request::GetInterfaceConfig { interface } => Response::InterfaceConfig {
                config: self.configs.get(&interface).cloned(),
                interface,
                allow_management_change: true,
            },
            Request::PendingNetworkChanges => Response::PendingNetworkChanges {
                changes: self
                    .pending
                    .as_ref()
                    .map(|(change, _)| change.clone())
                    .into_iter()
                    .collect(),
            },
            Request::ListRoutes { .. } => Response::Routes { routes: vec![] },
            Request::GetSecurityConfig => Response::SecurityConfig {
                active: SecuritySettings {
                    rollback_timeout_seconds: 30,
                },
                desired: SecuritySettings {
                    rollback_timeout_seconds: 30,
                },
                override_active: false,
                restart_required: false,
            },
            Request::GetVpnConfig => Response::VpnConfig { enabled: false },
            Request::DryRunInterfaceEdit { interface, edit } => {
                let observed = self
                    .inventory()
                    .into_iter()
                    .find(|entry| entry.name == interface)
                    .and_then(|entry| entry.observed)
                    .unwrap();
                let cidr: ipnet::Ipv4Net = edit.cidr.parse().unwrap();
                Response::InterfacePlan {
                    plan: InterfaceChangePlanView {
                        interface,
                        mac_address: edit.mac_address,
                        delete_ipv4: observed.ipv4_addresses,
                        retag_ipv4: None,
                        add_ipv4: Some(Ipv4AddressInfoView {
                            interface_index: observed.interface.index,
                            address: cidr.addr(),
                            prefix_len: cidr.prefix_len(),
                            protocol: Some(201),
                        }),
                        set_link_up: true,
                        management_change: false,
                        dhcp_action: DhcpChangeActionView::Unchanged,
                        releasing_management: false,
                    },
                }
            }
            Request::ApplyInterfaceEdit { interface, edit } => {
                let before = self.configs.clone();
                let config = self.configs.get_mut(&interface).unwrap();
                config.ipv4 = edit.cidr.parse().ok();
                config.mac_address = edit.mac_address;
                config.role = edit.role;
                config.managed = edit.managed;
                self.begin(interface, before)
            }
            Request::CommitNetworkChange { token } => {
                let (change, _) = self.pending.take().unwrap();
                assert_eq!(change.token, token);
                self.revision += 1;
                Response::NetworkChangeCommitted { change }
            }
            Request::RollbackNetworkChange { token } => {
                let (change, before) = self.pending.take().unwrap();
                assert_eq!(change.token, token);
                self.configs = before;
                self.revision += 1;
                Response::NetworkChangeRolledBack { change }
            }
            Request::ForgetInterfaceConfig {
                interface,
                expected_revision,
            } => {
                assert_eq!(expected_revision, self.revision);
                self.configs.remove(&interface);
                self.suppressed.insert(interface.clone());
                self.revision += 1;
                Response::InterfaceIntentSaved {
                    interface: interface.clone(),
                    revision: self.revision,
                    deferred: true,
                    missing_dependencies: vec![interface],
                }
            }
            Request::ListWifiInventory => {
                let interfaces = self
                    .inventory()
                    .into_iter()
                    .filter(|entry| entry.name.starts_with("wlan"))
                    .map(|entry| {
                        let config = entry.configured.as_ref().unwrap();
                        let ap_runtime =
                            WifiApSpecView::from_validated_interface_config(&entry.name, config)
                                .map(|spec| WifiApStatusView {
                                    interface: entry.name.clone(),
                                    spec,
                                    pid: 4242,
                                    hostapd_state: HostapdStateView::Enabled,
                                    num_stations: Some(2),
                                    health: WifiHealthView::Healthy,
                                });
                        let client_runtime =
                            config
                                .wifi_client
                                .as_ref()
                                .map(|wifi| WifiClientStatusView {
                                    interface: entry.name.clone(),
                                    spec: WifiClientSpecView {
                                        interface: entry.name.clone(),
                                        ssid: wifi.ssid.clone(),
                                        country_code: wifi.country_code.clone(),
                                        security: wifi.security,
                                        passphrase_file: None,
                                    },
                                    pid: 4243,
                                    wpa_state: WpaStateView::Completed,
                                    bssid: Some("02:11:22:33:44:55".parse().unwrap()),
                                    freq: Some(2412),
                                    health: WifiHealthView::Healthy,
                                });
                        WifiInventoryEntry {
                            interface: entry,
                            ap_runtime,
                            client_runtime,
                        }
                    })
                    .collect();
                Response::WifiInventory {
                    revision: self.revision,
                    ap_execution_available: true,
                    client_execution_available: true,
                    interfaces,
                    observation_error: None,
                }
            }
            Request::WifiClientScan { interface } => Response::WifiClientScanResults {
                interface,
                results: [
                    ("Home Wi-Fi", -43, WpaSupplicantScanSecurity::Wpa2Psk),
                    ("Guest", -61, WpaSupplicantScanSecurity::Open),
                    ("Office", -76, WpaSupplicantScanSecurity::Wpa3Sae),
                ]
                .into_iter()
                .enumerate()
                .map(
                    |(index, (ssid, signal, security))| WpaSupplicantScanResult {
                        bssid: MacAddr::new([2, 0, 0, 0, 0, index as u8 + 1]),
                        frequency_mhz: 2412,
                        signal_dbm: signal,
                        ssid: ssid.into(),
                        ssid_bytes: ssid.as_bytes().to_vec(),
                        raw_flags: "[WPA2-PSK-CCMP][ESS]".into(),
                        security,
                    },
                )
                .collect(),
            },
            Request::ListWifiClientProfiles => Response::WifiClientProfiles {
                profiles: vec![WifiClientProfileSummary {
                    id: "home".into(),
                    ssid: "Home Wi-Fi".into(),
                    country_code: Some("UA".into()),
                    security: WifiClientSecurity::Wpa2,
                    priority: 10,
                    autoconnect: true,
                    has_passphrase: true,
                    created_at: 0,
                    modified_at: 0,
                }],
            },
            Request::ProvisionWifiClient {
                interface,
                settings,
            } => {
                let before = self.configs.clone();
                let config = self.configs.get_mut(&interface).unwrap();
                match settings.ip_policy {
                    WifiClientIpPolicy::Dhcp => config.ipv4 = None,
                    WifiClientIpPolicy::Static { cidr } => config.ipv4 = Some(cidr),
                    WifiClientIpPolicy::Preserve => {}
                }
                self.begin(interface, before)
            }
            Request::ListWifiStations { interface } => Response::WifiStations {
                interface,
                stations: ["02:aa:bb:cc:dd:01", "02:aa:bb:cc:dd:02"]
                    .into_iter()
                    .map(|mac| Station {
                        mac: mac.parse().unwrap(),
                        raw: BTreeMap::new(),
                    })
                    .collect(),
            },
            Request::ListLeases { interface } => Response::Leases {
                interface,
                leases: (1..=2)
                    .map(|index| DhcpLeaseView {
                        mac: [2, 170, 187, 204, 221, index],
                        ip: std::net::Ipv4Addr::new(172, 20, 0, index + 10),
                        expires_at_unix: current_unix_time() + 3600,
                    })
                    .collect(),
            },
            _ => Response::Error {
                message: format!("Unsupported recording request: {:?}", self.calls.last()),
            },
        }
    }
}

struct DemoApi {
    client: ApiClient,
    state: Arc<Mutex<DemoNetwork>>,
    task: tokio::task::JoinHandle<()>,
    _directory: tempfile::TempDir,
}
impl Drop for DemoApi {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl DemoApi {
    async fn start() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("demo.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let state = Arc::new(Mutex::new(DemoNetwork::new()));
        let server_state = state.clone();
        let task = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let state = server_state.clone();
                tokio::spawn(async move {
                    http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(stream),
                            service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                                let state = state.clone();
                                async move {
                                    let body =
                                        request.into_body().collect().await.unwrap().to_bytes();
                                    let request: Request = serde_json::from_slice(&body).unwrap();
                                    let response = state.lock().unwrap().respond(request);
                                    Ok::<_, std::convert::Infallible>(hyper::Response::new(
                                        Full::new(Bytes::from(
                                            serde_json::to_vec(&response).unwrap(),
                                        )),
                                    ))
                                }
                            }),
                        )
                        .await
                        .unwrap();
                });
            }
        });
        Self {
            client: ApiClient::new(socket),
            state,
            task,
            _directory: directory,
        }
    }
}

#[derive(Serialize)]
struct RecordedFrame {
    file: String,
    duration_ms: u64,
}
#[derive(Serialize)]
struct Chapter {
    at_ms: u64,
    title: String,
}
struct Recorder {
    directory: PathBuf,
    real_time: bool,
    terminal: Terminal<TestBackend>,
    frames: Vec<RecordedFrame>,
    chapters: Vec<Chapter>,
    elapsed_ms: u64,
    started_at: Instant,
    last_sample_ms: u64,
    poll_at_ms: u64,
    last: Option<(Buffer, String, String)>,
    title: String,
    input: String,
}
impl Recorder {
    fn new(directory: PathBuf) -> Self {
        std::fs::create_dir_all(&directory).unwrap();
        Self {
            directory,
            real_time: std::env::var_os("TRAFFIC_MASQ_DEMO_VALIDATE").is_none(),
            terminal: Terminal::new(TestBackend::new(WIDTH, HEIGHT)).unwrap(),
            frames: vec![],
            chapters: vec![],
            elapsed_ms: 0,
            started_at: Instant::now(),
            last_sample_ms: 0,
            poll_at_ms: 0,
            last: None,
            title: String::new(),
            input: "Keyboard only · live TUI · demonstration data".into(),
        }
    }
    fn chapter(&mut self, title: &str) {
        self.title = title.into();
        self.chapters.push(Chapter {
            at_ms: self.elapsed_ms,
            title: title.into(),
        });
    }
    fn capture(&mut self, app: &mut TuiApp) {
        self.terminal
            .draw(|frame| render(frame, app, false))
            .unwrap();
        let buffer = self.terminal.backend().buffer();
        let state = (buffer.clone(), self.title.clone(), self.input.clone());
        let at_ms = if self.frames.is_empty() {
            self.started_at = Instant::now();
            0
        } else if self.real_time {
            (self.started_at.elapsed().as_millis() as u64 / 10) * 10
        } else {
            self.elapsed_ms
        };
        if let Some(previous) = self.frames.last_mut() {
            previous.duration_ms += at_ms.saturating_sub(self.last_sample_ms);
        }
        if self.last.as_ref() != Some(&state) {
            let file = format!("{:05}.json", self.frames.len());
            let cells: Vec<_> = buffer
                .content()
                .iter()
                .map(|cell| {
                    serde_json::json!([
                        cell.symbol(),
                        format!("{:?}", cell.fg),
                        format!("{:?}", cell.bg)
                    ])
                })
                .collect();
            let document = serde_json::json!({"title":self.title, "input":self.input, "width":WIDTH, "height":HEIGHT, "cells":cells});
            std::fs::write(
                self.directory.join(&file),
                serde_json::to_vec(&document).unwrap(),
            )
            .unwrap();
            self.frames.push(RecordedFrame {
                file,
                duration_ms: 0,
            });
            self.last = Some(state);
        }
        self.last_sample_ms = at_ms;
        self.elapsed_ms = at_ms + if self.real_time { 0 } else { TICK_MS };
    }
    async fn hold(&mut self, app: &mut TuiApp, api: &DemoApi, ms: u64) {
        for _ in 0..ms.div_ceil(TICK_MS) {
            if self.elapsed_ms >= self.poll_at_ms {
                dashboard::accept_update(app, Box::pin(load_daemon_dashboard(&api.client)).await);
                refresh_pending_screen(app);
                normalize_selection(app);
                self.poll_at_ms = self.elapsed_ms + 2000;
            }
            self.capture(app);
            if self.real_time {
                tokio::time::sleep(Duration::from_millis(TICK_MS)).await;
            }
        }
    }
    async fn key(&mut self, app: &mut TuiApp, api: &DemoApi, key: KeyCode) {
        self.input = if key == KeyCode::BackTab {
            "Keyboard: Shift+Tab".into()
        } else {
            format!("Keyboard: {key:?}")
        };
        self.hold(app, api, 150).await;
        Box::pin(handle_key_event(
            app,
            KeyEvent::new(key, KeyModifiers::NONE),
            &api.client,
            false,
        ))
        .await;
        self.hold(app, api, 300).await;
    }
    async fn type_text(&mut self, app: &mut TuiApp, api: &DemoApi, text: &str, label: &str) {
        self.input = format!("Typing: {label}");
        for character in text.chars() {
            Box::pin(handle_key(
                app,
                KeyCode::Char(character),
                &api.client,
                false,
            ))
            .await;
            self.hold(app, api, 150).await;
        }
        self.hold(app, api, 500).await;
    }
    async fn tabs(&mut self, app: &mut TuiApp, api: &DemoApi, count: usize) {
        for _ in 0..count {
            self.key(app, api, KeyCode::Tab).await;
        }
    }
    async fn section(&mut self, app: &mut TuiApp, api: &DemoApi, target: Section) {
        // The shortest keyboard route avoids unrelated router/VPN workflows.
        let sections = active_sections(app.show_dhcp_client);
        let current = sections
            .iter()
            .position(|s| *s == section_of_app(app))
            .unwrap();
        let destination = sections.iter().position(|s| *s == target).unwrap();
        let forward = (destination + sections.len() - current) % sections.len();
        let backward = (current + sections.len() - destination) % sections.len();
        let next = forward < backward;
        for _ in 0..forward.min(backward) {
            self.input = if next {
                "Keyboard: Ctrl+N"
            } else {
                "Keyboard: Ctrl+P"
            }
            .into();
            self.hold(app, api, 150).await;
            Box::pin(handle_key_event(
                app,
                KeyEvent::new(
                    KeyCode::Char(if next { 'n' } else { 'p' }),
                    KeyModifiers::CONTROL,
                ),
                &api.client,
                false,
            ))
            .await;
            self.hold(app, api, 300).await;
        }
        assert_eq!(section_of_app(app), target);
    }
    fn finish(mut self) {
        if self.real_time {
            self.elapsed_ms = (self.started_at.elapsed().as_millis() as u64 / 10) * 10;
        }
        self.frames.last_mut().unwrap().duration_ms +=
            self.elapsed_ms.saturating_sub(self.last_sample_ms);
        let manifest = serde_json::json!({"real_time":self.real_time, "input_mode":"keyboard", "tick_ms":TICK_MS, "duration_ms":self.elapsed_ms, "frames":self.frames, "chapters":self.chapters});
        std::fs::write(
            self.directory.join("timeline.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        println!(
            "Recorded {} changing frames over {:.1}s",
            self.frames.len(),
            self.elapsed_ms as f64 / 1000.0
        );
    }
}

#[test]
#[ignore = "records a real-time TUI session; use packaging/render-tui-demo.py"]
fn export_walkthrough() {
    std::thread::Builder::new()
        .name("tui-recording".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(Box::pin(record_walkthrough()))
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn record_walkthrough() {
    let directory =
        PathBuf::from(std::env::var_os("TRAFFIC_MASQ_DEMO_DIR").expect("TRAFFIC_MASQ_DEMO_DIR"));
    let api = DemoApi::start().await;
    let mut app = TuiApp {
        connected_endpoint: Some("Demonstration data · 120×30".into()),
        ..Default::default()
    };
    let mut recorder = Recorder::new(directory);
    recorder.chapter("Live traffic and interface inventory");
    recorder.hold(&mut app, &api, 1800).await;
    recorder.section(&mut app, &api, Section::Interfaces).await;
    recorder.hold(&mut app, &api, 1000).await;
    recorder.key(&mut app, &api, KeyCode::Home).await;
    recorder.key(&mut app, &api, KeyCode::Enter).await;
    assert_eq!(app.screen, Screen::InterfaceEditor);

    recorder.chapter("Edit LAN: type IPv4 and open advanced MAC settings");
    recorder.key(&mut app, &api, KeyCode::Home).await;
    recorder.input = "Keyboard: Delete".into();
    for _ in 0..15 {
        handle_key(&mut app, KeyCode::Delete, &api.client, false).await;
        recorder.hold(&mut app, &api, 50).await;
    }
    recorder
        .type_text(&mut app, &api, "192.168.60.1/24", "IPv4 / CIDR")
        .await;
    for _ in 0..4 {
        recorder.key(&mut app, &api, KeyCode::Tab).await;
    }
    recorder.key(&mut app, &api, KeyCode::Enter).await;
    recorder.key(&mut app, &api, KeyCode::Tab).await;
    assert_eq!(
        app.editor.as_ref().unwrap().field,
        interfaces::InterfaceEditorField::MacAddress
    );
    recorder
        .type_text(&mut app, &api, "02:11:22:33:44:55", "manual MAC address")
        .await;
    recorder.tabs(&mut app, &api, 2).await;
    recorder.key(&mut app, &api, KeyCode::Enter).await;
    assert_eq!(app.screen, Screen::Preview);
    recorder.chapter("Review the actual plan, then apply temporarily");
    recorder.hold(&mut app, &api, 2000).await;
    recorder.key(&mut app, &api, KeyCode::PageDown).await;
    recorder.key(&mut app, &api, KeyCode::End).await;
    recorder.hold(&mut app, &api, 1200).await;
    recorder.key(&mut app, &api, KeyCode::Enter).await;
    assert_eq!(app.screen, Screen::PendingChange);
    recorder.chapter("Network changed: verify connectivity and confirm before rollback");
    recorder.hold(&mut app, &api, 3500).await;
    recorder.key(&mut app, &api, KeyCode::Enter).await;
    assert_eq!(app.screen, Screen::InterfaceList);
    recorder.hold(&mut app, &api, 2100).await;

    recorder.chapter("Absent adapter: compare restore and delete confirmations");
    recorder.key(&mut app, &api, KeyCode::Down).await;
    recorder.key(&mut app, &api, KeyCode::Enter).await;
    assert_eq!(app.editor.as_ref().unwrap().interface, "usb-lan0");
    recorder.tabs(&mut app, &api, 7).await;
    assert_eq!(
        app.editor.as_ref().unwrap().field,
        interfaces::InterfaceEditorField::Reset
    );
    recorder.key(&mut app, &api, KeyCode::Enter).await;
    recorder.hold(&mut app, &api, 1500).await;
    recorder.key(&mut app, &api, KeyCode::Esc).await;
    recorder.key(&mut app, &api, KeyCode::BackTab).await;
    assert_eq!(
        app.editor.as_ref().unwrap().field,
        interfaces::InterfaceEditorField::Forget
    );
    recorder.key(&mut app, &api, KeyCode::Enter).await;
    recorder.hold(&mut app, &api, 2000).await;
    recorder.key(&mut app, &api, KeyCode::Enter).await;
    recorder.hold(&mut app, &api, 2100).await;
    assert!(api.state.lock().unwrap().suppressed.contains("usb-lan0"));

    recorder.chapter("Wi-Fi: scan nearby networks and select a saved profile");
    recorder.section(&mut app, &api, Section::Wifi).await;
    recorder.key(&mut app, &api, KeyCode::Home).await;
    recorder.key(&mut app, &api, KeyCode::Enter).await;
    recorder.key(&mut app, &api, KeyCode::Enter).await;
    assert_eq!(app.screen, Screen::WifiScan);
    recorder.hold(&mut app, &api, 1300).await;
    recorder.key(&mut app, &api, KeyCode::Down).await;
    recorder.key(&mut app, &api, KeyCode::Up).await;
    recorder.key(&mut app, &api, KeyCode::Enter).await;
    assert_eq!(app.screen, Screen::WifiConnectPrompt);
    recorder.chapter("Choose static IPv4 for the connection, then review");
    recorder.key(&mut app, &api, KeyCode::Down).await;
    recorder.key(&mut app, &api, KeyCode::Enter).await;
    recorder
        .type_text(&mut app, &api, "192.0.2.99/24", "connection IPv4 / CIDR")
        .await;
    recorder.key(&mut app, &api, KeyCode::Enter).await;
    recorder.key(&mut app, &api, KeyCode::Enter).await;
    recorder.hold(&mut app, &api, 2000).await;
    recorder.key(&mut app, &api, KeyCode::Enter).await;
    assert_eq!(app.screen, Screen::PendingChange);
    recorder.chapter("Roll back a temporary Wi-Fi change");
    recorder.hold(&mut app, &api, 2500).await;
    recorder.key(&mut app, &api, KeyCode::Tab).await;
    recorder.key(&mut app, &api, KeyCode::Enter).await;
    assert_eq!(app.screen, Screen::Wifi);
    recorder.hold(&mut app, &api, 1200).await;
    assert!(api.state.lock().unwrap().configs["wlan0"].ipv4.is_none());

    recorder.chapter("Access point: edit SSID, review, then keep the draft");
    recorder.key(&mut app, &api, KeyCode::Esc).await;
    recorder.key(&mut app, &api, KeyCode::Down).await;
    recorder.key(&mut app, &api, KeyCode::Enter).await;
    recorder.key(&mut app, &api, KeyCode::Enter).await;
    assert_eq!(app.screen, Screen::WifiEditor);
    recorder.key(&mut app, &api, KeyCode::Home).await;
    recorder.input = "Keyboard: Delete".into();
    for _ in 0..12 {
        handle_key(&mut app, KeyCode::Delete, &api.client, false).await;
        recorder.hold(&mut app, &api, 50).await;
    }
    recorder
        .type_text(&mut app, &api, "Guest LAN", "access point SSID")
        .await;
    for _ in 0..13 {
        recorder.key(&mut app, &api, KeyCode::Tab).await;
    }
    recorder.key(&mut app, &api, KeyCode::Enter).await;
    recorder.hold(&mut app, &api, 1800).await;
    recorder.key(&mut app, &api, KeyCode::Esc).await;
    recorder.key(&mut app, &api, KeyCode::Esc).await;
    recorder.hold(&mut app, &api, 1000).await;
    recorder.key(&mut app, &api, KeyCode::Enter).await;
    assert!(app.ap_drafts.contains_key("wlan1"));

    recorder.chapter("Connected AP devices and operation details");
    recorder.key(&mut app, &api, KeyCode::Tab).await;
    recorder.key(&mut app, &api, KeyCode::Enter).await;
    assert_eq!(app.screen, Screen::WifiStations);
    recorder.hold(&mut app, &api, 1600).await;
    recorder.key(&mut app, &api, KeyCode::Down).await;
    recorder.hold(&mut app, &api, 1200).await;
    recorder.key(&mut app, &api, KeyCode::Esc).await;
    recorder.section(&mut app, &api, Section::Log).await;
    recorder.hold(&mut app, &api, 2200).await;
    assert!(!app.logs.iter().any(|entry| entry.level == LogLevel::Error));
    let state = api.state.lock().unwrap();
    for kind in [
        "dry_run_interface_edit",
        "apply_interface_edit",
        "commit_network_change",
        "forget_interface_config",
        "wifi_client_scan",
        "provision_wifi_client",
        "rollback_network_change",
        "list_wifi_stations",
    ] {
        assert!(
            state.calls.iter().any(|call| call == kind),
            "Missing live action: {kind}"
        );
    }
    drop(state);
    recorder.finish();
}
