use std::os::unix::net::{SocketAddr as StdSocketAddr, UnixDatagram as StdUnixDatagram};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use tempfile::tempdir;
use traffic_masq::wifi::client::ctrl::WpaSupplicantScanSecurity;
use traffic_masq::wifi::{
    CtrlError, MacAddr, WpaState, WpaSupplicantCtrlClient, WpaSupplicantEvent,
    WpaSupplicantEventClient,
};

const CLIENT_TIMEOUT: Duration = Duration::from_secs(2);
const BSSID: MacAddr = MacAddr::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);

struct FakeWpaSupplicant {
    shutdown: Arc<AtomicBool>,
    emit: mpsc::Sender<String>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl FakeWpaSupplicant {
    fn spawn(ctrl_path: std::path::PathBuf, initial_state: &str) -> Self {
        let socket = StdUnixDatagram::bind(&ctrl_path).expect("bind fake ctrl socket");
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("set read timeout");

        let shutdown = Arc::new(AtomicBool::new(false));
        let (emit_tx, emit_rx) = mpsc::channel::<String>();

        let shutdown_for_thread = shutdown.clone();
        let state = initial_state.to_string();
        let join = std::thread::spawn(move || {
            Self::run(socket, state, emit_rx, shutdown_for_thread);
        });

        Self {
            shutdown,
            emit: emit_tx,
            join: Some(join),
        }
    }

    fn emit_event(&self, body: &str) {
        self.emit
            .send(body.to_string())
            .expect("fake wpa_supplicant thread is alive");
    }

    fn run(
        socket: StdUnixDatagram,
        mut state: String,
        emit_rx: mpsc::Receiver<String>,
        shutdown: Arc<AtomicBool>,
    ) {
        let mut attached: Vec<StdSocketAddr> = Vec::new();
        let mut buffer = [0u8; 4096];

        while !shutdown.load(Ordering::Relaxed) {
            for body in emit_rx.try_iter() {
                let message = format!("<3>{body}");
                for address in &attached {
                    let _ = socket.send_to_addr(message.as_bytes(), address);
                }
            }

            let (read, from) = match socket.recv_from(&mut buffer) {
                Ok(result) => result,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(_) => break,
            };
            let command = String::from_utf8_lossy(&buffer[..read]).into_owned();

            let reply = handle_command(&command, &mut state, &mut attached, &from);
            let _ = socket.send_to_addr(reply.as_bytes(), &from);
        }
    }
}

impl Drop for FakeWpaSupplicant {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn handle_command(
    command: &str,
    state: &mut String,
    attached: &mut Vec<StdSocketAddr>,
    from: &StdSocketAddr,
) -> String {
    match command {
        "PING" => "PONG\n".to_string(),
        "STATUS" => {
            if state == "COMPLETED" {
                format!(
                    "bssid={BSSID}\n\
                     freq=2437\n\
                     ssid=upstream\n\
                     id=0\n\
                     mode=station\n\
                     wpa_state={state}\n\
                     address=02:00:00:00:00:99\n"
                )
            } else {
                format!("wpa_state={state}\naddress=02:00:00:00:00:99\n")
            }
        }
        "SCAN" => "OK\n".to_string(),
        "BSS FIRST" => format!("id=0\nbssid={BSSID}\nfreq=2412\nlevel=-42\nflags=[WPA2-PSK-CCMP][SAE][ESS]\nssid=upstream\n"),
        "BSS NEXT-0" => String::new(),
        "RECONNECT" => {
            *state = "SCANNING".to_string();
            "OK\n".to_string()
        }
        "REASSOCIATE" => {
            *state = "ASSOCIATING".to_string();
            "OK\n".to_string()
        }
        "DISCONNECT" => {
            *state = "DISCONNECTED".to_string();
            "OK\n".to_string()
        }
        "ATTACH" => {
            attached.push(from.clone());
            "OK\n".to_string()
        }
        "DETACH" => {
            use std::os::linux::net::SocketAddrExt;
            if let Some(name) = from.as_abstract_name() {
                attached.retain(|address| address.as_abstract_name() != Some(name));
            }
            "OK\n".to_string()
        }
        _ => "UNKNOWN COMMAND\n".to_string(),
    }
}

async fn client(ctrl_path: &std::path::Path) -> WpaSupplicantCtrlClient {
    WpaSupplicantCtrlClient::connect(ctrl_path, CLIENT_TIMEOUT)
        .await
        .expect("connect")
}

#[tokio::test]
async fn ping_pong_round_trips_over_a_real_datagram_socket() {
    let dir = tempdir().expect("tempdir");
    let ctrl_path = dir.path().join("wlan0");
    let _server = FakeWpaSupplicant::spawn(ctrl_path.clone(), "COMPLETED");

    client(&ctrl_path).await.ping().await.expect("ping");
}

#[tokio::test]
async fn status_reports_a_completed_association() {
    let dir = tempdir().expect("tempdir");
    let ctrl_path = dir.path().join("wlan0");
    let _server = FakeWpaSupplicant::spawn(ctrl_path.clone(), "COMPLETED");

    let status = client(&ctrl_path).await.status().await.expect("status");

    assert_eq!(status.wpa_state, WpaState::Completed);
    assert!(status.wpa_state.is_connected());
    assert_eq!(status.ssid.as_deref(), Some("upstream"));
    assert_eq!(status.bssid, Some(BSSID));
    assert_eq!(status.freq, Some(2437));
}

#[tokio::test]
async fn a_mid_handshake_status_is_not_reported_as_connected() {
    let dir = tempdir().expect("tempdir");
    let ctrl_path = dir.path().join("wlan0");
    let _server = FakeWpaSupplicant::spawn(ctrl_path.clone(), "4WAY_HANDSHAKE");

    let status = client(&ctrl_path).await.status().await.expect("status");

    assert_eq!(status.wpa_state, WpaState::FourWayHandshake);
    assert!(!status.wpa_state.is_connected());
    assert_eq!(status.bssid, None);
}

#[tokio::test]
async fn scan_and_scan_results_round_trip_over_the_control_transport() {
    let dir = tempdir().expect("tempdir");
    let ctrl_path = dir.path().join("wlan0");
    let _server = FakeWpaSupplicant::spawn(ctrl_path.clone(), "COMPLETED");
    let client = client(&ctrl_path).await;

    client.scan().await.expect("scan");
    let results = client.scan_results().await.expect("scan results");

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].bssid, BSSID);
    assert_eq!(results[0].frequency_mhz, 2412);
    assert_eq!(results[0].signal_dbm, -42);
    assert_eq!(results[0].ssid, "upstream");
    assert_eq!(
        results[0].security,
        WpaSupplicantScanSecurity::Wpa2Wpa3Transition
    );
}

#[tokio::test]
async fn reconnect_disconnect_and_reassociate_each_move_the_supplicant() {
    let dir = tempdir().expect("tempdir");
    let ctrl_path = dir.path().join("wlan0");
    let _server = FakeWpaSupplicant::spawn(ctrl_path.clone(), "COMPLETED");
    let client = client(&ctrl_path).await;

    client.disconnect().await.expect("disconnect");
    assert_eq!(
        client.status().await.expect("status").wpa_state,
        WpaState::Disconnected
    );

    client.reconnect().await.expect("reconnect");
    assert_eq!(
        client.status().await.expect("status").wpa_state,
        WpaState::Scanning
    );

    client.reassociate().await.expect("reassociate");
    assert_eq!(
        client.status().await.expect("status").wpa_state,
        WpaState::Associating
    );
}

#[tokio::test]
async fn an_unrecognised_command_is_a_typed_error_not_text() {
    let dir = tempdir().expect("tempdir");
    let ctrl_path = dir.path().join("wlan0");
    let _server = FakeWpaSupplicant::spawn(ctrl_path.clone(), "COMPLETED");

    let error = client(&ctrl_path)
        .await
        .request("NOT-A-REAL-COMMAND")
        .await
        .unwrap_err();
    assert!(matches!(error, CtrlError::UnknownCommand(_)), "{error:?}");
}

#[tokio::test]
async fn a_request_against_a_socket_with_no_listener_times_out() {
    let dir = tempdir().expect("tempdir");

    let ctrl_path = dir.path().join("wlan0");
    let client = WpaSupplicantCtrlClient::connect(&ctrl_path, Duration::from_millis(100)).await;

    match client {
        Ok(client) => {
            let error = client.ping().await.unwrap_err();
            assert!(
                matches!(error, CtrlError::Timeout(_) | CtrlError::Io(_)),
                "{error:?}"
            );
        }
        Err(error) => assert!(matches!(error, CtrlError::Io(_)), "{error:?}"),
    }
}

#[tokio::test]
async fn event_client_receives_the_association_lifecycle_after_attaching() {
    let dir = tempdir().expect("tempdir");
    let ctrl_path = dir.path().join("wlan0");
    let server = FakeWpaSupplicant::spawn(ctrl_path.clone(), "SCANNING");

    let (event_client, mut events) = WpaSupplicantEventClient::attach(&ctrl_path, CLIENT_TIMEOUT)
        .await
        .expect("attach");

    server.emit_event(&format!(
        "CTRL-EVENT-CONNECTED - Connection to {BSSID} completed [id=0 id_str=]"
    ));
    server.emit_event(&format!(
        "CTRL-EVENT-DISCONNECTED bssid={BSSID} reason=3 locally_generated=1"
    ));

    let mut received = Vec::new();
    for _ in 0..2 {
        received.push(
            tokio::time::timeout(CLIENT_TIMEOUT, events.recv())
                .await
                .expect("did not time out")
                .expect("event"),
        );
    }

    assert_eq!(
        received,
        vec![
            WpaSupplicantEvent::Connected { bssid: Some(BSSID) },
            WpaSupplicantEvent::Disconnected {
                bssid: Some(BSSID),
                reason: Some(3),
            },
        ]
    );

    event_client.close().await;
}

#[tokio::test]
async fn a_wrong_passphrase_arrives_as_its_own_event() {
    let dir = tempdir().expect("tempdir");
    let ctrl_path = dir.path().join("wlan0");
    let server = FakeWpaSupplicant::spawn(ctrl_path.clone(), "4WAY_HANDSHAKE");

    let (event_client, mut events) = WpaSupplicantEventClient::attach(&ctrl_path, CLIENT_TIMEOUT)
        .await
        .expect("attach");

    server.emit_event(
        "CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid=\"upstream\" auth_failures=1 duration=10 reason=WRONG_KEY",
    );

    let event = tokio::time::timeout(CLIENT_TIMEOUT, events.recv())
        .await
        .expect("did not time out")
        .expect("event");
    assert_eq!(
        event,
        WpaSupplicantEvent::AuthenticationFailed {
            reason: "WRONG_KEY".to_string(),
        }
    );

    event_client.close().await;
}

#[tokio::test]
async fn a_command_socket_never_receives_attach_only_events() {
    let dir = tempdir().expect("tempdir");
    let ctrl_path = dir.path().join("wlan0");
    let server = FakeWpaSupplicant::spawn(ctrl_path.clone(), "COMPLETED");

    let (event_client, mut events) = WpaSupplicantEventClient::attach(&ctrl_path, CLIENT_TIMEOUT)
        .await
        .expect("attach");

    let command_client = client(&ctrl_path).await;

    server.emit_event("CTRL-EVENT-SCAN-RESULTS ");

    assert_eq!(
        tokio::time::timeout(CLIENT_TIMEOUT, events.recv())
            .await
            .expect("event delivery")
            .expect("event stream"),
        WpaSupplicantEvent::ScanResults
    );

    let status = command_client.status().await.expect("status is a status");
    assert_eq!(status.wpa_state, WpaState::Completed);
    event_client.close().await;
}
