use std::collections::VecDeque;
use std::os::unix::net::{SocketAddr as StdSocketAddr, UnixDatagram as StdUnixDatagram};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use tempfile::tempdir;
use traffic_masq::wifi::{CtrlError, HostapdEvent, HostapdState, MacAddr};

const CLIENT_TIMEOUT: Duration = Duration::from_secs(2);

struct FakeHostapd {
    shutdown: Arc<AtomicBool>,
    emit: mpsc::Sender<String>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl FakeHostapd {
    fn spawn(ctrl_path: std::path::PathBuf, stations: Vec<MacAddr>) -> Self {
        let socket = StdUnixDatagram::bind(&ctrl_path).expect("bind fake hostapd ctrl socket");
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("set read timeout");

        let shutdown = Arc::new(AtomicBool::new(false));
        let (emit_tx, emit_rx) = mpsc::channel::<String>();

        let shutdown_for_thread = shutdown.clone();
        let stations: VecDeque<MacAddr> = stations.into_iter().collect();
        let join = std::thread::spawn(move || {
            Self::run(socket, stations, emit_rx, shutdown_for_thread);
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
            .expect("fake hostapd thread is alive");
    }

    fn run(
        socket: StdUnixDatagram,
        mut stations: VecDeque<MacAddr>,
        emit_rx: mpsc::Receiver<String>,
        shutdown: Arc<AtomicBool>,
    ) {
        let mut attached: Vec<StdSocketAddr> = Vec::new();
        let mut buffer = [0u8; 4096];

        while !shutdown.load(Ordering::Relaxed) {
            for body in emit_rx.try_iter() {
                let message = format!("<2>{body}");
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

            let reply = handle_command(&command, &mut stations, &mut attached, &from);
            let _ = socket.send_to_addr(reply.as_bytes(), &from);
        }
    }
}

impl Drop for FakeHostapd {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn handle_command(
    command: &str,
    stations: &mut VecDeque<MacAddr>,
    attached: &mut Vec<StdSocketAddr>,
    from: &StdSocketAddr,
) -> String {
    if command == "PING" {
        return "PONG\n".to_string();
    }
    if command == "STATUS" {
        return format!(
            "state=ENABLED\n\
             phy=phy0\n\
             channel=6\n\
             freq=2437\n\
             ssid[0]=traffic-masq\n\
             bssid[0]=02:00:00:00:00:00\n\
             num_sta[0]={}\n",
            stations.len()
        );
    }
    if command == "STA-FIRST" {
        return match stations.front() {
            Some(mac) => format!("{mac}\naid=1\nflags=[AUTH][ASSOC]\n"),
            None => "FAIL\n".to_string(),
        };
    }
    if let Some(current) = command.strip_prefix("STA-NEXT ") {
        let Ok(current_mac) = current.trim().parse::<MacAddr>() else {
            return "FAIL\n".to_string();
        };
        let position = stations.iter().position(|mac| *mac == current_mac);
        return match position.and_then(|index| stations.get(index + 1)) {
            Some(mac) => format!("{mac}\naid=2\nflags=[AUTH][ASSOC]\n"),
            None => "FAIL\n".to_string(),
        };
    }
    if let Some(target) = command.strip_prefix("DEAUTHENTICATE ") {
        let Ok(mac) = target.trim().parse::<MacAddr>() else {
            return "FAIL\n".to_string();
        };
        stations.retain(|station| *station != mac);
        return "OK\n".to_string();
    }
    if command == "RELOAD" {
        return "OK\n".to_string();
    }
    if command == "ATTACH" {
        attached.push(from.clone());
        return "OK\n".to_string();
    }
    if command == "DETACH" {
        use std::os::linux::net::SocketAddrExt;
        if let Some(name) = from.as_abstract_name() {
            attached.retain(|address| address.as_abstract_name() != Some(name));
        }
        return "OK\n".to_string();
    }

    "UNKNOWN COMMAND\n".to_string()
}

#[tokio::test]
async fn ping_pong_round_trips_over_a_real_datagram_socket() {
    let dir = tempdir().expect("tempdir");
    let ctrl_path = dir.path().join("wlan0");
    let _server = FakeHostapd::spawn(ctrl_path.clone(), Vec::new());

    let client = traffic_masq::wifi::HostapdCtrlClient::connect(&ctrl_path, CLIENT_TIMEOUT)
        .await
        .expect("connect");
    client.ping().await.expect("ping");
}

#[tokio::test]
async fn status_reports_the_configured_access_point() {
    let dir = tempdir().expect("tempdir");
    let ctrl_path = dir.path().join("wlan0");
    let _server = FakeHostapd::spawn(ctrl_path.clone(), Vec::new());

    let client = traffic_masq::wifi::HostapdCtrlClient::connect(&ctrl_path, CLIENT_TIMEOUT)
        .await
        .expect("connect");
    let status = client.status().await.expect("status");

    assert_eq!(status.state, HostapdState::Enabled);
    assert_eq!(status.ssid.as_deref(), Some("traffic-masq"));
    assert_eq!(status.channel, Some(6));
}

#[tokio::test]
async fn stations_pages_through_sta_first_and_sta_next() {
    let dir = tempdir().expect("tempdir");
    let ctrl_path = dir.path().join("wlan0");
    let macs = vec![
        MacAddr::new([0x02, 0, 0, 0, 0, 1]),
        MacAddr::new([0x02, 0, 0, 0, 0, 2]),
        MacAddr::new([0x02, 0, 0, 0, 0, 3]),
    ];
    let _server = FakeHostapd::spawn(ctrl_path.clone(), macs.clone());

    let client = traffic_masq::wifi::HostapdCtrlClient::connect(&ctrl_path, CLIENT_TIMEOUT)
        .await
        .expect("connect");
    let stations = client.stations().await.expect("stations");

    assert_eq!(
        stations
            .iter()
            .map(|station| station.mac)
            .collect::<Vec<_>>(),
        macs
    );
}

#[tokio::test]
async fn stations_is_empty_without_hitting_an_error_when_none_are_associated() {
    let dir = tempdir().expect("tempdir");
    let ctrl_path = dir.path().join("wlan0");
    let _server = FakeHostapd::spawn(ctrl_path.clone(), Vec::new());

    let client = traffic_masq::wifi::HostapdCtrlClient::connect(&ctrl_path, CLIENT_TIMEOUT)
        .await
        .expect("connect");
    assert_eq!(client.stations().await.expect("stations"), Vec::new());
}

#[tokio::test]
async fn deauthenticate_removes_the_station() {
    let dir = tempdir().expect("tempdir");
    let ctrl_path = dir.path().join("wlan0");
    let mac = MacAddr::new([0x02, 0, 0, 0, 0, 9]);
    let _server = FakeHostapd::spawn(ctrl_path.clone(), vec![mac]);

    let client = traffic_masq::wifi::HostapdCtrlClient::connect(&ctrl_path, CLIENT_TIMEOUT)
        .await
        .expect("connect");
    assert_eq!(client.stations().await.expect("stations").len(), 1);

    client.deauthenticate(mac).await.expect("deauthenticate");
    assert_eq!(client.stations().await.expect("stations"), Vec::new());
}

#[tokio::test]
async fn reload_is_acknowledged() {
    let dir = tempdir().expect("tempdir");
    let ctrl_path = dir.path().join("wlan0");
    let _server = FakeHostapd::spawn(ctrl_path.clone(), Vec::new());

    let client = traffic_masq::wifi::HostapdCtrlClient::connect(&ctrl_path, CLIENT_TIMEOUT)
        .await
        .expect("connect");
    client.reload().await.expect("reload");
}

#[tokio::test]
async fn an_unrecognised_command_is_a_typed_error_not_text() {
    let dir = tempdir().expect("tempdir");
    let ctrl_path = dir.path().join("wlan0");
    let _server = FakeHostapd::spawn(ctrl_path.clone(), Vec::new());

    let client = traffic_masq::wifi::HostapdCtrlClient::connect(&ctrl_path, CLIENT_TIMEOUT)
        .await
        .expect("connect");
    let error = client.request("NOT-A-REAL-COMMAND").await.unwrap_err();
    assert!(matches!(error, CtrlError::UnknownCommand(_)), "{error:?}");
}

#[tokio::test]
async fn a_request_against_a_socket_with_no_listener_times_out() {
    let dir = tempdir().expect("tempdir");

    let ctrl_path = dir.path().join("wlan0");
    let client =
        traffic_masq::wifi::HostapdCtrlClient::connect(&ctrl_path, Duration::from_millis(100))
            .await;

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
async fn event_client_receives_lifecycle_and_station_events_after_attaching() {
    let dir = tempdir().expect("tempdir");
    let ctrl_path = dir.path().join("wlan0");
    let server = FakeHostapd::spawn(ctrl_path.clone(), Vec::new());

    let (event_client, mut events) =
        traffic_masq::wifi::HostapdEventClient::attach(&ctrl_path, CLIENT_TIMEOUT)
            .await
            .expect("attach");

    let mac = MacAddr::new([0x02, 0, 0, 0, 0, 4]);
    server.emit_event("AP-ENABLED");
    server.emit_event(&format!("AP-STA-CONNECTED {mac}"));
    server.emit_event(&format!("AP-STA-DISCONNECTED {mac}"));

    let first = tokio::time::timeout(CLIENT_TIMEOUT, events.recv())
        .await
        .expect("did not time out")
        .expect("event");
    let second = tokio::time::timeout(CLIENT_TIMEOUT, events.recv())
        .await
        .expect("did not time out")
        .expect("event");
    let third = tokio::time::timeout(CLIENT_TIMEOUT, events.recv())
        .await
        .expect("did not time out")
        .expect("event");

    assert_eq!(first, HostapdEvent::ApEnabled);
    assert_eq!(second, HostapdEvent::StaConnected(mac));
    assert_eq!(third, HostapdEvent::StaDisconnected(mac));

    event_client.close().await;
}

#[tokio::test]
async fn a_command_socket_never_receives_attach_only_events() {
    let dir = tempdir().expect("tempdir");
    let ctrl_path = dir.path().join("wlan0");
    let server = FakeHostapd::spawn(ctrl_path.clone(), Vec::new());

    let (_event_client, _events) =
        traffic_masq::wifi::HostapdEventClient::attach(&ctrl_path, CLIENT_TIMEOUT)
            .await
            .expect("attach");

    let command_client = traffic_masq::wifi::HostapdCtrlClient::connect(&ctrl_path, CLIENT_TIMEOUT)
        .await
        .expect("connect");

    server.emit_event("AP-ENABLED");

    tokio::time::sleep(Duration::from_millis(50)).await;

    command_client
        .ping()
        .await
        .expect("ping still works cleanly");
}
