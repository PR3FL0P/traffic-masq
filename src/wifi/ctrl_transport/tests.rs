use super::*;

#[test]
fn formats_and_parses_a_mac_address() {
    let mac = MacAddr::new([0x02, 0x00, 0x0a, 0x1b, 0xff, 0x01]);
    assert_eq!(mac.to_string(), "02:00:0a:1b:ff:01");
    assert_eq!("02:00:0a:1b:ff:01".parse(), Ok(mac));
}

#[test]
fn rejects_malformed_mac_addresses() {
    for bad in [
        "",
        "not-a-mac",
        "02:00:0a:1b:ff",
        "02:00:0a:1b:ff:01:02",
        "gg:00:0a:1b:ff:01",
    ] {
        assert!(
            bad.parse::<MacAddr>().is_err(),
            "{bad:?} should be rejected"
        );
    }
}

#[test]
fn strips_a_well_formed_priority_prefix() {
    assert_eq!(
        strip_priority_prefix("<3>AP-STA-CONNECTED"),
        "AP-STA-CONNECTED"
    );
    assert_eq!(strip_priority_prefix("AP-ENABLED"), "AP-ENABLED");
}

#[test]
fn leaves_a_malformed_priority_prefix_in_the_body() {
    assert_eq!(
        strip_priority_prefix("<not-a-number>AP-ENABLED"),
        "<not-a-number>AP-ENABLED"
    );
    assert_eq!(strip_priority_prefix("<>AP-ENABLED"), "<>AP-ENABLED");
}

#[test]
fn parses_key_value_lines_ignoring_ones_without_an_equals_sign() {
    let parsed = parse_kv_lines("state=ENABLED\nfreeform line\nchannel=6\n");
    assert_eq!(parsed.get("state"), Some(&"ENABLED".to_string()));
    assert_eq!(parsed.get("channel"), Some(&"6".to_string()));
    assert_eq!(parsed.len(), 2);
}

#[test]
fn indexed_field_prefers_the_indexed_form_and_falls_back_to_bare() {
    let mut raw = std::collections::BTreeMap::new();
    raw.insert("ssid[0]".to_string(), "indexed".to_string());
    raw.insert("other".to_string(), "bare".to_string());
    assert_eq!(indexed_field(&raw, "ssid"), Some("indexed"));
    assert_eq!(indexed_field(&raw, "other"), Some("bare"));
    assert_eq!(indexed_field(&raw, "missing"), None);
}

#[tokio::test]
async fn control_request_deadline_includes_a_blocked_send() {
    let (client, _unresponsive_daemon) = std::os::unix::net::UnixDatagram::pair().unwrap();
    client.set_nonblocking(true).unwrap();
    // Fill the peer queue without reading it, as when a daemon stalls.
    let payload = [0u8; MAX_CTRL_MESSAGE_BYTES];
    loop {
        match client.send(&payload) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("failed to fill control socket: {error}"),
        }
    }
    let client = UnixDatagram::from_std(client).unwrap();
    let budget = Duration::from_millis(20);
    let result = tokio::time::timeout(
        Duration::from_millis(200),
        control_request(&client, budget, "PING"),
    )
    .await
    .expect("control request exceeded its deadline while sending to a stalled daemon");
    assert!(matches!(result, Err(CtrlError::Timeout(value)) if value == budget));
}

#[tokio::test]
async fn control_request_times_out_when_daemon_accepts_but_does_not_reply() {
    let (client, _unresponsive_daemon) = UnixDatagram::pair().unwrap();
    let budget = Duration::from_millis(20);
    let result = control_request(&client, budget, "PING").await;
    assert!(matches!(result, Err(CtrlError::Timeout(value)) if value == budget));
}

#[tokio::test]
async fn control_request_still_exchanges_commands_and_replies() {
    let (client, daemon) = UnixDatagram::pair().unwrap();
    let reply = async {
        let mut buffer = [0u8; 32];
        let read = daemon.recv(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..read], b"PING");
        daemon.send(b"PONG\n").await.unwrap();
    };
    let (response, ()) = tokio::join!(
        control_request(&client, Duration::from_secs(1), "PING"),
        reply,
    );
    assert_eq!(response.unwrap(), "PONG\n");
}
