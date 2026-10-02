use super::*;

#[tokio::test]
async fn empty_bss_table_returns_no_networks() {
    for reply in ["", "FAIL\n"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ctrl");
        let socket = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let server = tokio::task::spawn_blocking(move || {
            let mut buffer = [0u8; 128];
            let (len, peer) = socket.recv_from(&mut buffer).unwrap();
            assert_eq!(&buffer[..len], b"BSS FIRST");
            socket.send_to_addr(reply.as_bytes(), &peer).unwrap();
        });
        let client = WpaSupplicantCtrlClient::connect(&path, Duration::from_secs(2))
            .await
            .unwrap();
        assert!(client.scan_results().await.unwrap().is_empty());
        server.await.unwrap();
    }
}

#[tokio::test]
async fn bss_iteration_reads_more_than_one_control_reply_can_hold() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ctrl");
    let socket = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
    let server = tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 4096];
        loop {
            let (len, peer) = socket.recv_from(&mut buf).unwrap();
            let command = std::str::from_utf8(&buf[..len]).unwrap();
            let index = if command == "BSS FIRST" {
                0
            } else {
                command
                    .strip_prefix("BSS NEXT-")
                    .unwrap()
                    .parse::<usize>()
                    .unwrap()
                    + 1
            };
            let reply = if index == 200 {
                String::new()
            } else {
                format!("id={index}\nbssid=02:00:00:00:{:02x}:{:02x}\nfreq=2412\nlevel=-40\nflags=[ESS]\nssid=network-{index}\n", index / 256, index % 256)
            };
            socket.send_to_addr(reply.as_bytes(), &peer).unwrap();
            if index == 200 {
                break;
            }
        }
    });
    let client = WpaSupplicantCtrlClient::connect(&path, Duration::from_secs(2))
        .await
        .unwrap();
    let results = client.scan_results().await.unwrap();
    assert_eq!(results.len(), 200);
    assert_eq!(results[199].ssid, "network-199");
    server.await.unwrap();
}

#[test]
fn bss_parser_handles_hidden_binary_and_malformed_replies() {
    let (_, hidden) =
        parse_bss("id=1\nbssid=02:00:00:00:00:01\nfreq=2412\nlevel=-40\nflags=[ESS]\nssid=\n")
            .unwrap();
    assert!(hidden.ssid_bytes.is_empty());
    let (_, binary) =
        parse_bss("id=2\nbssid=02:00:00:00:00:02\nfreq=2412\nlevel=-40\nflags=[ESS]\nssid=\\xff\n")
            .unwrap();
    assert_eq!(binary.ssid_bytes, vec![0xff]);
    assert!(parse_bss("id=garbage\n").is_err());
}

#[test]
fn parses_a_status_reply() {
    let reply = "bssid=02:00:00:00:00:01\n\
                 freq=2437\n\
                 ssid=upstream\n\
                 id=0\n\
                 mode=station\n\
                 wpa_state=COMPLETED\n\
                 address=02:00:00:00:00:99\n";
    let status = parse_status(reply).expect("parse");

    assert_eq!(status.wpa_state, WpaState::Completed);
    assert!(status.wpa_state.is_connected());
    assert_eq!(status.ssid.as_deref(), Some("upstream"));
    assert_eq!(status.bssid, Some(MacAddr::new([0x02, 0, 0, 0, 0, 0x01])));
    assert_eq!(status.freq, Some(2437));
    assert_eq!(status.raw.get("mode"), Some(&"station".to_string()));
}

#[test]
fn a_disconnected_status_carries_no_association_details() {
    let status = parse_status("wpa_state=DISCONNECTED\n").expect("parse");
    assert_eq!(status.wpa_state, WpaState::Disconnected);
    assert!(!status.wpa_state.is_connected());
    assert_eq!(status.bssid, None);
    assert_eq!(status.ssid, None);
}

#[test]
fn parses_every_state_of_the_association_machine() {
    for (wire, expected) in [
        ("DISCONNECTED", WpaState::Disconnected),
        ("INTERFACE_DISABLED", WpaState::InterfaceDisabled),
        ("INACTIVE", WpaState::Inactive),
        ("SCANNING", WpaState::Scanning),
        ("AUTHENTICATING", WpaState::Authenticating),
        ("ASSOCIATING", WpaState::Associating),
        ("ASSOCIATED", WpaState::Associated),
        ("4WAY_HANDSHAKE", WpaState::FourWayHandshake),
        ("GROUP_HANDSHAKE", WpaState::GroupHandshake),
        ("COMPLETED", WpaState::Completed),
    ] {
        assert_eq!(WpaState::parse(wire), expected, "{wire}");
    }
}

#[test]
fn only_completed_counts_as_connected() {
    assert!(WpaState::Completed.is_connected());
    for state in [
        WpaState::Associated,
        WpaState::FourWayHandshake,
        WpaState::GroupHandshake,
        WpaState::Scanning,
        WpaState::Disconnected,
    ] {
        assert!(!state.is_connected(), "{state:?}");
    }
}

#[test]
fn an_unrecognised_state_is_preserved_rather_than_rejected() {
    let status = parse_status("wpa_state=SOME_FUTURE_STATE\n").expect("parse");
    assert_eq!(
        status.wpa_state,
        WpaState::Other("SOME_FUTURE_STATE".to_string())
    );
    assert!(!status.wpa_state.is_connected());
}

#[test]
fn parses_scan_results_and_classifies_security() {
    let reply = "bssid / frequency / signal level / flags / ssid\n\
                 02:00:00:00:00:01\t2412\t-41\t[ESS]\topen\n\
                 02:00:00:00:00:02\t5180\t-52\t[WPA2-PSK-CCMP][ESS]\twpa2\n\
                 02:00:00:00:00:03\t5955\t-63\t[RSN-SAE-CCMP][ESS]\twpa3\n\
                 02:00:00:00:00:04\t5220\t-70\t[WPA2-PSK-CCMP][SAE][ESS]\ttransition\n\
                 02:00:00:00:00:05\t2462\t-80\t[WPA2-EAP-CCMP][ESS]\tcorp\n\
                 02:00:00:00:00:06\t2437\t-81\t[FUTURE-AKM][ESS]\tfuture\textra\n";
    let results = parse_scan_results(reply);

    assert_eq!(results.len(), 6);
    assert_eq!(results[0].security, WpaSupplicantScanSecurity::Open);
    assert_eq!(results[1].security, WpaSupplicantScanSecurity::Wpa2Psk);
    assert_eq!(results[2].security, WpaSupplicantScanSecurity::Wpa3Sae);
    assert_eq!(
        results[3].security,
        WpaSupplicantScanSecurity::Wpa2Wpa3Transition
    );
    assert_eq!(
        results[4].security,
        WpaSupplicantScanSecurity::EnterpriseOrUnsupported
    );
    assert_eq!(results[5].security, WpaSupplicantScanSecurity::Unknown);
    assert_eq!(results[5].ssid, "future\textra");
    assert_eq!(results[1].frequency_mhz, 5180);
    assert_eq!(results[1].signal_dbm, -52);
    assert_eq!(results[1].raw_flags, "[WPA2-PSK-CCMP][ESS]");
}

#[test]
fn malformed_scan_rows_are_skipped_without_losing_valid_rows() {
    let reply = "bssid / frequency / signal level / flags / ssid\n\
                 not-a-mac\t2412\t-40\t[ESS]\tbad mac\n\
                 02:00:00:00:00:02\tnot-a-frequency\t-50\t[ESS]\tbad freq\n\
                 02:00:00:00:00:03\t2437\tnot-a-signal\t[ESS]\tbad signal\n\
                 too\tfew\tfields\n\
                 02:00:00:00:00:04\t2462\t-60\t[ESS]\tgood\n";

    let results = parse_scan_results(reply);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].ssid, "good");
}

#[test]
fn empty_flags_are_open_and_empty_ssids_are_retained() {
    let results = parse_scan_results("02:00:00:00:00:01\t2412\t-40\t\t\n");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].security, WpaSupplicantScanSecurity::Open);
    assert_eq!(results[0].ssid, "");
}

#[test]
fn parses_the_prose_shaped_connected_event() {
    assert_eq!(
        WpaSupplicantEvent::parse(
            "<3>CTRL-EVENT-CONNECTED - Connection to 02:00:00:00:00:01 completed [id=0 id_str=]"
        ),
        WpaSupplicantEvent::Connected {
            bssid: Some(MacAddr::new([0x02, 0, 0, 0, 0, 0x01])),
        }
    );
}

#[test]
fn parses_a_disconnected_event_with_and_without_its_trailing_field() {
    assert_eq!(
        WpaSupplicantEvent::parse("<3>CTRL-EVENT-DISCONNECTED bssid=02:00:00:00:00:01 reason=3"),
        WpaSupplicantEvent::Disconnected {
            bssid: Some(MacAddr::new([0x02, 0, 0, 0, 0, 0x01])),
            reason: Some(3),
        }
    );

    assert_eq!(
        WpaSupplicantEvent::parse(
            "<3>CTRL-EVENT-DISCONNECTED bssid=02:00:00:00:00:01 reason=3 locally_generated=1"
        ),
        WpaSupplicantEvent::Disconnected {
            bssid: Some(MacAddr::new([0x02, 0, 0, 0, 0, 0x01])),
            reason: Some(3),
        }
    );
}

#[test]
fn a_wrong_key_is_reported_as_an_authentication_failure() {
    assert_eq!(
        WpaSupplicantEvent::parse(
            "<3>CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid=\"upstream\" auth_failures=1 duration=10 reason=WRONG_KEY"
        ),
        WpaSupplicantEvent::AuthenticationFailed {
            reason: "WRONG_KEY".to_string(),
        }
    );
}

#[test]
fn an_ssid_containing_the_reason_field_does_not_confuse_the_parse() {
    assert_eq!(
        WpaSupplicantEvent::parse(
            "<3>CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid=\"reason=NOT_THIS\" auth_failures=1 duration=10 reason=WRONG_KEY"
        ),
        WpaSupplicantEvent::AuthenticationFailed {
            reason: "WRONG_KEY".to_string(),
        }
    );
}

#[test]
fn parses_the_remaining_lifecycle_events() {
    assert_eq!(
        WpaSupplicantEvent::parse("<3>CTRL-EVENT-NETWORK-NOT-FOUND "),
        WpaSupplicantEvent::NetworkNotFound
    );
    assert_eq!(
        WpaSupplicantEvent::parse("<3>CTRL-EVENT-SCAN-RESULTS "),
        WpaSupplicantEvent::ScanResults
    );

    assert_eq!(
        WpaSupplicantEvent::parse("<3>CTRL-EVENT-SCAN-RESULTS id=1"),
        WpaSupplicantEvent::ScanResults
    );
    assert_eq!(
        WpaSupplicantEvent::parse("<0>CTRL-EVENT-TERMINATING "),
        WpaSupplicantEvent::Terminating
    );
}

#[test]
fn an_event_without_a_priority_prefix_still_parses() {
    assert_eq!(
        WpaSupplicantEvent::parse("CTRL-EVENT-TERMINATING"),
        WpaSupplicantEvent::Terminating
    );
}

#[test]
fn an_unrecognised_event_is_preserved_verbatim() {
    assert_eq!(
        WpaSupplicantEvent::parse("<3>CTRL-EVENT-SOMETHING-NEW extra data"),
        WpaSupplicantEvent::Other("<3>CTRL-EVENT-SOMETHING-NEW extra data".to_string())
    );
}

#[test]
fn a_connected_event_without_a_parsable_bssid_is_still_a_connection() {
    assert_eq!(
        WpaSupplicantEvent::parse("<3>CTRL-EVENT-CONNECTED - Connection to garbage completed"),
        WpaSupplicantEvent::Connected { bssid: None }
    );
}

#[test]
fn scan_decodes_unicode_and_literal_backslashes_without_loss() {
    let results = parse_scan_results(
        "02:00:00:00:00:01\t2412\t-41\t[ESS]\t\\xd0\\x94\\xd1\\x96\\xd0\\xbc\\\\wifi\n",
    );
    assert_eq!(results[0].ssid, "Дім\\wifi");
    assert_eq!(decode_ssid(r#"a\"b\tc"#), Some("a\"b\tc".into()));
    assert_eq!(decode_ssid(r"\xff"), None);
    assert_eq!(decode_ssid(r"\xzz"), None);
    let status =
        parse_status("wpa_state=COMPLETED\nssid=\\xd0\\x94\\xd1\\x96\\xd0\\xbc\n").unwrap();
    assert_eq!(status.ssid.as_deref(), Some("Дім"));
}

#[test]
fn binary_ssids_are_retained_with_exact_bytes_and_an_escaped_display() {
    let rows = parse_scan_results("02:00:00:00:00:01\t2412\t-40\t[ESS]\t\\xff\\x80\n");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].ssid_bytes, vec![0xff, 0x80]);
    assert_eq!(rows[0].ssid, r"\xff\x80");
}
