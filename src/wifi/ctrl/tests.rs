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
fn parses_a_status_reply_with_indexed_bss_fields() {
    let reply = "state=ENABLED\n\
                  phy=phy0\n\
                  channel=6\n\
                  freq=2437\n\
                  ssid[0]=traffic-masq\n\
                  bssid[0]=02:00:00:00:00:01\n\
                  num_sta[0]=2\n";
    let status = parse_status(reply).expect("parse");
    assert_eq!(status.state, HostapdState::Enabled);
    assert_eq!(status.ssid.as_deref(), Some("traffic-masq"));
    assert_eq!(
        status.bssid,
        Some(MacAddr::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]))
    );
    assert_eq!(status.channel, Some(6));
    assert_eq!(status.freq, Some(2437));
    assert_eq!(status.num_stations, Some(2));
    assert_eq!(status.raw.get("phy"), Some(&"phy0".to_string()));
}

#[test]
fn an_unrecognised_state_is_preserved_rather_than_rejected() {
    let status = parse_status("state=SOME_FUTURE_STATE\n").expect("parse");
    assert_eq!(
        status.state,
        HostapdState::Other("SOME_FUTURE_STATE".to_string())
    );
}

#[test]
fn parses_a_station_reply() {
    let reply = "02:00:00:00:00:05\naid=3\nflags=[AUTH][ASSOC]\n";
    let station = parse_station(reply).expect("parse");
    assert_eq!(station.mac, MacAddr::new([0x02, 0, 0, 0, 0, 5]));
    assert_eq!(station.raw.get("aid"), Some(&"3".to_string()));
}

#[test]
fn parses_lifecycle_events() {
    assert_eq!(
        HostapdEvent::parse("<2>AP-ENABLED"),
        HostapdEvent::ApEnabled
    );
    assert_eq!(
        HostapdEvent::parse("<2>AP-DISABLED\n"),
        HostapdEvent::ApDisabled
    );
    assert_eq!(
        HostapdEvent::parse("<0>CTRL-EVENT-TERMINATING"),
        HostapdEvent::Terminating
    );
}

#[test]
fn parses_station_lifecycle_events_with_their_mac() {
    let mac = MacAddr::new([0x02, 0, 0, 0, 0, 7]);
    assert_eq!(
        HostapdEvent::parse("<3>AP-STA-CONNECTED 02:00:00:00:00:07"),
        HostapdEvent::StaConnected(mac)
    );
    assert_eq!(
        HostapdEvent::parse("<3>AP-STA-DISCONNECTED 02:00:00:00:00:07"),
        HostapdEvent::StaDisconnected(mac)
    );
}

#[test]
fn an_event_without_a_priority_prefix_still_parses() {
    assert_eq!(HostapdEvent::parse("AP-ENABLED"), HostapdEvent::ApEnabled);
}

#[test]
fn an_unrecognised_event_is_preserved_verbatim() {
    assert_eq!(
        HostapdEvent::parse("<2>CTRL-EVENT-SOMETHING-NEW extra data"),
        HostapdEvent::Other("<2>CTRL-EVENT-SOMETHING-NEW extra data".to_string())
    );
}

#[test]
fn a_malformed_priority_prefix_is_left_in_the_body() {
    assert_eq!(
        HostapdEvent::parse("<not-a-number>AP-ENABLED"),
        HostapdEvent::Other("<not-a-number>AP-ENABLED".to_string())
    );
}
