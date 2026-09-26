use super::*;
use crate::wifi::MacAddr;

fn sample_profile(
    id: &str,
    ssid: &str,
    security: WifiClientSecurity,
    priority: i32,
    autoconnect: bool,
    has_passphrase: bool,
) -> WifiClientProfileSummary {
    WifiClientProfileSummary {
        id: id.to_string(),
        ssid: ssid.to_string(),
        country_code: None,
        security,
        priority,
        autoconnect,
        created_at: 0,
        modified_at: 0,
        has_passphrase,
    }
}

fn sample_network(ssid: &str, security: WpaSupplicantScanSecurity) -> WpaSupplicantScanResult {
    WpaSupplicantScanResult {
        bssid: MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        frequency_mhz: 2412,
        signal_dbm: -50,
        ssid: ssid.to_string(),
        ssid_bytes: Vec::new(),
        raw_flags: String::new(),
        security,
    }
}

#[test]
fn test_matching_network_security() {
    use WpaSupplicantScanSecurity as Scan;

    let p_open = sample_profile("p1", "Net", WifiClientSecurity::Open, 0, true, false);
    assert!(matching_network(
        &p_open,
        &sample_network("Net", Scan::Open)
    ));
    assert!(!matching_network(
        &p_open,
        &sample_network("Net", Scan::Wpa2Psk)
    ));
    assert!(!matching_network(
        &p_open,
        &sample_network("Net", Scan::Wpa3Sae)
    ));

    let p_wpa2 = sample_profile("p2", "Net", WifiClientSecurity::Wpa2, 0, true, true);
    assert!(matching_network(
        &p_wpa2,
        &sample_network("Net", Scan::Wpa2Psk)
    ));
    assert!(matching_network(
        &p_wpa2,
        &sample_network("Net", Scan::Wpa2Wpa3Transition)
    ));
    assert!(!matching_network(
        &p_wpa2,
        &sample_network("Net", Scan::Open)
    ));
    assert!(!matching_network(
        &p_wpa2,
        &sample_network("Net", Scan::Wpa3Sae)
    ));

    let p_wpa3 = sample_profile("p3", "Net", WifiClientSecurity::Wpa3, 0, true, true);
    assert!(matching_network(
        &p_wpa3,
        &sample_network("Net", Scan::Wpa3Sae)
    ));
    assert!(matching_network(
        &p_wpa3,
        &sample_network("Net", Scan::Wpa2Wpa3Transition)
    ));
    assert!(!matching_network(
        &p_wpa3,
        &sample_network("Net", Scan::Open)
    ));
    assert!(!matching_network(
        &p_wpa3,
        &sample_network("Net", Scan::Wpa2Psk)
    ));

    // SSID mismatch
    assert!(!matching_network(
        &p_open,
        &sample_network("Other", Scan::Open)
    ));
}

#[test]
fn test_choose_profile_priority_and_filtering() {
    let now = Instant::now();
    let state = AutoconnectState::default();
    let networks = vec![
        sample_network("NetA", WpaSupplicantScanSecurity::Wpa2Psk),
        sample_network("NetB", WpaSupplicantScanSecurity::Wpa2Psk),
    ];

    let profiles = vec![
        // autoconnect is false -> skip
        sample_profile("p1", "NetA", WifiClientSecurity::Wpa2, 10, false, true),
        // no passphrase -> skip
        sample_profile("p2", "NetA", WifiClientSecurity::Wpa2, 10, true, false),
        // valid match
        sample_profile("p3", "NetA", WifiClientSecurity::Wpa2, 5, true, true),
        // valid match with higher priority
        sample_profile("p4", "NetB", WifiClientSecurity::Wpa2, 10, true, true),
    ];

    let chosen = choose_profile(&profiles, &networks, "wlan0", &state, now).unwrap();
    assert_eq!(chosen.id, "p4");
}

#[test]
fn test_choose_profile_tie_breaking() {
    let now = Instant::now();
    let state = AutoconnectState::default();
    let networks = vec![sample_network("Net", WpaSupplicantScanSecurity::Wpa2Psk)];

    let profiles = vec![
        sample_profile("beta", "Net", WifiClientSecurity::Wpa2, 10, true, true),
        sample_profile("alpha", "Net", WifiClientSecurity::Wpa2, 10, true, true),
    ];

    let chosen = choose_profile(&profiles, &networks, "wlan0", &state, now).unwrap();
    assert_eq!(chosen.id, "alpha");
}

#[test]
fn test_choose_profile_retry_delay_backoff() {
    let now = Instant::now();
    let mut state = AutoconnectState::default();
    let networks = vec![sample_network("Net", WpaSupplicantScanSecurity::Open)];
    let profiles = vec![sample_profile(
        "p1",
        "Net",
        WifiClientSecurity::Open,
        10,
        true,
        false,
    )];

    // Recent attempt (30 seconds ago) -> skipped
    state
        .attempts
        .entry("wlan0".to_string())
        .or_default()
        .insert("p1".to_string(), now - Duration::from_secs(30));
    assert!(choose_profile(&profiles, &networks, "wlan0", &state, now).is_none());

    // Old attempt (121 seconds ago) -> chosen
    state
        .attempts
        .get_mut("wlan0")
        .unwrap()
        .insert("p1".to_string(), now - Duration::from_secs(121));
    assert!(choose_profile(&profiles, &networks, "wlan0", &state, now).is_some());
}

#[test]
fn test_autoconnect_state_suspend_and_resume() {
    let mut state = AutoconnectState::default();
    state
        .attempts
        .entry("wlan0".to_string())
        .or_default()
        .insert("p1".to_string(), Instant::now());
    state.suspend("wlan0");
    assert!(state.suspended.contains("wlan0"));

    state.resume("wlan0");
    assert!(!state.suspended.contains("wlan0"));
    assert!(state.connecting_since.contains_key("wlan0"));
    assert!(!state.attempts.contains_key("wlan0"));
}
