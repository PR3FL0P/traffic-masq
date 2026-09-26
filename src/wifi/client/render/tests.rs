use std::collections::BTreeMap;

use super::*;

fn spec(security: WifiClientSecurity) -> WifiClientSpec {
    WifiClientSpec {
        interface: "wlan0".to_string(),
        ssid: "upstream".to_string(),
        country_code: Some("PL".to_string()),
        security,
        passphrase_file: None,
    }
}

fn passphrase() -> WifiPassphrase {
    WifiPassphrase::new("correct horse battery").expect("valid passphrase")
}

fn render(spec: &WifiClientSpec, passphrase: Option<&WifiPassphrase>) -> RenderedClientConfig {
    render_wpa_supplicant_config(ClientRenderInput {
        spec,
        ctrl_interface: Path::new("/run/traffic-masq/wpa_supplicant"),
        ctrl_interface_group: None,
        passphrase,
    })
    .expect("render succeeds")
}

fn network_directives(rendered: &str) -> BTreeMap<&str, &str> {
    rendered
        .lines()
        .skip_while(|line| !line.starts_with("network={"))
        .filter(|line| line.starts_with('\t'))
        .filter_map(|line| line.trim().split_once('='))
        .collect()
}

fn global_directives(rendered: &str) -> BTreeMap<&str, &str> {
    rendered
        .lines()
        .take_while(|line| !line.starts_with("network={"))
        .filter_map(|line| line.split_once('='))
        .collect()
}

#[test]
fn renders_a_wpa2_network_with_a_derived_key() {
    let rendered = render(&spec(WifiClientSecurity::Wpa2), Some(&passphrase()));

    let globals = global_directives(&rendered.text);
    assert_eq!(globals["update_config"], "0");
    assert_eq!(globals["country"], "PL");
    assert_eq!(
        globals["ctrl_interface"],
        "/run/traffic-masq/wpa_supplicant"
    );

    let network = network_directives(&rendered.text);
    assert_eq!(network["key_mgmt"], "WPA-PSK");
    assert_eq!(network["proto"], "RSN");
    assert_eq!(network["pairwise"], "CCMP");
    assert_eq!(network["ssid"], "757073747265616d");
    assert_eq!(network["psk"].len(), 64);
    assert!(!network.contains_key("sae_password"));

    assert!(!rendered.text.contains(passphrase().expose()));
}

#[test]
fn the_wpa2_key_is_the_ieee_80211i_derivation() {
    let spec = WifiClientSpec {
        ssid: "IEEE".to_string(),
        country_code: None,
        ..spec(WifiClientSecurity::Wpa2)
    };
    let rendered = render(
        &spec,
        Some(&WifiPassphrase::new("password").expect("valid")),
    );

    assert_eq!(
        network_directives(&rendered.text)["psk"],
        "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"
    );
}

#[test]
fn renders_a_wpa3_network_with_a_hex_encoded_sae_password() {
    let rendered = render(&spec(WifiClientSecurity::Wpa3), Some(&passphrase()));
    let network = network_directives(&rendered.text);

    assert_eq!(network["key_mgmt"], "SAE");

    assert_eq!(network["ieee80211w"], "2");

    assert!(!network.contains_key("psk"));
    assert_eq!(
        network["sae_password"],
        hex_encode(passphrase().expose().as_bytes())
    );
    assert!(!rendered.text.contains(passphrase().expose()));
}

#[test]
fn renders_an_open_network_with_no_key_material() {
    let rendered = render(&spec(WifiClientSecurity::Open), None);
    let network = network_directives(&rendered.text);

    assert_eq!(network["key_mgmt"], "NONE");
    assert!(!network.contains_key("psk"));
    assert!(!network.contains_key("sae_password"));
    assert!(!network.contains_key("ieee80211w"));
}

#[test]
fn an_ssid_that_looks_like_a_directive_stays_one_value() {
    let spec = WifiClientSpec {
        ssid: "a\" key_mgmt=NONE #".to_string(),
        ..spec(WifiClientSecurity::Wpa2)
    };
    let rendered = render(&spec, Some(&passphrase()));

    assert_eq!(network_directives(&rendered.text)["key_mgmt"], "WPA-PSK");

    assert_eq!(
        rendered.text.matches("key_mgmt=").count(),
        1,
        "{}",
        rendered.text
    );
    assert!(!rendered.text.contains('"'));
    assert_eq!(
        network_directives(&rendered.text)["ssid"],
        hex_encode(spec.ssid.as_bytes())
    );
}

#[test]
fn a_passphrase_that_looks_like_a_directive_stays_one_value() {
    let passphrase = WifiPassphrase::new("a\"b\\c key_mgmt=NONE").expect("valid");
    let rendered = render(&spec(WifiClientSecurity::Wpa3), Some(&passphrase));

    assert_eq!(network_directives(&rendered.text)["key_mgmt"], "SAE");
    assert_eq!(rendered.text.matches("key_mgmt=").count(), 1);
    assert!(!rendered.text.contains('"'));
    assert!(!rendered.text.contains('\\'));
}

#[test]
fn the_control_socket_group_uses_the_dir_group_form() {
    let rendered = render_wpa_supplicant_config(ClientRenderInput {
        spec: &spec(WifiClientSecurity::Open),
        ctrl_interface: Path::new("/run/traffic-masq/wpa_supplicant"),
        ctrl_interface_group: Some(42),
        passphrase: None,
    })
    .expect("render succeeds");

    assert_eq!(
        global_directives(&rendered.text)["ctrl_interface"],
        "DIR=/run/traffic-masq/wpa_supplicant GROUP=42"
    );
}

#[test]
fn a_missing_or_surplus_passphrase_is_refused() {
    let error = render_wpa_supplicant_config(ClientRenderInput {
        spec: &spec(WifiClientSecurity::Wpa2),
        ctrl_interface: Path::new("/run"),
        ctrl_interface_group: None,
        passphrase: None,
    })
    .expect_err("WPA2 without a passphrase cannot be rendered");
    assert!(matches!(
        error,
        ClientRenderError::PassphraseRequired { .. }
    ));

    let error = render_wpa_supplicant_config(ClientRenderInput {
        spec: &spec(WifiClientSecurity::Open),
        ctrl_interface: Path::new("/run"),
        ctrl_interface_group: None,
        passphrase: Some(&passphrase()),
    })
    .expect_err("an open network with a passphrase cannot be rendered");
    assert!(matches!(
        error,
        ClientRenderError::PassphraseNotApplicable { .. }
    ));
}

#[test]
fn an_invalid_spec_is_refused_rather_than_rendered() {
    let spec = WifiClientSpec {
        ssid: String::new(),
        ..spec(WifiClientSecurity::Open)
    };
    let error = render_wpa_supplicant_config(ClientRenderInput {
        spec: &spec,
        ctrl_interface: Path::new("/run"),
        ctrl_interface_group: None,
        passphrase: None,
    })
    .expect_err("an empty SSID cannot be rendered");
    assert!(matches!(error, ClientRenderError::InvalidSpec { .. }));
}

#[test]
fn rendering_is_deterministic_and_the_digests_track_what_changed() {
    let wpa2 = spec(WifiClientSecurity::Wpa2);
    let first = render(&wpa2, Some(&passphrase()));
    let second = render(&wpa2, Some(&passphrase()));
    assert_eq!(first.text, second.text);
    assert_eq!(first.config_digest, second.config_digest);
    assert_eq!(first.key_digest, second.key_digest);

    let other = render(
        &wpa2,
        Some(&WifiPassphrase::new("a different secret").expect("valid")),
    );
    assert_eq!(first.config_digest, other.config_digest);
    assert_ne!(first.key_digest, other.key_digest);

    let renamed = WifiClientSpec {
        ssid: "somewhere-else".to_string(),
        ..wpa2.clone()
    };
    assert_ne!(
        first.config_digest,
        render(&renamed, Some(&passphrase())).config_digest
    );
}

#[test]
fn a_client_digest_never_collides_with_an_access_point_one() {
    let client = render(&spec(WifiClientSecurity::Wpa2), Some(&passphrase()));
    let ap_style = WifiDigest::of(&[b"psk", &derive_psk(&passphrase(), "upstream")]);
    assert_ne!(client.key_digest, ap_style);
}

#[test]
fn the_config_path_sits_beside_the_control_sockets() {
    let rendered = render(&spec(WifiClientSecurity::Open), None);
    assert_eq!(
        rendered.path,
        Path::new("/run/traffic-masq/wpa_supplicant/wlan0.conf")
    );
}

#[test]
fn the_scan_config_renders_ctrl_interface_and_update_config() {
    let path = scan_config_path(Path::new("/run/wpa"), "wlan1");
    assert_eq!(path, Path::new("/run/wpa/wlan1-scan.conf"));

    let rendered = render_scan_config(Path::new("/run/wpa"));
    assert_eq!(rendered, "ctrl_interface=/run/wpa\nupdate_config=0\n");
}

#[test]
fn transition_network_offers_sae_and_psk_with_optional_pmf() {
    let rendered = render(&spec(WifiClientSecurity::Wpa2Wpa3), Some(&passphrase()));
    let network = network_directives(&rendered.text);
    assert_eq!(network["key_mgmt"], "SAE WPA-PSK");
    assert_eq!(network["ieee80211w"], "1");
    assert_eq!(network["psk"].len(), 64);
    let encoded = &network["sae_password"];
    let decoded: Vec<u8> = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    assert_eq!(decoded, passphrase().expose().as_bytes());
}
