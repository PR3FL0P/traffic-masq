use std::collections::BTreeMap;

use super::*;
use crate::config::{InterfaceConfig, InterfaceRole, WifiApConfig};

fn spec(security: WifiSecurity) -> WifiApSpec {
    let config = InterfaceConfig {
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some("192.168.101.1/24".parse().expect("network")),
        dhcp: None,
        dhcp_client: None,
        wifi: Some(WifiApConfig {
            ssid: "traffic-masq".to_string(),
            country_code: Some("PL".to_string()),
            band: WifiBand::Ghz2,
            channel: 6,
            channel_width: WifiChannelWidth::Ht20,
            security,
            hidden: false,
            client_isolation: false,
            max_stations: 32,
            passphrase_file: None,
        }),
        wifi_client: None,
        nat: true,
    };
    WifiApSpec::from_interface_config("wlan0", &config)
        .expect("valid")
        .expect("spec")
}

fn passphrase() -> WifiPassphrase {
    WifiPassphrase::new("correct horse battery").expect("valid passphrase")
}

fn render(spec: &WifiApSpec, passphrase: Option<&WifiPassphrase>) -> RenderedApConfig {
    render_hostapd_config(ApRenderInput {
        spec,
        ctrl_interface: Path::new("/run/traffic-masq/hostapd"),
        ctrl_interface_group: None,
        passphrase,
    })
    .expect("render")
}

fn directives(rendered: &RenderedApConfig) -> BTreeMap<&str, &str> {
    rendered
        .text
        .lines()
        .map(|line| {
            let (key, value) = line.split_once('=').expect("every line is key=value");
            (key, value)
        })
        .collect()
}

#[test]
fn renders_a_wpa2_access_point() {
    let spec = spec(WifiSecurity::Wpa2);
    let rendered = render(&spec, Some(&passphrase()));
    let directives = directives(&rendered);

    assert_eq!(directives["interface"], "wlan0");
    assert_eq!(directives["driver"], "nl80211");
    assert_eq!(directives["ctrl_interface"], "/run/traffic-masq/hostapd");
    assert_eq!(directives["hw_mode"], "g");
    assert_eq!(directives["channel"], "6");
    assert_eq!(directives["country_code"], "PL");
    assert_eq!(directives["wpa"], "2");
    assert_eq!(directives["wpa_key_mgmt"], "WPA-PSK");
    assert_eq!(directives["rsn_pairwise"], "CCMP");
    assert_eq!(directives["max_num_sta"], "32");
    assert_eq!(directives["ap_isolate"], "0");
    assert_eq!(directives["ignore_broadcast_ssid"], "0");
    assert!(rendered.text.ends_with('\n'));

    assert_eq!(
        rendered.path,
        PathBuf::from("/run/traffic-masq/hostapd/wlan0.conf")
    );
}

#[test]
fn wpa2_carries_a_derived_key_and_never_the_passphrase() {
    let spec = spec(WifiSecurity::Wpa2);
    let passphrase = passphrase();
    let rendered = render(&spec, Some(&passphrase));

    assert!(
        !rendered.text.contains(passphrase.expose()),
        "a WPA2 config must not contain the passphrase in any form"
    );
    assert!(!rendered.text.contains("wpa_passphrase"));

    let psk = directives(&rendered)["wpa_psk"];
    assert_eq!(psk.len(), 64, "a PSK is 32 bytes of hex");
    assert!(psk.bytes().all(|byte| byte.is_ascii_hexdigit()));
}

#[test]
fn derives_the_psk_from_the_802_11i_test_vector() {
    let psk = derive_psk(&WifiPassphrase::new("password").expect("valid"), "IEEE");
    assert_eq!(
        hex_encode(&psk),
        "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"
    );
}

#[test]
fn wpa3_needs_the_plaintext_and_says_so() {
    let spec = spec(WifiSecurity::Wpa3);
    let passphrase = passphrase();
    let rendered = render(&spec, Some(&passphrase));
    let directives = directives(&rendered);

    assert_eq!(directives["wpa_key_mgmt"], "SAE");
    assert_eq!(directives["ieee80211w"], "2");

    assert_eq!(directives["sae_password"], passphrase.expose());
    assert!(!directives.contains_key("wpa_psk"));
}

#[test]
fn transition_mode_serves_both_generations() {
    let spec = spec(WifiSecurity::Wpa2Wpa3);
    let passphrase = passphrase();
    let rendered = render(&spec, Some(&passphrase));
    let directives = directives(&rendered);

    assert_eq!(directives["wpa_key_mgmt"], "WPA-PSK SAE");
    assert_eq!(directives["ieee80211w"], "1");
    assert_eq!(directives["sae_require_mfp"], "1");
    assert_eq!(directives["wpa_psk"].len(), 64);
    assert_eq!(directives["sae_password"], passphrase.expose());
}

#[test]
fn an_open_access_point_carries_no_security_directives() {
    let spec = spec(WifiSecurity::Open);
    let rendered = render(&spec, None);

    for directive in [
        "wpa",
        "wpa_key_mgmt",
        "wpa_psk",
        "sae_password",
        "ieee80211w",
    ] {
        assert!(
            !rendered.text.contains(&format!("\n{directive}=")),
            "open AP must not emit {directive}"
        );
    }
}

#[test]
fn refuses_to_guess_when_security_and_key_material_disagree() {
    let secured = spec(WifiSecurity::Wpa2);
    assert_eq!(
        render_hostapd_config(ApRenderInput {
            spec: &secured,
            ctrl_interface: Path::new("/run/traffic-masq/hostapd"),
            ctrl_interface_group: None,
            passphrase: None,
        }),
        Err(RenderError::PassphraseRequired {
            interface: "wlan0".to_string(),
            security: WifiSecurity::Wpa2,
        })
    );

    let open = spec(WifiSecurity::Open);
    let passphrase = passphrase();
    assert_eq!(
        render_hostapd_config(ApRenderInput {
            spec: &open,
            ctrl_interface: Path::new("/run/traffic-masq/hostapd"),
            ctrl_interface_group: None,
            passphrase: Some(&passphrase),
        }),
        Err(RenderError::PassphraseNotApplicable {
            interface: "wlan0".to_string(),
        })
    );
}

#[test]
fn an_ssid_full_of_config_syntax_stays_inside_its_own_directive() {
    let mut spec = spec(WifiSecurity::Wpa2);

    let hostile = r#"wpa=0 #" ssid=free"#;
    spec.ssid = hostile.to_string();

    let rendered = render(&spec, Some(&passphrase()));
    let emitted = directives(&rendered);

    assert_eq!(emitted["wpa"], "2", "wpa must not have been overridden");
    assert_eq!(emitted.get("ssid"), None);
    assert_eq!(emitted["ssid2"], hex_encode(hostile.as_bytes()));

    assert!(emitted["ssid2"]
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit()));

    assert_eq!(emitted.len(), rendered.text.lines().count());
}

#[test]
fn an_ssid_containing_a_line_break_never_reaches_the_renderer() {
    let mut spec = spec(WifiSecurity::Wpa2);
    spec.ssid = "a\nwpa=0".to_string();

    let error = render_hostapd_config(ApRenderInput {
        spec: &spec,
        ctrl_interface: Path::new("/run/traffic-masq/hostapd"),
        ctrl_interface_group: None,
        passphrase: Some(&passphrase()),
    })
    .expect_err("a control character in an SSID must be refused");

    assert!(matches!(error, RenderError::InvalidSpec { .. }), "{error}");
}

#[test]
fn a_passphrase_cannot_inject_a_directive_into_the_sae_line() {
    assert!(WifiPassphrase::new("secret\nwpa=0").is_err());

    let spec = spec(WifiSecurity::Wpa3);
    let passphrase = WifiPassphrase::new("wpa=0 #comment").expect("printable ASCII");
    let rendered = render(&spec, Some(&passphrase));
    let emitted = directives(&rendered);

    assert_eq!(emitted["wpa"], "2");
    assert_eq!(emitted["sae_password"], "wpa=0 #comment");
    assert_eq!(emitted.len(), rendered.text.lines().count());
}

#[test]
fn config_digest_ignores_key_material_but_key_digest_does_not() {
    let spec = spec(WifiSecurity::Wpa2);
    let first = render(&spec, Some(&passphrase()));
    let second = render(
        &spec,
        Some(&WifiPassphrase::new("a different secret").expect("valid")),
    );

    assert_eq!(
        first.config_digest, second.config_digest,
        "the shape of the configuration did not change"
    );
    assert_ne!(
        first.key_digest, second.key_digest,
        "a passphrase change must remain detectable"
    );
}

#[test]
fn the_psk_and_therefore_the_key_digest_depend_on_the_ssid() {
    let spec = spec(WifiSecurity::Wpa2);
    let mut renamed = spec.clone();
    renamed.ssid = "traffic-masq-2".to_string();

    let first = render(&spec, Some(&passphrase()));
    let second = render(&renamed, Some(&passphrase()));

    assert_ne!(first.config_digest, second.config_digest);
    assert_ne!(
        first.key_digest, second.key_digest,
        "PBKDF2 is salted with the SSID, so the same passphrase yields a different PSK"
    );
}

#[test]
fn rendering_is_deterministic() {
    let spec = spec(WifiSecurity::Wpa2);
    let first = render(&spec, Some(&passphrase()));
    let second = render(&spec, Some(&passphrase()));
    assert_eq!(first, second);
}

#[test]
fn hidden_and_isolated_access_points_set_their_directives() {
    let mut spec = spec(WifiSecurity::Wpa2);
    spec.hidden = true;
    spec.client_isolation = true;

    let rendered = render(&spec, Some(&passphrase()));
    let emitted = directives(&rendered);
    assert_eq!(emitted["ignore_broadcast_ssid"], "1");
    assert_eq!(emitted["ap_isolate"], "1");
}

#[test]
fn ht40_picks_the_secondary_channel_side_the_primary_forces() {
    let mut spec = spec(WifiSecurity::Wpa2);
    spec.channel_width = WifiChannelWidth::Ht40;

    let mut secondary_channel_side = |channel: u8| {
        spec.channel = channel;
        let rendered = render(&spec, Some(&passphrase()));
        directives(&rendered)["ht_capab"].to_string()
    };

    assert_eq!(secondary_channel_side(1), "[HT40+]");
    assert_eq!(secondary_channel_side(11), "[HT40-]");

    spec.band = WifiBand::Ghz5;
    let mut secondary_channel_side = |channel: u8| {
        spec.channel = channel;
        let rendered = render(&spec, Some(&passphrase()));
        directives(&rendered)["ht_capab"].to_string()
    };
    assert_eq!(secondary_channel_side(36), "[HT40+]");
    assert_eq!(secondary_channel_side(40), "[HT40-]");
    assert_eq!(secondary_channel_side(149), "[HT40+]");
}

#[test]
fn vht80_pins_the_centre_of_its_block_unless_acs_chooses() {
    let mut spec = spec(WifiSecurity::Wpa2);
    spec.band = WifiBand::Ghz5;
    spec.channel_width = WifiChannelWidth::Vht80;

    spec.channel = 40;
    let rendered = render(&spec, Some(&passphrase()));
    let aligned = directives(&rendered);
    assert_eq!(aligned["ieee80211ac"], "1");
    assert_eq!(aligned["vht_oper_chwidth"], "1");
    assert_eq!(aligned["vht_oper_centr_freq_seg0_idx"], "42");

    spec.channel = 157;
    let rendered = render(&spec, Some(&passphrase()));
    assert_eq!(directives(&rendered)["vht_oper_centr_freq_seg0_idx"], "155");

    spec.channel = 0;
    let rendered = render(&spec, Some(&passphrase()));
    assert!(!directives(&rendered).contains_key("vht_oper_centr_freq_seg0_idx"));
}

#[test]
fn five_gigahertz_enables_dfs_handling() {
    let mut spec = spec(WifiSecurity::Wpa2);
    spec.band = WifiBand::Ghz5;
    spec.channel = 36;

    let rendered = render(&spec, Some(&passphrase()));
    let emitted = directives(&rendered);
    assert_eq!(emitted["hw_mode"], "a");
    assert_eq!(emitted["ieee80211d"], "1");
    assert_eq!(emitted["ieee80211h"], "1");
}

#[test]
fn a_control_group_is_emitted_only_when_requested() {
    let spec = spec(WifiSecurity::Wpa2);
    let passphrase = passphrase();
    let without = render(&spec, Some(&passphrase));
    assert!(!without.text.contains("ctrl_interface_group"));

    let with = render_hostapd_config(ApRenderInput {
        spec: &spec,
        ctrl_interface: Path::new("/run/traffic-masq/hostapd"),
        ctrl_interface_group: Some(42),
        passphrase: Some(&passphrase),
    })
    .expect("render");
    assert_eq!(directives(&with)["ctrl_interface_group"], "42");
    assert_ne!(without.config_digest, with.config_digest);
}

#[test]
fn a_digest_round_trips_through_json() {
    let rendered = render(&spec(WifiSecurity::Wpa2), Some(&passphrase()));
    let encoded = serde_json::to_string(&rendered.config_digest).expect("serialize");
    assert_eq!(encoded, format!("\"{}\"", rendered.config_digest));
    let decoded: WifiDigest = serde_json::from_str(&encoded).expect("deserialize");
    assert_eq!(decoded, rendered.config_digest);
}
