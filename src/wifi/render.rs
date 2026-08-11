use std::fmt::{self, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::config::{vht80_center_channel, WifiBand, WifiChannelWidth, WifiSecurity};
use crate::wifi::secret::WifiPassphrase;
use crate::wifi::WifiApSpec;

const PSK_ITERATIONS: u32 = 4096;

const DIGEST_DOMAIN: &[u8] = b"traffic-masq:wifi:v1\0";

const REDACTED: &str = "<redacted>";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WifiDigest(#[serde(with = "hex_digest")] [u8; 32]);

impl WifiDigest {
    pub(crate) fn of(parts: &[&[u8]]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DIGEST_DOMAIN);
        for part in parts {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
        Self(hasher.finalize().into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for WifiDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

mod hex_digest {
    use serde::{de::Error as _, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        let mut encoded = String::with_capacity(64);
        for byte in value {
            encoded.push_str(&format!("{byte:02x}"));
        }
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() != 64 {
            return Err(D::Error::custom("expected a 64-character hex digest"));
        }
        let mut bytes = [0u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16)
                .map_err(D::Error::custom)?;
        }
        Ok(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RenderError {
    #[error("{security:?} requires a passphrase, but none is available for {interface}")]
    PassphraseRequired {
        interface: String,
        security: WifiSecurity,
    },

    #[error("an open access point on {interface} was given a passphrase")]
    PassphraseNotApplicable { interface: String },

    #[error("access point specification for {interface} is invalid: {message}")]
    InvalidSpec { interface: String, message: String },
}

pub struct ApRenderInput<'a> {
    pub spec: &'a WifiApSpec,

    pub ctrl_interface: &'a Path,

    pub ctrl_interface_group: Option<u32>,
    pub passphrase: Option<&'a WifiPassphrase>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedApConfig {
    pub text: String,

    pub config_digest: WifiDigest,

    pub key_digest: WifiDigest,

    pub path: PathBuf,
}

pub(crate) enum Line {
    Plain(String, String),
    Secret(String, String),
}

impl Line {
    pub(crate) fn plain(key: &str, value: impl fmt::Display) -> Self {
        Line::Plain(key.to_string(), value.to_string())
    }

    pub(crate) fn secret(key: &str, value: impl fmt::Display) -> Self {
        Line::Secret(key.to_string(), value.to_string())
    }

    pub(crate) fn key(&self) -> &str {
        match self {
            Line::Plain(key, _) | Line::Secret(key, _) => key,
        }
    }

    pub(crate) fn value(&self) -> &str {
        match self {
            Line::Plain(_, value) | Line::Secret(_, value) => value,
        }
    }

    pub(crate) fn digest_value(&self) -> &str {
        match self {
            Line::Plain(_, value) => value,
            Line::Secret(_, _) => REDACTED,
        }
    }
}

pub fn render_hostapd_config(input: ApRenderInput<'_>) -> Result<RenderedApConfig, RenderError> {
    let spec = input.spec;
    spec.validate().map_err(|error| RenderError::InvalidSpec {
        interface: spec.interface.clone(),
        message: format!("{error:#}"),
    })?;

    match (spec.security.requires_passphrase(), input.passphrase) {
        (true, None) => {
            return Err(RenderError::PassphraseRequired {
                interface: spec.interface.clone(),
                security: spec.security,
            })
        }
        (false, Some(_)) => {
            return Err(RenderError::PassphraseNotApplicable {
                interface: spec.interface.clone(),
            })
        }
        _ => {}
    }

    let psk = input
        .passphrase
        .map(|passphrase| derive_psk(passphrase, &spec.ssid));

    let mut lines = Vec::new();
    lines.push(Line::plain("interface", &spec.interface));
    lines.push(Line::plain("driver", "nl80211"));
    lines.push(Line::plain(
        "ctrl_interface",
        input.ctrl_interface.display(),
    ));
    if let Some(group) = input.ctrl_interface_group {
        lines.push(Line::plain("ctrl_interface_group", group));
    }

    lines.push(Line::plain("ssid2", hex_encode(spec.ssid.as_bytes())));
    lines.push(Line::plain("utf8_ssid", 1));

    if let Some(country) = &spec.country_code {
        lines.push(Line::plain("country_code", country));

        lines.push(Line::plain("ieee80211d", 1));
        if spec.band == WifiBand::Ghz5 {
            lines.push(Line::plain("ieee80211h", 1));
        }
    }

    lines.push(Line::plain(
        "hw_mode",
        match spec.band {
            WifiBand::Ghz2 => "g",
            WifiBand::Ghz5 => "a",
        },
    ));
    lines.push(Line::plain("channel", spec.channel));

    lines.push(Line::plain("ieee80211n", 1));
    match spec.channel_width {
        WifiChannelWidth::Ht20 => {}
        WifiChannelWidth::Ht40 => {
            lines.push(Line::plain("ht_capab", ht40_capability(spec)));
        }
        WifiChannelWidth::Vht80 => {
            lines.push(Line::plain("ht_capab", ht40_capability(spec)));
            lines.push(Line::plain("ieee80211ac", 1));
            lines.push(Line::plain("vht_oper_chwidth", 1));

            if let Some(center) = vht80_center_channel(spec.channel) {
                lines.push(Line::plain("vht_oper_centr_freq_seg0_idx", center));
            }
        }
    }

    lines.push(Line::plain("wmm_enabled", 1));

    lines.push(Line::plain("auth_algs", 1));
    lines.push(Line::plain("ignore_broadcast_ssid", u8::from(spec.hidden)));
    lines.push(Line::plain("ap_isolate", u8::from(spec.client_isolation)));
    lines.push(Line::plain("max_num_sta", spec.max_stations));

    append_security_lines(
        &mut lines,
        spec,
        input.passphrase,
        psk.as_ref().map(|psk| psk.as_slice()),
    );

    let mut text = String::new();
    let mut digest_source = String::new();
    for line in &lines {
        let _ = writeln!(text, "{}={}", line.key(), line.value());
        let _ = writeln!(digest_source, "{}={}", line.key(), line.digest_value());
    }

    let key_digest = match &psk {
        Some(psk) => WifiDigest::of(&[b"psk", psk]),
        None => WifiDigest::of(&[b"open"]),
    };

    Ok(RenderedApConfig {
        config_digest: WifiDigest::of(&[digest_source.as_bytes()]),
        key_digest,
        path: config_path(input.ctrl_interface, &spec.interface),
        text,
    })
}

pub fn config_path(runtime_dir: &Path, interface: &str) -> PathBuf {
    runtime_dir.join(format!("{interface}.conf"))
}

fn append_security_lines(
    lines: &mut Vec<Line>,
    spec: &WifiApSpec,
    passphrase: Option<&WifiPassphrase>,
    psk: Option<&[u8]>,
) {
    match spec.security {
        WifiSecurity::Open => {}
        WifiSecurity::Wpa2 => {
            lines.push(Line::plain("wpa", 2));
            lines.push(Line::plain("wpa_key_mgmt", "WPA-PSK"));
            lines.push(Line::plain("rsn_pairwise", "CCMP"));
            if let Some(psk) = psk {
                lines.push(Line::secret("wpa_psk", hex_encode(psk)));
            }
        }
        WifiSecurity::Wpa2Wpa3 => {
            lines.push(Line::plain("wpa", 2));
            lines.push(Line::plain("wpa_key_mgmt", "WPA-PSK SAE"));
            lines.push(Line::plain("rsn_pairwise", "CCMP"));

            lines.push(Line::plain("ieee80211w", 1));
            lines.push(Line::plain("sae_require_mfp", 1));
            if let Some(psk) = psk {
                lines.push(Line::secret("wpa_psk", hex_encode(psk)));
            }
            if let Some(passphrase) = passphrase {
                lines.push(Line::secret("sae_password", passphrase.expose()));
            }
        }
        WifiSecurity::Wpa3 => {
            lines.push(Line::plain("wpa", 2));
            lines.push(Line::plain("wpa_key_mgmt", "SAE"));
            lines.push(Line::plain("rsn_pairwise", "CCMP"));
            lines.push(Line::plain("ieee80211w", 2));
            if let Some(passphrase) = passphrase {
                lines.push(Line::secret("sae_password", passphrase.expose()));
            }
        }
    }
}

fn ht40_capability(spec: &WifiApSpec) -> &'static str {
    const ABOVE: &str = "[HT40+]";
    const BELOW: &str = "[HT40-]";

    match spec.band {
        WifiBand::Ghz2 if spec.channel == 0 || spec.channel <= 7 => ABOVE,
        WifiBand::Ghz2 => BELOW,
        WifiBand::Ghz5 if spec.channel == 0 => ABOVE,
        WifiBand::Ghz5 => {
            if (spec.channel.saturating_sub(36) / 4).is_multiple_of(2) {
                ABOVE
            } else {
                BELOW
            }
        }
    }
}

pub(crate) fn derive_psk(passphrase: &WifiPassphrase, ssid: &str) -> Zeroizing<Vec<u8>> {
    let mut psk = Zeroizing::new(vec![0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha1>(
        passphrase.expose().as_bytes(),
        ssid.as_bytes(),
        PSK_ITERATIONS,
        psk.as_mut_slice(),
    );
    psk
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(test)]
mod tests {
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
}
