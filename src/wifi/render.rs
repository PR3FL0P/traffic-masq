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
                lines.push(Line::secret("wpa_passphrase", passphrase.expose()));
            }
        }
        WifiSecurity::Wpa3 => {
            lines.push(Line::plain("wpa", 2));
            lines.push(Line::plain("wpa_key_mgmt", "SAE"));
            lines.push(Line::plain("rsn_pairwise", "CCMP"));
            lines.push(Line::plain("ieee80211w", 2));
            if let Some(passphrase) = passphrase {
                lines.push(Line::secret("wpa_passphrase", passphrase.expose()));
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
mod tests;
