use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::config::WifiClientSecurity;
use crate::wifi::render::{derive_psk, hex_encode, Line, WifiDigest};
use crate::wifi::secret::WifiPassphrase;
use crate::wifi::WifiClientSpec;

const CLIENT_DIGEST_TAG: &[u8] = b"wpa_supplicant";

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ClientRenderError {
    #[error("{security:?} requires a passphrase, but none is available for {interface}")]
    PassphraseRequired {
        interface: String,
        security: WifiClientSecurity,
    },

    #[error("an open network on {interface} was given a passphrase")]
    PassphraseNotApplicable { interface: String },

    #[error("Wi-Fi client specification for {interface} is invalid: {message}")]
    InvalidSpec { interface: String, message: String },
}

pub struct ClientRenderInput<'a> {
    pub spec: &'a WifiClientSpec,

    pub ctrl_interface: &'a Path,

    pub ctrl_interface_group: Option<u32>,
    pub passphrase: Option<&'a WifiPassphrase>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedClientConfig {
    pub text: String,

    pub config_digest: WifiDigest,

    pub key_digest: WifiDigest,

    pub path: PathBuf,
}

pub fn render_wpa_supplicant_config(
    input: ClientRenderInput<'_>,
) -> Result<RenderedClientConfig, ClientRenderError> {
    let spec = input.spec;
    spec.validate()
        .map_err(|error| ClientRenderError::InvalidSpec {
            interface: spec.interface.clone(),
            message: format!("{error:#}"),
        })?;

    match (spec.requires_passphrase(), input.passphrase) {
        (true, None) => {
            return Err(ClientRenderError::PassphraseRequired {
                interface: spec.interface.clone(),
                security: spec.security,
            })
        }
        (false, Some(_)) => {
            return Err(ClientRenderError::PassphraseNotApplicable {
                interface: spec.interface.clone(),
            })
        }
        _ => {}
    }

    let psk = input
        .passphrase
        .map(|passphrase| derive_psk(passphrase, &spec.ssid));

    let mut globals = Vec::new();
    globals.push(Line::plain(
        "ctrl_interface",
        match input.ctrl_interface_group {
            Some(group) => format!("DIR={} GROUP={group}", input.ctrl_interface.display()),
            None => input.ctrl_interface.display().to_string(),
        },
    ));
    globals.push(Line::plain("update_config", 0));
    if spec.randomize_mac {
        globals.push(Line::plain("mac_addr", 1));
        globals.push(Line::plain("preassoc_mac_addr", 1));
        globals.push(Line::plain("rand_addr_lifetime", 0));
    }
    if let Some(country) = &spec.country_code {
        globals.push(Line::plain("country", country));
    }

    let mut network = Vec::new();

    network.push(Line::plain("ssid", hex_encode(spec.ssid.as_bytes())));

    network.push(Line::plain("scan_ssid", 1));
    append_security_lines(
        &mut network,
        spec,
        input.passphrase,
        psk.as_ref().map(|psk| psk.as_slice()),
    );

    let mut text = String::new();
    let mut digest_source = String::new();
    for line in &globals {
        let _ = writeln!(text, "{}={}", line.key(), line.value());
        let _ = writeln!(digest_source, "{}={}", line.key(), line.digest_value());
    }
    text.push_str("\nnetwork={\n");
    digest_source.push_str("network={\n");
    for line in &network {
        let _ = writeln!(text, "\t{}={}", line.key(), line.value());
        let _ = writeln!(digest_source, "\t{}={}", line.key(), line.digest_value());
    }
    text.push_str("}\n");
    digest_source.push_str("}\n");

    let key_digest = match &psk {
        Some(psk) => WifiDigest::of(&[CLIENT_DIGEST_TAG, b"psk", psk]),
        None => WifiDigest::of(&[CLIENT_DIGEST_TAG, b"open"]),
    };

    // Static MAC is applied through netlink before supplicant starts. Keep it
    // in the process identity even though it is not a supplicant directive.
    let config_digest = match spec.mac_address {
        Some(mac) => WifiDigest::of(&[CLIENT_DIGEST_TAG, digest_source.as_bytes(), &mac.octets()]),
        None => WifiDigest::of(&[CLIENT_DIGEST_TAG, digest_source.as_bytes()]),
    };
    Ok(RenderedClientConfig {
        config_digest,
        key_digest,
        path: config_path(input.ctrl_interface, &spec.interface),
        text,
    })
}

pub fn config_path(runtime_dir: &Path, interface: &str) -> PathBuf {
    runtime_dir.join(format!("{interface}.conf"))
}

pub fn scan_config_path(runtime_dir: &Path, interface: &str) -> PathBuf {
    runtime_dir.join(format!("{interface}-scan.conf"))
}

pub fn render_scan_config(ctrl_interface: &Path) -> String {
    format!(
        "ctrl_interface={}\nupdate_config=0\n",
        ctrl_interface.display()
    )
}

fn append_security_lines(
    lines: &mut Vec<Line>,
    spec: &WifiClientSpec,
    passphrase: Option<&WifiPassphrase>,
    psk: Option<&[u8]>,
) {
    match spec.security {
        WifiClientSecurity::Open => {
            lines.push(Line::plain("key_mgmt", "NONE"));
        }

        WifiClientSecurity::Wpa2 => {
            lines.push(Line::plain("proto", "RSN"));
            lines.push(Line::plain("key_mgmt", "WPA-PSK"));
            lines.push(Line::plain("pairwise", "CCMP"));
            if let Some(psk) = psk {
                lines.push(Line::secret("psk", hex_encode(psk)));
            }
        }
        WifiClientSecurity::Wpa3 | WifiClientSecurity::Wpa2Wpa3 => {
            lines.push(Line::plain("proto", "RSN"));
            let transition = spec.security == WifiClientSecurity::Wpa2Wpa3;
            lines.push(Line::plain(
                "key_mgmt",
                if transition { "SAE WPA-PSK" } else { "SAE" },
            ));
            if transition {
                if let Some(psk) = psk {
                    lines.push(Line::secret("psk", hex_encode(psk)));
                }
            }
            lines.push(Line::plain("pairwise", "CCMP"));

            lines.push(Line::plain("ieee80211w", if transition { 1 } else { 2 }));
            // sae_password is STR_KEY in wpa_supplicant/config.c: the string
            // parser decodes an unquoted hex value to the original bytes.
            if let Some(passphrase) = passphrase {
                lines.push(Line::secret(
                    "sae_password",
                    hex_encode(passphrase.expose().as_bytes()),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests;
