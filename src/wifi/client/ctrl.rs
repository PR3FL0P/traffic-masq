use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::wifi::ctrl_transport::{self, CtrlSocket, EventClient, EventConnection};

pub use crate::wifi::ctrl_transport::{CtrlError, MacAddr, MacAddrParseError};

pub use traffic_masq_protocol::{WpaSupplicantScanResult, WpaSupplicantScanSecurity};

fn classify_scan_security(flags: &str) -> WpaSupplicantScanSecurity {
    let tokens: Vec<&str> = flags
        .split('[')
        .filter_map(|part| part.split_once(']').map(|(token, _)| token))
        .collect();
    let sae = tokens.iter().any(|token| token.contains("SAE"));
    let wpa2_psk = tokens
        .iter()
        .any(|token| token.starts_with("WPA2-PSK") || token.starts_with("RSN-PSK"));

    if sae && wpa2_psk {
        return WpaSupplicantScanSecurity::Wpa2Wpa3Transition;
    }
    if sae {
        return WpaSupplicantScanSecurity::Wpa3Sae;
    }
    if wpa2_psk {
        return WpaSupplicantScanSecurity::Wpa2Psk;
    }
    if tokens.iter().any(|token| {
        token.contains("EAP")
            || token.contains("802.1X")
            || token.contains("WEP")
            || token.contains("OWE")
            || token.contains("DPP")
            || token.starts_with("WPA-PSK")
    }) {
        return WpaSupplicantScanSecurity::EnterpriseOrUnsupported;
    }
    if tokens
        .iter()
        .all(|token| matches!(*token, "ESS" | "IBSS" | "WPS" | "P2P"))
    {
        WpaSupplicantScanSecurity::Open
    } else {
        WpaSupplicantScanSecurity::Unknown
    }
}

// wpa_supplicant exposes SSIDs using printf_encode, not literal UTF-8.
// Reject invalid UTF-8 rather than connecting to a different, lossy SSID.
fn decode_ssid_bytes(value: &str) -> Option<Vec<u8>> {
    let mut bytes = value.bytes();
    let mut decoded = Vec::with_capacity(value.len());
    while let Some(byte) = bytes.next() {
        if byte != b'\\' {
            decoded.push(byte);
            continue;
        }
        decoded.push(match bytes.next()? {
            b'\\' => b'\\',
            b'"' => b'"',
            b'n' => b'\n',
            b'r' => b'\r',
            b't' => b'\t',
            b'e' => 27,
            b'x' => {
                let high = (bytes.next()? as char).to_digit(16)?;
                let low = (bytes.next()? as char).to_digit(16)?;
                (high * 16 + low) as u8
            }
            _ => return None,
        });
    }
    Some(decoded)
}

fn decode_ssid(value: &str) -> Option<String> {
    String::from_utf8(decode_ssid_bytes(value)?).ok()
}

#[cfg(test)]
fn parse_scan_results(reply: &str) -> Vec<WpaSupplicantScanResult> {
    reply
        .lines()
        .filter_map(|line| {
            if line.trim().is_empty() || line.starts_with("bssid /") {
                return None;
            }
            let mut fields = line.splitn(5, '\t');
            let bssid = fields.next()?.parse().ok()?;
            let frequency_mhz = fields.next()?.parse().ok()?;
            let signal_dbm = fields.next()?.parse().ok()?;
            let raw_flags = fields.next()?.to_string();
            let ssid_bytes = decode_ssid_bytes(fields.next()?)?;
            let ssid = String::from_utf8(ssid_bytes.clone()).unwrap_or_else(|_| {
                ssid_bytes
                    .iter()
                    .map(|byte| format!("\\x{byte:02x}"))
                    .collect()
            });
            let security = classify_scan_security(&raw_flags);
            Some(WpaSupplicantScanResult {
                bssid,
                frequency_mhz,
                signal_dbm,
                ssid,
                ssid_bytes,
                raw_flags,
                security,
            })
        })
        .collect()
}

fn parse_bss(reply: &str) -> Result<(u32, WpaSupplicantScanResult), CtrlError> {
    let fields = ctrl_transport::parse_kv_lines(reply);
    let required = |key: &str| {
        fields
            .get(key)
            .ok_or_else(|| CtrlError::MalformedReply(format!("BSS missing {key}")))
    };
    let id = required("id")?
        .parse::<u32>()
        .map_err(|_| CtrlError::MalformedReply("invalid BSS id".into()))?;
    let bssid = required("bssid")?.parse()?;
    let frequency_mhz = required("freq")?
        .parse()
        .map_err(|_| CtrlError::MalformedReply("invalid BSS frequency".into()))?;
    let signal_dbm = required("level")?
        .parse()
        .map_err(|_| CtrlError::MalformedReply("invalid BSS signal".into()))?;
    let raw_flags = required("flags")?.clone();
    let ssid_bytes = decode_ssid_bytes(required("ssid")?)
        .ok_or_else(|| CtrlError::MalformedReply("invalid BSS SSID encoding".into()))?;
    let ssid = String::from_utf8(ssid_bytes.clone()).unwrap_or_else(|_| {
        ssid_bytes
            .iter()
            .map(|byte| format!("\\x{byte:02x}"))
            .collect()
    });
    Ok((
        id,
        WpaSupplicantScanResult {
            bssid,
            frequency_mhz,
            signal_dbm,
            ssid,
            ssid_bytes,
            security: classify_scan_security(&raw_flags),
            raw_flags,
        },
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WpaState {
    Disconnected,
    InterfaceDisabled,
    Inactive,
    Scanning,
    Authenticating,
    Associating,
    Associated,
    FourWayHandshake,
    GroupHandshake,
    Completed,
    Other(String),
}

impl WpaState {
    fn parse(value: &str) -> Self {
        match value {
            "DISCONNECTED" => Self::Disconnected,
            "INTERFACE_DISABLED" => Self::InterfaceDisabled,
            "INACTIVE" => Self::Inactive,
            "SCANNING" => Self::Scanning,
            "AUTHENTICATING" => Self::Authenticating,
            "ASSOCIATING" => Self::Associating,
            "ASSOCIATED" => Self::Associated,

            "4WAY_HANDSHAKE" => Self::FourWayHandshake,
            "GROUP_HANDSHAKE" => Self::GroupHandshake,
            "COMPLETED" => Self::Completed,
            other => Self::Other(other.to_string()),
        }
    }

    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Completed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WpaSupplicantStatus {
    pub wpa_state: WpaState,
    pub ssid: Option<String>,
    pub bssid: Option<MacAddr>,
    pub freq: Option<u32>,
    pub raw: std::collections::BTreeMap<String, String>,
}

fn parse_status(reply: &str) -> Result<WpaSupplicantStatus, CtrlError> {
    let raw = ctrl_transport::parse_kv_lines(reply);
    let wpa_state = raw
        .get("wpa_state")
        .map(|value| WpaState::parse(value))
        .unwrap_or_else(|| WpaState::Other(String::new()));

    let bssid = raw.get("bssid").map(|value| value.parse()).transpose()?;
    let freq = raw.get("freq").and_then(|value| value.parse().ok());
    let ssid = raw.get("ssid").and_then(|value| decode_ssid(value));

    Ok(WpaSupplicantStatus {
        wpa_state,
        ssid,
        bssid,
        freq,
        raw,
    })
}

pub struct WpaSupplicantCtrlClient {
    socket: CtrlSocket,
}

impl WpaSupplicantCtrlClient {
    pub async fn connect(ctrl_path: &Path, timeout: Duration) -> Result<Self, CtrlError> {
        Ok(Self {
            socket: CtrlSocket::connect(ctrl_path, timeout).await?,
        })
    }

    pub async fn request(&self, command: &str) -> Result<String, CtrlError> {
        self.socket.request(command).await
    }

    pub async fn ping(&self) -> Result<(), CtrlError> {
        let reply = self.request("PING").await?;
        if reply.trim_end() == "PONG" {
            Ok(())
        } else {
            Err(CtrlError::MalformedReply(reply))
        }
    }

    pub async fn status(&self) -> Result<WpaSupplicantStatus, CtrlError> {
        parse_status(&self.request("STATUS").await?)
    }

    pub async fn scan(&self) -> Result<(), CtrlError> {
        let reply = self.request("SCAN").await?;
        ctrl_transport::expect_ok("SCAN", &reply)
    }

    pub async fn scan_results(&self) -> Result<Vec<WpaSupplicantScanResult>, CtrlError> {
        const MAX_BSS: usize = 4096;
        let mut results = Vec::new();
        let mut seen = HashSet::new();
        let mut command = "BSS FIRST".to_string();
        loop {
            let reply = match self.request(&command).await {
                Ok(reply) => reply,
                Err(CtrlError::Failed) => return Ok(results),
                Err(error) => return Err(error),
            };
            if reply.trim() == "FAIL" {
                return Ok(results);
            }
            let (id, result) = parse_bss(&reply)?;
            if !seen.insert(id) {
                return Err(CtrlError::MalformedReply(format!("duplicate BSS id {id}")));
            }
            if results.len() >= MAX_BSS {
                return Err(CtrlError::MalformedReply(format!(
                    "BSS count exceeds {MAX_BSS}"
                )));
            }
            results.push(result);
            command = format!("BSS NEXT-{id}");
        }
    }

    pub async fn reconnect(&self) -> Result<(), CtrlError> {
        let reply = self.request("RECONNECT").await?;
        ctrl_transport::expect_ok("RECONNECT", &reply)
    }

    pub async fn disconnect(&self) -> Result<(), CtrlError> {
        let reply = self.request("DISCONNECT").await?;
        ctrl_transport::expect_ok("DISCONNECT", &reply)
    }

    pub async fn reassociate(&self) -> Result<(), CtrlError> {
        let reply = self.request("REASSOCIATE").await?;
        ctrl_transport::expect_ok("REASSOCIATE", &reply)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WpaSupplicantEvent {
    Connected {
        bssid: Option<MacAddr>,
    },
    Disconnected {
        bssid: Option<MacAddr>,
        reason: Option<u32>,
    },

    AuthenticationFailed {
        reason: String,
    },

    NetworkNotFound,
    ScanResults,
    Terminating,
    Other(String),
}

impl WpaSupplicantEvent {
    fn parse(raw: &str) -> Self {
        let trimmed = raw.trim_end_matches(['\n', '\r']);
        let body = ctrl_transport::strip_priority_prefix(trimmed).trim_end();

        if let Some(rest) = body.strip_prefix("CTRL-EVENT-CONNECTED") {
            let bssid = rest
                .split_whitespace()
                .skip_while(|token| *token != "to")
                .nth(1)
                .and_then(|token| token.parse().ok());
            return Self::Connected { bssid };
        }
        if let Some(rest) = body.strip_prefix("CTRL-EVENT-DISCONNECTED") {
            return Self::Disconnected {
                bssid: whitespace_field(rest, "bssid").and_then(|value| value.parse().ok()),
                reason: whitespace_field(rest, "reason").and_then(|value| value.parse().ok()),
            };
        }
        if let Some(rest) = body.strip_prefix("CTRL-EVENT-SSID-TEMP-DISABLED") {
            let reason = rest
                .rfind("reason=")
                .map(|index| rest[index + "reason=".len()..].trim().to_string())
                .unwrap_or_default();
            return Self::AuthenticationFailed { reason };
        }
        if body.starts_with("CTRL-EVENT-NETWORK-NOT-FOUND") {
            return Self::NetworkNotFound;
        }
        if body.starts_with("CTRL-EVENT-SCAN-RESULTS") {
            return Self::ScanResults;
        }
        if body.starts_with("CTRL-EVENT-TERMINATING") {
            return Self::Terminating;
        }

        Self::Other(trimmed.to_string())
    }
}

fn whitespace_field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.split_whitespace()
        .find_map(|token| token.strip_prefix(key)?.strip_prefix('='))
}

pub(crate) struct WpaSupplicantEventConnection(
    EventConnection<WpaSupplicantEvent, fn(&str) -> WpaSupplicantEvent>,
);

impl WpaSupplicantEventConnection {
    pub(crate) async fn attach(
        self,
    ) -> Result<
        (
            WpaSupplicantEventClient,
            broadcast::Receiver<WpaSupplicantEvent>,
        ),
        CtrlError,
    > {
        let (inner, receiver) = self.0.attach().await?;
        Ok((WpaSupplicantEventClient(inner), receiver))
    }
}

pub struct WpaSupplicantEventClient(EventClient<WpaSupplicantEvent>);

impl WpaSupplicantEventClient {
    /// Connect without sending ATTACH. Supervisors can prove ownership of the
    /// connected endpoint before any control command is sent.
    pub(crate) async fn connect(
        ctrl_path: &Path,
        timeout: Duration,
    ) -> Result<WpaSupplicantEventConnection, CtrlError> {
        let parse: fn(&str) -> WpaSupplicantEvent = WpaSupplicantEvent::parse;
        Ok(WpaSupplicantEventConnection(
            EventClient::connect(ctrl_path, timeout, parse).await?,
        ))
    }

    pub async fn attach(
        ctrl_path: &Path,
        timeout: Duration,
    ) -> Result<(Self, broadcast::Receiver<WpaSupplicantEvent>), CtrlError> {
        Self::connect(ctrl_path, timeout).await?.attach().await
    }

    pub async fn close(self) {
        self.0.close().await
    }
}

#[cfg(test)]
mod tests;
