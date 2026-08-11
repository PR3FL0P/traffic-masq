use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::wifi::ctrl_transport::{self, CtrlSocket, EventClient};

pub use crate::wifi::ctrl_transport::{CtrlError, MacAddr, MacAddrParseError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WpaSupplicantScanSecurity {
    Open,
    Wpa2Psk,
    Wpa3Sae,
    Wpa2Wpa3Transition,
    EnterpriseOrUnsupported,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WpaSupplicantScanResult {
    pub bssid: MacAddr,

    pub frequency_mhz: u32,
    pub signal_dbm: i32,
    pub ssid: String,

    pub raw_flags: String,
    pub security: WpaSupplicantScanSecurity,
}

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
            let ssid = fields.next()?.to_string();
            let security = classify_scan_security(&raw_flags);
            Some(WpaSupplicantScanResult {
                bssid,
                frequency_mhz,
                signal_dbm,
                ssid,
                raw_flags,
                security,
            })
        })
        .collect()
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
    let ssid = raw.get("ssid").cloned();

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
        Ok(parse_scan_results(&self.request("SCAN_RESULTS").await?))
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

pub struct WpaSupplicantEventClient(EventClient<WpaSupplicantEvent>);

impl WpaSupplicantEventClient {
    pub async fn attach(
        ctrl_path: &Path,
        timeout: Duration,
    ) -> Result<(Self, broadcast::Receiver<WpaSupplicantEvent>), CtrlError> {
        let (inner, receiver) =
            EventClient::attach(ctrl_path, timeout, WpaSupplicantEvent::parse).await?;
        Ok((Self(inner), receiver))
    }

    pub async fn close(self) {
        self.0.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            WpaSupplicantEvent::parse(
                "<3>CTRL-EVENT-DISCONNECTED bssid=02:00:00:00:00:01 reason=3"
            ),
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
}
