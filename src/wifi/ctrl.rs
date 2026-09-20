use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::wifi::ctrl_transport::{self, CtrlSocket, EventClient};

pub use crate::wifi::ctrl_transport::{CtrlError, MacAddr, MacAddrParseError};

const MAX_STATION_ITERATIONS: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostapdState {
    Uninitialized,
    CountryUpdate,
    Acs,
    HtScan,
    Dfs,
    Disabled,
    Enabled,
    Other(String),
}

impl HostapdState {
    fn parse(value: &str) -> Self {
        match value {
            "UNINITIALIZED" => Self::Uninitialized,
            "COUNTRY_UPDATE" => Self::CountryUpdate,
            "ACS" => Self::Acs,
            "HT_SCAN" => Self::HtScan,
            "DFS" => Self::Dfs,
            "DISABLED" => Self::Disabled,
            "ENABLED" => Self::Enabled,
            other => Self::Other(other.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostapdStatus {
    pub state: HostapdState,
    pub ssid: Option<String>,
    pub bssid: Option<MacAddr>,
    pub channel: Option<u32>,
    pub freq: Option<u32>,
    pub num_stations: Option<u32>,
    pub raw: std::collections::BTreeMap<String, String>,
}

fn parse_status(reply: &str) -> Result<HostapdStatus, CtrlError> {
    let raw = ctrl_transport::parse_kv_lines(reply);
    let state = raw
        .get("state")
        .map(|value| HostapdState::parse(value))
        .unwrap_or_else(|| HostapdState::Other(String::new()));
    let bssid = ctrl_transport::indexed_field(&raw, "bssid")
        .map(str::parse)
        .transpose()?;
    let channel = raw.get("channel").and_then(|value| value.parse().ok());
    let freq = raw.get("freq").and_then(|value| value.parse().ok());
    let num_stations =
        ctrl_transport::indexed_field(&raw, "num_sta").and_then(|value| value.parse().ok());
    let ssid = ctrl_transport::indexed_field(&raw, "ssid").map(str::to_string);

    Ok(HostapdStatus {
        state,
        ssid,
        bssid,
        channel,
        freq,
        num_stations,
        raw,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Station {
    pub mac: MacAddr,
    pub raw: std::collections::BTreeMap<String, String>,
}

fn parse_station(reply: &str) -> Result<Station, CtrlError> {
    let mut lines = reply.lines();
    let mac_line = lines
        .next()
        .ok_or_else(|| CtrlError::MalformedReply(reply.to_string()))?;
    let mac = mac_line.parse()?;
    let raw = lines
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();
    Ok(Station { mac, raw })
}

pub struct HostapdCtrlClient {
    socket: CtrlSocket,
}

impl HostapdCtrlClient {
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

    pub async fn status(&self) -> Result<HostapdStatus, CtrlError> {
        parse_status(&self.request("STATUS").await?)
    }

    pub async fn stations(&self) -> Result<Vec<Station>, CtrlError> {
        let mut stations = Vec::new();
        let mut reply = match self.request("STA-FIRST").await {
            Ok(reply) => reply,
            Err(CtrlError::Failed) => return Ok(stations),
            Err(error) => return Err(error),
        };

        for _ in 0..MAX_STATION_ITERATIONS {
            if reply.trim().is_empty() {
                return Ok(stations);
            }
            let station = parse_station(&reply)?;
            let mac = station.mac;
            stations.push(station);

            let command = format!("STA-NEXT {mac}");
            reply = match self.request(&command).await {
                Ok(reply) => reply,
                Err(CtrlError::Failed) => return Ok(stations),
                Err(error) => return Err(error),
            };
        }
        Err(CtrlError::MalformedReply(
            "STA-NEXT never returned FAIL".to_string(),
        ))
    }

    pub async fn deauthenticate(&self, mac: MacAddr) -> Result<(), CtrlError> {
        let command = format!("DEAUTHENTICATE {mac}");
        let reply = self.request(&command).await?;
        ctrl_transport::expect_ok(&command, &reply)
    }

    pub async fn reload(&self) -> Result<(), CtrlError> {
        let reply = self.request("RELOAD").await?;
        ctrl_transport::expect_ok("RELOAD", &reply)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostapdEvent {
    ApEnabled,
    ApDisabled,
    StaConnected(MacAddr),
    StaDisconnected(MacAddr),
    Terminating,
    Other(String),
}

impl HostapdEvent {
    fn parse(raw: &str) -> Self {
        let trimmed = raw.trim_end_matches(['\n', '\r']);
        let body = ctrl_transport::strip_priority_prefix(trimmed);

        if body == "AP-ENABLED" {
            return Self::ApEnabled;
        }
        if body == "AP-DISABLED" {
            return Self::ApDisabled;
        }
        if body == "CTRL-EVENT-TERMINATING" {
            return Self::Terminating;
        }
        if let Some(mac) = body
            .strip_prefix("AP-STA-CONNECTED ")
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|mac| mac.parse().ok())
        {
            return Self::StaConnected(mac);
        }
        if let Some(mac) = body
            .strip_prefix("AP-STA-DISCONNECTED ")
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|mac| mac.parse().ok())
        {
            return Self::StaDisconnected(mac);
        }

        Self::Other(trimmed.to_string())
    }
}

pub struct HostapdEventClient(EventClient<HostapdEvent>);

impl HostapdEventClient {
    pub async fn attach(
        ctrl_path: &Path,
        timeout: Duration,
    ) -> Result<(Self, broadcast::Receiver<HostapdEvent>), CtrlError> {
        let (inner, receiver) =
            EventClient::attach(ctrl_path, timeout, HostapdEvent::parse).await?;
        Ok((Self(inner), receiver))
    }

    pub async fn close(self) {
        self.0.close().await
    }
}

#[cfg(test)]
mod tests;
