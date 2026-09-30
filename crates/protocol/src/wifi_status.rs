//! Supervised Wi-Fi status returned by the control API.

use serde::{Deserialize, Serialize};

use crate::{MacAddr, WifiApSpecView, WifiClientSpecView};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostapdStateView {
    Uninitialized,
    CountryUpdate,
    Acs,
    HtScan,
    Dfs,
    Disabled,
    Enabled,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WpaStateView {
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

impl WpaStateView {
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Completed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum WifiHealthView {
    Healthy,
    Starting,
    Retrying {
        error: String,
        attempts: u32,
        retry_in_secs: Option<u64>,
        competing_managers: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        advice: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifiApStatusView {
    pub interface: String,
    pub spec: WifiApSpecView,
    pub pid: u32,
    pub hostapd_state: HostapdStateView,
    pub num_stations: Option<u32>,
    pub health: WifiHealthView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifiClientStatusView {
    pub interface: String,
    pub spec: WifiClientSpecView,
    pub pid: u32,
    pub wpa_state: WpaStateView,
    pub bssid: Option<MacAddr>,
    pub freq: Option<u32>,
    pub health: WifiHealthView,
}
