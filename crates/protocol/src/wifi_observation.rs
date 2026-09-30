//! Wi-Fi observations shared by the control API and Wi-Fi runtime.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    pub const fn octets(&self) -> [u8; 6] {
        self.0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

impl Serialize for MacAddr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacAddrParseError(String);

impl fmt::Display for MacAddrParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid MAC address {:?}", self.0)
    }
}

impl std::error::Error for MacAddrParseError {}

impl FromStr for MacAddr {
    type Err = MacAddrParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut octets = [0u8; 6];
        let mut groups = value.split(':');
        for octet in &mut octets {
            let group = groups
                .next()
                .ok_or_else(|| MacAddrParseError(value.to_string()))?;
            if group.len() != 2 {
                return Err(MacAddrParseError(value.to_string()));
            }
            *octet =
                u8::from_str_radix(group, 16).map_err(|_| MacAddrParseError(value.to_string()))?;
        }
        if groups.next().is_some() {
            return Err(MacAddrParseError(value.to_string()));
        }
        Ok(Self(octets))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Station {
    pub mac: MacAddr,
    pub raw: BTreeMap<String, String>,
}

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
    #[serde(default)]
    pub ssid_bytes: Vec<u8>,
    pub raw_flags: String,
    pub security: WpaSupplicantScanSecurity,
}
