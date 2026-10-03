use std::fmt;
use std::net::SocketAddr;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ipnet::IpNet;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, PartialEq, Eq)]
pub struct WireGuardKey(pub [u8; 32]);

impl Zeroize for WireGuardKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for WireGuardKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl WireGuardKey {
    pub fn parse(raw: &str, field: &'static str) -> Result<Self, ProfileError> {
        let trimmed = raw.trim();

        let mut decoded = Zeroizing::new(
            BASE64
                .decode(trimmed)
                .map_err(|_| ProfileError::InvalidKey { field })?,
        );
        let bytes: [u8; 32] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| ProfileError::InvalidKey { field })?;
        decoded.zeroize();
        Ok(WireGuardKey(bytes))
    }
}

impl fmt::Debug for WireGuardKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl fmt::Display for WireGuardKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

#[derive(Clone)]
pub struct WireGuardInterfaceConfig {
    pub private_key: WireGuardKey,

    pub listen_port: Option<u16>,

    pub addresses: Vec<IpNet>,

    pub dns: Vec<std::net::IpAddr>,

    pub mtu: Option<u32>,
}

impl fmt::Debug for WireGuardInterfaceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireGuardInterfaceConfig")
            .field("private_key", &"[REDACTED]")
            .field("listen_port", &self.listen_port)
            .field("addresses", &self.addresses)
            .field("dns", &self.dns)
            .field("mtu", &self.mtu)
            .finish()
    }
}

/// Endpoint syntax is validated on import; DNS is resolved at connection time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireGuardEndpoint {
    Address(SocketAddr),
    Hostname { host: String, port: u16 },
}

impl std::str::FromStr for WireGuardEndpoint {
    type Err = ProfileError;
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        if let Ok(address) = raw.parse::<SocketAddr>() {
            return Ok(Self::Address(address));
        }
        let invalid = || ProfileError::InvalidEndpoint(raw.into());
        let (host, port) = raw.rsplit_once(':').ok_or_else(invalid)?;
        let port = port.parse::<u16>().map_err(|_| invalid())?;
        if port == 0
            || host.is_empty()
            || host.len() > 253
            || host.contains(':')
            || !host
                .strip_suffix('.')
                .unwrap_or(host)
                .split('.')
                .all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                })
        {
            return Err(invalid());
        }
        Ok(Self::Hostname {
            host: host.into(),
            port,
        })
    }
}

impl WireGuardEndpoint {
    pub async fn resolve(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Address(address) => Ok(*address),
            Self::Hostname { host, port } => {
                let addresses = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    tokio::net::lookup_host((host.as_str(), *port)),
                )
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "WireGuard endpoint DNS lookup timed out",
                    )
                })??;
                let addresses: Vec<_> = addresses.collect();
                addresses
                    .iter()
                    .find(|address| address.is_ipv4())
                    .copied()
                    .or_else(|| addresses.first().copied())
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "WireGuard endpoint DNS lookup returned no addresses",
                        )
                    })
            }
        }
    }
}

#[derive(Clone)]
pub struct WireGuardPeerConfig {
    pub public_key: WireGuardKey,
    pub allowed_ips: Vec<IpNet>,
    pub endpoint: Option<WireGuardEndpoint>,
    pub persistent_keepalive: Option<u16>,

    pub preshared_key: Option<WireGuardKey>,
}

impl fmt::Debug for WireGuardPeerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireGuardPeerConfig")
            .field("public_key", &"[REDACTED]")
            .field("allowed_ips", &self.allowed_ips)
            .field("endpoint", &self.endpoint)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .field(
                "preshared_key",
                &self.preshared_key.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[derive(Clone)]
pub struct WireGuardProfile {
    pub name: String,
    pub interface: WireGuardInterfaceConfig,
    pub peers: Vec<WireGuardPeerConfig>,
}

impl fmt::Debug for WireGuardProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireGuardProfile")
            .field("name", &self.name)
            .field("interface", &self.interface)
            .field("peers", &self.peers)
            .finish()
    }
}

impl fmt::Display for WireGuardProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WireGuardProfile({})", self.name)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProfileError {
    #[error("profile name must not be empty")]
    EmptyName,

    #[error("profile name must be a plain basename ending in .conf, got: {0}")]
    InvalidName(String),

    #[error("profile config is not valid UTF-8")]
    InvalidEncoding,

    #[error("missing required [Interface] section")]
    MissingInterfaceSection,

    #[error("missing required field '{0}' in [Interface] section")]
    MissingInterfaceField(&'static str),

    #[error("invalid key in field '{field}'")]
    InvalidKey { field: &'static str },

    #[error("invalid listen port: {0}")]
    InvalidListenPort(String),

    #[error("invalid address/CIDR value '{value}' in field '{field}'")]
    InvalidCidr { field: &'static str, value: String },

    #[error("invalid IP address '{value}' in field '{field}'")]
    InvalidIpAddr { field: &'static str, value: String },

    #[error("invalid endpoint '{0}'")]
    InvalidEndpoint(String),

    #[error("invalid persistent keepalive '{0}'")]
    InvalidKeepalive(String),

    #[error("invalid MTU '{0}'")]
    InvalidMtu(String),

    #[error("peer at index {0} is missing required field 'PublicKey'")]
    MissingPeerPublicKey(usize),

    #[error("profile has no [Peer] sections")]
    NoPeers,

    #[error("unknown section header '{0}'")]
    UnknownSection(String),

    #[error("malformed line (expected 'Key = Value'): {0}")]
    MalformedLine(String),
}

/// Reject profile names that cannot safely identify a stored WireGuard profile.
pub fn validate_wireguard_profile_name(name: &str) -> Result<(), ProfileError> {
    if name.is_empty() {
        return Err(ProfileError::EmptyName);
    }

    if name.contains('/') || name.contains('\\') || name == "." || name == ".." {
        return Err(ProfileError::InvalidName(name.to_string()));
    }

    let valid_charset = name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'));

    if !valid_charset || !name.ends_with(".conf") || name == ".conf" {
        return Err(ProfileError::InvalidName(name.to_string()));
    }

    Ok(())
}

/// Parse the supported WireGuard configuration fields and reject unsupported or invalid values.
fn parse_config(name: &str, raw: &[u8]) -> Result<WireGuardProfile, ProfileError> {
    validate_wireguard_profile_name(name)?;

    let text = std::str::from_utf8(raw).map_err(|_| ProfileError::InvalidEncoding)?;

    #[derive(Default)]
    struct RawInterface {
        private_key: Option<String>,
        listen_port: Option<String>,
        addresses: Vec<String>,
        dns: Vec<String>,
        mtu: Option<String>,
    }

    #[derive(Default)]
    struct RawPeer {
        public_key: Option<String>,
        allowed_ips: Vec<String>,
        endpoint: Option<String>,
        persistent_keepalive: Option<String>,
        preshared_key: Option<String>,
    }

    enum Section {
        None,
        Interface,
        Peer,
    }

    let mut interface_raw: Option<RawInterface> = None;
    let mut peers_raw: Vec<RawPeer> = Vec::new();
    let mut section = Section::None;

    for raw_line in text.lines() {
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        if line.starts_with('[') {
            let header = line.trim_start_matches('[').trim_end_matches(']').trim();
            match header.to_ascii_lowercase().as_str() {
                "interface" => {
                    if interface_raw.is_some() {
                        return Err(ProfileError::MalformedLine(line.to_string()));
                    }
                    interface_raw = Some(RawInterface::default());
                    section = Section::Interface;
                }
                "peer" => {
                    peers_raw.push(RawPeer::default());
                    section = Section::Peer;
                }
                _ => return Err(ProfileError::UnknownSection(header.to_string())),
            }
            continue;
        }

        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| ProfileError::MalformedLine(line.to_string()))?;
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim().to_string();

        match section {
            Section::None => return Err(ProfileError::MalformedLine(line.to_string())),
            Section::Interface => {
                let iface = interface_raw
                    .as_mut()
                    .expect("Interface section state present");
                match key.as_str() {
                    "privatekey" => iface.private_key = Some(value),
                    "listenport" => iface.listen_port = Some(value),
                    "address" => iface.addresses.extend(split_csv(&value)),
                    "dns" => iface.dns.extend(split_csv(&value)),
                    "mtu" => iface.mtu = Some(value),
                    _ => {}
                }
            }
            Section::Peer => {
                let peer = peers_raw.last_mut().expect("Peer section state present");
                match key.as_str() {
                    "publickey" => peer.public_key = Some(value),
                    "allowedips" => peer.allowed_ips.extend(split_csv(&value)),
                    "endpoint" => peer.endpoint = Some(value),
                    "persistentkeepalive" => peer.persistent_keepalive = Some(value),
                    "presharedkey" => peer.preshared_key = Some(value),
                    _ => {}
                }
            }
        }
    }

    let interface_raw = interface_raw.ok_or(ProfileError::MissingInterfaceSection)?;

    let private_key_raw = interface_raw
        .private_key
        .ok_or(ProfileError::MissingInterfaceField("PrivateKey"))?;
    let private_key = WireGuardKey::parse(&private_key_raw, "Interface.PrivateKey")?;

    let listen_port = match interface_raw.listen_port {
        Some(raw) => Some(
            raw.parse::<u16>()
                .map_err(|_| ProfileError::InvalidListenPort(raw.clone()))?,
        ),
        None => None,
    };

    if interface_raw.addresses.is_empty() {
        return Err(ProfileError::MissingInterfaceField("Address"));
    }
    let addresses = interface_raw
        .addresses
        .iter()
        .map(|value| {
            value
                .parse::<IpNet>()
                .map_err(|_| ProfileError::InvalidCidr {
                    field: "Interface.Address",
                    value: value.clone(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let dns = interface_raw
        .dns
        .iter()
        .map(|value| {
            value
                .parse::<std::net::IpAddr>()
                .map_err(|_| ProfileError::InvalidIpAddr {
                    field: "Interface.DNS",
                    value: value.clone(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mtu = match interface_raw.mtu {
        Some(raw) => Some(
            raw.parse::<u32>()
                .map_err(|_| ProfileError::InvalidMtu(raw.clone()))?,
        ),
        None => None,
    };

    if peers_raw.is_empty() {
        return Err(ProfileError::NoPeers);
    }

    let mut peers = Vec::with_capacity(peers_raw.len());
    for (index, peer_raw) in peers_raw.into_iter().enumerate() {
        let public_key_raw = peer_raw
            .public_key
            .ok_or(ProfileError::MissingPeerPublicKey(index))?;
        let public_key = WireGuardKey::parse(&public_key_raw, "Peer.PublicKey")?;

        let allowed_ips = peer_raw
            .allowed_ips
            .iter()
            .map(|value| {
                value
                    .parse::<IpNet>()
                    .map_err(|_| ProfileError::InvalidCidr {
                        field: "Peer.AllowedIPs",
                        value: value.clone(),
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let endpoint = match peer_raw.endpoint {
            Some(raw) => Some(
                raw.parse::<WireGuardEndpoint>()
                    .map_err(|_| ProfileError::InvalidEndpoint(raw.clone()))?,
            ),
            None => None,
        };

        let persistent_keepalive = match peer_raw.persistent_keepalive {
            Some(raw) => Some(
                raw.parse::<u16>()
                    .map_err(|_| ProfileError::InvalidKeepalive(raw.clone()))?,
            ),
            None => None,
        };

        let preshared_key = match peer_raw.preshared_key {
            Some(raw) => Some(WireGuardKey::parse(&raw, "Peer.PresharedKey")?),
            None => None,
        };

        peers.push(WireGuardPeerConfig {
            public_key,
            allowed_ips,
            endpoint,
            persistent_keepalive,
            preshared_key,
        });
    }

    Ok(WireGuardProfile {
        name: name.to_string(),
        interface: WireGuardInterfaceConfig {
            private_key,
            listen_port,
            addresses,
            dns,
            mtu,
        },
        peers,
    })
}

fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(idx) => &line[..idx],
        None => line,
    }
}

fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|part| part.trim().to_string())
        .filter(|part| !part.is_empty())
        .collect()
}

#[derive(Debug, Default, Clone, Copy)]
pub struct WireGuardDriver;

impl WireGuardDriver {
    /// Validate the profile name and parse its configuration without applying kernel changes.
    pub fn parse_named_profile(
        &self,
        name: &str,
        raw: &[u8],
    ) -> Result<WireGuardProfile, ProfileError> {
        parse_config(name, raw)
    }
}

#[cfg(test)]
mod tests;
