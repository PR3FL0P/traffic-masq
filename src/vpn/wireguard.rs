use std::fmt;
use std::net::SocketAddr;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ipnet::IpNet;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::vpn::{VpnDriver, VpnDriverError, VpnKind, VpnProvider};

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

#[derive(Clone)]
pub struct WireGuardPeerConfig {
    pub public_key: WireGuardKey,
    pub allowed_ips: Vec<IpNet>,
    pub endpoint: Option<SocketAddr>,
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
                raw.parse::<SocketAddr>()
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
    pub fn parse_named_profile(
        &self,
        name: &str,
        raw: &[u8],
    ) -> Result<WireGuardProfile, ProfileError> {
        parse_config(name, raw)
    }
}

pub struct WireGuardVpnDriver {
    parser: WireGuardDriver,
    store: crate::vpn::store::WireGuardProfileStore,
    provider: std::sync::Arc<dyn VpnProvider>,
}

impl WireGuardVpnDriver {
    pub fn new(
        provider: std::sync::Arc<dyn VpnProvider>,
        store: crate::vpn::store::WireGuardProfileStore,
    ) -> Self {
        Self {
            parser: WireGuardDriver,
            store,
            provider,
        }
    }
}

#[async_trait::async_trait]
impl VpnDriver for WireGuardVpnDriver {
    type Profile = WireGuardProfile;
    type OwnershipProof = WireGuardKey;

    fn kind(&self) -> VpnKind {
        VpnKind::WireGuard
    }

    fn list_profiles(
        &self,
    ) -> Result<Vec<crate::vpn::store::WireGuardProfileSummary>, VpnDriverError> {
        Ok(self.store.list()?)
    }

    fn import_profile(&self, name: &str, raw: &[u8]) -> Result<Self::Profile, VpnDriverError> {
        Ok(self.store.import(&self.parser, name, raw)?)
    }

    fn delete_profile(&self, name: &str) -> Result<(), VpnDriverError> {
        Ok(self.store.delete(name)?)
    }

    fn read_profile(&self, name: &str) -> Result<Self::Profile, VpnDriverError> {
        Ok(self.store.read(&self.parser, name)?)
    }

    async fn link_exists(&self, interface: &str) -> Result<bool, VpnDriverError> {
        Ok(self.provider.link_exists(interface).await?)
    }

    async fn is_up(&self, interface: &str) -> Result<bool, VpnDriverError> {
        Ok(self.provider.is_up(interface).await?)
    }

    async fn read_ownership_proof(
        &self,
        interface: &str,
    ) -> Result<Option<Self::OwnershipProof>, VpnDriverError> {
        Ok(self.provider.public_key(interface).await?)
    }

    async fn activate(
        &self,
        interface: &str,
        profile: &Self::Profile,
    ) -> Result<Self::OwnershipProof, VpnDriverError> {
        self.provider
            .create_link(
                interface,
                &profile.interface.private_key,
                profile.interface.listen_port,
            )
            .await?;

        let activation = async {
            self.provider
                .set_addresses(interface, &profile.interface.addresses)
                .await?;
            self.provider.set_peers(interface, &profile.peers).await?;
            self.provider.set_link_up(interface).await?;

            self.provider.public_key(interface).await?.ok_or_else(|| {
                tracing::error!(
                    interface,
                    "kernel reported no public key for the interface immediately after \
                     create_link/set_addresses/set_peers/set_link_up; refusing to report \
                     ownership (this means the interface has no private key configured, not \
                     that a foreign interface is present)"
                );
                VpnDriverError::NoOwnershipProof(interface.to_string())
            })
        }
        .await;

        match activation {
            Ok(proof) => Ok(proof),
            Err(error) => match self.provider.delete_link(interface).await {
                Ok(()) => Err(error),
                Err(cleanup) => Err(VpnDriverError::ActivationCleanupFailed {
                    interface: interface.to_string(),
                    activation: error.to_string(),
                    cleanup: cleanup.to_string(),
                }),
            },
        }
    }

    async fn deactivate(&self, interface: &str) -> Result<(), VpnDriverError> {
        self.provider.set_link_down(interface).await?;
        self.provider.delete_link(interface).await?;
        Ok(())
    }

    fn encode_ownership_proof(&self, proof: &Self::OwnershipProof) -> Vec<u8> {
        proof.0.to_vec()
    }

    fn decode_ownership_proof(&self, raw: &[u8]) -> Result<Self::OwnershipProof, VpnDriverError> {
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| VpnDriverError::InvalidOwnershipProof)?;
        Ok(WireGuardKey(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_PRIVATE_KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const VALID_PUBLIC_KEY: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    const VALID_PRESHARED_KEY: &str = "FpCyhw6bDwNTKAP1sJ8fWTlwGJ8yVCLzYIT+DP4a6D4=";

    fn valid_config() -> String {
        format!(
            "[Interface]\n\
             PrivateKey = {VALID_PRIVATE_KEY}\n\
             Address = 10.0.0.2/24, fd00::2/64\n\
             DNS = 1.1.1.1, 9.9.9.9\n\
             MTU = 1420\n\
             ListenPort = 51820\n\
             \n\
             [Peer]\n\
             PublicKey = {VALID_PUBLIC_KEY}\n\
             PresharedKey = {VALID_PRESHARED_KEY}\n\
             AllowedIPs = 0.0.0.0/0, ::/0\n\
             Endpoint = 203.0.113.1:51820\n\
             PersistentKeepalive = 25\n"
        )
    }

    #[test]
    fn valid_profile_parses_through_driver() {
        let driver = WireGuardDriver;
        let profile = driver
            .parse_named_profile("home.conf", valid_config().as_bytes())
            .expect("valid profile should parse");

        assert_eq!(profile.name, "home.conf");
        assert_eq!(profile.interface.listen_port, Some(51820));
        assert_eq!(profile.interface.addresses.len(), 2);
        assert_eq!(profile.interface.dns.len(), 2);
        assert_eq!(profile.interface.mtu, Some(1420));
        assert_eq!(profile.peers.len(), 1);
        assert_eq!(profile.peers[0].allowed_ips.len(), 2);
        assert_eq!(
            profile.peers[0].endpoint,
            Some("203.0.113.1:51820".parse().unwrap())
        );
        assert_eq!(profile.peers[0].persistent_keepalive, Some(25));
        assert!(profile.peers[0].preshared_key.is_some());
    }

    #[test]
    fn rejects_bad_base64_private_key() {
        let bad = valid_config().replace(VALID_PRIVATE_KEY, "not-valid-base64!!");
        let err = WireGuardDriver
            .parse_named_profile("home.conf", bad.as_bytes())
            .unwrap_err();
        assert_eq!(
            err,
            ProfileError::InvalidKey {
                field: "Interface.PrivateKey"
            }
        );
    }

    #[test]
    fn rejects_wrong_length_key() {
        let short_key = base64::engine::general_purpose::STANDARD.encode(b"tooshort");
        let bad = valid_config().replace(VALID_PUBLIC_KEY, &short_key);
        let err = WireGuardDriver
            .parse_named_profile("home.conf", bad.as_bytes())
            .unwrap_err();
        assert_eq!(
            err,
            ProfileError::InvalidKey {
                field: "Peer.PublicKey"
            }
        );
    }

    #[test]
    fn rejects_missing_required_field() {
        let missing_private_key =
            valid_config().replace(&format!("PrivateKey = {VALID_PRIVATE_KEY}\n"), "");
        let err = WireGuardDriver
            .parse_named_profile("home.conf", missing_private_key.as_bytes())
            .unwrap_err();
        assert_eq!(err, ProfileError::MissingInterfaceField("PrivateKey"));
    }

    #[test]
    fn rejects_missing_address() {
        let missing_address = valid_config().replace("Address = 10.0.0.2/24, fd00::2/64\n", "");
        let err = WireGuardDriver
            .parse_named_profile("home.conf", missing_address.as_bytes())
            .unwrap_err();
        assert_eq!(err, ProfileError::MissingInterfaceField("Address"));
    }

    #[test]
    fn rejects_malformed_cidr() {
        let bad_cidr = valid_config().replace(
            "Address = 10.0.0.2/24, fd00::2/64\n",
            "Address = not-an-ip/24\n",
        );
        let err = WireGuardDriver
            .parse_named_profile("home.conf", bad_cidr.as_bytes())
            .unwrap_err();
        assert_eq!(
            err,
            ProfileError::InvalidCidr {
                field: "Interface.Address",
                value: "not-an-ip/24".to_string()
            }
        );
    }

    #[test]
    fn rejects_invalid_listen_port() {
        let bad_port = valid_config().replace("ListenPort = 51820\n", "ListenPort = 99999\n");
        let err = WireGuardDriver
            .parse_named_profile("home.conf", bad_port.as_bytes())
            .unwrap_err();
        assert_eq!(err, ProfileError::InvalidListenPort("99999".to_string()));
    }

    #[test]
    fn rejects_endpoint_missing_port() {
        let bad =
            valid_config().replace("Endpoint = 203.0.113.1:51820\n", "Endpoint = 203.0.113.1\n");
        let err = WireGuardDriver
            .parse_named_profile("home.conf", bad.as_bytes())
            .unwrap_err();
        assert_eq!(
            err,
            ProfileError::InvalidEndpoint("203.0.113.1".to_string())
        );
    }

    #[test]
    fn rejects_endpoint_ipv6_without_brackets() {
        let bad =
            valid_config().replace("Endpoint = 203.0.113.1:51820\n", "Endpoint = ::1:51820\n");
        let err = WireGuardDriver
            .parse_named_profile("home.conf", bad.as_bytes())
            .unwrap_err();
        assert_eq!(err, ProfileError::InvalidEndpoint("::1:51820".to_string()));
    }

    #[test]
    fn rejects_endpoint_garbage_host() {
        let bad = valid_config().replace(
            "Endpoint = 203.0.113.1:51820\n",
            "Endpoint = not-an-endpoint\n",
        );
        let err = WireGuardDriver
            .parse_named_profile("home.conf", bad.as_bytes())
            .unwrap_err();
        assert_eq!(
            err,
            ProfileError::InvalidEndpoint("not-an-endpoint".to_string())
        );
    }

    #[test]
    fn rejects_endpoint_with_hostname_instead_of_ip() {
        let bad = valid_config().replace(
            "Endpoint = 203.0.113.1:51820\n",
            "Endpoint = vpn.example.com:51820\n",
        );
        let err = WireGuardDriver
            .parse_named_profile("home.conf", bad.as_bytes())
            .unwrap_err();
        assert_eq!(
            err,
            ProfileError::InvalidEndpoint("vpn.example.com:51820".to_string())
        );
    }

    #[test]
    fn rejects_endpoint_with_out_of_range_port() {
        let bad = valid_config().replace(
            "Endpoint = 203.0.113.1:51820\n",
            "Endpoint = 203.0.113.1:99999\n",
        );
        let err = WireGuardDriver
            .parse_named_profile("home.conf", bad.as_bytes())
            .unwrap_err();
        assert_eq!(
            err,
            ProfileError::InvalidEndpoint("203.0.113.1:99999".to_string())
        );
    }

    #[test]
    fn rejects_empty_private_key() {
        let bad = valid_config().replace(
            &format!("PrivateKey = {VALID_PRIVATE_KEY}"),
            "PrivateKey = ",
        );
        let err = WireGuardDriver
            .parse_named_profile("home.conf", bad.as_bytes())
            .unwrap_err();
        assert_eq!(
            err,
            ProfileError::InvalidKey {
                field: "Interface.PrivateKey"
            }
        );
    }

    #[test]
    fn rejects_overlong_base64_key() {
        let long_key = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 64]);
        let bad = valid_config().replace(VALID_PRIVATE_KEY, &long_key);
        let err = WireGuardDriver
            .parse_named_profile("home.conf", bad.as_bytes())
            .unwrap_err();
        assert_eq!(
            err,
            ProfileError::InvalidKey {
                field: "Interface.PrivateKey"
            }
        );
    }

    #[test]
    fn rejects_malformed_preshared_key_without_touching_public_key() {
        let bad = valid_config().replace(VALID_PRESHARED_KEY, "not-valid-base64!!");
        let err = WireGuardDriver
            .parse_named_profile("home.conf", bad.as_bytes())
            .unwrap_err();
        assert_eq!(
            err,
            ProfileError::InvalidKey {
                field: "Peer.PresharedKey"
            }
        );
    }

    #[test]
    fn rejects_invalid_persistent_keepalive() {
        let bad = valid_config().replace(
            "PersistentKeepalive = 25\n",
            "PersistentKeepalive = not-a-number\n",
        );
        let err = WireGuardDriver
            .parse_named_profile("home.conf", bad.as_bytes())
            .unwrap_err();
        assert_eq!(
            err,
            ProfileError::InvalidKeepalive("not-a-number".to_string())
        );
    }

    #[test]
    fn rejects_negative_persistent_keepalive() {
        let bad =
            valid_config().replace("PersistentKeepalive = 25\n", "PersistentKeepalive = -1\n");
        let err = WireGuardDriver
            .parse_named_profile("home.conf", bad.as_bytes())
            .unwrap_err();
        assert_eq!(err, ProfileError::InvalidKeepalive("-1".to_string()));
    }

    #[test]
    fn rejects_invalid_mtu() {
        let bad = valid_config().replace("MTU = 1420\n", "MTU = jumbo\n");
        let err = WireGuardDriver
            .parse_named_profile("home.conf", bad.as_bytes())
            .unwrap_err();
        assert_eq!(err, ProfileError::InvalidMtu("jumbo".to_string()));
    }

    #[test]
    fn rejects_invalid_dns_address() {
        let bad = valid_config().replace("DNS = 1.1.1.1, 9.9.9.9\n", "DNS = not-an-ip\n");
        let err = WireGuardDriver
            .parse_named_profile("home.conf", bad.as_bytes())
            .unwrap_err();
        assert_eq!(
            err,
            ProfileError::InvalidIpAddr {
                field: "Interface.DNS",
                value: "not-an-ip".to_string()
            }
        );
    }

    #[test]
    fn rejects_malformed_allowed_ips() {
        let bad = valid_config().replace(
            "AllowedIPs = 0.0.0.0/0, ::/0\n",
            "AllowedIPs = garbage/64\n",
        );
        let err = WireGuardDriver
            .parse_named_profile("home.conf", bad.as_bytes())
            .unwrap_err();
        assert_eq!(
            err,
            ProfileError::InvalidCidr {
                field: "Peer.AllowedIPs",
                value: "garbage/64".to_string()
            }
        );
    }

    #[test]
    fn rejects_missing_peer_public_key() {
        let bad = valid_config().replace(&format!("PublicKey = {VALID_PUBLIC_KEY}\n"), "");
        let err = WireGuardDriver
            .parse_named_profile("home.conf", bad.as_bytes())
            .unwrap_err();
        assert_eq!(err, ProfileError::MissingPeerPublicKey(0));
    }

    #[test]
    fn rejects_malformed_line_without_equals_sign() {
        let bad = valid_config().replace(
            "PersistentKeepalive = 25\n",
            "PersistentKeepalive = 25\nThisLineHasNoEquals\n",
        );
        let err = WireGuardDriver
            .parse_named_profile("home.conf", bad.as_bytes())
            .unwrap_err();
        assert_eq!(
            err,
            ProfileError::MalformedLine("ThisLineHasNoEquals".to_string())
        );
    }

    #[test]
    fn rejects_unknown_section_header() {
        let bad = format!("[Bogus]\nFoo = bar\n\n{}", valid_config());
        let err = WireGuardDriver
            .parse_named_profile("home.conf", bad.as_bytes())
            .unwrap_err();
        assert_eq!(err, ProfileError::UnknownSection("Bogus".to_string()));
    }

    #[test]
    fn rejects_non_utf8_config_bytes() {
        let mut bad = valid_config().into_bytes();
        bad.push(0xFF);
        let err = WireGuardDriver
            .parse_named_profile("home.conf", &bad)
            .unwrap_err();
        assert_eq!(err, ProfileError::InvalidEncoding);
    }

    #[test]
    fn rejects_empty_config() {
        let err = WireGuardDriver
            .parse_named_profile("home.conf", b"")
            .unwrap_err();
        assert_eq!(err, ProfileError::MissingInterfaceSection);
    }

    #[test]
    fn rejects_no_peers() {
        let no_peer =
            format!("[Interface]\nPrivateKey = {VALID_PRIVATE_KEY}\nAddress = 10.0.0.2/24\n");
        let err = WireGuardDriver
            .parse_named_profile("home.conf", no_peer.as_bytes())
            .unwrap_err();
        assert_eq!(err, ProfileError::NoPeers);
    }

    #[test]
    fn rejects_path_traversal_in_name() {
        for name in [
            "../etc/passwd.conf",
            "../../evil.conf",
            "sub/dir.conf",
            "..",
            ".",
        ] {
            let err = validate_wireguard_profile_name(name).unwrap_err();
            assert!(matches!(
                err,
                ProfileError::InvalidName(_) | ProfileError::EmptyName
            ));
        }
    }

    #[test]
    fn rejects_non_conf_extension() {
        let err = validate_wireguard_profile_name("profile.txt").unwrap_err();
        assert_eq!(err, ProfileError::InvalidName("profile.txt".to_string()));
    }

    #[test]
    fn accepts_safe_basename() {
        assert!(validate_wireguard_profile_name("my-home_profile.1.conf").is_ok());
    }

    #[test]
    fn debug_output_never_contains_secret_material() {
        let profile = WireGuardDriver
            .parse_named_profile("home.conf", valid_config().as_bytes())
            .expect("valid profile should parse");

        let debug_output = format!("{profile:?}");
        assert!(!debug_output.contains(VALID_PRIVATE_KEY));
        assert!(!debug_output.contains(VALID_PUBLIC_KEY));
        assert!(!debug_output.contains(VALID_PRESHARED_KEY));
        assert!(debug_output.contains("[REDACTED]"));

        let iface_debug = format!("{:?}", profile.interface);
        assert!(!iface_debug.contains(VALID_PRIVATE_KEY));

        let peer_debug = format!("{:?}", profile.peers[0]);
        assert!(!peer_debug.contains(VALID_PUBLIC_KEY));
        assert!(!peer_debug.contains(VALID_PRESHARED_KEY));

        assert_eq!(format!("{}", profile.interface.private_key), "[REDACTED]");
        assert_eq!(
            format!("{}", profile.peers[0].preshared_key.as_ref().unwrap()),
            "[REDACTED]"
        );

        let display_output = format!("{profile}");
        assert!(!display_output.contains(VALID_PRIVATE_KEY));
    }
}
