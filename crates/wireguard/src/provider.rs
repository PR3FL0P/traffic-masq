use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::{StreamExt, TryStreamExt};
use genetlink::GenetlinkHandle;
use ipnet::IpNet;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;
use netlink_packet_route::link::{LinkAttribute, LinkFlag, LinkMessage};
use netlink_packet_wireguard::{
    WireguardAddressFamily, WireguardAllowedIp, WireguardAllowedIpAttr, WireguardAttribute,
    WireguardCmd, WireguardDeviceFlags, WireguardMessage, WireguardPeer, WireguardPeerAttribute,
};
use rtnetlink::{new_connection, Handle};
use thiserror::Error;
use tokio::task::JoinHandle;

use crate::wireguard::{WireGuardEndpoint, WireGuardKey, WireGuardPeerConfig};

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("failed to open netlink connection: {0}")]
    Connect(String),

    #[error("netlink request failed: {0}")]
    Netlink(String),

    #[error("interface '{0}' not found")]
    NotFound(String),

    #[error("backend operation '{command}' failed (status {status}): {stderr}")]
    CommandFailed {
        command: &'static str,
        status: String,
        stderr: String,
    },
}

#[async_trait]
pub trait VpnProvider: Send + Sync {
    async fn link_exists(&self, name: &str) -> Result<bool, ProviderError>;

    async fn create_link(
        &self,
        name: &str,
        private_key: &WireGuardKey,
        listen_port: Option<u16>,
        launch_marker: &str,
    ) -> Result<(), ProviderError>;

    async fn delete_link_if_launch_marker(
        &self,
        name: &str,
        launch_marker: &str,
    ) -> Result<bool, ProviderError>;

    async fn set_mtu(&self, name: &str, mtu: u32) -> Result<(), ProviderError>;

    async fn set_addresses(&self, name: &str, addresses: &[IpNet]) -> Result<(), ProviderError>;

    async fn set_peers(
        &self,
        name: &str,
        peers: &[WireGuardPeerConfig],
    ) -> Result<(), ProviderError>;

    async fn set_link_up(&self, name: &str) -> Result<(), ProviderError>;

    async fn set_link_down(&self, name: &str) -> Result<(), ProviderError>;

    async fn delete_link(&self, name: &str) -> Result<(), ProviderError>;

    async fn public_key(&self, name: &str) -> Result<Option<WireGuardKey>, ProviderError>;

    async fn is_up(&self, name: &str) -> Result<bool, ProviderError>;
}

#[async_trait]
impl VpnProvider for Arc<dyn VpnProvider> {
    async fn link_exists(&self, name: &str) -> Result<bool, ProviderError> {
        (**self).link_exists(name).await
    }

    async fn create_link(
        &self,
        name: &str,
        private_key: &WireGuardKey,
        listen_port: Option<u16>,
        launch_marker: &str,
    ) -> Result<(), ProviderError> {
        (**self)
            .create_link(name, private_key, listen_port, launch_marker)
            .await
    }

    async fn delete_link_if_launch_marker(
        &self,
        name: &str,
        launch_marker: &str,
    ) -> Result<bool, ProviderError> {
        (**self)
            .delete_link_if_launch_marker(name, launch_marker)
            .await
    }

    async fn set_mtu(&self, name: &str, mtu: u32) -> Result<(), ProviderError> {
        (**self).set_mtu(name, mtu).await
    }

    async fn set_addresses(&self, name: &str, addresses: &[IpNet]) -> Result<(), ProviderError> {
        (**self).set_addresses(name, addresses).await
    }

    async fn set_peers(
        &self,
        name: &str,
        peers: &[WireGuardPeerConfig],
    ) -> Result<(), ProviderError> {
        (**self).set_peers(name, peers).await
    }

    async fn set_link_up(&self, name: &str) -> Result<(), ProviderError> {
        (**self).set_link_up(name).await
    }

    async fn set_link_down(&self, name: &str) -> Result<(), ProviderError> {
        (**self).set_link_down(name).await
    }

    async fn delete_link(&self, name: &str) -> Result<(), ProviderError> {
        (**self).delete_link(name).await
    }

    async fn public_key(&self, name: &str) -> Result<Option<WireGuardKey>, ProviderError> {
        (**self).public_key(name).await
    }

    async fn is_up(&self, name: &str) -> Result<bool, ProviderError> {
        (**self).is_up(name).await
    }
}

/// Lazily opens the rtnetlink/genetlink handles used by the WireGuard provider.
///
/// Router recovery and control-plane construction should not fail merely because VPN is unused.
/// The first operation that actually needs WireGuard performs the connection and later calls reuse
/// it. A failed connection is not cached, so a later retry can recover after the kernel/runtime
/// dependency becomes available.
pub struct LazyNetlinkVpnProvider {
    inner: tokio::sync::Mutex<Option<Arc<NetlinkVpnProvider>>>,
}

impl LazyNetlinkVpnProvider {
    pub fn new() -> Self {
        Self {
            inner: tokio::sync::Mutex::new(None),
        }
    }

    async fn provider(&self) -> Result<Arc<NetlinkVpnProvider>, ProviderError> {
        let mut inner = self.inner.lock().await;
        if let Some(provider) = inner.as_ref() {
            return Ok(provider.clone());
        }
        let provider = Arc::new(NetlinkVpnProvider::connect()?);
        *inner = Some(provider.clone());
        Ok(provider)
    }
}

impl Default for LazyNetlinkVpnProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl VpnProvider for LazyNetlinkVpnProvider {
    async fn link_exists(&self, name: &str) -> Result<bool, ProviderError> {
        self.provider().await?.link_exists(name).await
    }

    async fn create_link(
        &self,
        name: &str,
        private_key: &WireGuardKey,
        listen_port: Option<u16>,
        launch_marker: &str,
    ) -> Result<(), ProviderError> {
        self.provider()
            .await?
            .create_link(name, private_key, listen_port, launch_marker)
            .await
    }

    async fn delete_link_if_launch_marker(
        &self,
        name: &str,
        launch_marker: &str,
    ) -> Result<bool, ProviderError> {
        self.provider()
            .await?
            .delete_link_if_launch_marker(name, launch_marker)
            .await
    }

    async fn set_mtu(&self, name: &str, mtu: u32) -> Result<(), ProviderError> {
        self.provider().await?.set_mtu(name, mtu).await
    }

    async fn set_addresses(&self, name: &str, addresses: &[IpNet]) -> Result<(), ProviderError> {
        self.provider().await?.set_addresses(name, addresses).await
    }

    async fn set_peers(
        &self,
        name: &str,
        peers: &[WireGuardPeerConfig],
    ) -> Result<(), ProviderError> {
        self.provider().await?.set_peers(name, peers).await
    }

    async fn set_link_up(&self, name: &str) -> Result<(), ProviderError> {
        self.provider().await?.set_link_up(name).await
    }

    async fn set_link_down(&self, name: &str) -> Result<(), ProviderError> {
        self.provider().await?.set_link_down(name).await
    }

    async fn delete_link(&self, name: &str) -> Result<(), ProviderError> {
        self.provider().await?.delete_link(name).await
    }

    async fn public_key(&self, name: &str) -> Result<Option<WireGuardKey>, ProviderError> {
        self.provider().await?.public_key(name).await
    }

    async fn is_up(&self, name: &str) -> Result<bool, ProviderError> {
        self.provider().await?.is_up(name).await
    }
}

pub struct NetlinkVpnProvider {
    rt_handle: Handle,
    genl_handle: GenetlinkHandle,
    _rt_connection_task: JoinHandle<()>,
    _genl_connection_task: JoinHandle<()>,
}

impl NetlinkVpnProvider {
    pub fn connect() -> Result<Self, ProviderError> {
        let (rt_connection, rt_handle, _) =
            new_connection().map_err(|error| ProviderError::Connect(error.to_string()))?;
        let rt_connection_task = tokio::spawn(rt_connection);

        let (genl_connection, genl_handle, _) = genetlink::new_connection()
            .map_err(|error| ProviderError::Connect(error.to_string()))?;
        let genl_connection_task = tokio::spawn(genl_connection);

        Ok(Self {
            rt_handle,
            genl_handle,
            _rt_connection_task: rt_connection_task,
            _genl_connection_task: genl_connection_task,
        })
    }

    async fn get_link(&self, name: &str) -> Option<LinkMessage> {
        let mut links = self
            .rt_handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute();
        links.try_next().await.ok().flatten()
    }

    async fn link_index(&self, name: &str) -> Result<u32, ProviderError> {
        self.get_link(name)
            .await
            .map(|link| link.header.index)
            .ok_or_else(|| ProviderError::NotFound(name.to_string()))
    }

    async fn set_device(&self, attributes: Vec<WireguardAttribute>) -> Result<(), ProviderError> {
        let genlmsg: GenlMessage<WireguardMessage> = GenlMessage::from_payload(WireguardMessage {
            cmd: WireguardCmd::SetDevice,
            attributes,
        });
        let mut nlmsg = NetlinkMessage::from(genlmsg);
        nlmsg.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut handle = self.genl_handle.clone();
        let mut response = handle
            .request(nlmsg)
            .await
            .map_err(|error| ProviderError::Netlink(error.to_string()))?;

        while let Some(result) = response.next().await {
            let packet = result.map_err(|error| ProviderError::Netlink(error.to_string()))?;
            if let NetlinkPayload::Error(error) = packet.payload {
                return Err(ProviderError::Netlink(error.to_io().to_string()));
            }
        }
        Ok(())
    }

    async fn get_device(&self, name: &str) -> Option<Vec<WireguardAttribute>> {
        let genlmsg: GenlMessage<WireguardMessage> = GenlMessage::from_payload(WireguardMessage {
            cmd: WireguardCmd::GetDevice,
            attributes: vec![WireguardAttribute::IfName(name.to_string())],
        });
        let mut nlmsg = NetlinkMessage::from(genlmsg);
        nlmsg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;

        let mut handle = self.genl_handle.clone();
        let mut response = handle.request(nlmsg).await.ok()?;

        let mut attributes = Vec::new();
        while let Some(result) = response.next().await {
            match result.ok()?.payload {
                NetlinkPayload::InnerMessage(genlmsg) => {
                    attributes.extend(genlmsg.payload.attributes);
                }
                NetlinkPayload::Error(_) => return None,
                _ => {}
            }
        }
        Some(attributes)
    }
}

fn peer_to_wireguard_peer(peer: &WireGuardPeerConfig) -> WireguardPeer {
    let mut attributes = vec![WireguardPeerAttribute::PublicKey(peer.public_key.0)];

    if let Some(preshared_key) = &peer.preshared_key {
        attributes.push(WireguardPeerAttribute::PresharedKey(preshared_key.0));
    }
    if let Some(WireGuardEndpoint::Address(endpoint)) = &peer.endpoint {
        attributes.push(WireguardPeerAttribute::Endpoint(*endpoint));
    }
    if let Some(keepalive) = peer.persistent_keepalive {
        attributes.push(WireguardPeerAttribute::PersistentKeepalive(keepalive));
    }
    if !peer.allowed_ips.is_empty() {
        let allowed_ips = peer
            .allowed_ips
            .iter()
            .map(|net| {
                let family = match net.addr() {
                    IpAddr::V4(_) => WireguardAddressFamily::Ipv4,
                    IpAddr::V6(_) => WireguardAddressFamily::Ipv6,
                };
                WireguardAllowedIp(vec![
                    WireguardAllowedIpAttr::Family(family),
                    WireguardAllowedIpAttr::IpAddr(net.addr()),
                    WireguardAllowedIpAttr::Cidr(net.prefix_len()),
                ])
            })
            .collect();
        attributes.push(WireguardPeerAttribute::AllowedIps(allowed_ips));
    }

    WireguardPeer(attributes)
}

#[async_trait]
impl VpnProvider for NetlinkVpnProvider {
    async fn link_exists(&self, name: &str) -> Result<bool, ProviderError> {
        Ok(self.get_link(name).await.is_some())
    }

    async fn create_link(
        &self,
        name: &str,
        private_key: &WireGuardKey,
        listen_port: Option<u16>,
        launch_marker: &str,
    ) -> Result<(), ProviderError> {
        // The alias is part of the same RTM_NEWLINK request as interface
        // creation. A crash can therefore never leave a newly-created link
        // without the durable launch marker needed to prove ownership.
        let mut request = self.rt_handle.link().add().wireguard(name.to_string());
        request
            .message_mut()
            .attributes
            .push(LinkAttribute::IfAlias(launch_marker.to_string()));
        request
            .execute()
            .await
            .map_err(|error| ProviderError::Netlink(error.to_string()))?;

        let mut attributes = vec![
            WireguardAttribute::IfName(name.to_string()),
            WireguardAttribute::PrivateKey(private_key.0),
        ];
        if let Some(port) = listen_port {
            attributes.push(WireguardAttribute::ListenPort(port));
        }
        self.set_device(attributes).await
    }

    async fn delete_link_if_launch_marker(
        &self,
        name: &str,
        launch_marker: &str,
    ) -> Result<bool, ProviderError> {
        let Some(link) = self.get_link(name).await else {
            return Ok(false);
        };
        let marker_matches = link.attributes.iter().any(|attribute| {
            matches!(attribute, LinkAttribute::IfAlias(value) if value == launch_marker)
        });
        if !marker_matches {
            return Ok(false);
        }

        // Delete by the index from the same link snapshot used to verify the
        // marker. This avoids re-resolving the interface by name during
        // cleanup, so an ordinary delete-and-recreate race targets the old
        // ifindex rather than the replacement interface.
        self.rt_handle
            .link()
            .del(link.header.index)
            .execute()
            .await
            .map_err(|error| ProviderError::Netlink(error.to_string()))?;
        Ok(true)
    }

    async fn set_mtu(&self, name: &str, mtu: u32) -> Result<(), ProviderError> {
        let index = self.link_index(name).await?;
        self.rt_handle
            .link()
            .set(index)
            .mtu(mtu)
            .execute()
            .await
            .map_err(|error| ProviderError::Netlink(error.to_string()))
    }

    async fn set_addresses(&self, name: &str, addresses: &[IpNet]) -> Result<(), ProviderError> {
        let index = self.link_index(name).await?;
        for address in addresses {
            self.rt_handle
                .address()
                .add(index, address.addr(), address.prefix_len())
                .execute()
                .await
                .map_err(|error| ProviderError::Netlink(error.to_string()))?;
        }
        Ok(())
    }

    async fn set_peers(
        &self,
        name: &str,
        peers: &[WireGuardPeerConfig],
    ) -> Result<(), ProviderError> {
        let mut peers = peers.to_vec();
        for peer in &mut peers {
            if let Some(endpoint) = &peer.endpoint {
                peer.endpoint = Some(WireGuardEndpoint::Address(
                    endpoint.resolve().await.map_err(|error| {
                        ProviderError::Connect(format!(
                            "WireGuard endpoint resolution failed: {error}"
                        ))
                    })?,
                ));
            }
        }
        let wg_peers = peers.iter().map(peer_to_wireguard_peer).collect();
        self.set_device(vec![
            WireguardAttribute::IfName(name.to_string()),
            WireguardAttribute::Flags(WireguardDeviceFlags::ReplacePeers),
            WireguardAttribute::Peers(wg_peers),
        ])
        .await
    }

    async fn set_link_up(&self, name: &str) -> Result<(), ProviderError> {
        let index = self.link_index(name).await?;
        self.rt_handle
            .link()
            .set(index)
            .up()
            .execute()
            .await
            .map_err(|error| ProviderError::Netlink(error.to_string()))
    }

    async fn set_link_down(&self, name: &str) -> Result<(), ProviderError> {
        let index = self.link_index(name).await?;
        self.rt_handle
            .link()
            .set(index)
            .down()
            .execute()
            .await
            .map_err(|error| ProviderError::Netlink(error.to_string()))
    }

    async fn delete_link(&self, name: &str) -> Result<(), ProviderError> {
        let index = self.link_index(name).await?;
        self.rt_handle
            .link()
            .del(index)
            .execute()
            .await
            .map_err(|error| ProviderError::Netlink(error.to_string()))
    }

    async fn public_key(&self, name: &str) -> Result<Option<WireGuardKey>, ProviderError> {
        let Some(attributes) = self.get_device(name).await else {
            return Ok(None);
        };
        Ok(attributes
            .into_iter()
            .find_map(|attribute| match attribute {
                WireguardAttribute::PublicKey(key) => Some(WireGuardKey(key)),
                _ => None,
            }))
    }

    async fn is_up(&self, name: &str) -> Result<bool, ProviderError> {
        Ok(self
            .get_link(name)
            .await
            .is_some_and(|link| link.header.flags.contains(&LinkFlag::Up)))
    }
}
