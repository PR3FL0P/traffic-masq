//! Keep generated hardware identities stable while a connection is active.
use std::collections::BTreeMap;

use anyhow::{Context, Result};
use traffic_masq_protocol::MacAddr;

use super::InterfaceManager;
use crate::config::{InterfaceConfig, InterfaceRole};

#[derive(Debug, Clone, Default)]
pub(crate) struct MacSessions {
    sessions: BTreeMap<String, Session>,
    restored: BTreeMap<String, MacAddr>,
    previews: BTreeMap<(String, u32, String), [u8; 32]>,
}

#[derive(Debug, Clone)]
struct Session {
    index: u32,
    seed: [u8; 32],
    key: String,
    carrier_down_count: Option<u64>,
    carrier: Option<bool>,
    restored: Option<(String, MacAddr)>,
}

impl MacSessions {
    fn select(
        &mut self,
        name: &str,
        index: u32,
        config: &InterfaceConfig,
        carrier: Option<bool>,
    ) -> MacAddr {
        self.select_connection(name, index, config, carrier, None)
    }

    fn identity_key(config: &InterfaceConfig) -> String {
        format!(
            "{:?}|{:?}|{:?}",
            config.role,
            config.ipv4,
            config
                .wifi
                .as_ref()
                .map(|wifi| &wifi.ssid)
                .or_else(|| config.wifi_client.as_ref().map(|wifi| &wifi.ssid))
        )
    }

    fn select_connection(
        &mut self,
        name: &str,
        index: u32,
        config: &InterfaceConfig,
        carrier: Option<bool>,
        carrier_down_count: Option<u64>,
    ) -> MacAddr {
        use sha2::{Digest, Sha256};
        let key = Self::identity_key(config);
        let seed = self.previews.remove(&(name.to_owned(), index, key.clone()));
        let session = self
            .sessions
            .entry(name.to_owned())
            .or_insert_with(|| Session {
                index,
                key: key.clone(),
                carrier_down_count,
                seed: seed.unwrap_or_else(rand::random),
                carrier,
                restored: None,
            });
        if session.index != index
            || session.key != key
            || (config.role == InterfaceRole::Input
                && carrier == Some(true)
                && carrier_down_count
                    .zip(session.carrier_down_count)
                    .is_some_and(|(now, previous)| now != previous))
            || (config.role == InterfaceRole::Input
                && carrier_down_count.is_none()
                && session.carrier == Some(false)
                && carrier == Some(true))
        {
            session.index = index;
            session.key = key.clone();
            session.seed = seed.unwrap_or_else(rand::random);
            session.restored = None;
        }
        if carrier != Some(false) && carrier_down_count.is_some() {
            session.carrier_down_count = carrier_down_count;
        }
        if carrier.is_some() {
            session.carrier = carrier;
        }
        if let Some(address) = self.restored.remove(name) {
            session.restored = Some((key.clone(), address));
        }
        if let Some((saved_key, address)) = &session.restored {
            if saved_key == &key {
                return *address;
            }
        }
        let mut hash = Sha256::new();
        hash.update(session.seed);
        hash.update(key.as_bytes());
        let digest = hash.finalize();
        let mut address = [0; 6];
        address.copy_from_slice(&digest[..6]);
        address[0] = (address[0] & 0xfc) | 0x02;
        MacAddr::new(address)
    }

    fn preview(&mut self, name: &str, index: u32, config: &InterfaceConfig) -> MacAddr {
        // Reserve a seed for a new device without replacing an active session.
        // Preview and apply must agree, but preview must not consume rollback
        // state or observe a carrier transition.
        if self.sessions.get(name).is_none_or(|session| {
            session.index != index || session.key != Self::identity_key(config)
        }) {
            self.previews
                .entry((name.to_owned(), index, Self::identity_key(config)))
                .or_insert_with(rand::random);
        }
        let mut preview = self.clone();
        preview.restored.remove(name);
        preview.select(name, index, config, None)
    }

    pub(super) fn restore(&mut self, name: &str, address: MacAddr) {
        self.restored.insert(name.to_owned(), address);
    }
}

async fn carrier_down_count(name: &str) -> Option<u64> {
    tokio::fs::read_to_string(
        std::path::Path::new("/sys/class/net")
            .join(name)
            .join("carrier_down_count"),
    )
    .await
    .ok()?
    .trim()
    .parse()
    .ok()
}

impl InterfaceManager {
    // Called while the interface is down, before bringing it back up. Exclude
    // our own administrative disconnect from the next connection observation.
    pub(super) async fn acknowledge_mac_disconnect(&self, name: &str) {
        let count = carrier_down_count(name).await;
        if let Some(session) = self.mac_sessions.lock().await.sessions.get_mut(name) {
            session.carrier_down_count = count;
            session.carrier = None;
        }
    }

    pub(crate) async fn bind_restored_mac_session(
        &self,
        name: &str,
        index: u32,
        config: &InterfaceConfig,
    ) {
        if config.randomize_mac && config.wifi_client.is_none() {
            let mut sessions = self.mac_sessions.lock().await;
            if sessions.restored.contains_key(name) {
                sessions.select(name, index, config, None);
            }
        }
    }

    pub(crate) async fn reset_mac_session(&self, name: &str) {
        let mut sessions = self.mac_sessions.lock().await;
        sessions.sessions.remove(name);
        sessions.restored.remove(name);
        sessions
            .previews
            .retain(|(interface, _, _), _| interface != name);
    }

    /// Wi-Fi stations use supplicant's per-connection identity policy. Other
    /// interfaces retain one generated identity until their connection changes.
    pub(crate) async fn target_mac(
        &self,
        name: &str,
        config: &InterfaceConfig,
    ) -> Result<Option<MacAddr>> {
        self.resolve_mac(name, config, true).await
    }

    pub(super) async fn planned_mac(
        &self,
        name: &str,
        config: &InterfaceConfig,
    ) -> Result<Option<MacAddr>> {
        // A read-only preview must never advance the active connection's seed.
        self.resolve_mac(name, config, false).await
    }

    async fn resolve_mac(
        &self,
        name: &str,
        config: &InterfaceConfig,
        observe_connection: bool,
    ) -> Result<Option<MacAddr>> {
        config.validate(name)?;
        if !config.randomize_mac || config.wifi_client.is_some() {
            return Ok(config.mac_address);
        }
        let links = self.provider.list_interfaces().await?;
        let Some(link) = links.iter().find(|link| link.name == name) else {
            if observe_connection {
                self.reset_mac_session(name).await;
            }
            anyhow::bail!("interface {name} is absent");
        };
        self.provider
            .mac_address(name)
            .await?
            .context("interface does not support Ethernet MAC addressing")?;
        let carrier =
            if observe_connection && config.role == InterfaceRole::Input && !link.is_wireless {
                tokio::fs::read_to_string(
                    std::path::Path::new("/sys/class/net")
                        .join(name)
                        .join("carrier"),
                )
                .await
                .ok()
                .and_then(|value| match value.trim() {
                    "0" => Some(false),
                    "1" => Some(true),
                    _ => None,
                })
            } else {
                None
            };
        let down_count =
            if observe_connection && config.role == InterfaceRole::Input && !link.is_wireless {
                carrier_down_count(name).await
            } else {
                None
            };
        let mut sessions = self.mac_sessions.lock().await;
        Ok(Some(if observe_connection {
            sessions.select_connection(name, link.index, config, carrier, down_count)
        } else {
            sessions.preview(name, link.index, config)
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(role: &str) -> InterfaceConfig {
        serde_json::from_value(
            serde_json::json!({"role": role, "managed": true, "randomize_mac": true}),
        )
        .unwrap()
    }

    #[test]
    fn short_disconnect_between_passes_rotates_once() {
        let mut sessions = MacSessions::default();
        let config = config("input");
        let first = sessions.select_connection("eth0", 1, &config, Some(true), Some(3));
        let next = sessions.select_connection("eth0", 1, &config, Some(true), Some(4));
        assert_ne!(next, first);
        assert_eq!(
            sessions.select_connection("eth0", 1, &config, Some(true), Some(4)),
            next
        );
        let session = sessions.sessions.get_mut("eth0").unwrap();
        session.carrier_down_count = Some(5);
        session.carrier = None;
        assert_eq!(
            sessions.select_connection("eth0", 1, &config, Some(false), Some(5)),
            next
        );
        assert_eq!(
            sessions.select_connection("eth0", 1, &config, Some(true), Some(5)),
            next
        );
    }

    #[test]
    fn wired_identity_rotates_on_reconnection_but_not_reconciliation() {
        let mut sessions = MacSessions::default();
        let config = config("input");
        let first = sessions.select("eth0", 1, &config, Some(true));
        assert_eq!(first.octets()[0] & 3, 2);
        assert_eq!(sessions.select("eth0", 1, &config, Some(true)), first);
        assert_eq!(sessions.select("eth0", 1, &config, None), first);
        assert_eq!(sessions.select("eth0", 1, &config, Some(false)), first);
        let next = sessions.select("eth0", 1, &config, Some(true));
        assert_ne!(next, first);
        assert_eq!(sessions.select("eth0", 1, &config, Some(true)), next);
        assert_ne!(sessions.select("eth0", 2, &config, Some(true)), next);
    }

    #[test]
    fn output_and_preview_identities_are_stable_and_rollback_restores_identity() {
        let mut sessions = MacSessions::default();
        let mut config = config("output");
        config.ipv4 = Some("192.168.1.1/24".parse().unwrap());
        let first = sessions.select("lan0", 1, &config, Some(true));
        assert_eq!(sessions.select("lan0", 1, &config, Some(false)), first);
        let mut preview = config.clone();
        preview.ipv4 = Some("192.168.2.1/24".parse().unwrap());
        let proposed = sessions.preview("lan0", 1, &preview);
        assert_eq!(sessions.preview("lan0", 1, &preview), proposed);
        assert_eq!(sessions.select("lan0", 1, &config, Some(true)), first);
        assert_eq!(sessions.select("lan0", 1, &preview, Some(true)), proposed);
        let returned = sessions.select("lan0", 1, &config, Some(true));
        assert_ne!(returned, first);
        assert_ne!(returned, proposed);
        assert_eq!(sessions.select("lan0", 1, &config, Some(true)), returned);
        sessions.restore("lan0", first);
        assert_eq!(sessions.select("lan0", 1, &config, None), first);
    }
    #[test]
    fn previews_preserve_rollback_and_carrier_state() {
        let mut sessions = MacSessions::default();
        let original = config("input");
        let first = sessions.select("eth0", 1, &original, Some(false));
        sessions.restore("eth0", first);
        let mut proposal = original.clone();
        proposal.ipv4 = Some("192.0.2.1/24".parse().unwrap());
        let preview = sessions.preview("eth0", 1, &proposal);
        assert_eq!(sessions.preview("eth0", 1, &proposal), preview);
        assert_eq!(sessions.restored.get("eth0"), Some(&first));
        assert_eq!(sessions.sessions["eth0"].carrier, Some(false));
        assert_eq!(sessions.select("eth0", 1, &original, Some(false)), first);
        assert_eq!(sessions.preview("eth0", 1, &proposal), preview);
        assert_eq!(sessions.select("eth0", 1, &original, None), first);
        assert_ne!(sessions.select("eth0", 1, &original, Some(true)), first);
    }

    #[test]
    fn preview_reserves_the_address_without_replacing_a_live_device() {
        let mut sessions = MacSessions::default();
        let config = config("output");
        let preview = sessions.preview("lan0", 1, &config);
        assert!(sessions.sessions.is_empty());
        assert_eq!(sessions.preview("lan0", 1, &config), preview);
        assert_eq!(sessions.select("lan0", 1, &config, None), preview);
        let replacement = sessions.preview("lan0", 2, &config);
        assert_eq!(sessions.sessions["lan0"].index, 1);
        assert_eq!(sessions.select("lan0", 1, &config, None), preview);
        assert_eq!(sessions.select("lan0", 2, &config, None), replacement);
    }
}
