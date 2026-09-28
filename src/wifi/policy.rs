//! Radio admission shared by API transactions, autoconnect and reconciliation.
//! Concurrent AP/STA VIFs are deliberately unsupported, matching router provisioning.
use crate::config::{InterfaceConfig, NetworkConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiRadioRole {
    Ap,
    Client,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("AP {ap_interface} and client {client_interface} share wireless PHY {phy}; concurrent AP/STA on one radio is unsupported")]
pub struct WifiRadioConflict {
    pub phy: String,
    pub ap_interface: String,
    pub client_interface: String,
}

pub struct WifiRadioPolicy;

impl WifiRadioPolicy {
    pub fn allocations(network: &NetworkConfig) -> Vec<(&str, WifiRadioRole)> {
        network
            .interfaces
            .iter()
            .filter(|(_, config)| config.managed)
            .flat_map(|(name, config)| {
                config
                    .wifi
                    .as_ref()
                    .map(|_| (name.as_str(), WifiRadioRole::Ap))
                    .into_iter()
                    .chain(
                        config
                            .wifi_client
                            .as_ref()
                            .map(|_| (name.as_str(), WifiRadioRole::Client)),
                    )
            })
            .collect()
    }

    pub fn validate_roles<'a>(
        allocations: impl IntoIterator<Item = (&'a str, WifiRadioRole)>,
        phy_for: impl Fn(&str) -> Option<String>,
    ) -> Result<(), WifiRadioConflict> {
        let mut radios = std::collections::BTreeMap::<String, Vec<(&str, WifiRadioRole)>>::new();
        for (interface, role) in allocations {
            // Absent interfaces have no physical allocation yet. Admission is
            // repeated during runtime reconciliation when devices appear.
            let Some(phy) = phy_for(interface) else {
                continue;
            };
            let radio = radios.entry(phy.clone()).or_default();
            if let Some(&(other, other_role)) =
                radio.iter().find(|(_, other_role)| *other_role != role)
            {
                let (ap, client) = if other_role == WifiRadioRole::Ap {
                    (other, interface)
                } else {
                    (interface, other)
                };
                return Err(WifiRadioConflict {
                    phy,
                    ap_interface: ap.into(),
                    client_interface: client.into(),
                });
            }
            radio.push((interface, role));
        }
        Ok(())
    }

    pub fn validate(
        network: &NetworkConfig,
        phy_for: impl Fn(&str) -> Option<String>,
    ) -> Result<(), WifiRadioConflict> {
        Self::validate_roles(Self::allocations(network), phy_for)
    }

    pub fn validate_transition(
        network: &NetworkConfig,
        interface: &str,
        target: &InterfaceConfig,
        phy_for: impl Fn(&str) -> Option<String>,
    ) -> Result<(), WifiRadioConflict> {
        let mut candidate = network.clone();
        candidate
            .interfaces
            .insert(interface.to_owned(), target.clone());
        Self::validate(&candidate, phy_for)
    }

    pub fn validate_scan(
        network: &NetworkConfig,
        interface: &str,
        phy_for: impl Fn(&str) -> Option<String>,
    ) -> Result<(), WifiRadioConflict> {
        // A scan may launch a temporary station process. Include it even when
        // the interface has no committed station configuration yet.
        let mut allocations = Self::allocations(network);
        allocations.push((interface, WifiRadioRole::Client));
        Self::validate_roles(allocations, phy_for)
    }

    pub fn validate_system(network: &NetworkConfig) -> Result<(), WifiRadioConflict> {
        Self::validate(network, crate::netlink::wireless_phy)
    }
}

#[cfg(test)]
mod tests;
