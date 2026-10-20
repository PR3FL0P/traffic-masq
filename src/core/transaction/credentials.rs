//! Credential preparation and compensation for interface transactions.
//! Preparation observes secrets only; apply runs after the snapshot is durable.

use crate::config::InterfaceConfig;
use crate::wifi::{
    secret::{WifiPassphrase, WifiPassphraseUpdate},
    store::{PassphraseStore, WifiCredentialRole},
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct SecretSnapshot {
    pub(super) role: WifiCredentialRole,
    pub(super) previous: Option<zeroize::Zeroizing<String>>,
}

impl SecretSnapshot {
    pub(super) fn restore(&self, state_dir: &std::path::Path, interface: &str) -> Result<()> {
        let store = PassphraseStore::for_role(state_dir, self.role);
        match &self.previous {
            Some(secret) => store.set(interface, &WifiPassphrase::new(secret.to_string())?)?,
            None => store.clear(interface)?,
        }
        Ok(())
    }
}

/// A validated role-specific edit and the secret needed to compensate it.
pub(super) struct PreparedCredentialChange {
    update: WifiPassphraseUpdate,
    store: Option<PassphraseStore>,
    pub(super) snapshot: Option<SecretSnapshot>,
}

impl PreparedCredentialChange {
    pub(super) fn prepare(
        state_dir: &Path,
        interface: &str,
        config: &InterfaceConfig,
        previous_config: Option<&InterfaceConfig>,
        update: WifiPassphraseUpdate,
    ) -> Result<Self> {
        let role = WifiCredentialRole::from_config(config);
        let previous_role = previous_config.and_then(WifiCredentialRole::from_config);
        let protected = config
            .wifi
            .as_ref()
            .is_some_and(|wifi| wifi.security.requires_passphrase())
            || config
                .wifi_client
                .as_ref()
                .is_some_and(|wifi| wifi.security.requires_passphrase());
        let explicit_file = config
            .wifi
            .as_ref()
            .and_then(|wifi| wifi.passphrase_file.as_ref())
            .or_else(|| {
                config
                    .wifi_client
                    .as_ref()
                    .and_then(|wifi| wifi.passphrase_file.as_ref())
            });
        let update = match update {
            WifiPassphraseUpdate::Keep if role.is_some() && role != previous_role => {
                anyhow::ensure!(!protected || explicit_file.is_some(),
                    "changing Wi-Fi credential role requires an explicit passphrase or passphrase_file");
                // A newly selected external file must not be shadowed by an
                // older credential left in the target role's store.
                WifiPassphraseUpdate::Clear
            }
            update => update,
        };
        // A pure Wi-Fi role removal has no target credential role, but an
        // explicit Clear still needs to address the role being removed so the
        // old secret can be journaled and restored on rollback.
        let secret_role = match (&update, role) {
            (WifiPassphraseUpdate::Clear, None) => previous_role,
            _ => role,
        };
        let store = secret_role.map(|role| PassphraseStore::for_role(state_dir, role));
        let snapshot = if matches!(&update, WifiPassphraseUpdate::Keep) {
            None
        } else {
            let store = store.as_ref().ok_or_else(|| {
                anyhow::anyhow!("a Wi-Fi secret update requires an unambiguous AP or client role")
            })?;
            Some(SecretSnapshot {
                role: secret_role.expect("credential role validated above"),
                previous: store
                    .get(interface)?
                    .map(|value| zeroize::Zeroizing::new(value.expose().to_owned())),
            })
        };
        Ok(Self {
            update,
            store,
            snapshot,
        })
    }

    pub(super) fn apply(&self, interface: &str) -> Result<()> {
        match (&self.update, self.store.as_ref()) {
            (WifiPassphraseUpdate::Keep, _) => Ok(()),
            (WifiPassphraseUpdate::Set(passphrase), Some(store)) => store
                .set(interface, passphrase)
                .map_err(anyhow::Error::from),
            (WifiPassphraseUpdate::Clear, Some(store)) => {
                store.clear(interface).map_err(anyhow::Error::from)
            }
            _ => unreachable!("secret role checked before journaling"),
        }
    }
}
