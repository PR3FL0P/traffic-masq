//! Atomic, private AP profiles. Settings and credentials commit in one document.
use crate::api::model::{WifiApProfileSummary, WifiApProfileWriteRequest};
use crate::state::private_store::{valid_document_key, PrivateJsonDirectory};
use crate::wifi::{WifiApSpec, WifiPassphrase};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
struct StoredProfile {
    version: u32,
    profile: WifiApProfileWriteRequest,
}

pub struct WifiApProfileStore(PrivateJsonDirectory);
impl WifiApProfileStore {
    pub fn open(root: &std::path::Path) -> Result<Self> {
        Ok(Self(PrivateJsonDirectory::open(root, "ap-profiles")?))
    }
    fn validate(profile: &WifiApProfileWriteRequest) -> Result<()> {
        if !valid_document_key(&profile.id) {
            bail!("profile id must be 1-15 ASCII letters, digits, dots, underscores or hyphens");
        }
        let c = &profile.configuration;
        let s = &c.settings;
        WifiApSpec {
            interface: "wlan0".into(),
            ssid: s.ssid.clone(),
            country_code: s.country_code.clone(),
            band: s.band,
            channel: s.channel,
            channel_width: s.channel_width,
            security: s.security,
            hidden: s.hidden,
            client_isolation: s.client_isolation,
            max_stations: s.max_stations,
            passphrase_file: None,
        }
        .validate()?;
        if s.security.requires_passphrase() {
            WifiPassphrase::new(
                c.passphrase
                    .as_ref()
                    .context("profile requires a passphrase")?
                    .clone(),
            )?;
            if c.clear_passphrase {
                bail!("secured profile cannot clear its passphrase");
            }
        } else if c.passphrase.is_some() {
            bail!("open profile cannot contain a passphrase");
        }
        Ok(())
    }
    pub fn get(&self, id: &str) -> Result<WifiApProfileWriteRequest> {
        let bytes = Zeroizing::new(self.0.read(id)?.context("AP profile not found")?);
        let stored: StoredProfile = serde_json::from_slice(&bytes)?;
        if stored.version != 1 || stored.profile.id != id {
            bail!("invalid AP profile metadata");
        }
        Self::validate(&stored.profile)?;
        Ok(stored.profile)
    }
    pub fn list(&self) -> Result<Vec<WifiApProfileSummary>> {
        self.0
            .keys()?
            .iter()
            .map(|id| self.get(id).map(|p| summary(&p)))
            .collect()
    }
    pub fn save(&self, mut profile: WifiApProfileWriteRequest) -> Result<WifiApProfileSummary> {
        // Blank credentials preserve only this profile's secret, never another AP's.
        if profile
            .configuration
            .settings
            .security
            .requires_passphrase()
            && profile.configuration.passphrase.is_none()
            && !profile.configuration.clear_passphrase
            && self.0.read(&profile.id)?.is_some()
        {
            profile.configuration.passphrase = self.get(&profile.id)?.configuration.passphrase;
        }
        Self::validate(&profile)?;
        let result = summary(&profile);
        let id = profile.id.clone();
        let bytes = Zeroizing::new(serde_json::to_vec(&StoredProfile {
            version: 1,
            profile,
        })?);
        self.0.write(&id, &bytes)?;
        Ok(result)
    }
    pub fn delete(&self, id: &str) -> Result<()> {
        self.0.remove(id)?;
        Ok(())
    }
}
fn summary(p: &WifiApProfileWriteRequest) -> WifiApProfileSummary {
    WifiApProfileSummary {
        id: p.id.clone(),
        settings: p.configuration.settings.clone(),
        configure_dhcp: p.configuration.configure_dhcp,
        has_passphrase: p.configuration.passphrase.is_some(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::model::{ProvisionWifiAccessPointRequest, WifiEditRequest};
    use crate::config::WifiSecurity;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn profile() -> WifiApProfileWriteRequest {
        WifiApProfileWriteRequest {
            id: "guest".into(),
            configuration: ProvisionWifiAccessPointRequest {
                settings: WifiEditRequest {
                    ssid: "Guest".into(),
                    country_code: Some("UA".into()),
                    band: Default::default(),
                    channel: 6,
                    channel_width: Default::default(),
                    security: WifiSecurity::Wpa2,
                    hidden: false,
                    client_isolation: true,
                    max_stations: 16,
                },
                passphrase: Some("guest-secret".into()),
                clear_passphrase: false,
                configure_dhcp: true,
            },
        }
    }
    #[test]
    fn profiles_survive_reopen_preserve_secrets_and_return_only_metadata() {
        let root = tempfile::tempdir().unwrap();
        let store = WifiApProfileStore::open(root.path()).unwrap();
        let saved = store.save(profile()).unwrap();
        assert!(saved.has_passphrase);
        assert!(!serde_json::to_string(&saved)
            .unwrap()
            .contains("guest-secret"));
        assert!(!format!("{:?}", profile()).contains("guest-secret"));
        let store = WifiApProfileStore::open(root.path()).unwrap();
        let mut update = profile();
        update.configuration.passphrase = None;
        update.configuration.settings.channel = 11;
        store.save(update).unwrap();
        let loaded = store.get("guest").unwrap();
        assert_eq!(loaded.configuration.settings.channel, 11);
        assert_eq!(
            loaded.configuration.passphrase.as_deref(),
            Some("guest-secret")
        );
        assert_eq!(
            std::fs::metadata(root.path().join("ap-profiles/guest.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(root.path().join("ap-profiles"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        store.delete("guest").unwrap();
        assert!(store.list().unwrap().is_empty());
    }
    #[test]
    fn failed_updates_preserve_previous_profile_and_open_mode_erases_secret() {
        let root = tempfile::tempdir().unwrap();
        let store = WifiApProfileStore::open(root.path()).unwrap();
        store.save(profile()).unwrap();
        let mut update = profile();
        update.configuration.passphrase = Some("short".into());
        assert!(store.save(update).is_err());
        assert_eq!(
            store
                .get("guest")
                .unwrap()
                .configuration
                .passphrase
                .as_deref(),
            Some("guest-secret")
        );
        let mut update = profile();
        update.configuration.settings.security = WifiSecurity::Open;
        update.configuration.passphrase = None;
        update.configuration.clear_passphrase = true;
        assert!(!store.save(update).unwrap().has_passphrase);
        assert!(
            !std::fs::read_to_string(root.path().join("ap-profiles/guest.json"))
                .unwrap()
                .contains("guest-secret")
        );
    }
    #[test]
    fn rejects_traversal_symlinks_and_credentials_missing_on_new_profiles() {
        let root = tempfile::tempdir().unwrap();
        let store = WifiApProfileStore::open(root.path()).unwrap();
        let mut invalid = profile();
        invalid.id = "../escape".into();
        assert!(store.save(invalid).is_err());
        let mut missing = profile();
        missing.configuration.passphrase = None;
        assert!(store.save(missing).is_err());
        let external = root.path().join("external");
        std::fs::write(&external, "untouched").unwrap();
        symlink(&external, root.path().join("ap-profiles/guest.json")).unwrap();
        assert!(store.save(profile()).is_err());
        assert!(store.get("guest").is_err());
        assert!(store.delete("guest").is_err());
        assert_eq!(std::fs::read_to_string(external).unwrap(), "untouched");
    }
}
