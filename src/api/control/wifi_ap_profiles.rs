use super::*;
use crate::api::model::WifiApProfileWriteRequest;
use crate::wifi::ap_profile::WifiApProfileStore;

impl ControlService {
    fn ap_profiles(&self) -> anyhow::Result<WifiApProfileStore> {
        WifiApProfileStore::open(&self.base_config.runtime.state_dir)
    }
    pub(super) fn list_wifi_ap_profiles(&self) -> Response {
        match self.ap_profiles().and_then(|store| store.list()) {
            Ok(profiles) => Response::WifiApProfiles { profiles },
            Err(error) => profile_error(error),
        }
    }
    pub(super) fn save_wifi_ap_profile(&self, profile: WifiApProfileWriteRequest) -> Response {
        match self.ap_profiles().and_then(|store| store.save(profile)) {
            Ok(profile) => Response::WifiApProfileSaved { profile },
            Err(error) => profile_error(error),
        }
    }
    pub(super) fn delete_wifi_ap_profile(&self, id: String) -> Response {
        match self.ap_profiles().and_then(|store| store.delete(&id)) {
            Ok(()) => Response::WifiApProfileDeleted { id },
            Err(error) => profile_error(error),
        }
    }
    pub(super) async fn activate_wifi_ap_profile(&self, interface: String, id: String) -> Response {
        let profile = match self.ap_profiles().and_then(|store| store.get(&id)) {
            Ok(profile) => profile,
            Err(error) => return profile_error(error),
        };
        let c = profile.configuration;
        self.provision_wifi_access_point(
            interface,
            c.settings,
            c.passphrase,
            c.clear_passphrase,
            c.configure_dhcp,
            c.subnet,
            c.disable_dhcp,
        )
        .await
    }
}
fn profile_error(error: anyhow::Error) -> Response {
    Response::WifiError {
        detail: WifiErrorDetail::Other {
            message: error.to_string(),
        },
    }
}
