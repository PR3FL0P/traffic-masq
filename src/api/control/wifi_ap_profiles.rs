use super::*;
use crate::api::model::WifiApProfileWriteRequest;
use crate::wifi::ap_profile::WifiApProfileStore;

impl ControlService {
    async fn with_ap_profiles<T: Send + 'static>(
        &self,
        operation: impl FnOnce(WifiApProfileStore) -> anyhow::Result<T> + Send + 'static,
    ) -> anyhow::Result<T> {
        let root = self.base_config.runtime.state_dir.clone();
        crate::wifi::store::blocking_store(move || operation(WifiApProfileStore::open(&root)?))
            .await
    }
    pub(super) async fn list_wifi_ap_profiles(&self) -> Response {
        match self.with_ap_profiles(|store| store.list()).await {
            Ok(profiles) => Response::WifiApProfiles { profiles },
            Err(error) => profile_error(error),
        }
    }
    pub(super) async fn save_wifi_ap_profile(
        &self,
        profile: WifiApProfileWriteRequest,
    ) -> Response {
        match self
            .with_ap_profiles(move |store| store.save(profile))
            .await
        {
            Ok(profile) => Response::WifiApProfileSaved { profile },
            Err(error) => profile_error(error),
        }
    }
    pub(super) async fn delete_wifi_ap_profile(&self, id: String) -> Response {
        let delete_id = id.clone();
        match self
            .with_ap_profiles(move |store| store.delete(&delete_id))
            .await
        {
            Ok(()) => Response::WifiApProfileDeleted { id },
            Err(error) => profile_error(error),
        }
    }
    pub(super) async fn activate_wifi_ap_profile(&self, interface: String, id: String) -> Response {
        let profile = match self.with_ap_profiles(move |store| store.get(&id)).await {
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
