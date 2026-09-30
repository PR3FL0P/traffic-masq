use crate::vpn::{VpnDriver, VpnDriverError, VpnKind, VpnProvider};

pub use traffic_masq_wireguard::{
    validate_wireguard_profile_name, ProfileError, WireGuardDriver, WireGuardInterfaceConfig,
    WireGuardKey, WireGuardPeerConfig, WireGuardProfile,
};

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

    async fn delete_if_launch_marker(
        &self,
        interface: &str,
        launch_marker: &str,
    ) -> Result<bool, VpnDriverError> {
        Ok(self
            .provider
            .delete_link_if_launch_marker(interface, launch_marker)
            .await?)
    }

    async fn activate(
        &self,
        interface: &str,
        profile: &Self::Profile,
        launch_marker: &str,
    ) -> Result<Self::OwnershipProof, VpnDriverError> {
        self.provider
            .create_link(
                interface,
                &profile.interface.private_key,
                profile.interface.listen_port,
                launch_marker,
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
            Err(error) => match self
                .provider
                .delete_link_if_launch_marker(interface, launch_marker)
                .await
            {
                Ok(true) => Err(error),
                Ok(false) => Err(VpnDriverError::ActivationCleanupFailed {
                    interface: interface.to_string(),
                    activation: error.to_string(),
                    cleanup: "launch marker no longer matches; refusing to delete the interface"
                        .to_string(),
                }),
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
