pub mod active_profile;
pub mod manager;
mod provider;
pub mod store;
pub mod wireguard;

use std::fmt;

pub use active_profile::{ActiveProfileError, ActiveProfileStore, PersistedActiveProfile};
pub use manager::{
    ManagerError, OwnedInterfaceRecord, ReconcileOutcome, VpnActiveStatus, VpnInterfaceSnapshot,
    VpnManager,
};
pub use provider::{NetlinkVpnProvider, ProviderError, VpnProvider};
pub use store::{StoreError, WireGuardProfileStore, WireGuardProfileSummary};
pub use wireguard::{
    ProfileError, WireGuardDriver, WireGuardInterfaceConfig, WireGuardPeerConfig, WireGuardProfile,
    WireGuardVpnDriver,
};

pub type ProductionVpnManager = VpnManager<WireGuardVpnDriver>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VpnKind {
    WireGuard,
}

impl fmt::Display for VpnKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VpnKind::WireGuard => write!(f, "wireguard"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VpnDriverError {
    #[error("profile parsing/validation failed: {0}")]
    Profile(#[from] ProfileError),

    #[error(transparent)]
    Provider(#[from] ProviderError),

    #[error(transparent)]
    Store(#[from] StoreError),

    #[error("interface '{0}' not found or has no readable ownership proof")]
    NoOwnershipProof(String),

    #[error("failed to decode a persisted ownership proof")]
    InvalidOwnershipProof,
}

#[async_trait::async_trait]
pub trait VpnDriver: Send + Sync {
    type Profile: fmt::Debug + Send + Sync;

    type OwnershipProof: Clone + PartialEq + Send + Sync + fmt::Debug;

    fn kind(&self) -> VpnKind;

    fn list_profiles(&self) -> Result<Vec<store::WireGuardProfileSummary>, VpnDriverError>;

    fn import_profile(&self, name: &str, raw: &[u8]) -> Result<Self::Profile, VpnDriverError>;

    fn delete_profile(&self, name: &str) -> Result<(), VpnDriverError>;

    fn read_profile(&self, name: &str) -> Result<Self::Profile, VpnDriverError>;

    async fn link_exists(&self, interface: &str) -> Result<bool, VpnDriverError>;

    async fn is_up(&self, interface: &str) -> Result<bool, VpnDriverError>;

    async fn read_ownership_proof(
        &self,
        interface: &str,
    ) -> Result<Option<Self::OwnershipProof>, VpnDriverError>;

    async fn activate(
        &self,
        interface: &str,
        profile: &Self::Profile,
    ) -> Result<Self::OwnershipProof, VpnDriverError>;

    async fn deactivate(&self, interface: &str) -> Result<(), VpnDriverError>;

    fn encode_ownership_proof(&self, proof: &Self::OwnershipProof) -> Vec<u8>;

    fn decode_ownership_proof(&self, raw: &[u8]) -> Result<Self::OwnershipProof, VpnDriverError>;
}
