use crate::core::mutation::NetworkMutationGate;
mod dhcp;
mod dhcp_client;
mod dispatch;
mod interfaces;
mod provisioning;
mod router;
mod runtime;
mod settings;
mod vpn;
mod wifi;
mod wifi_ap_profiles;
mod wifi_autoconnect;
mod wifi_client;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::Mutex;

use crate::api::model::{
    ApiHttpsSettings, DhcpClientConfigRequest, DhcpClientErrorDetail, DhcpClientOperationalState,
    DhcpClientStatusView, DhcpEditRequest, InterfaceEditRequest, InterfaceStatus,
    ProvisioningDownstreamView, ProvisioningOutputView, ProvisioningStage, ProvisioningUplinkView,
    ProvisioningWarning, Request, Response, RouteStatus, RouterErrorDetail, RouterProposalRequest,
    RouterProvisioningApplyRequest, RouterProvisioningErrorDetail,
    RouterProvisioningPreviewRequest, RouterProvisioningPreviewView, RouterProvisioningRequest,
    RouterProvisioningStatusView, RouterRecoveryNotice, SecuritySettings, VpnErrorDetail,
    VpnPolicyErrorDetail, VpnPolicyStatusView, WifiClientEditRequest, WifiClientErrorDetail,
    WifiClientProfileErrorDetail, WifiClientProfileWriteRequest, WifiEditRequest, WifiErrorDetail,
};
use crate::config::{
    ApiConfig, AppConfig, DhcpClientInterfaceConfig, DhcpInterfaceConfig, InterfaceConfig,
    InterfaceRole, SecurityConfig, TcpApiConfig, UplinkMode, VpnPolicyMode, WifiApConfig,
    WifiClientConfig, WifiSecurity,
};
use crate::core::desired::DesiredNetworkState;
use crate::core::interface::{InterfaceManager, InterfaceSnapshot};
use crate::core::override_manager::RuntimeOverrideManager;
use crate::core::ownership::AddressOwnershipJournal;
use crate::core::router::{RouterApplyError, RouterDesired};
use crate::core::router_candidate::{RouterIntentProposal, StaleCandidateError};
use crate::core::router_provisioning::{
    derive_router_provisioning, ProvisioningInterfaceObservation, ProvisioningKnownNetwork,
    ProvisioningOutput, ProvisioningUplink, RouterProvisioningContext, RouterProvisioningDesired,
    RouterProvisioningEffective, RouterProvisioningError, DEFAULT_DHCP_LEASE_SECONDS,
    DEFAULT_DOWNSTREAM_PREFIX, DEFAULT_DOWNSTREAM_THIRD_OCTET,
};
use crate::core::router_transaction::{
    CoordinatorConflict, CoordinatorStatus, NoPendingTransactionError, RouterTransactionCoordinator,
};
use crate::core::transaction::NetworkTransactionManager;
use crate::core::vpn_policy_manager::VpnPolicyManager;
use crate::core::vpn_policy_manager::{vpn_policy_desired, vpn_policy_teardown_target};
use crate::dhcp::client::{
    DhcpClientRunState, DhcpClientSpec, DhcpClientStatus, DhcpClientSupervisor,
};
use crate::dhcp::store::LeaseStore;
use crate::dhcp::supervisor::{DhcpServiceSpec, DhcpSupervisor};
use crate::firewall::NftExecutor;
use crate::netlink::{Ipv4AddressInfo, NetworkProvider};
use crate::vpn::manager::OWNED_INTERFACE_NAME;
use crate::vpn::{
    ManagerError, ProductionVpnManager, StoreError, VpnDriverError, WireGuardVpnDriver,
};
use crate::wifi::client::render::ClientRenderError;
use crate::wifi::client::ClientSupervisorError;
use crate::wifi::render::RenderError;
use crate::wifi::secret::{WifiPassphrase, WifiPassphraseUpdate};
use crate::wifi::store::ResolvePassphraseError;
use crate::wifi::{
    CtrlError, HostapdSupervisor, MacAddr, ProcessError, SupervisorError, WifiApSpec,
    WifiClientProfileError, WifiClientProfileInput, WifiClientProfileSecretUpdate,
    WifiClientProfileStore, WifiClientSpec, WifiClientSupervisor,
};

#[derive(Clone)]
pub struct ControlService {
    operations: crate::api::operations::Operations,
    /// The configuration that is actually running, as it was when the daemon
    /// started. Reported as "active" so the UI can tell the user which settings
    /// need a restart to take effect.
    config: AppConfig,
    /// The on-disk configuration that runtime overrides are merged onto.
    ///
    /// Deliberately *not* `config`: merging overrides onto an already-merged
    /// config makes removing an override a no-op, because the removed value is
    /// still baked into the base. The runtime reconcile loop merges onto the
    /// file config, so anything else here would make the two disagree about
    /// what the effective configuration is.
    base_config: AppConfig,
    network: Arc<dyn NetworkProvider>,
    transactions: NetworkTransactionManager,
    /// Serializes entry into network-mutating API calls. Long-lived pending
    /// transactions are protected by coordinator status checks in dispatch.
    network_mutations: Arc<NetworkMutationGate>,
    dhcp: DhcpSupervisor,
    overrides: RuntimeOverrideManager,
    dhcp_mutations: Arc<Mutex<()>>,
    dhcp_client: Option<DhcpClientSupervisor>,
    dhcp_client_mutations: Arc<Mutex<()>>,

    router: Option<RouterTransactionCoordinator>,

    vpn: Option<Arc<ProductionVpnManager>>,

    vpn_policy: Option<Arc<VpnPolicyManager<WireGuardVpnDriver, Arc<dyn NftExecutor>>>>,

    wifi: Option<HostapdSupervisor>,
    wifi_mutations: Arc<Mutex<()>>,

    wifi_client: Option<WifiClientSupervisor>,
    wifi_client_profiles: WifiClientProfileStore,

    wifi_client_mutations: Arc<Mutex<()>>,
    wifi_autoconnect: Arc<Mutex<wifi_autoconnect::AutoconnectState>>,
    /// Pending operator-requested client deactivations. Autoconnect is only
    /// suspended after the corresponding tentative network change commits;
    /// rollback/timeout must leave the previous autoconnect policy intact.
    pending_wifi_client_deactivations: Arc<Mutex<BTreeMap<String, String>>>,
}

impl ControlService {
    /// A service with an ownership journal of its own, which is to say one that
    /// is not written down. For tests and tooling; the daemon shares the
    /// journal it opened at startup through [`Self::new_with_baselines`].
    pub fn new(
        config: AppConfig,
        network: Arc<dyn NetworkProvider>,
        dhcp: DhcpSupervisor,
        overrides: RuntimeOverrideManager,
    ) -> Self {
        Self::new_with_baselines(
            config,
            network,
            dhcp,
            overrides,
            Vec::new(),
            AddressOwnershipJournal::in_memory(),
        )
    }

    pub fn new_with_baselines(
        config: AppConfig,
        network: Arc<dyn NetworkProvider>,
        dhcp: DhcpSupervisor,
        overrides: RuntimeOverrideManager,
        baselines: Vec<InterfaceSnapshot>,
        journal: AddressOwnershipJournal,
    ) -> Self {
        let network_mutations = Arc::new(NetworkMutationGate::default());
        let transactions = NetworkTransactionManager::new_with_services(
            InterfaceManager::new(network.clone(), journal),
            Duration::from_secs(config.security.rollback_timeout_seconds),
            baselines,
            dhcp.clone(),
            config.dhcp.default_lease_seconds,
            // Replaced by `with_desired_state` once the converger exists. On
            // its own this one answers what the desired configuration is and
            // takes proposals; nobody converges it.
            DesiredNetworkState::new(config.clone(), overrides.clone()),
        );

        transactions.set_runtime_gate(network_mutations.clone());
        let wifi_client_profiles =
            WifiClientProfileStore::new(config.runtime.state_dir.join("wifi/client-profiles"));

        Self {
            operations: Default::default(),
            base_config: config.clone(),
            config,
            network,
            transactions,
            network_mutations,
            dhcp,
            overrides,
            dhcp_mutations: Arc::new(Mutex::new(())),
            dhcp_client: None,
            dhcp_client_mutations: Arc::new(Mutex::new(())),
            router: None,
            vpn: None,
            vpn_policy: None,
            wifi: None,
            wifi_mutations: Arc::new(Mutex::new(())),
            wifi_client: None,
            wifi_client_profiles,
            wifi_client_mutations: Arc::new(Mutex::new(())),
            wifi_autoconnect: Default::default(),
            pending_wifi_client_deactivations: Default::default(),
        }
    }

    /// Set the on-disk configuration that runtime overrides are merged onto.
    ///
    /// Without this the service merges onto whatever it was constructed with,
    /// which for the daemon is the already-merged startup configuration.
    pub fn with_base_config(mut self, base_config: AppConfig) -> Self {
        self.base_config = base_config;
        self
    }

    /// Share the desired state that the convergence loop is driving.
    ///
    /// Like `with_base_config`, the daemon has to call this: the service is
    /// built before the converger exists, so it starts with a desired state of
    /// its own. Applying a change against that one would propose it where
    /// nothing is converging — the change would be reported as applied without
    /// anything having reached the machine.
    pub fn with_desired_state(self, desired: DesiredNetworkState) -> Self {
        self.transactions.set_desired_state(desired);
        self
    }

    pub(crate) fn with_network_mutation_gate(mut self, gate: Arc<NetworkMutationGate>) -> Self {
        self.transactions.set_runtime_gate(gate.clone());
        self.network_mutations = gate;
        self
    }

    pub fn with_router_coordinator(mut self, coordinator: RouterTransactionCoordinator) -> Self {
        self.router = Some(coordinator);
        self
    }

    pub fn with_vpn_manager(mut self, vpn: Arc<ProductionVpnManager>) -> Self {
        self.vpn = Some(vpn);
        self
    }

    pub fn with_vpn_policy_manager(
        mut self,
        vpn_policy: Arc<VpnPolicyManager<WireGuardVpnDriver, Arc<dyn NftExecutor>>>,
    ) -> Self {
        self.vpn_policy = Some(vpn_policy);
        self
    }

    pub fn with_wifi_supervisor(mut self, wifi: HostapdSupervisor) -> Self {
        self.wifi = Some(wifi);
        self
    }

    pub fn with_wifi_client_supervisor(mut self, wifi_client: WifiClientSupervisor) -> Self {
        self.wifi_client = Some(wifi_client);
        self
    }

    pub fn with_dhcp_client_supervisor(mut self, dhcp_client: DhcpClientSupervisor) -> Self {
        self.dhcp_client = Some(dhcp_client);
        self
    }

    pub fn transactions(&self) -> NetworkTransactionManager {
        self.transactions.clone()
    }

    /// Close operation admission and wait for accepted requests before runtime shutdown.
    pub async fn finish_operations(&self) {
        self.operations.close().await;
    }

    /// Execute a control request through the tracked operation service so caller cancellation
    /// does not interrupt an accepted network mutation.
    pub async fn dispatch(&self, request: Request) -> Response {
        let service = self.clone();
        match self
            .operations
            .run(async move { service.dispatch_inner(request).await })
            .await
        {
            Ok(response) => response,
            Err(error) => runtime::error_response(error),
        }
    }
}

#[cfg(test)]
mod tests;
