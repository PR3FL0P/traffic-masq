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
mod wifi_intent;

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
    interface_observation: Arc<Mutex<Vec<InterfaceStatus>>>,
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

/// Required shared dependencies for a control service driven by reconciliation.
/// The daemon supplies its file configuration separately from active settings,
/// and the same desired state and mutation gate used by its runtime workers.
pub struct ControlRuntime {
    pub active_config: AppConfig,
    pub base_config: AppConfig,
    pub network: Arc<dyn NetworkProvider>,
    pub dhcp: DhcpSupervisor,
    pub overrides: RuntimeOverrideManager,
    pub baselines: Vec<InterfaceSnapshot>,
    pub ownership_journal: AddressOwnershipJournal,
    pub desired_state: DesiredNetworkState,
    pub mutation_gate: Arc<NetworkMutationGate>,
}

/// Optional runtimes, selected explicitly when assembling the daemon.
#[derive(Default)]
pub struct ControlSubsystems {
    pub router: Option<RouterTransactionCoordinator>,
    pub dhcp_client: Option<DhcpClientSupervisor>,
    pub vpn: Option<Arc<ProductionVpnManager>>,
    pub vpn_policy: Option<Arc<VpnPolicyManager<WireGuardVpnDriver, Arc<dyn NftExecutor>>>>,
    pub wifi: Option<HostapdSupervisor>,
    pub wifi_client: Option<WifiClientSupervisor>,
}

impl ControlService {
    /// Assemble the service with its final shared state before exposing it.
    pub fn from_runtime(runtime: ControlRuntime, subsystems: ControlSubsystems) -> Self {
        let ControlRuntime {
            active_config: config,
            base_config,
            network,
            dhcp,
            overrides,
            baselines,
            ownership_journal,
            desired_state,
            mutation_gate: network_mutations,
        } = runtime;
        let transactions = NetworkTransactionManager::new_with_services(
            InterfaceManager::new(network.clone(), ownership_journal),
            Duration::from_secs(config.security.rollback_timeout_seconds),
            baselines,
            dhcp.clone(),
            config.dhcp.default_lease_seconds,
            desired_state,
        );
        transactions.set_runtime_gate(network_mutations.clone());
        transactions.require_converger(true);
        if let Some(router) = &subsystems.router {
            router.set_timeout_mutation_gate(network_mutations.clone());
        }
        let wifi_client_profiles =
            WifiClientProfileStore::new(config.runtime.state_dir.join("wifi/client-profiles"));

        Self {
            operations: Default::default(),
            base_config,
            config,
            network,
            transactions,
            interface_observation: Default::default(),
            network_mutations,
            dhcp,
            overrides,
            dhcp_mutations: Arc::new(Mutex::new(())),
            dhcp_client: subsystems.dhcp_client,
            dhcp_client_mutations: Arc::new(Mutex::new(())),
            router: subsystems.router,
            vpn: subsystems.vpn,
            vpn_policy: subsystems.vpn_policy,
            wifi: subsystems.wifi,
            wifi_mutations: Arc::new(Mutex::new(())),
            wifi_client: subsystems.wifi_client,
            wifi_client_profiles,
            wifi_client_mutations: Arc::new(Mutex::new(())),
            wifi_autoconnect: Default::default(),
            pending_wifi_client_deactivations: Default::default(),
        }
    }

    /// A service with an ownership journal of its own, which is to say one that
    /// is not written down. For tests and tooling; the daemon shares the
    /// journal it opened at startup through [`Self::from_runtime`].
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

    /// Standalone construction for tests and tooling without a runtime worker.
    /// Daemon startup uses [`Self::from_runtime`] instead.
    pub fn new_with_baselines(
        config: AppConfig,
        network: Arc<dyn NetworkProvider>,
        dhcp: DhcpSupervisor,
        overrides: RuntimeOverrideManager,
        baselines: Vec<InterfaceSnapshot>,
        journal: AddressOwnershipJournal,
    ) -> Self {
        let desired_state = DesiredNetworkState::new(config.clone(), overrides.clone());
        let service = Self::from_runtime(
            ControlRuntime {
                active_config: config.clone(),
                base_config: config,
                network,
                dhcp,
                overrides,
                baselines,
                ownership_journal: journal,
                desired_state,
                mutation_gate: Arc::new(NetworkMutationGate::default()),
            },
            ControlSubsystems::default(),
        );
        service.transactions.require_converger(false);
        service
    }

    /// Set the merge base for a standalone service built by tests or tooling.
    /// Daemon startup supplies its file configuration through [`ControlRuntime`].
    ///
    pub fn with_base_config(mut self, base_config: AppConfig) -> Self {
        self.base_config = base_config;
        self
    }

    /// Share the desired state that the convergence loop is driving.
    ///
    /// For standalone tests and tooling. Daemon construction supplies this
    /// dependency through [`ControlRuntime`] without replacing live state.
    pub fn with_desired_state(self, desired: DesiredNetworkState) -> Self {
        self.transactions.set_desired_state(desired);
        self
    }

    pub fn with_router_coordinator(mut self, coordinator: RouterTransactionCoordinator) -> Self {
        coordinator.set_timeout_mutation_gate(self.network_mutations.clone());
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
