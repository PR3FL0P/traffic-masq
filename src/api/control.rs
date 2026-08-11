use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::Mutex;

use crate::api::model::{
    ApiHttpsSettings, DhcpClientConfigRequest, DhcpClientErrorDetail, DhcpClientOperationalState,
    DhcpClientStatusView, DhcpEditRequest, InterfaceEditRequest, InterfaceStatus,
    ProvisioningDownstreamView, ProvisioningOutputView, ProvisioningStage, ProvisioningUplinkView,
    ProvisioningWarning, Request, Response, RouterErrorDetail, RouterProposalRequest,
    RouterProvisioningApplyRequest, RouterProvisioningErrorDetail,
    RouterProvisioningPreviewRequest, RouterProvisioningPreviewView, RouterProvisioningRequest,
    RouterProvisioningStatusView, SecuritySettings, VpnErrorDetail, VpnPolicyErrorDetail,
    VpnPolicyStatusView, WifiClientEditRequest, WifiClientErrorDetail,
    WifiClientProfileErrorDetail, WifiClientProfileWriteRequest, WifiEditRequest, WifiErrorDetail,
};
use crate::app::{vpn_policy_desired, vpn_policy_teardown_target};
use crate::config::{
    ApiConfig, AppConfig, DhcpClientInterfaceConfig, DhcpInterfaceConfig, InterfaceConfig,
    InterfaceRole, SecurityConfig, TcpApiConfig, UplinkMode, VpnPolicyMode, WifiApConfig,
    WifiClientConfig,
};
use crate::core::interface::{InterfaceManager, InterfaceSnapshot};
use crate::core::router::{RouterApplyError, RouterDesired};
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
use crate::dhcp::client::{
    DhcpClientRunState, DhcpClientSpec, DhcpClientStatus, DhcpClientSupervisor,
};
use crate::dhcp::store::LeaseStore;
use crate::dhcp::supervisor::{DhcpServiceSpec, DhcpSupervisor};
use crate::firewall::NftExecutor;
use crate::netlink::{Ipv4AddressInfo, NetworkProvider};
use crate::state::candidate::{RouterIntentProposal, StaleCandidateError};
use crate::state::overrides::RuntimeOverrideManager;
use crate::vpn::manager::OWNED_INTERFACE_NAME;
use crate::vpn::{
    ManagerError, ProductionVpnManager, StoreError, VpnDriverError, WireGuardVpnDriver,
};
use crate::wifi::client::render::ClientRenderError;
use crate::wifi::client::ClientSupervisorError;
use crate::wifi::render::RenderError;
use crate::wifi::secret::WifiPassphrase;
use crate::wifi::store::ResolvePassphraseError;
use crate::wifi::{
    CtrlError, HostapdSupervisor, MacAddr, ProcessError, SupervisorError, WifiApSpec,
    WifiClientProfileError, WifiClientProfileInput, WifiClientProfileSecretUpdate,
    WifiClientProfileStore, WifiClientSpec, WifiClientSupervisor,
};

#[derive(Clone)]
pub struct ControlService {
    config: AppConfig,
    network: Arc<dyn NetworkProvider>,
    transactions: NetworkTransactionManager,
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
}

impl ControlService {
    pub fn new(
        config: AppConfig,
        network: Arc<dyn NetworkProvider>,
        dhcp: DhcpSupervisor,
        overrides: RuntimeOverrideManager,
    ) -> Self {
        Self::new_with_baselines(config, network, dhcp, overrides, Vec::new())
    }

    pub fn new_with_baselines(
        config: AppConfig,
        network: Arc<dyn NetworkProvider>,
        dhcp: DhcpSupervisor,
        overrides: RuntimeOverrideManager,
        baselines: Vec<InterfaceSnapshot>,
    ) -> Self {
        let transactions = NetworkTransactionManager::new_with_services(
            InterfaceManager::new(network.clone()),
            Duration::from_secs(config.security.rollback_timeout_seconds),
            baselines,
            dhcp.clone(),
            config.dhcp.default_lease_seconds,
        );

        let wifi_client_profiles =
            WifiClientProfileStore::new(config.runtime.state_dir.join("wifi/client-profiles"));

        Self {
            config,
            network,
            transactions,
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
        }
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

    async fn api_https_config_response(&self) -> Result<Response> {
        let snapshot = self.overrides.snapshot().await;
        let desired = self.overrides.effective_api_config().await?;
        let active = api_https_settings_from_config(&self.config.api);
        let desired = api_https_settings_from_config(&desired);
        Ok(Response::ApiHttpsConfig {
            restart_required: active != desired,
            override_active: snapshot.api.is_some(),
            active,
            desired,
        })
    }

    async fn configure_api_https_settings(&self, settings: ApiHttpsSettings) -> Result<Response> {
        let api = api_https_settings_to_config(settings)?;
        self.overrides.set_api_config(api).await?;
        self.api_https_config_response().await
    }

    async fn reset_api_https_settings(&self) -> Result<Response> {
        self.overrides.clear_api_config().await?;
        self.api_https_config_response().await
    }

    async fn security_config_response(&self) -> Result<Response> {
        let snapshot = self.overrides.snapshot().await;
        let desired = self.overrides.effective_security_config().await?;
        let active = SecuritySettings::from(&self.config.security);
        let desired = SecuritySettings::from(&desired);
        Ok(Response::SecurityConfig {
            restart_required: active != desired,
            override_active: snapshot.security.is_some(),
            active,
            desired,
        })
    }

    async fn configure_security_settings(&self, settings: SecuritySettings) -> Result<Response> {
        let security = SecurityConfig {
            rollback_timeout_seconds: settings.rollback_timeout_seconds,
        };
        self.overrides.set_security_config(security).await?;
        self.security_config_response().await
    }

    async fn reset_security_settings(&self) -> Result<Response> {
        self.overrides.clear_security_config().await?;
        self.security_config_response().await
    }

    pub async fn dispatch(&self, request: Request) -> Response {
        match request {
            Request::Ping => Response::Pong,
            Request::GetApiHttpsConfig => match self.api_https_config_response().await {
                Ok(response) => response,
                Err(error) => Response::Error {
                    message: error.to_string(),
                },
            },
            Request::ConfigureApiHttpsSettings { settings } => {
                match self.configure_api_https_settings(settings).await {
                    Ok(response) => response,
                    Err(error) => Response::Error {
                        message: error.to_string(),
                    },
                }
            }
            Request::ResetApiHttpsSettings => match self.reset_api_https_settings().await {
                Ok(response) => response,
                Err(error) => Response::Error {
                    message: error.to_string(),
                },
            },
            Request::GetSecurityConfig => match self.security_config_response().await {
                Ok(response) => response,
                Err(error) => Response::Error {
                    message: error.to_string(),
                },
            },
            Request::ConfigureSecuritySettings { settings } => {
                match self.configure_security_settings(settings).await {
                    Ok(response) => response,
                    Err(error) => Response::Error {
                        message: error.to_string(),
                    },
                }
            }
            Request::ResetSecuritySettings => match self.reset_security_settings().await {
                Ok(response) => response,
                Err(error) => Response::Error {
                    message: error.to_string(),
                },
            },
            Request::ListInterfaces => match interface_statuses(self.network.as_ref()).await {
                Ok(interfaces) => Response::Interfaces { interfaces },
                Err(error) => Response::Error {
                    message: error.to_string(),
                },
            },
            Request::GetInterfaceConfig { interface } => {
                match self.interface_config_response(interface).await {
                    Ok(response) => response,
                    Err(error) => Response::Error {
                        message: error.to_string(),
                    },
                }
            }
            Request::DhcpStatus => Response::DhcpStatus {
                running_interfaces: self.dhcp.running_interfaces().await,
                unhealthy_interfaces: self.dhcp.unhealthy_interfaces().await,
            },
            Request::DhcpClientStatus => self.dhcp_client_status().await,
            Request::GetDhcpClient { interface } => self.get_dhcp_client(interface).await,
            Request::ConfigureDhcpClient { interface, config } => {
                self.configure_dhcp_client(interface, config).await
            }
            Request::DisableDhcpClient { interface } => self.disable_dhcp_client(interface).await,
            Request::RenewDhcpClient { interface } => self.renew_dhcp_client(interface).await,
            Request::ReleaseDhcpClient { interface } => self.release_dhcp_client(interface).await,
            Request::GetDhcpConfig { interface } => Response::DhcpConfig {
                spec: self.dhcp.spec(&interface).await,
                interface,
            },
            Request::ConfigureDhcp {
                interface,
                config: dhcp_config,
            } => match build_effective_dhcp_service(
                &interface,
                dhcp_config,
                &self.overrides,
                self.network.as_ref(),
                self.config.dhcp.default_lease_seconds,
            )
            .await
            {
                Ok(spec) => {
                    let _mutation = self.dhcp_mutations.lock().await;
                    match configure_dhcp_persisted(&self.dhcp, &self.overrides, spec.clone()).await
                    {
                        Ok(()) => Response::DhcpConfigured { spec },
                        Err(error) => Response::Error {
                            message: error.to_string(),
                        },
                    }
                }
                Err(error) => Response::Error {
                    message: error.to_string(),
                },
            },
            Request::ConfigureDhcpSettings {
                interface,
                settings,
            } => match build_effective_dhcp_service(
                &interface,
                dhcp_edit_request_to_config(settings),
                &self.overrides,
                self.network.as_ref(),
                self.config.dhcp.default_lease_seconds,
            )
            .await
            {
                Ok(spec) => {
                    let _mutation = self.dhcp_mutations.lock().await;
                    match configure_dhcp_persisted(&self.dhcp, &self.overrides, spec.clone()).await
                    {
                        Ok(()) => Response::DhcpConfigured { spec },
                        Err(error) => Response::Error {
                            message: error.to_string(),
                        },
                    }
                }
                Err(error) => Response::Error {
                    message: error.to_string(),
                },
            },
            Request::DisableDhcp { interface } => {
                let _mutation = self.dhcp_mutations.lock().await;
                match disable_dhcp_persisted(&self.dhcp, &self.overrides, &interface).await {
                    Ok(()) => Response::DhcpDisabled { interface },
                    Err(error) => Response::Error {
                        message: error.to_string(),
                    },
                }
            }
            Request::ListLeases { interface } => {
                if self.dhcp.spec(&interface).await.is_none() {
                    return Response::Error {
                        message: format!("DHCP is not configured for interface {interface}"),
                    };
                }

                let store = LeaseStore::for_interface(&self.config.dhcp.leases_dir, &interface);
                match store.load().await {
                    Ok(leases) => Response::Leases { interface, leases },
                    Err(error) => Response::Error {
                        message: error.to_string(),
                    },
                }
            }
            Request::DryRunInterface {
                interface,
                config,
                allow_management_change,
            } => {
                let current_role = match self.current_interface_role(&interface).await {
                    Ok(role) => role,
                    Err(error) => {
                        return Response::Error {
                            message: error.to_string(),
                        }
                    }
                };
                match self
                    .transactions
                    .dry_run(&interface, &config, current_role, allow_management_change)
                    .await
                {
                    Ok(plan) => Response::InterfacePlan { plan },
                    Err(error) => Response::Error {
                        message: error.to_string(),
                    },
                }
            }
            Request::DryRunInterfaceEdit { interface, edit } => {
                let current = match self.overrides.effective_interface(&interface).await {
                    Ok(current) => current,
                    Err(error) => {
                        return Response::Error {
                            message: error.to_string(),
                        }
                    }
                };
                let current_role = current.as_ref().map(|config| config.role);
                match interface_edit_request_to_config(edit, current) {
                    Ok((config, allow_management_change)) => match self
                        .transactions
                        .dry_run(&interface, &config, current_role, allow_management_change)
                        .await
                    {
                        Ok(plan) => Response::InterfacePlan { plan },
                        Err(error) => Response::Error {
                            message: error.to_string(),
                        },
                    },
                    Err(error) => Response::Error {
                        message: error.to_string(),
                    },
                }
            }
            Request::ApplyInterface {
                interface,
                config,
                allow_management_change,
            } => {
                let current_role = match self.current_interface_role(&interface).await {
                    Ok(role) => role,
                    Err(error) => {
                        return Response::Error {
                            message: error.to_string(),
                        }
                    }
                };
                match self
                    .transactions
                    .apply(&interface, &config, current_role, allow_management_change)
                    .await
                {
                    Ok(change) => Response::NetworkChangePending { change },
                    Err(error) => Response::Error {
                        message: error.to_string(),
                    },
                }
            }
            Request::ApplyInterfaceEdit { interface, edit } => {
                let current = match self.overrides.effective_interface(&interface).await {
                    Ok(current) => current,
                    Err(error) => {
                        return Response::Error {
                            message: error.to_string(),
                        }
                    }
                };
                let current_role = current.as_ref().map(|config| config.role);
                match interface_edit_request_to_config(edit, current) {
                    Ok((config, allow_management_change)) => match self
                        .transactions
                        .apply(&interface, &config, current_role, allow_management_change)
                        .await
                    {
                        Ok(change) => Response::NetworkChangePending { change },
                        Err(error) => Response::Error {
                            message: error.to_string(),
                        },
                    },
                    Err(error) => Response::Error {
                        message: error.to_string(),
                    },
                }
            }
            Request::CommitNetworkChange { token } => match self
                .transactions
                .commit_with(&token, |interface, config, allow_management_change| {
                    self.overrides
                        .set_interface(interface, config, allow_management_change)
                })
                .await
            {
                Ok(change) => Response::NetworkChangeCommitted { change },
                Err(error) => Response::Error {
                    message: error.to_string(),
                },
            },
            Request::RollbackNetworkChange { token } => {
                match self.transactions.rollback(&token).await {
                    Ok(change) => Response::NetworkChangeRolledBack { change },
                    Err(error) => Response::Error {
                        message: error.to_string(),
                    },
                }
            }
            Request::PendingNetworkChanges => Response::PendingNetworkChanges {
                changes: self.transactions.pending().await,
            },
            Request::RouterStatus => self.router_status().await,
            Request::RouterPlan { proposal } => self.router_plan(proposal).await,
            Request::RouterApply { proposal } => self.router_apply(proposal).await,
            Request::RouterCommit => self.router_commit().await,
            Request::RouterRollback => self.router_rollback().await,
            Request::RouterPendingTransaction => self.router_pending_transaction().await,
            Request::RouterProvisioningPreview { request } => {
                self.router_provisioning_preview(request).await
            }
            Request::RouterProvisioningApply { request } => {
                self.router_provisioning_apply(request).await
            }
            Request::RouterProvisioningStatus => self.router_provisioning_status().await,
            Request::RouterProvisioningRepair => self.router_provisioning_repair().await,
            Request::VpnListProfiles => self.vpn_list_profiles().await,
            Request::VpnImportProfile { name, contents } => {
                self.vpn_import_profile(name, contents).await
            }
            Request::VpnDeleteProfile { name } => self.vpn_delete_profile(name).await,
            Request::VpnStatus => self.vpn_status().await,
            Request::VpnActivate { name } => self.vpn_activate(name).await,
            Request::VpnDeactivate => self.vpn_deactivate().await,
            Request::VpnPolicyStatus => self.vpn_policy_status().await,
            Request::VpnPolicySetMode { mode } => self.vpn_policy_set_mode(mode).await,
            Request::VpnPolicyClearMode => self.vpn_policy_clear_mode().await,
            Request::WifiStatus => self.wifi_status().await,
            Request::GetWifiConfig { interface } => self.get_wifi_config(interface).await,
            Request::ConfigureWifi {
                interface,
                settings,
            } => self.configure_wifi(interface, settings).await,
            Request::ProvisionWifiAccessPoint {
                interface,
                settings,
                passphrase,
                configure_dhcp,
            } => {
                self.provision_wifi_access_point(interface, settings, passphrase, configure_dhcp)
                    .await
            }
            Request::DisableWifi { interface } => self.disable_wifi(interface).await,
            Request::WifiSetPassphrase {
                interface,
                passphrase,
            } => self.wifi_set_passphrase(interface, passphrase).await,
            Request::ListWifiStations { interface } => self.list_wifi_stations(interface).await,
            Request::WifiDeauthStation { interface, mac } => {
                self.wifi_deauth_station(interface, mac).await
            }
            Request::WifiReload { interface } => self.wifi_reload(interface).await,
            Request::WifiClientStatus => self.wifi_client_status().await,
            Request::GetWifiClientConfig { interface } => {
                self.get_wifi_client_config(interface).await
            }
            Request::ConfigureWifiClient {
                interface,
                settings,
            } => self.configure_wifi_client(interface, settings).await,
            Request::DisableWifiClient { interface } => self.disable_wifi_client(interface).await,
            Request::WifiClientSetPassphrase {
                interface,
                passphrase,
            } => self.wifi_client_set_passphrase(interface, passphrase).await,
            Request::WifiClientReconnect { interface } => {
                self.wifi_client_reconnect(interface).await
            }
            Request::WifiClientScan { interface } => self.wifi_client_scan(interface).await,
            Request::ListWifiClientProfiles => self.list_wifi_client_profiles().await,
            Request::GetWifiClientProfile { id } => self.get_wifi_client_profile(id).await,
            Request::CreateWifiClientProfile { profile } => {
                self.create_wifi_client_profile(profile).await
            }
            Request::UpdateWifiClientProfile { id, profile } => {
                self.update_wifi_client_profile(id, profile).await
            }
            Request::DeleteWifiClientProfile { id } => self.delete_wifi_client_profile(id).await,
            Request::ActivateWifiClientProfile {
                interface,
                profile_id,
            } => {
                self.activate_wifi_client_profile(interface, profile_id)
                    .await
            }
            Request::DeactivateWifiClientProfile { interface } => {
                self.disable_wifi_client(interface).await
            }
        }
    }

    async fn current_interface_role(&self, interface: &str) -> Result<Option<InterfaceRole>> {
        Ok(self
            .overrides
            .effective_interface(interface)
            .await?
            .map(|config| config.role))
    }

    async fn interface_config_response(&self, interface: String) -> Result<Response> {
        let snapshot = self.overrides.snapshot().await;
        let effective = snapshot.effective_config(&self.config)?;
        let config = effective.network.interfaces.get(&interface).cloned();
        let allow_management_change = snapshot
            .interfaces
            .get(&interface)
            .map(|value| value.allow_management_change)
            .unwrap_or(false);
        Ok(Response::InterfaceConfig {
            interface,
            config,
            allow_management_change,
        })
    }

    async fn vpn_list_profiles(&self) -> Response {
        let Some(vpn) = &self.vpn else {
            return vpn_disabled();
        };
        match vpn.list_profiles() {
            Ok(profiles) => Response::VpnProfiles {
                profiles: profiles.into_iter().map(Into::into).collect(),
            },
            Err(error) => classify_vpn_error(error),
        }
    }

    async fn vpn_import_profile(&self, name: String, contents: String) -> Response {
        let Some(vpn) = &self.vpn else {
            return vpn_disabled();
        };
        match vpn.import_profile(&name, contents.as_bytes()) {
            Ok(name) => Response::VpnProfileImported { name },
            Err(error) => classify_vpn_error(error),
        }
    }

    async fn vpn_delete_profile(&self, name: String) -> Response {
        let Some(vpn) = &self.vpn else {
            return vpn_disabled();
        };
        match vpn.delete_profile(&name) {
            Ok(()) => Response::VpnProfileDeleted { name },
            Err(error) => classify_vpn_error(error),
        }
    }

    async fn vpn_status(&self) -> Response {
        let Some(vpn) = &self.vpn else {
            return vpn_disabled();
        };
        match vpn.status().await {
            Ok(active) => Response::VpnStatus {
                active: active.map(Into::into),
            },
            Err(error) => classify_vpn_error(error),
        }
    }

    async fn vpn_activate(&self, name: String) -> Response {
        let Some(vpn) = &self.vpn else {
            return vpn_disabled();
        };
        if let Err(error) = vpn.activate(&name).await {
            return classify_vpn_error(error);
        }
        match vpn.status().await {
            Ok(Some(active)) => Response::VpnActivated {
                active: active.into(),
            },
            Ok(None) => {
                tracing::error!("VPN activation reported success but no interface is active");
                Response::Error {
                    message: "VPN activation succeeded but left no active interface".to_string(),
                }
            }
            Err(error) => classify_vpn_error(error),
        }
    }

    async fn vpn_deactivate(&self) -> Response {
        let Some(vpn) = &self.vpn else {
            return vpn_disabled();
        };
        match vpn.deactivate().await {
            Ok(()) => Response::VpnDeactivated,
            Err(error) => classify_vpn_error(error),
        }
    }

    async fn vpn_policy_status(&self) -> Response {
        let (Some(policy), Some(vpn)) = (&self.vpn_policy, &self.vpn) else {
            return vpn_policy_disabled();
        };
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(error) => return vpn_policy_error(VpnPolicyErrorDetail::Other { message: error }),
        };
        self.vpn_policy_status_for(policy, vpn, &effective).await
    }

    async fn vpn_policy_status_for(
        &self,
        policy: &VpnPolicyManager<WireGuardVpnDriver, Arc<dyn NftExecutor>>,
        vpn: &ProductionVpnManager,
        effective: &AppConfig,
    ) -> Response {
        let tunnel = match vpn.status().await {
            Ok(active) => active,
            Err(error) => return classify_vpn_error(error),
        };
        let tunnel_healthy = tunnel
            .as_ref()
            .is_some_and(|status| status.up && status.interface == OWNED_INTERFACE_NAME);

        let snapshot = match policy.snapshot(&vpn_policy_teardown_target()).await {
            Ok(snapshot) => snapshot,
            Err(error) => return vpn_policy_error(classify_vpn_policy_error(&error)),
        };
        let policy_active = snapshot.is_active();

        let desired = vpn_policy_desired(effective);
        let mode = self.overrides.effective_vpn_mode().await;
        let mode_override_active = self.overrides.snapshot().await.vpn_mode.is_some();

        Response::VpnPolicyStatus {
            status: VpnPolicyStatusView {
                mode,
                mode_override_active,
                tunnel: tunnel.map(Into::into),
                tunnel_healthy,
                policy_active,
                kill_switch_active: policy_active,
                protected_subnets: desired
                    .as_ref()
                    .map(|desired| desired.protected_subnets.clone())
                    .unwrap_or_default(),
                physical_uplink: desired.map(|desired| desired.physical_uplink),
            },
        }
    }

    async fn vpn_policy_apply_mode(
        &self,
        policy: &VpnPolicyManager<WireGuardVpnDriver, Arc<dyn NftExecutor>>,
        effective: &AppConfig,
        target: VpnPolicyMode,
    ) -> Result<(), Response> {
        match target {
            VpnPolicyMode::Vpn => {
                let Some(desired) = vpn_policy_desired(effective) else {
                    return Err(vpn_policy_error(VpnPolicyErrorDetail::NoProtectedSubnets));
                };
                policy
                    .activate(&desired)
                    .await
                    .map(|_| ())
                    .map_err(|error| vpn_policy_error(classify_vpn_policy_error(&error)))
            }
            VpnPolicyMode::Direct => {
                let desired =
                    vpn_policy_desired(effective).unwrap_or_else(vpn_policy_teardown_target);
                policy.deactivate(&desired).await.map_err(|error| {
                    vpn_policy_error(VpnPolicyErrorDetail::Other {
                        message: error.to_string(),
                    })
                })
            }
        }
    }

    async fn vpn_policy_set_mode(&self, mode: VpnPolicyMode) -> Response {
        let (Some(policy), Some(_vpn)) = (&self.vpn_policy, &self.vpn) else {
            return vpn_policy_disabled();
        };
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(error) => return vpn_policy_error(VpnPolicyErrorDetail::Other { message: error }),
        };
        if let Err(response) = self.vpn_policy_apply_mode(policy, &effective, mode).await {
            return response;
        }
        if let Err(error) = self.overrides.set_vpn_mode(mode).await {
            if mode == VpnPolicyMode::Vpn {
                let _ = self
                    .vpn_policy_apply_mode(policy, &effective, VpnPolicyMode::Direct)
                    .await;
            }
            return vpn_policy_error(VpnPolicyErrorDetail::Other {
                message: error.to_string(),
            });
        }
        self.vpn_policy_status().await
    }

    async fn vpn_policy_clear_mode(&self) -> Response {
        let (Some(policy), Some(_vpn)) = (&self.vpn_policy, &self.vpn) else {
            return vpn_policy_disabled();
        };
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(error) => return vpn_policy_error(VpnPolicyErrorDetail::Other { message: error }),
        };
        let target = effective.vpn.policy.default_mode;
        if let Err(response) = self.vpn_policy_apply_mode(policy, &effective, target).await {
            return response;
        }
        if let Err(error) = self.overrides.clear_vpn_mode().await {
            if target == VpnPolicyMode::Vpn {
                let _ = self
                    .vpn_policy_apply_mode(policy, &effective, VpnPolicyMode::Direct)
                    .await;
            }
            return vpn_policy_error(VpnPolicyErrorDetail::Other {
                message: error.to_string(),
            });
        }
        self.vpn_policy_status().await
    }

    async fn wifi_status(&self) -> Response {
        let Some(wifi) = &self.wifi else {
            return wifi_disabled();
        };
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(message) => return wifi_error(WifiErrorDetail::Other { message }),
        };
        let mut interfaces = Vec::new();
        for (name, config) in &effective.network.interfaces {
            if config.wifi.is_some() {
                if let Some(status) = wifi.status(name).await {
                    interfaces.push(status);
                }
            }
        }
        Response::WifiStatus { interfaces }
    }

    async fn get_wifi_config(&self, interface: String) -> Response {
        if self.wifi.is_none() {
            return wifi_disabled();
        }
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(message) => return wifi_error(WifiErrorDetail::Other { message }),
        };
        let spec = match effective.network.interfaces.get(&interface) {
            Some(config) => match WifiApSpec::from_interface_config(&interface, config) {
                Ok(spec) => spec,
                Err(error) => {
                    return wifi_error(WifiErrorDetail::InvalidSpec {
                        message: error.to_string(),
                    })
                }
            },
            None => None,
        };
        Response::WifiConfig { interface, spec }
    }

    async fn configure_wifi(&self, interface: String, settings: WifiEditRequest) -> Response {
        let Some(wifi) = &self.wifi else {
            return wifi_disabled();
        };
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(message) => return wifi_error(WifiErrorDetail::Other { message }),
        };
        let Some(mut interface_config) = effective.network.interfaces.get(&interface).cloned()
        else {
            return wifi_error(WifiErrorDetail::InterfaceNotFound);
        };

        interface_config.wifi = Some(wifi_edit_request_to_config(settings));

        let spec = match WifiApSpec::from_interface_config(&interface, &interface_config) {
            Ok(Some(spec)) => spec,
            Ok(None) => {
                return wifi_error(WifiErrorDetail::InvalidSpec {
                    message: "a Wi-Fi access point requires a managed output interface".to_string(),
                })
            }
            Err(error) => {
                return wifi_error(WifiErrorDetail::InvalidSpec {
                    message: error.to_string(),
                })
            }
        };

        let _mutation = self.wifi_mutations.lock().await;
        let previous = wifi.status(&interface).await.map(|status| status.spec);
        if let Err(error) = wifi.configure(spec.clone()).await {
            return classify_wifi_error(error);
        }
        if let Err(error) = self
            .overrides
            .set_interface(interface.clone(), interface_config, false)
            .await
        {
            match previous {
                Some(previous) => {
                    let _ = wifi.configure(previous).await;
                }
                None => {
                    let _ = wifi.disable(&interface).await;
                }
            }
            return wifi_error(WifiErrorDetail::Other {
                message: format!(
                    "failed to persist Wi-Fi override; runtime state was restored: {error}"
                ),
            });
        }
        Response::WifiConfigured { spec }
    }

    async fn provision_wifi_access_point(
        &self,
        interface: String,
        settings: WifiEditRequest,
        passphrase: Option<String>,
        configure_dhcp: bool,
    ) -> Response {
        let Some(wifi) = &self.wifi else {
            return wifi_disabled();
        };
        let staged_passphrase = match passphrase {
            Some(value) => match WifiPassphrase::new(value) {
                Ok(value) => Some(value),
                Err(error) => {
                    return wifi_error(WifiErrorDetail::InvalidSpec {
                        message: error.to_string(),
                    })
                }
            },
            None => None,
        };
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(message) => return wifi_error(WifiErrorDetail::Other { message }),
        };
        let Some(previous_interface) = effective.network.interfaces.get(&interface).cloned() else {
            return wifi_error(WifiErrorDetail::InterfaceNotFound);
        };
        let Some(cidr) = previous_interface.ipv4 else {
            return wifi_error(WifiErrorDetail::InvalidSpec {
                message: "AP provisioning requires a configured IPv4 CIDR".to_string(),
            });
        };
        if !previous_interface.managed || previous_interface.role != InterfaceRole::Output {
            return wifi_error(WifiErrorDetail::InvalidSpec {
                message: "AP provisioning requires a managed output interface".to_string(),
            });
        }

        let mut desired_interface = previous_interface.clone();
        desired_interface.wifi = Some(wifi_edit_request_to_config(settings));
        let spec = match WifiApSpec::from_interface_config(&interface, &desired_interface) {
            Ok(Some(spec)) => spec,
            Ok(None) => unreachable!("managed output checked above"),
            Err(error) => {
                return wifi_error(WifiErrorDetail::InvalidSpec {
                    message: error.to_string(),
                })
            }
        };
        let dhcp_settings = if configure_dhcp {
            match default_dhcp_settings(cidr) {
                Ok(settings) => Some(settings),
                Err(message) => return wifi_error(WifiErrorDetail::InvalidSpec { message }),
            }
        } else {
            None
        };

        let _wifi_mutation = self.wifi_mutations.lock().await;
        let _dhcp_mutation = self.dhcp_mutations.lock().await;
        let previous_ap = wifi.status(&interface).await.map(|status| status.spec);
        let previous_secret = match wifi.stored_passphrase(&interface).await {
            Ok(secret) => secret,
            Err(error) => return classify_wifi_error(error),
        };
        let previous_dhcp = self.dhcp.spec(&interface).await;

        if let Some(secret) = staged_passphrase.as_ref() {
            if let Err(error) = wifi.set_passphrase(&interface, secret).await {
                return classify_wifi_error(error);
            }
        }
        if let Err(error) = wifi.configure(spec.clone()).await {
            compensate_ap(wifi, &interface, previous_ap, previous_secret).await;
            return classify_wifi_error(error);
        }
        if let Err(error) = self
            .overrides
            .set_interface(interface.clone(), desired_interface.clone(), false)
            .await
        {
            compensate_ap(wifi, &interface, previous_ap, previous_secret).await;
            return wifi_error(WifiErrorDetail::Other {
                message: format!("AP provisioning failed to persist Wi-Fi settings; prior AP and secret were restored where possible: {error}"),
            });
        }

        let configured_dhcp = if let Some(settings) = dhcp_settings {
            let mut dhcp_interface = desired_interface;
            dhcp_interface.dhcp = Some(dhcp_edit_request_to_config(settings));
            let result = match DhcpServiceSpec::from_interface_config(
                &interface,
                &dhcp_interface,
                self.config.dhcp.default_lease_seconds,
            ) {
                Ok(Some(spec)) => {
                    configure_dhcp_persisted(&self.dhcp, &self.overrides, spec.clone())
                        .await
                        .map(|()| spec)
                }
                Ok(None) => unreachable!("managed output was checked before provisioning"),
                Err(error) => Err(error),
            };
            match result {
                Ok(spec) => Some(spec),
                Err(error) => {
                    let _ = self
                        .overrides
                        .set_interface(interface.clone(), previous_interface, false)
                        .await;
                    match previous_dhcp {
                        Some(spec) => {
                            let _ = self.dhcp.configure(spec).await;
                        }
                        None => {
                            let _ = self.dhcp.disable(&interface).await;
                        }
                    }
                    compensate_ap(wifi, &interface, previous_ap, previous_secret).await;
                    return wifi_error(WifiErrorDetail::Other {
                        message: format!("AP provisioning failed while configuring DHCP; prior AP, secret, DHCP, and interface override were restored where possible: {error}"),
                    });
                }
            }
        } else {
            None
        };

        Response::WifiAccessPointProvisioned {
            spec,
            dhcp: configured_dhcp,
        }
    }

    async fn disable_wifi(&self, interface: String) -> Response {
        let Some(wifi) = &self.wifi else {
            return wifi_disabled();
        };
        let _mutation = self.wifi_mutations.lock().await;
        let previous = wifi.status(&interface).await.map(|status| status.spec);

        if let Err(error) = wifi.disable(&interface).await {
            return classify_wifi_error(error);
        }

        let committed = match self.overrides.effective_interface(&interface).await {
            Ok(config) => config,
            Err(error) => {
                return wifi_error(WifiErrorDetail::Other {
                    message: error.to_string(),
                })
            }
        };
        let Some(mut interface_config) = committed else {
            return Response::WifiDisabled { interface };
        };
        interface_config.wifi = None;
        if let Err(error) = self
            .overrides
            .set_interface(interface.clone(), interface_config, false)
            .await
        {
            if let Some(previous) = previous {
                let _ = wifi.configure(previous).await;
            }
            return wifi_error(WifiErrorDetail::Other {
                message: format!(
                    "failed to persist Wi-Fi disable; runtime state was restored: {error}"
                ),
            });
        }
        Response::WifiDisabled { interface }
    }

    async fn wifi_set_passphrase(&self, interface: String, passphrase: String) -> Response {
        let Some(wifi) = &self.wifi else {
            return wifi_disabled();
        };
        let passphrase = match WifiPassphrase::new(passphrase) {
            Ok(passphrase) => passphrase,
            Err(error) => {
                return wifi_error(WifiErrorDetail::InvalidSpec {
                    message: error.to_string(),
                })
            }
        };
        if let Err(error) = wifi.set_passphrase(&interface, &passphrase).await {
            return classify_wifi_error(error);
        }

        let Some(status) = wifi.status(&interface).await else {
            return wifi_error(WifiErrorDetail::InterfaceNotFound);
        };
        let spec = status.spec;
        match wifi.configure(spec.clone()).await {
            Ok(()) => Response::WifiConfigured { spec },
            Err(error) => classify_wifi_error(error),
        }
    }

    async fn list_wifi_stations(&self, interface: String) -> Response {
        let Some(wifi) = &self.wifi else {
            return wifi_disabled();
        };
        match wifi.stations(&interface).await {
            Ok(stations) => Response::WifiStations {
                interface,
                stations,
            },
            Err(error) => classify_wifi_error(error),
        }
    }

    async fn wifi_deauth_station(&self, interface: String, mac: String) -> Response {
        let Some(wifi) = &self.wifi else {
            return wifi_disabled();
        };
        let mac: MacAddr = match mac.parse() {
            Ok(mac) => mac,
            Err(error) => {
                return wifi_error(WifiErrorDetail::InvalidSpec {
                    message: format!("{error}"),
                })
            }
        };
        if let Err(error) = wifi.deauthenticate(&interface, mac).await {
            return classify_wifi_error(error);
        }
        match wifi.stations(&interface).await {
            Ok(stations) => Response::WifiStations {
                interface,
                stations,
            },
            Err(error) => classify_wifi_error(error),
        }
    }

    async fn wifi_reload(&self, interface: String) -> Response {
        let Some(wifi) = &self.wifi else {
            return wifi_disabled();
        };
        match wifi.reload(&interface).await {
            Ok(spec) => Response::WifiConfigured { spec },
            Err(error) => classify_wifi_error(error),
        }
    }

    async fn dhcp_client_status(&self) -> Response {
        let Some(supervisor) = &self.dhcp_client else {
            return dhcp_client_error(DhcpClientErrorDetail::DhcpClientDisabled);
        };
        Response::DhcpClientStatus {
            interfaces: supervisor
                .statuses()
                .await
                .into_iter()
                .map(dhcp_client_status_view)
                .collect(),
        }
    }

    async fn get_dhcp_client(&self, interface: String) -> Response {
        let Some(supervisor) = &self.dhcp_client else {
            return dhcp_client_error(DhcpClientErrorDetail::DhcpClientDisabled);
        };
        match supervisor.status(&interface).await {
            Some(status) => Response::DhcpClientInterface {
                status: dhcp_client_status_view(status),
            },
            None => {
                let effective = match self.effective_config().await {
                    Ok(config) => config,
                    Err(message) => {
                        return dhcp_client_error(DhcpClientErrorDetail::RuntimeFailure { message })
                    }
                };
                match effective.network.interfaces.get(&interface) {
                    None => dhcp_client_error(DhcpClientErrorDetail::InterfaceNotFound),
                    Some(config) if config.dhcp_client.is_some() => {
                        dhcp_client_error(DhcpClientErrorDetail::Disabled)
                    }
                    Some(_) => dhcp_client_error(DhcpClientErrorDetail::Disabled),
                }
            }
        }
    }

    async fn configure_dhcp_client(
        &self,
        interface: String,
        request: DhcpClientConfigRequest,
    ) -> Response {
        let Some(supervisor) = &self.dhcp_client else {
            return dhcp_client_error(DhcpClientErrorDetail::DhcpClientDisabled);
        };
        let _mutation = self.dhcp_client_mutations.lock().await;
        let effective = match self.effective_config().await {
            Ok(config) => config,
            Err(message) => {
                return dhcp_client_error(DhcpClientErrorDetail::RuntimeFailure { message })
            }
        };
        let Some(mut interface_config) = effective.network.interfaces.get(&interface).cloned()
        else {
            return dhcp_client_error(DhcpClientErrorDetail::InterfaceNotFound);
        };
        interface_config.role = InterfaceRole::Input;
        interface_config.managed = true;
        interface_config.ipv4 = None;
        interface_config.dhcp = None;
        interface_config.dhcp_client = Some(dhcp_client_request_to_config(&request, true));
        let spec = match DhcpClientSpec::from_interface_config(&interface, &interface_config) {
            Ok(Some(spec)) => spec,
            Ok(None) => return dhcp_client_error(DhcpClientErrorDetail::Disabled),
            Err(error) => {
                return dhcp_client_error(DhcpClientErrorDetail::InvalidConfig {
                    message: error.to_string(),
                })
            }
        };

        if let Err(error) = self
            .overrides
            .check_interface(&interface, &interface_config, false)
            .await
        {
            return dhcp_client_error(DhcpClientErrorDetail::InvalidConfig {
                message: error.to_string(),
            });
        }
        let previous = supervisor.spec(&interface).await;
        supervisor.configure(spec.clone()).await;
        if let Err(error) = self
            .overrides
            .set_interface(interface.clone(), interface_config, false)
            .await
        {
            if let Some(previous) = previous {
                supervisor.configure(previous).await;
            } else {
                let _ = supervisor.disable(&interface).await;
            }
            return dhcp_client_error(DhcpClientErrorDetail::PersistenceFailure {
                message: format!(
                    "failed to persist DHCP client intent; runtime state was restored: {error}"
                ),
            });
        }
        match supervisor.status(&interface).await {
            Some(status) => Response::DhcpClientInterface {
                status: dhcp_client_status_view(status),
            },
            None => dhcp_client_error(DhcpClientErrorDetail::RuntimeFailure {
                message: "DHCP client disappeared after configuration".to_string(),
            }),
        }
    }

    async fn disable_dhcp_client(&self, interface: String) -> Response {
        let Some(supervisor) = &self.dhcp_client else {
            return dhcp_client_error(DhcpClientErrorDetail::DhcpClientDisabled);
        };
        let _mutation = self.dhcp_client_mutations.lock().await;
        let effective = match self.effective_config().await {
            Ok(config) => config,
            Err(message) => {
                return dhcp_client_error(DhcpClientErrorDetail::RuntimeFailure { message })
            }
        };
        let Some(mut config) = effective.network.interfaces.get(&interface).cloned() else {
            return dhcp_client_error(DhcpClientErrorDetail::InterfaceNotFound);
        };
        let previous = supervisor.spec(&interface).await;
        if previous.is_none() {
            return dhcp_client_error(DhcpClientErrorDetail::Disabled);
        }
        config.managed = false;
        config.dhcp_client = Some(dhcp_client_request_to_config(
            &DhcpClientConfigRequest::default(),
            false,
        ));

        if let Err(error) = self
            .overrides
            .check_interface(&interface, &config, false)
            .await
        {
            return dhcp_client_error(DhcpClientErrorDetail::InvalidConfig {
                message: error.to_string(),
            });
        }
        if let Err(error) = supervisor.disable(&interface).await {
            return dhcp_client_error(DhcpClientErrorDetail::OwnershipConflict {
                message: error.to_string(),
            });
        }
        if let Err(error) = self
            .overrides
            .set_interface(interface.clone(), config, false)
            .await
        {
            if let Some(previous) = previous {
                supervisor.configure(previous).await;
            }
            return dhcp_client_error(DhcpClientErrorDetail::PersistenceFailure {
                message: format!(
                    "failed to persist DHCP client disable; runtime state was restored: {error}"
                ),
            });
        }
        Response::DhcpClientDisabled { interface }
    }

    async fn renew_dhcp_client(&self, interface: String) -> Response {
        let Some(supervisor) = &self.dhcp_client else {
            return dhcp_client_error(DhcpClientErrorDetail::DhcpClientDisabled);
        };
        match supervisor.renew_now(&interface).await {
            Ok(status) => Response::DhcpClientInterface {
                status: dhcp_client_status_view(status),
            },
            Err(_) => dhcp_client_error(DhcpClientErrorDetail::Disabled),
        }
    }

    async fn release_dhcp_client(&self, interface: String) -> Response {
        let Some(supervisor) = &self.dhcp_client else {
            return dhcp_client_error(DhcpClientErrorDetail::DhcpClientDisabled);
        };
        match supervisor.release_and_reacquire(&interface).await {
            Ok(status) => Response::DhcpClientInterface {
                status: dhcp_client_status_view(status),
            },
            Err(error) => dhcp_client_error(DhcpClientErrorDetail::RuntimeFailure {
                message: error.to_string(),
            }),
        }
    }

    async fn wifi_client_status(&self) -> Response {
        let Some(wifi_client) = &self.wifi_client else {
            return wifi_client_disabled();
        };
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(message) => return wifi_client_error(WifiClientErrorDetail::Other { message }),
        };
        let mut interfaces = Vec::new();
        for (name, config) in &effective.network.interfaces {
            if config.wifi_client.is_some() {
                if let Some(status) = wifi_client.status(name).await {
                    interfaces.push(status);
                }
            }
        }
        Response::WifiClientStatus { interfaces }
    }

    async fn get_wifi_client_config(&self, interface: String) -> Response {
        if self.wifi_client.is_none() {
            return wifi_client_disabled();
        }
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(message) => return wifi_client_error(WifiClientErrorDetail::Other { message }),
        };
        let spec = match effective.network.interfaces.get(&interface) {
            Some(config) => match WifiClientSpec::from_interface_config(&interface, config) {
                Ok(spec) => spec,
                Err(error) => {
                    return wifi_client_error(WifiClientErrorDetail::InvalidSpec {
                        message: error.to_string(),
                    })
                }
            },
            None => None,
        };
        Response::WifiClientConfig { interface, spec }
    }

    async fn configure_wifi_client(
        &self,
        interface: String,
        settings: WifiClientEditRequest,
    ) -> Response {
        let Some(wifi_client) = &self.wifi_client else {
            return wifi_client_disabled();
        };
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(message) => return wifi_client_error(WifiClientErrorDetail::Other { message }),
        };
        let Some(mut interface_config) = effective.network.interfaces.get(&interface).cloned()
        else {
            return wifi_client_error(WifiClientErrorDetail::InterfaceNotFound);
        };

        interface_config.wifi_client = Some(wifi_client_edit_request_to_config(settings));

        let spec = match WifiClientSpec::from_interface_config(&interface, &interface_config) {
            Ok(Some(spec)) => spec,
            Ok(None) => {
                return wifi_client_error(WifiClientErrorDetail::InvalidSpec {
                    message: "a Wi-Fi client requires an unmanaged input interface".to_string(),
                })
            }
            Err(error) => {
                return wifi_client_error(WifiClientErrorDetail::InvalidSpec {
                    message: error.to_string(),
                })
            }
        };

        let _mutation = self.wifi_client_mutations.lock().await;
        let previous = wifi_client
            .status(&interface)
            .await
            .map(|status| status.spec);
        if let Err(error) = wifi_client.configure(spec.clone()).await {
            return classify_wifi_client_error(error);
        }
        if let Err(error) = self
            .overrides
            .set_interface(interface.clone(), interface_config, false)
            .await
        {
            match previous {
                Some(previous) => {
                    let _ = wifi_client.configure(previous).await;
                }
                None => {
                    let _ = wifi_client.disable(&interface).await;
                }
            }
            return wifi_client_error(WifiClientErrorDetail::Other {
                message: format!(
                    "failed to persist Wi-Fi client override; runtime state was restored: {error}"
                ),
            });
        }
        Response::WifiClientConfigured { spec }
    }

    async fn disable_wifi_client(&self, interface: String) -> Response {
        let Some(wifi_client) = &self.wifi_client else {
            return wifi_client_disabled();
        };
        let _mutation = self.wifi_client_mutations.lock().await;
        let previous = wifi_client
            .status(&interface)
            .await
            .map(|status| status.spec);

        if let Err(error) = wifi_client.disable(&interface).await {
            return classify_wifi_client_error(error);
        }

        let committed = match self.overrides.effective_interface(&interface).await {
            Ok(config) => config,
            Err(error) => {
                return wifi_client_error(WifiClientErrorDetail::Other {
                    message: error.to_string(),
                })
            }
        };
        let Some(mut interface_config) = committed else {
            return Response::WifiClientDisabled { interface };
        };
        interface_config.wifi_client = None;
        if let Err(error) = self
            .overrides
            .set_interface(interface.clone(), interface_config, false)
            .await
        {
            if let Some(previous) = previous {
                let _ = wifi_client.configure(previous).await;
            }
            return wifi_client_error(WifiClientErrorDetail::Other {
                message: format!(
                    "failed to persist Wi-Fi client disable; runtime state was restored: {error}"
                ),
            });
        }
        Response::WifiClientDisabled { interface }
    }

    async fn wifi_client_set_passphrase(&self, interface: String, passphrase: String) -> Response {
        let Some(wifi_client) = &self.wifi_client else {
            return wifi_client_disabled();
        };
        let passphrase = match WifiPassphrase::new(passphrase) {
            Ok(passphrase) => passphrase,
            Err(error) => {
                return wifi_client_error(WifiClientErrorDetail::InvalidSpec {
                    message: error.to_string(),
                })
            }
        };
        if let Err(error) = wifi_client.set_passphrase(&interface, &passphrase).await {
            return classify_wifi_client_error(error);
        }

        let Some(status) = wifi_client.status(&interface).await else {
            return wifi_client_error(WifiClientErrorDetail::InterfaceNotFound);
        };
        let spec = status.spec;
        match wifi_client.configure(spec.clone()).await {
            Ok(()) => Response::WifiClientConfigured { spec },
            Err(error) => classify_wifi_client_error(error),
        }
    }

    async fn list_wifi_client_profiles(&self) -> Response {
        if self.wifi_client.is_none() {
            return wifi_client_profile_error(WifiClientProfileErrorDetail::WifiClientDisabled);
        }
        match self.wifi_client_profiles.list() {
            Ok(profiles) => Response::WifiClientProfiles { profiles },
            Err(error) => classify_wifi_client_profile_error(error),
        }
    }

    async fn get_wifi_client_profile(&self, id: String) -> Response {
        if self.wifi_client.is_none() {
            return wifi_client_profile_error(WifiClientProfileErrorDetail::WifiClientDisabled);
        }
        match self.wifi_client_profiles.get(&id) {
            Ok(profile) => Response::WifiClientProfile { profile },
            Err(error) => classify_wifi_client_profile_error(error),
        }
    }

    async fn create_wifi_client_profile(
        &self,
        mut request: WifiClientProfileWriteRequest,
    ) -> Response {
        if self.wifi_client.is_none() {
            return wifi_client_profile_error(WifiClientProfileErrorDetail::WifiClientDisabled);
        }
        let _mutation = self.wifi_client_mutations.lock().await;
        let passphrase = match request.passphrase.take() {
            Some(raw) => match WifiPassphrase::new(&raw) {
                Ok(passphrase) => Some(passphrase),
                Err(error) => {
                    return wifi_client_profile_error(
                        WifiClientProfileErrorDetail::InvalidProfile {
                            message: error.to_string(),
                        },
                    )
                }
            },
            None => None,
        };
        let input = wifi_client_profile_input(request);
        match self.wifi_client_profiles.create(input, passphrase) {
            Ok(profile) => Response::WifiClientProfile { profile },
            Err(error) => classify_wifi_client_profile_error(error),
        }
    }

    async fn update_wifi_client_profile(
        &self,
        id: String,
        mut request: WifiClientProfileWriteRequest,
    ) -> Response {
        if self.wifi_client.is_none() {
            return wifi_client_profile_error(WifiClientProfileErrorDetail::WifiClientDisabled);
        }
        if request.id != id {
            return wifi_client_profile_error(WifiClientProfileErrorDetail::InvalidProfile {
                message: "profile id in the path and body must match".to_string(),
            });
        }
        if request.clear_passphrase && request.passphrase.is_some() {
            return wifi_client_profile_error(WifiClientProfileErrorDetail::InvalidProfile {
                message: "passphrase and clear_passphrase are mutually exclusive".to_string(),
            });
        }
        let _mutation = self.wifi_client_mutations.lock().await;
        let secret_update = if request.clear_passphrase {
            WifiClientProfileSecretUpdate::Clear
        } else if let Some(raw) = request.passphrase.take() {
            match WifiPassphrase::new(&raw) {
                Ok(passphrase) => WifiClientProfileSecretUpdate::Replace(passphrase),
                Err(error) => {
                    return wifi_client_profile_error(
                        WifiClientProfileErrorDetail::InvalidProfile {
                            message: error.to_string(),
                        },
                    )
                }
            }
        } else {
            WifiClientProfileSecretUpdate::Unchanged
        };
        let input = wifi_client_profile_input(request);
        match self.wifi_client_profiles.update(input, secret_update) {
            Ok(profile) => Response::WifiClientProfile { profile },
            Err(error) => classify_wifi_client_profile_error(error),
        }
    }

    async fn delete_wifi_client_profile(&self, id: String) -> Response {
        let Some(wifi_client) = &self.wifi_client else {
            return wifi_client_profile_error(WifiClientProfileErrorDetail::WifiClientDisabled);
        };
        let _mutation = self.wifi_client_mutations.lock().await;
        let profile = match self.wifi_client_profiles.get(&id) {
            Ok(profile) => profile,
            Err(error) => return classify_wifi_client_profile_error(error),
        };
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(message) => {
                return wifi_client_profile_error(WifiClientProfileErrorDetail::Other { message })
            }
        };
        let mut active = Vec::new();
        for interface in effective.network.interfaces.keys() {
            if let Some(status) = wifi_client.status(interface).await {
                if status.spec.ssid == profile.ssid
                    && status.spec.country_code == profile.country_code
                    && status.spec.security == profile.security
                {
                    active.push(interface.clone());
                }
            }
        }
        if !active.is_empty() {
            return wifi_client_profile_error(WifiClientProfileErrorDetail::ProfileActive {
                interfaces: active,
            });
        }
        match self.wifi_client_profiles.delete(&id) {
            Ok(()) => Response::WifiClientProfileDeleted { id },
            Err(error) => classify_wifi_client_profile_error(error),
        }
    }

    async fn activate_wifi_client_profile(
        &self,
        interface: String,
        profile_id: String,
    ) -> Response {
        let Some(wifi_client) = &self.wifi_client else {
            return wifi_client_profile_error(WifiClientProfileErrorDetail::WifiClientDisabled);
        };
        let _mutation = self.wifi_client_mutations.lock().await;
        let profile = match self.wifi_client_profiles.get(&profile_id) {
            Ok(profile) => profile,
            Err(error) => return classify_wifi_client_profile_error(error),
        };
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(message) => {
                return wifi_client_profile_error(WifiClientProfileErrorDetail::Other { message })
            }
        };
        let Some(mut interface_config) = effective.network.interfaces.get(&interface).cloned()
        else {
            return wifi_client_profile_error(WifiClientProfileErrorDetail::InterfaceNotFound);
        };
        interface_config.wifi_client = Some(WifiClientConfig {
            ssid: profile.ssid.clone(),
            country_code: profile.country_code.clone(),
            security: profile.security,
            passphrase_file: None,
        });
        let spec = match WifiClientSpec::from_interface_config(&interface, &interface_config) {
            Ok(Some(spec)) => spec,
            Ok(None) | Err(_) => {
                return wifi_client_profile_error(WifiClientProfileErrorDetail::InvalidProfile {
                    message: "profile activation requires an unmanaged input interface".to_string(),
                })
            }
        };

        let previous_status = wifi_client.status(&interface).await;
        let previous_secret = match wifi_client.stored_passphrase(&interface).await {
            Ok(secret) => secret,
            Err(error) => {
                return wifi_client_profile_error(WifiClientProfileErrorDetail::ActivationFailed {
                    message: error.to_string(),
                })
            }
        };
        let profile_secret = match self.wifi_client_profiles.get_passphrase(&profile_id) {
            Ok(secret) => secret,
            Err(error) => return classify_wifi_client_profile_error(error),
        };
        let secret_result = match profile_secret.as_ref() {
            Some(secret) => wifi_client.set_passphrase(&interface, secret).await,
            None => wifi_client.clear_passphrase(&interface).await,
        };
        if let Err(error) = secret_result {
            return wifi_client_profile_error(WifiClientProfileErrorDetail::ActivationFailed {
                message: error.to_string(),
            });
        }
        if let Err(error) = wifi_client.configure(spec).await {
            restore_wifi_client_secret(wifi_client, &interface, previous_secret.as_ref()).await;
            return wifi_client_profile_error(WifiClientProfileErrorDetail::ActivationFailed {
                message: error.to_string(),
            });
        }
        if let Err(error) = self
            .overrides
            .set_interface(interface.clone(), interface_config, false)
            .await
        {
            restore_wifi_client_secret(wifi_client, &interface, previous_secret.as_ref()).await;
            match previous_status {
                Some(previous) => {
                    let _ = wifi_client.configure(previous.spec).await;
                }
                None => {
                    let _ = wifi_client.disable(&interface).await;
                }
            }
            return wifi_client_profile_error(WifiClientProfileErrorDetail::PersistenceFailed {
                message: error.to_string(),
            });
        }
        match wifi_client.status(&interface).await {
            Some(status) => Response::WifiClientProfileActivated {
                interface,
                profile,
                status,
            },
            None => wifi_client_profile_error(WifiClientProfileErrorDetail::ActivationFailed {
                message: "supplicant disappeared after profile activation".to_string(),
            }),
        }
    }

    async fn wifi_client_scan(&self, interface: String) -> Response {
        let Some(wifi_client) = &self.wifi_client else {
            return wifi_client_disabled();
        };
        match wifi_client.scan(&interface).await {
            Ok(results) => Response::WifiClientScanResults { interface, results },
            Err(error) => classify_wifi_client_error(error),
        }
    }

    async fn wifi_client_reconnect(&self, interface: String) -> Response {
        let Some(wifi_client) = &self.wifi_client else {
            return wifi_client_disabled();
        };
        if let Err(error) = wifi_client.reconnect(&interface).await {
            return classify_wifi_client_error(error);
        }

        match wifi_client.status(&interface).await {
            Some(status) => Response::WifiClientConfigured { spec: status.spec },
            None => wifi_client_error(WifiClientErrorDetail::InterfaceNotFound),
        }
    }

    async fn effective_config(&self) -> Result<AppConfig, String> {
        self.overrides
            .snapshot()
            .await
            .effective_config(&self.config)
            .map_err(|error| error.to_string())
    }

    async fn router_status(&self) -> Response {
        let Some(router) = &self.router else {
            return router_disabled();
        };
        let desired = match self.current_router_desired().await {
            Ok(desired) => desired,
            Err(response) => return response,
        };
        let health = router.manager().health(&desired).await;
        let coordinator_status = router.status().await;
        Response::RouterStatus {
            enabled: desired.enabled,
            ready: desired.enabled && health.ready(),
            coordinator_status,
            health,
        }
    }

    async fn router_plan(&self, proposal: RouterProposalRequest) -> Response {
        let Some(router) = &self.router else {
            return router_disabled();
        };
        let candidate = match self
            .overrides
            .build_candidate(&build_router_proposal(proposal))
            .await
        {
            Ok(candidate) => candidate,
            Err(error) => return classify_router_error(error),
        };
        match router.plan(candidate).await {
            Ok(plan) => Response::RouterPlan {
                plan: plan.plan().clone(),
            },
            Err(error) => classify_router_error(error),
        }
    }

    async fn router_apply(&self, proposal: RouterProposalRequest) -> Response {
        let Some(router) = &self.router else {
            return router_disabled();
        };
        let candidate = match self
            .overrides
            .build_candidate(&build_router_proposal(proposal))
            .await
        {
            Ok(candidate) => candidate,
            Err(error) => return classify_router_error(error),
        };
        let transaction_plan = match router.plan(candidate).await {
            Ok(plan) => plan,
            Err(error) => return classify_router_error(error),
        };
        let plan_preview = transaction_plan.plan().clone();
        match router.apply(transaction_plan).await {
            Ok(token) => Response::RouterTransactionPending {
                token,
                plan: plan_preview,
            },
            Err(error) => classify_router_error(error),
        }
    }

    async fn router_commit(&self) -> Response {
        let Some(router) = &self.router else {
            return router_disabled();
        };
        match router.commit().await {
            Ok(revision) => Response::RouterCommitted { revision },
            Err(error) => classify_router_error(error),
        }
    }

    async fn router_rollback(&self) -> Response {
        let Some(router) = &self.router else {
            return router_disabled();
        };
        match router.rollback().await {
            Ok(()) => Response::RouterRolledBack,
            Err(error) => {
                if let Some(failure) = router.rollback_failure().await {
                    Response::RouterError {
                        detail: RouterErrorDetail::RollbackFailed {
                            failures: failure.failures,
                        },
                    }
                } else {
                    classify_router_error(error)
                }
            }
        }
    }

    async fn router_pending_transaction(&self) -> Response {
        let Some(router) = &self.router else {
            return router_disabled();
        };
        let status = router.status().await;
        let rollback_failure = router
            .rollback_failure()
            .await
            .map(|failure| failure.failures);
        Response::RouterPendingTransaction {
            status,
            rollback_failure,
        }
    }

    async fn router_provisioning_preview(
        &self,
        request: RouterProvisioningPreviewRequest,
    ) -> Response {
        if self.router.is_none() {
            return provisioning_error(RouterProvisioningErrorDetail::RouterDisabled);
        }

        let desired = provisioning_desired(&request.provisioning);
        let secrets = ProvisioningSecretAvailability {
            uplink_pending: request.uplink_secret_pending,
            output_pending: request.output_secret_pending,
        };
        let context = match self.provisioning_context(&desired, secrets).await {
            Ok(context) => context,
            Err(detail) => return provisioning_error(detail),
        };

        match derive_router_provisioning(&desired, &context) {
            Ok(effective) => Response::RouterProvisioningPreview {
                preview: provisioning_preview_view(
                    &request.provisioning,
                    &effective,
                    &context,
                    secrets,
                ),
            },
            Err(error) => provisioning_error(classify_provisioning_derivation_error(error)),
        }
    }

    async fn router_provisioning_apply(&self, request: RouterProvisioningApplyRequest) -> Response {
        let Some(router) = &self.router else {
            return provisioning_error(RouterProvisioningErrorDetail::RouterDisabled);
        };

        let uplink_passphrase = match parse_optional_passphrase(request.uplink_passphrase.clone()) {
            Ok(passphrase) => passphrase,
            Err(detail) => return provisioning_error(detail),
        };
        let output_passphrase = match parse_optional_passphrase(request.output_passphrase.clone()) {
            Ok(passphrase) => passphrase,
            Err(detail) => return provisioning_error(detail),
        };

        let desired = provisioning_desired(&request.provisioning);
        let context = match self
            .provisioning_context(
                &desired,
                ProvisioningSecretAvailability {
                    uplink_pending: uplink_passphrase.is_some(),
                    output_pending: output_passphrase.is_some(),
                },
            )
            .await
        {
            Ok(context) => context,
            Err(detail) => return provisioning_error(detail),
        };
        let effective = match derive_router_provisioning(&desired, &context) {
            Ok(effective) => effective,
            Err(error) => return provisioning_error(classify_provisioning_derivation_error(error)),
        };

        let preview = provisioning_preview_view(
            &request.provisioning,
            &effective,
            &context,
            ProvisioningSecretAvailability::default(),
        );

        let _wifi_mutation = self.wifi_mutations.lock().await;
        let _wifi_client_mutation = self.wifi_client_mutations.lock().await;

        let uplink_interface = desired.uplink.interface.clone();
        let output_interface = desired.output.interface.clone();
        let mut staged_uplink = None;
        let mut staged_output = None;

        if let Some(passphrase) = &output_passphrase {
            let Some(supervisor) = &self.wifi else {
                return provisioning_error(RouterProvisioningErrorDetail::GlobalServiceDisabled {
                    service: "wifi".to_owned(),
                });
            };
            let previous = match supervisor.stored_passphrase(&output_interface).await {
                Ok(previous) => previous,
                Err(error) => {
                    return provisioning_error(RouterProvisioningErrorDetail::Other {
                        message: error.to_string(),
                    })
                }
            };
            if let Err(error) = supervisor
                .set_passphrase(&output_interface, passphrase)
                .await
            {
                return provisioning_error(RouterProvisioningErrorDetail::InvalidSecret {
                    message: error.to_string(),
                });
            }
            staged_output = Some(previous);
        }

        if let Some(passphrase) = &uplink_passphrase {
            let Some(supervisor) = &self.wifi_client else {
                self.restore_staged_provisioning_secrets(
                    &uplink_interface,
                    staged_uplink,
                    &output_interface,
                    staged_output,
                )
                .await;
                return provisioning_error(RouterProvisioningErrorDetail::GlobalServiceDisabled {
                    service: "wifi_client".to_owned(),
                });
            };
            let previous = match supervisor.stored_passphrase(&uplink_interface).await {
                Ok(previous) => previous,
                Err(error) => {
                    self.restore_staged_provisioning_secrets(
                        &uplink_interface,
                        staged_uplink,
                        &output_interface,
                        staged_output,
                    )
                    .await;
                    return provisioning_error(RouterProvisioningErrorDetail::Other {
                        message: error.to_string(),
                    });
                }
            };
            if let Err(error) = supervisor
                .set_passphrase(&uplink_interface, passphrase)
                .await
            {
                self.restore_staged_provisioning_secrets(
                    &uplink_interface,
                    staged_uplink,
                    &output_interface,
                    staged_output,
                )
                .await;
                return provisioning_error(RouterProvisioningErrorDetail::InvalidSecret {
                    message: error.to_string(),
                });
            }
            staged_uplink = Some(previous);
        }

        let proposal = effective.into_router_intent_proposal();
        let candidate = match self.overrides.build_candidate(&proposal).await {
            Ok(candidate) => candidate,
            Err(error) => {
                self.restore_staged_provisioning_secrets(
                    &uplink_interface,
                    staged_uplink,
                    &output_interface,
                    staged_output,
                )
                .await;
                return provisioning_error(classify_provisioning_transaction_error(&error));
            }
        };
        let transaction_plan = match router.plan(candidate).await {
            Ok(plan) => plan,
            Err(error) => {
                self.restore_staged_provisioning_secrets(
                    &uplink_interface,
                    staged_uplink,
                    &output_interface,
                    staged_output,
                )
                .await;
                return provisioning_error(classify_provisioning_transaction_error(&error));
            }
        };
        match router.apply(transaction_plan).await {
            Ok(token) => Response::RouterProvisioningApplied { token, preview },
            Err(error) => {
                self.restore_staged_provisioning_secrets(
                    &uplink_interface,
                    staged_uplink,
                    &output_interface,
                    staged_output,
                )
                .await;
                provisioning_error(classify_provisioning_transaction_error(&error))
            }
        }
    }

    async fn router_provisioning_status(&self) -> Response {
        let Some(router) = &self.router else {
            return provisioning_error(RouterProvisioningErrorDetail::RouterDisabled);
        };
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(message) => {
                return provisioning_error(RouterProvisioningErrorDetail::Other { message })
            }
        };
        let desired = match RouterDesired::from_effective_config(&effective) {
            Ok(desired) => desired,
            Err(error) => {
                return provisioning_error(RouterProvisioningErrorDetail::InvalidConfiguration {
                    message: error.to_string(),
                })
            }
        };

        let readiness = router.manager().health(&desired).await;
        let coordinator = router.status().await;
        let failures = router
            .rollback_failure()
            .await
            .map(|failure| failure.failures)
            .unwrap_or_default();
        let ready = desired.enabled && readiness.ready();
        let stage = match coordinator {
            CoordinatorStatus::RollbackFailed => ProvisioningStage::RollbackFailed,
            CoordinatorStatus::Pending => ProvisioningStage::AwaitingConfirmation,
            CoordinatorStatus::Idle if !desired.enabled => ProvisioningStage::Inactive,
            CoordinatorStatus::Idle if ready => ProvisioningStage::Ready,
            CoordinatorStatus::Idle => ProvisioningStage::Degraded,
        };

        Response::RouterProvisioningStatus {
            status: RouterProvisioningStatusView {
                stage,
                enabled: desired.enabled,
                ready,
                coordinator,
                readiness,
                failures,
            },
        }
    }

    async fn router_provisioning_repair(&self) -> Response {
        let Some(router) = &self.router else {
            return provisioning_error(RouterProvisioningErrorDetail::RouterDisabled);
        };
        let effective = match self.effective_config().await {
            Ok(effective) => effective,
            Err(message) => {
                return provisioning_error(RouterProvisioningErrorDetail::Other { message })
            }
        };
        let desired = match RouterDesired::from_effective_config(&effective) {
            Ok(desired) if desired.enabled => desired,
            Ok(_) => return provisioning_error(RouterProvisioningErrorDetail::RouterDisabled),
            Err(error) => {
                return provisioning_error(RouterProvisioningErrorDetail::InvalidConfiguration {
                    message: error.to_string(),
                })
            }
        };

        if let Err(error) = router.repair(desired).await {
            return provisioning_error(classify_provisioning_transaction_error(&error));
        }
        match self.router_provisioning_status().await {
            Response::RouterProvisioningStatus { status } => {
                Response::RouterProvisioningRepaired { status }
            }
            response => response,
        }
    }

    async fn provisioning_context(
        &self,
        desired: &RouterProvisioningDesired,
        secrets: ProvisioningSecretAvailability,
    ) -> Result<RouterProvisioningContext, RouterProvisioningErrorDetail> {
        let effective_config = self
            .effective_config()
            .await
            .map_err(|message| RouterProvisioningErrorDetail::Other { message })?;
        let observed = self.network.list_interfaces().await.map_err(|error| {
            RouterProvisioningErrorDetail::Other {
                message: error.to_string(),
            }
        })?;

        let provisioned = [
            desired.uplink.interface.as_str(),
            desired.output.interface.as_str(),
        ];
        let mut interfaces = BTreeMap::new();
        let mut known_networks = Vec::new();

        for interface in &observed {
            interfaces.insert(
                interface.name.clone(),
                ProvisioningInterfaceObservation {
                    role: effective_config
                        .network
                        .interfaces
                        .get(&interface.name)
                        .map(|config| config.role),
                    wireless_phy: if interface.is_wireless {
                        crate::netlink::wireless_phy(&interface.name)
                    } else {
                        None
                    },
                },
            );

            if provisioned.contains(&interface.name.as_str()) {
                continue;
            }
            let addresses = self
                .network
                .list_ipv4_addresses(&interface.name)
                .await
                .map_err(|error| RouterProvisioningErrorDetail::Other {
                    message: error.to_string(),
                })?;
            for address in addresses {
                if let Ok(network) = ipnet::Ipv4Net::new(address.address, address.prefix_len) {
                    known_networks.push(ProvisioningKnownNetwork {
                        network: network.trunc(),
                        source: format!("observed {}", interface.name),
                    });
                }
            }
        }

        for (name, config) in &effective_config.network.interfaces {
            if provisioned.contains(&name.as_str()) {
                continue;
            }
            if let Some(ipv4) = config.ipv4 {
                known_networks.push(ProvisioningKnownNetwork {
                    network: ipv4.trunc(),
                    source: format!("configured {name}"),
                });
            }
        }

        let mut runtime_sta_secrets = BTreeSet::new();
        if secrets.uplink_pending
            || self
                .stored_uplink_secret(&desired.uplink.interface)
                .await
                .map_err(|message| RouterProvisioningErrorDetail::Other { message })?
        {
            runtime_sta_secrets.insert(desired.uplink.interface.clone());
        }
        let mut runtime_ap_secrets = BTreeSet::new();
        if secrets.output_pending
            || self
                .stored_output_secret(&desired.output.interface)
                .await
                .map_err(|message| RouterProvisioningErrorDetail::Other { message })?
        {
            runtime_ap_secrets.insert(desired.output.interface.clone());
        }

        Ok(RouterProvisioningContext {
            effective_config,
            interfaces,
            known_networks,
            runtime_ap_secrets,
            runtime_sta_secrets,
        })
    }

    async fn stored_uplink_secret(&self, interface: &str) -> Result<bool, String> {
        let Some(supervisor) = &self.wifi_client else {
            return Ok(false);
        };
        supervisor
            .stored_passphrase(interface)
            .await
            .map(|secret| secret.is_some())
            .map_err(|error| error.to_string())
    }

    async fn stored_output_secret(&self, interface: &str) -> Result<bool, String> {
        let Some(supervisor) = &self.wifi else {
            return Ok(false);
        };
        supervisor
            .stored_passphrase(interface)
            .await
            .map(|secret| secret.is_some())
            .map_err(|error| error.to_string())
    }

    async fn restore_staged_provisioning_secrets(
        &self,
        uplink_interface: &str,
        staged_uplink: Option<Option<WifiPassphrase>>,
        output_interface: &str,
        staged_output: Option<Option<WifiPassphrase>>,
    ) {
        if let (Some(previous), Some(supervisor)) = (staged_uplink, self.wifi_client.as_ref()) {
            restore_wifi_client_secret(supervisor, uplink_interface, previous.as_ref()).await;
        }
        if let (Some(previous), Some(supervisor)) = (staged_output, self.wifi.as_ref()) {
            restore_wifi_secret(supervisor, output_interface, previous.as_ref()).await;
        }
    }

    async fn current_router_desired(&self) -> Result<RouterDesired, Response> {
        let snapshot = self.overrides.snapshot().await;
        let effective = snapshot
            .effective_config(&self.config)
            .map_err(classify_router_error)?;
        RouterDesired::from_effective_config(&effective).map_err(classify_router_error)
    }
}

fn router_disabled() -> Response {
    Response::RouterError {
        detail: RouterErrorDetail::RouterDisabled,
    }
}

fn provisioning_error(detail: RouterProvisioningErrorDetail) -> Response {
    Response::RouterProvisioningError { detail }
}

#[derive(Debug, Clone, Copy, Default)]
struct ProvisioningSecretAvailability {
    uplink_pending: bool,
    output_pending: bool,
}

fn provisioning_desired(request: &RouterProvisioningRequest) -> RouterProvisioningDesired {
    RouterProvisioningDesired {
        uplink: ProvisioningUplink {
            interface: request.uplink.interface.clone(),
            ssid: request.uplink.ssid.clone(),
            country_code: request.uplink.country_code.clone(),
            security: request.uplink.security,
            passphrase_file: None,
        },
        output: ProvisioningOutput {
            interface: request.output.interface.clone(),
            ssid: request.output.ssid.clone(),
            country_code: request.output.country_code.clone(),
            band: request.output.band,
            channel: request.output.channel,
            channel_width: request.output.channel_width,
            security: request.output.security,
            hidden: request.output.hidden,
            client_isolation: request.output.client_isolation,
            max_stations: request.output.max_stations,
            passphrase_file: None,
        },
        downstream: request.downstream.clone(),
        allow_management_change: request.allow_management_change,
    }
}

fn parse_optional_passphrase(
    value: Option<String>,
) -> Result<Option<WifiPassphrase>, RouterProvisioningErrorDetail> {
    value.map(WifiPassphrase::new).transpose().map_err(|error| {
        RouterProvisioningErrorDetail::InvalidSecret {
            message: error.to_string(),
        }
    })
}

fn preferred_downstream_subnet() -> ipnet::Ipv4Net {
    ipnet::Ipv4Net::new(
        std::net::Ipv4Addr::new(10, 77, DEFAULT_DOWNSTREAM_THIRD_OCTET, 0),
        DEFAULT_DOWNSTREAM_PREFIX,
    )
    .expect("documented default downstream candidate is valid")
}

fn provisioning_preview_view(
    request: &RouterProvisioningRequest,
    effective: &RouterProvisioningEffective,
    context: &RouterProvisioningContext,
    secrets: ProvisioningSecretAvailability,
) -> RouterProvisioningPreviewView {
    let uplink_interface = &request.uplink.interface;
    let output_interface = &request.output.interface;
    let dhcp = effective
        .output_interface
        .dhcp
        .as_ref()
        .expect("derived output interface always carries a DHCP service");
    let interface_ipv4 = effective
        .output_interface
        .ipv4
        .expect("derived output interface always carries an IPv4 address");

    let mut warnings = Vec::new();
    for interface in [uplink_interface, output_interface] {
        if context
            .interfaces
            .get(interface)
            .is_some_and(|observation| observation.role == Some(InterfaceRole::Management))
        {
            warnings.push(ProvisioningWarning::ManagementInterfaceAffected {
                interface: interface.clone(),
            });
        }
    }
    if request.downstream.interface_ipv4.is_none() {
        let preferred = preferred_downstream_subnet();
        if effective.downstream_subnet != preferred {
            warnings.push(ProvisioningWarning::DownstreamSubnetRelocated {
                preferred,
                selected: effective.downstream_subnet,
            });
        }
    }
    if effective.dns_servers.is_empty() {
        warnings.push(ProvisioningWarning::NoDownstreamDns);
    }
    for (interface, derived) in [
        (uplink_interface, &effective.uplink_interface),
        (output_interface, &effective.output_interface),
    ] {
        if context
            .effective_config
            .network
            .interfaces
            .get(interface)
            .is_some_and(|current| current != derived)
        {
            warnings.push(ProvisioningWarning::InterfaceConfigurationReplaced {
                interface: interface.clone(),
            });
        }
    }
    if secrets.uplink_pending {
        warnings.push(ProvisioningWarning::PendingSecret {
            interface: uplink_interface.clone(),
        });
    }
    if secrets.output_pending {
        warnings.push(ProvisioningWarning::PendingSecret {
            interface: output_interface.clone(),
        });
    }

    RouterProvisioningPreviewView {
        uplink: ProvisioningUplinkView {
            interface: uplink_interface.clone(),
            ssid: request.uplink.ssid.clone(),
            country_code: request.uplink.country_code.clone(),
            security: request.uplink.security,
            mode: effective
                .router
                .uplink
                .as_ref()
                .map_or(UplinkMode::Dhcp, |uplink| uplink.mode),
            secret_available: context.runtime_sta_secrets.contains(uplink_interface),
        },
        output: ProvisioningOutputView {
            interface: output_interface.clone(),
            ssid: request.output.ssid.clone(),
            country_code: request.output.country_code.clone(),
            band: request.output.band,
            channel: request.output.channel,
            channel_width: request.output.channel_width,
            security: request.output.security,
            hidden: request.output.hidden,
            client_isolation: request.output.client_isolation,
            max_stations: request.output.max_stations,
            secret_available: context.runtime_ap_secrets.contains(output_interface),
        },
        downstream: ProvisioningDownstreamView {
            subnet: effective.downstream_subnet,
            interface_ipv4,
            router: dhcp.router,
            pool_start: dhcp.pool_start,
            pool_end: dhcp.pool_end,
            dns_servers: effective.dns_servers.clone(),
            lease_seconds: dhcp.lease_seconds.unwrap_or(DEFAULT_DHCP_LEASE_SECONDS),
        },
        warnings,
    }
}

fn classify_provisioning_derivation_error(
    error: RouterProvisioningError,
) -> RouterProvisioningErrorDetail {
    match error {
        RouterProvisioningError::InterfaceReused { interface } => {
            RouterProvisioningErrorDetail::InterfaceReused { interface }
        }
        RouterProvisioningError::InterfaceNotFound { interface } => {
            RouterProvisioningErrorDetail::InterfaceNotFound { interface }
        }
        RouterProvisioningError::RadioReused {
            phy,
            uplink,
            output,
        } => RouterProvisioningErrorDetail::RadioReused {
            phy,
            uplink,
            output,
        },
        RouterProvisioningError::ManagementConfirmationRequired { interface } => {
            RouterProvisioningErrorDetail::ManagementConfirmationRequired { interface }
        }
        RouterProvisioningError::GlobalServiceDisabled { service } => {
            RouterProvisioningErrorDetail::GlobalServiceDisabled {
                service: service.to_owned(),
            }
        }
        RouterProvisioningError::MissingUplinkSecret { interface } => {
            RouterProvisioningErrorDetail::UplinkSecretMissing { interface }
        }
        RouterProvisioningError::MissingOutputSecret { interface } => {
            RouterProvisioningErrorDetail::OutputSecretMissing { interface }
        }
        RouterProvisioningError::SubnetConflict {
            requested,
            conflicting,
            conflict_source,
        } => RouterProvisioningErrorDetail::SubnetConflict {
            requested,
            conflicting,
            conflict_source,
        },
        RouterProvisioningError::NoAvailableDownstreamSubnet => {
            RouterProvisioningErrorDetail::NoAvailableSubnet
        }
        error @ (RouterProvisioningError::PartialDhcpPool
        | RouterProvisioningError::PoolWithoutExplicitNetwork) => {
            RouterProvisioningErrorDetail::InvalidPool {
                message: error.to_string(),
            }
        }
        RouterProvisioningError::InvalidEffectiveConfig(message) => {
            RouterProvisioningErrorDetail::InvalidConfiguration { message }
        }
    }
}

fn classify_provisioning_transaction_error(error: &anyhow::Error) -> RouterProvisioningErrorDetail {
    if let Some(conflict) = error.downcast_ref::<CoordinatorConflict>() {
        return match conflict {
            CoordinatorConflict::TransactionPending => {
                RouterProvisioningErrorDetail::TransactionPending
            }
            CoordinatorConflict::RollbackRecoveryRequired => {
                RouterProvisioningErrorDetail::RollbackRecoveryRequired
            }
        };
    }
    if let Some(stale) = error.downcast_ref::<StaleCandidateError>() {
        return RouterProvisioningErrorDetail::StaleCandidate {
            candidate_revision: stale.candidate,
            current_revision: stale.current,
        };
    }
    if error
        .downcast_ref::<crate::core::router_transaction::StalePlanError>()
        .is_some()
    {
        return RouterProvisioningErrorDetail::StalePlan;
    }
    if let Some(apply) = error.downcast_ref::<RouterApplyError>() {
        if !apply.rollback_failures.is_empty() {
            return RouterProvisioningErrorDetail::RollbackFailed {
                failures: apply.rollback_failures.clone(),
            };
        }
        if apply.original.contains("readiness timed out") {
            return RouterProvisioningErrorDetail::ReadinessTimeout {
                detail: apply.original.clone(),
            };
        }
        return RouterProvisioningErrorDetail::ApplyFailed {
            detail: apply.original.clone(),
        };
    }
    RouterProvisioningErrorDetail::Other {
        message: error.to_string(),
    }
}

fn vpn_disabled() -> Response {
    Response::VpnError {
        detail: VpnErrorDetail::VpnDisabled,
    }
}

fn vpn_policy_disabled() -> Response {
    vpn_policy_error(VpnPolicyErrorDetail::VpnDisabled)
}

fn vpn_policy_error(detail: VpnPolicyErrorDetail) -> Response {
    Response::VpnPolicyError { detail }
}

fn classify_vpn_policy_error(error: &anyhow::Error) -> VpnPolicyErrorDetail {
    let message = error.to_string();
    tracing::warn!(error = %message, "VPN policy request failed");
    if message.contains("no active VPN tunnel")
        || message.contains("does not match the expected VPN policy interface")
    {
        VpnPolicyErrorDetail::TunnelUnhealthy { message }
    } else if message.contains("foreign objects occupy the reserved namespace") {
        VpnPolicyErrorDetail::ReservedNamespaceConflict { message }
    } else {
        VpnPolicyErrorDetail::Other { message }
    }
}

fn classify_vpn_error(error: ManagerError) -> Response {
    tracing::warn!(error = %error, "VPN request failed");
    let detail = match error {
        ManagerError::Driver(VpnDriverError::Store(StoreError::NotFound(name))) => {
            VpnErrorDetail::NotFound { name }
        }
        ManagerError::Driver(VpnDriverError::Store(StoreError::Profile(profile_error)))
        | ManagerError::Driver(VpnDriverError::Profile(profile_error)) => {
            VpnErrorDetail::InvalidProfile {
                message: profile_error.to_string(),
            }
        }
        ManagerError::AlreadyActive => VpnErrorDetail::AlreadyActive,
        ManagerError::NotActive => VpnErrorDetail::NotActive,
        ManagerError::ForeignInterfaceConflict(_) | ManagerError::OwnershipProofFailed(_) => {
            VpnErrorDetail::ForeignInterfaceConflict
        }
        other => VpnErrorDetail::Other {
            message: other.to_string(),
        },
    };
    Response::VpnError { detail }
}

fn wifi_disabled() -> Response {
    Response::WifiError {
        detail: WifiErrorDetail::WifiDisabled,
    }
}

fn wifi_error(detail: WifiErrorDetail) -> Response {
    Response::WifiError { detail }
}

fn classify_wifi_error(error: SupervisorError) -> Response {
    tracing::warn!(error = %error, "Wi-Fi request failed");
    let detail = match error {
        SupervisorError::NotConfigured { .. } => WifiErrorDetail::InterfaceNotFound,
        SupervisorError::NotOwned { .. } => WifiErrorDetail::NotOwned,
        SupervisorError::StartupTimeout { .. } => WifiErrorDetail::CtrlTimeout,
        SupervisorError::Ctrl(CtrlError::Timeout(_)) => WifiErrorDetail::CtrlTimeout,
        SupervisorError::Ctrl(error) => WifiErrorDetail::HostapdFailed {
            message: error.to_string(),
        },
        SupervisorError::Process(ProcessError::Spawn { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            WifiErrorDetail::HostapdMissing
        }
        SupervisorError::Process(error) => WifiErrorDetail::HostapdFailed {
            message: error.to_string(),
        },
        SupervisorError::Render(RenderError::PassphraseRequired { .. }) => {
            WifiErrorDetail::PassphraseMissing
        }
        SupervisorError::Render(error) => WifiErrorDetail::InvalidSpec {
            message: error.to_string(),
        },
        SupervisorError::ResolvePassphrase(ResolvePassphraseError::Empty(_)) => {
            WifiErrorDetail::PassphraseMissing
        }
        SupervisorError::ResolvePassphrase(error) => WifiErrorDetail::Other {
            message: error.to_string(),
        },
        SupervisorError::Record(error) => WifiErrorDetail::Other {
            message: error.to_string(),
        },
        SupervisorError::Configuration(error) => WifiErrorDetail::InvalidSpec {
            message: error.to_string(),
        },
    };
    Response::WifiError { detail }
}

fn wifi_client_disabled() -> Response {
    Response::WifiClientError {
        detail: WifiClientErrorDetail::WifiClientDisabled,
    }
}

fn wifi_client_profile_input(request: WifiClientProfileWriteRequest) -> WifiClientProfileInput {
    WifiClientProfileInput {
        id: request.id,
        ssid: request.ssid,
        country_code: request.country_code,
        security: request.security,
        priority: request.priority,
    }
}

async fn restore_wifi_client_secret(
    supervisor: &WifiClientSupervisor,
    interface: &str,
    previous: Option<&WifiPassphrase>,
) {
    match previous {
        Some(passphrase) => {
            let _ = supervisor.set_passphrase(interface, passphrase).await;
        }
        None => {
            let _ = supervisor.clear_passphrase(interface).await;
        }
    }
}

fn wifi_client_profile_error(detail: WifiClientProfileErrorDetail) -> Response {
    Response::WifiClientProfileError { detail }
}

fn classify_wifi_client_profile_error(error: WifiClientProfileError) -> Response {
    tracing::warn!(error = %error, "Wi-Fi client profile request failed");
    let detail = match error {
        WifiClientProfileError::InvalidId | WifiClientProfileError::InvalidProfile(_) => {
            WifiClientProfileErrorDetail::InvalidProfile {
                message: error.to_string(),
            }
        }
        WifiClientProfileError::AlreadyExists => WifiClientProfileErrorDetail::ProfileAlreadyExists,
        WifiClientProfileError::NotFound => WifiClientProfileErrorDetail::ProfileNotFound,
        WifiClientProfileError::Passphrase(_) => WifiClientProfileErrorDetail::InvalidProfile {
            message: error.to_string(),
        },
        WifiClientProfileError::Io(_)
        | WifiClientProfileError::Errno(_)
        | WifiClientProfileError::Json(_)
        | WifiClientProfileError::UnsupportedVersion(_)
        | WifiClientProfileError::SymlinkRejected(_)
        | WifiClientProfileError::UnsafeDirectory(_) => {
            WifiClientProfileErrorDetail::PersistenceFailed {
                message: error.to_string(),
            }
        }
    };
    wifi_client_profile_error(detail)
}

fn dhcp_client_request_to_config(
    request: &DhcpClientConfigRequest,
    enabled: bool,
) -> DhcpClientInterfaceConfig {
    DhcpClientInterfaceConfig {
        enabled,
        route_metric: request.route_metric,
        install_default_route: request.install_default_route,
        request_dns: request.request_dns,
        send_release_on_shutdown: request.send_release_on_shutdown,
    }
}

fn dhcp_client_status_view(status: DhcpClientStatus) -> DhcpClientStatusView {
    let (state, degraded_reason) = match status.state {
        DhcpClientRunState::WaitingForInterface => (DhcpClientOperationalState::Waiting, None),
        DhcpClientRunState::Running => (DhcpClientOperationalState::Running, None),
        DhcpClientRunState::Degraded { reason } => {
            (DhcpClientOperationalState::Degraded, Some(reason))
        }
    };
    let lease = status.lease.as_ref();
    DhcpClientStatusView {
        interface: status.interface,
        state,
        address: lease.map(|lease| lease.address),
        prefix_length: lease.map(|lease| lease.prefix_len),
        server: lease.map(|lease| lease.server_identifier),
        expires_at_unix: lease.map(|lease| lease.expires_at_unix),
        dns_servers: lease
            .map(|lease| lease.dns_servers.clone())
            .unwrap_or_default(),
        degraded_reason,
        config: DhcpClientConfigRequest {
            route_metric: status.spec.route_metric,
            install_default_route: status.spec.install_default_route,
            request_dns: status.spec.request_dns,
            send_release_on_shutdown: status.spec.send_release_on_shutdown,
        },
    }
}

fn dhcp_client_error(detail: DhcpClientErrorDetail) -> Response {
    Response::DhcpClientError { detail }
}

fn wifi_client_error(detail: WifiClientErrorDetail) -> Response {
    Response::WifiClientError { detail }
}

fn classify_wifi_client_error(error: ClientSupervisorError) -> Response {
    tracing::warn!(error = %error, "Wi-Fi client request failed");
    let detail = match error {
        ClientSupervisorError::NotConfigured { .. } => WifiClientErrorDetail::InterfaceNotFound,
        ClientSupervisorError::NotOwned { .. } => WifiClientErrorDetail::NotOwned,
        ClientSupervisorError::StartupTimeout { .. } => WifiClientErrorDetail::CtrlTimeout,
        ClientSupervisorError::ScanBusy { .. } => WifiClientErrorDetail::ScanBusy,
        ClientSupervisorError::ScanTimeout { .. } => WifiClientErrorDetail::ScanTimeout,
        ClientSupervisorError::Ctrl(CtrlError::Timeout(_)) => WifiClientErrorDetail::CtrlTimeout,
        ClientSupervisorError::Ctrl(CtrlError::Io(_)) => WifiClientErrorDetail::CtrlUnavailable,
        ClientSupervisorError::Ctrl(error @ CtrlError::MalformedReply(_))
        | ClientSupervisorError::Ctrl(error @ CtrlError::UnknownCommand(_))
        | ClientSupervisorError::Ctrl(error @ CtrlError::InvalidMacAddr(_)) => {
            WifiClientErrorDetail::ProtocolFailure {
                message: error.to_string(),
            }
        }
        ClientSupervisorError::Ctrl(error) => WifiClientErrorDetail::WpaSupplicantFailed {
            message: error.to_string(),
        },
        ClientSupervisorError::Process(ProcessError::Spawn { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            WifiClientErrorDetail::WpaSupplicantMissing
        }
        ClientSupervisorError::Process(error) => WifiClientErrorDetail::WpaSupplicantFailed {
            message: error.to_string(),
        },
        ClientSupervisorError::Render(ClientRenderError::PassphraseRequired { .. }) => {
            WifiClientErrorDetail::PassphraseMissing
        }
        ClientSupervisorError::Render(error) => WifiClientErrorDetail::InvalidSpec {
            message: error.to_string(),
        },
        ClientSupervisorError::ResolvePassphrase(ResolvePassphraseError::Empty(_)) => {
            WifiClientErrorDetail::PassphraseMissing
        }
        ClientSupervisorError::ResolvePassphrase(error) => WifiClientErrorDetail::Other {
            message: error.to_string(),
        },
        ClientSupervisorError::Record(error) => WifiClientErrorDetail::Other {
            message: error.to_string(),
        },
        ClientSupervisorError::Configuration(error) => WifiClientErrorDetail::InvalidSpec {
            message: error.to_string(),
        },
    };
    Response::WifiClientError { detail }
}

fn wifi_client_edit_request_to_config(settings: WifiClientEditRequest) -> WifiClientConfig {
    WifiClientConfig {
        ssid: settings.ssid,
        country_code: settings.country_code,
        security: settings.security,
        passphrase_file: None,
    }
}

fn wifi_edit_request_to_config(settings: WifiEditRequest) -> WifiApConfig {
    WifiApConfig {
        ssid: settings.ssid,
        country_code: settings.country_code,
        band: settings.band,
        channel: settings.channel,
        channel_width: settings.channel_width,
        security: settings.security,
        hidden: settings.hidden,
        client_isolation: settings.client_isolation,
        max_stations: settings.max_stations,
        passphrase_file: None,
    }
}

fn interface_edit_request_to_config(
    edit: InterfaceEditRequest,
    existing: Option<InterfaceConfig>,
) -> Result<(InterfaceConfig, bool)> {
    let ipv4 = if edit.cidr.trim().is_empty() {
        None
    } else {
        Some(edit.cidr.trim().parse()?)
    };
    Ok((
        InterfaceConfig {
            role: edit.role,
            managed: edit.managed,
            ipv4,
            dhcp: existing.and_then(|config| config.dhcp),
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        },
        edit.allow_management_change,
    ))
}

fn default_dhcp_settings(cidr: ipnet::Ipv4Net) -> Result<DhcpEditRequest, String> {
    if cidr.prefix_len() >= 31 {
        return Err(format!(
            "cannot derive a DHCP pool for /{}: no usable client range",
            cidr.prefix_len()
        ));
    }
    let network = u32::from(cidr.network());
    let broadcast = u32::from(cidr.broadcast());
    let router = u32::from(cidr.addr());
    if router <= network || router >= broadcast {
        return Err("configured interface address is not a usable DHCP router address".to_string());
    }

    let lower = (network + 1, router.saturating_sub(1));
    let upper = (router + 1, broadcast - 1);
    let lower_len = if lower.0 <= lower.1 {
        lower.1 - lower.0 + 1
    } else {
        0
    };
    let upper_len = if upper.0 <= upper.1 {
        upper.1 - upper.0 + 1
    } else {
        0
    };
    let (start, end) = if upper_len > lower_len { upper } else { lower };
    if start > end {
        return Err("configured subnet has no usable DHCP client addresses".to_string());
    }

    Ok(DhcpEditRequest {
        pool_start: start.into(),
        pool_end: end.into(),
        router: router.into(),
        dns_servers: Vec::new(),
        lease_seconds: None,
    })
}

async fn restore_wifi_secret(
    wifi: &HostapdSupervisor,
    interface: &str,
    previous: Option<&WifiPassphrase>,
) {
    match previous {
        Some(secret) => {
            let _ = wifi.set_passphrase(interface, secret).await;
        }
        None => {
            let _ = wifi.clear_passphrase(interface).await;
        }
    }
}

async fn compensate_ap(
    wifi: &HostapdSupervisor,
    interface: &str,
    previous_ap: Option<WifiApSpec>,
    previous_secret: Option<WifiPassphrase>,
) {
    restore_wifi_secret(wifi, interface, previous_secret.as_ref()).await;
    match previous_ap {
        Some(spec) => {
            let _ = wifi.configure(spec).await;
        }
        None => {
            let _ = wifi.disable(interface).await;
        }
    }
}

fn dhcp_edit_request_to_config(settings: DhcpEditRequest) -> DhcpInterfaceConfig {
    DhcpInterfaceConfig {
        pool_start: settings.pool_start,
        pool_end: settings.pool_end,
        router: settings.router,
        dns_servers: settings.dns_servers,
        lease_seconds: settings.lease_seconds,
    }
}

fn api_https_settings_from_config(config: &ApiConfig) -> ApiHttpsSettings {
    config
        .tcp
        .as_ref()
        .map(ApiHttpsSettings::from)
        .unwrap_or_default()
}

fn api_https_settings_to_config(settings: ApiHttpsSettings) -> Result<ApiConfig> {
    let tcp = TcpApiConfig {
        enabled: settings.enabled,
        listen: settings.listen.trim().parse()?,
        certificate_path: settings
            .certificate_path
            .and_then(normalize_optional_path_string)
            .map(Into::into),
        private_key_path: settings
            .private_key_path
            .and_then(normalize_optional_path_string)
            .map(Into::into),
    };
    let api = ApiConfig { tcp: Some(tcp) };
    let candidate = AppConfig {
        api: api.clone(),
        ..Default::default()
    };
    candidate.validate()?;
    Ok(api)
}

fn normalize_optional_path_string(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn build_router_proposal(request: RouterProposalRequest) -> RouterIntentProposal {
    let mut proposal = RouterIntentProposal::new();
    if request.clear_router {
        proposal = proposal.clear_router();
    } else if let Some(router) = request.set_router {
        proposal = proposal.set_router(router);
    }
    for (interface, over) in request.set_interfaces {
        proposal = proposal.set_interface(interface, over.config, over.allow_management_change);
    }
    for interface in request.remove_interfaces {
        proposal = proposal.remove_interface(interface);
    }
    proposal
}

fn classify_router_error(error: anyhow::Error) -> Response {
    let detail = if let Some(conflict) = error.downcast_ref::<CoordinatorConflict>() {
        match conflict {
            CoordinatorConflict::TransactionPending => RouterErrorDetail::TransactionPending,
            CoordinatorConflict::RollbackRecoveryRequired => {
                RouterErrorDetail::RollbackRecoveryRequired
            }
        }
    } else if let Some(stale) = error.downcast_ref::<StaleCandidateError>() {
        RouterErrorDetail::StaleCandidate {
            candidate_revision: stale.candidate,
            current_revision: stale.current,
        }
    } else if error
        .downcast_ref::<crate::core::router_transaction::StalePlanError>()
        .is_some()
    {
        RouterErrorDetail::StalePlan
    } else if error.downcast_ref::<NoPendingTransactionError>().is_some() {
        RouterErrorDetail::NoPendingTransaction
    } else {
        RouterErrorDetail::Other {
            message: error.to_string(),
        }
    };
    Response::RouterError { detail }
}

async fn configure_dhcp_persisted(
    dhcp: &DhcpSupervisor,
    overrides: &RuntimeOverrideManager,
    spec: DhcpServiceSpec,
) -> Result<()> {
    let interface = spec.interface.clone();
    let previous = dhcp.spec(&interface).await;
    let mut interface_config = overrides
        .effective_interface(&interface)
        .await?
        .ok_or_else(|| anyhow::anyhow!("interface {interface} is not configured"))?;
    interface_config.dhcp = Some(DhcpInterfaceConfig {
        pool_start: spec.pool_start,
        pool_end: spec.pool_end,
        router: spec.router,
        dns_servers: spec.dns_servers.clone(),
        lease_seconds: Some(spec.lease_seconds),
    });
    dhcp.configure(spec).await?;

    if let Err(error) = overrides
        .set_interface(interface.clone(), interface_config, false)
        .await
    {
        if let Some(previous) = previous {
            let _ = dhcp.configure(previous).await;
        } else {
            let _ = dhcp.disable(&interface).await;
        }
        return Err(error).context("failed to persist DHCP override; runtime state was restored");
    }

    Ok(())
}

async fn disable_dhcp_persisted(
    dhcp: &DhcpSupervisor,
    overrides: &RuntimeOverrideManager,
    interface: &str,
) -> Result<()> {
    let previous = dhcp.spec(interface).await;
    let mut interface_config = overrides
        .effective_interface(interface)
        .await?
        .ok_or_else(|| anyhow::anyhow!("interface {interface} is not configured"))?;
    interface_config.dhcp = None;
    dhcp.disable(interface).await?;

    if let Err(error) = overrides
        .set_interface(interface.to_string(), interface_config, false)
        .await
    {
        if let Some(previous) = previous {
            let _ = dhcp.configure(previous).await;
        }
        return Err(error)
            .context("failed to persist DHCP disable override; runtime state was restored");
    }

    Ok(())
}

async fn build_effective_dhcp_service(
    interface: &str,
    dhcp: DhcpInterfaceConfig,
    overrides: &RuntimeOverrideManager,
    network_provider: &dyn NetworkProvider,
    default_lease_seconds: u32,
) -> Result<DhcpServiceSpec> {
    let mut interface_config = overrides
        .effective_interface(interface)
        .await?
        .ok_or_else(|| anyhow::anyhow!("interface {interface} is not configured"))?;
    if !interface_config.managed || interface_config.role != InterfaceRole::Output {
        anyhow::bail!("DHCP requires a managed output interface: {interface}");
    }
    let spec = build_dhcp_spec(
        interface,
        dhcp.clone(),
        network_provider,
        default_lease_seconds,
    )
    .await?;
    interface_config.ipv4 = Some(ipnet::Ipv4Net::new(spec.server_ip, spec.prefix_len)?);
    interface_config.dhcp = Some(dhcp);
    interface_config.validate(interface)?;
    Ok(spec)
}

async fn build_dhcp_spec(
    interface: &str,
    dhcp: DhcpInterfaceConfig,
    network_provider: &dyn NetworkProvider,
    default_lease_seconds: u32,
) -> Result<DhcpServiceSpec> {
    let addresses = network_provider.list_ipv4_addresses(interface).await?;
    let network = select_dhcp_network(interface, &addresses, &dhcp)?;
    let interface_config = InterfaceConfig {
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some(network),
        dhcp: Some(dhcp.clone()),
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    };
    DhcpServiceSpec::from_interface_config(interface, &interface_config, default_lease_seconds)?
        .ok_or_else(|| anyhow::anyhow!("DHCP is not enabled by the interface configuration"))
}

fn select_dhcp_network(
    interface: &str,
    addresses: &[Ipv4AddressInfo],
    dhcp: &DhcpInterfaceConfig,
) -> Result<ipnet::Ipv4Net> {
    let mut candidates = Vec::new();

    for address in addresses {
        let Ok(network) = ipnet::Ipv4Net::new(address.address, address.prefix_len) else {
            continue;
        };
        let candidate = InterfaceConfig {
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some(network),
            dhcp: Some(dhcp.clone()),
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        };
        if candidate.validate(interface).is_ok() {
            candidates.push(network);
        }
    }

    match candidates.as_slice() {
        [network] => Ok(*network),
        [] => anyhow::bail!(
            "interface {interface} has no IPv4 address with a subnet valid for DHCP pool {}-{} and router {}",
            dhcp.pool_start,
            dhcp.pool_end,
            dhcp.router
        ),
        _ => {
            let candidates = candidates
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "interface {interface} has multiple IPv4 addresses with subnets valid for DHCP pool {}-{} and router {}: {candidates}",
                dhcp.pool_start,
                dhcp.pool_end,
                dhcp.router
            )
        }
    }
}

async fn interface_statuses(network: &dyn NetworkProvider) -> Result<Vec<InterfaceStatus>> {
    let mut result = Vec::new();
    for interface in network.list_interfaces().await? {
        let ipv4_addresses = network.list_ipv4_addresses(&interface.name).await?;
        result.push(InterfaceStatus {
            interface,
            ipv4_addresses,
        });
    }
    result.sort_by(|left, right| left.interface.name.cmp(&right.interface.name));
    Ok(result)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use anyhow::Result;
    use async_trait::async_trait;

    use crate::netlink::NetworkInterface;

    use super::*;

    #[test]
    fn default_ap_dhcp_pool_uses_larger_side_of_router_in_24() {
        let settings = default_dhcp_settings("192.168.50.128/24".parse().unwrap()).unwrap();
        assert_eq!(settings.router, Ipv4Addr::new(192, 168, 50, 128));
        assert_eq!(settings.pool_start, Ipv4Addr::new(192, 168, 50, 1));
        assert_eq!(settings.pool_end, Ipv4Addr::new(192, 168, 50, 127));
        assert!(settings.dns_servers.is_empty());
        assert_eq!(settings.lease_seconds, None);
    }

    #[test]
    fn default_ap_dhcp_pool_supports_30() {
        let settings = default_dhcp_settings("192.168.50.1/30".parse().unwrap()).unwrap();
        assert_eq!(settings.pool_start, Ipv4Addr::new(192, 168, 50, 2));
        assert_eq!(settings.pool_end, Ipv4Addr::new(192, 168, 50, 2));
    }

    #[test]
    fn default_ap_dhcp_pool_rejects_31() {
        let error = default_dhcp_settings("192.168.50.0/31".parse().unwrap()).unwrap_err();
        assert!(error.contains("/31"));
    }

    struct FakeNetwork {
        addresses: Vec<Ipv4AddressInfo>,
    }

    #[async_trait]
    impl NetworkProvider for FakeNetwork {
        async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
            Ok(Vec::new())
        }

        async fn list_ipv4_addresses(&self, _interface: &str) -> Result<Vec<Ipv4AddressInfo>> {
            Ok(self.addresses.clone())
        }

        async fn set_link_up(&self, _name: &str) -> Result<()> {
            Ok(())
        }

        async fn set_link_down(&self, _name: &str) -> Result<()> {
            Ok(())
        }

        async fn add_ipv4_address(
            &self,
            _interface: &str,
            _address: Ipv4Addr,
            _prefix_len: u8,
        ) -> Result<()> {
            Ok(())
        }

        async fn delete_ipv4_address(
            &self,
            _interface: &str,
            _address: Ipv4Addr,
            _prefix_len: u8,
        ) -> Result<()> {
            Ok(())
        }
    }

    fn address(address: [u8; 4], prefix_len: u8) -> Ipv4AddressInfo {
        Ipv4AddressInfo {
            interface_index: 1,
            address: Ipv4Addr::from(address),
            prefix_len,
        }
    }

    fn dhcp_config() -> DhcpInterfaceConfig {
        DhcpInterfaceConfig {
            pool_start: Ipv4Addr::new(192, 168, 50, 10),
            pool_end: Ipv4Addr::new(192, 168, 50, 100),
            router: Ipv4Addr::new(192, 168, 50, 1),
            dns_servers: Vec::new(),
            lease_seconds: None,
        }
    }

    #[test]
    fn interface_edit_request_preserves_existing_dhcp_settings() {
        let existing_dhcp = dhcp_config();
        let existing = InterfaceConfig {
            role: InterfaceRole::Output,
            managed: true,
            ipv4: Some("192.168.50.1/24".parse().expect("valid cidr")),
            dhcp: Some(existing_dhcp.clone()),
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        };
        let edit = InterfaceEditRequest {
            cidr: "192.168.60.1/24".to_string(),
            role: InterfaceRole::Output,
            managed: true,
            allow_management_change: false,
        };

        let (config, allow_management_change) =
            interface_edit_request_to_config(edit, Some(existing)).expect("edit must convert");

        assert_eq!(
            config.ipv4,
            Some("192.168.60.1/24".parse().expect("valid cidr"))
        );
        assert_eq!(config.dhcp, Some(existing_dhcp));
        assert!(!allow_management_change);
    }

    #[tokio::test]
    async fn selects_the_only_address_whose_subnet_validates_dhcp() {
        let network = FakeNetwork {
            addresses: vec![address([10, 0, 0, 1], 24), address([192, 168, 50, 1], 24)],
        };

        let spec = build_dhcp_spec("test0", dhcp_config(), &network, 3_600)
            .await
            .expect("one live subnet should match");

        assert_eq!(spec.server_ip, Ipv4Addr::new(192, 168, 50, 1));
        assert_eq!(spec.prefix_len, 24);
    }

    #[tokio::test]
    async fn rejects_when_no_address_has_a_valid_dhcp_subnet() {
        let network = FakeNetwork {
            addresses: vec![address([10, 0, 0, 1], 24), address([172, 16, 0, 1], 16)],
        };

        let error = build_dhcp_spec("test0", dhcp_config(), &network, 3_600)
            .await
            .expect_err("no live subnet should match");

        assert!(error
            .to_string()
            .contains("no IPv4 address with a subnet valid"));
    }

    #[tokio::test]
    async fn selects_the_live_address_that_matches_the_dhcp_router() {
        let network = FakeNetwork {
            addresses: vec![
                address([192, 168, 50, 1], 24),
                address([192, 168, 50, 2], 24),
            ],
        };

        let spec = build_dhcp_spec("test0", dhcp_config(), &network, 3_600)
            .await
            .expect("the DHCP router must identify the server address");

        assert_eq!(spec.server_ip, Ipv4Addr::new(192, 168, 50, 1));
        assert_eq!(spec.router, spec.server_ip);
    }

    use crate::config::{RouterConfig, UplinkConfig, UplinkMode};
    use crate::core::interface::{DhcpChangeAction, InterfaceChangePlan};
    use crate::core::route::{RoutePlan, RouteSnapshot};
    use crate::core::router::{DhcpPlan, RouterSubsystems};
    use crate::firewall::{OwnedFirewallIntegrity, RouterDataplanePlan, RouterDataplaneSnapshot};
    use tempfile::tempdir;

    #[derive(Default)]
    struct FakeRouterSubsystems {
        unhealthy_interfaces: std::sync::Mutex<bool>,
        unhealthy_routes: std::sync::Mutex<bool>,
        unhealthy_dhcp: std::sync::Mutex<bool>,
        unhealthy_dataplane: std::sync::Mutex<bool>,
    }

    impl FakeRouterSubsystems {
        fn fail_health(&self, subsystem: &str) {
            let flag = match subsystem {
                "interfaces" => &self.unhealthy_interfaces,
                "routes" => &self.unhealthy_routes,
                "dhcp" => &self.unhealthy_dhcp,
                "dataplane" => &self.unhealthy_dataplane,
                other => panic!("unknown subsystem: {other}"),
            };
            *flag.lock().unwrap() = true;
        }
    }

    fn fake_dataplane_snapshot() -> RouterDataplaneSnapshot {
        RouterDataplaneSnapshot {
            ipv4_forwarding: true,
            owned: None,
            owned_firewall_integrity: OwnedFirewallIntegrity::Intact,
        }
    }

    #[async_trait]
    impl RouterSubsystems for FakeRouterSubsystems {
        async fn plan_interfaces(&self, _: &RouterDesired) -> Result<Vec<InterfaceChangePlan>> {
            Ok(vec![InterfaceChangePlan {
                interface: "lan0".into(),
                delete_ipv4: Vec::new(),
                add_ipv4: None,
                set_link_up: false,
                management_change: false,
                dhcp_action: DhcpChangeAction::Unchanged,
            }])
        }
        async fn plan_routes(&self, _: &RouterDesired) -> Result<RoutePlan> {
            Ok(RoutePlan {
                add: Vec::new(),
                delete: Vec::new(),
            })
        }
        async fn plan_dhcp(&self, _: &RouterDesired) -> Result<Vec<DhcpPlan>> {
            Ok(Vec::new())
        }
        async fn plan_dataplane(&self, desired: &RouterDesired) -> Result<RouterDataplanePlan> {
            Ok(RouterDataplanePlan {
                snapshot: fake_dataplane_snapshot(),
                target: desired.dataplane.clone(),
                requires_apply: true,
            })
        }
        async fn snapshot_interfaces(&self) -> Result<Vec<InterfaceSnapshot>> {
            Ok(Vec::new())
        }
        async fn snapshot_routes(&self) -> Result<RouteSnapshot> {
            Ok(RouteSnapshot::empty())
        }
        async fn snapshot_dhcp(&self) -> Result<Vec<DhcpServiceSpec>> {
            Ok(Vec::new())
        }
        async fn snapshot_dataplane(&self) -> Result<RouterDataplaneSnapshot> {
            Ok(fake_dataplane_snapshot())
        }
        async fn apply_interfaces(&self, _: &[InterfaceChangePlan]) -> Result<()> {
            Ok(())
        }
        async fn apply_routes(&self, _: &RoutePlan) -> Result<()> {
            Ok(())
        }
        async fn apply_dhcp(&self, _: &[DhcpPlan]) -> Result<()> {
            Ok(())
        }
        async fn apply_dataplane(&self, _: &RouterDataplanePlan) -> Result<()> {
            Ok(())
        }
        async fn rollback_interfaces(&self, _: &[InterfaceSnapshot]) -> Result<()> {
            Ok(())
        }
        async fn rollback_routes(&self, _: &RouteSnapshot) -> Result<()> {
            Ok(())
        }
        async fn rollback_dhcp(&self, _: &[DhcpServiceSpec]) -> Result<()> {
            Ok(())
        }
        async fn rollback_dataplane(&self, _: &RouterDataplaneSnapshot) -> Result<()> {
            Ok(())
        }
        async fn health_interfaces(&self, _: &RouterDesired) -> Result<()> {
            if *self.unhealthy_interfaces.lock().unwrap() {
                anyhow::bail!("injected interfaces health failure");
            }
            Ok(())
        }
        async fn health_routes(&self, _: &RouterDesired) -> Result<()> {
            if *self.unhealthy_routes.lock().unwrap() {
                anyhow::bail!("injected routes health failure");
            }
            Ok(())
        }
        async fn health_dhcp(&self, _: &RouterDesired) -> Result<()> {
            if *self.unhealthy_dhcp.lock().unwrap() {
                anyhow::bail!("injected dhcp health failure");
            }
            Ok(())
        }
        async fn health_dataplane(&self, _: &RouterDesired) -> Result<()> {
            if *self.unhealthy_dataplane.lock().unwrap() {
                anyhow::bail!("injected dataplane health failure");
            }
            Ok(())
        }
    }

    fn router_base_config() -> AppConfig {
        let mut config = AppConfig::default();
        config.network.interfaces.insert(
            "wan0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Input,
                managed: false,
                ipv4: None,
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
            },
        );

        config.network.interfaces.insert(
            "lan0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Output,
                managed: true,
                ipv4: Some("192.168.10.1/24".parse().unwrap()),
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
            },
        );
        config
    }

    fn router_proposal() -> RouterProposalRequest {
        RouterProposalRequest {
            set_router: Some(RouterConfig {
                enabled: true,
                uplink: Some(UplinkConfig {
                    interface: "wan0".to_string(),
                    mode: UplinkMode::External,
                }),
                owned_routes: Vec::new(),
                allow_default_route_change: false,
            }),
            clear_router: false,
            set_interfaces: Default::default(),
            remove_interfaces: Vec::new(),
        }
    }

    #[tokio::test]
    async fn api_https_settings_dispatch_persists_override_and_requires_restart() {
        let directory = tempdir().expect("tempdir");
        let mut config = router_base_config();
        config.api.tcp = Some(TcpApiConfig {
            enabled: false,
            listen: "127.0.0.1:8443".parse().expect("socket address"),
            certificate_path: None,
            private_key_path: None,
        });
        let overrides = RuntimeOverrideManager::load(directory.path(), &config)
            .await
            .expect("overrides");
        let dhcp = DhcpSupervisor::start(&config, &overrides.snapshot().await)
            .await
            .expect("dhcp supervisor");
        let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
            addresses: Vec::new(),
        });
        let service = ControlService::new(config.clone(), network, dhcp, overrides.clone());

        let settings = ApiHttpsSettings {
            enabled: true,
            listen: "0.0.0.0:9443".to_string(),
            certificate_path: Some("/etc/traffic-masq/server.pem".to_string()),
            private_key_path: Some("/etc/traffic-masq/server-key.pem".to_string()),
        };

        match service
            .dispatch(Request::ConfigureApiHttpsSettings {
                settings: settings.clone(),
            })
            .await
        {
            Response::ApiHttpsConfig {
                active,
                desired,
                override_active,
                restart_required,
            } => {
                assert!(!active.enabled);
                assert_eq!(desired, settings);
                assert!(override_active);
                assert!(restart_required);
            }
            response => panic!("unexpected response: {response:?}"),
        }
        assert!(overrides.snapshot().await.api.is_some());

        match service.dispatch(Request::ResetApiHttpsSettings).await {
            Response::ApiHttpsConfig {
                active,
                desired,
                override_active,
                restart_required,
            } => {
                assert_eq!(active, desired);
                assert!(!override_active);
                assert!(!restart_required);
            }
            response => panic!("unexpected response: {response:?}"),
        }
        assert!(overrides.snapshot().await.api.is_none());
    }

    #[tokio::test]
    async fn security_settings_dispatch_persists_override_and_requires_restart() {
        let directory = tempdir().expect("tempdir");
        let config = router_base_config();
        let overrides = RuntimeOverrideManager::load(directory.path(), &config)
            .await
            .expect("overrides");
        let dhcp = DhcpSupervisor::start(&config, &overrides.snapshot().await)
            .await
            .expect("dhcp supervisor");
        let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
            addresses: Vec::new(),
        });
        let service = ControlService::new(config.clone(), network, dhcp, overrides.clone());

        let settings = SecuritySettings {
            rollback_timeout_seconds: 120,
        };

        match service
            .dispatch(Request::ConfigureSecuritySettings { settings })
            .await
        {
            Response::SecurityConfig {
                active,
                desired,
                override_active,
                restart_required,
            } => {
                assert_eq!(active.rollback_timeout_seconds, 60);
                assert_eq!(desired, settings);
                assert!(override_active);
                assert!(restart_required);
            }
            response => panic!("unexpected response: {response:?}"),
        }
        assert!(overrides.snapshot().await.security.is_some());

        match service.dispatch(Request::ResetSecuritySettings).await {
            Response::SecurityConfig {
                active,
                desired,
                override_active,
                restart_required,
            } => {
                assert_eq!(active, desired);
                assert!(!override_active);
                assert!(!restart_required);
            }
            response => panic!("unexpected response: {response:?}"),
        }
        assert!(overrides.snapshot().await.security.is_none());
    }

    async fn router_enabled_service() -> (ControlService, tempfile::TempDir) {
        router_enabled_service_with(Arc::new(FakeRouterSubsystems::default())).await
    }

    async fn router_enabled_service_with(
        fake: Arc<FakeRouterSubsystems>,
    ) -> (ControlService, tempfile::TempDir) {
        router_service_with_config(fake, router_base_config()).await
    }

    fn router_base_config_with_router_enabled() -> AppConfig {
        let mut config = router_base_config();
        config.router = RouterConfig {
            enabled: true,
            uplink: Some(UplinkConfig {
                interface: "wan0".to_string(),
                mode: UplinkMode::External,
            }),
            owned_routes: Vec::new(),
            allow_default_route_change: false,
        };
        config
    }

    async fn router_service_with_config(
        fake: Arc<FakeRouterSubsystems>,
        config: AppConfig,
    ) -> (ControlService, tempfile::TempDir) {
        let directory = tempdir().expect("tempdir");
        let overrides = RuntimeOverrideManager::load(directory.path(), &config)
            .await
            .expect("overrides");
        let manager = crate::core::router::RouterManager::new(fake);
        let coordinator = RouterTransactionCoordinator::new(
            manager,
            overrides.clone(),
            Duration::from_millis(200),
        );
        let dhcp = DhcpSupervisor::start(&config, &overrides.snapshot().await)
            .await
            .expect("dhcp supervisor");
        let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
            addresses: Vec::new(),
        });
        let service = ControlService::new(config, network, dhcp, overrides)
            .with_router_coordinator(coordinator);
        (service, directory)
    }

    #[tokio::test]
    async fn router_requests_are_rejected_when_router_mode_is_disabled() {
        let directory = tempdir().expect("tempdir");
        let config = router_base_config();
        let overrides = RuntimeOverrideManager::load(directory.path(), &config)
            .await
            .expect("overrides");
        let dhcp = DhcpSupervisor::start(&config, &overrides.snapshot().await)
            .await
            .expect("dhcp supervisor");
        let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
            addresses: Vec::new(),
        });
        let service = ControlService::new(config, network, dhcp, overrides);

        for request in [
            Request::RouterStatus,
            Request::RouterPlan {
                proposal: router_proposal(),
            },
            Request::RouterApply {
                proposal: router_proposal(),
            },
            Request::RouterCommit,
            Request::RouterRollback,
            Request::RouterPendingTransaction,
        ] {
            let response = service.dispatch(request).await;
            assert!(matches!(
                response,
                Response::RouterError {
                    detail: RouterErrorDetail::RouterDisabled
                }
            ));
        }
    }

    #[tokio::test]
    async fn router_plan_apply_commit_workflow_dispatches_through_control_service() {
        let (service, _directory) = router_enabled_service().await;

        match service.dispatch(Request::RouterStatus).await {
            Response::RouterStatus { enabled, .. } => assert!(!enabled),
            other => panic!("unexpected response: {other:?}"),
        }

        match service
            .dispatch(Request::RouterPlan {
                proposal: router_proposal(),
            })
            .await
        {
            Response::RouterPlan { plan } => assert!(plan.desired.enabled),
            other => panic!("unexpected response: {other:?}"),
        }

        let token = match service
            .dispatch(Request::RouterApply {
                proposal: router_proposal(),
            })
            .await
        {
            Response::RouterTransactionPending { token, plan } => {
                assert!(plan.desired.enabled);
                token
            }
            other => panic!("unexpected response: {other:?}"),
        };
        assert!(!token.is_empty());

        match service.dispatch(Request::RouterPendingTransaction).await {
            Response::RouterPendingTransaction { status, .. } => {
                assert_eq!(
                    status,
                    crate::core::router_transaction::CoordinatorStatus::Pending
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }

        match service.dispatch(Request::RouterCommit).await {
            Response::RouterCommitted { revision } => assert_eq!(revision, 1),
            other => panic!("unexpected response: {other:?}"),
        }

        match service.dispatch(Request::RouterStatus).await {
            Response::RouterStatus { enabled, ready, .. } => {
                assert!(enabled);
                assert!(ready);
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn router_plan_apply_rollback_workflow_dispatches_through_control_service() {
        let (service, _directory) = router_enabled_service().await;

        match service
            .dispatch(Request::RouterApply {
                proposal: router_proposal(),
            })
            .await
        {
            Response::RouterTransactionPending { .. } => {}
            other => panic!("unexpected response: {other:?}"),
        }

        match service.dispatch(Request::RouterRollback).await {
            Response::RouterRolledBack => {}
            other => panic!("unexpected response: {other:?}"),
        }

        match service.dispatch(Request::RouterPendingTransaction).await {
            Response::RouterPendingTransaction { status, .. } => {
                assert_eq!(
                    status,
                    crate::core::router_transaction::CoordinatorStatus::Idle
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }

        match service.dispatch(Request::RouterRollback).await {
            Response::RouterError {
                detail: RouterErrorDetail::NoPendingTransaction,
            } => {}
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn second_concurrent_router_apply_is_rejected_with_typed_conflict() {
        let (service, _directory) = router_enabled_service().await;

        service
            .dispatch(Request::RouterApply {
                proposal: router_proposal(),
            })
            .await;

        match service
            .dispatch(Request::RouterApply {
                proposal: router_proposal(),
            })
            .await
        {
            Response::RouterError {
                detail: RouterErrorDetail::TransactionPending,
            } => {}
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn router_status_reports_ready_false_only_for_the_unhealthy_subsystem() {
        for subsystem in ["interfaces", "routes", "dhcp", "dataplane"] {
            let fake = Arc::new(FakeRouterSubsystems::default());
            fake.fail_health(subsystem);
            let (service, _directory) =
                router_service_with_config(fake, router_base_config_with_router_enabled()).await;

            match service.dispatch(Request::RouterStatus).await {
                Response::RouterStatus {
                    enabled,
                    ready,
                    health,
                    ..
                } => {
                    assert!(enabled, "subsystem {subsystem}");
                    assert!(!ready, "subsystem {subsystem}");
                    let statuses = [
                        ("interfaces", health.interfaces.is_some()),
                        ("routes", health.routes.is_some()),
                        ("dhcp", health.dhcp.is_some()),
                        ("dataplane", health.dataplane.is_some()),
                    ];
                    for (name, is_unhealthy) in statuses {
                        assert_eq!(
                            is_unhealthy,
                            name == subsystem,
                            "subsystem {subsystem}: unexpected health.{name} state"
                        );
                    }
                }
                other => panic!("unexpected response for {subsystem}: {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn router_status_is_ready_when_all_subsystems_are_healthy() {
        let fake = Arc::new(FakeRouterSubsystems::default());
        let (service, _directory) =
            router_service_with_config(fake, router_base_config_with_router_enabled()).await;

        match service.dispatch(Request::RouterStatus).await {
            Response::RouterStatus {
                enabled,
                ready,
                health,
                ..
            } => {
                assert!(enabled);
                assert!(ready);
                assert!(health.interfaces.is_none());
                assert!(health.routes.is_none());
                assert!(health.dhcp.is_none());
                assert!(health.dataplane.is_none());
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    use crate::vpn::wireguard::WireGuardKey;
    use sha2::Digest;
    use std::collections::HashMap as StdHashMap;
    use std::sync::Mutex as StdMutex;

    const VALID_VPN_PRIVATE_KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const VALID_VPN_PUBLIC_KEY: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    const OTHER_VPN_PRIVATE_KEY: &str = "SBmoW+ojuoJZeh6P/2sh8aetgAy4dTZTAO8UzHzKtGY=";

    fn valid_vpn_profile_contents() -> String {
        format!(
            "[Interface]\n\
             PrivateKey = {VALID_VPN_PRIVATE_KEY}\n\
             Address = 10.0.0.2/24\n\
             \n\
             [Peer]\n\
             PublicKey = {VALID_VPN_PUBLIC_KEY}\n\
             AllowedIPs = 0.0.0.0/0\n\
             Endpoint = 203.0.113.1:51820\n"
        )
    }

    #[derive(Debug, Clone)]
    struct FakeVpnLink {
        private_key: WireGuardKey,
        up: bool,
    }

    #[derive(Default)]
    struct FakeVpnProvider {
        links: StdMutex<StdHashMap<String, FakeVpnLink>>,
    }

    impl FakeVpnProvider {
        fn seed_foreign_link(&self, name: &str, private_key: &str) {
            let key = WireGuardKey::parse(private_key, "test").unwrap();
            self.links.lock().unwrap().insert(
                name.to_string(),
                FakeVpnLink {
                    private_key: key,
                    up: true,
                },
            );
        }
    }

    #[async_trait]
    impl crate::vpn::VpnProvider for FakeVpnProvider {
        async fn link_exists(&self, name: &str) -> Result<bool, crate::vpn::ProviderError> {
            Ok(self.links.lock().unwrap().contains_key(name))
        }

        async fn create_link(
            &self,
            name: &str,
            private_key: &WireGuardKey,
            _listen_port: Option<u16>,
        ) -> Result<(), crate::vpn::ProviderError> {
            let mut links = self.links.lock().unwrap();
            if links.contains_key(name) {
                return Err(crate::vpn::ProviderError::CommandFailed {
                    command: "ip",
                    status: "exit code: 1".to_string(),
                    stderr: "link already exists".to_string(),
                });
            }
            links.insert(
                name.to_string(),
                FakeVpnLink {
                    private_key: private_key.clone(),
                    up: false,
                },
            );
            Ok(())
        }

        async fn set_addresses(
            &self,
            name: &str,
            _addresses: &[ipnet::IpNet],
        ) -> Result<(), crate::vpn::ProviderError> {
            self.require_link(name)
        }

        async fn set_peers(
            &self,
            name: &str,
            _peers: &[crate::vpn::WireGuardPeerConfig],
        ) -> Result<(), crate::vpn::ProviderError> {
            self.require_link(name)
        }

        async fn set_link_up(&self, name: &str) -> Result<(), crate::vpn::ProviderError> {
            let mut links = self.links.lock().unwrap();
            let link = links
                .get_mut(name)
                .ok_or_else(|| crate::vpn::ProviderError::NotFound(name.to_string()))?;
            link.up = true;
            Ok(())
        }

        async fn set_link_down(&self, name: &str) -> Result<(), crate::vpn::ProviderError> {
            let mut links = self.links.lock().unwrap();
            let link = links
                .get_mut(name)
                .ok_or_else(|| crate::vpn::ProviderError::NotFound(name.to_string()))?;
            link.up = false;
            Ok(())
        }

        async fn delete_link(&self, name: &str) -> Result<(), crate::vpn::ProviderError> {
            self.links
                .lock()
                .unwrap()
                .remove(name)
                .map(|_| ())
                .ok_or_else(|| crate::vpn::ProviderError::NotFound(name.to_string()))
        }

        async fn public_key(
            &self,
            name: &str,
        ) -> Result<Option<WireGuardKey>, crate::vpn::ProviderError> {
            Ok(self.links.lock().unwrap().get(name).map(|link| {
                let digest = sha2::Sha256::digest(link.private_key.0);
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&digest[..32]);
                WireGuardKey(bytes)
            }))
        }

        async fn is_up(&self, name: &str) -> Result<bool, crate::vpn::ProviderError> {
            Ok(self
                .links
                .lock()
                .unwrap()
                .get(name)
                .map(|link| link.up)
                .unwrap_or(false))
        }
    }

    impl FakeVpnProvider {
        fn require_link(&self, name: &str) -> Result<(), crate::vpn::ProviderError> {
            if self.links.lock().unwrap().contains_key(name) {
                Ok(())
            } else {
                Err(crate::vpn::ProviderError::NotFound(name.to_string()))
            }
        }
    }

    async fn vpn_enabled_service() -> (ControlService, tempfile::TempDir) {
        vpn_enabled_service_with_provider(FakeVpnProvider::default()).await
    }

    async fn vpn_enabled_service_with_provider(
        provider: FakeVpnProvider,
    ) -> (ControlService, tempfile::TempDir) {
        let directory = tempdir().expect("tempdir");
        let config = router_base_config();
        let overrides = RuntimeOverrideManager::load(directory.path(), &config)
            .await
            .expect("overrides");
        let dhcp = DhcpSupervisor::start(&config, &overrides.snapshot().await)
            .await
            .expect("dhcp supervisor");
        let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
            addresses: Vec::new(),
        });
        let vpn_store = crate::vpn::WireGuardProfileStore::new(directory.path().join("wireguard"));
        let active_profile_store =
            crate::vpn::ActiveProfileStore::new(directory.path().join("active-profile.json"));
        let provider: Arc<dyn crate::vpn::VpnProvider> = Arc::new(provider);
        let driver = crate::vpn::WireGuardVpnDriver::new(provider, vpn_store);
        let vpn_manager = Arc::new(crate::vpn::VpnManager::new(driver, active_profile_store));
        let service =
            ControlService::new(config, network, dhcp, overrides).with_vpn_manager(vpn_manager);
        (service, directory)
    }

    #[tokio::test]
    async fn vpn_requests_are_rejected_when_vpn_is_disabled() {
        let directory = tempdir().expect("tempdir");
        let config = router_base_config();
        let overrides = RuntimeOverrideManager::load(directory.path(), &config)
            .await
            .expect("overrides");
        let dhcp = DhcpSupervisor::start(&config, &overrides.snapshot().await)
            .await
            .expect("dhcp supervisor");
        let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
            addresses: Vec::new(),
        });
        let service = ControlService::new(config, network, dhcp, overrides);

        for request in [
            Request::VpnListProfiles,
            Request::VpnImportProfile {
                name: "home.conf".to_string(),
                contents: valid_vpn_profile_contents(),
            },
            Request::VpnDeleteProfile {
                name: "home.conf".to_string(),
            },
            Request::VpnStatus,
            Request::VpnActivate {
                name: "home.conf".to_string(),
            },
            Request::VpnDeactivate,
        ] {
            let response = service.dispatch(request).await;
            assert!(matches!(
                response,
                Response::VpnError {
                    detail: VpnErrorDetail::VpnDisabled
                }
            ));
        }
    }

    #[tokio::test]
    async fn vpn_import_list_delete_profile_round_trip_never_leaks_the_private_key() {
        let (service, _directory) = vpn_enabled_service().await;

        match service
            .dispatch(Request::VpnImportProfile {
                name: "home.conf".to_string(),
                contents: valid_vpn_profile_contents(),
            })
            .await
        {
            Response::VpnProfileImported { name } => assert_eq!(name, "home.conf"),
            other => panic!("unexpected response: {other:?}"),
        }

        let profiles = match service.dispatch(Request::VpnListProfiles).await {
            Response::VpnProfiles { profiles } => profiles,
            other => panic!("unexpected response: {other:?}"),
        };
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "home.conf");
        assert!(profiles[0].size_bytes > 0);

        let debug = format!("{profiles:?}");
        assert!(!debug.contains(VALID_VPN_PRIVATE_KEY));
        let json = serde_json::to_string(&profiles).expect("serialize");
        assert!(!json.contains(VALID_VPN_PRIVATE_KEY));

        match service
            .dispatch(Request::VpnDeleteProfile {
                name: "home.conf".to_string(),
            })
            .await
        {
            Response::VpnProfileDeleted { name } => assert_eq!(name, "home.conf"),
            other => panic!("unexpected response: {other:?}"),
        }

        match service.dispatch(Request::VpnListProfiles).await {
            Response::VpnProfiles { profiles } => assert!(profiles.is_empty()),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn vpn_delete_missing_profile_returns_typed_not_found() {
        let (service, _directory) = vpn_enabled_service().await;

        match service
            .dispatch(Request::VpnDeleteProfile {
                name: "missing.conf".to_string(),
            })
            .await
        {
            Response::VpnError {
                detail: VpnErrorDetail::NotFound { name },
            } => assert_eq!(name, "missing.conf"),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn vpn_activate_status_deactivate_workflow_dispatches_through_control_service() {
        let (service, _directory) = vpn_enabled_service().await;
        service
            .dispatch(Request::VpnImportProfile {
                name: "home.conf".to_string(),
                contents: valid_vpn_profile_contents(),
            })
            .await;

        match service.dispatch(Request::VpnStatus).await {
            Response::VpnStatus { active } => assert!(active.is_none()),
            other => panic!("unexpected response: {other:?}"),
        }

        match service
            .dispatch(Request::VpnActivate {
                name: "home.conf".to_string(),
            })
            .await
        {
            Response::VpnActivated { active } => {
                assert_eq!(active.profile_name, "home.conf");
                assert!(active.up);
            }
            other => panic!("unexpected response: {other:?}"),
        }

        match service.dispatch(Request::VpnStatus).await {
            Response::VpnStatus {
                active: Some(active),
            } => {
                assert_eq!(active.profile_name, "home.conf");
                assert!(active.up);
            }
            other => panic!("unexpected response: {other:?}"),
        }

        match service.dispatch(Request::VpnDeactivate).await {
            Response::VpnDeactivated => {}
            other => panic!("unexpected response: {other:?}"),
        }

        match service.dispatch(Request::VpnStatus).await {
            Response::VpnStatus { active } => assert!(active.is_none()),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn vpn_activate_conflict_with_foreign_interface_returns_typed_error() {
        let provider = FakeVpnProvider::default();
        provider.seed_foreign_link(
            crate::vpn::manager::OWNED_INTERFACE_NAME,
            OTHER_VPN_PRIVATE_KEY,
        );
        let (service, _directory) = vpn_enabled_service_with_provider(provider).await;
        service
            .dispatch(Request::VpnImportProfile {
                name: "home.conf".to_string(),
                contents: valid_vpn_profile_contents(),
            })
            .await;

        match service
            .dispatch(Request::VpnActivate {
                name: "home.conf".to_string(),
            })
            .await
        {
            Response::VpnError {
                detail: VpnErrorDetail::ForeignInterfaceConflict,
            } => {}
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn vpn_activate_when_already_active_returns_typed_error() {
        let (service, _directory) = vpn_enabled_service().await;
        service
            .dispatch(Request::VpnImportProfile {
                name: "home.conf".to_string(),
                contents: valid_vpn_profile_contents(),
            })
            .await;
        match service
            .dispatch(Request::VpnActivate {
                name: "home.conf".to_string(),
            })
            .await
        {
            Response::VpnActivated { .. } => {}
            other => panic!("unexpected response: {other:?}"),
        }

        match service
            .dispatch(Request::VpnActivate {
                name: "home.conf".to_string(),
            })
            .await
        {
            Response::VpnError {
                detail: VpnErrorDetail::AlreadyActive,
            } => {}
            other => panic!("unexpected response: {other:?}"),
        }
    }

    use crate::firewall::vpn::test_support::nft_ruleset;
    use crate::firewall::vpn::{VpnPolicyFirewallBackend, VpnPolicyFirewallDesired};

    fn vpn_policy_firewall_desired() -> VpnPolicyFirewallDesired {
        VpnPolicyFirewallDesired {
            protected_subnets: vec!["192.168.10.1/24".parse().unwrap()],
            vpn_interface: OWNED_INTERFACE_NAME.to_string(),
            physical_uplink: "wan0".to_string(),
        }
    }

    #[derive(Default)]
    struct StatefulFakeNftExecutor {
        installed: StdMutex<Option<VpnPolicyFirewallDesired>>,
    }

    impl NftExecutor for StatefulFakeNftExecutor {
        fn execute(&self, arguments: &[&str], input: &[u8]) -> Result<Vec<u8>> {
            match arguments {
                ["--json", "list", "ruleset"] => {
                    Ok(nft_ruleset(self.installed.lock().unwrap().as_ref()))
                }
                ["-f", "-"] => {
                    let batch = String::from_utf8_lossy(input);
                    let mut installed = self.installed.lock().unwrap();
                    *installed = if batch.contains("table inet traffic_masq_vpn {") {
                        Some(vpn_policy_firewall_desired())
                    } else {
                        None
                    };
                    Ok(Vec::new())
                }
                other => anyhow::bail!("unexpected nft invocation: {other:?}"),
            }
        }
    }

    #[derive(Default)]
    struct FakePolicyNetwork {
        interfaces: StdMutex<Vec<NetworkInterface>>,
        rules: StdMutex<Vec<crate::netlink::Ipv4RuleInfo>>,
        routes: StdMutex<Vec<crate::netlink::Ipv4RouteInfo>>,
    }

    impl FakePolicyNetwork {
        fn with_owned_interface() -> Arc<Self> {
            let network = Self::default();
            network.interfaces.lock().unwrap().push(NetworkInterface {
                is_wireless: false,
                index: 42,
                name: OWNED_INTERFACE_NAME.to_string(),
                is_up: true,
                rx_bytes: 0,
                tx_bytes: 0,
            });
            Arc::new(network)
        }
    }

    #[async_trait]
    impl NetworkProvider for FakePolicyNetwork {
        async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
            Ok(self.interfaces.lock().unwrap().clone())
        }

        async fn list_ipv4_addresses(&self, _interface: &str) -> Result<Vec<Ipv4AddressInfo>> {
            Ok(Vec::new())
        }

        async fn set_link_up(&self, _name: &str) -> Result<()> {
            Ok(())
        }

        async fn set_link_down(&self, _name: &str) -> Result<()> {
            Ok(())
        }

        async fn add_ipv4_address(
            &self,
            _interface: &str,
            _address: Ipv4Addr,
            _prefix_len: u8,
        ) -> Result<()> {
            Ok(())
        }

        async fn delete_ipv4_address(
            &self,
            _interface: &str,
            _address: Ipv4Addr,
            _prefix_len: u8,
        ) -> Result<()> {
            Ok(())
        }

        async fn list_ipv4_rules(&self) -> Result<Vec<crate::netlink::Ipv4RuleInfo>> {
            Ok(self.rules.lock().unwrap().clone())
        }

        async fn add_ipv4_rule(&self, rule: &crate::netlink::Ipv4RuleSpec) -> Result<()> {
            self.rules
                .lock()
                .unwrap()
                .push(crate::netlink::Ipv4RuleInfo {
                    source: rule.source,
                    destination: rule.destination,
                    table: rule.table,
                    priority: rule.priority,
                    fw_mark: rule.fw_mark,
                    fw_mask: rule.fw_mask,
                    input_interface: rule.input_interface.clone(),
                    output_interface: rule.output_interface.clone(),
                });
            Ok(())
        }

        async fn delete_ipv4_rule(&self, rule: &crate::netlink::Ipv4RuleInfo) -> Result<()> {
            self.rules.lock().unwrap().retain(|current| current != rule);
            Ok(())
        }

        async fn list_ipv4_routes(&self) -> Result<Vec<crate::netlink::Ipv4RouteInfo>> {
            Ok(self.routes.lock().unwrap().clone())
        }

        async fn add_ipv4_route(&self, route: &crate::netlink::Ipv4RouteSpec) -> Result<()> {
            self.routes
                .lock()
                .unwrap()
                .push(crate::netlink::Ipv4RouteInfo {
                    destination: route.destination,
                    gateway: route.gateway,
                    output_interface_index: route.output_interface_index,
                    table: route.table,
                    metric: route.metric,
                    protocol: route.protocol,
                    scope: 253,
                });
            Ok(())
        }

        async fn delete_ipv4_route(&self, route: &crate::netlink::Ipv4RouteInfo) -> Result<()> {
            self.routes
                .lock()
                .unwrap()
                .retain(|current| current != route);
            Ok(())
        }
    }

    fn router_and_vpn_base_config(wireguard_dir: std::path::PathBuf) -> AppConfig {
        let mut config = router_base_config_with_router_enabled();
        config.vpn.enabled = true;
        config.vpn.wireguard_config_dir = wireguard_dir;
        config
    }

    struct VpnPolicyFixture {
        service: ControlService,
        overrides: RuntimeOverrideManager,
        _directory: tempfile::TempDir,
    }

    async fn vpn_policy_fixture(activate_tunnel: bool) -> VpnPolicyFixture {
        let directory = tempdir().expect("tempdir");
        let config = router_and_vpn_base_config(directory.path().join("wireguard"));
        let overrides = RuntimeOverrideManager::load(directory.path(), &config)
            .await
            .expect("overrides");
        let dhcp = DhcpSupervisor::start(&config, &overrides.snapshot().await)
            .await
            .expect("dhcp supervisor");
        let network: Arc<dyn NetworkProvider> = FakePolicyNetwork::with_owned_interface();

        let vpn_store =
            crate::vpn::WireGuardProfileStore::new(config.vpn.wireguard_config_dir.clone());
        let active_profile_store =
            crate::vpn::ActiveProfileStore::new(directory.path().join("active-profile.json"));
        let provider: Arc<dyn crate::vpn::VpnProvider> = Arc::new(FakeVpnProvider::default());
        let driver = crate::vpn::WireGuardVpnDriver::new(provider, vpn_store);
        let tunnel = Arc::new(crate::vpn::VpnManager::new(driver, active_profile_store));

        if activate_tunnel {
            tunnel
                .import_profile("home.conf", valid_vpn_profile_contents().as_bytes())
                .expect("import profile");
            tunnel.activate("home.conf").await.expect("activate tunnel");
        }

        let executor: Arc<dyn NftExecutor> = Arc::new(StatefulFakeNftExecutor::default());
        let firewall = VpnPolicyFirewallBackend::new(executor);
        let policy = Arc::new(VpnPolicyManager::new(
            network.clone(),
            firewall,
            tunnel.clone(),
        ));

        let service = ControlService::new(config, network, dhcp, overrides.clone())
            .with_vpn_manager(tunnel)
            .with_vpn_policy_manager(policy);

        VpnPolicyFixture {
            service,
            overrides,
            _directory: directory,
        }
    }

    #[tokio::test]
    async fn vpn_policy_requests_are_rejected_when_vpn_is_disabled() {
        let directory = tempdir().expect("tempdir");
        let config = router_base_config();
        let overrides = RuntimeOverrideManager::load(directory.path(), &config)
            .await
            .expect("overrides");
        let dhcp = DhcpSupervisor::start(&config, &overrides.snapshot().await)
            .await
            .expect("dhcp supervisor");
        let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
            addresses: Vec::new(),
        });
        let service = ControlService::new(config, network, dhcp, overrides);

        for request in [
            Request::VpnPolicyStatus,
            Request::VpnPolicySetMode {
                mode: VpnPolicyMode::Vpn,
            },
            Request::VpnPolicyClearMode,
        ] {
            match service.dispatch(request).await {
                Response::VpnPolicyError {
                    detail: VpnPolicyErrorDetail::VpnDisabled,
                } => {}
                other => panic!("unexpected response: {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn vpn_policy_set_mode_vpn_activates_when_tunnel_is_healthy_and_persists() {
        let fixture = vpn_policy_fixture(true).await;

        match fixture
            .service
            .dispatch(Request::VpnPolicySetMode {
                mode: VpnPolicyMode::Vpn,
            })
            .await
        {
            Response::VpnPolicyStatus { status } => {
                assert_eq!(status.mode, VpnPolicyMode::Vpn);
                assert!(status.mode_override_active);
                assert!(status.policy_active);
                assert!(status.kill_switch_active);
                assert!(status.tunnel_healthy);
                assert_eq!(status.physical_uplink.as_deref(), Some("wan0"));
                assert_eq!(
                    status.protected_subnets,
                    vec!["192.168.10.1/24".parse().unwrap()]
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }

        assert_eq!(
            fixture.overrides.effective_vpn_mode().await,
            VpnPolicyMode::Vpn
        );

        match fixture.service.dispatch(Request::VpnPolicyStatus).await {
            Response::VpnPolicyStatus { status } => assert!(status.policy_active),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn vpn_policy_set_mode_vpn_fails_closed_without_active_tunnel() {
        let fixture = vpn_policy_fixture(false).await;

        match fixture
            .service
            .dispatch(Request::VpnPolicySetMode {
                mode: VpnPolicyMode::Vpn,
            })
            .await
        {
            Response::VpnPolicyError {
                detail: VpnPolicyErrorDetail::TunnelUnhealthy { message },
            } => {
                assert!(message.contains("no active VPN tunnel"));
            }
            other => panic!("unexpected response: {other:?}"),
        }

        assert_eq!(
            fixture.overrides.effective_vpn_mode().await,
            VpnPolicyMode::Direct
        );

        match fixture.service.dispatch(Request::VpnPolicyStatus).await {
            Response::VpnPolicyStatus { status } => {
                assert!(!status.policy_active);
                assert!(!status.mode_override_active);
                assert_eq!(status.mode, VpnPolicyMode::Direct);
                assert!(!status.tunnel_healthy);
                assert!(status.tunnel.is_none());
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn vpn_policy_set_mode_direct_after_vpn_deactivates_and_persists() {
        let fixture = vpn_policy_fixture(true).await;
        fixture
            .service
            .dispatch(Request::VpnPolicySetMode {
                mode: VpnPolicyMode::Vpn,
            })
            .await;

        match fixture
            .service
            .dispatch(Request::VpnPolicySetMode {
                mode: VpnPolicyMode::Direct,
            })
            .await
        {
            Response::VpnPolicyStatus { status } => {
                assert_eq!(status.mode, VpnPolicyMode::Direct);
                assert!(status.mode_override_active);
                assert!(!status.policy_active);
            }
            other => panic!("unexpected response: {other:?}"),
        }

        assert_eq!(
            fixture.overrides.effective_vpn_mode().await,
            VpnPolicyMode::Direct
        );
    }

    #[tokio::test]
    async fn vpn_policy_clear_mode_falls_back_to_base_default() {
        let fixture = vpn_policy_fixture(true).await;
        fixture
            .service
            .dispatch(Request::VpnPolicySetMode {
                mode: VpnPolicyMode::Vpn,
            })
            .await;
        assert!(fixture.overrides.snapshot().await.vpn_mode.is_some());

        match fixture.service.dispatch(Request::VpnPolicyClearMode).await {
            Response::VpnPolicyStatus { status } => {
                assert_eq!(status.mode, VpnPolicyMode::Direct);
                assert!(!status.mode_override_active);
                assert!(!status.policy_active);
            }
            other => panic!("unexpected response: {other:?}"),
        }

        assert!(fixture.overrides.snapshot().await.vpn_mode.is_none());
    }

    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering as WifiOrdering};

    use crate::config::{WifiBand, WifiChannelWidth, WifiConfig, WifiSecurity};
    use crate::wifi::process::SupervisedProcess;
    use crate::wifi::{HostapdSupervisor as WifiSupervisor, ProcessError as WifiProcessError};

    struct FakeWifiHostapd {
        shutdown: Arc<std::sync::atomic::AtomicBool>,
        join: Option<std::thread::JoinHandle<()>>,
        ctrl_path: std::path::PathBuf,
    }

    impl FakeWifiHostapd {
        fn spawn(ctrl_path: std::path::PathBuf, config_path: std::path::PathBuf) -> Self {
            let socket =
                std::os::unix::net::UnixDatagram::bind(&ctrl_path).expect("bind fake ctrl socket");
            socket
                .set_read_timeout(Some(Duration::from_millis(20)))
                .expect("set read timeout");
            let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let shutdown_for_thread = shutdown.clone();

            let join = std::thread::spawn(move || {
                let read_ssid = |path: &std::path::Path| -> String {
                    let content = std::fs::read_to_string(path).expect("read fake config");
                    let hex = content
                        .lines()
                        .find_map(|line| line.strip_prefix("ssid2="))
                        .expect("ssid2 present");
                    let bytes: Vec<u8> = (0..hex.len())
                        .step_by(2)
                        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
                        .collect();
                    String::from_utf8(bytes).expect("utf8 ssid")
                };
                let mut ssid = read_ssid(&config_path);
                let mut buffer = [0u8; 4096];
                while !shutdown_for_thread.load(WifiOrdering::Relaxed) {
                    let (read, from) = match socket.recv_from(&mut buffer) {
                        Ok(result) => result,
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) =>
                        {
                            continue;
                        }
                        Err(_) => break,
                    };
                    let command = String::from_utf8_lossy(&buffer[..read]).into_owned();
                    let reply = if command == "PING" {
                        "PONG\n".to_string()
                    } else if command == "STATUS" {
                        format!("state=ENABLED\nssid[0]={ssid}\nbssid[0]=02:00:00:00:00:00\nnum_sta[0]=0\n")
                    } else if command == "RELOAD" {
                        ssid = read_ssid(&config_path);
                        "OK\n".to_string()
                    } else if command == "STA-FIRST" {
                        "FAIL\n".to_string()
                    } else if command.starts_with("DEAUTHENTICATE ") {
                        "OK\n".to_string()
                    } else {
                        "UNKNOWN COMMAND\n".to_string()
                    };
                    let _ = socket.send_to_addr(reply.as_bytes(), &from);
                }
            });

            Self {
                shutdown,
                join: Some(join),
                ctrl_path,
            }
        }
    }

    impl Drop for FakeWifiHostapd {
        fn drop(&mut self) {
            self.shutdown.store(true, WifiOrdering::Relaxed);
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
            let _ = std::fs::remove_file(&self.ctrl_path);
        }
    }

    #[derive(Default)]
    struct FakeWifiProcess {
        responders: StdMutex<HashMap<u32, FakeWifiHostapd>>,
        configs: StdMutex<HashMap<u32, std::path::PathBuf>>,
        next_pid: AtomicU32,
    }

    impl FakeWifiProcess {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                next_pid: AtomicU32::new(2000),
                ..Default::default()
            })
        }
    }

    #[async_trait]
    impl SupervisedProcess for FakeWifiProcess {
        async fn spawn(
            &self,
            _binary: &std::path::Path,
            config_path: &std::path::Path,
        ) -> Result<u32, WifiProcessError> {
            let pid = self.next_pid.fetch_add(1, WifiOrdering::Relaxed);
            let ctrl_path = config_path.with_extension("");
            let responder = FakeWifiHostapd::spawn(ctrl_path, config_path.to_path_buf());
            self.responders.lock().unwrap().insert(pid, responder);
            self.configs
                .lock()
                .unwrap()
                .insert(pid, config_path.to_path_buf());
            Ok(pid)
        }

        async fn is_alive(&self, pid: u32) -> Result<bool, WifiProcessError> {
            Ok(self.responders.lock().unwrap().contains_key(&pid))
        }

        async fn cmdline_contains(
            &self,
            pid: u32,
            config_path: &std::path::Path,
        ) -> Result<bool, WifiProcessError> {
            Ok(self
                .configs
                .lock()
                .unwrap()
                .get(&pid)
                .is_some_and(|recorded| recorded == config_path))
        }

        async fn terminate(&self, pid: u32) -> Result<(), WifiProcessError> {
            self.responders.lock().unwrap().remove(&pid);
            self.configs.lock().unwrap().remove(&pid);
            Ok(())
        }

        async fn kill(&self, pid: u32) -> Result<(), WifiProcessError> {
            self.responders.lock().unwrap().remove(&pid);
            self.configs.lock().unwrap().remove(&pid);
            Ok(())
        }
    }

    fn wifi_ap_config(ssid: &str, security: WifiSecurity) -> crate::config::WifiApConfig {
        crate::config::WifiApConfig {
            ssid: ssid.to_string(),
            country_code: Some("PL".to_string()),
            band: WifiBand::Ghz2,
            channel: 6,
            channel_width: WifiChannelWidth::Ht20,
            security,
            hidden: false,
            client_isolation: false,
            max_stations: 32,
            passphrase_file: None,
        }
    }

    fn wifi_base_config(directory: &std::path::Path) -> AppConfig {
        let mut config = AppConfig::default();
        config.runtime.state_dir = directory.to_path_buf();
        config.wifi = WifiConfig {
            enabled: true,
            hostapd_binary: PathBuf::from("/usr/sbin/hostapd"),
            runtime_dir: directory.join("hostapd"),
            restart_backoff_seconds: 1,
        };
        config.network.interfaces.insert(
            "wlan0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Output,
                managed: true,
                ipv4: Some("192.168.101.1/24".parse().unwrap()),
                dhcp: None,
                dhcp_client: None,
                wifi: Some(wifi_ap_config("net-a", WifiSecurity::Open)),
                wifi_client: None,
            },
        );
        config
    }

    struct WifiFixture {
        service: ControlService,
        process: Arc<FakeWifiProcess>,
        _directory: tempfile::TempDir,
    }

    async fn configure_wlan0(wifi: &WifiSupervisor, config: &AppConfig) {
        let interface_config = config
            .network
            .interfaces
            .get("wlan0")
            .expect("wlan0 declared");
        let spec = WifiApSpec::from_interface_config("wlan0", interface_config)
            .expect("valid")
            .expect("wifi declared on wlan0");
        wifi.configure(spec).await.expect("configure wlan0");
    }

    async fn wifi_enabled_fixture() -> WifiFixture {
        let directory = tempdir().expect("tempdir");
        let config = wifi_base_config(directory.path());
        let overrides = RuntimeOverrideManager::load(directory.path(), &config)
            .await
            .expect("overrides");
        let dhcp = DhcpSupervisor::start(&config, &overrides.snapshot().await)
            .await
            .expect("dhcp supervisor");
        let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
            addresses: Vec::new(),
        });
        let process = FakeWifiProcess::new();
        let wifi = WifiSupervisor::start_with_process(
            &config,
            &overrides.snapshot().await,
            process.clone(),
        )
        .await
        .expect("wifi supervisor");
        configure_wlan0(&wifi, &config).await;
        let service =
            ControlService::new(config, network, dhcp, overrides).with_wifi_supervisor(wifi);
        WifiFixture {
            service,
            process,
            _directory: directory,
        }
    }

    #[tokio::test]
    async fn wifi_requests_are_rejected_when_wifi_is_disabled() {
        let directory = tempdir().expect("tempdir");
        let config = router_base_config();
        let overrides = RuntimeOverrideManager::load(directory.path(), &config)
            .await
            .expect("overrides");
        let dhcp = DhcpSupervisor::start(&config, &overrides.snapshot().await)
            .await
            .expect("dhcp supervisor");
        let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
            addresses: Vec::new(),
        });
        let service = ControlService::new(config, network, dhcp, overrides);

        for request in [
            Request::WifiStatus,
            Request::GetWifiConfig {
                interface: "wlan0".to_string(),
            },
            Request::ConfigureWifi {
                interface: "wlan0".to_string(),
                settings: WifiEditRequest {
                    ssid: "net-a".to_string(),
                    country_code: Some("PL".to_string()),
                    band: WifiBand::Ghz2,
                    channel: 6,
                    channel_width: WifiChannelWidth::Ht20,
                    security: WifiSecurity::Open,
                    hidden: false,
                    client_isolation: false,
                    max_stations: 32,
                },
            },
            Request::DisableWifi {
                interface: "wlan0".to_string(),
            },
            Request::WifiSetPassphrase {
                interface: "wlan0".to_string(),
                passphrase: "correct horse battery".to_string(),
            },
            Request::ListWifiStations {
                interface: "wlan0".to_string(),
            },
            Request::WifiDeauthStation {
                interface: "wlan0".to_string(),
                mac: "02:00:00:00:00:01".to_string(),
            },
            Request::WifiReload {
                interface: "wlan0".to_string(),
            },
        ] {
            let response = service.dispatch(request).await;
            assert!(
                matches!(
                    response,
                    Response::WifiError {
                        detail: WifiErrorDetail::WifiDisabled
                    }
                ),
                "{response:?}"
            );
        }
    }

    #[tokio::test]
    async fn wifi_status_reports_a_configured_access_point_because_start_up_brought_it_up() {
        let fixture = wifi_enabled_fixture().await;

        assert_eq!(fixture.process.configs.lock().unwrap().len(), 1);

        match fixture.service.dispatch(Request::WifiStatus).await {
            Response::WifiStatus { interfaces } => {
                assert_eq!(interfaces.len(), 1);
                assert_eq!(interfaces[0].interface, "wlan0");
                assert_eq!(interfaces[0].spec.ssid, "net-a");
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_wifi_config_reports_none_for_an_interface_without_a_wifi_block() {
        let mut fixture_directory = tempdir().expect("tempdir");
        let mut config = wifi_base_config(fixture_directory.path());
        config.network.interfaces.insert(
            "wan0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Input,
                managed: false,
                ipv4: None,
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
            },
        );
        let overrides = RuntimeOverrideManager::load(fixture_directory.path(), &config)
            .await
            .expect("overrides");
        let dhcp = DhcpSupervisor::start(&config, &overrides.snapshot().await)
            .await
            .expect("dhcp supervisor");
        let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
            addresses: Vec::new(),
        });
        let process = FakeWifiProcess::new();
        let wifi =
            WifiSupervisor::start_with_process(&config, &overrides.snapshot().await, process)
                .await
                .expect("wifi supervisor");
        let service =
            ControlService::new(config, network, dhcp, overrides).with_wifi_supervisor(wifi);
        let _ = &mut fixture_directory;

        match service
            .dispatch(Request::GetWifiConfig {
                interface: "wan0".to_string(),
            })
            .await
        {
            Response::WifiConfig { interface, spec } => {
                assert_eq!(interface, "wan0");
                assert!(spec.is_none());
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_wifi_config_reports_unknown_interface_as_none_too() {
        let fixture = wifi_enabled_fixture().await;
        match fixture
            .service
            .dispatch(Request::GetWifiConfig {
                interface: "does-not-exist".to_string(),
            })
            .await
        {
            Response::WifiConfig { spec, .. } => assert!(spec.is_none()),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn configure_wifi_reconfigures_and_persists_the_new_ssid() {
        let fixture = wifi_enabled_fixture().await;
        let response = fixture
            .service
            .dispatch(Request::ConfigureWifi {
                interface: "wlan0".to_string(),
                settings: WifiEditRequest {
                    ssid: "net-b".to_string(),
                    country_code: Some("PL".to_string()),
                    band: WifiBand::Ghz2,
                    channel: 6,
                    channel_width: WifiChannelWidth::Ht20,
                    security: WifiSecurity::Open,
                    hidden: false,
                    client_isolation: false,
                    max_stations: 32,
                },
            })
            .await;
        match response {
            Response::WifiConfigured { spec } => assert_eq!(spec.ssid, "net-b"),
            other => panic!("unexpected response: {other:?}"),
        }

        match fixture
            .service
            .dispatch(Request::GetWifiConfig {
                interface: "wlan0".to_string(),
            })
            .await
        {
            Response::WifiConfig {
                spec: Some(spec), ..
            } => assert_eq!(spec.ssid, "net-b"),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn configure_wifi_on_an_unknown_interface_is_interface_not_found() {
        let fixture = wifi_enabled_fixture().await;
        let response = fixture
            .service
            .dispatch(Request::ConfigureWifi {
                interface: "does-not-exist".to_string(),
                settings: WifiEditRequest {
                    ssid: "net-a".to_string(),
                    country_code: None,
                    band: WifiBand::Ghz2,
                    channel: 6,
                    channel_width: WifiChannelWidth::Ht20,
                    security: WifiSecurity::Open,
                    hidden: false,
                    client_isolation: false,
                    max_stations: 32,
                },
            })
            .await;
        assert!(matches!(
            response,
            Response::WifiError {
                detail: WifiErrorDetail::InterfaceNotFound
            }
        ));
    }

    #[tokio::test]
    async fn disable_wifi_stops_the_access_point_and_persists_the_removal() {
        let fixture = wifi_enabled_fixture().await;
        let response = fixture
            .service
            .dispatch(Request::DisableWifi {
                interface: "wlan0".to_string(),
            })
            .await;
        assert!(matches!(
            response,
            Response::WifiDisabled { interface } if interface == "wlan0"
        ));

        match fixture.service.dispatch(Request::WifiStatus).await {
            Response::WifiStatus { interfaces } => assert!(interfaces.is_empty()),
            other => panic!("unexpected response: {other:?}"),
        }
        match fixture
            .service
            .dispatch(Request::GetWifiConfig {
                interface: "wlan0".to_string(),
            })
            .await
        {
            Response::WifiConfig { spec, .. } => assert!(spec.is_none()),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_wifi_stations_on_an_unconfigured_interface_is_interface_not_found() {
        let fixture = wifi_enabled_fixture().await;
        let response = fixture
            .service
            .dispatch(Request::ListWifiStations {
                interface: "does-not-exist".to_string(),
            })
            .await;
        assert!(matches!(
            response,
            Response::WifiError {
                detail: WifiErrorDetail::InterfaceNotFound
            }
        ));
    }

    #[tokio::test]
    async fn wifi_deauth_station_rejects_a_malformed_mac() {
        let fixture = wifi_enabled_fixture().await;
        let response = fixture
            .service
            .dispatch(Request::WifiDeauthStation {
                interface: "wlan0".to_string(),
                mac: "not-a-mac".to_string(),
            })
            .await;
        assert!(matches!(
            response,
            Response::WifiError {
                detail: WifiErrorDetail::InvalidSpec { .. }
            }
        ));
    }

    #[tokio::test]
    async fn wifi_reload_sends_reload_and_returns_the_current_spec() {
        let fixture = wifi_enabled_fixture().await;
        let response = fixture
            .service
            .dispatch(Request::WifiReload {
                interface: "wlan0".to_string(),
            })
            .await;
        match response {
            Response::WifiConfigured { spec } => assert_eq!(spec.ssid, "net-a"),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn configure_wifi_to_wpa2_without_a_passphrase_is_refused_and_changes_nothing() {
        let fixture = wifi_enabled_fixture().await;
        let response = fixture
            .service
            .dispatch(Request::ConfigureWifi {
                interface: "wlan0".to_string(),
                settings: WifiEditRequest {
                    ssid: "net-a".to_string(),
                    country_code: Some("PL".to_string()),
                    band: WifiBand::Ghz2,
                    channel: 6,
                    channel_width: WifiChannelWidth::Ht20,
                    security: WifiSecurity::Wpa2,
                    hidden: false,
                    client_isolation: false,
                    max_stations: 32,
                },
            })
            .await;
        assert!(
            matches!(
                response,
                Response::WifiError {
                    detail: WifiErrorDetail::PassphraseMissing
                }
            ),
            "{response:?}"
        );

        match fixture
            .service
            .dispatch(Request::GetWifiConfig {
                interface: "wlan0".to_string(),
            })
            .await
        {
            Response::WifiConfig {
                spec: Some(spec), ..
            } => assert_eq!(spec.security, WifiSecurity::Open),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn wifi_set_passphrase_applies_live_via_reload() {
        let directory = tempdir().expect("tempdir");
        let mut config = wifi_base_config(directory.path());
        config.network.interfaces.insert(
            "wlan0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Output,
                managed: true,
                ipv4: Some("192.168.101.1/24".parse().unwrap()),
                dhcp: None,
                dhcp_client: None,
                wifi: Some(wifi_ap_config("net-a", WifiSecurity::Wpa2)),
                wifi_client: None,
            },
        );
        let overrides = RuntimeOverrideManager::load(directory.path(), &config)
            .await
            .expect("overrides");
        let dhcp = DhcpSupervisor::start(&config, &overrides.snapshot().await)
            .await
            .expect("dhcp supervisor");
        let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
            addresses: Vec::new(),
        });
        let process = FakeWifiProcess::new();
        let wifi =
            WifiSupervisor::start_with_process(&config, &overrides.snapshot().await, process)
                .await
                .expect("wifi supervisor");

        let passphrase_store = crate::wifi::PassphraseStore::new(directory.path().join("wifi/psk"));
        passphrase_store
            .set(
                "wlan0",
                &crate::wifi::WifiPassphrase::new("first passphrase").unwrap(),
            )
            .unwrap();
        configure_wlan0(&wifi, &config).await;
        let service =
            ControlService::new(config, network, dhcp, overrides).with_wifi_supervisor(wifi);

        match service
            .dispatch(Request::WifiSetPassphrase {
                interface: "wlan0".to_string(),
                passphrase: "second passphrase".to_string(),
            })
            .await
        {
            Response::WifiConfigured { spec } => assert_eq!(spec.security, WifiSecurity::Wpa2),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn no_wifi_response_variant_can_hold_a_passphrase() {
        fn assert_no_passphrase_field(spec: &WifiApSpec) {
            let WifiApSpec {
                interface: _,
                ssid: _,
                country_code: _,
                band: _,
                channel: _,
                channel_width: _,
                security: _,
                hidden: _,
                client_isolation: _,
                max_stations: _,
                passphrase_file: _,
            } = spec;
        }
        let _ = assert_no_passphrase_field;
    }

    #[tokio::test]
    async fn wifi_configured_response_never_serializes_the_passphrase_that_was_just_set() {
        let directory = tempdir().expect("tempdir");
        let mut config = wifi_base_config(directory.path());
        config.network.interfaces.insert(
            "wlan0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Output,
                managed: true,
                ipv4: Some("192.168.101.1/24".parse().unwrap()),
                dhcp: None,
                dhcp_client: None,
                wifi: Some(wifi_ap_config("net-a", WifiSecurity::Wpa2)),
                wifi_client: None,
            },
        );
        let overrides = RuntimeOverrideManager::load(directory.path(), &config)
            .await
            .expect("overrides");
        let dhcp = DhcpSupervisor::start(&config, &overrides.snapshot().await)
            .await
            .expect("dhcp supervisor");
        let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
            addresses: Vec::new(),
        });
        let process = FakeWifiProcess::new();

        let passphrase_store = crate::wifi::PassphraseStore::new(directory.path().join("wifi/psk"));
        passphrase_store
            .set(
                "wlan0",
                &crate::wifi::WifiPassphrase::new("seed passphrase").unwrap(),
            )
            .unwrap();
        let wifi =
            WifiSupervisor::start_with_process(&config, &overrides.snapshot().await, process)
                .await
                .expect("wifi supervisor");
        configure_wlan0(&wifi, &config).await;
        let service =
            ControlService::new(config, network, dhcp, overrides).with_wifi_supervisor(wifi);

        let secret = "super secret passphrase, must never leak";
        let response = service
            .dispatch(Request::WifiSetPassphrase {
                interface: "wlan0".to_string(),
                passphrase: secret.to_string(),
            })
            .await;
        let encoded = serde_json::to_string(&response).expect("serialize");
        assert!(
            !encoded.contains(secret),
            "a Wi-Fi response must never echo back a passphrase: {encoded}"
        );

        for other in [
            service.dispatch(Request::WifiStatus).await,
            service
                .dispatch(Request::GetWifiConfig {
                    interface: "wlan0".to_string(),
                })
                .await,
            service
                .dispatch(Request::ListWifiStations {
                    interface: "wlan0".to_string(),
                })
                .await,
        ] {
            let encoded = serde_json::to_string(&other).expect("serialize");
            assert!(!encoded.contains(secret), "{encoded}");
        }
    }

    use crate::config::{WifiClientGlobalConfig, WifiClientSecurity};
    use crate::wifi::WifiClientSupervisor as ClientSupervisor;

    struct FakeSupplicant {
        shutdown: Arc<std::sync::atomic::AtomicBool>,
        join: Option<std::thread::JoinHandle<()>>,
        ctrl_path: std::path::PathBuf,
    }

    impl FakeSupplicant {
        fn spawn(ctrl_path: std::path::PathBuf, config_path: std::path::PathBuf) -> Self {
            let socket =
                std::os::unix::net::UnixDatagram::bind(&ctrl_path).expect("bind fake ctrl socket");
            socket
                .set_read_timeout(Some(Duration::from_millis(20)))
                .expect("set read timeout");
            let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let shutdown_for_thread = shutdown.clone();

            let join = std::thread::spawn(move || {
                let content = std::fs::read_to_string(&config_path).expect("read fake config");
                let hex = content
                    .lines()
                    .map(str::trim)
                    .find_map(|line| line.strip_prefix("ssid="))
                    .expect("ssid present");
                let bytes: Vec<u8> = (0..hex.len())
                    .step_by(2)
                    .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
                    .collect();
                let ssid = String::from_utf8(bytes).expect("utf8 ssid");

                let mut buffer = [0u8; 4096];
                while !shutdown_for_thread.load(WifiOrdering::Relaxed) {
                    let (read, from) = match socket.recv_from(&mut buffer) {
                        Ok(result) => result,
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) =>
                        {
                            continue;
                        }
                        Err(_) => break,
                    };
                    let command = String::from_utf8_lossy(&buffer[..read]).into_owned();
                    let reply = match command.as_str() {
                        "PING" => "PONG\n".to_string(),
                        "STATUS" => format!(
                            "wpa_state=COMPLETED\nssid={ssid}\nbssid=02:00:00:00:00:01\nfreq=2437\n"
                        ),
                        "RECONNECT" | "DISCONNECT" | "REASSOCIATE" => "OK\n".to_string(),
                        _ => "UNKNOWN COMMAND\n".to_string(),
                    };
                    let _ = socket.send_to_addr(reply.as_bytes(), &from);
                }
            });

            Self {
                shutdown,
                join: Some(join),
                ctrl_path,
            }
        }
    }

    impl Drop for FakeSupplicant {
        fn drop(&mut self) {
            self.shutdown.store(true, WifiOrdering::Relaxed);
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
            let _ = std::fs::remove_file(&self.ctrl_path);
        }
    }

    #[derive(Default)]
    struct FakeSupplicantProcess {
        responders: StdMutex<HashMap<u32, FakeSupplicant>>,
        configs: StdMutex<HashMap<u32, std::path::PathBuf>>,
        next_pid: AtomicU32,
    }

    impl FakeSupplicantProcess {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                next_pid: AtomicU32::new(3000),
                ..Default::default()
            })
        }
    }

    #[async_trait]
    impl SupervisedProcess for FakeSupplicantProcess {
        async fn spawn(
            &self,
            _binary: &std::path::Path,
            config_path: &std::path::Path,
        ) -> Result<u32, WifiProcessError> {
            let pid = self.next_pid.fetch_add(1, WifiOrdering::Relaxed);
            let ctrl_path = config_path.with_extension("");
            let responder = FakeSupplicant::spawn(ctrl_path, config_path.to_path_buf());
            self.responders.lock().unwrap().insert(pid, responder);
            self.configs
                .lock()
                .unwrap()
                .insert(pid, config_path.to_path_buf());
            Ok(pid)
        }

        async fn is_alive(&self, pid: u32) -> Result<bool, WifiProcessError> {
            Ok(self.responders.lock().unwrap().contains_key(&pid))
        }

        async fn cmdline_contains(
            &self,
            pid: u32,
            config_path: &std::path::Path,
        ) -> Result<bool, WifiProcessError> {
            Ok(self
                .configs
                .lock()
                .unwrap()
                .get(&pid)
                .is_some_and(|recorded| recorded == config_path))
        }

        async fn terminate(&self, pid: u32) -> Result<(), WifiProcessError> {
            self.responders.lock().unwrap().remove(&pid);
            self.configs.lock().unwrap().remove(&pid);
            Ok(())
        }

        async fn kill(&self, pid: u32) -> Result<(), WifiProcessError> {
            self.responders.lock().unwrap().remove(&pid);
            self.configs.lock().unwrap().remove(&pid);
            Ok(())
        }
    }

    fn wifi_client_base_config(directory: &std::path::Path) -> AppConfig {
        let mut config = AppConfig::default();
        config.runtime.state_dir = directory.to_path_buf();
        config.wifi_client = WifiClientGlobalConfig {
            enabled: true,
            wpa_supplicant_binary: PathBuf::from("/usr/sbin/wpa_supplicant"),
            runtime_dir: directory.join("wpa_supplicant"),
            restart_backoff_seconds: 1,
        };
        config.network.interfaces.insert(
            "wlan1".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Input,
                managed: false,
                ipv4: None,
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: Some(crate::config::WifiClientConfig {
                    ssid: "upstream".to_string(),
                    country_code: Some("PL".to_string()),
                    security: WifiClientSecurity::Open,
                    passphrase_file: None,
                }),
            },
        );
        config
    }

    struct WifiClientFixture {
        service: ControlService,
        _directory: tempfile::TempDir,
    }

    async fn wifi_client_enabled_fixture() -> WifiClientFixture {
        let directory = tempdir().expect("tempdir");
        let config = wifi_client_base_config(directory.path());
        let overrides = RuntimeOverrideManager::load(directory.path(), &config)
            .await
            .expect("overrides");
        let dhcp = DhcpSupervisor::start(&config, &overrides.snapshot().await)
            .await
            .expect("dhcp supervisor");
        let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
            addresses: Vec::new(),
        });
        let wifi_client = ClientSupervisor::start_with_process(
            &config,
            &overrides.snapshot().await,
            FakeSupplicantProcess::new(),
        )
        .await
        .expect("wifi client supervisor");

        let interface_config = config
            .network
            .interfaces
            .get("wlan1")
            .expect("wlan1 declared");
        let spec = WifiClientSpec::from_interface_config("wlan1", interface_config)
            .expect("valid")
            .expect("wifi_client declared on wlan1");
        wifi_client.configure(spec).await.expect("configure wlan1");

        let service = ControlService::new(config, network, dhcp, overrides)
            .with_wifi_client_supervisor(wifi_client);
        WifiClientFixture {
            service,
            _directory: directory,
        }
    }

    #[tokio::test]
    async fn wifi_client_requests_are_rejected_when_client_mode_is_disabled() {
        let directory = tempdir().expect("tempdir");
        let config = router_base_config();
        let overrides = RuntimeOverrideManager::load(directory.path(), &config)
            .await
            .expect("overrides");
        let dhcp = DhcpSupervisor::start(&config, &overrides.snapshot().await)
            .await
            .expect("dhcp supervisor");
        let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
            addresses: Vec::new(),
        });
        let service = ControlService::new(config, network, dhcp, overrides);

        for request in [
            Request::WifiClientStatus,
            Request::GetWifiClientConfig {
                interface: "wlan1".to_string(),
            },
            Request::DisableWifiClient {
                interface: "wlan1".to_string(),
            },
            Request::WifiClientReconnect {
                interface: "wlan1".to_string(),
            },
            Request::WifiClientScan {
                interface: "wlan1".to_string(),
            },
            Request::WifiClientSetPassphrase {
                interface: "wlan1".to_string(),
                passphrase: "a-secret-value".to_string(),
            },
        ] {
            assert!(
                matches!(
                    service.dispatch(request).await,
                    Response::WifiClientError {
                        detail: WifiClientErrorDetail::WifiClientDisabled
                    }
                ),
                "every client request must report the subsystem as disabled"
            );
        }
    }

    #[tokio::test]
    async fn saved_wifi_client_profile_crud_activation_and_active_delete_guard() {
        let fixture = wifi_client_enabled_fixture().await;
        let create = fixture
            .service
            .dispatch(Request::CreateWifiClientProfile {
                profile: WifiClientProfileWriteRequest {
                    id: "office".to_string(),
                    ssid: "profile-network".to_string(),
                    country_code: Some("PL".to_string()),
                    security: WifiClientSecurity::Open,
                    priority: 10,
                    passphrase: None,
                    clear_passphrase: false,
                },
            })
            .await;
        let Response::WifiClientProfile { profile } = create else {
            panic!("expected profile response, got {create:?}");
        };
        assert_eq!(profile.id, "office");
        assert!(!profile.has_passphrase);
        let serialized = serde_json::to_string(&profile).unwrap();
        assert!(serialized.contains("has_passphrase"));
        assert!(!serialized.contains("a-secret-value"));

        let Response::WifiClientProfiles { profiles } = fixture
            .service
            .dispatch(Request::ListWifiClientProfiles)
            .await
        else {
            panic!("expected profile list");
        };
        assert_eq!(profiles.len(), 1);

        let activated = fixture
            .service
            .dispatch(Request::ActivateWifiClientProfile {
                interface: "wlan1".to_string(),
                profile_id: "office".to_string(),
            })
            .await;
        let Response::WifiClientProfileActivated { status, .. } = activated else {
            panic!("expected activation response, got {activated:?}");
        };
        assert_eq!(status.spec.ssid, "profile-network");

        assert!(matches!(
            fixture
                .service
                .dispatch(Request::DeleteWifiClientProfile {
                    id: "office".to_string(),
                })
                .await,
            Response::WifiClientProfileError {
                detail: WifiClientProfileErrorDetail::ProfileActive { .. }
            }
        ));
        assert!(matches!(
            fixture
                .service
                .dispatch(Request::DeactivateWifiClientProfile {
                    interface: "wlan1".to_string(),
                })
                .await,
            Response::WifiClientDisabled { .. }
        ));
        assert!(matches!(
            fixture
                .service
                .dispatch(Request::DeleteWifiClientProfile {
                    id: "office".to_string(),
                })
                .await,
            Response::WifiClientProfileDeleted { .. }
        ));
    }

    #[tokio::test]
    async fn wifi_client_status_reports_the_live_association() {
        let fixture = wifi_client_enabled_fixture().await;
        let Response::WifiClientStatus { interfaces } =
            fixture.service.dispatch(Request::WifiClientStatus).await
        else {
            panic!("expected a client status response");
        };
        assert_eq!(interfaces.len(), 1);
        assert_eq!(interfaces[0].interface, "wlan1");
        assert_eq!(interfaces[0].spec.ssid, "upstream");
        assert!(interfaces[0].wpa_state.is_connected());
    }

    #[tokio::test]
    async fn configure_wifi_client_applies_and_persists_the_new_network() {
        let fixture = wifi_client_enabled_fixture().await;
        let response = fixture
            .service
            .dispatch(Request::ConfigureWifiClient {
                interface: "wlan1".to_string(),
                settings: WifiClientEditRequest {
                    ssid: "somewhere-else".to_string(),
                    country_code: Some("PL".to_string()),
                    security: WifiClientSecurity::Open,
                },
            })
            .await;
        let Response::WifiClientConfigured { spec } = response else {
            panic!("expected a configured response, got {response:?}");
        };
        assert_eq!(spec.ssid, "somewhere-else");

        let Response::WifiClientConfig { spec, .. } = fixture
            .service
            .dispatch(Request::GetWifiClientConfig {
                interface: "wlan1".to_string(),
            })
            .await
        else {
            panic!("expected a config response");
        };
        assert_eq!(spec.expect("spec persisted").ssid, "somewhere-else");
    }

    #[tokio::test]
    async fn configuring_an_unknown_interface_reports_it_as_not_found() {
        let fixture = wifi_client_enabled_fixture().await;
        let response = fixture
            .service
            .dispatch(Request::ConfigureWifiClient {
                interface: "nope0".to_string(),
                settings: WifiClientEditRequest {
                    ssid: "upstream".to_string(),
                    country_code: None,
                    security: WifiClientSecurity::Open,
                },
            })
            .await;
        assert!(
            matches!(
                response,
                Response::WifiClientError {
                    detail: WifiClientErrorDetail::InterfaceNotFound
                }
            ),
            "got {response:?}"
        );
    }

    #[tokio::test]
    async fn configuring_a_client_on_an_output_interface_is_an_invalid_spec() {
        let directory = tempdir().expect("tempdir");
        let mut config = wifi_client_base_config(directory.path());
        config.network.interfaces.insert(
            "wlan2".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Output,
                managed: true,
                ipv4: Some("192.168.9.1/24".parse().unwrap()),
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
            },
        );
        let overrides = RuntimeOverrideManager::load(directory.path(), &config)
            .await
            .expect("overrides");
        let dhcp = DhcpSupervisor::start(&config, &overrides.snapshot().await)
            .await
            .expect("dhcp supervisor");
        let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
            addresses: Vec::new(),
        });
        let wifi_client = ClientSupervisor::start_with_process(
            &config,
            &overrides.snapshot().await,
            FakeSupplicantProcess::new(),
        )
        .await
        .expect("wifi client supervisor");
        let service = ControlService::new(config, network, dhcp, overrides)
            .with_wifi_client_supervisor(wifi_client);

        let response = service
            .dispatch(Request::ConfigureWifiClient {
                interface: "wlan2".to_string(),
                settings: WifiClientEditRequest {
                    ssid: "upstream".to_string(),
                    country_code: None,
                    security: WifiClientSecurity::Open,
                },
            })
            .await;
        assert!(
            matches!(
                response,
                Response::WifiClientError {
                    detail: WifiClientErrorDetail::InvalidSpec { .. }
                }
            ),
            "got {response:?}"
        );
    }

    #[tokio::test]
    async fn disable_wifi_client_stops_it_and_clears_the_persisted_block() {
        let fixture = wifi_client_enabled_fixture().await;
        let response = fixture
            .service
            .dispatch(Request::DisableWifiClient {
                interface: "wlan1".to_string(),
            })
            .await;
        assert!(
            matches!(response, Response::WifiClientDisabled { .. }),
            "got {response:?}"
        );

        let Response::WifiClientStatus { interfaces } =
            fixture.service.dispatch(Request::WifiClientStatus).await
        else {
            panic!("expected a client status response");
        };
        assert!(
            interfaces.is_empty(),
            "a disabled client must not still be reported"
        );
    }

    #[tokio::test]
    async fn a_passphrase_is_never_echoed_back_in_any_response() {
        const SECRET: &str = "a-very-secret-passphrase";
        let fixture = wifi_client_enabled_fixture().await;

        fixture
            .service
            .dispatch(Request::ConfigureWifiClient {
                interface: "wlan1".to_string(),
                settings: WifiClientEditRequest {
                    ssid: "upstream".to_string(),
                    country_code: Some("PL".to_string()),
                    security: WifiClientSecurity::Wpa2,
                },
            })
            .await;
        let set = fixture
            .service
            .dispatch(Request::WifiClientSetPassphrase {
                interface: "wlan1".to_string(),
                passphrase: SECRET.to_string(),
            })
            .await;
        let status = fixture.service.dispatch(Request::WifiClientStatus).await;
        let config = fixture
            .service
            .dispatch(Request::GetWifiClientConfig {
                interface: "wlan1".to_string(),
            })
            .await;

        for response in [set, status, config] {
            let encoded = serde_json::to_string(&response).expect("serialize");
            assert!(
                !encoded.contains(SECRET),
                "a passphrase leaked into {encoded}"
            );
        }
    }

    #[tokio::test]
    async fn reconnect_reports_the_network_it_reconnected_to() {
        let fixture = wifi_client_enabled_fixture().await;
        let response = fixture
            .service
            .dispatch(Request::WifiClientReconnect {
                interface: "wlan1".to_string(),
            })
            .await;
        let Response::WifiClientConfigured { spec } = response else {
            panic!("expected the running spec back, got {response:?}");
        };
        assert_eq!(spec.ssid, "upstream");
    }

    #[tokio::test]
    async fn reconnecting_an_unmanaged_interface_reports_it_as_not_found() {
        let fixture = wifi_client_enabled_fixture().await;
        let response = fixture
            .service
            .dispatch(Request::WifiClientReconnect {
                interface: "wlan9".to_string(),
            })
            .await;
        assert!(
            matches!(
                response,
                Response::WifiClientError {
                    detail: WifiClientErrorDetail::InterfaceNotFound
                }
            ),
            "got {response:?}"
        );
    }

    struct DhcpClientControlFixture {
        service: ControlService,
        overrides: RuntimeOverrideManager,
        supervisor: DhcpClientSupervisor,
        directory: tempfile::TempDir,
    }

    async fn dhcp_client_control_fixture(enabled: bool) -> DhcpClientControlFixture {
        dhcp_client_control_fixture_with_router(enabled, false).await
    }

    async fn dhcp_client_control_fixture_with_router(
        enabled: bool,
        router_uplink: bool,
    ) -> DhcpClientControlFixture {
        let directory = tempdir().expect("tempdir");
        let mut config = AppConfig::default();
        config.runtime.state_dir = directory.path().to_path_buf();
        config.dhcp.leases_dir = directory.path().join("leases");
        if router_uplink {
            config.router.enabled = true;
            config.router.uplink = Some(UplinkConfig {
                interface: "wan0".to_string(),
                mode: UplinkMode::Dhcp,
            });
            config.network.interfaces.insert(
                "lan0".to_string(),
                InterfaceConfig {
                    role: InterfaceRole::Output,
                    managed: true,
                    ipv4: Some("10.9.0.1/24".parse().expect("output subnet")),
                    dhcp: None,
                    dhcp_client: None,
                    wifi: None,
                    wifi_client: None,
                },
            );
        }
        config.network.interfaces.insert(
            "wan0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Input,
                managed: enabled,
                ipv4: None,
                dhcp: None,
                dhcp_client: enabled.then(DhcpClientInterfaceConfig::default),
                wifi: None,
                wifi_client: Some(WifiClientConfig {
                    ssid: "upstream".to_string(),
                    country_code: Some("PL".to_string()),
                    security: WifiClientSecurity::Open,
                    passphrase_file: None,
                }),
            },
        );
        let overrides = RuntimeOverrideManager::load(directory.path(), &config)
            .await
            .expect("overrides");
        let network: Arc<dyn NetworkProvider> = Arc::new(FakeNetwork {
            addresses: Vec::new(),
        });
        let dhcp = DhcpSupervisor::start(&config, &overrides.snapshot().await)
            .await
            .expect("server supervisor");
        let supervisor = DhcpClientSupervisor::start(&config, network.clone())
            .await
            .expect("client supervisor");
        let service = ControlService::new(config, network, dhcp, overrides.clone())
            .with_dhcp_client_supervisor(supervisor.clone());
        DhcpClientControlFixture {
            service,
            overrides,
            supervisor,
            directory,
        }
    }

    #[tokio::test]
    async fn dhcp_client_control_list_get_and_typed_missing_states() {
        let fixture = dhcp_client_control_fixture(true).await;
        assert!(matches!(
            fixture.service.dispatch(Request::DhcpClientStatus).await,
            Response::DhcpClientStatus { interfaces } if interfaces.len() == 1 && interfaces[0].interface == "wan0"
        ));
        assert!(matches!(
            fixture.service.dispatch(Request::GetDhcpClient { interface: "wan0".into() }).await,
            Response::DhcpClientInterface { status } if status.interface == "wan0"
        ));
        assert!(matches!(
            fixture
                .service
                .dispatch(Request::GetDhcpClient {
                    interface: "missing0".into()
                })
                .await,
            Response::DhcpClientError {
                detail: DhcpClientErrorDetail::InterfaceNotFound
            }
        ));
        let disabled = dhcp_client_control_fixture(false).await;
        assert!(matches!(
            disabled
                .service
                .dispatch(Request::GetDhcpClient {
                    interface: "wan0".into()
                })
                .await,
            Response::DhcpClientError {
                detail: DhcpClientErrorDetail::Disabled
            }
        ));
    }

    #[tokio::test]
    async fn dhcp_client_control_configure_preserves_wifi_client() {
        let fixture = dhcp_client_control_fixture(false).await;
        let response = fixture
            .service
            .dispatch(Request::ConfigureDhcpClient {
                interface: "wan0".into(),
                config: DhcpClientConfigRequest {
                    route_metric: 77,
                    ..Default::default()
                },
            })
            .await;
        assert!(
            matches!(response, Response::DhcpClientInterface { .. }),
            "{response:?}"
        );
        let persisted = fixture
            .overrides
            .effective_interface("wan0")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(persisted.dhcp_client.unwrap().route_metric, 77);
        assert_eq!(persisted.wifi_client.unwrap().ssid, "upstream");
        assert!(persisted.managed);
        assert_eq!(persisted.role, InterfaceRole::Input);
    }

    #[tokio::test]
    async fn dhcp_client_control_configure_compensates_runtime_when_persistence_fails() {
        let fixture = dhcp_client_control_fixture(false).await;
        std::fs::create_dir(fixture.directory.path().join("runtime-overrides.json"))
            .expect("block override file rename");
        let response = fixture
            .service
            .dispatch(Request::ConfigureDhcpClient {
                interface: "wan0".into(),
                config: DhcpClientConfigRequest::default(),
            })
            .await;
        assert!(
            matches!(
                response,
                Response::DhcpClientError {
                    detail: DhcpClientErrorDetail::PersistenceFailure { .. }
                }
            ),
            "{response:?}"
        );
        assert!(fixture.supervisor.spec("wan0").await.is_none());
    }

    #[tokio::test]
    async fn dhcp_client_control_delete_cleans_runtime_and_persists_disabled_intent() {
        let fixture = dhcp_client_control_fixture(true).await;
        let response = fixture
            .service
            .dispatch(Request::DisableDhcpClient {
                interface: "wan0".into(),
            })
            .await;
        assert!(
            matches!(response, Response::DhcpClientDisabled { interface } if interface == "wan0")
        );
        assert!(fixture.supervisor.spec("wan0").await.is_none());
        let persisted = fixture
            .overrides
            .effective_interface("wan0")
            .await
            .unwrap()
            .unwrap();
        assert!(
            !persisted.managed,
            "disabled client returns the input to external-L3 semantics"
        );
        assert!(!persisted.dhcp_client.unwrap().enabled);
        assert_eq!(persisted.wifi_client.unwrap().ssid, "upstream");
    }

    #[tokio::test]
    async fn dhcp_client_control_delete_refuses_router_held_uplink_without_touching_runtime() {
        let fixture = dhcp_client_control_fixture_with_router(true, true).await;
        let response = fixture
            .service
            .dispatch(Request::DisableDhcpClient {
                interface: "wan0".into(),
            })
            .await;
        assert!(
            matches!(
                response,
                Response::DhcpClientError {
                    detail: DhcpClientErrorDetail::InvalidConfig { .. }
                }
            ),
            "{response:?}"
        );

        assert!(fixture.supervisor.spec("wan0").await.is_some());
        let persisted = fixture
            .overrides
            .effective_interface("wan0")
            .await
            .unwrap()
            .unwrap();
        assert!(persisted.managed);
        assert!(persisted.dhcp_client.unwrap().enabled);
    }

    #[tokio::test]
    async fn dhcp_client_control_renew_and_release_dispatch_keep_intent() {
        let fixture = dhcp_client_control_fixture(true).await;
        for request in [
            Request::RenewDhcpClient {
                interface: "wan0".into(),
            },
            Request::ReleaseDhcpClient {
                interface: "wan0".into(),
            },
        ] {
            let response = fixture.service.dispatch(request).await;
            assert!(
                matches!(response, Response::DhcpClientInterface { ref status } if status.interface == "wan0"),
                "{response:?}"
            );
            assert!(fixture.supervisor.spec("wan0").await.is_some());
        }
    }

    use crate::api::model::{ProvisioningOutputRequest, ProvisioningUplinkRequest};
    use crate::core::router::{RouterManager, WifiPlan, WifiSnapshot};
    use crate::core::router_provisioning::ProvisioningDownstreamOverrides;

    #[derive(Default)]
    struct FakeProvisioningSubsystems {
        applied_uplink_wifi: StdMutex<Vec<WifiClientSpec>>,
        applied_output_wifi: StdMutex<Vec<WifiApSpec>>,
        uplink_dhcp_unready: StdMutex<bool>,
        unhealthy_dataplane: StdMutex<bool>,
    }

    #[async_trait]
    impl RouterSubsystems for FakeProvisioningSubsystems {
        async fn plan_interfaces(&self, _: &RouterDesired) -> Result<Vec<InterfaceChangePlan>> {
            Ok(Vec::new())
        }
        async fn plan_uplink_wifi(
            &self,
            desired: &RouterDesired,
        ) -> Result<Vec<WifiPlan<WifiClientSpec>>> {
            Ok(desired
                .uplink_wifi
                .iter()
                .map(|spec| WifiPlan::Start {
                    desired: spec.clone(),
                })
                .collect())
        }
        async fn plan_output_wifi(
            &self,
            desired: &RouterDesired,
        ) -> Result<Vec<WifiPlan<WifiApSpec>>> {
            Ok(desired
                .output_wifi
                .iter()
                .map(|spec| WifiPlan::Start {
                    desired: spec.clone(),
                })
                .collect())
        }
        async fn plan_routes(&self, _: &RouterDesired) -> Result<RoutePlan> {
            Ok(RoutePlan {
                add: Vec::new(),
                delete: Vec::new(),
            })
        }
        async fn plan_dhcp(&self, _: &RouterDesired) -> Result<Vec<DhcpPlan>> {
            Ok(Vec::new())
        }
        async fn plan_dataplane(&self, desired: &RouterDesired) -> Result<RouterDataplanePlan> {
            Ok(RouterDataplanePlan {
                snapshot: fake_dataplane_snapshot(),
                target: desired.dataplane.clone(),
                requires_apply: true,
            })
        }
        async fn snapshot_interfaces(&self) -> Result<Vec<InterfaceSnapshot>> {
            Ok(Vec::new())
        }
        async fn snapshot_uplink_wifi(&self) -> Result<Vec<WifiSnapshot<WifiClientSpec>>> {
            Ok(Vec::new())
        }
        async fn snapshot_output_wifi(&self) -> Result<Vec<WifiSnapshot<WifiApSpec>>> {
            Ok(Vec::new())
        }
        async fn snapshot_routes(&self) -> Result<RouteSnapshot> {
            Ok(RouteSnapshot::empty())
        }
        async fn snapshot_dhcp(&self) -> Result<Vec<DhcpServiceSpec>> {
            Ok(Vec::new())
        }
        async fn snapshot_dataplane(&self) -> Result<RouterDataplaneSnapshot> {
            Ok(fake_dataplane_snapshot())
        }
        async fn apply_interfaces(&self, _: &[InterfaceChangePlan]) -> Result<()> {
            Ok(())
        }
        async fn apply_uplink_wifi(&self, plan: &[WifiPlan<WifiClientSpec>]) -> Result<()> {
            for step in plan {
                if let WifiPlan::Start { desired } = step {
                    self.applied_uplink_wifi
                        .lock()
                        .unwrap()
                        .push(desired.clone());
                }
            }
            Ok(())
        }
        async fn apply_output_wifi(&self, plan: &[WifiPlan<WifiApSpec>]) -> Result<()> {
            for step in plan {
                if let WifiPlan::Start { desired } = step {
                    self.applied_output_wifi
                        .lock()
                        .unwrap()
                        .push(desired.clone());
                }
            }
            Ok(())
        }
        async fn apply_routes(&self, _: &RoutePlan) -> Result<()> {
            Ok(())
        }
        async fn apply_dhcp(&self, _: &[DhcpPlan]) -> Result<()> {
            Ok(())
        }
        async fn apply_dataplane(&self, _: &RouterDataplanePlan) -> Result<()> {
            Ok(())
        }
        async fn rollback_interfaces(&self, _: &[InterfaceSnapshot]) -> Result<()> {
            Ok(())
        }
        async fn rollback_uplink_wifi(&self, _: &[WifiSnapshot<WifiClientSpec>]) -> Result<()> {
            Ok(())
        }
        async fn rollback_output_wifi(&self, _: &[WifiSnapshot<WifiApSpec>]) -> Result<()> {
            Ok(())
        }
        async fn rollback_routes(&self, _: &RouteSnapshot) -> Result<()> {
            Ok(())
        }
        async fn rollback_dhcp(&self, _: &[DhcpServiceSpec]) -> Result<()> {
            Ok(())
        }
        async fn rollback_dataplane(&self, _: &RouterDataplaneSnapshot) -> Result<()> {
            Ok(())
        }
        async fn health_interfaces(&self, _: &RouterDesired) -> Result<()> {
            Ok(())
        }
        async fn health_uplink_wifi(&self, _: &RouterDesired) -> Result<()> {
            Ok(())
        }
        async fn health_output_wifi(&self, _: &RouterDesired) -> Result<()> {
            Ok(())
        }
        async fn health_routes(&self, _: &RouterDesired) -> Result<()> {
            Ok(())
        }
        async fn health_dhcp(&self, _: &RouterDesired) -> Result<()> {
            Ok(())
        }
        async fn health_uplink_dhcp(
            &self,
            _: &RouterDesired,
        ) -> Option<crate::core::router::RouterDhcpHealthReason> {
            self.uplink_dhcp_unready.lock().unwrap().then(|| {
                crate::core::router::RouterDhcpHealthReason::Waiting {
                    interface: "wlan-up".to_string(),
                }
            })
        }
        async fn health_dataplane(&self, _: &RouterDesired) -> Result<()> {
            if *self.unhealthy_dataplane.lock().unwrap() {
                anyhow::bail!("injected dataplane health failure");
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct ProvisioningNetwork {
        interfaces: Vec<NetworkInterface>,
        addresses: StdHashMap<String, Vec<Ipv4AddressInfo>>,
    }

    impl ProvisioningNetwork {
        fn with_wireless(names: &[&str]) -> Self {
            Self {
                interfaces: names
                    .iter()
                    .enumerate()
                    .map(|(index, name)| NetworkInterface {
                        index: index as u32 + 1,
                        name: (*name).to_string(),
                        is_up: true,
                        rx_bytes: 0,
                        tx_bytes: 0,
                        is_wireless: true,
                    })
                    .collect(),
                addresses: StdHashMap::new(),
            }
        }

        fn with_address(mut self, interface: &str, address: [u8; 4], prefix_len: u8) -> Self {
            self.interfaces.push(NetworkInterface {
                index: self.interfaces.len() as u32 + 1,
                name: interface.to_string(),
                is_up: true,
                rx_bytes: 0,
                tx_bytes: 0,
                is_wireless: false,
            });
            self.addresses.insert(
                interface.to_string(),
                vec![Ipv4AddressInfo {
                    interface_index: self.interfaces.len() as u32,
                    address: Ipv4Addr::from(address),
                    prefix_len,
                }],
            );
            self
        }
    }

    #[async_trait]
    impl NetworkProvider for ProvisioningNetwork {
        async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
            Ok(self.interfaces.clone())
        }

        async fn list_ipv4_addresses(&self, interface: &str) -> Result<Vec<Ipv4AddressInfo>> {
            Ok(self.addresses.get(interface).cloned().unwrap_or_default())
        }

        async fn set_link_up(&self, _name: &str) -> Result<()> {
            Ok(())
        }

        async fn set_link_down(&self, _name: &str) -> Result<()> {
            Ok(())
        }

        async fn add_ipv4_address(&self, _: &str, _: Ipv4Addr, _: u8) -> Result<()> {
            Ok(())
        }

        async fn delete_ipv4_address(&self, _: &str, _: Ipv4Addr, _: u8) -> Result<()> {
            Ok(())
        }
    }

    struct ProvisioningFixture {
        service: ControlService,
        overrides: RuntimeOverrideManager,
        subsystems: Arc<FakeProvisioningSubsystems>,
        wifi: WifiSupervisor,
        wifi_client: ClientSupervisor,
        _directory: tempfile::TempDir,
    }

    fn provisioning_base_config(directory: &std::path::Path) -> AppConfig {
        let mut config = AppConfig::default();
        config.runtime.state_dir = directory.to_path_buf();
        config.wifi = WifiConfig {
            enabled: true,
            hostapd_binary: PathBuf::from("/usr/sbin/hostapd"),
            runtime_dir: directory.join("hostapd"),
            restart_backoff_seconds: 1,
        };
        config.wifi_client = WifiClientGlobalConfig {
            enabled: true,
            wpa_supplicant_binary: PathBuf::from("/usr/sbin/wpa_supplicant"),
            runtime_dir: directory.join("wpa_supplicant"),
            restart_backoff_seconds: 1,
        };
        config
    }

    async fn provisioning_fixture_with(
        subsystems: Arc<FakeProvisioningSubsystems>,
        config: AppConfig,
        network: ProvisioningNetwork,
        readiness_timeout: Duration,
    ) -> ProvisioningFixture {
        let directory = tempdir().expect("tempdir");
        let mut config = config;
        config.runtime.state_dir = directory.path().to_path_buf();
        config.wifi.runtime_dir = directory.path().join("hostapd");
        config.wifi_client.runtime_dir = directory.path().join("wpa_supplicant");
        config.validate().expect("valid provisioning base config");

        let overrides = RuntimeOverrideManager::load(directory.path(), &config)
            .await
            .expect("overrides");
        let dhcp = DhcpSupervisor::start(&config, &overrides.snapshot().await)
            .await
            .expect("dhcp supervisor");

        let wifi = WifiSupervisor::start(&config, &overrides.snapshot().await)
            .await
            .expect("wifi supervisor");
        let wifi_client = ClientSupervisor::start(&config, &overrides.snapshot().await)
            .await
            .expect("wifi client supervisor");
        let manager = RouterManager::new(subsystems.clone())
            .with_dhcp_readiness_timing(readiness_timeout, Duration::from_millis(10));
        let coordinator =
            RouterTransactionCoordinator::new(manager, overrides.clone(), Duration::from_secs(30));
        let service = ControlService::new(
            config,
            Arc::new(network) as Arc<dyn NetworkProvider>,
            dhcp,
            overrides.clone(),
        )
        .with_router_coordinator(coordinator)
        .with_wifi_supervisor(wifi.clone())
        .with_wifi_client_supervisor(wifi_client.clone());

        ProvisioningFixture {
            service,
            overrides,
            subsystems,
            wifi,
            wifi_client,
            _directory: directory,
        }
    }

    async fn provisioning_fixture() -> ProvisioningFixture {
        let directory = tempdir().expect("tempdir");
        provisioning_fixture_with(
            Arc::new(FakeProvisioningSubsystems::default()),
            provisioning_base_config(directory.path()),
            ProvisioningNetwork::with_wireless(&["wlan-up", "wlan-out"]),
            Duration::from_millis(200),
        )
        .await
    }

    fn provisioning_request() -> RouterProvisioningRequest {
        RouterProvisioningRequest {
            uplink: ProvisioningUplinkRequest {
                interface: "wlan-up".to_string(),
                ssid: "upstream".to_string(),
                country_code: Some("PL".to_string()),
                security: WifiClientSecurity::Wpa2,
            },
            output: ProvisioningOutputRequest {
                interface: "wlan-out".to_string(),
                ssid: "traffic-masq".to_string(),
                country_code: Some("PL".to_string()),
                band: WifiBand::Ghz2,
                channel: 6,
                channel_width: WifiChannelWidth::Ht20,
                security: WifiSecurity::Wpa2,
                hidden: false,
                client_isolation: false,
                max_stations: 32,
            },
            downstream: ProvisioningDownstreamOverrides::default(),
            allow_management_change: false,
        }
    }

    fn preview_request(provisioning: RouterProvisioningRequest) -> Request {
        Request::RouterProvisioningPreview {
            request: RouterProvisioningPreviewRequest {
                provisioning,
                uplink_secret_pending: true,
                output_secret_pending: true,
            },
        }
    }

    fn apply_request(provisioning: RouterProvisioningRequest) -> Request {
        Request::RouterProvisioningApply {
            request: RouterProvisioningApplyRequest {
                provisioning,
                uplink_passphrase: Some("upstream-secret".to_string()),
                output_passphrase: Some("downstream-secret".to_string()),
            },
        }
    }

    fn preview_of(response: Response) -> RouterProvisioningPreviewView {
        match response {
            Response::RouterProvisioningPreview { preview } => preview,
            other => panic!("expected a preview, got {other:?}"),
        }
    }

    fn provisioning_detail(response: Response) -> RouterProvisioningErrorDetail {
        match response {
            Response::RouterProvisioningError { detail } => detail,
            other => panic!("expected a provisioning error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn provisioning_preview_derives_complete_downstream_defaults() {
        let fixture = provisioning_fixture().await;

        let preview = preview_of(
            fixture
                .service
                .dispatch(preview_request(provisioning_request()))
                .await,
        );

        assert_eq!(
            preview.downstream.interface_ipv4,
            "10.77.0.1/24".parse().unwrap()
        );
        assert_eq!(preview.downstream.subnet, "10.77.0.0/24".parse().unwrap());
        assert_eq!(preview.downstream.router, Ipv4Addr::new(10, 77, 0, 1));
        assert_eq!(preview.downstream.pool_start, Ipv4Addr::new(10, 77, 0, 100));
        assert_eq!(preview.downstream.pool_end, Ipv4Addr::new(10, 77, 0, 200));
        assert_eq!(preview.downstream.lease_seconds, DEFAULT_DHCP_LEASE_SECONDS);
        assert!(preview.downstream.dns_servers.is_empty());
        assert_eq!(preview.uplink.mode, UplinkMode::Dhcp);
        assert!(preview
            .warnings
            .contains(&ProvisioningWarning::NoDownstreamDns));
        assert!(preview
            .warnings
            .contains(&ProvisioningWarning::PendingSecret {
                interface: "wlan-out".to_string()
            }));

        assert_eq!(fixture.overrides.committed_revision().await, 0);
    }

    #[tokio::test]
    async fn provisioning_preview_carries_no_secret_or_secret_path() {
        let fixture = provisioning_fixture().await;
        fixture
            .wifi
            .set_passphrase(
                "wlan-out",
                &WifiPassphrase::new("downstream-secret").expect("valid passphrase"),
            )
            .await
            .expect("stage AP secret");

        let response = fixture
            .service
            .dispatch(Request::RouterProvisioningPreview {
                request: RouterProvisioningPreviewRequest {
                    provisioning: provisioning_request(),
                    uplink_secret_pending: true,
                    output_secret_pending: false,
                },
            })
            .await;
        let encoded = serde_json::to_string(&response).expect("serializable response");

        assert!(!encoded.contains("downstream-secret"), "{encoded}");
        assert!(!encoded.contains("passphrase_file"), "{encoded}");
        assert!(!encoded.contains("psk"), "{encoded}");
        let preview = preview_of(response);

        assert!(preview.output.secret_available);
        assert!(preview.uplink.secret_available);
    }

    #[tokio::test]
    async fn provisioning_preview_relocates_a_conflicting_default_subnet() {
        let directory = tempdir().expect("tempdir");
        let fixture = provisioning_fixture_with(
            Arc::new(FakeProvisioningSubsystems::default()),
            provisioning_base_config(directory.path()),
            ProvisioningNetwork::with_wireless(&["wlan-up", "wlan-out"]).with_address(
                "eth0",
                [10, 77, 0, 5],
                24,
            ),
            Duration::from_millis(200),
        )
        .await;

        let preview = preview_of(
            fixture
                .service
                .dispatch(preview_request(provisioning_request()))
                .await,
        );

        assert_eq!(
            preview.downstream.interface_ipv4,
            "10.77.1.1/24".parse().unwrap()
        );
        assert!(preview
            .warnings
            .contains(&ProvisioningWarning::DownstreamSubnetRelocated {
                preferred: "10.77.0.0/24".parse().unwrap(),
                selected: "10.77.1.0/24".parse().unwrap(),
            }));
    }

    #[tokio::test]
    async fn provisioning_rejects_a_management_interface_without_confirmation() {
        let directory = tempdir().expect("tempdir");
        let mut config = provisioning_base_config(directory.path());
        config.network.interfaces.insert(
            "wlan-up".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Management,
                managed: false,
                ipv4: Some("192.168.1.20/24".parse().unwrap()),
                dhcp: None,
                dhcp_client: None,
                wifi: None,
                wifi_client: None,
            },
        );
        let fixture = provisioning_fixture_with(
            Arc::new(FakeProvisioningSubsystems::default()),
            config,
            ProvisioningNetwork::with_wireless(&["wlan-up", "wlan-out"]),
            Duration::from_millis(200),
        )
        .await;

        assert_eq!(
            provisioning_detail(
                fixture
                    .service
                    .dispatch(apply_request(provisioning_request()))
                    .await
            ),
            RouterProvisioningErrorDetail::ManagementConfirmationRequired {
                interface: "wlan-up".to_string()
            }
        );
        assert_eq!(fixture.overrides.committed_revision().await, 0);
    }

    #[tokio::test]
    async fn provisioning_rejects_a_protected_network_with_no_available_secret() {
        let fixture = provisioning_fixture().await;

        let response = fixture
            .service
            .dispatch(Request::RouterProvisioningApply {
                request: RouterProvisioningApplyRequest {
                    provisioning: provisioning_request(),
                    uplink_passphrase: Some("upstream-secret".to_string()),
                    output_passphrase: None,
                },
            })
            .await;

        assert_eq!(
            provisioning_detail(response),
            RouterProvisioningErrorDetail::OutputSecretMissing {
                interface: "wlan-out".to_string()
            }
        );

        assert!(fixture
            .wifi_client
            .stored_passphrase("wlan-up")
            .await
            .expect("store readable")
            .is_none());
        assert_eq!(fixture.overrides.committed_revision().await, 0);
    }

    #[tokio::test]
    async fn provisioning_apply_stages_secrets_and_opens_one_coordinator_transaction() {
        let fixture = provisioning_fixture().await;

        let (token, preview) = match fixture
            .service
            .dispatch(apply_request(provisioning_request()))
            .await
        {
            Response::RouterProvisioningApplied { token, preview } => (token, preview),
            other => panic!("expected an applied transaction, got {other:?}"),
        };
        assert!(!token.is_empty());
        assert!(preview.output.secret_available);
        assert!(preview.uplink.secret_available);
        assert!(!preview
            .warnings
            .iter()
            .any(|warning| matches!(warning, ProvisioningWarning::PendingSecret { .. })));

        assert!(fixture
            .wifi
            .stored_passphrase("wlan-out")
            .await
            .expect("store readable")
            .is_some());
        assert!(fixture
            .wifi_client
            .stored_passphrase("wlan-up")
            .await
            .expect("store readable")
            .is_some());
        assert_eq!(
            fixture.subsystems.applied_output_wifi.lock().unwrap().len(),
            1
        );
        assert_eq!(
            fixture.subsystems.applied_uplink_wifi.lock().unwrap().len(),
            1
        );

        match fixture
            .service
            .dispatch(Request::RouterProvisioningStatus)
            .await
        {
            Response::RouterProvisioningStatus { status } => {
                assert_eq!(status.stage, ProvisioningStage::AwaitingConfirmation);
                assert_eq!(status.coordinator, CoordinatorStatus::Pending);
            }
            other => panic!("expected provisioning status, got {other:?}"),
        }

        assert!(matches!(
            fixture.service.dispatch(Request::RouterCommit).await,
            Response::RouterCommitted { revision: 1 }
        ));

        match fixture
            .service
            .dispatch(Request::RouterProvisioningStatus)
            .await
        {
            Response::RouterProvisioningStatus { status } => {
                assert_eq!(status.stage, ProvisioningStage::Ready);
                assert!(status.enabled);
                assert!(status.ready);
                assert!(status.failures.is_empty());
            }
            other => panic!("expected provisioning status, got {other:?}"),
        }

        let output = fixture
            .overrides
            .effective_interface("wlan-out")
            .await
            .expect("effective interface")
            .expect("provisioned output interface");
        let dhcp = output.dhcp.expect("derived downstream DHCP service");
        assert_eq!(output.ipv4, Some("10.77.0.1/24".parse().unwrap()));
        assert_eq!(dhcp.pool_start, Ipv4Addr::new(10, 77, 0, 100));
        assert_eq!(dhcp.pool_end, Ipv4Addr::new(10, 77, 0, 200));
        assert_eq!(dhcp.lease_seconds, Some(DEFAULT_DHCP_LEASE_SECONDS));
    }

    #[tokio::test]
    async fn provisioning_apply_is_idempotent_about_the_derived_subnet() {
        let fixture = provisioning_fixture().await;
        assert!(matches!(
            fixture
                .service
                .dispatch(apply_request(provisioning_request()))
                .await,
            Response::RouterProvisioningApplied { .. }
        ));
        assert!(matches!(
            fixture.service.dispatch(Request::RouterCommit).await,
            Response::RouterCommitted { .. }
        ));

        let preview = preview_of(
            fixture
                .service
                .dispatch(preview_request(provisioning_request()))
                .await,
        );
        assert_eq!(
            preview.downstream.interface_ipv4,
            "10.77.0.1/24".parse().unwrap()
        );
    }

    #[tokio::test]
    async fn provisioning_apply_refuses_a_second_concurrent_transaction() {
        let fixture = provisioning_fixture().await;
        assert!(matches!(
            fixture
                .service
                .dispatch(apply_request(provisioning_request()))
                .await,
            Response::RouterProvisioningApplied { .. }
        ));

        assert_eq!(
            provisioning_detail(
                fixture
                    .service
                    .dispatch(apply_request(provisioning_request()))
                    .await
            ),
            RouterProvisioningErrorDetail::TransactionPending
        );
    }

    #[tokio::test]
    async fn provisioning_apply_reports_a_readiness_timeout_and_restores_prior_secrets() {
        let directory = tempdir().expect("tempdir");
        let subsystems = Arc::new(FakeProvisioningSubsystems::default());
        *subsystems.uplink_dhcp_unready.lock().unwrap() = true;
        let fixture = provisioning_fixture_with(
            subsystems,
            provisioning_base_config(directory.path()),
            ProvisioningNetwork::with_wireless(&["wlan-up", "wlan-out"]),
            Duration::from_millis(50),
        )
        .await;

        let detail = provisioning_detail(
            fixture
                .service
                .dispatch(apply_request(provisioning_request()))
                .await,
        );
        assert!(
            matches!(
                detail,
                RouterProvisioningErrorDetail::ReadinessTimeout { .. }
            ),
            "{detail:?}"
        );

        assert!(fixture
            .wifi
            .stored_passphrase("wlan-out")
            .await
            .expect("store readable")
            .is_none());
        assert!(fixture
            .wifi_client
            .stored_passphrase("wlan-up")
            .await
            .expect("store readable")
            .is_none());
        assert_eq!(fixture.overrides.committed_revision().await, 0);
    }

    #[tokio::test]
    async fn provisioning_status_reports_a_degraded_committed_topology() {
        let fixture = provisioning_fixture().await;
        assert!(matches!(
            fixture
                .service
                .dispatch(apply_request(provisioning_request()))
                .await,
            Response::RouterProvisioningApplied { .. }
        ));
        assert!(matches!(
            fixture.service.dispatch(Request::RouterCommit).await,
            Response::RouterCommitted { .. }
        ));
        *fixture.subsystems.unhealthy_dataplane.lock().unwrap() = true;

        match fixture
            .service
            .dispatch(Request::RouterProvisioningStatus)
            .await
        {
            Response::RouterProvisioningStatus { status } => {
                assert_eq!(status.stage, ProvisioningStage::Degraded);
                assert!(status.enabled);
                assert!(!status.ready);
                assert!(status.readiness.dataplane.is_some());
                assert!(status.readiness.interfaces.is_none());
            }
            other => panic!("expected provisioning status, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn provisioning_requests_are_rejected_when_the_router_is_disabled() {
        let directory = tempdir().expect("tempdir");
        let config = provisioning_base_config(directory.path());
        let overrides = RuntimeOverrideManager::load(directory.path(), &config)
            .await
            .expect("overrides");
        let dhcp = DhcpSupervisor::start(&config, &overrides.snapshot().await)
            .await
            .expect("dhcp supervisor");
        let service = ControlService::new(
            config,
            Arc::new(ProvisioningNetwork::with_wireless(&["wlan-up", "wlan-out"]))
                as Arc<dyn NetworkProvider>,
            dhcp,
            overrides,
        );

        for request in [
            preview_request(provisioning_request()),
            apply_request(provisioning_request()),
            Request::RouterProvisioningStatus,
        ] {
            assert_eq!(
                provisioning_detail(service.dispatch(request).await),
                RouterProvisioningErrorDetail::RouterDisabled
            );
        }
    }

    #[tokio::test]
    async fn provisioning_rejects_one_interface_in_both_roles() {
        let fixture = provisioning_fixture().await;
        let mut request = provisioning_request();
        request.output.interface = request.uplink.interface.clone();

        assert_eq!(
            provisioning_detail(fixture.service.dispatch(preview_request(request)).await),
            RouterProvisioningErrorDetail::InterfaceReused {
                interface: "wlan-up".to_string()
            }
        );
    }

    #[tokio::test]
    async fn provisioning_rejects_an_interface_that_does_not_exist() {
        let fixture = provisioning_fixture().await;
        let mut request = provisioning_request();
        request.output.interface = "wlan-absent".to_string();

        assert_eq!(
            provisioning_detail(fixture.service.dispatch(preview_request(request)).await),
            RouterProvisioningErrorDetail::InterfaceNotFound {
                interface: "wlan-absent".to_string()
            }
        );
    }

    #[tokio::test]
    async fn provisioning_rejects_an_advanced_pool_override_without_its_network() {
        let fixture = provisioning_fixture().await;
        let mut request = provisioning_request();
        request.downstream.pool_start = Some(Ipv4Addr::new(10, 77, 0, 50));
        request.downstream.pool_end = Some(Ipv4Addr::new(10, 77, 0, 60));

        assert!(
            matches!(
                provisioning_detail(fixture.service.dispatch(preview_request(request)).await),
                RouterProvisioningErrorDetail::InvalidPool { .. }
            ),
            "an explicit pool without an explicit network must be typed, not accepted"
        );
    }

    #[tokio::test]
    async fn provisioning_applies_advanced_downstream_overrides_verbatim() {
        let fixture = provisioning_fixture().await;
        let mut request = provisioning_request();
        request.downstream = ProvisioningDownstreamOverrides {
            interface_ipv4: Some("172.20.5.1/24".parse().unwrap()),
            pool_start: Some(Ipv4Addr::new(172, 20, 5, 20)),
            pool_end: Some(Ipv4Addr::new(172, 20, 5, 40)),
            dns_servers: vec![Ipv4Addr::new(9, 9, 9, 9)],
            lease_seconds: Some(600),
        };

        let preview = preview_of(
            fixture
                .service
                .dispatch(preview_request(request.clone()))
                .await,
        );
        assert_eq!(
            preview.downstream.interface_ipv4,
            "172.20.5.1/24".parse().unwrap()
        );
        assert_eq!(preview.downstream.pool_start, Ipv4Addr::new(172, 20, 5, 20));
        assert_eq!(preview.downstream.pool_end, Ipv4Addr::new(172, 20, 5, 40));
        assert_eq!(
            preview.downstream.dns_servers,
            vec![Ipv4Addr::new(9, 9, 9, 9)]
        );
        assert_eq!(preview.downstream.lease_seconds, 600);
        assert!(!preview
            .warnings
            .contains(&ProvisioningWarning::NoDownstreamDns));

        assert!(matches!(
            fixture.service.dispatch(apply_request(request)).await,
            Response::RouterProvisioningApplied { .. }
        ));
        assert!(matches!(
            fixture.service.dispatch(Request::RouterCommit).await,
            Response::RouterCommitted { .. }
        ));
        let output = fixture
            .overrides
            .effective_interface("wlan-out")
            .await
            .expect("effective interface")
            .expect("provisioned output interface");
        let dhcp = output.dhcp.expect("derived downstream DHCP service");
        assert_eq!(dhcp.pool_start, Ipv4Addr::new(172, 20, 5, 20));
        assert_eq!(dhcp.dns_servers, vec![Ipv4Addr::new(9, 9, 9, 9)]);
        assert_eq!(dhcp.lease_seconds, Some(600));
    }

    #[tokio::test]
    async fn provisioning_rejects_an_explicit_downstream_conflict() {
        let directory = tempdir().expect("tempdir");
        let fixture = provisioning_fixture_with(
            Arc::new(FakeProvisioningSubsystems::default()),
            provisioning_base_config(directory.path()),
            ProvisioningNetwork::with_wireless(&["wlan-up", "wlan-out"]).with_address(
                "eth0",
                [192, 168, 1, 20],
                24,
            ),
            Duration::from_millis(200),
        )
        .await;
        let mut request = provisioning_request();
        request.downstream.interface_ipv4 = Some("192.168.1.1/24".parse().unwrap());

        let detail = provisioning_detail(fixture.service.dispatch(preview_request(request)).await);
        match detail {
            RouterProvisioningErrorDetail::SubnetConflict {
                requested,
                conflicting,
                ..
            } => {
                assert_eq!(requested, "192.168.1.0/24".parse().unwrap());
                assert_eq!(conflicting, "192.168.1.0/24".parse().unwrap());
            }
            other => panic!("expected a typed subnet conflict, got {other:?}"),
        }
    }

    #[test]
    fn provisioning_apply_request_debug_redacts_key_material() {
        let formatted = format!(
            "{:?}",
            Request::RouterProvisioningApply {
                request: RouterProvisioningApplyRequest {
                    provisioning: provisioning_request(),
                    uplink_passphrase: Some("upstream-secret".to_string()),
                    output_passphrase: None,
                },
            }
        );

        assert!(!formatted.contains("upstream-secret"), "{formatted}");
        assert!(formatted.contains("<redacted>"), "{formatted}");
        assert!(formatted.contains("<absent>"), "{formatted}");
    }
}
