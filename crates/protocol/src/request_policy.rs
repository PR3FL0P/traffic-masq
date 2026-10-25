//! Admission and authorization policy shared by REST, control RPC and clients.
use crate::Request;

/// Execution discipline; interface transactions must leave convergence workers free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationKind {
    ReadOnly,
    /// Persisted settings share the committed document and serialize with runtime writers.
    Settings,
    Direct,
    InterfaceTransaction,
    RouterTransaction,
}

#[derive(Debug, Clone, Copy)]
pub struct RequestPolicy<'a> {
    pub administrator: bool,
    pub mutation: MutationKind,
    pub recovery_interface: Option<&'a str>,
    pub provisioning_recovery: bool,
    /// Reject overlapping direct/convenience writes while an interface change
    /// is pending. Scoped interface owners and router coordinator requests
    /// enforce their own transaction ownership instead.
    pub requires_idle_interfaces: bool,
    /// Preserve the longer deadline for writes, scans and dry-run plans.
    pub long_running: bool,
}

impl RequestPolicy<'_> {
    pub fn network_mutation(self) -> bool {
        matches!(
            self.mutation,
            MutationKind::Direct
                | MutationKind::InterfaceTransaction
                | MutationKind::RouterTransaction
        )
    }

    pub fn direct_network_mutation(self) -> bool {
        matches!(
            self.mutation,
            MutationKind::Direct | MutationKind::InterfaceTransaction
        )
    }

    /// Retain admission across convergence waits.
    pub fn needs_admission(self) -> bool {
        self.mutation != MutationKind::ReadOnly
    }

    /// Interface transactions leave execution free for their convergence workers.
    pub fn needs_execution(self) -> bool {
        matches!(
            self.mutation,
            MutationKind::Settings | MutationKind::Direct | MutationKind::RouterTransaction
        )
    }
}

impl<Interface, Proposal> Request<Interface, Proposal> {
    /// Exhaustive by design: adding a command requires an explicit policy.
    pub fn policy(&self) -> RequestPolicy<'_> {
        use MutationKind::*;
        use Request::*;
        match self {
            Ping
            | GetApiHttpsConfig
            | GetSecurityConfig
            | ListInterfaces
            | ListInterfaceInventory
            | ListWifiInventory
            | DhcpStatus
            | DhcpClientStatus
            | PendingNetworkChanges
            | RouterStatus
            | RouterPendingTransaction
            | ListRouteInventory { .. }
            | ListRoutes { .. }
            | GetRouterConfig
            | RouterProvisioningStatus
            | VpnListProfiles
            | GetVpnConfig
            | VpnStatus
            | VpnPolicyStatus
            | WifiStatus
            | WifiClientStatus
            | ListWifiApProfiles
            | ListWifiClientProfiles
            | GetWifiClientProfile { .. } => RequestPolicy {
                administrator: false,
                mutation: ReadOnly,
                recovery_interface: None,
                provisioning_recovery: false,
                requires_idle_interfaces: false,
                long_running: false,
            },
            DaemonLogs { .. } | VpnListSources => RequestPolicy {
                administrator: true,
                mutation: ReadOnly,
                recovery_interface: None,
                provisioning_recovery: false,
                requires_idle_interfaces: false,
                long_running: false,
            },
            ConfigureApiHttpsSettings { .. }
            | ResetApiHttpsSettings
            | ConfigureSecuritySettings { .. }
            | ResetSecuritySettings => RequestPolicy {
                administrator: true,
                mutation: Settings,
                recovery_interface: None,
                provisioning_recovery: false,
                requires_idle_interfaces: false,
                long_running: true,
            },
            SaveWifiClientProfile { interface, .. }
            | SaveWifiInterface { interface, .. }
            | SaveInterfaceConfig { interface, .. }
            | ForgetInterfaceConfig { interface, .. }
            | ResetInterfaceOverride { interface, .. }
            | RenewDhcpClient { interface, .. }
            | ReleaseDhcpClient { interface, .. }
            | WifiDeauthStation { interface, .. }
            | WifiReload { interface, .. }
            | WifiClientReconnect { interface, .. }
            | WifiClientScan { interface, .. } => RequestPolicy {
                administrator: true,
                mutation: Direct,
                recovery_interface: Some(interface),
                provisioning_recovery: false,
                requires_idle_interfaces: true,
                long_running: true,
            },
            GetInterfaceConfig { interface, .. }
            | GetDhcpClient { interface, .. }
            | GetDhcpConfig { interface, .. }
            | ListLeases { interface, .. }
            | GetWifiConfig { interface, .. }
            | ListWifiStations { interface, .. }
            | GetWifiClientConfig { interface, .. } => RequestPolicy {
                administrator: false,
                mutation: ReadOnly,
                recovery_interface: Some(interface),
                provisioning_recovery: false,
                requires_idle_interfaces: false,
                long_running: false,
            },
            ConfigureDhcpClient { interface, .. }
            | DisableDhcpClient { interface, .. }
            | ConfigureDhcpSettings { interface, .. }
            | ConfigureDhcp { interface, .. }
            | DisableDhcp { interface, .. }
            | WifiSetPassphrase { interface, .. }
            | WifiClientSetPassphrase { interface, .. }
            | ConfigureWifi { interface, .. }
            | ProvisionWifiAccessPoint { interface, .. }
            | DisableWifi { interface, .. }
            | ConfigureWifiClient { interface, .. }
            | DisableWifiClient { interface, .. }
            | ActivateWifiApProfile { interface, .. }
            | ProvisionWifiClient { interface, .. }
            | ActivateWifiClientProfile { interface, .. }
            | DeactivateWifiClientProfile { interface, .. } => RequestPolicy {
                administrator: true,
                mutation: InterfaceTransaction,
                recovery_interface: Some(interface),
                provisioning_recovery: false,
                requires_idle_interfaces: true,
                long_running: true,
            },
            ApplyInterface { interface, .. } | ApplyInterfaceEdit { interface, .. } => {
                RequestPolicy {
                    administrator: true,
                    mutation: InterfaceTransaction,
                    recovery_interface: Some(interface),
                    provisioning_recovery: false,
                    requires_idle_interfaces: false,
                    long_running: true,
                }
            }
            DryRunInterface { interface, .. } | DryRunInterfaceEdit { interface, .. } => {
                RequestPolicy {
                    administrator: false,
                    mutation: ReadOnly,
                    recovery_interface: Some(interface),
                    provisioning_recovery: false,
                    requires_idle_interfaces: false,
                    long_running: true,
                }
            }
            CommitNetworkChange { .. } => RequestPolicy {
                administrator: true,
                mutation: InterfaceTransaction,
                recovery_interface: None,
                provisioning_recovery: false,
                requires_idle_interfaces: false,
                long_running: true,
            },
            RollbackNetworkChange { .. } => RequestPolicy {
                administrator: true,
                mutation: InterfaceTransaction,
                recovery_interface: None,
                provisioning_recovery: true,
                requires_idle_interfaces: false,
                long_running: true,
            },
            SaveRouterIntent { .. }
            | VpnImportFromSource { .. }
            | VpnImportProfile { .. }
            | VpnDeleteProfile { .. }
            | SetVpnEnabled { .. }
            | VpnActivate { .. }
            | VpnDeactivate
            | VpnPolicySetMode { .. }
            | VpnPolicyClearMode
            | SaveWifiApProfile { .. }
            | DeleteWifiApProfile { .. }
            | CreateWifiClientProfile { .. }
            | UpdateWifiClientProfile { .. }
            | DeleteWifiClientProfile { .. } => RequestPolicy {
                administrator: true,
                mutation: Direct,
                recovery_interface: None,
                provisioning_recovery: false,
                requires_idle_interfaces: true,
                long_running: true,
            },
            RouterIntentPreview { .. } | RouterPlan { .. } | RouterProvisioningPreview { .. } => {
                RequestPolicy {
                    administrator: false,
                    mutation: ReadOnly,
                    recovery_interface: None,
                    provisioning_recovery: false,
                    requires_idle_interfaces: false,
                    long_running: true,
                }
            }
            RouterApply { .. } | RouterProvisioningApply { .. } | RouterProvisioningRepair => {
                RequestPolicy {
                    administrator: true,
                    mutation: RouterTransaction,
                    recovery_interface: None,
                    provisioning_recovery: false,
                    requires_idle_interfaces: false,
                    long_running: true,
                }
            }
            RouterCommit { .. } | RouterRollback { .. } => RequestPolicy {
                administrator: true,
                mutation: RouterTransaction,
                recovery_interface: None,
                provisioning_recovery: true,
                requires_idle_interfaces: false,
                long_running: true,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ControlRequest as Request;

    #[test]
    fn interface_convergence_can_run_while_other_writers_keep_execution_reserved() {
        let interface = Request::ApplyInterfaceEdit {
            interface: "wan0".into(),
            edit: crate::InterfaceEditRequest {
                mac_address: None,
                cidr: String::new(),
                role: crate::InterfaceRole::Input,
                managed: true,
                allow_management_change: false,
            },
        };
        assert!(interface.policy().needs_admission());
        assert!(!interface.policy().needs_execution());
        assert_eq!(interface.policy().recovery_interface, Some("wan0"));
        for writer in [
            Request::RouterApply {
                proposal: Default::default(),
            },
            Request::ResetSecuritySettings,
            Request::WifiClientScan {
                interface: "wan0".into(),
            },
        ] {
            assert!(writer.policy().needs_admission());
            assert!(writer.policy().needs_execution());
        }
        assert!(!Request::ResetSecuritySettings.policy().network_mutation());
    }

    #[test]
    fn recovery_and_administrative_reads_are_independent_of_mutation() {
        for request in [Request::DaemonLogs { limit: 1 }, Request::VpnListSources] {
            assert!(request.policy().administrator);
            assert!(!request.policy().needs_admission());
            assert!(!request.policy().long_running);
        }
        assert!(
            Request::RollbackNetworkChange { token: "t".into() }
                .policy()
                .provisioning_recovery
        );
        assert!(
            !Request::CommitNetworkChange { token: "t".into() }
                .policy()
                .provisioning_recovery
        );
        assert!(
            Request::RouterCommit { token: "t".into() }
                .policy()
                .provisioning_recovery
        );
        assert!(
            Request::RouterRollback { token: "t".into() }
                .policy()
                .provisioning_recovery
        );
    }
}

#[cfg(test)]
mod pending_change_tests {
    use crate::ControlRequest as Request;

    #[test]
    fn overlapping_writes_require_idle_but_reads_and_transaction_owners_remain_available() {
        for request in [
            Request::WifiReload {
                interface: "lan0".into(),
            },
            Request::DisableWifi {
                interface: "lan0".into(),
            },
            Request::DisableDhcpClient {
                interface: "wan0".into(),
            },
            Request::VpnDeactivate,
            Request::DeleteWifiClientProfile {
                id: "office".into(),
            },
        ] {
            let policy = request.policy();
            assert!(policy.network_mutation(), "{request:?}");
            assert!(policy.requires_idle_interfaces, "{request:?}");
        }
        for request in [
            Request::Ping,
            Request::PendingNetworkChanges,
            Request::CommitNetworkChange { token: "t".into() },
            Request::RollbackNetworkChange { token: "t".into() },
            Request::ApplyInterfaceEdit {
                interface: "lan0".into(),
                edit: crate::InterfaceEditRequest {
                    mac_address: None,
                    cidr: "192.0.2.1/24".into(),
                    role: crate::InterfaceRole::Output,
                    managed: true,
                    allow_management_change: true,
                },
            },
        ] {
            assert!(!request.policy().requires_idle_interfaces, "{request:?}");
        }
    }
}
