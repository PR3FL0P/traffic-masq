use super::*;

pub(super) fn provisioning_error(detail: RouterProvisioningErrorDetail) -> Response {
    Response::RouterProvisioningError { detail }
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct ProvisioningSecretAvailability {
    pub(super) uplink_pending: bool,
    pub(super) output_pending: bool,
}

pub(super) fn provisioning_desired(request: &RouterProvisioningRequest) -> RouterProvisioningDesired {
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

pub(super) fn parse_optional_passphrase(
    value: Option<String>,
) -> Result<Option<WifiPassphrase>, RouterProvisioningErrorDetail> {
    value.map(WifiPassphrase::new).transpose().map_err(|error| {
        RouterProvisioningErrorDetail::InvalidSecret {
            message: error.to_string(),
        }
    })
}

pub(super) fn preferred_downstream_subnet() -> ipnet::Ipv4Net {
    ipnet::Ipv4Net::new(
        std::net::Ipv4Addr::new(10, 77, DEFAULT_DOWNSTREAM_THIRD_OCTET, 0),
        DEFAULT_DOWNSTREAM_PREFIX,
    )
    .expect("documented default downstream candidate is valid")
}

pub(super) fn provisioning_preview_view(
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
            .is_some_and(|observation| observation.role == Some(InterfaceRole::None))
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

pub(super) fn classify_provisioning_derivation_error(
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

pub(super) fn classify_provisioning_transaction_error(error: &anyhow::Error) -> RouterProvisioningErrorDetail {
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
