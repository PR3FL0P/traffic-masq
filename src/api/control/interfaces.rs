use super::*;

impl ControlService {
    pub(super) async fn interface_inventory(&self) -> Result<Response> {
        use traffic_masq_protocol::{
            InterfaceConfigSource, InterfaceInventoryEntry, InterfacePresence, InterfaceReadiness,
            InterfaceReadinessBlocker,
        };
        let snapshot = self.overrides.snapshot().await;
        let effective = snapshot.effective_config(&self.base_config)?;
        let observation = interface_statuses(self.network.as_ref(), &self.transactions).await;
        let mut cache = self.interface_observation.lock().await;
        let observation_error = match observation {
            Ok(observed) => {
                *cache = observed;
                None
            }
            Err(error) => Some(format!("{error:#}")),
        };
        let mut names: BTreeSet<String> = effective.network.interfaces.keys().cloned().collect();
        names.extend(snapshot.suppressed_interfaces.iter().cloned());
        names.extend(cache.iter().map(|entry| entry.interface.name.clone()));
        let mut references: BTreeMap<String, Vec<String>> = BTreeMap::new();
        if let Some(uplink) = &effective.router.uplink {
            references
                .entry(uplink.interface.clone())
                .or_default()
                .push("router.uplink".into());
        }
        for (index, rule) in effective.router.forwarding.iter().flatten().enumerate() {
            references
                .entry(rule.from.clone())
                .or_default()
                .push(format!("router.forwarding[{index}].from"));
            references
                .entry(rule.to.clone())
                .or_default()
                .push(format!("router.forwarding[{index}].to"));
        }
        for (index, route) in effective.router.owned_routes.iter().enumerate() {
            if let Some(name) = &route.output_interface {
                references
                    .entry(name.clone())
                    .or_default()
                    .push(format!("router.owned_routes[{index}]"));
            }
        }
        names.extend(references.keys().cloned());
        let interfaces = names
            .into_iter()
            .map(|name| {
                let observed = cache
                    .iter()
                    .find(|entry| entry.interface.name == name)
                    .cloned();
                let configured = effective.network.interfaces.get(&name).cloned();
                let config_source = match snapshot.interfaces.get(&name) {
                    Some(value) if value.dhcp_client_only => InterfaceConfigSource::Derived,
                    Some(_) => InterfaceConfigSource::Override,
                    None if configured.is_some() => InterfaceConfigSource::Base,
                    None => InterfaceConfigSource::None,
                };
                let presence = if observation_error.is_some() {
                    InterfacePresence::Unknown
                } else if observed.is_some() {
                    InterfacePresence::Present
                } else {
                    InterfacePresence::Missing
                };
                let (readiness, blockers) = match presence {
                    InterfacePresence::Unknown => (
                        InterfaceReadiness::Unknown,
                        vec![InterfaceReadinessBlocker::ObservationFailed {
                            message: observation_error.clone().unwrap_or_default(),
                        }],
                    ),
                    InterfacePresence::Missing
                        if configured.is_some() || references.contains_key(&name) =>
                    {
                        (
                            InterfaceReadiness::WaitingDevice,
                            vec![InterfaceReadinessBlocker::MissingInterface {
                                interface: name.clone(),
                            }],
                        )
                    }
                    InterfacePresence::Missing => (InterfaceReadiness::Disabled, Vec::new()),
                    InterfacePresence::Present => (InterfaceReadiness::Ready, Vec::new()),
                };
                InterfaceInventoryEntry {
                    readiness,
                    blockers,
                    references: references.remove(&name).unwrap_or_default(),
                    suppressed: snapshot.suppressed_interfaces.contains(&name),
                    name,
                    observed: observed.map(Into::into),
                    configured: configured.map(Into::into),
                    config_source,
                    presence,
                    observation_stale: observation_error.is_some(),
                }
            })
            .collect();
        Ok(Response::InterfaceInventory {
            revision: snapshot.revision,
            interfaces,
            suppressed_interfaces: snapshot.suppressed_interfaces.into_iter().collect(),
            observation_error,
        })
    }

    pub(super) async fn save_missing_interface_intent(
        &self,
        interface: String,
        proposal: RouterIntentProposal,
        expected_revision: u64,
    ) -> Result<Response> {
        let observed = self.check_missing_interface_write(&interface).await?;
        let candidate = self.overrides.build_candidate(&proposal).await?;
        if candidate.base_revision() != expected_revision {
            return Err(StaleCandidateError {
                candidate: expected_revision,
                current: candidate.base_revision(),
            }
            .into());
        }
        let mut missing_dependencies: Vec<String> = candidate
            .desired()
            .required_existing_interfaces()
            .into_iter()
            .filter(|name| !observed.iter().any(|entry| entry.name == *name))
            .map(str::to_owned)
            .collect();
        if candidate
            .effective_config()
            .network
            .interfaces
            .contains_key(&interface)
        {
            missing_dependencies.push(interface.clone());
        }
        missing_dependencies.sort();
        missing_dependencies.dedup();
        // Cleanup has its own durable process/lease ownership proofs. Until all
        // services stop, the existing committed intent remains the rollback
        // target, including after interruption/restart. Never restart a service
        // against a missing or replacement device merely to compensate a stop.
        let _resume = MissingCleanupWakeup(&self.overrides);
        self.cleanup_missing_interface_runtime(&interface)
            .await
            .map_err(|error| {
                let message = format!("missing-device runtime cleanup failed; previous saved intent retained: {error:#}");
                error.context(message)
            })?;
        self.check_missing_interface_write(&interface)
            .await
            .map_err(|error| {
                let message = format!("device observation changed during cleanup; previous saved intent retained: {error:#}");
                error.context(message)
            })?;
        let revision = self.overrides.commit_candidate(&candidate).await?;
        Ok(Response::InterfaceIntentSaved {
            interface,
            revision,
            deferred: !missing_dependencies.is_empty(),
            missing_dependencies,
        })
    }

    pub(super) async fn check_missing_interface_write(
        &self,
        interface: &str,
    ) -> Result<Vec<crate::netlink::NetworkInterface>> {
        traffic_masq_protocol::validate_interface_name(interface).map_err(anyhow::Error::msg)?;
        let observed = self.network.list_interfaces().await?;
        if observed.iter().any(|entry| entry.name == interface) {
            anyhow::bail!(
                "interface {interface} is present; use a confirmed live interface transaction"
            );
        }
        Ok(observed)
    }

    async fn cleanup_missing_interface_runtime(&self, interface: &str) -> Result<()> {
        use crate::wifi::record::{WifiProcessKind, WifiRecordStore};
        let records = self.config.runtime.state_dir.join("wifi");
        // A missing supervisor does not prove that its persisted processes or
        // leases are gone. Scans have no retained service task to stop here.
        for (kind, available, directory) in [
            (
                WifiProcessKind::AccessPoint,
                self.wifi.is_some(),
                &self.config.wifi.runtime_dir,
            ),
            (
                WifiProcessKind::Client,
                self.wifi_client.is_some(),
                &self.config.wifi_client.runtime_dir,
            ),
            (
                WifiProcessKind::Scan,
                false,
                &self.config.wifi_client.runtime_dir,
            ),
        ] {
            if !available {
                let store = WifiRecordStore::new(kind, &records, directory, interface);
                anyhow::ensure!(store.load().await?.is_none() && !store.transition_pending().await?,
                    "interface {interface} retains {kind:?} ownership without a service task; recovery required");
            }
        }
        if self.dhcp_client.is_none() {
            let store = crate::dhcp::client::store::DhcpClientLeaseStore::new(
                &self.config.runtime.state_dir,
            )?;
            anyhow::ensure!(store.load(interface)?.is_none(),
                "interface {interface} retains DHCP lease ownership without its supervisor; recovery required");
        }
        // Check all Wi-Fi ownership documents before stopping any service.
        // An orphan, changed proof or interrupted launch is recovery work, not
        // authority to forget a process based on its interface name.
        if let Some(runtime) = &self.wifi {
            runtime.check_cleanup_ownership(interface).await?;
        }
        if let Some(runtime) = &self.wifi_client {
            runtime.check_cleanup_ownership(interface).await?;
        }
        // Lease cleanup verifies the device identity and exact owned routes.
        // Do it first so a conflict cannot stop otherwise healthy Wi-Fi tasks.
        if let Some(runtime) = &self.dhcp_client {
            runtime.disable(interface).await?;
        }
        if let Some(runtime) = &self.wifi_client {
            runtime.disable(interface).await?;
        }
        if let Some(runtime) = &self.wifi {
            runtime.disable(interface).await?;
        }
        self.dhcp.disable(interface).await?;
        Ok(())
    }

    pub(super) async fn validate_default_route_management(
        &self,
        interface: &str,
        current: Option<&InterfaceConfig>,
        config: &InterfaceConfig,
        allow_management_change: bool,
    ) -> Result<()> {
        if allow_management_change
            || (!config.managed && !current.is_some_and(|current| current.managed))
        {
            return Ok(());
        }

        let Some(index) = self
            .network
            .list_interfaces()
            .await?
            .into_iter()
            .find(|candidate| candidate.name == interface)
            .map(|candidate| candidate.index)
        else {
            return Ok(());
        };
        let routes = self.network.list_ipv4_routes().await.with_context(|| {
            format!("failed to inspect IPv4 routes before changing {interface}")
        })?;
        let carries_default_route = routes.iter().any(|route| {
            route.destination.prefix_len() == 0 && route.output_interface_index == Some(index)
        });
        if carries_default_route {
            anyhow::bail!(
                "interface {interface} carries the default route; set allow_management_change=true to confirm the connectivity risk"
            );
        }
        Ok(())
    }

    /// Unmanaging (or re-roling away from Output) an interface that currently
    /// carries a router-owned AP or DHCP server does not stop those services
    /// — they are only started/stopped by `RouterManager::apply`, which this
    /// edit path never triggers. Rather than silently leaving hostapd/dnsmasq
    /// running on an interface that just lost its IP, require the same
    /// explicit confirmation already used for the default-route and
    /// Management-role risks, and tell the operator where to actually finish
    /// the job (the Router tab), instead of "fixing" it with a second,
    /// independently-triggered mutation path into router state.
    pub(super) fn validate_router_service_management(
        interface: &str,
        current: Option<&InterfaceConfig>,
        new_config: &InterfaceConfig,
        allow_management_change: bool,
    ) -> Result<()> {
        if allow_management_change {
            return Ok(());
        }
        let Some(current) = current else {
            return Ok(());
        };
        if current.role != InterfaceRole::Output || !current.managed {
            return Ok(());
        }
        let losing_service = new_config.role != InterfaceRole::Output || !new_config.managed;
        if !losing_service {
            return Ok(());
        }
        if current.wifi.is_none() && current.dhcp.is_none() {
            return Ok(());
        }
        let mut running = Vec::new();
        if let Some(wifi) = &current.wifi {
            running.push(format!("access point '{}'", wifi.ssid));
        }
        if current.dhcp.is_some() {
            running.push("DHCP server".to_string());
        }
        anyhow::bail!(
            "{interface} still runs {} started by the router; set allow_management_change=true to confirm, then re-apply the router config to actually stop them",
            running.join(" and ")
        );
    }

    pub(super) async fn interface_config_response(&self, interface: String) -> Result<Response> {
        let snapshot = self.overrides.snapshot().await;
        let effective = snapshot.effective_config(&self.base_config)?;
        let config = effective.network.interfaces.get(&interface).cloned();
        let allow_management_change = snapshot
            .interfaces
            .get(&interface)
            .map(|value| value.allow_management_change)
            .unwrap_or(false);
        Ok(Response::InterfaceConfig {
            interface,
            config: config.map(Into::into),
            allow_management_change,
        })
    }

    pub(super) async fn effective_config(&self) -> Result<AppConfig, String> {
        self.overrides
            .snapshot()
            .await
            .effective_config(&self.base_config)
            .map_err(|error| error.to_string())
    }
}

pub(super) fn interface_edit_request_to_config(
    edit: InterfaceEditRequest,
    existing: Option<&InterfaceConfig>,
) -> Result<(InterfaceConfig, bool)> {
    if !edit.managed && !edit.cidr.trim().is_empty() {
        anyhow::bail!("cannot change IP while the interface is unmanaged; enable Managed first");
    }
    // An empty CIDR is the removal request: the interface keeps its role and
    // stays managed, it just stops carrying an address. The DHCP server cannot
    // follow it there — it serves the subnet of that very address — so name the
    // conflict here rather than letting interface validation report a missing
    // address the operator deliberately removed.
    if edit.managed
        && edit.cidr.trim().is_empty()
        && existing.is_some_and(|config| config.dhcp.is_some())
    {
        anyhow::bail!(
            "cannot remove the IPv4 address while a DHCP server is configured on this interface; disable DHCP first"
        );
    }
    let ipv4 = if edit.cidr.trim().is_empty() {
        None
    } else {
        Some(edit.cidr.trim().parse()?)
    };
    let is_output = edit.role == InterfaceRole::Output;
    let is_input = edit.role == InterfaceRole::Input;

    let dhcp = if is_output && edit.managed {
        existing.and_then(|config| config.dhcp.clone())
    } else {
        None
    };
    let wifi = if is_output && edit.managed {
        existing.and_then(|config| config.wifi.clone())
    } else {
        None
    };
    let dhcp_client = if is_input && edit.managed && ipv4.is_none() {
        existing.and_then(|config| config.dhcp_client.clone())
    } else {
        None
    };
    let wifi_client = if is_input {
        existing
            .filter(|config| edit.managed || !config.managed)
            .and_then(|config| config.wifi_client.clone())
    } else {
        None
    };

    Ok((
        InterfaceConfig {
            role: edit.role,
            managed: edit.managed,
            ipv4,
            dhcp,
            dhcp_client,
            wifi,
            wifi_client,
            nat: existing.is_none_or(|config| config.nat),
        },
        edit.allow_management_change,
    ))
}

pub(super) async fn interface_statuses(
    network: &dyn NetworkProvider,
    transactions: &NetworkTransactionManager,
) -> Result<Vec<InterfaceStatus>> {
    let mut result = Vec::new();
    let routes = match network.list_ipv4_routes().await {
        Ok(routes) => routes,
        Err(error) => {
            tracing::warn!(%error, "failed to inspect IPv4 routes while listing interfaces");
            Vec::new()
        }
    };
    for interface in network.list_interfaces().await? {
        let ipv4_addresses = network.list_ipv4_addresses(&interface.name).await?;
        let has_default_route = routes.iter().any(|route| {
            route.destination.prefix_len() == 0
                && route.output_interface_index == Some(interface.index)
        });
        let mut owned = Vec::new();
        for address in &ipv4_addresses {
            if transactions.owns_address(&interface.name, address).await {
                owned.push(address.clone());
            }
        }
        result.push(InterfaceStatus {
            owned_ipv4_addresses: Some(owned),
            interface,
            ipv4_addresses,
            has_default_route,
        });
    }
    result.sort_by(|left, right| left.interface.name.cmp(&right.interface.name));
    Ok(result)
}

/// Also wakes the unchanged committed intent if an API future is cancelled.
struct MissingCleanupWakeup<'a>(&'a RuntimeOverrideManager);

impl Drop for MissingCleanupWakeup<'_> {
    fn drop(&mut self) {
        self.0.request_reconcile();
    }
}
