use std::fmt;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::config::{AppConfig, InterfaceConfig, InterfaceRole, UplinkMode};
use crate::core::interface::{InterfaceChangePlan, InterfaceSnapshot};
use crate::core::route::{desired_owned_routes, ManagedIpv4Route, RoutePlan, RouteSnapshot};
use crate::core::vpn_chain::{VpnHopDesired, VpnHopKind, VpnHopRoutingDesired};
use crate::core::vpn_policy::VpnPolicyReservedIds;
use crate::core::vpn_policy_manager::VpnPolicyDesired;
use crate::dhcp::client::DhcpClientSpec;
use crate::dhcp::supervisor::{DhcpServiceSpec, DhcpSupervisor};
use crate::firewall::{
    OutputNetwork, RouterDataplaneDesired, RouterDataplanePlan, RouterDataplaneSnapshot,
    RouterDataplaneTarget,
};
use crate::vpn::manager::hop_interface_name;
use crate::wifi::client::WifiClientSpec;
use crate::wifi::WifiApSpec;

pub use traffic_masq_protocol::{RouterDhcpHealthReason, RouterHealthReport};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterInterfaceDesired {
    pub name: String,
    pub config: InterfaceConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterDesired {
    pub enabled: bool,
    pub uplink_wifi: Option<WifiClientSpec>,

    pub uplink_dhcp: Option<DhcpClientSpec>,
    pub output_wifi: Vec<WifiApSpec>,
    pub dhcp: Vec<DhcpServiceSpec>,
    pub routes: Vec<ManagedIpv4Route>,
    pub allow_default_route_change: bool,
    /// Ordered VPN hop chain; index 0 = hop closest to the uplink. Empty
    /// means "no VPN" (formerly `VpnPolicyMode::Direct`); length 1 with an
    /// `Exit` kind is today's single-tunnel `VpnPolicyMode::Vpn`.
    pub vpn_chain: Vec<VpnHopDesired>,
    pub dataplane: RouterDataplaneTarget,
    pub interfaces: Vec<RouterInterfaceDesired>,
}

impl RouterDesired {
    /// Interfaces that must already exist before applying intent. Router-owned
    /// VPN hops are created during apply; externally managed tunnels are not.
    pub(crate) fn required_existing_interfaces(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self
            .interfaces
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        if let RouterDataplaneTarget::Enabled(dataplane) = &self.dataplane {
            if let Some(rules) = &dataplane.forwarding {
                for rule in rules {
                    names.extend([rule.from.as_str(), rule.to.as_str()]);
                }
            } else {
                names.push(&dataplane.uplink);
                names.extend(
                    dataplane
                        .outputs
                        .iter()
                        .map(|output| output.interface.as_str()),
                );
            }
        }
        names.extend(
            self.routes
                .iter()
                .filter_map(|route| route.output_interface.as_deref()),
        );
        names.retain(|name| !self.vpn_chain.iter().any(|hop| hop.interface == *name));
        names.sort_unstable();
        names.dedup();
        names
    }

    /// Derive and validate router intent, including interfaces, VPN chain, routes, and forwarding.
    pub fn from_effective_config(config: &AppConfig) -> Result<Self> {
        config.validate()?;
        crate::wifi::policy::WifiRadioPolicy::validate_system(&config.network)?;
        Self::from_validated_config(config)
    }

    /// Derive router intent during startup recovery without admitting unrelated subsystems.
    pub(crate) fn from_router_recovery_config(config: &AppConfig) -> Result<Self> {
        config.validate_router_recovery()?;
        Self::from_validated_config(config)
    }

    fn from_validated_config(config: &AppConfig) -> Result<Self> {
        if config.router.is_active() && !config.vpn.enabled && !config.router.vpn_chain.is_empty() {
            anyhow::bail!("Enable VPN before enabling a router VPN chain");
        }
        let mut dhcp = DhcpSupervisor::service_specs(config)?;
        dhcp.sort_by(|left, right| left.interface.cmp(&right.interface));

        if !config.router.is_active() {
            return Ok(Self {
                enabled: false,
                uplink_wifi: None,
                uplink_dhcp: None,
                output_wifi: Vec::new(),
                dhcp,
                routes: Vec::new(),
                // Removing routing intent still removes previously owned routes,
                // so preserve permission to delete an owned default route.
                allow_default_route_change: config.router.allow_default_route_change,
                vpn_chain: Vec::new(),
                dataplane: RouterDataplaneTarget::Disabled,
                interfaces: Vec::new(),
            });
        }

        let routes = desired_owned_routes(&config.router);
        let allow_default_route_change = config.router.allow_default_route_change;

        let managed_outputs = managed_output_interfaces(config);

        if let Some(forwarding) = &config.router.forwarding {
            let mut interfaces = managed_outputs.clone();
            if let Some(uplink) = &config.router.uplink {
                let interface = config
                    .network
                    .interfaces
                    .get(&uplink.interface)
                    .ok_or_else(|| anyhow::anyhow!("configured uplink interface is missing"))?;
                interfaces.push(RouterInterfaceDesired {
                    name: uplink.interface.clone(),
                    config: interface.clone(),
                });
            }
            let output_wifi = output_wifi(&interfaces)?;
            let dataplane = if forwarding.is_empty() {
                RouterDataplaneTarget::Disabled
            } else {
                RouterDataplaneTarget::Enabled(RouterDataplaneDesired {
                    forwarding: Some(forwarding.clone()),
                    uplink: String::new(),
                    outputs: Vec::new(),
                })
            };
            let uplink_config = config.router.uplink.as_ref().and_then(|uplink| {
                config
                    .network
                    .interfaces
                    .get(&uplink.interface)
                    .map(|interface| (uplink, interface))
            });
            let uplink_wifi = uplink_config
                .map(|(uplink, interface)| {
                    WifiClientSpec::from_interface_config(&uplink.interface, interface)
                })
                .transpose()?
                .flatten();
            let uplink_dhcp = uplink_config
                .filter(|(uplink, _)| uplink.mode == UplinkMode::Dhcp)
                .map(|(uplink, interface)| {
                    DhcpClientSpec::from_interface_config(&uplink.interface, interface)
                })
                .transpose()?
                .flatten();
            return Ok(Self {
                enabled: true,
                uplink_wifi,
                uplink_dhcp,
                output_wifi,
                dhcp,
                routes,
                allow_default_route_change,
                vpn_chain: Vec::new(),
                dataplane,
                interfaces,
            });
        }

        let Some(uplink) = config.router.uplink.as_ref() else {
            let interfaces = managed_outputs;
            let mut output_wifi = output_wifi(&interfaces)?;
            output_wifi.sort_by(|left, right| left.interface.cmp(&right.interface));

            return Ok(Self {
                enabled: true,
                uplink_wifi: None,
                uplink_dhcp: None,
                output_wifi,
                dhcp,
                routes,
                allow_default_route_change,
                vpn_chain: Vec::new(),
                dataplane: RouterDataplaneTarget::Disabled,
                interfaces,
            });
        };

        let uplink_config = config
            .network
            .interfaces
            .get(&uplink.interface)
            .expect("validated router uplink interface is configured");
        let outputs = managed_outputs
            .iter()
            .filter(|interface| interface.config.nat)
            .map(|interface| OutputNetwork {
                interface: interface.name.clone(),
                subnet: interface
                    .config
                    .ipv4
                    .expect("validated router output has IPv4")
                    .trunc(),
            })
            .collect();
        let dataplane = RouterDataplaneDesired {
            forwarding: None,
            uplink: uplink.interface.clone(),
            outputs,
        };
        dataplane.validate()?;

        let mut interfaces = vec![RouterInterfaceDesired {
            name: uplink.interface.clone(),
            config: uplink_config.clone(),
        }];
        interfaces.extend(managed_outputs);

        let uplink_wifi = WifiClientSpec::from_interface_config(&uplink.interface, uplink_config)?;
        let mut output_wifi = output_wifi(&interfaces)?;
        output_wifi.sort_by(|left, right| left.interface.cmp(&right.interface));

        let uplink_dhcp = if uplink.mode == UplinkMode::Dhcp {
            DhcpClientSpec::from_interface_config(&uplink.interface, uplink_config)?
        } else {
            None
        };

        let protected_subnets: Vec<ipnet::Ipv4Net> = config
            .network
            .interfaces
            .values()
            .filter(|interface| {
                interface.role == InterfaceRole::Output && interface.managed && interface.nat
            })
            .filter_map(|interface| interface.ipv4)
            .map(|network| network.trunc())
            .collect();

        let chain_len = config.router.vpn_chain.len();
        let mut vpn_chain = Vec::with_capacity(chain_len);
        for (index, hop_config) in config.router.vpn_chain.iter().enumerate() {
            let hop_index = index as u32;
            let interface = hop_interface_name(hop_index);
            let upstream = if index == 0 {
                uplink.interface.clone()
            } else {
                hop_interface_name(hop_index - 1)
            };
            let reserved = VpnPolicyReservedIds::for_hop(hop_index)?;
            let is_last = index + 1 == chain_len;
            let kind = if is_last {
                VpnHopKind::Exit {
                    policy: VpnPolicyDesired {
                        protected_subnets: protected_subnets.clone(),
                        vpn_interface: interface.clone(),
                        physical_uplink: upstream.clone(),
                        route_host_traffic: config.router.route_host_traffic,
                        chain_profiles: if config.router.route_host_traffic {
                            config
                                .router
                                .vpn_chain
                                .iter()
                                .map(|hop| hop.profile_name.clone())
                                .collect()
                        } else {
                            Vec::new()
                        },
                        host_endpoints: Vec::new(),
                    },
                }
            } else {
                VpnHopKind::Relay {
                    own_route: VpnHopRoutingDesired {
                        hop_interface: interface.clone(),
                        upstream_interface: upstream.clone(),
                    },
                }
            };
            vpn_chain.push(VpnHopDesired {
                hop_index,
                profile_name: hop_config.profile_name.clone(),
                interface,
                upstream,
                reserved,
                kind,
            });
        }

        Ok(Self {
            enabled: true,
            uplink_wifi,
            uplink_dhcp,
            output_wifi,
            dhcp,
            routes,
            allow_default_route_change,
            vpn_chain,
            dataplane: RouterDataplaneTarget::Enabled(dataplane),
            interfaces,
        })
    }
}

fn managed_output_interfaces(config: &AppConfig) -> Vec<RouterInterfaceDesired> {
    config
        .network
        .interfaces
        .iter()
        .filter(|(_, interface)| interface.role == InterfaceRole::Output && interface.managed)
        .map(|(name, interface)| RouterInterfaceDesired {
            name: name.clone(),
            config: interface.clone(),
        })
        .collect()
}

fn output_wifi(interfaces: &[RouterInterfaceDesired]) -> Result<Vec<WifiApSpec>> {
    interfaces
        .iter()
        .filter_map(|interface| {
            WifiApSpec::from_interface_config(&interface.name, &interface.config).transpose()
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RouterRisk {
    pub changes_default_route: bool,
    pub requires_management_confirmation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum DhcpPlan {
    Start {
        desired: DhcpServiceSpec,
    },
    Stop {
        current: DhcpServiceSpec,
    },
    Reconfigure {
        current: DhcpServiceSpec,
        desired: DhcpServiceSpec,
    },
    Unchanged {
        current: DhcpServiceSpec,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum WifiPlan<T> {
    Start { desired: T },
    Stop { current: T },
    Reconfigure { current: T, desired: T },
    Unchanged { current: T },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterPlan {
    pub desired: RouterDesired,
    pub interfaces: Vec<InterfaceChangePlan>,
    pub uplink_wifi: Vec<WifiPlan<WifiClientSpec>>,
    pub output_wifi: Vec<WifiPlan<WifiApSpec>>,
    pub dhcp: Vec<DhcpPlan>,
    pub routes: RoutePlan,
    pub vpn_chain: VpnChainPlan,
    pub dataplane: RouterDataplanePlan,
    pub risk: RouterRisk,
}

/// Observations and operations collected for a full router plan. The manager
/// attaches the desired intent and derives the risk shown to callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterSubsystemPlan {
    pub interfaces: Vec<InterfaceChangePlan>,
    pub uplink_wifi: Vec<WifiPlan<WifiClientSpec>>,
    pub output_wifi: Vec<WifiPlan<WifiApSpec>>,
    pub routes: RoutePlan,
    pub dhcp: Vec<DhcpPlan>,
    pub vpn_chain: VpnChainPlan,
    pub dataplane: RouterDataplanePlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifiSnapshot<T> {
    pub interface: String,

    pub spec: Option<T>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VpnChainPlan {
    pub hops: Vec<VpnHopDesired>,
}

impl VpnChainPlan {
    pub fn empty() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default, Deserialize)]
pub struct VpnChainSnapshot {
    /// The interfaces (by name) that were active hops before this
    /// transaction started, in the same order they were applied.
    pub hops: Vec<String>,
    /// The full previous hop chain, in application order, kept alongside
    /// `hops` so `rollback_vpn_chain` can fully reconstruct the prior state
    /// (profile, kind, reserved IDs) rather than only knowing the names of
    /// the interfaces that used to exist.
    pub previous_hops: Vec<VpnHopDesired>,
}

impl VpnChainSnapshot {
    pub fn empty() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpClientSnapshot {
    pub interface: String,
    /// DHCP configuration intent. This is the only DHCP state owned by router
    /// transaction rollback.
    pub spec: Option<DhcpClientSpec>,
    /// Compatibility-only field for callers compiled against the older public
    /// snapshot shape. Dynamic leases are deliberately excluded from durable
    /// journals/fingerprints and are never replayed during rollback.
    #[serde(skip)]
    pub lease: Option<crate::dhcp::client::lease::DhcpClientLease>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterSnapshot {
    pub interfaces: Vec<InterfaceSnapshot>,
    pub uplink_wifi: Vec<WifiSnapshot<WifiClientSpec>>,
    pub uplink_dhcp: Option<DhcpClientSpec>,
    #[serde(default)]
    pub dhcp_clients: Vec<DhcpClientSnapshot>,
    pub output_wifi: Vec<WifiSnapshot<WifiApSpec>>,
    pub dhcp: Vec<DhcpServiceSpec>,

    pub dhcp_absent_interfaces: Vec<String>,
    pub routes: RouteSnapshot,
    pub vpn_chain: VpnChainSnapshot,
    pub dataplane: RouterDataplaneSnapshot,
}

#[async_trait]
/// Subsystem hooks used under router mutation serialization. Planning and
/// snapshots are observational, and snapshots cover affected owned resources,
/// not arbitrary system state. Apply hooks can fail after partial changes;
/// callers must journal the snapshot before applying and recover on failure.
/// Rollback restores only proved owned resources and must refuse foreign
/// replacements. Retry rollback using the retained snapshot until it succeeds.
/// DHCP client hooks are required: implementations without a client must reject
/// nonempty intent and recovery snapshots, never report a successful no-op.
pub trait RouterSubsystems: Send + Sync {
    /// Reject unavailable dependencies before opening a journal or mutating
    /// any subsystem. Recovery of an existing snapshot must bypass this check.
    async fn preflight(&self, _desired: &RouterDesired) -> Result<()> {
        Ok(())
    }

    /// Removal-only convergence of committed intent; no services or additions.
    async fn cleanup_removed_dataplane(&self, _desired: &RouterDesired) -> Result<()> {
        anyhow::bail!("removal-only router cleanup is unavailable")
    }

    /// Rebuild volatile ownership/runtime bookkeeping from durable proofs
    /// before crash recovery or startup repair touches the data plane.
    /// Implementations must not adopt resources without an ownership proof.
    async fn prepare_recovery(&self, _current: &RouterDesired) -> Result<()> {
        Ok(())
    }

    /// Collect the complete plan in dependency order. Keep narrow route, VPN,
    /// and dataplane planners for drift repair without replanning the router.
    async fn plan_for(&self, desired: &RouterDesired) -> Result<RouterSubsystemPlan>;
    /// Observe route differences without mutating kernel state or ownership.
    async fn plan_routes(&self, desired: &RouterDesired) -> Result<RoutePlan>;
    /// Observe dataplane differences without adopting resources or applying rules.
    async fn plan_dataplane(&self, desired: &RouterDesired) -> Result<RouterDataplanePlan>;

    /// Plan the VPN hop chain for narrow drift repair as well as full plans.
    /// An implementation without VPN support safely no-ops for an empty
    /// chain and errors when the desired state needs one.
    async fn plan_vpn_chain(&self, desired: &RouterDesired) -> Result<VpnChainPlan> {
        if !desired.vpn_chain.is_empty() {
            anyhow::bail!("VPN chain runtime is unavailable")
        }
        Ok(VpnChainPlan::empty())
    }

    /// Widen volatile ownership to cover an intent that is about to mutate the
    /// machine. Planning and snapshotting must stay observational; adoption is
    /// deliberately a separate apply-time step so a plan preview cannot change
    /// later reconciliation behaviour.
    async fn adopt_router_interfaces(&self, _desired: &RouterDesired) {}

    /// Narrow ownership to exactly these interfaces.
    ///
    /// Called once a transaction settles, so the owned set tracks the intent
    /// that is actually in force instead of accumulating every interface that
    /// was ever part of one. Doing nothing is correct for a subsystem that
    /// keeps no such record.
    async fn retain_router_interfaces(&self, _interfaces: &[String]) {}

    /// Capture recovery state for the subsystems affected by the desired router intent.
    async fn snapshot_for(&self, desired: &RouterDesired) -> Result<RouterSnapshot>;

    /// Apply interface plans in order; an error may leave earlier changes applied.
    async fn apply_interfaces(&self, plan: &[InterfaceChangePlan]) -> Result<()>;
    /// Apply client Wi-Fi plans; partial errors require snapshot-based recovery.
    async fn apply_uplink_wifi(&self, plan: &[WifiPlan<WifiClientSpec>]) -> Result<()> {
        if !plan.is_empty() {
            anyhow::bail!("uplink Wi-Fi runtime is unavailable")
        }
        Ok(())
    }
    /// Apply AP plans; partial errors require snapshot-based recovery.
    async fn apply_output_wifi(&self, plan: &[WifiPlan<WifiApSpec>]) -> Result<()> {
        if !plan.is_empty() {
            anyhow::bail!("output Wi-Fi runtime is unavailable")
        }
        Ok(())
    }
    /// Apply planned owned route changes, refusing conflicting foreign state.
    async fn apply_routes(&self, plan: &RoutePlan) -> Result<()>;
    /// Apply server DHCP plans; errors may leave some services changed.
    async fn apply_dhcp(&self, plan: &[DhcpPlan]) -> Result<()>;
    /// Apply the planned owned dataplane; retain snapshot on partial error.
    async fn apply_dataplane(&self, plan: &RouterDataplanePlan) -> Result<()>;
    /// Stop DHCP clients whose ownership must disappear before interface
    /// configuration is mutated.
    async fn quiesce_uplink_dhcp(&self, desired: Option<&DhcpClientSpec>) -> Result<()>;
    /// Apply candidate DHCP intent and report whether rollback should quiesce
    /// candidate runtime before restoring interfaces.
    async fn apply_uplink_dhcp_candidate(&self, desired: Option<&DhcpClientSpec>) -> Result<bool>;
    /// Activate hops 0..N in order. On any hop's failure, must roll back
    /// N..0 internally before returning `Err` — the outer `RouterManager`
    /// rollback only ever calls `rollback_vpn_chain` once, against the
    /// pre-apply snapshot, never mid-chain state.
    async fn apply_vpn_chain(&self, plan: &VpnChainPlan) -> Result<()> {
        if !plan.hops.is_empty() {
            anyhow::bail!("VPN chain runtime is unavailable")
        }
        Ok(())
    }

    /// Restore recorded interfaces without removing unproved foreign addresses.
    async fn rollback_interfaces(&self, snapshot: &[InterfaceSnapshot]) -> Result<()>;
    /// Restore recorded client intent/runtime; refuse foreign process identities.
    async fn rollback_uplink_wifi(&self, snapshot: &[WifiSnapshot<WifiClientSpec>]) -> Result<()> {
        if !snapshot.is_empty() {
            anyhow::bail!("uplink Wi-Fi runtime is unavailable")
        }
        Ok(())
    }
    /// Restore recorded AP intent/runtime; refuse foreign process identities.
    async fn rollback_output_wifi(&self, snapshot: &[WifiSnapshot<WifiApSpec>]) -> Result<()> {
        if !snapshot.is_empty() {
            anyhow::bail!("output Wi-Fi runtime is unavailable")
        }
        Ok(())
    }
    /// Restore scoped owned routes, refusing conflicting foreign identities.
    async fn rollback_routes(&self, snapshot: &RouteSnapshot) -> Result<()>;
    /// Restore captured servers and stop only services recorded as previously absent.
    async fn rollback_dhcp_scoped(
        &self,
        snapshot: &[DhcpServiceSpec],
        previously_absent: &[String],
    ) -> Result<()>;
    /// Restore the captured owned dataplane; preserve foreign tables and rules.
    async fn rollback_dataplane(&self, snapshot: &RouterDataplaneSnapshot) -> Result<()>;
    /// Stop DHCP runtime installed by the candidate before interface rollback.
    /// Previous DHCP intent is restored by `rollback_dhcp_clients` afterwards.
    async fn rollback_candidate_uplink_dhcp(&self) -> Result<()>;
    /// Restore captured client configuration, with legacy uplink compatibility,
    /// without replaying captured leases. Production verifies a current lease
    /// before reporting restoration complete. Keep durable lease ownership on
    /// cleanup failure.
    async fn rollback_dhcp_clients(
        &self,
        snapshots: &[DhcpClientSnapshot],
        legacy: Option<&DhcpClientSpec>,
    ) -> Result<()>;
    /// Restore the captured chain using recorded launch ownership; refuse foreign links.
    async fn rollback_vpn_chain(&self, snapshot: &VpnChainSnapshot) -> Result<()> {
        if !snapshot.hops.is_empty() {
            anyhow::bail!("VPN chain runtime is unavailable")
        }
        Ok(())
    }

    async fn health_interfaces(&self, desired: &RouterDesired) -> Result<()>;
    async fn health_uplink_wifi(&self, desired: &RouterDesired) -> Result<()> {
        if desired.uplink_wifi.is_some() {
            anyhow::bail!("uplink Wi-Fi runtime is unavailable")
        }
        Ok(())
    }
    async fn health_output_wifi(&self, desired: &RouterDesired) -> Result<()> {
        if !desired.output_wifi.is_empty() {
            anyhow::bail!("output Wi-Fi runtime is unavailable")
        }
        Ok(())
    }
    async fn health_routes(&self, desired: &RouterDesired) -> Result<()>;
    async fn health_dhcp(&self, desired: &RouterDesired) -> Result<()>;
    async fn health_uplink_dhcp(&self, desired: &RouterDesired) -> Option<RouterDhcpHealthReason>;
    async fn health_dataplane(&self, desired: &RouterDesired) -> Result<()>;
    async fn health_vpn_chain(&self, desired: &RouterDesired) -> Result<()> {
        if !desired.vpn_chain.is_empty() {
            anyhow::bail!("VPN chain runtime is unavailable")
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterApplyError {
    pub original: String,
    pub rollback_failures: Vec<String>,
}

impl fmt::Display for RouterApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "router apply failed: {}", self.original)?;
        if !self.rollback_failures.is_empty() {
            write!(
                formatter,
                "; rollback failures: {}",
                self.rollback_failures.join("; ")
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for RouterApplyError {}

#[derive(Clone)]
pub struct RouterManager {
    subsystems: Arc<dyn RouterSubsystems>,
    dhcp_readiness_timeout: std::time::Duration,
    dhcp_readiness_poll: std::time::Duration,
}

impl RouterManager {
    pub fn new(subsystems: Arc<dyn RouterSubsystems>) -> Self {
        Self {
            subsystems,
            dhcp_readiness_timeout: std::time::Duration::from_secs(5),
            dhcp_readiness_poll: std::time::Duration::from_millis(100),
        }
    }

    pub fn with_dhcp_readiness_timing(
        mut self,
        timeout: std::time::Duration,
        poll: std::time::Duration,
    ) -> Self {
        self.dhcp_readiness_timeout = timeout;
        self.dhcp_readiness_poll = poll;
        self
    }

    /// Inspect router subsystems and prepare the ordered operations required by desired intent.
    pub async fn plan(&self, desired: RouterDesired) -> Result<RouterPlan> {
        self.preflight(&desired).await?;
        let RouterSubsystemPlan {
            interfaces,
            uplink_wifi,
            output_wifi,
            routes,
            dhcp,
            vpn_chain,
            dataplane,
        } = self.subsystems.plan_for(&desired).await?;
        let risk = RouterRisk {
            changes_default_route: routes.changes_default_route(),
            requires_management_confirmation: interfaces
                .iter()
                .any(|change| change.management_change),
        };
        Ok(RouterPlan {
            desired,
            interfaces,
            uplink_wifi,
            output_wifi,
            dhcp,
            routes,
            vpn_chain,
            dataplane,
            risk,
        })
    }

    /// Collect subsystem health against desired intent, preserving individual failure reasons.
    pub async fn health(&self, desired: &RouterDesired) -> RouterHealthReport {
        RouterHealthReport {
            interfaces: if let Err(error) = self.subsystems.health_interfaces(desired).await {
                Some(format!("{error:#}"))
            } else if let Err(error) = self.subsystems.health_uplink_wifi(desired).await {
                Some(format!("uplink Wi-Fi: {error:#}"))
            } else if let Err(error) = self.subsystems.health_output_wifi(desired).await {
                Some(format!("output Wi-Fi: {error:#}"))
            } else {
                None
            },
            routes: self
                .subsystems
                .health_routes(desired)
                .await
                .err()
                .map(|error| format!("{error:#}")),
            dhcp: self
                .subsystems
                .health_dhcp(desired)
                .await
                .err()
                .map(|error| format!("{error:#}")),
            uplink_dhcp: self.subsystems.health_uplink_dhcp(desired).await,
            dataplane: self
                .subsystems
                .health_dataplane(desired)
                .await
                .err()
                .map(|error| format!("{error:#}")),
        }
    }

    /// rtnetlink route and policy-rule notifications cover the kernel routing
    /// side. nftables integrity is audited separately because it has no
    /// rtnetlink event. Check health first so our own notifications do not
    /// trigger a write loop.
    pub async fn dataplane_needs_reconcile(&self, desired: &RouterDesired) -> bool {
        self.subsystems.health_routes(desired).await.is_err()
            || self.subsystems.health_vpn_chain(desired).await.is_err()
            || self.subsystems.health_dataplane(desired).await.is_err()
    }

    pub async fn cleanup_removed_dataplane(&self, desired: &RouterDesired) -> Result<()> {
        self.subsystems.cleanup_removed_dataplane(desired).await
    }

    /// Repair route and firewall drift for the supplied committed router intent.
    pub async fn reconcile_dataplane(&self, desired: &RouterDesired) -> Result<()> {
        self.preflight(desired).await?;
        if self.subsystems.health_vpn_chain(desired).await.is_err() {
            let plan = self.subsystems.plan_vpn_chain(desired).await?;
            self.subsystems.apply_vpn_chain(&plan).await?;
            self.subsystems.health_vpn_chain(desired).await?;
        }
        if self.subsystems.health_routes(desired).await.is_err() {
            let plan = self.subsystems.plan_routes(desired).await?;
            self.subsystems.apply_routes(&plan).await?;
            self.subsystems.health_routes(desired).await?;
        }
        if self.subsystems.health_dataplane(desired).await.is_err() {
            let plan = self.subsystems.plan_dataplane(desired).await?;
            self.subsystems.apply_dataplane(&plan).await?;
            self.subsystems.health_dataplane(desired).await?;
        }
        Ok(())
    }

    /// Capture recovery state for the subsystems affected by the desired router intent.
    pub async fn snapshot_for(&self, desired: &RouterDesired) -> Result<RouterSnapshot> {
        self.subsystems.snapshot_for(desired).await
    }

    pub async fn prepare_recovery(&self, current: &RouterDesired) -> Result<()> {
        self.subsystems.prepare_recovery(current).await
    }

    pub async fn preflight(&self, desired: &RouterDesired) -> Result<()> {
        self.subsystems.preflight(desired).await
    }

    pub async fn retain_router_interfaces(&self, interfaces: &[String]) {
        self.subsystems.retain_router_interfaces(interfaces).await;
    }

    /// Apply router operations in dependency order and verify DHCP readiness before dependent work.
    pub async fn apply(&self, plan: &RouterPlan) -> Result<()> {
        self.apply_inner(plan, true).await
    }

    /// Execute under a coordinator-owned journal. The coordinator restores
    /// credentials before compensating runtime consumers on any failure.
    pub(crate) async fn apply_transaction(&self, plan: &RouterPlan) -> Result<()> {
        self.apply_inner(plan, false).await
    }

    async fn apply_inner(&self, plan: &RouterPlan, compensate: bool) -> Result<()> {
        self.preflight(&plan.desired).await?;
        // Ownership changes only when execution begins. A dry-run plan calls
        // snapshot_for too, and must not acquire resources merely by observing
        // them. Adopt before the apply snapshot so DHCP/Wi-Fi teardown covers
        // interfaces newly introduced by this intent.
        self.subsystems.adopt_router_interfaces(&plan.desired).await;
        let snapshot = if compensate {
            Some(self.snapshot_for(&plan.desired).await?)
        } else {
            None
        };
        let mut started = Vec::new();

        macro_rules! apply_stage {
            ($stage:expr, $operation:expr) => {{
                started.push($stage);
                if let Err(error) = $operation.await {
                    return Err(self
                        .rollback_error(error, snapshot.as_ref(), &started)
                        .await);
                }
            }};
        }

        // DHCP rollback has two phases. The restore marker is placed before
        // interfaces so old DHCP intent is restarted only after interface
        // rollback. Candidate DHCP is recorded after interfaces so it is
        // stopped before interface rollback. This also handles DHCP(A) ->
        // DHCP(B) without either actor racing restored address state.
        started.push(Stage::UplinkDhcpRestore);
        if let Err(error) = self
            .subsystems
            .quiesce_uplink_dhcp(plan.desired.uplink_dhcp.as_ref())
            .await
        {
            return Err(self
                .rollback_error(error, snapshot.as_ref(), &started)
                .await);
        }

        apply_stage!(
            Stage::Interfaces,
            self.subsystems.apply_interfaces(&plan.interfaces)
        );
        // A radio cannot run the old AP while its new station is starting.
        // Record this stage before stopping anything so an uplink failure
        // restores the AP too.
        let output_stops: Vec<_> = plan
            .output_wifi
            .iter()
            .filter(|item| matches!(item, WifiPlan::Stop { .. }))
            .cloned()
            .collect();
        if !output_stops.is_empty() {
            apply_stage!(
                Stage::OutputWifi,
                self.subsystems.apply_output_wifi(&output_stops)
            );
        }
        apply_stage!(
            Stage::UplinkWifi,
            self.subsystems.apply_uplink_wifi(&plan.uplink_wifi)
        );
        match self
            .subsystems
            .apply_uplink_dhcp_candidate(plan.desired.uplink_dhcp.as_ref())
            .await
        {
            Ok(true) => started.push(Stage::UplinkDhcpCandidate),
            Ok(false) => {}
            Err(error) => {
                // A failed apply may already have changed runtime state.
                started.push(Stage::UplinkDhcpCandidate);
                return Err(self
                    .rollback_error(error, snapshot.as_ref(), &started)
                    .await);
            }
        }
        apply_stage!(
            Stage::VpnChain,
            self.subsystems.apply_vpn_chain(&plan.vpn_chain)
        );
        if output_stops.is_empty() {
            started.push(Stage::OutputWifi);
        }
        let output_changes: Vec<_> = plan
            .output_wifi
            .iter()
            .filter(|item| !matches!(item, WifiPlan::Stop { .. }))
            .cloned()
            .collect();
        if let Err(error) = self.subsystems.apply_output_wifi(&output_changes).await {
            return Err(self
                .rollback_error(error, snapshot.as_ref(), &started)
                .await);
        }
        apply_stage!(Stage::Dhcp, self.subsystems.apply_dhcp(&plan.dhcp));
        apply_stage!(Stage::Routes, self.subsystems.apply_routes(&plan.routes));
        apply_stage!(
            Stage::Dataplane,
            self.subsystems.apply_dataplane(&plan.dataplane)
        );

        macro_rules! check_health {
            ($name:literal, $operation:expr) => {
                if let Err(error) = $operation.await {
                    let error = anyhow::anyhow!(concat!($name, " health failed: {}"), error);
                    return Err(self
                        .rollback_error(error, snapshot.as_ref(), &started)
                        .await);
                }
            };
        }
        check_health!(
            "interfaces",
            self.subsystems.health_interfaces(&plan.desired)
        );
        check_health!(
            "uplink Wi-Fi",
            self.subsystems.health_uplink_wifi(&plan.desired)
        );
        if plan.desired.uplink_dhcp.is_some() {
            let deadline = tokio::time::Instant::now() + self.dhcp_readiness_timeout;
            loop {
                let Some(reason) = self.subsystems.health_uplink_dhcp(&plan.desired).await else {
                    break;
                };
                if tokio::time::Instant::now() >= deadline {
                    let error = anyhow::anyhow!("uplink DHCP readiness timed out: {reason:?}");
                    return Err(self
                        .rollback_error(error, snapshot.as_ref(), &started)
                        .await);
                }
                tokio::time::sleep(self.dhcp_readiness_poll).await;
            }
        }
        check_health!(
            "output Wi-Fi",
            self.subsystems.health_output_wifi(&plan.desired)
        );
        check_health!("vpn_chain", self.subsystems.health_vpn_chain(&plan.desired));
        check_health!("dhcp", self.subsystems.health_dhcp(&plan.desired));
        check_health!("routes", self.subsystems.health_routes(&plan.desired));
        check_health!("dataplane", self.subsystems.health_dataplane(&plan.desired));
        Ok(())
    }

    async fn rollback_error(
        &self,
        original: anyhow::Error,
        snapshot: Option<&RouterSnapshot>,
        started: &[Stage],
    ) -> anyhow::Error {
        let rollback_failures = match snapshot {
            Some(snapshot) => self.rollback_stages(snapshot, started).await,
            None => Vec::new(),
        };
        RouterApplyError {
            original: format!("{original:#}"),
            rollback_failures,
        }
        .into()
    }

    /// Attempt subsystem restoration from the snapshot and collect all rollback failures.
    pub async fn rollback_to(&self, snapshot: &RouterSnapshot) -> Vec<String> {
        self.rollback_stages(
            snapshot,
            &[
                Stage::UplinkDhcpRestore,
                Stage::Interfaces,
                Stage::UplinkWifi,
                Stage::UplinkDhcpCandidate,
                Stage::VpnChain,
                Stage::OutputWifi,
                Stage::Dhcp,
                Stage::Routes,
                Stage::Dataplane,
            ],
        )
        .await
    }

    /// Preserve error types until the recovery policy has classified the failure.
    pub async fn rollback_to_classified(&self, snapshot: &RouterSnapshot) -> Result<()> {
        let errors = self
            .rollback_stages_classified(
                snapshot,
                &[
                    Stage::UplinkDhcpRestore,
                    Stage::Interfaces,
                    Stage::UplinkWifi,
                    Stage::UplinkDhcpCandidate,
                    Stage::VpnChain,
                    Stage::OutputWifi,
                    Stage::Dhcp,
                    Stage::Routes,
                    Stage::Dataplane,
                ],
            )
            .await;
        crate::core::recovery_control::aggregate(errors, "router rollback was incomplete")
    }

    async fn rollback_stages(&self, snapshot: &RouterSnapshot, stages: &[Stage]) -> Vec<String> {
        self.rollback_stages_classified(snapshot, stages)
            .await
            .into_iter()
            .map(|error| format!("{error:#}"))
            .collect()
    }

    async fn rollback_stages_classified(
        &self,
        snapshot: &RouterSnapshot,
        stages: &[Stage],
    ) -> Vec<anyhow::Error> {
        let mut rollback_failures = Vec::new();
        for stage in stages.iter().rev() {
            let result = match stage {
                Stage::Interfaces => {
                    self.subsystems
                        .rollback_interfaces(&snapshot.interfaces)
                        .await
                }
                Stage::UplinkWifi => {
                    self.subsystems
                        .rollback_uplink_wifi(&snapshot.uplink_wifi)
                        .await
                }
                Stage::UplinkDhcpCandidate => {
                    self.subsystems.rollback_candidate_uplink_dhcp().await
                }
                Stage::UplinkDhcpRestore => {
                    self.subsystems
                        .rollback_dhcp_clients(
                            &snapshot.dhcp_clients,
                            snapshot.uplink_dhcp.as_ref(),
                        )
                        .await
                }
                Stage::VpnChain => {
                    self.subsystems
                        .rollback_vpn_chain(&snapshot.vpn_chain)
                        .await
                }
                Stage::OutputWifi => {
                    self.subsystems
                        .rollback_output_wifi(&snapshot.output_wifi)
                        .await
                }
                Stage::Dhcp => {
                    self.subsystems
                        .rollback_dhcp_scoped(&snapshot.dhcp, &snapshot.dhcp_absent_interfaces)
                        .await
                }
                Stage::Routes => self.subsystems.rollback_routes(&snapshot.routes).await,
                Stage::Dataplane => {
                    self.subsystems
                        .rollback_dataplane(&snapshot.dataplane)
                        .await
                }
            };
            if let Err(error) = result {
                rollback_failures.push(error.context(stage.name()));
            }
        }
        rollback_failures
    }
}

#[derive(Clone, Copy)]
enum Stage {
    UplinkDhcpRestore,
    Interfaces,
    UplinkWifi,
    UplinkDhcpCandidate,
    VpnChain,
    OutputWifi,
    Dhcp,
    Routes,
    Dataplane,
}

impl Stage {
    fn name(self) -> &'static str {
        match self {
            Self::UplinkDhcpRestore => "uplink_dhcp_restore",
            Self::Interfaces => "interfaces",
            Self::UplinkWifi => "uplink_wifi",
            Self::UplinkDhcpCandidate => "uplink_dhcp_candidate",
            Self::VpnChain => "vpn_chain",
            Self::OutputWifi => "output_wifi",
            Self::Dhcp => "dhcp",
            Self::Routes => "routes",
            Self::Dataplane => "dataplane",
        }
    }
}

#[cfg(test)]
mod tests;
