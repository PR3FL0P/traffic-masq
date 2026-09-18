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
    pub fn from_effective_config(config: &AppConfig) -> Result<Self> {
        config.validate()?;
        let mut dhcp = DhcpSupervisor::service_specs(config)?;
        dhcp.sort_by(|left, right| left.interface.cmp(&right.interface));

        if !config.router.enabled {
            return Ok(Self {
                enabled: false,
                uplink_wifi: None,
                uplink_dhcp: None,
                output_wifi: Vec::new(),
                dhcp,
                routes: Vec::new(),
                // Disabling the router still removes its owned routes, so
                // retain explicit permission to delete an owned default route.
                allow_default_route_change: config.router.allow_default_route_change,
                vpn_chain: Vec::new(),
                dataplane: RouterDataplaneTarget::Disabled,
                interfaces: Vec::new(),
            });
        }

        let routes = desired_owned_routes(&config.router);
        let allow_default_route_change = config.router.allow_default_route_change;

        let managed_outputs: Vec<(&String, &InterfaceConfig)> = config
            .network
            .interfaces
            .iter()
            .filter(|(_, interface)| interface.role == InterfaceRole::Output && interface.managed)
            .collect();

        if let Some(forwarding) = &config.router.forwarding {
            let mut interfaces: Vec<_> = managed_outputs
                .iter()
                .map(|(name, interface)| RouterInterfaceDesired {
                    name: (*name).clone(),
                    config: (*interface).clone(),
                })
                .collect();
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
            let output_wifi = interfaces
                .iter()
                .filter_map(|interface| {
                    WifiApSpec::from_interface_config(&interface.name, &interface.config)
                        .transpose()
                })
                .collect::<Result<Vec<_>>>()?;
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
            let interfaces: Vec<_> = managed_outputs
                .into_iter()
                .map(|(name, interface)| RouterInterfaceDesired {
                    name: name.clone(),
                    config: interface.clone(),
                })
                .collect();

            let mut output_wifi = interfaces
                .iter()
                .filter_map(|interface| {
                    WifiApSpec::from_interface_config(&interface.name, &interface.config)
                        .transpose()
                })
                .collect::<Result<Vec<_>>>()?;
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
            .filter(|(_, interface)| interface.nat)
            .map(|(name, interface)| OutputNetwork {
                interface: (*name).clone(),
                subnet: interface
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
        interfaces.extend(managed_outputs.into_iter().map(|(name, interface)| {
            RouterInterfaceDesired {
                name: name.clone(),
                config: interface.clone(),
            }
        }));

        let uplink_wifi = WifiClientSpec::from_interface_config(&uplink.interface, uplink_config)?;
        let mut output_wifi = interfaces
            .iter()
            .filter_map(|interface| {
                WifiApSpec::from_interface_config(&interface.name, &interface.config).transpose()
            })
            .collect::<Result<Vec<_>>>()?;
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RouterHealthReport {
    pub interfaces: Option<String>,
    pub routes: Option<String>,
    pub dhcp: Option<String>,

    pub uplink_dhcp: Option<RouterDhcpHealthReason>,
    pub dataplane: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum RouterDhcpHealthReason {
    IntentMissing { interface: String },
    IntentMismatch { interface: String },
    Waiting { interface: String },
    Degraded { interface: String, detail: String },
    LeaseMissing { interface: String },
    LeaseNotBound { interface: String },
    LeaseExpired { interface: String },
    ObservationMismatch { interface: String, detail: String },
}

impl RouterHealthReport {
    pub fn ready(&self) -> bool {
        self.interfaces.is_none()
            && self.routes.is_none()
            && self.dhcp.is_none()
            && self.uplink_dhcp.is_none()
            && self.dataplane.is_none()
    }
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
pub struct RouterSnapshot {
    pub interfaces: Vec<InterfaceSnapshot>,
    pub uplink_wifi: Vec<WifiSnapshot<WifiClientSpec>>,
    pub uplink_dhcp: Option<DhcpClientSpec>,
    pub output_wifi: Vec<WifiSnapshot<WifiApSpec>>,
    pub dhcp: Vec<DhcpServiceSpec>,

    pub dhcp_absent_interfaces: Vec<String>,
    pub routes: RouteSnapshot,
    pub vpn_chain: VpnChainSnapshot,
    pub dataplane: RouterDataplaneSnapshot,
}

#[async_trait]
pub trait RouterSubsystems: Send + Sync {
    /// Rebuild volatile ownership/runtime bookkeeping from durable proofs
    /// before crash recovery or startup repair touches the data plane.
    /// Implementations must not adopt resources without an ownership proof.
    async fn prepare_recovery(&self, _current: &RouterDesired) -> Result<()> {
        Ok(())
    }

    async fn plan_interfaces(&self, desired: &RouterDesired) -> Result<Vec<InterfaceChangePlan>>;
    async fn plan_uplink_wifi(
        &self,
        desired: &RouterDesired,
    ) -> Result<Vec<WifiPlan<WifiClientSpec>>> {
        if desired.uplink_wifi.is_some() {
            anyhow::bail!("uplink Wi-Fi runtime is unavailable")
        }
        Ok(Vec::new())
    }
    async fn plan_output_wifi(&self, desired: &RouterDesired) -> Result<Vec<WifiPlan<WifiApSpec>>> {
        if !desired.output_wifi.is_empty() {
            anyhow::bail!("output Wi-Fi runtime is unavailable")
        }
        Ok(Vec::new())
    }
    async fn plan_routes(&self, desired: &RouterDesired) -> Result<RoutePlan>;
    async fn plan_dhcp(&self, desired: &RouterDesired) -> Result<Vec<DhcpPlan>>;
    async fn plan_dataplane(&self, desired: &RouterDesired) -> Result<RouterDataplanePlan>;

    /// Plan the VPN hop chain. Mirrors the `uplink_wifi`/`output_wifi`
    /// default pattern: a subsystem implementor that doesn't support
    /// chaining safely no-ops when there is nothing to chain, and errors
    /// only if the desired state actually wants one.
    async fn plan_vpn_chain(&self, desired: &RouterDesired) -> Result<VpnChainPlan> {
        if !desired.vpn_chain.is_empty() {
            anyhow::bail!("VPN chain runtime is unavailable")
        }
        Ok(VpnChainPlan::empty())
    }

    async fn snapshot_interfaces(&self) -> Result<Vec<InterfaceSnapshot>>;
    async fn snapshot_uplink_wifi(&self) -> Result<Vec<WifiSnapshot<WifiClientSpec>>> {
        Ok(Vec::new())
    }
    async fn snapshot_output_wifi(&self) -> Result<Vec<WifiSnapshot<WifiApSpec>>> {
        Ok(Vec::new())
    }
    async fn snapshot_routes(&self) -> Result<RouteSnapshot>;
    async fn snapshot_dhcp(&self) -> Result<Vec<DhcpServiceSpec>>;
    async fn snapshot_dataplane(&self) -> Result<RouterDataplaneSnapshot>;
    async fn snapshot_uplink_dhcp(&self) -> Result<Option<DhcpClientSpec>> {
        Ok(None)
    }
    async fn snapshot_vpn_chain(&self) -> Result<VpnChainSnapshot> {
        Ok(VpnChainSnapshot::empty())
    }

    /// Narrow ownership to exactly these interfaces.
    ///
    /// Called once a transaction settles, so the owned set tracks the intent
    /// that is actually in force instead of accumulating every interface that
    /// was ever part of one. Doing nothing is correct for a subsystem that
    /// keeps no such record.
    async fn retain_router_interfaces(&self, _interfaces: &[String]) {}

    async fn snapshot_for(&self, _desired: &RouterDesired) -> Result<RouterSnapshot> {
        Ok(RouterSnapshot {
            interfaces: self.snapshot_interfaces().await?,
            uplink_wifi: self.snapshot_uplink_wifi().await?,
            uplink_dhcp: self.snapshot_uplink_dhcp().await?,
            output_wifi: self.snapshot_output_wifi().await?,
            routes: self.snapshot_routes().await?,
            dhcp: self.snapshot_dhcp().await?,
            dhcp_absent_interfaces: Vec::new(),
            vpn_chain: self.snapshot_vpn_chain().await?,
            dataplane: self.snapshot_dataplane().await?,
        })
    }

    async fn apply_interfaces(&self, plan: &[InterfaceChangePlan]) -> Result<()>;
    async fn apply_uplink_wifi(&self, plan: &[WifiPlan<WifiClientSpec>]) -> Result<()> {
        if !plan.is_empty() {
            anyhow::bail!("uplink Wi-Fi runtime is unavailable")
        }
        Ok(())
    }
    async fn apply_output_wifi(&self, plan: &[WifiPlan<WifiApSpec>]) -> Result<()> {
        if !plan.is_empty() {
            anyhow::bail!("output Wi-Fi runtime is unavailable")
        }
        Ok(())
    }
    async fn apply_routes(&self, plan: &RoutePlan) -> Result<()>;
    async fn apply_dhcp(&self, plan: &[DhcpPlan]) -> Result<()>;
    async fn apply_dataplane(&self, plan: &RouterDataplanePlan) -> Result<()>;
    async fn apply_uplink_dhcp(&self, _desired: Option<&DhcpClientSpec>) -> Result<()> {
        Ok(())
    }
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

    async fn rollback_interfaces(&self, snapshot: &[InterfaceSnapshot]) -> Result<()>;
    async fn rollback_uplink_wifi(&self, snapshot: &[WifiSnapshot<WifiClientSpec>]) -> Result<()> {
        if !snapshot.is_empty() {
            anyhow::bail!("uplink Wi-Fi runtime is unavailable")
        }
        Ok(())
    }
    async fn rollback_output_wifi(&self, snapshot: &[WifiSnapshot<WifiApSpec>]) -> Result<()> {
        if !snapshot.is_empty() {
            anyhow::bail!("output Wi-Fi runtime is unavailable")
        }
        Ok(())
    }
    async fn rollback_routes(&self, snapshot: &RouteSnapshot) -> Result<()>;
    async fn rollback_dhcp(&self, snapshot: &[DhcpServiceSpec]) -> Result<()>;
    async fn rollback_dhcp_scoped(
        &self,
        snapshot: &[DhcpServiceSpec],
        _previously_absent: &[String],
    ) -> Result<()> {
        self.rollback_dhcp(snapshot).await
    }
    async fn rollback_dataplane(&self, snapshot: &RouterDataplaneSnapshot) -> Result<()>;
    async fn rollback_uplink_dhcp(&self, _snapshot: Option<&DhcpClientSpec>) -> Result<()> {
        Ok(())
    }
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
    async fn health_uplink_dhcp(&self, _desired: &RouterDesired) -> Option<RouterDhcpHealthReason> {
        None
    }
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

    pub async fn plan(&self, desired: RouterDesired) -> Result<RouterPlan> {
        let interfaces = self.subsystems.plan_interfaces(&desired).await?;
        let uplink_wifi = self.subsystems.plan_uplink_wifi(&desired).await?;
        let output_wifi = self.subsystems.plan_output_wifi(&desired).await?;
        let routes = self.subsystems.plan_routes(&desired).await?;
        let dhcp = self.subsystems.plan_dhcp(&desired).await?;
        let vpn_chain = self.subsystems.plan_vpn_chain(&desired).await?;
        let dataplane = self.subsystems.plan_dataplane(&desired).await?;
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

    pub async fn health(&self, desired: &RouterDesired) -> RouterHealthReport {
        RouterHealthReport {
            interfaces: if let Err(error) = self.subsystems.health_interfaces(desired).await {
                Some(error.to_string())
            } else if let Err(error) = self.subsystems.health_uplink_wifi(desired).await {
                Some(format!("uplink Wi-Fi: {error}"))
            } else if let Err(error) = self.subsystems.health_output_wifi(desired).await {
                Some(format!("output Wi-Fi: {error}"))
            } else {
                None
            },
            routes: self
                .subsystems
                .health_routes(desired)
                .await
                .err()
                .map(|error| error.to_string()),
            dhcp: self
                .subsystems
                .health_dhcp(desired)
                .await
                .err()
                .map(|error| error.to_string()),
            uplink_dhcp: self.subsystems.health_uplink_dhcp(desired).await,
            dataplane: self
                .subsystems
                .health_dataplane(desired)
                .await
                .err()
                .map(|error| error.to_string()),
        }
    }

    pub async fn snapshot(&self) -> Result<RouterSnapshot> {
        Ok(RouterSnapshot {
            interfaces: self.subsystems.snapshot_interfaces().await?,
            uplink_wifi: self.subsystems.snapshot_uplink_wifi().await?,
            uplink_dhcp: self.subsystems.snapshot_uplink_dhcp().await?,
            output_wifi: self.subsystems.snapshot_output_wifi().await?,
            routes: self.subsystems.snapshot_routes().await?,
            dhcp: self.subsystems.snapshot_dhcp().await?,
            dhcp_absent_interfaces: Vec::new(),
            vpn_chain: self.subsystems.snapshot_vpn_chain().await?,
            dataplane: self.subsystems.snapshot_dataplane().await?,
        })
    }

    pub async fn snapshot_for(&self, desired: &RouterDesired) -> Result<RouterSnapshot> {
        self.subsystems.snapshot_for(desired).await
    }

    pub async fn prepare_recovery(&self, current: &RouterDesired) -> Result<()> {
        self.subsystems.prepare_recovery(current).await
    }

    pub async fn retain_router_interfaces(&self, interfaces: &[String]) {
        self.subsystems.retain_router_interfaces(interfaces).await;
    }

    pub async fn apply(&self, plan: &RouterPlan) -> Result<()> {
        let snapshot = self.snapshot_for(&plan.desired).await?;
        let mut started = Vec::new();

        macro_rules! apply_stage {
            ($stage:expr, $operation:expr) => {{
                started.push($stage);
                if let Err(error) = $operation.await {
                    return Err(self.rollback_error(error, &snapshot, &started).await.into());
                }
            }};
        }

        apply_stage!(
            Stage::Interfaces,
            self.subsystems.apply_interfaces(&plan.interfaces)
        );
        apply_stage!(
            Stage::UplinkWifi,
            self.subsystems.apply_uplink_wifi(&plan.uplink_wifi)
        );
        apply_stage!(
            Stage::UplinkDhcp,
            self.subsystems
                .apply_uplink_dhcp(plan.desired.uplink_dhcp.as_ref())
        );
        apply_stage!(
            Stage::VpnChain,
            self.subsystems.apply_vpn_chain(&plan.vpn_chain)
        );
        apply_stage!(
            Stage::OutputWifi,
            self.subsystems.apply_output_wifi(&plan.output_wifi)
        );
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
                    return Err(self.rollback_error(error, &snapshot, &started).await.into());
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
                if self
                    .subsystems
                    .health_uplink_dhcp(&plan.desired)
                    .await
                    .is_none()
                {
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    let reason = self
                        .subsystems
                        .health_uplink_dhcp(&plan.desired)
                        .await
                        .expect("DHCP uplink remained unready");
                    let error = anyhow::anyhow!("uplink DHCP readiness timed out: {reason:?}");
                    return Err(self.rollback_error(error, &snapshot, &started).await.into());
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
        snapshot: &RouterSnapshot,
        started: &[Stage],
    ) -> RouterApplyError {
        RouterApplyError {
            original: original.to_string(),
            rollback_failures: self.rollback_stages(snapshot, started).await,
        }
    }

    pub async fn rollback_to(&self, snapshot: &RouterSnapshot) -> Vec<String> {
        self.rollback_stages(
            snapshot,
            &[
                Stage::Interfaces,
                Stage::UplinkWifi,
                Stage::UplinkDhcp,
                Stage::VpnChain,
                Stage::OutputWifi,
                Stage::Dhcp,
                Stage::Routes,
                Stage::Dataplane,
            ],
        )
        .await
    }

    async fn rollback_stages(&self, snapshot: &RouterSnapshot, stages: &[Stage]) -> Vec<String> {
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
                Stage::UplinkDhcp => {
                    self.subsystems
                        .rollback_uplink_dhcp(snapshot.uplink_dhcp.as_ref())
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
                rollback_failures.push(format!("{}: {error}", stage.name()));
            }
        }
        rollback_failures
    }
}

#[derive(Clone, Copy)]
enum Stage {
    Interfaces,
    UplinkWifi,
    UplinkDhcp,
    VpnChain,
    OutputWifi,
    Dhcp,
    Routes,
    Dataplane,
}

impl Stage {
    fn name(self) -> &'static str {
        match self {
            Self::Interfaces => "interfaces",
            Self::UplinkWifi => "uplink_wifi",
            Self::UplinkDhcp => "uplink_dhcp",
            Self::VpnChain => "vpn_chain",
            Self::OutputWifi => "output_wifi",
            Self::Dhcp => "dhcp",
            Self::Routes => "routes",
            Self::Dataplane => "dataplane",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    use crate::config::{
        DhcpClientInterfaceConfig, DhcpInterfaceConfig, InterfaceConfig, RouterConfig,
        UplinkConfig, UplinkMode,
    };
    use crate::core::interface::DhcpChangeAction;
    use crate::firewall::OwnedFirewallIntegrity;
    use crate::netlink::{Ipv4RouteSpec, TRAFFIC_MASQ_ROUTE_PROTOCOL};

    use super::*;

    fn enabled_config() -> AppConfig {
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
                nat: true,
            },
        );
        for (name, address, pool_start, pool_end) in [
            ("lan0", "192.168.10.1/24", 100, 150),
            ("lan1", "192.168.20.1/24", 100, 150),
        ] {
            let ipv4: ipnet::Ipv4Net = address.parse().expect("IPv4 network");
            let octet = ipv4.addr().octets()[2];
            config.network.interfaces.insert(
                name.to_string(),
                InterfaceConfig {
                    role: InterfaceRole::Output,
                    managed: true,
                    ipv4: Some(ipv4),
                    dhcp: Some(DhcpInterfaceConfig {
                        pool_start: Ipv4Addr::new(192, 168, octet, pool_start),
                        pool_end: Ipv4Addr::new(192, 168, octet, pool_end),
                        router: ipv4.addr(),
                        dns_servers: Vec::new(),
                        lease_seconds: None,
                    }),
                    dhcp_client: None,
                    wifi: None,
                    wifi_client: None,
                    nat: true,
                },
            );
        }
        config.router = RouterConfig {
            forwarding: None,
            vpn_chain: Vec::new(),
            enabled: true,
            uplink: Some(UplinkConfig {
                interface: "wan0".to_string(),
                mode: UplinkMode::External,
            }),
            owned_routes: vec![crate::config::OwnedIpv4RouteConfig {
                destination: "203.0.113.0/24".parse().expect("route"),
                gateway: None,
                output_interface: Some("wan0".to_string()),
                table: 254,
                metric: Some(100),
            }],
            allow_default_route_change: false,
        };
        config
    }

    #[test]
    fn explicit_connections_replace_legacy_nat_and_empty_does_not_restore_it() {
        let mut config = enabled_config();
        let connections = vec![crate::config::ForwardingConfig {
            source_subnet: None,
            from: "lan0".into(),
            to: "wg0".into(),
            masquerade: false,
        }];
        config.router.forwarding = Some(connections.clone());
        let desired = RouterDesired::from_effective_config(&config).unwrap();
        let RouterDataplaneTarget::Enabled(dataplane) = desired.dataplane else {
            panic!("enabled");
        };
        assert_eq!(dataplane.forwarding, Some(connections));
        assert!(dataplane.outputs.is_empty());
        assert!(dataplane.uplink.is_empty());
        assert_eq!(desired.dhcp.len(), 2);
        assert_eq!(desired.routes.len(), 1);
        config.router.forwarding = Some(vec![]);
        assert_eq!(
            RouterDesired::from_effective_config(&config)
                .unwrap()
                .dataplane,
            RouterDataplaneTarget::Disabled
        );
    }

    #[test]
    fn builds_enabled_router_desired_from_one_effective_config() {
        let desired = RouterDesired::from_effective_config(&enabled_config()).expect("desired");
        assert!(desired.enabled);
        assert!(desired.uplink_wifi.is_none());
        assert!(desired.output_wifi.is_empty());
        assert_eq!(desired.dhcp.len(), 2);
        assert_eq!(desired.routes.len(), 1);
        assert!(!desired.allow_default_route_change);
        assert_eq!(
            desired.dataplane,
            RouterDataplaneTarget::Enabled(RouterDataplaneDesired {
                forwarding: None,
                uplink: "wan0".to_string(),
                outputs: vec![
                    OutputNetwork {
                        interface: "lan0".to_string(),
                        subnet: "192.168.10.0/24".parse().expect("subnet"),
                    },
                    OutputNetwork {
                        interface: "lan1".to_string(),
                        subnet: "192.168.20.0/24".parse().expect("subnet"),
                    },
                ],
            })
        );
    }

    #[test]
    fn dhcp_uplink_desired_requires_the_exact_client_intent() {
        let mut config = enabled_config();
        let uplink = config.network.interfaces.get_mut("wan0").unwrap();
        uplink.managed = true;
        uplink.dhcp_client = Some(DhcpClientInterfaceConfig {
            route_metric: 321,
            request_dns: false,
            ..DhcpClientInterfaceConfig::default()
        });
        config.router.uplink.as_mut().unwrap().mode = UplinkMode::Dhcp;

        let desired = RouterDesired::from_effective_config(&config).expect("desired");
        let intent = desired.uplink_dhcp.expect("DHCP uplink intent");
        assert_eq!(intent.interface, "wan0");
        assert_eq!(intent.route_metric, 321);
        assert!(!intent.request_dns);
    }

    #[test]
    fn switching_to_connections_preserves_existing_uplink_services() {
        let mut config = enabled_config();
        let uplink = config.network.interfaces.get_mut("wan0").unwrap();
        uplink.managed = true;
        uplink.dhcp_client = Some(DhcpClientInterfaceConfig::default());
        config.router.uplink.as_mut().unwrap().mode = UplinkMode::Dhcp;
        let before = RouterDesired::from_effective_config(&config).unwrap();
        config.router.forwarding = Some(vec![]);
        let after = RouterDesired::from_effective_config(&config).unwrap();
        assert_eq!(after.uplink_dhcp, before.uplink_dhcp);
        assert_eq!(after.uplink_wifi, before.uplink_wifi);
        assert_eq!(after.output_wifi, before.output_wifi);
        assert_eq!(after.dhcp, before.dhcp);
        assert_eq!(after.interfaces.len(), before.interfaces.len());
    }

    #[test]
    fn disabled_router_does_not_claim_routes_or_dataplane() {
        let mut config = enabled_config();
        config.router.enabled = false;
        let desired = RouterDesired::from_effective_config(&config).expect("desired");
        assert!(!desired.enabled);
        assert!(desired.uplink_wifi.is_none());
        assert!(desired.output_wifi.is_empty());
        assert_eq!(desired.dhcp.len(), 2);
        assert!(desired.routes.is_empty());
        assert!(!desired.allow_default_route_change);
        assert_eq!(desired.dataplane, RouterDataplaneTarget::Disabled);
    }

    #[test]
    fn enabled_router_without_uplink_claims_routes_with_disabled_dataplane() {
        let mut config = enabled_config();
        config.router.uplink = None;

        let desired = RouterDesired::from_effective_config(&config).expect("desired");

        assert!(desired.enabled);
        assert_eq!(desired.interfaces.len(), 2);
        assert_eq!(desired.routes.len(), 1);
        assert!(desired.uplink_wifi.is_none());
        assert!(desired.uplink_dhcp.is_none());
        assert_eq!(desired.dataplane, RouterDataplaneTarget::Disabled);
    }

    struct FakeSubsystems {
        events: Mutex<Vec<String>>,
        fail: Mutex<Option<String>>,
        rollback_fail: Mutex<Option<String>>,
        default_route: bool,
    }

    impl FakeSubsystems {
        fn new(fail: Option<&str>) -> Arc<Self> {
            Arc::new(Self {
                events: Mutex::new(Vec::new()),
                fail: Mutex::new(fail.map(str::to_string)),
                rollback_fail: Mutex::new(None),
                default_route: false,
            })
        }

        fn with_default_route() -> Arc<Self> {
            Arc::new(Self {
                events: Mutex::new(Vec::new()),
                fail: Mutex::new(None),
                rollback_fail: Mutex::new(None),
                default_route: true,
            })
        }

        fn event(&self, event: &str) -> Result<()> {
            self.events.lock().unwrap().push(event.to_string());
            if self.fail.lock().unwrap().as_deref() == Some(event) {
                anyhow::bail!("injected {event} failure");
            }
            if event.starts_with("rollback_")
                && self.rollback_fail.lock().unwrap().as_deref() == Some(event)
            {
                anyhow::bail!("injected {event} failure");
            }
            Ok(())
        }

        fn events(&self) -> Vec<String> {
            self.events.lock().unwrap().clone()
        }
    }

    fn dataplane_snapshot() -> RouterDataplaneSnapshot {
        RouterDataplaneSnapshot {
            ipv4_forwarding: false,
            owned: None,
            owned_firewall_integrity: OwnedFirewallIntegrity::Intact,
        }
    }

    fn plan() -> RouterPlan {
        let desired = RouterDesired::from_effective_config(&enabled_config()).unwrap();
        RouterPlan {
            desired: desired.clone(),
            interfaces: vec![InterfaceChangePlan {
                interface: "lan0".into(),
                delete_ipv4: Vec::new(),
                retag_ipv4: None,
                add_ipv4: None,
                set_link_up: false,
                management_change: false,
                dhcp_action: DhcpChangeAction::Unchanged,
                releasing_management: false,
            }],
            uplink_wifi: Vec::new(),
            output_wifi: Vec::new(),
            dhcp: Vec::new(),
            routes: RoutePlan {
                add: Vec::new(),
                delete: Vec::new(),
            },
            vpn_chain: VpnChainPlan::empty(),
            dataplane: RouterDataplanePlan {
                snapshot: dataplane_snapshot(),
                target: desired.dataplane,
                requires_apply: true,
            },
            risk: RouterRisk::default(),
        }
    }

    #[async_trait]
    impl RouterSubsystems for FakeSubsystems {
        async fn plan_interfaces(&self, _: &RouterDesired) -> Result<Vec<InterfaceChangePlan>> {
            self.event("plan_interfaces")?;
            Ok(plan().interfaces)
        }
        async fn plan_uplink_wifi(
            &self,
            _: &RouterDesired,
        ) -> Result<Vec<WifiPlan<WifiClientSpec>>> {
            self.event("plan_uplink_wifi")?;
            Ok(Vec::new())
        }
        async fn plan_output_wifi(&self, _: &RouterDesired) -> Result<Vec<WifiPlan<WifiApSpec>>> {
            self.event("plan_output_wifi")?;
            Ok(Vec::new())
        }
        async fn plan_routes(&self, _: &RouterDesired) -> Result<RoutePlan> {
            self.event("plan_routes")?;
            let add = self.default_route.then(|| Ipv4RouteSpec {
                destination: "0.0.0.0/0".parse().unwrap(),
                gateway: None,
                output_interface_index: Some(1),
                table: 254,
                metric: None,
                protocol: TRAFFIC_MASQ_ROUTE_PROTOCOL,
            });
            Ok(RoutePlan {
                add: add.into_iter().collect(),
                delete: Vec::new(),
            })
        }
        async fn plan_dhcp(&self, _: &RouterDesired) -> Result<Vec<DhcpPlan>> {
            self.event("plan_dhcp")?;
            Ok(Vec::new())
        }
        async fn plan_dataplane(&self, desired: &RouterDesired) -> Result<RouterDataplanePlan> {
            self.event("plan_dataplane")?;
            Ok(RouterDataplanePlan {
                snapshot: dataplane_snapshot(),
                target: desired.dataplane.clone(),
                requires_apply: true,
            })
        }
        async fn snapshot_interfaces(&self) -> Result<Vec<InterfaceSnapshot>> {
            self.event("snapshot_interfaces")?;
            Ok(Vec::new())
        }
        async fn snapshot_uplink_wifi(&self) -> Result<Vec<WifiSnapshot<WifiClientSpec>>> {
            self.event("snapshot_uplink_wifi")?;
            Ok(Vec::new())
        }
        async fn snapshot_output_wifi(&self) -> Result<Vec<WifiSnapshot<WifiApSpec>>> {
            self.event("snapshot_output_wifi")?;
            Ok(Vec::new())
        }
        async fn snapshot_routes(&self) -> Result<RouteSnapshot> {
            self.event("snapshot_routes")?;
            Ok(RouteSnapshot::empty())
        }
        async fn snapshot_dhcp(&self) -> Result<Vec<DhcpServiceSpec>> {
            self.event("snapshot_dhcp")?;
            Ok(Vec::new())
        }
        async fn snapshot_dataplane(&self) -> Result<RouterDataplaneSnapshot> {
            self.event("snapshot_dataplane")?;
            Ok(dataplane_snapshot())
        }
        async fn apply_interfaces(&self, _: &[InterfaceChangePlan]) -> Result<()> {
            self.event("apply_interfaces")
        }
        async fn apply_uplink_wifi(&self, _: &[WifiPlan<WifiClientSpec>]) -> Result<()> {
            self.event("apply_uplink_wifi")
        }
        async fn apply_output_wifi(&self, _: &[WifiPlan<WifiApSpec>]) -> Result<()> {
            self.event("apply_output_wifi")
        }
        async fn apply_routes(&self, _: &RoutePlan) -> Result<()> {
            self.event("apply_routes")
        }
        async fn apply_dhcp(&self, _: &[DhcpPlan]) -> Result<()> {
            self.event("apply_dhcp")
        }
        async fn apply_dataplane(&self, _: &RouterDataplanePlan) -> Result<()> {
            self.event("apply_dataplane")
        }
        async fn rollback_interfaces(&self, _: &[InterfaceSnapshot]) -> Result<()> {
            self.event("rollback_interfaces")
        }
        async fn rollback_uplink_wifi(&self, _: &[WifiSnapshot<WifiClientSpec>]) -> Result<()> {
            self.event("rollback_uplink_wifi")
        }
        async fn rollback_output_wifi(&self, _: &[WifiSnapshot<WifiApSpec>]) -> Result<()> {
            self.event("rollback_output_wifi")
        }
        async fn rollback_routes(&self, _: &RouteSnapshot) -> Result<()> {
            self.event("rollback_routes")
        }
        async fn rollback_dhcp(&self, _: &[DhcpServiceSpec]) -> Result<()> {
            self.event("rollback_dhcp")
        }
        async fn rollback_dataplane(&self, _: &RouterDataplaneSnapshot) -> Result<()> {
            self.event("rollback_dataplane")
        }
        async fn health_interfaces(&self, _: &RouterDesired) -> Result<()> {
            self.event("health_interfaces")
        }
        async fn health_uplink_wifi(&self, _: &RouterDesired) -> Result<()> {
            self.event("health_uplink_wifi")
        }
        async fn health_output_wifi(&self, _: &RouterDesired) -> Result<()> {
            self.event("health_output_wifi")
        }
        async fn health_routes(&self, _: &RouterDesired) -> Result<()> {
            self.event("health_routes")
        }
        async fn health_dhcp(&self, _: &RouterDesired) -> Result<()> {
            self.event("health_dhcp")
        }
        async fn health_dataplane(&self, _: &RouterDesired) -> Result<()> {
            self.event("health_dataplane")
        }
    }

    #[tokio::test]
    async fn snapshots_before_first_mutation_and_exact_success_order() {
        let fake = FakeSubsystems::new(None);
        RouterManager::new(fake.clone())
            .apply(&plan())
            .await
            .unwrap();
        assert_eq!(
            fake.events(),
            [
                "snapshot_interfaces",
                "snapshot_uplink_wifi",
                "snapshot_output_wifi",
                "snapshot_routes",
                "snapshot_dhcp",
                "snapshot_dataplane",
                "apply_interfaces",
                "apply_uplink_wifi",
                "apply_output_wifi",
                "apply_dhcp",
                "apply_routes",
                "apply_dataplane",
                "health_interfaces",
                "health_uplink_wifi",
                "health_output_wifi",
                "health_dhcp",
                "health_routes",
                "health_dataplane",
            ]
        );
    }

    #[tokio::test]
    async fn every_stage_and_health_failure_rolls_back_started_stages_in_reverse() {
        let full_reverse = vec![
            "rollback_dataplane",
            "rollback_routes",
            "rollback_dhcp",
            "rollback_output_wifi",
            "rollback_uplink_wifi",
            "rollback_interfaces",
        ];
        for (failure, rollbacks) in [
            ("apply_interfaces", vec!["rollback_interfaces"]),
            (
                "apply_uplink_wifi",
                vec!["rollback_uplink_wifi", "rollback_interfaces"],
            ),
            (
                "apply_output_wifi",
                vec![
                    "rollback_output_wifi",
                    "rollback_uplink_wifi",
                    "rollback_interfaces",
                ],
            ),
            (
                "apply_dhcp",
                vec![
                    "rollback_dhcp",
                    "rollback_output_wifi",
                    "rollback_uplink_wifi",
                    "rollback_interfaces",
                ],
            ),
            (
                "apply_routes",
                vec![
                    "rollback_routes",
                    "rollback_dhcp",
                    "rollback_output_wifi",
                    "rollback_uplink_wifi",
                    "rollback_interfaces",
                ],
            ),
            ("apply_dataplane", full_reverse.clone()),
            ("health_interfaces", full_reverse.clone()),
            ("health_uplink_wifi", full_reverse.clone()),
            ("health_output_wifi", full_reverse.clone()),
            ("health_dhcp", full_reverse.clone()),
            ("health_routes", full_reverse.clone()),
            ("health_dataplane", full_reverse.clone()),
        ] {
            let fake = FakeSubsystems::new(Some(failure));
            RouterManager::new(fake.clone())
                .apply(&plan())
                .await
                .unwrap_err();
            let actual: Vec<_> = fake
                .events()
                .into_iter()
                .filter(|event| event.starts_with("rollback_"))
                .collect();
            assert_eq!(actual, rollbacks, "failure at {failure}");
        }
    }

    #[tokio::test]
    async fn rollback_continues_and_error_preserves_original_and_rollback_failure() {
        let fake = FakeSubsystems::new(Some("health_interfaces"));
        *fake.rollback_fail.lock().unwrap() = Some("rollback_dhcp".into());
        let error = RouterManager::new(fake.clone())
            .apply(&plan())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("injected health_interfaces failure"));
        assert!(error.contains("injected rollback_dhcp failure"));
        assert!(fake.events().ends_with(&[
            "rollback_dataplane".into(),
            "rollback_routes".into(),
            "rollback_dhcp".into(),
            "rollback_output_wifi".into(),
            "rollback_uplink_wifi".into(),
            "rollback_interfaces".into(),
        ]));
    }

    #[tokio::test]
    async fn plan_aggregates_default_route_risk() {
        let fake = FakeSubsystems::with_default_route();
        let desired = RouterDesired::from_effective_config(&enabled_config()).unwrap();
        let router_plan = RouterManager::new(fake).plan(desired).await.unwrap();
        assert!(router_plan.risk.changes_default_route);
        assert!(!router_plan.risk.requires_management_confirmation);
    }

    #[tokio::test]
    async fn health_reports_only_the_failing_subsystem() {
        let desired = RouterDesired::from_effective_config(&enabled_config()).unwrap();

        for failing in [
            "health_interfaces",
            "health_routes",
            "health_dhcp",
            "health_dataplane",
        ] {
            let fake = FakeSubsystems::new(Some(failing));
            let report = RouterManager::new(fake).health(&desired).await;
            assert!(!report.ready(), "failing {failing}");

            let fields = [
                ("health_interfaces", &report.interfaces),
                ("health_routes", &report.routes),
                ("health_dhcp", &report.dhcp),
                ("health_dataplane", &report.dataplane),
            ];
            for (event, value) in fields {
                if event == failing {
                    assert!(value.is_some(), "expected {event} to be unhealthy");
                } else {
                    assert!(value.is_none(), "expected {event} to stay healthy");
                }
            }
        }
    }

    #[tokio::test]
    async fn health_is_ready_when_every_subsystem_succeeds() {
        let desired = RouterDesired::from_effective_config(&enabled_config()).unwrap();
        let fake = FakeSubsystems::new(None);
        let report = RouterManager::new(fake).health(&desired).await;
        assert!(report.ready());
        assert!(report.interfaces.is_none());
        assert!(report.routes.is_none());
        assert!(report.dhcp.is_none());
        assert!(report.dataplane.is_none());
    }
}
