use super::dhcp::*;
use super::interfaces::*;
use super::*;
use crate::api::model::{ProvisioningOutputRequest, ProvisioningUplinkRequest};
use crate::config::{RouterConfig, UplinkConfig, UplinkMode};
use crate::config::{WifiBand, WifiChannelWidth, WifiConfig, WifiSecurity};
use crate::config::{WifiClientGlobalConfig, WifiClientSecurity};
use crate::core::interface::{DhcpChangeAction, InterfaceChangePlan};
use crate::core::route::{RoutePlan, RouteSnapshot};
use crate::core::router::{
    DhcpPlan, RouterSnapshot, RouterSubsystemPlan, RouterSubsystems, VpnChainSnapshot,
};
use crate::core::router::{RouterManager, WifiPlan, WifiSnapshot};
use crate::core::router_provisioning::ProvisioningDownstreamOverrides;
use crate::core::transaction::InterfaceChange;
use crate::firewall::vpn::test_support::nft_ruleset;
use crate::firewall::vpn::{VpnPolicyFirewallBackend, VpnPolicyFirewallDesired};
use crate::firewall::{OwnedFirewallIntegrity, RouterDataplanePlan, RouterDataplaneSnapshot};
use crate::netlink::AddressOwnership;
use crate::netlink::NetworkInterface;
use crate::test_support::FakeVpnProvider;
use crate::wifi::process::SupervisedProcess;
use crate::wifi::WifiClientSupervisor as ClientSupervisor;
use crate::wifi::{HostapdSupervisor as WifiSupervisor, ProcessError as WifiProcessError};
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap as StdHashMap;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering as WifiOrdering};
use std::sync::Mutex as StdMutex;
use tempfile::tempdir;

mod fixtures;
use fixtures::*;

mod dhcp;
mod interfaces;
mod offline_intent;
mod offline_wifi;
mod provisioning;
mod router;
mod settings;
mod vpn;
mod vpn_policy;
mod wifi_ap;
mod wifi_client;
