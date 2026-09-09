//! Core state reconciliation and network management.
//!
//! This module contains the desired-state model, commit-confirm transactions,
//! address and route ownership tracking, router provisioning, and VPN policy.
//! System mutations must pass through this layer so they remain reversible and
//! resilient to external drift.

pub mod desired;
pub mod interface;
pub mod override_manager;
pub mod ownership;
pub mod route;
pub mod router;
pub mod router_candidate;
pub mod router_provisioning;
pub mod router_subsystems;
pub mod router_transaction;
pub mod transaction;
pub mod vpn_chain;
pub mod vpn_policy;
pub mod vpn_policy_manager;
