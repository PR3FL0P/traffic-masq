//! `traffic-masq` — an IPv4 router, Wi-Fi access point, and VPN gateway for Linux.
//!
//! This crate contains the daemon state model and system adapters used by
//! `traffic-masqd`. The `traffic-masq` terminal client lives in the separate
//! `traffic-masq-tui` crate.
//!
//! The project converges the running system toward a desired state. Interface,
//! router, Wi-Fi configuration, AP/STA provisioning, profile activation and live
//! deactivation use commit-confirm. Expiry schedules rollback; admitted work and
//! recovery retries can delay completion. Missing-device edits save durable intent
//! after cleanup without a timer. Standalone DHCP, Wi-Fi runtime commands,
//! passphrase and profile-library edits, and VPN mutations apply immediately and
//! rely on durable ownership records plus startup recovery. Ownership
//! proofs prevent the daemon from removing addresses, routes, processes, or VPN
//! interfaces created by other software.
//!
//! For an overview, start with [`config`], [`core`], and [`api`], then inspect
//! the [`dhcp`], [`wifi`], and [`vpn`] subsystems.

pub mod api;
pub mod app;
pub use traffic_masq_atomic_file as atomic_file;
pub mod auth;
mod command;
pub mod config;
pub mod core;
pub mod dhcp;
pub mod firewall;
pub mod logging;

pub use traffic_masq_netlink as netlink;
pub mod state;
#[cfg(test)]
pub(crate) mod test_support;
pub mod vpn;
pub mod wifi;
