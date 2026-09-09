//! `traffic-masq` — an IPv4 router, Wi-Fi access point, and VPN gateway for Linux.
//!
//! The library contains the shared state model and system adapters used by two
//! binaries: `traffic-masqd` manages the network with elevated privileges,
//! while `traffic-masq` provides the terminal UI.
//!
//! The project converges the running system toward a desired state. Changes
//! are applied through confirmation transactions: if the operator does not
//! confirm them in time, the previous state is restored. Ownership journals
//! prevent the daemon from removing addresses, routes, processes, or VPN
//! interfaces created by other software.
//!
//! For an overview, start with [`config`], [`core`], and [`api`], then inspect
//! the [`dhcp`], [`wifi`], and [`vpn`] subsystems.

pub mod api;
pub mod app;
pub mod atomic_file;
pub mod auth;
pub mod config;
pub mod core;
pub mod dhcp;
pub mod firewall;
pub mod logging;

pub mod netlink;
pub mod state;
pub mod tui;
pub mod vpn;
pub mod wifi;
