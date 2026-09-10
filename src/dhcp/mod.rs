//! DHCP server, DHCP client, lease storage, and supervisors.
//!
//! The subsystem assigns IPv4 addresses to local clients and obtains an
//! address for an upstream interface. Lease state is persisted and runtime
//! loops are restarted by supervisors after failures.

pub mod client;
pub mod defaults;
pub mod lease;
pub mod packet;
pub mod runtime;
pub mod server;
pub mod store;
pub mod supervisor;

pub use lease::{DhcpLease, LeaseManager, LeasePoolConfig};
