//! Host observations shared by the daemon and its independent terminal client.
//! This leaf crate has no dependency on wire DTOs or daemon policy.

mod init;
mod managers;

pub use init::{
    detect_init_system, format_competing_manager_advice, format_competing_manager_advice_for_init,
    InitSystem,
};
pub use managers::find_competing_network_managers;

mod ports;
pub use ports::{
    foreign_ipv4_udp_listener_diagnostics, tcp_bind_conflict_diagnostics,
    udp_bind_conflict_diagnostics,
};

mod locks;
pub use locks::file_lock_diagnostics;
