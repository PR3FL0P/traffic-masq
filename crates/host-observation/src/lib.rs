//! Host observations shared by the daemon and its independent terminal client.
//! This leaf crate has no dependency on wire DTOs or daemon policy.

mod init;
mod managers;

pub use init::{
    detect_init_system, format_competing_manager_advice, format_competing_manager_advice_for_init,
    InitSystem,
};
pub use managers::find_competing_network_managers;
