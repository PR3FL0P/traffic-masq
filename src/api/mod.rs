//! HTTP API and models for the daemon-client control protocol.

use std::time::Duration;

/// Hard bound enforced by the server for one HTTP connection/request.
pub(crate) const HTTP_CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);
pub mod client;
pub mod control;
pub mod model;
pub mod server;

pub(crate) mod operations;
