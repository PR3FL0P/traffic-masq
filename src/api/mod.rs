//! HTTP API and models for the daemon-client control protocol.

use std::time::Duration;

/// Hard bound enforced by the server for one HTTP connection/request.
pub(crate) const HTTP_CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);
/// Client deadline for state-changing control requests. Keep this outside the
/// server's hard deadline so the server, not the client transport, decides the
/// outcome of an admitted mutation.
pub(crate) const CONTROL_MUTATION_REQUEST_TIMEOUT: Duration =
    Duration::from_secs(HTTP_CONNECTION_TIMEOUT.as_secs() + 5);

pub mod client;
pub mod control;
pub mod model;
pub mod server;

pub(crate) mod operations;
