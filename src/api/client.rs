//! Client API specialized to the daemon's current response model.

pub type ApiClient = traffic_masq_api_client::ControlApiClient;
pub use traffic_masq_api_client::ClientAuthentication;

#[cfg(test)]
use hyper::Method;
#[cfg(test)]
use traffic_masq_api_client::{
    control_request_timeout, map_request, CONTROL_MUTATION_REQUEST_TIMEOUT, DEFAULT_REQUEST_TIMEOUT,
};

#[cfg(test)]
mod tests;
