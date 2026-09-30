//! Client-only API surface used by the terminal UI.

pub(crate) mod client {
    pub(crate) use traffic_masq_api_client::{ClientAuthentication, ControlApiClient as ApiClient};
}

pub(crate) mod model {
    pub(crate) use traffic_masq_protocol::*;

    pub(crate) type Request = traffic_masq_protocol::ControlRequest;
    pub(crate) type Response = traffic_masq_protocol::ControlResponse;
}
