//! Encodes typed commands for the control endpoint.
use anyhow::{Context, Result};
use hyper::Method;
use serde::Serialize;

pub struct RestRequest {
    pub method: Method,
    pub path: String,
    pub body: Option<Vec<u8>>,
    pub synthesize_pong: bool,
}

pub fn map_request<Interface: Serialize, Proposal: Serialize>(
    request: &traffic_masq_protocol::Request<Interface, Proposal>,
) -> Result<RestRequest> {
    // Availability checks run before login, including first-time setup.
    if matches!(request, traffic_masq_protocol::Request::Ping) {
        return Ok(RestRequest {
            method: Method::GET,
            path: "/api/v1/status".into(),
            body: None,
            synthesize_pong: true,
        });
    }
    Ok(RestRequest {
        method: Method::POST,
        path: "/api/v1/control".into(),
        body: Some(serde_json::to_vec(request).context("failed to encode control request")?),
        synthesize_pong: false,
    })
}
