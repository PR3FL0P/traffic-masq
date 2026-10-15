//! Authenticated typed control client for local Unix sockets and verified HTTPS.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use hyper::body::Bytes;
use hyper::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{map_request, RawResponse, RestRequest};

pub const DEFAULT_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
pub const CONTROL_MUTATION_REQUEST_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(65);
const API_PREFIX: &str = "/api/v1";

#[derive(Debug, Clone, Deserialize)]
pub struct LoginSession {
    pub token: String,
    pub principal: serde_json::Value,
    pub idle_expires_at: i64,
    pub absolute_expires_at: i64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ClientAuthentication {
    pub token: zeroize::Zeroizing<String>,
    pub authenticated_at: u64,
    pub absolute_expires_at: i64,
}

impl ClientAuthentication {
    fn from_login(session: &LoginSession) -> Self {
        Self {
            token: zeroize::Zeroizing::new(session.token.clone()),
            authenticated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            absolute_expires_at: session.absolute_expires_at,
        }
    }
}

pub struct ApiClient<Response> {
    _response: std::marker::PhantomData<fn() -> Response>,
    endpoint: crate::endpoint::Endpoint,
    session: Arc<RwLock<Option<ClientAuthentication>>>,
}

impl<Response> Clone for ApiClient<Response> {
    fn clone(&self) -> Self {
        Self {
            _response: std::marker::PhantomData,
            endpoint: self.endpoint.clone(),
            session: self.session.clone(),
        }
    }
}

impl<Response: serde::de::DeserializeOwned> std::fmt::Debug for ApiClient<Response> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiClient")
            .field("endpoint", &self.endpoint_label())
            .finish_non_exhaustive()
    }
}

impl<Response: serde::de::DeserializeOwned> ApiClient<Response> {
    /// Create an unauthenticated Unix-socket client; clones share authentication state.
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            endpoint: crate::endpoint::Endpoint::Unix(socket_path.into()),
            _response: std::marker::PhantomData,
            session: Arc::new(RwLock::new(None)),
        }
    }

    /// Clear local credentials without contacting the server.
    pub async fn forget_authentication(&self) {
        *self.session.write().await = None;
    }

    pub async fn authentication(&self) -> Option<ClientAuthentication> {
        self.session.read().await.clone()
    }

    /// Install cached credentials locally; the next request still requires server validation.
    pub async fn restore_authentication(&self, session: ClientAuthentication) {
        *self.session.write().await = Some(session);
    }

    pub fn socket_path(&self) -> Option<&Path> {
        match &self.endpoint {
            crate::endpoint::Endpoint::Unix(path) => Some(path),
            _ => None,
        }
    }

    /// Use certificate and hostname verification with an explicit or system CA bundle.
    pub fn https(url: &str, ca_file: Option<&Path>) -> Result<Self> {
        Ok(Self {
            endpoint: crate::endpoint::Endpoint::Https(Arc::new(
                crate::endpoint::HttpsEndpoint::new(url, ca_file)?,
            )),
            _response: std::marker::PhantomData,
            session: Arc::new(RwLock::new(None)),
        })
    }

    pub fn endpoint_label(&self) -> String {
        match &self.endpoint {
            crate::endpoint::Endpoint::Unix(path) => path.display().to_string(),
            crate::endpoint::Endpoint::Https(remote) => format!("https://{}", remote.authority),
        }
    }

    /// Remote sessions are scoped to both origin and the trusted CA bundle.
    pub fn remote_session_identity(&self) -> Option<&str> {
        match &self.endpoint {
            crate::endpoint::Endpoint::Https(remote) => Some(&remote.identity),
            _ => None,
        }
    }

    /// Query whether the daemon has an initialized device password.
    pub async fn auth_initialized(&self) -> Result<bool> {
        let response = self
            .send(Method::GET, &format!("{API_PREFIX}/auth/status"), None)
            .await?;
        let body = into_success_body(response)?;
        let status: AuthStatusResponse = serde_json::from_slice(&body)
            .context("failed to decode authentication status from the API")?;
        Ok(status.initialized)
    }

    /// Initialize the device password and cache the returned authenticated session.
    pub async fn initialize(&self, password: &str) -> Result<LoginSession> {
        if self.socket_path().is_none() {
            bail!("initialize the device password locally over the Unix socket first");
        }
        let body = serialize_json(&PasswordRequest { password })?;
        let response = self
            .send(
                Method::POST,
                &format!("{API_PREFIX}/auth/initialize"),
                Some(body),
            )
            .await?;
        let body = into_success_body(response)?;
        let session: LoginSession = serde_json::from_slice(&body)
            .context("failed to decode password initialization response from the API")?;
        *self.session.write().await = Some(ClientAuthentication::from_login(&session));
        Ok(session)
    }

    /// Authenticate with the device password and share the returned session across client clones.
    pub async fn login(&self, password: &str) -> Result<LoginSession> {
        let body = serialize_json(&LoginRequest {
            password,
            client: "traffic-masq-tui",
        })?;
        let response = self
            .send(
                Method::POST,
                &format!("{API_PREFIX}/auth/login"),
                Some(body),
            )
            .await?;
        let body = into_success_body(response)?;
        let session: LoginSession = serde_json::from_slice(&body)
            .context("failed to decode login response from the API")?;

        *self.session.write().await = Some(ClientAuthentication::from_login(&session));
        Ok(session)
    }

    /// Change the device password and discard local credentials after server success.
    pub async fn change_password(&self, current_password: &str, new_password: &str) -> Result<()> {
        let body = serialize_json(&ChangePasswordRequest {
            current_password,
            new_password,
        })?;
        let response = self
            .send(
                Method::POST,
                &format!("{API_PREFIX}/auth/password"),
                Some(body),
            )
            .await?;
        into_success_body(response)?;
        *self.session.write().await = None;
        Ok(())
    }

    /// Ask the daemon to revoke this session and clear local credentials even if the request fails.
    pub async fn logout(&self) -> Result<()> {
        let result = match self
            .send(Method::POST, &format!("{API_PREFIX}/auth/logout"), None)
            .await
        {
            Ok(response) => into_success_body(response).map(|_| ()),
            Err(error) => Err(error),
        };

        *self.session.write().await = None;
        result
    }

    /// Report whether local credentials exist; this does not verify server-side session validity.
    pub async fn is_authenticated(&self) -> bool {
        self.session.read().await.is_some()
    }

    /// Send a typed command to the control endpoint and decode its response.
    /// Transport, HTTP status, and response decoding failures are returned to the caller.
    /// HTTP 200 domain errors decode successfully as `Ok(Response::*Error)`;
    /// callers must inspect the variant. Reads use 10 seconds; writes, scans and plans 65.
    /// A lost response leaves mutation outcome unknown: inspect state before
    /// retrying and never automatically retry such a mutation.
    pub async fn request(
        &self,
        request: &traffic_masq_protocol::ControlRequest,
    ) -> anyhow::Result<Response> {
        let RestRequest {
            method,
            path,
            body,
            synthesize_pong,
        } = map_request(request)?;
        let deadline = control_request_timeout(request);
        let response = self
            .send_with_timeout(method, &path, body, deadline)
            .await?;
        let body = into_success_body(response)?;

        if synthesize_pong {
            return serde_json::from_slice(br#"{"type":"pong"}"#)
                .context("failed to decode synthetic ping response");
        }

        serde_json::from_slice(&body).context("failed to decode response from the API")
    }

    /// Send a short request with the default ten-second deadline.
    async fn send(&self, method: Method, path: &str, body: Option<Vec<u8>>) -> Result<RawResponse> {
        self.send_with_timeout(method, path, body, DEFAULT_REQUEST_TIMEOUT)
            .await
    }

    /// Bound request duration and discard credentials on an unauthorized response.
    /// A timeout does not prove the server-side operation was cancelled.
    pub async fn send_with_timeout(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
        deadline: std::time::Duration,
    ) -> Result<RawResponse> {
        let response = tokio::time::timeout(deadline, self.send_inner(method, path, body))
            .await
            .context("API request timed out; operation outcome may be unknown. Inspect current state before retrying")??;
        if response.status == StatusCode::UNAUTHORIZED {
            *self.session.write().await = None;
        }
        Ok(response)
    }

    async fn send_inner(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<RawResponse> {
        let token = self
            .session
            .read()
            .await
            .as_ref()
            .map(|session| session.token.to_string());
        crate::send_endpoint(&self.endpoint, method, path, body, token.as_deref()).await
    }
}

#[derive(Serialize)]
struct LoginRequest<'a> {
    password: &'a str,
    client: &'static str,
}

#[derive(Serialize)]
struct PasswordRequest<'a> {
    password: &'a str,
}

#[derive(Serialize)]
struct ChangePasswordRequest<'a> {
    current_password: &'a str,
    new_password: &'a str,
}

#[derive(Deserialize)]
struct AuthStatusResponse {
    initialized: bool,
}

#[derive(Deserialize)]
struct ErrorResponse {
    #[serde(alias = "error")]
    message: String,
}

fn serialize_json(value: &(impl Serialize + ?Sized)) -> Result<Vec<u8>> {
    serde_json::to_vec(value).context("failed to encode API request body")
}

/// Bound client waiting independently of the shared POST transport.
/// Writes, scans and plans retain 65 seconds; observations use 10 seconds.
pub fn control_request_timeout(
    request: &traffic_masq_protocol::ControlRequest,
) -> std::time::Duration {
    if request.policy().long_running {
        CONTROL_MUTATION_REQUEST_TIMEOUT
    } else {
        DEFAULT_REQUEST_TIMEOUT
    }
}

fn into_success_body(response: RawResponse) -> Result<Bytes> {
    if response.status.is_success() {
        return Ok(response.body);
    }

    if response.status == StatusCode::UNAUTHORIZED {
        bail!("authentication required (HTTP 401 Unauthorized)");
    }

    let message = serde_json::from_slice::<ErrorResponse>(&response.body)
        .ok()
        .map(|error| error.message)
        .filter(|message| !message.trim().is_empty());

    if let Some(message) = message {
        bail!(
            "API request failed with status {}: {message}",
            response.status
        );
    }

    let fallback = String::from_utf8_lossy(&response.body);
    let fallback = fallback.trim();
    if fallback.is_empty() {
        bail!("API request failed with status {}", response.status);
    }

    bail!(
        "API request failed with status {}: {fallback}",
        response.status
    )
}
