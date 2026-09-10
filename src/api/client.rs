use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::client::conn::http1;
use hyper::header::{AUTHORIZATION, CONNECTION, CONTENT_TYPE, HOST};
use hyper::{Method, Request as HttpRequest, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::net::UnixStream;
use tokio::sync::RwLock;

use crate::auth::LoginSession;

const API_PREFIX: &str = "/api/v1";
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const HOST_VALUE: &str = "localhost";

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct ClientAuthentication {
    pub(crate) token: zeroize::Zeroizing<String>,
    pub(crate) authenticated_at: u64,
    pub(crate) absolute_expires_at: i64,
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

#[derive(Clone)]
pub struct ApiClient {
    socket_path: PathBuf,
    session: Arc<RwLock<Option<ClientAuthentication>>>,
}

impl std::fmt::Debug for ApiClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiClient")
            .field("socket_path", &self.socket_path)
            .finish_non_exhaustive()
    }
}

impl ApiClient {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            session: Arc::new(RwLock::new(None)),
        }
    }

    pub(crate) async fn forget_authentication(&self) {
        *self.session.write().await = None;
    }

    pub(crate) async fn authentication(&self) -> Option<ClientAuthentication> {
        self.session.read().await.clone()
    }

    pub(crate) async fn restore_authentication(&self, session: ClientAuthentication) {
        *self.session.write().await = Some(session);
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub async fn auth_initialized(&self) -> Result<bool> {
        let response = self
            .send(Method::GET, &format!("{API_PREFIX}/auth/status"), None)
            .await?;
        let body = into_success_body(response)?;
        let status: AuthStatusResponse = serde_json::from_slice(&body)
            .context("failed to decode authentication status from the API")?;
        Ok(status.initialized)
    }

    pub async fn initialize(&self, password: &str) -> Result<LoginSession> {
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

    pub async fn is_authenticated(&self) -> bool {
        self.session.read().await.is_some()
    }

    pub async fn request(
        &self,
        request: &crate::api::model::Request,
    ) -> anyhow::Result<crate::api::model::Response> {
        let RestRequest {
            method,
            path,
            body,
            synthesize_pong,
        } = map_request(request)?;
        let response = self.send(method, &path, body).await?;
        let body = into_success_body(response)?;

        if synthesize_pong {
            return Ok(crate::api::model::Response::Pong);
        }

        serde_json::from_slice(&body).context("failed to decode response from the API")
    }

    async fn send(&self, method: Method, path: &str, body: Option<Vec<u8>>) -> Result<RawResponse> {
        let response = tokio::time::timeout(std::time::Duration::from_secs(10), self.send_inner(method, path, body))
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
            .map(|session| session.token.clone());
        let stream = UnixStream::connect(&self.socket_path)
            .await
            .with_context(|| {
                format!(
                    "failed to connect to API socket {}",
                    self.socket_path.display()
                )
            })?;
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .context("failed to establish HTTP/1 connection to the API")?;
        let mut connection_task = tokio::spawn(connection);
        let _abort_on_drop = AbortConnection(connection_task.abort_handle());

        let has_json_body = body.is_some();
        let mut builder = HttpRequest::builder()
            .method(method)
            .uri(path)
            .header(HOST, HOST_VALUE)
            .header(CONNECTION, "close");
        if has_json_body {
            builder = builder.header(CONTENT_TYPE, "application/json");
        }
        if let Some(token) = token {
            builder = builder.header(AUTHORIZATION, format!("Bearer {}", token.as_str()));
        }

        let request = builder
            .body(Full::new(Bytes::from(body.unwrap_or_default())))
            .context("failed to build API request")?;
        let response = match sender.send_request(request).await {
            Ok(response) => response,
            Err(error) => {
                drop(sender);
                connection_task.abort();
                return Err(error).context("failed to send request to the API");
            }
        };
        drop(sender);

        let status = response.status();
        let body_result = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
            .collect()
            .await
            .map(|collected| collected.to_bytes())
            .map_err(|error| {
                anyhow::anyhow!("failed to read API response body (maximum size is 1 MiB): {error}")
            });
        let connection_result = (&mut connection_task).await;

        let body = body_result?;
        connection_result
            .context("API HTTP connection task failed")?
            .context("API HTTP connection failed")?;

        Ok(RawResponse { status, body })
    }
}

struct AbortConnection(tokio::task::AbortHandle);
impl Drop for AbortConnection {
    fn drop(&mut self) {
        self.0.abort();
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

#[derive(Serialize)]
struct InterfaceRequestBody<'a> {
    config: &'a crate::config::InterfaceConfig,
    allow_management_change: bool,
}

#[derive(Serialize)]
struct TransactionRequestBody<'a> {
    token: &'a str,
}

#[derive(Serialize)]
struct VpnImportProfileRequestBody<'a> {
    name: &'a str,
    contents: &'a str,
}

#[derive(Serialize)]
struct VpnActivateRequestBody<'a> {
    name: &'a str,
}

#[derive(Serialize)]
struct VpnPolicySetModeRequestBody {
    mode: crate::config::VpnPolicyMode,
}

#[derive(Serialize)]
struct WifiSetPassphraseRequestBody<'a> {
    passphrase: &'a str,
}

#[derive(Serialize)]
struct ProvisionWifiAccessPointRequestBody<'a> {
    settings: &'a crate::api::model::WifiEditRequest,
    passphrase: &'a Option<String>,
    configure_dhcp: bool,
}

struct RestRequest {
    method: Method,
    path: String,
    body: Option<Vec<u8>>,
    synthesize_pong: bool,
}

struct RawResponse {
    status: StatusCode,
    body: Bytes,
}

#[derive(Deserialize)]
struct ErrorResponse {
    #[serde(alias = "error")]
    message: String,
}

fn map_request(request: &crate::api::model::Request) -> Result<RestRequest> {
    use crate::api::model::Request;

    let mapped = match request {
        Request::Ping => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/status"),
            body: None,
            synthesize_pong: true,
        },
        Request::GetApiHttpsConfig => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/access/https"),
            body: None,
            synthesize_pong: false,
        },
        Request::ConfigureApiHttpsSettings { settings } => RestRequest {
            method: Method::PUT,
            path: format!("{API_PREFIX}/access/https"),
            body: Some(serialize_json(settings)?),
            synthesize_pong: false,
        },
        Request::ResetApiHttpsSettings => RestRequest {
            method: Method::DELETE,
            path: format!("{API_PREFIX}/access/https"),
            body: None,
            synthesize_pong: false,
        },
        Request::GetSecurityConfig => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/security/settings"),
            body: None,
            synthesize_pong: false,
        },
        Request::ConfigureSecuritySettings { settings } => RestRequest {
            method: Method::PUT,
            path: format!("{API_PREFIX}/security/settings"),
            body: Some(serialize_json(settings)?),
            synthesize_pong: false,
        },
        Request::ResetSecuritySettings => RestRequest {
            method: Method::DELETE,
            path: format!("{API_PREFIX}/security/settings"),
            body: None,
            synthesize_pong: false,
        },
        Request::ListInterfaces => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/interfaces"),
            body: None,
            synthesize_pong: false,
        },
        Request::GetInterfaceConfig { interface } => RestRequest {
            method: Method::GET,
            path: format!(
                "{API_PREFIX}/interfaces/{}/config",
                encode_path_segment(interface)
            ),
            body: None,
            synthesize_pong: false,
        },
        Request::DhcpStatus => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/dhcp"),
            body: None,
            synthesize_pong: false,
        },
        Request::DhcpClientStatus => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/dhcp-client"),
            body: None,
            synthesize_pong: false,
        },
        Request::GetDhcpClient { interface } => RestRequest {
            method: Method::GET,
            path: dhcp_client_path(interface),
            body: None,
            synthesize_pong: false,
        },
        Request::ConfigureDhcpClient { interface, config } => RestRequest {
            method: Method::PUT,
            path: dhcp_client_path(interface),
            body: Some(serialize_json(config)?),
            synthesize_pong: false,
        },
        Request::DisableDhcpClient { interface } => RestRequest {
            method: Method::DELETE,
            path: dhcp_client_path(interface),
            body: None,
            synthesize_pong: false,
        },
        Request::RenewDhcpClient { interface } => RestRequest {
            method: Method::POST,
            path: format!("{}/renew", dhcp_client_path(interface)),
            body: None,
            synthesize_pong: false,
        },
        Request::ReleaseDhcpClient { interface } => RestRequest {
            method: Method::POST,
            path: format!("{}/release", dhcp_client_path(interface)),
            body: None,
            synthesize_pong: false,
        },
        Request::ConfigureDhcpSettings {
            interface,
            settings,
        } => RestRequest {
            method: Method::PUT,
            path: format!(
                "{API_PREFIX}/dhcp/{}/settings",
                encode_path_segment(interface)
            ),
            body: Some(serialize_json(settings)?),
            synthesize_pong: false,
        },
        Request::GetDhcpConfig { interface } => RestRequest {
            method: Method::GET,
            path: dhcp_path(interface),
            body: None,
            synthesize_pong: false,
        },
        Request::ConfigureDhcp { interface, config } => RestRequest {
            method: Method::PUT,
            path: dhcp_path(interface),
            body: Some(serialize_json(config)?),
            synthesize_pong: false,
        },
        Request::DisableDhcp { interface } => RestRequest {
            method: Method::DELETE,
            path: dhcp_path(interface),
            body: None,
            synthesize_pong: false,
        },
        Request::ListLeases { interface } => RestRequest {
            method: Method::GET,
            path: format!("{}/leases", dhcp_path(interface)),
            body: None,
            synthesize_pong: false,
        },
        Request::DryRunInterface {
            interface,
            config,
            allow_management_change,
        } => RestRequest {
            method: Method::POST,
            path: format!(
                "{API_PREFIX}/interfaces/{}/plan",
                encode_path_segment(interface)
            ),
            body: Some(serialize_json(&InterfaceRequestBody {
                config,
                allow_management_change: *allow_management_change,
            })?),
            synthesize_pong: false,
        },
        Request::DryRunInterfaceEdit { interface, edit } => RestRequest {
            method: Method::POST,
            path: format!(
                "{API_PREFIX}/interfaces/{}/edit/plan",
                encode_path_segment(interface)
            ),
            body: Some(serialize_json(edit)?),
            synthesize_pong: false,
        },
        Request::ApplyInterface {
            interface,
            config,
            allow_management_change,
        } => RestRequest {
            method: Method::POST,
            path: format!(
                "{API_PREFIX}/interfaces/{}/apply",
                encode_path_segment(interface)
            ),
            body: Some(serialize_json(&InterfaceRequestBody {
                config,
                allow_management_change: *allow_management_change,
            })?),
            synthesize_pong: false,
        },
        Request::ApplyInterfaceEdit { interface, edit } => RestRequest {
            method: Method::POST,
            path: format!(
                "{API_PREFIX}/interfaces/{}/edit/apply",
                encode_path_segment(interface)
            ),
            body: Some(serialize_json(edit)?),
            synthesize_pong: false,
        },
        Request::CommitNetworkChange { token } => RestRequest {
            method: Method::POST,
            path: format!("{API_PREFIX}/network-transactions/commit"),
            body: Some(serialize_json(&TransactionRequestBody { token })?),
            synthesize_pong: false,
        },
        Request::RollbackNetworkChange { token } => RestRequest {
            method: Method::POST,
            path: format!("{API_PREFIX}/network-transactions/rollback"),
            body: Some(serialize_json(&TransactionRequestBody { token })?),
            synthesize_pong: false,
        },
        Request::PendingNetworkChanges => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/network-transactions"),
            body: None,
            synthesize_pong: false,
        },
        Request::RouterStatus => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/router/status"),
            body: None,
            synthesize_pong: false,
        },
        Request::RouterPlan { proposal } => RestRequest {
            method: Method::POST,
            path: format!("{API_PREFIX}/router/plan"),
            body: Some(serialize_json(proposal)?),
            synthesize_pong: false,
        },
        Request::RouterApply { proposal } => RestRequest {
            method: Method::POST,
            path: format!("{API_PREFIX}/router/apply"),
            body: Some(serialize_json(proposal)?),
            synthesize_pong: false,
        },
        Request::RouterCommit => RestRequest {
            method: Method::POST,
            path: format!("{API_PREFIX}/router/commit"),
            body: None,
            synthesize_pong: false,
        },
        Request::RouterRollback => RestRequest {
            method: Method::POST,
            path: format!("{API_PREFIX}/router/rollback"),
            body: None,
            synthesize_pong: false,
        },
        Request::RouterPendingTransaction => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/router/pending"),
            body: None,
            synthesize_pong: false,
        },

        Request::RouterProvisioningPreview { request } => RestRequest {
            method: Method::POST,
            path: format!("{API_PREFIX}/router/provisioning/preview"),
            body: Some(serialize_json(request)?),
            synthesize_pong: false,
        },
        Request::RouterProvisioningApply { request } => RestRequest {
            method: Method::POST,
            path: format!("{API_PREFIX}/router/provisioning/apply"),
            body: Some(serialize_json(request)?),
            synthesize_pong: false,
        },
        Request::RouterProvisioningStatus => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/router/provisioning/status"),
            body: None,
            synthesize_pong: false,
        },
        Request::RouterProvisioningRepair => RestRequest {
            method: Method::POST,
            path: format!("{API_PREFIX}/router/provisioning/repair"),
            body: None,
            synthesize_pong: false,
        },
        Request::VpnListProfiles => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/vpn/profiles"),
            body: None,
            synthesize_pong: false,
        },
        Request::VpnImportProfile { name, contents } => RestRequest {
            method: Method::POST,
            path: format!("{API_PREFIX}/vpn/profiles"),
            body: Some(serialize_json(&VpnImportProfileRequestBody {
                name,
                contents,
            })?),
            synthesize_pong: false,
        },
        Request::VpnDeleteProfile { name } => RestRequest {
            method: Method::DELETE,
            path: format!("{API_PREFIX}/vpn/profiles/{}", encode_path_segment(name)),
            body: None,
            synthesize_pong: false,
        },
        Request::VpnStatus => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/vpn/status"),
            body: None,
            synthesize_pong: false,
        },
        Request::VpnActivate { name } => RestRequest {
            method: Method::POST,
            path: format!("{API_PREFIX}/vpn/activate"),
            body: Some(serialize_json(&VpnActivateRequestBody { name })?),
            synthesize_pong: false,
        },
        Request::VpnDeactivate => RestRequest {
            method: Method::POST,
            path: format!("{API_PREFIX}/vpn/deactivate"),
            body: None,
            synthesize_pong: false,
        },
        Request::VpnPolicyStatus => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/vpn-policy/status"),
            body: None,
            synthesize_pong: false,
        },
        Request::VpnPolicySetMode { mode } => RestRequest {
            method: Method::PUT,
            path: format!("{API_PREFIX}/vpn-policy/mode"),
            body: Some(serialize_json(&VpnPolicySetModeRequestBody {
                mode: *mode,
            })?),
            synthesize_pong: false,
        },
        Request::VpnPolicyClearMode => RestRequest {
            method: Method::DELETE,
            path: format!("{API_PREFIX}/vpn-policy/mode"),
            body: None,
            synthesize_pong: false,
        },
        Request::WifiStatus => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/wifi"),
            body: None,
            synthesize_pong: false,
        },
        Request::GetWifiConfig { interface } => RestRequest {
            method: Method::GET,
            path: wifi_path(interface),
            body: None,
            synthesize_pong: false,
        },
        Request::ConfigureWifi {
            interface,
            settings,
        } => RestRequest {
            method: Method::PUT,
            path: wifi_path(interface),
            body: Some(serialize_json(settings)?),
            synthesize_pong: false,
        },
        Request::ProvisionWifiAccessPoint {
            interface,
            settings,
            passphrase,
            configure_dhcp,
        } => RestRequest {
            method: Method::POST,
            path: format!("{}/provision", wifi_path(interface)),
            body: Some(serialize_json(&ProvisionWifiAccessPointRequestBody {
                settings,
                passphrase,
                configure_dhcp: *configure_dhcp,
            })?),
            synthesize_pong: false,
        },
        Request::DisableWifi { interface } => RestRequest {
            method: Method::DELETE,
            path: wifi_path(interface),
            body: None,
            synthesize_pong: false,
        },
        Request::WifiSetPassphrase {
            interface,
            passphrase,
        } => RestRequest {
            method: Method::PUT,
            path: format!("{}/passphrase", wifi_path(interface)),
            body: Some(serialize_json(&WifiSetPassphraseRequestBody {
                passphrase,
            })?),
            synthesize_pong: false,
        },
        Request::ListWifiStations { interface } => RestRequest {
            method: Method::GET,
            path: format!("{}/stations", wifi_path(interface)),
            body: None,
            synthesize_pong: false,
        },
        Request::WifiDeauthStation { interface, mac } => RestRequest {
            method: Method::POST,
            path: format!(
                "{}/stations/{}/deauthenticate",
                wifi_path(interface),
                encode_path_segment(mac)
            ),
            body: None,
            synthesize_pong: false,
        },
        Request::WifiReload { interface } => RestRequest {
            method: Method::POST,
            path: format!("{}/reload", wifi_path(interface)),
            body: None,
            synthesize_pong: false,
        },
        Request::WifiClientStatus => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/wifi-client"),
            body: None,
            synthesize_pong: false,
        },
        Request::GetWifiClientConfig { interface } => RestRequest {
            method: Method::GET,
            path: wifi_client_path(interface),
            body: None,
            synthesize_pong: false,
        },
        Request::ConfigureWifiClient {
            interface,
            settings,
        } => RestRequest {
            method: Method::PUT,
            path: wifi_client_path(interface),
            body: Some(serialize_json(settings)?),
            synthesize_pong: false,
        },
        Request::DisableWifiClient { interface } => RestRequest {
            method: Method::DELETE,
            path: wifi_client_path(interface),
            body: None,
            synthesize_pong: false,
        },
        Request::WifiClientSetPassphrase {
            interface,
            passphrase,
        } => RestRequest {
            method: Method::PUT,
            path: format!("{}/passphrase", wifi_client_path(interface)),
            body: Some(serialize_json(&WifiSetPassphraseRequestBody {
                passphrase,
            })?),
            synthesize_pong: false,
        },
        Request::WifiClientReconnect { interface } => RestRequest {
            method: Method::POST,
            path: format!("{}/reconnect", wifi_client_path(interface)),
            body: None,
            synthesize_pong: false,
        },
        Request::WifiClientScan { interface } => RestRequest {
            method: Method::POST,
            path: format!("{}/scan", wifi_client_path(interface)),
            body: None,
            synthesize_pong: false,
        },
        Request::ListWifiClientProfiles => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/wifi-client/profiles"),
            body: None,
            synthesize_pong: false,
        },
        Request::GetWifiClientProfile { id } => RestRequest {
            method: Method::GET,
            path: wifi_client_profile_path(id),
            body: None,
            synthesize_pong: false,
        },
        Request::CreateWifiClientProfile { profile } => RestRequest {
            method: Method::POST,
            path: format!("{API_PREFIX}/wifi-client/profiles"),
            body: Some(serialize_json(profile)?),
            synthesize_pong: false,
        },
        Request::UpdateWifiClientProfile { id, profile } => RestRequest {
            method: Method::PUT,
            path: wifi_client_profile_path(id),
            body: Some(serialize_json(profile)?),
            synthesize_pong: false,
        },
        Request::DeleteWifiClientProfile { id } => RestRequest {
            method: Method::DELETE,
            path: wifi_client_profile_path(id),
            body: None,
            synthesize_pong: false,
        },
        Request::ActivateWifiClientProfile {
            interface,
            profile_id,
        } => RestRequest {
            method: Method::PUT,
            path: format!("{}/active-profile", wifi_client_path(interface)),
            body: Some(serialize_json(
                &crate::api::model::WifiClientProfileActivationRequest {
                    profile_id: profile_id.clone(),
                },
            )?),
            synthesize_pong: false,
        },
        Request::DeactivateWifiClientProfile { interface } => RestRequest {
            method: Method::DELETE,
            path: format!("{}/active-profile", wifi_client_path(interface)),
            body: None,
            synthesize_pong: false,
        },
    };

    Ok(mapped)
}

fn dhcp_path(interface: &str) -> String {
    format!("{API_PREFIX}/dhcp/{}", encode_path_segment(interface))
}

fn wifi_path(interface: &str) -> String {
    format!("{API_PREFIX}/wifi/{}", encode_path_segment(interface))
}

fn wifi_client_profile_path(id: &str) -> String {
    format!(
        "{API_PREFIX}/wifi-client/profiles/{}",
        encode_path_segment(id)
    )
}

fn dhcp_client_path(interface: &str) -> String {
    format!(
        "{API_PREFIX}/dhcp-client/{}",
        encode_path_segment(interface)
    )
}

fn wifi_client_path(interface: &str) -> String {
    format!(
        "{API_PREFIX}/wifi-client/{}",
        encode_path_segment(interface)
    )
}

fn serialize_json(value: &(impl Serialize + ?Sized)) -> Result<Vec<u8>> {
    serde_json::to_vec(value).context("failed to encode API request body")
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

fn encode_path_segment(segment: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut encoded = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::model::Request;

    #[tokio::test(start_paused = true)]
    async fn silent_api_times_out_and_closes_connection() {
        use tokio::io::AsyncReadExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let client = ApiClient::new(path);
        let request = tokio::spawn(async move { client.request(&Request::Ping).await });
        let (mut peer, _) = listener.accept().await.unwrap();
        tokio::time::advance(std::time::Duration::from_secs(11)).await;
        assert!(request
            .await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("timed out"));
        let mut bytes = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            peer.read_to_end(&mut bytes),
        )
        .await
        .unwrap()
        .unwrap();
    }

    #[test]
    fn percent_encodes_path_segments() {
        assert_eq!(encode_path_segment("eth0.100-guest_~"), "eth0.100-guest_~");
        assert_eq!(encode_path_segment("vlan/guest %"), "vlan%2Fguest%20%25");
        assert_eq!(encode_path_segment("é"), "%C3%A9");
    }

    #[test]
    fn maps_ping_to_status_and_synthesizes_pong() {
        let mapped = map_request(&Request::Ping).expect("ping should map");

        assert_eq!(mapped.method, Method::GET);
        assert_eq!(mapped.path, "/api/v1/status");
        assert!(mapped.body.is_none());
        assert!(mapped.synthesize_pong);
    }

    #[test]
    fn maps_all_dhcp_client_paths_without_using_server_dhcp_routes() {
        let cases = [
            (
                Request::GetDhcpClient {
                    interface: "wan/0".into(),
                },
                Method::GET,
                "/api/v1/dhcp-client/wan%2F0",
            ),
            (
                Request::ConfigureDhcpClient {
                    interface: "wan/0".into(),
                    config: Default::default(),
                },
                Method::PUT,
                "/api/v1/dhcp-client/wan%2F0",
            ),
            (
                Request::DisableDhcpClient {
                    interface: "wan/0".into(),
                },
                Method::DELETE,
                "/api/v1/dhcp-client/wan%2F0",
            ),
            (
                Request::RenewDhcpClient {
                    interface: "wan/0".into(),
                },
                Method::POST,
                "/api/v1/dhcp-client/wan%2F0/renew",
            ),
            (
                Request::ReleaseDhcpClient {
                    interface: "wan/0".into(),
                },
                Method::POST,
                "/api/v1/dhcp-client/wan%2F0/release",
            ),
        ];
        for (request, method, path) in cases {
            let mapped = map_request(&request).expect("DHCP client request should map");
            assert_eq!(mapped.method, method);
            assert_eq!(mapped.path, path);
            assert!(mapped.path.contains("dhcp-client"));
            assert!(!mapped.path.starts_with("/api/v1/dhcp/"));
        }
    }

    #[test]
    fn maps_and_encodes_wifi_client_scan() {
        let mapped = map_request(&Request::WifiClientScan {
            interface: "wlan/guest".to_string(),
        })
        .expect("scan should map");

        assert_eq!(mapped.method, Method::POST);
        assert_eq!(mapped.path, "/api/v1/wifi-client/wlan%2Fguest/scan");
        assert!(mapped.body.is_none());
        assert!(!mapped.synthesize_pong);
    }

    #[test]
    fn maps_provisioning_paths_under_the_existing_router_surface() {
        use crate::api::model::{
            ProvisioningOutputRequest, ProvisioningUplinkRequest, RouterProvisioningApplyRequest,
            RouterProvisioningPreviewRequest, RouterProvisioningRequest,
        };

        let provisioning = RouterProvisioningRequest {
            uplink: ProvisioningUplinkRequest {
                interface: "wlan-up".to_string(),
                ssid: "upstream".to_string(),
                country_code: None,
                security: Default::default(),
            },
            output: ProvisioningOutputRequest {
                interface: "wlan-out".to_string(),
                ssid: "traffic-masq".to_string(),
                country_code: None,
                band: Default::default(),
                channel: 6,
                channel_width: Default::default(),
                security: Default::default(),
                hidden: false,
                client_isolation: false,
                max_stations: 32,
            },
            downstream: Default::default(),
            allow_management_change: false,
        };

        let preview = map_request(&Request::RouterProvisioningPreview {
            request: RouterProvisioningPreviewRequest {
                provisioning: provisioning.clone(),
                uplink_secret_pending: true,
                output_secret_pending: true,
            },
        })
        .expect("preview should map");
        assert_eq!(preview.method, Method::POST);
        assert_eq!(preview.path, "/api/v1/router/provisioning/preview");
        let encoded = String::from_utf8(preview.body.expect("preview body")).expect("utf-8 body");
        assert!(!encoded.contains("passphrase"), "{encoded}");

        let apply = map_request(&Request::RouterProvisioningApply {
            request: RouterProvisioningApplyRequest {
                provisioning,
                uplink_passphrase: Some("upstream-secret".to_string()),
                output_passphrase: None,
            },
        })
        .expect("apply should map");
        assert_eq!(apply.method, Method::POST);
        assert_eq!(apply.path, "/api/v1/router/provisioning/apply");
        assert!(apply.body.is_some());

        let status = map_request(&Request::RouterProvisioningStatus).expect("status should map");
        assert_eq!(status.method, Method::GET);
        assert_eq!(status.path, "/api/v1/router/provisioning/status");
        assert!(status.body.is_none());

        let repair = map_request(&Request::RouterProvisioningRepair).expect("repair should map");
        assert_eq!(repair.method, Method::POST);
        assert_eq!(repair.path, "/api/v1/router/provisioning/repair");
        assert!(repair.body.is_none());
    }

    #[test]
    fn maps_and_encodes_mutation_tokens() {
        let mapped = map_request(&Request::CommitNetworkChange {
            token: "pending/change".to_string(),
        })
        .expect("commit should map");

        assert_eq!(mapped.method, Method::POST);
        assert_eq!(mapped.path, "/api/v1/network-transactions/commit");
        assert!(mapped.body.is_some());
        assert!(!mapped.synthesize_pong);
    }
}
