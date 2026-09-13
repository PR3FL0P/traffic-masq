use std::fs::{self, File, Metadata};
use std::io::BufReader;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use axum::extract::{
    DefaultBodyLimit, Extension, Path as AxumPath, Query, Request as AxumRequest, State,
};
use axum::http::{header::AUTHORIZATION, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response as AxumResponse};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use nix::errno::Errno;
use nix::unistd::{chown, Group};
use rustls::ServerConfig;
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

use crate::api::control::ControlService;
use crate::api::model::{
    ApiHttpsSettings, DhcpClientConfigRequest, DhcpEditRequest, InterfaceEditRequest,
    ProvisionWifiAccessPointRequest, Request, Response, RouterProposalRequest,
    RouterProvisioningApplyRequest, RouterProvisioningPreviewRequest, SecuritySettings,
    WifiClientEditRequest, WifiClientProfileActivationRequest, WifiClientProfileWriteRequest,
    WifiEditRequest,
};
use crate::auth::{
    AuthError, AuthService, LoginSession, Principal, Role, MINIMUM_PASSWORD_CHARACTERS,
};
use crate::config::{AppConfig, DhcpInterfaceConfig, InterfaceConfig, TcpApiConfig};

const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

const MAX_CONCURRENT_TLS_CONNECTIONS: usize = 128;

const WEAK_PASSWORD_MESSAGE: &str = "password must contain at least 12 characters";
const _: () = assert!(
    MINIMUM_PASSWORD_CHARACTERS == 12,
    "WEAK_PASSWORD_MESSAGE is stale"
);

pub struct HttpApiBindings {
    unix_listener: StdUnixListener,
    tcp_listener: Option<StdTcpListener>,
    tls_acceptor: Option<TlsAcceptor>,
    socket_path: PathBuf,
    socket_cleanup: OwnedSocketPath,
}

impl HttpApiBindings {
    pub fn bind(config: &AppConfig) -> Result<Self> {
        let (tcp_listener, tls_acceptor) = bind_tls_listener(config.api.tcp.as_ref())?;
        let socket_path = config.runtime.socket_path.clone();
        let socket_group = config.runtime.socket_group.as_deref().map(|name| {
            Group::from_name(name)?.ok_or_else(|| anyhow::anyhow!("socket group {name} does not exist"))
        }).transpose()?.map(|group| group.gid);
        crate::app::runtime::prepare_socket_directory(&socket_path, socket_group)?;
        prepare_socket_path(&socket_path)?;
        let unix_listener = StdUnixListener::bind(&socket_path)
            .with_context(|| format!("failed to bind HTTP API socket {}", socket_path.display()))?;
        let socket_cleanup = OwnedSocketPath::capture(socket_path.clone())?;
        unix_listener
            .set_nonblocking(true)
            .context("failed to make the HTTP API Unix listener nonblocking")?;
        configure_socket_access(&socket_path, config.runtime.socket_group.as_deref())?;

        Ok(Self {
            unix_listener,
            tcp_listener,
            tls_acceptor,
            socket_path,
            socket_cleanup,
        })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn into_server(self, control: ControlService, auth: AuthService) -> HttpApiServer {
        HttpApiServer {
            unix_listener: self.unix_listener,
            tcp_listener: self.tcp_listener,
            tls_acceptor: self.tls_acceptor,
            router: build_router(AppState { control, auth }),
            socket_path: self.socket_path,
            socket_cleanup: self.socket_cleanup,
        }
    }
}

pub struct HttpApiServer {
    unix_listener: StdUnixListener,
    tcp_listener: Option<StdTcpListener>,
    tls_acceptor: Option<TlsAcceptor>,
    router: Router,
    socket_path: PathBuf,
    socket_cleanup: OwnedSocketPath,
}

impl HttpApiServer {
    pub fn bind(config: &AppConfig, control: ControlService, auth: AuthService) -> Result<Self> {
        Ok(HttpApiBindings::bind(config)?.into_server(control, auth))
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn tcp_local_addr(&self) -> Result<Option<SocketAddr>> {
        self.tcp_listener
            .as_ref()
            .map(StdTcpListener::local_addr)
            .transpose()
            .context("failed to read HTTPS listener address")
    }

    pub async fn run(self, shutdown: watch::Receiver<bool>) -> Result<()> {
        let Self {
            unix_listener,
            tcp_listener,
            tls_acceptor,
            router,
            socket_path: _,
            socket_cleanup: _socket_cleanup,
        } = self;

        let unix_listener = UnixListener::from_std(unix_listener)
            .context("failed to register the HTTP API Unix listener with Tokio")?;

        if let (Some(tcp_listener), Some(tls_acceptor)) = (tcp_listener, tls_acceptor) {
            let tcp_listener = TcpListener::from_std(tcp_listener)
                .context("failed to register the HTTPS listener with Tokio")?;
            let (unix_result, tls_result) = tokio::join!(
                run_unix_accept_loop(unix_listener, router.clone(), shutdown.clone()),
                run_tls_accept_loop(tcp_listener, tls_acceptor, router, shutdown),
            );
            unix_result?;
            tls_result?;
        } else {
            run_unix_accept_loop(unix_listener, router, shutdown).await?;
        }

        Ok(())
    }
}

#[derive(Clone)]
struct AppState {
    control: ControlService,
    auth: AuthService,
}

fn build_router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(current_principal))
        .route("/auth/password", post(change_password))
        .route(
            "/access/https",
            get(get_api_https_config)
                .put(put_api_https_config)
                .delete(delete_api_https_config),
        )
        .route(
            "/security/settings",
            get(get_security_config)
                .put(put_security_config)
                .delete(delete_security_config),
        )
        .route("/interfaces", get(list_interfaces))
        .route("/interfaces/{interface}/config", get(get_interface_config))
        .route("/interfaces/{interface}/plan", post(plan_interface))
        .route("/interfaces/{interface}/apply", post(apply_interface))
        .route(
            "/interfaces/{interface}/edit/plan",
            post(plan_interface_edit),
        )
        .route(
            "/interfaces/{interface}/edit/apply",
            post(apply_interface_edit),
        )
        .route("/dhcp", get(dhcp_status))
        .route(
            "/dhcp/{interface}",
            get(get_dhcp_config)
                .put(put_dhcp_config)
                .delete(delete_dhcp_config),
        )
        .route("/dhcp/{interface}/settings", put(put_dhcp_settings))
        .route("/dhcp/{interface}/leases", get(list_dhcp_leases))
        .route("/dhcp-client", get(dhcp_client_status))
        .route(
            "/dhcp-client/{interface}",
            get(get_dhcp_client)
                .put(put_dhcp_client)
                .delete(delete_dhcp_client),
        )
        .route("/dhcp-client/{interface}/renew", post(renew_dhcp_client))
        .route(
            "/dhcp-client/{interface}/release",
            post(release_dhcp_client),
        )
        .route("/network-transactions", get(pending_transactions))
        .route("/network-transactions/commit", post(commit_transaction))
        .route("/network-transactions/rollback", post(rollback_transaction))
        .route("/routes", get(routes_list))
        .route("/router/config", get(router_get_config))
        .route("/router/status", get(router_status))
        .route("/router/plan", post(router_plan))
        .route("/router/apply", post(router_apply))
        .route("/router/commit", post(router_commit))
        .route("/router/rollback", post(router_rollback))
        .route("/router/pending", get(router_pending_transaction))
        .route(
            "/router/provisioning/preview",
            post(router_provisioning_preview),
        )
        .route(
            "/router/provisioning/apply",
            post(router_provisioning_apply),
        )
        .route(
            "/router/provisioning/status",
            get(router_provisioning_status),
        )
        .route(
            "/router/provisioning/repair",
            post(router_provisioning_repair),
        )
        .route(
            "/vpn/profiles",
            get(vpn_list_profiles).post(vpn_import_profile),
        )
        .route(
            "/vpn/profiles/{name}",
            axum::routing::delete(vpn_delete_profile),
        )
        .route("/vpn/status", get(vpn_status))
        .route("/vpn/activate", post(vpn_activate))
        .route("/vpn/deactivate", post(vpn_deactivate))
        .route("/vpn-policy/status", get(vpn_policy_status))
        .route(
            "/vpn-policy/mode",
            put(vpn_policy_set_mode).delete(vpn_policy_clear_mode),
        )
        .route("/wifi", get(wifi_status))
        .route(
            "/wifi/{interface}",
            get(get_wifi_config)
                .put(put_wifi_config)
                .delete(delete_wifi_config),
        )
        .route("/wifi/{interface}/passphrase", put(put_wifi_passphrase))
        .route(
            "/wifi/{interface}/provision",
            post(provision_wifi_access_point),
        )
        .route("/wifi/{interface}/stations", get(list_wifi_stations))
        .route(
            "/wifi/{interface}/stations/{mac}/deauthenticate",
            post(wifi_deauth_station),
        )
        .route("/wifi/{interface}/reload", post(wifi_reload))
        .route("/wifi-client", get(wifi_client_status))
        .route(
            "/wifi-client/{interface}",
            get(get_wifi_client_config)
                .put(put_wifi_client_config)
                .delete(delete_wifi_client_config),
        )
        .route(
            "/wifi-client/{interface}/passphrase",
            put(put_wifi_client_passphrase),
        )
        .route(
            "/wifi-client/{interface}/reconnect",
            post(wifi_client_reconnect),
        )
        .route("/wifi-client/{interface}/scan", post(wifi_client_scan))
        .route(
            "/wifi-client/profiles",
            get(list_wifi_client_profiles).post(create_wifi_client_profile),
        )
        .route(
            "/wifi-client/profiles/{id}",
            get(get_wifi_client_profile)
                .put(update_wifi_client_profile)
                .delete(delete_wifi_client_profile),
        )
        .route(
            "/wifi-client/{interface}/active-profile",
            put(activate_wifi_client_profile).delete(deactivate_wifi_client_profile),
        )
        .route_layer(from_fn_with_state(state.clone(), authenticate_request));

    let api = Router::new()
        .route("/status", get(status))
        .route("/auth/status", get(auth_status))
        .route("/auth/initialize", post(initialize_password))
        .route("/auth/login", post(login))
        .merge(protected)
        .with_state(state);

    Router::new()
        .nest("/api/v1", api)
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
}

async fn authenticate_request(
    State(state): State<AppState>,
    mut request: AxumRequest,
    next: Next,
) -> AxumResponse {
    let Some(token) = bearer_token(request.headers().get(AUTHORIZATION)).map(str::to_owned) else {
        return ApiError::Unauthorized("authentication required").into_response();
    };

    let principal = match state.auth.authenticate(&token).await {
        Ok(principal) => principal,
        Err(AuthError::InvalidSession) => {
            return ApiError::Unauthorized("authentication required").into_response();
        }
        Err(error) => {
            tracing::error!(%error, "bearer authentication failed");
            return ApiError::Internal.into_response();
        }
    };

    request.extensions_mut().insert(principal);
    request.extensions_mut().insert(BearerToken(token));
    next.run(request).await
}

fn bearer_token(header: Option<&axum::http::HeaderValue>) -> Option<&str> {
    let value = header?.to_str().ok()?;
    let mut parts = value.split_ascii_whitespace();
    let scheme = parts.next()?;
    let token = parts.next()?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() || parts.next().is_some() {
        return None;
    }
    Some(token)
}

#[derive(Clone)]
struct BearerToken(String);

#[derive(Clone, Debug)]
enum ConnectionInfo {
    Unix {
        pid: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
    },
    Tls {
        peer: SocketAddr,
    },
}

impl ConnectionInfo {
    fn auth_peer(&self) -> String {
        match self {
            Self::Unix { pid, uid, gid } => format!(
                "unix:pid={},uid={},gid={}",
                display_optional(*pid),
                display_optional(*uid),
                display_optional(*gid)
            ),
            Self::Tls { peer } => format!("tls:{peer}"),
        }
    }

    fn is_local_root(&self) -> bool {
        matches!(self, Self::Unix { uid: Some(0), .. })
    }
}

fn display_optional(value: Option<u32>) -> String {
    value.map_or_else(|| "unknown".to_owned(), |value| value.to_string())
}

#[derive(Deserialize)]
struct LoginRequest {
    password: Zeroizing<String>,
    #[serde(default, alias = "client_name")]
    client: Option<String>,
}

#[derive(Deserialize)]
struct PasswordRequest {
    password: Zeroizing<String>,
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    current_password: Zeroizing<String>,
    new_password: Zeroizing<String>,
}

#[derive(Serialize)]
struct AuthStatusResponse {
    initialized: bool,
}

async fn auth_status(State(state): State<AppState>) -> Result<Json<AuthStatusResponse>, ApiError> {
    let initialized = state.auth.is_initialized().await.map_err(|error| {
        tracing::error!(%error, "failed to read authentication initialization state");
        ApiError::Internal
    })?;
    Ok(Json(AuthStatusResponse { initialized }))
}

async fn initialize_password(
    State(state): State<AppState>,
    Extension(connection): Extension<ConnectionInfo>,
    Json(request): Json<PasswordRequest>,
) -> Result<Json<LoginSession>, ApiError> {
    if !connection.is_local_root() {
        return Err(ApiError::ForbiddenMessage(
            "initial password setup requires a local root client",
        ));
    }
    let peer = connection.auth_peer();
    state
        .auth
        .initialize_device_password(&request.password)
        .await
        .map_err(|error| match error {
            AuthError::AlreadyInitialized => {
                ApiError::Conflict("device password is already initialized")
            }
            AuthError::WeakPassword => ApiError::BadRequest(WEAK_PASSWORD_MESSAGE),
            other => {
                tracing::error!(error = %other, "device password initialization failed");
                ApiError::Internal
            }
        })?;
    state
        .auth
        .login_device(&request.password, Some("traffic-masq-tui"), Some(&peer))
        .await
        .map(Json)
        .map_err(|error| {
            tracing::error!(%error, "login after device password initialization failed");
            ApiError::Internal
        })
}

async fn login(
    State(state): State<AppState>,
    Extension(connection): Extension<ConnectionInfo>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<LoginSession>, ApiError> {
    let peer = connection.auth_peer();
    match state
        .auth
        .login_device(&request.password, request.client.as_deref(), Some(&peer))
        .await
    {
        Ok(session) => Ok(Json(session)),
        Err(AuthError::InvalidCredentials) => Err(ApiError::Unauthorized("invalid credentials")),
        Err(error) => {
            tracing::error!(%error, "login failed");
            Err(ApiError::Internal)
        }
    }
}

async fn logout(
    State(state): State<AppState>,
    Extension(token): Extension<BearerToken>,
) -> Result<StatusCode, ApiError> {
    state.auth.logout(&token.0).await.map_err(|error| {
        tracing::error!(%error, "logout failed");
        ApiError::Internal
    })?;
    Ok(StatusCode::NO_CONTENT)
}

async fn current_principal(Extension(principal): Extension<Principal>) -> Json<Principal> {
    Json(principal)
}

async fn change_password(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(request): Json<ChangePasswordRequest>,
) -> Result<StatusCode, ApiError> {
    if principal.role != Role::Administrator {
        return Err(ApiError::Forbidden);
    }
    state
        .auth
        .change_device_password(&request.current_password, &request.new_password)
        .await
        .map_err(|error| match error {
            AuthError::InvalidCredentials => ApiError::Unauthorized("invalid credentials"),
            AuthError::WeakPassword => ApiError::BadRequest(WEAK_PASSWORD_MESSAGE),
            other => {
                tracing::error!(error = %other, "device password change failed");
                ApiError::Internal
            }
        })?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct StatusResponse {
    service: &'static str,
    version: &'static str,
    api_version: u32,
    authentication_required: bool,
    capabilities: &'static [&'static str],
}

async fn status() -> Json<StatusResponse> {
    Json(StatusResponse {
        service: "traffic-masqd",
        version: env!("CARGO_PKG_VERSION"),
        api_version: 1,
        authentication_required: true,
        capabilities: &["interfaces", "dhcp", "network_transactions", "vpn"],
    })
}

async fn get_api_https_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::GetApiHttpsConfig).await
}

async fn put_api_https_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(settings): Json<ApiHttpsSettings>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::ConfigureApiHttpsSettings { settings },
    )
    .await
}

async fn delete_api_https_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::ResetApiHttpsSettings).await
}

async fn get_security_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::GetSecurityConfig).await
}

async fn put_security_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(settings): Json<SecuritySettings>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::ConfigureSecuritySettings { settings },
    )
    .await
}

async fn delete_security_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::ResetSecuritySettings).await
}

async fn list_interfaces(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::ListInterfaces).await
}

async fn dhcp_status(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::DhcpStatus).await
}

async fn get_interface_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::GetInterfaceConfig { interface },
    )
    .await
}

async fn dhcp_client_status(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::DhcpClientStatus).await
}

async fn get_dhcp_client(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::GetDhcpClient { interface }).await
}

async fn put_dhcp_client(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
    Json(config): Json<DhcpClientConfigRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::ConfigureDhcpClient { interface, config },
    )
    .await
}

async fn delete_dhcp_client(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::DisableDhcpClient { interface }).await
}

async fn renew_dhcp_client(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::RenewDhcpClient { interface }).await
}

async fn release_dhcp_client(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::ReleaseDhcpClient { interface }).await
}

async fn get_dhcp_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::GetDhcpConfig { interface }).await
}

async fn put_dhcp_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
    Json(config): Json<DhcpInterfaceConfig>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::ConfigureDhcp { interface, config },
    )
    .await
}

async fn put_dhcp_settings(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
    Json(settings): Json<DhcpEditRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::ConfigureDhcpSettings {
            interface,
            settings,
        },
    )
    .await
}

async fn delete_dhcp_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::DisableDhcp { interface }).await
}

async fn list_dhcp_leases(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::ListLeases { interface }).await
}

#[derive(Deserialize)]
struct InterfaceChangeRequest {
    config: InterfaceConfig,
    #[serde(default)]
    allow_management_change: bool,
}

async fn plan_interface(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
    Json(request): Json<InterfaceChangeRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::DryRunInterface {
            interface,
            config: request.config,
            allow_management_change: request.allow_management_change,
        },
    )
    .await
}

async fn apply_interface(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
    Json(request): Json<InterfaceChangeRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::ApplyInterface {
            interface,
            config: request.config,
            allow_management_change: request.allow_management_change,
        },
    )
    .await
}

async fn plan_interface_edit(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
    Json(edit): Json<InterfaceEditRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::DryRunInterfaceEdit { interface, edit },
    )
    .await
}

async fn apply_interface_edit(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
    Json(edit): Json<InterfaceEditRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::ApplyInterfaceEdit { interface, edit },
    )
    .await
}

async fn pending_transactions(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::PendingNetworkChanges).await
}

#[derive(Deserialize)]
struct TransactionRequest {
    token: String,
}

async fn commit_transaction(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(request): Json<TransactionRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::CommitNetworkChange {
            token: request.token,
        },
    )
    .await
}

async fn rollback_transaction(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(request): Json<TransactionRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::RollbackNetworkChange {
            token: request.token,
        },
    )
    .await
}

#[derive(Debug, Deserialize)]
pub struct ListRoutesQuery {
    #[serde(default)]
    pub include_local_table: bool,
}

async fn routes_list(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<ListRoutesQuery>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::ListRoutes {
            include_local_table: query.include_local_table,
        },
    )
    .await
}

async fn router_get_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::GetRouterConfig).await
}

async fn router_status(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::RouterStatus).await
}

async fn router_plan(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(proposal): Json<RouterProposalRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::RouterPlan { proposal }).await
}

async fn router_apply(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(proposal): Json<RouterProposalRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::RouterApply { proposal }).await
}

async fn router_commit(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::RouterCommit).await
}

async fn router_rollback(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::RouterRollback).await
}

async fn router_pending_transaction(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::RouterPendingTransaction).await
}

async fn router_provisioning_preview(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(request): Json<RouterProvisioningPreviewRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::RouterProvisioningPreview { request },
    )
    .await
}

async fn router_provisioning_apply(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(request): Json<RouterProvisioningApplyRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::RouterProvisioningApply { request },
    )
    .await
}

async fn router_provisioning_status(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::RouterProvisioningStatus).await
}

async fn router_provisioning_repair(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::RouterProvisioningRepair).await
}

async fn vpn_list_profiles(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::VpnListProfiles).await
}

#[derive(Deserialize)]
struct VpnImportProfileRequest {
    name: String,
    contents: String,
}

async fn vpn_import_profile(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(request): Json<VpnImportProfileRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::VpnImportProfile {
            name: request.name,
            contents: request.contents,
        },
    )
    .await
}

async fn vpn_delete_profile(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(name): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::VpnDeleteProfile { name }).await
}

async fn vpn_status(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::VpnStatus).await
}

#[derive(Deserialize)]
struct VpnActivateRequest {
    name: String,
}

async fn vpn_activate(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(request): Json<VpnActivateRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::VpnActivate { name: request.name },
    )
    .await
}

async fn vpn_deactivate(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::VpnDeactivate).await
}

async fn vpn_policy_status(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::VpnPolicyStatus).await
}

#[derive(Deserialize)]
struct VpnPolicySetModeRequest {
    mode: crate::config::VpnPolicyMode,
}

async fn vpn_policy_set_mode(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(request): Json<VpnPolicySetModeRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::VpnPolicySetMode { mode: request.mode },
    )
    .await
}

async fn vpn_policy_clear_mode(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::VpnPolicyClearMode).await
}

async fn wifi_status(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::WifiStatus).await
}

async fn get_wifi_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::GetWifiConfig { interface }).await
}

async fn put_wifi_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
    Json(settings): Json<WifiEditRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::ConfigureWifi {
            interface,
            settings,
        },
    )
    .await
}

async fn provision_wifi_access_point(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
    Json(request): Json<ProvisionWifiAccessPointRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::ProvisionWifiAccessPoint {
            interface,
            settings: request.settings,
            passphrase: request.passphrase,
            configure_dhcp: request.configure_dhcp,
        },
    )
    .await
}

async fn delete_wifi_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::DisableWifi { interface }).await
}

#[derive(Deserialize)]
struct WifiPassphraseRequest {
    passphrase: String,
}

async fn put_wifi_passphrase(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
    Json(request): Json<WifiPassphraseRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::WifiSetPassphrase {
            interface,
            passphrase: request.passphrase,
        },
    )
    .await
}

async fn list_wifi_stations(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::ListWifiStations { interface }).await
}

async fn wifi_deauth_station(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath((interface, mac)): AxumPath<(String, String)>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::WifiDeauthStation { interface, mac },
    )
    .await
}

async fn wifi_reload(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::WifiReload { interface }).await
}

async fn wifi_client_status(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::WifiClientStatus).await
}

async fn get_wifi_client_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::GetWifiClientConfig { interface },
    )
    .await
}

async fn put_wifi_client_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
    Json(settings): Json<WifiClientEditRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::ConfigureWifiClient {
            interface,
            settings,
        },
    )
    .await
}

async fn delete_wifi_client_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::DisableWifiClient { interface }).await
}

async fn put_wifi_client_passphrase(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
    Json(request): Json<WifiPassphraseRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::WifiClientSetPassphrase {
            interface,
            passphrase: request.passphrase,
        },
    )
    .await
}

async fn list_wifi_client_profiles(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::ListWifiClientProfiles).await
}

async fn get_wifi_client_profile(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::GetWifiClientProfile { id }).await
}

async fn create_wifi_client_profile(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(profile): Json<WifiClientProfileWriteRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::CreateWifiClientProfile { profile },
    )
    .await
}

async fn update_wifi_client_profile(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(id): AxumPath<String>,
    Json(profile): Json<WifiClientProfileWriteRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::UpdateWifiClientProfile { id, profile },
    )
    .await
}

async fn delete_wifi_client_profile(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::DeleteWifiClientProfile { id }).await
}

async fn activate_wifi_client_profile(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
    Json(request): Json<WifiClientProfileActivationRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::ActivateWifiClientProfile {
            interface,
            profile_id: request.profile_id,
        },
    )
    .await
}

async fn deactivate_wifi_client_profile(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::DeactivateWifiClientProfile { interface },
    )
    .await
}

async fn wifi_client_scan(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::WifiClientScan { interface }).await
}

async fn wifi_client_reconnect(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::WifiClientReconnect { interface },
    )
    .await
}

async fn dispatch_control(
    state: &AppState,
    principal: &Principal,
    request: Request,
) -> Result<Json<Response>, ApiError> {
    authorize_control_request(principal, &request)?;
    Ok(Json(state.control.dispatch(request).await))
}

fn authorize_control_request(principal: &Principal, request: &Request) -> Result<(), ApiError> {
    if control_request_requires_administrator(request) && principal.role != Role::Administrator {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

fn control_request_requires_administrator(request: &Request) -> bool {
    matches!(
        request,
        Request::ConfigureApiHttpsSettings { .. }
            | Request::ResetApiHttpsSettings
            | Request::ConfigureDhcp { .. }
            | Request::ConfigureDhcpSettings { .. }
            | Request::DisableDhcp { .. }
            | Request::ConfigureDhcpClient { .. }
            | Request::DisableDhcpClient { .. }
            | Request::RenewDhcpClient { .. }
            | Request::ReleaseDhcpClient { .. }
            | Request::ApplyInterface { .. }
            | Request::ApplyInterfaceEdit { .. }
            | Request::CommitNetworkChange { .. }
            | Request::RollbackNetworkChange { .. }
            | Request::RouterApply { .. }
            | Request::RouterCommit
            | Request::RouterRollback
            | Request::RouterProvisioningApply { .. }
            | Request::RouterProvisioningRepair
            | Request::VpnImportProfile { .. }
            | Request::VpnDeleteProfile { .. }
            | Request::VpnActivate { .. }
            | Request::VpnDeactivate
            | Request::VpnPolicySetMode { .. }
            | Request::VpnPolicyClearMode
            | Request::ConfigureSecuritySettings { .. }
            | Request::ResetSecuritySettings
            | Request::ConfigureWifi { .. }
            | Request::ProvisionWifiAccessPoint { .. }
            | Request::DisableWifi { .. }
            | Request::WifiSetPassphrase { .. }
            | Request::WifiDeauthStation { .. }
            | Request::WifiReload { .. }
            | Request::ConfigureWifiClient { .. }
            | Request::DisableWifiClient { .. }
            | Request::WifiClientSetPassphrase { .. }
            | Request::WifiClientReconnect { .. }
            | Request::WifiClientScan { .. }
            | Request::CreateWifiClientProfile { .. }
            | Request::UpdateWifiClientProfile { .. }
            | Request::DeleteWifiClientProfile { .. }
            | Request::ActivateWifiClientProfile { .. }
            | Request::DeactivateWifiClientProfile { .. }
    )
}

#[derive(Debug)]
enum ApiError {
    BadRequest(&'static str),
    Unauthorized(&'static str),
    Forbidden,
    ForbiddenMessage(&'static str),
    Conflict(&'static str),
    Internal,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> AxumResponse {
        let (status, message) = match self {
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, message),
            Self::Unauthorized(message) => (StatusCode::UNAUTHORIZED, message),
            Self::Forbidden => (StatusCode::FORBIDDEN, "administrator role required"),
            Self::ForbiddenMessage(message) => (StatusCode::FORBIDDEN, message),
            Self::Conflict(message) => (StatusCode::CONFLICT, message),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal server error"),
        };
        (status, Json(ErrorResponse { error: message })).into_response()
    }
}

fn bind_tls_listener(
    tcp: Option<&TcpApiConfig>,
) -> Result<(Option<StdTcpListener>, Option<TlsAcceptor>)> {
    let Some(tcp) = tcp.filter(|tcp| tcp.enabled) else {
        return Ok((None, None));
    };

    let certificate_path = tcp.certificate_path.as_deref().ok_or_else(|| {
        anyhow::anyhow!("api.tcp.certificate_path is required when HTTPS is enabled")
    })?;
    let private_key_path = tcp.private_key_path.as_deref().ok_or_else(|| {
        anyhow::anyhow!("api.tcp.private_key_path is required when HTTPS is enabled")
    })?;
    let tls_acceptor = load_tls_acceptor(certificate_path, private_key_path)?;

    let listener = StdTcpListener::bind(tcp.listen)
        .with_context(|| format!("failed to bind HTTPS listener on {}", tcp.listen))?;
    listener
        .set_nonblocking(true)
        .context("failed to make the HTTPS listener nonblocking")?;

    Ok((Some(listener), Some(tls_acceptor)))
}

fn load_tls_acceptor(certificate_path: &Path, private_key_path: &Path) -> Result<TlsAcceptor> {
    let certificate_file = File::open(certificate_path).with_context(|| {
        format!(
            "failed to open HTTPS certificate {}",
            certificate_path.display()
        )
    })?;
    let certificates = rustls_pemfile::certs(&mut BufReader::new(certificate_file))
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| {
            format!(
                "failed to parse HTTPS certificate {}",
                certificate_path.display()
            )
        })?;
    if certificates.is_empty() {
        bail!(
            "HTTPS certificate file {} contains no certificates",
            certificate_path.display()
        );
    }

    let private_key_file = File::open(private_key_path).with_context(|| {
        format!(
            "failed to open HTTPS private key {}",
            private_key_path.display()
        )
    })?;
    let private_key = rustls_pemfile::private_key(&mut BufReader::new(private_key_file))
        .with_context(|| {
            format!(
                "failed to parse HTTPS private key {}",
                private_key_path.display()
            )
        })?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "HTTPS private key file {} contains no private key",
                private_key_path.display()
            )
        })?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .context("HTTPS certificate and private key are not compatible")?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn reap_finished_connections(connections: &mut JoinSet<()>, listener_name: &'static str) {
    while let Some(result) = connections.try_join_next() {
        if let Err(error) = result {
            tracing::warn!(%error, listener = listener_name, "HTTP connection task failed");
        }
    }
}

async fn run_unix_accept_loop(
    listener: UnixListener,
    router: Router,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut connections = JoinSet::new();

    if !*shutdown.borrow() {
        loop {
            reap_finished_connections(&mut connections, "Unix HTTP");
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    let (stream, _) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => {
                            tracing::warn!(%error, "failed to accept Unix HTTP connection");
                            tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                            continue;
                        }
                    };
                    let connection = unix_connection_info(&stream);
                    log_connection_accepted(&connection);
                    let service = router.clone().layer(Extension(connection.clone()));
                    connections.spawn(async move {
                        if let Err(error) = serve_unix_connection(stream, service).await {
                            tracing::debug!(%error, ?connection, "Unix HTTP connection ended with an error");
                        }
                    });
                }
            }
        }
    }

    drain_connections(&mut connections, "Unix HTTP").await;
    Ok(())
}

fn unix_connection_info(stream: &UnixStream) -> ConnectionInfo {
    match stream.peer_cred() {
        Ok(credentials) => ConnectionInfo::Unix {
            pid: credentials.pid().and_then(|pid| u32::try_from(pid).ok()),
            uid: Some(credentials.uid()),
            gid: Some(credentials.gid()),
        },
        Err(error) => {
            tracing::warn!(%error, "failed to read Unix HTTP peer credentials");
            ConnectionInfo::Unix {
                pid: None,
                uid: None,
                gid: None,
            }
        }
    }
}

async fn run_tls_accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    router: Router,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut connections = JoinSet::new();

    if !*shutdown.borrow() {
        loop {
            reap_finished_connections(&mut connections, "HTTPS");

            if connections.len() >= MAX_CONCURRENT_TLS_CONNECTIONS {
                if let Some(Err(error)) = connections.join_next().await {
                    tracing::warn!(%error, listener = "HTTPS", "HTTP connection task failed");
                }
            }
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    let (stream, peer) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => {
                            tracing::warn!(%error, "failed to accept HTTPS connection");
                            tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                            continue;
                        }
                    };
                    let connection = ConnectionInfo::Tls { peer };
                    log_connection_accepted(&connection);
                    let acceptor = acceptor.clone();
                    let service = router.clone().layer(Extension(connection.clone()));
                    connections.spawn(async move {
                        match timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                            Ok(Ok(stream)) => {
                                if let Err(error) = serve_tls_connection(stream, service).await {
                                    tracing::debug!(%error, ?connection, "HTTPS connection ended with an error");
                                }
                            }
                            Ok(Err(error)) => {
                                tracing::warn!(%error, ?connection, "TLS handshake failed");
                            }
                            Err(_) => {
                                tracing::warn!(?connection, "TLS handshake timed out");
                            }
                        }
                    });
                }
            }
        }
    }

    drain_connections(&mut connections, "HTTPS").await;
    Ok(())
}

fn log_connection_accepted(connection: &ConnectionInfo) {
    match connection {
        ConnectionInfo::Unix { pid, uid, gid } => {
            tracing::debug!(?pid, ?uid, ?gid, "accepted Unix HTTP connection");
        }
        ConnectionInfo::Tls { peer } => {
            tracing::debug!(%peer, "accepted HTTPS connection");
        }
    }
}

async fn serve_unix_connection(stream: UnixStream, service: Router) -> Result<()> {
    timeout(
        HTTP_CONNECTION_TIMEOUT,
        http1::Builder::new()
            .keep_alive(false)
            .serve_connection(TokioIo::new(stream), TowerToHyperService::new(service)),
    )
    .await
    .context("Unix HTTP connection timed out")?
    .context("failed to serve Unix HTTP connection")?;
    Ok(())
}

async fn serve_tls_connection(stream: TlsStream<TcpStream>, service: Router) -> Result<()> {
    timeout(
        HTTP_CONNECTION_TIMEOUT,
        http1::Builder::new()
            .keep_alive(false)
            .serve_connection(TokioIo::new(stream), TowerToHyperService::new(service)),
    )
    .await
    .context("HTTPS connection timed out")?
    .context("failed to serve HTTPS connection")?;
    Ok(())
}

async fn drain_connections(connections: &mut JoinSet<()>, listener_name: &'static str) {
    while let Some(result) = connections.join_next().await {
        if let Err(error) = result {
            tracing::warn!(%error, listener = listener_name, "HTTP connection task failed");
        }
    }
}

fn prepare_socket_path(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect HTTP API socket {}", path.display()));
        }
    };

    ensure_socket_file(path, &metadata)?;
    let expected = SocketIdentity::from_metadata(&metadata);

    match StdUnixStream::connect(path) {
        Ok(_) => bail!("HTTP API socket {} is already in use", path.display()),
        Err(error) if error.raw_os_error() == Some(Errno::ECONNREFUSED as i32) => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "refusing to remove HTTP API socket {} because its state could not be proven stale",
                    path.display()
                )
            });
        }
    }

    let current = fs::symlink_metadata(path).with_context(|| {
        format!(
            "HTTP API socket {} changed while checking whether it was stale",
            path.display()
        )
    })?;
    ensure_socket_file(path, &current)?;
    if SocketIdentity::from_metadata(&current) != expected {
        bail!(
            "HTTP API socket {} was replaced while checking whether it was stale",
            path.display()
        );
    }

    fs::remove_file(path)
        .with_context(|| format!("failed to remove stale HTTP API socket {}", path.display()))?;
    Ok(())
}

fn ensure_socket_file(path: &Path, metadata: &Metadata) -> Result<()> {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        bail!(
            "refusing to use HTTP API socket path {} because it is a symbolic link",
            path.display()
        );
    }
    if !file_type.is_socket() {
        bail!(
            "refusing to use HTTP API socket path {} because it is not a socket",
            path.display()
        );
    }
    Ok(())
}

fn configure_socket_access(path: &Path, group_name: Option<&str>) -> Result<()> {
    if let Some(group_name) = group_name {
        let group = Group::from_name(group_name)
            .with_context(|| format!("failed to resolve socket group {group_name}"))?
            .ok_or_else(|| anyhow::anyhow!("socket group {group_name} does not exist"))?;
        chown(path, None, Some(group.gid)).with_context(|| {
            format!(
                "failed to set group {group_name} on HTTP API socket {}",
                path.display()
            )
        })?;
    }

    fs::set_permissions(path, fs::Permissions::from_mode(0o660)).with_context(|| {
        format!(
            "failed to set permissions on HTTP API socket {}",
            path.display()
        )
    })?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

impl SocketIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

struct OwnedSocketPath {
    path: PathBuf,
    identity: SocketIdentity,
}

impl OwnedSocketPath {
    fn capture(path: PathBuf) -> Result<Self> {
        let metadata = fs::symlink_metadata(&path).with_context(|| {
            format!(
                "failed to inspect newly bound HTTP API socket {}",
                path.display()
            )
        })?;
        ensure_socket_file(&path, &metadata)?;
        Ok(Self {
            path,
            identity: SocketIdentity::from_metadata(&metadata),
        })
    }
}

impl Drop for OwnedSocketPath {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if !metadata.file_type().is_socket()
            || SocketIdentity::from_metadata(&metadata) != self.identity
        {
            return;
        }
        if let Err(error) = fs::remove_file(&self.path) {
            tracing::warn!(
                %error,
                path = %self.path.display(),
                "failed to remove owned HTTP API socket"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::config::InterfaceRole;

    fn principal(role: Role) -> Principal {
        Principal {
            user_id: 1,
            username: "test-user".to_owned(),
            role,
        }
    }

    fn interface_config() -> InterfaceConfig {
        InterfaceConfig {
            nat: true,
            role: InterfaceRole::Output,
            managed: true,
            ipv4: None,
            dhcp: None,
            dhcp_client: None,
            wifi: None,
            wifi_client: None,
        }
    }

    fn dhcp_config() -> DhcpInterfaceConfig {
        DhcpInterfaceConfig {
            pool_start: Ipv4Addr::new(192, 0, 2, 10),
            pool_end: Ipv4Addr::new(192, 0, 2, 20),
            router: Ipv4Addr::new(192, 0, 2, 1),
            dns_servers: Vec::new(),
            lease_seconds: None,
        }
    }

    fn interface_edit() -> InterfaceEditRequest {
        InterfaceEditRequest {
            cidr: "192.0.2.1/24".to_owned(),
            role: InterfaceRole::Output,
            managed: true,
            allow_management_change: false,
        }
    }

    fn dhcp_edit() -> DhcpEditRequest {
        DhcpEditRequest {
            pool_start: Ipv4Addr::new(192, 0, 2, 10),
            pool_end: Ipv4Addr::new(192, 0, 2, 20),
            router: Ipv4Addr::new(192, 0, 2, 1),
            dns_servers: Vec::new(),
            lease_seconds: None,
        }
    }

    fn api_https_settings() -> ApiHttpsSettings {
        ApiHttpsSettings {
            enabled: true,
            listen: "0.0.0.0:9443".to_owned(),
            certificate_path: Some("/etc/traffic-masq/server.pem".to_owned()),
            private_key_path: Some("/etc/traffic-masq/server-key.pem".to_owned()),
        }
    }

    #[test]
    fn dhcp_client_routes_allow_viewer_gets_and_require_admin_for_every_mutation() {
        for request in [
            Request::DhcpClientStatus,
            Request::GetDhcpClient {
                interface: "wan0".into(),
            },
        ] {
            assert!(authorize_control_request(&principal(Role::Viewer), &request).is_ok());
            assert!(authorize_control_request(&principal(Role::Administrator), &request).is_ok());
        }
        for request in [
            Request::ConfigureDhcpClient {
                interface: "wan0".into(),
                config: DhcpClientConfigRequest::default(),
            },
            Request::DisableDhcpClient {
                interface: "wan0".into(),
            },
            Request::RenewDhcpClient {
                interface: "wan0".into(),
            },
            Request::ReleaseDhcpClient {
                interface: "wan0".into(),
            },
        ] {
            assert!(matches!(
                authorize_control_request(&principal(Role::Viewer), &request),
                Err(ApiError::Forbidden)
            ));
            assert!(matches!(
                authorize_control_request(&principal(Role::Operator), &request),
                Err(ApiError::Forbidden)
            ));
            assert!(authorize_control_request(&principal(Role::Administrator), &request).is_ok());
        }
    }

    #[test]
    fn every_control_request_has_the_expected_authorization_class() {
        let read_requests = [
            Request::Ping,
            Request::GetApiHttpsConfig,
            Request::ListInterfaces,
            Request::DhcpStatus,
            Request::DhcpClientStatus,
            Request::GetDhcpClient {
                interface: "wan0".to_owned(),
            },
            Request::GetDhcpConfig {
                interface: "eth0".to_owned(),
            },
            Request::ListLeases {
                interface: "eth0".to_owned(),
            },
            Request::DryRunInterface {
                interface: "eth0".to_owned(),
                config: interface_config(),
                allow_management_change: false,
            },
            Request::DryRunInterfaceEdit {
                interface: "eth0".to_owned(),
                edit: interface_edit(),
            },
            Request::PendingNetworkChanges,
            Request::VpnPolicyStatus,
            Request::GetSecurityConfig,
            Request::WifiClientStatus,
            Request::GetWifiClientConfig {
                interface: "wlan0".to_owned(),
            },
            Request::ListWifiClientProfiles,
            Request::GetWifiClientProfile {
                id: "office".to_owned(),
            },
        ];
        for request in read_requests {
            assert!(!control_request_requires_administrator(&request));
            assert!(authorize_control_request(&principal(Role::Viewer), &request).is_ok());
            assert!(authorize_control_request(&principal(Role::Operator), &request).is_ok());
        }

        let mutation_requests = [
            Request::ConfigureApiHttpsSettings {
                settings: api_https_settings(),
            },
            Request::ResetApiHttpsSettings,
            Request::ConfigureDhcp {
                interface: "eth0".to_owned(),
                config: dhcp_config(),
            },
            Request::ConfigureDhcpSettings {
                interface: "eth0".to_owned(),
                settings: dhcp_edit(),
            },
            Request::DisableDhcp {
                interface: "eth0".to_owned(),
            },
            Request::ConfigureDhcpClient {
                interface: "wan0".to_owned(),
                config: DhcpClientConfigRequest::default(),
            },
            Request::DisableDhcpClient {
                interface: "wan0".to_owned(),
            },
            Request::RenewDhcpClient {
                interface: "wan0".to_owned(),
            },
            Request::ReleaseDhcpClient {
                interface: "wan0".to_owned(),
            },
            Request::ApplyInterface {
                interface: "eth0".to_owned(),
                config: interface_config(),
                allow_management_change: false,
            },
            Request::ApplyInterfaceEdit {
                interface: "eth0".to_owned(),
                edit: interface_edit(),
            },
            Request::CommitNetworkChange {
                token: "transaction-token".to_owned(),
            },
            Request::RollbackNetworkChange {
                token: "transaction-token".to_owned(),
            },
            Request::VpnPolicySetMode {
                mode: crate::config::VpnPolicyMode::Direct,
            },
            Request::VpnPolicyClearMode,
            Request::ConfigureSecuritySettings {
                settings: SecuritySettings {
                    rollback_timeout_seconds: 60,
                },
            },
            Request::ResetSecuritySettings,
            Request::ProvisionWifiAccessPoint {
                interface: "wlan0".to_owned(),
                settings: WifiEditRequest {
                    ssid: "provisioned".to_owned(),
                    country_code: None,
                    band: Default::default(),
                    channel: 0,
                    channel_width: Default::default(),
                    security: Default::default(),
                    hidden: false,
                    client_isolation: false,
                    max_stations: 32,
                },
                passphrase: Some("write-only-secret".to_owned()),
                configure_dhcp: true,
            },
            Request::ConfigureWifiClient {
                interface: "wlan0".to_owned(),
                settings: WifiClientEditRequest {
                    ssid: "upstream".to_owned(),
                    country_code: None,
                    security: crate::config::WifiClientSecurity::Open,
                },
            },
            Request::DisableWifiClient {
                interface: "wlan0".to_owned(),
            },
            Request::WifiClientSetPassphrase {
                interface: "wlan0".to_owned(),
                passphrase: "a-secret-value".to_owned(),
            },
            Request::WifiClientReconnect {
                interface: "wlan0".to_owned(),
            },
            Request::WifiClientScan {
                interface: "wlan0".to_owned(),
            },
            Request::CreateWifiClientProfile {
                profile: WifiClientProfileWriteRequest {
                    id: "office".to_owned(),
                    ssid: "upstream".to_owned(),
                    country_code: None,
                    security: crate::config::WifiClientSecurity::Open,
                    priority: 0,
                    passphrase: None,
                    clear_passphrase: false,
                },
            },
            Request::UpdateWifiClientProfile {
                id: "office".to_owned(),
                profile: WifiClientProfileWriteRequest {
                    id: "office".to_owned(),
                    ssid: "updated".to_owned(),
                    country_code: None,
                    security: crate::config::WifiClientSecurity::Open,
                    priority: 1,
                    passphrase: None,
                    clear_passphrase: false,
                },
            },
            Request::DeleteWifiClientProfile {
                id: "office".to_owned(),
            },
            Request::ActivateWifiClientProfile {
                interface: "wlan0".to_owned(),
                profile_id: "office".to_owned(),
            },
            Request::DeactivateWifiClientProfile {
                interface: "wlan0".to_owned(),
            },
        ];
        for request in mutation_requests {
            assert!(control_request_requires_administrator(&request));
            assert!(matches!(
                authorize_control_request(&principal(Role::Viewer), &request),
                Err(ApiError::Forbidden)
            ));
            assert!(matches!(
                authorize_control_request(&principal(Role::Operator), &request),
                Err(ApiError::Forbidden)
            ));
            assert!(authorize_control_request(&principal(Role::Administrator), &request).is_ok());
        }
    }

    #[test]
    fn first_time_initialization_accepts_only_local_root_connections() {
        assert!(ConnectionInfo::Unix {
            pid: Some(1),
            uid: Some(0),
            gid: Some(0),
        }
        .is_local_root());
        assert!(!ConnectionInfo::Unix {
            pid: Some(1000),
            uid: Some(1000),
            gid: Some(1000),
        }
        .is_local_root());
        assert!(!ConnectionInfo::Tls {
            peer: "127.0.0.1:12345".parse().expect("peer"),
        }
        .is_local_root());
    }

    #[test]
    fn bearer_header_parser_is_strict_and_case_insensitive() {
        use axum::http::HeaderValue;

        assert_eq!(
            bearer_token(Some(&HeaderValue::from_static("Bearer opaque-token"))),
            Some("opaque-token")
        );
        assert_eq!(
            bearer_token(Some(&HeaderValue::from_static("bearer opaque-token"))),
            Some("opaque-token")
        );
        assert_eq!(
            bearer_token(Some(&HeaderValue::from_static("Basic opaque-token"))),
            None
        );
        assert_eq!(
            bearer_token(Some(&HeaderValue::from_static("Bearer one two"))),
            None
        );
    }
}
