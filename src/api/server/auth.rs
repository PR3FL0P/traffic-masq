use super::*;

#[derive(Deserialize)]
pub(super) struct LoginRequest {
    password: Zeroizing<String>,
    #[serde(default)]
    client: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct PasswordRequest {
    password: Zeroizing<String>,
}

#[derive(Deserialize)]
pub(super) struct ChangePasswordRequest {
    current_password: Zeroizing<String>,
    new_password: Zeroizing<String>,
}

#[derive(Serialize)]
pub(super) struct AuthStatusResponse {
    initialized: bool,
}

pub(super) async fn auth_status(
    State(state): State<AppState>,
) -> Result<Json<AuthStatusResponse>, ApiError> {
    let initialized = state.auth.is_initialized().await.map_err(|error| {
        tracing::error!(%error, "failed to read authentication initialization state");
        ApiError::Internal
    })?;
    Ok(Json(AuthStatusResponse { initialized }))
}

pub(super) async fn initialize_password(
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
            AuthError::Busy => ApiError::Busy,
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

pub(super) async fn login(
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
        Err(AuthError::Busy) => Err(ApiError::Busy),
        Err(error) => {
            tracing::error!(%error, "login failed");
            Err(ApiError::Internal)
        }
    }
}

pub(super) async fn logout(
    State(state): State<AppState>,
    Extension(token): Extension<BearerToken>,
) -> Result<StatusCode, ApiError> {
    state.auth.logout(&token.0).await.map_err(|error| {
        tracing::error!(%error, "logout failed");
        ApiError::Internal
    })?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn current_principal(
    Extension(principal): Extension<Principal>,
) -> Json<Principal> {
    Json(principal)
}

pub(super) async fn change_password(
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
            AuthError::Busy => ApiError::Busy,
            AuthError::WeakPassword => ApiError::BadRequest(WEAK_PASSWORD_MESSAGE),
            other => {
                tracing::error!(error = %other, "device password change failed");
                ApiError::Internal
            }
        })?;
    Ok(StatusCode::NO_CONTENT)
}
