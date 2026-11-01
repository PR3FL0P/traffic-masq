use super::*;

pub(super) async fn get_api_https_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::GetApiHttpsConfig).await
}

pub(super) async fn put_api_https_config(
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

pub(super) async fn delete_api_https_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::ResetApiHttpsSettings).await
}

pub(super) async fn get_security_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::GetSecurityConfig).await
}

pub(super) async fn put_security_config(
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

pub(super) async fn delete_security_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::ResetSecuritySettings).await
}
