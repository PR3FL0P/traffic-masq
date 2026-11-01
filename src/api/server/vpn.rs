use super::*;

pub(super) async fn vpn_list_sources(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::VpnListSources).await
}
pub(super) async fn vpn_import_from_source(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(name): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::VpnImportFromSource { name }).await
}

pub(super) async fn vpn_list_profiles(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::VpnListProfiles).await
}

#[derive(Deserialize)]
pub(super) struct VpnImportProfileRequest {
    name: String,
    contents: String,
}

pub(super) async fn vpn_import_profile(
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

pub(super) async fn vpn_delete_profile(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(name): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::VpnDeleteProfile { name }).await
}

pub(super) async fn vpn_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::GetVpnConfig).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VpnEnabledRequest {
    enabled: bool,
}

pub(super) async fn set_vpn_enabled(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(request): Json<VpnEnabledRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::SetVpnEnabled {
            enabled: request.enabled,
        },
    )
    .await
}

pub(super) async fn vpn_status(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::VpnStatus).await
}

#[derive(Deserialize)]
pub(super) struct VpnActivateRequest {
    name: String,
}

pub(super) async fn vpn_activate(
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

pub(super) async fn vpn_deactivate(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::VpnDeactivate).await
}

pub(super) async fn vpn_policy_status(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::VpnPolicyStatus).await
}

#[derive(Deserialize)]
pub(super) struct VpnPolicySetModeRequest {
    mode: crate::config::VpnPolicyMode,
}

pub(super) async fn vpn_policy_set_mode(
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

pub(super) async fn vpn_policy_clear_mode(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::VpnPolicyClearMode).await
}
