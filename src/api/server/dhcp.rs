use super::*;

pub(super) async fn dhcp_status(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::DhcpStatus).await
}

pub(super) async fn get_interface_config(
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

pub(super) async fn dhcp_client_status(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::DhcpClientStatus).await
}

pub(super) async fn get_dhcp_client(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::GetDhcpClient { interface }).await
}

pub(super) async fn put_dhcp_client(
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

pub(super) async fn delete_dhcp_client(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::DisableDhcpClient { interface }).await
}

pub(super) async fn renew_dhcp_client(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::RenewDhcpClient { interface }).await
}

pub(super) async fn release_dhcp_client(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::ReleaseDhcpClient { interface }).await
}

pub(super) async fn get_dhcp_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::GetDhcpConfig { interface }).await
}

pub(super) async fn put_dhcp_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
    Json(config): Json<DhcpEditRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::ConfigureDhcp { interface, config },
    )
    .await
}

pub(super) async fn put_dhcp_settings(
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

pub(super) async fn delete_dhcp_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::DisableDhcp { interface }).await
}

pub(super) async fn list_dhcp_leases(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::ListLeases { interface }).await
}
