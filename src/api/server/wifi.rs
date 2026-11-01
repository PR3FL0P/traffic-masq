use super::*;

pub(super) async fn wifi_status(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::WifiStatus).await
}

pub(super) async fn get_wifi_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::GetWifiConfig { interface }).await
}

pub(super) async fn put_wifi_config(
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

pub(super) async fn provision_wifi_access_point(
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
            clear_passphrase: request.clear_passphrase,
            configure_dhcp: request.configure_dhcp,
            subnet: request.subnet,
            disable_dhcp: request.disable_dhcp,
        },
    )
    .await
}

pub(super) async fn delete_wifi_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::DisableWifi { interface }).await
}

#[derive(Deserialize)]
pub(super) struct WifiPassphraseRequest {
    passphrase: String,
}

pub(super) async fn put_wifi_passphrase(
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

pub(super) async fn list_wifi_stations(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::ListWifiStations { interface }).await
}

pub(super) async fn wifi_deauth_station(
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

pub(super) async fn wifi_reload(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::WifiReload { interface }).await
}

pub(super) async fn wifi_client_status(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::WifiClientStatus).await
}

pub(super) async fn get_wifi_client_config(
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

pub(super) async fn put_wifi_client_config(
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

pub(super) async fn delete_wifi_client_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::DisableWifiClient { interface }).await
}

pub(super) async fn put_wifi_client_passphrase(
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

pub(super) async fn list_wifi_client_profiles(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::ListWifiClientProfiles).await
}

pub(super) async fn get_wifi_client_profile(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::GetWifiClientProfile { id }).await
}

pub(super) async fn create_wifi_client_profile(
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

pub(super) async fn update_wifi_client_profile(
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

pub(super) async fn delete_wifi_client_profile(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::DeleteWifiClientProfile { id }).await
}

pub(super) async fn provision_wifi_client(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
    Json(settings): Json<crate::api::model::ProvisionWifiClientRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::ProvisionWifiClient {
            interface,
            settings,
        },
    )
    .await
}

pub(super) async fn activate_wifi_client_profile(
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

pub(super) async fn deactivate_wifi_client_profile(
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

pub(super) async fn wifi_client_scan(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::WifiClientScan { interface }).await
}

pub(super) async fn wifi_client_reconnect(
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

/// Typed control transport; REST adapters use the same authorization and dispatcher.

pub(super) async fn list_wifi_ap_profiles(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::ListWifiApProfiles).await
}
pub(super) async fn save_wifi_ap_profile(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(profile): Json<crate::api::model::WifiApProfileWriteRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::SaveWifiApProfile { profile }).await
}
pub(super) async fn delete_wifi_ap_profile(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::DeleteWifiApProfile { id }).await
}
pub(super) async fn activate_wifi_ap_profile(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
    Json(request): Json<WifiClientProfileActivationRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::ActivateWifiApProfile {
            interface,
            profile_id: request.profile_id,
        },
    )
    .await
}
