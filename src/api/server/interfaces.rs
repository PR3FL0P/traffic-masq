use super::*;

pub(super) async fn list_interfaces(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::ListInterfaces).await
}

pub(super) async fn list_wifi_inventory(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::ListWifiInventory).await
}

#[derive(Deserialize)]
pub(super) struct SaveWifiClientIntentRequest {
    settings: traffic_masq_protocol::ProvisionWifiClientRequest,
    expected_revision: u64,
}

pub(super) async fn save_wifi_client_intent(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
    Json(request): Json<SaveWifiClientIntentRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::SaveWifiClientProfile {
            interface,
            settings: request.settings,
            expected_revision: request.expected_revision,
        },
    )
    .await
}

#[derive(Deserialize)]
pub(super) struct SaveWifiIntentRequest {
    config: traffic_masq_protocol::InterfaceConfigView,
    expected_revision: u64,
    #[serde(default)]
    passphrase: Option<String>,
}

pub(super) async fn save_wifi_intent(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
    Json(request): Json<SaveWifiIntentRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::SaveWifiInterface {
            interface,
            config: request.config,
            expected_revision: request.expected_revision,
            passphrase: request.passphrase,
        },
    )
    .await
}

pub(super) async fn list_interface_inventory(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::ListInterfaceInventory).await
}

#[derive(Deserialize)]
pub(super) struct SaveInterfaceIntentRequest {
    pub(super) config: traffic_masq_protocol::InterfaceConfigView,
    #[serde(default)]
    allow_management_change: bool,
    expected_revision: u64,
}

#[derive(Deserialize)]
pub(super) struct IntentRevisionRequest {
    expected_revision: u64,
}

pub(super) async fn save_interface_intent(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
    Json(request): Json<SaveInterfaceIntentRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::SaveInterfaceConfig {
            interface,
            config: request.config,
            allow_management_change: request.allow_management_change,
            expected_revision: request.expected_revision,
        },
    )
    .await
}

pub(super) async fn forget_interface_intent(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
    Json(request): Json<IntentRevisionRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::ForgetInterfaceConfig {
            interface,
            expected_revision: request.expected_revision,
        },
    )
    .await
}

pub(super) async fn reset_interface_intent(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    AxumPath(interface): AxumPath<String>,
    Json(request): Json<IntentRevisionRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::ResetInterfaceOverride {
            interface,
            expected_revision: request.expected_revision,
        },
    )
    .await
}
