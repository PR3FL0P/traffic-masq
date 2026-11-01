use super::*;

#[derive(Deserialize)]
pub(super) struct InterfaceChangeRequest {
    config: traffic_masq_protocol::InterfaceConfigView,
    #[serde(default)]
    allow_management_change: bool,
}

pub(super) async fn plan_interface(
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

pub(super) async fn apply_interface(
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

pub(super) async fn plan_interface_edit(
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

pub(super) async fn apply_interface_edit(
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

pub(super) async fn pending_transactions(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::PendingNetworkChanges).await
}

#[derive(Deserialize)]
pub(super) struct TransactionRequest {
    pub(super) token: String,
}

pub(super) async fn commit_transaction(
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

pub(super) async fn rollback_transaction(
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
