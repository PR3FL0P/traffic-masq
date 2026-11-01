use super::*;

#[derive(Debug, Deserialize)]
pub struct ListRoutesQuery {
    #[serde(default)]
    pub include_local_table: bool,
}

pub(super) async fn list_route_inventory(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<ListRoutesQuery>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::ListRouteInventory {
            include_local_table: query.include_local_table,
        },
    )
    .await
}

pub(super) async fn routes_list(
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

#[derive(Deserialize)]
pub(super) struct LogQuery {
    #[serde(default = "default_log_limit")]
    limit: usize,
}
pub(super) fn default_log_limit() -> usize {
    500
}
pub(super) async fn daemon_logs(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<LogQuery>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::DaemonLogs { limit: query.limit },
    )
    .await
}

pub(super) async fn router_get_config(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::GetRouterConfig).await
}

pub(super) async fn router_status(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::RouterStatus).await
}

#[derive(Deserialize)]
pub(super) struct SaveRouterIntentBody {
    config: traffic_masq_protocol::RouterConfigView,
    expected_revision: u64,
}

pub(super) async fn save_router_intent(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(request): Json<SaveRouterIntentBody>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::SaveRouterIntent {
            config: request.config,
            expected_revision: request.expected_revision,
        },
    )
    .await
}

pub(super) async fn router_intent_preview(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(proposal): Json<traffic_masq_protocol::RouterProposalRequestView>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::RouterIntentPreview { proposal },
    )
    .await
}

pub(super) async fn router_plan(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(proposal): Json<traffic_masq_protocol::RouterProposalRequestView>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::RouterPlan { proposal }).await
}

pub(super) async fn router_apply(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(proposal): Json<traffic_masq_protocol::RouterProposalRequestView>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::RouterApply { proposal }).await
}

pub(super) async fn router_commit(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(request): Json<TransactionRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::RouterCommit {
            token: request.token,
        },
    )
    .await
}

pub(super) async fn router_rollback(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(request): Json<TransactionRequest>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(
        &state,
        &principal,
        Request::RouterRollback {
            token: request.token,
        },
    )
    .await
}

pub(super) async fn router_pending_transaction(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::RouterPendingTransaction).await
}

pub(super) async fn router_provisioning_preview(
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

pub(super) async fn router_provisioning_apply(
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

pub(super) async fn router_provisioning_status(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::RouterProvisioningStatus).await
}

pub(super) async fn router_provisioning_repair(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Response>, ApiError> {
    dispatch_control(&state, &principal, Request::RouterProvisioningRepair).await
}
