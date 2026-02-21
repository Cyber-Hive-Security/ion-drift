use axum::extract::State;
use axum::response::{Json, Response};

use crate::middleware::RequireAuth;
use crate::state::AppState;

use super::api_error;

/// GET /api/traffic/vlan-flows
pub async fn vlan_flows(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let flows = mikrotik_core::VlanFlowManager::get_flows(&state.mikrotik)
        .await
        .map_err(api_error)?;
    Ok(Json(serde_json::to_value(flows).unwrap()))
}
