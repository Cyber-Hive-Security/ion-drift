use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde::Deserialize;

use crate::middleware::RequireAuth;
use crate::state::AppState;

#[derive(Deserialize, Default)]
pub struct InterfaceFilter {
    #[serde(rename = "type")]
    pub iface_type: Option<String>,
    pub running: Option<bool>,
}

pub async fn list(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(filter): Query<InterfaceFilter>,
) -> Result<Json<serde_json::Value>, Response> {
    let mut interfaces = state.mikrotik.interfaces().await.map_err(api_error)?;

    if let Some(ref t) = filter.iface_type {
        interfaces.retain(|i| i.iface_type == *t);
    }
    if let Some(running) = filter.running {
        interfaces.retain(|i| i.running == running);
    }

    Ok(Json(serde_json::to_value(interfaces).unwrap()))
}

pub async fn vlans(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let vlans = state.mikrotik.vlan_interfaces().await.map_err(api_error)?;
    Ok(Json(serde_json::to_value(vlans).unwrap()))
}

fn api_error(e: mikrotik_core::MikrotikError) -> Response {
    tracing::error!("router API error: {e}");
    (
        StatusCode::BAD_GATEWAY,
        Json(serde_json::json!({ "error": e.to_string() })),
    )
        .into_response()
}
