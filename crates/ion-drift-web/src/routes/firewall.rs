use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde::Deserialize;

use crate::middleware::RequireAuth;
use crate::state::AppState;

#[derive(Deserialize, Default)]
pub struct ChainFilter {
    pub chain: Option<String>,
}

pub async fn filter(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(f): Query<ChainFilter>,
) -> Result<Json<serde_json::Value>, Response> {
    let mut rules = state
        .mikrotik
        .firewall_filter_rules()
        .await
        .map_err(api_error)?;

    if let Some(ref chain) = f.chain {
        rules.retain(|r| r.chain == *chain);
    }

    Ok(Json(serde_json::to_value(rules).unwrap()))
}

pub async fn nat(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(f): Query<ChainFilter>,
) -> Result<Json<serde_json::Value>, Response> {
    let mut rules = state
        .mikrotik
        .firewall_nat_rules()
        .await
        .map_err(api_error)?;

    if let Some(ref chain) = f.chain {
        rules.retain(|r| r.chain == *chain);
    }

    Ok(Json(serde_json::to_value(rules).unwrap()))
}

pub async fn mangle(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(f): Query<ChainFilter>,
) -> Result<Json<serde_json::Value>, Response> {
    let mut rules = state
        .mikrotik
        .firewall_mangle_rules()
        .await
        .map_err(api_error)?;

    if let Some(ref chain) = f.chain {
        rules.retain(|r| r.chain == *chain);
    }

    Ok(Json(serde_json::to_value(rules).unwrap()))
}

fn api_error(e: mikrotik_core::MikrotikError) -> Response {
    tracing::error!("router API error: {e}");
    (
        StatusCode::BAD_GATEWAY,
        Json(serde_json::json!({ "error": e.to_string() })),
    )
        .into_response()
}
