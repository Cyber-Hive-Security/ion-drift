use axum::extract::{Query, State};
use axum::response::{Json, Response};
use serde::Deserialize;

use crate::middleware::RequireAuth;
use crate::state::AppState;
use super::api_error;

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
