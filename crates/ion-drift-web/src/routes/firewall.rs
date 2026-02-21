use axum::extract::{Query, State};
use axum::response::{Json, Response};
use serde::{Deserialize, Serialize};

use crate::middleware::RequireAuth;
use crate::state::AppState;
use super::api_error;

#[derive(Serialize)]
pub struct FirewallDropsSummary {
    pub total_drop_packets: u64,
    pub total_drop_bytes: u64,
}

/// GET /api/firewall/drops
pub async fn drops(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<FirewallDropsSummary>, Response> {
    let rules = state
        .mikrotik
        .firewall_filter_rules()
        .await
        .map_err(api_error)?;

    let (total_packets, total_bytes) = rules
        .iter()
        .filter(|r| r.action == "drop")
        .fold((0u64, 0u64), |(p, b), r| {
            (p + r.packets.unwrap_or(0), b + r.bytes.unwrap_or(0))
        });

    Ok(Json(FirewallDropsSummary {
        total_drop_packets: total_packets,
        total_drop_bytes: total_bytes,
    }))
}

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
