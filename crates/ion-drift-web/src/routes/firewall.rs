use axum::extract::{Query, State};
use axum::response::{Json, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::geo::GeoCache;
use crate::middleware::RequireAuth;
use crate::state::AppState;
use super::{api_error, internal_error};

#[derive(Serialize)]
pub struct DropCountryEntry {
    pub code: String,
    pub name: String,
    pub count: usize,
    pub flagged: bool,
}

#[derive(Serialize)]
pub struct FirewallDropsSummary {
    pub total_drop_packets: u64,
    pub total_drop_bytes: u64,
    pub top_drop_countries: Vec<DropCountryEntry>,
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

    // Try to resolve top drop source countries from recent log entries
    // Resolve top drop source countries from recent log entries (cache-only geo)
    let top_drop_countries = {
        let logs = state.mikrotik.log_entries().await.unwrap_or_default();
        let mut country_counts: HashMap<String, (String, usize)> = HashMap::new();

        for entry in &logs {
            if !entry.message.contains("drop") && !entry.message.contains("input") {
                continue;
            }
            for word in entry.message.split_whitespace() {
                if let Some(ip_str) = word.strip_prefix("src=").or_else(|| word.strip_prefix("src-address=")) {
                    let ip = ip_str.split(':').next().unwrap_or(ip_str);
                    if let Some(geo) = state.geo_cache.lookup_cached(ip) {
                        let entry = country_counts
                            .entry(geo.country_code.clone())
                            .or_insert_with(|| (geo.country.clone(), 0));
                        entry.1 += 1;
                    }
                }
            }
        }

        let mut entries: Vec<DropCountryEntry> = country_counts
            .into_iter()
            .map(|(code, (name, count))| DropCountryEntry {
                flagged: GeoCache::is_flagged(&code),
                code,
                name,
                count,
            })
            .collect();
        entries.sort_by(|a, b| b.count.cmp(&a.count));
        entries.truncate(5);
        entries
    };

    Ok(Json(FirewallDropsSummary {
        total_drop_packets: total_packets,
        total_drop_bytes: total_bytes,
        top_drop_countries,
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

    Ok(Json(serde_json::to_value(rules).map_err(|e| internal_error("serialize filter rules", e))?))
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

    Ok(Json(serde_json::to_value(rules).map_err(|e| internal_error("serialize nat rules", e))?))
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

    Ok(Json(serde_json::to_value(rules).map_err(|e| internal_error("serialize mangle rules", e))?))
}
