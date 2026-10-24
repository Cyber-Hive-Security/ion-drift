use axum::extract::{Query, State};
use axum::response::{Json, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{api_error, internal_error, live_or_degrade, Degradable, LiveOr};
use crate::middleware::RequireAuth;
use crate::state::AppState;
use mikrotik_core::resources::firewall::FilterRule;

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
    pub logs_unavailable: bool,
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
    let (top_drop_countries, logs_unavailable) = {
        let (logs, logs_unavailable) = match state.mikrotik.log_entries().await {
            Ok(logs) => (logs, false),
            Err(e) => {
                tracing::warn!("failed to load firewall logs for drop summary: {e}");
                (Vec::new(), true)
            }
        };
        let mut country_counts: HashMap<String, (String, usize)> = HashMap::new();

        for entry in &logs {
            if !entry.message.contains("drop") && !entry.message.contains("input") {
                continue;
            }
            for word in entry.message.split_whitespace() {
                if let Some(ip_str) = word
                    .strip_prefix("src=")
                    .or_else(|| word.strip_prefix("src-address="))
                {
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
                flagged: state.geo_cache.is_flagged(&code),
                code,
                name,
                count,
            })
            .collect();
        entries.sort_by_key(|x| std::cmp::Reverse(x.count));
        entries.truncate(5);
        (entries, logs_unavailable)
    };

    Ok(Json(FirewallDropsSummary {
        total_drop_packets: total_packets,
        total_drop_bytes: total_bytes,
        top_drop_countries,
        logs_unavailable,
    }))
}

#[derive(Deserialize, Default)]
pub struct ChainFilter {
    pub chain: Option<String>,
}

/// GET /api/firewall/filter
///
/// Degrades to the last-known rules from `firewall_rules_cache` when the router
/// is unreachable, instead of 502ing (DRIFT P3). The cache holds only a
/// monotonic `Instant`, so no wall-clock `as_of` is available on the degraded
/// path.
pub async fn filter(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(f): Query<ChainFilter>,
) -> Result<Json<Degradable<FilterRule>>, Response> {
    match live_or_degrade(state.mikrotik.firewall_filter_rules().await) {
        LiveOr::Live(mut rules) => {
            if let Some(ref chain) = f.chain {
                rules.retain(|r| r.chain == *chain);
            }
            Ok(Json(Degradable::live(rules)))
        }
        LiveOr::Degraded => {
            let cached = state.firewall_rules_cache.read().await;
            let rules = filter_rules_by_chain(&cached.0, f.chain.as_deref());
            Ok(Json(Degradable::degraded(rules, None)))
        }
    }
}

/// Filter cached filter rules by chain (pure — unit-testable).
fn filter_rules_by_chain(rules: &[FilterRule], chain: Option<&str>) -> Vec<FilterRule> {
    rules
        .iter()
        .filter(|r| chain.is_none_or(|c| r.chain == c))
        .cloned()
        .collect()
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

    Ok(Json(
        serde_json::to_value(rules).map_err(|e| internal_error("serialize nat rules", e))?,
    ))
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

    Ok(Json(serde_json::to_value(rules).map_err(|e| {
        internal_error("serialize mangle rules", e)
    })?))
}

#[cfg(test)]
mod degradation_tests {
    use super::*;
    use crate::routes::{live_or_degrade, Degradable, LiveOr};
    use mikrotik_core::MikrotikError;

    fn rule(id: &str, chain: &str) -> FilterRule {
        serde_json::from_value(serde_json::json!({
            ".id": id,
            "chain": chain,
            "action": "accept",
        }))
        .expect("valid FilterRule")
    }

    #[test]
    fn filter_rules_by_chain_filters_and_passes_through() {
        let rules = vec![rule("*1", "forward"), rule("*2", "input"), rule("*3", "forward")];
        assert_eq!(filter_rules_by_chain(&rules, None).len(), 3);
        let forward = filter_rules_by_chain(&rules, Some("forward"));
        assert_eq!(forward.len(), 2);
        assert!(forward.iter().all(|r| r.chain == "forward"));
        assert_eq!(filter_rules_by_chain(&rules, Some("nope")).len(), 0);
    }

    #[test]
    fn degraded_envelope_marks_unavailable() {
        let env = Degradable::degraded(vec![rule("*1", "forward")], None);
        assert!(!env.live_available);
        assert_eq!(env.items.len(), 1);
        let v = serde_json::to_value(&env).unwrap();
        assert_eq!(v["live_available"], serde_json::json!(false));
        assert!(v.get("as_of").is_none());
    }

    #[test]
    fn live_envelope_marks_available() {
        let env = Degradable::live(vec![rule("*1", "forward")]);
        let v = serde_json::to_value(&env).unwrap();
        assert_eq!(v["live_available"], serde_json::json!(true));
    }

    #[test]
    fn erroring_call_maps_to_degraded() {
        let r: Result<Vec<FilterRule>, MikrotikError> = Err(MikrotikError::AuthFailed);
        assert!(matches!(live_or_degrade(r), LiveOr::Degraded));
    }
}
