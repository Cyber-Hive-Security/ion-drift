use axum::extract::State;
use axum::response::{Json, Response};
use serde::Serialize;
use std::collections::HashMap;

use crate::middleware::RequireAuth;
use crate::state::AppState;
use super::api_error;

#[derive(Serialize)]
pub struct ConnectionSummary {
    pub total_connections: usize,
    pub tcp_count: usize,
    pub udp_count: usize,
    pub other_count: usize,
    pub max_entries: Option<u64>,
}

/// Normalize protocol name — RouterOS may return either the name ("tcp")
/// or the IANA protocol number ("6").
fn normalize_protocol(proto: &str) -> &str {
    match proto {
        "6" | "tcp" => "tcp",
        "17" | "udp" => "udp",
        _ => "other",
    }
}

/// GET /api/connections/summary
pub async fn summary(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<ConnectionSummary>, Response> {
    let connections = state
        .mikrotik
        .firewall_connections(".id,protocol")
        .await
        .map_err(api_error)?;

    let tracking = state
        .mikrotik
        .connection_tracking()
        .await
        .map_err(api_error)?;

    let mut counts: HashMap<&str, usize> = HashMap::new();
    for c in &connections {
        let key = c.protocol.as_deref().map(normalize_protocol).unwrap_or("other");
        *counts.entry(key).or_default() += 1;
    }

    Ok(Json(ConnectionSummary {
        total_connections: connections.len(),
        tcp_count: counts.get("tcp").copied().unwrap_or(0),
        udp_count: counts.get("udp").copied().unwrap_or(0),
        other_count: counts.get("other").copied().unwrap_or(0),
        max_entries: tracking.max_entries,
    }))
}
