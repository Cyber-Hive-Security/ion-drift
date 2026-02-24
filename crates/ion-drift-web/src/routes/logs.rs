use axum::extract::{Query, State};
use axum::response::{Json, Response};
use serde::Deserialize;

use crate::log_parser::{self, LogsResponse, StructuredLogEntry};
use crate::middleware::RequireAuth;
use crate::state::AppState;

use super::api_error;

#[derive(Deserialize, Default)]
pub struct LogFilter {
    /// Comma-separated topic filter (e.g., "firewall,dhcp").
    pub topics: Option<String>,
    /// Max entries to return (from the tail).
    pub limit: Option<usize>,
    /// Filter by action: "drop", "accept", or "all".
    pub action: Option<String>,
    /// Filter by severity: "info", "warning", "error", "critical".
    pub severity: Option<String>,
}

pub async fn list(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(f): Query<LogFilter>,
) -> Result<Json<LogsResponse>, Response> {
    let raw_entries = state.mikrotik.log_entries().await.map_err(api_error)?;

    // Parse all entries into structured form
    let entries: Vec<StructuredLogEntry> = raw_entries
        .iter()
        .map(|e| log_parser::parse_log_entry(e, &state.geo_cache, &state.oui_db))
        .collect();

    // Deduplicate log+drop/accept pairs (same packet, non-terminating log rule
    // followed by terminating rule) before filtering and analytics.
    let mut entries = log_parser::deduplicate_log_pairs(entries);

    // Filter by topics
    if let Some(ref topics) = f.topics {
        let filter_topics: Vec<&str> = topics.split(',').map(|s| s.trim()).collect();
        entries.retain(|e| {
            e.topics
                .iter()
                .any(|t| filter_topics.iter().any(|ft| t.contains(ft)))
        });
    }

    // Filter by action
    if let Some(ref action) = f.action {
        if action != "all" {
            entries.retain(|e| {
                e.parsed
                    .as_ref()
                    .and_then(|p| p.action.as_deref())
                    .map(|a| a == action)
                    .unwrap_or(false)
            });
        }
    }

    // Filter by severity
    if let Some(ref severity) = f.severity {
        if severity != "all" {
            entries.retain(|e| e.level == *severity);
        }
    }

    // Compute analytics before truncating
    let analytics = log_parser::compute_analytics(&entries);

    // Limit to last N entries (capped at 5000)
    let limit = f.limit.unwrap_or(500).min(5000);
    let len = entries.len();
    if limit < len {
        entries = entries.split_off(len - limit);
    }

    Ok(Json(LogsResponse { entries, analytics }))
}
