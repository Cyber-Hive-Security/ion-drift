//! Policy API endpoints — infrastructure policy map and sync control.

use axum::extract::State;
use axum::response::{Json, Response};
use serde::Serialize;

use super::internal_error;
use crate::middleware::RequireAuth;
use crate::state::AppState;

#[derive(Serialize)]
pub struct PolicyEntry {
    pub id: i64,
    pub service: String,
    pub protocol: Option<String>,
    pub port: Option<i64>,
    pub authorized_targets: Vec<String>,
    pub vlan_scope: Option<Vec<i64>>,
    pub source: String,
    pub priority: String,
    pub last_synced: i64,
}

#[derive(Serialize)]
pub struct IonTagEntry {
    pub rule_id: String,
    pub chain: String,
    pub action: String,
    pub tag: String,
    pub comment: String,
    pub rule_summary: String,
    pub last_synced: i64,
}

#[derive(Serialize)]
pub struct PolicyOverview {
    pub policies: Vec<PolicyEntry>,
    pub ion_tags: Vec<IonTagEntry>,
    pub policy_count: usize,
    pub tag_count: usize,
}

/// GET /api/policy
pub async fn policy_overview(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<PolicyOverview>, Response> {
    let policies = state
        .behavior_store
        .get_all_policies()
        .await
        .map_err(|e| internal_error("policy overview", e))?;

    let ion_tags = state
        .behavior_store
        .get_ion_tags()
        .await
        .map_err(|e| internal_error("policy ion tags", e))?;

    let policy_entries: Vec<PolicyEntry> = policies
        .into_iter()
        .map(|p| PolicyEntry {
            id: p.id,
            service: p.service,
            protocol: p.protocol,
            port: p.port,
            authorized_targets: p.authorized_targets,
            vlan_scope: p.vlan_scope,
            source: p.source,
            priority: p.priority,
            last_synced: p.last_synced,
        })
        .collect();

    let tag_entries: Vec<IonTagEntry> = ion_tags
        .into_iter()
        .map(|t| IonTagEntry {
            rule_id: t.rule_id,
            chain: t.chain,
            action: t.action,
            tag: t.tag,
            comment: t.comment,
            rule_summary: t.rule_summary,
            last_synced: t.last_synced,
        })
        .collect();

    let policy_count = policy_entries.len();
    let tag_count = tag_entries.len();

    Ok(Json(PolicyOverview {
        policies: policy_entries,
        ion_tags: tag_entries,
        policy_count,
        tag_count,
    }))
}
