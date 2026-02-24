//! History API endpoints for browsing weekly snapshots.

use axum::extract::{Path, State};
use axum::response::{Json, Response};

use crate::middleware::RequireAuth;
use crate::state::AppState;
use super::internal_error;

/// GET /api/history/snapshots — list available weekly snapshots.
pub async fn list_snapshots(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::connection_store::SnapshotListEntry>>, Response> {
    let snapshots = state
        .connection_store
        .list_snapshots()
        .map_err(|e| internal_error("list snapshots", e))?;
    Ok(Json(snapshots))
}

/// GET /api/history/snapshot/:week/:type — get a specific snapshot.
pub async fn get_snapshot(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Path((week, snapshot_type)): Path<(String, String)>,
) -> Result<Json<Option<crate::connection_store::WeeklySnapshot>>, Response> {
    let snapshot = state
        .connection_store
        .get_snapshot(&week, &snapshot_type)
        .map_err(|e| internal_error("get snapshot", e))?;
    Ok(Json(snapshot))
}
