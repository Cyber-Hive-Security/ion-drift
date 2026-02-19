use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde::Deserialize;

use crate::middleware::RequireAuth;
use crate::state::AppState;

#[derive(Deserialize, Default)]
pub struct LogFilter {
    pub topics: Option<String>,
    pub limit: Option<usize>,
}

pub async fn list(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
    Query(f): Query<LogFilter>,
) -> Result<Json<serde_json::Value>, Response> {
    let mut entries = state.mikrotik.log_entries().await.map_err(api_error)?;

    if let Some(ref topics) = f.topics {
        let filter_topics: Vec<&str> = topics.split(',').collect();
        entries.retain(|e| {
            if let Some(ref t) = e.topics {
                filter_topics.iter().any(|ft| t.contains(ft))
            } else {
                false
            }
        });
    }

    if let Some(limit) = f.limit {
        // Return the last N entries (most recent)
        let len = entries.len();
        if limit < len {
            entries = entries.split_off(len - limit);
        }
    }

    Ok(Json(serde_json::to_value(entries).unwrap()))
}

fn api_error(e: mikrotik_core::MikrotikError) -> Response {
    tracing::error!("router API error: {e}");
    (
        StatusCode::BAD_GATEWAY,
        Json(serde_json::json!({ "error": e.to_string() })),
    )
        .into_response()
}
