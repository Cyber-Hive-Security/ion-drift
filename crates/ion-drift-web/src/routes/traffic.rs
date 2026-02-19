use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};

use crate::middleware::RequireAuth;
use crate::state::AppState;

pub async fn current(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    let totals = state.traffic_tracker.get_totals().await.map_err(|e| {
        tracing::error!("traffic tracker error: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response()
    })?;

    Ok(Json(serde_json::to_value(totals).unwrap()))
}
