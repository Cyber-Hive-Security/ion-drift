//! Vulnerability feed status and consent.
//!
//! Anyone signed in may read the status (the Findings page needs it); only an
//! administrator may answer the consent question. `unanswered` is rejected as
//! an answer so the only way out of the dialog is an explicit on or off.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use ion_drift_storage::FeedSourceState;
use serde::{Deserialize, Serialize};

use super::internal_error;
use crate::advisory::consent::{self, ConsentRecord, FeedConsent};
use crate::advisory::exploitation::now_unix;
use crate::middleware::{RequireAdmin, RequireAuth};
use crate::state::AppState;

/// A source is stale once it has been tried and has not succeeded for this long.
pub(crate) const STALE_AFTER_SECS: i64 = 3 * 86_400;

#[derive(Serialize)]
pub struct FeedStatusResponse {
    #[serde(flatten)]
    consent: ConsentRecord,
    sources: Vec<FeedSourceState>,
    stale: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentBody {
    consent: FeedConsent,
}

pub(crate) fn is_stale(consent: FeedConsent, sources: &[FeedSourceState], now: i64) -> bool {
    consent == FeedConsent::On
        && sources
            .iter()
            .any(|s| s.last_success_at.is_none_or(|t| now - t > STALE_AFTER_SECS))
}

async fn build_status(state: &AppState) -> Result<FeedStatusResponse, Response> {
    let consent = consent::load(&state.switch_store)
        .await
        .map_err(|e| internal_error("load feed consent", e))?;
    let sources = state
        .advisory_store
        .feed_states()
        .await
        .map_err(|e| internal_error("load feed state", e))?;
    let stale = is_stale(consent.consent, &sources, now_unix());
    Ok(FeedStatusResponse { consent, sources, stale })
}

// ── GET /api/advisory/feed ──────────────────────────────────────

pub async fn feed_status(
    RequireAuth(_session): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<FeedStatusResponse>, Response> {
    build_status(&state).await.map(Json)
}

// ── POST /api/advisory/feed/consent ─────────────────────────────

pub async fn set_feed_consent(
    RequireAdmin(session): RequireAdmin,
    State(state): State<AppState>,
    Json(body): Json<ConsentBody>,
) -> Result<Json<FeedStatusResponse>, Response> {
    if body.consent == FeedConsent::Unanswered {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "consent must be \"on\" or \"off\"" })),
        )
            .into_response());
    }
    consent::save(&state.switch_store, body.consent, &session.username, now_unix())
        .await
        .map_err(|e| internal_error("save feed consent", e))?;
    tracing::info!(consent = ?body.consent, by = %session.username, "advisory feed consent recorded");
    build_status(&state).await.map(Json)
}


#[cfg(test)]
mod tests {
    use super::*;
    use ion_drift_storage::FeedSourceState;

    const DAY: i64 = 86_400;

    fn src(source: &str, last_success_at: Option<i64>, last_attempt_at: i64) -> FeedSourceState {
        FeedSourceState { source: source.into(), last_success_at, last_attempt_at, last_error: None, records: 1 }
    }

    #[test]
    fn fresh_sources_are_not_stale() {
        let now = 10 * DAY;
        let s = [src("kev", Some(now - DAY), now - DAY), src("nvd", Some(now - DAY), now - DAY)];
        assert!(!is_stale(FeedConsent::On, &s, now));
    }

    #[test]
    fn source_without_success_for_three_days_is_stale() {
        let now = 10 * DAY;
        let s = [src("kev", Some(now - DAY), now), src("nvd", Some(now - 4 * DAY), now)];
        assert!(is_stale(FeedConsent::On, &s, now));
    }

    #[test]
    fn source_that_never_succeeded_is_stale() {
        assert!(is_stale(FeedConsent::On, &[src("nvd", None, 5)], 10));
    }

    #[test]
    fn no_attempt_yet_is_pending_not_stale() {
        assert!(!is_stale(FeedConsent::On, &[], 10));
    }

    #[test]
    fn staleness_only_applies_when_consent_is_on() {
        let s = [src("nvd", None, 5)];
        assert!(!is_stale(FeedConsent::Off, &s, 10 * DAY));
        assert!(!is_stale(FeedConsent::Unanswered, &s, 10 * DAY));
    }

    #[test]
    fn consent_body_accepts_only_known_values() {
        assert!(serde_json::from_str::<ConsentBody>(r#"{"consent":"on"}"#).is_ok());
        assert!(serde_json::from_str::<ConsentBody>(r#"{"consent":"maybe"}"#).is_err());
        assert!(serde_json::from_str::<ConsentBody>(r#"{"consent":"on","extra":1}"#).is_err());
    }
}
