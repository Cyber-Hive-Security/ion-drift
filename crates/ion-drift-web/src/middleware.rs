use axum::extract::{FromRef, FromRequestParts};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Json, Response};
use axum_extra::extract::CookieJar;
use serde::Serialize;

use crate::auth::SessionData;
use crate::state::AppState;

/// Axum extractor that requires a valid session.
///
/// Use as a handler parameter: `RequireAuth(session)` gives you the `SessionData`.
/// Returns 401 JSON error if no valid session cookie is present.
pub struct RequireAuth(pub SessionData);

/// Axum extractor that requires a valid session **with admin privileges**.
///
/// Use as a handler parameter: `RequireAdmin(session)` gives you the `SessionData`.
/// Returns 401 if not authenticated, 403 if authenticated but not an admin.
/// Admin status is determined by the `ion-drift-admin` Keycloak realm role.
pub struct RequireAdmin(pub SessionData);

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

/// Extract and validate the session from the cookie jar.
/// Shared logic between RequireAuth and RequireAdmin.
async fn extract_session<S>(parts: &mut Parts, state: &S) -> Result<SessionData, Response>
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    let app_state = AppState::from_ref(state);
    let jar = CookieJar::from_headers(&parts.headers);

    let session_id = jar
        .get(&app_state.config.session.cookie_name)
        .map(|c| c.value().to_string())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "authentication required".into(),
                }),
            )
                .into_response()
        })?;

    let session = app_state.sessions.get(&session_id).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "session expired or invalid".into(),
            }),
        )
            .into_response()
    })?;

    let ip = None;
    let ua = parts
        .headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    app_state.sessions.record_access(&session_id, ip, ua);

    Ok(session)
}

impl<S> FromRequestParts<S> for RequireAuth
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(RequireAuth(extract_session(parts, state).await?))
    }
}

impl<S> FromRequestParts<S> for RequireAdmin
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let session = extract_session(parts, state).await?;
        if !session.is_admin() {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "admin privileges required".into(),
                }),
            )
                .into_response());
        }
        Ok(RequireAdmin(session))
    }
}
