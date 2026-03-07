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

impl<S> FromRequestParts<S> for RequireAuth
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        // Extract the cookie jar from headers
        let jar = CookieJar::from_headers(&parts.headers);

        let session_id = jar
            .get(&app_state.config.session.cookie_name)
            .map(|c| c.value().to_string());

        let session_id = session_id.ok_or_else(|| {
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

        Ok(RequireAuth(session))
    }
}

impl<S> FromRequestParts<S> for RequireAdmin
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // First, require a valid session (reuses the same logic as RequireAuth).
        let RequireAuth(session) = RequireAuth::from_request_parts(parts, state).await?;

        if !session.is_admin {
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
