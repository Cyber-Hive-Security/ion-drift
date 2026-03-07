use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Redirect, Response};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use dashmap::DashMap;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, EndUserEmail, EndUserUsername, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use serde::{Deserialize, Serialize};

use crate::config::ServerConfig;
use crate::state::AppState;

/// The fully-resolved OIDC client type after provider discovery + endpoint setup.
///
/// `from_provider_metadata` returns all `EndpointNotSet`, so we chain
/// `.set_auth_uri()` and `.set_token_uri()` to get the correct type state.
pub type OidcClient = CoreClient<
    EndpointSet,       // HasAuthUrl
    EndpointNotSet,    // HasDeviceAuthUrl
    EndpointNotSet,    // HasIntrospectionUrl
    EndpointNotSet,    // HasRevocationUrl
    EndpointSet,       // HasTokenUrl
    EndpointMaybeSet,  // HasUserInfoUrl (set_redirect_uri transitions this)
>;

// ── Session store ─────────────────────────────────────────────────

/// Data stored for an authenticated session.
#[derive(Debug, Clone, Serialize)]
pub struct SessionData {
    pub user_id: String,
    pub username: String,
    pub email: Option<String>,
    pub roles: Vec<String>,
    pub created_at: u64,
}

impl SessionData {
    /// Check if this session has a specific role.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Check if this user has the admin role.
    pub fn is_admin(&self) -> bool {
        self.has_role("ion-drift-admin")
    }
}

/// Temporary data stored while the OIDC auth flow is in progress.
struct PendingAuth {
    nonce: Nonce,
    pkce_verifier: PkceCodeVerifier,
    created_at: u64,
}

/// In-memory session store using DashMap for lock-free concurrent access.
#[derive(Clone)]
pub struct SessionStore {
    sessions: Arc<DashMap<String, SessionData>>,
    pending_auth: Arc<DashMap<String, PendingAuth>>,
    max_age: Duration,
}

impl SessionStore {
    pub fn new(max_age_seconds: u64) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            pending_auth: Arc::new(DashMap::new()),
            max_age: Duration::from_secs(max_age_seconds),
        }
    }

    /// Look up a session by ID, returning None if expired.
    pub fn get(&self, session_id: &str) -> Option<SessionData> {
        let entry = self.sessions.get(session_id)?;
        let now = now_secs();
        if now - entry.created_at > self.max_age.as_secs() {
            drop(entry);
            self.sessions.remove(session_id);
            return None;
        }
        Some(entry.clone())
    }

    fn insert_session(&self, session_id: String, data: SessionData) {
        self.sessions.insert(session_id, data);
    }

    fn remove_session(&self, session_id: &str) {
        self.sessions.remove(session_id);
    }

    /// Insert a pending auth entry. Returns false if the map is at capacity
    /// (prevents memory exhaustion from login endpoint flooding).
    fn insert_pending(&self, csrf_token: String, nonce: Nonce, pkce_verifier: PkceCodeVerifier) -> bool {
        const MAX_PENDING: usize = 1000;
        if self.pending_auth.len() >= MAX_PENDING {
            return false;
        }
        self.pending_auth.insert(
            csrf_token,
            PendingAuth {
                nonce,
                pkce_verifier,
                created_at: now_secs(),
            },
        );
        true
    }

    fn take_pending(&self, csrf_token: &str) -> Option<(Nonce, PkceCodeVerifier)> {
        let (_, pending) = self.pending_auth.remove(csrf_token)?;
        Some((pending.nonce, pending.pkce_verifier))
    }

    /// Remove all sessions (used when session secret is regenerated).
    pub fn clear_all(&self) {
        self.sessions.clear();
        self.pending_auth.clear();
    }

    /// Remove expired sessions and stale pending auth entries.
    pub fn cleanup(&self) {
        let now = now_secs();
        let session_max = self.max_age.as_secs();
        let pending_max = 300; // 5 minutes

        self.sessions
            .retain(|_, v| now - v.created_at <= session_max);
        self.pending_auth
            .retain(|_, v| now - v.created_at <= pending_max);
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── OIDC client setup ─────────────────────────────────────────────

/// Build the `reqwest::Client` with the Smallstep CA cert loaded.
pub fn build_oidc_http_client(ca_cert_path: Option<&str>) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30));
    if let Some(ca_path) = ca_cert_path {
        let pem = std::fs::read(ca_path)
            .map_err(|e| anyhow::anyhow!("failed to read OIDC CA cert {ca_path}: {e}"))?;
        let cert = reqwest::Certificate::from_pem(&pem)
            .map_err(|e| anyhow::anyhow!("invalid OIDC CA certificate: {e}"))?;
        builder = builder.add_root_certificate(cert);
    }
    Ok(builder.build()?)
}

/// Discover the OIDC provider and build a properly typed client.
pub async fn discover_oidc(
    config: &ServerConfig,
    http_client: &reqwest::Client,
) -> anyhow::Result<OidcClient> {
    let issuer_url = IssuerUrl::new(config.oidc.issuer_url.clone())
        .map_err(|e| anyhow::anyhow!("invalid issuer URL: {e}"))?;

    let provider_metadata =
        CoreProviderMetadata::discover_async(issuer_url, http_client)
            .await
            .map_err(|e| anyhow::anyhow!("OIDC discovery failed: {e}"))?;

    // Extract endpoints from provider metadata before consuming it
    let auth_url = provider_metadata.authorization_endpoint().clone();
    let token_url = provider_metadata
        .token_endpoint()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("OIDC provider has no token endpoint"))?;

    let redirect_uri = RedirectUrl::new(config.oidc.redirect_uri.clone())
        .map_err(|e| anyhow::anyhow!("invalid redirect URI: {e}"))?;

    // Build client: from_provider_metadata returns EndpointNotSet for all endpoints,
    // so we chain set_auth_uri + set_token_uri to get the proper type state.
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(config.oidc.client_id.clone()),
        Some(ClientSecret::new(config.oidc.client_secret.clone())),
    )
    .set_auth_uri(auth_url)
    .set_token_uri(token_url)
    .set_redirect_uri(redirect_uri);

    Ok(client)
}

// ── Error response helper ─────────────────────────────────────────

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

fn json_error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(ErrorResponse { error: msg.into() })).into_response()
}

// ── Handlers ──────────────────────────────────────────────────────

/// `GET /auth/login` — Start the OIDC authorization code flow.
pub async fn login(State(state): State<AppState>) -> Response {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token, nonce) = state
        .oidc_client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    if !state.sessions.insert_pending(
        csrf_token.secret().clone(),
        nonce,
        pkce_verifier,
    ) {
        return json_error(
            StatusCode::TOO_MANY_REQUESTS,
            "too many pending login attempts, try again later",
        );
    }

    Redirect::temporary(auth_url.as_str()).into_response()
}

#[derive(Deserialize)]
pub struct CallbackParams {
    code: String,
    state: String,
}

/// `GET /auth/callback` — Handle the OIDC redirect from Keycloak.
pub async fn callback(
    State(state): State<AppState>,
    Query(params): Query<CallbackParams>,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect), Response> {
    // Retrieve and consume the pending auth state
    let (nonce, pkce_verifier) = state
        .sessions
        .take_pending(&params.state)
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "invalid or expired state parameter",
            )
        })?;

    // Exchange authorization code for tokens
    let token_response = state
        .oidc_client
        .exchange_code(AuthorizationCode::new(params.code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(&state.http_client)
        .await
        .map_err(|e| {
            tracing::error!("token exchange failed: {e}");
            json_error(StatusCode::UNAUTHORIZED, "token exchange failed")
        })?;

    // Validate the ID token
    let id_token = token_response
        .id_token()
        .ok_or_else(|| json_error(StatusCode::UNAUTHORIZED, "no ID token in response"))?;

    let verifier = state.oidc_client.id_token_verifier();
    let claims = id_token.claims(&verifier, &nonce).map_err(|e| {
        tracing::error!("ID token verification failed: {e}");
        json_error(StatusCode::UNAUTHORIZED, "ID token verification failed")
    })?;

    // Extract user info from claims
    let user_id = claims.subject().to_string();
    let username = claims
        .preferred_username()
        .map(|u: &EndUserUsername| u.to_string())
        .unwrap_or_else(|| user_id.clone());
    let email = claims
        .email()
        .map(|e: &EndUserEmail| e.to_string());

    // Extract roles from Keycloak's realm_access claim.
    // The token is already signature-verified above, so decoding the payload is safe.
    let roles = extract_keycloak_roles(id_token.to_string().as_str());

    tracing::info!(user_id, username, ?roles, "user authenticated via OIDC");

    // Create session with 256-bit cryptographic token
    let session_bytes: [u8; 32] = rand::random();
    let session_id = hex::encode(session_bytes);
    let session_data = SessionData {
        user_id,
        username,
        email,
        roles,
        created_at: now_secs(),
    };
    state
        .sessions
        .insert_session(session_id.clone(), session_data);

    // Set session cookie
    let max_age_secs = state.config.session.max_age_seconds as i64;
    let same_site = match state.config.session.same_site.to_lowercase().as_str() {
        "strict" => SameSite::Strict,
        "none" => SameSite::None,
        _ => SameSite::Lax,
    };

    let cookie = Cookie::build((state.config.session.cookie_name.clone(), session_id))
        .path("/")
        .http_only(true)
        .secure(state.config.session.secure)
        .max_age(cookie::time::Duration::seconds(max_age_secs))
        .same_site(same_site)
        .build();

    Ok((jar.add(cookie), Redirect::temporary("/")))
}

/// `POST /auth/logout` — Destroy the session and clear the cookie.
pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> (CookieJar, Json<serde_json::Value>) {
    if let Some(cookie) = jar.get(&state.config.session.cookie_name) {
        state.sessions.remove_session(cookie.value());
    }

    let same_site = match state.config.session.same_site.to_lowercase().as_str() {
        "strict" => SameSite::Strict,
        "none" => SameSite::None,
        _ => SameSite::Lax,
    };
    let removal = Cookie::build(state.config.session.cookie_name.clone())
        .path("/")
        .http_only(true)
        .secure(state.config.session.secure)
        .same_site(same_site)
        .max_age(cookie::time::Duration::ZERO)
        .build();

    (
        jar.remove(removal),
        Json(serde_json::json!({ "status": "logged_out" })),
    )
}

#[derive(Serialize)]
pub struct AuthStatus {
    authenticated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<UserInfo>,
}

#[derive(Serialize)]
pub struct UserInfo {
    user_id: String,
    username: String,
    email: Option<String>,
    is_admin: bool,
}

/// `GET /auth/status` — Check whether the current request has a valid session.
pub async fn status(State(state): State<AppState>, jar: CookieJar) -> Json<AuthStatus> {
    let session = jar
        .get(&state.config.session.cookie_name)
        .and_then(|c| state.sessions.get(c.value()));

    match session {
        Some(data) => Json(AuthStatus {
            authenticated: true,
            user: Some(UserInfo {
                user_id: data.user_id.clone(),
                username: data.username.clone(),
                email: data.email.clone(),
                is_admin: data.is_admin(),
            }),
        }),
        None => Json(AuthStatus {
            authenticated: false,
            user: None,
        }),
    }
}

// ── Keycloak role extraction ──────────────────────────────────────

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Extract realm roles from a Keycloak JWT's `realm_access.roles` claim.
///
/// The token must already be signature-verified before calling this.
/// Returns an empty vec if the claim is missing or malformed.
fn extract_keycloak_roles(jwt: &str) -> Vec<String> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Vec::new();
    }

    let payload = match URL_SAFE_NO_PAD.decode(parts[1]) {
        Ok(bytes) => bytes,
        Err(_) => return Vec::new(),
    };

    let value: serde_json::Value = match serde_json::from_slice(&payload) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    value
        .get("realm_access")
        .and_then(|ra| ra.get("roles"))
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}
