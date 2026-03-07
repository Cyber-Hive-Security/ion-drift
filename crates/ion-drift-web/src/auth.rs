use std::sync::Arc;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Redirect, Response};
use base64::Engine;
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use dashmap::DashMap;
use rusqlite::params;
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
    pub last_accessed: u64,
    pub created_ip: Option<String>,
    pub user_agent: Option<String>,
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

#[derive(Debug, Clone)]
struct SessionRecord {
    data: SessionData,
    dirty: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionListEntry {
    pub session_id: String,
    pub username: String,
    pub created_at: u64,
    pub last_accessed: u64,
    pub created_ip: Option<String>,
    pub user_agent: Option<String>,
    pub is_current: bool,
}

/// In-memory session store using DashMap for lock-free concurrent access.
#[derive(Clone)]
pub struct SessionStore {
    sessions: Arc<DashMap<String, SessionRecord>>,
    pending_auth: Arc<DashMap<String, PendingAuth>>,
    db: Arc<std::sync::Mutex<rusqlite::Connection>>,
    max_age: Duration,
}

impl SessionStore {
    pub fn new(max_age_seconds: u64, db_path: &Path) -> anyhow::Result<Self> {
        let conn = rusqlite::Connection::open(db_path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                username TEXT NOT NULL,
                email TEXT,
                roles TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                last_accessed INTEGER NOT NULL,
                created_ip TEXT,
                user_agent TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions (created_at);",
        )?;
        let store = Self {
            sessions: Arc::new(DashMap::new()),
            pending_auth: Arc::new(DashMap::new()),
            db: Arc::new(std::sync::Mutex::new(conn)),
            max_age: Duration::from_secs(max_age_seconds),
        };
        store.load_active_from_db();
        Ok(store)
    }

    fn load_active_from_db(&self) {
        let now = now_secs();
        let max_age = self.max_age.as_secs() as i64;
        let Ok(db) = self.db.lock() else {
            return;
        };
        let mut stmt = match db.prepare(
            "SELECT session_id, user_id, username, email, roles, created_at, last_accessed, created_ip, user_agent
             FROM sessions
             WHERE (?1 - created_at) <= ?2",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("failed to prepare session preload query: {e}");
                return;
            }
        };
        let rows = match stmt.query_map(params![now as i64, max_age], |row| {
            let roles_json: String = row.get(4)?;
            let roles: Vec<String> = serde_json::from_str(&roles_json).unwrap_or_default();
            Ok((
                row.get::<_, String>(0)?,
                SessionData {
                    user_id: row.get(1)?,
                    username: row.get(2)?,
                    email: row.get(3)?,
                    roles,
                    created_at: row.get::<_, i64>(5)? as u64,
                    last_accessed: row.get::<_, i64>(6)? as u64,
                    created_ip: row.get(7)?,
                    user_agent: row.get(8)?,
                },
            ))
        }) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("failed to query persisted sessions: {e}");
                return;
            }
        };
        for row in rows.flatten() {
            self.sessions.insert(
                row.0,
                SessionRecord {
                    data: row.1,
                    dirty: false,
                },
            );
        }
        if !self.sessions.is_empty() {
            tracing::info!(count = self.sessions.len(), "loaded active sessions from sqlite");
        }
    }

    /// Look up a session by ID, returning None if expired.
    pub fn get(&self, session_id: &str) -> Option<SessionData> {
        let mut entry = self.sessions.get_mut(session_id)?;
        let now = now_secs();
        if now - entry.data.created_at > self.max_age.as_secs() {
            drop(entry);
            self.sessions.remove(session_id);
            self.delete_from_db(session_id);
            return None;
        }
        entry.data.last_accessed = now;
        entry.dirty = true;
        Some(entry.data.clone())
    }

    fn insert_session(&self, session_id: String, data: SessionData) {
        self.upsert_db(&session_id, &data);
        self.sessions.insert(
            session_id,
            SessionRecord {
                data,
                dirty: false,
            },
        );
    }

    fn remove_session(&self, session_id: &str) {
        self.sessions.remove(session_id);
        self.delete_from_db(session_id);
    }

    pub fn record_access(&self, session_id: &str, ip: Option<String>, ua: Option<String>) {
        if let Some(mut entry) = self.sessions.get_mut(session_id) {
            entry.data.last_accessed = now_secs();
            if entry.data.created_ip.is_none() {
                entry.data.created_ip = ip;
            }
            if entry.data.user_agent.is_none() {
                entry.data.user_agent = ua;
            }
            entry.dirty = true;
        }
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
        // Reject entries older than 300 seconds (5 minutes)
        if now_secs() - pending.created_at > 300 {
            return None;
        }
        Some((pending.nonce, pending.pkce_verifier))
    }

    /// Remove all sessions (used when session secret is regenerated).
    pub fn clear_all(&self) {
        self.sessions.clear();
        self.pending_auth.clear();
        if let Ok(db) = self.db.lock() {
            let _ = db.execute("DELETE FROM sessions", []);
        }
    }

    /// Remove expired sessions and stale pending auth entries.
    pub fn cleanup(&self) {
        let now = now_secs();
        let session_max = self.max_age.as_secs();
        let pending_max = 300; // 5 minutes

        let mut expired_ids = Vec::new();
        self.sessions.retain(|id, v| {
            let keep = now - v.data.created_at <= session_max;
            if !keep {
                expired_ids.push(id.clone());
            }
            keep
        });
        for id in expired_ids {
            self.delete_from_db(&id);
        }
        self.pending_auth
            .retain(|_, v| now - v.created_at <= pending_max);

        if let Ok(db) = self.db.lock() {
            let cutoff = (now.saturating_sub(session_max)) as i64;
            let _ = db.execute("DELETE FROM sessions WHERE created_at < ?1", params![cutoff]);
        }
    }

    pub fn flush_dirty(&self) {
        for mut entry in self.sessions.iter_mut() {
            if entry.dirty {
                self.upsert_db(entry.key(), &entry.data);
                entry.dirty = false;
            }
        }
    }

    pub fn list_sessions(&self, current_session: Option<&str>) -> Vec<SessionListEntry> {
        let mut out = Vec::new();
        for entry in self.sessions.iter() {
            let data = &entry.data;
            out.push(SessionListEntry {
                session_id: entry.key().clone(),
                username: data.username.clone(),
                created_at: data.created_at,
                last_accessed: data.last_accessed,
                created_ip: data.created_ip.clone(),
                user_agent: data.user_agent.clone(),
                is_current: current_session == Some(entry.key().as_str()),
            });
        }
        out.sort_by(|a, b| b.last_accessed.cmp(&a.last_accessed));
        out
    }

    pub fn revoke_session(&self, session_id: &str) -> bool {
        let existed = self.sessions.remove(session_id).is_some();
        self.delete_from_db(session_id);
        existed
    }

    fn upsert_db(&self, session_id: &str, data: &SessionData) {
        let roles = match serde_json::to_string(&data.roles) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("failed to serialize session roles: {e}");
                return;
            }
        };
        if let Ok(db) = self.db.lock() {
            let _ = db.execute(
                "INSERT INTO sessions
                    (session_id, user_id, username, email, roles, created_at, last_accessed, created_ip, user_agent)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(session_id) DO UPDATE SET
                    user_id = excluded.user_id,
                    username = excluded.username,
                    email = excluded.email,
                    roles = excluded.roles,
                    created_at = excluded.created_at,
                    last_accessed = excluded.last_accessed,
                    created_ip = excluded.created_ip,
                    user_agent = excluded.user_agent",
                params![
                    session_id,
                    data.user_id,
                    data.username,
                    data.email,
                    roles,
                    data.created_at as i64,
                    data.last_accessed as i64,
                    data.created_ip,
                    data.user_agent
                ],
            );
        }
    }

    fn delete_from_db(&self, session_id: &str) {
        if let Ok(db) = self.db.lock() {
            let _ = db.execute("DELETE FROM sessions WHERE session_id = ?1", params![session_id]);
        }
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
    headers: axum::http::HeaderMap,
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
    let created_at = now_secs();
    let created_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .filter(|s| !s.is_empty());
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let session_data = SessionData {
        user_id,
        username,
        email,
        roles,
        created_at,
        last_accessed: created_at,
        created_ip,
        user_agent,
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
