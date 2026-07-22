use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Redirect, Response};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use base64::Engine;
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndUserEmail, EndUserUsername,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::ServerConfig;
use crate::state::AppState;

/// The fully-resolved OIDC client type after provider discovery + endpoint setup.
///
/// `from_provider_metadata` returns all `EndpointNotSet`, so we chain
/// `.set_auth_uri()` and `.set_token_uri()` to get the correct type state.
pub type OidcClient = CoreClient<
    EndpointSet,      // HasAuthUrl
    EndpointNotSet,   // HasDeviceAuthUrl
    EndpointNotSet,   // HasIntrospectionUrl
    EndpointNotSet,   // HasRevocationUrl
    EndpointSet,      // HasTokenUrl
    EndpointMaybeSet, // HasUserInfoUrl (set_redirect_uri transitions this)
>;

// ── Session store ─────────────────────────────────────────────────

/// Name of the short-lived cookie that binds an in-progress OIDC flow to the
/// initiating browser (DRIFT-2026-0002 login-CSRF / session-fixation defense).
const OIDC_STATE_COOKIE: &str = "ion_drift_oidc_state";

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

/// Derive the at-rest storage key for a session. The full signed token is the
/// bearer credential and must NEVER be stored (review ID-09): we key both the
/// in-memory map and the `sessions` table by `SHA-256(token)`, so a stolen
/// sessions.db (or backup) can't be replayed — the token itself lives only in
/// the client cookie. Callers that hold a raw cookie value pass it here; the
/// list/revoke API instead uses this key directly as an opaque handle.
fn session_storage_key(session_id: &str) -> String {
    hex::encode(Sha256::digest(session_id.as_bytes()))
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
    signing_key: Arc<tokio::sync::RwLock<Vec<u8>>>,
    max_age: Duration,
    /// Idle timeout; `Duration::ZERO` disables idle expiry (WSTG-SESS-07).
    idle_max: Duration,
}

impl SessionStore {
    pub fn new(max_age_seconds: u64, db_path: &Path, session_secret: &str) -> anyhow::Result<Self> {
        Self::with_idle_timeout(max_age_seconds, 0, db_path, session_secret)
    }

    pub fn with_idle_timeout(
        max_age_seconds: u64,
        idle_timeout_seconds: u64,
        db_path: &Path,
        session_secret: &str,
    ) -> anyhow::Result<Self> {
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
            signing_key: Arc::new(tokio::sync::RwLock::new(session_secret.as_bytes().to_vec())),
            max_age: Duration::from_secs(max_age_seconds),
            // Cap idle at the absolute max_age; 0 = disabled.
            idle_max: Duration::from_secs(idle_timeout_seconds.min(max_age_seconds)),
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
            // `row.0` is the storage key (SHA-256 of the token), not the token
            // itself, so it can't be HMAC-verified here — integrity is enforced
            // at request time in `get()`, which verifies the raw cookie's
            // signature before hashing it to this key.
            self.sessions.insert(
                row.0,
                SessionRecord {
                    data: row.1,
                    dirty: false,
                },
            );
        }
        if !self.sessions.is_empty() {
            tracing::info!(
                count = self.sessions.len(),
                "loaded active sessions from sqlite"
            );
        }
    }

    /// Look up a session by ID, returning None if expired.
    pub fn get(&self, session_id: &str) -> Option<SessionData> {
        // Verify the raw cookie's HMAC signature FIRST, then hash it to the
        // storage key for lookup (review ID-09).
        if !self.is_valid_session_id(session_id) {
            return None;
        }
        let key = session_storage_key(session_id);
        let mut entry = self.sessions.get_mut(&key)?;
        let now = now_secs();
        // Absolute timeout (created_at) OR idle timeout (last_accessed).
        let absolute_expired = now.saturating_sub(entry.data.created_at) > self.max_age.as_secs();
        let idle_expired = self.idle_max > Duration::ZERO
            && now.saturating_sub(entry.data.last_accessed) > self.idle_max.as_secs();
        if absolute_expired || idle_expired {
            drop(entry);
            self.sessions.remove(&key);
            self.delete_from_db(&key);
            return None;
        }
        entry.data.last_accessed = now;
        entry.dirty = true;
        Some(entry.data.clone())
    }

    fn insert_session(&self, session_id: String, data: SessionData) {
        // Store keyed by hash; the raw token is only ever sent to the client.
        let key = session_storage_key(&session_id);
        self.upsert_db(&key, &data);
        self.sessions
            .insert(key, SessionRecord { data, dirty: false });
    }

    fn remove_session(&self, session_id: &str) {
        if !self.is_valid_session_id(session_id) {
            return;
        }
        let key = session_storage_key(session_id);
        self.sessions.remove(&key);
        self.delete_from_db(&key);
    }

    pub fn record_access(&self, session_id: &str, ip: Option<String>, ua: Option<String>) {
        let key = session_storage_key(session_id);
        if let Some(mut entry) = self.sessions.get_mut(&key) {
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
    fn insert_pending(
        &self,
        csrf_token: String,
        nonce: Nonce,
        pkce_verifier: PkceCodeVerifier,
    ) -> bool {
        const MAX_PENDING: usize = 1000;
        let now = now_secs();
        // Expire stale entries BEFORE the capacity check (review ID-04). Cleanup
        // otherwise runs only every 5 minutes, so a burst of abandoned
        // login-starts could hold all 1000 slots — and lock out every new login
        // with 429 — for the whole interval. Pruning on insert lets capacity
        // self-heal continuously; an attacker must now sustain fresh entries.
        self.pending_auth.retain(|_, v| now - v.created_at <= 300);
        if self.pending_auth.len() >= MAX_PENDING {
            return false;
        }
        self.pending_auth.insert(
            csrf_token,
            PendingAuth {
                nonce,
                pkce_verifier,
                created_at: now,
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
            let _ = db.execute(
                "DELETE FROM sessions WHERE created_at < ?1",
                params![cutoff],
            );
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
        // The exposed `session_id` is the storage key (a SHA-256 hash), not the
        // bearer token — it's an opaque handle safe to show and to pass back to
        // `revoke_session`. `is_current` compares against the hash of the
        // caller's own cookie.
        let current_key = current_session.map(session_storage_key);
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
                is_current: current_key.as_deref() == Some(entry.key().as_str()),
            });
        }
        out.sort_by(|a, b| b.last_accessed.cmp(&a.last_accessed));
        out
    }

    /// Revoke a session by its storage-key handle (as returned by
    /// [`list_sessions`](Self::list_sessions)) — this is already the hashed key,
    /// not a signed token, so it is used directly.
    pub fn revoke_session(&self, storage_key: &str) -> bool {
        let existed = self.sessions.remove(storage_key).is_some();
        self.delete_from_db(storage_key);
        existed
    }

    pub async fn rotate_signing_secret(&self, session_secret: &str) {
        let mut key = self.signing_key.write().await;
        *key = session_secret.as_bytes().to_vec();
    }

    pub async fn issue_session_id(&self) -> anyhow::Result<String> {
        use rand::rngs::OsRng;
        use rand::TryRngCore;
        let mut token_bytes = [0u8; 32];
        OsRng.try_fill_bytes(&mut token_bytes)
            .map_err(|e| anyhow::anyhow!("OS RNG failed generating session token: {e}"))?;
        let token = hex::encode(token_bytes);
        self.sign_session_id(&token).await
    }

    async fn sign_session_id(&self, token: &str) -> anyhow::Result<String> {
        let key = self.signing_key.read().await;
        let mut mac = Hmac::<Sha256>::new_from_slice(&key)
            .map_err(|e| anyhow::anyhow!("invalid session signing key: {e}"))?;
        mac.update(token.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());
        Ok(format!("{token}.{signature}"))
    }

    fn is_valid_session_id(&self, session_id: &str) -> bool {
        let Some((token, provided_sig)) = session_id.split_once('.') else {
            return false;
        };
        let Ok(provided_sig) = hex::decode(provided_sig) else {
            return false;
        };
        let Ok(key) = self.signing_key.try_read() else {
            return false;
        };
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(&key) else {
            return false;
        };
        mac.update(token.as_bytes());
        mac.verify_slice(&provided_sig).is_ok()
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
            let _ = db.execute(
                "DELETE FROM sessions WHERE session_id = ?1",
                params![session_id],
            );
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Login rate limiter ────────────────────────────────────────────

/// Extract client IP from request headers (reverse proxy) or peer address.
/// Uses the rightmost X-Forwarded-For entry (set by the nearest trusted proxy),
/// then X-Real-IP, then falls back to "unknown". Values are validated as IP addresses
/// to prevent spoofed non-IP strings from bypassing rate limiting.
pub fn extract_client_ip(headers: &axum::http::HeaderMap, trust_proxy_headers: bool) -> String {
    // When not explicitly behind a trusted proxy, do NOT trust client-supplied
    // forwarding headers — otherwise an attacker rotates them to defeat the
    // per-IP rate limiter (DRIFT-2026-0009). Falls back to "unknown" (a single
    // shared bucket); the per-username limiter remains the primary backstop.
    if !trust_proxy_headers {
        return "unknown".to_string();
    }
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        // Use rightmost entry — set by the nearest proxy, harder to spoof than leftmost
        if let Some(last) = xff.rsplit(',').next() {
            let trimmed = last.trim();
            if !trimmed.is_empty() && trimmed.parse::<std::net::IpAddr>().is_ok() {
                return trimmed.to_string();
            }
        }
    }
    if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let trimmed = real_ip.trim();
        if !trimmed.is_empty() && trimmed.parse::<std::net::IpAddr>().is_ok() {
            return trimmed.to_string();
        }
    }
    "unknown".to_string()
}

/// Per-key rate limiter for login attempts.
/// Tracks failed attempts by both username and client IP independently.
#[derive(Clone)]
pub struct LoginRateLimiter {
    /// Map of key → (attempt_count, last_attempt_timestamp)
    attempts: Arc<DashMap<String, (u32, u64)>>,
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        Self {
            attempts: Arc::new(DashMap::new()),
        }
    }

    /// Check if a key is rate-limited. Returns Ok(()) if allowed, Err(seconds_until_retry) if blocked.
    pub fn check(&self, key: &str) -> Result<(), u64> {
        let now = now_secs();
        if let Some(entry) = self.attempts.get(key) {
            let (count, last) = *entry;
            // Exponential backoff: 1s, 2s, 4s, 8s, 16s, 30s max
            let cooldown = match count {
                0..=1 => 0,
                2 => 1,
                3 => 2,
                4 => 4,
                5 => 8,
                6 => 16,
                _ => 30,
            };
            let elapsed = now.saturating_sub(last);
            if elapsed < cooldown {
                return Err(cooldown - elapsed);
            }
        }
        Ok(())
    }

    /// Atomically record an attempt and return `Err(retry_after)` if the key is
    /// now in cooldown. Unlike [`check`](Self::check), this reserves the slot
    /// BEFORE the expensive password verification, so a concurrent burst of
    /// wrong-password requests can't all be admitted before the first one
    /// finishes and records a failure (review ID-03). On a successful login the
    /// caller must call [`record_success`](Self::record_success) to refund.
    pub fn reserve(&self, key: &str) -> Result<(), u64> {
        let now = now_secs();
        let entry = self
            .attempts
            .entry(key.to_string())
            .and_modify(|(count, last)| {
                *count = count.saturating_add(1);
                *last = now;
            })
            .or_insert((1, now));
        let count = entry.0;
        drop(entry); // release the shard lock before returning
        // Because reserve() counts the attempt up front (unlike check(), which
        // only counted failures), allow the first two attempts free before the
        // backoff ramp — preserving the prior two-strikes UX.
        let cooldown = match count {
            0..=2 => 0,
            3 => 1,
            4 => 2,
            5 => 4,
            6 => 8,
            7 => 16,
            _ => 30,
        };
        if cooldown > 0 {
            Err(cooldown)
        } else {
            Ok(())
        }
    }

    /// Record a failed attempt.
    pub fn record_failure(&self, key: &str) {
        let now = now_secs();
        self.attempts
            .entry(key.to_string())
            .and_modify(|(count, last)| {
                *count = count.saturating_add(1);
                *last = now;
            })
            .or_insert((1, now));
    }

    /// Clear attempts for a key (on successful login).
    pub fn record_success(&self, key: &str) {
        self.attempts.remove(key);
    }

    /// Periodic cleanup of stale entries (call from a background task or inline).
    pub fn cleanup(&self) {
        let now = now_secs();
        self.attempts.retain(|_, (_, last)| now - *last < 300); // 5 min TTL
    }
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
    let oidc = config.oidc.as_ref()
        .ok_or_else(|| anyhow::anyhow!("OIDC is not configured — cannot discover provider"))?;

    let issuer_url = IssuerUrl::new(oidc.issuer_url.clone())
        .map_err(|e| anyhow::anyhow!("invalid issuer URL: {e}"))?;

    let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, http_client)
        .await
        .map_err(|e| anyhow::anyhow!("OIDC discovery failed: {e}"))?;

    // Extract endpoints from provider metadata before consuming it
    let auth_url = provider_metadata.authorization_endpoint().clone();
    let token_url = provider_metadata
        .token_endpoint()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("OIDC provider has no token endpoint"))?;

    let redirect_uri = RedirectUrl::new(oidc.redirect_uri.clone())
        .map_err(|e| anyhow::anyhow!("invalid redirect URI: {e}"))?;

    // Build client: from_provider_metadata returns EndpointNotSet for all endpoints,
    // so we chain set_auth_uri + set_token_uri to get the proper type state.
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(oidc.client_id.clone()),
        Some(ClientSecret::new(oidc.client_secret.clone())),
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
pub async fn login(State(state): State<AppState>, jar: CookieJar) -> Response {
    let oidc_client = match &state.oidc_client {
        Some(c) => c,
        None => return json_error(StatusCode::SERVICE_UNAVAILABLE, "OIDC is not configured"),
    };
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token, nonce) = oidc_client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("roles".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    if !state
        .sessions
        .insert_pending(csrf_token.secret().clone(), nonce, pkce_verifier)
    {
        return json_error(
            StatusCode::TOO_MANY_REQUESTS,
            "too many pending login attempts, try again later",
        );
    }

    // Bind this pending flow to THIS browser (DRIFT-2026-0002 login-CSRF /
    // session fixation). The state value is echoed into a short-lived
    // HttpOnly cookie; the callback requires the cookie to match the `state`
    // query param, so a state minted by an attacker cannot be completed in a
    // victim's browser. PKCE+nonce already prevent token injection; this
    // prevents cross-browser delivery.
    let same_site = match state.config.session.same_site.to_lowercase().as_str() {
        "strict" => SameSite::Strict,
        "none" => SameSite::None,
        _ => SameSite::Lax,
    };
    let state_cookie = Cookie::build((OIDC_STATE_COOKIE, csrf_token.secret().clone()))
        .path("/")
        .http_only(true)
        .secure(state.config.session.secure)
        .max_age(cookie::time::Duration::seconds(600))
        .same_site(same_site)
        .build();

    (jar.add(state_cookie), Redirect::temporary(auth_url.as_str())).into_response()
}

#[derive(Deserialize)]
pub struct CallbackParams {
    code: String,
    state: String,
}

#[derive(Deserialize)]
pub struct LocalLoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct AuthConfigResponse {
    pub local_auth_enabled: bool,
    pub oidc_enabled: bool,
    pub oidc_provider_name: Option<String>,
}

/// `GET /auth/callback` — Handle the OIDC redirect from Keycloak.
pub async fn callback(
    State(state): State<AppState>,
    Query(params): Query<CallbackParams>,
    jar: CookieJar,
    headers: axum::http::HeaderMap,
) -> Result<(CookieJar, Redirect), Response> {
    // Verify the state is bound to THIS browser before doing anything else
    // (DRIFT-2026-0002). The login handler set an HttpOnly cookie to the state
    // value; require it to match the `state` query param. Constant-time compare.
    let bound = jar
        .get(OIDC_STATE_COOKIE)
        .map(|c| {
            use subtle::ConstantTimeEq;
            c.value().as_bytes().ct_eq(params.state.as_bytes()).unwrap_u8() == 1
        })
        .unwrap_or(false);
    if !bound {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "state does not match this browser's login flow",
        ));
    }

    // Retrieve and consume the pending auth state
    let (nonce, pkce_verifier) = state.sessions.take_pending(&params.state).ok_or_else(|| {
        json_error(
            StatusCode::BAD_REQUEST,
            "invalid or expired state parameter",
        )
    })?;

    let oidc_client = state.oidc_client.as_ref().ok_or_else(|| {
        json_error(StatusCode::SERVICE_UNAVAILABLE, "OIDC is not configured")
    })?;

    // Exchange authorization code for tokens
    let token_response = oidc_client
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

    let verifier = oidc_client.id_token_verifier();
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
    let email = claims.email().map(|e: &EndUserEmail| e.to_string());

    // Extract roles from the ID token using the configured claim path.
    // The token is already signature-verified above, so decoding the payload is safe.
    let roles_claim = state.config.oidc.as_ref()
        .map(|o| o.roles_claim.as_str())
        .unwrap_or("realm_access.roles");
    let admin_role = state.config.oidc.as_ref()
        .map(|o| o.admin_role.as_str())
        .unwrap_or("ion-drift-admin");
    let id_token_str = id_token.to_string();
    let mut roles = extract_oidc_roles(&id_token_str, roles_claim);
    // Normalize: if the configured admin role is present, ensure "ion-drift-admin" is in the list
    if admin_role != "ion-drift-admin" && roles.contains(&admin_role.to_string()) {
        roles.push("ion-drift-admin".to_string());
    }

    tracing::info!(user_id, username, ?roles, "user authenticated via OIDC");

    // Create a session id bound to the current session secret.
    let session_id = state.sessions.issue_session_id().await.map_err(|e| {
        tracing::error!("failed to issue session id: {e}");
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to create session",
        )
    })?;
    let created_at = now_secs();
    let created_ip = None;
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

    // Clear the one-time OIDC state-binding cookie now that the flow is done.
    let jar = jar
        .add(cookie)
        .remove(Cookie::from(OIDC_STATE_COOKIE));
    Ok((jar, Redirect::temporary("/")))
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

    // Build OIDC end-session URL if available (kills the IdP session too)
    let oidc_logout_url = state.config.oidc.as_ref().map(|oidc| {
        let base = oidc.issuer_url.trim_end_matches('/');
        let redirect = oidc.redirect_uri.replace("/auth/callback", "/");
        let encoded_redirect = redirect.replace(':', "%3A").replace('/', "%2F");
        format!("{base}/protocol/openid-connect/logout?client_id={}&post_logout_redirect_uri={encoded_redirect}", oidc.client_id)
    });

    (
        jar.remove(removal),
        Json(serde_json::json!({
            "status": "logged_out",
            "oidc_logout_url": oidc_logout_url,
        })),
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

/// `GET /auth/config` — Returns available auth methods (no auth required).
pub async fn auth_config(State(state): State<AppState>) -> Json<AuthConfigResponse> {
    let oidc_enabled = state.oidc_client.is_some();
    let oidc_provider_name = if oidc_enabled {
        state.config.oidc.as_ref().map(|o| {
            // Extract hostname from issuer URL as provider name
            o.issuer_url.split("//").nth(1)
                .and_then(|s| s.split('/').next())
                .unwrap_or("SSO Provider")
                .to_string()
        })
    } else {
        None
    };

    // Local auth is only enabled if we have a secrets manager AND local users exist
    let local_auth_enabled = if let Some(ref sm) = state.secrets_manager {
        sm.read().await.has_local_users().await.unwrap_or(false)
    } else {
        false
    };

    Json(AuthConfigResponse {
        local_auth_enabled,
        oidc_enabled,
        oidc_provider_name,
    })
}

/// Global cap on concurrent local-login password verifications so a flood of
/// admitted attempts across many usernames can't saturate the CPU with parallel
/// Argon2 hashing (review ID-03).
static LOGIN_VERIFY_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(8);

/// `POST /auth/local-login` — Authenticate with username/password.
pub async fn local_login(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<LocalLoginRequest>,
) -> Result<(CookieJar, Json<serde_json::Value>), Response> {
    // Rate limit by both username and client IP. Reserve the attempt BEFORE
    // verification (review ID-03) so a concurrent burst can't all be admitted;
    // a successful login refunds below. The IP key is only used when the IP is
    // actually known — when running without a trusted proxy the IP collapses to
    // "unknown", and rate-limiting a single shared bucket would let one client
    // (or a legit user's own retries) lock out everyone. The per-username
    // reserve is the primary backstop in that mode.
    let client_ip = extract_client_ip(&headers, state.config.server.trust_proxy_headers);
    let ip_key = (client_ip != "unknown").then(|| format!("ip:{client_ip}"));
    if let Err(retry_after) = state.login_limiter.reserve(&req.username) {
        tracing::warn!(username = %req.username, client_ip = %client_ip, "login rate limited by username");
        return Err(json_error(
            StatusCode::TOO_MANY_REQUESTS,
            &format!("too many login attempts, retry in {retry_after}s"),
        ));
    }
    if let Some(ref ip_key) = ip_key {
        if let Err(retry_after) = state.login_limiter.reserve(ip_key) {
            tracing::warn!(client_ip = %client_ip, "login rate limited by IP");
            return Err(json_error(
                StatusCode::TOO_MANY_REQUESTS,
                &format!("too many login attempts, retry in {retry_after}s"),
            ));
        }
    }

    let sm = state.secrets_manager.as_ref().ok_or_else(|| {
        json_error(StatusCode::SERVICE_UNAVAILABLE, "local auth not available")
    })?;

    // Bound concurrent password verifications globally so admitted attempts
    // across many distinct usernames can't saturate the CPU with parallel
    // Argon2 hashing (review ID-03).
    let _verify_permit = LOGIN_VERIFY_SLOTS.acquire().await.map_err(|_| {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication temporarily unavailable",
        )
    })?;

    let sm = sm.read().await;
    let user = sm.verify_local_user(&req.username, &req.password).await
        .map_err(|e| {
            tracing::error!("local auth error: {e}");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "authentication error")
        })?
        .ok_or_else(|| {
            // The attempt was already counted by reserve(); nothing to record
            // here. Same error for "user not found" and "wrong password" to
            // prevent user enumeration.
            tracing::warn!(username = %req.username, client_ip = %client_ip, "failed local login attempt");
            json_error(StatusCode::UNAUTHORIZED, "invalid username or password")
        })?;
    drop(sm);

    // Map role to internal admin role if it matches
    let admin_role = state.config.oidc.as_ref()
        .map(|o| o.admin_role.as_str())
        .unwrap_or("ion-drift-admin");
    let roles = if user.role == "admin" || user.role == admin_role {
        vec!["ion-drift-admin".to_string()]
    } else {
        vec![user.role.clone()]
    };

    let session_id = state.sessions.issue_session_id().await
        .map_err(|e| {
            tracing::error!("failed to issue session ID: {e}");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "session error")
        })?;

    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let data = SessionData {
        user_id: format!("local:{}", req.username),
        username: req.username.clone(),
        email: None,
        roles,
        created_at: now_secs(),
        last_accessed: now_secs(),
        created_ip: None,
        user_agent,
    };

    state.sessions.insert_session(session_id.clone(), data);

    // Set session cookie — matching the exact pattern from the OIDC callback handler
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

    let jar = CookieJar::new().add(cookie);

    // Successful login — refund the reserved attempts for both keys.
    state.login_limiter.record_success(&req.username);
    if let Some(ref ip_key) = ip_key {
        state.login_limiter.record_success(ip_key);
    }
    tracing::info!(username = %req.username, client_ip = %client_ip, "local login successful");

    Ok((jar, Json(serde_json::json!({ "authenticated": true }))))
}

// ── OIDC role extraction ──────────────────────────────────────────

use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Extract roles from an OIDC JWT using a configurable claim path.
///
/// The token must already be signature-verified before calling this.
/// Supports dot-notation traversal (e.g., "realm_access.roles").
/// Falls back to "roles" then "groups" at root if the configured claim is not found.
fn extract_oidc_roles(jwt: &str, roles_claim: &str) -> Vec<String> {
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

    // Try configured claim path first (dot-notation)
    if let Some(roles) = navigate_claim(&value, roles_claim) {
        return roles;
    }
    // Fallback: try "roles" at root
    if roles_claim != "roles" {
        if let Some(roles) = extract_string_array(&value, "roles") {
            return roles;
        }
    }
    // Fallback: try "groups" at root
    if roles_claim != "groups" {
        if let Some(roles) = extract_string_array(&value, "groups") {
            return roles;
        }
    }
    Vec::new()
}

/// Navigate a dot-separated claim path in a JSON value and extract a string array.
fn navigate_claim(value: &serde_json::Value, path: &str) -> Option<Vec<String>> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    extract_string_array_from_value(current)
}

/// Extract a string array from a named field in a JSON object.
fn extract_string_array(value: &serde_json::Value, key: &str) -> Option<Vec<String>> {
    extract_string_array_from_value(value.get(key)?)
}

/// Extract a string array from a JSON value.
fn extract_string_array_from_value(value: &serde_json::Value) -> Option<Vec<String>> {
    value.as_array().map(|arr| {
        arr.iter().filter_map(|v| v.as_str().map(String::from)).collect()
    })
}

#[cfg(test)]
mod reserve_tests {
    use super::LoginRateLimiter;

    #[test]
    fn reserve_admits_two_then_backs_off() {
        let l = LoginRateLimiter::new();
        // First two attempts admitted up front (reserve counts before verify).
        assert!(l.reserve("user").is_ok());
        assert!(l.reserve("user").is_ok());
        // Third within the window is refused with a positive retry-after.
        let retry = l.reserve("user").expect_err("third attempt should back off");
        assert!(retry >= 1);
    }

    #[test]
    fn record_success_refunds_reservation() {
        let l = LoginRateLimiter::new();
        let _ = l.reserve("user");
        let _ = l.reserve("user");
        let _ = l.reserve("user"); // now in cooldown
        l.record_success("user"); // successful login clears the key
        assert!(l.reserve("user").is_ok());
    }

    #[test]
    fn reserve_keys_are_independent() {
        let l = LoginRateLimiter::new();
        for _ in 0..5 {
            let _ = l.reserve("alice");
        }
        // alice is throttled but bob is unaffected.
        assert!(l.reserve("alice").is_err());
        assert!(l.reserve("bob").is_ok());
    }
}

#[cfg(test)]
mod session_hash_tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn sample_data() -> SessionData {
        let now = now_secs();
        SessionData {
            user_id: "u1".into(),
            username: "alice".into(),
            email: None,
            roles: vec!["ion-drift-admin".into()],
            created_at: now,
            last_accessed: now,
            created_ip: None,
            user_agent: None,
        }
    }

    #[tokio::test]
    async fn sessions_are_stored_by_hash_not_raw_token() {
        let tmp = NamedTempFile::new().unwrap();
        let store = SessionStore::new(3600, tmp.path(), "test-signing-secret").unwrap();
        let token = store.issue_session_id().await.unwrap();
        store.insert_session(token.clone(), sample_data());

        // The raw cookie still resolves (HMAC-verified, then hashed to look up).
        assert!(store.get(&token).is_some());

        // The list/revoke handle is the hash, never the bearer token (ID-09).
        let list = store.list_sessions(Some(&token));
        assert_eq!(list.len(), 1);
        assert_ne!(list[0].session_id, token, "must not expose the raw token");
        assert_eq!(list[0].session_id, session_storage_key(&token));
        assert!(list[0].is_current);

        // Revoking by the raw token is a no-op; by the hash handle it works.
        assert!(!store.revoke_session(&token));
        assert!(store.revoke_session(&session_storage_key(&token)));
        assert!(store.get(&token).is_none());
    }
}
