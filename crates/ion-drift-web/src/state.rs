use std::sync::Arc;

use mikrotik_core::{MikrotikClient, SpeedTestStore, TrafficTracker};
use crate::auth::{OidcClient, SessionStore};
use crate::config::ServerConfig;

/// Shared application state, passed to all Axum handlers via `State<AppState>`.
#[derive(Clone)]
pub struct AppState {
    /// RouterOS REST API client.
    pub mikrotik: MikrotikClient,
    /// OpenID Connect client for Keycloak authentication.
    pub oidc_client: OidcClient,
    /// Shared HTTP client configured with the Smallstep CA cert.
    pub http_client: reqwest::Client,
    /// In-memory session store (DashMap-backed).
    pub sessions: SessionStore,
    /// Background traffic tracker (WAN interface counters).
    pub traffic_tracker: Arc<TrafficTracker>,
    /// Persistent speed test result store (SQLite).
    pub speedtest_store: Arc<SpeedTestStore>,
    /// Immutable server configuration.
    pub config: Arc<ServerConfig>,
}
