use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64};

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
    /// Whether a speed test is currently running.
    pub speedtest_running: Arc<AtomicBool>,
    /// Unix timestamp of the last completed speed test (for cooldown).
    pub speedtest_last_completed: Arc<AtomicI64>,
}
