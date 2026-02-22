use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64};

use tokio::sync::RwLock;

use mikrotik_core::{BehaviorStore, MikrotikClient, MetricsStore, SpeedTestStore, TrafficTracker};
use mikrotik_core::resources::firewall::FilterRule;
use crate::auth::{OidcClient, SessionStore};
use crate::config::ServerConfig;
use crate::geo::GeoDb;
use crate::live_traffic::LiveTrafficBuffer;
use crate::oui::OuiDb;
use crate::routes::network_map_status::NetworkMapStatusCache;

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
    /// CPU/memory metrics history store (SQLite).
    pub metrics_store: Arc<MetricsStore>,
    /// In-memory ring buffer for real-time traffic rates.
    pub live_traffic: Arc<LiveTrafficBuffer>,
    /// Immutable server configuration.
    pub config: Arc<ServerConfig>,
    /// Whether a speed test is currently running.
    pub speedtest_running: Arc<AtomicBool>,
    /// Unix timestamp of the last completed speed test (for cooldown).
    pub speedtest_last_completed: Arc<AtomicI64>,
    /// MAC OUI manufacturer lookup database.
    pub oui_db: Arc<OuiDb>,
    /// GeoIP country lookup database (optional).
    pub geo_db: Arc<GeoDb>,
    /// Cached network map status (DHCP + ARP + interfaces), refreshed every 5s.
    pub network_map_cache: Arc<RwLock<Option<NetworkMapStatusCache>>>,
    /// Device behavioral fingerprinting store (SQLite).
    pub behavior_store: Arc<BehaviorStore>,
    /// Cached firewall filter rules for behavior correlation.
    pub firewall_rules_cache: Arc<RwLock<(Vec<FilterRule>, std::time::Instant)>>,
}
