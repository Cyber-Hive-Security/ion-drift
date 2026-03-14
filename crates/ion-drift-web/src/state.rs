use std::sync::Arc;

use tokio::sync::RwLock;

use mikrotik_core::MikrotikClient;
use ion_drift_storage::{BehaviorStore, MetricsStore, SwitchStore};
use mikrotik_core::TrafficTracker;
use ion_drift_storage::behavior::VlanRegistry;
use mikrotik_core::resources::firewall::FilterRule;
use crate::auth::{LoginRateLimiter, OidcClient, SessionStore};
use crate::config::ServerConfig;
use crate::connection_store::ConnectionStore;
use crate::device_manager::DeviceManager;
use crate::geo::GeoCache;
use crate::live_traffic::LiveTrafficBuffer;
use crate::oui::OuiDb;
use crate::poller_registry::PollerRegistry;
use crate::routes::network_map_status::NetworkMapStatusCache;
use crate::secrets::SecretsManager;
use crate::task_supervisor::TaskSupervisor;
use crate::topology::NetworkTopology;

/// Shared application state, passed to all Axum handlers via `State<AppState>`.
#[derive(Clone)]
pub struct AppState {
    /// RouterOS REST API client.
    pub mikrotik: MikrotikClient,
    /// OpenID Connect client for Keycloak authentication (None if OIDC not configured).
    pub oidc_client: Option<OidcClient>,
    /// Shared HTTP client configured with the Smallstep CA cert.
    pub http_client: reqwest::Client,
    /// In-memory session store (DashMap-backed).
    pub sessions: SessionStore,
    /// Background traffic tracker (WAN interface counters).
    pub traffic_tracker: Arc<TrafficTracker>,
    /// CPU/memory metrics history store (SQLite).
    pub metrics_store: Arc<MetricsStore>,
    /// In-memory ring buffer for real-time traffic rates.
    pub live_traffic: Arc<LiveTrafficBuffer>,
    /// Immutable server configuration.
    pub config: Arc<ServerConfig>,
    /// MAC OUI manufacturer lookup database.
    pub oui_db: Arc<OuiDb>,
    /// IP geolocation cache (MaxMind primary, ip-api.com fallback).
    pub geo_cache: Arc<GeoCache>,
    /// Persistent connection history store (SQLite).
    pub connection_store: Arc<ConnectionStore>,
    /// Cached network map status (DHCP + ARP + interfaces), refreshed every 5s.
    pub network_map_cache: Arc<RwLock<Option<NetworkMapStatusCache>>>,
    /// Device behavioral fingerprinting store (SQLite).
    pub behavior_store: Arc<BehaviorStore>,
    /// Cached firewall filter rules for behavior correlation.
    pub firewall_rules_cache: Arc<RwLock<(Vec<FilterRule>, std::time::Instant)>>,
    /// Encrypted secrets manager (None if bootstrap not configured).
    pub secrets_manager: Option<Arc<RwLock<SecretsManager>>>,
    /// Multi-device manager (router + switches).
    pub device_manager: Arc<RwLock<DeviceManager>>,
    /// Switch-specific data store (port metrics, MAC table, neighbors, etc.).
    pub switch_store: Arc<SwitchStore>,
    /// Cached auto-generated network topology, recomputed every 120s.
    pub topology_cache: Arc<RwLock<Option<NetworkTopology>>>,
    /// VLAN registry built from database VlanConfig entries.
    /// Refreshed when VLAN configs change.
    pub vlan_registry: Arc<RwLock<VlanRegistry>>,
    /// Registry of running per-device poller tasks for dynamic start/stop.
    pub poller_registry: Arc<RwLock<PollerRegistry>>,
    /// Background task supervisor — tracks health and restarts panicked tasks.
    pub task_supervisor: TaskSupervisor,
    /// Per-key rate limiter for local login attempts.
    pub login_limiter: LoginRateLimiter,
}
