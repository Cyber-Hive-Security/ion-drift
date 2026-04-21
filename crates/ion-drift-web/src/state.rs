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
use crate::modules_registry::{EventDispatcher, ModuleRegistryService, ModuleRegistryStore};
use crate::secrets::SecretsManager;
use crate::stats_store::StatsStore;
use crate::attack_techniques::AttackTechniqueDb;
use crate::infrastructure_snapshot::InfrastructureSnapshotState;
use crate::device_queue_registry::DeviceQueueRegistry;
use crate::router_queue::RouterQueue;
use crate::task_supervisor::TaskSupervisor;
use ion_drift_module_api::ShutdownSignal;
use ion_drift_module_host::registry::ModuleRegistry;
use ion_drift_module_host::EventBus;
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
    /// Persistence for externally-registered modules (shares `secrets.db`
    /// with SecretsManager; None if bootstrap not yet run).
    pub module_registry_store: Option<Arc<ModuleRegistryStore>>,
    /// Registration + manifest-validation service layered over the store.
    pub module_registry_service: Option<Arc<ModuleRegistryService>>,
    /// HMAC-signed event dispatcher; the run loop is spawned in main.rs
    /// and subscribes to every `EventKind` on the in-process EventBus.
    pub module_event_dispatcher: Option<Arc<EventDispatcher>>,
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
    /// Page view statistics store (SQLite).
    pub stats_store: Arc<StatsStore>,
    /// Background task supervisor — tracks health and restarts panicked tasks.
    pub task_supervisor: TaskSupervisor,
    /// Per-key rate limiter for local login attempts.
    pub login_limiter: LoginRateLimiter,
    /// ATT&CK technique database for policy deviation enrichment.
    pub attack_techniques: Arc<AttackTechniqueDb>,
    /// Serialized request queue for router API access (background pollers).
    pub router_queue: RouterQueue,
    /// Per-device API queues for managed switches (RouterOS).
    pub device_queues: Arc<RwLock<DeviceQueueRegistry>>,
    /// Event bus for internal and module event publication.
    pub event_bus: EventBus,
    /// Registry of loaded modules and their merged HTTP routes.
    pub module_registry: Arc<RwLock<ModuleRegistry>>,
    /// Cooperative shutdown signal shared with modules and background tasks.
    pub module_shutdown: ShutdownSignal,
    /// Resolved infrastructure snapshot — platform's canonical view of network truth.
    /// Produced by correlation engine, consumed by topology builder and others.
    pub infrastructure_snapshot: Arc<RwLock<InfrastructureSnapshotState>>,
}
