//! Test-only harness for end-to-end handler tests.
//!
//! Provides [`MockRouter`] (a configurable [`RouterApi`] double) and
//! [`test_app_state`], which builds a complete [`AppState`] backed by the mock
//! router plus temp-file SQLite stores and safe defaults for every other field.
//! This is the harness whose absence limited the P3 graceful-degradation work to
//! unit-testing `live_or_degrade` and the pure builders; with it, the handlers
//! can be exercised end-to-end.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tempfile::TempDir;
use tokio::sync::RwLock;

use mikrotik_core::resources::connection::{
    ConnectionEntry, ConnectionTracking, FullConnectionEntry,
};
use mikrotik_core::resources::ethernet::EthernetInterface;
use mikrotik_core::resources::firewall::{FilterRule, MangleRule, NatRule};
use mikrotik_core::resources::interface::{Interface, MonitorTrafficEntry, VlanInterface};
use mikrotik_core::resources::ip::{ArpEntry, DhcpLease, DhcpServer, IpAddress, IpPool, Route};
use mikrotik_core::resources::log::LogEntry;
use mikrotik_core::resources::system::{SystemIdentity, SystemResource};
use mikrotik_core::vlan_flows::VlanFlow;
use mikrotik_core::MikrotikError;

use crate::router_api::RouterApi;
use crate::state::AppState;

/// A configurable [`RouterApi`] test double.
///
/// * [`MockRouter::healthy`] returns small, self-consistent canned data from
///   every method (the live path).
/// * [`MockRouter::erroring`] returns [`MikrotikError::AuthFailed`] from every
///   method, simulating an unreachable/failing router (the degraded path).
pub(crate) struct MockRouter {
    healthy: bool,
}

impl MockRouter {
    /// A router that answers every call with canned data.
    pub(crate) fn healthy() -> Arc<dyn RouterApi + Send + Sync> {
        Arc::new(Self { healthy: true })
    }

    /// A router that fails every call (as an offline/unauthorized router would).
    pub(crate) fn erroring() -> Arc<dyn RouterApi + Send + Sync> {
        Arc::new(Self { healthy: false })
    }

    fn fail<T>(&self) -> Result<T, MikrotikError> {
        Err(MikrotikError::AuthFailed)
    }
}

/// Deserialize canned RouterOS JSON (kebab-case, as the router emits it).
fn from_json<T: serde::de::DeserializeOwned>(v: serde_json::Value) -> T {
    serde_json::from_value(v).expect("canned mock JSON is valid")
}

#[async_trait]
impl RouterApi for MockRouter {
    async fn arp_table(&self) -> Result<Vec<ArpEntry>, MikrotikError> {
        if !self.healthy {
            return self.fail();
        }
        Ok(vec![from_json(serde_json::json!({
            ".id": "*a1",
            "address": "10.0.0.2",
            "mac-address": "AA:BB:CC:DD:EE:01",
            "interface": "bridge",
        }))])
    }

    async fn connection_tracking(&self) -> Result<ConnectionTracking, MikrotikError> {
        if !self.healthy {
            return self.fail();
        }
        Ok(ConnectionTracking {
            max_entries: Some(1000),
        })
    }

    async fn dhcp_leases(&self) -> Result<Vec<DhcpLease>, MikrotikError> {
        if !self.healthy {
            return self.fail();
        }
        Ok(vec![from_json(serde_json::json!({
            ".id": "*d1",
            "address": "10.0.0.2",
            "mac-address": "AA:BB:CC:DD:EE:01",
            "host-name": "test-host",
            "server": "dhcp1",
            "status": "bound",
        }))])
    }

    async fn dhcp_servers(&self) -> Result<Vec<DhcpServer>, MikrotikError> {
        if !self.healthy {
            return self.fail();
        }
        Ok(vec![from_json(serde_json::json!({
            ".id": "*s1",
            "name": "dhcp1",
            "interface": "bridge",
            "address-pool": "pool1",
        }))])
    }

    async fn ethernet_interfaces(&self) -> Result<Vec<EthernetInterface>, MikrotikError> {
        if !self.healthy {
            return self.fail();
        }
        Ok(Vec::new())
    }

    async fn firewall_connections(
        &self,
        _proplist: &str,
    ) -> Result<Vec<ConnectionEntry>, MikrotikError> {
        if !self.healthy {
            return self.fail();
        }
        Ok(vec![
            from_json(serde_json::json!({ ".id": "*c1", "protocol": "tcp" })),
            from_json(serde_json::json!({ ".id": "*c2", "protocol": "udp" })),
        ])
    }

    async fn firewall_connections_full(
        &self,
    ) -> Result<Vec<FullConnectionEntry>, MikrotikError> {
        if !self.healthy {
            return self.fail();
        }
        Ok(vec![from_json(serde_json::json!({
            ".id": "*c1",
            "protocol": "tcp",
            "src-address": "10.0.0.5",
            "dst-address": "192.168.1.1",
            "src-port": "1024",
            "dst-port": "443",
            "tcp-state": "established",
            "orig-bytes": "100",
            "repl-bytes": "200",
        }))])
    }

    async fn firewall_filter_rules(&self) -> Result<Vec<FilterRule>, MikrotikError> {
        if !self.healthy {
            return self.fail();
        }
        Ok(vec![
            from_json(serde_json::json!({ ".id": "*f1", "chain": "forward", "action": "accept" })),
            from_json(serde_json::json!({ ".id": "*f2", "chain": "input", "action": "drop" })),
        ])
    }

    async fn firewall_mangle_rules(&self) -> Result<Vec<MangleRule>, MikrotikError> {
        if !self.healthy {
            return self.fail();
        }
        Ok(Vec::new())
    }

    async fn firewall_nat_rules(&self) -> Result<Vec<NatRule>, MikrotikError> {
        if !self.healthy {
            return self.fail();
        }
        Ok(Vec::new())
    }

    async fn interfaces(&self) -> Result<Vec<Interface>, MikrotikError> {
        if !self.healthy {
            return self.fail();
        }
        Ok(vec![Interface {
            id: "*i1".into(),
            name: "bridge".into(),
            default_name: None,
            iface_type: "bridge".into(),
            mtu: Some(1500),
            actual_mtu: Some(1500),
            mac_address: Some("AA:BB:CC:DD:EE:00".into()),
            running: true,
            disabled: false,
            comment: None,
            rx_byte: Some(1_000),
            tx_byte: Some(2_000),
            rx_packet: Some(10),
            tx_packet: Some(20),
            last_link_up_time: None,
        }])
    }

    async fn ip_addresses(&self) -> Result<Vec<IpAddress>, MikrotikError> {
        if !self.healthy {
            return self.fail();
        }
        Ok(Vec::new())
    }

    async fn ip_pools(&self) -> Result<Vec<IpPool>, MikrotikError> {
        if !self.healthy {
            return self.fail();
        }
        Ok(vec![from_json(serde_json::json!({
            ".id": "*p1",
            "name": "pool1",
            "ranges": "10.0.0.2-10.0.0.10",
        }))])
    }

    async fn ip_routes(&self) -> Result<Vec<Route>, MikrotikError> {
        if !self.healthy {
            return self.fail();
        }
        Ok(Vec::new())
    }

    async fn log_entries(&self) -> Result<Vec<LogEntry>, MikrotikError> {
        if !self.healthy {
            return self.fail();
        }
        Ok(vec![
            from_json(serde_json::json!({
                ".id": "*l1",
                "time": "sep/24 00:00:00",
                "topics": "firewall,info",
                "message": "input: in:ether1 src=1.2.3.4 dropped",
            })),
            from_json(serde_json::json!({
                ".id": "*l2",
                "time": "sep/24 00:00:01",
                "topics": "dhcp,info",
                "message": "dhcp1 assigned 10.0.0.2 to AA:BB:CC:DD:EE:01",
            })),
        ])
    }

    async fn monitor_traffic(
        &self,
        _interface: &str,
    ) -> Result<Vec<MonitorTrafficEntry>, MikrotikError> {
        if !self.healthy {
            return self.fail();
        }
        Ok(Vec::new())
    }

    async fn system_identity(&self) -> Result<SystemIdentity, MikrotikError> {
        if !self.healthy {
            return self.fail();
        }
        Ok(SystemIdentity {
            name: "test-router".into(),
        })
    }

    async fn system_resources(&self) -> Result<SystemResource, MikrotikError> {
        if !self.healthy {
            return self.fail();
        }
        Ok(SystemResource {
            id: None,
            uptime: "1w".into(),
            version: "7.0".into(),
            build_time: None,
            factory_software: None,
            free_memory: 100,
            total_memory: 200,
            cpu: "arm".into(),
            cpu_count: 1,
            cpu_frequency: 1000,
            cpu_load: 5,
            free_hdd_space: 100,
            total_hdd_space: 200,
            architecture_name: None,
            board_name: "TestBoard".into(),
            platform: "MikroTik".into(),
        })
    }

    async fn vlan_interfaces(&self) -> Result<Vec<VlanInterface>, MikrotikError> {
        if !self.healthy {
            return self.fail();
        }
        Ok(Vec::new())
    }

    async fn vlan_flows(&self) -> Result<Vec<VlanFlow>, MikrotikError> {
        if !self.healthy {
            return self.fail();
        }
        Ok(Vec::new())
    }
}

/// Build a full [`AppState`] wired to `router`, with temp-file SQLite stores and
/// safe defaults for every other field.
///
/// Returns the state together with the owning [`TempDir`]; the caller must keep
/// the `TempDir` alive for the duration of the test (its DB files back the
/// stores).
pub(crate) async fn test_app_state(
    router: Arc<dyn RouterApi + Send + Sync>,
) -> (AppState, TempDir) {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let d = tmp.path();

    // Minimal config: every field of [server]/[router] has a serde default.
    let config: crate::config::ServerConfig =
        toml::from_str("[server]\n[router]\n").expect("minimal config parses");
    let config = Arc::new(config);

    // A dummy concrete client for the fields that still require one (the request
    // queue and traffic tracker). It is never driven in these tests — building it
    // performs no network I/O.
    let dummy_client = mikrotik_core::MikrotikClient::new(mikrotik_core::MikrotikConfig::default())
        .expect("client builds without network I/O");

    let supervisor = crate::task_supervisor::TaskSupervisor::new();

    // Module registry: an empty registry built from empty host deps.
    let event_bus = ion_drift_module_host::EventBus::new(1024);
    let module_shutdown = ion_drift_module_api::ShutdownSignal::new();
    let task_spawner: Arc<dyn ion_drift_module_api::context::TaskSpawner> =
        Arc::new(crate::module_adapters::SupervisorSpawner::new(supervisor.clone()));
    let secret_resolver: Arc<dyn ion_drift_module_api::context::SecretResolver> =
        Arc::new(crate::module_adapters::EnvSecretResolver);
    let state_reads = ion_drift_module_api::context::StateReadHandles {
        behavior: None,
        switch: None,
        connection: None,
        snapshot: None,
        devices: None,
    };
    let host_deps = ion_drift_module_host::registry::HostDeps {
        data_dir: d.to_path_buf(),
        event_bus: event_bus.clone(),
        task_spawner,
        secret_resolver,
        shutdown: module_shutdown.clone(),
        state_reads,
        modules_config: toml::Table::new(),
    };
    let module_registry = Arc::new(RwLock::new(
        ion_drift_module_host::ModuleRegistry::load(Vec::new(), host_deps).await,
    ));

    let device_manager = crate::device_manager::DeviceManager::from_config(
        &config,
        "test-router",
        "Test Router",
        None,
    )
    .expect("device manager from config");

    let state = AppState {
        mikrotik: router,
        oidc_client: None,
        http_client: reqwest::Client::new(),
        sessions: crate::auth::SessionStore::with_idle_timeout(
            3600,
            0,
            &d.join("sessions.db"),
            "test-session-secret-0123456789abcd",
        )
        .expect("session store"),
        traffic_tracker: Arc::new(
            mikrotik_core::TrafficTracker::new(&d.join("traffic.db"), "ether1")
                .expect("traffic tracker"),
        ),
        metrics_store: Arc::new(
            ion_drift_storage::MetricsStore::new(&d.join("metrics.db")).expect("metrics store"),
        ),
        live_traffic: Arc::new(crate::live_traffic::LiveTrafficBuffer::new(100)),
        config: config.clone(),
        oui_db: crate::oui::OuiDb::load(),
        geo_cache: Arc::new(
            crate::geo::GeoCache::new(&d.join("geo.db"), None, Vec::new()).expect("geo cache"),
        ),
        connection_store: Arc::new(
            crate::connection_store::ConnectionStore::new(&d.join("connections.db"))
                .expect("connection store"),
        ),
        network_map_cache: Arc::new(RwLock::new(None)),
        behavior_store: Arc::new(
            ion_drift_storage::BehaviorStore::new(&d.join("behavior.db")).expect("behavior store"),
        ),
        findings_store: Arc::new(
            ion_drift_storage::FindingsStore::new(&d.join("findings.db")).expect("findings store"),
        ),
        advisory_store: Arc::new(
            ion_drift_storage::AdvisoryStore::new(&d.join("advisory.db"))
                .await
                .expect("advisory store"),
        ),
        dns_store: Arc::new(
            ion_drift_storage::DnsStore::new(&d.join("dns.db"))
                .await
                .expect("dns store"),
        ),
        firewall_rules_cache: Arc::new(RwLock::new((Vec::new(), std::time::Instant::now()))),
        secrets_manager: None,
        module_registry_store: None,
        module_registry_service: None,
        module_event_dispatcher: None,
        nonce_cache: Arc::new(crate::modules_registry::NonceCache::new()),
        device_manager: Arc::new(RwLock::new(device_manager)),
        switch_store: Arc::new(
            ion_drift_storage::SwitchStore::new(&d.join("switch.db")).expect("switch store"),
        ),
        topology_cache: Arc::new(RwLock::new(None)),
        vlan_registry: Arc::new(RwLock::new(
            ion_drift_storage::behavior::VlanRegistry::from_configs(&[]),
        )),
        poller_registry: Arc::new(RwLock::new(crate::poller_registry::PollerRegistry::new())),
        stats_store: Arc::new(
            crate::stats_store::StatsStore::new(&d.join("stats.db")).expect("stats store"),
        ),
        task_supervisor: supervisor,
        login_limiter: crate::auth::LoginRateLimiter::new(),
        attack_techniques: Arc::new(crate::attack_techniques::AttackTechniqueDb::load()),
        router_queue: crate::router_queue::RouterQueue::new(dummy_client, Duration::from_secs(1)),
        device_queues: Arc::new(RwLock::new(
            crate::device_queue_registry::DeviceQueueRegistry::new(Duration::from_secs(1)),
        )),
        event_bus,
        module_registry,
        infrastructure_snapshot: Arc::new(RwLock::new(
            crate::infrastructure_snapshot::InfrastructureSnapshotState::new(),
        )),
    };

    (state, tmp)
}

/// A minimal authenticated session for driving handlers that require auth.
pub(crate) fn test_session() -> crate::middleware::RequireAuth {
    crate::middleware::RequireAuth(crate::auth::SessionData {
        user_id: "test-user".into(),
        username: "tester".into(),
        email: None,
        roles: vec!["admin".into()],
        created_at: 0,
        last_accessed: 0,
        created_ip: None,
        user_agent: None,
    })
}
