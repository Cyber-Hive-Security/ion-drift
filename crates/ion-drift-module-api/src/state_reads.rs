//! Read-only trait interfaces to Drift's core state stores.
//!
//! These traits define the query surface modules can use to inspect Drift's
//! state. They deliberately contain no mutation methods — the type system
//! enforces that modules cannot write to core state, only read it. Write
//! authority remains with the engines inside the main Drift binary.
//!
//! The concrete implementations live in `ion-drift-storage` (and in some
//! cases `ion-drift-web` for cache-backed views). The host builds the trait
//! object handles and attaches them to [`crate::ModuleContext`] based on
//! declared [`crate::StateReads`] capabilities.
//!
//! All methods are async and return [`BoxFuture`] to keep the traits
//! object-safe. Modules that need to call many reads in a hot loop should
//! consider caching the returned data themselves.

use std::sync::Arc;

use crate::context::BoxFuture;

/// Lightweight reference to a behavior baseline row. Full details live in the
/// behavior store; this struct carries just enough for modules to decide
/// whether to fetch more.
#[derive(Debug, Clone)]
pub struct BehaviorBaselineRef {
    pub device_mac: String,
    pub status: String,
    pub observation_count: i64,
    pub learning_until_unix: i64,
}

/// Lightweight reference to an anomaly row.
#[derive(Debug, Clone)]
pub struct AnomalyRef {
    pub id: i64,
    pub device_mac: String,
    pub severity: String,
    pub anomaly_type: String,
    pub vlan: Option<i64>,
    pub timestamp_unix: i64,
}

/// Read-only view of the behavior store.
pub trait BehaviorRead: Send + Sync {
    /// Get a lightweight baseline reference for a device, if one exists.
    fn get_baseline<'a>(
        &'a self,
        device_mac: &'a str,
    ) -> BoxFuture<'a, Option<BehaviorBaselineRef>>;

    /// Return recent anomalies since the given unix timestamp (seconds).
    fn recent_anomalies<'a>(
        &'a self,
        since_unix: i64,
        limit: usize,
    ) -> BoxFuture<'a, Vec<AnomalyRef>>;
}

/// Lightweight reference to a MAC-to-port observation.
#[derive(Debug, Clone)]
pub struct MacLocationRef {
    pub mac: String,
    pub device_id: Option<String>,
    pub port_name: Option<String>,
    pub vlan_id: Option<i64>,
    pub last_seen_unix: i64,
}

/// Read-only view of the switch store.
pub trait SwitchRead: Send + Sync {
    /// Look up where a MAC was most recently observed.
    fn locate_mac<'a>(&'a self, mac: &'a str) -> BoxFuture<'a, Option<MacLocationRef>>;

    /// Return all devices known to the switch store.
    fn device_ids<'a>(&'a self) -> BoxFuture<'a, Vec<String>>;
}

/// Lightweight reference to a tracked connection.
#[derive(Debug, Clone)]
pub struct ConnectionRef {
    pub src_mac: Option<String>,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub state: String,
    pub timestamp_unix: i64,
}

/// Read-only view of the connection store.
///
/// **v1.0 status:** the trait exists but the host does not yet wire a
/// concrete implementation. Modules that declare
/// [`crate::StateReads::connection`] will receive `None` from
/// [`crate::ModuleContext::connection`] until a host-backed implementation
/// lands in a future minor bump. Treat this trait as forward-compatible
/// scaffolding, not a working accessor.
pub trait ConnectionRead: Send + Sync {
    /// Return connections involving a device, most recent first.
    fn for_device<'a>(
        &'a self,
        device_mac: &'a str,
        limit: usize,
    ) -> BoxFuture<'a, Vec<ConnectionRef>>;
}

/// Lightweight reference to a node in the resolved infrastructure snapshot.
#[derive(Debug, Clone)]
pub struct SnapshotNodeRef {
    pub id: String,
    pub kind: String,
    pub name: Option<String>,
}

/// Read-only view of the resolved infrastructure snapshot.
///
/// **v1.0 status:** the trait exists but the host does not yet wire a
/// concrete implementation. Modules that declare
/// [`crate::StateReads::snapshot`] will receive `None` from
/// [`crate::ModuleContext::snapshot`] until a host-backed implementation
/// lands in a future minor bump.
pub trait SnapshotRead: Send + Sync {
    /// Current snapshot generation number.
    fn generation<'a>(&'a self) -> BoxFuture<'a, u64>;

    /// All nodes in the snapshot.
    fn nodes<'a>(&'a self) -> BoxFuture<'a, Vec<SnapshotNodeRef>>;
}

/// Lightweight reference to a managed device.
#[derive(Debug, Clone)]
pub struct DeviceRef {
    pub id: String,
    pub name: String,
    pub host: String,
    pub device_type: String,
    pub is_online: bool,
}

/// Read-only view of the device manager.
///
/// **v1.0 status:** the trait exists but the host does not yet wire a
/// concrete implementation. Modules that declare
/// [`crate::StateReads::devices`] will receive `None` from
/// [`crate::ModuleContext::devices`] until a host-backed implementation
/// lands in a future minor bump.
pub trait DeviceManagerRead: Send + Sync {
    /// All devices currently managed.
    fn list<'a>(&'a self) -> BoxFuture<'a, Vec<DeviceRef>>;

    /// Look up a single device by ID.
    fn get<'a>(&'a self, device_id: &'a str) -> BoxFuture<'a, Option<DeviceRef>>;
}

/// Bundle of read handles attached to a [`crate::ModuleContext`].
///
/// Each field is `Some` only if the corresponding [`crate::StateReads`]
/// capability was declared.
#[derive(Clone, Default)]
pub struct StateReadHandleSet {
    pub behavior: Option<Arc<dyn BehaviorRead>>,
    pub switch: Option<Arc<dyn SwitchRead>>,
    pub connection: Option<Arc<dyn ConnectionRead>>,
    pub snapshot: Option<Arc<dyn SnapshotRead>>,
    pub devices: Option<Arc<dyn DeviceManagerRead>>,
}
