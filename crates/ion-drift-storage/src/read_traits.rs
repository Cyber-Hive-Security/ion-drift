//! Implementations of the module-api read-only traits for the concrete
//! store types in this crate.
//!
//! Modules receive these as `Arc<dyn BehaviorRead>` etc. via the module
//! host. The trait surface deliberately exposes only the query methods
//! modules need; anything write-facing remains on the concrete store type
//! and is inaccessible through the trait object.

use std::sync::Arc;

use ion_drift_module_api::context::BoxFuture;
use ion_drift_module_api::state_reads::{
    AnomalyRef, BehaviorBaselineRef, BehaviorRead, ConnectionRef, ConnectionRead,
    DeviceManagerRead, DeviceRef, MacLocationRef, SnapshotNodeRef, SnapshotRead,
    SwitchRead,
};

use crate::behavior::BehaviorStore;
use crate::switch::SwitchStore;

// ── BehaviorRead on BehaviorStore ────────────────────────────────────

impl BehaviorRead for BehaviorStore {
    fn get_baseline<'a>(
        &'a self,
        device_mac: &'a str,
    ) -> BoxFuture<'a, Option<BehaviorBaselineRef>> {
        Box::pin(async move {
            let db = self.db().await;
            db.query_row(
                "SELECT mac, baseline_status, learning_until
                 FROM device_profiles
                 WHERE mac = ?1",
                [device_mac],
                |row| {
                    Ok(BehaviorBaselineRef {
                        device_mac: row.get::<_, String>(0)?,
                        status: row.get::<_, String>(1)?,
                        observation_count: 0, // per-device observation count lives in baselines aggregation, omitted here
                        learning_until_unix: row.get::<_, i64>(2)?,
                    })
                },
            )
            .ok()
        })
    }

    fn recent_anomalies<'a>(
        &'a self,
        since_unix: i64,
        limit: usize,
    ) -> BoxFuture<'a, Vec<AnomalyRef>> {
        Box::pin(async move {
            let db = self.db().await;
            let mut stmt = match db.prepare(
                "SELECT id, mac, severity, anomaly_type, vlan, timestamp
                 FROM device_anomalies
                 WHERE timestamp >= ?1
                 ORDER BY timestamp DESC
                 LIMIT ?2",
            ) {
                Ok(s) => s,
                Err(_) => return Vec::new(),
            };
            let rows = stmt.query_map(
                rusqlite::params![since_unix, limit as i64],
                |row| {
                    Ok(AnomalyRef {
                        id: row.get(0)?,
                        device_mac: row.get(1)?,
                        severity: row.get(2)?,
                        anomaly_type: row.get(3)?,
                        vlan: Some(row.get::<_, i64>(4)?),
                        timestamp_unix: row.get(5)?,
                    })
                },
            );
            match rows {
                Ok(iter) => iter.filter_map(Result::ok).collect(),
                Err(_) => Vec::new(),
            }
        })
    }
}

/// Wrap a `BehaviorStore` as a trait object.
pub fn behavior_read(store: Arc<BehaviorStore>) -> Arc<dyn BehaviorRead> {
    store
}

// ── SwitchRead on SwitchStore ────────────────────────────────────────

impl SwitchRead for SwitchStore {
    fn locate_mac<'a>(&'a self, mac: &'a str) -> BoxFuture<'a, Option<MacLocationRef>> {
        Box::pin(async move {
            let db = self.db().await;
            db.query_row(
                "SELECT mac_address, device_id, interface, vlan_id, last_seen
                 FROM mac_table
                 WHERE mac_address = ?1
                 ORDER BY last_seen DESC
                 LIMIT 1",
                [mac],
                |row| {
                    Ok(MacLocationRef {
                        mac: row.get::<_, String>(0)?,
                        device_id: row.get::<_, Option<String>>(1)?,
                        port_name: row.get::<_, Option<String>>(2)?,
                        vlan_id: row.get::<_, Option<i64>>(3)?,
                        last_seen_unix: row.get::<_, i64>(4)?,
                    })
                },
            )
            .ok()
        })
    }

    fn device_ids<'a>(&'a self) -> BoxFuture<'a, Vec<String>> {
        Box::pin(async move {
            let db = self.db().await;
            let mut stmt = match db
                .prepare("SELECT DISTINCT device_id FROM mac_table WHERE device_id IS NOT NULL")
            {
                Ok(s) => s,
                Err(_) => return Vec::new(),
            };
            let rows = stmt.query_map([], |row| row.get::<_, String>(0));
            match rows {
                Ok(iter) => iter.filter_map(Result::ok).collect(),
                Err(_) => Vec::new(),
            }
        })
    }
}

/// Wrap a `SwitchStore` as a trait object.
pub fn switch_read(store: Arc<SwitchStore>) -> Arc<dyn SwitchRead> {
    store
}

// ── Placeholder stubs for ConnectionRead / SnapshotRead / DeviceManagerRead ──
//
// Phase 1 only exposes BehaviorRead and SwitchRead directly from this crate.
// The other trait objects (ConnectionRead, SnapshotRead, DeviceManagerRead)
// are implemented by the host crate on the corresponding types that live
// there (ConnectionStore, InfrastructureSnapshotState, DeviceManager). The
// module API crate carries the trait definitions so consumers can accept
// `Option<Arc<dyn ConnectionRead>>` without depending on the host crate.

// Empty no-op implementations that always return empty results. Useful as
// defaults during wiring; the host replaces them with real implementations.

/// A connection read that always returns an empty list.
pub struct EmptyConnectionRead;

impl ConnectionRead for EmptyConnectionRead {
    fn for_device<'a>(
        &'a self,
        _device_mac: &'a str,
        _limit: usize,
    ) -> BoxFuture<'a, Vec<ConnectionRef>> {
        Box::pin(async { Vec::new() })
    }
}

/// A snapshot read that always returns zero generation and no nodes.
pub struct EmptySnapshotRead;

impl SnapshotRead for EmptySnapshotRead {
    fn generation<'a>(&'a self) -> BoxFuture<'a, u64> {
        Box::pin(async { 0 })
    }
    fn nodes<'a>(&'a self) -> BoxFuture<'a, Vec<SnapshotNodeRef>> {
        Box::pin(async { Vec::new() })
    }
}

/// A device-manager read that always returns no devices.
pub struct EmptyDeviceManagerRead;

impl DeviceManagerRead for EmptyDeviceManagerRead {
    fn list<'a>(&'a self) -> BoxFuture<'a, Vec<DeviceRef>> {
        Box::pin(async { Vec::new() })
    }
    fn get<'a>(&'a self, _device_id: &'a str) -> BoxFuture<'a, Option<DeviceRef>> {
        Box::pin(async { None })
    }
}
