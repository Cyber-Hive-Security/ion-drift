//! Event bus payloads and discriminants.
//!
//! Events are advisory broadcast messages published by Drift engines at
//! meaningful lifecycle points. Modules subscribe to the kinds they care
//! about via [`crate::EventSubscriptions::subscribe`]. Events are NOT durable:
//! a lagging subscriber will see [`crate::EventError::Lagged`] and is
//! expected to resync from the authoritative stores.
//!
//! # Versioning
//!
//! - [`DriftEvent`] is `#[non_exhaustive]`. Adding variants is a minor bump
//!   and forces consumers to write a `_ => {}` fallthrough.
//! - Each variant's payload is a struct suffixed `V1`. Adding fields to a
//!   payload requires a new `V2` struct and a new enum variant; the old
//!   variant is kept for backward compatibility.
//! - Removing variants is a major bump and requires explicit deprecation.

use std::sync::Arc;

/// A coarse discriminant for events, used in capability declarations.
///
/// Modules declare what they want to subscribe to and publish using
/// `EventKind` values rather than full payloads. The host filters the bus
/// accordingly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventKind {
    AnomalyDetected,
    BehaviorBaselineUpdated,
    InvestigationStarted,
    InvestigationCompleted,
    InfrastructureSnapshotUpdated,
    DeviceAdded,
    DeviceRemoved,
    DeviceUnreachable,
    SwitchTopologyChanged,
    ConnectionStateChanged,
    ModuleCustom,
}

impl EventKind {
    pub fn of(event: &DriftEvent) -> Self {
        match event {
            DriftEvent::AnomalyDetected(_) => Self::AnomalyDetected,
            DriftEvent::BehaviorBaselineUpdated(_) => Self::BehaviorBaselineUpdated,
            DriftEvent::InvestigationStarted(_) => Self::InvestigationStarted,
            DriftEvent::InvestigationCompleted(_) => Self::InvestigationCompleted,
            DriftEvent::InfrastructureSnapshotUpdated(_) => Self::InfrastructureSnapshotUpdated,
            DriftEvent::DeviceAdded(_) => Self::DeviceAdded,
            DriftEvent::DeviceRemoved(_) => Self::DeviceRemoved,
            DriftEvent::DeviceUnreachable(_) => Self::DeviceUnreachable,
            DriftEvent::SwitchTopologyChanged(_) => Self::SwitchTopologyChanged,
            DriftEvent::ConnectionStateChanged(_) => Self::ConnectionStateChanged,
            DriftEvent::ModuleCustom { .. } => Self::ModuleCustom,
        }
    }
}

/// An advisory event broadcast by Drift engines and modules.
///
/// `#[non_exhaustive]` — consumers must include a fallthrough arm when matching.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum DriftEvent {
    /// A behavior anomaly was detected. Payload is a lightweight reference;
    /// full anomaly details should be looked up via the behavior store.
    AnomalyDetected(AnomalyDetectedV1),

    /// A device's behavior baseline was updated (recomputed).
    BehaviorBaselineUpdated(BehaviorBaselineUpdatedV1),

    /// An automated investigation started for an anomaly.
    InvestigationStarted(InvestigationStartedV1),

    /// An automated investigation finished and has a verdict.
    InvestigationCompleted(InvestigationCompletedV1),

    /// A new infrastructure snapshot generation was published by the
    /// correlation engine.
    InfrastructureSnapshotUpdated(InfrastructureSnapshotUpdatedV1),

    /// A new device was added to the managed inventory.
    DeviceAdded(DeviceAddedV1),

    /// A device was removed from the managed inventory.
    DeviceRemoved(DeviceRemovedV1),

    /// A device stopped responding to polls.
    DeviceUnreachable(DeviceUnreachableV1),

    /// Topology of a managed switch changed.
    SwitchTopologyChanged(SwitchTopologyChangedV1),

    /// A tracked connection changed state (new, closed, reclassified).
    ConnectionStateChanged(ConnectionStateChangedV1),

    /// Escape hatch for module-to-module communication without touching the
    /// core event enum. The `source` field is **host-populated** with the
    /// publishing module's actual name — modules cannot spoof it. Payload is
    /// an arbitrary JSON value; `kind` is a free-form identifier the
    /// publishing module chooses to discriminate its own custom events.
    ///
    /// Use [`crate::EventHandle::publish_custom`] to publish; the plain
    /// `publish` method rejects this variant for that reason.
    ModuleCustom {
        source: &'static str,
        kind: &'static str,
        payload: Arc<serde_json::Value>,
    },
}

// ── v1 payloads ──────────────────────────────────────────────────────

/// Payload for [`DriftEvent::AnomalyDetected`].
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AnomalyDetectedV1 {
    pub anomaly_id: i64,
    pub device_mac: String,
    pub severity: String,
    pub anomaly_type: String,
    pub vlan: Option<i64>,
    pub timestamp_unix: i64,
}

/// Payload for [`DriftEvent::BehaviorBaselineUpdated`].
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BehaviorBaselineUpdatedV1 {
    pub device_mac: String,
    pub status: String,
    pub observation_count: i64,
    pub timestamp_unix: i64,
}

/// Payload for [`DriftEvent::InvestigationStarted`].
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct InvestigationStartedV1 {
    pub investigation_id: i64,
    pub anomaly_id: Option<i64>,
    pub device_mac: String,
    pub timestamp_unix: i64,
}

/// Payload for [`DriftEvent::InvestigationCompleted`].
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct InvestigationCompletedV1 {
    pub investigation_id: i64,
    pub anomaly_id: Option<i64>,
    pub device_mac: String,
    pub verdict: String,
    pub timestamp_unix: i64,
}

/// Payload for [`DriftEvent::InfrastructureSnapshotUpdated`].
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct InfrastructureSnapshotUpdatedV1 {
    pub generation: u64,
    pub node_count: usize,
    pub edge_count: usize,
    pub timestamp_unix: i64,
}

/// Payload for [`DriftEvent::DeviceAdded`].
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DeviceAddedV1 {
    pub device_id: String,
    pub name: String,
    pub host: String,
    pub device_type: String,
    pub timestamp_unix: i64,
}

/// Payload for [`DriftEvent::DeviceRemoved`].
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DeviceRemovedV1 {
    pub device_id: String,
    pub timestamp_unix: i64,
}

/// Payload for [`DriftEvent::DeviceUnreachable`].
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DeviceUnreachableV1 {
    pub device_id: String,
    pub error: String,
    pub timestamp_unix: i64,
}

/// Payload for [`DriftEvent::SwitchTopologyChanged`].
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SwitchTopologyChangedV1 {
    pub device_id: String,
    pub port_count: usize,
    pub timestamp_unix: i64,
}

/// Payload for [`DriftEvent::ConnectionStateChanged`].
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ConnectionStateChangedV1 {
    pub src_mac: Option<String>,
    pub dst_ip: String,
    pub dst_port: Option<u16>,
    pub state: String,
    pub timestamp_unix: i64,
}
