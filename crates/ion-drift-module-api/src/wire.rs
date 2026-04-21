//! On-wire types for out-of-process module transports (API v1.1+).
//!
//! Modules running as external services (Phase 1: HTTP) or inside a WASM
//! sandbox (Phase 2: planned) exchange events and metadata with Drift using
//! the types in this module. The in-process [`crate::Module`] trait and
//! [`crate::DriftEvent`] enum remain the canonical contract; the wire
//! types here are derivable adapters that are `Serialize + Deserialize`
//! and own their data.
//!
//! The forward-compat design is: one event schema, many transports. A
//! scout-shield binary and a future scout-shield WASM blob both exchange
//! [`EventEnvelope`] payloads with identical shape; only the plumbing
//! differs.

use serde::{Deserialize, Serialize};

use crate::event::{
    AnomalyDetectedV1, BehaviorBaselineUpdatedV1, ConnectionStateChangedV1, DeviceAddedV1,
    DeviceRemovedV1, DeviceUnreachableV1, DriftEvent, EventKind, InfrastructureSnapshotUpdatedV1,
    InvestigationCompletedV1, InvestigationStartedV1, SwitchTopologyChangedV1,
};
use crate::module::ApiVersion;

/// Which transport a registered module uses.
///
/// `#[non_exhaustive]` so future transports (WASM, local IPC) can be added
/// without a major bump. Serialized as snake_case so JSON consumers can
/// switch on stable string values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProtocolVariant {
    /// Out-of-process HTTP transport. Drift delivers events via signed
    /// POSTs to `<module_url>/events` and reverse-proxies
    /// `/api/modules/<name>/*` to `<module_url>/*`.
    Http,
}

/// Declarative description a module returns from `GET /manifest`.
///
/// Drift fetches this during registration to learn what the module is,
/// what API version it targets, which events it wants delivered, and which
/// HTTP routes it exposes for reverse-proxying.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Stable module identifier, also used as the URL segment in
    /// `/api/modules/<name>/`. Must match the same regex enforced on the
    /// in-process trait: `^[a-z][a-z0-9_-]{1,31}$`.
    pub name: String,

    /// Semantic version of the module itself (not the API).
    pub version: String,

    /// API version this module was built against. Drift uses the same
    /// compatibility rule as for in-process modules: same major, module
    /// minor ≤ host minor.
    pub api_version: ApiVersion,

    /// Transport the module speaks.
    pub protocol: ProtocolVariant,

    /// Human-readable description shown in the Drift admin UI.
    #[serde(default)]
    pub description: Option<String>,

    /// Events this module wants delivered as webhooks. Drift filters its
    /// internal event bus against this set per module.
    #[serde(default)]
    pub subscribed_events: Vec<EventKind>,

    /// HTTP routes the module exposes. Drift reverse-proxies
    /// `/api/modules/<name>/<path>` → `<module_url>/<path>` after
    /// admin-authenticating the inbound caller and injecting the module's
    /// per-registration bearer token.
    #[serde(default)]
    pub exposed_routes: Vec<RouteDescriptor>,
}

/// A single HTTP route a module advertises via its manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteDescriptor {
    /// Path relative to the module root, e.g. `/watchlist`.
    pub path: String,

    /// HTTP method. Defaults to `"GET"`.
    #[serde(default = "default_method")]
    pub method: String,

    /// Short human description shown in the admin UI.
    #[serde(default)]
    pub description: Option<String>,
}

fn default_method() -> String {
    "GET".to_string()
}

/// Signed delivery envelope for a single event.
///
/// Drift serializes this struct to JSON and signs the bytes with
/// HMAC-SHA256 over `shared_secret ∥ timestamp_unix ∥ nonce ∥ body`. The
/// signature travels in the `X-IonDrift-Signature` header alongside the
/// POST. Receivers reject envelopes with stale timestamps or replayed
/// `event_id` / `nonce` pairs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    /// API version of the crate that produced this envelope.
    pub api_version: ApiVersion,

    /// UUIDv4 assigned per delivery attempt. Stable across retries so
    /// receivers can dedupe idempotently.
    pub event_id: String,

    /// Unix seconds at dispatch time.
    pub timestamp_unix: i64,

    /// Random 16-byte value, hex-encoded. Used alongside `event_id` for
    /// replay protection and to make the HMAC input domain-separated from
    /// any plain body.
    pub nonce: String,

    /// Coarse discriminant matching `event.kind()`. Lets receivers filter
    /// without fully parsing `event`.
    pub kind: EventKind,

    /// The event payload in wire form.
    pub event: DriftEventWire,
}

/// Wire-serializable mirror of [`DriftEvent`].
///
/// This enum exists because [`DriftEvent::ModuleCustom`] carries
/// `&'static str` fields that don't round-trip through serde. The wire
/// variant uses owned `String`s, and the [`From`] impl below copies on
/// dispatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
#[non_exhaustive]
pub enum DriftEventWire {
    AnomalyDetected(AnomalyDetectedV1),
    BehaviorBaselineUpdated(BehaviorBaselineUpdatedV1),
    InvestigationStarted(InvestigationStartedV1),
    InvestigationCompleted(InvestigationCompletedV1),
    InfrastructureSnapshotUpdated(InfrastructureSnapshotUpdatedV1),
    DeviceAdded(DeviceAddedV1),
    DeviceRemoved(DeviceRemovedV1),
    DeviceUnreachable(DeviceUnreachableV1),
    SwitchTopologyChanged(SwitchTopologyChangedV1),
    ConnectionStateChanged(ConnectionStateChangedV1),
    ModuleCustom(ModuleCustomWireV1),
}

/// Owned-data mirror of the `DriftEvent::ModuleCustom` struct variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleCustomWireV1 {
    /// Host-populated name of the publishing module. Modules do not set
    /// this field; Drift fills it from the registered module's name at
    /// dispatch time.
    pub source: String,

    /// Free-form discriminant the publishing module chose.
    pub kind: String,

    /// Arbitrary JSON payload.
    pub payload: serde_json::Value,
}

impl From<&DriftEvent> for DriftEventWire {
    fn from(event: &DriftEvent) -> Self {
        match event {
            DriftEvent::AnomalyDetected(p) => Self::AnomalyDetected(p.clone()),
            DriftEvent::BehaviorBaselineUpdated(p) => Self::BehaviorBaselineUpdated(p.clone()),
            DriftEvent::InvestigationStarted(p) => Self::InvestigationStarted(p.clone()),
            DriftEvent::InvestigationCompleted(p) => Self::InvestigationCompleted(p.clone()),
            DriftEvent::InfrastructureSnapshotUpdated(p) => {
                Self::InfrastructureSnapshotUpdated(p.clone())
            }
            DriftEvent::DeviceAdded(p) => Self::DeviceAdded(p.clone()),
            DriftEvent::DeviceRemoved(p) => Self::DeviceRemoved(p.clone()),
            DriftEvent::DeviceUnreachable(p) => Self::DeviceUnreachable(p.clone()),
            DriftEvent::SwitchTopologyChanged(p) => Self::SwitchTopologyChanged(p.clone()),
            DriftEvent::ConnectionStateChanged(p) => Self::ConnectionStateChanged(p.clone()),
            DriftEvent::ModuleCustom {
                source,
                kind,
                payload,
            } => Self::ModuleCustom(ModuleCustomWireV1 {
                source: (*source).to_string(),
                kind: (*kind).to_string(),
                payload: (**payload).clone(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_envelope_round_trips() {
        let env = EventEnvelope {
            api_version: ApiVersion::CURRENT,
            event_id: "11111111-2222-3333-4444-555555555555".to_string(),
            timestamp_unix: 1_700_000_000,
            nonce: "a1b2c3d4e5f60718".to_string(),
            kind: EventKind::AnomalyDetected,
            event: DriftEventWire::AnomalyDetected(AnomalyDetectedV1 {
                anomaly_id: 42,
                device_mac: "aa:bb:cc:dd:ee:ff".to_string(),
                severity: "high".to_string(),
                anomaly_type: "new_destination".to_string(),
                vlan: Some(25),
                timestamp_unix: 1_700_000_000,
            }),
        };
        let json = serde_json::to_string(&env).expect("serialize");
        let back: EventEnvelope = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.event_id, env.event_id);
        assert_eq!(back.kind, EventKind::AnomalyDetected);
    }

    #[test]
    fn event_kind_serializes_snake_case() {
        let s = serde_json::to_string(&EventKind::AnomalyDetected).unwrap();
        assert_eq!(s, "\"anomaly_detected\"");
    }

    #[test]
    fn drift_event_wire_from_in_process() {
        let ev = DriftEvent::DeviceAdded(DeviceAddedV1 {
            device_id: "d1".into(),
            name: "core-sw".into(),
            host: "10.0.0.1".into(),
            device_type: "mikrotik".into(),
            timestamp_unix: 1,
        });
        let wire: DriftEventWire = (&ev).into();
        let json = serde_json::to_string(&wire).unwrap();
        assert!(json.contains("\"type\":\"device_added\""));
    }

    #[test]
    fn manifest_with_defaults_round_trips() {
        let json = r#"{
            "name": "scout-shield",
            "version": "0.1.0",
            "api_version": { "major": 1, "minor": 1 },
            "protocol": "http"
        }"#;
        let m: Manifest = serde_json::from_str(json).unwrap();
        assert_eq!(m.name, "scout-shield");
        assert!(matches!(m.protocol, ProtocolVariant::Http));
        assert!(m.subscribed_events.is_empty());
        assert!(m.exposed_routes.is_empty());
    }
}
