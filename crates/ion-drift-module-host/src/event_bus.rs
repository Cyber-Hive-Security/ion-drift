//! Event bus — per-`EventKind` broadcast channels.
//!
//! Each [`EventKind`] gets its own `tokio::sync::broadcast` channel. Drift
//! engines publish to the bus via [`EventBus::publish`], which routes to the
//! sender for the event's kind. Modules subscribe via per-kind receivers
//! merged into a single mpsc by an internal forwarder task — they see one
//! `EventReceiver::recv()` API and never need to know about per-kind channels.
//!
//! ## Why per-kind channels
//!
//! A single bus channel with client-side filtering allows a high-rate topic
//! (e.g., `ConnectionStateChanged`) to advance the channel head past a
//! low-rate topic (e.g., `AnomalyDetected`), causing low-rate subscribers to
//! see `RecvError::Lagged` and miss events. Per-kind channels eliminate
//! this noisy-neighbor risk: each kind has its own buffer, and subscribers
//! only ever lag on the specific kinds they care about.

use std::collections::HashMap;
use std::sync::Arc;

use ion_drift_module_api::context::{EventHandleSenders, EventHandleShared};
use ion_drift_module_api::{DriftEvent, EventHandle, EventKind};
use tokio::sync::broadcast;

/// The shared event bus, holding one `broadcast::Sender` per `EventKind`.
#[derive(Clone)]
pub struct EventBus {
    inner: Arc<EventBusInner>,
}

struct EventBusInner {
    senders: HashMap<EventKind, broadcast::Sender<DriftEvent>>,
    capacity: usize,
}

impl EventBus {
    /// Construct a new bus with a per-kind channel capacity. All known
    /// `EventKind` values are pre-allocated their own channel.
    pub fn new(capacity: usize) -> Self {
        let mut senders = HashMap::new();
        for kind in [
            EventKind::AnomalyDetected,
            EventKind::BehaviorBaselineUpdated,
            EventKind::InvestigationStarted,
            EventKind::InvestigationCompleted,
            EventKind::InfrastructureSnapshotUpdated,
            EventKind::DeviceAdded,
            EventKind::DeviceRemoved,
            EventKind::DeviceUnreachable,
            EventKind::SwitchTopologyChanged,
            EventKind::ConnectionStateChanged,
            EventKind::ModuleCustom,
        ] {
            let (sender, _) = broadcast::channel(capacity);
            senders.insert(kind, sender);
        }
        Self {
            inner: Arc::new(EventBusInner { senders, capacity }),
        }
    }

    /// Publish an event to the per-kind channel matching its variant.
    ///
    /// If no subscribers are listening on that kind, the broadcast is cheap:
    /// a single atomic operation with no allocation. This is the zero-overhead
    /// path for stock OSS builds with no modules loaded.
    pub fn publish(&self, event: DriftEvent) {
        let kind = EventKind::of(&event);
        if let Some(sender) = self.inner.senders.get(&kind) {
            let _ = sender.send(event);
        }
    }

    /// Create an [`EventHandle`] for a module, scoped to its declared
    /// publish/subscribe sets. The module name is host-stamped onto every
    /// `ModuleCustom` event published through this handle.
    pub fn handle_for(
        &self,
        module_name: &'static str,
        declared_publish: Vec<EventKind>,
        declared_subscribe: Vec<EventKind>,
    ) -> EventHandle {
        let mut publish_senders: HashMap<EventKind, broadcast::Sender<DriftEvent>> =
            HashMap::new();
        for k in &declared_publish {
            if let Some(s) = self.inner.senders.get(k) {
                publish_senders.insert(*k, s.clone());
            }
        }
        let mut subscribe_senders: HashMap<EventKind, broadcast::Sender<DriftEvent>> =
            HashMap::new();
        for k in &declared_subscribe {
            if let Some(s) = self.inner.senders.get(k) {
                subscribe_senders.insert(*k, s.clone());
            }
        }

        let shared = EventHandleShared {
            module_name,
            declared_publish: Arc::new(declared_publish),
            declared_subscribe: Arc::new(declared_subscribe),
            senders: EventHandleSenders {
                publish: Arc::new(publish_senders),
                subscribe: Arc::new(subscribe_senders),
            },
        };

        EventHandle::from_shared(shared)
    }

    /// Total subscriber count across all per-kind channels (for diagnostics).
    pub fn subscriber_count(&self) -> usize {
        self.inner
            .senders
            .values()
            .map(|s| s.receiver_count())
            .sum()
    }

    /// Per-kind capacity (every channel uses this).
    pub fn capacity(&self) -> usize {
        self.inner.capacity
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ion_drift_module_api::{
        AnomalyDetectedV1, ConnectionStateChangedV1, DriftEvent, EventKind,
    };

    /// A high-rate publisher of `ConnectionStateChanged` events must NOT
    /// cause a low-rate `AnomalyDetected` subscriber to lag and miss its
    /// single rare event. This is the per-kind isolation guarantee.
    #[tokio::test]
    async fn high_rate_topic_does_not_lag_low_rate_subscriber() {
        // Use a small per-kind capacity so the high-rate channel would
        // definitely fill up if subscribers shared a single channel.
        let bus = EventBus::new(64);

        // Subscribe to ONLY AnomalyDetected — modeling a security-critical
        // module that does not care about per-connection chatter.
        let handle = bus.handle_for(
            "alpha",
            vec![],
            vec![EventKind::AnomalyDetected],
        );
        let mut rx = handle.subscribe();

        // Give the forwarder task a tick to install its broadcast subscription.
        tokio::task::yield_now().await;

        // Flood ConnectionStateChanged at 10x the channel capacity.
        for _ in 0..640 {
            bus.publish(DriftEvent::ConnectionStateChanged(
                ConnectionStateChangedV1 {
                    src_mac: None,
                    dst_ip: "1.2.3.4".into(),
                    dst_port: Some(443),
                    state: "established".into(),
                    timestamp_unix: 0,
                },
            ));
        }

        // Now publish ONE AnomalyDetected event.
        bus.publish(DriftEvent::AnomalyDetected(AnomalyDetectedV1 {
            anomaly_id: 42,
            device_mac: "aa:bb:cc:dd:ee:ff".into(),
            severity: "critical".into(),
            anomaly_type: "test".into(),
            vlan: Some(25),
            timestamp_unix: 100,
        }));

        // The low-rate subscriber must receive its event without being
        // starved by the high-rate ConnectionStateChanged firehose.
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            rx.recv(),
        )
        .await
        .expect("recv must not time out");

        match received {
            Ok(DriftEvent::AnomalyDetected(payload)) => {
                assert_eq!(payload.anomaly_id, 42);
            }
            other => panic!("expected AnomalyDetected, got {other:?}"),
        }
    }
}
