//! Event bus — a thin wrapper around `tokio::sync::broadcast` that Drift
//! engines publish to and modules subscribe to via their [`EventHandle`].

use std::sync::Arc;

use ion_drift_module_api::{DriftEvent, EventHandle, EventKind};
use tokio::sync::broadcast;

/// The shared event bus. Drop-in replacement for a bare broadcast sender
/// that also tracks publication metrics for future metrics exposition.
#[derive(Clone)]
pub struct EventBus {
    inner: Arc<EventBusInner>,
}

struct EventBusInner {
    sender: broadcast::Sender<DriftEvent>,
}

impl EventBus {
    /// Construct a new bus with the given capacity. Capacity is the number
    /// of in-flight events a slow subscriber can buffer before they are
    /// dropped (and the subscriber sees [`ion_drift_module_api::EventError::Lagged`]).
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            inner: Arc::new(EventBusInner { sender }),
        }
    }

    /// Publish an event to all current subscribers.
    ///
    /// If no subscribers are listening, the broadcast is cheap: a single
    /// atomic operation with no allocation. This is the zero-overhead path
    /// for stock OSS builds that have no modules loaded.
    pub fn publish(&self, event: DriftEvent) {
        // We ignore the `Err(SendError(..))` case because it only means
        // "no receivers" — events are advisory and not retained.
        let _ = self.inner.sender.send(event);
    }

    /// Create an [`EventHandle`] for a module, scoped to its declared
    /// publish/subscribe set.
    pub fn handle_for(
        &self,
        declared_publish: Vec<EventKind>,
        declared_subscribe: Vec<EventKind>,
    ) -> EventHandle {
        EventHandle::new(
            self.inner.sender.clone(),
            declared_publish,
            declared_subscribe,
        )
    }

    /// Number of active subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.inner.sender.receiver_count()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(1024)
    }
}
