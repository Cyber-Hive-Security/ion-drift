//! Per-device API queue registry.
//!
//! Each RouterOS managed switch gets its own `RouterQueue` with an independent
//! worker, circuit breaker, and metrics. This prevents session accumulation on
//! switches with limited API session tables (e.g., CRS326).

use std::collections::HashMap;
use std::time::Duration;

use mikrotik_core::MikrotikClient;

use crate::router_queue::RouterQueue;

/// Registry of per-device RouterQueue instances.
pub struct DeviceQueueRegistry {
    queues: HashMap<String, RouterQueue>,
    /// Default gap between batches for new queues.
    default_gap: Duration,
}

impl DeviceQueueRegistry {
    pub fn new(default_gap: Duration) -> Self {
        Self {
            queues: HashMap::new(),
            default_gap,
        }
    }

    /// Get or create a RouterQueue for a RouterOS device.
    /// Creates a new queue + worker on first access.
    pub fn get_or_create(&mut self, device_id: &str, client: &MikrotikClient) -> RouterQueue {
        self.queues
            .entry(device_id.to_string())
            .or_insert_with(|| {
                tracing::info!(device = %device_id, "creating per-device API queue");
                RouterQueue::new(client.clone(), self.default_gap)
            })
            .clone()
    }

    /// Get an existing queue.
    pub fn get(&self, device_id: &str) -> Option<RouterQueue> {
        self.queues.get(device_id).cloned()
    }

    /// Remove a device's queue (on device removal/disable).
    /// The queue worker exits when all senders are dropped.
    pub fn remove(&mut self, device_id: &str) {
        if self.queues.remove(device_id).is_some() {
            tracing::info!(device = %device_id, "removed per-device API queue");
        }
    }
}
