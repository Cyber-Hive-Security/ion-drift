//! In-memory ring buffer for real-time traffic samples.

use std::collections::VecDeque;
use std::sync::Arc;

use serde::Serialize;
use tokio::sync::Mutex;

/// A single traffic rate sample.
#[derive(Debug, Clone, Serialize)]
pub struct TrafficSample {
    pub timestamp: i64,
    pub rx_bps: f64,
    pub tx_bps: f64,
}

/// Ring buffer holding the last N traffic samples.
pub struct LiveTrafficBuffer {
    buf: Arc<Mutex<VecDeque<TrafficSample>>>,
    capacity: usize,
}

impl LiveTrafficBuffer {
    /// Create a new buffer with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            buf: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
            capacity,
        }
    }

    /// Push a sample, evicting the oldest if at capacity.
    pub async fn push(&self, sample: TrafficSample) {
        let mut buf = self.buf.lock().await;
        if buf.len() >= self.capacity {
            buf.pop_front();
        }
        buf.push_back(sample);
    }

    /// Clone the entire buffer contents.
    pub async fn snapshot(&self) -> Vec<TrafficSample> {
        let buf = self.buf.lock().await;
        buf.iter().cloned().collect()
    }
}
