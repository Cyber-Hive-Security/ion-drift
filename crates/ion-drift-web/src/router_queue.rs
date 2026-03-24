//! Centralized request queue for router API access.
//!
//! Serializes all background poller requests through a single worker to prevent
//! concurrent TLS sessions from overwhelming low-end routers. Features:
//!
//! - **Priority tiers:** High (alerts, connections) → Normal (metrics, traffic) → Low (topology, discovery)
//! - **Batch submission:** Pollers submit multiple requests as a single batch; executed sequentially
//! - **Deduplication:** Each poller gets at most one pending batch; newest replaces oldest
//! - **Adaptive gap:** Inter-batch delay adjusts based on router response latency and error rate
//! - **Circuit breaker:** Pauses queue after repeated failures to let the router recover
//! - **Starvation detection:** Warns when a poller hasn't executed in too long
//!
//! Frontend API requests bypass the queue entirely — only background pollers use it.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot, Mutex};
use serde_json::Value;

use mikrotik_core::MikrotikClient;
use mikrotik_core::MikrotikError;

// ── Types ────────────────────────────────────────────────────────

/// Priority tier for queue scheduling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    High = 0,   // alerts, connection tracking
    Normal = 1, // metrics, traffic, behavior
    Low = 2,    // topology, discovery, policy sync
}

/// A single API request within a batch.
#[derive(Debug, Clone)]
pub struct QueuedRequest {
    pub path: String,
}

impl QueuedRequest {
    pub fn get(path: &str) -> Self {
        Self { path: path.to_string() }
    }
}

/// A batch of requests from a single poller.
struct QueuedBatch {
    poller_id: String,
    priority: Priority,
    requests: Vec<QueuedRequest>,
    response_tx: oneshot::Sender<Vec<Result<Value, MikrotikError>>>,
    submitted_at: Instant,
}

/// Queue health metrics, accessible for logging and future API exposure.
#[derive(Debug, Clone, Default)]
pub struct QueueMetrics {
    pub queue_depth: usize,
    pub total_batches_executed: u64,
    pub total_batches_dropped: u64,
    pub total_requests_executed: u64,
    pub total_errors: u64,
    pub avg_batch_latency_ms: f64,
    pub current_gap_ms: u64,
    pub circuit_open: bool,
    pub poller_last_run: HashMap<String, Instant>,
}

/// Shared metrics state.
type SharedMetrics = Arc<Mutex<QueueMetrics>>;

// ── Queue ────────────────────────────────────────────────────────

/// Handle for submitting batches to the queue.
#[derive(Clone)]
pub struct RouterQueue {
    tx: mpsc::Sender<QueuedBatch>,
    metrics: SharedMetrics,
}

impl RouterQueue {
    /// Create a new queue with a worker that drains batches against the given client.
    pub fn new(client: MikrotikClient, base_gap: Duration) -> Self {
        let (tx, rx) = mpsc::channel::<QueuedBatch>(64);
        let metrics = Arc::new(Mutex::new(QueueMetrics {
            current_gap_ms: base_gap.as_millis() as u64,
            ..Default::default()
        }));

        let worker_metrics = metrics.clone();
        tokio::spawn(queue_worker(rx, client, base_gap, worker_metrics));

        Self { tx, metrics }
    }

    /// Submit a batch of requests. Returns responses in order.
    /// If this poller already has a pending batch, the old one is dropped (superseded).
    pub async fn submit(
        &self,
        poller_id: &str,
        priority: Priority,
        requests: Vec<QueuedRequest>,
    ) -> Result<Vec<Result<Value, MikrotikError>>, QueueError> {
        let (response_tx, response_rx) = oneshot::channel();
        let batch = QueuedBatch {
            poller_id: poller_id.to_string(),
            priority,
            requests,
            response_tx,
            submitted_at: Instant::now(),
        };

        self.tx.send(batch).await.map_err(|_| QueueError::QueueClosed)?;

        response_rx.await.map_err(|_| QueueError::WorkerDropped)
    }

    /// Submit a single GET request. Convenience wrapper.
    #[allow(dead_code)]
    pub async fn get(
        &self,
        poller_id: &str,
        priority: Priority,
        path: &str,
    ) -> Result<Result<Value, MikrotikError>, QueueError> {
        let results = self.submit(poller_id, priority, vec![QueuedRequest::get(path)]).await?;
        Ok(results.into_iter().next().unwrap_or(Err(MikrotikError::Config("empty response".into()))))
    }

    /// Submit a single GET request and deserialize the response.
    pub async fn get_typed<T: serde::de::DeserializeOwned>(
        &self,
        poller_id: &str,
        priority: Priority,
        path: &str,
    ) -> Result<T, String> {
        let result = self.get(poller_id, priority, path).await
            .map_err(|e| format!("queue error: {e}"))?;
        let value = result.map_err(|e| format!("{e}"))?;
        serde_json::from_value(value).map_err(|e| format!("deserialize {path}: {e}"))
    }

    /// Submit a batch and deserialize each response into the same type.
    /// Returns results in the same order as the requests.
    pub async fn submit_typed<T: serde::de::DeserializeOwned>(
        &self,
        poller_id: &str,
        priority: Priority,
        requests: Vec<QueuedRequest>,
    ) -> Result<Vec<Result<T, String>>, String> {
        let results = self.submit(poller_id, priority, requests).await
            .map_err(|e| format!("queue error: {e}"))?;
        Ok(results.into_iter().map(|r| {
            let value = r.map_err(|e| format!("{e}"))?;
            serde_json::from_value(value).map_err(|e| format!("deserialize: {e}"))
        }).collect())
    }

    /// Get current queue metrics.
    pub async fn metrics(&self) -> QueueMetrics {
        self.metrics.lock().await.clone()
    }
}

#[derive(Debug)]
pub enum QueueError {
    QueueClosed,
    WorkerDropped,
    Superseded,
}

impl std::fmt::Display for QueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QueueClosed => write!(f, "router queue closed"),
            Self::WorkerDropped => write!(f, "queue worker dropped response"),
            Self::Superseded => write!(f, "batch superseded by newer submission"),
        }
    }
}

// ── Worker ───────────────────────────────────────────────────────

/// Circuit breaker state.
struct CircuitBreaker {
    failure_count: u32,
    last_failure: Option<Instant>,
    open_until: Option<Instant>,
}

impl CircuitBreaker {
    fn new() -> Self {
        Self {
            failure_count: 0,
            last_failure: None,
            open_until: None,
        }
    }

    fn record_success(&mut self) {
        self.failure_count = 0;
        self.open_until = None;
    }

    fn record_failure(&mut self) {
        self.failure_count += 1;
        self.last_failure = Some(Instant::now());

        // Open circuit after 5 consecutive failures: pause for escalating duration
        if self.failure_count >= 5 {
            let pause = match self.failure_count {
                5..=9 => Duration::from_secs(10),
                10..=19 => Duration::from_secs(30),
                _ => Duration::from_secs(60),
            };
            self.open_until = Some(Instant::now() + pause);
            tracing::warn!(
                failures = self.failure_count,
                pause_secs = pause.as_secs(),
                "circuit breaker open — pausing router requests"
            );
        }
    }

    fn is_open(&self) -> bool {
        if let Some(until) = self.open_until {
            if Instant::now() < until {
                return true;
            }
            // Circuit half-open — will close on next success
        }
        false
    }
}

/// Adaptive gap calculator.
struct AdaptiveGap {
    _base: Duration,
    current: Duration,
    min: Duration,
    max: Duration,
    recent_latencies: Vec<f64>,
    recent_errors: u32,
    recent_successes: u32,
}

impl AdaptiveGap {
    fn new(base: Duration) -> Self {
        Self {
            _base: base,
            current: base,
            min: Duration::from_millis(500),
            max: Duration::from_secs(30),
            recent_latencies: Vec::new(),
            recent_errors: 0,
            recent_successes: 0,
        }
    }

    fn record_latency(&mut self, latency: Duration) {
        self.recent_latencies.push(latency.as_millis() as f64);
        if self.recent_latencies.len() > 20 {
            self.recent_latencies.remove(0);
        }
    }

    fn record_success(&mut self) {
        self.recent_successes += 1;
        self.adjust();
    }

    fn record_error(&mut self) {
        self.recent_errors += 1;
        self.adjust();
    }

    fn adjust(&mut self) {
        // Every 10 events, recalculate
        let total = self.recent_successes + self.recent_errors;
        if total < 10 {
            return;
        }

        let error_rate = self.recent_errors as f64 / total as f64;
        let avg_latency = if self.recent_latencies.is_empty() {
            0.0
        } else {
            self.recent_latencies.iter().sum::<f64>() / self.recent_latencies.len() as f64
        };

        let new_gap = if error_rate > 0.3 {
            // High error rate — back off significantly
            (self.current.as_millis() as f64 * 1.5) as u64
        } else if error_rate > 0.1 || avg_latency > 2000.0 {
            // Moderate issues — increase slightly
            (self.current.as_millis() as f64 * 1.2) as u64
        } else if error_rate < 0.05 && avg_latency < 500.0 {
            // Healthy — decrease toward base
            (self.current.as_millis() as f64 * 0.9) as u64
        } else {
            self.current.as_millis() as u64
        };

        self.current = Duration::from_millis(new_gap).clamp(self.min, self.max);

        // Reset counters
        self.recent_errors = 0;
        self.recent_successes = 0;
    }

    fn gap(&self) -> Duration {
        self.current
    }
}

/// The queue worker loop. Drains batches by priority, deduplicates, and executes.
async fn queue_worker(
    mut rx: mpsc::Receiver<QueuedBatch>,
    client: MikrotikClient,
    base_gap: Duration,
    metrics: SharedMetrics,
) {
    let mut pending: HashMap<String, QueuedBatch> = HashMap::new();
    let mut circuit = CircuitBreaker::new();
    let mut adaptive = AdaptiveGap::new(base_gap);
    let mut starvation_tracker: HashMap<String, Instant> = HashMap::new();

    // Starvation threshold: warn if a poller hasn't run in 5x its expected interval
    let starvation_threshold = Duration::from_secs(300);

    tracing::info!(
        gap_ms = base_gap.as_millis() as u64,
        "router request queue worker started"
    );

    loop {
        // Drain all available batches into pending map (dedup by poller_id)
        loop {
            match rx.try_recv() {
                Ok(batch) => {
                    let poller_id = batch.poller_id.clone();
                    // If an older batch from the same poller exists, drop it
                    if let Some(old) = pending.remove(&poller_id) {
                        // Notify the old submitter it was superseded
                        let _ = old.response_tx.send(vec![Err(MikrotikError::Config(
                            "superseded by newer batch".into(),
                        ))]);
                        let mut m = metrics.lock().await;
                        m.total_batches_dropped += 1;
                        tracing::debug!(poller = %poller_id, "dropped stale batch (superseded)");
                    }
                    pending.insert(poller_id, batch);
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    tracing::info!("router queue channel closed, worker exiting");
                    return;
                }
            }
        }

        // If nothing pending, wait for the next batch
        if pending.is_empty() {
            match rx.recv().await {
                Some(batch) => {
                    pending.insert(batch.poller_id.clone(), batch);
                }
                None => {
                    tracing::info!("router queue channel closed, worker exiting");
                    return;
                }
            }
        }

        // Check circuit breaker
        if circuit.is_open() {
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        // Pick the highest-priority batch
        let next_id = pending
            .iter()
            .min_by_key(|(_, b)| (b.priority, b.submitted_at))
            .map(|(id, _)| id.clone());

        let Some(next_id) = next_id else {
            continue;
        };
        let batch = pending.remove(&next_id).unwrap();

        // Update metrics
        {
            let mut m = metrics.lock().await;
            m.queue_depth = pending.len();
        }

        // Execute the batch
        let batch_start = Instant::now();
        let mut results = Vec::with_capacity(batch.requests.len());
        let mut had_error = false;

        for req in &batch.requests {
            let req_start = Instant::now();
            let result = tokio::time::timeout(
                Duration::from_secs(10),
                client.get::<Value>(&req.path),
            )
            .await;

            let result = match result {
                Ok(r) => r,
                Err(_) => Err(MikrotikError::Config(format!(
                    "request timeout: {}",
                    req.path
                ))),
            };

            let latency = req_start.elapsed();
            adaptive.record_latency(latency);

            if result.is_err() {
                had_error = true;
                adaptive.record_error();
            } else {
                adaptive.record_success();
            }

            results.push(result);
        }

        let batch_latency = batch_start.elapsed();

        // Update circuit breaker
        if had_error {
            circuit.record_failure();
        } else {
            circuit.record_success();
        }

        // Update metrics
        {
            let mut m = metrics.lock().await;
            m.total_batches_executed += 1;
            m.total_requests_executed += batch.requests.len() as u64;
            if had_error {
                m.total_errors += results.iter().filter(|r| r.is_err()).count() as u64;
            }
            // Exponential moving average for latency
            let latency_ms = batch_latency.as_millis() as f64;
            m.avg_batch_latency_ms = m.avg_batch_latency_ms * 0.8 + latency_ms * 0.2;
            m.current_gap_ms = adaptive.gap().as_millis() as u64;
            m.circuit_open = circuit.is_open();
            m.poller_last_run.insert(batch.poller_id.clone(), Instant::now());
        }

        // Starvation detection
        starvation_tracker.insert(batch.poller_id.clone(), Instant::now());
        for (poller_id, last_run) in &starvation_tracker {
            if last_run.elapsed() > starvation_threshold {
                tracing::warn!(
                    poller = %poller_id,
                    elapsed_secs = last_run.elapsed().as_secs(),
                    "poller starvation detected — hasn't executed in over {}s",
                    starvation_threshold.as_secs()
                );
            }
        }

        // Send results back to the poller
        let _ = batch.response_tx.send(results);

        // Inter-batch gap (adaptive)
        let gap = adaptive.gap();
        tracing::trace!(
            gap_ms = gap.as_millis() as u64,
            queue_remaining = pending.len(),
            "queue batch complete, sleeping"
        );
        tokio::time::sleep(gap).await;
    }
}
