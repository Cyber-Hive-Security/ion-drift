//! Event dispatcher — fans Drift's internal events out to registered
//! external modules via HMAC-signed POSTs.
//!
//! # Wire contract
//!
//! Drift POSTs a JSON-serialized [`EventEnvelope`] to
//! `<module_url>/events` with two headers:
//!
//! - `Content-Type: application/json`
//! - `X-IonDrift-Signature: t=<timestamp>,v1=<hex_hmac_sha256>`
//!
//! The signature covers `<timestamp_str>.<body_bytes>` using the
//! module's per-registration shared secret (HMAC-SHA256). Receivers
//! should reject envelopes whose `t=` is further than 5 minutes from
//! their wall clock, and must compare the signature in constant time.
//! (This is the same scheme Stripe uses for webhooks.)
//!
//! # Delivery semantics
//!
//! - Per-module, per-event delivery is fire-and-forget from the main
//!   event loop: each delivery runs on its own tokio task so one slow
//!   module can't backpressure another.
//! - Failed deliveries retry on the configured backoff schedule. Once
//!   `circuit_break_after` consecutive failures accumulate, the
//!   dispatcher stops trying that module until
//!   `circuit_retest_after` has elapsed.
//! - The store is consulted per event (`store.list()` + the subscribed
//!   manifest), so enable/disable and registration changes take effect
//!   on the next event with no cache invalidation needed.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use ion_drift_module_api::{
    ApiVersion, DriftEvent, DriftEventWire, EventEnvelope, EventKind,
};
use secrecy::ExposeSecret;
use serde::Serialize;
use sha2::Sha256;
use tokio::sync::RwLock;
use tracing::{info, warn};

use super::store::{ModuleRegistryStore, RegisteredModule};

type HmacSha256 = Hmac<Sha256>;

/// Header Drift sets on every outbound event POST.
pub const SIGNATURE_HEADER: &str = "X-IonDrift-Signature";

/// Tunables for the dispatcher.
#[derive(Clone)]
pub struct DispatcherConfig {
    pub request_timeout: Duration,
    /// Delays between retry attempts. `vec![Duration::ZERO, d1, d2]`
    /// means three total attempts: immediate, then after `d1`, then
    /// after `d2`. An empty vec means one attempt with no retry.
    pub retry_backoffs: Vec<Duration>,
    /// After this many consecutive failures, the circuit opens.
    pub circuit_break_after: u32,
    /// Time to wait before allowing a probe attempt on an open circuit.
    pub circuit_retest_after: Duration,
}

impl Default for DispatcherConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(5),
            retry_backoffs: vec![
                Duration::ZERO,
                Duration::from_secs(5),
                Duration::from_secs(30),
            ],
            circuit_break_after: 10,
            circuit_retest_after: Duration::from_secs(60),
        }
    }
}

/// Per-module running delivery stats. Exposed via a future admin API.
#[derive(Clone, Debug, Default, Serialize)]
pub struct DeliveryStats {
    pub success_count: u64,
    pub failure_count: u64,
    pub consecutive_failures: u32,
    pub last_attempt_at: Option<i64>,
    pub last_success_at: Option<i64>,
    pub last_error: Option<String>,
    pub circuit_open: bool,
    pub circuit_opened_at: Option<i64>,
}

pub struct EventDispatcher {
    store: Arc<ModuleRegistryStore>,
    http: reqwest::Client,
    stats: RwLock<HashMap<String, DeliveryStats>>,
    config: DispatcherConfig,
}

impl EventDispatcher {
    pub fn new(
        store: Arc<ModuleRegistryStore>,
        http: reqwest::Client,
        config: DispatcherConfig,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            http,
            stats: RwLock::new(HashMap::new()),
            config,
        })
    }

    /// Dispatch a single event to every enabled module that subscribes
    /// to its kind. Per-module delivery runs on a spawned task.
    pub async fn dispatch(self: &Arc<Self>, event: &DriftEvent) {
        let kind = EventKind::of(event);
        let wire = DriftEventWire::from(event);

        let modules = match self.store.list().await {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, "dispatcher could not load module list; dropping event");
                return;
            }
        };

        for module in modules {
            if !module.enabled {
                continue;
            }
            if !module.manifest.subscribed_events.contains(&kind) {
                continue;
            }
            if self.is_circuit_open(&module.name).await {
                continue;
            }

            let secret = match self.store.get_shared_secret(&module.name).await {
                Ok(Some(s)) => s.expose_secret().to_string(),
                Ok(None) => {
                    warn!(module = %module.name, "no shared secret; skipping");
                    continue;
                }
                Err(e) => {
                    warn!(module = %module.name, error = %e, "shared secret lookup failed");
                    continue;
                }
            };

            let envelope = EventEnvelope {
                api_version: ApiVersion::CURRENT,
                event_id: uuid::Uuid::new_v4().to_string(),
                timestamp_unix: now_unix(),
                nonce: random_nonce_hex(),
                kind,
                event: wire.clone(),
            };

            let self_cloned = Arc::clone(self);
            tokio::spawn(async move {
                self_cloned.deliver(&module, envelope, secret).await;
            });
        }
    }

    /// Snapshot current stats. Keyed by module name.
    pub async fn stats_snapshot(&self) -> HashMap<String, DeliveryStats> {
        self.stats.read().await.clone()
    }

    /// Inner retry loop for a single module delivery. Public for tests.
    pub async fn deliver(
        self: &Arc<Self>,
        module: &RegisteredModule,
        envelope: EventEnvelope,
        secret: String,
    ) {
        let body = match serde_json::to_vec(&envelope) {
            Ok(b) => b,
            Err(e) => {
                warn!(module = %module.name, error = %e, "envelope serialize failed");
                return;
            }
        };

        let attempts = self.config.retry_backoffs.len().max(1);
        for attempt in 0..attempts {
            if attempt > 0 {
                if let Some(delay) = self.config.retry_backoffs.get(attempt) {
                    if !delay.is_zero() {
                        tokio::time::sleep(*delay).await;
                    }
                }
            }

            match self
                .deliver_once(&module.url, &body, envelope.timestamp_unix, &secret)
                .await
            {
                Ok(()) => {
                    self.record_success(&module.name).await;
                    return;
                }
                Err(e) => {
                    let last = attempt + 1 == attempts;
                    self.record_failure(&module.name, &e).await;
                    if last {
                        warn!(module = %module.name, error = %e, attempts, "delivery failed after retries");
                    }
                }
            }
        }
    }

    async fn deliver_once(
        &self,
        module_url: &str,
        body: &[u8],
        timestamp: i64,
        secret: &str,
    ) -> Result<(), String> {
        let sig = sign_bytes(secret, timestamp, body);
        let url = format!("{}/events", module_url.trim_end_matches('/'));
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .header(SIGNATURE_HEADER, format!("t={timestamp},v1={sig}"))
            .body(body.to_vec())
            .send()
            .await
            .map_err(|e| format!("http: {e}"))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("status {}", resp.status()))
        }
    }

    async fn is_circuit_open(&self, module_name: &str) -> bool {
        let stats = self.stats.read().await;
        let Some(s) = stats.get(module_name) else {
            return false;
        };
        if !s.circuit_open {
            return false;
        }
        let Some(opened) = s.circuit_opened_at else {
            return false;
        };
        let retest = self.config.circuit_retest_after.as_secs() as i64;
        (now_unix() - opened) < retest
    }

    async fn record_success(&self, module_name: &str) {
        let mut stats = self.stats.write().await;
        let s = stats.entry(module_name.to_string()).or_default();
        let now = now_unix();
        s.success_count += 1;
        s.consecutive_failures = 0;
        s.last_attempt_at = Some(now);
        s.last_success_at = Some(now);
        s.last_error = None;
        s.circuit_open = false;
        s.circuit_opened_at = None;
    }

    async fn record_failure(&self, module_name: &str, err: &str) {
        let mut stats = self.stats.write().await;
        let s = stats.entry(module_name.to_string()).or_default();
        s.failure_count += 1;
        s.consecutive_failures += 1;
        s.last_attempt_at = Some(now_unix());
        s.last_error = Some(err.to_string());
        if s.consecutive_failures >= self.config.circuit_break_after && !s.circuit_open {
            s.circuit_open = true;
            s.circuit_opened_at = Some(now_unix());
            warn!(
                module = %module_name,
                consecutive = s.consecutive_failures,
                "dispatcher circuit opened"
            );
        }
    }
}

/// Stripe-style HMAC-SHA256 over `<timestamp>.<body>`. Returns hex.
pub fn sign_bytes(secret: &str, timestamp: i64, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("hmac can take any key length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn random_nonce_hex() -> String {
    use rand::rngs::OsRng;
    use rand::TryRngCore;
    let mut bytes = [0u8; 16];
    // If the OS RNG fails, fall back to a hash of the timestamp so we
    // never panic here. An attacker that can make OsRng fail already
    // has the host; weak nonce isn't the concern.
    if OsRng.try_fill_bytes(&mut bytes).is_err() {
        let t = now_unix();
        bytes[..8].copy_from_slice(&t.to_le_bytes());
    }
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::{Aes256Gcm, Key};
    use axum::{
        extract::State,
        http::{HeaderMap, StatusCode},
        routing::post,
        Router,
    };
    use ion_drift_module_api::{
        AnomalyDetectedV1, Manifest, ProtocolVariant, RouteDescriptor,
    };
    use std::sync::atomic::{AtomicU32, Ordering};
    use tempfile::NamedTempFile;
    use tokio::sync::Mutex;

    use super::super::store::NewModuleRegistration;

    fn test_kek() -> Key<Aes256Gcm> {
        Key::<Aes256Gcm>::from_slice(&[11u8; 32]).to_owned()
    }

    fn manifest_subscribed(name: &str, subs: Vec<EventKind>) -> Manifest {
        Manifest {
            name: name.into(),
            version: "0.1.0".into(),
            api_version: ApiVersion::CURRENT,
            protocol: ProtocolVariant::Http,
            description: None,
            subscribed_events: subs,
            exposed_routes: vec![RouteDescriptor {
                path: "/watchlist".into(),
                method: "GET".into(),
                description: None,
            }],
        }
    }

    fn sample_event() -> DriftEvent {
        DriftEvent::AnomalyDetected(AnomalyDetectedV1 {
            anomaly_id: 1,
            device_mac: "aa:bb:cc:dd:ee:ff".into(),
            severity: "high".into(),
            anomaly_type: "x".into(),
            vlan: None,
            timestamp_unix: 1_700_000_000,
        })
    }

    const SECRET: &str = "shared-secret-at-least-32-chars-long-!!";

    #[derive(Default)]
    struct MockState {
        received: Mutex<Vec<ReceivedPost>>,
        fail_count: AtomicU32,
        behavior: std::sync::Mutex<MockBehavior>,
    }

    #[derive(Default, Clone, Copy)]
    enum MockBehavior {
        #[default]
        AlwaysOk,
        AlwaysFail,
        FailNThenOk(u32),
    }

    struct ReceivedPost {
        sig_header: String,
        body: Vec<u8>,
    }

    async fn events_handler(
        State(state): State<Arc<MockState>>,
        headers: HeaderMap,
        body: axum::body::Bytes,
    ) -> StatusCode {
        let sig = headers
            .get(SIGNATURE_HEADER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        state.received.lock().await.push(ReceivedPost {
            sig_header: sig,
            body: body.to_vec(),
        });

        let behavior = *state.behavior.lock().unwrap();
        let resp = match behavior {
            MockBehavior::AlwaysOk => StatusCode::OK,
            MockBehavior::AlwaysFail => {
                state.fail_count.fetch_add(1, Ordering::SeqCst);
                StatusCode::INTERNAL_SERVER_ERROR
            }
            MockBehavior::FailNThenOk(n) => {
                let c = state.fail_count.fetch_add(1, Ordering::SeqCst);
                if c < n {
                    StatusCode::INTERNAL_SERVER_ERROR
                } else {
                    StatusCode::OK
                }
            }
        };
        resp
    }

    async fn spawn_mock(behavior: MockBehavior) -> (String, Arc<MockState>) {
        let state = Arc::new(MockState::default());
        *state.behavior.lock().unwrap() = behavior;
        let app = Router::new()
            .route("/events", post(events_handler))
            .with_state(Arc::clone(&state));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), state)
    }

    fn fast_config() -> DispatcherConfig {
        DispatcherConfig {
            request_timeout: Duration::from_secs(2),
            retry_backoffs: vec![
                Duration::ZERO,
                Duration::from_millis(20),
                Duration::from_millis(20),
            ],
            circuit_break_after: 3,
            circuit_retest_after: Duration::from_secs(60),
        }
    }

    async fn setup(subs: Vec<EventKind>, enabled: bool, behavior: MockBehavior)
        -> (Arc<EventDispatcher>, Arc<MockState>, NamedTempFile)
    {
        let tmp = NamedTempFile::new().unwrap();
        let store = Arc::new(ModuleRegistryStore::new(tmp.path(), test_kek()).unwrap());
        let (base, state) = spawn_mock(behavior).await;
        let m = manifest_subscribed("m", subs);
        store
            .register(NewModuleRegistration {
                name: "m",
                url: &base,
                manifest: &m,
                shared_secret: SECRET,
                api_token: "api-token-that-is-longer-than-32-ch",
            })
            .await
            .unwrap();
        if !enabled {
            store.set_enabled("m", false).await.unwrap();
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let disp = EventDispatcher::new(store, http, fast_config());
        (disp, state, tmp)
    }

    #[test]
    fn sign_bytes_is_deterministic_and_covers_timestamp() {
        let a = sign_bytes("k", 100, b"abc");
        let b = sign_bytes("k", 100, b"abc");
        assert_eq!(a, b);
        let c = sign_bytes("k", 101, b"abc");
        assert_ne!(a, c);
        let d = sign_bytes("kk", 100, b"abc");
        assert_ne!(a, d);
    }

    async fn wait_for<F: Fn(&Arc<MockState>) -> bool>(state: &Arc<MockState>, f: F) {
        for _ in 0..50 {
            if f(state) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn dispatches_to_subscribed_enabled_module() {
        let (disp, state, _tmp) =
            setup(vec![EventKind::AnomalyDetected], true, MockBehavior::AlwaysOk).await;
        disp.dispatch(&sample_event()).await;
        wait_for(&state, |s| {
            s.received.try_lock().map(|g| !g.is_empty()).unwrap_or(false)
        })
        .await;
        let received = state.received.lock().await;
        assert_eq!(received.len(), 1);
        // Signature header present and in the expected format.
        assert!(received[0].sig_header.starts_with("t="));
        assert!(received[0].sig_header.contains(",v1="));
        // Body is a parseable envelope.
        let env: EventEnvelope = serde_json::from_slice(&received[0].body).unwrap();
        assert_eq!(env.kind, EventKind::AnomalyDetected);
    }

    #[tokio::test]
    async fn skips_disabled_module() {
        let (disp, state, _tmp) =
            setup(vec![EventKind::AnomalyDetected], false, MockBehavior::AlwaysOk).await;
        disp.dispatch(&sample_event()).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(state.received.lock().await.is_empty());
    }

    #[tokio::test]
    async fn skips_unsubscribed_event() {
        let (disp, state, _tmp) = setup(
            vec![EventKind::DeviceAdded],
            true,
            MockBehavior::AlwaysOk,
        )
        .await;
        disp.dispatch(&sample_event()).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(state.received.lock().await.is_empty());
    }

    #[tokio::test]
    async fn retries_then_succeeds() {
        let (disp, state, _tmp) = setup(
            vec![EventKind::AnomalyDetected],
            true,
            MockBehavior::FailNThenOk(2),
        )
        .await;
        disp.dispatch(&sample_event()).await;
        wait_for(&state, |s| {
            s.received.try_lock().map(|g| g.len() >= 3).unwrap_or(false)
        })
        .await;
        let stats = disp.stats_snapshot().await;
        let m = stats.get("m").unwrap();
        assert_eq!(m.success_count, 1);
        assert_eq!(m.failure_count, 2);
        assert_eq!(m.consecutive_failures, 0);
        assert!(!m.circuit_open);
    }

    #[tokio::test]
    async fn circuit_opens_after_repeated_failures() {
        let (disp, state, _tmp) = setup(
            vec![EventKind::AnomalyDetected],
            true,
            MockBehavior::AlwaysFail,
        )
        .await;
        // Three attempts per dispatch × dispatch twice => >= 3 consecutive failures.
        disp.dispatch(&sample_event()).await;
        wait_for(&state, |s| {
            s.received.try_lock().map(|g| g.len() >= 3).unwrap_or(false)
        })
        .await;
        let stats = disp.stats_snapshot().await;
        let m = stats.get("m").unwrap();
        assert!(m.circuit_open, "expected circuit open, stats: {m:?}");
        assert!(m.consecutive_failures >= 3);
    }

    #[test]
    fn signature_verifies_on_receiver_side() {
        // Simulates what scout-shield will do: parse header, recompute,
        // constant-time compare.
        let timestamp = 1_700_000_000_i64;
        let body = br#"{"kind":"anomaly_detected"}"#;
        let sig = sign_bytes(SECRET, timestamp, body);
        let header = format!("t={timestamp},v1={sig}");
        let parts: HashMap<&str, &str> = header
            .split(',')
            .filter_map(|p| p.split_once('='))
            .collect();
        let got_t: i64 = parts["t"].parse().unwrap();
        let got_sig = parts["v1"];
        let expected = sign_bytes(SECRET, got_t, body);
        // constant_time_eq not pulled in for tests; a plain eq is fine
        // here since we just want to prove the round-trip.
        assert_eq!(got_sig, expected);
    }
}
