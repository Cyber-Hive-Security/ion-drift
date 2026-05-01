//! Inbound publish endpoint — the Anticorruption Layer for modules
//! pushing events INTO Drift.
//!
//! `POST /api/v1/modules/{name}/events`
//!
//! This is the highest-trust-boundary HTTP surface in Drift: an external
//! module is sending us events, and we cannot trust anything in the
//! payload. The order of checks below is deliberately cheap-first so
//! unauthenticated/malformed traffic is rejected before we do crypto.
//!
//! 1. Body size limit — 1 MiB.
//! 2. Module lookup by name. 404 if unknown (same shape as auth failures
//!    so we don't leak whether a name exists).
//! 3. Header sanity. 401 if the signature header is missing/malformed.
//! 4. Timestamp window — reject if `|now - ts| > 300s`. 401.
//! 5. HMAC verify in constant time. 401.
//! 6. Body deserialize as `EventEnvelope`. 400.
//! 7. Nonce dedup against an in-memory TTL cache. 409.
//! 8. Authorization: envelope kind must appear in
//!    `manifest.declared_publish`. 403.
//! 9. Host-stamp the event source from the URL path; drop any payload
//!    `source` claim.
//! 10. Publish to the `EventBus`. 202.
//!
//! Error responses are intentionally opaque (`{"error":"rejected"}`) so
//! attackers can't fingerprint which check failed. The handler logs the
//! specific reason server-side for diagnostics.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, FromRef, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::post,
    Router,
};
use ion_drift_module_api::{DriftEvent, EventEnvelope, EventKind, FindingV1};
use ion_drift_module_host::EventBus;
use ion_drift_storage::FindingsStore;
use secrecy::ExposeSecret;
use serde_json::json;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use super::hmac::{
    parse_sig_header, verify_signature, DEFAULT_TIMESTAMP_SKEW_SECS, SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
};
use super::store::ModuleRegistryStore;
use crate::state::AppState;

/// Narrow subset of [`AppState`] the inbound endpoint actually uses.
///
/// Extracting this lets us wire HMAC + persistence into a tiny test
/// router without standing up the full `AppState`. In production,
/// [`FromRef<AppState>`] picks these fields out of the larger state.
#[derive(Clone)]
pub struct InboundState {
    pub event_bus: EventBus,
    pub module_registry_store: Option<Arc<ModuleRegistryStore>>,
    pub findings_store: Arc<FindingsStore>,
    pub nonce_cache: Arc<NonceCache>,
}

impl FromRef<AppState> for InboundState {
    fn from_ref(state: &AppState) -> Self {
        Self {
            event_bus: state.event_bus.clone(),
            module_registry_store: state.module_registry_store.clone(),
            findings_store: state.findings_store.clone(),
            nonce_cache: state.nonce_cache.clone(),
        }
    }
}

/// Maximum body size for an inbound publish, in bytes. Larger bodies
/// are rejected with 413 by the body-limit layer before any handler
/// code runs.
pub const MAX_BODY_BYTES: usize = 1_048_576; // 1 MiB

/// How long an envelope's nonce stays in the dedup cache. Comfortably
/// covers the timestamp window with margin so a delayed but in-window
/// retry is still detected as a duplicate.
pub const NONCE_TTL_SECS: u64 = 600;

/// In-memory `(module_name, nonce) → seen_at` set with TTL eviction.
///
/// Defense-in-depth against replay: even if an attacker captures a
/// valid envelope and replays it inside the 5-minute clock window, the
/// nonce was already recorded when the legit envelope arrived.
#[derive(Default)]
pub struct NonceCache {
    inner: Mutex<HashMap<(String, String), u64>>,
}

impl NonceCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a `(module, nonce)` pair and report whether it was already
    /// present. Side-effects an opportunistic GC of expired entries on
    /// each call so the map cannot grow without bound.
    pub async fn record(&self, module: &str, nonce: &str, now_unix: u64) -> bool {
        let mut guard = self.inner.lock().await;
        guard.retain(|_, t| now_unix.saturating_sub(*t) < NONCE_TTL_SECS);
        let key = (module.to_string(), nonce.to_string());
        match guard.insert(key, now_unix) {
            Some(_) => true,  // already present
            None => false,
        }
    }

    /// Number of cached entries (for tests/diagnostics).
    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }
}

/// Build the unauthenticated inbound router. The body-size limit and
/// route are baked in here; CSRF/session-auth layers from the main
/// `/api` tree are intentionally **not** applied — modules don't have
/// user sessions, and the request shape is not browser-form-like.
pub fn inbound_router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/modules/{name}/events", post(handle_publish))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

fn rejected(status: StatusCode) -> Response {
    (status, Json(json!({ "error": "rejected" }))).into_response()
}

async fn handle_publish(
    State(state): State<InboundState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(store) = state.module_registry_store.clone() else {
        // Bootstrap not run — pretend the endpoint doesn't exist.
        return rejected(StatusCode::NOT_FOUND);
    };
    let nonce_cache = state.nonce_cache.clone();

    match try_publish(&state, &store, &nonce_cache, &name, &headers, &body).await {
        Ok(envelope) => {
            info!(
                module = %name,
                event_id = %envelope.event_id,
                kind = ?envelope.kind,
                "module event accepted"
            );
            (
                StatusCode::ACCEPTED,
                Json(json!({ "event_id": envelope.event_id })),
            )
                .into_response()
        }
        Err(rej) => {
            // Server-side log carries the real reason. Wire response is
            // opaque so attackers cannot fingerprint which check failed.
            let RejectionReason { status, reason } = rej;
            debug!(
                module = %name,
                status = %status,
                reason = %reason,
                "module event rejected"
            );
            rejected(status)
        }
    }
}

struct RejectionReason {
    status: StatusCode,
    reason: &'static str,
}

fn reject(status: StatusCode, reason: &'static str) -> RejectionReason {
    RejectionReason { status, reason }
}

async fn try_publish(
    state: &InboundState,
    store: &Arc<ModuleRegistryStore>,
    nonce_cache: &Arc<NonceCache>,
    name: &str,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<EventEnvelope, RejectionReason> {
    // Step 2: module lookup.
    let module = match store.get_by_name(name).await {
        Ok(Some(m)) => m,
        Ok(None) => return Err(reject(StatusCode::NOT_FOUND, "unknown module")),
        Err(_) => return Err(reject(StatusCode::INTERNAL_SERVER_ERROR, "store error")),
    };
    if !module.enabled {
        // Disabled modules look the same as unknown ones to the client.
        return Err(reject(StatusCode::NOT_FOUND, "module disabled"));
    }

    // Step 3: header sanity. We accept either packed `t=...,v1=...` form
    // (matches the dispatcher's outbound shape) or split timestamp +
    // signature headers.
    let sig_hdr = headers
        .get(SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| reject(StatusCode::UNAUTHORIZED, "missing signature header"))?;

    let (timestamp, signature_hex) = if let Some(parsed) = parse_sig_header(sig_hdr) {
        (parsed.timestamp, parsed.signature_hex.to_string())
    } else {
        // Fall back to split headers: signature is raw hex, timestamp is
        // its own header.
        let ts: i64 = headers
            .get(TIMESTAMP_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| reject(StatusCode::UNAUTHORIZED, "missing timestamp header"))?;
        (ts, sig_hdr.trim().to_string())
    };

    // Step 4 + 5: timestamp window + HMAC verify (verify_signature does
    // both, in that order).
    let secret = match store.get_shared_secret(name).await {
        Ok(Some(s)) => s,
        Ok(None) => return Err(reject(StatusCode::UNAUTHORIZED, "no shared secret")),
        Err(_) => {
            return Err(reject(
                StatusCode::INTERNAL_SERVER_ERROR,
                "secret decrypt failed",
            ))
        }
    };
    if let Err(_e) = verify_signature(
        secret.expose_secret(),
        timestamp,
        body.as_ref(),
        now_unix(),
        &signature_hex,
        DEFAULT_TIMESTAMP_SKEW_SECS,
    ) {
        return Err(reject(StatusCode::UNAUTHORIZED, "signature verify failed"));
    }

    // Step 6: body parse.
    let envelope: EventEnvelope = serde_json::from_slice(body)
        .map_err(|_| reject(StatusCode::BAD_REQUEST, "bad envelope"))?;

    // Sanity-check that the envelope's self-described timestamp matches
    // the signed-over timestamp. They MUST agree; otherwise an attacker
    // could keep a valid signature header but swap the envelope's claim.
    if envelope.timestamp_unix != timestamp {
        return Err(reject(
            StatusCode::BAD_REQUEST,
            "envelope timestamp mismatch",
        ));
    }

    // Step 7: nonce dedup.
    if nonce_cache
        .record(name, &envelope.nonce, now_unix() as u64)
        .await
    {
        return Err(reject(StatusCode::CONFLICT, "duplicate nonce"));
    }

    // Step 8: authorization — module must have declared this kind in its
    // manifest.
    if !module.manifest.declared_publish.contains(&envelope.kind) {
        return Err(reject(StatusCode::FORBIDDEN, "kind not declared"));
    }

    // Step 9 + 10: convert wire to in-process event, host-stamp source,
    // persist to durable store with the URL-path identity, and publish to
    // the bus for module fan-out.
    let event =
        wire_to_event(&envelope.kind, envelope.event.clone(), name).ok_or_else(|| {
            reject(
                StatusCode::BAD_REQUEST,
                "envelope kind/payload disagreement",
            )
        })?;

    // Findings persist at the ACL boundary so the host-stamped module
    // name lives on the row. Other event kinds are advisory-only and not
    // persisted here.
    if let DriftEvent::Finding(ref finding) = event {
        if let Err(e) = state
            .findings_store
            .upsert_finding(
                name,
                finding,
                Some(envelope.event_id.as_str()),
                Some(envelope.nonce.as_str()),
            )
            .await
        {
            warn!(module = %name, error = %e, "findings persist failed");
            return Err(reject(
                StatusCode::INTERNAL_SERVER_ERROR,
                "findings persist failed",
            ));
        }
    }

    state.event_bus.publish(event);

    // Best-effort: bump last_seen_at on a successful publish.
    let _ = store.touch_last_seen(name).await;

    Ok(envelope)
}

/// Translate a wire event into an in-process [`DriftEvent`], dropping any
/// payload-claimed source on `ModuleCustom` (in-process only — but if a
/// module ever serializes one, we still don't trust the source field).
///
/// Returns `None` if the envelope's `kind` discriminant disagrees with
/// the actual payload variant.
fn wire_to_event(
    kind: &EventKind,
    wire: ion_drift_module_api::DriftEventWire,
    _module_name: &str,
) -> Option<DriftEvent> {
    use ion_drift_module_api::DriftEventWire as W;
    let event = match wire {
        W::Finding(payload) => {
            // Currently the only inbound-supported kind. Other kinds may
            // be added to the publish whitelist in future minor versions.
            ensure_kind(kind, EventKind::Finding)?;
            DriftEvent::Finding(payload)
        }
        // All other kinds are intentionally not constructible from the
        // network. Drift's engines own them; modules that want to emit
        // them must wait for an explicit minor-version uplift.
        W::AnomalyDetected(_)
        | W::BehaviorBaselineUpdated(_)
        | W::InvestigationStarted(_)
        | W::InvestigationCompleted(_)
        | W::InfrastructureSnapshotUpdated(_)
        | W::DeviceAdded(_)
        | W::DeviceRemoved(_)
        | W::DeviceUnreachable(_)
        | W::SwitchTopologyChanged(_)
        | W::ConnectionStateChanged(_)
        | W::ModuleCustom(_) => return None,
        // `DriftEventWire` is `#[non_exhaustive]`; reject any future variant
        // by default until it's explicitly allowed inbound.
        _ => return None,
    };
    Some(event)
}

fn ensure_kind(claimed: &EventKind, actual: EventKind) -> Option<()> {
    if *claimed == actual {
        Some(())
    } else {
        None
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// Silence unused-import warnings if FindingV1 isn't directly referenced
// after a future refactor.
#[allow(dead_code)]
const _ASSERT_FINDING_V1_USED: Option<FindingV1> = None;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn nonce_cache_records_and_evicts() {
        let cache = NonceCache::new();
        assert!(!cache.record("m", "abc", 1000).await);
        assert!(cache.record("m", "abc", 1001).await); // duplicate
        assert_eq!(cache.len().await, 1);

        // Far-future timestamp evicts old entries on next insert.
        assert!(!cache.record("m", "xyz", 1000 + NONCE_TTL_SECS + 1).await);
        // After GC, the old `abc` entry is gone.
        assert_eq!(cache.len().await, 1);
    }

    #[test]
    fn wire_to_event_translates_finding() {
        use ion_drift_module_api::{
            DriftEventWire, FindingEvidence, FindingSeverity, FindingV1,
        };
        let payload = FindingV1 {
            finding_id: "f1".into(),
            title: "t".into(),
            narrative: "n".into(),
            severity: FindingSeverity::High,
            category: "geographic".into(),
            recommended_actions: vec!["block".into()],
            evidence: vec![FindingEvidence::Anomaly { anomaly_id: 7 }],
            device_macs: vec!["aa:bb:cc:dd:ee:ff".into()],
            timestamp_unix: 1_700_000_000,
            metadata: None,
        };
        let wire = DriftEventWire::Finding(payload.clone());
        let ev = wire_to_event(&EventKind::Finding, wire, "scout").unwrap();
        match ev {
            DriftEvent::Finding(p) => assert_eq!(p.finding_id, "f1"),
            _ => panic!("expected Finding"),
        }
    }

    #[test]
    fn wire_to_event_rejects_kind_mismatch() {
        use ion_drift_module_api::{DriftEventWire, FindingEvidence, FindingSeverity, FindingV1};
        let payload = FindingV1 {
            finding_id: "f1".into(),
            title: "t".into(),
            narrative: "n".into(),
            severity: FindingSeverity::Low,
            category: "x".into(),
            recommended_actions: vec![],
            evidence: vec![],
            device_macs: vec![],
            timestamp_unix: 0,
            metadata: None,
        };
        let _ = FindingEvidence::Custom {
            label: "x".into(),
            payload: serde_json::Value::Null,
        };
        let wire = DriftEventWire::Finding(payload);
        // Claim the wrong kind.
        assert!(wire_to_event(&EventKind::AnomalyDetected, wire, "m").is_none());
    }

    #[test]
    fn wire_to_event_rejects_module_custom() {
        use ion_drift_module_api::{DriftEventWire, ModuleCustomWireV1};
        let wire = DriftEventWire::ModuleCustom(ModuleCustomWireV1 {
            source: "bad".into(),
            kind: "kk".into(),
            payload: serde_json::Value::Null,
        });
        assert!(wire_to_event(&EventKind::ModuleCustom, wire, "m").is_none());
    }

    #[allow(dead_code)]
    fn _duration_used_marker() -> Duration {
        Duration::from_secs(1)
    }
}

#[cfg(test)]
mod integration_tests {
    //! End-to-end tests through the inbound router. Each test stands up
    //! a tempfile-backed registry + findings store, registers one module,
    //! and `oneshot`s a request through `Router<InboundState>`.
    //!
    //! These cover the load-bearing ACL invariant (host-stamped
    //! `module_name`) and the full STRIDE rejection table from the plan.

    use super::*;
    use aes_gcm::{Aes256Gcm, Key};
    use axum::body::Body;
    use axum::http::Request;
    use axum::Router;
    use ion_drift_module_api::{
        ApiVersion, DriftEventWire, EventEnvelope, EventKind, FindingEvidence,
        FindingSeverity, FindingV1, Manifest, ProtocolVariant,
    };
    use ion_drift_module_host::EventBus;
    use ion_drift_storage::{FindingsQuery, FindingsStore};
    use serde_json::json;
    use std::sync::Arc;
    use tempfile::NamedTempFile;
    use tower::ServiceExt;

    use super::super::hmac::sign_bytes;
    use super::super::store::{ModuleRegistryStore, NewModuleRegistration};

    const TEST_SECRET: &str = "shared-secret-32-chars-or-more!!!";

    fn test_kek() -> Key<Aes256Gcm> {
        let bytes: [u8; 32] = [9u8; 32];
        Key::<Aes256Gcm>::from_slice(&bytes).to_owned()
    }

    /// Test fixture — owns the tempfiles so the SQLite DBs survive for
    /// the lifetime of the test, and exposes the assembled
    /// [`InboundState`] plus the shared HMAC secret.
    struct Fixture {
        _secrets_db: NamedTempFile,
        _findings_db: NamedTempFile,
        state: InboundState,
        secret: String,
    }

    async fn fixture(module_name: &str, declared_publish: Vec<EventKind>) -> Fixture {
        let secrets_db = NamedTempFile::new().unwrap();
        let findings_db = NamedTempFile::new().unwrap();

        let store =
            Arc::new(ModuleRegistryStore::new(secrets_db.path(), test_kek()).unwrap());
        let manifest = Manifest {
            name: module_name.into(),
            version: "0.1.0".into(),
            api_version: ApiVersion::CURRENT,
            protocol: ProtocolVariant::Http,
            description: None,
            subscribed_events: vec![],
            declared_publish,
            exposed_routes: vec![],
        };
        store
            .register(NewModuleRegistration {
                name: module_name,
                url: "http://127.0.0.1:9999",
                manifest: &manifest,
                shared_secret: TEST_SECRET,
                api_token: "bearer",
            })
            .await
            .unwrap();

        let findings_store =
            Arc::new(FindingsStore::new(findings_db.path()).unwrap());
        let state = InboundState {
            event_bus: EventBus::new(16),
            module_registry_store: Some(store),
            findings_store,
            nonce_cache: Arc::new(NonceCache::new()),
        };

        Fixture {
            _secrets_db: secrets_db,
            _findings_db: findings_db,
            state,
            secret: TEST_SECRET.to_string(),
        }
    }

    fn make_router(state: InboundState) -> Router {
        Router::new()
            .route("/api/v1/modules/{name}/events", post(handle_publish))
            .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
            .with_state(state)
    }

    fn make_finding(finding_id: &str, timestamp_unix: i64) -> FindingV1 {
        FindingV1 {
            finding_id: finding_id.into(),
            title: "Suspicious traffic".into(),
            narrative: "Module narrative".into(),
            severity: FindingSeverity::High,
            category: "geographic".into(),
            recommended_actions: vec!["block".into()],
            evidence: vec![FindingEvidence::Anomaly { anomaly_id: 7 }],
            device_macs: vec!["aa:bb:cc:dd:ee:ff".into()],
            timestamp_unix,
            // Payload metadata claims a different "source" — must be ignored
            // by the ACL; URL path wins.
            metadata: Some(json!({ "claimed_source": "evil-module" })),
        }
    }

    fn make_envelope(finding_id: &str, timestamp_unix: i64) -> EventEnvelope {
        EventEnvelope {
            api_version: ApiVersion::CURRENT,
            event_id: format!("evt-{finding_id}"),
            timestamp_unix,
            nonce: format!("nonce-{finding_id}"),
            kind: EventKind::Finding,
            event: DriftEventWire::Finding(make_finding(finding_id, timestamp_unix)),
        }
    }

    /// Build a fully signed POST request. `path_name` is what goes into
    /// the URL path — tests pass a different value than the registered
    /// module name to exercise the unknown-module case.
    fn signed_request(
        path_name: &str,
        secret: &str,
        envelope: &EventEnvelope,
    ) -> Request<Body> {
        let body = serde_json::to_vec(envelope).unwrap();
        let sig = sign_bytes(secret, envelope.timestamp_unix, &body);
        let header = format!("t={},v1={}", envelope.timestamp_unix, sig);
        Request::builder()
            .method("POST")
            .uri(format!("/api/v1/modules/{path_name}/events"))
            .header("content-type", "application/json")
            .header(SIGNATURE_HEADER, header)
            .body(Body::from(body))
            .unwrap()
    }

    /// Happy path + the load-bearing ACL invariant: even though the
    /// payload's `metadata` claims to come from `evil-module`, the
    /// persisted row's `module_name` is the URL path identity ("test").
    #[tokio::test]
    async fn host_stamps_module_name_from_url_path() {
        let fx = fixture("test", vec![EventKind::Finding]).await;
        let envelope = make_envelope("f-1", now_unix());
        let app = make_router(fx.state.clone());

        let resp = app
            .oneshot(signed_request("test", &fx.secret, &envelope))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let rows = fx
            .state
            .findings_store
            .list_findings(&FindingsQuery {
                status: None,
                severity: None,
                module_name: None,
                category: None,
                since: None,
                limit: None,
                offset: None,
            })
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        // The whole point of this test: URL-path identity wins, not
        // anything in the payload.
        assert_eq!(rows[0].module_name, "test");
        assert_eq!(rows[0].finding_id, "f-1");
        assert_eq!(rows[0].envelope_event_id.as_deref(), Some("evt-f-1"));
        assert_eq!(rows[0].envelope_nonce.as_deref(), Some("nonce-f-1"));
    }

    #[tokio::test]
    async fn rejects_bad_signature_with_401() {
        let fx = fixture("test", vec![EventKind::Finding]).await;
        let envelope = make_envelope("f-1", now_unix());
        let app = make_router(fx.state.clone());

        // Sign with the wrong secret — header is well-formed but doesn't
        // verify against the secret stored at registration.
        let resp = app
            .oneshot(signed_request("test", "wrong-secret", &envelope))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            fx.state.findings_store.list_findings(&q_all()).await.unwrap().len(),
            0
        );
    }

    #[tokio::test]
    async fn rejects_expired_timestamp_with_401() {
        let fx = fixture("test", vec![EventKind::Finding]).await;
        // Timestamp far outside the 300s window — signature is valid for
        // its own timestamp, but `now - timestamp > 300` so verify fails.
        let envelope = make_envelope("f-1", now_unix() - 10_000);
        let app = make_router(fx.state.clone());

        let resp = app
            .oneshot(signed_request("test", &fx.secret, &envelope))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_replayed_nonce_with_409() {
        let fx = fixture("test", vec![EventKind::Finding]).await;
        let envelope = make_envelope("f-1", now_unix());
        let app = make_router(fx.state.clone());

        let first = app
            .clone()
            .oneshot(signed_request("test", &fx.secret, &envelope))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::ACCEPTED);

        // Same envelope, same nonce — replay.
        let second = app
            .oneshot(signed_request("test", &fx.secret, &envelope))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn rejects_undeclared_kind_with_403() {
        // Module registered with empty `declared_publish` — any inbound
        // kind is unauthorized.
        let fx = fixture("test", vec![]).await;
        let envelope = make_envelope("f-1", now_unix());
        let app = make_router(fx.state.clone());

        let resp = app
            .oneshot(signed_request("test", &fx.secret, &envelope))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(fx.state.findings_store.list_findings(&q_all()).await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn rejects_unknown_module_with_404() {
        let fx = fixture("test", vec![EventKind::Finding]).await;
        let envelope = make_envelope("f-1", now_unix());
        let app = make_router(fx.state.clone());

        // POST to a module name that wasn't registered.
        let resp = app
            .oneshot(signed_request("nope", &fx.secret, &envelope))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn rejects_oversize_body_with_413() {
        let fx = fixture("test", vec![EventKind::Finding]).await;
        let app = make_router(fx.state.clone());

        // Build a body that exceeds the 1 MiB layer limit. Signature
        // doesn't matter — the layer rejects before the handler runs.
        let oversized = vec![b'x'; MAX_BODY_BYTES + 1024];
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/modules/test/events")
            .header("content-type", "application/json")
            .header(SIGNATURE_HEADER, "t=0,v1=00")
            .body(Body::from(oversized))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    fn q_all() -> FindingsQuery {
        FindingsQuery {
            status: None,
            severity: None,
            module_name: None,
            category: None,
            since: None,
            limit: None,
            offset: None,
        }
    }
}
