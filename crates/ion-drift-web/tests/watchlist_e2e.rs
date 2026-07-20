//! Live end-to-end test against a running drift-watchlist module.
//!
//! Exercises the real chain the deployed system uses:
//!
//! 1. `ModuleRegistryService::register` probes the live module's
//!    `GET /manifest` and persists the registration (encrypted secrets).
//! 2. `EventDispatcher::dispatch` signs an `AnomalyDetected` envelope with
//!    the registered shared secret and POSTs it to the module's `/events`.
//! 3. The module verifies the HMAC, stores the MAC in its SQLite watchlist.
//! 4. The module proxy router (what the Drift UI calls) fetches
//!    `/{name}/watchlist` and the MAC is present.
//!
//! A companion negative test registers a *diverged* secret and asserts the
//! dispatcher records the module's 401 — the failure mode the secret
//! fingerprint surfacing exists to catch.
//!
//! These tests need a live module and are `#[ignore]`d by default:
//!
//! ```sh
//! DRIFT_WATCHLIST_E2E_SECRET_FILE=/path/to/shared-secret \
//! DRIFT_WATCHLIST_E2E_BEARER="$(the module's bearer_token)" \
//! cargo test -p ion-drift-web --test watchlist_e2e -- --ignored
//! ```
//!
//! Optional: `DRIFT_WATCHLIST_E2E_URL` (default `http://127.0.0.1:8991`).

use std::sync::Arc;
use std::time::Duration;

use aes_gcm::{Aes256Gcm, Key};
use ion_drift_module_api::{AnomalyDetectedV1, DriftEvent};
use ion_drift_web::modules_registry::{
    DispatcherConfig, EventDispatcher, ModuleRegistryService, ModuleRegistryStore,
    RegisterRequest,
};
use ion_drift_web::routes::module_proxy::{module_proxy_router, ModuleProxyState};
use tempfile::NamedTempFile;
use tower::ServiceExt;

fn test_kek() -> Key<Aes256Gcm> {
    Key::<Aes256Gcm>::from_slice(&[42u8; 32]).to_owned()
}

fn module_url() -> String {
    std::env::var("DRIFT_WATCHLIST_E2E_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8991".to_string())
}

fn module_secret() -> String {
    let path = std::env::var("DRIFT_WATCHLIST_E2E_SECRET_FILE")
        .expect("set DRIFT_WATCHLIST_E2E_SECRET_FILE to the module's shared-secret file");
    std::fs::read_to_string(path)
        .expect("reading shared secret file")
        .trim()
        .to_string()
}

fn module_bearer() -> String {
    std::env::var("DRIFT_WATCHLIST_E2E_BEARER")
        .expect("set DRIFT_WATCHLIST_E2E_BEARER to the module's bearer_token")
}

fn anomaly(mac: &str) -> DriftEvent {
    DriftEvent::AnomalyDetected(AnomalyDetectedV1 {
        anomaly_id: 424242,
        device_mac: mac.to_string(),
        severity: "info".into(),
        anomaly_type: "e2e_test".into(),
        vlan: Some(25),
        timestamp_unix: chrono::Utc::now().timestamp(),
    })
}

async fn setup(
    secret: &str,
) -> (Arc<ModuleRegistryStore>, Arc<ModuleRegistryService>, String, NamedTempFile) {
    let tmp = NamedTempFile::new().unwrap();
    let store = Arc::new(ModuleRegistryStore::new(tmp.path(), test_kek()).unwrap());
    let service = Arc::new(ModuleRegistryService::new(Arc::clone(&store)).unwrap());
    // Real registration path: probes the live module's /manifest.
    let module = service
        .register(RegisterRequest {
            url: module_url(),
            shared_secret: secret.to_string(),
            api_token: module_bearer(),
        })
        .await
        .expect("registering against the live module (is drift-watchlist running?)");
    (store, service, module.name, tmp)
}

/// Poll dispatcher stats until `pred` passes or the deadline expires.
async fn wait_for_stats<F>(dispatcher: &Arc<EventDispatcher>, name: &str, pred: F) -> bool
where
    F: Fn(&ion_drift_web::modules_registry::DeliveryStats) -> bool,
{
    for _ in 0..100 {
        if let Some(stats) = dispatcher.stats_snapshot().await.get(name) {
            if pred(stats) {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[tokio::test]
#[ignore = "needs a live drift-watchlist instance; see module docs"]
async fn full_chain_dispatch_to_watchlist() {
    let secret = module_secret();
    let (store, _service, name, _tmp) = setup(&secret).await;
    assert_eq!(name, "drift-watchlist");

    let http = reqwest::Client::new();
    let dispatcher =
        EventDispatcher::new(Arc::clone(&store), http.clone(), DispatcherConfig::default());

    // Unique MAC per run so reruns don't false-positive on stale rows.
    let mac = format!(
        "E2:E0:{:02X}:{:02X}:{:02X}:{:02X}",
        rand_byte(),
        rand_byte(),
        rand_byte(),
        rand_byte()
    );
    dispatcher.dispatch(&anomaly(&mac)).await;

    assert!(
        wait_for_stats(&dispatcher, &name, |s| s.success_count >= 1).await,
        "dispatcher never recorded a successful delivery: {:?}",
        dispatcher.stats_snapshot().await.get(&name)
    );

    // What the Drift UI does: proxy /api/modules/drift-watchlist/watchlist.
    let proxy = module_proxy_router(ModuleProxyState { store, http });
    let resp = proxy
        .oneshot(
            axum::http::Request::builder()
                .uri(format!("/{name}/watchlist"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let body = String::from_utf8_lossy(&body);
    assert!(
        body.contains(&mac),
        "watchlist response missing dispatched MAC {mac}: {body}"
    );
}

#[tokio::test]
#[ignore = "needs a live drift-watchlist instance; see module docs"]
async fn diverged_secret_is_visible_as_401() {
    // Register with a secret the module does NOT hold — the silent-divergence
    // scenario. The module must reject the delivery and the dispatcher must
    // surface the 401 in its stats (which is what makes divergence *loud*).
    let wrong = "deliberately-diverged-secret-0123456789abcdef";
    let (store, _service, name, _tmp) = setup(wrong).await;

    let http = reqwest::Client::new();
    // No retries: one attempt is enough to observe the 401.
    let cfg = DispatcherConfig {
        retry_backoffs: vec![],
        ..DispatcherConfig::default()
    };
    let dispatcher = EventDispatcher::new(Arc::clone(&store), http, cfg);

    dispatcher.dispatch(&anomaly("E2:E0:BA:D5:EC:00")).await;

    assert!(
        wait_for_stats(&dispatcher, &name, |s| {
            s.failure_count >= 1
                && s.last_error.as_deref().is_some_and(|e| e.contains("401"))
        })
        .await,
        "dispatcher did not record a 401 failure: {:?}",
        dispatcher.stats_snapshot().await.get(&name)
    );
}

fn rand_byte() -> u8 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Cheap per-call entropy; uniqueness across runs is all we need.
    (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos()
        % 251) as u8
}
