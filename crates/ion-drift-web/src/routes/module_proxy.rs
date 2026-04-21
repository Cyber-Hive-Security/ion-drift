//! Reverse-proxy handler for registered modules.
//!
//! Mounted under the admin-authenticated `/api/modules` root by the
//! main router, this handler forwards requests to the external module's
//! base URL with the per-registration bearer token injected. It
//! preserves method, path tail, query string, and body; it filters hop-
//! by-hop headers on both legs and strips any inbound `Authorization`
//! (which we always overwrite with our stored token).
//!
//! Body size is capped at 10 MB. Scout-shield and similar modules
//! exchange small JSON documents, not large uploads; streaming can
//! come later if a module's surface grows.
//!
//! The handler is deliberately standalone — it takes its own
//! [`ModuleProxyState`] via `with_state`, not the full `AppState`. The
//! admin-auth middleware is applied at mount time by the parent router
//! (see Task 8 for integration).

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::any,
    Router,
};
use secrecy::ExposeSecret;

use crate::modules_registry::ModuleRegistryStore;

/// Max request body forwarded to a module.
const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

/// Everything the proxy handler needs. Cheaply cloneable.
#[derive(Clone)]
pub struct ModuleProxyState {
    pub store: Arc<ModuleRegistryStore>,
    pub http: reqwest::Client,
}

/// Build a router for `/{name}` and `/{name}/{*tail}` routes.
///
/// Mount like: `Router::new().nest("/api/modules", module_proxy_router(state))`.
pub fn module_proxy_router(state: ModuleProxyState) -> Router {
    Router::new()
        .route("/{name}", any(proxy_root))
        .route("/{name}/{*tail}", any(proxy_tail))
        .with_state(state)
}

async fn proxy_root(
    State(state): State<ModuleProxyState>,
    Path(name): Path<String>,
    req: Request,
) -> Response {
    proxy_impl(state, name, String::new(), req).await
}

async fn proxy_tail(
    State(state): State<ModuleProxyState>,
    Path((name, tail)): Path<(String, String)>,
    req: Request,
) -> Response {
    proxy_impl(state, name, tail, req).await
}

async fn proxy_impl(
    state: ModuleProxyState,
    name: String,
    tail: String,
    req: Request,
) -> Response {
    let module = match state.store.get_by_name(&name).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": format!("module '{name}' not registered")
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::warn!(module = %name, error = %e, "module lookup failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "module lookup failed" })),
            )
                .into_response();
        }
    };

    if !module.enabled {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": format!("module '{name}' is disabled")
            })),
        )
            .into_response();
    }

    let api_token = match state.store.get_api_token(&name).await {
        Ok(Some(t)) => t,
        _ => {
            tracing::warn!(module = %name, "api token missing");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "module api token missing" })),
            )
                .into_response();
        }
    };

    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let tail_segment = if tail.is_empty() {
        String::new()
    } else {
        format!("/{tail}")
    };
    let target_url = format!(
        "{}{}{}",
        module.url.trim_end_matches('/'),
        tail_segment,
        query
    );

    let method = req.method().clone();
    let mut builder = state.http.request(method, &target_url);

    for (hname, value) in req.headers() {
        let s = hname.as_str();
        if matches!(
            s,
            "host"
                | "connection"
                | "transfer-encoding"
                | "cookie"
                | "authorization"
                | "content-length"
        ) {
            continue;
        }
        if let Ok(v) = reqwest::header::HeaderValue::from_bytes(value.as_bytes()) {
            builder = builder.header(s, v);
        }
    }

    builder = builder.header(
        "Authorization",
        format!("Bearer {}", api_token.expose_secret()),
    );

    let body_bytes = match axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(serde_json::json!({ "error": "request body too large" })),
            )
                .into_response();
        }
    };
    if !body_bytes.is_empty() {
        builder = builder.body(body_bytes.to_vec());
    }

    let response = match builder.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(module = %name, target = %target_url, error = %e, "module proxy failed");
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": format!("module '{name}' unreachable"),
                    "detail": e.to_string(),
                })),
            )
                .into_response();
        }
    };

    let _ = state.store.touch_last_seen(&name).await;

    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut resp = Response::builder().status(status);
    for (hname, value) in response.headers() {
        let s = hname.as_str();
        if matches!(s, "transfer-encoding" | "connection" | "content-length") {
            continue;
        }
        if let Ok(v) = HeaderValue::from_bytes(value.as_bytes()) {
            resp = resp.header(s, v);
        }
    }

    let resp_body = match response.bytes().await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(module = %name, error = %e, "module response read failed");
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": "module response read failed" })),
            )
                .into_response();
        }
    };

    resp.body(Body::from(resp_body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules_registry::store::NewModuleRegistration;
    use aes_gcm::{Aes256Gcm, Key};
    use axum::{extract::State as AxState, http::Method, routing::any, Json as AxJson};
    use ion_drift_module_api::{ApiVersion, EventKind, Manifest, ProtocolVariant, RouteDescriptor};
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use tempfile::NamedTempFile;
    use tower::ServiceExt;

    fn test_kek() -> Key<Aes256Gcm> {
        Key::<Aes256Gcm>::from_slice(&[13u8; 32]).to_owned()
    }

    fn sample_manifest(name: &str) -> Manifest {
        Manifest {
            name: name.into(),
            version: "0.1.0".into(),
            api_version: ApiVersion::CURRENT,
            protocol: ProtocolVariant::Http,
            description: None,
            subscribed_events: vec![EventKind::AnomalyDetected],
            exposed_routes: vec![RouteDescriptor {
                path: "/watchlist".into(),
                method: "GET".into(),
                description: None,
            }],
        }
    }

    #[derive(Default)]
    struct TargetCapture {
        last_method: Mutex<Option<Method>>,
        last_path: Mutex<Option<String>>,
        last_query: Mutex<Option<String>>,
        last_auth: Mutex<Option<String>>,
        last_body: Mutex<Option<Vec<u8>>>,
        last_custom: Mutex<Option<String>>,
    }

    async fn spawn_target() -> (String, Arc<TargetCapture>) {
        let cap = Arc::new(TargetCapture::default());
        let state = Arc::clone(&cap);
        let app = Router::new()
            .fallback(any(
                move |AxState(cap): AxState<Arc<TargetCapture>>, req: Request| async move {
                    *cap.last_method.lock().unwrap() = Some(req.method().clone());
                    *cap.last_path.lock().unwrap() = Some(req.uri().path().to_string());
                    *cap.last_query.lock().unwrap() =
                        req.uri().query().map(|s| s.to_string());
                    *cap.last_auth.lock().unwrap() = req
                        .headers()
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .map(String::from);
                    *cap.last_custom.lock().unwrap() = req
                        .headers()
                        .get("x-custom")
                        .and_then(|v| v.to_str().ok())
                        .map(String::from);
                    let body = axum::body::to_bytes(req.into_body(), 1 << 20)
                        .await
                        .unwrap_or_default()
                        .to_vec();
                    *cap.last_body.lock().unwrap() = Some(body.clone());
                    AxJson(serde_json::json!({ "ok": true, "echo": body.len() }))
                },
            ))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), cap)
    }

    async fn setup_proxy(
        name: &str,
        target_url: &str,
        enabled: bool,
    ) -> (Router, Arc<ModuleRegistryStore>, NamedTempFile) {
        let tmp = NamedTempFile::new().unwrap();
        let store = Arc::new(ModuleRegistryStore::new(tmp.path(), test_kek()).unwrap());
        let m = sample_manifest(name);
        store
            .register(NewModuleRegistration {
                name,
                url: target_url,
                manifest: &m,
                shared_secret: "shared-secret-at-least-32-chars-long!",
                api_token: "api-token-at-least-32-chars-long-xyz0",
            })
            .await
            .unwrap();
        if !enabled {
            store.set_enabled(name, false).await.unwrap();
        }
        let http = reqwest::Client::new();
        let router = module_proxy_router(ModuleProxyState {
            store: Arc::clone(&store),
            http,
        });
        (router, store, tmp)
    }

    #[tokio::test]
    async fn forwards_get_and_injects_bearer() {
        let (target, cap) = spawn_target().await;
        let (router, _store, _tmp) = setup_proxy("scout-shield", &target, true).await;

        let req = Request::builder()
            .method(Method::GET)
            .uri("/scout-shield/watchlist")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        assert_eq!(
            cap.last_method.lock().unwrap().as_ref().unwrap(),
            &Method::GET
        );
        assert_eq!(
            cap.last_path.lock().unwrap().as_deref(),
            Some("/watchlist")
        );
        let auth = cap.last_auth.lock().unwrap().clone().unwrap();
        assert_eq!(auth, "Bearer api-token-at-least-32-chars-long-xyz0");
    }

    #[tokio::test]
    async fn preserves_query_and_nested_path() {
        let (target, cap) = spawn_target().await;
        let (router, _store, _tmp) = setup_proxy("m", &target, true).await;

        let req = Request::builder()
            .method(Method::GET)
            .uri("/m/api/v1/items?limit=5&mac=aa:bb")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        assert_eq!(
            cap.last_path.lock().unwrap().as_deref(),
            Some("/api/v1/items")
        );
        assert_eq!(
            cap.last_query.lock().unwrap().as_deref(),
            Some("limit=5&mac=aa:bb")
        );
    }

    #[tokio::test]
    async fn forwards_post_body_and_custom_header() {
        let (target, cap) = spawn_target().await;
        let (router, _store, _tmp) = setup_proxy("m", &target, true).await;

        let body = br#"{"hello":"world"}"#.to_vec();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/m/submit")
            .header("x-custom", "value-1")
            .body(Body::from(body.clone()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        assert_eq!(
            cap.last_method.lock().unwrap().as_ref().unwrap(),
            &Method::POST
        );
        assert_eq!(cap.last_body.lock().unwrap().clone().unwrap(), body);
        assert_eq!(
            cap.last_custom.lock().unwrap().as_deref(),
            Some("value-1")
        );
    }

    #[tokio::test]
    async fn strips_inbound_authorization_and_replaces() {
        let (target, cap) = spawn_target().await;
        let (router, _store, _tmp) = setup_proxy("m", &target, true).await;

        let req = Request::builder()
            .method(Method::GET)
            .uri("/m/ping")
            .header("authorization", "Bearer a-user-token-that-leaks")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let forwarded = cap.last_auth.lock().unwrap().clone().unwrap();
        assert_eq!(forwarded, "Bearer api-token-at-least-32-chars-long-xyz0");
        assert!(!forwarded.contains("a-user-token-that-leaks"));
    }

    #[tokio::test]
    async fn returns_404_for_unknown_module() {
        let (target, _cap) = spawn_target().await;
        let (router, _store, _tmp) = setup_proxy("known", &target, true).await;

        let req = Request::builder()
            .method(Method::GET)
            .uri("/unknown/path")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn returns_503_for_disabled_module() {
        let (target, _cap) = spawn_target().await;
        let (router, _store, _tmp) = setup_proxy("m", &target, false).await;

        let req = Request::builder()
            .method(Method::GET)
            .uri("/m/anything")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn handles_empty_tail_root() {
        let (target, cap) = spawn_target().await;
        let (router, _store, _tmp) = setup_proxy("m", &target, true).await;

        let req = Request::builder()
            .method(Method::GET)
            .uri("/m")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(cap.last_path.lock().unwrap().as_deref(), Some("/"));
    }
}
