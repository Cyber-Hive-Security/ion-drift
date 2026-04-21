//! Admin API for managing registered modules.
//!
//! These routes back the React "Modules" admin page (Task 7). The
//! parent router applies `RequireAdmin` at mount time, so handlers
//! here can assume the caller is an authenticated admin.
//!
//! The router is parameterized on an [`Arc<ModuleRegistryService>`]
//! rather than the full `AppState`, matching the shape of the proxy
//! router in [`super::module_proxy`]. Task 8 wires both into the
//! global admin-protected router.
//!
//! # Routes
//!
//! | Method | Path                           | Purpose                   |
//! |--------|--------------------------------|---------------------------|
//! | GET    | `/`                            | list registered modules   |
//! | POST   | `/`                            | register a new module     |
//! | DELETE | `/{name}`                      | unregister a module       |
//! | POST   | `/{name}/enable`               | enable delivery/proxy     |
//! | POST   | `/{name}/disable`              | disable delivery/proxy    |
//! | POST   | `/{name}/test`                 | probe `/manifest` + touch |

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
    Router,
};
use ion_drift_module_api::Manifest;
use serde::{Deserialize, Serialize};

use crate::modules_registry::{
    ModuleRegistryService, RegisterRequest, RegisteredModule,
};

pub fn admin_modules_router(service: Arc<ModuleRegistryService>) -> Router {
    Router::new()
        .route("/", get(list).post(register))
        .route("/{name}", delete(unregister))
        .route("/{name}/enable", post(enable))
        .route("/{name}/disable", post(disable))
        .route("/{name}/test", post(test_connection))
        .with_state(service)
}

#[derive(Debug, Deserialize)]
struct RegisterBody {
    url: String,
    shared_secret: String,
    api_token: String,
}

#[derive(Serialize)]
struct ListResponse {
    modules: Vec<RegisteredModule>,
}

#[derive(Serialize)]
struct ModuleResponse {
    module: RegisteredModule,
}

#[derive(Serialize)]
struct ManifestResponse {
    manifest: Manifest,
}

#[derive(Serialize)]
struct OkResponse {
    ok: bool,
}

async fn list(
    State(service): State<Arc<ModuleRegistryService>>,
) -> Result<Json<ListResponse>, ApiError> {
    let modules = service.list().await.map_err(api_err)?;
    Ok(Json(ListResponse { modules }))
}

async fn register(
    State(service): State<Arc<ModuleRegistryService>>,
    Json(body): Json<RegisterBody>,
) -> Result<(StatusCode, Json<ModuleResponse>), ApiError> {
    let module = service
        .register(RegisterRequest {
            url: body.url,
            shared_secret: body.shared_secret,
            api_token: body.api_token,
        })
        .await
        .map_err(api_err)?;
    Ok((StatusCode::CREATED, Json(ModuleResponse { module })))
}

async fn unregister(
    State(service): State<Arc<ModuleRegistryService>>,
    Path(name): Path<String>,
) -> Result<Json<OkResponse>, ApiError> {
    let removed = service.unregister(&name).await.map_err(api_err)?;
    if !removed {
        return Err(ApiError::not_found(&name));
    }
    Ok(Json(OkResponse { ok: true }))
}

async fn enable(
    State(service): State<Arc<ModuleRegistryService>>,
    Path(name): Path<String>,
) -> Result<Json<OkResponse>, ApiError> {
    let changed = service.set_enabled(&name, true).await.map_err(api_err)?;
    if !changed {
        return Err(ApiError::not_found(&name));
    }
    Ok(Json(OkResponse { ok: true }))
}

async fn disable(
    State(service): State<Arc<ModuleRegistryService>>,
    Path(name): Path<String>,
) -> Result<Json<OkResponse>, ApiError> {
    let changed = service.set_enabled(&name, false).await.map_err(api_err)?;
    if !changed {
        return Err(ApiError::not_found(&name));
    }
    Ok(Json(OkResponse { ok: true }))
}

async fn test_connection(
    State(service): State<Arc<ModuleRegistryService>>,
    Path(name): Path<String>,
) -> Result<Json<ManifestResponse>, ApiError> {
    match service.test_connection(&name).await {
        Ok(manifest) => Ok(Json(ManifestResponse { manifest })),
        Err(e) => {
            let msg = e.to_string();
            // "module '...' not registered" → 404; everything else
            // is a probe failure from our POV, mapped to 502.
            if msg.contains("not registered") {
                Err(ApiError::not_found(&name))
            } else {
                Err(ApiError::bad_gateway(msg))
            }
        }
    }
}

/// Lightweight error wrapper so handlers can return meaningful
/// status codes with a stable JSON shape: `{ "error": "<msg>" }`.
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
    fn not_found(name: &str) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            format!("module '{name}' not registered"),
        )
    }
    fn bad_gateway(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, msg)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}

fn api_err(e: anyhow::Error) -> ApiError {
    let msg = e.to_string();
    let status = if msg.contains("already registered") {
        StatusCode::CONFLICT
    } else if msg.contains("not registered") {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::BAD_REQUEST
    };
    ApiError::new(status, msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules_registry::store::NewModuleRegistration;
    use crate::modules_registry::ModuleRegistryStore;
    use aes_gcm::{Aes256Gcm, Key};
    use axum::{body::Body, http::Request};
    use ion_drift_module_api::{ApiVersion, EventKind, ProtocolVariant, RouteDescriptor};
    use tempfile::NamedTempFile;
    use tower::ServiceExt;

    fn test_kek() -> Key<Aes256Gcm> {
        Key::<Aes256Gcm>::from_slice(&[17u8; 32]).to_owned()
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

    async fn spawn_manifest_mock(m: Option<Manifest>) -> String {
        use axum::routing::get as get_r;
        async fn handler(
            State(m): State<Arc<Option<Manifest>>>,
        ) -> Response {
            match m.as_ref() {
                Some(m) => Json(m.clone()).into_response(),
                None => (StatusCode::NOT_FOUND, "missing").into_response(),
            }
        }
        let app = Router::new()
            .route("/manifest", get_r(handler))
            .with_state(Arc::new(m));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    async fn setup() -> (Router, Arc<ModuleRegistryStore>, NamedTempFile) {
        let tmp = NamedTempFile::new().unwrap();
        let store = Arc::new(ModuleRegistryStore::new(tmp.path(), test_kek()).unwrap());
        let svc = Arc::new(ModuleRegistryService::new(Arc::clone(&store)).unwrap());
        (admin_modules_router(svc), store, tmp)
    }

    async fn prebake(store: &Arc<ModuleRegistryStore>, name: &str, enabled: bool) {
        store
            .register(NewModuleRegistration {
                name,
                url: "http://127.0.0.1:1",
                manifest: &sample_manifest(name),
                shared_secret: "shared-secret-at-least-32-chars-long!",
                api_token: "api-token-at-least-32-chars-long-xyz0",
            })
            .await
            .unwrap();
        if !enabled {
            store.set_enabled(name, false).await.unwrap();
        }
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn list_empty() {
        let (router, _store, _tmp) = setup().await;
        let req = Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["modules"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn list_returns_registered_modules() {
        let (router, store, _tmp) = setup().await;
        prebake(&store, "a", true).await;
        prebake(&store, "b", false).await;

        let resp = router
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let json = body_json(resp).await;
        let arr = json["modules"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
    }

    #[tokio::test]
    async fn register_happy_path() {
        let (router, _store, _tmp) = setup().await;
        let target = spawn_manifest_mock(Some(sample_manifest("new-mod"))).await;
        let body = serde_json::json!({
            "url": target,
            "shared_secret": "shared-secret-at-least-32-chars-long!",
            "api_token":     "api-token-at-least-32-chars-long-xyz0",
        });
        let req = Request::builder()
            .method("POST")
            .uri("/")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let json = body_json(resp).await;
        assert_eq!(json["module"]["name"], "new-mod");
    }

    #[tokio::test]
    async fn register_rejects_short_secret() {
        let (router, _store, _tmp) = setup().await;
        let target = spawn_manifest_mock(Some(sample_manifest("x"))).await;
        let body = serde_json::json!({
            "url": target,
            "shared_secret": "short",
            "api_token":     "api-token-at-least-32-chars-long-xyz0",
        });
        let req = Request::builder()
            .method("POST")
            .uri("/")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = body_json(resp).await;
        assert!(json["error"].as_str().unwrap().contains("shared_secret"));
    }

    #[tokio::test]
    async fn register_conflict_on_duplicate() {
        let (router, store, _tmp) = setup().await;
        prebake(&store, "dup", true).await;
        let target = spawn_manifest_mock(Some(sample_manifest("dup"))).await;
        let body = serde_json::json!({
            "url": target,
            "shared_secret": "shared-secret-at-least-32-chars-long!",
            "api_token":     "api-token-at-least-32-chars-long-xyz0",
        });
        let req = Request::builder()
            .method("POST")
            .uri("/")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn disable_then_enable() {
        let (router, store, _tmp) = setup().await;
        prebake(&store, "m", true).await;

        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/m/disable")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/m/enable")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn disable_unknown_returns_404() {
        let (router, _store, _tmp) = setup().await;
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/nope/disable")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn unregister_removes_and_then_404() {
        let (router, store, _tmp) = setup().await;
        prebake(&store, "gone", true).await;

        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/gone")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = router
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/gone")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_connection_unknown_module_is_404() {
        let (router, _store, _tmp) = setup().await;
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/nope/test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_connection_unreachable_is_502() {
        let (router, store, _tmp) = setup().await;
        // Pre-register with a bogus URL (nothing listening).
        prebake(&store, "dead", true).await;
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/dead/test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }
}
