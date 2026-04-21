//! Registration and lifecycle orchestration for out-of-process modules.
//!
//! The service sits above [`super::store::ModuleRegistryStore`] and handles
//! everything that is *not* just persistence: probing the module's
//! `/manifest` endpoint, validating the manifest against the host's
//! [`ApiVersion`], enforcing the module name rules, and emitting tracing
//! events at registration boundaries.
//!
//! The HTTP client uses a short timeout (5s). Probes run with the
//! registered bearer token deliberately *not* attached — the `/manifest`
//! endpoint is declarative metadata and should be reachable before the
//! module trusts Drift. The bearer token is only used on reverse-proxied
//! admin calls (Task 5).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use ion_drift_module_api::{ApiVersion, EventKind, Manifest, ProtocolVariant};
use reqwest::Url;
use tracing::info;

use super::store::{ModuleRegistryStore, NewModuleRegistration, RegisteredModule};

/// Minimum acceptable length for per-module secrets (chars). Keeps the
/// door closed on obvious "password123" registrations.
const MIN_SECRET_LEN: usize = 32;
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Inputs for [`ModuleRegistryService::register`].
pub struct RegisterRequest {
    /// Base URL of the module, e.g. `http://10.20.25.50:3099`.
    pub url: String,
    /// HMAC-SHA256 shared secret used to sign outbound event deliveries.
    /// The operator generates this on the module side and pastes it here.
    pub shared_secret: String,
    /// Bearer token Drift sends on reverse-proxied admin requests to the
    /// module. Also operator-generated.
    pub api_token: String,
}

/// High-level registration service.
pub struct ModuleRegistryService {
    store: Arc<ModuleRegistryStore>,
    http: reqwest::Client,
}

impl ModuleRegistryService {
    pub fn new(store: Arc<ModuleRegistryStore>) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(PROBE_TIMEOUT)
            .user_agent(concat!("ion-drift-modules/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("build module registry http client")?;
        Ok(Self { store, http })
    }

    /// For tests: build with a custom reqwest client.
    #[cfg(test)]
    pub fn with_client(store: Arc<ModuleRegistryStore>, http: reqwest::Client) -> Self {
        Self { store, http }
    }

    /// Register a new module.
    ///
    /// Probes `GET <url>/manifest`, validates the returned manifest
    /// against the host's [`ApiVersion`] and the module name rules, and
    /// persists the record if everything checks out.
    pub async fn register(&self, req: RegisterRequest) -> anyhow::Result<RegisteredModule> {
        let base = parse_module_url(&req.url)?;
        if req.shared_secret.chars().count() < MIN_SECRET_LEN {
            return Err(anyhow!(
                "shared_secret must be at least {MIN_SECRET_LEN} characters"
            ));
        }
        if req.api_token.chars().count() < MIN_SECRET_LEN {
            return Err(anyhow!(
                "api_token must be at least {MIN_SECRET_LEN} characters"
            ));
        }

        let manifest = self.fetch_manifest(&base).await?;
        validate_manifest(&manifest)?;

        if self.store.get_by_name(&manifest.name).await?.is_some() {
            return Err(anyhow!(
                "module '{}' is already registered; unregister it first",
                manifest.name
            ));
        }

        let canonical_url = base.as_str().trim_end_matches('/').to_string();
        let id = self
            .store
            .register(NewModuleRegistration {
                name: &manifest.name,
                url: &canonical_url,
                manifest: &manifest,
                shared_secret: &req.shared_secret,
                api_token: &req.api_token,
            })
            .await?;

        info!(module = %manifest.name, id, url = %canonical_url, "module registered");

        self.store
            .get_by_name(&manifest.name)
            .await?
            .ok_or_else(|| anyhow!("registered module disappeared between insert and read"))
    }

    pub async fn unregister(&self, name: &str) -> anyhow::Result<bool> {
        let removed = self.store.unregister(name).await?;
        if removed {
            info!(module = %name, "module unregistered");
        }
        Ok(removed)
    }

    pub async fn set_enabled(&self, name: &str, enabled: bool) -> anyhow::Result<bool> {
        let changed = self.store.set_enabled(name, enabled).await?;
        if changed {
            info!(module = %name, enabled, "module enable state updated");
        }
        Ok(changed)
    }

    pub async fn list(&self) -> anyhow::Result<Vec<RegisteredModule>> {
        self.store.list().await
    }

    pub async fn get_by_name(&self, name: &str) -> anyhow::Result<Option<RegisteredModule>> {
        self.store.get_by_name(name).await
    }

    /// Probe a registered module's `/manifest` endpoint and touch its
    /// `last_seen_at` on success. Does not persist the manifest.
    pub async fn test_connection(&self, name: &str) -> anyhow::Result<Manifest> {
        let module = self
            .store
            .get_by_name(name)
            .await?
            .ok_or_else(|| anyhow!("module '{name}' not registered"))?;
        let base = Url::parse(&module.url).context("stored URL is not parseable")?;
        let manifest = self.fetch_manifest(&base).await?;
        validate_manifest(&manifest)?;
        self.store.touch_last_seen(name).await?;
        Ok(manifest)
    }

    /// Probe the module, replace the cached manifest with the fresh copy.
    pub async fn refresh_manifest(&self, name: &str) -> anyhow::Result<Manifest> {
        let manifest = self.test_connection(name).await?;
        self.store.update_manifest(name, &manifest).await?;
        Ok(manifest)
    }

    async fn fetch_manifest(&self, base: &Url) -> anyhow::Result<Manifest> {
        let manifest_url = Url::parse(&format!(
            "{}/manifest",
            base.as_str().trim_end_matches('/')
        ))
        .context("construct manifest URL")?;
        let resp = self
            .http
            .get(manifest_url.clone())
            .send()
            .await
            .with_context(|| format!("GET {manifest_url}"))?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "GET {manifest_url} returned {}",
                resp.status()
            ));
        }
        let manifest: Manifest = resp
            .json()
            .await
            .with_context(|| format!("parse manifest body from {manifest_url}"))?;
        Ok(manifest)
    }
}

fn parse_module_url(s: &str) -> anyhow::Result<Url> {
    let url = Url::parse(s).context("module URL is not valid")?;
    match url.scheme() {
        "http" | "https" => {}
        other => {
            return Err(anyhow!(
                "unsupported scheme '{other}'; expected http or https"
            ))
        }
    }
    if url.host_str().is_none() {
        return Err(anyhow!("module URL must include a host"));
    }
    Ok(url)
}

/// Validate a manifest against host rules. Pure function so callers can
/// exercise this without an HTTP probe.
pub fn validate_manifest(m: &Manifest) -> anyhow::Result<()> {
    validate_module_name(&m.name)?;
    if !m.api_version.is_compatible_with(ApiVersion::CURRENT) {
        return Err(anyhow!(
            "module api_version {} is not compatible with host {}",
            m.api_version,
            ApiVersion::CURRENT
        ));
    }
    if !matches!(m.protocol, ProtocolVariant::Http) {
        return Err(anyhow!(
            "only 'http' protocol is supported in this release"
        ));
    }
    if m
        .subscribed_events
        .iter()
        .any(|k| matches!(k, EventKind::ModuleCustom))
    {
        return Err(anyhow!(
            "subscribed_events cannot include ModuleCustom; that variant is for \
             in-process module-to-module communication only"
        ));
    }
    Ok(())
}

/// Same rule as the in-process [`ion_drift_module_api::Module::name`]:
/// `^[a-z][a-z0-9_-]{1,31}$`. We spell it out by hand to avoid pulling
/// in the regex crate for one check.
fn validate_module_name(name: &str) -> anyhow::Result<()> {
    let len = name.chars().count();
    if !(2..=32).contains(&len) {
        return Err(anyhow!(
            "module name length must be 2..=32; got {len}"
        ));
    }
    let mut iter = name.chars();
    let first = iter.next().unwrap();
    if !first.is_ascii_lowercase() {
        return Err(anyhow!(
            "module name must start with a lowercase letter"
        ));
    }
    for c in iter {
        let ok = c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_';
        if !ok {
            return Err(anyhow!(
                "module name contains invalid character {c:?}"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::{Aes256Gcm, Key};
    use axum::{extract::State, routing::get, Json, Router};
    use ion_drift_module_api::RouteDescriptor;
    use tempfile::NamedTempFile;

    fn test_kek() -> Key<Aes256Gcm> {
        let bytes: [u8; 32] = [9u8; 32];
        Key::<Aes256Gcm>::from_slice(&bytes).to_owned()
    }

    fn sample_manifest(name: &str) -> Manifest {
        Manifest {
            name: name.to_string(),
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

    async fn spawn_mock(manifest: Option<Manifest>) -> String {
        async fn manifest_route(State(m): State<Arc<Option<Manifest>>>) -> axum::response::Response {
            use axum::http::StatusCode;
            use axum::response::IntoResponse;
            match m.as_ref() {
                Some(m) => Json(m.clone()).into_response(),
                None => (StatusCode::NOT_FOUND, "no manifest").into_response(),
            }
        }
        let state = Arc::new(manifest);
        let app = Router::new()
            .route("/manifest", get(manifest_route))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    async fn build_service() -> (ModuleRegistryService, NamedTempFile) {
        let tmp = NamedTempFile::new().unwrap();
        let store = Arc::new(ModuleRegistryStore::new(tmp.path(), test_kek()).unwrap());
        let svc = ModuleRegistryService::new(store).unwrap();
        (svc, tmp)
    }

    fn long_secret() -> String {
        "x".repeat(32)
    }

    #[test]
    fn valid_name_passes() {
        validate_module_name("scout-shield").unwrap();
        validate_module_name("a1").unwrap();
        validate_module_name("m_2").unwrap();
    }

    #[test]
    fn invalid_name_rejected() {
        assert!(validate_module_name("").is_err());
        assert!(validate_module_name("A").is_err());
        assert!(validate_module_name("1abc").is_err());
        assert!(validate_module_name("with space").is_err());
        assert!(validate_module_name("Nope").is_err());
        assert!(validate_module_name(&"a".repeat(33)).is_err());
    }

    #[test]
    fn manifest_validation_rejects_bad_api_version() {
        let mut m = sample_manifest("m");
        m.api_version = ApiVersion {
            major: 99,
            minor: 0,
        };
        assert!(validate_manifest(&m).is_err());
    }

    #[test]
    fn manifest_validation_rejects_module_custom_subscription() {
        let mut m = sample_manifest("m");
        m.subscribed_events.push(EventKind::ModuleCustom);
        assert!(validate_manifest(&m).is_err());
    }

    #[test]
    fn url_parse_rejects_non_http() {
        assert!(parse_module_url("ftp://example.com").is_err());
        assert!(parse_module_url("not a url").is_err());
        assert!(parse_module_url("http://").is_err());
    }

    #[tokio::test]
    async fn register_happy_path() {
        let (svc, _tmp) = build_service().await;
        let base = spawn_mock(Some(sample_manifest("scout-shield"))).await;
        let got = svc
            .register(RegisterRequest {
                url: base.clone(),
                shared_secret: long_secret(),
                api_token: long_secret(),
            })
            .await
            .unwrap();
        assert_eq!(got.name, "scout-shield");
        assert_eq!(got.url, base.trim_end_matches('/'));
        assert!(got.enabled);
    }

    #[tokio::test]
    async fn register_rejects_short_secret() {
        let (svc, _tmp) = build_service().await;
        let base = spawn_mock(Some(sample_manifest("m"))).await;
        let err = svc
            .register(RegisterRequest {
                url: base,
                shared_secret: "tooshort".into(),
                api_token: long_secret(),
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("shared_secret"));
    }

    #[tokio::test]
    async fn register_rejects_missing_manifest() {
        let (svc, _tmp) = build_service().await;
        let base = spawn_mock(None).await;
        let err = svc
            .register(RegisterRequest {
                url: base,
                shared_secret: long_secret(),
                api_token: long_secret(),
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("404"));
    }

    #[tokio::test]
    async fn duplicate_registration_rejected() {
        let (svc, _tmp) = build_service().await;
        let base = spawn_mock(Some(sample_manifest("dup"))).await;
        svc.register(RegisterRequest {
            url: base.clone(),
            shared_secret: long_secret(),
            api_token: long_secret(),
        })
        .await
        .unwrap();
        let err = svc
            .register(RegisterRequest {
                url: base,
                shared_secret: long_secret(),
                api_token: long_secret(),
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("already registered"));
    }

    #[tokio::test]
    async fn test_connection_touches_last_seen() {
        let (svc, _tmp) = build_service().await;
        let base = spawn_mock(Some(sample_manifest("probe-me"))).await;
        svc.register(RegisterRequest {
            url: base,
            shared_secret: long_secret(),
            api_token: long_secret(),
        })
        .await
        .unwrap();

        let before = svc.get_by_name("probe-me").await.unwrap().unwrap();
        assert!(before.last_seen_at.is_none());

        let _m = svc.test_connection("probe-me").await.unwrap();
        let after = svc.get_by_name("probe-me").await.unwrap().unwrap();
        assert!(after.last_seen_at.is_some());
    }
}
